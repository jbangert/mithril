require_relative 'elf'
module Elf
  module Writer

    def self.elf_hash(value)      
      h=0 
      g=0
      value.chars.map(&:ord).each {|char|
        h = ((h << 4) + (char % 256) )
        g = h & 0xf0000000
        if g!=0
          h = h ^ (g>> 24) # This simulates overflow; elf spec is clever
        end
        h &= ~g
      }
      h
    end
    def self.gnu_hash(value)
      h = 5381
      value.chars.map(&:ord).each {|char|
        h = (h*33 + char) & 0xffffffff
      }
      pp "Gnu_hash #{value} #{h}"
      h
    end
    class StringTable #Replace with compacting string table
      attr_reader :buf
      def initialize 
        @buf = StringIO.new("\0")
        @buf.seek 1 
        @strings = {} #TODO: Do substring matching, compress the string
        #table.
        # Actually, make all string tables except dynstr one, might save
        # a bit 
      end
      def add_string(string) 
        unless @strings.include? string
          @strings[string] =  @buf.tell.tap {|x| 
            BinData::Stringz::new(string).write(@buf)
          }
        end
        @strings[string]
      end      
      def buf()
        @buf
      end
    end
    class OutputSection 
      attr_accessor :name, :type,:flags,:vaddr,:siz,:link,:info, :align, :entsize, :data, :shdr, :off
      attr_accessor :index
      # TODO: Use params array
      def initialize(name,type,flags,vaddr,siz,link,info,align,entsize,data) #link and info are strings, offset is done by output stage
        @name,@type,@flags, @vaddr, @siz, @link, @info, @align, @entsize, @data= name,type,flags,vaddr,siz,link,info,align,entsize, data
        @off = nil
        @index = nil
      end
      def end
        @vaddr + @siz
      end
      
    end

    class Layout
      def initialize(factory)
        @layout_by_flags = {}
        @layout = RBTree.new()
        @shstrtab = StringTable.new()
        @factory = factory
        @phdrs = [] #BinData::Array.new(:type => @factory.phdr)
        @unallocated =[]
        @sections = [OutputSection.new("", SHT::SHT_NULL, 0,0,0,0,0,0,0,"")]
        @sections[0].index = 0

        @pinned_sections = {} # Name to vaddr
      end
      def pin_section(name,size,vaddr)
        x = OutputSection.new(".pin_dummy",SHT::SHT_NULL,0,vaddr,0,0,0,0,0,
                              BinData::Array.new(type: :int8, initial_length: size).to_binary_s)
        raise RuntimeError.new "Invalid pin" unless range_available?(@layout,vaddr,vaddr+size)
        @layout[vaddr] = x
        @pinned_sections[name] = vaddr
      end
      def [](idx)
        @sections[idx]
      end
      def add(*sections)       #Ordering as follows: Fixed
        #(non-nil vaddrs) go where they have to go
        # Flexible sections are added to lowest hole after section of
        # the same type
        retval = []
        return [] if sections.empty?
        sections.each{|sect|
          sect.index = @sections.size
          expect_value "Correct size", sect.data.bytesize, sect.siz
          @sections << sect
          retval << sect.index
        }
        flags = sections.first.flags
        @layout_by_flags[flags] ||= RBTree.new()
        if sections.length > 1 || sections.first.vaddr.nil?
          sections.each { |i| 
            expect_value "All adjacent sections have the same flags", i.flags,flags
            expect_value "All sections must float", i.vaddr, nil
          }
          if sections.length == 1 && @pinned_sections.include?(sections.first.name)
            sections.first.vaddr = @pinned_sections[sections.first.name]
            @layout.delete sections.first.vaddr
            @pinned_sections.delete @sections.first.name
          else
            allocate_sections(sections)
          end
        end
        #TODO: Handle the damn nobits
        if(flags & SHF::SHF_ALLOC == 0)
          sections.each {|i| @unallocated << i}
        else
          sections.each {|i|

            expect_value "Sections shouldn't overlap",  range_available?(@layout,i.vaddr,i.end), true 
            @layout[i.vaddr] = i 
            @layout_by_flags[i.flags][i.vaddr] = i
          }
        end
        retval
      end 
      def add_with_phdr(sections,type,flags)
        raise RuntimeError.new "need one section in phdr" if sections.empty?
        x=self.add *sections
        @phdrs << [sections,type,flags]
        x
      end
      def shstrtab(buf) # Last section written, TODO: Move to layout
        name = ".shstrtab"
        idx = @shstrtab.add_string name
        x=@factory.shdr.new
        x.name= idx 
        x.type = SHT::SHT_STRTAB
        x.off = buf.tell
        x.siz = @shstrtab.buf.size
        buf.write @shstrtab.buf.string
        x
      end

      LoadMap = Struct.new(:off,:end,:vaddr,:memsz,:flags,:align)
      def pagealign_loadmap(loadmaps)
        #TODO: Be smarter about this..
        loadmaps.sort_by(&:vaddr).each_cons(2) do |low,high|
            if rounddown(low.vaddr + low.memsz,PAGESIZE) >= rounddown(high.vaddr,PAGESIZE)
              low.flags |= high.flags
              high.flags |= low.flags              
            end
        end
        loadmaps
      end
      attr_accessor :tbss_size
      def write_phdrs(buf,filehdr,load)
        phdrs = BinData::Array.new(:type => @factory.phdr)
        expect_value "Too many PHDRS",true, @phdrs.size + load.size < RESERVED_PHDRS
        @phdrs.each {|x|
          sections, type,flags =*x
          x =  @factory.phdr.new
          x.align = sections.map(&:align).max
          x.vaddr = sections.map(&:vaddr).min
          x.paddr = x.vaddr
          x.filesz = sections.map(&:end).max - x.vaddr
          if type == PT::PT_TLS and @tbss_size #HACK
            x.memsz = x.filesz + @tbss_size
          else
            x.memsz = x.filesz
          end
          x.flags = flags
          x.off = sections.map(&:off).min
          x.type = type
          phdrs.push x
        }
        #
        load.first.andand.tap{|l|
          l.vaddr -= l.off
          l.memsz += l.off
          l.off = 0
        }
        pagealign_loadmap(load)
        load.each {|l|
          phdrs.push @factory.phdr.new.tap {|x|
            x.align = [PAGESIZE,l.align].max
            x.vaddr = l.vaddr
            x.paddr = x.vaddr
            x.type = PT::PT_LOAD
            x.filesz = l.end - l.off#TODO: handle nobits
            x.memsz = x.filesz # l.memsz
            x.off = l.off
            x.flags = PF::PF_R
            x.flags |= PF::PF_W if(l.flags & SHF::SHF_WRITE != 0)
            x.flags |= PF::PF_X if(l.flags & SHF::SHF_EXECINSTR != 0)

          }
        }
        
        #phdrs.unshift @factory.phdr.new.tap {|x|
        #  x.align = 4
        #  x.vaddr = 
        # x.type = PT::PT_PHDRS
        #}
        #      pp load
        filehdr.phoff = buf.tell
        filehdr.phentsize = @factory.phdr.new.num_bytes
        filehdr.phnum = phdrs.size
        phdrs.write buf

      end
      RESERVED_PHDRS = 16
      def write_sections(buf,filehdr)
        first_shdr = @sections.first 
        first_shdr.index = 0
        
        #Get more clever about mapping files
        # We put actual program headers right at the beginning.
        phdr_off = buf.tell
        buf.seek phdr_off + RESERVED_PHDRS * @factory.phdr.new.num_bytes
        offset = buf.tell
        @sections[0].off = 0
        (@layout.to_a.sort_by(&:first).map(&:last) + @unallocated).each {|s|
          if s.flags & SHF::SHF_ALLOC != 0
            offset = align_mod(offset,s.vaddr, PAGESIZE)     
          end
          s.off = offset
          offset += s.data.bytesize
          
        }
        idx = 0
        @sections.each{|s|  expect_value "Size field correct", s.siz, s.data.bytesize}
        @sections.sort_by(&:off).each_cons(2){|low,high|
          expect_value "Offsets should not overlap", true, low.off + low.data.bytesize <= high.off
        }
        shdrs = BinData::Array.new(:type=>@factory.shdr).push *@sections.map{ |s|
          expect_value "aligned to vaddr", 0,s.vaddr % s.align if s.align != 0
          expect_value "idx", idx,s.index
          idx +=1 
          #expect_value "aligned to pagesize",0, PAGESIZE % s.align
          
          buf.seek s.off
          old_off = buf.tell 
          buf.write(s.data)
#          pp "#{idx }#{s.name} written to offset #{old_off} to #{buf.tell}"

          
          expect_value "size", s.data.bytesize, s.siz
          link_value = lambda do |name|
            if name.is_a? String
              @sections.to_enum.with_index.select {|sect,idx| sect.name == name}.first.last rescue raise RuntimeError.new("Invalid Section reference #{name}") #Index of first match TODO: check unique
            else
              name || 0
            end
          end
          x=  @factory.shdr.new
          x.name   = @shstrtab.add_string(s.name)
          x.type   = s.type
          x.flags  = s.flags
          x.vaddr  = s.vaddr
          x.off    = s.off
          x.siz    = s.siz
          x.link   = link_value.call(s.link) 
          x.info   = link_value.call(s.info)
          x.addralign  = s.align
          x.entsize= s.entsize
         # x.flags |= SHF::SHF_ALLOC if(@file.gnu_tls.tbss == s)
          x
        }
        #remove
        mapped = @sections.select{|x| x.flags & SHF::SHF_ALLOC != 0}.sort_by(&:vaddr)
        mapped.each_cons(2){|low,high| expect_value "Mapped sections should not overlap", true,low.vaddr + low.siz<= high.vaddr}
        load = mapped.group_by(&:flags).map{|flags,sections| 
          sections.group_by{|x| x.vaddr - x.off}.map do |align,sections|
            memsize = sections.last.off + sections.last.siz - sections.first.off
           # if sections.last.type == SHT::SHT_            end
          # sections.select{|x| x.type == SHT::SHT_NOBITS}.tap {|nobits|
          #    if nobits.size > 0
           #     expect_value "At most one NOBITS", nobits.size,1
           #     expect_value "NOBITS is the last section",sections.last.type, SHT::SHT_NOBITS
           #     last_file_addr = nobits.first.vaddr
           #     memsize = sections.last.off - sections.first.off
           #   end
           # } 
            LoadMap.new(sections.first.off,  sections.last.off + sections.last.siz,
                        sections.first.vaddr, memsize ,flags,sections.map(&:align).max) #TODO: LCM?
          end
        }.flatten     
        buf.seek 0,IO::SEEK_END
        
        shdrs << shstrtab(buf)
        filehdr.shstrndx = shdrs.size - 1
        filehdr.shoff = buf.tell 
        filehdr.shentsize = shdrs[0].num_bytes
        filehdr.shnum = shdrs.size
        shdrs.write buf      
        
        buf.seek roundup(buf.tell, PAGESIZE)-1
        buf.write '\0' # pad to pagesize
        buf.seek phdr_off
        write_phdrs(buf,filehdr,load)
      end
      private
      def allocate_sections(chunk)
        return unless chunk.first.flags & SHF::SHF_ALLOC != 0
        align = chunk.max_by{ |x| x.align}.align #Should technically be the
        #lcm

        #TODO: check that they are powers of two
        size = chunk.reduce(0) {|i,x| i+roundup(x.siz,align)}
        addr = @layout_by_flags[chunk.first.flags].last.andand { |x| roundup(x[1].end,align)}
        if(addr.nil? or !range_available?(@layout,addr,addr+size))
          addr = roundup(@layout.last[1].end,align)
          expect_value "Address space has room", range_available?(@layout,addr,addr+size),true
        end
        chunk.each  do |section|
          section.vaddr = roundup(addr,align)
          addr = section.end
        end
      end
      def rounddown(number,align)
        return number if align == 0
        case number % align
        when 0
          number
        else
          number - (number % align)
        end
      end
      def roundup(number, align)
        return number if align == 0
        case number % align
        when 0
          number
        else
          number + align - (number % align)
        end
      end
      def align_mod(number,align,mod)
        align = align % mod
        x = number  + align -  number % mod
        if(x<number)
          x+mod
        else
          x 
        end
      end
      def range_available?(tree,from,to)
        if tree.empty?
          true
        else
          ( (tree.upper_bound(from).andand.last.andand.end || -1) <= from ) &&
            ( (tree.lower_bound(to).andand.last.andand.vaddr || +1.0/0.0) >= to)
        end
      end
    end
    PAGESIZE = 1 << 12  #KLUDGE: largest pagesize , align everything to
    
    UINT64_MOD = 2**64
    #TODO: Needs a unique class for 'allocatable' sections. 
    #Then just sort, and write them out
    class Writer #TODO: Completely refactor this

      #pagesizes 
      def initialize(file,factory)
        @factory = factory
        @file = file
        @layout = Layout.new(@factory)
        @shdrs= BinData::Array::new(type: @factory.shdr,initial_length: 0)
        @phdrs= BinData::Array::new(type: @factory.phdr,initial_length: 0)
        @buf = StringIO.new()
        @progbit_indices = {}
        @section_vaddrs = {}

        @file.pinned_sections.andand.each {|name,pin|  @layout.pin_section(name,pin[:size],pin[:vaddr])
        }
        write_to_buf
      end
      def self.to_file(filename,elf)
        factory = ElfStructFactory.instance(elf.endian,elf.bits) 
        writer = Writer.new(elf,factory)
        IO.write filename,writer.buf.string
      end
      attr_reader :buf
      private
      def progbits
        @file.gnu_tls.andand(&:tbss).andand{|x|
          x.flags &= ~SHF::SHF_ALLOC
          @layout.tbss_size = x.size
        }
        bits = (@file.progbits + @file.nobits).sort {|a,b|( a.addr and b.addr ) ? a.addr <=> b.addr : ( a.addr ? -1 : 1 ) }
        bits.each do |sect|

          out =  OutputSection.new(sect.name,sect.sect_type, sect.flags, sect.addr, sect.size,0,0,sect.align, sect.entsize, sect.data.string)
          #          binding.pry if sect.sect_type == SHT::SHT_INIT_ARRAY
          if sect.phdr.nil?
            @layout.add out
          else
            @layout.add_with_phdr [out], sect.phdr, sect.phdr_flags
          end
          @progbit_indices[sect] = out.index
          @section_vaddrs[sect] = out.vaddr
        end
        
      end
      def note
        os= @file.notes.map {|name,note|
          OutputSection.new(name, SHT::SHT_NOTE, NOTE_FLAGS, nil, note.num_bytes,0,0,NOTE_ALIGN, NOTE_ENTSIZE,note.to_binary_s)
        }
        @layout.add_with_phdr os, PT::PT_NOTE, PF::PF_R unless os.empty?
        #TODO: add phdr
      end
      def interp
        if(@file.interp)
          interp  = BinData::Stringz.new(@file.interp)
          @interp_section = OutputSection.new(".interp",SHT::SHT_PROGBITS, SHF::SHF_ALLOC, nil, interp.num_bytes,0,0,1,0,interp.to_binary_s)
          idx, _ =@layout.add_with_phdr [@interp_section], PT::PT_INTERP, PF::PF_R
          @progbit_indices[".interp"]=idx
        end
      end
      def hashtab(table)
        hashtab = BinData::Array.new(:type => "uint32#{@file.endian == :big ? 'be' : 'le'}".to_sym)
        nbuckets = 5
        nchain = table.size
        buckets = Array.new(nbuckets,0)
        chain = Array.new(nchain,0)

        table.each {|sym,idx|
          
          expect_value "Valid symbol index", idx<table.size,true
          i = Elf::Writer::elf_hash(sym.name) % nbuckets
          if(buckets[i] == 0)
            buckets[i] = idx
          else
            i = buckets[i]
            while(chain[i] != 0)
              i= chain[i]
            end
            chain[i] = idx
          end        
        }
        hashtab.assign [nbuckets,nchain] + buckets + chain

        sect = OutputSection.new(".hash",SHT::SHT_HASH,SHF::SHF_ALLOC,nil, hashtab.num_bytes, ".dynsym", 0,8,@file.bits/8, hashtab.to_binary_s)
        @layout.add sect
        @dynamic << @factory.dyn.new(tag: DT::DT_HASH, val: sect.vaddr)
        # pp hashtab.snapshot
      end
      def versions(dynsym,dynstrtab) #TODO: Use parser combinator
        @versions = {}
        gnu_versions =  dynsym.map(&:gnu_version).uniq.select{|x|x.is_a? GnuVersion}
        
        defined_versions = gnu_versions.select{|x| x.needed == false}
        unless @file.dynamic.gnu_version_basename.nil?
          defined_versions.unshift GnuVersion.new(@file.dynamic.soname,@file.dynamic.gnu_version_basename, ElfFlags::GnuVerFlags::VERFLAG_BASE, false)
        end
        buffer = StringIO.new()
        defined_versions.each_with_index {|ver,definedidx|
          expect_value "Defined SONAME",false, @file.dynamic.gnu_version_basename.nil?
          expect_value "Defined version file name",ver.file, @file.dynamic.soname
          verdef = @factory.verdef.new
          verdef.version = 1
          verdef.flags = ver.flags
          if ver.flags & ElfFlags::GnuVerFlags::VERFLAG_BASE != 0
            verdef.ndx = 1
          else
            verdef.ndx = @versions.size + 2
            @versions[ver] = @versions.size + 2
          end
          verdef.hsh = Elf::Writer::elf_hash(ver.version)
          verdaux = BinData::Array.new(type: @factory.verdaux)
          verdaux << @factory.verdaux.new.tap{|x|
            x.name = dynstrtab.add_string(ver.version)
            x.nextoff =  x.num_bytes
          }
          ver.parents.each_with_index {|parent,idx|
            aux = @factory.verdaux.new
            aux.name = dynstrtab.add_string(parent.version)
            aux.nextoff = if(idx == ver.parents.size - 1)
                            0
                          else
                            aux.num_bytes
                          end  
            verdaux << aux
          }
          verdef.cnt = verdaux.size
          verdef.aux = verdef.num_bytes
          if(defined_versions.size - 1 == definedidx)
            verdef.nextoff = 0
          else
            verdef.nextoff = verdaux.num_bytes + verdef.num_bytes
          end
          verdef.write(buffer)
          verdaux.write(buffer)
        }
        unless defined_versions.empty?
          sect = OutputSection.new(".gnu.version_d", SHT::SHT_GNU_VERDEF,SHF::SHF_ALLOC,nil,buffer.size,".dynstr",defined_versions.size,8,0,buffer.string)
          @layout.add sect
          @dynamic << @factory.dyn.new(tag: DT::DT_VERDEF, val: sect.vaddr)
          @dynamic << @factory.dyn.new(tag: DT::DT_VERDEFNUM, val: defined_versions.size)
        end
        buffer = StringIO.new()
        needed_versions = gnu_versions.select{|x| x.needed == true}.group_by(&:file)
        needed_idx = 0
        needed_versions.each {|file, versions|
          needed_idx+=1
          #Create VERNEED for this file
          verneed = @factory.verneed.new
          verneed.version = 1
          verneed.cnt = versions.size
          verneed.file = dynstrtab.add_string(file)
          verneed.aux = verneed.num_bytes
          vernauxs = BinData::Array.new(type: @factory.vernaux)
          versions.each {|ver|
            vernauxs.push @factory.vernaux.new.tap {|x|
              x.hsh = Elf::Writer::elf_hash(ver.version)
              x.flags = ver.flags
              x.other = @versions.size + 2
              x.name = dynstrtab.add_string(ver.version)
              x.nextoff = if vernauxs.size == versions.size - 1
                            0
                          else
                            x.num_bytes
                          end
              @versions[ver] = x.other.to_i
            }          
          }
          if (needed_versions.size == needed_idx)
            verneed.nextoff = 0 #  0 for last
          else
            verneed.nextoff = verneed.num_bytes + vernauxs.num_bytes
          end
          verneed.write(buffer)
          vernauxs.write(buffer)
        }
        unless needed_versions.empty?
          sect = OutputSection.new(".gnu.version_r", SHT::SHT_GNU_VERNEED,SHF::SHF_ALLOC,nil,buffer.size,".dynstr",needed_versions.size,8,0,buffer.string)
          @layout.add sect
          @dynamic << @factory.dyn.new(tag: DT::DT_VERNEED, val: sect.vaddr)
          @dynamic << @factory.dyn.new(tag: DT::DT_VERNEEDNUM, val: needed_versions.size)
        end

        @versions
      end
      def versym(versions,symbols)
        data = BinData::Array.new(type: @factory.versym)
        symbols.each{|sym|
          veridx = case sym.gnu_version
                   when :local
                     0
                   when :global
                     1
                   else
                     versions[sym.gnu_version]
                   end
          data.push @factory.versym.new(veridx: veridx)        
        }
        sect = OutputSection.new(".gnu.version",SHT::SHT_GNU_VERSYM, SHF::SHF_ALLOC, nil, data.num_bytes, ".dynsym",0, 8,2, data.to_binary_s)
        @layout.add sect
        @dynamic << @factory.dyn.new(tag: DT::DT_VERSYM, val: sect.vaddr)
      end
      def dynsym(dynstrtab)
        symtab = BinData::Array.new(:type => @factory.sym) #TODO: use initial length here to save on
        #some allocations
        syms = [Elf::Symbol.new("",nil,STT::STT_NOTYPE,0,STB::STB_LOCAL,0).tap{
                |x| x.gnu_version = :local; x.semantics = 0}] + @file.symbols.select(&:is_dynamic)
        versions = versions(syms, dynstrtab)
        @dynsym = {}
        #symtab << @factory.sym.new
        syms.each_with_index.each do |sym,idx|
          s = @factory.sym.new
          s.name = dynstrtab.add_string(sym.name)
          s.type = sym.type
          s.binding = sym.bind
          if sym.semantics.nil?
            s.shndx = @progbit_indices[sym.section] || nil
            unless s.shndx
              pp "warning, symbol ", s,"does not have a valid progbits index"
              s.shndx = nil
            end
          else
            s.shndx = sym.semantics
          end
          s.other = sym.visibility
          unless sym.section.nil?
            expect_value "valid symbol offset",  sym.sectoffset <= sym.section.size,true #Symbol can point to end of section
          end
          
          s.val = (@layout[s.shndx.to_i].andand.vaddr || 0) + sym.sectoffset #TODO: find output section

          s.siz = sym.size
          @dynsym[sym] = symtab.size
          symtab.push s
        end
        last_local_idx = syms.to_enum.with_index.select{|v,i| v.bind == STB::STB_LOCAL}.andand.last.andand.last || -1
        dynsym = OutputSection.new(".dynsym",SHT::SHT_DYNSYM, SHF::SHF_ALLOC, nil,symtab.num_bytes,".dynstr", last_local_idx+1,1,@factory.sym.new.num_bytes, symtab.to_binary_s)
        versym(versions,syms)
        @layout.add dynsym
        hashtab(@dynsym)
        @dynamic << @factory.dyn.new(tag: DT::DT_SYMTAB,val: dynsym.vaddr)
        @dynamic << @factory.dyn.new(tag: DT::DT_SYMENT,val: @factory.sym.new.num_bytes)
        
      end # Produce a hash and a GNU_HASH as well
      def dynamic
        @dynamic = BinData::Array.new(:type => @factory.dyn)
        dynstrtab = StringTable.new()
        reladyn(dynstrtab)
        #PHDR
        @file.dynamic.needed.each{|lib|
          @dynamic << @factory.dyn.new(tag: DT::DT_NEEDED, val: dynstrtab.add_string(lib))
        }
        section_tag = lambda {|tag,value|
          unless(value.nil?)
            @dynamic << @factory.dyn.new(tag: tag, val: value.addr)
            true
          else
            nil
          end
        }
        unless @file.dynamic.soname.nil?
          @dynamic << @factory.dyn.new(tag: DT::DT_SONAME, val: dynstrtab.add_string(@file.dynamic.soname))
        end
        unless @file.dynamic.rpath.nil?
          @dynamic << @factory.dyn.new(tag: DT::DT_RPATH, val: dynstrtab.add_string(@file.dynamic.rpath))
        end
        section_tag.call(DT::DT_PLTGOT,@file.dynamic.pltgot)
        if section_tag.call(DT::DT_INIT_ARRAY,@file.dynamic.init_array)
          @dynamic << @factory.dyn.new(tag: DT::DT_INIT_ARRAYSZ,val: @file.dynamic.init_array.size)
        end
        if section_tag.call(DT::DT_FINI_ARRAY,@file.dynamic.fini_array)
          @dynamic << @factory.dyn.new(tag: DT::DT_FINI_ARRAYSZ,val: @file.dynamic.fini_array.size)
        end
        #        section_tag.call(DT::DT_INIT,@file.dynamic.init)
        #        section_tag.call(DT::DT_FINI,@file.dynamic.fini)
        @dynamic << @factory.dyn.new(tag: DT::DT_INIT, val: @file.dynamic.init) if @file.dynamic.init
        @dynamic << @factory.dyn.new(tag: DT::DT_FINI, val: @file.dynamic.fini) if @file.dynamic.fini
        
        #@file.dynamic.debug_val.each {|dbg| 
        #  @dynamic << @factory.dyn.new(tag: DT::DT_DEBUG, val: dbg)
        #}
        #@file.dynamic.extra_dynamic.each{ |extra|
        #  @dynamic << @factory.dyn.new(tag: extra[:tag], val: extra[:val])
        #}
        if @file.dynamic.flags
          @dynamic << @factory.dyn.new(tag: DT::DT_FLAGS, val: @file.dynamic.flags)
        end
        if @file.dynamic.flags1
          @dynamic << @factory.dyn.new(tag: DT::DT_FLAGS_1, val: @file.dynamic.flags1)
        end
        #string table
        dynstr = OutputSection.new(".dynstr", SHT::SHT_STRTAB, SHF::SHF_ALLOC,nil, dynstrtab.buf.size, 0,0,1,0,dynstrtab.buf.string)
        @layout.add dynstr 
        @dynamic << @factory.dyn.new(tag: DT::DT_STRTAB, val: dynstr.vaddr)
        @dynamic << @factory.dyn.new(tag: DT::DT_STRSZ, val: dynstr.siz)

        @dynamic <<  @factory.dyn.new(tag: DT::DT_NULL, val: 0) # End marker
        @layout.add_with_phdr [OutputSection.new(".dynamic", SHT::SHT_DYNAMIC, SHF::SHF_ALLOC | SHF::SHF_WRITE, nil, @dynamic.num_bytes,".dynstr",0,8,@factory.dyn.new.num_bytes,@dynamic.to_binary_s)], PT::PT_DYNAMIC, PF::PF_R
        #dynstr -> STRTAB STRSZ
        #dynsym -> DT_SYMENT, D
      end # Write note, etc for the above
      RELATIVE_RELOCS=[R::R_X86_64_RELATIVE]
      def rela_buffer(relocations)
        relative_rela_count = 0
        buf = BinData::Array.new(:type =>@factory.rela).new.tap{|retval|
          relocations.sort_by{|x| RELATIVE_RELOCS.include?(x.type) ? 0 : 1}.each_with_index {|rel,idx|
            entry = @factory.rela.new
            entry.off = @section_vaddrs[rel.section] + rel.offset
            if rel.symbol.nil?
              entry.sym = ElfFlags::SymbolName::STN_UNDEF              
            else
              entry.sym = @dynsym[rel.symbol]  
            end
            relative_rela_count +=1 if(RELATIVE_RELOCS.include? rel.type)
            entry.type = rel.type
            entry.addend = rel.addend
            retval.push entry
          }
        }
        [buf, relative_rela_count]
      end
      
      def reladyn(dynstrtab)        
        @file.relocations.each{ |r|
          r.symbol.andand {|x| x.is_dynamic  = true}
        }
        dynsym(dynstrtab)
        relaentsize = @factory.rela.new.num_bytes

        pltrel = @file.relocations.select(&:is_dynamic).select(&:is_lazy)
        dynrel = @file.relocations.select(&:is_dynamic).select{|x| not x.is_lazy}
        rela_sections = []
        unless dynrel.empty?
          #All other relocations go into .rela.dyn
          relabuf,relacount = rela_buffer(dynrel)
          reladyn = OutputSection.new(".rela.dyn", SHT::SHT_RELA, SHF::SHF_ALLOC,nil, relabuf.num_bytes,".dynsym",0,8, relaentsize, relabuf.to_binary_s)
          rela_sections << reladyn
          @dynamic << @factory.dyn.new(tag: DT::DT_RELACOUNT, val: relacount)
        end
        unless(pltrel.empty?)
          relabuf,_=rela_buffer(pltrel)
          relaplt = OutputSection.new(".rela.plt", SHT::SHT_RELA, SHF::SHF_ALLOC, nil, relabuf.num_bytes,".dynsym",@file.dynamic.pltgot.name,8, relaentsize, relabuf.to_binary_s)
          rela_sections << relaplt
        end
        @layout.add *rela_sections # They need to in this order to produce a correct ld.so
        unless dynrel.empty?
          @dynamic << @factory.dyn.new(tag: DT::DT_PLTRELSZ, val: relabuf.num_bytes)
          @dynamic << @factory.dyn.new(tag: DT::DT_PLTREL, val: DT::DT_RELA)
          @dynamic << @factory.dyn.new(tag: DT::DT_JMPREL, val: relaplt.vaddr)
        end
        begin
          @dynamic << @factory.dyn.new(tag: DT::DT_RELA, val: reladyn.vaddr)
          @dynamic << @factory.dyn.new(tag: DT::DT_RELASZ, val: reladyn.siz)     
          @dynamic << @factory.dyn.new(tag: DT::DT_RELAENT, val: relaentsize)
        end
      end
      def write_headers
        hdr = @factory.hdr.new
        case @file.endian
        when :big
          hdr.ident.id_data =  ElfFlags::IdentData::ELFDATA2MSB 
        when :little
          hdr.ident.id_data =  ElfFlags::IdentData::ELFDATA2LSB 
        else 
          raise ArgumentError.new "Invalid endianness"
        end
        case @file.bits 
        when 64 
          hdr.ident.id_class = ElfFlags::IdentClass::ELFCLASS64
        when 32
          hdr.ident.id_class = ElfFlags::IdentClass::ELFCLASS32
        else
          raise ArgumentError.new "Invalid class"
        end
        hdr.ident.id_version = ElfFlags::Version::EV_CURRENT
        hdr.ehsize = hdr.num_bytes
        hdr.type = @file.filetype
        hdr.machine = @file.machine
        hdr.version = @file.version
        hdr.entry = @file.entry
        hdr.flags = @file.flags
        
        @layout.write_sections(@buf,hdr)
        
        @buf.seek 0 
        hdr.write @buf
      end
      #TODO: Fix things like INTERP
      

      def write_to_buf #Make this memoized
        @buf.seek @factory.hdr.new.num_bytes #Leave space for header.
        #this is pretty bad
        progbits
        interp 
        note
        dynamic
        write_headers
      end
    end
  end
end
