require_relative 'elf'
module Elf
  module Writer

  class StringTable #Replace with compacting string table
    attr_reader :buf
    def initialize 
      @buf = StringIO.new("\0")
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
      @current_idx = 1
    end
    def add(*sections)       #Ordering as follows: Fixed
      #(non-nil vaddrs) go where they have to go
      # Flexible sections are added to lowest hole after section of
      # the same type
      return if sections.empty?
      sections.each{|shdr|
        shdr.index = @current_idx
        @current_idx += 1
      }
      flags = sections.first.flags
      @layout_by_flags[flags] ||= RBTree.new()
      if sections.length > 1 || sections.first.vaddr.nil?
        sections.each { |i| 
          expect_value "All adjacent sections have the same flags", i.flags,flags
          expect_value "All sections must float", i.vaddr, nil
        }
        allocate_sections(sections)
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
    end 
    def add_with_phdr(sections,type,flags) 
      self.add *sections
      @phdrs << [sections,type,flags]
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
        x.memsz = x.filesz
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
      first_shdr = OutputSection.new("", SHT::SHT_NULL, 0,0,0,0,0,0,0,"")
      first_shdr.index = 0
      sections = ([first_shdr] +@layout.to_a.sort_by(&:first).map(&:last) + @unallocated)
      
      #Get more clever about mapping files
      # We put actual program headers right at the beginning.
      phdr_off = buf.tell
      buf.seek phdr_off + RESERVED_PHDRS * @factory.phdr.new.num_bytes
      idx = 0
      shdrs = BinData::Array.new(:type=>@factory.shdr).push *sections.map{ |s|
        expect_value "aligned to vaddr", 0,s.vaddr % s.align if s.align != 0
        #expect_value "idx", idx,s.index
        idx +=1 
        #expect_value "aligned to pagesize",0, PAGESIZE % s.align 
        if s.flags & SHF::SHF_ALLOC != 0
          off = align_mod(buf.tell,s.vaddr, PAGESIZE)        
        else
          off = buf.tell
        end
        s.off = off
        buf.seek off
        buf.write(s.data) 
        link_value = lambda do |name|
          if name.is_a? String
            sections.to_enum.with_index.select {|sect,idx| sect.name == name}.first.last rescue raise RuntimeError.new("Invalid Section reference #{name}") #Index of first match TODO: check unique
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
        x
      }
      #remove
      mapped = sections.select{|x| x.flags & SHF::SHF_ALLOC != 0}.sort_by(&:vaddr)
      mapped.each_cons(2){|low,high| expect_value "Mapped sections should not overlap", true,low.vaddr + low.siz<= high.vaddr}
      load = mapped.group_by(&:flags).map{|flags,sections| # 
        sections.group_by{|x| x.vaddr - x.off}.map do |align,sections|
          memsize = sections.last.off + sections.last.siz - sections.first.off
          sections.select{|x| x.type == SHT::SHT_NOBITS}.tap {|nobits|
            if nobits.size > 0
              expect_value "At most one NOBITS", nobits.size,1
              expect_value "NOBITS is the last section",sections.last.type, SHT::SHT_NOBITS
              last_file_addr = nobits.first.vaddr
              memsize = sections.last.off - sections.first.off
            end
          }
          LoadMap.new(sections.first.off,  sections.last.off + sections.last.siz,
                      sections.first.vaddr, memsize,flags,sections.map(&:align).max) #TODO: LCM?
        end
      }.flatten     
      
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
        section.vaddr = roundup(addr + section.siz,align)
        addr = section.end
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
      (@file.progbits + @file.nobits).each do |sect| 
        @layout.add OutputSection.new(sect.name,sect.sect_type, sect.flags, sect.addr, sect.size,0,0,sect.align, sect.entsize, sect.data.string)
      end
    end
    def note
      os= @file.notes.map {|name,note|
        OutputSection.new(name, SHT::SHT_NOTE, NOTE_FLAGS, nil, note.num_bytes,0,0,NOTE_ALIGN, NOTE_ENTSIZE,note.to_binary_s)
      }
      @layout.add_with_phdr os, PT::PT_NOTE, PF::PF_R
      #TODO: add phdr
    end
    def interp
      if(@file.interp)
        interp  = BinData::Stringz.new(@file.interp)
        pp interp.snapshot
        @layout.add_with_phdr [OutputSection.new(".interp",SHT::SHT_PROGBITS, SHF::SHF_ALLOC, nil, interp.num_bytes,0,0,1,0,interp.to_binary_s)], PT::PT_INTERP, PF::PF_R
      end
    end
    def elf_hash(value)
      h=0 
      g=0
      value.chars.map(&:ord).each {|char|
        h = (h << 4) + char
        g = h & 0xf0000000
        h = h ^ (g>> 24)
        h &= ~g
      }
      h
    end
    def hashtab(table)
      hashtab = BinData::Array.new(:type => "uint#{@file.bits}#{@file.endian == :big ? 'be' : 'le'}".to_sym)
      nbuckets = 64
      nchain  =  table.size
      hashtab[0] = nbuckets
      hashtab[1] = nchain
      (0..nbuckets+nchain -1).each do |b|
        hashtab[2+b]= 0
      end
      table.each {|name,idx|
        i = 2+(elf_hash(name) % nbuckets) #initial bucket
        while(hashtab[i] != 0)
          i = 2+nbuckets+hashtab[i] # Collision record for that entry
        end
        hashtab[i]=idx
      }
      sect = OutputSection.new(".hash",SHT::SHT_HASH,SHF::SHF_ALLOC,nil, hashtab.num_bytes, ".dynsym", 0,8,@file.bits/8, hashtab.to_binary_s)
      @layout.add sect
      @dynamic << @factory.dyn.new(tag: DT::DT_HASH, val: sect.vaddr)
      # pp hashtab.snapshot
    end
    def verneed(dynsym,dynstrtab) #TODO: Use parser combinator
      @versions = {}
      buffer = StringIO.new()
      versions_by_file =  dynsym.map(&:gnu_version).uniq.select{|x| x.is_a? GnuVersion}.group_by(&:file)
      i = 0
      versions_by_file.each {|file, versions|
        i+=1
        #Create VERNEED for this file
        verneed = @factory.verneed.new
        verneed.version = 1
        verneed.cnt = versions.size
        verneed.file = dynstrtab.add_string(file)
        verneed.aux = verneed.num_bytes
        vernauxs = BinData::Array.new(type: @factory.vernaux)
        versions.each {|ver|
          vernauxs.push @factory.vernaux.new.tap {|x|
            x.hsh = elf_hash(ver.version)
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
        if (versions_by_file.size == i)
          verneed.nextoff = 0
        else
          verneed.nextoff = verneed.num_bytes + vernauxs.num_bytes # TODO: 0 for last
        end
        verneed.write(buffer)
        vernauxs.write(buffer)
      }
      sect = OutputSection.new(".gnu.version_r", SHT::SHT_GNU_VERNEED,SHF::SHF_ALLOC,nil,buffer.size,".dynstr",versions_by_file.size,8,0,buffer.string)
      @layout.add sect
      @dynamic << @factory.dyn.new(tag: DT::DT_VERNEED, val: sect.vaddr)
      @dynamic << @factory.dyn.new(tag: DT::DT_VERNEEDNUM, val: versions_by_file.size)
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
      symtab = BinData::Array.new(:type => @factory.sym)
      syms = @file.symbols.values.select(&:is_dynamic)
      versions = verneed(syms, dynstrtab)
      @dynsym = {}
      syms.to_enum.with_index.each do |sym,idx|
        s = @factory.sym.new
        s.name = dynstrtab.add_string(sym.name)
        s.type = sym.type
        s.binding = sym.bind
        s.shndx = 0# 0xabcd
        unless sym.section.nil?
          expect_value "valid symbol offset",  sym.sectoffset <= sym.section.size,true #Symbol can point to end of section
        end
        s.val = (sym.section.andand.addr || 0) + sym.sectoffset
        s.siz = sym.size
        @dynsym[sym.name] = idx
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
        end
      }
      section_tag.call(DT::DT_PLTGOT,@file.dynamic.pltgot)
      section_tag.call(DT::DT_INIT,@file.dynamic.init)
      section_tag.call(DT::DT_FINI,@file.dynamic.fini)
      #@file.dynamic.debug_val.each {|dbg| 
      #  @dynamic << @factory.dyn.new(tag: DT::DT_DEBUG, val: dbg)
      #}
      #@file.dynamic.extra_dynamic.each{ |extra|
      #  @dynamic << @factory.dyn.new(tag: extra[:tag], val: extra[:val])
      #}

      #string table
      dynstr = OutputSection.new(".dynstr", SHT::SHT_STRTAB, SHF::SHF_ALLOC,nil, dynstrtab.buf.size, 0,0,1,0,dynstrtab.buf.string)
      @layout.add dynstr 
      @dynamic << @factory.dyn.new(tag: DT::DT_STRTAB, val: dynstr.vaddr)
      @dynamic << @factory.dyn.new(tag: DT::DT_STRSZ, val: dynstr.siz)

      @dynamic <<  @factory.dyn.new(tag: DT::DT_NULL, val: 0) # End marker
      @layout.add_with_phdr [OutputSection.new(".dynamic", SHT::SHT_DYNAMIC, SHF::SHF_ALLOC, nil, @dynamic.num_bytes,".dynstr",0,8,@factory.dyn.new.num_bytes,@dynamic.to_binary_s)], PT::PT_DYNAMIC, PF::PF_R
      #dynstr -> STRTAB STRSZ
      #dynsym -> DT_SYMENT, D
    end # Write note, etc for the above
    def rela_buffer(relocations)
      BinData::Array.new(:type =>@factory.rela).new.tap{|retval|
        relocations.each {|rel|
          entry = @factory.rela.new
          entry.off = rel.section.addr + rel.offset
          entry.sym = @dynsym[rel.symbol.name]  #TODO: Find constant for
          #SHN undef
          entry.type = rel.type
          entry.addend = rel.addend
          retval.push entry
        }
      }
    end
    def reladyn(dynstrtab)
      @file.relocations.each{ |r|
        r.symbol.is_dynamic  = true
      }
      dynsym(dynstrtab)
      relaentsize = @factory.rela.new.num_bytes
      rel_by_section = @file.relocations.select(&:is_dynamic).group_by(&:section)
      if(rel_by_section[@file.dynamic.pltgot]) 
        relabuf=rela_buffer(rel_by_section[@file.dynamic.pltgot])
        relaplt = OutputSection.new(".rela.plt", SHT::SHT_RELA, SHF::SHF_ALLOC, nil, relabuf.num_bytes,".dynsym",@file.dynamic.pltgot.name,32, relaentsize, relabuf.to_binary_s)
        @layout.add relaplt
        @dynamic << @factory.dyn.new(tag: DT::DT_PLTRELSZ, val: relabuf.num_bytes)
        @dynamic << @factory.dyn.new(tag: DT::DT_PLTREL, val: DT::DT_RELA)
        @dynamic << @factory.dyn.new(tag: DT::DT_JMPREL, val: relaplt.vaddr)
        rel_by_section.delete @file.dynamic.pltgot
      end
      #All other relocations go into .rela.dyn
      relabuf = rela_buffer(rel_by_section.values.flatten)
      reladyn = OutputSection.new(".rela.dyn", SHT::SHT_RELA, SHF::SHF_ALLOC,nil, relabuf.num_bytes,".dynsym",0,32, relaentsize, relabuf.to_binary_s)
      @layout.add reladyn
      @dynamic << @factory.dyn.new(tag: DT::DT_RELA, val: reladyn.vaddr)
      @dynamic << @factory.dyn.new(tag: DT::DT_RELASZ, val: reladyn.siz)     
      @dynamic << @factory.dyn.new(tag: DT::DT_RELAENT, val: relaentsize)
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
      note
      dynamic
      interp
      write_headers
    end

  end
end
end
