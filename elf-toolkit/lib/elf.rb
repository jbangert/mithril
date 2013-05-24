require 'bundler'
require 'andand'
require_relative 'elf_enums'
require_relative 'elf_structs'

require 'pp'
require 'set'
require 'segment_tree'
require 'rbtree'
def enum(name, type, enum_class )         # To be done
  klass = Class.new BinData::Primitive  do
    type value
    def get
      value
    end
    def set(v)
      raise RuntimeError.new "#{v} is not an acceptable value (#{enum_class.acceptable_values})"  unless
        enum_class.acceptable_values.include? v
      value = v
    end
  end
end
def expect_value(desc,is,should)
  raise RuntimeError.new "Invalid #{desc}, expected #{should} instead of #{is}" if is != should
end

module Elf 
  DT = ElfFlags::DynamicType
  SHT = ElfFlags::SectionType
  SHF = ElfFlags::SectionFlags
  SHN = ElfFlags::SpecialSection
  STB = ElfFlags::SymbolBinding
  ET = ElfFlags::Type
  PT = ElfFlags::PhdrType
  PF = ElfFlags::PhdrFlags
  NOTE_ALIGN = 4
  NOTE_FLAGS = SHF::SHF_ALLOC
  NOTE_ENTSIZE =0
  class StringTable
    def initialize(data)
      expect_value "First byte of string table", data.bytes.first, 0
      @data = StringIO.new(data)
    end
    def [](offset)
      @data.seek offset
      obj = BinData::Stringz.new
      obj.read(@data)
      obj.snapshot
    end
  end
  class NilStringTable
    def [](offset)
      return ""
    end
  end 
  class Dynamic
    attr_accessor :bind_now, :symbolic, :needed, :init, :fini, :pltgot, :debug_val, :extra_dynamic
  end
  class ProgBits
    attr_accessor :data,:name, :addr, :flags, :align, :entsize
    def initialize(name,shdr,data)
      @data = StringIO.new(data)
      @name = name
      @addr = shdr.vaddr
      @flags = shdr.flags
      expect_value "PROGBITS link", shdr.link, 0
      expect_value "PROGBITS info", shdr.info, 0
      @align = shdr.addralign
      @entsize = shdr.entsize # Expect 0 for now?
      #      expect_value "PROGBITS entsize", @entsize,0
      expect_value "Progbits must be full present", @data.size, shdr.siz
    end
    def sect_type
      SHT::SHT_PROGBITS
    end
    def size
      @data.size
    end
  end
  class NoBits
    attr_accessor :name, :addr, :flags, :align, :index
    def initialize(name,shdr)
      @name = name
      @addr = shdr.vaddr
      @flags = shdr.flags
      expect_value "NOBITS link", shdr.link, 0
      expect_value "NOBITS info", shdr.info, 0
      @align = shdr.addralign
      @entsize = shdr.entsize # Expect 0 for now?
      @size = shdr.siz
      #      expect_value "PROGBITS entsize", @entsize,0
    end
    def data
      StringIO.new("")
    end
    def sect_type
      SHT::SHT_NOBITS
    end
    def entsize
      1
    end
    def size
      @size
    end
  end
  class Symbol #All values here are section offsets
    attr_accessor :name, :section,:type, :sectoffset, :bind, :size,:is_dynamic
    def initialize(name,section,type,sectoffset, bind,size)
      @name,@section, @type, @sectoffset, @bind, @size = name.to_s,section,type,sectoffset, bind,size
      @is_dynamic = false
    end
  end
  class Relocation
    attr_accessor :section, :offset, :type, :symbol, :addend
    attr_accessor :is_dynamic #false for static, true otherwise.
    def initialize
      @is_dynamic = false
    end
  end
  class ElfFile
    attr_accessor :filetype, :machine, :entry, :flags, :version
    attr_accessor :progbits, :nobits, :dynamic, :symbols, :relocations
    attr_accessor :notes, :bits, :endian, :interp, :extra_phdrs
  end
  class Parser
    attr_reader :file
    def initialize(string)
      @data = StringIO.new(string)
      @file = ElfFile.new
      ident = ElfStructs::ElfIdentification.read(@data)
      print ident.snapshot.inspect
      raise RuntimeError.new "Invalid ELF version #{ident.id_version}" if ident.id_version != ElfFlags::Version::EV_CURRENT
      case ident.id_class
      when ElfFlags::IdentClass::ELFCLASS64
        @file.bits = 64
      when ElfFlags::IdentClass::ELFCLASS32
        @file.bits = 32
      else
        RuntimeError.new "Invalid ELF class #{ident.id_class}"
      end
      case ident.id_data
      when ElfFlags::IdentData::ELFDATA2LSB
        @file.endian = :little
      when ElfFlags::IdentData::ELFDATA2MSB
        @file.endian = :big
      else
        RuntimeError.new  "Invalid ELF endianness #{ident.id_data}"
      end
      @factory = ElfStructFactory.instance(@file.endian,@file.bits)
      parse_with_factory()
    end
    def self.from_file(filename)
      contents = IO.read(filename)
      Parser.new(contents).file
    end
    private
    def unique_section(sects, type)
      if sects.include? type
        expect_value "Number of #{type} sections", sects[type].size, 1
        return sects[type].first
      else
        return nil
      end
    end
    def safe_strtab(index)
      if(index ==0)
        NilStringTable.new()
      else
        hdr = @shdrs[index]
        expect_value "STRTAB type", hdr.type, ElfFlags::SectionType::SHT_STRTAB
        @data.seek hdr.off
        @unparsed_sections.delete index
        StringTable.new(@data.read(hdr.siz))
      end
    end
    def parse_symtable(sect,strtab)
      return [] if sect.nil?
      expect_value "Size of symbol table entry", @factory.sym.new.num_bytes, sect.entsize
      @data.seek sect.off
      @unparsed_sections.delete sect.index
      BinData::Array.new( :type=> @factory.sym, :initial_length => sect.siz / sect.entsize).read(@data).map do |sym|
        #TODO: find appropriate section
        if sym.shndx.to_i == 0  || sym.shndx.to_i == SHN::SHN_ABS
          #TODO: Find section by vaddr
          section =  nil
          value = sym.val.to_i
        else
          section = @bits_by_index[sym.shndx.to_i] 
          if([ET::ET_EXEC, ET::ET_DYN].include? @file.filetype)
            value = sym.val.to_i - section.addr #TODO: Only if absolute.
          else 
            value = sym.val.to_i
          end
          expect_value "Section index #{sym.shndx.to_i} in symbol should be in progbits", false, section.nil?
        end
        
        Symbol.new(strtab[sym.name],section, sym.type.to_i, value, sym.binding.to_i, sym.siz.to_i)
      end
    end
    def parse_nobits(shdr)
      @unparsed_sections.delete shdr.index
      NoBits.new(@shstrtab[shdr.name],shdr)
    end
    def parse_progbits(shdr)
      @data.seek shdr.off
      @unparsed_sections.delete shdr.index
      expect_value "PROGBITS link",shdr.link,0
      ProgBits.new(@shstrtab[shdr.name], shdr.snapshot,  @data.read(shdr.siz))
    end
    DYNAMIC_FLAGS =            {
      DT::DT_TEXTREL=>:@textrel,
      DT::DT_BIND_NOW => :@bind_now,
      DT::DT_SYMBOLIC => :@symbolic
    }
    def parse_rel_common(relocations,sect_idx,symtab_idx, uses_addresses)
      case @shdrs[symtab_idx].type.to_i
      when SHT::SHT_DYNSYM
        symtab= @dynsym
      when SHT::SHT_SYMTAB
        symtab= @symtab
      else
        raise ArgumentError.new "Invalid link field #{symtab_idx} in relocation section"
      end
      if sect_idx == 0 and uses_addresses
        applies_to = nil
      else
        applies_to = @bits_by_index[sect_idx]
        raise ArgumentError.new "Section index #{sect_idx} not referring to PROGBITS for relocation table" if applies_to.nil?
      end
      relocations.map {|rel_entry|
        Relocation.new.tap { |rel|
          if  uses_addresses
            rel.section = @relocatable_sections.find(rel_entry.off.to_i).andand(&:value)
            print "Warning: Invalid relocation address 0x#{rel_entry.off.snapshot.to_s(16)}\n" unless rel.section
            rel.offset = rel_entry.off - rel.section.addr
          else
            rel.section = applies_to
            rel.offset = rel_entry.off
          end
          rel.type = @factory.rel_info_type(rel_entry.info)
          rel.symbol = symtab[ @factory.rel_info_sym(rel_entry.info)]
          rel.addend = rel_entry.addend
        }
      }
    end

    def parse_rela(shdr,has_addrs)
      @unparsed_sections.delete shdr.index
      @data.seek shdr.off
      expect_value "RELA entsize", shdr.entsize, @factory.rela.new.num_bytes
      rela = BinData::Array.new(:type => @factory.rela, :initial_length => shdr.siz/shdr.entsize).read(@data)
      parse_rel_common(rela,shdr.info, shdr.link,has_addrs)
    end
    def parse_rel(shdr,has_addrs)
      @unparsed_sections.delete shdr.index
      @data.seek shdr.off
      expect_value "REL entsize", shdr.entsize, @factory.rel.new.num_bytes
      rela = BinData::Array.new(:type => @factory.rel, :initial_length => shdr.siz/shdr.entsize).read(@data)
      parse_rel_common(rela,shdr.info, shdr.link,has_addrs)
    end
    def parse_dynamic(shdr)
      retval = Dynamic.new

      @data.seek shdr.off
      #TODO: find unused dynamic entries
      expect_value "Size of dynamic entry", @factory.dyn.new.num_bytes, shdr.entsize
      dynamic = BinData::Array.new(:type=> @factory.dyn, :initial_length => shdr.siz/ shdr.entsize).read(@data)
      @unparsed_sections.delete shdr.index
      by_type = dynamic.group_by {|x| x.tag.to_i}
      expect_unique = lambda do |sym,optional| # Validates that either one
        # or zero entries of this type exist, returning the one entry
        # if it exists
        if(by_type.include? sym)
          expect_value  "Dynamic entry #{sym} count", by_type[sym].size,1
          by_type[sym].first
        else
          if(optional)
            nil
          else
            raise ArgumentError.new "Missing mandatory dynamic entry #{sym}"
          end
        end
      end


      expect_value "DT_NULL", dynamic.last, @factory.dyn.new()

      by_type.delete DT::DT_NULL

      expect_unique.call DT::DT_STRTAB,false
      expect_unique.call DT::DT_STRSZ,false  #TODO: check that this a strtab and get a strtab
      strtab_hdr= @sect_types[SHT::SHT_STRTAB].group_by(&:vaddr)[by_type[DT::DT_STRTAB].first.val].andand(&:first)

      expect_value "Some STRTAB section should be mapped at DT_STRTAB", strtab_hdr.nil?,false
      by_type.delete DT::DT_STRTAB
      expect_value "STRSZ", by_type[DT::DT_STRSZ].first.val, strtab_hdr.siz
      by_type.delete DT::DT_STRSZ
      @dynstr = safe_strtab(strtab_hdr.index)

      expect_unique.call DT::DT_SYMENT, false
      expect_value "Dynamic SYMENT",by_type[DT::DT_SYMENT].first.val,  @factory.sym.new.num_bytes
      by_type.delete DT::DT_SYMENT
      expect_unique.call DT::DT_SYMTAB, false
      expect_value "Dynamic symbol table needs to be mapped", by_type[DT::DT_SYMTAB].first.val,@sect_types[SHT::SHT_DYNSYM].first.vaddr
      by_type.delete DT::DT_SYMTAB
      expect_unique.call DT::DT_HASH, true# We totally ignore the hash
      by_type.delete DT::DT_HASH
      retval.needed = []
      by_type[DT::DT_NEEDED].each do |needed|
        retval.needed << @dynstr[needed.val]
      end
      by_type.delete DT::DT_NEEDED

      DYNAMIC_FLAGS.each do |tag, var|
        val  = false
        expect_unique.call(tag,true) { |x| val = true}
        instance_variable_set(var,val)
        by_type.delete tag
      end


      progbits_by_addr = @progbits.group_by(&:addr) #TODO: check
      #that vaddrs don't overlap

      expect_unique.call(DT::DT_INIT,true).andand { |init|
        expect_value "DT_INIT should point to a valid progbits section",
        progbits_by_addr.include?(init.val), true

        retval.init = progbits_by_addr[init.val].first
      }
      by_type.delete DT::DT_INIT
      expect_unique.call(DT::DT_FINI,true).andand { |init|
        expect_value "DT_FINI should point to a valid progbits section",
        progbits_by_addr.include?(init.val), true

        retval.fini = progbits_by_addr[init.val].first
      }
      by_type.delete DT::DT_FINI
      expect_unique.call(DT::DT_PLTGOT,true).andand { |init|
        expect_value "DT_PLTGOT should point to a valid progbits section",
        progbits_by_addr.include?(init.val), true

        retval.pltgot = progbits_by_addr[init.val].first
      }#TODO: check processor supplements
      by_type.delete DT::DT_PLTGOT

      #TODO: write 'expect_group'
      expect_unique.call(DT::DT_RELA,true).andand{ |rela|
        x= @sect_types[SHT::SHT_RELA].group_by{|x| x.vaddr.to_i}
        expect_value "DT_RELA should point to a valid relocation section", x.include?(rela.val), true
        #assert that no overlap?
        reladyn_hdr = x[rela.val].first #TODO: Use parsed relocations!
        expect_unique.call(DT::DT_RELAENT,false).andand {|relaent|
          expect_value "DT_RELAENT size", relaent.val, @factory.rela.new.num_bytes
        }
        expect_unique.call(DT::DT_RELASZ,false).andand {|relasz|
          expect_value "DT_RELASZ", relasz.val, reladyn_hdr.siz
        }
        @relocation_sections[reladyn_hdr.index].each{|rel| rel.is_dynamic = true}
      }
      #TODO: maybe use eval to delete duplication?
      expect_unique.call(DT::DT_REL,true).andand{ |rela|
        x= @sect_types[SHT::SHT_REL].group_by{|x| x.vaddr.to_i}
        expect_value "DT_REL should point to a valid relocation section", x.include?(rela.val), true
        reladyn_hdr = x[rela.val] #TODO: Use parsed relocations!
        expect_unique.call(DT::DT_RELENT,false).andand {|relaent|
          expect_value "DT_RELENT size", relaent.val, @factory.rela.new.num_bytes
        }
        expect_unique.call(DT::DT_RELSZ,false).andand {|relasz|
          expect_value "DT_RELSZ", relasz.val, reladyn_hdr.siz
        }
        @relocation_sections[reladyn_hdr.index].each{|rel| rel.is_dynamic = true}
      }
      [DT::DT_RELA, DT::DT_RELAENT, DT::DT_RELASZ, DT::DT_REL, DT::DT_RELENT, DT::DT_RELSZ].each {|x|  by_type.delete x}
      #Parse RELA.plt or REL.plt
      expect_unique.call(DT::DT_JMPREL,true).andand{ |rela| #TODO:Make
        #this better too!!!
        expect_unique.call(DT::DT_PLTREL,false).andand {|pltrel|
          if pltrel.val == DT::DT_RELA
            type = SHT::SHT_RELA
          elsif pltrel.val == DT::DT_REL
            type = SHT::SHT_REL
          else
            raise ArgumentError.new "Invalid DT_PLTREL"
          end
          x= @sect_types[type].group_by{|x| x.vaddr.to_i}
          expect_value "DT_PLREL should point to a valid relocation section", x.include?(rela.val), true
          reladyn_hdr = x[rela.val].first
          #TODO: Use parsed      #relocations!
          expect_unique.call(DT::DT_PLTRELSZ,false).andand {|relasz|
            expect_value "DT_PLTRELSZ", relasz.val, reladyn_hdr.siz
          }
          @relocation_sections[reladyn_hdr.index].each{|rel| rel.is_dynamic = true}
          by_type.delete DT::DT_PLTRELSZ
        }
        by_type.delete DT::DT_PLTREL
      }
      by_type.delete DT::DT_JMPREL

      retval.debug_val = []
      by_type[DT::DT_DEBUG].each {|x| retval.debug_val << x}
      by_type.delete DT::DT_DEBUG

      #TODO: gnu extensions
      retval.extra_dynamic = by_type.values.flatten
      unless by_type.empty?
        print "Warning, unparsed dynamic entries \n"
        pp by_type
      end
      retval
    end
    def parse_note(note)
      note_name = @shstrtab[note.name] || ".note.unk.#{note.off}"
      @data.seek note.off
      expect_value "Note alignment", note.addralign, NOTE_ALIGN
      expect_value "Note flags", note.flags, NOTE_FLAGS
      expect_value "Note entsize", note.entsize, NOTE_ENTSIZE
      @unparsed_sections.delete @data
      [note_name, @factory.note.read(@data).tap {|n|
         expect_value "Note size",n.num_bytes, note.siz 
      } ]
    end

    def parse_phdrs()
      #TODO: validate flags
      by_type = @phdrs.group_by{|x| x.type.to_i}
      by_type.delete PT::PT_NULL
      process_unique = lambda do |sym| # Validates that either one
        # or zero entries of this type exist, returning the one entry
        # if it exists
        if(by_type.include? sym)
          expect_value  "PHDR #{sym} count", by_type[sym].size,1
          by_type[sym].first.tap { by_type.delete sym }
        else
          nil
        end
      end

      process_unique.call(PT::PT_PHDR).andand do |pt_phdr|
        expect_value "PHD offset",pt_phdr.off, @hdr.phoff
        expect_value "PHDR size",pt_phdr.filesz, @hdr.phnum * @hdr.phentsize
      end

      by_type.delete PT::PT_LOAD # TODO:: validate range and that
      # section vaddr is correct!
=begin all notes go into one or multiple program headers.
      by_type[PT::PT_NOTE].each {|note|
        expect_value "SHT_NOTE at this address",
        @sect_types[SHT::SHT_NOTE].find{|n| note.vaddr.to_i == n.vaddr.to_i}.andand {|n|
          [n.off.to_i,n.siz.to_i]
        }, [note.off.to_i,note.filesz.to_i]   }
=end
      by_type.delete PT::PT_NOTE

      process_unique.call(PT::PT_INTERP).andand do |pt_interp| #Technically
        #not needed according to spec, INTERP doesn't need to have its
        #own section. Instead just check what is at that vaddr
        interp_section = @progbits.select {|x| x.addr  == pt_interp.vaddr.to_i}.first
        expect_value ".interp section", interp_section.nil?, false
        @file.interp = interp_section.data.read
        @progbits.delete interp_section
      end
      process_unique.call(PT::PT_DYNAMIC).andand do |pt_dynamic|
        dynamic_section = @sect_types[SHT::SHT_DYNAMIC].first
        expect_value "PT_dynamic address", pt_dynamic.vaddr, dynamic_section.vaddr
        expect_value "PT_dynamic offset" , pt_dynamic.off, dynamic_section.off
        expect_value "PT_dynamic size", pt_dynamic.filesz, dynamic_section.siz
      end
      @file.extra_phdrs  = by_type.values.flatten
      unless(@file.extra_phdrs.empty?)
        print "Unparsed PHDR\n"
        pp @file.extra_phdrs
      end
    end
    def parse_with_factory()
      @data.rewind
      @hdr = @factory.hdr.read(@data)
      @file.filetype = @hdr.type
      @file.machine = @hdr.machine
      @file.version = @hdr.version # Shouldn't this always be the current one
      @file.flags = @hdr.flags
      @file.entry = @hdr.entry
      expect_value "ELF version",@file.version, ElfFlags::Version::EV_CURRENT
      #pp hdr.snapshot

      expect_value "PHT size", @factory.phdr.new.num_bytes, @hdr.phentsize
      @data.seek @hdr.phoff
      @phdrs = BinData::Array.new(:type => @factory.phdr, :initial_length => @hdr.phnum)
      @phdrs.read(@data)


      @data.seek @hdr.shoff
      @shdrs = BinData::Array.new(:type => @factory.shdr, :initial_length => @hdr.shnum)
      @shdrs.read(@data)
      @unparsed_sections = Set.new []
      expect_value "SHT size", @shdrs[0].num_bytes, @hdr.shentsize
      @shstrtab = safe_strtab(@hdr.shstrndx)

      @shdrs.to_enum.with_index.each do |elem, i|
        elem.index = i
        @unparsed_sections.add i 
        unless elem.flags & SHF::SHF_ALLOC
          expect_value "Unallocated section address", elem.vaddr, 0
        end
      end


      #Keep a hash of sections by type
      @sect_types = @shdrs.group_by {|x| x.type.to_i}
      #TODO: keep track which    #sections we have already parsed to find unparsed sections
      @bits_by_index = Hash.new.tap{|h| @sect_types[SHT::SHT_PROGBITS].each { |s| h[s.index] = parse_progbits(s)} }
      @progbits = @bits_by_index.values
      @file.progbits = @progbits

      @nobits = @sect_types[SHT::SHT_NOBITS].map{ |x| parse_nobits(x).tap{|y| y.index = x.index}}
      @nobits.each{|nobit| @bits_by_index[nobit.index] = nobit}
      @file.nobits = @nobits

      @relocatable_sections = SegmentTree.new(Hash.new.tap{|h|
                                                (@progbits + @nobits).each{ |pb|
                                                  h[(pb.addr)..(pb.addr + pb.size)]=pb
                                                }
                                              })

      parse_phdrs()
      @symtab = unique_section(@sect_types, ElfFlags::SectionType::SHT_SYMTAB).andand {|symtab| parse_symtable symtab, safe_strtab(symtab.link); @unparsed_sections.delete  }
      @dynsym = unique_section(@sect_types, ElfFlags::SectionType::SHT_DYNSYM).andand {|symtab| parse_symtable symtab, safe_strtab(symtab.link) }
      
      @file.symbols = Hash.new.tap{|h| (@symtab || []).each{|sym| h[sym.name] = sym}}
      (@dynsym|| []).each {|sym|
        sym.is_dynamic = true
        if @file.symbols.include? sym.name
          staticsym =  @file.symbols[sym.name]
          expect_value "Dynamic #{sym.name} value", sym.sectoffset, staticsym.sectoffset
          expect_value "Dynamic #{sym.name} value", sym.section, staticsym.section
          expect_value "Dynamic #{sym.name} size", sym.size,  staticsym.size
          staticsym.is_dynamic = true
        else
          @file.symbols[sym.name] = sym
        end
      }    
      rels_addrs = [ET::ET_EXEC, ET::ET_DYN].include? @hdr.type
      rel =  (@sect_types[SHT::SHT_RELA] || []).map {|rela| [rela.index, parse_rela(rela,rels_addrs)] }+ (@sect_types[SHT::SHT_REL] || []).map{|rel| [rela.index,parse_rel(rela,rels_addrs)]}

      @relocation_sections = Hash[*rel.flatten(1)]
   

      @file.dynamic = unique_section(@sect_types, ElfFlags::SectionType::SHT_DYNAMIC).andand{|dynamic| parse_dynamic dynamic}
      
      

      #TODO: gnu extensions, in particular gnu_hash

      @file.notes = Hash[(@sect_types[SHT::SHT_NOTE] || []).map{|note| parse_note note}]
      #TODO: expect non-nil dynamic for some types
      @file.relocations = @relocation_sections.values.flatten
      #TODO: Validate flags
      #TODO: Validate header?
      
    end
  end

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
    # TODO: Use params array
    def initialize(name,type,flags,vaddr,siz,link,info,align,entsize,data) #link and info are strings, offset is done by output stage
      @name,@type,@flags, @vaddr, @siz, @link, @info, @align, @entsize, @data= name,type,flags,vaddr,siz,link,info,align,entsize, data
      @off = nil
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

    end
    def add(*sections)       #Ordering as follows: Fixed
      #(non-nil vaddrs) go where they have to go
      # Flexible sections are added to lowest hole after section of
      # the same type
      return if sections.empty?
      flags = sections.first.flags
      @layout_by_flags[flags] ||= RBTree.new()
      if sections.length > 1 || sections.first.vaddr.nil?
        sections.each { |i| 
          expect_value "All adjacent sections have the same flags", i.flags,flags
          expect_value "All sections must float", i.vaddr, nil
        }
        allocate_sections(sections)
      end
      
      sections.each {|i| 
        expect_value "Sections shouldn't overlap",  range_available?(@layout,i.vaddr,i.end), true
        @layout[i.vaddr] = i 
        @layout_by_flags[i.flags][i.vaddr] = i
      }
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

    LoadMap = Struct.new(:off,:end,:vaddr,:flags,:align)
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
      load.each {|l|
        phdrs.push @factory.phdr.new.tap {|x|
          x.align = l.align
          x.vaddr = l.vaddr
          x.paddr = x.vaddr
          x.type = PT::PT_LOAD
          x.filesz = l.end - l.off#TODO: handle nobits
          x.memsz = x.filesz
          x.off = l.off
          x.flags = PF::PF_R

          x.flags |= PF::PF_W if(l.flags & SHF::SHF_WRITE != 0)
          x.flags |= PF::PF_X if(l.flags & SHF::SHF_EXECINSTR != 0)

        }
      }
#      pp load
      filehdr.phoff = buf.tell
      filehdr.phentsize = @factory.phdr.new.num_bytes
      filehdr.phnum = phdrs.size
      phdrs.write buf

    end
    RESERVED_PHDRS = 64 
    def write_sections(buf,filehdr)
      sections = @layout.to_a.sort_by(&:first).map(&:last)
      #Get more clever about mapping files
      # We put actual program headers right at the beginning.
      phdr_off = buf.tell
      buf.seek phdr_off + RESERVED_PHDRS * @factory.phdr.new.num_bytes
      
      shdrs = BinData::Array.new(:type=>@factory.shdr).push *sections.map{ |s|
        expect_value "aligned to vaddr", 0,s.vaddr % s.align
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
      load = mapped.group_by(&:flags).map{|flags,sections|
        sections.group_by{|x| x.vaddr - x.off}.map do |align,sections|
          LoadMap.new(sections.first.off,sections.last.off + sections.last.siz, sections.first.vaddr,flags,sections.map(&:align).max) #TODO: LCM?
        end
      }.flatten     
      
      shdrs << shstrtab(buf)
      filehdr.shstrndx = shdrs.size - 1
      filehdr.shoff = buf.tell 
      filehdr.shentsize = shdrs[0].num_bytes
      filehdr.shnum = shdrs.size
      shdrs.write buf      
      
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
        ( (tree.lower_bound(to).andand.last.andand.vaddr || +1.0/0.0) > to)
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
    def make_symtab(name,symbols,strtab)
      
    end
    def dynsym(dynstrtab)
      symtab = BinData::Array.new(:type => @factory.sym)
      syms = @file.symbols.values.select(&:is_dynamic)

      syms.each do |sym|
        s = @factory.sym.new
        s.name = dynstrtab.add_string(sym.name)
        s.type = sym.type
        s.binding = sym.bind
        s.shndx = 0
        unless sym.section.nil?
          expect_value "valid symbol offset",  sym.sectoffset < sym.section.size,true
        end
        s.val = (sym.section.andand.addr || 0) + sym.sectoffset
        s.siz = sym.size
        symtab.push s
      end
      last_local_idx = syms.to_enum.with_index.select{|v,i| v.bind == STB::STB_LOCAL}.andand.last.andand.last || -1
      dynsym = OutputSection.new(".dynsym",SHT::SHT_DYNSYM, SHF::SHF_ALLOC, nil,symtab.num_bytes,".dynstr", last_local_idx+1,1,@factory.sym.new.num_bytes, symtab.to_binary_s)
      @layout.add dynsym
      @dynamic << @factory.dyn.new(tag: DT::DT_SYMTAB,val: dynsym.vaddr)
      @dynamic << @factory.dyn.new(tag: DT::DT_SYMENT,val: @factory.sym.new.num_bytes)
      
    end # Produce a hash and a GNU_HASH as well
    def dynamic
      @dynamic = BinData::Array.new(:type => @factory.dyn)
      dynstrtab = StringTable.new()
      reladyn(dynstrtab)
      
      dynstr = OutputSection.new(".dynstr", SHT::SHT_STRTAB, SHF::SHF_ALLOC,nil, dynstrtab.buf.size, 0,0,1,0,dynstrtab.buf)
      @layout.add dynstr
      @dynamic << @factory.dyn.new(tag: DT::DT_STRTAB, val: dynstr.vaddr)
      @dynamic << @factory.dyn.new(tag: DT::DT_STRSZ, val: dynstr.siz)
      @dynamic <<  @factory.dyn.new(tag: DT::DT_NULL, val: 0)
      @layout.add_with_phdr [OutputSection.new(".dynamic", SHT::SHT_DYNAMIC, SHF::SHF_ALLOC, nil, @dynamic.num_bytes,".dynstr",0,8,@factory.dyn.new.num_bytes,@dynamic.to_binary_s)], PT::PT_DYNAMIC, PF::PF_R
      #dynstr -> STRTAB STRSZ
      #dynsym -> DT_SYMENT, D
    end # Write note, etc for the above

    def reladyn(dynstrtab)
      @file.relocations.each{ |r|
        r.symbol.is_dynamic  = true
      }
      dynsym(dynstrtab)
      
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

$parse = Elf::Parser.from_file "/bin/ls"
Elf::Writer::Writer.to_file("/tmp/tst",$parse)
`chmod +x /tmp/tst`
#pp parse # .instance_variables
##TODO: Do enums as custom records.

