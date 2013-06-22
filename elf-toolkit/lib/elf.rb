require 'bundler'
require 'andand'
require_relative 'elf_enums'
require_relative 'elf_structs'

require 'pp'
require 'set'
require 'segment_tree'
require 'rbtree'
module Elf 
  DT = ElfFlags::DynamicType
  SHT = ElfFlags::SectionType
  SHF = ElfFlags::SectionFlags
  SHN = ElfFlags::SpecialSection
  STB = ElfFlags::SymbolBinding
  STT= ElfFlags::SymbolType
  ET = ElfFlags::Type
  PT = ElfFlags::PhdrType
  PF = ElfFlags::PhdrFlags
  NOTE_ALIGN = 4
  NOTE_FLAGS = SHF::SHF_ALLOC
  NOTE_ENTSIZE =0

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
      StringIO.new("").tap{|x|
        x.seek size
        x.write '\0' # CRUMMY, but works
      }
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
  GnuVersion = Struct.new(:file,:version,:flags)
  class Symbol #All values here are section offsets
    attr_accessor :name, :section,:type, :sectoffset, :bind, :size,:is_dynamic
    attr_accessor :gnu_version, :gnu_file
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
end
