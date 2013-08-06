require 'bundler'
require 'andand'
require_relative 'elf_enums'
require_relative 'elf_structs'

require 'pp'
require 'set'
require 'segment_tree'
require 'rbtree'
#TODO: freeze some things after parse? 
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
    attr_accessor :bind_now, :symbolic, :needed, :init, :fini, :pltgot, :debug_val, :soname
    attr_accessor :extra_dynamic, :soname, :init_array, :fini_array
  end
  class ProgBits
    attr_accessor :data,:name, :addr, :flags, :align, :entsize
    attr_accessor :phdr, :phdr_flags # Makes a PHDR for this section
    attr_accessor :sect_type
    def initialize(name,shdr,data)
      @data = StringIO.new(data)
      @name = name
      if shdr.nil?
        @addr = nil
        @flags = 0
        @align = 0
        @entsize = 0
        @sect_type = 0
      else
        @addr = shdr.vaddr
        @flags = shdr.flags
        expect_value "PROGBITS link", shdr.link, 0
        expect_value "PROGBITS info", shdr.info, 0
        @align = shdr.addralign
        @entsize = shdr.entsize # Expect 0 for now?
        @sect_type = shdr.type.to_i
        #      expect_value "PROGBITS entsize", @entsize,0
        expect_value "Progbits must be full present", @data.size, shdr.siz
      end
      
    end
    
    def size
      @data.size
    end
  end
  class NoBits
    attr_accessor :name, :addr, :flags, :align, :index, :phdr, :phdr_flags
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
      StringIO.new().tap{|x|
        BinData::Array.new(type: :uint8le,initial_length: @size).write x
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
  class GnuVersion 
    attr_accessor :file,:version,:flags, :needed
    attr_accessor  :parents
    def initialize(file,version,flags,needed)
      @file, @version,@flags,@needed = file,version,flags,needed
      @parents = []
    end
  end

  class Symbol #All values here are section offsets
    attr_accessor :name, :section, :file ,:type, :sectoffset, :bind, :size,:is_dynamic
    attr_accessor :gnu_version, :hidden
    def initialize(name,section,file,type,sectoffset, bind,size)
      @name,@section,@file, @type, @sectoffset, @bind, @size = name.to_s,section,file,type,sectoffset, bind,size
      @is_dynamic = false
      @gnu_version =  :global
    end
  end
  class SymbolTable
    #TODO: hook symbol.version=
    include Enumerable
    def initialize
      @all_symbols = []
      @named_symbols = {}
      @versioned_symbols = {}
    end
    def each(&block)
      @all_symbols.each(&block)
    end
    def <<(symbol)
      @all_symbols << symbol
      unless symbol.hidden
        name = symbol.name
        version = symbol.gnu_version
        @versioned_symbols[version] ||= {}
        if(@versioned_symbols[version].include? name)
          #TODO: emit some form of warning!
          #raise RuntimeError.new "Symbol #{name} version #{version} not unique"
        else
          @versioned_symbols[version][name] = symbol
        end
        @named_symbols[name] ||= []
        @named_symbols[name] << symbol
      end
    end
    
    def lookup(name,version=nil)
      if(version.nil?)
        @named_symbols[name].andand {|x|
          if(x.length > 1)
            raise RuntimeError.new("Multiple definitions of symbol #{name}")
          end
          x.first
        }
      else
        @versioned_symbols[version].andand{|x| x[name]}
      end
    end
    def lookup_all(name)
      @named_symbols[name]
    end
    def include?(name,version=nil)
      if version.nil?
        @named_symbols.include? name
      else
        @versioned_symbols[version].include? name
      end
    end
    def [](name)
      lookup(name)
    end
  end
  class Relocation
    attr_accessor :section, :offset, :type, :symbol, :addend
    attr_accessor :is_dynamic #false for static, true otherwise.
    attr_accessor :is_lazy # Is in PLT 
    def initialize
      @is_dynamic = false
      @is_lazy = false
    end
  end
  class TLS
    attr_accessor :tbss_size,:tdata
  end
  class ElfFile
    attr_accessor :filetype, :machine, :entry, :flags, :version
    attr_accessor :progbits, :nobits, :dynamic,  :relocations
    attr_accessor :gnu_tls
    attr_accessor :symbols, :relocated_symbols
    attr_accessor :notes, :bits, :endian, :interp, :extra_phdrs
  end
end

