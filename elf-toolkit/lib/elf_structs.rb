
require 'bindata'
require_relative 'elf_enums'
module ElfStructs
  class ElfIdentification   < BinData::Record
    endian :little
    string :id_magic,  :length=>4 ,   :initial_value => "\x7FELF" #TODO: validate?
    uint8  :id_class
    uint8  :id_data
    uint8  :id_version
    skip   :length => 9
  end

  def alias_recordtype(from,to)
    self.class.class_eval do
      define_method from do  |*args|
        send(to,*args)
      end
    end
  end
  def hdr
     elf_identification :ident
     #end of identification
     half :type #File type.
     half :machine #Machine architecture.
     word :version #ELF format version.
     addr :entry #Entry point.
     off :phoff #Program header file offset.
     off :shoff #Section header file offset.
     word :flags #Architecture-specific flags.
     half :ehsize #Size of ELF header in bytes.
     half :phentsize #Size of program header entry.
     half :phnum #Number of program header entries.
     half :shentsize #Size of section header entry.
     half :shnum #Number of section header entries.
     half :shstrndx #Section name strings section.
  end

  def note
    uint32	:namesz, :value => lambda{name.num_bytes}	#Length of name.
    uint32	:descsz, :value => lambda{desc.num_bytes}	# Length of descriptor.
    uint32	:type		# Type of this note.
    string      :name, :read_length => lambda{ (namesz.to_i  * 4 + 3)/4 } # Round up
    string      :desc, :read_length => lambda{ (descsz.to_i  * 4 + 3)/4 }
    attr_accessor :section_name
  end

  def shdr
    word :name #Section name (index into section header string table
    word :type #Section type.
    xword :flags #Section flags.
    addr :vaddr #Address in memory image.
    off :off #Offset in file.
    xword :siz#Size in bytes. Patch: Had to change to siz
    word :link #Index of a related section.
    word :info #Depends on section type.
    xword :addralign #Alignment in bytes.
    xword :entsize #Size of each entry in section.


    attr_accessor :index # So we retain the index after parsing
  end
  def phdr32  # FAIL  different layout with 32 and 64
    word :type #Entry type.
    off :off #File offset of contents.
    addr :vaddr #Virtual address in memory image.
    addr :paddr #Physical address (not used).
    xword :filesz #Size of contents in file.
    xword :memsz #Size of contents in memory.
    word :flags #Access permission flags.
    xword :align #Alignment in memory and file.
  end
  def phdr64 
    word :type
    word :flags 
    off  :off
    addr :vaddr
    addr :paddr
    xword :filesz
    xword :memsz
    xword :align
  end
# Dynamic structure.  The ".dynamic" section contains an array of them.
  def dyn
    sxword :tag #Entry type.
    addr :val #Address value or raw value
  end
# * Relocation entries
#  Relocations that don't need an addend field. */
  def rel_common
    case @bits
    when 32
      define_method :sym do 
         info.to_i >> 8
      end
      define_method :type do
        info.to_i & 0xff
      end
      define_method :sym= do |val|
        self.info = type | (val << 8)
      end
      define_method :type= do |val|
        self.info = (val &0xff) | (sym << 8)
      end
    when 64
      define_method :sym do 
         info.to_i >> 32
      end
      define_method :type do
        info.to_i & 0xffffffff
      end
      define_method :sym= do |val|
        self.info = type | (val << 32)
      end
      define_method :type= do |val|
        self.info = (val &0xffffffff) | (sym << 32)
      end      
    end
  end
  def rel
    addr :off #Location to be relocated.
    xword :info #Relocation type and symbol index.
    define_method :addend do
      nil
    end
    rel_common
  end

# Relocations that need an addend field. */
  def rela
    addr :off #Location to be relocated.
    xword :info #Relocation type and symbol index.
    sxword :addend #Addend.
    rel_common
  end

#Elf Symbol
  def sym_common
    define_method :type do 
      info & 0xf
    end
    define_method :binding do 
      info >> 4 
    end
    define_method :type= do |val|
      raise RuntimeError.new "Invalid param" unless val & 0xf == val
      self.info = (info&0xf0) | val 
    end 
    define_method :binding= do |val|
      raise RuntimeError.new "Invalid param" unless val & 0xf == val
      self.info = (info&0xf) | (val << 4)
    end
  end
  def sym32
    word :name #String table index of name.
    addr :val #Symbol value. PATCH: change to val so as to avoid name conflict
    word :siz #Size of associated object. PATCH: Change to val
    char :info #Type and binding information.
    char :other #Reserved (not used).
    half :shndx #Section index of symbol.
    sym_common
  end
  def sym64
    word  :name
    uint8 :info
    uint8 :other
    half  :shndx
    addr  :val
    xword :siz
    sym_common
  end
  ELF_OBJECTS =  [:sym, :rela, :rel, :dyn, :phdr, :shdr, :hdr, :note]
  Split = {
    phdr: {
      32 => :phdr32,
      64 => :phdr64
    },
    sym: {
      32 => :sym32,
      64 => :sym64
    }
  }
  def bitness(bits)    
    @bits = bits
    alias_recordtype :char, :uint8
    case bits
    when 32
      alias_recordtype :word, :uint32
      alias_recordtype :sword, :int32
      alias_recordtype :half, :uint16
      alias_recordtype :off, :uint32
      alias_recordtype :addr, :uint32
      alias_recordtype :xword, :uint32
      alias_recordtype :sxword, :uint32
    when 64
      alias_recordtype :addr, :uint64
      alias_recordtype :off, :uint64
      alias_recordtype :half, :uint16
      alias_recordtype :word, :uint32
      alias_recordtype :sword, :int32
      alias_recordtype :xword, :uint64
      alias_recordtype :sxword, :int64
    else
      raise RuntimeError.new "We only know about 32-bit or 64-bit ELF formats, not about #{bits}"
    end
  end
end
class ElfStructFactory
  attr_reader *ElfStructs::ELF_OBJECTS
  def self.instance(endian, bits)
     @@instances[endian][bits]
  end
  def rel_info_sym(info)
    if @width == 32
        info.to_i >> 8
    else 
        info.to_i >> 32
    end
  end
  def rel_info_type(info) 
    if @width == 32
      info.to_i & 0xff
    else
      info.to_i & 0xffffffff
    end
  end   
  def rel_build_info(sym,type) 
    if @width == 32
      (sym.to_i << 8) | (type.to_i &0xff)
    else
      (sym.to_i << 32) | (type.to_i &0xffffffff)
    end
  end
  
  def initialize(endian,width)
    @endian = endian
    @width = width
    ElfStructs::ELF_OBJECTS.each do |object|
      klass = Class.new BinData::Record do
        extend ElfStructs
        endian  endian
        bitness width
        if(ElfStructs::Split.include? object)
          self.send(ElfStructs::Split[object][width])
        else
          self.send(object)
        end
      end
      instance_variable_set("@#{object.to_s}",klass)
    end
  end
  @@instances = {:little => {32 => ElfStructFactory.new(:little,32), 64=>ElfStructFactory.new(:little,64) },
                  :big => {32 => ElfStructFactory.new(:big,32) , 64 => ElfStructFactory.new(:big,64)}  }
end
