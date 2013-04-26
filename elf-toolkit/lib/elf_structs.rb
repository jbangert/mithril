
require 'bindata'
require_relative 'elf_enums'
module ElfStructs
  class ElfIdentification   < BinData::Record
    endian :little
    string :id_magic,  :length=>4  #  :value => "\x7FELF"
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
    uint32	:n_namesz	#Length of name.
    uint32	:n_descsz	# Length of descriptor.
    uint32	:n_type		# Type of this note.
  end

  def shdr
    word :name #Section name (index into section header string table
    word :type #Section type.
    word :flags #Section flags.
    addr :vaddr #Address in memory image.
    off :off #Offset in file.
    word :siz#Size in bytes. Patch: Had to change to siz
    word :link #Index of a related section.
    word :info #Depends on section type.
    word :addralign #Alignment in bytes.
    word :entsize #Size of each entry in section.
  end
  def phdr  #
    word :type #Entry type.
    off :off #File offset of contents.
    addr :vaddr #Virtual address in memory image.
    addr :paddr #Physical address (not used).
    word :filesz #Size of contents in file.
    word :memsz #Size of contents in memory.
    word :flags #Access permission flags.
    word :align #Alignment in memory and file.
  end
# Dynamic structure.  The ".dynamic" section contains an array of them.
  def dyn
    sword :d_tag #Entry type.
    addr :d_ptr_val #Address value or raw value
  end
# * Relocation entries
#  Relocations that don't need an addend field. */
  def rel
    addr :off #Location to be relocated.
    word :info #Relocation type and symbol index.
  end

# Relocations that need an addend field. */
  def rela
    addr :off #Location to be relocated.
    word :info #Relocation type and symbol index.
    sword :addend #Addend.
  end

#Elf Symbol
  def sym
    word :name #String table index of name.
    addr :val #Symbol value. PATCH: change to val so as to avoid name conflict
    word :siz #Size of associated object. PATCH: Change to val
    char :info #Type and binding information.
    char :other #Reserved (not used).
    half :shndx #Section index of symbol.
  end
  ELF_OBJECTS =  [:sym, :rela, :rel, :dyn, :phdr, :shdr, :hdr, :note]

  def bitness(bits)
    alias_recordtype :char, :uint8
    case bits
      when 32
        alias_recordtype :word, :uint32
        alias_recordtype :sword, :int32
        alias_recordtype :half, :uint16
        alias_recordtype :off, :uint32
        alias_recordtype :addr, :uint32
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
  def initialize(endian,width)
    @endian = endian
    @width = width
    ElfStructs::ELF_OBJECTS.each do |object|
      klass = Class.new BinData::Record do
        extend ElfStructs
        endian  endian
        bitness width
        self.send(object)
      end
      instance_variable_set("@#{object.to_s}",klass)
    end
  end
  @@instances = {:little => {32 => ElfStructFactory.new(:little,32), 64=>ElfStructFactory.new(:little,64) },
                  :big => {32 => ElfStructFactory.new(:big,32) , 64 => ElfStructFactory.new(:big,64)}  }
end
