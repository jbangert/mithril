require 'bundler'
require_relative 'elf_enums'
require_relative 'elf_structs'


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

module Elf
  class Elf
    attr_accessor :filetype, :machine, :entry, :flags
    def initialize(data)
      ident = ElfStructs::ElfIdentification.read(data)
      print ident.snapshot.inspect
      raise RuntimeError.new "Invalid ELF version #{ident.id_version}" if ident.id_version != ElfFlags::Version::EV_CURRENT
      case ident.id_class
        when ElfFlags::IdentClass::ELFCLASS64
          bits = 64
        when ElfFlags::IdentClass::ELFCLASS32
          bits = 32
        else
          RuntimeError.new "Invalid ELF class #{ident.id_class}"
      end
      case ident.id_data
        when ElfFlags::IdentData::ELFDATA2LSB
          endian = :little
        when ElfFlags::IdentData::ELFDATA2MSB
          endian = :big
        else
          RuntimeError.new  "Invalid ELF endianness #{ident.id_data}"
      end
      parser_factory = ElfStructFactory.instance(endian,bits)
      parse_with_factory(data,parser_factory)
    end
    def self.from_file(filename)
      contents = IO.read(filename)
      Elf.new(contents)
    end
    private
    def parse_with_factory(data,factory)
      hdr = factory.hdr.read(data)
      @filetype = hdr.type
      @machine = hdr.machine
      @version = hdr.version # Shouldn't this always be the current one
      @flags = hdr.flags

      # Assert hdr.shentsize         == sizeof section
      sections = BinData::Array.new(:type => factory.shdr, :initial_length =>
          hdr.shnum)
      sections.read(data.drop(hdr.shoff))
      print sections.snapshot

      phdrs = BinData::Array.new(:type => factory.phdr, :initial_length => hdr.phnum)
      phdrs.read(data.drop(hdr.phoff))
      print phdrs.snapshot
            #Read all sections
      #Read all segments
      #Build out string tables
      #
      #TODO: Validate flags
      #TODO: Validate header?
    end
  end

end
##TODO: Do enums as custom records.
