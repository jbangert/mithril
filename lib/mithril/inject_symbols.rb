module Elf::Policy
  def self.inject_symbols(file)
      case file.filetype
      when ElfFlags::Type::ET_EXEC
        filename = ""
      when ElfFlags::Type::ET_DYN
        filename = file.dynamic.soname
      else 
        raise RuntimeError.new "section_symbols works only for ET_DYN and ET_EXEC files"
      end
    (file.progbits + file.nobits).each{|section|         
      name = Elf::Policy::section_symbol_name(filename,section.name)
      next if file.symbols.include? name
      sym = Elf::Symbol.new(name,section,ElfFlags::SymbolType::STT_OBJECT,0,ElfFlags::SymbolBinding::STB_GLOBAL,section.size)  # STT_SECTION is ignored for lookup!
#      print "Injecting #{name}"
      sym.gnu_version = :global
      sym.hidden = false
      sym.is_dynamic = true
      file.symbols << sym
      }
  end
end
