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
    file.progbits.each{|section|
         return if file.symbols.include? section.name
      name = Elf::Policy::section_symbol_name(filename,section.name)
      sym = Elf::Symbol.new(name,section,ElfFlags::SymbolType::STT_SECTION,0,ElfFlags::SymbolBinding::STB_GLOBAL,section.size)
      sym.gnu_version = :global
      sym.hidden = false
      sym.is_dynamic = true
      file.symbols << sym
      }
  end
end
