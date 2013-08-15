#!/usr/bin/env ruby
require_relative 'parser'
require_relative 'writer'
require_relative 'policy'

def inject_symbol(file,filename,section)
  return if file.symbols.include? section.name
  name = Elf::Policy::section_symbol_name(filename,section.name)
  sym = Elf::Symbol.new(name,section,ElfFlags::SymbolType::STT_SECTION,0,ElfFlags::SymbolBinding::STB_GLOBAL,section.size)
  sym.gnu_version = :global
  sym.hidden = false
  sym.is_dynamic = true
  file.symbols << sym
end

Elf::rewrite(ARGV[0]){|file|
  unless ElfFlags::Type::ET_DYN == file.filetype
    print "section_symbols works only for ET_DYN files"
    exit(-1)
  end
  file.progbits.each{|progbit|
    inject_symbol(file, file.dynamic.soname, progbit)
  }
}
