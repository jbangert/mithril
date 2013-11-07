module Elf
  class ElfFile
    def build_policy(&builder)
      Elf::Policy::inject_symbols(self)
      p = Elf::Policy.build(&builder)
      p.inject(self)
    end
  end
end
