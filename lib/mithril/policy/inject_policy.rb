module Elf
  class ElfFile
    def build_policy(&builder)
      Elf::Policy::inject_symbols(self)
      p = Elf::Policy.build(&builder)
      p.inject(self)
    end
  end
  def self.policy(&block)
    Elf::rewrite(ARGV[0]) do |file|
      file.build_policy do
        instance_exec(file,&block)
      end
    end
  end
end
