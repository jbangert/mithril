module Elf::Policy::Hacks
  def initializer_functions(filename)
    lib = `objdump -D #{filename} | grep -B 3  'callq.*libc_start_main' `
    init_addr = /\$0x([0-9a-f]*),\%r8/.match(lib)[1].to_i(16)
    fini_addr = /\$0x([0-9a-f]*),\%rcx/.match(lib)[1].to_i(16)
    main_addr = /\$0x([0-9a-f]*),\%rdi/.match(lib)[1].to_i(16)
    [init_addr,fini_addr,main_addr]
  end
end
