module Elf::Policy::Generator
  H= Elf::Policy::Hacks
  def twostate(file,filename)
    
    tag('program') do
      section('.init')
      section('.fini')
      section('.text')
      section('.plt')
      section('.data')
      section('.bss')
      section('.rodata')
      section('.got')
    end
    tag('libraries') do
      section('.plt')
#      libs.each do |lib|
#        section('.text',lib)
#        section('.plt',lib)
#        section('.data',lib)
#        section('.bss',lib)
#        section('.rodata',lib)
#        section('.plt',lib)
#        section('.got.plt',lib)
 #     end
    end
    state('main')  do
      exec 'program'
      readwrite 'libraries'
      readwrite 'program'
      readwrite :default 
      to('libs') do
        plt = file.progbits.select{|x|x.name==".plt"}.first
        (plt.addr .. (plt.addr + plt.size)).step(8).each do |plt_addr|            #FIXME: This is a
          #hack
          call plt_addr
        end
      end
      to('libs') do
        call '_dl_runtime_resolve'
      end
    end 
    state('libs')  do
      exec 'libraries'
      readwrite 'libraries'
      readwrite 'program'
      readwrite :default
      exec :default # Really, this sucks
      to 'main' do
        call file.entry.to_i
        H::initializer_functions(filename).each {|initializer|
          call initializer
        }
        call '_fini'
      end
    end 
    start 'libs'
  end
end
