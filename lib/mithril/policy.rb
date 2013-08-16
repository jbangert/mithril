require 'bindata'
#Nothing to see here. For background, see Dartmouth College CS
#TR2013-727 (ELFbac)
module Elf
  module Policy
    def self.section_symbol_name(file_name,section_name)
        "_elfp_#{file_name}#{section_name}"
    end
    R = ElfFlags::Relocation
    ELFP = ElfFlags::ElfPData
    class Transition
      attr_accessor :from, :to 
    end
    class Call < Transition
      attr_accessor :symbol
      attr_accessor :parambytes,:returnbytes
      def initialize(from,to, symbol, parambytes, returnbytes)
        @from, @to, @symbol, @parambytes, @returnbytes = from,to, symbol, parambytes, returnbytes
      end
      def allows_return?
        @returnbytes >= 0
      end
    end
    class Data < Transition
      attr_accessor :low
      attr_accessor :high
      attr_accessor :read,:write, :exec 
      def initialize(from,to, low,high , read=false ,write=false,exec=false)
        @from, @to, @low, @high, @read,@write,@exec = from,to, low,high,read,write,exec
      end
    end
    class Policy
      attr_accessor :data, :calls
      def states
        t = [data + calls]
        (t.map(&:from) + t.map(&:to)).uniq 
      end
      def <<(*transitions)
        transitions.each do |t|
          if t.is_a? Data
            data << t
          elsif t.is_a? Call
            calls << t
          else
            raise ArgumentError.new "#{t.class} is not a valid transition"
          end
        end
      end
      def initialize
        @data=[]
        @calls=[]
      end
      def resolve_reference(elffile, relocations,offset, ref)
        if(ref.is_a? Integer)
          ref.to_i
        else
          raise RuntimeError.new "Symbol #{ref} not found" unless elffile.symbols.include? ref          
          relocations << Elf::Relocation.new.tap{|x|
            x.type = R::R_X86_64_64
            x.offset = offset
            x.symbol = elffile.symbols[ref]
            x.is_dynamic = true
            x.addend = 0
          }
          2**64-1
        end
      end
      def write_amd64(elffile)
        out = @factory.elfp_header.new()
        states = {}
        relocations = []
        #These have to be filled in the order in which they are written
        self.states.with_index.each do |state,index|
          out.states << @factory.elfp_state.new.tap {|x|
            x.id = index + 1
            x.stackid = 0 
          }
          states[state] = index  + 1
        end        
        self.calls.each do |call|
          out.calls << @factory.elfp_call.new.tap {|x|
            x.from = states[call.from]
            x.to = states[call.to]
            x.parambytes = call.parambytes
            x.returnbytes = call.parambytes
          }
          out.calls.last.off = resolve_reference(elffile,relocations,out.calls.last.off.offset, call.symbol)
        end
        self.data.each do |data|
          out.data << @factory.elfp_data.new.tap {|x|
            x.from = states[data.from]
            x.to = states[data.to]
            x.type = 0
            x.type |= ELFP::ELFP_RW_READ if data.read
            x.type |= ELFP::ELFP_RW_WRITE if data.write
            x.type |= ELFP::ELFP_RW_EXEC if data.exec
          }
          out.data.last.tap {|x|
            x.low = resolve_reference(elffile,relocations,x.low.offset,data.low)
            if(data.high.nil?)
              raise ArgumentError.new "Need to specify a range when using fixed addresses in data transition #{data}" if data.high.is_a? Integer
              x.high = 0 # 2**64-1
              x.type|= ELFP::ELFP_RW_SIZE
              relocations << Elf::Relocation.new.tap{|rel|
                rel.type = R::R_X86_64_SIZE64
                rel.offset = x.high.offset
                raise RuntimeError.new "Symbol #{x.low} not found" unless elffile.symbols.include? ref    
                rel.symbol = elffile.symbols[x.low]
                rel.addend = 0
                rel.is_dynamic = true
              }
            else
              x.high = resolve_reference(elffile, relocations,x.high.offset, data.high)
            end            
          }
        end
        out = Elf::ProgBits.new(".elfbac",nil,out.to_binary_s)
        out.phdr = ElfFlags::PhdrType::PHDR_PT_ELFBAC
        out.phdr_flags =  ElfFlags::PhdrFlags::PF_R
        relocations.each { |rel|
          rel.section = out
          elffile.relocations << rel
        }
        elffile.progbits << out
      end
    end
    class DataBuilder
      def initialize(transition)
        @transition = transition
      end
      def read(v=true)
        @transition.read = v
      end
      def write(v=true)
        @transition.write = v
      end
      def exec(v=true)
        @transition.exec = v
      end      
    end
    class StateBuilder
      def initialize(from,pol)
        @from = from
        @policy = pol
      end

      {
        text: ".text",
        data: ".data",
        bss:".bss"
      }.each{|function,name|
        define_method function, lambda{|library=''| section(name,library)}
      }
      def call(to,symbol, parambytes= 0, returnbytes=0)
        @policy << Call.new(@from,to, symbol, parambytes, returnbytes)
      end
      def range(to,low,high, &block)
        d = Data.new(@from,to,low,high)
        DataBuilder.new(d).instance_eval(block)
        @policy << d
      end 
      def transition(trans)
        @policy << trans 
      end
    end
    class PolicyBuilder
      def initialize()
        @policy = Policy.new()
      end
      def state(name, &block)
        StateBuilder.new(name,@policy).instance_eval block
      end
      
      def call_noreturn(from,to,symbol, parambytes=0)
        @policy << Call.new(from,to, symbol, parambytes,-1)        
      end
      def read
        @policy << Data.new(from,to,from,to )
      end
    end
    def build_policy(&block)
      x= PolicyBuilder.new().instance_eval block 
    end
  end

end
