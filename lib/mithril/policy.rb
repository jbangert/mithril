require 'bindata'
#Nothing to see here. For background, see Dartmouth College CS
#TR2013-727 (ELFbac)
module Elf
  module Policy
    def self.section_symbol_name(file_name,section_name)
        "_elfp_#{file_name}.#{section_name}"
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
      attr_accessor :data, :calls, :start
      attr_accessor :imported_symbols
      def states
        t = data + calls
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
        @imported_symbols = {}
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
        factory = ElfStructFactory.instance(:little,64)
        @imported_symbols.each_key {|symbol|
          elffile.symbols << Elf::Symbol.new(symbol,nil,Elf::STT::STT_SECTION, 0, Elf::STB::STB_GLOBAL, 0).tap {|x|
            x.semantics = Elf::SHN::SHN_UNDEF
          }
        }
        out = factory.elfp_header.new()
        state_ids = {}
        relocations = []
        states = states()
        @start = states.first unless states.include? @start
        #These have to be filled in the order in which they are written
        states.each_with_index do |state,index|
          id = index + 2
          id = 1 if @start == state
          out.states << factory.elfp_state.new.tap {|x|
            x.id = id
            x.stackid = 0 
          }
          state_ids[state] = id
        end        
        self.calls.each do |call|
          out.calls << factory.elfp_call.new.tap {|x|
            x.from = state_ids[call.from]
            x.to = state_ids[call.to]
            x.parambytes = call.parambytes
            x.returnbytes = call.parambytes
          }
          out.calls.last.off = resolve_reference(elffile,relocations,out.calls.last.off.offset, call.symbol)
        end
        self.data.each do |data|
          out.data << factory.elfp_data.new.tap {|x|
            x.from = state_ids[data.from]
            x.to = state_ids[data.to]
            x.type = 0
            x.type |= ELFP::ELFP_RW_READ if data.read
            x.type |= ELFP::ELFP_RW_WRITE if data.write
            x.type |= ELFP::ELFP_RW_EXEC if data.exec
          }
          out.data.last.tap {|x|
            x.low = resolve_reference(elffile,relocations,x.low.offset,data.low)
            if(data.high.nil?)
              raise ArgumentError.new "Need to specify a range when using fixed addresses in data transition #{data}" if data.high.is_a? Numeric
              x.high = 0 # 2**64-1
              x.type|= ELFP::ELFP_RW_SIZE
              relocations << Elf::Relocation.new.tap{|rel|
                rel.type = R::R_X86_64_SIZE64
                rel.offset = x.high.offset
                raise RuntimeError.new "Symbol #{data.low} not found" unless elffile.symbols.include? data.low    
                rel.symbol = elffile.symbols[data.low]
                rel.addend = 0
                rel.is_dynamic = true
              }
            else
              x.high = resolve_reference(elffile, relocations,x.high.offset, data.high)
            end            
          }
        end
        out = Elf::ProgBits.new(".elfbac",nil,out.to_binary_s)
        out.align = 8
        out.flags = SHF::SHF_ALLOC | SHF::SHF_WRITE
        out.sect_type = SHT::SHT_PROGBITS
        out.phdr = ElfFlags::PhdrType::PT_ELFBAC
        out.phdr_flags =  ElfFlags::PhdrFlags::PF_R
        relocations.each { |rel|
          rel.section = out
          elffile.relocations << rel
        }
        elffile.progbits << out
        
      end
      def inject(file)
        case file.machine
        when ElfFlags::Machine::EM_X86_64
          write_amd64(file)
        else
          raise RuntimeError.new "Wrong architecture for ARM64"
        end
      end
    end
    module BuilderHelper
      def section(name,file_name="")
        Elf::Policy.section_symbol_name(file_name,name).tap{|x| @policy.imported_symbols[x] = true}  
      end
    end
    class DataBuilder
      include BuilderHelper
      def initialize(transition)
        @transition = transition
      end
      def read(v=true) #TODO: Unify transitions? Intervaltree?
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
      include BuilderHelper
      def initialize(from,to,pol)
        @from = from
        @to = to
        @policy = pol
      end

      {
        text: ".text",
        data: ".data",
        bss:".bss"
      }.each{|function,name|
        define_method function, lambda{|library=''| section(name,library)}
      }
      def call(symbol, parambytes= 0, returnbytes=0)
        raise RuntimeError.new "Call has to have a destination" if @from == @to 
        @policy << Call.new(@from,@to, symbol, parambytes, returnbytes)
      end
      def range(low,high=nil, &block)
        d = Data.new(@from,@to,low,high)
        DataBuilder.new(d).instance_eval(&block)
        @policy << d
      end
      def exec(low,high=nil)
        range(low,high){
          exec        }
      end
      def read(low,high=nil)
        range(low,high){
          read
        }
      end
      def write(low,high=nil)
        range(low,high){
          write
        }
      end
      
      def to(name,&block)
        raise RuntimeError.new "Cannot nest to{} blocks" if @from != @to#  or name == @from
        StateBuilder.new(@from,name, @policy).instance_eval(&block)
      end
      def transition(trans)
        @policy << trans 
      end
    end
    class PolicyBuilder
      include BuilderHelper
      attr_reader :policy
      def initialize()
        @policy = Policy.new()
      end
      def state(name, &block)
        StateBuilder.new(name,name,@policy).instance_eval(&block)
      end      
      def call_noreturn(from,to,symbol, parambytes=0)
        @policy << Call.new(from,to, symbol, parambytes,-1)        
      end
      def read
        @policy << Data.new(from,to,from,to )
      end
      def start(name)
        @policy.start = name
      end
    end
    def self.build(&block)
      x= PolicyBuilder.new()
      x.instance_eval(&block)
      x.policy
    end
  end

end
