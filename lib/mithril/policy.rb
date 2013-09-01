require 'bindata'
#Nothing to see here. For background, see Dartmouth College CS
#TR2013-727 (ELFbac)
module Elf
  module Policy
    def self.section_symbol_name(file_name,section_name)
        "_elfp_#{file_name}_#{section_name}"
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
      attr_accessor :tag
      attr_accessor :read,:write, :exec 
      def initialize(from,to,tag , read=false ,write=false,exec=false)
        @from, @to, @tag, @read,@write,@exec = from,to,tag,read,write,exec
      end
    end
    class MemoryRange
      attr_accessor  :low, :high
      def initialize(from,to)
        @low,@high = from,to
      end
    end
    class Policy
      attr_accessor :data, :calls, :start, :tags
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
        @tags = {}
        @imported_symbols = {}
      end
      def resolve_reference(elffile, relocations,offset, ref)
        if(ref.is_a? Integer)
          ref.to_i
        elsif(ref == "_dl_runtime_resolve") #HACK:HACK:HACK: I couldn't hack ld.so to fix this, so
          #here comes a nasty hack
          #note that the address of _dl_runtime_resolve is 16 bytes into PLT.GOT
          if !elffile.symbols.include? "_elfp_hidden_trampolineaddr"
            pltgot = elffile.dynamic.pltgot or raise RuntimeError.new "No plt.got for _dl_runtime_resolve hack"
            elffile.symbols << Elf::Symbol.new("_elfp_hidden_trampolineaddr", pltgot,STT::STT_OBJECT,16, STB::STB_LOCAL,8)            
          end
          symb = elffile.symbols["_elfp_hidden_trampolineaddr"]
          relocations << Elf::Relocation.new.tap{|x|
            x.type = R::R_X86_64_COPY
            x.offset = offset
            x.symbol = symb
            x.is_dynamic = true
            x.addend = 0
          }
          0xDEADBEEF
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
      def resolve_size(elffile,relocations, offset, ref)
          if(ref.is_a? Integer)
          ref.to_i
        else
          raise RuntimeError.new "Symbol #{ref} not found" unless elffile.symbols.include? ref          
          relocations << Elf::Relocation.new.tap{|x|
            x.type = R::R_X86_64_SIZE64
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
          if elffile.symbols.include?(symbol)
            elffile.symbols[symbol].is_dynamic = true
          else
            elffile.symbols << Elf::Symbol.new(symbol,nil,Elf::STT::STT_OBJECT, 0, Elf::STB::STB_GLOBAL, 0).tap {|x|
              x.semantics = Elf::SHN::SHN_UNDEF
            }
          end
        }
        out = factory.elfp_header.new()
        state_ids = {}
        tag_ids = {}
        relocations = []
        states = states()
        @start = states.first unless states.include? @start
        #These have to be filled in the order in which they are written
        #FIXME: Make these aware of double transitions to the same range/ state
        states.each_with_index do |state,index|
          id = index + 2
          id = 1 if @start == state
          out.states << factory.elfp_state.new.tap {|x|
            x.id = id
            x.stackid = 0 
          }
          state_ids[state] = id
          print "State #{state} #{id}\n"
        end
        tag_ids[:default] = 0 
        @tags.each_with_index do |(name,ranges),index|
          tag_ids[name] = index+1
          ranges.each do |data|
            out.tags << factory.elfp_tag.new.tap {|x|
              x.tag = index + 1
              x.addr = 0
              x.siz = 0
            }
            out.tags.last.tap {|x|
              x.addr  = resolve_reference(elffile,relocations,x.addr.offset,data.low)
              if data.high.nil?
                x.siz = resolve_size(elffile,relocations,x.siz.offset,data.low)
              else
                pp "Warning, emitting SIZE symbol with value  #{ data.high.to_i rescue data.high.name}"
                x.siz = resolve_reference(elffile,relocations,x.siz.offset,data.high)
              end
            }
          end
          print "Tag #{name} #{index + 1} \n"
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
            raise RuntimeError.new "Unknown tag #{data.tag}" unless tag_ids.include? data.tag
            x.tag =   tag_ids[data.tag]
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
      def section_start(name, file_name="")
        Elf::Policy.section_symbol_name(file_name,name).tap{|x| @policy.imported_symbols[x] = true}
      end
    end
    class TagBuilder
      include BuilderHelper
      attr_accessor :ranges
      def initialize(pol)
        @policy = pol
        @ranges = []
      end
      def section(name,file_name="")
        range(section_start(name,file_name))
      end
      def range(low,high=nil)
        @ranges << MemoryRange.new(low,high)
      end
      def symbol(sym)
        range(sym)
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
        @transition.read ||= v
      end
      def exec(v=true)
        @transition.exec = v
        @transition.read ||= v
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
      def call_noreturn(symbol,parambytes=0)
        call(symbol, parambytes,-1)
      end
      def mem(tag, &block)
        d = Data.new(@from,@to,tag)
        DataBuilder.new(d).instance_eval(&block)
        @policy << d
      end
      def exec(tag)
        mem(tag){
          exec        }
      end
      def read(tag)
        mem(tag){
          read
        }
      end
      def write(tag)
        mem(tag){
          write
        }
      end
      def readwrite(tag)
        mem(tag){
          read
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
      def tag(name, &block)
        policy.tags[name] ||= []
        x =TagBuilder.new(@policy)
        x.instance_eval(&block)
        policy.tags[name] += x.ranges
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
