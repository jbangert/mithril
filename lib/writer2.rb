require_relative 'elf'
module Elf
  module Writer2
    class StringTable < BinData::Record
      array :strtab, :initial_length => 1 do
        stringz :initial_value => ""
      end
      def initialize 
        @strings = {} #TODO: Do substring matching, compress the string
        #table.
        def add_string(string) 
          unless @strings.include? string
            @strings[string] = self.strtab.num_bytes
            self.strtab << BinData::Stringz(string)
          end
          @strings[string]
        end
      end
      class OutputLayout < BinData::Record
      end
      
      
    end
  end
end
a= Elf::Writer2::StringTable.new
a.add_string("Hello")
pp a.to_binary_string
binding.pry
