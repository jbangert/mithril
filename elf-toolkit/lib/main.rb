require_relative 'parser'
require_relative 'writer'

$parse = Elf::Parser.from_file (ARGV[0] || "/bin/ls")
Elf::Writer::Writer.to_file("/tmp/tst",$parse)
`chmod +x /tmp/tst`
#binding.pry

#pp parse # .instance_variables
##TODO: Do enums as custom records.

