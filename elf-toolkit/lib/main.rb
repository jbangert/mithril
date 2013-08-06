require_relative 'parser'
require_relative 'writer'

nginx_path = "/home/julian/important/12W/elf-policy/webserver-samples/nginx-install/sbin/"
$parse = Elf::Parser.from_file (ARGV[0] || nginx_path + "nginx-ori")
binding.pry
outfile=  ARGV[1] || nginx_path+"nginx"
Elf::Writer::Writer.to_file(outfile ,$parse)
`chmod +x #{outfile}`

#pp parse # .instance_variables
##TODO: Do enums as custom records.

