--- !ruby/object:Gem::Specification
name: bindata
version: !ruby/object:Gem::Version
  version: 1.4.5
  prerelease: 
platform: ruby
authors:
- Dion Mendel
autorequire: 
bindir: bin
cert_chain: []
date: 2013-04-26 00:00:00.000000000 Z
dependencies:
- !ruby/object:Gem::Dependency
  name: rspec
  requirement: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: 2.10.0
  type: :development
  prerelease: false
  version_requirements: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: 2.10.0
- !ruby/object:Gem::Dependency
  name: haml
  requirement: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: '0'
  type: :development
  prerelease: false
  version_requirements: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: '0'
- !ruby/object:Gem::Dependency
  name: maruku
  requirement: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: '0'
  type: :development
  prerelease: false
  version_requirements: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: '0'
- !ruby/object:Gem::Dependency
  name: syntax
  requirement: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: '0'
  type: :development
  prerelease: false
  version_requirements: !ruby/object:Gem::Requirement
    none: false
    requirements:
    - - ! '>='
      - !ruby/object:Gem::Version
        version: '0'
description: ! 'BinData is a declarative way to read and write binary file formats.


  This means the programmer specifies *what* the format of the binary

  data is, and BinData works out *how* to read and write data in this

  format.  It is an easier ( and more readable ) alternative to

  ruby''s #pack and #unpack methods.

'
email: dion@lostrealm.com
executables: []
extensions: []
extra_rdoc_files:
- NEWS
files:
- INSTALL
- README
- COPYING
- ChangeLog
- NEWS
- Rakefile
- BSDL
- examples/ip_address.rb
- examples/NBT.txt
- examples/list.rb
- examples/gzip.rb
- examples/nbt.rb
- spec/primitive_spec.rb
- spec/array_spec.rb
- spec/struct_spec.rb
- spec/base_spec.rb
- spec/stringz_spec.rb
- spec/choice_spec.rb
- spec/system_spec.rb
- spec/count_bytes_remaining_spec.rb
- spec/base_primitive_spec.rb
- spec/spec_common.rb
- spec/wrapper_spec.rb
- spec/float_spec.rb
- spec/example.rb
- spec/lazy_spec.rb
- spec/rest_spec.rb
- spec/alignment_spec.rb
- spec/io_spec.rb
- spec/deprecated_spec.rb
- spec/string_spec.rb
- spec/registry_spec.rb
- spec/skip_spec.rb
- spec/int_spec.rb
- spec/bits_spec.rb
- spec/record_spec.rb
- lib/bindata/choice.rb
- lib/bindata/params.rb
- lib/bindata/bits.rb
- lib/bindata/offset.rb
- lib/bindata/skip.rb
- lib/bindata/rest.rb
- lib/bindata/primitive.rb
- lib/bindata/string.rb
- lib/bindata/count_bytes_remaining.rb
- lib/bindata/io.rb
- lib/bindata/alignment.rb
- lib/bindata/dsl.rb
- lib/bindata/struct.rb
- lib/bindata/registry.rb
- lib/bindata/sanitize.rb
- lib/bindata/array.rb
- lib/bindata/base_primitive.rb
- lib/bindata/base.rb
- lib/bindata/trace.rb
- lib/bindata/float.rb
- lib/bindata/record.rb
- lib/bindata/lazy.rb
- lib/bindata/stringz.rb
- lib/bindata/int.rb
- lib/bindata/deprecated.rb
- lib/bindata/wrapper.rb
- lib/bindata.rb
- tasks/manual.rake
- tasks/pkg.rake
- tasks/rspec.rake
- tasks/rdoc.rake
- setup.rb
- manual.haml
- manual.md
homepage: http://bindata.rubyforge.org
licenses: []
post_install_message: 
rdoc_options:
- --main
- NEWS
require_paths:
- lib
required_ruby_version: !ruby/object:Gem::Requirement
  none: false
  requirements:
  - - ! '>='
    - !ruby/object:Gem::Version
      version: '0'
required_rubygems_version: !ruby/object:Gem::Requirement
  none: false
  requirements:
  - - ! '>='
    - !ruby/object:Gem::Version
      version: '0'
requirements: []
rubyforge_project: bindata
rubygems_version: 1.8.24
signing_key: 
specification_version: 3
summary: A declarative way to read and write binary file formats
test_files: []
