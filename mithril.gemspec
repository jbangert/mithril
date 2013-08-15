# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'mithril/version'

Gem::Specification.new do |spec|
  spec.name          = "elf-mithril"
  spec.version       = Mithril::VERSION
  spec.authors       = ["Julian Bangert"]
  spec.email         = ["jbangert@acm.org"]
  spec.description   = %q{TODO: Write a gem description}
  spec.summary       = %q{TODO: Write a gem summary}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_dependency 'bindata'
  spec.add_dependency 'renum'  , '1.4.0'
  spec.add_dependency 'andand'
  spec.add_dependency 'segment_tree'
  spec.add_dependency 'rbtree-pure'
  spec.executables << 'mithril-rewrite'
  spec.executables << 'mithril-section-symbols'  
end
