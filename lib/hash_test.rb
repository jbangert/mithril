require_relative  'writer'
require 'test/unit'
class TestHash < Test::Unit::TestCase
  def test_hash
    assert_equal( 0x668c3, Elf::Writer::elf_hash("__environ"))
  end
end
