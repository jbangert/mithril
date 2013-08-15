#!/bin/bash
define_enum() {
echo "class $2 < Enum # $1"
grep "[[:space:]]$1" elf.h | awk '{print $2, " = ", $3}' 
echo "end"
}

define_enum EV_ Version
define_enum ELFCLASS IdentClass
define_enum ELFDATA IdentData
define_enum ELFOSABI OsAbi
define_enum ET_ Type
define_enum EM_ Machine
define_enum SHN_ SpecialSection
define_enum SHT_ SectionType
define_enum SHF_ SectionFlags
define_enum PT_ PhdrType
define_enum PF_ PhdrFlags
define_enum DT_ DynamicType
define_enum DF_ DynamicFlags
define_enum NT_ CoreNType
define_enum STB_ SymbolBinding
define_enum STT_ SymbolType
define_enum STV_ SymbolVisibility
define_enum STN_ SymbolName
define_enum R_ Relocation
