#!/bin/bash
# One time use more less  - quick editor script to parse elf.h  (from
# FreeBSD or go) into ruby-esque DSL
sed -e 's/\_/ /' -e 's/\;//g'  | awk '{printf "%s :%s #", tolower($2) ,$3; for(i=5;i<NF;i++) printf "%s ", $i; printf "\n"}'   

