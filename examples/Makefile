# Makefile for examples

find := $(shell find . -maxdepth 1 -type d)
dirs := $(filter-out RCS code crypto . , $(find:./%=%))
codedirs := $(dirs:%=code/%)

all:	$(codedirs)

$(codedirs): code/%: % ../bin/netspoc ../lib/Netspoc.pm
	test -d $@ || mkdir $@
	perl -I ../lib ../bin/netspoc --comment_routes $< $@


