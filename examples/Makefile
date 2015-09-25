# Makefile for examples

find := $(shell find . -maxdepth 1 -type d)
dirs := $(filter-out CVS code . , $(find:./%=%))
codedirs := $(dirs:%=code/%)

all:	$(codedirs)

$(codedirs): code/%: % ../bin/netspoc ../lib/Netspoc.pm
	test -d $@ || mkdir -p $@
	perl -I ../lib ../bin/netspoc $< $@


