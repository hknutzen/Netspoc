# Makefile for examples

find := $(shell find . -maxdepth 1 -type d)
dirs := $(filter-out RCS code . , $(find:./%=%))
codedirs := $(dirs:%=code/%)

all:	$(codedirs)

$(codedirs): code/%: % ../netspoc ../Netspoc.pm
	test -d $@ || mkdir $@
	../netspoc --comment_acls --comment_routes $< $@


