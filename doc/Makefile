# Makefile for NetSPoC

all:	netspoc.man netspoc.html CSPM.html toc-lang.html

language.html: pre-lang.html .hypertocrc
	# hypertoc uses options from file .hypertocrc in current directory.
	hypertoc --gen_anchors $< > $@
	hypertoc --gen_toc --inline --overwrite --bak '' $@


netspoc.man: netspoc.pod
	pod2man -c "NetSPoC documentation" netspoc.pod >netspoc.man

netspoc.html: netspoc.pod
	pod2html netspoc.pod | perl -pe 's/="([^"]*)">/($$_=$$1,tr.A-Za-z0-9#..cd,qq.="$$_">.)/e' >netspoc.html

CSPM.html: CSPM.pod
	pod2html CSPM.pod | perl -pe 's/="([^"]*)">/($$_=$$1,tr.A-Za-z0-9#..cd,qq.="$$_">.)/e' >CSPM.html

current := $(shell cat VERSION)
tar-file := $(current).tar.gz
cwd := $(shell pwd)
tar: $(tar-file)

$(tar-file): Netspoc.pm netspoc COPYING INSTALL CSPM.html CSPM.pod ChangeLog Makefile NEWS.html TODO examples index.html language.html netspoc.html netspoc.man netspoc.pod newpolicy VERSION
	echo Building $(current)
	cd ..;ln -snf $(cwd) $(current)
	tar cvzf $@ -C ..  $(addprefix $(current)/, $^)
