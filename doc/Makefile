# Makefile for NetSPoC

all:	netspoc.man netspoc.html CSPM.html


netspoc.man: netspoc.pod
	pod2man -c "NetSPoC documentation" netspoc.pod >netspoc.man

netspoc.html: netspoc.pod
	pod2html netspoc.pod | perl -pe 's/="([^"]*)">/($$_=$$1,tr.A-Za-z0-9#..cd,qq.="$$_">.)/e' >netspoc.html

CSPM.html: CSPM.pod
	pod2html CSPM.pod | perl -pe 's/="([^"]*)">/($$_=$$1,tr.A-Za-z0-9#..cd,qq.="$$_">.)/e' >CSPM.html

current := $(shell cat VERSION)

tar: $(current)

$(current): COPYING CSPM.html CSPM.pod ChangeLog Makefile NEWS TODO examples index.html language.html netspoc netspoc.html netspoc.man netspoc.pod newpolicy VERSION
	echo Building $(current)
	cd ..;ln -sf develop $(current)
	tar cvzf $@ -C ..  $(addprefix $(current)/, $^)
