# Makefile for NetSPoC documentation

all:	netspoc.html CSPM.html language.html

language.html: pre-lang.html .hypertocrc
	# hypertoc uses options from file .hypertocrc in current directory.
	hypertoc --gen_anchors $< > $@
	hypertoc --gen_toc --inline --overwrite --bak '' $@

netspoc.html: ../bin/netspoc
	pod2html $< > $@

CSPM.html: CSPM.pod
	pod2html $< > $@