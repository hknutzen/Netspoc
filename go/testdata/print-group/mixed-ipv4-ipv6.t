
############################################################
=TITLE=print-group: Automatically select IPv4 in IPv4
=TEMPL=input
--file
area:all = { anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = { interface:n1; }
--ipv6
area:all6 = { anchor = network:n2; }
network:n2 = { ip = 1000::abcd:0001:0/112;}
router:r1 = { interface:n2; }
=END=
=INPUT=[[input]]
=OUTPUT=
10.1.1.0/24	network:n1
=END=
=PARAM=network:[area:all]

############################################################
=TITLE=print-group: Automatically select IPv6 in IPv4
=INPUT=[[input]]
=OUTPUT=
1000::abcd:1:0/112	network:n2
=END=
=PARAM=network:[area:all6]

############################################################
=TITLE=print-group: interface:..[all] selects IPv4 in IPv4
=INPUT=[[input]]
=OUTPUT=
short	interface:r1.n1
=END=
=PARAM=interface:r1.[all]

############################################################
=TITLE=print-group: Automatically select IPv4 in IPv6
=TEMPL=input
--ipv4
area:all = { anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = { interface:n1; }
--file
area:all6 = { anchor = network:n2; }
network:n2 = { ip = 1000::abcd:0001:0/112;}
router:r1 = { interface:n2; }
=END=
=INPUT=[[input]]
=OUTPUT=
10.1.1.0/24	network:n1
=END=
=OPTIONS=--ipv6
=PARAM=network:[area:all]

############################################################
=TITLE=print-group: Automatically select IPv6 in IPv6
=INPUT=[[input]]
=OUTPUT=
1000::abcd:1:0/112	network:n2
=END=
=OPTIONS=--ipv6
=PARAM=network:[area:all6]

############################################################
=TITLE=print-group: interface:..[all] selects IPv6 in IPv6
=INPUT=[[input]]
=OUTPUT=
short	interface:r1.n2
=END=
=OPTIONS=--ipv6
=PARAM=interface:r1.[all]
