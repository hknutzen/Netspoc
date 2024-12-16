
############################################################
=TITLE=Combined IPv4/IPv6 network, show name and IP
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; }
}
=INPUT=[[input]]
=OUTPUT=
10.1.1.0/24	network:n1
2001:db8:1:1::/64	network:n1
=PARAM=network:n1

############################################################
=TITLE=Combined IPv4/IPv6 network, show only name
=INPUT=[[input]]
=OUTPUT=
network:n1
=OPTIONS=--name
=PARAM=network:n1

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
=INPUT=[[input]]
=OUTPUT=
10.1.1.0/24	network:n1
=PARAM=network:[area:all]

############################################################
=TITLE=print-group: Automatically select IPv6 in IPv4
=INPUT=[[input]]
=OUTPUT=
1000::abcd:1:0/112	network:n2
=PARAM=network:[area:all6]

############################################################
=TITLE=print-group: interface:..[all] shows IPv4+IPv6
=INPUT=[[input]]
=OUTPUT=
short	interface:r1.n1
short	interface:r1.n2
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
=INPUT=[[input]]
=OUTPUT=
10.1.1.0/24	network:n1
=OPTIONS=--ipv6
=PARAM=network:[area:all]

############################################################
=TITLE=print-group: Automatically select IPv6 in IPv6
=INPUT=[[input]]
=OUTPUT=
1000::abcd:1:0/112	network:n2
=OPTIONS=--ipv6
=PARAM=network:[area:all6]

############################################################
=TITLE=print-group: interface:..[all] shows IPv4+IPv6 even with --ipv6
=INPUT=[[input]]
=OUTPUT=
short	interface:r1.n1
short	interface:r1.n2
=OPTIONS=--ipv6
=PARAM=interface:r1.[all]

############################################################
=TITLE=Anonymous matching aggregate where attribute ip has v6 address
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
group:g1 = any:[ip = 2001:db8:1:1::/64 & network:n1];
=ERROR=
Error: IPv4 address expected in any:[ip = 2001:db8:1:1::/64 & ..] of group:g1
=PARAM=group:g1

############################################################
=TITLE=Anonymous matching aggregate where attribute ip6 has v4 address
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
group:g1 = any:[ip6 = 10.1.0.0/16 & network:n1];
=ERROR=
Error: IPv6 address expected in any:[ip6 = 10.1.0.0/16 & ..] of group:g1
=PARAM=group:g1

############################################################
=TITLE=Combined area from anchor
=INPUT=
area:all = { anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
=OUTPUT=
area:all
=OPTIONS=-n
=PARAM=area:all

############################################################
=TITLE=Group of combined areas
=INPUT=
area:a1 = { border = interface:r1.n1; }
area:a2 = { inclusive_border = interface:r1.n1; }
group:g1 = area:a1, area:a2;
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
=OUTPUT=
area:a1
area:a2
=OPTIONS=-n
=PARAM=group:g1
