
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
=TITLE=Combined interface:..[all]
=INPUT=[[input]]
=OUTPUT=
10.1.1.1	interface:r1.n1
2001:db8:1:1::1	interface:r1.n1
=PARAM=interface:r1.[all]

############################################################
=TITLE=All interfaces from combined router from v4 interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
=OUTPUT=
10.1.1.1	interface:r1.n1
10.1.2.1	interface:r1.n2
2001:db8:1:2::1	interface:r1.n2
=PARAM=interface:[interface:r1.n1].[all]

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

############################################################
=TITLE=Non matching aggregates of combined area
=INPUT=
area:all = { anchor = network:n1; }
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
}
=OUTPUT=
0.0.0.0/0	any:[network:n1]
::/0	any:[network:n1]
=PARAM=any:[area:all]

############################################################
=TITLE=Networks of combined area
=INPUT=
area:all = { anchor = network:n1; }
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
}
=OUTPUT=
10.1.1.0/24	network:n1
2001:db8:1:1::/64	network:n1
=PARAM=network:[area:all]

############################################################
=TITLE=Hosts of combined area
=INPUT=
area:all = { anchor = network:n1; auto_ipv6_hosts = readable; }
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 host:h4 = { ip = 10.1.1.4; }
 host:h6 = { ip6 = 2001:db8:1:1::6; }
}
=OUTPUT=
10.1.1.4	host:h4
2001:db8:1:1::6	host:h6
2001:db8:1:1:10:1:1:4	host:h4
=PARAM=host:[area:all]

############################################################
=TITLE=Interfaces of combined area
=INPUT=
area:all = { anchor = network:n1; auto_ipv6_hosts = readable; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; }
 interface:n2;
}
=OUTPUT=
10.1.1.1	interface:r1.n1
short	interface:r1.n2
2001:db8:1:1::1	interface:r1.n1
=PARAM=interface:[area:all].[all]

############################################################
=TEMPL=topo
area:all = { anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64;
 host:h6 = { ip = 10.1.2.6; ip6 = 2001:db8:1:2::6; }
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
=END=

############################################################
=TITLE=Combined non matching aggregates of v4 area
=INPUT=[[topo]]
=OUTPUT=
0.0.0.0/0	any:[network:n1]
0.0.0.0/0	any:[network:n2]
::/0	any:[network:n2]
=PARAM=any:[area:all]

############################################################
=TITLE=Combined networks of v4 area
=INPUT=[[topo]]
=OUTPUT=
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
2001:db8:1:2::/64	network:n2
=PARAM=network:[area:all]

############################################################
=TITLE=Combined hosts of v4 area
=INPUT=[[topo]]
=OUTPUT=
10.1.1.4	host:h4
10.1.2.6	host:h6
2001:db8:1:2::6	host:h6
=PARAM=host:[area:all]

############################################################
=TITLE=Combined interfaces of v4 area
=INPUT=[[topo]]
=OUTPUT=
10.1.1.1	interface:r1.n1
10.1.2.1	interface:r1.n2
2001:db8:1:2::1	interface:r1.n2
=PARAM=interface:[area:all].[all]

############################################################
=TITLE=Networks and sub networks of dual stack network:Internet
=INPUT=
area:Internet = { anchor = network:Internet; }
network:Internet = {
 ip = 0.0.0.0/0;
 ip6 = ::/0;
 has_subnets;
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:Internet = {
 interface:Internet;
 interface:n1;
}
=OUTPUT=
0.0.0.0/0	network:Internet
10.1.1.0/24	network:n1
::/0	network:Internet
2001:db8:1:1::/64	network:n1
=PARAM=network:[network:Internet]

############################################################
=TITLE=Networks and sub networks of dual stack area:Internet
=INPUT=
area:Internet = { anchor = network:n1; }
network:Internet = {
 ip = 0.0.0.0/0;
 ip6 = ::/0;
 has_subnets;
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:Internet = {
 interface:Internet;
 interface:n1;
}
=OUTPUT=
0.0.0.0/0	network:Internet
::/0	network:Internet
10.1.1.0/24	network:n1
2001:db8:1:1::/64	network:n1
=PARAM=network:[area:Internet]
