
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR 'group:name,...'
  -a, --admins       Show admins of elements as comma separated list
  -i, --ip           Show only IP address of elements
  -n, --name         Show only name of elements
      --nat string   Use network:name as reference when resolving IP address
  -o, --owner        Show owner of elements
  -q, --quiet        Don't print progress messages
  -u, --unused       Show only elements not used in any rules
=END=

############################################################
=TITLE=Missing group parameter
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR 'group:name,...'
  -a, --admins       Show admins of elements as comma separated list
  -i, --ip           Show only IP address of elements
  -n, --name         Show only name of elements
      --nat string   Use network:name as reference when resolving IP address
  -o, --owner        Show owner of elements
  -q, --quiet        Don't print progress messages
  -u, --unused       Show only elements not used in any rules
=END=

############################################################
=TITLE=Unknown option
=INPUT=NONE
=PARAMS=--abc
=ERROR=
Error: unknown flag: --abc
=END=

############################################################
=TITLE=Invalid Netspoc config
=INPUT=
invalid
=ERROR=
Error: Typed name expected at line 1 of INPUT, near "--HERE-->invalid"
Aborted
=PARAM=network:n1

############################################################
=TITLE=Reference unknown network for NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Unknown network:n2 of option '--nat'
Aborted
=OPTIONS=--nat network:n2
=PARAM=network:n1

############################################################
=TITLE=Invalid group parameter
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->INVALID"
Aborted
=PARAM=INVALID

############################################################
=TITLE=Unexpected content after ";"
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Unexpected content after ";" at line 1 of command line, near "network:n1; --HERE-->INVALID"
Aborted
=PARAM=network:n1; INVALID

############################################################
=TITLE=Empty parameter
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=OUTPUT=NONE
=WARNING=
Warning: print-group is empty
=PARAM=

=END=

############################################################
=TITLE=Comment as parameter
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=OUTPUT=NONE
=WARNING=
Warning: print-group is empty
=PARAM=
###
=END=

############################################################
=TITLE=Unknown group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Can't resolve group:g1 in print-group
=PARAM=group:g1

############################################################
=TITLE=Unknown group in parameter list
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
group:g1 = network:n1;
=ERROR=
Error: Can't resolve group:g2 in print-group
Error: Can't resolve group:g3 in print-group
Error: Can't resolve group:g4 in network:[..] of print-group
=OUTPUT=
10.1.1.0/24	network:n1
=PARAM=group:g1, group:g2, group:g3, network:[group:g4]

############################################################
=TITLE=Show warnings
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
group:g1 = network:n1;
group:g2 = group:g1 &! network:n1;
=WARNING=
Warning: Empty intersection in group:g2:
group:g1
&! network:n1
Warning: Duplicate elements in print-group:
 - network:n1
=OUTPUT=
10.1.1.0/24	network:n1
=PARAM=group:g1,network:n1,group:g2

############################################################
=TITLE=Ignore trailing comma at input
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=OUTPUT=
10.1.1.0/24	network:n1
=PARAM=network:n1,

############################################################
=TEMPL=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24;
 host:h3a = { range = 10.1.3.10-10.1.3.15; }
 host:h3b = { ip = 10.1.3.26; }
}
network:n3sub = { ip = 10.1.3.64/27; subnet_of = network:n3;
 host:h3c = { ip = 10.1.3.66; }
 host:h3d = { range = 10.1.3.65 - 10.1.3.67; }
}
router:u = {
 interface:n3 = { ip = 10.1.3.1; }
 interface:n3sub;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Find unused hosts
=INPUT=
[[topo]]
service:s = {
 user = host:h3a, host:h3c;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
10.1.1.10	host:h1
10.1.3.26	host:h3b
10.1.3.65-10.1.3.67	host:h3d
=OPTIONS=--unused
=PARAM=host:[network:n1, network:n3]

############################################################
=TITLE=Find unused interface when [auto] is in use
=INPUT=
[[topo]]
service:s = {
 user = interface:r2.[auto];
 permit src = network:n1; dst = user; prt = udp 161;
}
=OUTPUT=
10.1.3.2	interface:r2.n3
=OPTIONS=--unused
=PARAM=interface:r2.[all]

############################################################
=TITLE=Find unused hosts, ignore host of automatic group
# If host is only referenced in automatic group, it should be substituted
# by expanded automatic group.
=INPUT=
[[topo]]
service:s = {
 user = network:[host:h3a], any:[host:h3c];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
10.1.1.10	host:h1
10.1.3.10-10.1.3.15	host:h3a
10.1.3.26	host:h3b
10.1.3.66	host:h3c
10.1.3.65-10.1.3.67	host:h3d
=OPTIONS=--unused
=PARAM=host:[network:n1, network:n3]

############################################################
=TITLE=Find unused hosts, ignore negated element
# If host is only referenced in negation, it should be removed completely.
=INPUT=
[[topo]]
group:g = host:h3a, host:h3b, host:h3c;
service:s = {
 user = group:g &! host:h3b;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
10.1.1.10	host:h1
10.1.3.26	host:h3b
10.1.3.65-10.1.3.67	host:h3d
=OPTIONS=--unused
=PARAM=host:[network:n1, network:n3]

############################################################
=TITLE=Automatic hosts
=INPUT=[[topo]]
=OUTPUT=
10.1.1.10	host:h1
10.1.3.10-10.1.3.15	host:h3a
=PARAM=host:[network:n1, host:h3a]

############################################################
=TITLE=Automatic network with subnets
=INPUT=[[topo]]
=OUTPUT=
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
=PARAM=network:[network:n3]

############################################################
=TITLE=Automatic network with subnets from group
=INPUT=
[[topo]]
group:g1 = network:[network:n3];
=OUTPUT=
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
=PARAM=group:g1

############################################################
=TITLE=Automatic network with subnets from any
=INPUT=[[topo]]
=OUTPUT=
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
=PARAM=network:[any:[network:n3sub]]

############################################################
=TITLE=Automatic hosts together with automatic network with subnets
=INPUT=[[topo]]
=OUTPUT=
10.1.1.10	host:h1
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
=PARAM=host:[network:n1],network:[network:n3]

############################################################
=TITLE=Toplevel group with more than 8 elements
=INPUT=
[[topo]]
group:g1 =
 network:n1,
 network:n2,
 network:n3,
 host:h3a,
 host:h3b,
 host:h3c,
 host:h3d,
;
=OUTPUT=
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
10.1.3.0/24	network:n3
10.1.3.10-10.1.3.15	host:h3a
10.1.3.26	host:h3b
10.1.3.66	host:h3c
10.1.3.65-10.1.3.67	host:h3d
=PARAM=group:g1

############################################################
=TITLE=Area as element with owner
=INPUT=
[[topo]]
owner:o1 = { admins = a1@example.com; }
owner:o2 = { admins = a2@example.com; }
area:a1 = { border = interface:r1.n1; owner = o1; }
area:a2 = { border = interface:r1.n2; owner = o2; }
group:g1 = area:a1, area:a2, network:[area:a2];
=OUTPUT=
	area:a1	owner:o1
	area:a2	owner:o2
10.1.2.0/24	network:n2	owner:o2
10.1.3.0/24	network:n3	owner:o2
10.1.3.64/27	network:n3sub	owner:o2
=OPTIONS=--owner --name --ip
=PARAM=group:g1

############################################################
=TITLE=Intersection
=INPUT=
[[topo]]
group:g1 = network:n1, network:n2;
group:g2 = network:n2, network:n3;
=OUTPUT=
10.1.2.0/24	network:n2
=PARAM=group:g1 & group:g2

############################################################
=TITLE=Intersection with complement
=INPUT=
[[topo]]
group:g1 = network:n1, network:n2;
=OUTPUT=
10.1.1.0/24	network:n1
=PARAM=group:g1 &! network:n2

############################################################
=TITLE=Multiple intersection with complement
=INPUT=
[[topo]]
group:g1 = host:h1, network:n2, network:n3;
=OUTPUT=
10.1.2.0/24	network:n2
=PARAM=group:g1 &! network:n3 &! host:h1

############################################################
=TITLE=Umlaut in group name
=INPUT=
[[topo]]
group:Über = network:n1;
=OUTPUT=
10.1.1.0/24	network:n1
=PARAM=group:Über

############################################################
=TITLE=Mark networks referenced by interface as used
=INPUT=
[[topo]]
area:all = { anchor = network:n1; }
service:s1 = {
 user = interface:r1.n1, interface:u.n3;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
10.1.3.64/27	network:n3sub
=OPTIONS=-u
=PARAM=network:[area:all]

############################################################
=TITLE=Find unused network that is referenced in argument
=INPUT=[[topo]]
=OUTPUT=
10.1.1.0/24	network:n1
=OPTIONS=-u
=PARAM=network:[any:[network:n1]]


### Topology for multiple tests.
=TEMPL=input
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/28; dynamic; }
 host:h1s = { ip = 10.1.1.10; nat:t1 = { ip = 10.9.1.10; } }
 host:h1d = { ip = 10.1.1.11; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:t1 = { ip = 10.9.2.0/24; }
 host:h2 = { ip = 10.1.2.10; }
}
network:n3 = {
 ip = 10.1.3.0/24;
 nat:t3 = { hidden; }
 host:h3 = { ip = 10.1.3.10; }
}
router:r1 =  {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; nat:t1 = { ip = 10.9.1.1; } hardware = n1; }
 interface:n2 = { negotiated; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t1 = { unnumbered; hardware = t; nat_out = t1, t3; }
}
network:t1 = { unnumbered; }
router:r2 = {
 interface:t1;
 interface:k1;
}
network:k1 = { ip = 10.2.2.0/24; }
=END=

############################################################
=TITLE=Dynamic NAT for network and static NAT for host
=INPUT=[[input]]
=OUTPUT=
10.9.1.0/28	network:n1
10.9.1.10	host:h1s
10.9.1.0/28	host:h1d
=OPTIONS=--nat k1
=PARAM=network:n1, host:h1s, host:h1d

############################################################
=TITLE=Static NAT for network and host
=INPUT=[[input]]
=OUTPUT=
10.9.2.0/24	network:n2
10.9.2.10	host:h2
=OPTIONS=--nat k1
=PARAM=network:n2,host:h2

############################################################
=TITLE=Hidden NAT for network and host
=INPUT=[[input]]
=OUTPUT=
hidden	network:n3
hidden	host:h3
=OPTIONS=--nat k1
=PARAM=network:n3,host:h3

############################################################
=TITLE=Unnumbered network
=INPUT=[[input]]
=OUTPUT=
unnumbered	network:t1
=OPTIONS=--nat k1
=PARAM=network:t1

############################################################
=TITLE=Show unnumbered from [all], show [auto] interface
=INPUT=[[input]]
=OUTPUT=
10.9.1.1	interface:r1.n1
10.9.2.0/24	interface:r1.n2
hidden	interface:r1.n3
unnumbered	interface:r1.t1
unknown	interface:r1.[auto]
=OPTIONS=--nat k1
=PARAM=interface:r1.[all],interface:r1.[auto]

############################################################
=TITLE=Short interface
=INPUT=[[input]]
=OUTPUT=
short	interface:r2.t1
short	interface:r2.k1
=PARAM=interface:r2.[all]

############################################################
=TITLE=Empty group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
 group:g1 = ;
=WARNING=NONE
=OUTPUT=NONE
=PARAM=group:g1

############################################################
=TITLE=Show bridged interface
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
router:r = {
 interface:n1/right = { ip = 10.1.1.2; }
}
=OUTPUT=
bridged	interface:bridge.n1/right
10.1.1.2	interface:r.n1/right
=PARAM=interface:[network:n1/right].[all]

############################################################
=TITLE=Show crosslink network that otherwise suppressed
=INPUT=
area:all = { anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
=OUTPUT=
10.1.1.0/27	network:n1
10.3.3.0/29	network:cr
10.2.2.0/27	network:n2
=PARAM=network:[area:all]


############################################################
=TITLE=Show owner
=TEMPL=topo
owner:o = { admins = o@b.c; }
network:n1 = { ip = 10.1.1.0/24; owner = o; }
router:r = {
 interface:n1;
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
=INPUT=[[topo]]
=OUTPUT=
10.1.1.0/24	network:n1	owner:o
10.1.2.0/24	network:n2	none
=OPTIONS=--owner
=PARAM=network:n1, network:n2

############################################################
=TITLE=Show owner and only name
=INPUT=[[topo]]
=OUTPUT=
network:n1	owner:o
network:n2	none
=OPTIONS=-n -o
=PARAM=network:[any:[network:n1]]

############################################################
=TITLE=Show only name
=INPUT=[[topo]]
=OUTPUT=
network:n1
network:n2
=OPTIONS=--name
=PARAM=network:[any:[network:n1]]

############################################################
=TITLE=Show only ip
=INPUT=[[topo]]
=OUTPUT=
10.1.1.0/24
10.1.2.0/24
=OPTIONS=--ip
=PARAM=network:[any:[network:n1]]

############################################################
=TITLE=Show owner and admins
=TEMPL=topo
owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2a@d.e.f, o2b@g.h.i; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
network:n2 = { ip = 10.1.2.0/24; owner = o2; }
network:n3 = { ip = 10.1.3.0/24; owner = o1; }
network:n3a = { ip = 10.1.3.0/25; subnet_of = network:n3; }
router:r = {
 interface:n1;
 interface:n2;
 interface:n3;
 interface:n3a;
}
=INPUT=[[topo]]
=OUTPUT=
network:n1	owner:o1	o1@b.c
network:n2	owner:o2	o2a@d.e.f,o2b@g.h.i
network:n3a	owner:o1	o1@b.c
=OPTIONS=--name --owner --admins
=PARAM=network:n1, network:n2, network:n3a

############################################################
=TITLE=Show only name and admins
=INPUT=[[topo]]
=OUTPUT=
network:n1	o1@b.c
network:n2	o2a@d.e.f,o2b@g.h.i
network:n3a	o1@b.c
=OPTIONS=--name -a
=PARAM=network:n1, network:n2, network:n3a

############################################################
=TITLE=Do not print full length prefixes
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/32; }
network:n4 = { ip = 10.1.4.0/32; }
network:n5 = { ip = 10.1.5.0/32;
 nat:nat1 = { ip = 10.7.7.0/32; dynamic; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat_out = nat1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 }
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; hardware = n1; }
 interface:n3 = { negotiated; hardware = n2; }
 interface:n4;
 interface:n5;
}
group:g1 = network:n4, interface:r2.n3, interface:r2.n5;
=OUTPUT=
10.1.4.0	network:n4
10.1.3.0	interface:r2.n3
10.7.7.0	interface:r2.n5
=OPTIONS=--nat n1
=PARAM=group:g1

############################################################
=TITLE=Must not ignore aggregate with only loopback network
=INPUT=
area:n2-lo = { border = interface:r1.n2; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { unnumbered; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { unnumbered; hardware = n2; }
 }
router:r2 = {
 interface:n2;
 interface:lo = { ip = 10.1.3.1; loopback; }
}
=OUTPUT=
0.0.0.0/0	any:[network:n2]
=PARAM=any:[area:n2-lo]

############################################################
