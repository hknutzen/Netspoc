=TEMPL=topo
area:test = { border = interface:filter.Trans; }
network:A = { ip6 = ::a03:300/121; }
network:sub = { ip6 = ::a03:308/125; subnet_of = network:A; }
network:B = { ip6 = ::a03:380/121; }
router:ras = {
 interface:A = { ip6 = ::a03:301; }
 interface:sub = { ip6 = ::a03:309; }
 interface:B = { ip6 = ::a03:381; }
 interface:Trans = { ip6 = ::a01:102; }
}
network:Trans = { ip6 = ::a01:100/120; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip6 = ::a01:101; hardware = VLAN1; }
 interface:Customer = { ip6 = ::a09:901; hardware = VLAN2; }
}
network:Customer = { ip6 = ::a09:900/120; }
=END=

############################################################
=TITLE=Implicit aggregate over 3 networks
=INPUT=
[[topo]]
service:test = {
 user = any:[ip6=::a00:0/104 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
=OUTPUT=
--ipv6/filter
ipv6 access-list VLAN1_in
 deny ipv6 any host ::a09:901
 permit tcp ::a00:0/104 ::a09:900/120 eq 80
 permit tcp ::a01:100/120 ::a09:900/120 eq 81
 permit tcp ::a03:300/120 ::a09:900/120 eq 81
 deny ipv6 any any
=END=

############################################################
=TITLE=Implicit aggregate over 2 networks
=INPUT=
[[topo]]
service:test = {
 user = any:[ip6=::a03:300/120 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
=OUTPUT=
--ipv6/filter
ipv6 access-list VLAN1_in
 deny ipv6 any host ::a09:901
 permit tcp ::a03:300/120 ::a09:900/120 eq 80
 permit tcp ::a03:300/120 ::a09:900/120 eq 81
 deny ipv6 any any
=END=

############################################################
=TITLE=Implicit aggregate between 2 networks
=INPUT=
[[topo]]
service:test1 = {
 user = any:[ip6=::a03:300/122 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
service:test2 = {
 overlaps = service:test1;
 user = network:sub;
 permit src = user; dst = network:Customer; prt = tcp 81;
}
=OUTPUT=
--ipv6/filter
ipv6 access-list VLAN1_in
 deny ipv6 any host ::a09:901
 permit tcp ::a03:300/122 ::a09:900/120 eq 80
 permit tcp ::a03:308/125 ::a09:900/120 eq 81
 deny ipv6 any any
=END=

############################################################
=TITLE=Multiple implicit aggregates
=INPUT=
network:Test =  { ip6 = ::a09:100/120; }
router:filter1 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Test = { ip6 = ::a09:101; hardware = Vlan20; }
  interface:Trans1 = { ip6 = ::a03:601; hardware = VLAN1; }
}
router:filter2 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Test = { ip6 = ::a09:102; hardware = Vlan20; }
  interface:Trans2 = { ip6 = ::a05:701; hardware = VLAN1; }
}
network:Trans1 = { ip6 = ::a03:600/120; }
network:Trans2 = { ip6 = ::a05:700/120; }
router:Kunde = {
  interface:Trans1 = { ip6 = ::a03:602; }
  interface:Trans2 = { ip6 = ::a05:702; }
  interface:Trans3 = { ip6 = ::a05:801; }
}
network:Trans3 = { ip6 = ::a05:800/120; }
router:r2 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Trans3 = { ip6 = ::a05:802; hardware = Vlan20; }
  interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;
service:t1 = {
  user = any:[ip6=::a00:0/108 & network:n2],
         any:[ip6=::a00:0/109 & network:Trans1],
         any:[ip6=::a00:0/109 & network:Trans2],
  ;
  permit src = user; dst = network:Test; prt = tcp 81;
}
service:t2 = {
  user = any:[ip6=::a00:0/110 & network:n2],
         any:[ip6=::a00:0/110 & network:Trans1],
         network:Trans2,
  ;
  permit src = user; dst = network:Test; prt = tcp 82;
}
=END=
# Warning is sub optimal.
# Netspoc doesn't show original aggregate names.
=WARNING=
Warning: Duplicate elements in user of service:t1:
 - any:[ip6=::a00:0/109 & network:Trans1]
 - any:[ip6=::a00:0/109 & network:Trans1]
 - any:[ip6=::a00:0/109 & network:Trans1]
=OUTPUT=
-- ipv6/filter1
! VLAN1_in
access-list VLAN1_in extended permit tcp ::a00:0/108 ::a09:100/120 eq 81
access-list VLAN1_in extended permit tcp ::a00:0/110 ::a09:100/120 eq 82
access-list VLAN1_in extended deny ip any6 any6
access-group VLAN1_in in interface VLAN1
-- ipv6/filter2
! VLAN1_in
object-group network v6g0
 network-object ::a00:0/110
 network-object ::a05:700/120
access-list VLAN1_in extended permit tcp ::a00:0/108 ::a09:100/120 eq 81
access-list VLAN1_in extended permit tcp object-group v6g0 ::a09:100/120 eq 82
access-list VLAN1_in extended deny ip any6 any6
access-group VLAN1_in in interface VLAN1
-- ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a00:0/108 ::a09:100/120 eq 81
access-list n2_in extended permit tcp ::a00:0/110 ::a09:100/120 eq 82
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Correctly insert implicit aggregate
=INPUT=
router:a = {
 interface:n1_20_16;
 interface:n1_20_00;
 interface:n1_16;
}
network:n1_20_16 = { ip6 = ::a01:1000/117; subnet_of = network:n1_16; }
network:n1_20_00 = { ip6 = ::a01:0/116; subnet_of = network:n1_16; }
network:n1_16 = { ip6 = ::a01:0/112; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1_16 = { ip6 = ::a01:6301; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; subnet_of = network:n1_20_00; }
service:s1 = {
  user = any:[ip6=::a01:0/118 & network:n1_16];
  permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
  user = network:n1_20_00;
  permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s2:
  permit src=any:[ip6=::a01:0/118 & network:n1_20_16]; dst=network:n2; prt=tcp 80; of service:s1
< permit src=network:n1_20_00; dst=network:n2; prt=tcp 80; of service:s2
=END=

############################################################
=TITLE=Find subnet relation even with intermediate aggregates
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:0/112; host:h1 = { range6 = ::a01:100 - ::a01:1ff; } }
any:n1-17 = { ip6 = ::a01:0/113; link = network:n2; }
any:n1-20 = { ip6 = ::a01:0/116; link = network:n1; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:1; hardware = n2; }
}
=WARNING=
Warning: IP of host:h1 overlaps with subnet network:n1 in nat_domain:[network:n1]
Warning: network:n1 is subnet of network:n2
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Find subnet relation with duplicate networks and intermediate aggregate
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:0/112; nat:h2 = { hidden; } }
network:n3 = { ip6 = ::a01:0/112; nat:h3 = { hidden; } }
any:n1-20 = { ip6 = ::a01:0/116; link = network:n1; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; nat_out = h2; }
 interface:n2 = { ip6 = ::a01:1; hardware = n2; nat_out = h3; }
 interface:n3 = { ip6 = ::a01:1; hardware = n3; nat_out = h2; }
}
=WARNING=
Warning: network:n1 is subnet of network:n2
 in nat_domain:[network:n2].
 If desired, declare attribute 'subnet_of'
Warning: network:n1 is subnet of network:n3
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Check aggregate at unnumbered interface
=INPUT=
network:Test = { ip6 = ::a09:100/120; }
router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Trans = { unnumbered6; hardware = Vlan2; }
}
network:Trans = { unnumbered6; }
router:filter2 = {
 managed;
 model = ASA;
 interface:Trans = { unnumbered6; hardware = Vlan3; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan4; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test = {
 user = any:[network:Kunde];
 permit src = user; dst = network:Test; prt = tcp 80;
}
# if any:trans is defined, a rule must be present.
any:Trans = { link = network:Trans; }
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 Generated ACL at interface:filter1.Trans would permit access from additional networks:
 - any:Trans
 Either replace any:[network:Kunde] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Two warnings for split protocol with and without modifiers
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
protocol:ftp-passive-data = tcp 1024 - 65535, stateless;
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n3]; prt = tcp 21, protocol:ftp-passive-data;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n3]; prt=tcp 21; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n2
 Either replace any:[network:n3] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n3]; prt=protocol:ftp-passive-data; stateless of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n2
 Either replace any:[network:n3] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Ignore hidden network in supernet check (1)
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; nat:h = { hidden; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; nat_out = h; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n3]; prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n3]; prt=tcp 80; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n2
 Either replace any:[network:n3] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Ignore hidden network in supernet check (2)
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; nat:h = { hidden; } }
network:n4 = { ip6 = ::a01:380/121; subnet_of = network:n3; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; nat_out = h; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:381; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=ERROR=
Error: network:n3 is hidden by nat:h in rule
 permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Permit matching aggregate at non matching interface
=TEMPL=input
network:Test = { ip6 = ::a09:100/120; }
router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Trans = { ip6 = f000::c0a8:101; hardware = Vlan2; }
}
network:Trans = { ip6 = f000::c0a8:100/125; }
router:filter2 = {
 managed;
 model = ASA;
 interface:Trans = { ip6 = f000::c0a8:102; hardware = Vlan3; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan4; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test = {
 user = any:[ip6=::a00:0/104 & network:Kunde];
 permit src = user; dst = network:Test; prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
--ipv6/filter1
access-list Vlan2_in extended permit tcp ::a00:0/104 ::a09:100/120 eq 80
access-list Vlan2_in extended deny ip any6 any6
access-group Vlan2_in in interface Vlan2
--ipv6/filter2
access-list Vlan4_in extended permit tcp ::a00:0/104 ::a09:100/120 eq 80
access-list Vlan4_in extended deny ip any6 any6
access-group Vlan4_in in interface Vlan4
=END=

############################################################
=TITLE=Warn on missing src aggregate
=INPUT=
[[input]]
router:T = {
 interface:Trans = { ip6 = f000::c0a8:103; }
 interface:N1;
}
network:N1 = { ip6 = ::ac0:0/120; }
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[ip6=::a00:0/104 & network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 Generated ACL at interface:filter1.Trans would permit access from additional networks:
 - network:N1
 Either replace any:[ip6=::a00:0/104 & network:Kunde] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Warn on multiple missing networks
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n3a = { ip6 = ::a01:304/126; subnet_of = network:n3; }
network:n3b = { ip6 = ::a01:310/124; subnet_of = network:n3; }
network:n3c = { ip6 = ::a01:324/126; subnet_of = network:n3; }
network:n3d = { ip6 = ::a01:340/123; subnet_of = network:n3; }
network:n3e = { ip6 = ::a01:360/123; subnet_of = network:n3; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 interface:n2  = { ip6 = ::a01:202; }
 interface:n3a;
 interface:n3b;
 interface:n3c;
 interface:n3d;
 interface:n3e;
}
service:s1 = {
 user = network:n3;
 permit src = network:n1; dst = user; prt = icmpv6 8;
}
=INPUT=
[[input]]
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=network:n3; prt=icmpv6 8; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n3a
 - network:n3b
 - network:n3c
 - ...
 Either replace network:n3 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule
 or add any:[ ip6=::a01:300/120 & network:n3a ] to dst of rule.
=END=

############################################################
=TITLE=Warn on multiple missing networks with aggregate
=INPUT=
[[input]]
any:n3x = { ip6 = ::a01:300/120; link = network:n3a; }
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=network:n3; prt=icmpv6 8; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n3a
 - network:n3b
 - network:n3c
 - ...
 Either replace network:n3 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule
 or add any:n3x to dst of rule.
=END=

############################################################
=TITLE=No missing subnets
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n3a = { ip6 = ::a01:304/126; subnet_of = network:n3; }
network:n3b = { ip6 = ::a01:308/126; subnet_of = network:n3; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 interface:n2  = { ip6 = ::a01:202; }
 interface:n3a;
 interface:n3b;
}
service:s1 = {
 user = network:n3, network:n3a, network:n3b;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Larger intermediate aggregate
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
service:s1 = {
 user = any:[ ip6 = ::a00:0/104 & network:n1 ],
        any:[ network:n2 ];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a00:0/104 ::a01:300/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp any6 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=permit any between two interfaces, 1x no_in_acl
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; no_in_acl; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
protocol:oneway_IP = ip, oneway;
# Allow unfiltered communication between n2 and n3.
service:s1 = {
 user = any:[network:n2], any:[network:n3];
 permit src = user; dst = user; prt = protocol:oneway_IP;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any any
--
ipv6 access-list n1_out
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 permit ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 permit ipv6 any any
--
interface n3
 ipv6 address ::a01:301/120
 ipv6 traffic-filter n3_in in
=END=
# Don't generate outgoing ACL with single line "permit ip any any"

############################################################
=TITLE=Loop with no_in_acl and in_zone eq no_in_zone
=INPUT=
network:Test = { ip6 = ::a01:0/112; }
router:u = {
 interface:Test;
 interface:Trans1;
 interface:Trans2;
}
network:Trans1 = { ip6 = f000::c0a8:100/125; }
network:Trans2 = { ip6 = f000::c0a8:200/125; }
router:filter = {
 managed;
 model = ASA;
 routing = manual;
 interface:Trans1 = { ip6 = f000::c0a8:102; hardware = Vlan4; no_in_acl; }
 interface:Trans2 = { ip6 = f000::c0a8:202; hardware = Vlan5; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan6; }
 interface:sub = { ip6 = ::a01:121; hardware = Vlan7; }
}
network:Kunde = { ip6 = ::a01:100/120; subnet_of = network:Test; }
network:sub = { ip6 = ::a01:120/125; subnet_of = network:Kunde; }
service:test = {
 user = any:[network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=OUTPUT=
--ipv6/filter
access-list Vlan5_in extended permit tcp any6 ::a01:100/120 eq 80
access-list Vlan5_in extended deny ip any6 any6
access-group Vlan5_in in interface Vlan5
--ipv6/filter
access-list Vlan6_out extended permit tcp any6 ::a01:100/120 eq 80
access-list Vlan6_out extended deny ip any6 any6
access-group Vlan6_out out interface Vlan6
=END=

############################################################
=TITLE=Nested aggregates
=TEMPL=input
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Trans = { unnumbered6; hardware = Vlan2; }
}
network:Trans = { unnumbered6; }
router:u = {
 interface:Trans;
 interface:Kunde1;
 interface:Kunde2;
 interface:Kunde3;
}
network:Kunde1 = { ip6 = ::a01:100/120; }
network:Kunde2 = { ip6 = ::a01:200/120; }
network:Kunde3 = { ip6 = ::a01:300/120; }
service:test1 = {
 user = any:[ip6=::a01:0/119 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 80;
}
service:test2 = {
 user = any:[ip6=::a01:0/118 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 81;
}
=INPUT=[[input]]
=OUTPUT=
--ipv6/filter
access-list Vlan2_in extended permit tcp ::a01:0/119 ::a09:100/120 eq 80
access-list Vlan2_in extended permit tcp ::a01:0/118 ::a09:100/120 eq 81
access-list Vlan2_in extended deny ip any6 any6
access-group Vlan2_in in interface Vlan2
=END=

############################################################
=TITLE=Redundant nested aggregates
=INPUT=
[[input]]
service:test3 = {
 user = any:[ip6=::a01:0/112 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test1 compared to service:test3:
  permit src=any:[ip6=::a01:0/119 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test1
< permit src=any:[ip6=::a01:0/112 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test3
=END=

############################################################
=TITLE=Prevent nondeterminism in nested aggregates
# /23 aggregates must be processed in fixed order.
# Otherwise network:[any:[ip6=::a01:0/113..] would be nondeterministic.
=INPUT=
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Trans = { unnumbered6; hardware = Vlan2; }
}
network:Trans = { unnumbered6; }
router:u = {
 interface:Trans;
 interface:Kunde1;
 interface:Kunde2;
}
network:Kunde1 = { ip6 = ::a01:0/120; }
network:Kunde2 = { ip6 = ::a01:200/120; }
service:test1a = {
 user = network:[any:[ip6=::a01:0/119 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 80;
}
service:test1b = {
 user = network:[any:[ip6=::a01:200/119 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 81;
}
service:test2 = {
 user = network:[any:[ip6=::a01:0/113 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 82;
}
=OUTPUT=
--ipv6/filter
access-list Vlan2_in extended permit tcp ::a01:0/120 ::a09:100/120 eq 80
access-list Vlan2_in extended permit tcp ::a01:0/120 ::a09:100/120 eq 82
access-list Vlan2_in extended permit tcp ::a01:200/120 ::a09:100/120 range 81 82
access-list Vlan2_in extended deny ip any6 any6
access-group Vlan2_in in interface Vlan2
=END=

############################################################
=TITLE=Redundant nested aggregates without matching network (1)
# Larger aggregate is inserted first.
=INPUT=
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan2; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test = {
 user = any:[ip6=::a01:0/112 & network:Test],
        any:[ip6=::a01:0/113 & network:Test],
        ;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=any:[ip6=::a01:0/113 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip6=::a01:0/112 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Redundant nested aggregates without matching network (2)
# Small aggregate is inserted first.
=INPUT=
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan2; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test = {
 user = any:[ip6=::a01:0/113 & network:Test],
        any:[ip6=::a01:0/112 & network:Test],
        ;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=any:[ip6=::a01:0/113 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip6=::a01:0/112 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Redundant matching aggregates as subnet of network
=INPUT=
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan2; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test1 = {
 user = any:[ip6=::a09:100/122 & network:Test],
        network:Test;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
service:test2 = {
 user = any:[ip6=::a09:100/121 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test1 compared to service:test1:
  permit src=any:[ip6=::a09:100/122 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=network:Test; dst=network:Kunde; prt=tcp 80; of service:test1
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=any:[ip6=::a09:100/122 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip6=::a09:100/121 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
Warning: Redundant rules in service:test2 compared to service:test1:
  permit src=any:[ip6=::a09:100/121 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
< permit src=network:Test; dst=network:Kunde; prt=tcp 80; of service:test1
=END=

############################################################
=TITLE=Mixed redundant matching aggregates
# Check for sub aggregate, even if sub-network was found
=INPUT=
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan2; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test1 = {
 user = any:[ip6=::a01:100/122 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
service:test2 = {
 user = any:[ip6=::a00:0/104 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=any:[ip6=::a01:100/122 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip6=::a00:0/104 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
=END=

############################################################
=TITLE=Mixed implicit and explicit aggregates
=INPUT=
any:10_0_0_0    = { ip6 = ::a00:0/104;    link = network:Test; }
any:10_253_0_0  = { ip6 = ::afd:0/112; link = network:Test; }
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan2; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test1 = {
 user = any:[network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=OUTPUT=
--ipv6/filter
access-list Vlan1_in extended permit tcp any6 ::a01:100/120 eq 80
access-list Vlan1_in extended deny ip any6 any6
access-group Vlan1_in in interface Vlan1
=END=

############################################################
=TITLE=Matching aggregate of implicit aggregate
=INPUT=
network:Test = { ip6 = ::a09:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip6 = ::a09:101; hardware = Vlan1; }
 interface:Kunde = { ip6 = ::a01:101; hardware = Vlan2; }
}
network:Kunde = { ip6 = ::a01:100/120; }
service:test = {
 user = any:[ip6=::a01:0/112 & any:[network:Test]];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=OUTPUT=
--ipv6/filter
access-list Vlan1_in extended permit tcp ::a01:0/112 ::a01:100/120 eq 80
access-list Vlan1_in extended deny ip any6 any6
access-group Vlan1_in in interface Vlan1
=END=

############################################################
=TITLE=Implicitly remove aggregate of loopback interface
=INPUT=
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:loop = { ip6 = ::a07:707; loopback; hardware = lo1; }
 interface:Customer = { ip6 = ::a09:901; hardware = VLAN2; no_in_acl; }
}
network:Customer = { ip6 = ::a09:900/120; }
service:test = {
 user = any:[interface:filter.[all]] &! any:[network:Customer];
 permit src = network:Customer; dst = user; prt = tcp 22;
}
=WARNING=
Warning: Empty intersection in user of service:test:
any:[..]
&! any:[..]
=END=

############################################################
=TITLE=Implicitly remove aggregate of loopback interface from area
=INPUT=
network:Trans = { ip6 = ::a01:100/120; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip6 = ::a01:101; hardware = VLAN1; }
 interface:loop = { ip6 = ::a07:707; loopback; hardware = lo1; }
 interface:Customer = { ip6 = ::a09:901; hardware = VLAN2; no_in_acl; }
}
network:Customer = { ip6 = ::a09:900/120; }
area:n1-lo = {
 inclusive_border = interface:filter.Customer;
}
service:test = {
 user = any:[area:n1-lo] &! any:[network:Trans];
 permit src = network:Customer; dst = user; prt = tcp 22;
}
=WARNING=
Warning: Empty intersection in user of service:test:
any:[..]
&! any:[..]
=END=

############################################################
=TITLE=Implicitly remove loopback network
=INPUT=
network:Trans = { ip6 = ::a01:100/120; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip6 = ::a01:101; hardware = VLAN1; }
 interface:loop = { ip6 = ::a07:707; loopback; hardware = lo1; }
 interface:Customer = { ip6 = ::a09:901; hardware = VLAN2; }
}
network:Customer = { ip6 = ::a09:900/120; }
service:test = {
 user = network:[interface:filter.[all]] &! network:Customer;
 permit src = network:Customer; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/filter
ipv6 access-list VLAN2_in
 deny ipv6 any host ::a01:101
 permit tcp ::a09:900/120 ::a01:100/120 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Multiple missing destination networks at one router
=TEMPL=topo
network:Customer = { ip6 = ::a09:900/120; }
router:r1 = {
 managed;
 model = {{.mod}};
 routing = manual;
 interface:Customer = { ip6 = ::a09:901; hardware = VLAN9; }
 interface:trans = { ip6 = ::a07:701; hardware = VLAN7; }
 interface:loop = { ip6 = ::a07:801; loopback; hardware = Lo1; }
}
network:trans = { ip6 = ::a07:700/120; }
router:r2 = {
 managed;
 model = {{.mod}};
 routing = manual;
 interface:trans = { ip6 = ::a07:702; hardware = VLAN77; }
 interface:n1 = { ip6 = ::a01:101; hardware = VLAN1; {{.no}}}
 interface:n2 = { ip6 = ::a01:201, ::a01:202; hardware = VLAN2; }
 interface:n3 = { ip6 = ::a01:301; hardware = VLAN3; }
 interface:n4 = { ip6 = ::a01:401; hardware = VLAN4; }
 interface:n128 = { ip6 = ::a80:101; hardware = VLAN128; }
}
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n128 = { ip6 = ::a80:100/120; }
=INPUT=
[[topo {no: "", mod: "IOS, FW"}]]
service:test = {
 user = #network:trans,
        any:[ip6=::a00:0/105 & network:n1],
        #any:[ip6=::a01:0/113 & network:n2],
        #network:n3,
        #any:[ip6=::a01:0/112 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip6=::a00:0/105 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r1.Customer would permit access to additional networks:
 - network:trans
 Either replace any:[ip6=::a00:0/105 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip6=::a00:0/105 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n2
 Either replace any:[ip6=::a00:0/105 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip6=::a00:0/105 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n3
 Either replace any:[ip6=::a00:0/105 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip6=::a00:0/105 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n4
 Either replace any:[ip6=::a00:0/105 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Multiple missing destination networks
=INPUT=
[[topo {no: "", mod: "IOS, FW"}]]
router:u = {
 interface:n2;
 interface:n2x;
}
network:n2x = { ip6 = ::a02:200/120; }
service:test = {
 user = network:trans,
        any:[ip6=::a00:0/105 & network:n1],
        #any:[ip6=::a01:0/113 & network:n2],
        network:n3,
        any:[ip6=::a01:0/112 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip6=::a00:0/105 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n2
 - network:n2x
 Either replace any:[ip6=::a00:0/105 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip6=::a01:0/112 & network:n4]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n2
 Either replace any:[ip6=::a01:0/112 & network:n4] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Warn on all missing networks of zone cluster
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n4]; prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n4]; prt=tcp 80; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n2
 Either replace any:[network:n4] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n4]; prt=tcp 80; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n3
 Either replace any:[network:n4] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Multiple destination aggregates
=INPUT=
[[topo {no: "", mod: "IOS, FW"}]]
service:test = {
 user = network:trans,
        any:[ip6=::a00:0/105 & network:n1],
        any:[ip6=::a00:0/105 & network:n2],
        network:n3,
        any:[ip6=::a00:0/105 & network:n4],
        # network:n128 doesn't match
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list VLAN9_in
 deny ipv6 any host ::a09:901
 deny ipv6 any host ::a07:701
 deny ipv6 any host ::a07:801
 permit ipv6 ::a09:900/120 ::a00:0/105
 deny ipv6 any any
--ipv6/r2
ipv6 access-list VLAN77_in
 deny ipv6 any host ::a07:702
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 deny ipv6 any host ::a01:401
 deny ipv6 any host ::a01:202
 permit ipv6 ::a09:900/120 ::a00:0/105
 deny ipv6 any any
=END=

############################################################
=TITLE=Check destination aggregate with no_in_acl
# Wir wissen nicht, welches der beiden Aggregate genommen wird,
# wegen der Optimierung in check_supernet_dst_collections.
# Aber dennoch wird korrekt geprüft.
# Wenn n1, dann ohne Prüfung, da an allen anderen Interfaces eine out_acl.
# Wenn n2, dann erfolgreiche Prüfung auf n1.
=INPUT=
[[topo {no: "no_in_acl;", mod: "IOS, FW"}]]
service:test = {
 user = network:trans,
        any:[ip6=::a00:0/105 & network:n1],
        any:[ip6=::a00:0/105 & network:n2],
        #network:n3,
        #any:[ip6=::a01:0/112 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=OUTPUT=
--ipv6/r2
ipv6 access-list VLAN77_in
 deny ipv6 any host ::a07:702
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 deny ipv6 any host ::a01:401
 deny ipv6 any host ::a01:202
 permit ipv6 ::a09:900/120 ::a00:0/105
 deny ipv6 any any
--ipv6/r2
ipv6 access-list VLAN1_in
 deny ipv6 any host ::a07:702
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 deny ipv6 any host ::a01:401
 deny ipv6 any host ::a80:101
 deny ipv6 any host ::a01:202
 permit ipv6 any any
--ipv6/r2
ipv6 access-list VLAN2_out
 permit ipv6 ::a09:900/120 ::a00:0/105
 deny ipv6 any any
=END=

############################################################
=TITLE=Check missing intermediate aggregate for Linux
# Linux only checks for missing intermediate aggregates,
# because filter is attached to pair of incoming and outgoing interface.
=INPUT=
[[topo {no: "", mod: "Linux"}]]
service:test = {
 user = any:[ip6=::a00:0/105 & network:n1],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip6=::a00:0/105 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r1.Customer would permit access to additional networks:
 - network:trans
 Either replace any:[ip6=::a00:0/105 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=No destination aggregate needed for Linux
# Linux only checks for missing intermediate aggregates,
# because filter is attached to pair of incoming and outgoing interface.
=INPUT=
[[topo {no: "", mod: "Linux"}]]
service:test = {
 user = network:trans,
        any:[ip6=::a00:0/105 & network:n1],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=OUTPUT=
--ipv6/r2
:VLAN77_VLAN1 -
-A VLAN77_VLAN1 -j ACCEPT -s ::a09:900/120 -d ::a00:0/105
-A FORWARD -j VLAN77_VLAN1 -i VLAN77 -o VLAN1
=END=

############################################################
=TITLE=Missing destination aggregate with loopback
=INPUT=
network:Customer = { ip6 = ::a09:900/120; }
router:r = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Customer = { ip6 = ::a09:901; hardware = VLAN9; }
 interface:n1 = { ip6 = ::a01:101; hardware = N1; }
 interface:n2 = { ip6 = ::a01:201; hardware = N2; }
}
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:u = {
 interface:n2;
 interface:l = { ip6 = ::a02:202; loopback; }
}
service:test = {
 user = any:[network:n1];
 permit src = network:Customer; dst = user; prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[network:n1]; prt=tcp 80; of service:test
 Generated ACL at interface:r.Customer would permit access to additional networks:
 - network:n2
 - interface:u.l
 Either replace any:[network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Check aggregate that is subnet of other network
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:trans = { ip6 = ::a03:111; hardware = trans; }
 interface:sub-27 = { ip6 = ::a01:221; hardware = sub-27; }
}
network:sub-27 = { ip6 = ::a01:220/123; subnet_of = network:n2; }
network:trans = { ip6 = ::a03:110/126; }
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip6 = ::a03:112; hardware = trans; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:u = {
 interface:n2;
 interface:sub-29;
}
any:sub-28 =     { ip6 = ::a01:230/124; link = network:n2; }
network:sub-29 = { ip6 = ::a01:230/125; subnet_of = network:sub-27; }
# Warning is shown, because some addresses of any:sub-28 are located
# inside network:sub-27.
# Hence also check larger networks since supernet is aggregate.
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:sub-28; prt = tcp 80;
}
# Show warning, same reasoning as for any:sub-28,
# but only check smaller subnets.
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 82;
}
# No warning, because we know that addresses of network:sub-29
# are located behind router:r2 and not inside network:sub-27.
service:s3 = {
 user = network:n1;
 permit src = user; dst = network:sub-29; prt = tcp 81;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:sub-28; prt=tcp 80; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:sub-27
 Either replace any:sub-28 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=network:n2; prt=tcp 82; of service:s2
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:sub-27
 Either replace network:n2 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Also check aggregate that is subnet of subnet in other zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:trans = { ip6 = ::a03:111; hardware = trans; }
 interface:sub-27 = { ip6 = ::a01:221; hardware = sub-27; }
}
network:sub-27 = { ip6 = ::a01:220/123; subnet_of = network:n2; }
network:trans = { ip6 = ::a03:110/126; }
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip6 = ::a03:112; hardware = trans; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:u = {
 interface:n2;
 interface:sub-28;
}
network:sub-28 = { ip6 = ::a01:230/124; subnet_of = network:sub-27; }
any:sub-29 =     { ip6 = ::a01:230/125; link = network:n2; }
# We could analyze, that addresses of any:sub-29 are located inside
# network:sub-28 and not inside network:sub-27, and hence show no
# warning. But this analysis is not implemented because it is too expensive.
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:sub-29; prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:sub-29; prt=tcp 80; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:sub-27
 Either replace any:sub-29 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Mark duplicate identical networks as supernet of aggregate
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; nat:n1 = { ip6 = ::101:100/120; } }
network:n4 = { ip6 = ::a01:100/120; nat:n4 = { ip6 = ::201:100/120; } }
any:Sub2 = { ip6 = ::a01:100/120; link = network:n2; }
any:Sub3 = { ip6 = ::a01:100/120; link = network:n3; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:t1 = { ip6 = ::a09:100/120; }
network:t2 = { ip6 = ::a09:200/120; }
network:t3 = { ip6 = ::a09:300/120; }
network:t4 = { ip6 = ::a09:400/120; }

router:r1 = {
 interface:n1 = { ip6 = ::a01:101; hardware = n1; nat_out = n4; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; nat_out = n4; }
 interface:t3 = { ip6 = ::a09:301; hardware = t3; nat_out = n1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:t1 = { ip6 = ::a09:102; hardware = t1; }
 interface:t2 = { ip6 = ::a09:202; hardware = t2; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:t3 = { ip6 = ::a09:302; hardware = t3; }
 interface:t4 = { ip6 = ::a09:402; hardware = t4; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
router:r4 = {
 interface:t2 = { ip6 = ::a09:201; hardware = t2; nat_out = n4; }
 interface:t4 = { ip6 = ::a09:401; hardware = t4; nat_out = n1; }
 interface:n4 = { ip6 = ::a01:101; hardware = n1; nat_out = n1; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
 permit src = network:n4; dst = user; prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=network:n4; prt=tcp 80; of service:s1
 Generated ACL at interface:r3.t3 would permit access to additional networks:
 - any:Sub3
 Either replace network:n4 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n4; dst=network:n1; prt=tcp 80; of service:s1
 Generated ACL at interface:r2.t2 would permit access to additional networks:
 - any:Sub2
 Either replace network:n1 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Don't check supernet of supernet.
=INPUT=
network:n1 = { ip6 = ::a01:0/112; }
network:n2 = { ip6 = ::a01:0/119; subnet_of = network:n1; }
network:n3 = { ip6 = ::a02:100/120; }
network:inet = { ip6 = ::/0; has_subnets; }
network:n4 = { ip6 = ::101:108/125; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:801; hardware = n1; }
 interface:n2 = { ip6 = ::a01:1; hardware = n2; }
 interface:n3 = { ip6 = ::a02:101; hardware = n3; }
}

router:r2 = {
 interface:n3 = { ip6 = ::a02:102; }
 interface:inet;
}

router:r3 = {
 model = IOS, FW;
 managed;
 routing = manual;
 interface:inet = { negotiated6; hardware = inet; }
 interface:n4 = { ip6 = ::101:109; hardware = n4; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 81;
}
=WARNING=NONE

############################################################
=TITLE=Ignore intermediate aggregate from empty automatic group
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a03:300/120; }
area:n2 = { border = interface:r1.n2; }
area:n3 = { border = interface:r1.n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a03:301; hardware = n3; }
}
service:s1 = {
 user = any:[ip6 = ::a01:0/112 & area:n2],
        # This automatic group is empty.
        network:[any:[ip6 = ::a01:0/112 & area:n3]],
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 3000;
}
=WARNING=NONE

############################################################
=TITLE=Ignore intermediate aggregate from automatic group
# Must not show warning on missing any:[ip6=::a01:0/112 & network:n3],
# because it is only used intermediately in automatic group.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a03:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
area:n2 = { border = interface:r1.n2; }
area:n3 = { border = interface:r1.n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a03:301; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
 interface:n5;
}
service:s1 = {
 user = any:[ip6 = ::a01:0/112 & area:n2],
        network:[any:[ip6 = ::a01:0/112 & area:n3]],
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 3000;
}
=WARNING=NONE

############################################################
=TITLE=Ignore aggregate if all its networks are added
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a03:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
any:n3_10_1 = { ip6 = ::a01:0/112; link = network:n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a03:301; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
 interface:n5;
}
service:s1 = {
 user = any:[ip6 = ::a01:0/112 & network:n2],
        network:n4, network:n5,
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 3000;
}
=WARNING=NONE

############################################################
=TITLE=One network is missing from aggregate
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a03:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
any:n3_10_1 = { ip6 = ::a01:0/112; link = network:n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a03:301; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
 interface:n5;
}
service:s1 = {
 user = any:[ip6 = ::a01:0/112 & network:n2],
        network:n4,
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 3000;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[ip6=::a01:0/112 & network:n2]; prt=tcp 3000; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n5
 Either replace any:[ip6=::a01:0/112 & network:n2] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule
 or add any:n3_10_1 to dst of rule.
=END=

############################################################
=TITLE=Missing destination networks in loop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:t1 = { ip6 = ::a07:101; hardware = t1; }
 interface:t2 = { ip6 = ::a07:201; hardware = t2; }
}
network:t1 = { ip6 = ::a07:100/120; }
network:t2 = { ip6 = ::a07:200/120; }
router:u = {
 interface:t1;
 interface:t3;
 interface:t2;
 interface:t4;
}
network:t3 = { ip6 = ::a07:300/120; }
network:t4 = { ip6 = ::a07:400/120; }
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t3 = { ip6 = ::a07:302; hardware = t3; }
 interface:t4 = { ip6 = ::a07:402; hardware = t4; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
pathrestriction:p1 =
 interface:r1.t2,
 interface:u.t4,
;
pathrestriction:p2 =
 interface:u.t1,
 interface:r2.t3,
;
service:test = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = udp 123;
}
=END=
# TODO:
# First warning should show missing networks t1, t2, t3 and t4.
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n2]; prt=udp 123; of service:test
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:t1
 Either replace any:[network:n2] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n2]; prt=udp 123; of service:test
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:t2
 - network:t3
 Either replace any:[network:n2] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n2]; prt=udp 123; of service:test
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:t4
 Either replace any:[network:n2] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[network:n2]; prt=udp 123; of service:test
 Generated ACL at interface:r2.t4 would permit access to additional networks:
 - network:n3
 Either replace any:[network:n2] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Missing aggregate from unmanaged interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:u = {
 interface:n2 = { ip6 = ::a01:202; }
 interface:n3 = { ip6 = ::a01:301; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
pathrestriction:p = interface:u.n2, interface:r2.n4;
service:s1 = {
 user = interface:u.n2;
 permit src = user; dst = any:[network:n1]; prt = tcp 22;
}
service:s2 = {
 user = interface:u.n3;
 permit src = user; dst = any:[network:n1]; prt = tcp 23;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=interface:u.n3; dst=any:[network:n1]; prt=tcp 23; of service:s2
 Generated ACL at interface:r3.n3 would permit access to additional networks:
 - network:n4
 Either replace any:[network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 permit tcp host ::a01:202 any eq 22
 permit tcp host ::a01:301 any eq 23
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n4_in
 deny ipv6 any host ::a01:102
 deny ipv6 any host ::a01:401
 permit tcp host ::a01:301 any eq 23
 deny ipv6 any any
--ipv6/r3
ipv6 access-list n3_in
 deny ipv6 any host ::a01:302
 deny ipv6 any host ::a01:402
 permit tcp host ::a01:301 any eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Missing aggregate at destination interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:test = {
 user = any:[ ip6 = ::a00:0/104 & network:n1 ];
 permit src = user; dst = interface:r2.n3; prt = udp 123;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[ip6=::a00:0/104 & network:n1]; dst=interface:r2.n3; prt=udp 123; of service:test
 Generated ACL at interface:r2.n3 would permit access from additional networks:
 - network:n3
 Either replace any:[ip6=::a00:0/104 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Missing aggregates for reverse rule
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS{{.fw1}};
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:trans = { ip6 = ::a07:701; hardware = trans; }
 interface:loop = { ip6 = ::a07:801; loopback; hardware = Lo1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:trans = { ip6 = ::a07:700/120; }
router:r2 = {
 managed;
 model = IOS{{.fw2}};
 routing = manual;
 interface:trans = { ip6 = ::a07:702; hardware = trans; }
 interface:n3 = { ip6 = ::a01:301, ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
service:test = {
 user = any:[ ip6 = ::a00:0/104 & network:n1 ],
        network:trans,
 ;
 permit src = user; dst = network:n4; prt = udp 123;
}
=INPUT=[[input {fw1: "", fw2: ""}]]
=WARNING=
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip6=::a00:0/104 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 Generated ACL at interface:r1.trans would permit access to additional networks:
 - network:n2
 Either replace any:[ip6=::a00:0/104 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip6=::a00:0/104 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 Generated ACL at interface:r2.n4 would permit access to additional networks:
 - network:n3
 Either replace any:[ip6=::a00:0/104 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Effect of stateful router in reversed direction
# router:r1 sees only reply packets filtered by stateful router:r2
# Hence no warning is shown.
=INPUT=[[input {fw1: "", fw2: ", FW"}]]
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit udp ::a00:0/104 ::a01:400/120 eq 123
 deny ipv6 any any
--
ipv6 access-list trans_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a07:701
 deny ipv6 any host ::a07:801
 deny ipv6 any host ::a01:201
 permit udp ::a01:400/120 eq 123 ::a00:0/104
 deny ipv6 any any
=END=

############################################################
=TITLE=No effect of stateful router in forward direction
=INPUT=[[input {fw1: ", FW", fw2: ""}]]
=WARNING=
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip6=::a00:0/104 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 Generated ACL at interface:r2.n4 would permit access to additional networks:
 - network:n3
 Either replace any:[ip6=::a00:0/104 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Must not check source zone in reverse rule
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:u = {
 interface:n1;
 interface:n2;
}
pathrestriction:p =
 interface:u.n2,
 interface:r1.n2,
;
service:test = {
 user = any:[ ip6 = ::a00:0/104 & network:n1 ];
 permit src = user; dst = network:n3; prt = udp 123;
}
=WARNING=NONE

############################################################
=TITLE=Managed router will not exploit reverse rule
# Reverse rule at router:r1 would allow router:r2 to access network:n2.
# But since r2 is managed, we assume it will not exploit this permission.
# Hence no warning is printed.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed = secondary;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:test = {
 user = any:[ ip6 = ::a00:0/104 & network:n1 ],
        network:n3,
 ;
 permit src = user; dst = interface:r2.n3; prt = udp 123;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n3_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 permit udp host ::a01:302 eq 123 ::a00:0/104
 deny ipv6 any any
-- ipv6/r2
ipv6 access-list n3_in
 permit udp ::a00:0/104 host ::a01:302 eq 123
 deny ipv6 any any
=END=

############################################################
=TITLE=Supernet rule to pathrestricted interface and no_in_acl
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401, ::a01:402; hardware = n4; no_in_acl; }
}
router:u = {
 interface:n2 = { ip6 = ::a01:203; }
}
pathrestriction:p =
 interface:r1.n2,
 interface:u.n2,
;
service:test = {
 user = any:[ network:n1 ];
 permit src = user; dst = interface:u.n2; prt = udp 123;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[network:n1]; dst=interface:u.n2; prt=udp 123; of service:test
 Generated ACL at interface:r3.n4 would permit access from additional networks:
 - network:n4
 Either replace any:[network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=any:[network:n1]; dst=interface:u.n2; prt=udp 123; of service:test
 Generated ACL at interface:r3.n3 would permit access from additional networks:
 - network:n3
 Either replace any:[network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=OUTPUT=
-- ipv6/r3
ipv6 access-list n2_out
 permit udp any host ::a01:203 eq 123
 deny ipv6 any any
--
ipv6 access-list n3_in
 permit udp any host ::a01:203 eq 123
 deny ipv6 any any
--
ipv6 access-list n4_in
 deny ipv6 any host ::a01:202
 deny ipv6 any host ::a01:302
 deny ipv6 any host ::a01:401
 deny ipv6 any host ::a01:402
 permit ipv6 any any
=END=

############################################################
=TITLE=Supernet rule to dst at no_in_acl
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; no_in_acl; }
}
service:test = {
 user = any:[ network:n1 ];
 permit src = user; dst = network:n3; prt = udp 123;
}
=WARNING=NONE

############################################################
=TITLE=Supernet rule to dst not directly behind no_in_acl
# Must show warning for router:r1, not router:r2.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
any:n2-10_1_3 = { ip6 = ::a01:300/120; link = network:n2; }
network:n3 = { ip6 = ::a01:300/120; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; no_in_acl; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3;}
}

service:s1 = {
 user = network:n3;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n3; dst=network:n1; prt=tcp 80; of service:s1
 Generated ACL at interface:r1.n2 would permit access from additional networks:
 - any:n2-10_1_3
 Either replace network:n3 by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Rule from supernet at no_in_acl
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; no_in_acl; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:test = {
 user = any:[ network:n1 ];
 permit src = user; dst = network:n3; prt = udp 123;
}
=WARNING=NONE

############################################################
=TITLE=Missing aggregate for reverse rule in loop
# Don't find network:t1 and network:t2 as missing,
# because both are located in same zone_cluster as dst.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:t1 = { ip6 = ::a07:101; hardware = t1; }
 interface:t2 = { ip6 = ::a07:201; hardware = t2; }
}
network:t1 = { ip6 = ::a07:100/120; }
network:t2 = { ip6 = ::a07:200/120; }
# router:u is split internally and hence interface:u.n4
# no longer has pathrestriction.
# We have this extra test case for this special situation.
router:u = {
 interface:t1;
 interface:t2;
 interface:n3;
 interface:n4 = { ip6 = ::a01:401; }
}
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
pathrestriction:p =
 interface:r.t2,
 interface:u.n4,
;
service:test = {
 user = any:[ ip6 = ::a00:0/104 & network:n1 ];
 permit src = user; dst = interface:u.n4; prt = udp 123;
}
=WARNING=
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip6=::a00:0/104 & network:n1]; dst=interface:u.n4; prt=udp 123; of service:test
 Generated ACL at interface:r.t1 would permit access to additional networks:
 - network:n2
 Either replace any:[ip6=::a00:0/104 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Suppress warning about missing aggregate rule
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120; }
network:sub = { ip6 = ::a01:180/121; subnet_of = network:n1;
{{.hosts}}
}
router:u = {
 interface:n1;
 interface:sub;
 interface:t;
 {{.interfaces}}
}
network:t = { ip6 = ::a09:200/120; }
any:t = {
 link = network:t;
 no_check_supernet_rules;
}
network:n2 = { ip6 = ::a01:200/120; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:t = { ip6 = ::a09:201; hardware = t; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n3 = { ip6 = ::a01:300/120; }
service:s = {
 user = any:[ ip6 = ::a01:0/112 & network:n2 ];
 permit src = network:n3; dst = user; prt = tcp 80;
}
=INPUT=
[[input
hosts: ""
interfaces: ""
]]
=WARNING=NONE

############################################################
=TITLE=Must not use no_check_supernet_rules with hosts
=INPUT=
[[input
hosts: "host:h = { ip6 = ::a01:182; }"
interfaces: "interface:lo = { ip6 = ::a09:901; loopback; }
interface:vip = { ip6 = ::a09:902; vip; }"
]]
=ERROR=
Error: Must not use attribute 'no_check_supernet_rules' at any:[network:t]
 with networks having host definitions:
 - network:sub
Error: Must not use attribute 'no_check_supernet_rules' at any:[network:t]
 having loopback/vip interfaces:
 - interface:u.lo
 - interface:u.vip
=END=

############################################################
=TITLE=No warning on aggregate in zone cluster of src
=INPUT=
network:n1 = { ip6 = ::a01:0/112; }
network:n1sub = { ip6 = ::a01:400/120; subnet_of = network:n1; }
network:n2 = { ip6 = ::a02:200/120; }
network:n3 = { ip6 = ::a02:300/120; }
network:n4 = { ip6 = ::a02:400/120; }
router:u1 = {
 interface:n1sub;
 interface:n1;
}
router:u2 = {
 interface:n1;
 interface:n2;
}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip6 = ::a02:201; hardware = n2; }
 interface:n3 = { ip6 = ::a02:301; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a02:302; hardware = n3; }
 interface:n4 = { ip6 = ::a02:402; hardware = n4; }
}
pathrestriction:p1 =
 interface:u2.n2,
 interface:r2.n1,
 interface:r2.n3,
;
# This implicitly creates aggregate at zone of n2.
service:s1 = {
 user = network:n4;
 permit src = user; dst = any:[ip6=::a01:0/112 & network:n1sub]; prt = tcp 80;
}
# Must not show warning on implicit aggregate, because it is located
# in same zone cluster as n1.
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = ip;
}
=OUTPUT=
-- ipv6/r1
! n2_in
access-list n2_in extended permit ip ::a01:0/112 ::a02:300/120
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp ::a02:400/120 ::a01:0/112 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=No warning on subnet in zone cluster of src/dst
=INPUT=
network:n1 = { ip6 = ::a01:0/112; }
network:n2 = { ip6 = ::a01:200/120; subnet_of = network:n1; }
network:n3 = { ip6 = ::a01:300/120; subnet_of = network:n1; }
network:n4 = { ip6 = ::a02:400/120; }
router:u1 = {
 interface:n1;
 interface:n2;
}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a02:402; hardware = n4; }
}
router:r3 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:1; hardware = n1; }
 interface:n4 = { ip6 = ::a02:401; hardware = n4; }
}
pathrestriction:p1 =
 interface:u1.n2,
 interface:r3.n1,
 interface:r3.n4,
;
# Must show warning for subnet n3, but not for subnet n2,
# because n2 is located in same zone cluster as n1.
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = ip;
 permit src = network:n4; dst = user; prt = ip;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=network:n4; prt=ip; of service:s1
 Generated ACL at interface:r2.n3 would permit access from additional networks:
 - network:n3
 Either replace network:n1 by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:n4; dst=network:n1; prt=ip; of service:s1
 Generated ACL at interface:r2.n4 would permit access to additional networks:
 - network:n3
 Either replace network:n1 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Missing transient rule with multiple protocols
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = icmpv6 3, tcp 81-85;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = icmpv6 4/4, tcp 80-90;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - host:h3
=END=

############################################################
=TITLE=Missing transient rule with ICMP type
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1a = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = icmpv6 3/13;
}
service:s1b = {
 user = host:h1;
 permit src = user; dst = any:[network:n2]; prt = icmpv6 3;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = icmpv6 3/13;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1a and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1a:
 - host:h3
Warning: Missing transient supernet rules
 between src of service:s1b and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - host:h1
 or add missing dst elements to service:s1b:
 - host:h3
=END=

############################################################
=TITLE=Missing transient rule with source port
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
protocol:ntp = udp 123:123;
protocol:ntp2 = udp 124:123;
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = protocol:ntp;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = udp 123-124;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - host:h3
=END=

############################################################
=TITLE=No missing transient rule with non matching source port
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
protocol:ntp = udp 123:123;
protocol:ntp2 = udp 124:123;
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = protocol:ntp;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = protocol:ntp2;
}
=WARNING=NONE

############################################################
=TITLE=Don't show missing transient rule for s2.dst in zone of s1.src
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:h1a = { ip6 = ::a01:10a; }
 host:h1b = { ip6 = ::a01:10b; }
}
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120;
 host:h3a = { ip6 = ::a01:30a; }
 host:h3b = { ip6 = ::a01:30b; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = tcp 80;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h1b, host:h3b; prt = tcp 80;
}
service:s3 = {
 user = host:h1a, host:h3a;
 permit src = user; dst = any:[network:n2]; prt = tcp 81;
}
service:s4 = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 81;
}
service:s5 = {
 user = host:h1a, host:h3a;
 permit src = user; dst = any:[network:n2]; prt = tcp 82;
}
service:s6 = {
 user = any:[network:n2];
 permit src = user; dst = host:h1b, host:h3b; prt = tcp 82;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - host:h3b
Warning: Missing transient supernet rules
 between src of service:s3 and dst of service:s4,
 matching at any:[network:n2].
 Add missing src elements to service:s4:
 - host:h1a
 or add missing dst elements to service:s3:
 - network:n3
Warning: Missing transient supernet rules
 between src of service:s5 and dst of service:s6,
 matching at any:[network:n2].
 Add missing src elements to service:s6:
 - host:h1a
 - host:h3a
 or add missing dst elements to service:s5:
 - host:h1b
 - host:h3b
=END=

############################################################
=TITLE=Missing transient rule with any + NAT
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/123;
 nat:n3 = { ip6 = ::a01:220/123; subnet_of = network:n2; }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; nat_out = n3; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = udp 123;
}
service:s2 = {
 user = any:[ip6=::a00:0/104 & network:n2];
 permit src = user; dst = network:n3; prt = ip;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at network:n2, any:[ip6=::a00:0/104 & network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - network:n3
=END=

############################################################
=TITLE=Missing transient rule, s1.dst has subnets, s2.dst does match
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[ip6=::a01:200/119 & network:n2]; prt = udp 123;
}
service:s2 = {
 user = any:[ip6=::a00:0/104 & network:n2];
 permit src = user; dst = network:n3; prt = udp;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[ip6=::a01:200/119 & network:n2], any:[ip6=::a00:0/104 & network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - network:n3
=END=

############################################################
=TITLE=No missing transient rule: supernet doesn't match
=INPUT=
network:n1 = { ip6 = ::a01:0/118; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
 interface:n5 = { ip6 = ::a01:502; hardware = n5; }
}
service:s1 = {
 user = any:[ip6=::a01:0/117 & network:n1];
 permit src = user; dst = any:[network:n4]; prt = udp 123;
}
service:s2 = {
 user = any:[ip6 = ::a01:400/119 & network:n4];
 permit src = user; dst = network:n5; prt = udp;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule, s1.dst has subnets, but s2.dst doesn't match
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[ip6=::a01:200/119 & network:n2]; prt = udp 123;
}
service:s2 = {
 user = any:[ip6=::a00:0/104 & network:n2];
 permit src = user; dst = network:n4; prt = ip;
}
=WARNING=NONE

############################################################
=TITLE=Missing transient rule with managed interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
service:s1 = {
 user = host:h1;
 permit src = user; dst = any:[network:n2]; prt = proto 50;
}
service:s2 = {
 user = interface:r2.n2;
 permit src = any:[user]; dst = user; prt = proto 50;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - host:h1
 or add missing dst elements to service:s1:
 - interface:r2.n2
=END=

############################################################
=TITLE=Missing transient rule with zone cluster
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2a = { ip6 = ::a01:200/121; }
network:n2b = { ip6 = ::a01:280/121; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2a = { ip6 = ::a01:201; hardware = n2a; }
}
router:u = {
 managed = routing_only;
 model = IOS;
 interface:n2a = { ip6 = ::a01:202; hardware = n2a; }
 interface:n2b = { ip6 = ::a01:281; hardware = n2b; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2b = { ip6 = ::a01:282; hardware = n2b; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2a]; prt = icmpv6 3;
}
service:s2 = {
 user = any:[network:n2b];
 permit src = user; dst = network:n3; prt = icmpv6;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2a].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - network:n3
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2a].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - network:n3
=END=

############################################################
=TITLE=Missing transient rule with subnet in aggregate
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:h1 = { ip6 = ::a01:103; }
 host:h2 = { ip6 = ::a01:105; }
 host:h3 = { ip6 = ::a01:107; }
 host:h4 = { ip6 = ::a01:109; }
 host:h5 = { ip6 = ::a01:10b; }
}
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n4sub = { ip6 = ::a01:420/123; subnet_of = network:n4; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:u1 = {
 interface:n2 = { ip6 = ::a01:203; }
 interface:n4;
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
router:u2 = {
 interface:n3 = { ip6 = ::a01:303; }
 interface:n4sub;
}
service:s1 = {
 user = host:h1, host:h2, host:h3, host:h4, host:h5;
 permit src = user; dst = network:n4; prt = ip;
}
service:s2 = {
 user = any:[ip6=::a00:0/104 & network:n2], any:[network:n3];
 permit src = user; dst = user; prt = udp;
}
service:s3 = {
 user = network:n4sub;
 permit src = user; dst = any:[ip6=::a01:100/121 & network:n2]; prt = icmpv6 4/4, icmpv6 3/13;
}
service:s4 = {
 user = network:n4;
 permit src = user; dst = network:n1; prt = icmpv6 3/13, icmpv6 4/5;
}
=END=
# Show matching subnet of dst aggregate.
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at network:n4, any:[ip6=::a00:0/104 & network:n2].
 Add missing src elements to service:s2:
 - host:h1
 - host:h2
 - host:h3
 - ...
 or add missing dst elements to service:s1:
 - network:n4sub
Warning: Missing transient supernet rules
 between src of service:s3 and dst of service:s4,
 matching at any:[ip6=::a01:100/121 & network:n2], network:n4.
 Add missing src elements to service:s4:
 - network:n4sub
 or add missing dst elements to service:s3:
 - network:n1
=END=

############################################################
=TITLE=No transient rule together with "foreach"
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:tr = { ip6 = ::a09:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:tr = { ip6 = ::a09:101; hardware = tr; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:tr = { ip6 = ::a09:102; hardware = tr; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
area:all = { anchor = network:tr;}
protocol:oneway_IP = ip, oneway;
# Allow unfiltered communication,
# but check src IP of each incoming network:n_i.
service:s1 = {
 user = foreach
        any:[network:tr],
	network:[area:all] & ! network:tr;
 permit src = user;
	dst = any:[area:all] &! any:[user];
	prt = protocol:oneway_IP;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a01:100/120 any6
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! tr_in
access-list tr_in extended permit ip any6 any6
access-group tr_in in interface tr
-- ipv6/r2
! tr_in
access-list tr_in extended permit ip any6 any6
access-group tr_in in interface tr
--
! n2_in
access-list n2_in extended permit ip ::a01:200/120 any6
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Disable check for missing transient rule at zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
any:n2 = { link = network:n2; no_check_supernet_rules; }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:n2; prt = tcp 81-85;
}
service:s2 = {
 user = any:n2;
 permit src = user; dst = host:h3; prt = tcp 80-90;
}
=WARNING=NONE

############################################################
=TITLE=Disable check for missing transient rule at protocol
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
protocol:ospf = proto 89, no_check_supernet_rules;
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = protocol:ospf;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = ip;
}
=WARNING=NONE

############################################################
=TITLE=Ignore the internet when checking for missing transient rule
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::/0; has_subnets; }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 81-85;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = tcp 80-90;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule with src/dst in subnet relation
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = any:[network:n2],
              any:[network:n3],
              ;
        prt = icmpv6;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user;
        dst = network:n3;
        prt = icmpv6 3;
}
service:s3 = {
 user = host:h1;
 permit src = user;
        dst = any:[network:n2],
              ;
        prt = tcp 81;
}
service:s4 = {
 user = any:[network:n2], network:n1;
 permit src = user;
        dst = network:n3;
        prt = tcp 81 - 89;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule for src and dst in same zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
# Add other zone, that any:[network:n2] is no leaf zone
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n3 = { ip6 = ::a01:300/120; }
service:s1 = {
 user = any:[network:n2];
 permit src = network:n1; dst = user; prt = icmpv6 3;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n1; prt = icmpv6;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 permit icmp ::a01:100/120 any 3
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any host ::a01:101
 permit icmp any ::a01:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=No missing transient rule for leaf zone
# A leaf security zone has only one connection.
# It can't lead to unwanted rule chains.
=INPUT=
router:r0 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
}
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
service:s1 = {
 user = network:n2;
 permit src = user; dst = any:[network:n1]; prt = tcp 80;
}
service:s2 = {
 user = any:[network:n1];
 permit src = user; dst = network:n3; prt = tcp;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:n1_self -
-A INPUT -j n1_self -i n1
--
:n1_n3 -
-A n1_n3 -j ACCEPT -d ::a01:300/120 -p tcp
-A FORWARD -j n1_n3 -i n1 -o n3
--
:n2_self -
-A INPUT -j n2_self -i n2
--
:n2_n1 -
-A n2_n1 -j ACCEPT -s ::a01:200/120 -p tcp --dport 80
-A FORWARD -j n2_n1 -i n2 -o n1
--
:n3_self -
-A INPUT -j n3_self -i n3
=END=

############################################################
=TITLE=No missing transient rule if zone isn\'t traversed
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
# Add other zone, that any:[network:n2] is no leaf zone
router:r2 = {
 managed;
 model = Linux;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = icmpv6 3/13;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = icmpv6 3;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule if zone in loop isn\'t traversed (1)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
}
# Traffic between n2 and n4 must not traverse n3.
pathrestriction:n3 = interface:r2.n2, interface:r3.n3;
# must not traverse n2 and n4.
pathrestriction:n2 = interface:r1.n2, interface:r2.n2;
pathrestriction:n4 = interface:r3.n4, interface:r4.n4;
service:s1 = {
 user = network:n2;
 permit src = user; dst = any:[network:n3]; prt = ip;
}
service:s2 = {
 user = any:[network:n3];
 permit src = user; dst = network:n4; prt = udp;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule if zone in loop isn\'t traversed (2)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
pathrestriction:p =
 interface:r1.n4,
 interface:r2.n4,
;
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = ip;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = udp;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule without valid path (1)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = Linux;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
pathrestriction:p1 =
 interface:r2.n1,
 interface:r2.n3,
;
pathrestriction:p2 =
 interface:r1.n1,
 interface:r1.n2,
;
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n3]; prt = ip;
}
service:s2 = {
 user = any:[network:n3];
 permit src = user; dst = network:n2; prt = ip;
}
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n3]
 for rule permit src=network:n1; dst=any:[network:n3]; prt=ip; of service:s1
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:p1 (blocked 1 path attempt)
  - pathrestriction:p2 (blocked 1 path attempt)
Error: No valid path
 from any:[network:n1]
 to any:[network:n3]
 for rule permit src=network:n1; dst=any:[network:n3]; prt=ip; of service:s1
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:p1 (blocked 1 path attempt)
  - pathrestriction:p2 (blocked 1 path attempt)
=END=

############################################################
=TITLE=No missing transient rule without valid path (2)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = Linux;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
pathrestriction:p1 =
 interface:r2.n3,
 interface:r3.n3,
;
pathrestriction:p2 =
 interface:r1.n1,
 interface:r1.n2,
;
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n3]; prt = ip;
}
service:s2 = {
 user = any:[network:n3];
 permit src = user; dst = network:n2; prt = ip;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule for unenforceable rule
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
any:n1 = { link = network:n1; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n3 = { ip6 = ::a01:300/120; }
# network:n1 -> any:n1 is unenforceable
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = any:n1, network:n3;
        prt = tcp 445;
}
service:s2 = {
 user = any:n1;
 permit src = user; dst = network:n2; prt = tcp 445;
}
=WARNING=
Warning: Some source/destination pairs of service:s1 don't affect any firewall:
 src=network:n1; dst=any:n1
=END=

############################################################
=TITLE=Supernet used as aggregate
=INPUT=
network:intern = { ip6 = ::a01:100/120; }
router:asa = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = ::102:302;
  hardware = outside;
 }
}
area:internet = { border = interface:asa.dmz; }
network:dmz = { ip6 = ::102:300/121; }
router:extern = {
 interface:dmz = { ip6 = ::102:301; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
service:test = {
 user = network:intern;
 permit src = user; dst = network:[area:internet]; prt = tcp 80;
}
=OUTPUT=
--ipv6/asa
! inside_in
access-list inside_in extended permit tcp ::a01:100/120 any6 eq 80
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Aggregate linked to non-network
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 interface:n1;
}
any:Trans = { link = router:r1; }
=ERROR=
Error: Must only use network name in 'link' of any:Trans
=END=

############################################################
=TITLE=Aggregate linked to unknown network
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
any:Trans = { link = network:n2; }
=ERROR=
Error: Referencing undefined network:n2 in 'link' of any:Trans
=END=

############################################################
=TITLE=Duplicate named aggregate in zone
=INPUT=
any:a1 = { link = network:n1; }
any:a2 = { link = network:n2; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r = {
 interface:n1;
 interface:n2;
}
=ERROR=
Error: Duplicate any:a1 and any:a2 in any:[network:n1]
=END=

############################################################
=TITLE=Duplicate named aggregate in zone cluster
=INPUT=
any:a1 = { ip6 = ::a00:0/104; link = network:n1; }
any:a2 = { ip6 = ::a00:0/104; link = network:n2; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:u = {
 interface:n1;
 interface:n2;
}
pathrestriction:p = interface:u.n1, interface:r1.n1;
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
=ERROR=
Error: Duplicate any:a1 and any:a2 in any:[network:n2]
=END=

############################################################
=TITLE=Network and aggregate have same address in zone (1)
=INPUT=
any:a1 = { ip6 = ::a00:0/104; link = network:n1; }
network:n1 = { ip6 = ::a00:0/104; }
=ERROR=
Error: any:a1 and network:n1 have identical address in any:[network:n1]
=END=

############################################################
=TITLE=Network and aggregate have same address in zone (2)
=INPUT=
any:a1 = { ip6 = ::a00:0/104; link = network:n1; }
network:n1 = { ip6 = ::a00:0/104; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
=ERROR=
Error: any:a1 and network:n1 have identical address in any:[network:n1]
=END=

############################################################
=TITLE=Network and aggregate have same address in zone cluster
=INPUT=
any:a1 = { ip6 = ::a01:200/120; link = network:n1; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:u = {
 interface:n1;
 interface:n2;
}
pathrestriction:p = interface:u.n1, interface:r1.n1;
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
=ERROR=
Error: any:a1 and network:n2 have identical address in any:[network:n1]
=END=

############################################################
=TITLE=Ignore duplicate aggregates from nested aggregate definition
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
group:clients = any:[network:n1];
service:s1 = {
 user = any:[ ip6 = ::a01:0/112 & group:clients ];
 permit src = user; dst = network:n4; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r2
! n3_in
access-list n3_in extended permit tcp ::a01:0/112 ::a01:400/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Must not expand aggregate set of zone cluster twice
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
group:clients = any:[network:n1];
service:s1 = {
 user = group:clients;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r2
! n3_in
access-list n3_in extended permit tcp any6 ::a01:400/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Zone cluster with keyword foreach
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
service:ping-local = {
 user = foreach any:[network:n3];
 permit src = network:[user]; dst = interface:[user].[all]; prt = icmpv6 8;
}
service:NTP-local = {
 user = foreach any:[ip6 = ::a01:200/119 & network:n3];
 permit src = network:[user]; dst = interface:[any:[user]].[all]; prt = udp 123;
}
=WARNING=
Warning: Some source/destination pairs of service:NTP-local don't affect any firewall:
 src=network:n2; dst=interface:r2.n2
 src=network:n2; dst=interface:r2.n3
 src=network:n2; dst=interface:r2.n4
 src=network:n3; dst=interface:r2.n2
 src=network:n3; dst=interface:r2.n3
 src=network:n3; dst=interface:r2.n4
Warning: Some source/destination pairs of service:ping-local don't affect any firewall:
 src=network:n2; dst=interface:r2.n2
 src=network:n2; dst=interface:r2.n3
 src=network:n2; dst=interface:r2.n4
 src=network:n3; dst=interface:r2.n2
 src=network:n3; dst=interface:r2.n3
 src=network:n3; dst=interface:r2.n4
 src=network:n4; dst=interface:r2.n2
 src=network:n4; dst=interface:r2.n3
 src=network:n4; dst=interface:r2.n4
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 permit udp ::a01:200/120 host ::a01:201 eq 123
 permit udp ::a01:300/120 host ::a01:201 eq 123
 permit icmp ::a01:200/120 host ::a01:201 8
 permit icmp ::a01:300/120 host ::a01:201 8
 permit icmp ::a01:400/120 host ::a01:201 8
 deny ipv6 any any
=END=
