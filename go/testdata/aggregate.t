=TEMPL=topo
area:test = { border = interface:filter.Trans; }
network:A = { ip = 10.3.3.0/25; }
network:sub = { ip = 10.3.3.8/29; subnet_of = network:A; }
network:B = { ip = 10.3.3.128/25; }
router:ras = {
 interface:A = { ip = 10.3.3.1; }
 interface:sub = { ip = 10.3.3.9; }
 interface:B = { ip = 10.3.3.129; }
 interface:Trans = { ip = 10.1.1.2; }
}
network:Trans = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; }
}
network:Customer = { ip = 10.9.9.0/24; }
=END=

############################################################
=TITLE=Implicit aggregate over 3 networks
=INPUT=
[[topo]]
service:test = {
 user = any:[ip=10.0.0.0/8 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
=OUTPUT=
--filter
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.0.0.0 0.255.255.255 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 81
 permit tcp 10.3.3.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
=END=

############################################################
=TITLE=Implicit aggregate over 2 networks
=INPUT=
[[topo]]
service:test = {
 user = any:[ip=10.3.3.0/24 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
=OUTPUT=
--filter
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.3.3.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.3.3.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
=END=

############################################################
=TITLE=Implicit aggregate between 2 networks
=INPUT=
[[topo]]
service:test1 = {
 user = any:[ip=10.3.3.0/26 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
service:test2 = {
 overlaps = service:test1;
 user = network:sub;
 permit src = user; dst = network:Customer; prt = tcp 81;
}
=OUTPUT=
--filter
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.3.3.0 0.0.0.63 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.3.3.8 0.0.0.7 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
=END=

############################################################
=TITLE=Multiple implicit aggregates
=INPUT=
network:Test =  { ip = 10.9.1.0/24; }
router:filter1 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Test = { ip = 10.9.1.1; hardware = Vlan20; }
  interface:Trans1 = { ip = 10.3.6.1; hardware = VLAN1; }
}
router:filter2 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Test = { ip = 10.9.1.2; hardware = Vlan20; }
  interface:Trans2 = { ip = 10.5.7.1; hardware = VLAN1; }
}
network:Trans1 = { ip = 10.3.6.0/24; }
network:Trans2 = { ip = 10.5.7.0/24; }
router:Kunde = {
  interface:Trans1 = { ip = 10.3.6.2; }
  interface:Trans2 = { ip = 10.5.7.2; }
  interface:Trans3 = { ip = 10.5.8.1; }
}
network:Trans3 = { ip = 10.5.8.0/24; }
router:r2 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Trans3 = { ip = 10.5.8.2; hardware = Vlan20; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;
service:t1 = {
  user = any:[ip=10.0.0.0/12 & network:n2],
         any:[ip=10.0.0.0/13 & network:Trans1],
         any:[ip=10.0.0.0/13 & network:Trans2],
  ;
  permit src = user; dst = network:Test; prt = tcp 81;
}
service:t2 = {
  user = any:[ip=10.0.0.0/14 & network:n2],
         any:[ip=10.0.0.0/14 & network:Trans1],
         network:Trans2,
  ;
  permit src = user; dst = network:Test; prt = tcp 82;
}
=END=
# Warning is sub optimal.
# Netspoc doesn't show original aggregate names.
=WARNING=
Warning: Duplicate elements in user of service:t1:
 - any:[ip=10.0.0.0/13 & network:Trans1]
 - any:[ip=10.0.0.0/13 & network:Trans1]
 - any:[ip=10.0.0.0/13 & network:Trans1]
=OUTPUT=
-- filter1
! VLAN1_in
access-list VLAN1_in extended permit tcp 10.0.0.0 255.240.0.0 10.9.1.0 255.255.255.0 eq 81
access-list VLAN1_in extended permit tcp 10.0.0.0 255.252.0.0 10.9.1.0 255.255.255.0 eq 82
access-list VLAN1_in extended deny ip any4 any4
access-group VLAN1_in in interface VLAN1
-- filter2
! VLAN1_in
object-group network g0
 network-object 10.0.0.0 255.252.0.0
 network-object 10.5.7.0 255.255.255.0
access-list VLAN1_in extended permit tcp 10.0.0.0 255.240.0.0 10.9.1.0 255.255.255.0 eq 81
access-list VLAN1_in extended permit tcp object-group g0 10.9.1.0 255.255.255.0 eq 82
access-list VLAN1_in extended deny ip any4 any4
access-group VLAN1_in in interface VLAN1
-- r2
! n2_in
access-list n2_in extended permit tcp 10.0.0.0 255.240.0.0 10.9.1.0 255.255.255.0 eq 81
access-list n2_in extended permit tcp 10.0.0.0 255.252.0.0 10.9.1.0 255.255.255.0 eq 82
access-list n2_in extended deny ip any4 any4
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
network:n1_20_16 = { ip = 10.1.16.0/21; subnet_of = network:n1_16; }
network:n1_20_00 = { ip = 10.1.0.0/20; subnet_of = network:n1_16; }
network:n1_16 = { ip = 10.1.0.0/16; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1_16 = { ip = 10.1.99.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; subnet_of = network:n1_20_00; }
service:s1 = {
  user = any:[ip=10.1.0.0/22 & network:n1_16];
  permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
  user = network:n1_20_00;
  permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s2:
  permit src=any:[ip=10.1.0.0/22 & network:n1_20_16]; dst=network:n2; prt=tcp 80; of service:s1
< permit src=network:n1_20_00; dst=network:n2; prt=tcp 80; of service:s2
=END=

############################################################
=TITLE=Find subnet relation even with intermediate aggregates
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.0.0/16; host:h1 = { range = 10.1.1.0 - 10.1.1.255; } }
any:n1-17 = { ip = 10.1.0.0/17; link = network:n2; }
any:n1-20 = { ip = 10.1.0.0/20; link = network:n1; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.0.1; hardware = n2; }
}
=WARNING=
Warning: IP of host:h1 overlaps with subnet network:n1 in nat_domain:[network:n1]
Warning: network:n1 is subnet of network:n2
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Find subnet relation with duplicate networks and intermediate aggregate
# No IPv6 NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.0.0/16; nat:h2 = { hidden; } }
network:n3 = { ip = 10.1.0.0/16; nat:h3 = { hidden; } }
any:n1-20 = { ip = 10.1.0.0/20; link = network:n1; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat_out = h2; }
 interface:n2 = { ip = 10.1.0.1; hardware = n2; nat_out = h3; }
 interface:n3 = { ip = 10.1.0.1; hardware = n3; nat_out = h2; }
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
network:Test = { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { unnumbered; hardware = Vlan2; }
}
network:Trans = { unnumbered; }
router:filter2 = {
 managed;
 model = ASA;
 interface:Trans = { unnumbered; hardware = Vlan3; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan4; }
}
network:Kunde = { ip = 10.1.1.0/24; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
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
# No IPv6 NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; nat:h = { hidden; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; nat_out = h; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
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
# No IPv6 NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:h = { hidden; } }
network:n4 = { ip = 10.1.3.128/25; subnet_of = network:n3; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; nat_out = h; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.3.129; hardware = n4; }
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
network:Test = { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { ip = 192.168.1.1; hardware = Vlan2; }
}
network:Trans = { ip = 192.168.1.0/29; }
router:filter2 = {
 managed;
 model = ASA;
 interface:Trans = { ip = 192.168.1.2; hardware = Vlan3; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan4; }
}
network:Kunde = { ip = 10.1.1.0/24; }
service:test = {
 user = any:[ip=10.0.0.0/8 & network:Kunde];
 permit src = user; dst = network:Test; prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
--filter1
access-list Vlan2_in extended permit tcp 10.0.0.0 255.0.0.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended deny ip any4 any4
access-group Vlan2_in in interface Vlan2
--filter2
access-list Vlan4_in extended permit tcp 10.0.0.0 255.0.0.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan4_in extended deny ip any4 any4
access-group Vlan4_in in interface Vlan4
=END=

############################################################
=TITLE=Warn on missing src aggregate
=INPUT=
[[input]]
router:T = {
 interface:Trans = { ip = 192.168.1.3; }
 interface:N1;
}
network:N1 = { ip = 10.192.0.0/24; }
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[ip=10.0.0.0/8 & network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 Generated ACL at interface:filter1.Trans would permit access from additional networks:
 - network:N1
 Either replace any:[ip=10.0.0.0/8 & network:Kunde] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Warn on multiple missing networks
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n3a = { ip = 10.1.3.4/30; subnet_of = network:n3; }
network:n3b = { ip = 10.1.3.16/28; subnet_of = network:n3; }
network:n3c = { ip = 10.1.3.36/30; subnet_of = network:n3; }
network:n3d = { ip = 10.1.3.64/27; subnet_of = network:n3; }
network:n3e = { ip = 10.1.3.96/27; subnet_of = network:n3; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 interface:n2  = { ip = 10.1.2.2; }
 interface:n3a;
 interface:n3b;
 interface:n3c;
 interface:n3d;
 interface:n3e;
}
service:s1 = {
 user = network:n3;
 permit src = network:n1; dst = user; prt = icmp 8;
}
=INPUT=
[[input]]
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=network:n3; prt=icmp 8; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n3a
 - network:n3b
 - network:n3c
 - ...
 Either replace network:n3 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule
 or add any:[ ip=10.1.3.0/24 & network:n3a ] to dst of rule.
=END=

############################################################
=TITLE=Warn on multiple missing networks with aggregate
=INPUT=
[[input]]
any:n3x = { ip = 10.1.3.0/24; link = network:n3a; }
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=network:n3; prt=icmp 8; of service:s1
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n3a = { ip = 10.1.3.4/30; subnet_of = network:n3; }
network:n3b = { ip = 10.1.3.8/30; subnet_of = network:n3; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 interface:n2  = { ip = 10.1.2.2; }
 interface:n3a;
 interface:n3b;
}
service:s1 = {
 user = network:n3, network:n3a, network:n3b;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Larger intermediate aggregate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ],
        any:[ network:n2 ];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.0.0.0 255.0.0.0 10.1.3.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n2_in
access-list n2_in extended permit tcp any4 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=permit any between two interfaces, 1x no_in_acl
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; no_in_acl; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
protocol:oneway_IP = ip, oneway;
# Allow unfiltered communication between n2 and n3.
service:s1 = {
 user = any:[network:n2], any:[network:n3];
 permit src = user; dst = user; prt = protocol:oneway_IP;
}
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any any
--
ip access-list extended n1_out
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 permit ip any any
--
ip access-list extended n3_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 permit ip any any
--
interface n3
 ip address 10.1.3.1 255.255.255.0
 ip access-group n3_in in
=END=
# Don't generate outgoing ACL with single line "permit ip any any"

############################################################
=TITLE=Loop with no_in_acl and in_zone eq no_in_zone
=INPUT=
network:Test = { ip = 10.1.0.0/16; }
router:u = {
 interface:Test;
 interface:Trans1;
 interface:Trans2;
}
network:Trans1 = { ip = 192.168.1.0/29; }
network:Trans2 = { ip = 192.168.2.0/29; }
router:filter = {
 managed;
 model = ASA;
 routing = manual;
 interface:Trans1 = { ip = 192.168.1.2; hardware = Vlan4; no_in_acl; }
 interface:Trans2 = { ip = 192.168.2.2; hardware = Vlan5; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan6; }
 interface:sub = { ip = 10.1.1.33; hardware = Vlan7; }
}
network:Kunde = { ip = 10.1.1.0/24; subnet_of = network:Test; }
network:sub = { ip = 10.1.1.32/29; subnet_of = network:Kunde; }
service:test = {
 user = any:[network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=OUTPUT=
--filter
access-list Vlan5_in extended permit tcp any4 10.1.1.0 255.255.255.0 eq 80
access-list Vlan5_in extended deny ip any4 any4
access-group Vlan5_in in interface Vlan5
--filter
access-list Vlan6_out extended permit tcp any4 10.1.1.0 255.255.255.0 eq 80
access-list Vlan6_out extended deny ip any4 any4
access-group Vlan6_out out interface Vlan6
=END=

############################################################
=TITLE=Nested aggregates
=TEMPL=input
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { unnumbered; hardware = Vlan2; }
}
network:Trans = { unnumbered; }
router:u = {
 interface:Trans;
 interface:Kunde1;
 interface:Kunde2;
 interface:Kunde3;
}
network:Kunde1 = { ip = 10.1.1.0/24; }
network:Kunde2 = { ip = 10.1.2.0/24; }
network:Kunde3 = { ip = 10.1.3.0/24; }
service:test1 = {
 user = any:[ip=10.1.0.0/23 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 80;
}
service:test2 = {
 user = any:[ip=10.1.0.0/22 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 81;
}
=INPUT=[[input]]
=OUTPUT=
--filter
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.254.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.252.0 10.9.1.0 255.255.255.0 eq 81
access-list Vlan2_in extended deny ip any4 any4
access-group Vlan2_in in interface Vlan2
=END=

############################################################
=TITLE=Redundant nested aggregates
=INPUT=
[[input]]
service:test3 = {
 user = any:[ip=10.1.0.0/16 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test1 compared to service:test3:
  permit src=any:[ip=10.1.0.0/23 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test1
< permit src=any:[ip=10.1.0.0/16 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test3
=END=

############################################################
=TITLE=Prevent nondeterminism in nested aggregates
# /23 aggregates must be processed in fixed order.
# Otherwise network:[any:[ip=10.1.0.0/17..] would be nondeterministic.
=INPUT=
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { unnumbered; hardware = Vlan2; }
}
network:Trans = { unnumbered; }
router:u = {
 interface:Trans;
 interface:Kunde1;
 interface:Kunde2;
}
network:Kunde1 = { ip = 10.1.0.0/24; }
network:Kunde2 = { ip = 10.1.2.0/24; }
service:test1a = {
 user = network:[any:[ip=10.1.0.0/23 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 80;
}
service:test1b = {
 user = network:[any:[ip=10.1.2.0/23 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 81;
}
service:test2 = {
 user = network:[any:[ip=10.1.0.0/17 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 82;
}
=OUTPUT=
--filter
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.255.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.255.0 10.9.1.0 255.255.255.0 eq 82
access-list Vlan2_in extended permit tcp 10.1.2.0 255.255.255.0 10.9.1.0 255.255.255.0 range 81 82
access-list Vlan2_in extended deny ip any4 any4
access-group Vlan2_in in interface Vlan2
=END=

############################################################
=TITLE=Redundant nested aggregates without matching network (1)
# Larger aggregate is inserted first.
=INPUT=
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:Kunde = { ip = 10.1.1.0/24; }
service:test = {
 user = any:[ip=10.1.0.0/16 & network:Test],
        any:[ip=10.1.0.0/17 & network:Test],
        ;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=any:[ip=10.1.0.0/17 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip=10.1.0.0/16 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Redundant nested aggregates without matching network (2)
# Small aggregate is inserted first.
=INPUT=
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:Kunde = { ip = 10.1.1.0/24; }
service:test = {
 user = any:[ip=10.1.0.0/17 & network:Test],
        any:[ip=10.1.0.0/16 & network:Test],
        ;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=any:[ip=10.1.0.0/17 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip=10.1.0.0/16 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Redundant matching aggregates as subnet of network
=INPUT=
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:Kunde = { ip = 10.1.1.0/24; }
service:test1 = {
 user = any:[ip=10.9.1.0/26 & network:Test],
        network:Test;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
service:test2 = {
 user = any:[ip=10.9.1.0/25 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test1 compared to service:test1:
  permit src=any:[ip=10.9.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=network:Test; dst=network:Kunde; prt=tcp 80; of service:test1
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=any:[ip=10.9.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip=10.9.1.0/25 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
Warning: Redundant rules in service:test2 compared to service:test1:
  permit src=any:[ip=10.9.1.0/25 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
< permit src=network:Test; dst=network:Kunde; prt=tcp 80; of service:test1
=END=

############################################################
=TITLE=Mixed redundant matching aggregates
# Check for sub aggregate, even if sub-network was found
=INPUT=
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:Kunde = { ip = 10.1.1.0/24; }
service:test1 = {
 user = any:[ip=10.1.1.0/26 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
service:test2 = {
 user = any:[ip=10.0.0.0/8 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=any:[ip=10.1.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip=10.0.0.0/8 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
=END=

############################################################
=TITLE=Mixed implicit and explicit aggregates
=INPUT=
any:10_0_0_0    = { ip = 10.0.0.0/8;    link = network:Test; }
any:10_253_0_0  = { ip = 10.253.0.0/16; link = network:Test; }
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:Kunde = { ip = 10.1.1.0/24; }
service:test1 = {
 user = any:[network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=OUTPUT=
--filter
access-list Vlan1_in extended permit tcp any4 10.1.1.0 255.255.255.0 eq 80
access-list Vlan1_in extended deny ip any4 any4
access-group Vlan1_in in interface Vlan1
=END=

############################################################
=TITLE=Matching aggregate of implicit aggregate
=INPUT=
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:Kunde = { ip = 10.1.1.0/24; }
service:test = {
 user = any:[ip=10.1.0.0/16 & any:[network:Test]];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=OUTPUT=
--filter
access-list Vlan1_in extended permit tcp 10.1.0.0 255.255.0.0 10.1.1.0 255.255.255.0 eq 80
access-list Vlan1_in extended deny ip any4 any4
access-group Vlan1_in in interface Vlan1
=END=

############################################################
=TITLE=Implicitly remove aggregate of loopback interface
=INPUT=
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:loop = { ip = 10.7.7.7; loopback; hardware = lo1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; no_in_acl; }
}
network:Customer = { ip = 10.9.9.0/24; }
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
network:Trans = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:loop = { ip = 10.7.7.7; loopback; hardware = lo1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; no_in_acl; }
}
network:Customer = { ip = 10.9.9.0/24; }
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
network:Trans = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:loop = { ip = 10.7.7.7; loopback; hardware = lo1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; }
}
network:Customer = { ip = 10.9.9.0/24; }
service:test = {
 user = network:[interface:filter.[all]] &! network:Customer;
 permit src = network:Customer; dst = user; prt = tcp 22;
}
=OUTPUT=
--filter
ip access-list extended VLAN2_in
 deny ip any host 10.1.1.1
 permit tcp 10.9.9.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 22
 deny ip any any
=END=

############################################################
=TITLE=Multiple missing destination networks at one router
=TEMPL=topo
network:Customer = { ip = 10.9.9.0/24; }
router:r1 = {
 managed;
 model = {{.mod}};
 routing = manual;
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN9; }
 interface:trans = { ip = 10.7.7.1; hardware = VLAN7; }
 interface:loop = { ip = 10.7.8.1; loopback; hardware = Lo1; }
}
network:trans = { ip = 10.7.7.0/24; }
router:r2 = {
 managed;
 model = {{.mod}};
 routing = manual;
 interface:trans = { ip = 10.7.7.2; hardware = VLAN77; }
 interface:n1 = { ip = 10.1.1.1; hardware = VLAN1; {{.no}}}
 interface:n2 = { ip = 10.1.2.1, 10.1.2.2; hardware = VLAN2; }
 interface:n3 = { ip = 10.1.3.1; hardware = VLAN3; }
 interface:n4 = { ip = 10.1.4.1; hardware = VLAN4; }
 interface:n128 = { ip = 10.128.1.1; hardware = VLAN128; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n128 = { ip = 10.128.1.0/24; }
=INPUT=
[[topo {no: "", mod: "IOS, FW"}]]
service:test = {
 user = #network:trans,
        any:[ip=10.0.0.0/9 & network:n1],
        #any:[ip=10.1.0.0/17 & network:n2],
        #network:n3,
        #any:[ip=10.1.0.0/16 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r1.Customer would permit access to additional networks:
 - network:trans
 Either replace any:[ip=10.0.0.0/9 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n2
 Either replace any:[ip=10.0.0.0/9 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n3
 Either replace any:[ip=10.0.0.0/9 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n4
 Either replace any:[ip=10.0.0.0/9 & network:n1] by smaller networks that are not supernet
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
network:n2x = { ip = 10.2.2.0/24; }
service:test = {
 user = network:trans,
        any:[ip=10.0.0.0/9 & network:n1],
        #any:[ip=10.1.0.0/17 & network:n2],
        network:n3,
        any:[ip=10.1.0.0/16 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n2
 - network:n2x
 Either replace any:[ip=10.0.0.0/9 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip=10.1.0.0/16 & network:n4]; prt=ip; of service:test
 Generated ACL at interface:r2.trans would permit access to additional networks:
 - network:n2
 Either replace any:[ip=10.1.0.0/16 & network:n4] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=END=

############################################################
=TITLE=Warn on all missing networks of zone cluster
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
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
        any:[ip=10.0.0.0/9 & network:n1],
        any:[ip=10.0.0.0/9 & network:n2],
        network:n3,
        any:[ip=10.0.0.0/9 & network:n4],
        # network:n128 doesn't match
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=OUTPUT=
--r1
ip access-list extended VLAN9_in
 deny ip any host 10.9.9.1
 deny ip any host 10.7.7.1
 deny ip any host 10.7.8.1
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
--r2
ip access-list extended VLAN77_in
 deny ip any host 10.7.7.2
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 deny ip any host 10.1.2.2
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
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
        any:[ip=10.0.0.0/9 & network:n1],
        any:[ip=10.0.0.0/9 & network:n2],
        #network:n3,
        #any:[ip=10.1.0.0/16 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=OUTPUT=
--r2
ip access-list extended VLAN77_in
 deny ip any host 10.7.7.2
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 deny ip any host 10.1.2.2
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
--r2
ip access-list extended VLAN1_in
 deny ip any host 10.7.7.2
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 deny ip any host 10.128.1.1
 deny ip any host 10.1.2.2
 permit ip any any
--r2
ip access-list extended VLAN2_out
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
=END=

############################################################
=TITLE=Check missing intermediate aggregate for Linux
# Linux only checks for missing intermediate aggregates,
# because filter is attached to pair of incoming and outgoing interface.
=INPUT=
[[topo {no: "", mod: "Linux"}]]
service:test = {
 user = any:[ip=10.0.0.0/9 & network:n1],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 Generated ACL at interface:r1.Customer would permit access to additional networks:
 - network:trans
 Either replace any:[ip=10.0.0.0/9 & network:n1] by smaller networks that are not supernet
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
        any:[ip=10.0.0.0/9 & network:n1],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
=OUTPUT=
--r2
:VLAN77_VLAN1 -
-A VLAN77_VLAN1 -j ACCEPT -s 10.9.9.0/24 -d 10.0.0.0/9
-A FORWARD -j VLAN77_VLAN1 -i VLAN77 -o VLAN1
=END=

############################################################
=TITLE=Missing destination aggregate with loopback
=INPUT=
network:Customer = { ip = 10.9.9.0/24; }
router:r = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN9; }
 interface:n1 = { ip = 10.1.1.1; hardware = N1; }
 interface:n2 = { ip = 10.1.2.1; hardware = N2; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:u = {
 interface:n2;
 interface:l = { ip = 10.2.2.2; loopback; }
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
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:trans = { ip = 10.3.1.17; hardware = trans; }
 interface:sub-27 = { ip = 10.1.2.33; hardware = sub-27; }
}
network:sub-27 = { ip = 10.1.2.32/27; subnet_of = network:n2; }
network:trans = { ip = 10.3.1.16/30; }
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.3.1.18; hardware = trans; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:u = {
 interface:n2;
 interface:sub-29;
}
any:sub-28 =     { ip = 10.1.2.48/28; link = network:n2; }
network:sub-29 = { ip = 10.1.2.48/29; subnet_of = network:sub-27; }
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
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:trans = { ip = 10.3.1.17; hardware = trans; }
 interface:sub-27 = { ip = 10.1.2.33; hardware = sub-27; }
}
network:sub-27 = { ip = 10.1.2.32/27; subnet_of = network:n2; }
network:trans = { ip = 10.3.1.16/30; }
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.3.1.18; hardware = trans; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:u = {
 interface:n2;
 interface:sub-28;
}
network:sub-28 = { ip = 10.1.2.48/28; subnet_of = network:sub-27; }
any:sub-29 =     { ip = 10.1.2.48/29; link = network:n2; }
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
# No IPv6 NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 1.1.1.0/24; } }
network:n4 = { ip = 10.1.1.0/24; nat:n4 = { ip = 2.1.1.0/24; } }
any:Sub2 = { ip = 10.1.1.0/24; link = network:n2; }
any:Sub3 = { ip = 10.1.1.0/24; link = network:n3; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:t1 = { ip = 10.9.1.0/24; }
network:t2 = { ip = 10.9.2.0/24; }
network:t3 = { ip = 10.9.3.0/24; }
network:t4 = { ip = 10.9.4.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat_out = n4; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; nat_out = n4; }
 interface:t3 = { ip = 10.9.3.1; hardware = t3; nat_out = n1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:t2 = { ip = 10.9.2.2; hardware = t2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:t3 = { ip = 10.9.3.2; hardware = t3; }
 interface:t4 = { ip = 10.9.4.2; hardware = t4; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r4 = {
 interface:t2 = { ip = 10.9.2.1; hardware = t2; nat_out = n4; }
 interface:t4 = { ip = 10.9.4.1; hardware = t4; nat_out = n1; }
 interface:n4 = { ip = 10.1.1.1; hardware = n1; nat_out = n1; }
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
network:n1 = { ip = 10.1.0.0/16; }
network:n2 = { ip = 10.1.0.0/23; subnet_of = network:n1; }
network:n3 = { ip = 10.2.1.0/24; }
network:inet = { ip = 0.0.0.0/0; has_subnets; }
network:n4 = { ip = 1.1.1.8/29; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.8.1; hardware = n1; }
 interface:n2 = { ip = 10.1.0.1; hardware = n2; }
 interface:n3 = { ip = 10.2.1.1; hardware = n3; }
}

router:r2 = {
 interface:n3 = { ip = 10.2.1.2; }
 interface:inet;
}

router:r3 = {
 model = IOS, FW;
 managed;
 routing = manual;
 interface:inet = { negotiated; hardware = inet; }
 interface:n4 = { ip = 1.1.1.9; hardware = n4; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 81;
}
=WARNING=NONE

############################################################
=TITLE=Ignore intermediate aggregate from empty automatic group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
area:n2 = { border = interface:r1.n2; }
area:n3 = { border = interface:r1.n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.3.3.1; hardware = n3; }
}
service:s1 = {
 user = any:[ip = 10.1.0.0/16 & area:n2],
        # This automatic group is empty.
        network:[any:[ip = 10.1.0.0/16 & area:n3]],
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 3000;
}
=WARNING=NONE

############################################################
=TITLE=Ignore intermediate aggregate from automatic group
# Must not show warning on missing any:[ip=10.1.0.0/16 & network:n3],
# because it is only used intermediately in automatic group.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
area:n2 = { border = interface:r1.n2; }
area:n3 = { border = interface:r1.n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.3.3.1; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
 interface:n5;
}
service:s1 = {
 user = any:[ip = 10.1.0.0/16 & area:n2],
        network:[any:[ip = 10.1.0.0/16 & area:n3]],
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 3000;
}
=WARNING=NONE

############################################################
=TITLE=Ignore aggregate if all its networks are added
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
any:n3_10_1 = { ip = 10.1.0.0/16; link = network:n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.3.3.1; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
 interface:n5;
}
service:s1 = {
 user = any:[ip = 10.1.0.0/16 & network:n2],
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
any:n3_10_1 = { ip = 10.1.0.0/16; link = network:n3; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.3.3.1; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
 interface:n5;
}
service:s1 = {
 user = any:[ip = 10.1.0.0/16 & network:n2],
        network:n4,
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 3000;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:n1; dst=any:[ip=10.1.0.0/16 & network:n2]; prt=tcp 3000; of service:s1
 Generated ACL at interface:r1.n1 would permit access to additional networks:
 - network:n5
 Either replace any:[ip=10.1.0.0/16 & network:n2] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule
 or add any:n3_10_1 to dst of rule.
=END=

############################################################
=TITLE=Missing destination networks in loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.7.1.1; hardware = t1; }
 interface:t2 = { ip = 10.7.2.1; hardware = t2; }
}
network:t1 = { ip = 10.7.1.0/24; }
network:t2 = { ip = 10.7.2.0/24; }
router:u = {
 interface:t1;
 interface:t3;
 interface:t2;
 interface:t4;
}
network:t3 = { ip = 10.7.3.0/24; }
network:t4 = { ip = 10.7.4.0/24; }
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t3 = { ip = 10.7.3.2; hardware = t3; }
 interface:t4 = { ip = 10.7.4.2; hardware = t4; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:u = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
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
--r1
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit tcp host 10.1.2.2 any eq 22
 permit tcp host 10.1.3.1 any eq 23
 deny ip any any
--r2
ip access-list extended n4_in
 deny ip any host 10.1.1.2
 deny ip any host 10.1.4.1
 permit tcp host 10.1.3.1 any eq 23
 deny ip any any
--r3
ip access-list extended n3_in
 deny ip any host 10.1.3.2
 deny ip any host 10.1.4.2
 permit tcp host 10.1.3.1 any eq 23
 deny ip any any
=END=

############################################################
=TITLE=Missing aggregate at destination interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ];
 permit src = user; dst = interface:r2.n3; prt = udp 123;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=interface:r2.n3; prt=udp 123; of service:test
 Generated ACL at interface:r2.n3 would permit access from additional networks:
 - network:n3
 Either replace any:[ip=10.0.0.0/8 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Missing aggregates for reverse rule
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS{{.fw1}};
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:trans = { ip = 10.7.7.1; hardware = trans; }
 interface:loop = { ip = 10.7.8.1; loopback; hardware = Lo1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:trans = { ip = 10.7.7.0/24; }
router:r2 = {
 managed;
 model = IOS{{.fw2}};
 routing = manual;
 interface:trans = { ip = 10.7.7.2; hardware = trans; }
 interface:n3 = { ip = 10.1.3.1, 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ],
        network:trans,
 ;
 permit src = user; dst = network:n4; prt = udp 123;
}
=INPUT=[[input {fw1: "", fw2: ""}]]
=WARNING=
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 Generated ACL at interface:r1.trans would permit access to additional networks:
 - network:n2
 Either replace any:[ip=10.0.0.0/8 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 Generated ACL at interface:r2.n4 would permit access to additional networks:
 - network:n3
 Either replace any:[ip=10.0.0.0/8 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Effect of stateful router in reversed direction
# router:r1 sees only reply packets filtered by stateful router:r2
# Hence no warning is shown.
=INPUT=[[input {fw1: "", fw2: ", FW"}]]
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 permit udp 10.0.0.0 0.255.255.255 10.1.4.0 0.0.0.255 eq 123
 deny ip any any
--
ip access-list extended trans_in
 deny ip any host 10.1.1.1
 deny ip any host 10.7.7.1
 deny ip any host 10.7.8.1
 deny ip any host 10.1.2.1
 permit udp 10.1.4.0 0.0.0.255 eq 123 10.0.0.0 0.255.255.255
 deny ip any any
=END=

############################################################
=TITLE=No effect of stateful router in forward direction
=INPUT=[[input {fw1: ", FW", fw2: ""}]]
=WARNING=
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 Generated ACL at interface:r2.n4 would permit access to additional networks:
 - network:n3
 Either replace any:[ip=10.0.0.0/8 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Must not check source zone in reverse rule
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
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
 user = any:[ ip = 10.0.0.0/8 & network:n1 ];
 permit src = user; dst = network:n3; prt = udp 123;
}
=WARNING=NONE

############################################################
=TITLE=Managed router will not exploit reverse rule
# Reverse rule at router:r1 would allow router:r2 to access network:n2.
# But since r2 is managed, we assume it will not exploit this permission.
# Hence no warning is printed.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed = secondary;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ],
        network:n3,
 ;
 permit src = user; dst = interface:r2.n3; prt = udp 123;
}
=OUTPUT=
-- r1
ip access-list extended n3_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 permit udp host 10.1.3.2 eq 123 10.0.0.0 0.255.255.255
 deny ip any any
-- r2
ip access-list extended n3_in
 permit udp 10.0.0.0 0.255.255.255 host 10.1.3.2 eq 123
 deny ip any any
=END=

############################################################
=TITLE=Supernet rule to pathrestricted interface and no_in_acl
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1, 10.1.4.2; hardware = n4; no_in_acl; }
}
router:u = {
 interface:n2 = { ip = 10.1.2.3; }
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
-- r3
ip access-list extended n2_out
 permit udp any host 10.1.2.3 eq 123
 deny ip any any
--
ip access-list extended n3_in
 permit udp any host 10.1.2.3 eq 123
 deny ip any any
--
ip access-list extended n4_in
 deny ip any host 10.1.2.2
 deny ip any host 10.1.3.2
 deny ip any host 10.1.4.1
 deny ip any host 10.1.4.2
 permit ip any any
=END=

############################################################
=TITLE=Supernet rule to dst at no_in_acl
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; no_in_acl; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
any:n2-10_1_3 = { ip = 10.1.3.0/24; link = network:n2; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; no_in_acl; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3;}
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.7.1.1; hardware = t1; }
 interface:t2 = { ip = 10.7.2.1; hardware = t2; }
}
network:t1 = { ip = 10.7.1.0/24; }
network:t2 = { ip = 10.7.2.0/24; }
# router:u is split internally and hence interface:u.n4
# no longer has pathrestriction.
# We have this extra test case for this special situation.
router:u = {
 interface:t1;
 interface:t2;
 interface:n3;
 interface:n4 = { ip = 10.1.4.1; }
}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
pathrestriction:p =
 interface:r.t2,
 interface:u.n4,
;
service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ];
 permit src = user; dst = interface:u.n4; prt = udp 123;
}
=WARNING=
Warning: This reversed supernet rule would permit unexpected access:
  permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=interface:u.n4; prt=udp 123; of service:test
 Generated ACL at interface:r.t1 would permit access to additional networks:
 - network:n2
 Either replace any:[ip=10.0.0.0/8 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to src of rule.
=END=

############################################################
=TITLE=Suppress warning about missing aggregate rule
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:sub = { ip = 10.1.1.128/25; subnet_of = network:n1;
{{.hosts}}
}
router:u = {
 interface:n1;
 interface:sub;
 interface:t;
 {{.interfaces}}
}
network:t = { ip = 10.9.2.0/24; }
any:t = {
 link = network:t;
 no_check_supernet_rules;
}
network:n2 = { ip = 10.1.2.0/24; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:t = { ip = 10.9.2.1; hardware = t; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:s = {
 user = any:[ ip = 10.1.0.0/16 & network:n2 ];
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
hosts: "host:h = { ip = 10.1.1.130; }"
interfaces: "interface:lo = { ip = 10.9.9.1; loopback; }
interface:vip = { ip = 10.9.9.2; vip; }"
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
network:n1 = { ip = 10.1.0.0/16; }
network:n1sub = { ip = 10.1.4.0/24; subnet_of = network:n1; }
network:n2 = { ip = 10.2.2.0/24; }
network:n3 = { ip = 10.2.3.0/24; }
network:n4 = { ip = 10.2.4.0/24; }
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
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:n3 = { ip = 10.2.3.1; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
 interface:n4 = { ip = 10.2.4.2; hardware = n4; }
}
pathrestriction:p1 =
 interface:u2.n2,
 interface:r2.n1,
 interface:r2.n3,
;
# This implicitly creates aggregate at zone of n2.
service:s1 = {
 user = network:n4;
 permit src = user; dst = any:[ip=10.1.0.0/16 & network:n1sub]; prt = tcp 80;
}
# Must not show warning on implicit aggregate, because it is located
# in same zone cluster as n1.
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = ip;
}
=OUTPUT=
-- r1
! n2_in
access-list n2_in extended permit ip 10.1.0.0 255.255.0.0 10.2.3.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp 10.2.4.0 255.255.255.0 10.1.0.0 255.255.0.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=No warning on subnet in zone cluster of src/dst
=INPUT=
network:n1 = { ip = 10.1.0.0/16; }
network:n2 = { ip = 10.1.2.0/24; subnet_of = network:n1; }
network:n3 = { ip = 10.1.3.0/24; subnet_of = network:n1; }
network:n4 = { ip = 10.2.4.0/24; }
router:u1 = {
 interface:n1;
 interface:n2;
}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.2.4.2; hardware = n4; }
}
router:r3 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.0.1; hardware = n1; }
 interface:n4 = { ip = 10.2.4.1; hardware = n4; }
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
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = icmp 3, tcp 81-85;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = icmp 4/4, tcp 80-90;
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
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1a = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = icmp 3/13;
}
service:s1b = {
 user = host:h1;
 permit src = user; dst = any:[network:n2]; prt = icmp 3;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = icmp 3/13;
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
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24;
 host:h1a = { ip = 10.1.1.10; }
 host:h1b = { ip = 10.1.1.11; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24;
 host:h3a = { ip = 10.1.3.10; }
 host:h3b = { ip = 10.1.3.11; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
# No IPv6 NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/27;
 nat:n3 = { ip = 10.1.2.32/27; subnet_of = network:n2; }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; nat_out = n3; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = udp 123;
}
service:s2 = {
 user = any:[ip=10.0.0.0/8 & network:n2];
 permit src = user; dst = network:n3; prt = ip;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at network:n2, any:[ip=10.0.0.0/8 & network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - network:n3
=END=

############################################################
=TITLE=Missing transient rule, s1.dst has subnets, s2.dst does match
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[ip=10.1.2.0/23 & network:n2]; prt = udp 123;
}
service:s2 = {
 user = any:[ip=10.0.0.0/8 & network:n2];
 permit src = user; dst = network:n3; prt = udp;
}
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[ip=10.1.2.0/23 & network:n2], any:[ip=10.0.0.0/8 & network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - network:n3
=END=

############################################################
=TITLE=No missing transient rule: supernet doesn't match
=INPUT=
network:n1 = { ip = 10.1.0.0/22; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
}
service:s1 = {
 user = any:[ip=10.1.0.0/21 & network:n1];
 permit src = user; dst = any:[network:n4]; prt = udp 123;
}
service:s2 = {
 user = any:[ip = 10.1.4.0/23 & network:n4];
 permit src = user; dst = network:n5; prt = udp;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule, s1.dst has subnets, but s2.dst doesn't match
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[ip=10.1.2.0/23 & network:n2]; prt = udp 123;
}
service:s2 = {
 user = any:[ip=10.0.0.0/8 & network:n2];
 permit src = user; dst = network:n4; prt = ip;
}
=WARNING=NONE

############################################################
=TITLE=Missing transient rule with managed interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2a = { ip = 10.1.2.0/25; }
network:n2b = { ip = 10.1.2.128/25; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2a = { ip = 10.1.2.1; hardware = n2a; }
}
router:u = {
 managed = routing_only;
 model = IOS;
 interface:n2a = { ip = 10.1.2.2; hardware = n2a; }
 interface:n2b = { ip = 10.1.2.129; hardware = n2b; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2b = { ip = 10.1.2.130; hardware = n2b; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2a]; prt = icmp 3;
}
service:s2 = {
 user = any:[network:n2b];
 permit src = user; dst = network:n3; prt = icmp;
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
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.3; }
 host:h2 = { ip = 10.1.1.5; }
 host:h3 = { ip = 10.1.1.7; }
 host:h4 = { ip = 10.1.1.9; }
 host:h5 = { ip = 10.1.1.11; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n4sub = { ip = 10.1.4.32/27; subnet_of = network:n4; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:u1 = {
 interface:n2 = { ip = 10.1.2.3; }
 interface:n4;
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:u2 = {
 interface:n3 = { ip = 10.1.3.3; }
 interface:n4sub;
}
service:s1 = {
 user = host:h1, host:h2, host:h3, host:h4, host:h5;
 permit src = user; dst = network:n4; prt = ip;
}
service:s2 = {
 user = any:[ip=10.0.0.0/8 & network:n2], any:[network:n3];
 permit src = user; dst = user; prt = udp;
}
service:s3 = {
 user = network:n4sub;
 permit src = user; dst = any:[ip=10.1.1.0/25 & network:n2]; prt = icmp 4/4, icmp 3/13;
}
service:s4 = {
 user = network:n4;
 permit src = user; dst = network:n1; prt = icmp 3/13, icmp 4/5;
}
=END=
# Show matching subnet of dst aggregate.
=WARNING=
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at network:n4, any:[ip=10.0.0.0/8 & network:n2].
 Add missing src elements to service:s2:
 - host:h1
 - host:h2
 - host:h3
 - ...
 or add missing dst elements to service:s1:
 - network:n4sub
Warning: Missing transient supernet rules
 between src of service:s3 and dst of service:s4,
 matching at any:[ip=10.1.1.0/25 & network:n2], network:n4.
 Add missing src elements to service:s4:
 - network:n4sub
 or add missing dst elements to service:s3:
 - network:n1
=END=

############################################################
=TITLE=No transient rule together with "foreach"
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:tr = { ip = 10.9.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:tr = { ip = 10.9.1.1; hardware = tr; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:tr = { ip = 10.9.1.2; hardware = tr; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
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
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 any4
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! tr_in
access-list tr_in extended permit ip any4 any4
access-group tr_in in interface tr
-- r2
! tr_in
access-list tr_in extended permit ip any4 any4
access-group tr_in in interface tr
--
! n2_in
access-list n2_in extended permit ip 10.1.2.0 255.255.255.0 any4
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Disable check for missing transient rule at zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
any:n2 = { link = network:n2; no_check_supernet_rules; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 0.0.0.0/0; has_subnets; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = any:[network:n2],
              any:[network:n3],
              ;
        prt = icmp;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user;
        dst = network:n3;
        prt = icmp 3;
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
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
# Add other zone, that any:[network:n2] is no leaf zone
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = any:[network:n2];
 permit src = network:n1; dst = user; prt = icmp 3;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n1; prt = icmp;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit icmp 10.1.1.0 0.0.0.255 any 3
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 permit icmp any 10.1.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=No missing transient rule for leaf zone
# A leaf security zone has only one connection.
# It can't lead to unwanted rule chains.
=INPUT=
router:r0 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = network:n2;
 permit src = user; dst = any:[network:n1]; prt = tcp 80;
}
service:s2 = {
 user = any:[network:n1];
 permit src = user; dst = network:n3; prt = tcp;
}
=OUTPUT=
--r1
# [ ACL ]
:n1_self -
-A INPUT -j n1_self -i n1
--
:n1_n3 -
-A n1_n3 -j ACCEPT -d 10.1.3.0/24 -p tcp
-A FORWARD -j n1_n3 -i n1 -o n3
--
:n2_self -
-A INPUT -j n2_self -i n2
--
:n2_n1 -
-A n2_n1 -j ACCEPT -s 10.1.2.0/24 -p tcp --dport 80
-A FORWARD -j n2_n1 -i n2 -o n1
--
:n3_self -
-A INPUT -j n3_self -i n3
=END=

############################################################
=TITLE=No missing transient rule if zone isn\'t traversed
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
# Add other zone, that any:[network:n2] is no leaf zone
router:r2 = {
 managed;
 model = Linux;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = icmp 3/13;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = icmp 3;
}
=WARNING=NONE

############################################################
=TITLE=No missing transient rule if zone in loop isn\'t traversed (1)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = Linux;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = Linux;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
network:n1 = { ip = 10.1.1.0/24; }
any:n1 = { link = network:n1; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
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
network:intern = { ip = 10.1.1.0/24; }
router:asa = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 1.2.3.2;
  hardware = outside;
 }
}
area:internet = { border = interface:asa.dmz; }
network:dmz = { ip = 1.2.3.0/25; }
router:extern = {
 interface:dmz = { ip = 1.2.3.1; }
 interface:internet;
}
network:internet = { ip = 0.0.0.0/0; has_subnets; }
service:test = {
 user = network:intern;
 permit src = user; dst = network:[area:internet]; prt = tcp 80;
}
=OUTPUT=
--asa
! inside_in
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 any4 eq 80
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Aggregate linked to non-network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
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
network:n1 = { ip = 10.1.1.0/24; }
any:Trans = { link = network:n2; }
=ERROR=
Error: Referencing undefined network:n2 in 'link' of any:Trans
=END=

############################################################
=TITLE=Duplicate named aggregate in zone
=INPUT=
any:a1 = { link = network:n1; }
any:a2 = { link = network:n2; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
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
any:a1 = { ip = 10.0.0.0/8; link = network:n1; }
any:a2 = { ip = 10.0.0.0/8; link = network:n2; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:u = {
 interface:n1;
 interface:n2;
}
pathrestriction:p = interface:u.n1, interface:r1.n1;
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=ERROR=
Error: Duplicate any:a1 and any:a2 in any:[network:n2]
=END=

############################################################
=TITLE=Network and aggregate have same address in zone (1)
=INPUT=
any:a1 = { ip = 10.0.0.0/8; link = network:n1; }
network:n1 = { ip = 10.0.0.0/8; }
=ERROR=
Error: any:a1 and network:n1 have identical address in any:[network:n1]
=END=

############################################################
=TITLE=Network and aggregate have same address in zone (2)
=INPUT=
any:a1 = { ip = 10.0.0.0/8; link = network:n1; }
network:n1 = { ip = 10.0.0.0/8; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=ERROR=
Error: any:a1 and network:n1 have identical address in any:[network:n1]
=END=

############################################################
=TITLE=Network and aggregate have same address in zone cluster
=INPUT=
any:a1 = { ip = 10.1.2.0/24; link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:u = {
 interface:n1;
 interface:n2;
}
pathrestriction:p = interface:u.n1, interface:r1.n1;
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=ERROR=
Error: any:a1 and network:n2 have identical address in any:[network:n1]
=END=

############################################################
=TITLE=Ignore duplicate aggregates from nested aggregate definition
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
group:clients = any:[network:n1];
service:s1 = {
 user = any:[ ip = 10.1.0.0/16 & group:clients ];
 permit src = user; dst = network:n4; prt = tcp 80;
}
=OUTPUT=
-- r2
! n3_in
access-list n3_in extended permit tcp 10.1.0.0 255.255.0.0 10.1.4.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Must not expand aggregate set of zone cluster twice
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
group:clients = any:[network:n1];
service:s1 = {
 user = group:clients;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=OUTPUT=
-- r2
! n3_in
access-list n3_in extended permit tcp any4 10.1.4.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Zone cluster with keyword foreach
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:ping-local = {
 user = foreach any:[network:n3], any:[network:n1];
 permit src = network:[user]; dst = interface:[user].[all]; prt = icmp 8;
}
service:NTP-local = {
 user = foreach any:[ip = 10.1.2.0/23 & network:n3];
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
--r1
ip access-list extended n1_in
 permit icmp 10.1.1.0 0.0.0.255 host 10.1.1.1 8
 deny ip any any
--
ip access-list extended n2_in
 permit udp 10.1.2.0 0.0.0.255 host 10.1.2.1 eq 123
 permit udp 10.1.3.0 0.0.0.255 host 10.1.2.1 eq 123
 permit icmp 10.1.2.0 0.0.0.255 host 10.1.2.1 8
 permit icmp 10.1.3.0 0.0.0.255 host 10.1.2.1 8
 permit icmp 10.1.4.0 0.0.0.255 host 10.1.2.1 8
 deny ip any any
=END=
