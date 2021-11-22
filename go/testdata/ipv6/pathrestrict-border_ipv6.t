
############################################################
# Shared topology for multiple tests.

############################################################
=TEMPL=topo
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
# Loop 1
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2  = {
 routing = manual;
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
# Loop end
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
# Loop 2
router:r4 = {
 managed;
 model = IOS;
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n5 = { ip = ::a01:501; hardware = n5; }
}
router:r5 = {
 managed;
 model = IOS;
 interface:n4 = { ip = ::a01:403; hardware = n4; }
 interface:n5 = { ip = ::a01:502; hardware = n5; }
}
# Loop end
# Pathrestriction at border of loop 1 at router.
pathrestriction:p1 = interface:r2.n1, interface:r2.n3;
# Pathrestriction at border of loop 2 at zone.
pathrestriction:p2 = interface:r3.n4, interface:r5.n4;
=END=

############################################################
=TITLE=Linear path from PR interface at border of loop at router
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = interface:r2.n3;
 permit src = user; dst = network:n4; prt = udp 514;
}
=END=
=OUTPUT=
--ipv6/r3
ipv6 access-list n3_in
 deny ipv6 any host ::a01:401
 permit udp host ::a01:301 ::a01:400/120 eq 514
 deny ipv6 any any
--
ipv6 access-list n4_in
 permit udp ::a01:400/120 eq 514 host ::a01:301
 deny ipv6 any any
=END=

############################################################
=TITLE=Linear path from PR interface at border of loop at zone
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s2 = {
 user = interface:r3.n4;
 permit src = user; dst = network:n3; prt = udp 514;
}
=END=
=OUTPUT=
--ipv6/r3
ipv6 access-list n3_in
 permit udp ::a01:300/120 eq 514 host ::a01:401
 deny ipv6 any any
--
ipv6 access-list n4_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Cyclic path from PR interface at border of loop at zone
# Name routers in mixed order, such that zone1 is placed inside loop.
=PARAMS=--ipv6
=INPUT=
router:r4 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
network:n1 = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {  ip = ::a01:102; hardware = n1; }
 interface:n2 = {  ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120;}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:103; hardware = n1; }
 interface:n3 = { ip = ::a01:301; hardware = n3;}
}
network:n3 = { ip = ::a01:300/120;}
router:r0 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
network:n4 = {  ip = ::a01:400/120;}
pathrestriction:p1 = interface:r4.n1, interface:r1.n2;
pathrestriction:p2 = interface:r2.n1, interface:r0.n3;
service:s1 = {
 user = interface:r4.[auto];
 permit src = user; dst = network:n4; prt = udp 514;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit udp host ::a01:101 ::a01:400/120 eq 514
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r2
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
# Changed topology for multiple tests.

############################################################
=TEMPL=topo
network:Test =  { ip = ::a09:100/120; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Test = {
  ip = ::a09:101;
  hardware = Vlan20;
 }
 interface:Trans = {
  ip = ::a05:645;
  hardware = GigabitEthernet0/1;
 }
 interface:GRE = {
  ip = ::a05:651;
  hardware = Tunnel1;
 }
}
network:Trans = { ip = ::a05:644/126; }
network:GRE =   { ip = ::a05:650/126; }
router:Kunde = {
 interface:Trans = { ip = ::a05:646; }
 interface:GRE =   { ip = ::a05:652; }
 interface:X =     { ip = ::a09:301; }
 interface:Schulung = { ip = ::a09:201; }
}
network:X =        { ip = ::a09:300/120; }
network:Schulung = { ip = ::a09:200/120; }
=END=

############################################################
=TITLE=Pathrestriction at border of loop (at router)
# Soll an router:filter für Interfaces GRE und Trans unterschiedliche
# ACLs generieren.
=PARAMS=--ipv6
=INPUT=
[[topo]]
pathrestriction:restrict =
 description = Nur network:X über GRE-Tunnel.
 interface:filter.GRE,
 interface:Kunde.Schulung,
;
protocol:IP = ip;
service:test = {
 user = network:Schulung, network:X;
 permit src = user;
	dst = network:Test;
	prt = protocol:IP;
}
=END=
=OUTPUT=
--ipv6/filter
ipv6 access-list GigabitEthernet0/1_in
 deny ipv6 any host ::a09:101
 permit ipv6 ::a09:200/119 ::a09:100/120
 deny ipv6 any any
--
ipv6 access-list Tunnel1_in
 deny ipv6 any host ::a09:101
 permit ipv6 ::a09:300/120 ::a09:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Two pathrestrictions at border of loop (at router)
=PARAMS=--ipv6
=INPUT=
[[topo]]
pathrestriction:restrict1 =
 description = Nur network:X über GRE-Tunnel.
 interface:filter.GRE,
 interface:Kunde.Schulung,
;
pathrestriction:restrict2 =
 description = network:X nur über GRE-Tunnel.
 interface:filter.Trans,
 interface:Kunde.X,
;
protocol:IP = ip;
service:test = {
 user = network:Schulung, network:X;
 permit src = user;
	dst = network:Test;
	prt = protocol:IP;
}
=END=
=OUTPUT=
--ipv6/filter
ipv6 access-list GigabitEthernet0/1_in
 deny ipv6 any host ::a09:101
 permit ipv6 ::a09:200/120 ::a09:100/120
 deny ipv6 any any
--
ipv6 access-list Tunnel1_in
 deny ipv6 any host ::a09:101
 permit ipv6 ::a09:300/120 ::a09:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestriction at border of loop (at router / at dst.)
# Soll Ausgang der Loop als Router erkennen, obwohl intern
# ein Interface verwendet wird.
=PARAMS=--ipv6
=INPUT=
[[topo]]
pathrestriction:restrict =
 interface:filter.Test,
 interface:filter.Trans,
;
service:test = {
 user = network:Schulung;
 permit src = user;
	dst = any:[network:Test];
	prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/filter
ipv6 access-list GigabitEthernet0/1_in
 deny ipv6 any any
--
ipv6 access-list Tunnel1_in
 deny ipv6 any host ::a09:101
 deny ipv6 any host ::a05:645
 deny ipv6 any host ::a05:651
 permit tcp ::a09:200/120 any eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestriction at border of loop (at any)
# Soll network:Trans beim path_walk wegen der Pathrestriction
# nicht versehentlich als Router ansehen
=PARAMS=--ipv6
=INPUT=
network:Test =  { ip = ::a09:100/120; }
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = {
  ip = ::a09:101;
  hardware = Vlan20;
 }
 interface:Trans = {
  ip = ::a05:601;
  hardware = GigabitEthernet0/1;
 }
}
router:filter2 = {
 managed;
 model = IOS, FW;
 interface:Test = {
  ip = ::a09:102;
  hardware = Vlan20;
 }
 interface:Trans = {
  ip = ::a05:602;
  hardware = GigabitEthernet0/1;
 }
}
network:Trans = { ip = ::a05:600/120; }
router:Kunde = {
 managed;
 model = IOS, FW;
 log_deny;
 interface:Trans = { ip = ::a05:646; hardware = E0; }
 interface:Schulung = { ip = ::a09:201; hardware = E1; }
}
network:Schulung = { ip = ::a09:200/120; }
pathrestriction:restrict =
 description = Nur über filter1
 interface:filter2.Trans,
 interface:Kunde.Trans,
;
protocol:IP = ip;
service:test = {
 user = network:Schulung;
 permit src = user;
	dst = network:Test;
	prt = protocol:IP;
}
=END=
=OUTPUT=
--ipv6/Kunde
ipv6 route ::a09:100/120 ::a05:601
--
ipv6 access-list E0_in
 deny ipv6 any any log
--
ipv6 access-list E1_in
 permit ipv6 ::a09:200/120 ::a09:100/120
 deny ipv6 any any log
=END=

############################################################
=TITLE=Pathrestriction at border of nested loop
# Soll auch bei verschachtelter Loop den Pfad finden.
=PARAMS=--ipv6
=INPUT=
network:top = { ip = ::a01:100/120;}
network:cnt = { ip = ::a03:1f0/126;}
router:c1 = {
 managed;
 model = IOS;
 interface:top = { ip = ::a01:101; hardware = Vlan13; }
 interface:lft = { ip = ::a03:1f5; hardware = Ethernet1; routing = dynamic; }
 interface:cnt = { ip = ::a03:1f1; hardware = Ethernet2; routing = dynamic; }
 interface:mng = { ip = ::a03:1f9; hardware = Ethernet3; }
}
router:c2 = {
 managed;
 model = IOS;
 interface:top = { ip = ::a01:102; hardware = Vlan14; }
 interface:rgt = { ip = ::a03:181; hardware = Ethernet4; routing = dynamic; }
 interface:cnt = { ip = ::a03:1f2; hardware = Ethernet5; routing = dynamic; }
}
network:mng = { ip = ::a03:1f8/126;}
network:lft = { ip = ::a03:1f4/126;}
network:rgt = { ip = ::a03:180/126;}
router:k2 = {
 interface:rgt  = {ip = ::a03:182;}
 interface:lft  = {ip = ::a03:1f6;}
 interface:dst;
}
network:dst = { ip = ::a03:1fc/126;}
pathrestriction:a = interface:c1.lft, interface:k2.rgt;
pathrestriction:mng = interface:c1.mng, interface:c2.top;
protocol:IP = ip;
service:intra = {
 user = any:[network:dst], any:[network:top], any:[network:cnt];
 permit src = interface:c1.mng;
        dst = user;
        prt = protocol:IP;
}
=END=
=OUTPUT=
--ipv6/c1
ipv6 access-list Vlan13_in
 permit ipv6 any host ::a03:1f9
 deny ipv6 any any
--ipv6/c2
ipv6 access-list Ethernet4_in
 permit ipv6 any host ::a03:1f9
 deny ipv6 any any
--
ipv6 access-list Ethernet5_in
 deny ipv6 any host ::a01:102
 deny ipv6 any host ::a03:181
 deny ipv6 any host ::a03:1f2
 permit ipv6 host ::a03:1f9 any
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestriction at border of loop and at end of path
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2;
 }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2;  }
}
network:n2 = { ip = ::a01:200/120; }
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = ::a01:246; hardware = E0; }
 interface:n3 = { ip = ::a01:301; hardware = E1; }
}
network:n3 = { ip = ::a01:300/120; }
pathrestriction:restrict1 =
 interface:r1.n1,
 interface:r3.n2,
;
pathrestriction:restrict2 =
 interface:r2.n1,
 interface:r3.n2,
;
service:test = {
 user = network:n1;
 permit src = user; dst = interface:r3.[auto]; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r2
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:246 eq 80
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp host ::a01:246 ::a01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Minimal path inside loop with pathrestriction at border inside path
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = ::a01:203; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
pathrestriction:p1 = interface:r1.n2, interface:r3.n2;
service:s1 = {
 user = network:n3;
 permit src = user; dst = interface:r1.n2; prt = icmpv6 8;
 permit src = interface:r1.n2; dst = user; prt = icmpv6 8;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 permit icmp ::a01:300/120 host ::a01:201 8
 deny ipv6 any any
--ipv6/r3
ipv6 access-list n2_in
 deny ipv6 any host ::a01:301
 permit icmp host ::a01:201 ::a01:300/120 8
 deny ipv6 any any
--
ipv6 access-list n3_in
 permit icmp ::a01:300/120 host ::a01:201 8
 deny ipv6 any any
=END=

############################################################
=TITLE=Mixed start and entry at pathrestriction at border of loop
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2;
 }
}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2;  }
}
network:n2 = { ip = ::a01:200/120; }
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:203; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
pathrestriction:restrict1 =
 interface:r2.n1,
 interface:r3.n2,
;
service:s1 = {
 user = interface:r3.n2;
 permit src = user; dst = network:n1; prt = tcp 80;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 81;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 deny ipv6 any host ::a01:101
 permit tcp host ::a01:203 ::a01:100/120 eq 80
 permit tcp ::a01:300/120 ::a01:100/120 eq 81
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n2_in
 deny ipv6 any host ::a01:102
 permit tcp host ::a01:203 ::a01:100/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Path ends at pathrestricted interface of zone at border of loop
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r4 = {
 interface:n4 = { ip = ::a01:403; hardware = n4; }
}
pathrestriction:restrict1 = interface:r2.n2, interface:r4.n4;
pathrestriction:restrict2 = interface:r3.n3, interface:r3.n4;
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r4.n4; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 host ::a01:403 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--ipv6/r3
! n3_in
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Valid pathrestriction at unmanged router
# Neighbor zones of any:[network:n2] all belong to same zone cluster.
# Therefore we need to check neighbors of all elements of zone cluster.
=TEMPL=input
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:u1 = {
 interface:n1;
 interface:n2;
}
router:u2 = {
 interface:n2;
 interface:n3;
}
router:r1 = {
 {{.}}
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r2 = {
 {{.}}
 model = ASA;
 routing = manual;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
}
pathrestriction:r = interface:u1.n2, interface:u2.n2;
=END=
=PARAMS=--ipv6
=INPUT=[[input managed;]]
=WARNING=NONE

############################################################
=TITLE=Useless pathrestriction at unmanged router
=PARAMS=--ipv6
=INPUT=[[input ""]]
=WARNING=
Warning: Useless pathrestriction:r.
 All interfaces are unmanaged and located inside the same security zone
=END=

############################################################
=TITLE=Pathrestriction at exit of minimal loop (at router)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1;
 interface:t1;
 interface:t2;
}
network:t1 = { unnumbered; }
network:t2 = { unnumbered; }
router:r2 = {
 model = Linux;
 managed;
 routing = manual;
 interface:t1 = { unnumbered;    hardware = t1; }
 interface:t2 = { unnumbered;    hardware = t2; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
pathrestriction:p1 =
 interface:r2.t1,
 interface:r2.t2,
 interface:r2.n2,
;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 1100;
}
=END=
# Pathrestriction must be effective even after optimizition.
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n2]
 for rule permit src=network:n1; dst=network:n2; prt=tcp 1100; of service:s1
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Pathrestriction at exit of minimal loop (at zone)
=TEMPL=input
network:n1 = { ip = ::a01:110/124;}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = ::a01:111; hardware = n1; }
 interface:t1 = { ip = ::a09:152; hardware = t1; }
 interface:t2 = { ip = ::a09:252; hardware = t2; }
}
network:t1 = { ip = ::a09:150/124; }
network:t2 = { ip = ::a09:250/124; }
router:r2 = {
 interface:t1;
 interface:t2;
 interface:t3;
}
network:t3 = { ip = ::a09:300/120; }
router:r3 = {
 interface:t3;
 interface:n2;
}
network:n2 = { ip = ::a01:200/120; }
pathrestriction:p1 =
 interface:r1.t1,
 interface:r1.t2,
 interface:r3.t3,
;
=PARAMS=--ipv6
=INPUT=
[[input]]
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
# Pathrestriction must be effective even after optimizition.
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n2]
 for rule permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Pathrestriction at exit of minimal loop (at zone, reversed)
=TEMPL=input
network:n1 = { ip = ::a01:110/124;}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = ::a01:111; hardware = n1; }
 interface:t1 = { ip = ::a09:152; hardware = t1; }
 interface:t2 = { ip = ::a09:252; hardware = t2; }
}
network:t1 = { ip = ::a09:150/124; }
network:t2 = { ip = ::a09:250/124; }
router:r2 = {
 interface:t1;
 interface:t2;
 interface:t3;
}
network:t3 = { ip = ::a09:300/120; }
router:r3 = {
 interface:t3;
 interface:n2;
}
network:n2 = { ip = ::a01:200/120; }
pathrestriction:p1 =
 interface:r1.t1,
 interface:r1.t2,
 interface:r3.t3,
;
=PARAMS=--ipv6
=INPUT=
[[input]]
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
# Pathrestriction must be effective even after optimizition.
=ERROR=
Error: No valid path
 from any:[network:n2]
 to any:[network:n1]
 for rule permit src=network:n2; dst=network:n1; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Pathrestriction at virtual interface at loop zone border
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;}
network:n2 = {ip = ::a02:200/120;}
network:n3 = { ip = ::a03:300/120;}
network:n4 = { ip = ::a04:400/120;}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = ::a01:101; hardware = E1;}
 interface:n2 = { ip = ::a02:203; virtual = {ip = ::a02:20a;} hardware = E2; }
 }
router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip = ::a03:301; hardware = E1; }
 interface:n2 = { ip = ::a02:201; hardware = E2; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = ::a03:302; hardware = E1; }
 interface:n2 = { ip = ::a02:202; hardware = E2; }
 interface:n4 = { ip = ::a04:401; hardware = E3; }
}
pathrestriction:p1 =
 interface:r3.n3,
 interface:r3.n4,
;
service:test = {
 user = network:n1;
 permit src =   user;
        dst =   network:n4;
        prt =   ip;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list E1_in
 permit ipv6 ::a01:100/120 ::a04:400/120
 deny ipv6 any any
--ipv6/r2
ipv6 access-list E2_in
 deny ipv6 any any
--ipv6/r3
ipv6 access-list E2_in
 deny ipv6 any host ::a04:401
 permit ipv6 ::a01:100/120 ::a04:400/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Path starting at restricted interface without entering the loop
# Must not assume, that path enters loop.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:u = {
 interface:n1 = { ip = ::a01:103; }
 interface:n3;
 interface:n4;
}
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r3 = {
 model = Linux;
 managed;
 routing = manual;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
pathrestriction:p1 = interface:r1.n1, interface:r3.n4;
service:s1 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2; prt = proto 50;
 permit src = network:n2; dst = user; prt = proto 50;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit 50 ::a01:200/120 host ::a01:101
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit 50 host ::a01:101 ::a01:200/120
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit 50 ::a01:200/120 host ::a01:101
 deny ipv6 any any
=END=

############################################################
