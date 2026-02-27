
############################################################
# Shared topology for multiple tests.

############################################################
=TEMPL=topo
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
# Loop 1
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2  = {
 routing = manual;
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
# Loop end
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
# Loop 2
router:r4 = {
 managed;
 model = IOS;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
router:r5 = {
 managed;
 model = IOS;
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
}
# Loop end
# Pathrestriction at border of loop 1 at router.
pathrestriction:p1 = interface:r2.n1, interface:r2.n3;
# Pathrestriction at border of loop 2 at zone.
pathrestriction:p2 = interface:r3.n4, interface:r5.n4;
=END=

############################################################
=TITLE=Linear path from PR interface at border of loop at router
=INPUT=
[[topo]]
service:s1 = {
 user = interface:r2.n3;
 permit src = user; dst = network:n4; prt = udp 514;
}
=OUTPUT=
--r3
ip access-list extended n3_in
 deny ip any host 10.1.4.1
 permit udp host 10.1.3.1 10.1.4.0 0.0.0.255 eq 514
 deny ip any any
--
ip access-list extended n4_in
 permit udp 10.1.4.0 0.0.0.255 eq 514 host 10.1.3.1
 deny ip any any
=END=

############################################################
=TITLE=Linear path from PR interface at border of loop at zone
=INPUT=
[[topo]]
service:s2 = {
 user = interface:r3.n4;
 permit src = user; dst = network:n3; prt = udp 514;
}
=OUTPUT=
--r3
ip access-list extended n3_in
 permit udp 10.1.3.0 0.0.0.255 eq 514 host 10.1.4.1
 deny ip any any
--
ip access-list extended n4_in
 deny ip any any
=END=

############################################################
=TITLE=Cyclic path from PR interface at border of loop at zone
# Name routers in mixed order, such that zone1 is placed inside loop.
=INPUT=
router:r4 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {  ip = 10.1.1.2; hardware = n1; }
 interface:n2 = {  ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24;}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3;}
}
network:n3 = { ip = 10.1.3.0/24;}
router:r0 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
network:n4 = {  ip = 10.1.4.0/24;}
pathrestriction:p1 = interface:r4.n1, interface:r1.n2;
pathrestriction:p2 = interface:r2.n1, interface:r0.n3;
service:s1 = {
 user = interface:r4.[auto];
 permit src = user; dst = network:n4; prt = udp 514;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit udp host 10.1.1.1 10.1.4.0 255.255.255.0 eq 514
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
# Changed topology for multiple tests.

############################################################
=TEMPL=topo
network:Test =  { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = Vlan20;
 }
 interface:Trans = {
  ip = 10.5.6.69;
  hardware = GigabitEthernet0/1;
 }
 interface:GRE = {
  ip = 10.5.6.81;
  hardware = Tunnel1;
 }
}
network:Trans = { ip = 10.5.6.68/30; }
network:GRE =   { ip = 10.5.6.80/30; }
router:Kunde = {
 interface:Trans = { ip = 10.5.6.70; }
 interface:GRE =   { ip = 10.5.6.82; }
 interface:X =     { ip = 10.9.3.1; }
 interface:Schulung = { ip = 10.9.2.1; }
}
network:X =        { ip = 10.9.3.0/24; }
network:Schulung = { ip = 10.9.2.0/24; }
=END=

############################################################
=TITLE=Pathrestriction at border of loop (at router)
# Soll an router:filter für Interfaces GRE und Trans unterschiedliche
# ACLs generieren.
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
=OUTPUT=
--filter
ip access-list extended GigabitEthernet0/1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.2.0 0.0.1.255 10.9.1.0 0.0.0.255
 deny ip any any
--
ip access-list extended Tunnel1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.3.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Two pathrestrictions at border of loop (at router)
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
=OUTPUT=
--filter
ip access-list extended GigabitEthernet0/1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.2.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
--
ip access-list extended Tunnel1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.3.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Pathrestriction at border of loop (at router / at dst.)
# Soll Ausgang der Loop als Router erkennen, obwohl intern
# ein Interface verwendet wird.
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
=OUTPUT=
--filter
ip access-list extended GigabitEthernet0/1_in
 deny ip any any
--
ip access-list extended Tunnel1_in
 deny ip any host 10.9.1.1
 deny ip any host 10.5.6.69
 deny ip any host 10.5.6.81
 permit tcp 10.9.2.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Pathrestriction at border of loop (at any)
# Soll network:Trans beim path_walk wegen der Pathrestriction
# nicht versehentlich als Router ansehen
=INPUT=
network:Test =  { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = Vlan20;
 }
 interface:Trans = {
  ip = 10.5.6.1;
  hardware = GigabitEthernet0/1;
 }
}
router:filter2 = {
 managed;
 model = IOS, FW;
 interface:Test = {
  ip = 10.9.1.2;
  hardware = Vlan20;
 }
 interface:Trans = {
  ip = 10.5.6.2;
  hardware = GigabitEthernet0/1;
 }
}
network:Trans = { ip = 10.5.6.0/24; }
router:Kunde = {
 managed;
 model = IOS, FW;
 log_deny;
 interface:Trans = { ip = 10.5.6.70; hardware = E0; }
 interface:Schulung = { ip = 10.9.2.1; hardware = E1; }
}
network:Schulung = { ip = 10.9.2.0/24; }
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
=OUTPUT=
--Kunde
ip route 10.9.1.0 255.255.255.0 10.5.6.1
--
ip access-list extended E0_in
 deny ip any any log
--
ip access-list extended E1_in
 permit ip 10.9.2.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any log
=END=

############################################################
=TITLE=Pathrestriction at border of nested loop
# Soll auch bei verschachtelter Loop den Pfad finden.
=INPUT=
network:top = { ip = 10.1.1.0/24;}
network:cnt = { ip = 10.3.1.240/30;}
router:c1 = {
 managed;
 model = IOS;
 interface:top = { ip = 10.1.1.1; hardware = Vlan13; }
 interface:lft = { ip = 10.3.1.245; hardware = Ethernet1; routing = dynamic; }
 interface:cnt = { ip = 10.3.1.241; hardware = Ethernet2; routing = dynamic; }
 interface:mng = { ip = 10.3.1.249; hardware = Ethernet3; }
}
router:c2 = {
 managed;
 model = IOS;
 interface:top = { ip = 10.1.1.2; hardware = Vlan14; }
 interface:rgt = { ip = 10.3.1.129; hardware = Ethernet4; routing = dynamic; }
 interface:cnt = { ip = 10.3.1.242; hardware = Ethernet5; routing = dynamic; }
}
network:mng = { ip = 10.3.1.248/30;}
network:lft = { ip = 10.3.1.244/30;}
network:rgt = { ip = 10.3.1.128/30;}
router:k2 = {
 interface:rgt  = {ip = 10.3.1.130;}
 interface:lft  = {ip = 10.3.1.246;}
 interface:dst;
}
network:dst = { ip = 10.3.1.252/30;}
pathrestriction:a = interface:c1.lft, interface:k2.rgt;
pathrestriction:mng = interface:c1.mng, interface:c2.top;
protocol:IP = ip;
service:intra = {
 user = any:[network:dst], any:[network:top], any:[network:cnt];
 permit src = interface:c1.mng;
        dst = user;
        prt = protocol:IP;
}
=OUTPUT=
--c1
ip access-list extended Vlan13_in
 permit ip any host 10.3.1.249
 deny ip any any
--c2
ip access-list extended Ethernet4_in
 permit ip any host 10.3.1.249
 deny ip any any
--
ip access-list extended Ethernet5_in
 deny ip any host 10.1.1.2
 deny ip any host 10.3.1.129
 deny ip any host 10.3.1.242
 permit ip host 10.3.1.249 any
 deny ip any any
=END=

############################################################
=TITLE=Pathrestriction at border of loop and at end of path
=INPUT=
network:n1 =  { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2;
 }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2;  }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.70; hardware = E0; }
 interface:n3 = { ip = 10.1.3.1; hardware = E1; }
}
network:n3 = { ip = 10.1.3.0/24; }
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
=OUTPUT=
--r2
! [ ACL ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.70 eq 80
 deny ip any any
--
ip access-list extended n2_in
 permit tcp host 10.1.2.70 10.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Minimal path inside loop with pathrestriction at border inside path
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
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
pathrestriction:p1 = interface:r1.n2, interface:r3.n2;
service:s1 = {
 user = network:n3;
 permit src = user; dst = interface:r1.n2; prt = icmp 8;
 permit src = interface:r1.n2; dst = user; prt = icmp 8;
}
=OUTPUT=
--r1
ip access-list extended n2_in
 permit icmp 10.1.3.0 0.0.0.255 host 10.1.2.1 8
 deny ip any any
--r3
ip access-list extended n2_in
 deny ip any host 10.1.3.1
 permit icmp host 10.1.2.1 10.1.3.0 0.0.0.255 8
 deny ip any any
--
ip access-list extended n3_in
 permit icmp 10.1.3.0 0.0.0.255 host 10.1.2.1 8
 deny ip any any
=END=

############################################################
=TITLE=Mixed start and entry at pathrestriction at border of loop
=INPUT=
network:n1 =  { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2;
 }
}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2;  }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
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
=OUTPUT=
--r1
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 permit tcp host 10.1.2.3 10.1.1.0 0.0.0.255 eq 80
 permit tcp 10.1.3.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 81
 deny ip any any
--r2
ip access-list extended n2_in
 deny ip any host 10.1.1.2
 permit tcp host 10.1.2.3 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Path ends at pathrestricted interface of zone at border of loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r4 = {
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
}
pathrestriction:restrict1 = interface:r2.n2, interface:r4.n4;
pathrestriction:restrict2 = interface:r3.n3, interface:r3.n4;
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r4.n4; prt = tcp 22;
}
=OUTPUT=
--r2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 host 10.1.4.3 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r3
! n3_in
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Valid pathrestriction at unmanged router
# Neighbor zones of any:[network:n2] all belong to same zone cluster.
# Therefore we need to check neighbors of all elements of zone cluster.
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 {{.}}
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
pathrestriction:r = interface:u1.n2, interface:u2.n2;
=INPUT=[[input managed;]]
=WARNING=NONE

############################################################
=TITLE=Useless pathrestriction at unmanged router
=INPUT=[[input ""]]
=WARNING=
Warning: Useless pathrestriction:r.
 All interfaces are unmanaged and located inside the same security zone
=END=

############################################################
=TITLE=Pathrestriction at exit of minimal loop (at router)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
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
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
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
 Possible blocking pathrestrictions:
  - pathrestriction:p1 (blocked 2 path attempts)
=END=

############################################################
=TITLE=Pathrestriction at exit of minimal loop (at zone)
=TEMPL=input
network:n1 = { ip = 10.1.1.16/28;}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
 interface:t2 = { ip = 10.9.2.82; hardware = t2; }
}
network:t1 = { ip = 10.9.1.80/28; }
network:t2 = { ip = 10.9.2.80/28; }
router:r2 = {
 interface:t1;
 interface:t2;
 interface:t3;
}
network:t3 = { ip = 10.9.3.0/24; }
router:r3 = {
 interface:t3;
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
pathrestriction:p1 =
 interface:r1.t1,
 interface:r1.t2,
 interface:r3.t3,
;
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
network:n1 = { ip = 10.1.1.16/28;}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
 interface:t2 = { ip = 10.9.2.82; hardware = t2; }
}
network:t1 = { ip = 10.9.1.80/28; }
network:t2 = { ip = 10.9.2.80/28; }
router:r2 = {
 interface:t1;
 interface:t2;
 interface:t3;
}
network:t3 = { ip = 10.9.3.0/24; }
router:r3 = {
 interface:t3;
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
pathrestriction:p1 =
 interface:r1.t1,
 interface:r1.t2,
 interface:r3.t3,
;
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = {ip = 10.2.2.0/24;}
network:n3 = { ip = 10.3.3.0/24;}
network:n4 = { ip = 10.4.4.0/24;}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = { ip = 10.2.2.3; virtual = {ip = 10.2.2.10;} hardware = E2; }
 }
router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.3.3.1; hardware = E1; }
 interface:n2 = { ip = 10.2.2.1; hardware = E2; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.3.3.2; hardware = E1; }
 interface:n2 = { ip = 10.2.2.2; hardware = E2; }
 interface:n4 = { ip = 10.4.4.1; hardware = E3; }
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
=OUTPUT=
--r1
ip access-list extended E1_in
 permit ip 10.1.1.0 0.0.0.255 10.4.4.0 0.0.0.255
 deny ip any any
--r2
ip access-list extended E2_in
 deny ip any any
--r3
ip access-list extended E2_in
 deny ip any host 10.4.4.1
 permit ip 10.1.1.0 0.0.0.255 10.4.4.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Path starting at restricted interface without entering the loop
# Must not assume, that path enters loop.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:u = {
 interface:n1 = { ip = 10.1.1.3; }
 interface:n3;
 interface:n4;
}
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r3 = {
 model = Linux;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
pathrestriction:p1 = interface:r1.n1, interface:r3.n4;
service:s1 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2; prt = proto 50;
 permit src = network:n2; dst = user; prt = proto 50;
}
=OUTPUT=
--r1
ip access-list extended n1_in
 permit 50 10.1.2.0 0.0.0.255 host 10.1.1.1
 deny ip any any
--r2
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit 50 host 10.1.1.1 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended n2_in
 permit 50 10.1.2.0 0.0.0.255 host 10.1.1.1
 deny ip any any
=END=

############################################################
=TITLE=Pathrestricted interface between two loops, router first
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r3 = {
 interface:n4;
 interface:n5;
}
router:r4 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
pathrestriction:pr1 = interface:r2.n4, interface:r1.n3;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = ip;
}
=OUTPUT=
--r2
! n2_in
access-list n2_in extended permit ip 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Pathrestricted interface between two loops, zone first
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
}
router:r4 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.4; hardware = n3; }
 interface:n4 = { ip = 10.1.4.4; hardware = n4; }
}
pathrestriction:pr1 = interface:r3.n2, interface:r3.n4;

service:s1 = {
 user = network:n4;
 permit src = user; dst = network:n1; prt = ip;
}
=OUTPUT=
--r3
! n3_in
access-list n3_in extended permit ip 10.1.4.0 255.255.255.0 10.1.1.0 255.255.255.0
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
--
! n4_in
access-list n4_in extended deny ip any4 any4
access-group n4_in in interface n4
=END=
