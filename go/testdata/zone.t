
############################################################
=TITLE=Implicit group of aggregates from zone cluster
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
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.2; }
}
pathrestriction:p = interface:r1.n2, interface:r3.n2;
service:s1 = {
 user = network:n1;
 # implicitly add any:[network:n2]
 permit src = user; dst = any:[network:n3]; prt = tcp 22;
}
=END=
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 any4 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 any4 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Inherit owner from all zones of zone cluster
=INPUT=
network:Test =  { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.1; hardware = Test; }
 interface:Trans1 = { ip = 10.5.6.1; hardware = Trans1; }
}
router:filter2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.2; hardware = Test; }
 interface:Trans2 = { ip = 10.5.7.1; hardware = Trans2; }
}
network:Trans1 = { ip = 10.5.6.0/24; }
network:Trans2 = { ip = 10.5.7.0/24; owner = t1;}
router:Kunde = {
 interface:Trans1 = { ip = 10.5.6.2; }
 interface:Trans2 = { ip = 10.5.7.2; }
}
pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;
owner:t1 = { admins = guest; }
any:Trans1 = { link = network:Trans1; owner = t1; }
=END=
=WARNING=
Warning: Useless owner:t1 at network:Trans2,
 it was already inherited from any:Trans1
=END=

############################################################
=TITLE=Networks with identical address in zone cluster
=INPUT=
network:n1a = { ip = 10.1.1.0/24; }
network:n1b = { ip = 10.1.1.0/24; }
router:u = {
 managed = routing_only;
 model = IOS;
 interface:n1a = { ip = 10.1.1.1; hardware = n1a; }
 interface:n1b = { ip = 10.1.1.1; hardware = n1b; }
}
=ERROR=
Error: network:n1a and network:n1b have identical IP/mask in any:[network:n1a]
=END=

############################################################
=TITLE=Duplicate IP from NAT in zone
=INPUT=
network:A = { ip = 10.3.3.120/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
network:B = { ip = 10.3.3.128/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
router:ras = {
 interface:A = { ip = 10.3.3.121; }
 interface:B = { ip = 10.3.3.129; }
 interface:Trans = { ip = 10.1.1.2; bind_nat = C; }
}
network:Trans = { ip = 10.1.1.0/24;}
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = Trans; }
}
service:s1 = {
 user = network:A;
 permit src = user; dst = interface:filter1.Trans; prt = tcp 22;
}
=END=
=ERROR=
Error: network:B and network:A have identical IP/mask in any:[network:Trans]
=END=

############################################################
=TITLE=No secondary optimization for network with subnet in other zone
=INPUT=
network:A = {
 ip = 10.3.3.0/25;
 host:h = { ip = 10.3.3.5; }
}
network:sub = { ip = 10.3.3.8/29; subnet_of = network:A; }
router:secondary = {
 managed = secondary;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip = 10.3.3.1; hardware = A; }
 interface:sub = { ip = 10.3.3.9; hardware = sub; }
 interface:Trans = { ip = 10.1.1.2; hardware = Trans; }
}
network:Trans = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.1.1.1; hardware = Trans; }
 interface:Customer = { ip = 10.9.9.1; hardware = Customer; }
}
network:Customer = { ip = 10.9.9.0/24; }
service:test = {
 user = network:Customer;
 permit src = user; dst = host:h; prt = tcp 80;
}
=END=
=OUTPUT=
--secondary
ip access-list extended Trans_in
 permit ip 10.9.9.0 0.0.0.255 host 10.3.3.5
 deny ip any any
=END=

############################################################
=TITLE=Skip supernet with subnet in other zone in secondary optimization
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:secondary = {
 model = IOS, FW;
 managed = secondary;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.1.8.1; hardware = t1; }
}
network:t1 = { ip = 10.1.8.0/24; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.1.8.2; hardware = t1; }
 interface:t2 = { ip = 10.1.9.1; hardware = t2; }
}
network:t2 = { ip = 10.1.9.0/24;}
router:trahza01 = {
 interface:t2;
 interface:super;
 interface:sub1;
}
# Must not use super as supernet, because it has sub2 as subnet in other zone.
network:super = {
 has_subnets;
 ip = 192.168.0.0/16;
}
network:sub1 = { ip = 192.168.1.0/24;}
# Must not use aggregate as supernet.
any:a1 = { ip = 192.168.0.0/21; link = network:sub2; }
router:r3 = {
 managed;
 model = ASA;
 interface:t1 = {ip = 10.1.8.3; hardware = t1;}
 interface:sub2 = { ip = 192.168.8.1; hardware = sub2; }
}
network:sub2 = { ip = 192.168.8.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:sub1; prt = tcp 49;
}
=END=
=OUTPUT=
--secondary
ip access-list extended n1_in
 permit ip 10.1.1.0 0.0.0.255 192.168.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Skip supernet with NAT in secondary optimization
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:secondary = {
 model = IOS, FW;
 managed = secondary;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; bind_nat = nat; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.1.8.1; hardware = t1; }
}
network:t1 = { ip = 10.1.8.0/24; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.1.8.2; hardware = t1; }
 interface:t2 = { ip = 10.1.9.1; hardware = t2; }
}
network:t2 = { ip = 10.1.9.0/24;}
router:trahza01 = {
 interface:t2;
 interface:super;
 interface:sub1;
 interface:sub2;
}
network:super = {
 has_subnets;
 ip = 192.168.0.0/16;
 nat:nat = { hidden; }
}
network:sub1 = {
 ip = 192.168.1.0/24;
 nat:nat = { identity; }
}
network:sub2 = { ip = 192.168.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:sub1; prt = tcp 49;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:sub2; prt = tcp 49;
}
=END=
=OUTPUT=
--secondary
ip access-list extended n1_in
 permit ip 10.1.1.0 0.0.0.255 192.168.1.0 0.0.0.255
 deny ip any any
--
ip access-list extended n2_in
 permit ip 10.1.2.0 0.0.0.255 192.168.0.0 0.0.255.255
 deny ip any any
=END=

############################################################
=TITLE=Get hosts also from subnet
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h10 = { ip = 10.1.2.10; } }
network:n2Sub = {
 ip = 10.1.2.32/27;
 subnet_of = network:n2;
 host:h40 = { ip = 10.1.2.40; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n2Sub = { ip = 10.1.2.33; }
}
service:s1 = {
 user = host:[network:n2];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
! n2_in
object-group network g0
 network-object host 10.1.2.10
 network-object host 10.1.2.40
access-list n2_in extended permit tcp object-group g0 10.1.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Prevent duplicate hosts from zone cluster in area
=INPUT=
area:n1-2 = { border = interface:r2.n2; }
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed = routing_only;
 model = IOS;
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
 user = host:[area:n1-2];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
-- r2
! n2_in
object-group network g0
 network-object host 10.1.1.10
 network-object host 10.1.2.10
access-list n2_in extended permit tcp object-group g0 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not accidently add zone twice to cluster
# If using 'activePath', zone:[n3] would be added twice.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24;}
network:n4 = { ip = 10.1.4.0/24;}
any:n1 = { link = network:n1;}
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = 10.1.3.1; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; routing = dynamic; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
pathrestriction:p = interface:r1.n2, interface:r2.n2;
service:s1 = {
 user = any:n1;
 permit src = user; dst = network:n4; prt = udp 123;
}
=END=
=OUTPUT=
--r2
! [ Routing ]
ip route 10.1.1.0 255.255.255.0 10.1.3.1
ip route 10.1.4.0 255.255.255.0 10.1.3.3
=END=

############################################################
=TITLE=Zone connected twice to routing_only router (1)
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24;}
router:r1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.1; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=
=ERROR=
Error: Two static routes for network:n1
 via interface:r2.n3 and interface:r2.n2
=END=

############################################################
=TITLE=Zone connected twice to routing_only router (2)
# Pathrestriction has no effect on traffic from router:r2,
# hence two routes are found.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24;}
router:r1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.1; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
pathrestriction:p = interface:r1.n2, interface:r2.n2;
=END=
=ERROR=
Error: Two static routes for network:n1
 via interface:r2.n3 and interface:r2.n2
=END=

############################################################
=TITLE=Zone connected twice to routing_only router (3)
# Pathrestriction is useless, hence two routes are found.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24;}
router:r1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.1; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
pathrestriction:p = interface:r1.n2, interface:r2.n3;
=END=
=ERROR=
Error: Two static routes for network:n1
 via interface:r2.n3 and interface:r2.n2
=END=

############################################################
