
############################################################
=TITLE=Combine adjacent routes to same hop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:u1 = {
 interface:t1 = { ip = 10.9.1.2; }
 interface:n2a;
 interface:n2b;
 interface:n2c;
 interface:n3a;
 interface:n4a;
 interface:n4b;
}
router:u2 = {
 interface:t1 = { ip = 10.9.1.3; }
 interface:n3b;
 interface:n4;
 interface:l5a = { ip = 10.5.0.4; loopback; }
 interface:l5b = { ip = 10.5.0.5; loopback; }
 interface:l5c = { ip = 10.5.0.6; loopback; }
 interface:l5d = { ip = 10.5.0.7; loopback; }
}
network:n2a = { ip = 10.1.2.0/26; }
network:n2b = { ip = 10.1.2.64/26; }
network:n2c = { ip = 10.1.2.128/25; }
network:n3a = { ip = 10.1.3.0/25; }
network:n3b = { ip = 10.1.3.128/25; }
network:n4a = { ip = 10.1.4.0/25; subnet_of = network:n4; }
network:n4b = { ip = 10.1.4.128/25; subnet_of = network:n4; }
network:n4  = { ip = 10.1.4.0/24; }
service:test = {
 user = network:n2a,
        network:n2b,
        network:n2c,
        network:n3a,
        network:n3b,
        network:n4a,
        network:n4b,
        interface:u2.l5a,
        interface:u2.l5b,
        interface:u2.l5c,
        interface:u2.l5d,
 ;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--r1
! [ Routing ]
ip route 10.1.3.0/25 10.9.1.2
ip route 10.1.4.0/25 10.9.1.2
ip route 10.1.4.128/25 10.9.1.2
ip route 10.1.2.0/24 10.9.1.2
ip route 10.5.0.4/30 10.9.1.3
ip route 10.1.3.128/25 10.9.1.3
ip route 10.1.4.0/24 10.9.1.3
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Remove redundant routes, even if combined already exists
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:u1 = {
 interface:t1 = { ip = 10.9.1.2; }
 interface:n2a;
 interface:n2b;
 interface:n2;
}
network:n2a = { ip = 10.1.2.0/25; subnet_of = network:n2; }
network:n2b = { ip = 10.1.2.128/25; subnet_of = network:n2; }
network:n2  = { ip = 10.1.2.0/24; }
service:test = {
 user = network:n2a, network:n2b;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--r1
! [ Routing ]
ip route 10.1.2.0/24 10.9.1.2
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Missing next hop
=INPUT=
network:N = { ip = 10.1.1.0/24; }
router:u = {
 interface:N;
 interface:Trans;
}
network:Trans = { ip = 10.9.9.0/24; }
router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.9.9.1; hardware = outside; }
 interface:Kunde = { ip = 10.2.2.1; hardware = inside; }
}
network:Kunde = { ip = 10.2.2.0/24; }
service:test = {
 user = network:N;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=END=
=ERROR=
Error: Can't generate static routes for interface:asa.Trans because IP address is unknown for:
 - interface:u.Trans
=END=

############################################################
=TITLE=Negotiated interface as next hop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { negotiated; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
# Error message should only be shown once, even if another interface is defined.
router:r3 = {
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=ERROR=
Error: Can't generate static routes for interface:r2.n2 because IP address is unknown for:
 - interface:r1.n2
=END=

############################################################
=TITLE=Two static unmanaged hops
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/29; }
router:h1 = {
 interface:t1 = { ip = 10.9.1.2; }
 interface:n2;
}
router:h2 = {
 interface:t1 = { ip = 10.9.1.3; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=ERROR=
Error: Two static routes for network:n2
 at interface:r.t1 via interface:h2.t1 and interface:h1.t1
=END=

############################################################
=TITLE=Sort hops by name to get deterministic default route
=INPUT=
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
network:t1 = { ip = 10.9.1.0/24; }
router:u2 = {
 interface:n1;
 interface:n2;
 interface:t1 = { ip = 10.9.1.2; }
}
router:u1 = {
 interface:n3;
 interface:n4;
 interface:t1 = { ip = 10.9.1.3; }
}
router:u3 = {
 interface:n5;
 interface:n6;
 interface:t1 = { ip = 10.9.1.4; }
}
router:r = {
 managed = routing_only;
 model = IOS;
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
=OUTPUT=
--r
! [ Routing ]
ip route 0.0.0.0 0.0.0.0 10.9.1.3
ip route 10.1.1.0 255.255.255.0 10.9.1.2
ip route 10.1.2.0 255.255.255.0 10.9.1.2
ip route 10.1.5.0 255.255.255.0 10.9.1.4
ip route 10.1.6.0 255.255.255.0 10.9.1.4
=END=

############################################################
=TITLE=Static route to network in unmanaged loop
=INPUT=
network:N = { ip = 10.1.1.0/24; }
router:u1 = {
 interface:N;
 interface:T1;
}
router:u2 = {
 interface:N;
 interface:T2;
}
network:T1 = { unnumbered; }
network:T2 = { unnumbered; }
router:u3 = {
 interface:T1;
 interface:T2;
 interface:Trans = { ip = 10.9.9.2; }
}
network:Trans = { ip = 10.9.9.0/24; }
router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.9.9.1; hardware = outside; }
 interface:Kunde = { ip = 10.2.2.1; hardware = inside; }
}
network:Kunde = { ip = 10.2.2.0/24; }
service:test = {
 user = network:N;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=END=
=OUTPUT=
--asa
route outside 10.1.1.0 255.255.255.0 10.9.9.2
=END=

############################################################
=TITLE=Route in zone to one member of virtual interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.3; virtual = { ip = 10.1.2.1; } }
 interface:n3;
}
router:r3 = {
 interface:n2 = { ip = 10.1.2.4; virtual = { ip = 10.1.2.1; } }
 interface:n4;
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3, network:n4; prt = udp 123;
}
=END=
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.3.0 255.255.255.0 10.1.2.3
route n2 10.1.4.0 255.255.255.0 10.1.2.4
=END=

############################################################
=TITLE=Handle recursion for routes in zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.3; virtual = { ip = 10.1.2.1; } }
 interface:n3;
}
router:r3 = {
 interface:n2 = { ip = 10.1.2.4; virtual = { ip = 10.1.2.1; } }
 interface:n4;
}
router:r4 = {
 interface:n3;
 interface:n5 = { ip = 10.1.5.3; virtual = { ip = 10.1.5.1; } }
}
router:r5 = {
 interface:n4;
 interface:n5 = { ip = 10.1.5.4; virtual = { ip = 10.1.5.1; } }
}
router:r6 = {
 managed;
 model = ASA;
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; }
}
service:s1 = {
 user = network:n3, network:n4, network:n5;
 permit src = network:n1; dst = user; prt = udp 123;
}
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.3.0 255.255.255.0 10.1.2.1
route n2 10.1.4.0 255.255.254.0 10.1.2.1
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Intermediate network hides subnet
=TEMPL=input
network:n1 = { ip = 10.1.1.0/28; subnet_of = network:n2; }
network:n2 = { ip = 10.1.1.0/24; subnet_of = network:n3; }
network:n3 = { ip = 10.1.0.0/16; }
network:n4 = { ip = 10.2.0.0/16; }
router:h1 = {
 interface:n1;
 interface:n3;
 interface:n4;
 interface:t1 = { ip = 10.9.1.2; }
}
router:h2 = {
 interface:n2;
 interface:t2 = { ip = 10.9.2.2; }
}
network:t1 = { ip = 10.9.1.0/30; }
network:t2 = { ip = 10.9.2.0/30; }
router:r = {
 model = Linux;
 managed;
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
}
service:test = {
 user = network:n1{{.n4}};
 permit src = user; dst = network:n2; prt = icmp 8;
}
=END=
=INPUT=[[input {n4: ""}]]
=OUTPUT=
--r
# [ Routing ]
ip route add 10.1.1.0/28 via 10.9.1.2
ip route add 10.1.0.0/16 via 10.9.1.2
ip route add 10.1.1.0/24 via 10.9.2.2
=END=

############################################################
=TITLE=Default route with intermediate network hides subnet
=INPUT=[[input {n4: ",network:n4"}]]
=OUTPUT=
--r
# [ Routing ]
ip route add 0.0.0.0/0 via 10.9.1.2
ip route add 10.1.1.0/28 via 10.9.1.2
ip route add 10.1.1.0/24 via 10.9.2.2
=END=

############################################################
=TITLE=Route for redundant subnet
=INPUT=
[[input {n4: ",network:n4"}]]
service:test2 = {
 user = network:n3;
 permit src = user; dst = network:n2; prt = icmp 8;
}
=OUTPUT=
--r
# [ Routing ]
ip route add 0.0.0.0/0 via 10.9.1.2
ip route add 10.1.1.0/28 via 10.9.1.2
ip route add 10.1.1.0/24 via 10.9.2.2
=END=
=OPTIONS=--check_redundant_rules=0

############################################################
=TITLE=Must not optimize route to supernet in other part of zone cluster
=TEMPL=topo
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.5.128/25; subnet_of = network:n5; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
}
router:r4 = {
 interface:n3;
 interface:n4;
}
router:r5 = {
 interface:n3;
 interface:n5;
}
router:r6 = {
 interface:n4;
 interface:n6;
}
pathrestriction:p1 = interface:r2.n3, interface:r4.n3;
pathrestriction:p2 = interface:r3.n4, interface:r4.n4;
=INPUT=
# Would create ambiguous route vor n5 if added as maxRoutingNet for n6.
[[topo]]
service:s1 = {
 user = network:n5, network:n6;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.5.0 255.255.255.0 10.1.2.2
route n2 10.1.5.128 255.255.255.128 10.1.2.3
=OPTIONS=--check_redundant_rules=0

############################################################
=TITLE=Add route for subnet with different path than supernet
=INPUT=
[[topo]]
service:s1 = {
 user = network:n5;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.5.0 255.255.255.0 10.1.2.2
route n2 10.1.5.128 255.255.255.128 10.1.2.3
--r3
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.5.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Add route for subnet with different path
=INPUT=
[[topo]]
any:00 = { link = network:n3; }
service:s1 = {
 user = network:[any:00];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.3.0 255.255.255.0 10.1.2.2
route n2 10.1.5.0 255.255.255.0 10.1.2.2
route n2 10.1.5.128 255.255.255.128 10.1.2.3
route n2 10.1.4.0 255.255.255.0 10.1.2.3
--r2
! n2_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object 10.1.5.0 255.255.255.0
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 object-group g0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r3
! n2_in
object-group network g0
 network-object 10.1.4.0 255.255.255.0
 network-object 10.1.5.128 255.255.255.128
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 object-group g0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Add routes for all subnets of aggregate having IP of supernet
=INPUT=
[[topo]]
service:s1 = {
 user = any:[ip = 10.1.5.0/24 & network:n6];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.5.0 255.255.255.0 10.1.2.2
route n2 10.1.5.128 255.255.255.128 10.1.2.3
=END=

############################################################
=TITLE=Add routes for all subnets of aggregate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/25; }
network:n6 = { ip = 10.1.5.128/25; }
any:n5 = { ip = 10.1.5.0/24; link = network:n5; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
}
router:r4 = {
 interface:n3;
 interface:n4;
}
router:r5 = {
 interface:n3;
 interface:n5;
}
router:r6 = {
 interface:n4;
 interface:n6;
}
pathrestriction:p1 = interface:r2.n3, interface:r4.n3;
pathrestriction:p2 = interface:r3.n4, interface:r4.n4;
service:s1 = {
 user = any:n5;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.5.0 255.255.255.128 10.1.2.2
route n2 10.1.5.128 255.255.255.128 10.1.2.3
=END=

############################################################
=TITLE=Check NAT when finding largest supernet for route.
=INPUT=
network:src = { ip = 10.1.1.0/24; }
router:r = {
 model = NX-OS;
 managed;
 interface:src = { ip = 10.1.1.1; hardware = src; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/30; }
router:hop = {
 model = NX-OS;
 managed;
 interface:t1 = { ip = 10.9.1.2; hardware = inside; bind_nat = h; }
 interface:t2 = { ip = 10.9.2.1; hardware = outside; }
}
network:t2 = { ip = 10.9.2.0/30; }
router:u = {
 interface:t2 = { ip = 10.9.2.2; }
 interface:n1;
 interface:n2;
 interface:n3;
}
network:n1 = {
 ip = 10.2.1.0/28;
 subnet_of = network:n2;
}
network:n2 = {
 ip = 10.2.1.0/24;
 nat:h = { identity; }
 subnet_of = network:n3;
}
network:n3 = {
 ip = 10.2.0.0/16;
 nat:h = { hidden; }
}
service:test = {
 user = network:n1;
 permit src = network:src; dst = user; prt = icmp 8;
}
service:test2 = {
 user = network:n3;
 permit src = interface:hop.t2; dst = user; prt = icmp 8;
}
=END=
=OUTPUT=
--r
! [ Routing ]
ip route 10.2.1.0/24 10.9.1.2
--hop
! [ Routing ]
ip route 10.1.1.0/24 10.9.1.1
ip route 10.2.0.0/16 10.9.2.2
=END=

############################################################
=TITLE=Networks inside and outside of zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
router:r2 = {
 model = NX-OS;
 managed;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:u = {
 interface:t1 = { ip = 10.9.1.3; }
 interface:n3;
}
service:test = {
 user = network:n2, network:n3;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--r1
! [ Routing ]
ip route 10.1.2.0/24 10.9.1.2
ip route 10.1.3.0/24 10.9.1.3
--r2
! [ Routing ]
ip route 10.1.1.0/24 10.9.1.1
=END=

############################################################
=TITLE=Zone cluster, two directions
# Find route from r1.n2 to n3, even if path from n2 to n3 is reused.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}
network:n2  = {ip = 10.1.2.0/24;}
router:r2 = {
 managed = routing_only;
 model = ASA;
 interface:n2 = {ip = 10.1.2.2; hardware = n2;}
 interface:n3 = {ip = 10.1.3.1; hardware = n3;}
}
network:n3  = {ip = 10.1.3.0/24;}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 10.1.3.2; hardware = n3;}
}
service:s1 = {
 user = network:n2;
 permit src = user; dst = interface:r3.n3; prt = tcp 80;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=END=
=OUTPUT=
--r1
! [ Routing ]
route n2 10.1.3.0 255.255.255.0 10.1.2.2
--r3
! [ Routing ]
route n3 10.1.2.0 255.255.255.0 10.1.3.1
=END=

############################################################
=TITLE=Zone cluster reaching multiple interfaces of router
# Generates route for n2, although n2 is directly connected.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2; routing = OSPF;}
}
router:u1 = {
 interface:n1 = {ip = 10.1.1.2;}
 interface:n2 = {ip = 10.1.2.2;}
}
network:n2  = {ip = 10.1.2.0/24;}
pathrestriction:n1 = interface:u1.n1, interface:r1.n1;
service:ping_local = {
 user = foreach interface:r1.n1, interface:r1.n2;
 permit src = any:[user]; dst = user; prt = icmp 8;
}
=END=
=OUTPUT=
--r1
! [ Routing ]
ip route 10.1.2.0 255.255.255.0 10.1.1.2
=END=

############################################################
=TITLE=No route between pair of virtual interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:u1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.4; }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; virtual = { ip = 10.1.2.3; } }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; virtual = { ip = 10.1.3.3; } }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; virtual = { ip = 10.1.2.3; } }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; virtual = { ip = 10.1.3.3; } }
}
router:u2 = {
 interface:n3 = { ip = 10.1.3.4; }
 interface:n4;
}
# Must not find route for path n1 -> u1.n2 -> r2.n2 -> r2.n3 -> r1.n3
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.n3.virtual; prt = tcp 80;
}
# Must not find route for path r1.n2 -> r2.n2 -> r2.n3 -> u2.n3 -> n3
service:s2 = {
 user = interface:r1.n2.virtual;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
! [ Routing ]
ip route 10.1.1.0 255.255.255.0 10.1.2.4
ip route 10.1.4.0 255.255.255.0 10.1.3.4
-- r2
! [ Routing ]
ip route 10.1.1.0 255.255.255.0 10.1.2.4
ip route 10.1.4.0 255.255.255.0 10.1.3.4
=END=

############################################################
=TITLE=Must not add routes for zone at start interface at zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
service:s1 = {
 user = network:n4;
 permit src = user; dst = network:n1; prt = tcp 80;
}
# Must generate route for n2, but not for n1 at router:r3.
service:s2 = {
 user = interface:r3.n4;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
-- r3
! [ Routing ]
route n4 10.1.2.0 255.255.255.0 10.1.4.1
=END=

############################################################
