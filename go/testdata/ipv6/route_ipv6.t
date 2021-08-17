
############################################################
=TITLE=Combine adjacent routes to same hop
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
network:t1 = { ip = ::a09:100/120; }
router:u1 = {
 interface:t1 = { ip = ::a09:102; }
 interface:n2a;
 interface:n2b;
 interface:n2c;
 interface:n3a;
 interface:n4a;
 interface:n4b;
}
router:u2 = {
 interface:t1 = { ip = ::a09:103; }
 interface:n3b;
 interface:n4;
 interface:l5a = { ip = ::a05:4; loopback; }
 interface:l5b = { ip = ::a05:5; loopback; }
 interface:l5c = { ip = ::a05:6; loopback; }
 interface:l5d = { ip = ::a05:7; loopback; }
}
network:n2a = { ip = ::a01:200/122; }
network:n2b = { ip = ::a01:240/122; }
network:n2c = { ip = ::a01:280/121; }
network:n3a = { ip = ::a01:300/121; }
network:n3b = { ip = ::a01:380/121; }
network:n4a = { ip = ::a01:400/121; subnet_of = network:n4; }
network:n4b = { ip = ::a01:480/121; subnet_of = network:n4; }
network:n4  = { ip = ::a01:400/120; }
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
--ipv6/r1
! [ Routing ]
ipv6 route ::a01:300/121 ::a09:102
ipv6 route ::a01:400/121 ::a09:102
ipv6 route ::a01:480/121 ::a09:102
ipv6 route ::a01:200/120 ::a09:102
ipv6 route ::a05:4/126 ::a09:103
ipv6 route ::a01:380/121 ::a09:103
ipv6 route ::a01:400/120 ::a09:103
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Remove redundant routes, even if combined already exists
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
network:t1 = { ip = ::a09:100/120; }
router:u1 = {
 interface:t1 = { ip = ::a09:102; }
 interface:n2a;
 interface:n2b;
 interface:n2;
}
network:n2a = { ip = ::a01:200/121; subnet_of = network:n2; }
network:n2b = { ip = ::a01:280/121; subnet_of = network:n2; }
network:n2  = { ip = ::a01:200/120; }
service:test = {
 user = network:n2a, network:n2b;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route ::a01:200/120 ::a09:102
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Missing next hop
=PARAMS=--ipv6
=INPUT=
network:N = { ip = ::a01:100/120; }
router:u = {
 interface:N;
 interface:Trans;
}
network:Trans = { ip = ::a09:900/120; }
router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip = ::a09:901; hardware = outside; }
 interface:Kunde = { ip = ::a02:201; hardware = inside; }
}
network:Kunde = { ip = ::a02:200/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { negotiated; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
# Error message should only be shown once, even if another interface is defined.
router:r3 = {
 interface:n2 = { ip = ::a01:203; hardware = n2; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
network:t1 = { ip = ::a09:100/125; }
router:h1 = {
 interface:t1 = { ip = ::a09:102; }
 interface:n2;
}
router:h2 = {
 interface:t1 = { ip = ::a09:103; }
 interface:n2;
}
network:n2 = { ip = ::a01:200/120; }
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
=TITLE=Static route to network in unmanaged loop
=PARAMS=--ipv6
=INPUT=
network:N = { ip = ::a01:100/120; }
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
 interface:Trans = { ip = ::a09:902; }
}
network:Trans = { ip = ::a09:900/120; }
router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip = ::a09:901; hardware = outside; }
 interface:Kunde = { ip = ::a02:201; hardware = inside; }
}
network:Kunde = { ip = ::a02:200/120; }
service:test = {
 user = network:N;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/asa
ipv6 route outside ::a01:100/120 ::a09:902
=END=

############################################################
=TITLE=Route in zone to one member of virtual interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = ::a01:203; virtual = { ip = ::a01:201; } }
 interface:n3;
}
router:r3 = {
 interface:n2 = { ip = ::a01:204; virtual = { ip = ::a01:201; } }
 interface:n4;
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3, network:n4; prt = udp 123;
}
=END=
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:300/120 ::a01:203
ipv6 route n2 ::a01:400/120 ::a01:204
=END=

############################################################
=TITLE=Handle recursion for routes in zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
network:n6 = { ip = ::a01:600/120; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = ::a01:203; virtual = { ip = ::a01:201; } }
 interface:n3;
}
router:r3 = {
 interface:n2 = { ip = ::a01:204; virtual = { ip = ::a01:201; } }
 interface:n4;
}
router:r4 = {
 interface:n3;
 interface:n5 = { ip = ::a01:503; virtual = { ip = ::a01:501; } }
}
router:r5 = {
 interface:n4;
 interface:n5 = { ip = ::a01:504; virtual = { ip = ::a01:501; } }
}
router:r6 = {
 managed;
 model = ASA;
 interface:n5 = { ip = ::a01:502; hardware = n5; }
 interface:n6 = { ip = ::a01:601; hardware = n6; }
}
service:s1 = {
 user = network:n3, network:n4, network:n5;
 permit src = network:n1; dst = user; prt = udp 123;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:300/120 ::a01:201
ipv6 route n2 ::a01:400/119 ::a01:201
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Intermediate network hides subnet
=VAR=input
network:n1 = { ip = ::a01:100/124; subnet_of = network:n2; }
network:n2 = { ip = ::a01:100/120; subnet_of = network:n3; }
network:n3 = { ip = ::a01:0/112; }
network:n4 = { ip = ::a02:0/112; }
router:h1 = {
 interface:n1;
 interface:n3;
 interface:n4;
 interface:t1 = { ip = ::a09:102; }
}
router:h2 = {
 interface:n2;
 interface:t2 = { ip = ::a09:202; }
}
network:t1 = { ip = ::a09:100/126; }
network:t2 = { ip = ::a09:200/126; }
router:r = {
 model = Linux;
 managed;
 interface:t1 = { ip = ::a09:101; hardware = t1; }
 interface:t2 = { ip = ::a09:201; hardware = t2; }
}
service:test = {
 user = network:n1;#, network:n4;
 permit src = user; dst = network:n2; prt = icmpv6 8;
}
=END=
=PARAMS=--ipv6
=INPUT=${input}
=OUTPUT=
--ipv6/r
# [ Routing ]
ip route add ::a01:100/124 via ::a09:102
ip route add ::a01:0/112 via ::a09:102
ip route add ::a01:100/120 via ::a09:202
=END=

############################################################
=TITLE=Default route with intermediate network hides subnet
=PARAMS=--ipv6
=INPUT=${input}
=SUBST=/;#,/,/
=OUTPUT=
--ipv6/r
# [ Routing ]
ip route add ::/0 via ::a09:102
ip route add ::a01:100/124 via ::a09:102
ip route add ::a01:100/120 via ::a09:202
=END=

############################################################
=TITLE=Route for redundant subnet
=PARAMS=--ipv6
=INPUT=
${input}
service:test2 = {
 user = network:n3;
 permit src = user; dst = network:n2; prt = icmpv6 8;
}
=END=
=SUBST=/;#,/,/
=OUTPUT=
--ipv6/r
# [ Routing ]
ip route add ::/0 via ::a09:102
ip route add ::a01:100/124 via ::a09:102
ip route add ::a01:100/120 via ::a09:202
=END=
=OPTIONS=--check_redundant_rules=0

############################################################
=TITLE=Check NAT when finding largest supernet for route.
=PARAMS=--ipv6
=INPUT=
network:src = { ip = ::a01:100/120; }
router:r = {
 model = NX-OS;
 managed;
 interface:src = { ip = ::a01:101; hardware = src; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
network:t1 = { ip = ::a09:100/126; }
router:hop = {
 model = NX-OS;
 managed;
 interface:t1 = { ip = ::a09:102; hardware = inside; bind_nat = h; }
 interface:t2 = { ip = ::a09:201; hardware = outside; }
}
network:t2 = { ip = ::a09:200/126; }
router:u = {
 interface:t2 = { ip = ::a09:202; }
 interface:n1;
 interface:n2;
 interface:n3;
}
network:n1 = {
 ip = ::a02:100/124;
 subnet_of = network:n2;
}
network:n2 = {
 ip = ::a02:100/120;
 nat:h = { identity; }
 subnet_of = network:n3;
}
network:n3 = {
 ip = ::a02:0/112;
 nat:h = { hidden; }
}
service:test = {
 user = network:n1;
 permit src = network:src; dst = user; prt = icmpv6 8;
}
service:test2 = {
 user = network:n3;
 permit src = interface:hop.t2; dst = user; prt = icmpv6 8;
}
=END=
=OUTPUT=
--ipv6/r
! [ Routing ]
ipv6 route ::a02:100/120 ::a09:102
--ipv6/hop
! [ Routing ]
ipv6 route ::a01:100/120 ::a09:101
ipv6 route ::a02:0/112 ::a09:202
=END=

############################################################
=TITLE=Networks inside and outside of zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
router:r2 = {
 model = NX-OS;
 managed;
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:t1 = { ip = ::a09:102; hardware = t1; }
}
network:t1 = { ip = ::a09:100/120; }
router:u = {
 interface:t1 = { ip = ::a09:103; }
 interface:n3;
}
service:test = {
 user = network:n2, network:n3;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route ::a01:200/120 ::a09:102
ipv6 route ::a01:300/120 ::a09:103
--ipv6/r2
! [ Routing ]
ipv6 route ::a01:100/120 ::a09:101
=END=

############################################################
=TITLE=Zone cluster, two directions
# Find route from r1.n2 to n3, even if path from n2 to n3 is reused.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = ::a01:101; hardware = n1;}
 interface:n2 = {ip = ::a01:201; hardware = n2; }
}
network:n2  = {ip = ::a01:200/120;}
router:r2 = {
 managed = routing_only;
 model = ASA;
 interface:n2 = {ip = ::a01:202; hardware = n2;}
 interface:n3 = {ip = ::a01:301; hardware = n3;}
}
network:n3  = {ip = ::a01:300/120;}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = {ip = ::a01:302; hardware = n3;}
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
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:300/120 ::a01:202
--ipv6/r3
! [ Routing ]
ipv6 route n3 ::a01:200/120 ::a01:301
=END=

############################################################
=TITLE=Zone cluster reaching multiple interfaces of router
# Generates route for n2, although n2 is directly connected.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = ::a01:101; hardware = n1;}
 interface:n2 = {ip = ::a01:201; hardware = n2; routing = OSPF;}
}
router:u1 = {
 interface:n1 = {ip = ::a01:102;}
 interface:n2 = {ip = ::a01:202;}
}
network:n2  = {ip = ::a01:200/120;}
pathrestriction:n1 = interface:u1.n1, interface:r1.n1;
service:ping_local = {
 user = foreach interface:r1.n1, interface:r1.n2;
 permit src = any:[user]; dst = user; prt = icmpv6 8;
}
=END=
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route ::a01:200/120 ::a01:102
=END=

############################################################
=TITLE=No route between pair of virtual interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:u1 = {
 interface:n1;
 interface:n2 = { ip = ::a01:204; }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = ::a01:201; hardware = n2; virtual = { ip = ::a01:203; } }
 interface:n3 = { ip = ::a01:301; hardware = n3; virtual = { ip = ::a01:303; } }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = ::a01:202; hardware = n2; virtual = { ip = ::a01:203; } }
 interface:n3 = { ip = ::a01:302; hardware = n3; virtual = { ip = ::a01:303; } }
}
router:u2 = {
 interface:n3 = { ip = ::a01:304; }
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
-- ipv6/r1
! [ Routing ]
ipv6 route ::a01:100/120 ::a01:204
ipv6 route ::a01:400/120 ::a01:304
-- ipv6/r2
! [ Routing ]
ipv6 route ::a01:100/120 ::a01:204
ipv6 route ::a01:400/120 ::a01:304
=END=

############################################################
=TITLE=Must not add routes for zone at start interface at zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n4 = { ip = ::a01:402; hardware = n4; }
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
-- ipv6/r3
! [ Routing ]
ipv6 route n4 ::a01:200/120 ::a01:401
=END=

############################################################
