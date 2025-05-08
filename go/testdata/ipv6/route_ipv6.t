
############################################################
=TITLE=Combine adjacent routes to same hop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
network:t1 = { ip6 = ::a09:100/120; }
router:u1 = {
 interface:t1 = { ip6 = ::a09:102; }
 interface:n2a;
 interface:n2b;
 interface:n2c;
 interface:n3a;
 interface:n4a;
 interface:n4b;
}
router:u2 = {
 interface:t1 = { ip6 = ::a09:103; }
 interface:n3b;
 interface:n4;
 interface:l5a = { ip6 = ::a05:4; loopback; }
 interface:l5b = { ip6 = ::a05:5; loopback; }
 interface:l5c = { ip6 = ::a05:6; loopback; }
 interface:l5d = { ip6 = ::a05:7; loopback; }
}
network:n2a = { ip6 = ::a01:200/122; }
network:n2b = { ip6 = ::a01:240/122; }
network:n2c = { ip6 = ::a01:280/121; }
network:n3a = { ip6 = ::a01:300/121; }
network:n3b = { ip6 = ::a01:380/121; }
network:n4a = { ip6 = ::a01:400/121; subnet_of = network:n4; }
network:n4b = { ip6 = ::a01:480/121; subnet_of = network:n4; }
network:n4  = { ip6 = ::a01:400/120; }
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
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Remove redundant routes, even if combined already exists
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
network:t1 = { ip6 = ::a09:100/120; }
router:u1 = {
 interface:t1 = { ip6 = ::a09:102; }
 interface:n2a;
 interface:n2b;
 interface:n2;
}
network:n2a = { ip6 = ::a01:200/121; subnet_of = network:n2; }
network:n2b = { ip6 = ::a01:280/121; subnet_of = network:n2; }
network:n2  = { ip6 = ::a01:200/120; }
service:test = {
 user = network:n2a, network:n2b;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route ::a01:200/120 ::a09:102
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Missing next hop
=INPUT=
network:N = { ip6 = ::a01:100/120; }
router:u = {
 interface:N;
 interface:Trans;
}
network:Trans = { ip6 = ::a09:900/120; }
router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip6 = ::a09:901; hardware = outside; }
 interface:Kunde = { ip6 = ::a02:201; hardware = inside; }
}
network:Kunde = { ip6 = ::a02:200/120; }
service:test = {
 user = network:N;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=ERROR=
Error: Can't generate static routes for interface:asa.Trans because IP address is unknown for:
 - interface:u.Trans
=END=

############################################################
=TITLE=Negotiated interface as next hop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { negotiated6; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
# Error message should only be shown once, even if another interface is defined.
router:r3 = {
 interface:n2 = { ip6 = ::a01:203; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=ERROR=
Error: Can't generate static routes for interface:r2.n2 because IP address is unknown for:
 - interface:r1.n2
=END=

############################################################
=TITLE=Two static unmanaged hops
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
network:t1 = { ip6 = ::a09:100/125; }
router:h1 = {
 interface:t1 = { ip6 = ::a09:102; }
 interface:n2;
}
router:h2 = {
 interface:t1 = { ip6 = ::a09:103; }
 interface:n2;
}
network:n2 = { ip6 = ::a01:200/120; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Two static routes for network:n2
 at interface:r.t1 via interface:h2.t1 and interface:h1.t1
=END=

############################################################
=TITLE=Sort hops by name to get deterministic default route
=INPUT=
network:n0 = { ip6 = ::a01:0/120; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
network:n6 = { ip6 = ::a01:600/120; }
network:t1 = { ip6 = ::a09:100/120; }
router:u2 = {
 interface:n1;
 interface:n2;
 interface:t1 = { ip6 = ::a09:102; }
}
router:u1 = {
 interface:n3;
 interface:n4;
 interface:t1 = { ip6 = ::a09:103; }
}
router:u3 = {
 interface:n5;
 interface:n6;
 interface:t1 = { ip6 = ::a09:104; }
}
router:r = {
 managed = routing_only;
 model = IOS;
 interface:n0 = { ip6 = ::a01:1; hardware = n0; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
=OUTPUT=
--ipv6/r
! [ Routing ]
ipv6 route ::/0 ::a09:103
ipv6 route ::a01:100/120 ::a09:102
ipv6 route ::a01:200/120 ::a09:102
ipv6 route ::a01:500/120 ::a09:104
ipv6 route ::a01:600/120 ::a09:104
=END=

############################################################
=TITLE=Default route for ASA
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip6 = ::a01:203; }
 interface:n3;
 interface:n4;
 interface:n5;
}
service:s1 = {
 user = network:n3, network:n4, network:n5;
 permit src = network:n1; dst = user; prt = udp 123;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::/0 ::a01:203
=END=

############################################################
=TITLE=No default route together with internet.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:inet = { ip6 = ::/0; has_subnets; }

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
 interface:inet = { ip6 = ::1; hardware = inet; }
}
router:r3 = {
 interface:n2 = { ip6 = ::a01:203; }
 interface:n3;
 interface:n4;
}
service:s1 = {
 user = network:n2, network:n3, network:n4, network:inet;
 permit src = network:n1; dst = user; prt = udp 123;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::/0 ::a01:202
ipv6 route n2 ::a01:300/120 ::a01:203
ipv6 route n2 ::a01:400/120 ::a01:203
=END=

############################################################
=TITLE=Static route to network in unmanaged loop
=INPUT=
network:N = { ip6 = ::a01:100/120; }
router:u1 = {
 interface:N;
 interface:T1;
}
router:u2 = {
 interface:N;
 interface:T2;
}
network:T1 = { unnumbered6; }
network:T2 = { unnumbered6; }
router:u3 = {
 interface:T1;
 interface:T2;
 interface:Trans = { ip6 = ::a09:902; }
}
network:Trans = { ip6 = ::a09:900/120; }
router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip6 = ::a09:901; hardware = outside; }
 interface:Kunde = { ip6 = ::a02:201; hardware = inside; }
}
network:Kunde = { ip6 = ::a02:200/120; }
service:test = {
 user = network:N;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=OUTPUT=
--ipv6/asa
ipv6 route outside ::a01:100/120 ::a09:902
=END=

############################################################
=TITLE=Route to unmanged single virtual interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip6 = ::a01:203; virtual = { ip6 = ::a01:201; } }
 interface:n3;
}
# Need a second route to prevent optimization
# which would generate a default route.
router:r3 = {
 interface:n2 = { ip6 = ::a01:204; }
 interface:n4;
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = udp 123;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:300/120 ::a01:201
=END=

############################################################
=TITLE=Route in zone to one member of virtual interfaces
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip6 = ::a01:203; virtual = { ip6 = ::a01:201; } }
 interface:n3;
}
router:r3 = {
 interface:n2 = { ip6 = ::a01:204; virtual = { ip6 = ::a01:201; } }
 interface:n4;
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3, network:n4; prt = udp 123;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:300/120 ::a01:203
ipv6 route n2 ::a01:400/120 ::a01:204
=END=

############################################################
=TITLE=Handle recursion for routes in zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
network:n6 = { ip6 = ::a01:600/120; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip6 = ::a01:203; virtual = { ip6 = ::a01:201; } }
 interface:n3;
}
router:r3 = {
 interface:n2 = { ip6 = ::a01:204; virtual = { ip6 = ::a01:201; } }
 interface:n4;
}
router:r4 = {
 interface:n3;
 interface:n5 = { ip6 = ::a01:503; virtual = { ip6 = ::a01:501; } }
}
router:r5 = {
 interface:n4;
 interface:n5 = { ip6 = ::a01:504; virtual = { ip6 = ::a01:501; } }
}
router:r6 = {
 managed;
 model = ASA;
 interface:n5 = { ip6 = ::a01:502; hardware = n5; }
 interface:n6 = { ip6 = ::a01:601; hardware = n6; }
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
=TEMPL=input
network:n1 = { ip6 = ::a01:100/124; subnet_of = network:n2; }
network:n2 = { ip6 = ::a01:100/120; subnet_of = network:n3; }
network:n3 = { ip6 = ::a01:0/112; }
network:n4 = { ip6 = ::a02:0/112; }
router:h1 = {
 interface:n1;
 interface:n3;
 interface:n4;
 interface:t1 = { ip6 = ::a09:102; }
}
router:h2 = {
 interface:n2;
 interface:t2 = { ip6 = ::a09:202; }
}
network:t1 = { ip6 = ::a09:100/126; }
network:t2 = { ip6 = ::a09:200/126; }
router:r = {
 model = Linux;
 managed;
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
 interface:t2 = { ip6 = ::a09:201; hardware = t2; }
}
service:test = {
 user = network:n1{{.n4}};
 permit src = user; dst = network:n2; prt = icmpv6 8;
}
=INPUT=[[input {n4: ""}]]
=OUTPUT=
--ipv6/r
# [ Routing ]
ip route add ::a01:100/124 via ::a09:102
ip route add ::a01:0/112 via ::a09:102
ip route add ::a01:100/120 via ::a09:202
=END=

############################################################
=TITLE=Default route with intermediate network hides subnet
=INPUT=[[input {n4: ",network:n4"}]]
=OUTPUT=
--ipv6/r
# [ Routing ]
ip route add ::/0 via ::a09:102
ip route add ::a01:100/124 via ::a09:102
ip route add ::a01:100/120 via ::a09:202
=END=

############################################################
=TITLE=Route for redundant subnet
=INPUT=
[[input {n4: ",network:n4"}]]
service:test2 = {
 user = network:n3;
 permit src = user; dst = network:n2; prt = icmpv6 8;
}
=OUTPUT=
--ipv6/r
# [ Routing ]
ip route add ::/0 via ::a09:102
ip route add ::a01:100/124 via ::a09:102
ip route add ::a01:100/120 via ::a09:202
=OPTIONS=--check_redundant_rules=0

############################################################
=TITLE=Must not optimize route to supernet in other part of zone cluster
=TEMPL=topo
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
network:n6 = { ip6 = ::a01:580/121; subnet_of = network:n5; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip6 = ::a01:203; hardware = n2; }
 interface:n4 = { ip6 = ::a01:403; hardware = n4; }
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
# Would create ambiguous route for n5 if added as maxRoutingNet for n6.
[[topo]]
service:s1 = {
 user = network:n5, network:n6;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:500/120 ::a01:202
ipv6 route n2 ::a01:580/121 ::a01:203
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
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:500/120 ::a01:202
ipv6 route n2 ::a01:580/121 ::a01:203
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:500/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--ipv6/r3
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:580/121 eq 80
access-list n2_in extended deny ip any6 any6
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
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:300/120 ::a01:202
ipv6 route n2 ::a01:500/120 ::a01:202
ipv6 route n2 ::a01:580/121 ::a01:203
ipv6 route n2 ::a01:400/120 ::a01:203
--ipv6/r2
! n2_in
object-group network v6g0
 network-object ::a01:300/120
 network-object ::a01:500/120
access-list n2_in extended permit tcp ::a01:100/120 object-group v6g0 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--ipv6/r3
! n2_in
object-group network v6g0
 network-object ::a01:400/120
 network-object ::a01:580/121
access-list n2_in extended permit tcp ::a01:100/120 object-group v6g0 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Add routes for all subnets of aggregate having IP of supernet
=INPUT=
[[topo]]
service:s1 = {
 user = any:[ip6 = ::a01:500/120 & network:n6];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:500/120 ::a01:202
ipv6 route n2 ::a01:580/121 ::a01:203
=END=

############################################################
=TITLE=Add routes for all subnets of aggregate
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/121; }
network:n6 = { ip6 = ::a01:580/121; }
any:n5 = { ip6 = ::a01:500/120; link = network:n5; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip6 = ::a01:203; hardware = n2; }
 interface:n4 = { ip6 = ::a01:403; hardware = n4; }
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
--ipv6/r1
! [ Routing ]
ipv6 route n2 ::a01:500/121 ::a01:202
ipv6 route n2 ::a01:580/121 ::a01:203
=END=

############################################################
=TITLE=Check NAT when finding largest supernet for route.
=TODO= No IPv6
=INPUT=
network:src = { ip6 = ::a01:100/120; }
router:r = {
 model = IOS;
 managed;
 interface:src = { ip6 = ::a01:101; hardware = src; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
network:t1 = { ip6 = ::a09:100/126; }
router:hop = {
 model = IOS;
 managed;
 interface:t1 = { ip6 = ::a09:102; hardware = inside; bind_nat = h; }
 interface:t2 = { ip6 = ::a09:201; hardware = outside; }
}
network:t2 = { ip6 = ::a09:200/126; }
router:u = {
 interface:t2 = { ip6 = ::a09:202; }
 interface:n1;
 interface:n2;
 interface:n3;
}
network:n1 = {
 ip6 = ::a02:100/124;
 subnet_of = network:n2;
}
network:n2 = {
 ip6 = ::a02:100/120;
 nat:h = { identity; }
 subnet_of = network:n3;
}
network:n3 = {
 ip6 = ::a02:0/112;
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
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:t1 = { ip6 = ::a09:102; hardware = t1; }
}
network:t1 = { ip6 = ::a09:100/120; }
router:u = {
 interface:t1 = { ip6 = ::a09:103; }
 interface:n3;
}
service:test = {
 user = network:n2, network:n3;
 permit src = network:n1; dst = user; prt = tcp 80;
}
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
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip6 = ::a01:101; hardware = n1;}
 interface:n2 = {ip6 = ::a01:201; hardware = n2; }
}
network:n2  = {ip6 = ::a01:200/120;}
router:r2 = {
 managed = routing_only;
 model = ASA;
 interface:n2 = {ip6 = ::a01:202; hardware = n2;}
 interface:n3 = {ip6 = ::a01:301; hardware = n3;}
}
network:n3  = {ip6 = ::a01:300/120;}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = {ip6 = ::a01:302; hardware = n3;}
}
service:s1 = {
 user = network:n2;
 permit src = user; dst = interface:r3.n3; prt = tcp 80;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
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
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip6 = ::a01:101; hardware = n1;}
 interface:n2 = {ip6 = ::a01:201; hardware = n2; routing = OSPF;}
}
router:u1 = {
 interface:n1 = {ip6 = ::a01:102;}
 interface:n2 = {ip6 = ::a01:202;}
}
network:n2  = {ip6 = ::a01:200/120;}
pathrestriction:n1 = interface:u1.n1, interface:r1.n1;
service:ping_local = {
 user = foreach interface:r1.n1, interface:r1.n2;
 permit src = any:[user]; dst = user; prt = icmpv6 8;
}
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route ::a01:200/120 ::a01:102
=END=

############################################################
=TITLE=No route between pair of virtual interfaces
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:u1 = {
 interface:n1;
 interface:n2 = { ip6 = ::a01:204; }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; virtual = { ip6 = ::a01:203; } }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; virtual = { ip6 = ::a01:303; } }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; virtual = { ip6 = ::a01:203; } }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; virtual = { ip6 = ::a01:303; } }
}
router:u2 = {
 interface:n3 = { ip6 = ::a01:304; }
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
=TITLE=Route from virtual interface
# Must no accidently ignore route.
=INPUT=
network:n0 = { ip6 = ::a01:0/120; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n0 = { ip6 = ::a01:1; hardware = n0; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; virtual = { ip6 = ::a01:103; } }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; virtual = { ip6 = ::a01:203; } }
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:104; hardware = n1; virtual = { ip6 = ::a01:103; } }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; virtual = { ip6 = ::a01:203; } }
}

service:s1 = {
 user = interface:r1.n0;
 permit src = user; dst = interface:r2.n1.virtual; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r2
! [ Routing ]
ipv6 route ::a01:0/120 ::a01:101
=END=

############################################################
=TITLE=Must not add routes for zone at start interface at zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
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
=OUTPUT=
-- ipv6/r3
! [ Routing ]
ipv6 route n4 ::a01:200/120 ::a01:401
=END=

############################################################
