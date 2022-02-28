
############################################################
=TITLE=IP header, route
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:30a; } }
router:r = {
 managed = routing_only;
 model = ASA;
 policy_distribution_point = host:h3;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:asa = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
service:test = {
 user = host:h3;
 permit src = user; dst = interface:r.[auto]; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r
! [ IP = ::a01:201 ]
--
! [ Routing ]
ipv6 route n2 ::a01:300/120 ::a01:202
=END=

############################################################
=TITLE=Unenforceable
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
router:r = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:test = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=END=
=WARNING=
Warning: No firewalls found between all source/destination pairs of service:test
=END=

############################################################
=TITLE=VRFs
=PARAMS=--ipv6
=INPUT=
network:m = { ip = ::a02:200/120;
}
router:r1@v1 = {
 managed = routing_only;
 model = NX-OS;
 interface:m = { ip = ::a02:201; hardware = e0; }
 interface:t1 = { ip = ::a09:101; hardware = e1; }
}
network:t1 = { ip = ::a09:100/120; }
router:r1@v2 = {
 managed = routing_only;
 model = NX-OS;
 interface:t1 = { ip = ::a09:102; hardware = e2; }
 interface:t2 = { ip = ::a09:201; hardware = e3; }
}
network:t2 = { ip = ::a09:200/120; }
router:r2 = {
 managed;
 model = NX-OS;
 interface:t2 = { ip = ::a09:202; hardware = e4; }
 interface:n = { ip = ::a01:101; hardware = e5; }
}
network:n = { ip = ::a01:100/120; }
service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ Routing for router:r1@v1 ]
vrf context v1
 ipv6 route ::a01:100/120 ::a09:102
 ipv6 route ::a09:200/120 ::a09:102
--
! [ Routing for router:r1@v2 ]
vrf context v2
 ipv6 route ::a02:200/120 ::a09:101
 ipv6 route ::a01:100/120 ::a09:202
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Add routes for zones at routing_only router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:t1 = { ip = ::a09:100/120; }
network:t2 = { ip = ::a09:200/120; }
network:t3 = { ip = ::a09:300/120; }
router:u1 = {
 interface:n1;
 interface:l1 = { ip = ::a08:101; loopback; }
 interface:t1 = { ip = ::a09:101; }
}
router:u2 = {
 interface:n2;
 interface:t2 = { ip = ::a09:201; }
}
router:r = {
 managed = routing_only;
 model = ASA;
 interface:t1 = { ip = ::a09:102, ::a09:103; hardware = t1; }
 interface:t2 = { ip = ::a09:202; hardware = t2; }
 interface:t3 = { ip = ::a09:302; hardware = t3; }
}
router:asa = {
 managed;
 model = ASA;
 interface:t3 = { ip = ::a09:301; hardware = t3; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
=END=
=OUTPUT=
--ipv6/r
! [ Routing ]
ipv6 route t1 ::a08:101/128 ::a09:101
ipv6 route t1 ::a01:100/120 ::a09:101
ipv6 route t2 ::a01:200/120 ::a09:201
=OPTIONS=--auto_default_route=0

############################################################
