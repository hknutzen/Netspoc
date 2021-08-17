
############################################################
=TITLE=Optimize subnet at secondary packet filter
=VAR=input
network:sub = { ip = ::a01:720/123; subnet_of = network:customer; }
router:r = { interface:sub; interface:customer = { ip = ::a01:71e; } }
network:customer = { ip = ::a01:700/120; }
router:gw = {
 managed = secondary;
 model = IOS, FW;
 interface:customer = { ip = ::a01:701;    hardware = outside;}
 interface:trans    = { ip = ::a01:301;   hardware = inside;}
}
network:trans = { ip = ::a01:300/120; }
router:b1 = {
 managed;
 model = Linux;
 interface:trans = {
  ip = ::a01:303;
  hardware = eth0;
 }
 interface:server = {
  ip = ::a01:201;
  hardware = eth1;
 }
}
network:server = {
 ip = ::a01:200/120;
 host:s10 = { ip = ::a01:20a; }
 host:s11 = { ip = ::a01:20b; }
}
protocol:Echo = icmpv6 8;
service:p1 = {
 user = network:sub;
 permit src = user; dst = host:s10; prt = protocol:Echo;
}
service:p2 = {
 user = network:customer;
 permit src = user; dst = host:s11; prt = protocol:Echo;
}
=END=
=PARAMS=--ipv6
=INPUT=${input}
=OUTPUT=
--ipv6/b1
# [ Routing ]
ip route add ::a01:700/120 via ::a01:301
--ipv6/gw
! [ Routing ]
ipv6 route ::a01:720/123 ::a01:71e
ipv6 route ::a01:200/120 ::a01:303
--
! [ ACL ]
ipv6 access-list outside_in
 permit ipv6 ::a01:700/120 ::a01:200/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Optimize subnet for protocol with flag dst_net
=PARAMS=--ipv6
=INPUT=${input}
=SUBST=/managed = secondary/managed/
=SUBST=/icmpv6 8/icmpv6 8, dst_net/
=OUTPUT=
--ipv6/gw
! [ ACL ]
ipv6 access-list outside_in
 permit icmp ::a01:700/120 ::a01:200/120 8
 deny ipv6 any any
=END=
=OPTIONS=--check_redundant_rules=0

############################################################
=TITLE=Combined hosts prevent optimal object group
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 host:h11 = { ip = ::a01:10b; }
 host:h13 = { ip = ::a01:10d; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h20 = { ip = ::a01:214; }
 host:h21 = { ip = ::a01:215; }
 host:h23 = { ip = ::a01:217; }
 host:h24 = { ip = ::a01:218; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 overlaps = service:s2, service:s3;
 user = host:h11, host:h13;
 permit src = user; dst = host:h20, host:h21, host:h23, host:h24; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = host:h20, host:h23; prt = tcp 80;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = host:h21, host:h24; prt = tcp 80;
}
=END=
=OUTPUT=
-- ipv6/r1
! n1_in
object-group network v6g0
 network-object ::a01:214/127
 network-object host ::a01:217
 network-object host ::a01:218
access-list n1_in extended permit tcp ::a01:100/120 object-group v6g0 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=TODO=Combined hosts prevent optimal object group


############################################################
=TITLE=Optimize subnet of NAT network in zone
=PARAMS=--ipv6
=INPUT=
network:customer = {
 ip = ::a09:900/120;
 nat:N = { ip = ::a01:700/120; }
 has_subnets;
}
router:r = {
 interface:customer = { bind_nat = SUB; }
 interface:sub = { ip = ::a01:722; bind_nat = N; }
}
network:sub = { ip = ::a01:720/123; nat:SUB = { ip = ::a09:920/123; }}
router:gw = {
 managed = secondary;
 model = IOS, FW;
 interface:sub   = { ip = ::a01:721; hardware = outside;}
 interface:trans = { ip = ::a01:301;  hardware = inside; }
}
network:trans = { ip = ::a01:300/120; }
router:b1 = {
 managed;
 model = Linux;
 interface:trans  = { ip = ::a01:303; hardware = eth0; }
 interface:server = { ip = ::a01:201; hardware = eth1; }
}
network:server = { ip = ::a01:200/120; }
protocol:Echo = icmpv6 8;
service:p1 = {
 user = network:sub;
 permit src = user; dst = network:server; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/gw
! [ Routing ]
ipv6 route ::a01:700/120 ::a01:722
ipv6 route ::a01:200/120 ::a01:303
--
! [ ACL ]
ipv6 access-list outside_in
 permit ipv6 ::a01:700/120 ::a01:200/120
 deny ipv6 any any
=END=
=TODO=Optimize subnet of NAT network in zone

############################################################
