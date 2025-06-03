
############################################################
=TITLE=Implicit group of aggregates from zone cluster
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
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 interface:n2 = { ip6 = ::a01:202; }
 interface:n3 = { ip6 = ::a01:302; }
}
pathrestriction:p = interface:r1.n2, interface:r3.n2;
service:s1 = {
 user = network:n1;
 # implicitly add any:[network:n2]
 permit src = user; dst = any:[network:n3]; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 any6 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r2
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 any6 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Inherit owner from all zones of zone cluster
=INPUT=
network:Test =  { ip6 = ::a09:100/120; }
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip6 = ::a09:101; hardware = Test; }
 interface:Trans1 = { ip6 = ::a05:601; hardware = Trans1; }
}
router:filter2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip6 = ::a09:102; hardware = Test; }
 interface:Trans2 = { ip6 = ::a05:701; hardware = Trans2; }
}
network:Trans1 = { ip6 = ::a05:600/120; }
network:Trans2 = { ip6 = ::a05:700/120; owner = t1;}
router:Kunde = {
 interface:Trans1 = { ip6 = ::a05:602; }
 interface:Trans2 = { ip6 = ::a05:702; }
}
pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;
owner:t1 = { admins = guest; }
any:Trans1 = { link = network:Trans1; owner = t1; }
=WARNING=
Warning: Useless owner:t1 at network:Trans2,
 it was already inherited from any:Trans1
=END=

############################################################
=TITLE=Networks with identical address in zone cluster
=INPUT=
network:n1a = { ip6 = ::a01:100/120; }
network:n1b = { ip6 = ::a01:100/120; }
router:u = {
 managed = routing_only;
 model = IOS;
 interface:n1a = { ip6 = ::a01:101; hardware = n1a; }
 interface:n1b = { ip6 = ::a01:101; hardware = n1b; }
}
=ERROR=
Error: network:n1a and network:n1b have identical address in any:[network:n1a]
=END=

############################################################
=TITLE=Duplicate IP from NAT in zone
=TODO= No IPv6
=INPUT=
network:A = { ip6 = ::a03:378/125; nat:C = { ip6 = ::a02:200/120; dynamic; }}
network:B = { ip6 = ::a03:380/125; nat:C = { ip6 = ::a02:200/120; dynamic; }}
router:ras = {
 interface:A = { ip6 = ::a03:379; }
 interface:B = { ip6 = ::a03:381; }
 interface:Trans = { ip6 = ::a01:102; nat_out = C; }
}
network:Trans = { ip6 = ::a01:100/120;}
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Trans = { ip6 = ::a01:101; hardware = Trans; }
}
service:s1 = {
 user = network:A;
 permit src = user; dst = interface:filter1.Trans; prt = tcp 22;
}
=ERROR=
Error: network:B and network:A have identical address in any:[network:Trans]
=END=

############################################################
=TITLE=No secondary optimization for network with subnet in other zone
=INPUT=
network:A = {
 ip6 = ::a03:300/121;
 host:h = { ip6 = ::a03:305; }
}
network:sub = { ip6 = ::a03:308/125; subnet_of = network:A; }
router:secondary = {
 managed = secondary;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip6 = ::a03:301; hardware = A; }
 interface:sub = { ip6 = ::a03:309; hardware = sub; }
 interface:Trans = { ip6 = ::a01:102; hardware = Trans; }
}
network:Trans = { ip6 = ::a01:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip6 = ::a01:101; hardware = Trans; }
 interface:Customer = { ip6 = ::a09:901; hardware = Customer; }
}
network:Customer = { ip6 = ::a09:900/120; }
service:test = {
 user = network:Customer;
 permit src = user; dst = host:h; prt = tcp 80;
}
=OUTPUT=
--ipv6/secondary
ipv6 access-list Trans_in
 permit ipv6 ::a09:900/120 host ::a03:305
 deny ipv6 any any
=END=

############################################################
=TITLE=Skip supernet with subnet in other zone in secondary optimization
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:secondary = {
 model = IOS, FW;
 managed = secondary;
 interface:n1 = {ip6 = ::a01:101; hardware = n1; }
 interface:t1 = { ip6 = ::a01:801; hardware = t1; }
}
network:t1 = { ip6 = ::a01:800/120; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip6 = ::a01:802; hardware = t1; }
 interface:t2 = { ip6 = ::a01:901; hardware = t2; }
}
network:t2 = { ip6 = ::a01:900/120;}
router:trahza01 = {
 interface:t2;
 interface:super;
 interface:sub1;
}
# Must not use super as supernet, because it has sub2 as subnet in other zone.
network:super = { ip6 = f000::c0a8:0/112; }
network:sub1 = { ip6 = f000::c0a8:100/120; subnet_of = network:super; }
# Must not use aggregate as supernet.
any:a1 = { ip6 = f000::c0a8:0/117; link = network:sub2; }
router:r3 = {
 managed;
 model = ASA;
 interface:t1 = {ip6 = ::a01:803; hardware = t1;}
 interface:sub2 = { ip6 = f000::c0a8:801; hardware = sub2; }
}
network:sub2 = { ip6 = f000::c0a8:800/120; subnet_of = network:super; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:sub1; prt = tcp 49;
}
=OUTPUT=
--ipv6/secondary
ipv6 access-list n1_in
 permit ipv6 ::a01:100/120 f000::c0a8:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Skip supernet with NAT in secondary optimization
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:secondary = {
 model = IOS, FW;
 managed = secondary;
 interface:n1 = {ip6 = ::a01:101; hardware = n1; nat_out = nat; }
 interface:n2 = {ip6 = ::a01:201; hardware = n2; }
 interface:t1 = { ip6 = ::a01:801; hardware = t1; }
}
network:t1 = { ip6 = ::a01:800/120; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip6 = ::a01:802; hardware = t1; }
 interface:t2 = { ip6 = ::a01:901; hardware = t2; }
}
network:t2 = { ip6 = ::a01:900/120;}
router:trahza01 = {
 interface:t2;
 interface:super;
 interface:sub1;
 interface:sub2;
}
network:super = {
 has_subnets;
 ip6 = f000::c0a8:0/112;
 nat:nat = { hidden; }
}
network:sub1 = {
 ip6 = f000::c0a8:100/120;
 nat:nat = { identity; }
}
network:sub2 = { ip6 = f000::c0a8:200/120; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:sub1; prt = tcp 49;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:sub2; prt = tcp 49;
}
=OUTPUT=
--ipv6/secondary
ipv6 access-list n1_in
 permit ipv6 ::a01:100/120 f000::c0a8:100/120
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit ipv6 ::a01:200/120 f000::c0a8:0/112
 deny ipv6 any any
=END=

############################################################
=TITLE=Get hosts also from subnet
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; host:h10 = { ip6 = ::a01:20a; } }
network:n2Sub = {
 ip6 = ::a01:220/123;
 subnet_of = network:n2;
 host:h40 = { ip6 = ::a01:228; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip6 = ::a01:202; }
 interface:n2Sub = { ip6 = ::a01:221; }
}
service:s1 = {
 user = host:[network:n2];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n2_in
object-group network v6g0
 network-object host ::a01:20a
 network-object host ::a01:228
access-list n2_in extended permit tcp object-group v6g0 ::a01:100/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Prevent duplicate hosts from zone cluster in area
=INPUT=
area:n1-2 = { border = interface:r2.n2; }
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; host:h2 = { ip6 = ::a01:20a; } }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed = routing_only;
 model = IOS;
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
 user = host:[area:n1-2];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r2
! n2_in
object-group network v6g0
 network-object host ::a01:10a
 network-object host ::a01:20a
access-list n2_in extended permit tcp object-group v6g0 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not accidently add zone twice to cluster
# If using 'activePath', zone:[n3] would be added twice.
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = { ip6 = ::a01:200/120;}
network:n3 = { ip6 = ::a01:300/120;}
network:n4 = { ip6 = ::a01:400/120;}
any:n1 = { link = network:n1;}
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip6 = ::a01:301; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; routing = dynamic; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip6 = ::a01:303; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
pathrestriction:p = interface:r1.n2, interface:r2.n2;
service:s1 = {
 user = any:n1;
 permit src = user; dst = network:n4; prt = udp 123;
}
=OUTPUT=
--ipv6/r2
! [ Routing ]
ipv6 route ::a01:100/120 ::a01:301
ipv6 route ::a01:400/120 ::a01:303
=END=

############################################################
=TITLE=Zone connected twice to routing_only router (1)
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = { ip6 = ::a01:200/120;}
network:n3 = { ip6 = ::a01:300/120;}
router:r1 = {
 interface:n1;
 interface:n2 = { ip6 = ::a01:201; }
 interface:n3 = { ip6 = ::a01:301; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
=ERROR=
Error: Two static routes for network:n1
 via interface:r2.n3 and interface:r2.n2
=END=

############################################################
=TITLE=Zone connected twice to routing_only router (2)
# Pathrestriction has no effect on traffic from router:r2,
# hence two routes are found.
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = { ip6 = ::a01:200/120;}
network:n3 = { ip6 = ::a01:300/120;}
router:r1 = {
 interface:n1;
 interface:n2 = { ip6 = ::a01:201; }
 interface:n3 = { ip6 = ::a01:301; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
pathrestriction:p = interface:r1.n2, interface:r2.n2;
=ERROR=
Error: Two static routes for network:n1
 via interface:r2.n3 and interface:r2.n2
=END=

############################################################
=TITLE=Zone connected twice to routing_only router (3)
# Pathrestriction is useless, hence two routes are found.
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = { ip6 = ::a01:200/120;}
network:n3 = { ip6 = ::a01:300/120;}
router:r1 = {
 interface:n1;
 interface:n2 = { ip6 = ::a01:201; }
 interface:n3 = { ip6 = ::a01:301; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
pathrestriction:p = interface:r1.n2, interface:r2.n3;
=ERROR=
Error: Two static routes for network:n1
 via interface:r2.n3 and interface:r2.n2
=END=

############################################################
