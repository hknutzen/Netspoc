
############################################################
=TITLE=Non matching mask of filter_only attribute
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:0/104;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
}
=ERROR=
Error: IP and mask of ::a3e:0/104 don't match in 'filter_only' of router:d32
=END=

############################################################
=TITLE=Missing attribute 'filter_only'
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:d32 = {
 model = ASA;
 managed = local;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
}
=ERROR=
Error: Missing attribute 'filter_only' for router:d32
=END=

############################################################
=TITLE=Ignoring attribute 'filter_only'
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:d32 = {
 model = ASA;
 managed;
 filter_only =  ::a3e:0/112;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
}
=WARNING=
Warning: Ignoring attribute 'filter_only' at router:d32; only valid with 'managed = local'
=END=

############################################################
=TITLE=Unsupported 'managed = local'
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:d32 = {
 model = Linux;
 managed = local;
 filter_only =  ::a3e:0/112;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
}
=ERROR=
Error: Must not use 'managed = local' at router:d32 of model Linux
=END=

############################################################
=TITLE=Local network doesn't match filter_only attribute
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:100/120;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
 interface:n2 = { ip = ::a3e:221; hardware = n2; }
}
network:n2 = { ip = ::a3e:220/123; }
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:100/120;
 interface:n2 = { ip = ::a3e:222; hardware = n2; }
 interface:n3 = { ip = ::a3e:101; hardware = n3; }
}
network:n3 = { ip = ::a3e:100/123; }
=END=
# Show message only once.
=ERROR=
Error: network:n2 doesn't match attribute 'filter_only' of router:r1
=END=

############################################################
=TITLE=Useless value in filter_only attribute
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:100/120, ::a3e:200/120, ::a3e:300/120;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
 interface:n2 = { ip = ::a3e:221; hardware = n2; }
}
network:n2 = { ip = ::a3e:220/123; }
=WARNING=
Warning: Useless 'filter_only = ::a3e:300/120' at router:r1
=END=

############################################################
=TITLE=NAT not allowed
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; nat:n1 = { ip = ::a3e:400/123; } }
network:n2 = { ip = ::a3e:200/123;  nat:n2 = { ip = ::a3e:500/123; } }
network:n3 = { ip = ::a3e:300/123; }
router:d32 = {
 model = ASA;
 managed = local;
 routing = manual;
 filter_only =  ::a3e:0/115;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
 interface:n2 = { ip = ::a3e:201; hardware = n2; bind_nat = n1;}
}
router:u = {
 interface:n2;
 interface:n3 = { bind_nat = n2; }
}
=ERROR=
Error: Attribute 'bind_nat' is not allowed at interface:d32.n2 with 'managed = local'
Error: Attribute 'bind_nat' is not allowed at interface:u.n3 in zone beside router with 'managed = local'
=END=

############################################################
=TITLE=Cluster must have identical values in attribute 'filter_only'
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
network:n2 = { ip = ::a3e:200/123; }
network:n3 = { ip = ::a3e:340/123; }
network:n4 = { ip = ::a3e:f200/125; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:f000/118, ::a3e:0/115;
 interface:n4 = { ip = ::a3e:f201; hardware = n4; }
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
}
router:r2 = {
 model = IOS;
 managed = local;
 filter_only =  ::a3e:f000/117, ::a3e:0/115,;
 interface:n4 = { ip = ::a3e:f202; hardware = n4; }
 interface:n2 = { ip = ::a3e:201; hardware = n2; }
}
router:r3 = {
 model = IOS;
 managed = local;
 filter_only =  ::a3e:f000/118, ::a3e:0/115, ::a3e:2000/115;
 interface:n4 = { ip = ::a3e:f203; hardware = n4; }
 interface:n3 = { ip = ::a3e:341; hardware = n3; }
}
=ERROR=
Error: router:r1 and router:r2 must have identical values in attribute 'filter_only'
Error: router:r1 and router:r3 must have identical values in attribute 'filter_only'
=END=

############################################################
# Shared topology

############################################################
=TEMPL=topo
network:n1 = { ip = ::a3e:120/123; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only = ::a3e:0/117, ::a3e:f100/120;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
 interface:n2 = { ip = ::a3e:f101; hardware = n2; }
}
network:n2 = { ip = ::a3e:f100/125; }
router:d31 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a3e:f102; hardware = inside; }
 interface:extern = { ip = ::a7d:301; hardware = outside; }
}
network:extern = { ip = ::a7d:300/120; }
router:r1 = {
 interface:extern = { ip = ::a7d:302; }
 interface:ex_match;
}
network:ex_match = { ip = ::a3e:700/120; }
=END=

############################################################
=TITLE=Reuse object groups for deny rules
=PARAMS=--ipv6
=INPUT=[[topo]]
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip object-group v6g0 object-group v6g0
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Filter src in deny rule with zone cluster
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a00:0/120; nat:n0 = { ip = ::a3e:0/120; } }
router:r0 = {
 interface:n0;
 interface:n1 = { ip = ::a3e:122; bind_nat = n0; }
}
[[topo]]
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended deny ip object-group v6g0 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip object-group v6g0 object-group v6g0
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=External rules are not filtered
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:Test = {
 user = network:n1;
 permit src = user; dst = network:extern; prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--ipv6/d31
! inside_in
access-list inside_in extended permit tcp ::a3e:120/123 ::a7d:300/120 eq 80
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Mixed matching and non matching external rules
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:Test = {
 user = network:extern, network:ex_match;
 permit src = network:n1; dst = user; prt = tcp 80;
 permit src = user; dst = network:n1; prt = tcp 81;
}
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended permit tcp ::a3e:120/123 ::a3e:700/120 eq 80
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a3e:700/120 ::a3e:120/123 eq 81
access-list n2_in extended deny ip object-group v6g0 object-group v6g0
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
--ipv6/d31
! inside_in
object-group network v6g0
 network-object ::a3e:700/120
 network-object ::a7d:300/120
access-list inside_in extended permit tcp ::a3e:120/123 object-group v6g0 eq 80
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit tcp object-group v6g0 ::a3e:120/123 eq 81
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Aggregate to extern
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = ::a3c:0/110 & network:n1, network:n2];
 permit src = user;
        dst = network:extern;
        prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Aggregate to local
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = ::a3c:0/110 & network:n1];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended permit tcp ::a3c:0/110 ::a3e:f100/125 eq 80
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Non matching aggregate to non matching aggregate
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = ::/0 & network:n1];
 permit src = user;
        dst = any:[ip = ::/0 & network:n2];
        prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended permit tcp any6 any6 eq 80
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Non matching aggregate to non matching aggregate with IP any
# This generates two identical lines 'permit ip any6 any6',
# Access-list with duplicate lines is not valid for ASA.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = ::/0 & network:n1];
 permit src = user;
        dst = any:[ip = ::/0 & network:n2];
        prt = ip;
}
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended permit ip any6 any6
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Ignore non matching local aggregate
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = ::a63:0/112 & network:n1];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a3e:0/117
 network-object ::a3e:f100/120
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=External supernet of local network
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:100/120; subnet_of = network:extern; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:0/112, ::a09:0/112;
 interface:n1 = { ip = ::a3e:101; hardware = n1; }
 interface:n2 = { ip = ::a09:101; hardware = n2; }
}
network:n2 = { ip = ::a09:100/125; }
router:d31 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = ::a09:102; hardware = inside; }
 interface:extern = { ip = ::a3e:1; hardware = outside; }
}
network:extern = { ip = ::a3e:0/113; }
service:Test = {
 user = network:n1;
 permit src = network:extern;
        dst = user;
        prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! n2_in
access-list n2_in extended permit tcp ::a3e:0/113 ::a3e:100/120 eq 80
access-list n2_in extended deny ip object-group v6g0 object-group v6g0
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Subnet of external supernet
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:100/120; subnet_of = network:extern; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:0/112, ::a09:0/112;
 interface:n1 = { ip = ::a3e:101; hardware = n1; }
 interface:n2 = { ip = ::a09:101; hardware = n2; }
}
network:n2 = { ip = ::a09:100/125; }
router:d31 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = ::a09:102; hardware = inside; }
 interface:extern = { ip = ::a3e:1; hardware = outside; }
}
network:extern = { ip = ::a3e:0/111; }
router:u = {
 interface:extern = { ip = ::a3e:2; }
 interface:sub;
}
network:sub = { ip = ::a3e:200/120; subnet_of = network:extern; }
service:Test = {
 user = network:n1;
 permit src = network:sub;
        dst = user;
        prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! n2_in
access-list n2_in extended permit tcp ::a3e:200/120 ::a3e:100/120 eq 80
access-list n2_in extended deny ip object-group v6g0 object-group v6g0
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Internal / external network exactly match filter_only
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a04:200/120; subnet_of = network:extern; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112, ::a04:0/112;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a04:201; hardware = n2; }
 interface:intern = { ip = ::a02:1; hardware = intern; }
}
network:intern = { ip = ::a02:0/112; }
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = ::a02:2; hardware = inside; }
 interface:extern = { ip = ::a04:1; hardware = outside; }
}
network:extern = { ip = ::a04:0/112; }
service:Test = {
 user = network:extern, network:intern;
 permit src = user;
        dst = network:n1, network:n2;
        prt = tcp 80;
}
=OUTPUT=
--ipv6/d32
! intern_in
object-group network v6g1
 network-object ::a02:0/112
 network-object ::a04:0/112
object-group network v6g2
 network-object ::a01:100/120
 network-object ::a04:200/120
access-list intern_in extended permit tcp object-group v6g1 object-group v6g2 eq 80
access-list intern_in extended deny ip object-group v6g0 object-group v6g0
access-list intern_in extended permit ip any6 any6
access-group intern_in in interface intern
=END=

############################################################
=TITLE=Multiple internal subnets, unnumbered, hidden
=PARAMS=--ipv6
=INPUT=
network:n1   = { ip = ::a01:100/120; }
network:n1-a = { ip = ::a01:120/123; subnet_of = network:n1; }
network:n1-b = { ip = ::a01:140/123; subnet_of = network:n1; }
network:un = { unnumbered; }
router:u = {
 interface:n1;
 interface:n1-a;
 interface:n1-b;
 interface:un;
}
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112;
 interface:un = { unnumbered; hardware = un; }
 interface:intern = { ip = ::a02:101; hardware = intern; }
}
network:intern = { ip = ::a02:100/120; }
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = ::a02:102; hardware = inside; bind_nat = h; }
 interface:extern = { ip = ::a04:1; hardware = outside; }
 interface:ex-hid = { ip = ::a02:281; hardware = ex-hid; }
}
network:extern = { ip = ::a04:0/112; }
network:ex-hid = { ip = ::a02:280/123; nat:h = { hidden; } }
service:Test = {
 user = network:extern, network:intern;
 permit src = user;
        dst = network:n1-a, network:n1-b;
        prt = tcp 80;
 permit src = user;
        dst = network:n1;
        prt = tcp 81;
}
=OUTPUT=
--ipv6/d32
! intern_in
object-group network v6g1
 network-object ::a01:120/123
 network-object ::a01:140/123
access-list intern_in extended permit tcp ::a02:100/120 object-group v6g1 eq 80
access-list intern_in extended permit tcp ::a02:100/120 ::a01:100/120 eq 81
access-list intern_in extended deny ip object-group v6g0 object-group v6g0
access-list intern_in extended permit ip any6 any6
access-group intern_in in interface intern
=END=

############################################################
=TITLE=Secondary filter near local filter filters fully
=TEMPL=input
network:n1 = { ip = ::a3e:120/123; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:0/112;
 interface:n1 = { ip = ::a3e:121; hardware = n1; }
 interface:trans = { ip = ::a3e:f101; hardware = trans; }
}
network:trans = { ip = ::a3e:f100/125; }
router:d31 = {
 model = ASA;
 managed = secondary;
 interface:trans = { ip = ::a3e:f102; hardware = inside; }
 interface:extern = { ip = ::a7d:301; hardware = outside; }
}
network:extern = { ip = ::a7d:300/120; }
service:Mail = {
 user = network:n1;
 permit src = user;
        dst = network:extern;
        prt = tcp 25;
}
=PARAMS=--ipv6
=INPUT=[[input]]
=OUTPUT=
--ipv6/d31
! inside_in
access-list inside_in extended permit tcp ::a3e:120/123 ::a7d:300/120 eq 25
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Different deny rules
=PARAMS=--ipv6
=INPUT=[[input]]
=OUTPUT=
--ipv6/d32
! n1_in
access-list n1_in extended deny ip any6 ::a3e:0/112
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--
! trans_in
access-list trans_in extended deny ip ::a3e:0/112 ::a3e:0/112
access-list trans_in extended permit ip any6 any6
access-group trans_in in interface trans
=END=

############################################################
=TITLE=Outgoing ACL
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a3e:0/115;
 interface:n1 = { ip = ::a3e:121; hardware = n1; no_in_acl;}
 interface:n2 = { ip = ::a3e:201; hardware = n2; }
}
network:n2 = { ip = ::a3e:200/123; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/d32
! n1_in
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a3e:200/123 ::a3e:120/123 eq 22
access-list n2_in extended deny ip any6 ::a3e:0/115
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
--
! n2_out
access-list n2_out extended permit tcp ::a3e:120/123 ::a3e:200/123 eq 80
access-list n2_out extended deny ip ::a3e:0/115 ::a3e:0/115
access-list n2_out extended permit ip any6 any6
access-group n2_out out interface n2
=END=

############################################################
=TITLE=Loop, virtual interfaces (1)
# Zone with virtual interfaces is recognized as leaf zone.
# Zone with other loop is handled as intermediate zone with
# possible connection to extern.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a3e:120/123; }
router:d1 = {
 model = IOS;
 managed = local;
 filter_only =  ::a3e:0/115;
 interface:n1 = {
  ip = ::a3e:122;
  virtual = { ip = ::a3e:121; }
  hardware = n1;
 }
 interface:n2 = { ip = ::a3e:201; hardware = n2; }
}
router:d2 = {
 model = IOS;
 managed = local;
 filter_only =  ::a3e:0/115;
 interface:n1 = {
  ip = ::a3e:123;
  virtual = { ip = ::a3e:121; }
  hardware = n21;
 }
 interface:trans = { ip = ::a3e:301; hardware = n22; }
}
network:trans = { ip = ::a3e:300/123; }
router:loop = {
 model = ASA;
 managed;
 interface:trans = { ip = ::a3e:302; hardware = inside; }
 interface:n2 = { ip = ::a3e:202; hardware = outside; }
}
network:n2 = { ip = ::a3e:200/123; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/d1
ipv6 access-list n1_in
 deny ipv6 any host ::a3e:201
 permit tcp ::a3e:120/123 ::a3e:200/123 eq 80
 permit tcp ::a3e:120/123 ::a3e:200/123 established
 deny ipv6 any ::a3e:0/115
 permit ipv6 any any
--ipv6/d1
ipv6 access-list n2_in
 deny ipv6 any host ::a3e:121
 deny ipv6 any host ::a3e:122
 permit tcp ::a3e:200/123 ::a3e:120/123 eq 22
 permit tcp ::a3e:200/123 ::a3e:120/123 established
 deny ipv6 ::a3e:0/115 ::a3e:0/115
 permit ipv6 any any
=END=

############################################################
=TITLE=Loop, secondary at border
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a02:100/123; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  ::a02:0/112;
 routing = manual;
 interface:n1 = { ip = ::a02:101; hardware = n1; }
 interface:tr = { ip = ::a02:901; hardware = tr; }
}
network:n2 = { ip = ::a02:200/123;}
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  ::a02:0/112;
 routing = manual;
 interface:n2 = { ip = ::a02:201; hardware = n2; }
 interface:tr = { ip = ::a02:902; hardware = tr; }
}
network:tr = { ip = ::a02:900/125; }
router:ex = {
 model = ASA;
 managed = secondary;
 interface:tr = { ip = ::a02:906; hardware = inside; }
 interface:extern = { ip = ::a05:301; hardware = outside; }
}
network:extern = { ip = ::a05:300/120; }
service:Mail = {
 user = network:n2;
 permit src = user;
        dst = network:extern, network:n1;
        prt = tcp 25;
}
=OUTPUT=
--ipv6/ex
! inside_in
access-list inside_in extended permit tcp ::a02:200/123 ::a05:300/120 eq 25
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--ipv6/r1
! tr_in
access-list tr_in extended permit tcp ::a02:200/123 ::a02:100/123 eq 25
access-list tr_in extended deny ip ::a02:0/112 ::a02:0/112
access-list tr_in extended permit ip any6 any6
access-group tr_in in interface tr
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a02:200/123 ::a02:100/123 eq 25
access-list n2_in extended deny ip any6 ::a02:0/112
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Don't check external aggregate rules
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
any:any1 = { link = network:n1; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = outside; }
 interface:n2 = { ip = ::a02:906; hardware = inside; }
}
network:n2 = { ip = ::a02:900/125; }
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  ::a02:0/112;
 interface:n2 = { ip = ::a02:901; hardware = outside; }
 interface:dst = { ip = ::a02:101; hardware = inside; }
}
network:dst = { ip = ::a02:100/123; }
service:t1 = {
 user = any:any1;
 permit src = user;
        dst = network:dst;
        prt = tcp 25;
}
service:t2 = {
 user = any:any1;
 permit src = network:dst;
        dst = user;
        prt = tcp 110;
}
=OUTPUT=
--ipv6/r2
! outside_in
access-list outside_in extended deny ip ::a02:0/112 ::a02:0/112
access-list outside_in extended permit ip any6 any6
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended deny ip any6 ::a02:0/112
access-list inside_in extended permit ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Check external aggregate covering filter_only network
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
any:any1 = { link = network:n1; }
router:u = {
  interface:n1;
 interface:t1 =  { ip = ::a02:909; }
}
network:t1 = { ip = ::a02:908/125; }
router:r1 = {
 model = ASA;
 managed;
 interface:t1 = { ip = ::a02:90a; hardware = outside; }
 interface:t2 = { ip = ::a02:906; hardware = inside; }
}
network:t2 = { ip = ::a02:900/125; }
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  ::a02:0/112;
 interface:t2 = { ip = ::a02:901; hardware = outside; }
 interface:dst = { ip = ::a02:101; hardware = inside; }
}
network:dst = { ip = ::a02:100/123; }
service:t1 = {
 user = any:any1, any:[network:t2];
 permit src = user;
        dst = network:dst;
        prt = tcp 25;
}
service:t2 = {
 user = any:any1, any:[network:t2];
 permit src = network:dst;
        dst = user;
        prt = tcp 110;
}
service:t3 = {
 user = any:any1;
 permit src = network:dst;
        dst = user;
        prt = tcp 81;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:dst; dst=any:any1; prt=tcp 81; of service:t3
 Generated ACL at interface:r2.dst would permit access to additional networks:
 - network:t2
 Either replace any:any1 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule
 or add any:[network:t2] to dst of rule.
=OUTPUT=
--ipv6/r2
! outside_in
access-list outside_in extended permit tcp any6 ::a02:100/123 eq 25
access-list outside_in extended deny ip ::a02:0/112 ::a02:0/112
access-list outside_in extended permit ip any6 any6
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended permit tcp ::a02:100/123 any6 eq 110
access-list inside_in extended permit tcp ::a02:100/123 any6 eq 81
access-list inside_in extended deny ip any6 ::a02:0/112
access-list inside_in extended permit ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Two disjunct local-filter parts
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
router:r1 = {
 managed = local;
 filter_only = ::a01:100/120, ::a01:200/120;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r4 = {
 managed = local;
 filter_only = ::a01:400/119;
 model = ASA;
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n5 = { ip = ::a01:501; hardware = n5; }
}
service:s1 = {
 user = network:n1, network:n4;
 permit src = user; dst = network:n5; prt = tcp 25;
}
=OUTPUT=
-- ipv6/r1
! n1_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:200/120
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
-- ipv6/r4
! n4_in
access-list n4_in extended permit tcp ::a01:400/120 ::a01:500/120 eq 25
access-list n4_in extended deny ip ::a01:400/119 ::a01:400/119
access-list n4_in extended permit ip any6 any6
access-group n4_in in interface n4
=END=

############################################################
=TITLE=local-filter cluster separated by semi-managed routers
=TEMPL=semi
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a02:500/120; }
router:r1 = {
 managed = local;
 filter_only = ::a01:0/112;#r1
 routing = dynamic;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 interface:n2;
 interface:n3;
}
router:r3 = {
 managed = local;
 filter_only = ::a01:0/112;
 routing = dynamic;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r4 = {
 interface:n4;
 interface:n1;
}
router:r5 = {
 managed;
 model = ASA;
 routing = dynamic;
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n5 = { ip = ::a02:501; hardware = n5; }
}
pathrestriction:p1 = interface:r2.n2, interface:r4.n4;
=PARAMS=--ipv6
=INPUT=
[[semi]]
service:s1 = {
 user = network:n1, network:n4, network:n5;
 permit src = user; dst = network:n3; prt = tcp 25;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 25
access-list n1_in extended deny ip ::a01:0/112 ::a01:0/112
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip ::a01:0/112 ::a01:0/112
access-list n2_in extended permit ip any6 any6
access-group n2_in in interface n2
-- ipv6/r3
! n3_in
access-list n3_in extended deny ip ::a01:0/112 ::a01:0/112
access-list n3_in extended permit ip any6 any6
access-group n3_in in interface n3
--
! n4_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:400/120
access-list n4_in extended permit tcp object-group v6g0 ::a01:300/120 eq 25
access-list n4_in extended deny ip ::a01:0/112 ::a01:0/112
access-list n4_in extended permit ip any6 any6
access-group n4_in in interface n4
=END=

############################################################
=TITLE=Different filter_only separated by semi-managed
=PARAMS=--ipv6
=INPUT=
[[semi]]
=SUBST=/16;#r1/18;/
=SUBST=/112;#r1/114;/
# Also replace in generated IPv6 test.
=ERROR=
Error: router:r1 and router:r3 must have identical values in attribute 'filter_only'
=END=

############################################################
=TITLE=general_permit
# Must not ignore general_permit rules at local filter.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112;
 general_permit = icmpv6;
 interface:n1 = { ip = ::a01:101; hardware = outside; }
 interface:n2 = { ip = ::a01:201; hardware = inside; }
}
network:n2 = { ip = ::a01:200/120; }
=OUTPUT=
--ipv6/r1
! outside_in
access-list outside_in extended permit icmp6 any6 any6
access-list outside_in extended deny ip any6 ::a01:0/112
access-list outside_in extended permit ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=filter_only with /32
# Must not ignore general_permit rules at local filter.
=PARAMS=--ipv6
=INPUT=
router:u = {
 interface:vip = { ip = ::a09:909; vip; }
 interface:n1;
}
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed = local;
 routing = manual;
 filter_only =  ::a01:0/112, ::a09:909/128;
 general_permit = icmpv6;
 interface:n1 = { ip = ::a01:101; hardware = outside; }
 interface:n2 = { ip = ::a01:201; hardware = inside; }
}
network:n2 = { ip = ::a01:200/120; }
=OUTPUT=
--ipv6/r1
! outside_in
object-group network v6g0
 network-object ::a01:0/112
 network-object host ::a09:909
access-list outside_in extended permit icmp6 any6 any6
access-list outside_in extended deny ip any6 object-group v6g0
access-list outside_in extended permit ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=VRF members with mixed managed and managed=local
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a00:100/120; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:d32 = {
 model = ASA;
 managed;
 interface:n0 = { ip = ::a00:101; hardware = n0; }
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
router:r1@v1 = {
 model = IOS;
 managed = local;
 filter_only = ::a01:0/112;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r1@v2 = {
 model = IOS;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2v2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
service:test = {
 user = network:n0, network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ ACL for router:r1@v1 ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 ::a01:300/120 eq 80
 deny ipv6 ::a01:0/112 ::a01:0/112
 permit ipv6 any any
--
ipv6 access-list n2_in
 permit tcp ::a01:300/120 ::a01:100/120 established
 deny ipv6 ::a01:0/112 ::a01:0/112
 permit ipv6 any any
--
interface n1
 ipv6 address ::a01:102/120
 ip vrf forwarding v1
 ipv6 traffic-filter n1_in in
interface n2
 ipv6 address ::a01:201/120
 ip vrf forwarding v1
 ipv6 traffic-filter n2_in in
--
! [ ACL for router:r1@v2 ]
ipv6 access-list n2v2_in
 deny ipv6 any host ::a01:302
 permit tcp ::a00:100/120 ::a01:300/120 eq 80
 permit tcp ::a01:100/120 ::a01:300/120 eq 80
 deny ipv6 any any
--
ipv6 access-list n3_in
 permit tcp ::a01:300/120 ::a00:100/120 established
 permit tcp ::a01:300/120 ::a01:100/120 established
 deny ipv6 any any
--
interface n3
 ipv6 address ::a01:302/120
 ip vrf forwarding v2
 ipv6 traffic-filter n3_in in
=END=

############################################################
=TITLE=VRF members with different value of filter_only
=PARAMS=--ipv6
=INPUT=
network:n11 = { ip = ::a01:100/120; }
network:n12 = { ip = ::a01:200/120; }
network:n21 = { ip = ::a02:100/120; }
network:n22 = { ip = ::a02:200/120; }
router:r1@v1 = {
 model = IOS;
 managed = local;
 filter_only = ::a01:0/112;
 interface:n11 = { ip = ::a01:102; hardware = n11; }
 interface:n12 = { ip = ::a01:201; hardware = n12; }
}
router:d32 = {
 model = ASA;
 managed;
 interface:n12 = { ip = ::a01:202; hardware = n12; }
 interface:n21 = { ip = ::a02:102; hardware = n21; }
}
router:r1@v2 = {
 model = IOS;
 managed = local;
 filter_only = ::a02:0/112;
 interface:n21 = { ip = ::a02:101; hardware = n21; }
 interface:n22 = { ip = ::a02:201; hardware = n22; }
}
service:test = {
 user = network:n11, network:n21;
 permit src = user; dst = network:n22; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ ACL for router:r1@v1 ]
ipv6 access-list n11_in
 deny ipv6 any ::a01:0/112
 permit ipv6 any any
--
ipv6 access-list n12_in
 deny ipv6 ::a01:0/112 ::a01:0/112
 permit ipv6 any any
--
interface n11
 ipv6 address ::a01:102/120
 ip vrf forwarding v1
 ipv6 traffic-filter n11_in in
interface n12
 ipv6 address ::a01:201/120
 ip vrf forwarding v1
 ipv6 traffic-filter n12_in in
--
! [ ACL for router:r1@v2 ]
ipv6 access-list n21_in
 deny ipv6 any host ::a02:201
 permit tcp ::a02:100/120 ::a02:200/120 eq 80
 deny ipv6 ::a02:0/112 ::a02:0/112
 permit ipv6 any any
--
ipv6 access-list n22_in
 permit tcp ::a02:200/120 ::a02:100/120 established
 deny ipv6 any ::a02:0/112
 permit ipv6 any any
--
interface n21
 ipv6 address ::a02:101/120
 ip vrf forwarding v2
 ipv6 traffic-filter n21_in in
interface n22
 ipv6 address ::a02:201/120
 ip vrf forwarding v2
 ipv6 traffic-filter n22_in in
=END=

############################################################
=TITLE=Local aggregate permits local network
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:intern = { ip = ::a02:0/112; }
network:extern = { ip = ::a04:0/112; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:intern = { ip = ::a02:1; hardware = intern; }
}
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = ::a02:2; hardware = inside; }
 interface:extern = { ip = ::a04:1; hardware = outside; }
}
service:s1 = {
 user = network:extern;
 permit src = user;
        dst = any:[ip = ::a01:0/112 & network:n1];
        prt = tcp 80;
 permit src = any:[ip = ::a01:0/112 & network:n1];
        dst = user;
        prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[ip=::a01:0/112 & network:n1]; dst=network:extern; prt=tcp 80; of service:s1
 router:d32 with 'managed = local' would allow unfiltered access
 from additional networks:
 - network:n2
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=any:[ip=::a01:0/112 & network:n1]; prt=tcp 80; of service:s1
 router:d32 with 'managed = local' would allow unfiltered access
 to additional networks:
 - network:n2
=END=

############################################################
=TITLE=Local supernet as destination permits local network behind supernet
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a02:200/120; subnet_of = network:intern; }
network:intern = { ip = ::a02:0/112; }
network:extern = { ip = ::a04:0/112; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
 interface:intern = { ip = ::a02:1; hardware = intern; }
}
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = ::a02:2; hardware = inside; }
 interface:extern = { ip = ::a04:1; hardware = outside; }
}
service:s1 = {
 user = network:extern;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
# Test coverage: access from supernet to interface in same cluster
service:s2 = {
 user = any:[network:n1];
 permit src = user;
        dst = interface:d32.intern;
        prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=network:intern; prt=tcp 80; of service:s1
 router:d32 with 'managed = local' would allow unfiltered access
 to additional networks:
 - network:n2
=END=

############################################################
=TITLE=Access from external network matching filter_only is filtered at both
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a02:200/120; }
network:intern = { ip = ::a02:300/120; }
network:extern = { ip = ::a02:400/120; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
 interface:intern = { ip = ::a02:301; hardware = intern; }
}
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = ::a02:302; hardware = inside; }
 interface:extern = { ip = ::a02:401; hardware = outside; }
}
service:s1 = {
 user = network:extern;
 permit src = user;
        dst = any:[ip=::a02:0/112&network:n1];
        prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=any:[ip=::a02:0/112 & network:n1]; prt=tcp 80; of service:s1
 Generated ACL at interface:d31.extern would permit access to additional networks:
 - network:intern
 Either replace any:[ip=::a02:0/112 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=any:[ip=::a02:0/112 & network:n1]; prt=tcp 80; of service:s1
 Generated ACL at interface:d32.intern would permit access to additional networks:
 - network:n2
 Either replace any:[ip=::a02:0/112 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=OUTPUT=
--ipv6/d32
! n1_in
object-group network v6g0
 network-object ::a01:0/112
 network-object ::a02:0/112
access-list n1_in extended deny ip any6 object-group v6g0
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--
! intern_in
access-list intern_in extended permit tcp ::a02:400/120 ::a02:0/112 eq 80
access-list intern_in extended deny ip object-group v6g0 object-group v6g0
access-list intern_in extended permit ip any6 any6
access-group intern_in in interface intern
--ipv6/d31
! outside_in
access-list outside_in extended permit tcp ::a02:400/120 ::a02:0/112 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Supernet permits subnets in separate local cluster
=PARAMS=--ipv6
=INPUT=
network:super = { ip = ::a01:0/112; }
network:n1 = { ip = ::a01:100/120; subnet_of = network:super; }
network:n2 = { ip = ::a01:200/120; subnet_of = network:super; }
network:n3 = { ip = ::a01:300/120; subnet_of = network:super; }
network:intern = { ip = ::a02:0/112; }
network:extern = { ip = ::a04:0/112; }
router:r1 = {
 model = ASA;
 managed;
 interface:super = { ip = ::a01:1; hardware = super; }
 interface:n1    = { ip = ::a01:101; hardware = n1; }
}
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:intern = { ip = ::a02:1; hardware = intern; }
}
router:r3 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:intern = { ip = ::a02:2; hardware = intern; }
}
router:r4 = {
 model = ASA;
 managed;
 interface:intern = { ip = ::a02:3; hardware = inside; }
 interface:extern = { ip = ::a04:1; hardware = outside; }
}
service:s1 = {
 user = network:super;
 permit src = user;
        dst = network:extern;
        prt = tcp 80;
}
service:s2 = {
 user = network:extern;
 permit src = user;
        dst = network:super;
        prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:super; dst=network:extern; prt=tcp 80; of service:s1
 router:r2 with 'managed = local' would allow unfiltered access
 from additional networks:
 - network:n1
 - network:n2
 - network:n3
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=network:super; prt=tcp 80; of service:s2
 router:r2 with 'managed = local' would allow unfiltered access
 to additional networks:
 - network:n1
 - network:n2
 - network:n3
=END=

############################################################
=TITLE=All supernets permitted in separate local cluster
=PARAMS=--ipv6
=INPUT=
network:super = { ip = ::a01:0/112; }
network:n1 = { ip = ::a01:100/120; subnet_of = network:super; }
network:n2 = { ip = ::a01:200/120; subnet_of = network:super; }
network:intern = { ip = ::a02:0/112; }
network:extern = { ip = ::a04:0/112; }
router:r1 = {
 model = ASA;
 managed;
 interface:super = { ip = ::a01:1; hardware = super; }
 interface:n1    = { ip = ::a01:101; hardware = n1; }
}
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  ::a01:0/112, ::a02:0/112;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:intern = { ip = ::a02:1; hardware = intern; }
}
router:r3 = {
 model = ASA;
 managed;
 interface:intern = { ip = ::a02:2; hardware = inside; }
 interface:extern = { ip = ::a04:1; hardware = outside; }
}

service:s1 = {
 user = network:super,
        any:[ip = ::a01:0/112 & network:n1],
        any:[ip = ::a01:0/112 & network:n2],
        ;
 permit src = user;
        dst = network:extern;
        prt = tcp 80;
}
=WARNING=NONE

############################################################
