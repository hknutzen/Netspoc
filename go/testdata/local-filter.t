
############################################################
=TITLE=Non matching mask of filter_only attribute
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/8;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
}
=ERROR=
Error: IP and mask of 10.62.0.0/8 don't match in 'filter_only' of router:d32
=END=

############################################################
=TITLE=Missing attribute 'filter_only'
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
}
=ERROR=
Error: Missing attribute 'filter_only' for router:d32
=END=

############################################################
=TITLE=Ignoring attribute 'filter_only'
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed;
 filter_only =  10.62.0.0/16;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
}
=WARNING=
Warning: Ignoring attribute 'filter_only' at router:d32; only valid with 'managed = local'
=END=

############################################################
=TITLE=Unsupported 'managed = local'
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = Linux;
 managed = local;
 filter_only =  10.62.0.0/16;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
}
=ERROR=
Error: Must not use 'managed = local' at router:d32 of model Linux
=END=

############################################################
=TITLE=Local network doesn't match filter_only attribute
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.1.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.2.33; hardware = n2; }
}
network:n2 = { ip = 10.62.2.32/27; }
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.1.0/24;
 interface:n2 = { ip = 10.62.2.34; hardware = n2; }
 interface:n3 = { ip = 10.62.1.1; hardware = n3; }
}
network:n3 = { ip = 10.62.1.0/27; }
=END=
# Show message only once.
=ERROR=
Error: network:n2 doesn't match attribute 'filter_only' of router:r1
=END=

############################################################
=TITLE=Useless value in filter_only attribute
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.1.0/24, 10.62.2.0/24, 10.62.3.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.2.33; hardware = n2; }
}
network:n2 = { ip = 10.62.2.32/27; }
=WARNING=
Warning: Useless 'filter_only = 10.62.3.0/24' at router:r1
=END=

############################################################
=TITLE=NAT not allowed
=INPUT=
network:n1 = { ip = 10.62.1.32/27; nat:n1 = { ip = 10.62.4.0/27; } }
network:n2 = { ip = 10.62.2.0/27;  nat:n2 = { ip = 10.62.5.0/27; } }
network:n3 = { ip = 10.62.3.0/27; }
router:d32 = {
 model = ASA;
 managed = local;
 routing = manual;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.2.1; hardware = n2; bind_nat = n1;}
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
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
network:n2 = { ip = 10.62.2.0/27; }
network:n3 = { ip = 10.62.3.64/27; }
network:n4 = { ip = 10.62.242.0/29; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.240.0/22, 10.62.0.0/19;
 interface:n4 = { ip = 10.62.242.1; hardware = n4; }
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
}
router:r2 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.62.240.0/21, 10.62.0.0/19,;
 interface:n4 = { ip = 10.62.242.2; hardware = n4; }
 interface:n2 = { ip = 10.62.2.1; hardware = n2; }
}
router:r3 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.62.240.0/22, 10.62.0.0/19, 10.62.32.0/19;
 interface:n4 = { ip = 10.62.242.3; hardware = n4; }
 interface:n3 = { ip = 10.62.3.65; hardware = n3; }
}
=ERROR=
Error: router:r1 and router:r2 must have identical values in attribute 'filter_only'
Error: router:r1 and router:r3 must have identical values in attribute 'filter_only'
=END=

############################################################
# Shared topology

############################################################
=TEMPL=topo
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only = 10.62.0.0/21, 10.62.241.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.241.1; hardware = n2; }
}
network:n2 = { ip = 10.62.241.0/29; }
router:d31 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.62.241.2; hardware = inside; }
 interface:extern = { ip = 10.125.3.1; hardware = outside; }
}
network:extern = { ip = 10.125.3.0/24; }
router:r1 = {
 interface:extern = { ip = 10.125.3.2; }
 interface:ex_match;
}
network:ex_match = { ip = 10.62.7.0/24; }
=END=

############################################################
=TITLE=Reuse object groups for deny rules
=INPUT=[[topo]]
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Filter src in deny rule with zone cluster
=INPUT=
network:n0 = { ip = 10.0.0.0/24; nat:n0 = { ip = 10.62.0.0/24; } }
router:r0 = {
 interface:n0;
 interface:n1 = { ip = 10.62.1.34; bind_nat = n0; }
}
[[topo]]
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip object-group g0 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=External rules are not filtered
=INPUT=
[[topo]]
service:Test = {
 user = network:n1;
 permit src = user; dst = network:extern; prt = tcp 80;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--d31
! inside_in
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 10.125.3.0 255.255.255.0 eq 80
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Mixed matching and non matching external rules
=INPUT=
[[topo]]
service:Test = {
 user = network:extern, network:ex_match;
 permit src = network:n1; dst = user; prt = tcp 80;
 permit src = user; dst = network:n1; prt = tcp 81;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended permit tcp 10.62.1.32 255.255.255.224 10.62.7.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.62.7.0 255.255.255.0 10.62.1.32 255.255.255.224 eq 81
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
--d31
! inside_in
object-group network g0
 network-object 10.62.7.0 255.255.255.0
 network-object 10.125.3.0 255.255.255.0
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 object-group g0 eq 80
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit tcp object-group g0 10.62.1.32 255.255.255.224 eq 81
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Aggregate to extern
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = 10.60.0.0/14 & network:n1, network:n2];
 permit src = user;
        dst = network:extern;
        prt = tcp 80;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Aggregate to local
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = 10.60.0.0/14 & network:n1];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended permit tcp 10.60.0.0 255.252.0.0 10.62.241.0 255.255.255.248 eq 80
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Non matching aggregate to non matching aggregate
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = 0.0.0.0/0 & network:n1];
 permit src = user;
        dst = any:[ip = 0.0.0.0/0 & network:n2];
        prt = tcp 80;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended permit tcp any4 any4 eq 80
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Non matching aggregate to non matching aggregate with IP any
# This generates two identical lines 'permit ip any4 any4',
# Access-list with duplicate lines is not valid for ASA.
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = 0.0.0.0/0 & network:n1];
 permit src = user;
        dst = any:[ip = 0.0.0.0/0 & network:n2];
        prt = ip;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended permit ip any4 any4
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Ignore non matching local aggregate
=INPUT=
[[topo]]
service:Test = {
 user = any:[ip = 10.99.0.0/16 & network:n1];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=External supernet of local network
=INPUT=
network:n1 = { ip = 10.62.1.0/24; subnet_of = network:extern; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/16, 10.9.0.0/16;
 interface:n1 = { ip = 10.62.1.1; hardware = n1; }
 interface:n2 = { ip = 10.9.1.1; hardware = n2; }
}
network:n2 = { ip = 10.9.1.0/29; }
router:d31 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.9.1.2; hardware = inside; }
 interface:extern = { ip = 10.62.0.1; hardware = outside; }
}
network:extern = { ip = 10.62.0.0/17; }
service:Test = {
 user = network:n1;
 permit src = network:extern;
        dst = user;
        prt = tcp 80;
}
=OUTPUT=
--d32
! n2_in
access-list n2_in extended permit tcp 10.62.0.0 255.255.128.0 10.62.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Subnet of external supernet
=INPUT=
network:n1 = { ip = 10.62.1.0/24; subnet_of = network:extern; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/16, 10.9.0.0/16;
 interface:n1 = { ip = 10.62.1.1; hardware = n1; }
 interface:n2 = { ip = 10.9.1.1; hardware = n2; }
}
network:n2 = { ip = 10.9.1.0/29; }
router:d31 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.9.1.2; hardware = inside; }
 interface:extern = { ip = 10.62.0.1; hardware = outside; }
}
network:extern = { ip = 10.62.0.0/15; }
router:u = {
 interface:extern = { ip = 10.62.0.2; }
 interface:sub;
}
network:sub = { ip = 10.62.2.0/24; subnet_of = network:extern; }
service:Test = {
 user = network:n1;
 permit src = network:sub;
        dst = user;
        prt = tcp 80;
}
=OUTPUT=
--d32
! n2_in
access-list n2_in extended permit tcp 10.62.2.0 255.255.255.0 10.62.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Internal / external network exactly match filter_only
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.4.2.0/24; subnet_of = network:extern; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16, 10.4.0.0/16;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.4.2.1; hardware = n2; }
 interface:intern = { ip = 10.2.0.1; hardware = intern; }
}
network:intern = { ip = 10.2.0.0/16; }
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.0.2; hardware = inside; }
 interface:extern = { ip = 10.4.0.1; hardware = outside; }
}
network:extern = { ip = 10.4.0.0/16; }
service:Test = {
 user = network:extern, network:intern;
 permit src = user;
        dst = network:n1, network:n2;
        prt = tcp 80;
}
=OUTPUT=
--d32
! intern_in
object-group network g1
 network-object 10.2.0.0 255.255.0.0
 network-object 10.4.0.0 255.255.0.0
object-group network g2
 network-object 10.1.1.0 255.255.255.0
 network-object 10.4.2.0 255.255.255.0
access-list intern_in extended permit tcp object-group g1 object-group g2 eq 80
access-list intern_in extended deny ip object-group g0 object-group g0
access-list intern_in extended permit ip any4 any4
access-group intern_in in interface intern
=END=

############################################################
=TITLE=Multiple internal subnets, unnumbered, hidden
=INPUT=
network:n1   = { ip = 10.1.1.0/24; }
network:n1-a = { ip = 10.1.1.32/27; subnet_of = network:n1; }
network:n1-b = { ip = 10.1.1.64/27; subnet_of = network:n1; }
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
 filter_only =  10.1.0.0/16, 10.2.0.0/16;
 interface:un = { unnumbered; hardware = un; }
 interface:intern = { ip = 10.2.1.1; hardware = intern; }
}
network:intern = { ip = 10.2.1.0/24; }
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.1.2; hardware = inside; bind_nat = h; }
 interface:extern = { ip = 10.4.0.1; hardware = outside; }
 interface:ex-hid = { ip = 10.2.2.129; hardware = ex-hid; }
}
network:extern = { ip = 10.4.0.0/16; }
network:ex-hid = { ip = 10.2.2.128/27; nat:h = { hidden; } }
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
--d32
! intern_in
object-group network g1
 network-object 10.1.1.32 255.255.255.224
 network-object 10.1.1.64 255.255.255.224
access-list intern_in extended permit tcp 10.2.1.0 255.255.255.0 object-group g1 eq 80
access-list intern_in extended permit tcp 10.2.1.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 81
access-list intern_in extended deny ip object-group g0 object-group g0
access-list intern_in extended permit ip any4 any4
access-group intern_in in interface intern
=END=

############################################################
=TITLE=Secondary filter near local filter filters fully
=TEMPL=input
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/16;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:trans = { ip = 10.62.241.1; hardware = trans; }
}
network:trans = { ip = 10.62.241.0/29; }
router:d31 = {
 model = ASA;
 managed = secondary;
 interface:trans = { ip = 10.62.241.2; hardware = inside; }
 interface:extern = { ip = 10.125.3.1; hardware = outside; }
}
network:extern = { ip = 10.125.3.0/24; }
service:Mail = {
 user = network:n1;
 permit src = user;
        dst = network:extern;
        prt = tcp 25;
}
=INPUT=[[input]]
=OUTPUT=
--d31
! inside_in
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 10.125.3.0 255.255.255.0 eq 25
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Different deny rules
=INPUT=[[input]]
=OUTPUT=
--d32
! n1_in
access-list n1_in extended deny ip any4 10.62.0.0 255.255.0.0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! trans_in
access-list trans_in extended deny ip 10.62.0.0 255.255.0.0 10.62.0.0 255.255.0.0
access-list trans_in extended permit ip any4 any4
access-group trans_in in interface trans
=END=

############################################################
=TITLE=Outgoing ACL
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; no_in_acl;}
 interface:n2 = { ip = 10.62.2.1; hardware = n2; }
}
network:n2 = { ip = 10.62.2.0/27; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
--d32
! n1_in
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.62.2.0 255.255.255.224 10.62.1.32 255.255.255.224 eq 22
access-list n2_in extended deny ip any4 10.62.0.0 255.255.224.0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
--
! n2_out
access-list n2_out extended permit tcp 10.62.1.32 255.255.255.224 10.62.2.0 255.255.255.224 eq 80
access-list n2_out extended deny ip 10.62.0.0 255.255.224.0 10.62.0.0 255.255.224.0
access-list n2_out extended permit ip any4 any4
access-group n2_out out interface n2
=END=

############################################################
=TITLE=Loop, virtual interfaces (1)
# Zone with virtual interfaces is recognized as leaf zone.
# Zone with other loop is handled as intermediate zone with
# possible connection to extern.
=INPUT=
network:n1 = { ip = 10.62.1.32/27; }
router:d1 = {
 model = IOS;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = {
  ip = 10.62.1.34;
  virtual = { ip = 10.62.1.33; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.62.2.1; hardware = n2; }
}
router:d2 = {
 model = IOS;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = {
  ip = 10.62.1.35;
  virtual = { ip = 10.62.1.33; }
  hardware = n21;
 }
 interface:trans = { ip = 10.62.3.1; hardware = n22; }
}
network:trans = { ip = 10.62.3.0/27; }
router:loop = {
 model = ASA;
 managed;
 interface:trans = { ip = 10.62.3.2; hardware = inside; }
 interface:n2 = { ip = 10.62.2.2; hardware = outside; }
}
network:n2 = { ip = 10.62.2.0/27; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
--d1
ip access-list extended n1_in
 deny ip any host 10.62.2.1
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 eq 80
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 established
 deny ip any 10.62.0.0 0.0.31.255
 permit ip any any
--d1
ip access-list extended n2_in
 deny ip any host 10.62.1.33
 deny ip any host 10.62.1.34
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 eq 22
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 established
 deny ip 10.62.0.0 0.0.31.255 10.62.0.0 0.0.31.255
 permit ip any any
=END=

############################################################
=TITLE=Loop, secondary at border
=INPUT=
network:n1 = { ip = 10.2.1.0/27; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:tr = { ip = 10.2.9.1; hardware = tr; }
}
network:n2 = { ip = 10.2.2.0/27;}
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:tr = { ip = 10.2.9.2; hardware = tr; }
}
network:tr = { ip = 10.2.9.0/29; }
router:ex = {
 model = ASA;
 managed = secondary;
 interface:tr = { ip = 10.2.9.6; hardware = inside; }
 interface:extern = { ip = 10.5.3.1; hardware = outside; }
}
network:extern = { ip = 10.5.3.0/24; }
service:Mail = {
 user = network:n2;
 permit src = user;
        dst = network:extern, network:n1;
        prt = tcp 25;
}
=OUTPUT=
--ex
! inside_in
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.224 10.5.3.0 255.255.255.0 eq 25
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--r1
! tr_in
access-list tr_in extended permit tcp 10.2.2.0 255.255.255.224 10.2.1.0 255.255.255.224 eq 25
access-list tr_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list tr_in extended permit ip any4 any4
access-group tr_in in interface tr
--r2
! n2_in
access-list n2_in extended permit tcp 10.2.2.0 255.255.255.224 10.2.1.0 255.255.255.224 eq 25
access-list n2_in extended deny ip any4 10.2.0.0 255.255.0.0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Don't check external aggregate rules
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
any:any1 = { link = network:n1; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.2.9.6; hardware = inside; }
}
network:n2 = { ip = 10.2.9.0/29; }
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 interface:n2 = { ip = 10.2.9.1; hardware = outside; }
 interface:dst = { ip = 10.2.1.1; hardware = inside; }
}
network:dst = { ip = 10.2.1.0/27; }
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
--r2
! outside_in
access-list outside_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list outside_in extended permit ip any4 any4
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended deny ip any4 10.2.0.0 255.255.0.0
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Check external aggregate covering filter_only network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
any:any1 = { link = network:n1; }
router:u = {
  interface:n1;
 interface:t1 =  { ip = 10.2.9.9; }
}
network:t1 = { ip = 10.2.9.8/29; }
router:r1 = {
 model = ASA;
 managed;
 interface:t1 = { ip = 10.2.9.10; hardware = outside; }
 interface:t2 = { ip = 10.2.9.6; hardware = inside; }
}
network:t2 = { ip = 10.2.9.0/29; }
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 interface:t2 = { ip = 10.2.9.1; hardware = outside; }
 interface:dst = { ip = 10.2.1.1; hardware = inside; }
}
network:dst = { ip = 10.2.1.0/27; }
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
--r2
! outside_in
access-list outside_in extended permit tcp any4 10.2.1.0 255.255.255.224 eq 25
access-list outside_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list outside_in extended permit ip any4 any4
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended permit tcp 10.2.1.0 255.255.255.224 any4 eq 110
access-list inside_in extended permit tcp 10.2.1.0 255.255.255.224 any4 eq 81
access-list inside_in extended deny ip any4 10.2.0.0 255.255.0.0
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Two disjunct local-filter parts
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
 managed = local;
 filter_only = 10.1.1.0/24, 10.1.2.0/24;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r4 = {
 managed = local;
 filter_only = 10.1.4.0/23;
 model = ASA;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
service:s1 = {
 user = network:n1, network:n4;
 permit src = user; dst = network:n5; prt = tcp 25;
}
=OUTPUT=
-- r1
! n1_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
-- r4
! n4_in
access-list n4_in extended permit tcp 10.1.4.0 255.255.255.0 10.1.5.0 255.255.255.0 eq 25
access-list n4_in extended deny ip 10.1.4.0 255.255.254.0 10.1.4.0 255.255.254.0
access-list n4_in extended permit ip any4 any4
access-group n4_in in interface n4
=END=

############################################################
=TITLE=local-filter cluster separated by semi-managed routers
=TEMPL=semi
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.2.5.0/24; }
router:r1 = {
 managed = local;
 filter_only = 10.1.0.0/16;#r1
 routing = dynamic;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2;
 interface:n3;
}
router:r3 = {
 managed = local;
 filter_only = 10.1.0.0/16;
 routing = dynamic;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r4 = {
 interface:n4;
 interface:n1;
}
router:r5 = {
 managed;
 model = ASA;
 routing = dynamic;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.2.5.1; hardware = n5; }
}
pathrestriction:p1 = interface:r2.n2, interface:r4.n4;
=INPUT=
[[semi]]
service:s1 = {
 user = network:n1, network:n4, network:n5;
 permit src = user; dst = network:n3; prt = tcp 25;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 25
access-list n1_in extended deny ip 10.1.0.0 255.255.0.0 10.1.0.0 255.255.0.0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip 10.1.0.0 255.255.0.0 10.1.0.0 255.255.0.0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
-- r3
! n3_in
access-list n3_in extended deny ip 10.1.0.0 255.255.0.0 10.1.0.0 255.255.0.0
access-list n3_in extended permit ip any4 any4
access-group n3_in in interface n3
--
! n4_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.4.0 255.255.255.0
access-list n4_in extended permit tcp object-group g0 10.1.3.0 255.255.255.0 eq 25
access-list n4_in extended deny ip 10.1.0.0 255.255.0.0 10.1.0.0 255.255.0.0
access-list n4_in extended permit ip any4 any4
access-group n4_in in interface n4
=END=

############################################################
=TITLE=Different filter_only separated by semi-managed
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16;
 general_permit = icmp;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.1.2.1; hardware = inside; }
}
network:n2 = { ip = 10.1.2.0/24; }
=OUTPUT=
--r1
! outside_in
access-list outside_in extended permit icmp any4 any4
access-list outside_in extended deny ip any4 10.1.0.0 255.255.0.0
access-list outside_in extended permit ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=filter_only with /32
# Must not ignore general_permit rules at local filter.
=INPUT=
router:u = {
 interface:vip = { ip = 10.9.9.9; vip; }
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed = local;
 routing = manual;
 filter_only =  10.1.0.0/16, 10.9.9.9/32;
 general_permit = icmp;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.1.2.1; hardware = inside; }
}
network:n2 = { ip = 10.1.2.0/24; }
=OUTPUT=
--r1
! outside_in
object-group network g0
 network-object 10.1.0.0 255.255.0.0
 network-object host 10.9.9.9
access-list outside_in extended permit icmp any4 any4
access-list outside_in extended deny ip any4 object-group g0
access-list outside_in extended permit ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=VRF members with mixed managed and managed=local
=INPUT=
network:n0 = { ip = 10.0.1.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:d32 = {
 model = ASA;
 managed;
 interface:n0 = { ip = 10.0.1.1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
router:r1@v1 = {
 model = IOS;
 managed = local;
 filter_only = 10.1.0.0/16;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r1@v2 = {
 model = IOS;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2v2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:test = {
 user = network:n0, network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
! [ ACL for router:r1@v1 ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80
 deny ip 10.1.0.0 0.0.255.255 10.1.0.0 0.0.255.255
 permit ip any any
--
ip access-list extended n2_in
 permit tcp 10.1.3.0 0.0.0.255 10.1.1.0 0.0.0.255 established
 deny ip 10.1.0.0 0.0.255.255 10.1.0.0 0.0.255.255
 permit ip any any
--
interface n1
 ip address 10.1.1.2 255.255.255.0
 ip vrf forwarding v1
 ip access-group n1_in in
interface n2
 ip address 10.1.2.1 255.255.255.0
 ip vrf forwarding v1
 ip access-group n2_in in
--
! [ ACL for router:r1@v2 ]
ip access-list extended n2v2_in
 deny ip any host 10.1.3.2
 permit tcp 10.0.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended n3_in
 permit tcp 10.1.3.0 0.0.0.255 10.0.1.0 0.0.0.255 established
 permit tcp 10.1.3.0 0.0.0.255 10.1.1.0 0.0.0.255 established
 deny ip any any
--
interface n3
 ip address 10.1.3.2 255.255.255.0
 ip vrf forwarding v2
 ip access-group n3_in in
=END=

############################################################
=TITLE=VRF members with different value of filter_only
=INPUT=
network:n11 = { ip = 10.1.1.0/24; }
network:n12 = { ip = 10.1.2.0/24; }
network:n21 = { ip = 10.2.1.0/24; }
network:n22 = { ip = 10.2.2.0/24; }
router:r1@v1 = {
 model = IOS;
 managed = local;
 filter_only = 10.1.0.0/16;
 interface:n11 = { ip = 10.1.1.2; hardware = n11; }
 interface:n12 = { ip = 10.1.2.1; hardware = n12; }
}
router:d32 = {
 model = ASA;
 managed;
 interface:n12 = { ip = 10.1.2.2; hardware = n12; }
 interface:n21 = { ip = 10.2.1.2; hardware = n21; }
}
router:r1@v2 = {
 model = IOS;
 managed = local;
 filter_only = 10.2.0.0/16;
 interface:n21 = { ip = 10.2.1.1; hardware = n21; }
 interface:n22 = { ip = 10.2.2.1; hardware = n22; }
}
service:test = {
 user = network:n11, network:n21;
 permit src = user; dst = network:n22; prt = tcp 80;
}
=OUTPUT=
--r1
! [ ACL for router:r1@v1 ]
ip access-list extended n11_in
 deny ip any 10.1.0.0 0.0.255.255
 permit ip any any
--
ip access-list extended n12_in
 deny ip 10.1.0.0 0.0.255.255 10.1.0.0 0.0.255.255
 permit ip any any
--
interface n11
 ip address 10.1.1.2 255.255.255.0
 ip vrf forwarding v1
 ip access-group n11_in in
interface n12
 ip address 10.1.2.1 255.255.255.0
 ip vrf forwarding v1
 ip access-group n12_in in
--
! [ ACL for router:r1@v2 ]
ip access-list extended n21_in
 deny ip any host 10.2.2.1
 permit tcp 10.2.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip 10.2.0.0 0.0.255.255 10.2.0.0 0.0.255.255
 permit ip any any
--
ip access-list extended n22_in
 permit tcp 10.2.2.0 0.0.0.255 10.2.1.0 0.0.0.255 established
 deny ip any 10.2.0.0 0.0.255.255
 permit ip any any
--
interface n21
 ip address 10.2.1.1 255.255.255.0
 ip vrf forwarding v2
 ip access-group n21_in in
interface n22
 ip address 10.2.2.1 255.255.255.0
 ip vrf forwarding v2
 ip access-group n22_in in
=END=

############################################################
=TITLE=Local aggregate permits local network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:intern = { ip = 10.2.0.0/16; }
network:extern = { ip = 10.4.0.0/16; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:intern = { ip = 10.2.0.1; hardware = intern; }
}
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.0.2; hardware = inside; }
 interface:extern = { ip = 10.4.0.1; hardware = outside; }
}
service:s1 = {
 user = network:extern;
 permit src = user;
        dst = any:[ip = 10.1.0.0/16 & network:n1];
        prt = tcp 80;
 permit src = any:[ip = 10.1.0.0/16 & network:n1];
        dst = user;
        prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=any:[ip=10.1.0.0/16 & network:n1]; dst=network:extern; prt=tcp 80; of service:s1
 router:d32 with 'managed = local' would allow unfiltered access
 from additional networks:
 - network:n2
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=any:[ip=10.1.0.0/16 & network:n1]; prt=tcp 80; of service:s1
 router:d32 with 'managed = local' would allow unfiltered access
 to additional networks:
 - network:n2
=END=

############################################################
=TITLE=Local supernet as destination permits local network behind supernet
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.2.2.0/24; subnet_of = network:intern; }
network:intern = { ip = 10.2.0.0/16; }
network:extern = { ip = 10.4.0.0/16; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:intern = { ip = 10.2.0.1; hardware = intern; }
}
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.0.2; hardware = inside; }
 interface:extern = { ip = 10.4.0.1; hardware = outside; }
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.2.2.0/24; }
network:intern = { ip = 10.2.3.0/24; }
network:extern = { ip = 10.2.4.0/24; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:intern = { ip = 10.2.3.1; hardware = intern; }
}
router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.3.2; hardware = inside; }
 interface:extern = { ip = 10.2.4.1; hardware = outside; }
}
service:s1 = {
 user = network:extern;
 permit src = user;
        dst = any:[ip=10.2.0.0/16&network:n1];
        prt = tcp 80;
}
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=any:[ip=10.2.0.0/16 & network:n1]; prt=tcp 80; of service:s1
 Generated ACL at interface:d31.extern would permit access to additional networks:
 - network:intern
 Either replace any:[ip=10.2.0.0/16 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
Warning: This supernet rule would permit unexpected access:
  permit src=network:extern; dst=any:[ip=10.2.0.0/16 & network:n1]; prt=tcp 80; of service:s1
 Generated ACL at interface:d32.intern would permit access to additional networks:
 - network:n2
 Either replace any:[ip=10.2.0.0/16 & network:n1] by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.1.0.0 255.255.0.0
 network-object 10.2.0.0 255.255.0.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! intern_in
access-list intern_in extended permit tcp 10.2.4.0 255.255.255.0 10.2.0.0 255.255.0.0 eq 80
access-list intern_in extended deny ip object-group g0 object-group g0
access-list intern_in extended permit ip any4 any4
access-group intern_in in interface intern
--d31
! outside_in
access-list outside_in extended permit tcp 10.2.4.0 255.255.255.0 10.2.0.0 255.255.0.0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Supernet permits subnets in separate local cluster
=INPUT=
network:super = { ip = 10.1.0.0/16; }
network:n1 = { ip = 10.1.1.0/24; subnet_of = network:super; }
network:n2 = { ip = 10.1.2.0/24; subnet_of = network:super; }
network:n3 = { ip = 10.1.3.0/24; subnet_of = network:super; }
network:intern = { ip = 10.2.0.0/16; }
network:extern = { ip = 10.4.0.0/16; }
router:r1 = {
 model = ASA;
 managed;
 interface:super = { ip = 10.1.0.1; hardware = super; }
 interface:n1    = { ip = 10.1.1.1; hardware = n1; }
}
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:intern = { ip = 10.2.0.1; hardware = intern; }
}
router:r3 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:intern = { ip = 10.2.0.2; hardware = intern; }
}
router:r4 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.0.3; hardware = inside; }
 interface:extern = { ip = 10.4.0.1; hardware = outside; }
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
=INPUT=
network:super = { ip = 10.1.0.0/16; }
network:n1 = { ip = 10.1.1.0/24; subnet_of = network:super; }
network:n2 = { ip = 10.1.2.0/24; subnet_of = network:super; }
network:intern = { ip = 10.2.0.0/16; }
network:extern = { ip = 10.4.0.0/16; }
router:r1 = {
 model = ASA;
 managed;
 interface:super = { ip = 10.1.0.1; hardware = super; }
 interface:n1    = { ip = 10.1.1.1; hardware = n1; }
}
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:intern = { ip = 10.2.0.1; hardware = intern; }
}
router:r3 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.0.2; hardware = inside; }
 interface:extern = { ip = 10.4.0.1; hardware = outside; }
}

service:s1 = {
 user = network:super,
        any:[ip = 10.1.0.0/16 & network:n1],
        any:[ip = 10.1.0.0/16 & network:n2],
        ;
 permit src = user;
        dst = network:extern;
        prt = tcp 80;
}
=WARNING=NONE

############################################################
