
############################################################
=TITLE=Secondary, primary, standard, full
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:20a; } }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
router:sec = {
 managed = secondary;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
network:t1 = { ip = ::a09:100/126; }
router:pri = {
 managed = primary;
 model = ASA;
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:t2 = { ip = ::a09:201; hardware = t2; }
}
network:t2 = { ip = ::a09:200/126; }
router:ful = {
 managed = full;
 model = ASA;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:t3 = { ip = ::a09:301; hardware = t3; }
}
network:t3 = { ip = ::a09:300/126; }
router:std = {
 managed = standard;
 model = ASA;
 interface:n4 = { ip = ::a01:401; hardware = n4; }
 interface:t4 = { ip = ::a09:401; hardware = t4; }
}
network:t4 = { ip = ::a09:400/126; }
router:hub = {
 managed = secondary;
 model = IOS;
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:t2 = { ip = ::a09:202; hardware = t2; }
 interface:t3 = { ip = ::a09:302; hardware = t3; }
 interface:t4 = { ip = ::a09:402; hardware = t4; }
 interface:n5 = { ip = ::a01:501; hardware = n5; }
}
service:s1 = {
 user = host:h1, host:h2;
 permit src = user;
        dst = network:n3, network:n4, network:n5;
        prt = tcp 80, udp 53;
}
=END=
=OUTPUT=
-- ipv6/sec
! n1_in
object-group network v6g0
 network-object ::a01:300/120
 network-object ::a01:400/120
access-list n1_in extended permit ip ::a01:100/120 object-group v6g0
access-list n1_in extended permit tcp host ::a01:10a ::a01:500/120 eq 80
access-list n1_in extended permit udp host ::a01:10a ::a01:500/120 eq 53
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
-- ipv6/pri
! n2_in
object-group network v6g0
 network-object ::a01:300/120
 network-object ::a01:400/119
access-list n2_in extended permit tcp host ::a01:20a object-group v6g0 eq 80
access-list n2_in extended permit udp host ::a01:20a object-group v6g0 eq 53
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
-- ipv6/ful
! t3_in
object-group network v6g0
 network-object host ::a01:10a
 network-object host ::a01:20a
access-list t3_in extended permit tcp object-group v6g0 ::a01:300/120 eq 80
access-list t3_in extended permit udp object-group v6g0 ::a01:300/120 eq 53
access-list t3_in extended deny ip any6 any6
access-group t3_in in interface t3
-- ipv6/std
! t4_in
access-list t4_in extended permit tcp host ::a01:10a ::a01:400/120 eq 80
access-list t4_in extended permit udp host ::a01:10a ::a01:400/120 eq 53
access-list t4_in extended permit ip ::a01:200/120 ::a01:400/120
access-list t4_in extended deny ip any6 any6
access-group t4_in in interface t4
-- ipv6/hub
! [ ACL ]
ipv6 access-list t1_in
 deny ipv6 any host ::a01:501
 permit ipv6 ::a01:100/120 ::a01:300/120
 permit ipv6 ::a01:100/120 ::a01:400/120
 permit tcp host ::a01:10a ::a01:500/120 eq 80
 permit udp host ::a01:10a ::a01:500/120 eq 53
 deny ipv6 any any
--
ipv6 access-list t2_in
 deny ipv6 any host ::a01:501
 permit ipv6 ::a01:200/120 ::a01:300/120
 permit ipv6 ::a01:200/120 ::a01:400/119
 deny ipv6 any any
--
ipv6 access-list t3_in
 permit ipv6 ::a01:300/120 ::a01:100/120
 permit ipv6 ::a01:300/120 ::a01:200/120
 deny ipv6 any any
--
ipv6 access-list t4_in
 permit ipv6 ::a01:400/120 ::a01:100/120
 permit ipv6 ::a01:400/120 ::a01:200/120
 deny ipv6 any any
--
ipv6 access-list n5_in
 permit tcp ::a01:500/120 host ::a01:10a established
 permit udp ::a01:500/120 eq 53 host ::a01:10a
 permit ipv6 ::a01:500/120 ::a01:200/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Secondary optimization to largest safe network
=PARAMS=--ipv6
=INPUT=
network:all_10 = { ip = ::a00:0/104; has_subnets; }
network:super = { ip = ::a01:0/112; has_subnets; }
any:10_1_0-1 = { ip = ::a01:0/113; link = network:super; }
router:u1 = {
 interface:all_10;
 interface:super;
 interface:sub = { ip = ::a01:201; }
}
network:sub = { ip = ::a01:200/120; subnet_of = network:super; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:sub = { ip = ::a01:2f1; hardware = Ethernet2; }
 interface:trans = { ip = ::a03:111; hardware = Ethernet3; }
}
network:trans = { ip = ::a03:110/126; }
router:r2 = {
 managed = secondary;
 model = IOS, FW;
 interface:trans = { ip = ::a03:112; hardware = Ethernet5; }
 interface:dst = { ip = ::a09:901; hardware = Ethernet4; }
 interface:loop = { ip = ::a00:1; hardware = Loopback1; loopback; }
}
network:dst = {
 ip = ::a09:900/120;
 subnet_of = network:dst_super;
 host:server = { ip = ::a09:909; }
}
router:u2 = {
 interface:dst = { ip = ::a09:902; }
 interface:dst_super;
}
network:dst_super = { ip = ::a09:0/112; }
service:test = {
 user = network:sub;
 permit src = user;
        dst = host:server, interface:r2.loop;
        prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r2
ipv6 access-list Ethernet5_in
 permit ipv6 ::a01:0/112 host ::a00:1
 deny ipv6 any host ::a09:901
 permit ipv6 ::a01:0/112 ::a09:0/112
 deny ipv6 any any
=END=

############################################################
=TITLE=No optimization if subnet of subnet is outside of zone
=VAR=input
network:src = { ip = ::a01:100/120; }
# src must not be allowed to access subsub.
router:r1 = {
 managed = secondary;
 model = IOS, FW;
 interface:src = { ip = ::a01:101; hardware = Ethernet1; }
 interface:subsub = { ip = ::a09:931; hardware = Ethernet2; }
 interface:trans = { ip = ::a03:111; hardware = Ethernet3; }
}
network:subsub = { ip = ::a09:930/125; subnet_of = network:sub; }
network:trans = { ip = ::a03:110/126; }
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = ::a03:112; hardware = Ethernet5; }
 interface:dst = { ip = ::a09:901; hardware = Ethernet4; }
}
network:dst = {
 ip = ::a09:900/120;
 host:server = { ip = ::a09:909; }
}
router:u = {
 interface:dst;
 interface:sub = { ip = ::a09:921; }
}
network:sub = { ip = ::a09:920/123;  subnet_of = network:dst; }
service:test = {
 user = network:src;
 permit src = user;
        dst = host:server;
        prt = tcp 80;
}
=END=
=PARAMS=--ipv6
=INPUT=${input}
=VAR=output
--ipv6/r1
ipv6 access-list Ethernet1_in
 permit ipv6 ::a01:100/120 host ::a09:909
 deny ipv6 any any
=OUTPUT=
${output}
=END=

############################################################
=TITLE=No optimization if subnet of subnet is outside of zone (2)
# Must recognize that dst has other subnet, even if subsub is
# processed later.
=PARAMS=--ipv6
=INPUT=${input}
=SUBST=/router:u/router:r0/
=OUTPUT=
${output}
=END=

############################################################
=TITLE=No optimization if subnet of subnet of subnet is outside of zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; host:h2 = { ip = ::a01:30a; } }
network:sub = { ip = ::a01:320/123; subnet_of = network:n3; }
network:subsub = { ip = ::a01:330/124; subnet_of = network:sub; }
network:subsubsub = { ip = ::a01:338/125; subnet_of = network:subsub; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed = secondary;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 interface:n3 = { ip = ::a01:303; }
 interface:sub;
}
router:r4 = {
 interface:sub;
 interface:subsub = { ip = ::a01:331; }
}
router:r5 = {
 managed;
 model = ASA;
 interface:subsub = { ip = ::a01:332; hardware = subsub; }
 interface:subsubsub = { ip = ::a01:339; hardware = subsubsub; }
}
service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r2
! n2_in
access-list n2_in extended permit ip ::a01:100/120 host ::a01:30a
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=No optimization on supernet, but partly on host
# Optimized rule "A -> B IP" would allow "A -> subB IP" accidently.
=PARAMS=--ipv6
=INPUT=
network:A = { ip = ::a03:300/121; host:a = { ip = ::a03:303; } }
network:subB = { ip = ::a08:808/125; subnet_of = network:B; }
router:secondary = {
 managed = secondary;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip = ::a03:301; hardware = A; }
 interface:subB = { ip = ::a08:809; hardware = subB; }
 interface:Trans = { ip = ::a01:102; hardware = Trans; }
}
network:Trans = { ip = ::a01:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip = ::a01:101; hardware = Trans; }
 interface:B = { ip = ::a08:801; hardware = B; }
}
network:B = { ip = ::a08:800/120; host:B = { ip = ::a08:807; } }
service:test1 = {
 user = network:A;
 permit src = user; dst = network:B, network:subB; prt = tcp 80;
}
service:test2 = {
 user = network:A;
 permit src = user; dst = host:B; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/secondary
! [ ACL ]
ipv6 access-list A_in
 deny ipv6 any host ::a08:809
 permit tcp ::a03:300/121 ::a08:800/120 eq 80
 permit ipv6 ::a03:300/121 host ::a08:807
 deny ipv6 any any
-- ipv6/filter
! Trans_in
access-list Trans_in extended permit tcp ::a03:300/121 ::a08:800/120 eq 80
access-list Trans_in extended permit tcp ::a03:300/121 host ::a08:807 eq 22
access-list Trans_in extended deny ip any6 any6
access-group Trans_in in interface Trans
=END=

############################################################
=TITLE=Optimize even if src range is different
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
protocol:p1 = udp 53:1-65535;
protocol:p2 = udp 123:1-65535;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = protocol:p1, protocol:p2;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a01:100/120 ::a01:300/120
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Interface of standard router as destination
# interface:r2.n2 must not be optimized
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:104; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
service:n1 = {
 user = interface:r2.n2;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp host ::a01:104 host ::a01:202 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Backside interface of standard router as destination
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:104; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
service:n1 = {
 user = interface:r2.n3;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a01:100/120 ::a01:300/120
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Multiple interfaces of standard router as destination
# interface:r2.n2 must not be optimized
# Optimization of interface:r2.n3 is not implemented.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:104; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
service:n1 = {
 user = interface:r2.n2, interface:r2.n3;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object host ::a01:202
 network-object host ::a01:302
access-list n1_in extended permit tcp host ::a01:104 object-group v6g0 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Multiple interfaces of standard router as destination
# Optimization of multiple interfaces is not implemented.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:104; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
}
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
service:n1 = {
 user = interface:r2.n3, interface:r2.n4;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object host ::a01:302
 network-object host ::a01:402
access-list n1_in extended permit tcp host ::a01:104 object-group v6g0 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Optimize real interface + loopback
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:t1 = { ip = ::a09:100/120; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
router:r2 = {
 model = IOS, FW;
 managed;
 routing = manual;
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:lo = { ip = ::a08:101; hardware = lo; loopback; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r2.lo, interface:r2.n3; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object ::a01:300/120
 network-object host ::a08:101
access-list n1_in extended permit ip ::a01:100/120 object-group v6g0
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Optimize multiple interfaces of secondary router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:t1 = { ip = ::a09:100/120; }
network:t2 = { ip = ::a09:200/120; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
router:r2 = {
 model = IOS, FW;
 managed;
 routing = manual;
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:t2 = { ip = ::a09:202; hardware = t2; }
}
router:r3 = {
 model = ASA;
 managed = secondary;
 interface:t2 = { ip = ::a09:201; hardware = t2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r3.t2, interface:r3.n3; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object ::a01:300/120
 network-object ::a09:200/120
access-list n1_in extended permit ip ::a01:100/120 object-group v6g0
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Don't optimize if aggregate rule starts behind secondary router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a02:100/123; host:h1 = { ip = ::a02:104; }}
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a02:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a02:202; hardware = n2; }
 interface:n3 = { ip = ::a02:302; hardware = n3; }
}
network:n3 = { ip = ::a02:300/123; }
service:n1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:h1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 22-23;
}
service:any = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp host ::a02:104 ::a02:300/123 range 22 23
access-list n1_in extended permit tcp ::a02:100/123 ::a02:300/123 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp any6 ::a02:300/123 eq 22
access-list n2_in extended permit tcp host ::a02:104 ::a02:300/123 range 22 23
access-list n2_in extended permit tcp ::a02:100/123 ::a02:300/123 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not optimize even if aggregate is not on path of oter rule.
=PARAMS=--ipv6
=INPUT=
network:n1  = { ip = ::a02:100/123; }
network:n2  = { ip = ::a02:200/123; }
network:n2a = { ip = ::a02:220/123; }
network:n3  = { ip = ::a02:300/123; }

router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a02:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
 interface:n2a = { ip = ::a02:222; hardware = n2a; }
}

router:r2 = {
 model = ASA;
 managed;
 interface:n2  = { ip = ::a02:202; hardware = n2; }
 interface:n3  = { ip = ::a02:302; hardware = n3; }
}

service:n1 = {
 user = network:n1;
 permit src = user;
        dst = network:n3;
        prt = tcp 80;
}

service:any = {
 user = any:[network:n2a], network:n2;
 permit src = user;
        dst = network:n3;
        prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a02:100/123 ::a02:300/123 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Don't optimize if aggregate rule ends before secondary router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a02:100/123; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a02:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123;}
router:r2 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = ::a02:202; hardware = n2; }
 interface:n3 = { ip = ::a02:302; hardware = n3; }
}
network:n3 = { ip = ::a02:300/123; }
router:r3 = {
 interface:n3 = { ip = ::a02:304; }
 interface:n4;
}
# Doesn't match aggregate, hence still optimize.
network:n4 = { ip = ::a04:400/120; }

service:n1 = {
 user = network:n1;
 permit src = user; dst = interface:r3.n3; prt = tcp 80;
}
service:n4 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 81;
}
service:any = {
 user = network:n1;
 permit src = user; dst = any:[ip = ::a02:0/112 & network:n2]; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a02:100/123 ::a02:0/112 eq 22
access-list n1_in extended permit tcp ::a02:100/123 host ::a02:304 eq 80
access-list n1_in extended permit tcp ::a02:100/123 ::a04:400/120 eq 81
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a02:100/123 host ::a02:304 eq 80
access-list n2_in extended permit ip ::a02:100/123 ::a04:400/120
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Don't optimize with primary router
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:104; } }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
router:r3 = {
 model = ASA;
 managed = primary;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
}
network:n4 = { ip = ::a01:400/120; }
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:any = {
 user = any:[ip=::a00:0/104 & network:n3];
 permit src = user; dst = network:n4; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp host ::a01:104 ::a01:400/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Disable secondary optimization for both primary and secondary.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a02:300/120; }
router:r1 = {
 managed = primary;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed = secondary;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a02:301; hardware = n3; }
}
service:s1 = {
 user = any:[ ip = ::a02:0/112 & network:n2 ];
 permit src = user; dst = network:n1; prt = tcp 3128;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r2
ipv6 access-list n3_in
 permit tcp ::a02:300/120 ::a01:100/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Find group, even if protocol IP comes from optimization
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h10 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = ASA;
 managed = primary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = ip;
}
=END=
=OUTPUT=
--ipv6/r2
! n2_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:200/120
access-list n2_in extended permit ip object-group v6g0 ::a01:300/120
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Unmanaged router with pathrestriction is not non secondary
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
router:r3 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = ::a01:203; hardware = n2; }
 interface:n3 = { ip = ::a01:303; hardware = n3; }
}
pathrestriction:p1 = interface:r1.n2, interface:r2.n2;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r3
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Still optimize with different destinations in same zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:30a; } }
network:n4 = { ip = ::a01:400/120; host:h4 = { ip = ::a01:40a; } }
network:t1 = { ip = ::a09:100/120; }
network:t2 = { ip = ::a09:200/120; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:t1 = { ip = ::a09:101; hardware = t1; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:t2 = { ip = ::a09:201; hardware = t2; }
}
router:r3 = {
 interface:t2;
 interface:n3;
 interface:n4;
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h3; prt = tcp 80;
}
service:s2 = {
 user = any:[network:n2], any:[network:t1];
 permit src = user; dst = host:h4; prt = tcp 81;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a01:100/120 ::a01:300/120
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp any6 host ::a01:40a eq 81
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--ipv6/r2
! t1_in
access-list t1_in extended permit tcp ::a01:100/120 host ::a01:30a eq 80
access-list t1_in extended permit tcp any6 host ::a01:40a eq 81
access-list t1_in extended deny ip any6 any6
access-group t1_in in interface t1
=END=

############################################################
=TITLE=Still optimize with supernet rule having no_check_supernet_rules
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a02:100/123; host:h1 = { ip = ::a02:104; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a02:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a02:202; hardware = n2; }
 interface:n3 = { ip = ::a02:302; hardware = n3; }
}
network:n3 = { ip = ::a02:300/123; }
protocol:Ping = icmpv6 8, no_check_supernet_rules;
service:h1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:any = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = protocol:Ping;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a02:100/123 ::a02:300/123
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Still optimize if supernet is used in same service
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:104; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:304; } }
service:n1 = {
 user = host:h1, any:[network:n2];
 permit src = user; dst = host:h3; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit ip host ::a01:104 ::a01:300/120
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=TODO=Should optimize protocol and destination

############################################################
