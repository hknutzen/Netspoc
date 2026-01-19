
############################################################
=TITLE=Secondary, primary, standard, full
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:sec = {
 managed = secondary;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/30; }
router:pri = {
 managed = primary;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
}
network:t2 = { ip = 10.9.2.0/30; }
router:ful = {
 managed = full;
 model = ASA;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t3 = { ip = 10.9.3.1; hardware = t3; }
}
network:t3 = { ip = 10.9.3.0/30; }
router:std = {
 managed = standard;
 model = ASA;
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:t4 = { ip = 10.9.4.1; hardware = t4; }
}
network:t4 = { ip = 10.9.4.0/30; }
router:hub = {
 managed = secondary;
 model = IOS;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:t2 = { ip = 10.9.2.2; hardware = t2; }
 interface:t3 = { ip = 10.9.3.2; hardware = t3; }
 interface:t4 = { ip = 10.9.4.2; hardware = t4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
service:s1 = {
 user = host:h1, host:h2;
 permit src = user;
        dst = network:n3, network:n4, network:n5;
        prt = tcp 80, udp 53;
}
=OUTPUT=
-- sec
! n1_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object 10.1.4.0 255.255.255.0
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 object-group g0
access-list n1_in extended permit tcp host 10.1.1.10 10.1.5.0 255.255.255.0 eq 80
access-list n1_in extended permit udp host 10.1.1.10 10.1.5.0 255.255.255.0 eq 53
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- pri
! n2_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object 10.1.4.0 255.255.254.0
access-list n2_in extended permit tcp host 10.1.2.10 object-group g0 eq 80
access-list n2_in extended permit udp host 10.1.2.10 object-group g0 eq 53
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
-- ful
! t3_in
object-group network g0
 network-object host 10.1.1.10
 network-object host 10.1.2.10
access-list t3_in extended permit tcp object-group g0 10.1.3.0 255.255.255.0 eq 80
access-list t3_in extended permit udp object-group g0 10.1.3.0 255.255.255.0 eq 53
access-list t3_in extended deny ip any4 any4
access-group t3_in in interface t3
-- std
! t4_in
access-list t4_in extended permit tcp host 10.1.1.10 10.1.4.0 255.255.255.0 eq 80
access-list t4_in extended permit udp host 10.1.1.10 10.1.4.0 255.255.255.0 eq 53
access-list t4_in extended permit ip 10.1.2.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list t4_in extended deny ip any4 any4
access-group t4_in in interface t4
-- hub
! [ ACL ]
ip access-list extended t1_in
 deny ip any host 10.1.5.1
 permit ip 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255
 permit ip 10.1.1.0 0.0.0.255 10.1.4.0 0.0.0.255
 permit tcp host 10.1.1.10 10.1.5.0 0.0.0.255 eq 80
 permit udp host 10.1.1.10 10.1.5.0 0.0.0.255 eq 53
 deny ip any any
--
ip access-list extended t2_in
 deny ip any host 10.1.5.1
 permit ip 10.1.2.0 0.0.0.255 10.1.3.0 0.0.0.255
 permit ip 10.1.2.0 0.0.0.255 10.1.4.0 0.0.1.255
 deny ip any any
--
ip access-list extended t3_in
 permit ip 10.1.3.0 0.0.0.255 10.1.1.0 0.0.0.255
 permit ip 10.1.3.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended t4_in
 permit ip 10.1.4.0 0.0.0.255 10.1.1.0 0.0.0.255
 permit ip 10.1.4.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended n5_in
 permit tcp 10.1.5.0 0.0.0.255 host 10.1.1.10 established
 permit udp 10.1.5.0 0.0.0.255 eq 53 host 10.1.1.10
 permit ip 10.1.5.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Optimize duplicate rules from secondary optimization
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h12 = { ip = 10.1.1.12; }
 host:h8-15 = { range = 10.1.1.8-10.1.1.15; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.1.128/25; subnet_of = network:n1; }

router:r1 = {
 managed = secondary;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.1.129; hardware = n3; }
}
service:s1 = {
 user = host:h8-15;
 permit src = user;
        dst = network:n3;
        prt = tcp 80;
}
service:s2 = {
 user = host:h10, host:h12;
 permit src = user;
        dst = network:n3;
        prt = tcp 81;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.8 255.255.255.248 10.1.1.128 255.255.255.128
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Secondary optimization to largest safe network
=INPUT=
network:all_10 = { ip = 10.0.0.0/8; }
network:super = { ip = 10.1.0.0/16; subnet_of = network:all_10; }
router:u1 = {
 interface:all_10;
 interface:super;
 interface:sub = { ip = 10.1.2.1; }
}
network:sub = { ip = 10.1.2.0/24; subnet_of = network:super; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:sub = { ip = 10.1.2.241; hardware = Ethernet2; }
 interface:trans = { ip = 10.3.1.17; hardware = Ethernet3; }
}
network:trans = { ip = 10.3.1.16/30; subnet_of = network:all_10; }
router:r2 = {
 managed = secondary;
 model = IOS, FW;
 interface:trans = { ip = 10.3.1.18; hardware = Ethernet5; }
 interface:dst = { ip = 10.9.9.1; hardware = Ethernet4; }
 interface:loop = {
  ip = 10.0.0.1;
  hardware = Loopback1;
  loopback;
  subnet_of = network:all_10;
 }
}
network:dst = {
 ip = 10.9.9.0/24;
 subnet_of = network:dst_super;
 host:server = { ip = 10.9.9.9; }
}
router:u2 = {
 interface:dst = { ip = 10.9.9.2; }
 interface:dst_super;
}
network:dst_super = { ip = 10.9.0.0/16; subnet_of = network:all_10; }
service:test = {
 user = network:sub;
 permit src = user;
        dst = host:server, interface:r2.loop;
        prt = tcp 80;
}
=OUTPUT=
--r2
ip access-list extended Ethernet5_in
 permit ip 10.1.0.0 0.0.255.255 host 10.0.0.1
 deny ip any host 10.9.9.1
 permit ip 10.1.0.0 0.0.255.255 10.9.0.0 0.0.255.255
 deny ip any any
=END=

############################################################
=TITLE=No optimization if subnet of subnet is outside of zone
=TEMPL=input
network:src = { ip = 10.1.1.0/24; }
# src must not be allowed to access subsub.
router:r1 = {
 managed = secondary;
 model = IOS, FW;
 interface:src = { ip = 10.1.1.1; hardware = Ethernet1; }
 interface:subsub = { ip = 10.9.9.49; hardware = Ethernet2; }
 interface:trans = { ip = 10.3.1.17; hardware = Ethernet3; }
}
network:subsub = { ip = 10.9.9.48/29; subnet_of = network:sub; }
network:trans = { ip = 10.3.1.16/30; }
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.3.1.18; hardware = Ethernet5; }
 interface:dst = { ip = 10.9.9.1; hardware = Ethernet4; }
}
network:dst = {
 ip = 10.9.9.0/24;
 host:server = { ip = 10.9.9.9; }
}
{{.}} = {
 interface:dst;
 interface:sub = { ip = 10.9.9.33; }
}
network:sub = { ip = 10.9.9.32/27;  subnet_of = network:dst; }
service:test = {
 user = network:src;
 permit src = user;
        dst = host:server;
        prt = tcp 80;
}
=INPUT=[[input router:u]]
=TEMPL=output
--r1
ip access-list extended Ethernet1_in
 permit ip 10.1.1.0 0.0.0.255 host 10.9.9.9
 deny ip any any
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=No optimization if subnet of subnet is outside of zone (2)
# Must recognize that dst has other subnet, even if subsub is
# processed later.
=INPUT=[[input router:r0]]
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=No optimization if subnet of subnet of subnet is outside of zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h2 = { ip = 10.1.3.10; } }
network:sub = { ip = 10.1.3.32/27; subnet_of = network:n3; }
network:subsub = { ip = 10.1.3.48/28; subnet_of = network:sub; }
network:subsubsub = { ip = 10.1.3.56/29; subnet_of = network:subsub; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed = secondary;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 interface:n3 = { ip = 10.1.3.3; }
 interface:sub;
}
router:r4 = {
 interface:sub;
 interface:subsub = { ip = 10.1.3.49; }
}
router:r5 = {
 managed;
 model = ASA;
 interface:subsub = { ip = 10.1.3.50; hardware = subsub; }
 interface:subsubsub = { ip = 10.1.3.57; hardware = subsubsub; }
}
service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
=OUTPUT=
--r2
! n2_in
access-list n2_in extended permit ip 10.1.1.0 255.255.255.0 host 10.1.3.10
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=No optimization on supernet, but partly on host
# Optimized rule "A -> B IP" would allow "A -> subB IP" accidently.
=INPUT=
network:A = { ip = 10.3.3.0/25; host:a = { ip = 10.3.3.3; } }
network:subB = { ip = 10.8.8.8/29; subnet_of = network:B; }
router:secondary = {
 managed = secondary;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip = 10.3.3.1; hardware = A; }
 interface:subB = { ip = 10.8.8.9; hardware = subB; }
 interface:Trans = { ip = 10.1.1.2; hardware = Trans; }
}
network:Trans = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.1.1.1; hardware = Trans; }
 interface:B = { ip = 10.8.8.1; hardware = B; }
}
network:B = { ip = 10.8.8.0/24; host:B = { ip = 10.8.8.7; } }
service:test1 = {
 user = network:A;
 permit src = user; dst = network:B, network:subB; prt = tcp 80;
}
service:test2 = {
 user = network:A;
 permit src = user; dst = host:B; prt = tcp 22;
}
=OUTPUT=
--secondary
! [ ACL ]
ip access-list extended A_in
 deny ip any host 10.8.8.9
 permit tcp 10.3.3.0 0.0.0.127 10.8.8.0 0.0.0.255 eq 80
 permit ip 10.3.3.0 0.0.0.127 host 10.8.8.7
 deny ip any any
-- filter
! Trans_in
access-list Trans_in extended permit tcp 10.3.3.0 255.255.255.128 10.8.8.0 255.255.255.0 eq 80
access-list Trans_in extended permit tcp 10.3.3.0 255.255.255.128 host 10.8.8.7 eq 22
access-list Trans_in extended deny ip any4 any4
access-group Trans_in in interface Trans
=END=

############################################################
=TITLE=No optimization with subnet in zone
# Must recognize related rules even with subnet relation inside zone.
=INPUT=
network:n1_sub = {
 ip = 10.1.1.240/28;
 subnet_of = network:n1;
 host:h1 = { ip = 10.1.1.251; }
}

router:u = {
 interface:n1_sub;
 interface:n1 = { ip = 10.1.1.2; }
}

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r2 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.5.1; hardware = n3; }
}

network:n3 = { ip = 10.1.5.0/24; }

service:any = {
 user = network:n1;
 permit src = user; dst = any:[ip = 10.1.4.0/23 & network:n2]; prt = tcp 22;
}

service:host = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- r2
! n2_in
access-list n2_in extended permit tcp host 10.1.1.251 10.1.5.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=No optimization with sub subnet in zone
=INPUT=
network:n1_subsub = {
 ip = 10.1.1.48/28;
 subnet_of = network:n1_sub;
 host:h1 = { ip = 10.1.1.51; }
}

network:n1_sub = { ip = 10.1.1.32/27; subnet_of = network:n1; }

router:u = {
 interface:n1_subsub;
 interface:n1_sub;
 interface:n1 = { ip = 10.1.1.2; }
}

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r2 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.5.1; hardware = n3; }
}

network:n3 = { ip = 10.1.5.0/24; }

service:any = {
 user = network:n1_sub;
 permit src = user; dst = any:[ip = 10.1.4.0/23 & network:n2]; prt = tcp 22;
}

service:host = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- r2
! n2_in
access-list n2_in extended permit tcp host 10.1.1.51 10.1.5.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=No optimization with same size aggregate in other zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

service:any = {
 user = any:[ip = 10.1.1.0/24 & network:n3];
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s1 = {
 user = host:h10, host:h12;
 permit src = user; dst = network:n4; prt = tcp 81;
}
=OUTPUT=
--r2
! n2_in
object-group network g0
 network-object host 10.1.1.10
 network-object host 10.1.1.12
access-list n2_in extended permit ip object-group g0 10.1.4.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Optimize with same size invisible aggregate in other zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

service:any = {
 user = network:[any:[ip = 10.1.1.0/24 & network:n3]];
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s1 = {
 user = host:h10, host:h12;
 permit src = user; dst = network:n4; prt = tcp 81;
}
=OUTPUT=
--r2
! n2_in
access-list n2_in extended permit ip 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Optimize even if src range is different
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
protocol:p1 = udp 53:1-65535;
protocol:p2 = udp 123:1-65535;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = protocol:p1, protocol:p2;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Interface of standard router as destination
# interface:r2.n2 must not be optimized
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:n1 = {
 user = interface:r2.n2;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.4 host 10.1.2.2 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Backside interface of standard router as destination
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:n1 = {
 user = interface:r2.n3;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Multiple interfaces of standard router as destination (1)
# interface:r2.n2 must not be optimized
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:n1 = {
 user = interface:r2.n2, interface:r2.n3;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.4 host 10.1.2.2 eq 80
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Multiple interfaces of standard router as destination (2)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
service:n1 = {
 user = interface:r2.n3, interface:r2.n4;
 permit src = host:h1; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object 10.1.4.0 255.255.255.0
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 object-group g0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Optimize real interface + loopback
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:t1 = { ip = 10.9.1.0/24; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
router:r2 = {
 model = IOS, FW;
 managed;
 routing = manual;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:lo = { ip = 10.8.1.1; hardware = lo; loopback; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r2.lo, interface:r2.n3; prt = tcp 22;
}
=OUTPUT=
--r1
! n1_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object host 10.8.1.1
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 object-group g0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Don't optimize if aggregate rule starts behind secondary router
=INPUT=
network:n1 = { ip = 10.2.1.0/27; host:h1 = { ip = 10.2.1.4; }}
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
}
network:n3 = { ip = 10.2.3.0/27; }
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
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp host 10.2.1.4 10.2.3.0 255.255.255.224 range 22 23
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n2_in
access-list n2_in extended permit tcp any4 10.2.3.0 255.255.255.224 eq 22
access-list n2_in extended permit tcp host 10.2.1.4 10.2.3.0 255.255.255.224 range 22 23
access-list n2_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not optimize even if aggregate is not on path of other rule.
=INPUT=
network:n1  = { ip = 10.2.1.0/27; }
network:n2  = { ip = 10.2.2.0/27; }
network:n2a = { ip = 10.2.2.32/27; }
network:n3  = { ip = 10.2.3.0/27; }

router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:n2a = { ip = 10.2.2.34; hardware = n2a; }
}

router:r2 = {
 model = ASA;
 managed;
 interface:n2  = { ip = 10.2.2.2; hardware = n2; }
 interface:n3  = { ip = 10.2.3.2; hardware = n3; }
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
--r1
! n1_in
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Don't optimize if aggregate rule ends before secondary router
=INPUT=
network:n1 = { ip = 10.2.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27;}
router:r2 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
}
network:n3 = { ip = 10.2.3.0/27; }
router:r3 = {
 interface:n3 = { ip = 10.2.3.4; }
 interface:n4;
}
# Doesn't match aggregate, hence still optimize.
network:n4 = { ip = 10.4.4.0/24; }

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
 permit src = user; dst = any:[ip = 10.2.0.0/16 & network:n2]; prt = tcp 22;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.0.0 255.255.0.0 eq 22
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 host 10.2.3.4 eq 80
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 10.4.4.0 255.255.255.0 eq 81
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n2_in
access-list n2_in extended permit tcp 10.2.1.0 255.255.255.224 host 10.2.3.4 eq 80
access-list n2_in extended permit ip 10.2.1.0 255.255.255.224 10.4.4.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not optimize interface rule if network is permitted
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24;}
router:r2 = {
 model = IOS, FW;
 managed = secondary;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
service:s2 = {
 user = network:n1;
 # Optimization is disabled, even if no network rule is present.
 permit src = user; dst = interface:r2.n2, interface:r2.n3; prt = udp 123;
}
=OUTPUT=
--r2
! [ ACL ]
ip access-list extended n2_in
 permit udp 10.1.1.0 0.0.0.255 host 10.1.2.2 eq 123
 permit udp 10.1.1.0 0.0.0.255 host 10.1.3.2 eq 123
 deny ip any any
=END=

############################################################
=TITLE=Don't optimize with primary router
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
router:r3 = {
 model = ASA;
 managed = primary;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
network:n4 = { ip = 10.1.4.0/24; }
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:any = {
 user = any:[ip=10.0.0.0/8 & network:n3];
 permit src = user; dst = network:n4; prt = tcp 22;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.4 10.1.4.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Disable secondary optimization for both primary and secondary.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.2.3.0/24; }
router:r1 = {
 managed = primary;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed = secondary;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.1; hardware = n3; }
}
service:s1 = {
 user = any:[ ip = 10.2.0.0/16 & network:n2 ];
 permit src = user; dst = network:n1; prt = tcp 3128;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
--r2
ip access-list extended n3_in
 permit tcp 10.2.3.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Find group, even if protocol IP comes from optimization
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h10 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = ASA;
 managed = primary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = ip;
}
=OUTPUT=
--r2
! n2_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
access-list n2_in extended permit ip object-group g0 10.1.3.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Unmanaged router with pathrestriction is not non secondary
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r3 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
}
pathrestriction:p1 = interface:r1.n2, interface:r2.n2;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r3
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Still optimize with different destinations in same zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
network:n4 = { ip = 10.1.4.0/24; host:h4 = { ip = 10.1.4.10; } }
network:t1 = { ip = 10.9.1.0/24; }
network:t2 = { ip = 10.9.2.0/24; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
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
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp any4 host 10.1.4.10 eq 81
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r2
! t1_in
access-list t1_in extended permit tcp 10.1.1.0 255.255.255.0 host 10.1.3.10 eq 80
access-list t1_in extended permit tcp any4 host 10.1.4.10 eq 81
access-list t1_in extended deny ip any4 any4
access-group t1_in in interface t1
=END=

############################################################
=TITLE=Still optimize with supernet rule having no_check_supernet_rules
=INPUT=
network:n1 = { ip = 10.2.1.0/27; host:h1 = { ip = 10.2.1.4; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
}
network:n3 = { ip = 10.2.3.0/27; }
protocol:Ping = icmp 8, no_check_supernet_rules;
service:h1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:any = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = protocol:Ping;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit ip 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Still optimize if supernet is used in same service
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24;}
router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.4; } }
service:n1 = {
 user = host:h1, any:[network:n2];
 permit src = user; dst = host:h3; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit ip host 10.1.1.4 10.1.3.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=TODO=Should optimize protocol and destination

############################################################
