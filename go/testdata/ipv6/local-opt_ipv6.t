
############################################################
=TITLE=Aggregates with identcal IP
=TEMPL=input
network:N1 = { ip6 = ::a04:600/120;}
router:R1 = {
 managed;
 model = IOS, FW;
 interface:N1 = {ip6 = ::a04:603;hardware = N1;}
 interface:T1 = {ip6 = ::a06:82e;hardware = T1;}
}
network:T1 = { ip6 = ::a06:82c/126;}
router:U = {
 interface:T1 = {ip6 = ::a06:82d;}
 interface:T2 = {ip6 = ::a06:801;}
}
network:T2 = { ip6 = ::a06:800/126;}
router:R2 = {
 managed;
 model = IOS, FW;
 interface:T2 = {ip6 = ::a06:802;hardware = T2;}
 interface:N2 = {ip6 = ::a05:101;hardware = N2;}
}
network:N2 = {ip6 = ::a05:100/126;}
any:ANY_G27 = {ip6 = ::/0; link = network:T1;}
service:Test = {
 user = network:N1;
 permit src = user;
	dst = any:ANY_G27, any:[ip6 = {{.}} & network:N2];
	prt = tcp 80;
}
=INPUT=[[input "::/0"]]
=OUTPUT=
--ipv6/R1
ipv6 access-list N1_in
 deny ipv6 any host ::a04:603
 deny ipv6 any host ::a06:82e
 permit tcp ::a04:600/120 any eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Aggregates in subnet relation
=INPUT=[[input "::a00:0/104"]]
# Unchanged ouput
=OUTPUT=
--ipv6/R1
ipv6 access-list N1_in
 deny ipv6 any host ::a04:603
 deny ipv6 any host ::a06:82e
 permit tcp ::a04:600/120 any eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Redundant port
=TODO= No IPv6
=INPUT=
network:A = { ip6 = ::a03:378/125; nat:C = { ip6 = ::a02:200/120; dynamic; }}
network:B = { ip6 = ::a03:380/125; nat:C = { ip6 = ::a02:200/120; dynamic; }}
router:ras = {
 managed;
 model = Linux;
 interface:A = { ip6 = ::a03:379; hardware = Fe0; }
 interface:B = { ip6 = ::a03:381; hardware = Fe1; }
 interface:Trans = { ip6 = ::a01:102; bind_nat = C; hardware = Fe2; }
}
network:Trans = { ip6 = ::a01:100/120;}
router:nak = {
 managed;
 model = IOS, FW;
 interface:Trans    = { ip6 = ::a01:101; hardware = eth0; }
 interface:Hosting  = { ip6 = ::a04:401; hardware = br0; }
}
network:Hosting = { ip6 = ::a04:400/120; }
service:A = {
 user = network:A;
 permit src = user;
	dst = network:Hosting;
	prt = tcp 55;
}
service:B = {
 user = network:B;
 permit src = user;
        dst = network:Hosting;
        prt = tcp 50-60;
}
=OUTPUT=
--ipv6/nak
! [ ACL ]
ipv6 access-list eth0_in
 deny ipv6 any host ::a04:401
 permit tcp ::a02:200/120 ::a04:400/120 range 50 60
 deny ipv6 any any
=END=

############################################################
=TITLE=Redundant tcp established
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n2-sub = { ip6 = ::a01:281; hardware = n2-sub; }
}
network:n2-sub = { ip6 = ::a01:280/121; subnet_of = network:n2; }
service:s1 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n2-sub; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = any:[network:n1]; prt = tcp;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 permit tcp any ::a01:280/121 eq 80
 permit tcp any ::a01:200/120 established
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:201
 permit tcp ::a01:200/120 any
 deny ipv6 any any
=END=

############################################################
=TITLE=Redundant managed interface at intermediate router
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = network:n2, interface:r2.n2;
 permit src = network:n1; dst = user; prt = tcp 22;
}
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit tcp ::a01:100/120 ::a01:200/120 eq 22
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp ::a01:200/120 ::a01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Redundant host
=TODO= No IPv6
=TEMPL=input
network:A = { ip6 = ::a03:300/121; host:a = { ip6 = ::a03:303; } }
network:sub = { ip6 = ::a03:308/125; subnet_of = network:A; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip6 = ::a03:301; hardware = VLAN1; }
 interface:sub = { ip6 = ::a03:309; hardware = VLAN9; }
 interface:Trans = { ip6 = ::a01:102; hardware = VLAN2; no_in_acl;}
}
network:Trans = { ip6 = ::a01:100/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:Trans = { ip6 = ::a01:101; hardware = VLAN1; bind_nat = dyn; }
 interface:Customer1 = { ip6 = ::a08:801; hardware = VLAN8; }
 interface:Customer2 = { ip6 = ::a09:901; hardware = VLAN9; }
}
network:Customer1 = { ip6 = ::a08:800/120; nat:dyn = { ip6 = ::a07:700/120; dynamic; } }
network:Customer2 = { ip6 = ::a09:900/120; nat:dyn = { ip6 = ::a07:700/120; dynamic; } }
service:test1 = {
 user = host:a;
 permit src = network:Customer1; dst = user; prt = tcp 80;
}
service:{{.}} = {
 user = network:A;
 permit src = network:Customer2; dst = user; prt = tcp 80-90;
}
=INPUT=[[input test2]]
=OUTPUT=
--ipv6/r1
ipv6 access-list VLAN1_out
 permit tcp ::a07:700/120 ::a03:300/121 range 80 90
 deny ipv6 any any
=END=

############################################################
=TITLE=Redundant host, changed order of rules
=TODO= No IPv6
=INPUT=[[input test0]]
# Unchanged output
=OUTPUT=
--ipv6/r1
ipv6 access-list VLAN1_out
 permit tcp ::a07:700/120 ::a03:300/121 range 80 90
 deny ipv6 any any
=END=

############################################################
=TITLE=Join adjacent and overlapping ports
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-82;
 permit src = user; dst = network:n2; prt = tcp 83-86;
}
service:t2 = {
 user = host:h1;
 permit src = network:n2; dst = user; prt = tcp 70-81;
 permit src = network:n2; dst = user; prt = tcp 82-85;
}
=OUTPUT=
-- ipv6/asa
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 range 80 86
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 host ::a01:10a range 70 85
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Join multiple adjacent ranges
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-82;
 permit src = user; dst = network:n2; prt = tcp 83-86;
}
service:t2 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 83-90;
}
=OUTPUT=
-- ipv6/asa
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 range 80 86
access-list n1_in extended permit tcp host ::a01:10a ::a01:200/120 range 83 90
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Find object-group after join ranges
=INPUT=
network:A1 = { ip6 = ::a01:100/120; }
network:A2 = { ip6 = ::a01:200/120; }
router:u = {
 interface:A1 = { ip6 = ::a01:101; }
 interface:A2 = { ip6 = ::a01:201; }
 interface:t = { ip6 = ::a09:101; }
}
network:t = { ip6 = ::a09:100/120; }
router:r = {
 model = ASA;
 managed;
 interface:t = { ip6 = ::a09:102; hardware = t; }
 interface:B = { ip6 = ::a02:101; hardware = B; }
}
network:B = { ip6 = ::a02:100/120; }
service:s1 = {
 user = network:A1;
 permit src = user; dst = network:B; prt = tcp 80-85;
 permit src = user; dst = network:B; prt = tcp 86;
}
service:s2 = {
 user = network:A2;
 permit src = user; dst = network:B; prt = tcp 80-86;
}
=OUTPUT=
-- ipv6/r
! t_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:200/120
access-list t_in extended permit tcp object-group v6g0 ::a02:100/120 range 80 86
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
--
! B_in
access-list B_in extended deny ip any6 any6
access-group B_in in interface B
=END=

############################################################
=TITLE=Don't join adjacent TCP and UDP ports
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = udp 81;
}
service:t2 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = udp 80;
 permit src = user; dst = network:n2; prt = tcp 81;
}
=OUTPUT=
-- ipv6/asa
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list n1_in extended permit udp ::a01:100/120 ::a01:200/120 eq 81
access-list n1_in extended permit udp host ::a01:10a ::a01:200/120 eq 80
access-list n1_in extended permit tcp host ::a01:10a ::a01:200/120 eq 81
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
