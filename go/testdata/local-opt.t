
############################################################
=TITLE=Aggregates with identcal IP
=TEMPL=input
network:N1 = { ip = 10.4.6.0/24;}
router:R1 = {
 managed;
 model = IOS, FW;
 interface:N1 = {ip = 10.4.6.3;hardware = N1;}
 interface:T1 = {ip = 10.6.8.46;hardware = T1;}
}
network:T1 = { ip = 10.6.8.44/30;}
router:U = {
 interface:T1 = {ip = 10.6.8.45;}
 interface:T2 = {ip = 10.6.8.1;}
}
network:T2 = { ip = 10.6.8.0/30;}
router:R2 = {
 managed;
 model = IOS, FW;
 interface:T2 = {ip = 10.6.8.2;hardware = T2;}
 interface:N2 = {ip = 10.5.1.1;hardware = N2;}
}
network:N2 = {ip = 10.5.1.0/30;}
any:ANY_G27 = {ip = 0.0.0.0/0; link = network:T1;}
service:Test = {
 user = network:N1;
 permit src = user;
	dst = any:ANY_G27, any:[ip = {{.}} & network:N2];
	prt = tcp 80;
}
=INPUT=[[input "0.0.0.0/0"]]
=OUTPUT=
--R1
ip access-list extended N1_in
 deny ip any host 10.4.6.3
 deny ip any host 10.6.8.46
 permit tcp 10.4.6.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Aggregates in subnet relation
=INPUT=[[input "10.0.0.0/8"]]
# Unchanged ouput
=OUTPUT=
--R1
ip access-list extended N1_in
 deny ip any host 10.4.6.3
 deny ip any host 10.6.8.46
 permit tcp 10.4.6.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Redundant port
=INPUT=
network:A = { ip = 10.3.3.120/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
network:B = { ip = 10.3.3.128/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
router:ras = {
 managed;
 model = Linux;
 interface:A = { ip = 10.3.3.121; hardware = Fe0; }
 interface:B = { ip = 10.3.3.129; hardware = Fe1; }
 interface:Trans = { ip = 10.1.1.2; bind_nat = C; hardware = Fe2; }
}
network:Trans = { ip = 10.1.1.0/24;}
router:nak = {
 managed;
 model = IOS, FW;
 interface:Trans    = { ip = 10.1.1.1; hardware = eth0; }
 interface:Hosting  = { ip = 10.4.4.1; hardware = br0; }
}
network:Hosting = { ip = 10.4.4.0/24; }
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
--nak
! [ ACL ]
ip access-list extended eth0_in
 deny ip any host 10.4.4.1
 permit tcp 10.2.2.0 0.0.0.255 10.4.4.0 0.0.0.255 range 50 60
 deny ip any any
=END=

############################################################
=TITLE=Redundant tcp established
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n2-sub = { ip = 10.1.2.129; hardware = n2-sub; }
}
network:n2-sub = { ip = 10.1.2.128/25; subnet_of = network:n2; }
service:s1 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n2-sub; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = any:[network:n1]; prt = tcp;
}
=OUTPUT=
-- r1
ip access-list extended n1_in
 permit tcp any 10.1.2.128 0.0.0.127 eq 80
 permit tcp any 10.1.2.0 0.0.0.255 established
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit tcp 10.1.2.0 0.0.0.255 any
 deny ip any any
=END=

############################################################
=TITLE=Redundant managed interface at intermediate router
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = network:n2, interface:r2.n2;
 permit src = network:n1; dst = user; prt = tcp 22;
}
=OUTPUT=
-- r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 eq 22
 deny ip any any
--
ip access-list extended n2_in
 permit tcp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Redundant host
=TEMPL=input
network:A = { ip = 10.3.3.0/25; host:a = { ip = 10.3.3.3; } }
network:sub = { ip = 10.3.3.8/29; subnet_of = network:A; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip = 10.3.3.1; hardware = VLAN1; }
 interface:sub = { ip = 10.3.3.9; hardware = VLAN9; }
 interface:Trans = { ip = 10.1.1.2; hardware = VLAN2; no_in_acl;}
}
network:Trans = { ip = 10.1.1.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; bind_nat = dyn; }
 interface:Customer1 = { ip = 10.8.8.1; hardware = VLAN8; }
 interface:Customer2 = { ip = 10.9.9.1; hardware = VLAN9; }
}
network:Customer1 = { ip = 10.8.8.0/24; nat:dyn = { ip = 10.7.7.0/24; dynamic; } }
network:Customer2 = { ip = 10.9.9.0/24; nat:dyn = { ip = 10.7.7.0/24; dynamic; } }
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
--r1
ip access-list extended VLAN1_out
 permit tcp 10.7.7.0 0.0.0.255 10.3.3.0 0.0.0.127 range 80 90
 deny ip any any
=END=

############################################################
=TITLE=Redundant host, changed order of rules
=INPUT=[[input test0]]
# Unchanged output
=OUTPUT=
--r1
ip access-list extended VLAN1_out
 permit tcp 10.7.7.0 0.0.0.255 10.3.3.0 0.0.0.127 range 80 90
 deny ip any any
=END=

############################################################
=TITLE=Join adjacent and overlapping ports
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
-- asa
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 range 80 86
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.10 range 70 85
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Join multiple adjacent ranges
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
-- asa
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 range 80 86
access-list n1_in extended permit tcp host 10.1.1.10 10.1.2.0 255.255.255.0 range 83 90
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Find object-group after join ranges
=INPUT=
network:A1 = { ip = 10.1.1.0/24; }
network:A2 = { ip = 10.1.2.0/24; }
router:u = {
 interface:A1 = { ip = 10.1.1.1; }
 interface:A2 = { ip = 10.1.2.1; }
 interface:t = { ip = 10.9.1.1; }
}
network:t = { ip = 10.9.1.0/24; }
router:r = {
 model = ASA;
 managed;
 interface:t = { ip = 10.9.1.2; hardware = t; }
 interface:B = { ip = 10.2.1.1; hardware = B; }
}
network:B = { ip = 10.2.1.0/24; }
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
-- r
! t_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
access-list t_in extended permit tcp object-group g0 10.2.1.0 255.255.255.0 range 80 86
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
--
! B_in
access-list B_in extended deny ip any4 any4
access-group B_in in interface B
=END=

############################################################
=TITLE=Don't join adjacent TCP and UDP ports
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
-- asa
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended permit udp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 81
access-list n1_in extended permit udp host 10.1.1.10 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended permit tcp host 10.1.1.10 10.1.2.0 255.255.255.0 eq 81
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
