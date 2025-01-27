
############################################################
=TITLE=Unnumbered network must not have attributes
=TODO= No IPv6
=INPUT=
network:u = {
 unnumbered6;
 nat:x = { ip6 = ::a01:200/120; }
 host:h = { ip6 = ::a01:10a; }
 has_subnets;
}
=ERROR=
Error: Unnumbered network:u must not have NAT definition
Error: Unnumbered network:u must not have attribute 'has_subnets'
Error: Unnumbered network:u must not have host definition
=END=

############################################################
=TITLE=Unnumbered interface must not have virtual IP
=INPUT=
network:u = { unnumbered6; }
router:r1 = {
  interface:u = { unnumbered6; virtual = { ip6 = ::a01:16f; } }
}
=ERROR=
Error: No virtual IP supported for unnumbered interface:r1.u
=END=

############################################################
=TITLE=Unnumbered interface must not have routing protocol
=INPUT=
network:u = { unnumbered6; }
router:r1 = {
 managed;
 model = IOS;
  interface:u = { unnumbered6; hardware = u; routing = OSPF; }
}
=ERROR=
Error: Routing 'OSPF' not supported for unnumbered interface:r1.u
=END=

############################################################
=TITLE=Unnumbered network to interface with IP
=INPUT=
network:u = {
 unnumbered6;
}
router:r1 = {
  interface:u = { ip6 = ::a01:101; }
}
=ERROR=
Error: interface:r1.u must not be linked to unnumbered network:u
=END=

############################################################
=TITLE=Unnumbered interface to network with IP
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
  interface:n1 = { unnumbered6; }
}
=ERROR=
Error: Unnumbered interface:r1.n1 must not be linked to network:n1
=END=

############################################################
=TITLE=Unnumbered network to more than two interfaces
=INPUT=
network:u = { unnumbered6; }
router:r1 = { interface:u = { unnumbered6; } }
router:r2 = { interface:u = { unnumbered6; } }
router:r3 = { interface:u = { unnumbered6; } }
=ERROR=
Error: Unnumbered network:u is connected to more than two interfaces:
 - interface:r1.u
 - interface:r2.u
 - interface:r3.u
=END=

############################################################
=TITLE=Must not use unnumbered network / interface in rule
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:un = { unnumbered6; hardware = un; }
}
network:un = { unnumbered6; }
service:test = {
 user = network:n1, interface:r.un;
 permit src = user; dst = network:un; prt = tcp 80;
}
=WARNING=
Warning: Ignoring unnumbered interface:r.un in src of rule in service:test
Warning: Ignoring unnumbered network:un in dst of rule in service:test
=END=

############################################################
=TITLE=Zone cluster with unnumbered network (1)
=TEMPL=input
network:servers = { ip6 = ::a01:720/123; }
router:r = {
 managed;
 model = IOS, FW;
 interface:servers = { ip6 = ::a01:721; hardware = e0; }
 interface:clients = { ip6 = ::a01:201; hardware = eth1; }
 interface:unn = { unnumbered6; hardware = eth2; }
}
network:unn = { unnumbered6; }
router:s = {
 interface:unn;
 interface:clients = { ip6 = ::a01:202; }
}
network:clients = { ip6 = ::a01:200/120; }
pathrestriction:clients = interface:s.clients, interface:r.clients;
service:test = {
 user = any:[network:{{.}}];
 permit src = user; dst = network:servers;
 prt = tcp 80;
}
=TEMPL=output
--ipv6/r
ipv6 access-list eth2_in
 deny ipv6 any host ::a01:721
 permit tcp any ::a01:720/123 eq 80
 deny ipv6 any any
=INPUT=[[input clients]]
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Zone cluster with unnumbered network (2)
=INPUT=[[input unn]]
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Auto aggregate in zone cluster with unnumbered (1)
=TEMPL=input
router:Z = {
 interface:c = { unnumbered6; }
 interface:L = { ip6 = ::a01:104; }
}
router:L = {
 managed;
 model = IOS;
 interface:c = { unnumbered6; hardware = G2; }
 interface:L = { ip6 = ::a01:103; hardware = G0; }
}
network:c = {unnumbered6;}
network:L = {ip6 = ::a01:100/120;}
pathrestriction:x = interface:Z.L, interface:L.L;
service:Test = {
 user = interface:L.[all];
 permit src = any:[{{.}}];
        dst = user;
        prt = icmpv6 8;
}
=INPUT=[[input user]]
=OUTPUT=
--ipv6/L
ipv6 access-list G2_in
 permit icmp any host ::a01:103 8
 deny ipv6 any any
--
ipv6 access-list G0_in
 permit icmp any host ::a01:103 8
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto aggregate in zone cluster with unnumbered (2)
=INPUT=[[input "ip6=::a00:0/104 & user"]]
=OUTPUT=
--ipv6/L
ipv6 access-list G2_in
 permit icmp ::a00:0/104 host ::a01:103 8
 deny ipv6 any any
--
ipv6 access-list G0_in
 permit icmp ::a00:0/104 host ::a01:103 8
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interface expands to short interface
=TEMPL=input
router:u1 = {
 model = IOS;
 interface:dummy{{.}}
}
network:dummy = { unnumbered6; }
router:u2 = {
 interface:dummy = { unnumbered6; }
 interface:n1 = { ip6 = ::a01:102; }
}
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip6 = ::a01:101; hardware = n1; }
 interface:n2 = {ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
service:s1 = {
 user = interface:u1.[auto];
 permit src = network:n2;
        dst = user;
	prt = tcp 22;
}
=INPUT=[[input ";"]]
=ERROR=
Error: interface:u1.dummy without IP address (from .[auto])
 must not be used in rule of service:s1
=END=

############################################################
=TITLE=Auto interface expands to unnumbered interface
# and this unnumbered interface is silently ignored.
=INPUT=[[input " = { unnumbered6; }"]]
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Auto interface to unnumbered with different destination
# Must not internally create rule with empty src-list from auto interface.
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = { ip6 = ::a01:200/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip6 = ::a01:101; hardware = n1;}
 interface:n2 = {ip6 = ::a01:201; hardware = n2;}
 interface:n3 = {ip6 = ::a01:301; hardware = n3;}
}
network:n3 = {ip6 = ::a01:300/120;}
router:r2 = {
 interface:n3 = {ip6 = ::a01:302;}
 interface:u  = {unnumbered6;}
}
network:u = {unnumbered6;}
router:r3 = {
 interface:u = {unnumbered6;}
}
service:s1  = {
 user = interface:r3.[auto], interface:r2.n3;
 permit src = user;
        dst = network:n1, network:n2;
        prt = tcp 49;
}
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n3_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:200/120
access-list n3_in extended permit tcp host ::a01:302 object-group v6g0 eq 49
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
