
############################################################
=TITLE=Unnumbered network must not have attributes
=PARAMS=--ipv6
=INPUT=
network:u = {
 unnumbered;
 nat:x = { ip = ::a01:200/120; }
 host:h = { ip = ::a01:10a; }
 has_subnets;
}
=END=
=ERROR=
Error: Unnumbered network:u must not have NAT definition
Error: Unnumbered network:u must not have attribute 'has_subnets'
Error: Unnumbered network:u must not have host definition
=END=

############################################################
=TITLE=Unnumbered interface must not have virtual IP
=PARAMS=--ipv6
=INPUT=
network:u = { unnumbered; }
router:r1 = {
  interface:u = { unnumbered; virtual = { ip = ::a01:16f; } }
}
=END=
=ERROR=
Error: No virtual IP supported for unnumbered interface:r1.u
=END=

############################################################
=TITLE=Unnumbered interface must not have routing protocol
=PARAMS=--ipv6
=INPUT=
network:u = { unnumbered; }
router:r1 = {
 managed;
 model = IOS;
  interface:u = { unnumbered; hardware = u; routing = OSPF; }
}
=END=
=ERROR=
Error: Routing 'OSPF' not supported for unnumbered interface:r1.u
=END=

############################################################
=TITLE=Unnumbered network to interface with IP
=PARAMS=--ipv6
=INPUT=
network:u = {
 unnumbered;
}
router:r1 = {
  interface:u = { ip = ::a01:101; }
}
=END=
=ERROR=
Error: interface:r1.u must not be linked to unnumbered network:u
=END=

############################################################
=TITLE=Unnumbered interface to network with IP
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
  interface:n1 = { unnumbered; }
}
=END=
=ERROR=
Error: Unnumbered interface:r1.n1 must not be linked to network:n1
=END=

############################################################
=TITLE=Unnumbered network to more than two interfaces
=PARAMS=--ipv6
=INPUT=
network:u = { unnumbered; }
router:r1 = { interface:u = { unnumbered; } }
router:r2 = { interface:u = { unnumbered; } }
router:r3 = { interface:u = { unnumbered; } }
=END=
=ERROR=
Error: Unnumbered network:u is connected to more than two interfaces:
 - interface:r1.u
 - interface:r2.u
 - interface:r3.u
=END=

############################################################
=TITLE=Must not use unnumbered network / interface in rule
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:un = { unnumbered; hardware = un; }
}
network:un = { unnumbered; }
service:test = {
 user = network:n1, interface:r.un;
 permit src = user; dst = network:un; prt = tcp 80;
}
=END=
=WARNING=
Warning: Ignoring unnumbered interface:r.un in src of rule in service:test
Warning: Ignoring unnumbered network:un in dst of rule in service:test
=END=

############################################################
=TITLE=Zone cluster with unnumbered network (1)
=TEMPL=input
network:servers = { ip = ::a01:720/123; }
router:r = {
 managed;
 model = IOS, FW;
 interface:servers = { ip = ::a01:721; hardware = e0; }
 interface:clients = { ip = ::a01:201; hardware = eth1; }
 interface:unn = { unnumbered; hardware = eth2; }
}
network:unn = { unnumbered; }
router:s = {
 interface:unn;
 interface:clients = { ip = ::a01:202; }
}
network:clients = { ip = ::a01:200/120; }
pathrestriction:clients = interface:s.clients, interface:r.clients;
service:test = {
 user = any:[network:{{.n}}];
 permit src = user; dst = network:servers;
 prt = tcp 80;
}
=END=
=TEMPL=output
--ipv6/r
ipv6 access-list eth2_in
 deny ipv6 any host ::a01:721
 permit tcp any ::a01:720/123 eq 80
 deny ipv6 any any
=END=
=PARAMS=--ipv6
=INPUT=[[input {n: clients}]]
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Zone cluster with unnumbered network (2)
=PARAMS=--ipv6
=INPUT=[[input {n: unn}]]
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Auto aggregate in zone cluster with unnumbered (1)
=TEMPL=input
router:Z = {
 interface:c = { unnumbered; }
 interface:L = { ip = ::a01:104; }
}
router:L = {
 managed;
 model = IOS;
 interface:c = { unnumbered; hardware = G2; }
 interface:L = { ip = ::a01:103; hardware = G0; }
}
network:c = {unnumbered;}
network:L = {ip = ::a01:100/120;}
pathrestriction:x = interface:Z.L, interface:L.L;
service:Test = {
 user = interface:L.[all];
 permit src = any:[{{.u}}];
        dst = user;
        prt = icmpv6 8;
}
=END=
=PARAMS=--ipv6
=INPUT=[[input {u: user}]]
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
=PARAMS=--ipv6
=INPUT=[[input {u: "ip=::a00:0/104 & user"}]]
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
 interface:dummy{{.u}}
}
network:dummy = { unnumbered; }
router:u2 = {
 interface:dummy = { unnumbered; }
 interface:n1 = { ip = ::a01:102; }
}
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = ::a01:101; hardware = n1; }
 interface:n2 = {ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = interface:u1.[auto];
 permit src = network:n2;
        dst = user;
	prt = tcp 22;
}
=END=
=PARAMS=--ipv6
=INPUT=[[input {u: ";"}]]
=ERROR=
Error: interface:u1.dummy without IP address (from .[auto])
 must not be used in rule of service:s1
=END=

############################################################
=TITLE=Auto interface expands to unnumbered interface
# and this unnumbered interface is silently ignored.
=PARAMS=--ipv6
=INPUT=[[input {u: " = { unnumbered; }"}]]
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Auto interface to unnumbered with different destination
# Must not internally create rule with empty src-list from auto interface.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;}
network:n2 = { ip = ::a01:200/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = ::a01:101; hardware = n1;}
 interface:n2 = {ip = ::a01:201; hardware = n2;}
 interface:n3 = {ip = ::a01:301; hardware = n3;}
}
network:n3 = {ip = ::a01:300/120;}
router:r2 = {
 interface:n3 = {ip = ::a01:302;}
 interface:u  = {unnumbered;}
}
network:u = {unnumbered;}
router:r3 = {
 interface:u = {unnumbered;}
}
service:s1  = {
 user = interface:r3.[auto], interface:r2.n3;
 permit src = user;
        dst = network:n1, network:n2;
        prt = tcp 49;
}
=END=
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
