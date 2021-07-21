
############################################################
=TITLE=Unnumbered network must not have attributes
=INPUT=
network:u = {
 unnumbered;
 nat:x = { ip = 10.1.2.0/24; }
 host:h = { ip = 10.1.1.10; }
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
=INPUT=
network:u = { unnumbered; }
router:r1 = {
  interface:u = { unnumbered; virtual = { ip = 10.1.1.111; } }
}
=END=
=ERROR=
Error: No virtual IP supported for unnumbered interface:r1.u
=END=

############################################################
=TITLE=Unnumbered interface must not have routing protocol
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
=INPUT=
network:u = {
 unnumbered;
}
router:r1 = {
  interface:u = { ip = 10.1.1.1; }
}
=END=
=ERROR=
Error: interface:r1.u must not be linked to unnumbered network:u
=END=

############################################################
=TITLE=Unnumbered interface to network with IP
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
  interface:n1 = { unnumbered; }
}
=END=
=ERROR=
Error: Unnumbered interface:r1.n1 must not be linked to network:n1
=END=

############################################################
=TITLE=Unnumbered network to more than two interfaces
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
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
=VAR=input
network:servers = { ip = 10.1.7.32/27; }
router:r = {
 managed;
 model = IOS, FW;
 interface:servers = { ip = 10.1.7.33; hardware = e0; }
 interface:clients = { ip = 10.1.2.1; hardware = eth1; }
 interface:unn = { unnumbered; hardware = eth2; }
}
network:unn = { unnumbered; }
router:s = {
 interface:unn;
 interface:clients = { ip = 10.1.2.2; }
}
network:clients = { ip = 10.1.2.0/24; }
pathrestriction:clients = interface:s.clients, interface:r.clients;
service:test = {
 user = any:[network:clients];
 permit src = user; dst = network:servers;
 prt = tcp 80;
}
=END=
=VAR=output
--r
ip access-list extended eth2_in
 deny ip any host 10.1.7.33
 permit tcp any 10.1.7.32 0.0.0.31 eq 80
 deny ip any any
=END=
=INPUT=${input}
=OUTPUT=
${output}
=END=

############################################################
=TITLE=Zone cluster with unnumbered network (2)
=INPUT=${input}
=SUBST=/[network:clients]/[network:unn]/
=OUTPUT=
${output}
=END=

############################################################
=TITLE=Auto aggregate in zone cluster with unnumbered (1)
=VAR=input
router:Z = {
 interface:c = { unnumbered; }
 interface:L = { ip = 10.1.1.4; }
}
router:L = {
 managed;
 model = IOS;
 interface:c = { unnumbered; hardware = G2; }
 interface:L = { ip = 10.1.1.3; hardware = G0; }
}
network:c = {unnumbered;}
network:L = {ip = 10.1.1.0/24;}
pathrestriction:x = interface:Z.L, interface:L.L;
service:Test = {
 user = interface:L.[all];
 permit src = any:[user];
        dst = user;
        prt = icmp 8;
}
=END=
=INPUT=${input}
=OUTPUT=
--L
ip access-list extended G2_in
 permit icmp any host 10.1.1.3 8
 deny ip any any
--
ip access-list extended G0_in
 permit icmp any host 10.1.1.3 8
 deny ip any any
=END=

############################################################
=TITLE=Auto aggregate in zone cluster with unnumbered (2)
=INPUT=${input}
=SUBST=|[user]|[ip=10.0.0.0/8 & user]|
=OUTPUT=
--L
ip access-list extended G2_in
 permit icmp 10.0.0.0 0.255.255.255 host 10.1.1.3 8
 deny ip any any
--
ip access-list extended G0_in
 permit icmp 10.0.0.0 0.255.255.255 host 10.1.1.3 8
 deny ip any any
=END=

############################################################
=TITLE=Auto interface expands to short interface
=VAR=input
router:u1 = {
 model = IOS;
 interface:dummy;
}
network:dummy = { unnumbered; }
router:u2 = {
 interface:dummy = { unnumbered; }
 interface:n1 = { ip = 10.1.1.2; }
}
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = interface:u1.[auto];
 permit src = network:n2;
        dst = user;
	prt = tcp 22;
}
=END=
=INPUT=${input}
=ERROR=
Error: interface:u1.dummy without IP address (from .[auto])
 must not be used in rule of service:s1
=END=

############################################################
=TITLE=Auto interface expands to unnumbered interface
# and this unnumbered interface is silently ignored.
=INPUT=${input}
=SUBST=/interface:dummy;/interface:dummy = { unnumbered; }/
=OUTPUT=
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Auto interface to unnumbered with different destination
# Must not internally create rule with empty src-list from auto interface.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2;}
 interface:n3 = {ip = 10.1.3.1; hardware = n3;}
}
network:n3 = {ip = 10.1.3.0/24;}
router:r2 = {
 interface:n3 = {ip = 10.1.3.2;}
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
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
access-list n3_in extended permit tcp host 10.1.3.2 object-group g0 eq 49
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
