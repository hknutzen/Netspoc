
############################################################
=VAR=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; disabled; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Ignore disabled host, network, interface in rule
=INPUT=
${topo}
service:test = {
    user = host:h1, network:n2, interface:r1.n1, interface:r2.n2,
           interface:r1.[auto], interface:r1.[all];
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Ignore disabled aggregate in rule
=INPUT=
${topo}
any:n1 = { link = network:n1; }
service:test = {
 user = any:n1;
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Ignore disabled area in rule
=INPUT=
${topo}
area:a2 = { border = interface:r1.n2, interface:r2.n2;  }
service:test = {
 user = network:[area:a2];
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Disable between disabled interfaces, ignore redundant disable.
=INPUT=
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip = 10.1.0.2; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; disabled; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n0 = { ip = 10.1.0.3; hardware = n0; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; disabled; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; disabled; }
}
=END=
=WARNING=NONE

############################################################
=TITLE=Must not disable single interface inside loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; disabled; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
=END=
=ERROR=
Error: interface:r1.n1 must not be disabled,
 since it is part of a loop
Error: topology seems to be empty
Aborted
=END=

############################################################
=TITLE=Only warn on unknown network at disabled interface
=INPUT=
#network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; disabled; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=END=
=WARNING=
Warning: Referencing undefined network:n1 from interface:r1.n1
=END=

############################################################
=TITLE=Internally disable hosts of unconnected network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
protocol:Ping_Netz = icmp 8, src_net, dst_net;
service:s = {
 user = network:n1;
 permit src = host:h2; dst = user; prt = protocol:Ping_Netz;
}
=END=
=ERROR=
Error: network:n2 isn't connected to any router
=END=

############################################################
=TITLE=Service timed out for 365 days
=VAR=topo
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=VAR=output
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=
=DATE=-365
=INPUT=
${topo}
service:s = {
 disable_at = ${DATE};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
${output}
=END=

=TITLE=Service timed out for 30 days
=DATE=-30
=INPUT=
${topo}
service:s = {
 disable_at = ${DATE};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
${output}
=END=

=TITLE=Service timed out for 1 day
=DATE=-1
=INPUT=
${topo}
service:s = {
 disable_at = ${DATE};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
${output}
=END=

=TITLE=Service timed out today
=DATE=-0
=INPUT=
${topo}
service:s = {
 disable_at = ${DATE};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
${output}
=END=

############################################################
=TITLE=Service times out tomorrow
=VAR=output
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=
=DATE=1
=INPUT=
${topo}
service:s = {
 disable_at = ${DATE};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
${output}
=END=

=TITLE=Service times out in 10 days
=DATE=10
=INPUT=
${topo}
service:s = {
 disable_at = ${DATE};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
${output}
=END=

=TITLE=Service times out in 1000 days
=DATE=1000
=INPUT=
${topo}
service:s = {
 disable_at = ${DATE};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
${output}
=END=

############################################################
=TITLE=Invalid time limit at service
=INPUT=
${topo}
service:s = {
 disable_at = 1-Jan-2020;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Date expected as yyyy-mm-dd in 'disable_at' of service:s
=END=

############################################################
