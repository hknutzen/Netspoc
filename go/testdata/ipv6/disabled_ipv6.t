
############################################################
=VAR=topo
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; disabled; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
=END=

############################################################
=TITLE=Ignore disabled host, network, interface in rule
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=TITLE=Partially disabled area with auto interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = ::a01:202; hardware = n2; disabled; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:303; hardware = n3; }
}
area:a2-3 = { inclusive_border = interface:r1.n1; border = interface:r3.n3; }
service:s1 = {
 user = interface:[area:a2-3].[auto];
 permit src = network:n3; dst = user; prt = tcp 22;
}
service:s2 = {
 user = interface:[interface:r2.n2].[auto];
 permit src = network:n3; dst = user; prt = tcp 23;
}
=OUTPUT=
-- ipv6/r2
ipv6 access-list n3_in
 permit tcp ::a01:300/120 host ::a01:302 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Disable between disabled interfaces, ignore redundant disable.
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a01:0/120; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip = ::a01:2; hardware = n0; }
 interface:n1 = { ip = ::a01:101; hardware = n1; disabled; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n0 = { ip = ::a01:3; hardware = n0; }
 interface:n2 = { ip = ::a01:201; hardware = n2; disabled; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; disabled; }
}
=END=
=WARNING=NONE

############################################################
=TITLE=Must not disable single interface inside loop
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; disabled; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
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
=PARAMS=--ipv6
=INPUT=
#network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; disabled; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
=END=
=WARNING=
Warning: Referencing undefined network:n1 from interface:r1.n1
=END=

############################################################
=TITLE=Internally disable hosts of unconnected network
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:103; hardware = n1; }
}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:20a; } }
protocol:Ping_Netz = icmpv6 8, src_net, dst_net;
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
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
=END=
=VAR=output
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=DATE=-365
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=DATE=1
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=TITLE=Invalid date format at service
=PARAMS=--ipv6
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
=TITLE=Invalid date at service
=PARAMS=--ipv6
=INPUT=
${topo}
service:s = {
 disable_at = 2031-31-31;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Invalid date in 'disable_at' of service:s: parsing time "2031-31-31": month out of range
=END=

############################################################
