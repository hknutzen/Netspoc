
############################################################
=VAR=topo
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120;
 host:h3a = { range = ::a01:30a-::a01:30f; }
 host:h3b = { ip = ::a01:31a; }
}
network:n3sub = { ip = ::a01:340/123; subnet_of = network:n3;
 host:h3c = { ip = ::a01:342; }
 host:h3d = { range = ::a01:341 - ::a01:343; }
}
router:u = {
 interface:n3;
 interface:n3sub;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
=END=

############################################################
=TITLE=Redundant from automatic hosts
=PARAMS=--ipv6
=INPUT=
${topo}
service:s = {
 user = host:[network:n3sub];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=END=
=WARNING=
Warning: Redundant rules in service:s compared to service:s:
  permit src=network:n1; dst=host:h3c; prt=tcp 80; of service:s
< permit src=network:n1; dst=host:h3d; prt=tcp 80; of service:s
=END=

############################################################
=TITLE=Automatic hosts in rule
=PARAMS=--ipv6
=INPUT=
${topo}
service:s1 = {
 user = host:[network:n3] &!host:h3c;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
-- ipv6/r2
! n3_in
object-group network v6g0
 network-object ::a01:30a/127
 network-object ::a01:30c/126
 network-object host ::a01:31a
 network-object host ::a01:341
 network-object ::a01:342/127
access-list n3_in extended permit tcp object-group v6g0 ::a01:200/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=No subnets in automatic network in rule
=PARAMS=--ipv6
=INPUT=
${topo}
service:s1 = {
 user = network:[any:[network:n3sub]];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
-- ipv6/r2
! n3_in
access-list n3_in extended permit tcp ::a01:300/120 ::a01:200/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Unexpected interface in automatic host
=PARAMS=--ipv6
=INPUT=
${topo}
service:s1 = {
 user = host:[interface:r1.n1];
permit src = user; dst = network:n1; prt = ip;
}
=END=
=ERROR=
Error: Unexpected 'interface:r1.n1' in host:[..] of user of service:s1
=END=

############################################################
=TITLE=Intersection of complement
=PARAMS=--ipv6
=INPUT=
${topo}
service:s1 = {
 user = ! network:n1 & ! network:n2;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=END=
=ERROR=
Error: Intersection needs at least one element which is not complement in user of service:s1
=END=

############################################################
=TITLE=Complement without intersection
=PARAMS=--ipv6
=INPUT=
${topo}
service:s1 = {
 user = ! network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=END=
=ERROR=
Error: Complement (!) is only supported as part of intersection in user of service:s1
=END=

############################################################
=TITLE=Mark group in empty rule as used
# Don't show warning "unused group:g2
=PARAMS=--ipv6
=INPUT=
network:n = { ip = ::a01:100/120; }
group:g1 = ;
group:g2 = network:n;
service:s1 = {
 user = group:g1;
 permit src = user; dst = group:g2; prt = tcp 22;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Mark group in disabled rule as used
# Don't show warning "unused group:g2
=PARAMS=--ipv6
=INPUT=
network:n = { ip = ::a01:100/120; }
group:g1 = ;
group:g2 = network:n;
service:s1 = {
 disabled;
 user = group:g2;
 permit src = user; dst = group:g2; prt = tcp 22;
}
=END=
=WARNING=
Warning: unused group:g1
=END=

############################################################
=TITLE=Recursive definition of group
=PARAMS=--ipv6
=INPUT=
network:n = { ip = ::a01:100/120; }
group:g1 = group:g2;
group:g2 = network:n, group:g1;
service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 22;
}
=END=
=ERROR=
Error: Found recursion in definition of group:g2
=END=

############################################################
=TITLE=Can't resolve object in group
=PARAMS=--ipv6
=INPUT=
network:n = { ip = ::a01:100/120; }
group:g1 = host:h1;
service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 80;
}
=END=
=ERROR=
Error: Can't resolve host:h1 in group:g1
=END=

############################################################
=TITLE=Unexpected type in group
=PARAMS=--ipv6
=INPUT=
network:n = { ip = ::a01:100/120; }

group:g1 = foo:bar;

service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 22;
}
=END=
=ERROR=
Error: Unknown element type at line 3 of INPUT, near "group:g1 = --HERE-->foo:bar"
Aborted
=END=

############################################################
=TITLE=Unexpected type of automatic group
=PARAMS=--ipv6
=INPUT=
network:n = { ip = ::a01:100/120; }

group:g1 = area:[network:n], foo:[network:n];

service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 22;
}
=END=
=ERROR=
Error: Unexpected automatic group at line 3 of INPUT, near "group:g1 = --HERE-->area:[network:n]"
Aborted
=END=

############################################################
=TITLE=Duplicate elements in group
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
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
group:g1 = network:n1, network:n2, network:n2, network:n1, network:n2;
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=
Warning: Duplicate elements in group:g1:
 - network:n2
 - network:n1
 - network:n2
=END=

############################################################
=TITLE=Silently ignore duplicate elements from automatic interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
group:g1 = interface:r1.n1, interface:r1.n2;
group:g2 = interface:[group:g1].[all];
service:s1 = {
 user = network:n1;
 permit src = user; dst = group:g2; prt = icmpv6;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Empty intersection
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = {
 ip = ::a01:300/120;
 host:h1 = { ip = ::a01:30a; }
 host:h2 = { ip = ::a01:30c; }
}
router:u = {
 interface:n1;
 interface:n2;
}
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
group:g0 = ;
group:g1 =
 interface:r1.n2,
 interface:r1.[all] &! interface:r1.n2 &! interface:r1.n3,
 network:[any:[network:n1]] &! network:n1 &! network:n2,
 !any:[ip= ::a00:0/104 & network:n1] & any:[ip= ::a00:0/104 & network:n2],
 # No warning on intersection with empty group.
 group:g0 &! group:g0,
;
service:s1 = {
 user = !group:g1 & group:g1;
 permit src = user; dst = host:[network:n3] &! host:h1 &! host:h2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user &! network:n1; dst = network:n3; prt = tcp 80;
}
service:s3 = {
 user = interface:[network:n1].[all] &! interface:u.n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=WARNING=
Warning: Empty intersection in group:g1:
interface:r1.[all]
&! interface:r1.n2
&! interface:r1.n3
Warning: Empty intersection in group:g1:
network:[..]
&! network:n1
&! network:n2
Warning: Empty intersection in group:g1:
! any:[..]
&any:[..]
Warning: Empty intersection in user of service:s1:
! group:g1
&group:g1
Warning: Empty intersection in dst of rule in service:s1:
host:[..]
&! host:h1
&! host:h2
Warning: Must not define service:s1 with empty users and empty rules
Warning: Empty intersection in src of rule in service:s2:
user
&! network:n1
Warning: Empty intersection in user of service:s3:
interface:[..].[all]
&! interface:u.n1
=END=

############################################################
=TITLE=Object group together with adjacent IP addresses
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120;
 host:h6 = { ip = ::a01:406; }
 host:h7 = { ip = ::a01:407; } }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:lo = { ip = ::a01:63; loopback; }
 interface:n3;
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
service:s1 = {
 user = network:n1, network:n2;
 permit src = user; dst = host:h6, host:h7; prt = tcp 25, tcp 80;
}
service:s2 = {
 user = interface:r1.lo;
 permit src = user; dst = host:h6, host:h7; prt = tcp 25;
}
=END=
=OUTPUT=
-- ipv6/r2
! n3_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:200/120
object-group network v6g1
 network-object host ::a01:63
 network-object ::a01:100/120
 network-object ::a01:200/120
access-list n3_in extended permit tcp object-group v6g0 ::a01:406/127 eq 80
access-list n3_in extended permit tcp object-group v6g1 ::a01:406/127 eq 25
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
