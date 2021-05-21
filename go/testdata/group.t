
############################################################
=VAR=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24;
 host:h3a = { range = 10.1.3.10-10.1.3.15; }
 host:h3b = { ip = 10.1.3.26; }
}
network:n3sub = { ip = 10.1.3.64/27; subnet_of = network:n3;
 host:h3c = { ip = 10.1.3.66; }
 host:h3d = { range = 10.1.3.65 - 10.1.3.67; }
}
router:u = {
 interface:n3;
 interface:n3sub;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Redundant from automatic hosts
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
=INPUT=
${topo}
service:s1 = {
 user = host:[network:n3] &!host:h3c;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
-- r2
! n3_in
object-group network g0
 network-object 10.1.3.10 255.255.255.254
 network-object 10.1.3.12 255.255.255.252
 network-object host 10.1.3.26
 network-object host 10.1.3.65
 network-object 10.1.3.66 255.255.255.254
access-list n3_in extended permit tcp object-group g0 10.1.2.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=No subnets in automatic network in rule
=INPUT=
${topo}
service:s1 = {
 user = network:[any:[network:n3sub]];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
-- r2
! n3_in
access-list n3_in extended permit tcp 10.1.3.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Unexpected interface in automatic host
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
=INPUT=
network:n = { ip = 10.1.1.0/24; }
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
=INPUT=
network:n = { ip = 10.1.1.0/24; }
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
=INPUT=
network:n = { ip = 10.1.1.0/24; }
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
=INPUT=
network:n = { ip = 10.1.1.0/24; }
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
=INPUT=
network:n = { ip = 10.1.1.0/24; }

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
=INPUT=
network:n = { ip = 10.1.1.0/24; }

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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
group:g1 = interface:r1.n1, interface:r1.n2;
group:g2 = interface:[group:g1].[all];
service:s1 = {
 user = network:n1;
 permit src = user; dst = group:g2; prt = icmp;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Empty intersection
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 host:h1 = { ip = 10.1.3.10; }
 host:h2 = { ip = 10.1.3.12; }
}
router:u = {
 interface:n1;
 interface:n2;
}
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
group:g0 = ;
group:g1 =
 interface:r1.n2,
 interface:r1.[all] &! interface:r1.n2 &! interface:r1.n3,
 network:[any:[network:n1]] &! network:n1 &! network:n2,
 !any:[ip= 10.0.0.0/8 & network:n1] & any:[ip= 10.0.0.0/8 & network:n2],
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24;
 host:h6 = { ip = 10.1.4.6; }
 host:h7 = { ip = 10.1.4.7; } }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:lo = { ip = 10.1.0.99; loopback; }
 interface:n3;
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
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
-- r2
! n3_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
object-group network g1
 network-object host 10.1.0.99
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
access-list n3_in extended permit tcp object-group g0 10.1.4.6 255.255.255.254 eq 80
access-list n3_in extended permit tcp object-group g1 10.1.4.6 255.255.255.254 eq 25
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
