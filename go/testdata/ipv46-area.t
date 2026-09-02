
############################################################
=TITLE=Dual stack area with v4 and v6 part and no combined border
=INPUT=
area:a2 =  { inclusive_border = interface:r1.n1, interface:r2.n3; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:1:3::2; hardware = n3; }
}
service:s1 = {
 user = network:n1, network:n3;
 permit src = user; dst = network:[area:a2]; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r2
! n3_in
access-list n3_in extended permit tcp 2001:db8:1:3::/64 2001:db8:1:2::/64 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=V4 and v6 part of dual stack area connected by border router
=INPUT=
area:a12 =  { inclusive_border = interface:r1.n3; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
service:s1 = {
 user = network:[area:a12];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n2_in
access-list n2_in extended permit tcp 2001:db8:1:2::/64 2001:db8:1:3::/64 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=V4 and v6 part of dual stack area connected by dual stack router
=INPUT=
area:a12 =  { inclusive_border = interface:r1.n3; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
service:s1 = {
 user = network:[area:a12];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n2_in
access-list n2_in extended permit tcp 2001:db8:1:2::/64 2001:db8:1:3::/64 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Disjoint v4 and v6 parts of dual stack area
# Dual stack area must contain at least one dual stack network
# and all networks must be connected.
=INPUT=
area:a13 =  { border = interface:r1.n1, interface:r2.n3; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:1:3::1; hardware = n3; }
}
=ERROR=
Error: Dual stack area:a13 must contain at least one common dual stack network
=END=

############################################################
=TITLE=Implicit v6 area is duplicate
=INPUT=
area:a12 = { border = interface:r2.n2; }
area:a2 =  { inclusive_border = interface:r1.n1; border = interface:r2.n2; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
}
=ERROR=
Error: Duplicate IPv6 area:a12 and IPv6 area:a2
=END=

############################################################
=TITLE=Implicit v4 area is duplicate
=INPUT=
area:a12 = { border = interface:r2.n2; }
area:a2 =  { inclusive_border = interface:r1.n1; border = interface:r2.n2; }
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
}
=ERROR=
Error: Duplicate IPv4 area:a12 and IPv4 area:a2
=END=

############################################################
=TITLE=Implicit v6 area is empty
=INPUT=
area:a1 =  { inclusive_border = interface:r1.n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=WARNING=
Warning: IPv6 area:a1 is empty
=END=

############################################################
=TITLE=Unreachable v6 border of dual stack area
=INPUT=
area:a23 =  { border = interface:r1.n2, interface:r3.n3; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
=ERROR=
Error: Unreachable border of IPv6 area:a23:
 - interface:r3.n3
=END=

############################################################
=TITLE=Inconsistent definition of v6 area in loop
=INPUT=
area:a1 = { border = interface:r1.n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = {                ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
}
=ERROR=
Error: Inconsistent definition of IPv6 area:a1 in loop.
 It is reached from outside via this path:
 - interface:r1.n1
 - interface:r2.n1
 - interface:r2.n2
 - interface:r1.n2
 - interface:r1.n1
=END=

############################################################
=TITLE=Overlapping v6 areas
=INPUT=
area:a1 = { inclusive_border = interface:r1.n1; }
area:a2 = { inclusive_border = interface:r2.n3; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = {                   ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n3 = {                ip6 = 2001:db8:1:3::1; hardware = n3; }
}
=ERROR=
Error: Overlapping IPv6 area:a1 and area:a2
 - both areas contain any:[network:n2],
 - only 1. area contains any:[network:n3],
 - only 2. area contains any:[network:n1]
=END=

############################################################
=TITLE=IPv4 policy_distribution_point at pure IPv6 area
=INPUT=
area:a1 = { anchor = network:n2;
 router_attributes = { policy_distribution_point = host:h1; }
}
network:n1 = { ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
}
network:n2 = {  ip6 = 2001:db8:1:2::/64; }
router:u = {
 interface:n1;
 interface:n2;
}
=WARNING=
Warning: Ignoring IPv4 'policy_distribution_point' at IPv6 area:a1
=END=

############################################################
=TITLE=Ignore IPv4 policy_distribution_point at IPv6 part of combined area
=INPUT=
area:a1 = { anchor = network:n1;
 router_attributes = { policy_distribution_point = host:h1; }
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip = 10.1.1.10; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
}
=WARNING=NONE

############################################################
=TITLE=Useless IPv6 policy_distribution_point
=INPUT=
area:all = { anchor = network:n2;
 router_attributes = { policy_distribution_point = host:h1; }
}
area:a1 = { border = interface:r1.n1;
 router_attributes = { policy_distribution_point = host:h1; }
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip6 = 2001:db8:1:1::10; }
}
network:n2 = { ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = interface:r1.n1;
 permit src = host:h1; dst = user; prt = tcp 22;
}
=WARNING=
Warning: Useless 'policy_distribution_point' at IPv6 area:a1,
 it was already inherited from router_attributes of area:all
Warning: Useless 'policy_distribution_point' at IPv6 router:r1,
 it was already inherited from router_attributes of area:all
=END=

############################################################
=TITLE=Use combined46 area in automatic group
=INPUT=
area:a23 = { inclusive_border = interface:r1.n1; }
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
}
network:n2 = {
 ip = 10.1.2.0/24;
 ip6 = 2001:db8:1:2::/64;
}
network:n3 = {
 ip = 10.1.3.0/24;
 ip6 = 2001:db8:1:3::/64;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:[area:a23]; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.254.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 2001:db8:1:1::/64 2001:db8:1:2::/63 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Missing owner for v6 part
=INPUT=
area:v4 = {
 owner = o1;
 router_attributes = { owner = o1; }
 inclusive_border = interface:r1.n3;
}
owner:o1 = { admins = a1@example.com; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = {
 ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64;
 host:h2 = { ip = 10.1.2.10; ip6 = 2001:db8:1:2::10; }
}
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = host:h2; prt = tcp 81;
 permit src = user; dst = interface:r1.n2; prt = tcp 82;
}
=WARNING=
Warning: Unknown owner for IPv6 host:h2 in service:s1
Warning: Unknown owner for IPv6 interface:r1.n2 in service:s1
Warning: Unknown owner for IPv6 network:n2 in service:s1
=OPTIONS=--check_service_unknown_owner=warn
