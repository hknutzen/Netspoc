
############################################################
=VAR=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Must not define anchor together with border
=INPUT=
${topo}
area:a = {
 anchor = network:n1;
 border = interface:asa2.n2;
 inclusive_border = interface:asa2.n3;
}
=END=
=ERROR=
Error: Attribute 'anchor' must not be defined together with 'border' or 'inclusive_border' for area:a
=END=

############################################################
=TITLE=Must define either anchor or border
=INPUT=
${topo}
area:a = {}
=END=
=ERROR=
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a
=END=

############################################################
=TITLE=Must not use interface as border and inclusive_border
=INPUT=
${topo}
area:a = {
 border = interface:asa1.n2, interface:asa2.n3;
 inclusive_border = interface:asa2.n3;
}
=END=
=ERROR=
Error: interface:asa2.n3 is used as 'border' and 'inclusive_border' in area:a
=END=

############################################################
=TITLE=Only interface as border
=INPUT=
${topo}
area:a = { inclusive_border = network:n1; border = interface:asa1.n2; }
=END=
=ERROR=
Error: Unexpected 'network:n1' in 'inclusive_border' of area:a
=END=

############################################################
=TITLE=No automatic interface as border
=INPUT=
${topo}
area:a = { inclusive_border = interface:asa1.[all] &! interface:asa1.n2; }
area:b = { border = interface:asa2.[auto]; }
=END=
=ERROR=
Error: Unexpected 'interface:asa2.[auto]' in 'border' of area:b
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:b
=END=

############################################################
=TITLE=Unmanaged interface can't be border
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = { interface:n1; }
area:a = { border = interface:r1.n1; }
=END=
=ERROR=
Error: Must not reference unmanaged interface:r1.n1 in 'border' of area:a
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a
=END=

############################################################
=TITLE=Policy distribution point from nested areas
=INPUT=
${topo}
# a3 < a2 < all, a1 < all
area:all = {
 anchor = network:n1;
 router_attributes = { policy_distribution_point = host:h1; }
}
area:a1 = { border = interface:asa1.n1; }
area:a2 = {
 border = interface:asa1.n2;
 router_attributes = { policy_distribution_point = host:h3; }
}
area:a3 = { border = interface:asa2.n3; }
service:pdp1 = {
 user = interface:[managed & area:all].[auto];
 permit src = host:h1; dst = user; prt = tcp 22;
}
service:pdp3 = {
 user = interface:[managed & area:a2].[auto];
 permit src = host:h3; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--asa1
! [ IP = 10.1.1.1 ]
--asa2
! [ IP = 10.1.3.2 ]
=END=
=OPTION=--check_policy_distribution_point=warn

############################################################
=TITLE=Missing policy distribution point
=INPUT=
${topo}
area:all = {
 anchor = network:n1;
}
area:a2 = {
 border = interface:asa1.n2;
 router_attributes = { policy_distribution_point = host:h3; }
}
service:pdp1 = {
 user = interface:[managed & area:all].[auto];
 permit src = host:h1; dst = user; prt = tcp 22;
}
service:pdp3 = {
 user = interface:[managed & area:a2].[auto];
 permit src = host:h3; dst = user; prt = tcp 22;
}
=END=
=WARNING=
Warning: Missing attribute 'policy_distribution_point' for 1 devices:
 - router:asa1
=END=
=OPTION=--check_policy_distribution_point=warn

############################################################
=TITLE=Overlapping areas
=INPUT=
${topo}
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
area:a2 = { border = interface:asa1.n2; }
area:a2x = { border = interface:asa2.n2; }
=END=
=ERROR=
Error: Overlapping area:a2 and area:a2x
 - both areas contain any:[network:n2],
 - only 1. area contains any:[network:n3],
 - only 2. area contains any:[network:n1]
=END=

############################################################
=TITLE=Duplicate areas
=INPUT=
${topo}
area:a2 = { border = interface:asa1.n2; }
area:a2x = { border = interface:asa1.n2; }
=END=
=ERROR=
Error: Duplicate area:a2 and area:a2x
=END=

############################################################
=TITLE=Distinct areas, only router is different
=INPUT=
${topo}
area:a2 = { border = interface:asa1.n2; }
area:a2r = { inclusive_border = interface:asa1.n1; }
=END=
=WARNING=NONE

############################################################
=TITLE=Secondary interface as area border
=INPUT=
${topo}
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = {
  ip = 10.1.2.3; secondary:2 = { ip = 10.1.2.4; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
area:a1 = { border = interface:asa3.n2.2; }
group:g1 = network:[area:a1];
=END=
=OUTPUT=
10.1.2.0/24	network:n2
10.1.1.0/24	network:n1
10.1.3.0/24	network:n3
=END=
=TODO=test_group($title, $in, 'group:g1', $out);

############################################################
=TITLE=Secondary interface with name = virtual as border
=INPUT=
${topo}
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = {
  ip = 10.1.2.3; secondary:virtual = { ip = 10.1.2.4; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
area:a1 = { border = interface:asa3.n2.virtual; }
group:g1 = network:[area:a1];
=END=
=OUTPUT=
10.1.2.0/24	network:n2
10.1.1.0/24	network:n1
10.1.3.0/24	network:n3
=END=
=TODO=test_group($title, $in, 'group:g1', $out);

############################################################
=TITLE=Virtual interface as border
=INPUT=
${topo}
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = {
   ip = 10.1.2.3; virtual = { ip = 10.1.2.10; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:asa4 = {
 managed;
 model = ASA;
 interface:n2 = {
   ip = 10.1.2.4; virtual = { ip = 10.1.2.10; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
area:a1 = {
  border = interface:asa3.n2.virtual,
           interface:asa4.n2.virtual;
}
group:g1 = network:[area:a1];
=END=
=OUTPUT=
10.1.2.0/24	network:n2
10.1.1.0/24	network:n1
10.1.3.0/24	network:n3
=END=
=TODO=test_group($title, $in, 'group:g1', $out);

############################################################
# Changed $topo

############################################################
=VAR=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:asa2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
}
=END=

############################################################
=TITLE=Overlapping areas at router
=INPUT=
${topo}
area:a1 = {
 inclusive_border = interface:asa1.n1;
}
area:a2 = {
 inclusive_border = interface:asa1.n2, interface:asa1.n3;
}
=END=
=ERROR=
Error: Overlapping area:a2 and area:a1
 - both areas contain router:asa1,
 - only 1. area contains any:[network:n1],
 - only 2. area contains any:[network:n2]
=END=

############################################################
=TITLE=Missing router in overlapping areas
=INPUT=
${topo}
area:a1 = {
 inclusive_border = interface:asa1.n1, interface:asa2.n5;
}
area:a2 = {
 border = interface:asa1.n2, interface:asa1.n3;
}
=END=
=ERROR=
Error: Overlapping area:a1 and area:a2
 - both areas contain any:[network:n2],
 - only 1. area contains router:asa1,
 - only 2. area contains any:[network:n5]
=END=

############################################################
=TITLE=Empty area
=INPUT=
${topo}
area:a1 = {
 inclusive_border = interface:asa1.n1, interface:asa1.n2, interface:asa1.n3;
}
=END=
=WARNING=
Warning: area:a1 is empty
=END=

############################################################
=TITLE=Inconsistent definition of area in loop
=INPUT=
${topo}
area:a1 = {
 border = interface:asa2.n2;
 inclusive_border = interface:asa1.n2;
}
area:a2 = {
 border = interface:asa2.n2;
}
=END=
=ERROR=
Error: Inconsistent definition of area:a1 in loop.
 It is reached from outside via this path:
 - interface:asa2.n2
 - interface:asa1.n2
Error: Inconsistent definition of area:a2 in loop.
 It is reached from outside via this path:
 - interface:asa2.n2
 - interface:asa1.n2
 - interface:asa1.n3
 - interface:asa2.n3
 - interface:asa2.n2
=END=

############################################################
=TITLE=ACL from inclusive area
# border and inclusive_border can contact at an interface.
=INPUT=
${topo}
area:a1 = {
 inclusive_border = interface:asa1.n2, interface:asa1.n3;
}
area:a2 = {
 border = interface:asa1.n2, interface:asa1.n3;
 inclusive_border = interface:asa2.n5;
}
service:t = {
 user = network:[area:a2];
 permit src = user; dst = network:[area:a1]; prt = tcp 80;
}
=END=
=OUTPUT=
-- asa1
! n2_in
object-group network g0
 network-object 10.1.2.0 255.255.254.0
 network-object 10.1.4.0 255.255.255.0
access-list n2_in extended permit tcp object-group g0 10.1.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp object-group g0 10.1.1.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Router attributes from inclusive area
=INPUT=
${topo}
area:a1 = {
 inclusive_border = interface:asa1.n2, interface:asa1.n3;
 router_attributes = { general_permit = icmp; }
}
=END=
=OUTPUT=
-- asa1
! n1_in
access-list n1_in extended permit icmp any4 any4
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- asa2
! n2_in
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Unreachable border
=INPUT=
${topo}
area:a1 = {border = interface:asa1.n1,
                    interface:asa2.n2;}
=END=
=ERROR=
Error: Unreachable border of area:a1:
 - interface:asa2.n2
=END=

############################################################
=TITLE=Must not use area directly in rule
=INPUT=
${topo}
area:a1 = {border = interface:asa1.n1;}
service:s1 = { user = area:a1; permit src = user; dst = network:n2; prt = tcp; }
=END=
=WARNING=
Warning: Ignoring area:a1 in src of rule in service:s1
=END=

############################################################
=TITLE=Ignore area with disabled anchor
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; disabled; }
}
area:all = { anchor = network:n2; }
service:s1 = {
 user = network:[area:all];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=WARNING=NONE

############################################################
