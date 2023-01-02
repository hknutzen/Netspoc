
############################################################
=TEMPL=topo
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:30a; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
=END=

############################################################
=TITLE=Must not define anchor together with border
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {
 anchor = network:n1;
 border = interface:asa2.n2;
}
area:a2 = {
 anchor = network:n1;
 inclusive_border = interface:asa2.n3;
}
area:a3 = {
 anchor = network:n1;
 border = interface:asa2.n2;
 inclusive_border = interface:asa2.n3;
}
=ERROR=
Error: Attribute 'anchor' must not be defined together with 'border' or 'inclusive_border' for area:a1
Error: Attribute 'anchor' must not be defined together with 'border' or 'inclusive_border' for area:a2
Error: Attribute 'anchor' must not be defined together with 'border' or 'inclusive_border' for area:a3
=END=

############################################################
=TITLE=Must define either anchor or border
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a = {}
=ERROR=
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a
=END=

############################################################
=TITLE=Must not use interface as border and inclusive_border
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a = {
 border = interface:asa1.n2, interface:asa2.n3;
 inclusive_border = interface:asa2.n3;
}
=ERROR=
Error: interface:asa2.n3 is used as 'border' and 'inclusive_border' in area:a
=END=

############################################################
=TITLE=Only interface as border
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a = { inclusive_border = network:n1; border = interface:asa1.n2; }
=ERROR=
Error: Unexpected 'network:n1' in 'inclusive_border' of area:a
=END=

############################################################
=TITLE=No automatic interface as border
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a = { inclusive_border = interface:asa1.[all] &! interface:asa1.n2; }
area:b = { border = interface:asa2.[auto]; }
=ERROR=
Error: Unexpected 'interface:asa2.[auto]' in 'border' of area:b
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:b
=END=

############################################################
=TITLE=Unmanaged interface can't be border
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = { interface:n1; }
area:a = { border = interface:r1.n1; }
=ERROR=
Error: Must not reference unmanaged interface:r1.n1 in 'border' of area:a
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a
=END=

############################################################
=TITLE=Policy distribution point from nested areas
=PARAMS=--ipv6
=INPUT=
[[topo]]
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
 permit src = host:h1; dst = user; prt = tcp;
}
service:pdp3 = {
 user = interface:[managed & area:a2].[auto];
 permit src = host:h3; dst = user; prt = ip;
}
=OUTPUT=
--ipv6/asa1
! [ IP = ::a01:101 ]
--ipv6/asa2
! [ IP = ::a01:302 ]
=END=
=OPTIONS=--check_policy_distribution_point=warn

############################################################
=TITLE=Missing policy distribution point
=PARAMS=--ipv6
=INPUT=
[[topo]]
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
=WARNING=
Warning: Missing attribute 'policy_distribution_point' for 1 devices:
 - router:asa1
=END=
=OPTIONS=--check_policy_distribution_point=warn

############################################################
=TITLE=Overlapping areas
=PARAMS=--ipv6
=INPUT=
[[topo]]
network:n4 = { ip = ::a01:400/120; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:203; hardware = n2; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
area:a2 = { border = interface:asa1.n2; }
area:a2x = { border = interface:asa2.n2; }
=ERROR=
Error: Overlapping area:a2 and area:a2x
 - both areas contain any:[network:n2],
 - only 1. area contains any:[network:n3],
 - only 2. area contains any:[network:n1]
=END=

############################################################
=TITLE=Duplicate areas
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = { border = interface:asa1.n1; }
area:a2 = { border = interface:asa2.n2; }
area:a2x = { border = interface:asa2.n2; }
=ERROR=
Error: Duplicate area:a2 and area:a2x
=END=

############################################################
=TITLE=Distinct areas, only router is different
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a2 = { border = interface:asa1.n2; }
area:a2r = { inclusive_border = interface:asa1.n1; }
=WARNING=NONE

############################################################
# Changed $topo

############################################################
=TEMPL=topo
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:30a; } }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:asa2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n5 = { ip = ::a01:502; hardware = n5; }
}
=END=

############################################################
=TITLE=Overlapping areas at router
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {
 inclusive_border = interface:asa1.n1;
}
area:a2 = {
 inclusive_border = interface:asa1.n2, interface:asa1.n3;
}
=ERROR=
Error: Overlapping area:a2 and area:a1
 - both areas contain router:asa1,
 - only 1. area contains any:[network:n1],
 - only 2. area contains any:[network:n2]
=END=

############################################################
=TITLE=Missing router in overlapping areas
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {
 inclusive_border = interface:asa1.n1, interface:asa2.n5;
}
area:a2 = {
 border = interface:asa1.n2, interface:asa1.n3;
}
=ERROR=
Error: Overlapping area:a1 and area:a2
 - both areas contain any:[network:n2],
 - only 1. area contains router:asa1,
 - only 2. area contains any:[network:n5]
=END=

############################################################
=TITLE=Overlap at area that has been processed before
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = { border = interface:asa1.n1; }
area:a12 = { border = interface:asa2.n2; inclusive_border = interface:asa1.n3; }
area:a123 = { border = interface:asa2.n2, interface:asa2.n3; }
area:a245 = { border = interface:asa1.n2; inclusive_border = interface:asa2.n3; }
=ERROR=
Error: Overlapping area:a123 and area:a245
 - both areas contain any:[network:n2],
 - only 1. area contains any:[network:n1],
 - only 2. area contains any:[network:n4]
=END=

############################################################
=TITLE=Empty area
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {
 inclusive_border = interface:asa1.n1, interface:asa1.n2, interface:asa1.n3;
}
=WARNING=
Warning: area:a1 is empty
=END=

############################################################
=TITLE=Inconsistent definition of area in loop
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {
 border = interface:asa2.n2;
 inclusive_border = interface:asa1.n2;
}
area:a2 = {
 border = interface:asa2.n2;
}
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
=PARAMS=--ipv6
=INPUT=
[[topo]]
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
=OUTPUT=
-- ipv6/asa1
! n2_in
object-group network v6g0
 network-object ::a01:200/119
 network-object ::a01:400/120
access-list n2_in extended permit tcp object-group v6g0 ::a01:100/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp object-group v6g0 ::a01:100/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Router attributes from inclusive area
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {
 inclusive_border = interface:asa1.n2, interface:asa1.n3;
 router_attributes = { general_permit = icmpv6; }
}
=OUTPUT=
-- ipv6/asa1
! n1_in
access-list n1_in extended permit icmp6 any6 any6
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
-- ipv6/asa2
! n2_in
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Unreachable border
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {border = interface:asa1.n1,
                    interface:asa2.n2;}
=ERROR=
Error: Unreachable border of area:a1:
 - interface:asa2.n2
=END=

############################################################
=TITLE=Must not use area directly in rule
=PARAMS=--ipv6
=INPUT=
[[topo]]
area:a1 = {border = interface:asa1.n1;}
service:s1 = { user = area:a1; permit src = user; dst = network:n2; prt = tcp; }
=WARNING=
Warning: Ignoring area:a1 in src of rule in service:s1
=END=

############################################################
=TITLE=Check for useless inheritance of policy_distribution_point
=PARAMS=--ipv6
=INPUT=
area:all = {
 anchor = network:n;
 router_attributes = { policy_distribution_point = host:h; }
}
network:n = { ip = ::a01:100/120; host:h = { ip = ::a01:16f; } }
router:r = {
 managed;
 model = NX-OS;
  policy_distribution_point = host:h;
 interface:n = { ip = ::a01:102; hardware = e1; }
}
=WARNING=
Warning: Useless attribute 'policy_distribution_point' at router:r,
 it was already inherited from router_attributes of area:all
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r
=END=

############################################################
=TITLE=Must not use unconnected network as anchor
=PARAMS=--ipv6
=INPUT=
router:r = {managed; model = IOS; interface:n1 = { ip = ::a0a:a02; hardware = port1; }}
network:n1 = { ip = ::a0a:a00/120; }
network:n2 = { ip = ::a0b:b00/120; }

area:a1 = {
 anchor = network:n2;
}
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n2]
 Use partition attribute, if intended.
=END=


############################################################