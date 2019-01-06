#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;
use Test_Group;

my ($title, $in, $out, $topo);

############################################################
$topo = <<'END';
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
END

############################################################
$title = 'Must not define anchor together with border';
############################################################

$in = $topo . <<'END';
area:a = {
 anchor = network:n1;
 border = interface:asa2.n2;
 inclusive_border = interface:asa2.n3;
}
END

$out = <<'END';
Error: Attribute 'anchor' must not be defined together with 'border' or 'inclusive_border' for area:a
END

test_err($title, $in, $out);

############################################################
$title = 'Must define either anchor or  border';
############################################################

$in = $topo . <<'END';
area:a = {}
END

$out = <<'END';
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a
END

test_err($title, $in, $out);

############################################################
$title = 'Only interface as border';
############################################################

$in = $topo . <<'END';
area:a = { inclusive_border = network:n1; }
END

$out = <<'END';
Error: Must only use interface names in 'inclusive_border' at line 18 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'No automatic interface as border';
############################################################

$in = $topo . <<'END';
area:a = { inclusive_border = interface:r1.[all]; }
area:b = { border = interface:r2.[auto]; }
END

$out = <<'END';
Error: Must only use interface names in 'inclusive_border' at line 18 of STDIN
Error: Must only use interface names in 'border' at line 19 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Unmanaged interface can\'t be border';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = { interface:n1; }
area:a = { border = interface:r1.n1; }
END

$out = <<'END';
Error: Referencing unmanaged interface:r1.n1 from area:a
Warning: area:a is empty
END

test_err($title, $in, $out);

############################################################
$title = 'Policy distribution point from nested areas';
############################################################

$in = $topo . <<'END';
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
END

$out = <<'END';
--asa1
! [ IP = 10.1.1.1 ]
--asa2
! [ IP = 10.1.3.2 ]
END

test_run($title, $in, $out, '--check_policy_distribution_point=warn');

############################################################
$title = 'Missing policy distribution point';
############################################################

$in = $topo . <<'END';
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
END

$out = <<'END';
Warning: Missing attribute 'policy_distribution_point' for 1 devices:
 - router:asa1
END

test_warn($title, $in, $out, '--check_policy_distribution_point=warn');

############################################################
$title = 'Overlapping areas';
############################################################

$in = $topo . <<'END';
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
area:a2 = { border = interface:asa1.n2; }
area:a2x = { border = interface:asa2.n2; }
END

$out = <<'END';
Error: Overlapping area:a2 and area:a2x
 - both areas contain any:[network:n2],
 - only 1. area contains any:[network:n3],
 - only 2. ares contains any:[network:n1]
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate areas';
############################################################

$in = $topo . <<'END';
area:a2 = { border = interface:asa1.n2; }
area:a2x = { border = interface:asa1.n2; }
END

$out = <<'END';
Error: Duplicate area:a2 and area:a2x
END

test_err($title, $in, $out);

############################################################
$title = 'Distinct areas, only router is different';
############################################################

$in = $topo . <<'END';
area:a2 = { border = interface:asa1.n2; }
area:a2r = { inclusive_border = interface:asa1.n1; }
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Area with auto_border';
############################################################

$in = $topo . <<'END';
network:n4 = { ip = 10.1.4.0/24; }

router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

router:asa4 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.3; hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}

area:a1 = { border = interface:asa3.n4;
            inclusive_border = interface:asa2.n2;
}
area:a2 = {anchor = network:n1; auto_border; }
group:g1 = network:[area:a2];
END

$out = <<'END';
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
END

test_group($title, $in, 'group:g1', $out);

############################################################
$title = 'Secondary interface as area border';
############################################################

$in = $topo . <<'END';
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
END

$out = <<'END';
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
10.1.3.0/24	network:n3
END

test_group($title, $in, 'group:g1', $out);

############################################################
$title = 'Secondary interface with name = virtual as border';
############################################################

$in = $topo . <<'END';
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
END

$out = <<'END';
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
10.1.3.0/24	network:n3
END

test_group($title, $in, 'group:g1', $out);

############################################################
$title = 'Virtual interface as border';
############################################################

$in = $topo . <<'END';
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
END

$out = <<'END';
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
10.1.3.0/24	network:n3
END

test_group($title, $in, 'group:g1', $out);

############################################################
# Changed $topo
############################################################
$topo = <<'END';
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
END

############################################################
$title = 'Overlapping areas at router';
############################################################

$in = $topo . <<'END';
area:a1 = {
 inclusive_border = interface:asa1.n1;
}
area:a2 = {
 inclusive_border = interface:asa1.n2, interface:asa1.n3;
}
END

$out = <<'END';
Error: Overlapping area:a2 and area:a1
 - both areas contain router:asa1,
 - only 1. area contains any:[network:n1],
 - only 2. ares contains any:[network:n2]
END

test_err($title, $in, $out);

############################################################
$title = 'Missing router in overlapping areas';
############################################################

$in = $topo . <<'END';
area:a1 = {
 inclusive_border = interface:asa1.n1, interface:asa2.n5;
}
area:a2 = {
 border = interface:asa1.n2, interface:asa1.n3;
}
END

$out = <<'END';
Error: Overlapping area:a1 and area:a2
 - both areas contain any:[network:n2],
 - only 1. area contains router:asa1,
 - only 2. ares contains any:[network:n5]
END

test_err($title, $in, $out);

############################################################
$title = 'Empty area';
############################################################

$in = $topo . <<'END';
area:a1 = {
 inclusive_border = interface:asa1.n1, interface:asa1.n2, interface:asa1.n3;
}
END

$out = <<'END';
Warning: area:a1 is empty
END

test_warn($title, $in, $out);

############################################################
$title = 'Inconsistent definition of area in loop';
############################################################

$in = $topo . <<'END';
area:a1 = {
 border = interface:asa2.n2;
 inclusive_border = interface:asa1.n2;
}
area:a2 = {
 border = interface:asa2.n2;
}
END

$out = <<'END';
Error: Inconsistent definition of area:a1.
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
END

test_err($title, $in, $out);

############################################################
$title = 'ACL from inclusive area';
############################################################

# border and inclusive_border can contact at an interface.

$in = $topo . <<'END';
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
END

$out = <<'END';
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
END

test_run($title, $in, $out);

############################################################
$title = 'Router attributes from inclusive area';
############################################################

$in = $topo . <<'END';
area:a1 = {
 inclusive_border = interface:asa1.n2, interface:asa1.n3;
 router_attributes = { general_permit = icmp; }
}
END

$out = <<'END';
-- asa1
! n1_in
access-list n1_in extended permit icmp any4 any4
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- asa2
! n2_in
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Unreachable border';
############################################################

$in = $topo . <<'END';
area:a1 = {border = interface:asa1.n1,
                    interface:asa2.n2;}
END

$out = <<'END';
Error: Unreachable border of area:a1:
 - interface:asa2.n2
END

test_err($title, $in, $out);

############################################################
$title = 'Must not use area directly in rule';
############################################################

$in = $topo . <<'END';
area:a1 = {border = interface:asa1.n1;}
service:s1 = { user = area:a1; permit src = user; dst = network:n2; prt = tcp; }
END

$out = <<'END';
Warning: Ignoring area:a1 in src of rule in service:s1
END

test_warn($title, $in, $out);

############################################################
$title = 'Ignore area with disabled anchor';
############################################################

$in = <<'END';
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
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
done_testing;
