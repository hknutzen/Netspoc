#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Duplicates from other owner';
############################################################

$in = <<'END';
owner:x = {
 admins = a@b.c;
 watchers = owner:y, b@b.c;
}
owner:y = {
 admins = a@b.c;
 watchers = b@b.c;
}
END

$out = <<'END';
Error: Duplicates in watchers of owner:x: b@b.c
Error: Duplicates in admins/watchers of owner:x: a@b.c
Error: Topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Unknown owner referenced in watchers';
############################################################

$in = <<'END';
owner:x = {
 admins = a@b.c;
 watchers = owner:y;
}
END

$out = <<'END';
Error: Unknown owner:y referenced in watcher of owner:x
Error: Topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Recursive definition of watchers';
############################################################

$in = <<'END';
owner:x = {
 admins = a@b.c;
 watchers = owner:y;
}

owner:y = {
 admins = b@b.c;
 watchers = owner:x;
}
END

$out = <<'END';
Error: Found recursive definition of watchers in owner:x
Error: Topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Check for owners with duplicate alias names';
############################################################

$in = <<'END';
owner:xx = {
 alias = X Quadrat;
 admins = a@b.c;
}

owner:x2 = {
 alias = X Quadrat;
 admins = a@b.c;
}
END

$out = <<'END';
Error: Name conflict between owners
 - owner:xx with alias 'X Quadrat'
 - owner:x2 with alias 'X Quadrat'
Error: Topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Check for owners with conflicting name and alias name';
############################################################

$in = <<'END';
owner:yy = {
 alias = z;
 admins = a@b.c;
}

owner:z = {
 admins = a@b.c;
}
END

$out = <<'END';
Error: Name conflict between owners
 - owner:z
 - owner:yy with alias 'z'
Error: Topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Owner at bridged network';
############################################################

$in = <<'END';
owner:xx = {
 admins = a@b.c;
}

area:all = { owner = xx; anchor = network:VLAN_40_41/40; }

network:VLAN_40_41/40 = { ip = 10.2.1.96/28; }

router:asa = {
 managed;
 model = ASA;

 interface:VLAN_40_41/40 = { hardware = outside; }
 interface:VLAN_40_41/41 = { hardware = inside; }
 interface:VLAN_40_41 = { ip = 10.2.1.99; hardware = device; }
}

network:VLAN_40_41/41 = { ip = 10.2.1.96/28; }

service:test = {
 user = network:VLAN_40_41/40;
 permit src = user; 
        dst = interface:asa.VLAN_40_41; 
        prt = ip;
}
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Redundant owner at bridged network';
############################################################

$in =~ s|(network:VLAN_40_41/41 = \{)|$1 owner = xx; |;

$out = <<'END';
Warning: Useless owner:xx at any:[network:VLAN_40_41/41],
 it was already inherited from area:all
END

test_warn($title, $in, $out);

############################################################
$title = 'Redundant owner at nested areas';
############################################################

$in = <<'END';
owner:x = {
 admins = a@b.c;
}

# a3 < a2 < all, a1 < all
area:all = { owner = x; anchor = network:n1; }
area:a1 = { owner = x; border = interface:asa1.n1; }
area:a2 = { owner = x; border = interface:asa1.n2; }
area:a3 = { owner = x; border = interface:asa2.n3; }

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; }
}
END

$out = <<'END';
Warning: Useless owner:x at area:a1,
 it was already inherited from area:all
Warning: Useless owner:x at area:a2,
 it was already inherited from area:all
Warning: Useless owner:x at area:a3,
 it was already inherited from area:a2
END

test_warn($title, $in, $out);

############################################################
$title = 'Owner at vip interface';
############################################################

$in = <<'END';
owner:x = { admins = x@a.b; }
owner:y = { admins = y@a.b; }

network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = ACE;
 owner = x;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:V = { ip = 10.3.3.3; vip; owner = y; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; dst = interface:R.V, interface:R.U; prt = tcp 80;
}
END

$out = <<'END';
Warning: service:test has multiple owners:
 x, y
END

test_warn($title, $in, $out);

############################################################
$title = 'Owner at invalid vip interface';
############################################################

# Must not access unprocessed owner.

$in = <<'END';
owner:y = { admins = y@a.b; }

network:U = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:V = { ip = 10.3.3.3; vip; owner = y; }
}
router:r2 = {
 interface:U;
 interface:V = { ip = 10.3.3.4; vip; owner = y; }
}

END

$out = <<'END';
Error: Must not use attribute 'vip' at router:r1
 'vip' is only allowed for model ACE
Error: Must not use attribute 'vip' at router:r2
 'vip' is only allowed for model ACE
Warning: Unused owner:y
END

test_err($title, $in, $out);

############################################################
$title = 'Owner with only watchers';
############################################################

$in = <<'END';
owner:x = { watchers = x@a.b; extend_only; }
owner:y = { watchers = y@a.b; }
area:all = { owner = x; anchor = network:n1; }
network:n1 = { owner = y; ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Missing attribute 'admins' in owner:y of network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Owner with extend_only only usable at area';
############################################################

$in = <<'END';
owner:x = { admins = a@a.b; watchers = x@a.b; extend_only; }
owner:y = { admins = b@a.b; watchers = y@a.b; extend_only; }
owner:z = { watchers = z@a.b; extend_only; }
any:a1 = { owner = x; link = network:n1; }
network:n1 = { 
 owner = y; ip = 10.1.1.0/24; 
 host:h1 = { owner = z; ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: owner:y with attribute 'extend_only' must only be used at area,
 not at network:n1
Error: Missing attribute 'admins' in owner:z of host:h1
Error: owner:z with attribute 'extend_only' must only be used at area,
 not at host:h1
Error: owner:x with attribute 'extend_only' must only be used at area,
 not at any:a1
END

test_err($title, $in, $out);

############################################################
$title = 'Inconsistent extended owners';
############################################################

$in = <<'END';
owner:a1 = { admins = a1@b.c; extend_only; }
owner:a3 = { admins = a3@b.c; extend_only; }
owner:a23 = { admins = a23@b.c; extend_only; }
owner:n1 = { admins = n1@b.c; }
owner:n3 = { admins = n3@b.c; }

area:a1 = { owner = a1; border = interface:asa1.n1; }
area:a3 = { owner = a3; border = interface:asa1.n3; }
area:a23 = { owner = a23; inclusive_border = interface:asa1.n1; }

network:n1 = { ip = 10.1.1.0/24; owner = n1; host:h1 = { ip = 10.1.1.9; owner = n3; } }
network:n2 = { ip = 10.1.2.0/24; owner = n1; }
network:n3 = { ip = 10.1.3.0/24; owner = n3; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.1; hardware = vlan3; }
}

END

$out = <<'END';
Warning: owner:n1 is extended by owner:a1
 - only at network:n1
 - but not at network:n2
Warning: owner:n1 is extended by owner:a23
 - only at network:n2
 - but not at network:n1
Warning: owner:n3 is extended by owner:a1
 - only at host:h1
 - but not at network:n3
Warning: owner:n3 is extended by owner:a3
 - only at network:n3
 - but not at host:h1
Warning: owner:n3 is extended by owner:a23
 - only at network:n3
 - but not at host:h1
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing part in owner with attribute "show_all"';
############################################################

$in = <<'END';
owner:a1 = { admins = a1@b.c; show_all; }

area:a1 = { owner = a1; border = interface:asa1.n1; }

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.1; hardware = vlan3; }
}

END

$out = <<"END";
Error: owner:a1 has attribute \'show_all\', but doesn\'t own whole topology.
 Missing:
 - any:[network:n2]
 - any:[network:n3]
END

test_err($title, $in, $out);

############################################################
$title = 'Inherit owner from router_attributes of area';
############################################################

$in = <<'END';
area:a1 = { 
 border = interface:asa1.n1;
 owner = xx;
 router_attributes = { owner = xx; }
}
network:n1 = { ip = 10.1.1.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
}
END

$out = <<'END';
Error: Can't resolve reference to 'xx' in attribute 'owner' of area:a1
Error: Can't resolve reference to 'xx' in attribute 'owner' of router_attributes of area:a1
END

test_err($title, $in, $out);

############################################################
$title = 'Owner mismatch of overlapping hosts';
############################################################

$in = <<'END';
owner:a1 = { admins = a1@b.c; }
owner:a2 = { admins = a2@b.c; }
owner:a3 = { admins = a3@b.c; }

network:n1 = { ip = 10.1.1.0/24;
 host:h1 = { range = 10.1.1.7-10.1.1.15; owner = a1; }
 host:h2 = { range = 10.1.1.7-10.1.1.16; owner = a2; }
 host:h3 = { ip = 10.1.1.7; owner = a3; }
 host:h4 = { ip = 10.1.1.16; owner = a3; }
 host:h5 = { range = 10.1.1.8-10.1.1.11; owner = a3; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
}
END

$out = <<'END';
Warning: Inconsistent owner definition for host:h1 and host:h2
Warning: Inconsistent owner definition for host:h1 and host:h2
Warning: Inconsistent owner definition for host:h1 and host:h3
Warning: Inconsistent owner definition for host:h2 and host:h4
Warning: Inconsistent owner definition for host:h1 and host:h5
END

test_warn($title, $in, $out);

############################################################
$title = 'Useless sub_owner, multi_owner, unknown_owner';
############################################################

$in = <<'END';
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = 10.1.1.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

network:n2 = { ip = 10.1.2.0/24; owner = o2; }

service:s1 = {
 unknown_owner;
 multi_owner;
 sub_owner = o2;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Warning: Useless owner:o2 at service:s1
Warning: Useless use of attribute 'multi_owner' at service:s1
Warning: Useless use of attribute 'unknown_owner' at service:s1
END

test_warn($title, $in, $out);

############################################################
$title = 'Unknown service owner';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

network:n2 = {
 ip = 10.1.2.0/24;
 host:h1 = { ip = 10.1.2.10; }
 host:h2 = { ip = 10.1.2.11; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = host:h1; prt = tcp 81;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 82;
 permit src = user; dst = host:h1; prt = tcp 83;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 83;
}
END

$out = <<'END';
Warning: Unknown owner for host:h1 in service:s1, service:s2
Warning: Unknown owner for host:h2 in service:s3
Warning: Unknown owner for network:n2 in service:s1, service:s2
END

test_warn($title, $in, $out, '-check_service_unknown_owner=warn');

############################################################
$title = 'Multiple service owners';
############################################################

$in = <<'END';
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = 10.1.1.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

network:n2 = {
 ip = 10.1.2.0/24; 
 host:h1 = { ip = 10.1.2.10; owner = o1; }
 host:h2 = { ip = 10.1.2.11; owner = o2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
END

$out = <<'END';
Warning: service:s1 has multiple owners:
 o1, o2
END

test_warn($title, $in, $out);

############################################################
done_testing;
