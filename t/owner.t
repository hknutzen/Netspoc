#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Unused owners';
############################################################

$in = <<'END';
owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2@b.c; }
owner:a1 = { admins = a1@b.c; }

network:n1 = { ip = 10.1.1.0/24; owner = o2; }
router:r1 = {
 interface:n1;
}
END

$out = <<'END';
Warning: Unused owner:a1
Warning: Unused owner:o1
END

test_warn($title, $in, $out);

############################################################
$title = 'Error on unused owners';
############################################################

$out = <<'END';
Error: Unused owner:a1
Error: Unused owner:o1
END

test_err($title, $in, $out, '--check_unused_owners=1');

############################################################
$title = 'Duplicates in admins/watchers';
############################################################

$in = <<'END';
owner:x = {
 admins = a@b.c, b@b.c, a@b.c;
 watchers = b@b.c, c@b.c, b@b.c;
}
owner:y = {
 admins = a@b.c;
 watchers = b@b.c;
}
END

$out = <<'END';
Error: Duplicates in admins of owner:x: a@b.c
Error: Duplicates in watchers of owner:x: b@b.c
Error: Duplicates in admins/watchers of owner:x: b@b.c
Error: topology seems to be empty
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

$out = <<'END';
Warning: Useless owner:x at area:a3,
 it was already inherited from area:a2
Warning: Useless owner:x at area:a1,
 it was already inherited from area:all
Warning: Useless owner:x at area:a2,
 it was already inherited from area:all
END

test_warn($title, $in, $out);

############################################################
$title = 'Owner at vip interface';
############################################################

$in = <<'END';
owner:x = { admins = x@a.b; }
owner:y = { admins = y@a.b; }

network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }
router:R = {
 interface:n2 = { ip = 10.1.2.2; owner = x; }
 interface:V = { ip = 10.3.3.3; vip; owner = y; }
}

service:test = {
    user = network:n1;
    permit src = user; dst = interface:R.V, interface:R.n2; prt = tcp 80;
}
END

$out = <<'END';
Warning: service:test has multiple owners:
 x, y
END

test_warn($title, $in, $out);

############################################################
$title = 'Owner at interface of managed router';
############################################################

$in = <<'END';
owner:y = { admins = y@a.b; }

network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; owner = y; }
 interface:V = { ip = 10.3.3.3; loopback; hardware = lo1; owner = y; }
}

END

$out = <<'END';
Warning: Ignoring attribute 'owner' at managed interface:r1.n1
Warning: Ignoring attribute 'owner' at managed interface:r1.V
Warning: Unused owner:y
END

test_warn($title, $in, $out);

############################################################
$title = 'vip interface at managed router';
############################################################

$in = <<'END';
owner:y = { admins = y@a.b; }

network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = e0; }
 interface:V  = { ip = 10.3.3.3; hardware = lo; vip; }
}

END

$out = <<'END';
Error: Must not use attribute 'vip' at managed router:r1
END

test_err($title, $in, $out);

############################################################
$title = 'Owner with only watchers';
############################################################

$in = <<'END';
owner:x = { watchers = x@a.b; }
owner:y = { watchers = y@a.b; }
area:all = { owner = x; anchor = network:n1; }
network:n1 = { owner = y; ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Missing attribute 'admins' in owner:y of network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Wildcard address not valid as admin';
############################################################

$in = <<'END';
owner:o1 = { admins = [all]@example.com; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
END

$out = <<'END';
Error: Invalid email address (ASCII only) in admins of owner:o1: [all]@example.com
END

test_err($title, $in, $out);

############################################################
$title = 'Owner with attribute only_watch only usable at area';
############################################################

$in = <<'END';
owner:x = { admins = a@a.b; watchers = x@a.b; only_watch; }
owner:y = { admins = b@a.b; watchers = y@a.b; only_watch; }
owner:z = { watchers = z@a.b; only_watch; }
any:a1 = { owner = x; link = network:n1; }
network:n1 = {
 owner = y; ip = 10.1.1.0/24;
 host:h1 = { owner = z; ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: owner:y with attribute 'only_watch' must only be used at area,
 not at network:n1
Error: Missing attribute 'admins' in owner:z of host:h1
Error: owner:z with attribute 'only_watch' must only be used at area,
 not at host:h1
Error: owner:x with attribute 'only_watch' must only be used at area,
 not at any:a1
END

test_err($title, $in, $out);

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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
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
$title = 'Owner with "show_all" must also own VPN transfer area';
############################################################

$in = <<'END';
isakmp:ikeaes256SHA = {
 identity = address;
 authentication = preshare;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
ipsec:ipsecaes256SHA = {
 key_exchange = isakmp:ikeaes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
 pfs_group = 2;
 lifetime = 3600 sec;
}
crypto:vpn = { type = ipsec:ipsecaes256SHA; }

owner:all = { admins = a@example.com; show_all; }
area:all = { anchor = network:n1; owner = all; }

network:n1 = { ip = 10.1.1.0/24;}

router:r = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = inside; }
 interface:n2 = { ip = 192.168.1.2; hardware = outside; hub = crypto:vpn; }
}

network:n2 = { ip = 192.168.1.0/28;}

router:dmz = {
 interface:n2 = { ip = 192.168.1.1; }
 interface:Internet;
}

network:Internet = { ip = 0.0.0.0/0; has_subnets; }

router:VPN1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:Internet = { ip = 1.1.1.1; spoke = crypto:vpn; hardware = Internet; }
 interface:v1 = { ip = 10.9.1.1; hardware = v1; }
}
network:v1 = { ip = 10.9.1.0/24; }
END

$out = <<"END";
Error: owner:all has attribute \'show_all\', but doesn\'t own whole topology.
 Missing:
 - any:[network:n2]
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid owner in area and router_attributes of area';
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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
END

$out = <<'END';
Error: Can't resolve reference to 'xx' in attribute 'owner' of area:a1
Error: Can't resolve reference to 'xx' in attribute 'owner' of router_attributes of area:a1
END

test_err($title, $in, $out);

############################################################
$title = 'Inherit owner from router_attributes of area';
############################################################

$in = <<'END';
area:all = {
 anchor = network:n1;
 router_attributes = { owner = o1; }
}
area:a2 = {
 border = interface:r1.n2;
 router_attributes = { owner = o2; }
}

owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2@b.c; }

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 owner = o1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 owner = o2;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
END

$out = <<'END';
Warning: Useless owner:o2 at router:r2,
 it was already inherited from router_attributes of area:a2
Warning: Useless owner:o1 at router:r1,
 it was already inherited from router_attributes of area:all
END

test_warn($title, $in, $out);

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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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

test_warn($title, $in, $out, '--check_service_unknown_owner=warn');

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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
$title = 'multi_owner with mixed coupling rules';
############################################################

$in = <<'END';
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip = 10.1.1.0/24; owner = o3; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = {
 ip = 10.1.2.0/24;
 host:h1 = { ip = 10.1.2.10; owner = o1; }
 host:h2 = { ip = 10.1.2.11; owner = o2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = user; prt = tcp 80;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
}
END

$out = <<'END';
Warning: service:s1 has multiple owners:
 o1, o2, o3
END

test_warn($title, $in, $out);

############################################################
done_testing;
