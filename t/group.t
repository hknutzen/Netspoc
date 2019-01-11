#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Group;
use Test_Netspoc;

my ($title, $in, $out, $topo, $groups);

############################################################
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24;
 host:h3a = { range = 10.1.3.10-10.1.3.15; }
 host:h3b = { ip = 10.1.3.26; }
 host:h3m = { managed; model = Linux; ip = 10.1.3.33; hardware = eth0; }
}
network:n3sub = { ip = 10.1.3.64/27; subnet_of = network:n3;
 host:h3c = { ip = 10.1.3.66; }
 host:h3d = { range = 10.1.3.65 - 10.1.3.67; }
 host:h3m2 = { managed; model = Linux; ip = 10.1.3.73; hardware = eth0; }
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
END

############################################################
$title = 'Find unused hosts';
############################################################

$in = $topo . <<'END';
service:s = {
 user = host:h3a, host:h3c;
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

$out = <<'END';
10.1.1.10	host:h1
10.1.3.26	host:h3b
10.1.3.33	host:h3m
10.1.3.65-10.1.3.67	host:h3d
10.1.3.73	host:h3m2
END

test_group($title, $in, 'host:[network:n1, network:n3]', $out, '-unused');

############################################################
$title = 'Automatic hosts';
############################################################

$in = $topo;

$out = <<'END';
10.1.1.10	host:h1
10.1.3.10-10.1.3.15	host:h3a
10.1.3.73	host:h3m2
END

test_group($title, $in, 'host:[network:n1, host:h3a, host:h3m2]', $out);

############################################################
$title = 'Redundant from automatic hosts';
############################################################

$in = $topo . <<'END';
service:s = {
 user = host:[network:n3sub];
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:s compared to service:s:
  permit src=network:n1; dst=host:h3c; prt=tcp 80; of service:s
< permit src=network:n1; dst=host:h3d; prt=tcp 80; of service:s
END

test_warn($title, $in, $out);

############################################################
$title = 'Automatic network with subnets';
############################################################

$in = $topo;

$out = <<'END';
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
END

test_group($title, $in, 'network:[network:n3]', $out);

############################################################
$title = 'Automatic network with subnets from any';
############################################################

$in = $topo;

$out = <<'END';
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
END

test_group($title, $in, 'network:[any:[network:n3sub]]', $out);

############################################################
$title = 'No subnets in automatic network in rule';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = network:[any:[network:n3sub]];
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
-- r2
! n3_in
access-list n3_in extended permit tcp 10.1.3.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
END

test_run($title, $in, $out);

############################################################
$title = 'Unexpected interface in automatic host';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = host:[interface:r1.n1];
permit src = user; dst = network:n1; prt = ip;
}
END

$out = <<'END';
Error: Unexpected interface in host:[..] of user of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'Toplevel group with more than 8 elements';
############################################################

$in = $topo . <<'END';
group:g1 =
 network:n1,
 network:n2,
 network:n3,
 host:h3a,
 host:h3b,
 host:h3m,
 host:h3c,
 host:h3d,
 host:h3m2,
;
END

$out = <<'END';
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
10.1.3.0/24	network:n3
10.1.3.10-10.1.3.15	host:h3a
10.1.3.26	host:h3b
10.1.3.33	host:h3m
10.1.3.65-10.1.3.67	host:h3d
10.1.3.66	host:h3c
10.1.3.73	host:h3m2
END

test_group($title, $in, 'group:g1', $out);

############################################################
$title = 'Intersection';
############################################################

$in = $topo . <<'END';
group:g1 = network:n1, network:n2;
group:g2 = network:n2, network:n3;
END

$out = <<'END';
10.1.2.0/24	network:n2
END

test_group($title, $in, 'group:g1 & group:g2', $out);

############################################################
$title = 'Intersection with complement';
############################################################

$in = $topo . <<'END';
group:g1 = network:n1, network:n2;
END

$out = <<'END';
10.1.1.0/24	network:n1
END

test_group($title, $in, 'group:g1 &! network:n2', $out);

############################################################
$title = 'Multiple intersection with complement';
############################################################

$in = $topo . <<'END';
group:g1 = host:h1, network:n2, network:n3;
END

$out = <<'END';
10.1.2.0/24	network:n2
END

test_group($title, $in, 'group:g1 &! network:n3 &! host:h1', $out);

############################################################
$title = 'Intersection of complement';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = ! network:n1 & ! network:n2;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Error: Intersection needs at least one element which is not complement in user of service:s1
Warning: Useless delete of network:n1 in user of service:s1
Warning: Useless delete of network:n2 in user of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'Complement without intersection';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = ! network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Error: Complement (!) is only supported as part of intersection in user of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'Umlaut in group name';
############################################################

$in = $topo . <<'END';
group:Über = network:n1;
END

$out = <<'END';
10.1.1.0/24	network:n1
END

test_group($title, $in, 'group:Über', $out);

############################################################
$title = 'Find unused network that is referenced in argument';
############################################################

$in = $topo;

$out = <<'END';
10.1.1.0/24	network:n1
END

test_group($title, $in, 'network:[any:[network:n1]]', $out, '-unused');

############################################################
$title = 'Print multiple groups at once';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:über = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:über = { ip = 10.1.3.1; hardware = n3; }
}

group:g1 = network:n1, network:n2;
group:g2 = network:n2, network:über;
group:g3 = network:n1, network:n2, network:über;
END

$groups = <<'END';
group:g1
group:g2
interface:r1.[all]
group:g3
group:g1, network:über
END

$out = <<'END';
# group:g1
network:n1
network:n2
# group:g2
network:n2
network:über
# interface:r1.[all]
interface:r1.n1
interface:r1.n2
interface:r1.über
# group:g3
network:n1
network:n2
network:über
# group:g1, network:über
network:n1
network:n2
network:über
END

test_group($title, $in, $groups, $out, '-name');

############################################################
$title = 'Unused elements of multiple groups';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24;
 host:h3a = { range = 10.1.3.10-10.1.3.15; }
 host:h3b = { ip = 10.1.3.26; }
 host:h3m = { managed; model = Linux; ip = 10.1.3.33; hardware = eth0; }
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
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

service:s = {
 user = host:h3a;
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

$groups = <<'END';
network:n1, network:n2, network:n3
host:[network:n1]
host:[network:n3]
END

$out = <<'END';
# network:n1, network:n2, network:n3
network:n2
# host:[network:n1]
host:h1
# host:[network:n3]
host:h3b
host:h3m
END

test_group($title, $in, $groups, $out, '-name -unused');

############################################################
$title = 'NAT, negotiated, unnumbered, short, auto';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/28; dynamic; }
 host:h1s = { ip = 10.1.1.10; nat:t1 = { ip = 10.9.1.10; } }
 host:h1d = { ip = 10.1.1.11; }
}

network:n2 = {
 ip = 10.1.2.0/24;
 nat:t1 = { ip = 10.9.2.0/24; }
 host:h2 = { ip = 10.1.2.10; }
}

network:n3 = {
 ip = 10.1.3.0/24;
 nat:t1 = { hidden; }
 host:h3 = { ip = 10.1.3.10; }
}

router:r1 =  {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; nat:t1 = { ip = 10.9.1.1; } hardware = n1; }
 interface:n2 = { negotiated; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t1 = { unnumbered; hardware = t; bind_nat = t1; }
}
network:t1 = { unnumbered; }

router:r2 = {
 interface:t1;
 interface:k1;
}

network:k1 = { ip = 10.2.2.0/24; }
END

$groups = <<'END';
network:n1
host:h1s, host:h1d
network:n2
host:h2
network:n3
host:h3
network:t1
interface:r1.[all]
interface:r1.[auto]
interface:r1.t1
interface:r2.[all]
END

$out = <<'END';
# network:n1
10.9.1.0/28	network:n1
# host:h1s, host:h1d
10.9.1.0/28	host:h1d
10.9.1.10	host:h1s
# network:n2
10.9.2.0/24	network:n2
# host:h2
10.9.2.10	host:h2
# network:n3
hidden	network:n3
# host:h3
hidden	host:h3
# network:t1
unnumbered	network:t1
# interface:r1.[all]
10.9.1.1	interface:r1.n1
10.9.2.0/24	interface:r1.n2
hidden	interface:r1.n3
# interface:r1.[auto]
unknown	interface:r1.[auto]
# interface:r1.t1
unnumbered	interface:r1.t1
# interface:r2.[all]
short	interface:r2.t1
short	interface:r2.k1
END

test_group($title, $in, $groups, $out, '-nat k1');

############################################################
$title = 'Show owner';
############################################################

$in = <<'END';
owner:o = { admins = o@b.c; }
network:n1 = { ip = 10.1.1.0/24; owner = o; }
router:r = {
 interface:n1;
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
10.1.1.0/24	network:n1	owner:o
10.1.2.0/24	network:n2	none
END

test_group($title, $in, 'network:n1, network:n2', $out, '-owner');

############################################################
$title = 'Mark group in empty rule as used';
############################################################
# Don't show warning "unused group:g2
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = ;
group:g2 = network:n;

service:s1 = {
 user = group:g1;
 permit src = user; dst = group:g2; prt = tcp 22;
}
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Mark group in disabled rule as used';
############################################################
# Don't show warning "unused group:g2
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = ;
group:g2 = network:n;

service:s1 = {
 disabled;
 user = group:g2;
 permit src = user; dst = group:g2; prt = tcp 22;
}
END

$out = <<'END';
Warning: unused group:g1
END

test_warn($title, $in, $out);

############################################################
$title = 'Recursive definition of group';
############################################################
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = group:g2;
group:g2 = network:n, group:g1;

service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 22;
}

END

$out = <<'END';
Error: Found recursion in definition of group:g2
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected type in group';
############################################################
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = foo:bar;

service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 22;
}

END

$out = <<'END';
Error: Can't resolve foo:bar in group:g1
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected type of automatic group';
############################################################
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = area:[network:n], foo:[network:n];

service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 22;
}

END

$out = <<'END';
Error: Unexpected area:[..] in group:g1
Error: Unexpected foo:[..] in group:g1
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate elements in group';
############################################################

$in = <<'END';
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

END

$out = <<'END';
Warning: Duplicate elements in group:g1:
 - network:n2
 - network:n1
 - network:n2
END

test_warn($title, $in, $out);

############################################################
$title = 'Silently ignore duplicate elements from automatic interfaces';
############################################################

$in = <<'END';
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
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Empty intersection';
############################################################

$in = <<'END';
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
END

$out = <<'END';
Warning: Empty intersection in group:g1:
  interface:r1.[all]
&!interface:r1.n2
&!interface:r1.n3
Warning: Empty intersection in group:g1:
  network:[..]
&!network:n1
&!network:n2
Warning: Empty intersection in group:g1:
 !any:[..]
& any:[..]
Warning: Empty intersection in user of service:s1:
 !group:g1
& group:g1
Warning: Empty intersection in dst of rule in service:s1:
  host:[..]
&!host:h1
&!host:h2
Warning: Must not define service:s1 with empty users and empty rules
END

test_warn($title, $in, $out);

############################################################
$title = 'Do not print full length prefixes';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/32; }
network:n4 = { ip = 10.1.4.0/32; }
network:n5 = { ip = 10.1.5.0/32;
 nat:nat1 = { ip = 10.7.7.0/32; dynamic; }
}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = nat1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 }

router:r2 = {
 interface:n2 = { ip = 10.1.2.2; hardware = n1; }
 interface:n3 = { negotiated; hardware = n2; }
 interface:n4;
 interface:n5;
}

group:g1 = network:n4, interface:r2.n3, interface:r2.n5;
END

$out = <<'END';
10.1.3.0	interface:r2.n3
10.1.4.0	network:n4
10.7.7.0	interface:r2.n5
END

test_group($title, $in, 'group:g1', $out, '-nat n1');

############################################################
$title = 'Must not ignore aggregate with only loopback network';
############################################################

$in = <<'END';
area:n2-lo = { border = interface:r1.n2; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { unnumbered; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { unnumbered; hardware = n2; }
 }

router:r2 = {
 interface:n2;
 interface:lo = { ip = 10.1.3.1; loopback; }
}
END

$out = <<'END';
0.0.0.0/0	any:[network:n2]
END

test_group($title, $in, 'any:[area:n2-lo]', $out);

############################################################
done_testing;
