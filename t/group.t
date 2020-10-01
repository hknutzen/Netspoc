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
10.1.3.65-10.1.3.67	host:h3d
END

test_group($title, $in, 'host:[network:n1, network:n3]', $out, '--unused');

############################################################
$title = 'Automatic hosts';
############################################################

$in = $topo;

$out = <<'END';
10.1.1.10	host:h1
10.1.3.10-10.1.3.15	host:h3a
END

test_group($title, $in, 'host:[network:n1, host:h3a]', $out);

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
$title = 'Automatic network with subnets from group';
############################################################

$in = $topo . <<'END';
group:g1 = network:[network:n3];
END

$out = <<'END';
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
END

test_group($title, $in, 'group:g1', $out);

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
$title = 'Automatic hosts together with automatic network with subnets';
############################################################

$in = $topo;

$out = <<'END';
10.1.1.10	host:h1
10.1.3.0/24	network:n3
10.1.3.64/27	network:n3sub
END

test_group($title, $in, 'host:[network:n1],network:[network:n3]', $out);

############################################################
$title = 'Automatic hosts in rule';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = host:[network:n3] &!host:h3c;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
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
END

test_run($title, $in, $out);

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
Error: Unexpected 'interface:r1.n1' in host:[..] of user of service:s1
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
 host:h3c,
 host:h3d,
;
END

$out = <<'END';
10.1.1.0/24	network:n1
10.1.2.0/24	network:n2
10.1.3.0/24	network:n3
10.1.3.10-10.1.3.15	host:h3a
10.1.3.26	host:h3b
10.1.3.66	host:h3c
10.1.3.65-10.1.3.67	host:h3d
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

test_group($title, $in, 'network:[any:[network:n1]]', $out, '-u');

### Topology for multiple tests.
$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/28; dynamic; }
 host:h1s = { ip = 10.1.1.10; nat:t1 = { ip = 10.9.1.10; } }
 host:h1d = { ip = 10.1.1.11; }
}

network:n2 = {
 ip = 10.1.2.0/24;
 nat:t2 = { ip = 10.9.2.0/24; }
 host:h2 = { ip = 10.1.2.10; }
}

network:n3 = {
 ip = 10.1.3.0/24;
 nat:t3 = { hidden; }
 host:h3 = { ip = 10.1.3.10; }
}

router:r1 =  {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; nat:t1 = { ip = 10.9.1.1; } hardware = n1; }
 interface:n2 = { negotiated; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t1 = { unnumbered; hardware = t; bind_nat = t1, t2, t3; }
}
network:t1 = { unnumbered; }

router:r2 = {
 interface:t1;
 interface:k1;
}

network:k1 = { ip = 10.2.2.0/24; }
END


############################################################
$title = 'Dynamic NAT for network and static NAT for host';
############################################################

$out = <<'END';
10.9.1.0/28	network:n1
10.9.1.10	host:h1s
10.9.1.0/28	host:h1d
END
test_group($title, $in, 'network:n1, host:h1s, host:h1d', $out, '--nat k1');

############################################################
$title = 'Static NAT for network and host';
############################################################

$out = <<'END';
10.9.2.0/24	network:n2
10.9.2.10	host:h2
END
test_group($title, $in, 'network:n2,host:h2', $out, '--nat k1');

############################################################
$title = 'Hidden NAT for network and host';
############################################################

$out = <<'END';
hidden	network:n3
hidden	host:h3
END
test_group($title, $in, 'network:n3,host:h3', $out, '--nat k1');

############################################################
$title = 'Unnumbered network';
############################################################

$out = <<'END';
unnumbered	network:t1
END
test_group($title, $in, 'network:t1', $out, '--nat k1');

############################################################
$title = 'Show unnumbered from [all], show [auto] interface';
############################################################

$out = <<'END';
10.9.1.1	interface:r1.n1
10.9.2.0/24	interface:r1.n2
hidden	interface:r1.n3
unnumbered	interface:r1.t1
unknown	interface:r1.[auto]
END
test_group($title, $in,
           'interface:r1.[all],interface:r1.[auto]',
           $out, '--nat k1');

############################################################
$title = 'Short interface';
############################################################

$out = <<'END';
short	interface:r2.t1
short	interface:r2.k1
END
test_group($title, $in, 'interface:r2.[all]', $out);


############################################################
$title = 'Empty group';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
 group:g1 = ;
END

$out = <<'END';
END

test_group($title, $in, 'group:g1', $out);

############################################################
$title = 'Show bridged interface';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}

network:n1/right = { ip = 10.1.1.0/24; }

router:r = {
 interface:n1/right = { ip = 10.1.1.2; }
}
END

$out = <<'END';
bridged	interface:bridge.n1/right
10.1.1.2	interface:r.n1/right
END

test_group($title, $in, 'interface:[network:n1/right].[all]', $out);

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

test_group($title, $in, 'network:n1, network:n2', $out, '--owner');

############################################################
$title = 'Show owner and only name';
############################################################

$out = <<'END';
network:n1	owner:o
network:n2	none
END

test_group($title, $in, 'network:[any:[network:n1]]', $out, '-n -o');

############################################################
$title = 'Show only name';
############################################################

$out = <<'END';
network:n1
network:n2
END

test_group($title, $in, 'network:[any:[network:n1]]', $out, '--name');

############################################################
$title = 'Show only ip';
############################################################

$out = <<'END';
10.1.1.0/24
10.1.2.0/24
END

test_group($title, $in, 'network:[any:[network:n1]]', $out, '--ip');

############################################################
$title = 'Show owner and admins';
############################################################

$in = <<'END';
owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2a@d.e.f, o2b@g.h.i; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
network:n2 = { ip = 10.1.2.0/24; owner = o2; }
network:n3 = { ip = 10.1.3.0/24; owner = o1; }
network:n3a = { ip = 10.1.3.0/25; subnet_of = network:n3; }
router:r = {
 interface:n1;
 interface:n2;
 interface:n3;
 interface:n3a;
}
END

$out = <<'END';
network:n1	owner:o1	o1@b.c
network:n2	owner:o2	o2a@d.e.f,o2b@g.h.i
network:n3a	owner:o1	o1@b.c
END

test_group($title, $in, 'network:n1, network:n2, network:n3a', $out,
           '--name --owner --admins');

############################################################
$title = 'Show only name and admins';
############################################################

$out = <<'END';
network:n1	o1@b.c
network:n2	o2a@d.e.f,o2b@g.h.i
network:n3a	o1@b.c
END

test_group($title, $in, 'network:n1, network:n2, network:n3a', $out,
           '--name -a');

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
$title = 'Can\'t resolve object in group';
############################################################
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = host:h1;

service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 80;
}
END

$out = <<'END';
Error: Can't resolve host:h1 in group:g1
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
Syntax error: Unknown element type at line 3 of STDIN, near "group:g1 = --HERE-->foo:bar"
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
Syntax error: Unexpected automatic group at line 3 of STDIN, near "group:g1 = --HERE-->area:[network:n]"
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
10.1.4.0	network:n4
10.1.3.0	interface:r2.n3
10.7.7.0	interface:r2.n5
END

test_group($title, $in, 'group:g1', $out, '--nat n1');

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
$title = 'Unexpected content after ";"';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Unexpected content after ";" at line 1 of command line, near "network:n1; --HERE-->INVALID"
END

test_group_err($title, $in, 'network:n1; INVALID', $out);

############################################################
$title = 'Object group together with adjacent IP addresses';
############################################################

$in = <<'END';
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
END

$out = <<'END';
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
END

test_run($title, $in, $out);

############################################################
done_testing;
