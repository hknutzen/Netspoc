#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Mixed IPv4 and IPv6';
############################################################

$in = <<'END';
-- ipv4/topo/net
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
-- ipv4/topo/router
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- ipv4/rules
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
-- ipv4/topo/ipv6
network:n3 = { ip = 1000::abcd:0001:0/112;}
network:n4 = { ip = 1000::abcd:0002:0/112;}
-- ipv6/router
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
-- ipv4/ipv6/rules
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'Mixed IPv6 and IPv4';
############################################################

$in =~ s|ipv4/ipv6|ipv6/ipv6|g;
$in =~ s|ipv4/topo/ipv6|topo|g;

test_run($title, $in, $out, '--ipv6');

############################################################
$title = 'IPv6 network is not subnet of 0.0.0.0/0';
############################################################

$in = <<'END';
-- file1
network:n1 = { ip = 10.1.1.0/24; subnet_of = network:Internet; }
network:n2 = { ip = 10.1.2.0/24; subnet_of = network:Internet; }
network:Internet = { ip = 0.0.0.0/0; }

router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:inet = {
 interface:n2;
 interface:Internet;
}
-- ipv6/file2
network:n3 = { ip = 1000::abcd:0001:0/112;}
network:n4 = { ip = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Must not reference IPv4 from IPv6';
############################################################

$in = <<'END';
-- file1
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
-- ipv6/file2
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Error: Must not reference IPv4 network:n1 in IPv6 context user of service:s2
Error: Must not reference IPv4 network:n2 in IPv6 context dst of rule in service:s2
END

test_err($title, $in, $out);

############################################################
$title = 'Reference IPv4/6 policy_distribution_point from IPv6/4';
############################################################

$in = <<'END';
-- file1
area:a = {
 anchor = network:n1;
 router_attributes = { policy_distribution_point = host:pdp6; }
}
network:n1 = { ip = 10.1.1.0/24; host:netspoc = { ip = 10.1.1.11; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- ipv6/file2
network:n3 = {
 ip = 1000::abcd:0001:0/112;
 host:pdp6 = { ip = 1000::abcd:0001:11; }
}

router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
END

$out = <<'END';
Error: Must not reference IPv4 host:netspoc in IPv6 context router:r1
Error: Must not reference IPv6 host:pdp6 in IPv4 context router_attributes of area:a
END

test_err($title, $in, $out);

############################################################
$title = 'Check model of IPv4/IPv6 router';
############################################################

$in = <<'END';
-- file1
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- ipv6
network:n3 = { ip = 1000::abcd:0001:0/112;}

router:r1 = {
 managed;
 model = IOS;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
END

$out = <<'END';
Error: All instances of router:r1 must have identical model
END

test_err($title, $in, $out);

############################################################
$title = 'Empty IPv6 topology';
############################################################

$in = <<'END';
-- file

-- ipv6/file

END

$out = <<'END';
Error: topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Empty IPv4 topology';
############################################################

$in = <<'END';
-- file

-- ipv4

END

$out = <<'END';
Error: topology seems to be empty
Aborted
END

test_err($title, $in, $out, '--ipv6');

############################################################
$title = 'Raw files for IPv4 and IPv6';
############################################################

$in = <<'END';
-- ipv4
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- raw/r1
access-list n1_in extended permit icmp any4 any4
access-group n1_in in interface n1
-- ipv6/topo
network:n3 = { ip = 1000::abcd:0001:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
-- raw/ipv6/r1
access-list n1_in extended permit icmp6 any6 any6
access-group n1_in in interface n1
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r1.raw
access-list n1_in extended permit icmp any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r1.raw
access-list n1_in extended permit icmp6 any6 any6
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'Raw files for IPv6 and IPv4';
############################################################

$in =~ s|raw/r1|raw/ipv4/r1|;
$in =~ s|raw/ipv6/r1|raw/r1|;

test_run($title, $in, $out, '--ipv6');

############################################################
$title = 'Invalid file and directory in raw/ipv6';
############################################################

$in = <<'END';
-- ipv4
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- raw/ipv6/r1
access-list n1_in extended permit icmp6 any6 any6
access-group n1_in in interface n1
-- raw/ipv6/ipv6/foo
foo
END

$out = <<'END';
Warning: Ignoring path raw/ipv6/ipv6
Warning: Found unused file raw/ipv6/r1
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_warn($title, $in, $out);

############################################################
$title = 'Verbose output with progress messages';
############################################################

$in = <<'END';
--ipv4
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp;
 permit src = user; dst = network:n2; prt = ip;
}
--ipv6
network:n3 = { ip = 1000::abcd:0001:0/112;}
network:n4 = { ip = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
service:s2 = {
 overlaps = service:s2;
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
 permit src = user; dst = network:n4; prt = tcp 80;
}
END

$out = <<'END';
Netspoc, version TESTING
Read: 2 routers, 4 networks, 1 hosts, 2 services
Arranging protocols
Linking topology
Preparing security zones and areas
Preparing fast path traversal
Distributing NAT
Finding subnets in zone
Normalizing services
Checking service owner
Converting hosts to subnets
Grouping rules
Grouped rule count: 4
Finding subnets in 2 NAT domains
Checking rules for unstable subnet relation
Checking rules with hidden or dynamic NAT
Checking supernet rules
Checking transient supernet rules
Checking for redundant rules
Expanded rule count: 4; duplicate: 1; redundant: 1
Removing simple duplicate rules
Setting policy distribution IP
Expanding crypto rules
Finding routes
Generating reverse rules for stateless routers
Marking rules for secondary optimization
Distributing rules
Saving 6 old files of '' to subdirectory '.prev'
Printing intermediate code
Reused 2 files from previous run
Finished
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
END

test_reuse_prev($title, $in, $in, $out, '--verbose');

############################################################
$title = 'No partition names for unconnected IPv6 and IPv4 partitions 1';
############################################################
$in = <<'END';
-- ipv4/topo/net
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
-- ipv4/topo/router
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- ipv4/topo/ipv6
network:n3 = {
 ip = 1000::abcd:0003:0/112;
 partition = part1;
}
network:n4 = { ip = 1000::abcd:0004:0/112; }
-- ipv6/router
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0003:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0004:0001; hardware = n2;}
}
END

$out = <<'END';
Warning: Spare partition name for single partition any:[network:n3]: part1.
END

test_warn($title, $in, $out);

############################################################
$title = 'No partition names for unconnected IPv6 and IPv4 partitions 2';
############################################################
$in =~ s/partition = part1;//;

$out = <<'END';
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'No unstable IPv4 subnet with IPv6 topology';
############################################################
# Secondary optimization must still work.

$in = <<'END';
-- ipv4
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n4sub = {
 ip = 10.1.4.0/26;
 nat:h = { hidden; }
 subnet_of = network:n4;
 host:h4 = { ip = 10.1.4.10; }
}
network:n5 = { ip = 10.1.5.0/24; }

router:r1  = {
 managed = secondary;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; bind_nat = h; }
}
router:r3 = {
 interface:n3 = { ip = 10.1.3.2; }
 interface:n4;
 interface:n4sub;
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h4; prt = tcp;
}
-- ipv6
network:n1_v6 = { ip = 1::/64; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1_v6 = { ip = 1::1; hardware = n1; }
}
END

$out = <<'END';
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
done_testing;
