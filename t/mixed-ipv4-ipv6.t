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
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
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

$in =~ s|file1|ipv4/file1|;
$in =~ s|ipv6/file2|file2|;

test_run($title, $in, $out, '-ipv6');

############################################################
$title = 'Empty IPv6 topology';
############################################################

$in = <<'END';
-- file

-- ipv6/file

END

$out = <<'END';
Error: IPv6 topology seems to be empty
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
Error: IPv4 topology seems to be empty
Aborted
END

test_err($title, $in, $out, '-ipv6');

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
network:n1 = { ip = 1000::abcd:0001:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
-- ipv6/raw/r1
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
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
service:s1 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Netspoc, version TESTING
Saving 6 old files of '' to subdirectory '.prev'
Read IPv6: 1 routers, 2 networks, 0 hosts, 1 services
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
Grouped rule count: 2
Finding subnets in 1 NAT domains
Checking rules for unstable subnet relation
Checking rules with hidden or dynamic NAT
Checking supernet rules
Checking transient supernet rules
Checking for redundant rules
Expanded rule count: 2; duplicate: 1; redundant: 0
Removing simple duplicate rules
Setting policy distribution IP
Expanding crypto rules
Finding routes
Generating reverse rules for stateless routers
Marking rules for secondary optimization
Distributing rules
Printing intermediate code
Read IPv4: 1 routers, 2 networks, 1 hosts, 1 services
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
Grouped rule count: 2
Finding subnets in 1 NAT domains
Checking rules for unstable subnet relation
Checking rules with hidden or dynamic NAT
Checking supernet rules
Checking transient supernet rules
Checking for redundant rules
Expanded rule count: 2; duplicate: 0; redundant: 1
Removing simple duplicate rules
Setting policy distribution IP
Expanding crypto rules
Finding routes
Generating reverse rules for stateless routers
Marking rules for secondary optimization
Distributing rules
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

test_reuse_prev($title, $in, $in, $out, '-verbose');

############################################################
done_testing;
