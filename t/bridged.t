#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Unexptected attribute at bridged interface';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside;  no_in_acl; dhcp_server; routing = OSPF; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Attribute 'no_in_acl' not supported for bridged interface:bridge.n1/left
Error: Attribute 'dhcp_server' not supported for bridged interface:bridge.n1/left
Error: Attribute 'routing' not supported for bridged interface:bridge.n1/left
END

test_err($title, $in, $out);

############################################################
$title = 'No dynamic routing at bridged interface';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; routing = OSPF; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Attribute 'routing' not supported for bridged interface:bridge.n1/left
END

test_err($title, $in, $out);

############################################################
$title = 'No routing = manual at bridge';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Must not apply attribute 'routing' to bridge router:bridge
END

test_err($title, $in, $out);

############################################################
$title = 'Bridged network must not have NAT';
############################################################

$in = <<'END';
network:n1/left = {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.1.2.0/26; dynamic; }
}

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; bind_nat = x; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Only identity NAT allowed for bridged network:n1/left
END

test_err($title, $in, $out);

############################################################
$title = 'Bridged network must not inherit NAT';
############################################################

$in = <<'END';
any:a = { link = network:n1/left; nat:x = { ip = 10.1.2.0/26; dynamic; } }
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Must not inherit nat:x at bridged network:n1/left from any:[network:n1/left]
END

test_err($title, $in, $out);

############################################################
$title = 'Bridged network must not have host with range';
############################################################

$in = <<'END';
network:n1/left = {
 ip = 10.1.1.0/24;
 host:h = { range = 10.1.1.10-10.1.1.20; }
}

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Bridged network:n1/left must not have host:h with range (not implemented)
END

test_err($title, $in, $out);

############################################################
$title = 'Other network must not use prefix name of bridged networks';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1/right = { ip = 10.1.1.2; }
 interface:n1;
}
network:n1 = { ip = 10.2.2.0/24; }
END

$out = <<'END';
Error: Must not define network:n1 together with bridged networks of same name
END

test_err($title, $in, $out);

############################################################
$title = 'Bridged networks must use identical IP addresses';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.2.2.0/24; }
END

$out = <<'END';
Error: network:n1/left and network:n1/right must have identical ip/mask
END

test_err($title, $in, $out);

############################################################
$title = 'Missing layer 3 interface';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Must define interface:n1 at router:bridge for corresponding bridge interfaces
END

test_err($title, $in, $out);

############################################################
$title = 'Layer 3 interface must not have secondary IP';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1, 10.1.1.2; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Layer3 interface:bridge.n1 must not have secondary or virtual IP
END

test_err($title, $in, $out);

############################################################
$title = 'Layer 3 IP must match bridged network IP/mask';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.2.2.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: interface:bridge.n1's IP doesn't match IP/mask of bridged networks
END

test_err($title, $in, $out);

############################################################
$title = 'Bridged networks must be connected by bridge';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1/left = { ip = 10.1.1.1; hardware = inside; }
 interface:n1/right = { ip = 10.1.1.2; hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: network:n1/right and network:n1/left must be connected by bridge
END

test_err($title, $in, $out);

############################################################
$title = 'Bridge must connect at least two networks';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
}
router:bridge2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: router:bridge1 can't bridge a single network
END

test_err($title, $in, $out);

############################################################
$title = 'Bridged must not be used solitary';
############################################################

$in = <<'END';
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Warning: Bridged network:n1/right must not be used solitary
END

test_warn($title, $in, $out);

############################################################
$title = 'Bridged network must not be unnumbered';
############################################################

$in = <<'END';
network:n1/left = { unnumbered; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { unnumbered; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}

network:n1/right = { unnumbered; }
END

$out = <<'END';
Error: Unnumbered network:n1/left must not be bridged
Error: Unnumbered network:n1/right must not be bridged
Error: Layer3 interface:bridge.n1 must have IP address
Error: interface:bridge.n1/left must not be linked to unnumbered network:n1/left
Error: interface:bridge.n1/right must not be linked to unnumbered network:n1/right
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate layer 3 IP';
############################################################

$in = <<'END';
network:n1/a = { ip = 10.1.1.0/24; }
network:n1/b = { ip = 10.1.1.0/24; }
network:n1/c = { ip = 10.1.1.0/24; }

router:bridge1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/a = { hardware = inside; }
 interface:n1/b = { hardware = outside; }
}
router:bridge2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/b = { hardware = inside; }
 interface:n1/c = { hardware = outside; }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:bridge1.n1 and interface:bridge2.n1
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate IP addresses in bridged parts';
############################################################

$in = <<'END';

router:r1 = {
 interface:n1/left = { ip = 10.1.1.1; }
}

network:n1/left = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; }
 host:h2a = { ip = 10.1.1.2; }
}

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = {
 ip = 10.1.1.0/24;
 host:h2b = { ip = 10.1.1.2; }
}

router:r2 = {
 interface:n1/right = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r1.n1/left and interface:bridge.n1
Error: Duplicate IP address for interface:r1.n1/left and interface:r2.n1/right
Error: Duplicate IP address for interface:r1.n1/left and host:h1
Error: Duplicate IP address for host:h2a and host:h2b
END

test_err($title, $in, $out);

############################################################
# Shared topology for multiple tests
############################################################

my $topology = <<'END';

network:intern = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:asa = {
 model = IOS;
 #managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = Ethernet0;
 }
 interface:dmz/left = {
  ip = 192.168.0.101;
  hardware = Ethernet1;
 }
}

network:dmz/left = { ip = 192.168.0.0/24; }

router:bridge = {
 model = ASA;
 managed;
 policy_distribution_point = host:netspoc;
 interface:dmz = { ip = 192.168.0.9; hardware = device; }
 interface:dmz/left = { hardware = inside; }
 interface:dmz/right = { hardware = outside; }
}

network:dmz/right = { ip = 192.168.0.0/24;}

router:extern = {
 interface:dmz/right = { ip = 192.168.0.1; }
 interface:extern;
}

network:extern = { ip = 10.9.9.0/24; }
END

############################################################
$title = 'Admin access to bridge';
############################################################

$in = $topology . <<'END';
service:admin = {
 user = interface:bridge.dmz;
 permit src = network:intern; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--bridge
! [ IP = 192.168.0.9 ]
END

test_run($title, $in, $out);

############################################################
$title = 'Admin access to bridge auto interface';
############################################################
$in = $topology . <<'END';
service:admin = {
 user =  interface:bridge.[auto];
 permit src = network:intern; dst = user; prt = tcp 22;
}
END

# $out is unchanged
test_run($title, $in, $out);

############################################################
$title = 'Admin access to bridge all interfaces';
############################################################
$in = $topology . <<'END';
service:admin = {
 user =  interface:bridge.[all];
 permit src = network:intern; dst = user; prt = tcp 22;
}
END

# $out is unchanged
test_run($title, $in, $out);

############################################################
$title = 'Access to both sides of bridged network';
############################################################

$topology =~ s/policy_distribution_point = .*;//;
$topology =~ s/#managed/managed/;
$in = $topology . <<'END';
service:test = {
 user = network:dmz/left, network:dmz/right;
 permit src = user; dst = host:[network:intern]; prt = tcp 80;
}
END

$out = <<'END';
--bridge
access-list outside_in extended permit tcp 192.168.0.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Access through bridged ASA';
############################################################

$in = $topology . <<'END';
service:test = {
 user = network:extern;
 permit src = user; dst = host:[network:intern]; prt = tcp 80;
}
END

# Must not use bridged interface as next hop in static route.
$out = <<'END';
--bridge
access-list outside_in extended permit tcp 10.9.9.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--asa
! [ Routing ]
ip route 10.9.9.0 255.255.255.0 192.168.0.1
END

test_run($title, $in, $out);

############################################################
$title = 'Must not use bridged interface in rule';
############################################################

$in = $topology . <<'END';
service:test = {
 user = network:intern;
 permit src = user; dst = interface:bridge.dmz/right; prt = tcp 22;
 permit src = interface:bridge.dmz/left; dst = user; prt = tcp 22;
}
END

$out = <<'END';
Warning: Ignoring bridged interface:bridge.dmz/right in dst of rule in service:test
Warning: Ignoring bridged interface:bridge.dmz/left in src of rule in service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Duplicate auto interface';
############################################################

# Two auto interfaces are found in topology,
# but are combined into a single layer 3 interface.

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; loopback; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1/left = { ip = 10.1.1.3; hardware = n1; }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n1/right = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:s = {
 user = interface:bridge.[auto];
 permit src = network:n2; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--r1
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.1 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r2
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.1 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Duplicate static routes behind bridge';
############################################################

$in = <<'END';
network:n0 = { ip = 10.1.0.0/24; }

router:r0 = {
 managed;
 model = ASA;
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1/center = { ip = 10.1.1.4; hardware = center; }
}

network:n1/center = { ip = 10.1.1.0/24; }
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left    = { hardware = left; }
 interface:n1/center  = { hardware = center; }
 interface:n1/right   = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1/left = { ip = 10.1.1.3; hardware = n1; }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n1/right = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:s = {
 user = network:n0;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Error: Two static routes for network:n2
 at interface:r0.n1/center via interface:r2.n1/right and interface:r1.n1/left
END

test_err($title, $in, $out);

############################################################
$title = 'Route behind chained bridges';
############################################################

$in = <<'END';
network:n0 = { ip = 10.1.0.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1/left = { ip = 10.1.1.4; hardware = left; }
}

network:n1/left = { ip = 10.1.1.0/24; }

# Use name, that is sorted behind r1, r2,
# so that we actually test recursion when searching hop with IP address.
router:zbridge1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left    = { hardware = left; }
 interface:n1/center  = { hardware = center; }
}

network:n1/center = { ip = 10.1.1.0/24; }

router:zbridge2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = device; }
 interface:n1/center  = { hardware = center; }
 interface:n1/right   = { hardware = right; }
}

network:n1/right = { ip = 10.1.1.0/24; }

router:r2 = {
 managed;
 model = ASA;
 interface:n1/right = { ip = 10.1.1.5; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:s = {
 user = network:n0;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
--r1
! [ Routing ]
route left 10.1.2.0 255.255.255.0 10.1.1.5
END

test_run($title, $in, $out);

############################################################
$title = 'Rules for hosts in bridged network';
############################################################

$in = <<'END';

network:n1/left = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; }
}

router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.9; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = {
 ip = 10.1.1.0/24;
 host:h2 = { ip = 10.1.1.2; }
}

router:r2 = {
 interface:n1/right = { ip = 10.1.1.10; }
 interface:n2;
}

network:n2 = { ip = 10.1.2.0/24; }

service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
service:s2 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 81;
}
service:s3 = {
 user = host:h1, host:h2;
 permit src = network:n2; dst = user; prt = tcp 82;
}
END

$out = <<'END';
Warning: service:s3 has unenforceable rules:
 src=network:n2; dst=host:h2
--bridge
! left_in
access-list left_in extended permit tcp host 10.1.1.1 host 10.1.1.2 eq 80
access-list left_in extended permit tcp host 10.1.1.1 10.1.2.0 255.255.255.0 eq 81
access-list left_in extended deny ip any4 any4
access-group left_in in interface left
--
! right_in
access-list right_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.1 eq 82
access-list right_in extended deny ip any4 any4
access-group right_in in interface right
END

test_warn($title, $in, $out);

############################################################
done_testing;
