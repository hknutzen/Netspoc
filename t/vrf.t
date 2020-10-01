#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'VRF sanity checks';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

# Unmanaged device is ignored.
router:r@v1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; } # Hardware is ignored.
}

router:r@v2 = {
 managed;
 model = NX-OS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r@v3 = {
 managed = routing_only;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
END

$out = <<'END';
Error: All instances of router:r must have identical model
Error: Duplicate hardware 'n3' at router:r@v2 and router:r@v3
END

test_err($title, $in, $out);

############################################################
$title = 'Combine object-groups from different VRFs';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24; }
router:r1@v1 = {
 managed;
 model = NX-OS;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t = { ip = 10.9.9.1; hardware = e1; }
}
network:t = { ip = 10.9.9.0/24; }
router:r1@v2 = {
 managed;
 model = NX-OS;
 interface:t = { ip = 10.9.9.2; hardware = e2; }
 interface:n = { ip = 10.1.1.1; hardware = e3; }
}
network:n = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h20 = { ip = 10.1.1.20; }
 host:h30 = { ip = 10.1.1.30; }
}

service:test = {
 user = host:h10, host:h20, host:h30;
 permit src = user; dst = network:m; prt = tcp 80;
}
END

$out = <<'END';
--r1
object-group ip address g0
 10 10.1.1.10/32
 20 10.1.1.20/32
 30 10.1.1.30/32
ip access-list e0_in
 10 permit tcp 10.2.2.0/24 addrgroup g0 established
 20 deny ip any any
--
ip access-list e2_in
 10 permit tcp 10.2.2.0/24 addrgroup g0 established
 20 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Protect interface with different VRFs';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24; }
router:r1@v1 = {
 managed;
 model = IOS, FW;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t = { ip = 10.9.9.1; hardware = e1; }
}
network:t = { ip = 10.9.9.0/24; }
router:r1@v2 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = 10.9.9.2; hardware = e2; }
 interface:n = { ip = 10.1.1.1; hardware = e3; }
}
network:n = { ip = 10.1.1.0/24; }

service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
 permit src = network:n; dst = user; prt = tcp 81;
}
END

$out = <<'END';
--r1
ip access-list extended e0_in
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 81
 deny ip any any
--
ip access-list extended e2_in
 deny ip any host 10.1.1.1
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended e3_in
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 81
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Mixed routing_only and VRFs';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24; }
router:r1@v1 = {
 managed = routing_only;
 model = IOS, FW;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t = { ip = 10.9.9.1; hardware = e1; }
}
network:t = { ip = 10.9.9.0/24; }
router:r1@v2 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = 10.9.9.2; hardware = e2; }
 interface:n = { ip = 10.1.1.1; hardware = e3; }
}
network:n = { ip = 10.1.1.0/24; }

service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
}
END

# Code for routing_only device is generated last.
$out = <<'END';
--r1
! [ Routing for router:r1@v2 ]
ip route vrf v2 10.2.2.0 255.255.255.0 10.9.9.1
--
ip access-list extended e2_in
 deny ip any host 10.1.1.1
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
--
! [ Routing for router:r1@v1 ]
ip route vrf v1 10.1.1.0 255.255.255.0 10.9.9.2
END

test_run($title, $in, $out);

############################################################
$title = 'No admin IP found in any VRF';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
END

$out = <<'END';
Warning: Missing rules to reach 2 devices from policy_distribution_point:
 - router:r1@v1
 - router:r1@v2
END

test_warn($title, $in, $out);

############################################################
$title = 'One admin IP for multiple VRFs';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}

service:admin = {
 user = interface:r1@v2.[auto];
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
END

$out = <<'END';
-- r1
! [ IP = 10.1.1.2 ]
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple admin IPs found in VRFs';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}

service:admin = {
 user = interface:r1@v1.[auto], interface:r1@v2.[auto];
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
END

$out = <<'END';
-- r1
! [ IP = 10.1.1.1,10.1.1.2 ]
END

test_run($title, $in, $out);

############################################################
$title = 'Missing policy distribution point at all VRF members';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
END

$out = <<'END';
Error: Missing attribute 'policy_distribution_point' for 1 devices:
 - at least one instance of router:r1
END

test_err($title, $in, $out, '--check_policy_distribution_point=1');

############################################################

done_testing;
