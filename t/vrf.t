#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

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
$title = 'No admin IP found in any VRFs';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24; 
 host:netspoc = { ip = 10.2.2.222; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t = { ip = 10.9.9.1; hardware = e1; }
}
network:t = { ip = 10.9.9.0/24; }
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:t = { ip = 10.9.9.2; hardware = e2; }
 interface:n = { ip = 10.1.1.1; hardware = e3; }
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Warning: Missing rules to reach devices from policy_distribution_point:
 - some VRF of router:r1
END

test_err($title, $in, $out);

############################################################

done_testing;
