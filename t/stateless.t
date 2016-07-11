#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($topo, $title, $in, $out);

$topo = <<'END';
network:x = { ip = 10.1.1.0/24; 
}
router:r = {
 model = IOS;
 managed;
 interface:x = { ip = 10.1.1.1; hardware = e0; }
 interface:y = { ip = 10.2.2.2; hardware = e1; }
}
network:y = { ip = 10.2.2.0/24; 
 host:y = { ip = 10.2.2.9; } 
}
END

############################################################
$title = 'Optimize reverse rules';
############################################################

$in = $topo . <<'END';
service:test1 = {
 user = network:x;
 permit src = user; dst = network:y; prt = ip;
}
service:test2 = {
 overlaps = service:test1;
 user = network:x;
 # globally redundant to rule of service:test1
 permit src = user; dst = host:y; prt = ip;
 # locally redundant at router:r,
 # after reverse rule has been generated for rule of service:test1
 permit src = host:y; dst = user; prt = ip;
 # a reverse rule will be generated internally:
 # permit src = user; dst = host:y; prt = ip; stateless;
 # This internal rule is globally redundant to rule of service:test1
}
END

$out = <<'END';
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit ip 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Reverse UDP ports';
############################################################

$in = $topo . <<'END';
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = udp 389;
}
END

$out = <<'END';
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 389
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 eq 389 10.1.1.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'UDP source port with unspecified destination port';
############################################################

$in = $topo . <<'END';
protocol:ike = udp 69:1-65535;
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = protocol:ike;
}
END

$out = <<'END';
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 eq 69 10.2.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 69
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'UDP source ports';
############################################################

$in = $topo . <<'END';
protocol:ike = udp 500:500;
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = protocol:ike;
}
END

$out = <<'END';
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 eq 500 10.2.2.0 0.0.0.255 eq 500
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 eq 500 10.1.1.0 0.0.0.255 eq 500
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Optimized UDP source ports';
############################################################

$in = $topo . <<'END';
protocol:ike = udp 500:500;
service:test = {
 user = network:x, network:y;
 permit src = user; dst = user; prt = protocol:ike;
}
END

$out = <<'END';
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 eq 500 10.2.2.0 0.0.0.255 eq 500
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 eq 500 10.1.1.0 0.0.0.255 eq 500
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No warning on overlapping stateless range';
############################################################

$in = $topo . <<'END';
protocol:ftp-passive-data = tcp 1024-65535, stateless;

service:s = {
 user = network:x;
 permit src =   user;
        dst =   network:y;
        prt =   protocol:ftp-passive-data, 
                tcp 3389,
                ;
}
END

$out = <<'END';
--r
! [ ACL ]
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 gt 1023
 deny ip any any
END

test_run($title, $in, $out);

############################################################

done_testing;
