#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Optimize subnet at secondary packet filter';
############################################################

$in = <<'END';
network:sub = { ip = 10.1.7.32/27; subnet_of = network:customer; }

router:r = { interface:sub; interface:customer = { ip = 10.1.7.30; } }

network:customer = { ip = 10.1.7.0/24; }

router:gw = {
 managed = secondary;
 model = IOS, FW;
 interface:customer = { ip = 10.1.7.1;    hardware = outside;}
 interface:trans    = { ip = 10.1.3.1;   hardware = inside;}
}

network:trans = { ip = 10.1.3.0/24; }

router:b1 = {
 managed;
 model = Linux;
 interface:trans = {
  ip = 10.1.3.3;
  hardware = eth0;
 }
 interface:server = {
  ip = 10.1.2.1;
  hardware = eth1;
 }
}

network:server = {
 ip = 10.1.2.0/24;
 host:s10 = { ip = 10.1.2.10; }
 host:s11 = { ip = 10.1.2.11; }
}

protocol:Echo = icmp 8;

service:p1 = {
 user = network:sub;
 permit src = user; dst = host:s10; prt = protocol:Echo;
}

service:p2 = {
 user = network:customer;
 permit src = user; dst = host:s11; prt = protocol:Echo;
}
END

$out = <<'END';
--b1
# [ Routing ]
ip route add 10.1.7.0/24 via 10.1.3.1
--gw
! [ Routing ]
ip route 10.1.7.32 255.255.255.224 10.1.7.30
ip route 10.1.2.0 255.255.255.0 10.1.3.3
--
! [ ACL ]
ip access-list extended outside_in
 permit ip 10.1.7.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Optimize subnet for protocol with flag dst_net';
############################################################

$in =~ s/managed = secondary/managed/ms;
$in =~ s/(protocol:Echo = icmp 8)/$1, dst_net/;

$out = <<'END';
--gw
! [ ACL ]
ip access-list extended outside_in
 permit icmp 10.1.7.0 0.0.0.255 10.1.2.0 0.0.0.255 8
 deny ip any any
END

test_run($title, $in, $out, '--check_redundant_rules=0');

############################################################
$title = 'Combined hosts prevent optimal object group';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 host:h11 = { ip = 10.1.1.11; }
 host:h13 = { ip = 10.1.1.13; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:h20 = { ip = 10.1.2.20; }
 host:h21 = { ip = 10.1.2.21; }
 host:h23 = { ip = 10.1.2.23; }
 host:h24 = { ip = 10.1.2.24; }
}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 overlaps = service:s2, service:s3;
 user = host:h11, host:h13;
 permit src = user; dst = host:h20, host:h21, host:h23, host:h24; prt = tcp 80;
}

service:s2 = {
 user = network:n1;
 permit src = user; dst = host:h20, host:h23; prt = tcp 80;
}

service:s3 = {
 user = network:n1;
 permit src = user; dst = host:h21, host:h24; prt = tcp 80;
}
END

$out = <<'END';
-- r1
! n1_in
object-group network g0
 network-object 10.1.2.20 255.255.255.254
 network-object host 10.1.2.23
 network-object host 10.1.2.24
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 object-group g0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

Test::More->builder->todo_start($title);
test_run($title, $in, $out);
Test::More->builder->todo_end;

############################################################
$title = 'Optimize subnet of NAT network in zone';
############################################################

$in = <<'END';
network:customer = {
 ip = 10.9.9.0/24;
 nat:N = { ip = 10.1.7.0/24; }
 has_subnets;
}

router:r = {
 interface:customer = { bind_nat = SUB; }
 interface:sub = { ip = 10.1.7.34; bind_nat = N; }
}

network:sub = { ip = 10.1.7.32/27; nat:SUB = { ip = 10.9.9.32/27; }}

router:gw = {
 managed = secondary;
 model = IOS, FW;
 interface:sub   = { ip = 10.1.7.33; hardware = outside;}
 interface:trans = { ip = 10.1.3.1;  hardware = inside; }
}

network:trans = { ip = 10.1.3.0/24; }

router:b1 = {
 managed;
 model = Linux;
 interface:trans  = { ip = 10.1.3.3; hardware = eth0; }
 interface:server = { ip = 10.1.2.1; hardware = eth1; }
}

network:server = { ip = 10.1.2.0/24; }

protocol:Echo = icmp 8;

service:p1 = {
 user = network:sub;
 permit src = user; dst = network:server; prt = tcp 80;
}
END

$out = <<'END';
--gw
! [ Routing ]
ip route 10.1.7.0 255.255.255.0 10.1.7.34
ip route 10.1.2.0 255.255.255.0 10.1.3.3
--
! [ ACL ]
ip access-list extended outside_in
 permit ip 10.1.7.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
END
Test::More->builder->todo_start($title);
test_run($title, $in, $out);
Test::More->builder->todo_end;

############################################################

done_testing;
