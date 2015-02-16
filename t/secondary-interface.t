#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
$title = 'Access named and positional secondary interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = 10.1.1.1; secondary:5th = { ip = 10.1.1.5; } hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1, 10.1.2.9; hardware = vlan2; }
}

service:t1 = {
 user = network:n1, network:n2;
 permit src = user; dst = interface:r1.n1.5th; prt = tcp 22;
 permit src = user; dst = interface:r1.n2.2; prt = tcp 23;
}
END

$out = <<'END';
--r1
ip access-list extended vlan1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.5 eq 22
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.9 eq 23
 deny ip any any
--
ip access-list extended vlan2_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.1.5 eq 22
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.2.9 eq 23
 deny ip any any
--
interface vlan1
 ip address 10.1.1.1 255.255.255.0
 ip address 10.1.1.5 255.255.255.0 secondary
 ip access-group vlan1_in in
interface vlan2
 ip address 10.1.2.1 255.255.255.0
 ip address 10.1.2.9 255.255.255.0 secondary
 ip access-group vlan2_in in
END

test_run($title, $in, $out);

############################################################
$title = 'Outgoing traffic from secondary interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = 10.1.1.1; secondary:5th = { ip = 10.1.1.5; } hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1, 10.1.2.9; hardware = vlan2; }
}

service:t1 = {
 user = network:n1, network:n2;
 permit src = interface:r1.n1.5th; dst = user; prt = udp 123;
 permit src = interface:r1.n2.2; dst = user; prt = udp 69;
}
END

$out = <<'END';
--r1
ip access-list extended vlan1_in
 permit udp 10.1.1.0 0.0.0.255 eq 123 host 10.1.1.5
 permit udp 10.1.1.0 0.0.0.255 eq 69 host 10.1.2.9
 deny ip any any
--
ip access-list extended vlan2_in
 permit udp 10.1.2.0 0.0.0.255 eq 123 host 10.1.1.5
 permit udp 10.1.2.0 0.0.0.255 eq 69 host 10.1.2.9
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Duplicate named secondary interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = {
  ip = 10.1.1.1; 
  secondary:5th = { ip = 10.1.1.5; } 
  secondary:5th = { ip = 10.1.1.6; } 
 }
}
END

$out = <<'END';
Error: Redefining interface:r1.n1.5th at line 8 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Name clash for named and positional secondary interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = {
  ip = 10.1.1.1, 10.1.1.4; 
  secondary:2 = { ip = 10.1.1.6; } 
 }
}
END

$out = <<'END';
Error: Redefining interface:r1.n1.2 at line 7 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Name clash for secondary and virtual interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = {
  ip = 10.1.1.1; 
  secondary:virtual = { ip = 10.1.1.6; }
  virtual = { ip = 10.1.1.9; }
 }
}
END

$out = <<'END';
Error: Redefining interface:r1.n1.virtual at line 8 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Identical IP at host and secondary interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h = { ip = 10.1.1.2; } }

router:r1 = {
 interface:n1 = {
  ip = 10.1.1.1, 10.1.1.2; 
 }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r1.n1.2 and host:h
END

test_err($title, $in, $out);

############################################################
$title = 'Identical IP at named and positional secondary interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = {
  ip = 10.1.1.1, 10.1.1.2; 
  secondary:s = { ip = 10.1.1.2; } 
 }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r1.n1.2 and interface:r1.n1.s
END

test_err($title, $in, $out);

############################################################

done_testing;
