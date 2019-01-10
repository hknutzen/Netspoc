#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

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
  ip = 10.1.1.1; secondary:5th = { ip = 10.1.1.5; } hardware = n1; }
 interface:n2 = { ip = 10.1.2.1, 10.1.2.9; hardware = n2; }
}

router:r2 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = 10.1.1.11,10.1.1.12;  hardware = n1; }
}

service:t1 = {
 user = network:n1, network:n2;
 permit src = user; dst = interface:r1.n1.5th; prt = tcp 22;
 permit src = user; dst = interface:r1.n2.2; prt = tcp 23;
}
service:t2 = {
 user = network:n1;
 permit src = user; dst = interface:r2.n1.2; prt = tcp 21;
}
END

$out = <<'END';
--r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.5 eq 22
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.9 eq 23
 deny ip any any
--
ip access-list extended n2_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.1.5 eq 22
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.2.9 eq 23
 deny ip any any
--
interface n1
 ip address 10.1.1.1 255.255.255.0
 ip address 10.1.1.5 255.255.255.0 secondary
 ip access-group n1_in in
interface n2
 ip address 10.1.2.1 255.255.255.0
 ip address 10.1.2.9 255.255.255.0 secondary
 ip access-group n2_in in
-- r2
ip access-list n1_in
 10 permit tcp 10.1.1.0/24 10.1.1.12/32 eq 21
 20 deny ip any any
--
interface n1
 ip address 10.1.1.11/24
 ip address 10.1.1.12/24 secondary
 ip access-group n1_in in
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
  ip = 10.1.1.1; secondary:5th = { ip = 10.1.1.5; } hardware = n1; }
 interface:n2 = { ip = 10.1.2.1, 10.1.2.9; hardware = n2; }
}

service:t1 = {
 user = network:n1, network:n2;
 permit src = interface:r1.n1.5th; dst = user; prt = udp 123;
 permit src = interface:r1.n2.2; dst = user; prt = udp 69;
}
END

$out = <<'END';
--r1
ip access-list extended n1_in
 permit udp 10.1.1.0 0.0.0.255 eq 123 host 10.1.1.5
 permit udp 10.1.1.0 0.0.0.255 eq 69 host 10.1.2.9
 deny ip any any
--
ip access-list extended n2_in
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
$title = 'Move secondary interface of  internally split router';
############################################################

$in = <<'END';
network:n1 =  { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

# r1 is split internally into two parts
# r1 connected with n1, n2
# r1' connected with n3
# both connected by unnumbered network.
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; }
 interface:n3 = { ip = 10.1.3.1; secondary:s = { ip = 10.1.3.99; } }
}

router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

pathrestriction:r =
 interface:r1.n3,
 interface:r2.n3,
;

service:s = {
 user = network:n4;

 # Find secondary  interface r1.n3.s of split interface r1.n3.
 permit src = user; dst = interface:r1.n3.s; prt = tcp 22;

}
END

$out = <<'END';
--r2
ip access-list extended n1_in
 permit tcp host 10.1.3.99 10.1.4.0 0.0.0.255 established
 deny ip any any
--
ip access-list extended n4_in
 permit tcp 10.1.4.0 0.0.0.255 host 10.1.3.99 eq 22
 deny ip any any
--
ip access-list extended n3_in
 permit tcp host 10.1.3.99 10.1.4.0 0.0.0.255 established
 deny ip any any
END

test_run($title, $in, $out);

############################################################

done_testing;
