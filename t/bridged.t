#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Bridged network must not have hosts or NAT';
############################################################

$in = <<'END';
network:n1/left = {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.1.2.0/24; }
 host:h = { ip = 10.1.1.10; }
 has_subnets;
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
Error: Bridged network:n1/left must not have host definition (not implemented)
Error: Only identity NAT allowed for bridged network:n1/left
END

test_err($title, $in, $out);

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
Error: Unnumbered network:n1/left must not have attribute 'bridged'
Error: Layer3 interface:bridge.n1 must not be unnumbered
Error: Unnumbered network:n1/right must not have attribute 'bridged'
Error: interface:bridge.n1/left must not be linked to unnumbered network:n1/left
Error: interface:bridge.n1/right must not be linked to unnumbered network:n1/right
END

test_err($title, $in, $out);

############################################################
$title = 'Admin access to bridge';
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

$in = $topology . <<'END';
service:admin = {
 user =  interface:bridge.dmz;
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
access-list outside_in extended deny ip any any
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

$out = <<'END';
--bridge
access-list outside_in extended permit tcp 10.9.9.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
done_testing;
