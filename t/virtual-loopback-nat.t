#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

############################################################
my $title = 'Dynamic NAT to multiple virtual loopback interfaces (secondary)';
############################################################

# Soll bei local_optimization loopback interfaces und NAT network als
# identisch erkennen.

my $in = <<END;
network:customer = { ip = 10.1.7.0/24; }

router:gw = {
 managed = secondary;
 model = ASA;
 interface:customer = { ip = 10.1.7.1;    hardware = outside;}
 interface:trans    = { ip = 10.1.3.1;   hardware = inside;}
}

network:trans = { ip = 10.1.3.0/24; }

router:b1 = {
 managed;
 model = Linux;
 interface:trans = {
  ip = 10.1.3.3;
  virtual = { ip = 10.1.3.2; type = VRRP; }
  bind_nat = extern;
  hardware = eth0;
 }
 interface:extern = { 
  virtual = { ip = 193.1.1.2; type = VRRP; }
  loopback;
  hardware = eth1;
 }
 interface:server = {
  virtual = { ip = 10.1.2.17; type = VRRP; }
  hardware = eth1;
 }
}

router:b2 = {
 managed;
 model = Linux;
 interface:trans = {
  ip = 10.1.3.4;
  virtual = { ip = 10.1.3.2; type = VRRP; }
  bind_nat = extern;
  hardware = eth0;
 }
 interface:extern = { 
  virtual = { ip = 193.1.1.2; type = VRRP; }
  loopback;
  hardware = eth1;
 }
 interface:server = {
  virtual = { ip = 10.1.2.17; type = VRRP; }
  hardware = eth1;
 }
}

network:server = {
 ip = 10.1.2.16/28;
 nat:extern = { ip = 193.1.1.2/32; dynamic; }
}

protocol:Echo = icmp 8;

service:p1 = {
 user = network:customer;
 permit src = user;
        dst = interface:b1.extern.virtual, interface:b2.extern.virtual;
        prt = protocol:Echo;
}

service:p2 = {
 user = network:customer;
 permit src = user; dst = network:server; prt = protocol:Echo;
}
END

my $out1 = <<END;
! [ ACL ]
access-list outside_in extended permit ip 10.1.7.0 255.255.255.0 host 193.1.1.2
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

my $head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Dynamic NAT to multiple virtual loopback interfaces';
############################################################

$in =~ s/managed = secondary/managed/ms;

my $out2 = <<END;
! [ ACL ]
access-list outside_in extended permit icmp 10.1.7.0 255.255.255.0 host 193.1.1.2 8
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

my $head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head2), $out2, $title);
############################################################
done_testing;
