#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

############################################################
my $title = 'Optimize subnet at secondary packet filter';
############################################################

my $in = <<END;
network:sub = { ip = 10.1.7.32/27; subnet_of = network:customer; }

router:r = { interface:sub; interface:customer = { ip = 10.1.7.33; } }

network:customer = { ip = 10.1.7.0/24; }

router:gw = {
 managed = secondary;
 model = IOS_FW;
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

service:Echo = icmp 8;

policy:p1 = {
 user = network:sub;
 permit src = user; dst = host:s10; srv = service:Echo;
}

policy:p2 = {
 user = network:customer;
 permit src = user; dst = host:s11; srv = service:Echo;
}
END

my $out1 = <<END;
! [ ACL ]
ip access-list extended outside_in
 permit ip 10.1.7.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
END

my $head1 = (split /\n/, $out1)[0];

TODO: {
      local $TODO = "recognize subnet during local_optimization";
      eq_or_diff(get_block(compile($in), $head1), $out1, $title);
}

############################################################
$title = 'Optimize subnet at secondary packet filter';
############################################################

$in =~ s/managed = secondary/managed/ms;
$in =~ s/(service:Echo = icmp 8)/$1, dst_net/;

my $out2 = <<END;
! [ ACL ]
ip access-list extended outside_in
 permit icmp 10.1.7.0 0.0.0.255 10.1.2.0 0.0.0.255 8
 deny ip any any
END

my $head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head2), $out2, $title);
############################################################

done_testing;
