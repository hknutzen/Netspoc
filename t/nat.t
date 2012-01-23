#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

############################################################
my $title = 'Multiple dynamic NAT at ASA';
############################################################

# Soll nur einen nat-Index pro Interface verwenden.

my $in = <<END;
network:Test =  { ip = 10.9.1.0/24; nat:C = { ip = 1.1.1.1/32; dynamic;} }

router:filter = {
 managed;
 model = ASA;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.3.1; hardware = outside; bind_nat = C;}
 interface:Y = { ip = 10.9.2.1; hardware = DMZ50; bind_nat = C;}
}

network:X = { ip = 10.9.3.0/24; }
network:Y = { ip = 10.9.2.0/24; }

service:IP = ip;

policy:test = {
 user = network:X, network:Y;
 permit src = user; 
	dst = network:Test;
	srv = service:IP;
}

END

my $out1 = <<END;
global (outside) 1 1.1.1.1 netmask 255.255.255.255
nat (inside) 1 10.9.1.0 255.255.255.0
global (DMZ50) 1 1.1.1.1 netmask 255.255.255.255
END

my $head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
done_testing;
