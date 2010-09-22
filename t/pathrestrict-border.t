#!/usr/bin/perl

use strict;
use Test::More tests => 1;
use lib 't';
use Test_Netspoc;

############################################################
my $title = 'Pathrestriction at border of loop';
############################################################

# Soll an router:filter für Interfaces GRE und Trans unterschiedliche 
# ACLs generieren.

my $in = <<END;
router:filter = {
 managed;
 model = IOS_FW;
 interface:Trans = { 
  ip = 10.5.6.69; 
  hardware = GigabitEthernet0/1; 
  routing = manual;
 }
 interface:GRE = {
  ip = 10.5.6.81; 
  routing = manual;
  hardware = Tunnel1;
 } 
 interface:Test = {
  ip = 10.9.1.1;
  routing = manual;
  hardware = Vlan20;
 }
}

network:Test =  { ip = 10.9.1.0/24; }
network:Trans = { ip = 10.5.6.68/30; }
network:GRE =   { ip = 10.5.6.80/30; }

router:Kunde = {
 interface:Trans = { ip = 10.5.6.70; }
 interface:GRE =   { ip = 10.5.6.82; } 
 interface:X =     { ip = 10.9.3.1; }
 interface:Schulung = { ip = 10.9.2.1; }
}

network:X =        { ip = 10.9.3.0/24; }
network:Schulung = { ip = 10.9.2.0/24; }

pathrestriction:restrict = 
 description = Nur network:X über GRE-Tunnel.
 interface:filter.GRE,
 interface:Kunde.Schulung,
;

service:IP = ip;

policy:test = {
 user = network:Schulung, network:X;
 permit src = user; 
	dst = network:Test;
	srv = service:IP;
}
END

my $out1 = <<END;
ip access-list extended GigabitEthernet0/1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.2.0 0.0.0.255 10.9.1.0 0.0.0.255
 permit ip 10.9.3.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
END
my $out2 = <<END;
ip access-list extended Tunnel1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.3.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
END

my $head1 = (split /\n/, $out1)[0];
my $head2 = (split /\n/, $out2)[0];

is_deeply(get_block(compile($in), $head1, $head2), $out1.$out2, $title);
