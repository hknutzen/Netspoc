#!/usr/bin/perl

use strict;
use Test::More;
use lib 't';
use Test_Netspoc;

############################################################
my $title = 'Pathrestriction at border of loop (at router)';
############################################################

# Soll an router:filter für Interfaces GRE und Trans unterschiedliche 
# ACLs generieren.

my $in = <<END;
network:Test =  { ip = 10.9.1.0/24; }

router:filter = {
 managed;
 model = IOS_FW;
 interface:Test = {
  ip = 10.9.1.1;
  routing = manual;
  hardware = Vlan20;
 }
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
}

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

############################################################
$title = 'Pathrestriction at border of loop (at any)';
############################################################

# Soll network:Trans beim path_walk wegen der Pathrestriction
# nicht versehentlich als Router ansehen

$in = <<END;
network:Test =  { ip = 10.9.1.0/24; }

router:filter1 = {
 managed;
 model = PIX;
 interface:Test = {
  ip = 10.9.1.1;
  routing = manual;
  hardware = Vlan20;
 }
 interface:Trans = { 
  ip = 10.5.6.1; 
  hardware = GigabitEthernet0/1; 
  routing = manual;
 }
}
router:filter2 = {
 managed;
 model = IOS_FW;
 interface:Test = {
  ip = 10.9.1.2;
  routing = manual;
  hardware = Vlan20;
 }
 interface:Trans = { 
  ip = 10.5.6.2; 
  hardware = GigabitEthernet0/1; 
  routing = manual;
 }
}
network:Trans = { ip = 10.5.6.0/24; }


router:Kunde = {
 managed;
 model = IOS, FW;
 interface:Trans = { ip = 10.5.6.70; hardware = E0; }
 interface:Schulung = { ip = 10.9.2.1; hardware = E1; }
}

network:Schulung = { ip = 10.9.2.0/24; }

pathrestriction:restrict = 
 description = Nur über filter1
 interface:filter2.Trans,
 interface:Kunde.Trans,
;

service:IP = ip;

policy:test = {
 user = network:Schulung;
 permit src = user; 
	dst = network:Test;
	srv = service:IP;
}
END

$out1 = <<END;
ip route 10.9.1.0 255.255.255.0 10.5.6.1
END

$out2 = <<END;
ip access-list extended E0_in
 deny ip any any
END

my $out3 = <<END;
ip access-list extended E1_in
 permit ip 10.9.2.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];
my $head3 = (split /\n/, $out3)[0];

is_deeply(get_block(compile($in), $head1, $head2, $head3), $out1.$out2.$out3, 
	  $title);

############################################################
done_testing;
