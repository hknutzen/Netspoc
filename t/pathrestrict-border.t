#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

$topo = <<'END';
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
END

############################################################
$title = 'Pathrestriction at border of loop (at router)';
############################################################

# Soll an router:filter für Interfaces GRE und Trans unterschiedliche 
# ACLs generieren.

$in = $topo . <<'END';
pathrestriction:restrict = 
 description = Nur network:X über GRE-Tunnel.
 interface:filter.GRE,
 interface:Kunde.Schulung,
;

protocol:IP = ip;

service:test = {
 user = network:Schulung, network:X;
 permit src = user; 
	dst = network:Test;
	prt = protocol:IP;
}
END

$out = <<'END';
--filter
ip access-list extended GigabitEthernet0/1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.2.0 0.0.0.255 10.9.1.0 0.0.0.255
 permit ip 10.9.3.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
--
ip access-list extended Tunnel1_in
 deny ip any host 10.9.1.1
 permit ip 10.9.3.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Pathrestriction at border of loop (at router / at dst.)';
############################################################

# Soll Ausgang der Loop als Router erkennen, obwohl intern 
# ein Interface verwendet wird.

$in = $topo . <<'END';
pathrestriction:restrict = 
 interface:filter.Test,
 interface:filter.Trans,
;

service:test = {
 user = network:Schulung;
 permit src = user; 
	dst = any:[network:Test];
	prt = tcp 80;
}
END

$out = <<'END';
--filter
ip access-list extended GigabitEthernet0/1_in
 deny ip any any
--
ip access-list extended Tunnel1_in
 deny ip any host 10.9.1.1
 deny ip any host 10.5.6.69
 deny ip any host 10.5.6.81
 permit tcp 10.9.2.0 0.0.0.255 any eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Pathrestriction at border of loop (at any)';
############################################################

# Soll network:Trans beim path_walk wegen der Pathrestriction
# nicht versehentlich als Router ansehen

$in = <<'END';
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
 log_deny;
 interface:Trans = { ip = 10.5.6.70; hardware = E0; }
 interface:Schulung = { ip = 10.9.2.1; hardware = E1; }
}

network:Schulung = { ip = 10.9.2.0/24; }

pathrestriction:restrict = 
 description = Nur über filter1
 interface:filter2.Trans,
 interface:Kunde.Trans,
;

protocol:IP = ip;

service:test = {
 user = network:Schulung;
 permit src = user; 
	dst = network:Test;
	prt = protocol:IP;
}
END

$out = <<'END';
--Kunde
ip route 10.9.1.0 255.255.255.0 10.5.6.1
--
ip access-list extended E0_in
 deny ip any any log
--
ip access-list extended E1_in
 permit ip 10.9.2.0 0.0.0.255 10.9.1.0 0.0.0.255
 deny ip any any log
END

test_run($title, $in, $out);

############################################################
$title = 'Pathrestriction at border of nested loop';
############################################################

# Soll auch bei verschachtelter Loop den Pfad finden.

$in = <<'END';
network:top = { ip = 10.1.1.0/24;}
network:cnt = { ip = 10.3.1.240/30;}

router:c1 = {
 managed;
 model = IOS;
 interface:top = { ip = 10.1.1.1; hardware = Vlan13; }
 interface:lft = { ip = 10.3.1.245; hardware = Ethernet1; routing = manual; }
 interface:cnt = { ip = 10.3.1.241; hardware = Ethernet2; routing = manual; }
 interface:mng = { ip = 10.3.1.249; hardware = Ethernet3; }
}
router:c2 = {
 managed;
 model = IOS;
 interface:top = { ip = 10.1.1.2; hardware = Vlan14; }
 interface:rgt = { ip = 10.3.1.129; hardware = Ethernet4; routing = manual; }
 interface:cnt = { ip = 10.3.1.242; hardware = Ethernet5; routing = manual; }
}
network:mng = { ip = 10.3.1.248/30;}
network:lft = { ip = 10.3.1.244/30;}
network:rgt = { ip = 10.3.1.128/30;}

router:k2 = {
 interface:rgt  = {ip = 10.3.1.130;}
 interface:lft  = {ip = 10.3.1.246;}
 interface:dst;
}
network:dst = { ip = 10.3.1.252/30;}

pathrestriction:a = interface:c1.lft, interface:k2.rgt;
pathrestriction:mng = interface:c1.mng, interface:c2.top;

protocol:IP = ip;

service:intra = {
 user = any:[network:dst], any:[network:top], any:[network:cnt];
 permit src = interface:c1.mng;
        dst = user;
        prt = protocol:IP;
}
END

$out = <<'END';
--c1
ip access-list extended Vlan13_in
 permit ip any host 10.3.1.249
 deny ip any any
--c2
ip access-list extended Ethernet4_in
 permit ip any host 10.3.1.249
 deny ip any any
--
ip access-list extended Ethernet5_in
 deny ip any host 10.1.1.2
 deny ip any host 10.3.1.129
 deny ip any host 10.3.1.242
 permit ip host 10.3.1.249 any
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Valid pathrestriction at unmanged router';
############################################################

$in = <<'END';
network:Test =  { ip = 10.9.1.0/24; }

router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; routing = manual; hardware = Vlan20; }
 interface:Trans1 = { ip = 10.5.6.1; hardware = VLAN1; routing = manual; }
}
router:filter2 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.2; routing = manual; hardware = Vlan20; }
 interface:Trans2 = { ip = 10.5.7.1; hardware = VLAN1; routing = manual; }
}
network:Trans1 = { ip = 10.5.6.0/24; }
network:Trans2 = { ip = 10.5.7.0/24; }

router:Kunde = {
 interface:Trans1 = { ip = 10.5.6.2; }
 interface:Trans2 = { ip = 10.5.7.2; }
}

pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;
END

test_err($title, $in, '');

############################################################
$title = 'Useless pathrestriction at unmanged router';
############################################################

$in =~ s/managed/#managed/;

$out = <<'END';
Warning: Useless pathrestriction:restrict.
 All interfaces are unmanaged and located inside the same security zone
END

test_err($title, $in, $out);

############################################################
done_testing;
