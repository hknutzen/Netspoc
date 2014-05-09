#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Only one generic aggregate in zone cluster';
############################################################

$in = <<END;
network:Test =  { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan20; }
 interface:Trans1 = { ip = 10.5.6.1; hardware = VLAN1; }
}
router:filter2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.2; hardware = Vlan20; }
 interface:Trans2 = { ip = 10.5.7.1; hardware = VLAN1; }
}
network:Trans1 = { ip = 10.5.6.0/24; }
network:Trans2 = { ip = 10.5.7.0/24; }

router:Kunde = {
 interface:Trans1 = { ip = 10.5.6.2; }
 interface:Trans2 = { ip = 10.5.7.2; }
}

pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;

any:Trans1 = { link = network:Trans1; }
any:Trans2 = { link = network:Trans2; }
END

$out = <<END;
Error: Duplicate any:Trans1 and any:Trans2 in any:[network:Trans2]
END

test_err($title, $in, $out);

############################################################
$title = 'Inherit owner from all zones of zone cluster';
############################################################

$in = <<END;
network:Test =  { ip = 10.9.1.0/24; }

router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan20; }
 interface:Trans1 = { ip = 10.5.6.1; hardware = VLAN1; }
}
router:filter2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.2; hardware = Vlan20; }
 interface:Trans2 = { ip = 10.5.7.1; hardware = VLAN1; }
}
network:Trans1 = { ip = 10.5.6.0/24; }
network:Trans2 = { ip = 10.5.7.0/24; owner = t1;}

router:Kunde = {
 interface:Trans1 = { ip = 10.5.6.2; }
 interface:Trans2 = { ip = 10.5.7.2; }
}

pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;

owner:t1 = { admins = guest; }

any:Trans1 = { link = network:Trans1; owner = t1; }
END

$out = <<END;
Warning: Useless owner:t1 at network:Trans2,
 it was already inherited from any:[network:Trans2]
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate IP from NAT in zone';
############################################################

$in = <<END;
network:A = { ip = 10.3.3.120/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
network:B = { ip = 10.3.3.128/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}

router:ras = {
 interface:A = { ip = 10.3.3.121; }
 interface:B = { ip = 10.3.3.129; }
 interface:Trans = { ip = 10.1.1.2; bind_nat = C; }
}

network:Trans = { ip = 10.1.1.0/24;}

router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
}
END

$out = <<END;
Error: network:B and network:A have identical IP/mask inside any:[network:Trans]
END

test_err($title, $in, $out);

############################################################
$title = 'Ambiguous subnet relation from NAT in zone';
############################################################

$in = <<END;
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:B = { ip = 10.3.3.10; hardware = VLAN1; }
}

network:A = { ip = 10.3.3.0/24; has_subnets; }
network:B = { 
 ip = 10.3.3.8/29; 
 nat:C = { ip = 10.1.1.8/29; }
}

router:ras = {
 interface:A = { ip = 10.3.3.1; }
 interface:B = { ip = 10.3.3.9; }
 interface:Trans = { ip = 10.1.1.2; bind_nat = C; }
}

network:Trans = { ip = 10.1.1.0/24; has_subnets; }

router:filter2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
}
END

$out = <<END;
Error: Ambiguous subnet relation from NAT.
 network:B is subnet of network:Trans and network:A
END

test_err($title, $in, $out);

$in =~ s|\Qnat:C = { ip = 10.1.1.8/29; }\E|nat:C = { ip = 10.2.2.8/29; }|;

$out = <<END;
Error: Ambiguous subnet relation from NAT.
 network:B is subnet of network:A,
 but has no subnet relation in other NAT domain.
END

test_err($title, $in, $out);

############################################################
$title = 'No secondary optimization for network with subnet in other zone';
############################################################

$in = <<END;
network:A = { 
 ip = 10.3.3.0/25;
 host:h = { ip = 10.3.3.5; }
}
network:sub = { ip = 10.3.3.8/29; subnet_of = network:A; }

router:secondary = {
 managed = secondary;
 model = IOS_FW;
 routing = manual;
 interface:A = { ip = 10.3.3.1; hardware = VLAN1; }
 interface:sub = { ip = 10.3.3.9; hardware = VLAN9; }
 interface:Trans = { ip = 10.1.1.2; hardware = VLAN2; }
}

network:Trans = { ip = 10.1.1.0/24; }

router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; }
}

network:Customer = { ip = 10.9.9.0/24; }

service:test = {
 user = host:h;
 permit src = user; dst = network:Customer; prt = tcp 80;
}
END

$out = <<END;
--secondary
ip access-list extended VLAN1_in
 permit ip host 10.3.3.5 10.9.9.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################

done_testing;
