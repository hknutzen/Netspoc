#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, @out, $head, $compiled);

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
Error: Duplicate any:Trans2 and any:Trans1 in any:[network:Trans1]
END

eq_or_diff(compile_err($in), $out, $title);

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

eq_or_diff(compile_err($in), $out, $title);

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

eq_or_diff(compile_err($in), $out, $title);

############################################################

done_testing;
