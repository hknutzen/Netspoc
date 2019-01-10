#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Implicit group of aggregates from zone cluster';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r3 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.2; }
}

pathrestriction:p = interface:r1.n2, interface:r3.n2;

service:s1 = {
 user = network:n1;

 # implicitly add any:[network:n2]
 permit src = user; dst = any:[network:n3]; prt = tcp 22;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 any4 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 any4 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'Inherit owner from all zones of zone cluster';
############################################################

$in = <<'END';
network:Test =  { ip = 10.9.1.0/24; }

router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.1; hardware = Test; }
 interface:Trans1 = { ip = 10.5.6.1; hardware = Trans1; }
}
router:filter2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:Test = { ip = 10.9.1.2; hardware = Test; }
 interface:Trans2 = { ip = 10.5.7.1; hardware = Trans2; }
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

$out = <<'END';
Warning: Useless owner:t1 at network:Trans2,
 it was already inherited from any:[network:Trans2]
END

test_warn($title, $in, $out);

############################################################
$title = 'Duplicate IP from NAT in zone';
############################################################
# Must only allow traffic from network:A, but not from network:B
# at filter1.

$in = <<'END';
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
 interface:Trans = { ip = 10.1.1.1; hardware = Trans; }
}

service:s1 = {
 user = network:A;
 permit src = user; dst = interface:filter1.Trans; prt = tcp 22;
}
END

$out = <<'END';
Error: network:B and network:A have identical IP/mask at interface:filter1.Trans
END

Test::More->builder->todo_start($title);
test_err($title, $in, $out);
Test::More->builder->todo_end;

############################################################
$title = 'No secondary optimization for network with subnet in other zone';
############################################################

$in = <<'END';
network:A = {
 ip = 10.3.3.0/25;
 host:h = { ip = 10.3.3.5; }
}
network:sub = { ip = 10.3.3.8/29; subnet_of = network:A; }

router:secondary = {
 managed = secondary;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip = 10.3.3.1; hardware = A; }
 interface:sub = { ip = 10.3.3.9; hardware = sub; }
 interface:Trans = { ip = 10.1.1.2; hardware = Trans; }
}

network:Trans = { ip = 10.1.1.0/24; }

router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.1.1.1; hardware = Trans; }
 interface:Customer = { ip = 10.9.9.1; hardware = Customer; }
}

network:Customer = { ip = 10.9.9.0/24; }

service:test = {
 user = network:Customer;
 permit src = user; dst = host:h; prt = tcp 80;
}
END

$out = <<'END';
--secondary
ip access-list extended Trans_in
 permit ip 10.9.9.0 0.0.0.255 host 10.3.3.5
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Skip supernet with subnet in other zone in secondary optimization';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:secondary = {
 model = IOS, FW;
 managed = secondary;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.1.8.1; hardware = t1; }
}
network:t1 = { ip = 10.1.8.0/24; }

router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.1.8.2; hardware = t1; }
 interface:t2 = { ip = 10.1.9.1; hardware = t2; }
}
network:t2 = { ip = 10.1.9.0/24;}
router:trahza01 = {
 interface:t2;
 interface:super;
 interface:sub1;
}
# Must not use super as supernet, because it has sub2 as subnet in other zone.
network:super = {
 has_subnets;
 ip = 192.168.0.0/16;
}
network:sub1 = { ip = 192.168.1.0/24;}
# Must not use aggregate as supernet.
any:a1 = { ip = 192.168.0.0/21; link = network:sub2; }

router:r3 = {
 managed;
 model = ASA;
 interface:t1 = {ip = 10.1.8.3; hardware = t1;}
 interface:sub2 = { ip = 192.168.8.1; hardware = sub2; }
}
network:sub2 = { ip = 192.168.8.0/24; }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:sub1; prt = tcp 49;
}
END

$out = <<'END';
--secondary
ip access-list extended n1_in
 permit ip 10.1.1.0 0.0.0.255 192.168.1.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Skip supernet with NAT in secondary optimization';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:secondary = {
 model = IOS, FW;
 managed = secondary;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; bind_nat = nat; }
 interface:t1 = { ip = 10.1.8.1; hardware = t1; }
}
network:t1 = { ip = 10.1.8.0/24; }

router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.1.8.2; hardware = t1; }
 interface:t2 = { ip = 10.1.9.1; hardware = t2; }
}
network:t2 = { ip = 10.1.9.0/24;}
router:trahza01 = {
 interface:t2;
 interface:super;
 interface:sub1;
}
network:super = {
 has_subnets;
 ip = 192.168.0.0/16;
 nat:nat = { hidden; }
}
network:sub1 = {
 ip = 192.168.1.0/24;
 nat:nat = { identity; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:sub1; prt = tcp 49;
}
END

$out = <<'END';
--secondary
ip access-list extended n1_in
 permit ip 10.1.1.0 0.0.0.255 192.168.1.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################

done_testing;
