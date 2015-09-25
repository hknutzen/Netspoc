#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
$title = 'Implicit aggregate over 3 networks';
############################################################

$topo = <<'END';
area:test = { border = interface:filter.Trans; }

network:A = { ip = 10.3.3.0/25; }
network:sub = { ip = 10.3.3.8/29; subnet_of = network:A; }
network:B = { ip = 10.3.3.128/25; }

router:ras = {
 interface:A = { ip = 10.3.3.1; }
 interface:sub = { ip = 10.3.3.9; }
 interface:B = { ip = 10.3.3.129; }
 interface:Trans = { ip = 10.1.1.2; }
}

network:Trans = { ip = 10.1.1.0/24; }

router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; }
}
network:Customer = { ip = 10.9.9.0/24; }
END

$in = $topo . <<'END';
service:test = {
 user = any:[ip=10.0.0.0/8 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
END

$out = <<'END';
--filter
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.0.0.0 0.255.255.255 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 81
 permit tcp 10.3.3.0 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 permit tcp 10.3.3.128 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Implicit aggregate over 2 networks';
############################################################

$in = $topo . <<'END';
service:test = {
 user = any:[ip=10.3.3.0/24 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
END

$out = <<'END';
--filter
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.3.3.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.3.3.0 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 permit tcp 10.3.3.128 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Implicit aggregate between 2 networks';
############################################################

$in = $topo . <<'END';
service:test1 = {
 user = any:[ip=10.3.3.0/26 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
service:test2 = {
 overlaps = service:test1;
 user = network:sub;
 permit src = user; dst = network:Customer; prt = tcp 81;
}
END

$out = <<'END';
--filter
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.3.3.0 0.0.0.63 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.3.3.8 0.0.0.7 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Check aggregate at unnumbered interface';
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { unnumbered; hardware = Vlan2; }
}

network:Trans = { unnumbered; }

router:filter2 = {
 managed;
 model = ASA;
 interface:Trans = { unnumbered; hardware = Vlan3; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan4; }
}
network:Kunde = { ip = 10.1.1.0/24; }

service:test = {
 user = any:[network:Kunde];
 permit src = user; dst = network:Test; prt = tcp 80;
}

# if any:trans is defined, a rule must be present.
any:Trans = { link = network:Trans; }
END

$out = <<'END';
Warning: Missing rule for supernet rule.
 permit src=any:[network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 can't be effective at interface:filter1.Trans.
 Tried any:Trans as src.
END

test_err($title, $in, $out);

############################################################
$title = 'Permit matching aggregate at non matching interface';
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { ip = 192.168.1.1; hardware = Vlan2; }
}

network:Trans = { ip = 192.168.1.0/29; }

router:filter2 = {
 managed;
 model = ASA;
 interface:Trans = { ip = 192.168.1.2; hardware = Vlan3; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan4; }
}
network:Kunde = { ip = 10.1.1.0/24; }

service:test = {
 user = any:[ip=10.0.0.0/8 & network:Kunde];
 permit src = user; dst = network:Test; prt = tcp 80;
}
END

$out = <<'END';
--filter1
access-list Vlan2_in extended permit tcp 10.0.0.0 255.0.0.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
--filter2
access-list Vlan4_in extended permit tcp 10.0.0.0 255.0.0.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan4_in extended deny ip any any
access-group Vlan4_in in interface Vlan4
END

test_run($title, $in, $out);

############################################################
$title = 'Warn on missing src aggregate';
############################################################

$in .= <<'END';
router:T = {
 interface:Trans = { ip = 192.168.1.3; }
 interface:N1; 
}

network:N1 = { ip = 10.192.0.0/24; }
END

$out = <<'END';
Warning: Missing rule for supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 can't be effective at interface:filter1.Trans.
 Tried network:N1 as src.
END

test_err($title, $in, $out);

############################################################
$title = 'Loop with no_in_acl and in_zone eq no_in_zone';
############################################################

$in = <<'END';
network:Test = { ip = 10.1.0.0/16; }

router:u = {
 interface:Test;
 interface:Trans1;
 interface:Trans2;
}

network:Trans1 = { ip = 192.168.1.0/29; }
network:Trans2 = { ip = 192.168.2.0/29; }

router:filter = {
 managed;
 model = ASA;
 routing = manual;
 interface:Trans1 = { ip = 192.168.1.2; hardware = Vlan4; no_in_acl; }
 interface:Trans2 = { ip = 192.168.2.2; hardware = Vlan5; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan6; }
 interface:sub = { ip = 10.1.1.33; hardware = Vlan7; }
}
network:Kunde = { ip = 10.1.1.0/24; subnet_of = network:Test; }
network:sub = { ip = 10.1.1.32/29; subnet_of = network:Kunde; }

service:test = {
 user = any:[network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
END

$out = <<'END';
--filter
access-list Vlan5_in extended permit tcp any 10.1.1.0 255.255.255.0 eq 80
access-list Vlan5_in extended deny ip any any
access-group Vlan5_in in interface Vlan5
--filter
access-list Vlan6_out extended permit tcp any 10.1.1.0 255.255.255.0 eq 80
access-list Vlan6_out extended deny ip any any
access-group Vlan6_out out interface Vlan6
END

test_run($title, $in, $out);

############################################################
$title = 'Nested aggregates';
############################################################

$in = <<'END';

network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { unnumbered; hardware = Vlan2; }
}

network:Trans = { unnumbered; }

router:u = {
 interface:Trans;
 interface:Kunde1;
 interface:Kunde2;
 interface:Kunde3;
}
network:Kunde1 = { ip = 10.1.1.0/24; }
network:Kunde2 = { ip = 10.1.2.0/24; }
network:Kunde3 = { ip = 10.1.3.0/24; }

service:test1 = {
 user = any:[ip=10.1.0.0/23 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 80;
}

service:test2 = {
 user = any:[ip=10.1.0.0/22 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 81;
}
END

$out = <<'END';
--filter
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.254.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.252.0 10.9.1.0 255.255.255.0 eq 81
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Redundant nested aggregates';
############################################################

$in .= <<'END';
service:test3 = {
 user = any:[ip=10.1.0.0/16 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:test1 compared to service:test3:
  permit src=any:[ip=10.1.0.0/23 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test1
< permit src=any:[ip=10.1.0.0/16 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test3
END

test_err($title, $in, $out);

############################################################
$title = 'Prevent nondeterminism in nested aggregates';
############################################################

# /23 aggregates must be processed in fixed order.
# Otherwise network:[any:[ip=10.1.0.0/17..] would be nondeterministic.

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { unnumbered; hardware = Vlan2; }
}

network:Trans = { unnumbered; }

router:u = {
 interface:Trans;
 interface:Kunde1;
 interface:Kunde2;
}
network:Kunde1 = { ip = 10.1.0.0/24; }
network:Kunde2 = { ip = 10.1.2.0/24; }

service:test1a = {
 user = network:[any:[ip=10.1.0.0/23 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 80;
}
service:test1b = {
 user = network:[any:[ip=10.1.2.0/23 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 81;
}
service:test2 = {
 user = network:[any:[ip=10.1.0.0/17 & network:Trans]];
 permit src = user; dst = network:Test; prt = tcp 82;
}
END

$out = <<'END';
--filter
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.255.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.255.0 10.9.1.0 255.255.255.0 eq 82
access-list Vlan2_in extended permit tcp 10.1.2.0 255.255.255.0 10.9.1.0 255.255.255.0 range 81 82
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Redundant nested aggregates without matching network (1)';
############################################################

# Larger aggregate is inserted first.
$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}

network:Kunde = { ip = 10.1.1.0/24; }

service:test = {
 user = any:[ip=10.1.0.0/16 & network:Test],
        any:[ip=10.1.0.0/17 & network:Test],
        ;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:test compared to service:test:
  permit src=any:[ip=10.1.0.0/17 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip=10.1.0.0/16 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Redundant nested aggregates without matching network (2)';
############################################################

# Small aggregate is inserted first.
$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}

network:Kunde = { ip = 10.1.1.0/24; }

service:test = {
 user = any:[ip=10.1.0.0/17 & network:Test],
        any:[ip=10.1.0.0/16 & network:Test],
        ;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:test compared to service:test:
  permit src=any:[ip=10.1.0.0/17 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip=10.1.0.0/16 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Redundant matching aggregates as subnet of network';
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}

network:Kunde = { ip = 10.1.1.0/24; }

service:test1 = {
 user = any:[ip=10.9.1.0/26 & network:Test],
        network:Test;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}

service:test2 = {
 user = any:[ip=10.9.1.0/25 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:test1 compared to service:test1:
  permit src=any:[ip=10.9.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=network:Test; dst=network:Kunde; prt=tcp 80; of service:test1
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=any:[ip=10.9.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip=10.9.1.0/25 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
Warning: Redundant rules in service:test2 compared to service:test1:
  permit src=any:[ip=10.9.1.0/25 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
< permit src=network:Test; dst=network:Kunde; prt=tcp 80; of service:test1
END

test_err($title, $in, $out);

############################################################
$title = 'Mixed redundant matching aggregates';
############################################################

# Check for sub aggregate, even if sub-network was found
$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}

network:Kunde = { ip = 10.1.1.0/24; }

service:test1 = {
 user = any:[ip=10.1.1.0/26 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}

service:test2 = {
 user = any:[ip=10.0.0.0/8 & network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=any:[ip=10.1.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip=10.0.0.0/8 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
END

test_err($title, $in, $out);

############################################################
$title = 'Mixed implicit and explicit aggregates';
############################################################

$in = <<'END';
any:10_0_0_0    = { ip = 10.0.0.0/8;    link = network:Test; }
any:10_253_0_0  = { ip = 10.253.0.0/16; link = network:Test; }
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}

network:Kunde = { ip = 10.1.1.0/24; }

service:test1 = {
 user = any:[network:Test];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
END

$out = <<'END';
--filter
access-list Vlan1_in extended permit tcp any 10.1.1.0 255.255.255.0 eq 80
access-list Vlan1_in extended deny ip any any
access-group Vlan1_in in interface Vlan1
END

test_run($title, $in, $out);

############################################################
$title = 'Matching aggregate of implicit aggregate';
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan2; }
}

network:Kunde = { ip = 10.1.1.0/24; }

service:test = {
 user = any:[ip=10.1.0.0/16 & any:[network:Test]];
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
END

$out = <<'END';
--filter
access-list Vlan1_in extended permit tcp 10.1.0.0 255.255.0.0 10.1.1.0 255.255.255.0 eq 80
access-list Vlan1_in extended deny ip any any
access-group Vlan1_in in interface Vlan1
END

test_run($title, $in, $out);

############################################################
$title = 'Aggregate of loopback interface';
############################################################

$topo = <<'END';
network:Trans = { ip = 10.1.1.0/24; }

router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:loop = { ip = 10.7.7.7; loopback; hardware = lo1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; }
}
network:Customer = { ip = 10.9.9.0/24; }
END

$in = $topo . <<'END';
service:test = {
 user = any:[interface:filter.[all]];
 permit src = network:Customer; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--filter
ip access-list extended VLAN2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.7.7.7
 deny ip any host 10.9.9.1
 permit tcp 10.9.9.0 0.0.0.255 any eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Remove loopback network from aggregate';
############################################################

$in = $topo . <<'END';
service:test = {
 user = network:[interface:filter.[all]];
 permit src = network:Customer; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--filter
ip access-list extended VLAN2_in
 deny ip any host 10.1.1.1
 permit tcp 10.9.9.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple missing destination aggregates at one router';
############################################################

$topo = <<'END';
network:Customer = { ip = 10.9.9.0/24; }

router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN9; }
 interface:trans = { ip = 10.7.7.1; hardware = VLAN7; }
 interface:loop = { ip = 10.7.8.1; loopback; hardware = Lo1; }
}

network:trans = { ip = 10.7.7.0/24; }

router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.7.7.2; hardware = VLAN77; }
 interface:n1 = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:n2 = { ip = 10.1.2.1; hardware = VLAN2; }
 interface:n3 = { ip = 10.1.3.1; hardware = VLAN3; }
 interface:n4 = { ip = 10.1.4.1; hardware = VLAN4; }
 interface:n128 = { ip = 10.128.1.1; hardware = VLAN128; }
}

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n128 = { ip = 10.128.1.0/24; }
END

$in = $topo . <<'END';
service:test = {
 user = #network:trans,
        any:[ip=10.0.0.0/9 & network:n1],
        #any:[ip=10.1.0.0/17 & network:n2],
        #network:n3,
        #any:[ip=10.1.0.0/16 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
END

$out = <<'END';
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can't be effective at interface:r1.Customer.
 Tried network:trans as dst.
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can't be effective at interface:r2.trans.
 Tried network:n2 as dst.
END

test_err($title, $in, $out);

############################################################
$title = 'Multiple missing destination networks';
############################################################

$in = $topo . <<'END';
router:u = {
 interface:n2;
 interface:n2x;
}
network:n2x = { ip = 10.2.2.0/24; }

service:test = {
 user = network:trans,
        any:[ip=10.0.0.0/9 & network:n1],
        #any:[ip=10.1.0.0/17 & network:n2],
        network:n3,
        any:[ip=10.1.0.0/16 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
END

$out = <<'END';
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can't be effective at interface:r2.trans.
 No supernet available for network:n2, network:n2x as dst.
END

test_err($title, $in, $out);

############################################################
$title = 'Multiple destination aggregates';
############################################################

$in = $topo . <<'END';
service:test = {
 user = network:trans,
        any:[ip=10.0.0.0/9 & network:n1],
        any:[ip=10.0.0.0/9 & network:n2],
        network:n3,
        any:[ip=10.0.0.0/9 & network:n4],
        # network:n128 doesn't match
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
END

$out = <<'END';
--r1
ip access-list extended VLAN9_in
 deny ip any host 10.9.9.1
 deny ip any host 10.7.7.1
 deny ip any host 10.7.8.1
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
--r2
ip access-list extended VLAN77_in
 deny ip any host 10.7.7.2
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Check destination aggregate with no_in_acl';
############################################################

# Wir wissen nicht, welches der beiden Aggregate genommen wird,
# wegen der Optimierung in check_supernet_dst_collections.
# Aber dennoch wird korrekt geprüft.
# Wenn n1, dann ohne Prüfung, da an allen anderen Interfaces eine out_acl.
# Wenn n2, dann erfolgreiche Prüfung auf n1.
($in = $topo) =~ s/VLAN1;/VLAN1; no_in_acl;/g;

$in .= <<'END';
service:test = {
 user = network:trans,
        any:[ip=10.0.0.0/9 & network:n1],
        any:[ip=10.0.0.0/9 & network:n2],
        #network:n3,
        #any:[ip=10.1.0.0/16 & network:n4],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
END

$out = <<'END';
--r2
ip access-list extended VLAN77_in
 deny ip any host 10.7.7.2
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
--r2
ip access-list extended VLAN1_in
 deny ip any host 10.7.7.2
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 deny ip any host 10.128.1.1
 permit ip any any
--r2
ip access-list extended VLAN2_out
 permit ip 10.9.9.0 0.0.0.255 10.0.0.0 0.127.255.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Check missing intermediate aggregate for Linux';
############################################################

# Linux only checks for missing intermediate aggregates,
# because filter is attached to pair of incoming and outgoing interface.
($in = $topo) =~ s/IOS, FW/Linux/g;

$in .= <<'END';
service:test = {
 user = #network:trans,
        any:[ip=10.0.0.0/9 & network:n1],
        ;
 permit src = network:Customer; dst = user; prt = ip;
}
END

$out = <<'END';
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can't be effective at interface:r1.Customer.
 Tried network:trans as dst.
END

test_err($title, $in, $out);

############################################################
$title = 'No destination aggregate needed for Linux';
############################################################

# Linux only hecks for mising intermediate aggregates,
# because filter is attached to pair of incoming and outgoing interface.
$in =~ s/#network:trans/network:trans/g;

$out = <<'END';
--r2
:VLAN77_self -
-A INPUT -j VLAN77_self -i VLAN77
:VLAN77_VLAN1 -
-A VLAN77_VLAN1 -j ACCEPT -s 10.9.9.0/24 -d 10.0.0.0/9
-A FORWARD -j VLAN77_VLAN1 -i VLAN77 -o VLAN1
END

test_run($title, $in, $out);

############################################################
$title = 'Missing destination aggregate with loopback';
############################################################

$in = <<'END';
network:Customer = { ip = 10.9.9.0/24; }

router:r = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN9; }
 interface:n1 = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:n2 = { ip = 10.1.2.1; hardware = VLAN2; }
}

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:u = {
 interface:n2;
 interface:l = { ip = 10.2.2.2; loopback; }
}

service:test = {
 user = any:[network:n1];
 permit src = network:Customer; dst = user; prt = tcp 80;
}
END

$out = <<'END';
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[network:n1]; prt=tcp 80; of service:test
 can't be effective at interface:r.Customer.
 No supernet available for network:n2, interface:u.l as dst.
END

test_err($title, $in, $out);

############################################################
$title = 'Supernet used as aggregate';
############################################################

$in = <<'END';
network:intern = { ip = 10.1.1.0/24; }

router:asa = {
 model = ASA, 8.4;
 managed;
 interface:intern = {
  ip = 10.1.1.101; 
  hardware = inside;
 }
 interface:dmz = { 
  ip = 1.2.3.2; 
  hardware = outside;
 }
}

area:internet = { border = interface:asa.dmz; }

network:dmz = { ip = 1.2.3.0/25; }

router:extern = { 
 interface:dmz = { ip = 1.2.3.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

service:test = {
 user = network:intern;
 permit src = user; dst = network:[area:internet]; prt = tcp 80;
}
END

$out = <<'END';
--asa
! [ ACL ]
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 any eq 80
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = 'Aggregate linked to non-network';
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:Trans = { unnumbered; hardware = Vlan2; }
}

network:Trans = { unnumbered; }

router:filter2 = {
 managed;
 model = ASA;
 interface:Trans = { unnumbered; hardware = Vlan3; }
 interface:Kunde = { ip = 10.1.1.1; hardware = Vlan4; }
}
network:Kunde = { ip = 10.1.1.0/24; }

any:Trans = { link = router:filter2; }
END

$out = <<'END';
Error: any:Trans must not be linked to router:filter2
END

test_err($title, $in, $out);

############################################################
done_testing;
