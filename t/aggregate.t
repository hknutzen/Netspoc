#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

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

############################################################
$title = 'Implicit aggregate over 3 networks';
############################################################

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
$title = 'Multiple implicit aggregates';
############################################################

$in = <<'END';
network:Test =  { ip = 10.9.1.0/24; }
router:filter1 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Test = { ip = 10.9.1.1; hardware = Vlan20; }
  interface:Trans1 = { ip = 10.3.6.1; hardware = VLAN1; }
}
router:filter2 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Test = { ip = 10.9.1.2; hardware = Vlan20; }
  interface:Trans2 = { ip = 10.5.7.1; hardware = VLAN1; }
}
network:Trans1 = { ip = 10.3.6.0/24; }
network:Trans2 = { ip = 10.5.7.0/24; }

router:Kunde = {
  interface:Trans1 = { ip = 10.3.6.2; }
  interface:Trans2 = { ip = 10.5.7.2; }
  interface:Trans3 = { ip = 10.5.8.1; }
}

network:Trans3 = { ip = 10.5.8.0/24; }

router:r2 = {
  managed;
  model = ASA;
  routing = manual;
  interface:Trans3 = { ip = 10.5.8.2; hardware = Vlan20; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }

pathrestriction:restrict = interface:Kunde.Trans1, interface:Kunde.Trans2;

service:t1 = {
  user = any:[ip=10.0.0.0/12 & network:n2],
         any:[ip=10.0.0.0/13 & network:Trans1],
         any:[ip=10.0.0.0/13 & network:Trans2],
  ;
  permit src = user; dst = network:Test; prt = tcp 81;
}
service:t2 = {
  user = any:[ip=10.0.0.0/14 & network:n2],
         any:[ip=10.0.0.0/14 & network:Trans1],
         network:Trans2,
  ;
  permit src = user; dst = network:Test; prt = tcp 82;
}
END

# Warning is sub optimal.
# Netspoc doesn't show original aggregate names.
$out = <<"END";
Warning: Duplicate elements in user of service:t1:
 any:[ip=10.0.0.0/13 & network:Trans1]
 any:[ip=10.0.0.0/13 & network:Trans1]
 any:[ip=10.0.0.0/13 & network:Trans1]
-- filter1
! VLAN1_in
access-list VLAN1_in extended permit tcp 10.0.0.0 255.240.0.0 10.9.1.0 255.255.255.0 eq 81
access-list VLAN1_in extended permit tcp 10.0.0.0 255.252.0.0 10.9.1.0 255.255.255.0 eq 82
access-list VLAN1_in extended deny ip any any
access-group VLAN1_in in interface VLAN1
-- filter2
! VLAN1_in
object-group network g0
 network-object 10.0.0.0 255.252.0.0
 network-object 10.5.7.0 255.255.255.0
access-list VLAN1_in extended permit tcp 10.0.0.0 255.240.0.0 10.9.1.0 255.255.255.0 eq 81
access-list VLAN1_in extended permit tcp object-group g0 10.9.1.0 255.255.255.0 eq 82
access-list VLAN1_in extended deny ip any any
access-group VLAN1_in in interface VLAN1
-- r2
! n2_in
access-list n2_in extended permit tcp 10.0.0.0 255.240.0.0 10.9.1.0 255.255.255.0 eq 81
access-list n2_in extended permit tcp 10.0.0.0 255.252.0.0 10.9.1.0 255.255.255.0 eq 82
access-list n2_in extended deny ip any any
access-group n2_in in interface n2
END

test_warn($title, $in, $out);

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

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=any:[network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 can\'t be effective at interface:filter1.Trans.
 Tried any:Trans as src.
END

test_warn($title, $in, $out);

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

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 can\'t be effective at interface:filter1.Trans.
 Tried network:N1 as src.
END

test_warn($title, $in, $out);

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

test_warn($title, $in, $out);

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

test_warn($title, $in, $out);

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

test_warn($title, $in, $out);

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

test_warn($title, $in, $out);

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

test_warn($title, $in, $out);

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
 user = any:[interface:filter.[all]] &! any:[network:Customer];
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
 user = network:[interface:filter.[all]] &! network:Customer;
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

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can\'t be effective at interface:r1.Customer.
 Tried network:trans as dst.
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can\'t be effective at interface:r2.trans.
 Tried network:n2 as dst.
END

test_warn($title, $in, $out);

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

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can\'t be effective at interface:r2.trans.
 No supernet available for network:n2, network:n2x as dst.
END

test_warn($title, $in, $out);

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

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[ip=10.0.0.0/9 & network:n1]; prt=ip; of service:test
 can\'t be effective at interface:r1.Customer.
 Tried network:trans as dst.
END

test_warn($title, $in, $out);

############################################################
$title = 'No destination aggregate needed for Linux';
############################################################

# Linux only checks for missing intermediate aggregates,
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

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=network:Customer; dst=any:[network:n1]; prt=tcp 80; of service:test
 can\'t be effective at interface:r.Customer.
 No supernet available for network:n2, interface:u.l as dst.
END

test_warn($title, $in, $out);

############################################################
$title = 'Check aggregate that is subnet of other network';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:trans = { ip = 10.3.1.17; hardware = trans; }
 interface:sub-27 = { ip = 10.1.2.33; hardware = sub-27; }
}
network:sub-27 = { ip = 10.1.2.32/27; subnet_of = network:n2; }

network:trans = { ip = 10.3.1.16/30; }

router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.3.1.18; hardware = trans; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:u = {
 interface:n2;
 interface:sub-29;
}

any:sub-28 =     { ip = 10.1.2.48/28; link = network:n2; }
network:sub-29 = { ip = 10.1.2.48/29; subnet_of = network:sub-27; }

# Warning is shown, because some addresses of any:sub-28 are located
# inside network:sub-27.
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:sub-28; prt = tcp 80;
}

# No warning, because we know, that addresses of network:sub-29
# are located behind router:r2 and not inside network:sub-27.
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:sub-29; prt = tcp 81;
}
END

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=network:n1; dst=any:sub-28; prt=tcp 80; of service:s1
 can\'t be effective at interface:r1.n1.
 Tried network:sub-27 as dst.
END

test_warn($title, $in, $out);

############################################################
$title = 'Don\'t check aggregate that is subnet of network in same zone';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:trans = { ip = 10.3.1.17; hardware = trans; }
 interface:sub-27 = { ip = 10.1.2.33; hardware = sub-27; }
}
network:sub-27 = { ip = 10.1.2.32/27; subnet_of = network:n2; }

network:trans = { ip = 10.3.1.16/30; }

router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.3.1.18; hardware = trans; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:u = {
 interface:n2;
 interface:sub-28;
}

network:sub-28 = { ip = 10.1.2.48/28; subnet_of = network:sub-27; }
any:sub-29 =     { ip = 10.1.2.48/29; link = network:n2; }

# No warning, because we know, that addresses of any:sub-29
# are located inside network:sub-28 and not inside network:sub-27.
service:s1 = {
 user = network:n1;
 permit src = user; dst = any:sub-29; prt = tcp 80;
}
END

$out = <<"END";
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing destination aggregates in loop';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.7.1.1; hardware = t1; }
 interface:t2 = { ip = 10.7.2.1; hardware = t2; }
}

network:t1 = { ip = 10.7.1.0/24; }
network:t2 = { ip = 10.7.2.0/24; }

router:u = {
 interface:t1;
 interface:t3;
 interface:t2;
 interface:t4;
}

network:t3 = { ip = 10.7.3.0/24; }
network:t4 = { ip = 10.7.4.0/24; }

router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t3 = { ip = 10.7.3.2; hardware = t3; }
 interface:t4 = { ip = 10.7.4.2; hardware = t4; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

pathrestriction:p1 =
 interface:r1.t2,
 interface:u.t4,
;

pathrestriction:p2 =
 interface:u.t1,
 interface:r2.t3,
;

service:test = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = udp 123;
}
END

# TODO:
# First warning should show missing networks t1, t2, t3 and t4.
$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=network:n1; dst=any:[network:n2]; prt=udp 123; of service:test
 can\'t be effective at interface:r1.n1.
 Tried network:t1 as dst.
Warning: Missing rule for supernet rule.
 permit src=network:n1; dst=any:[network:n2]; prt=udp 123; of service:test
 can\'t be effective at interface:r2.t4.
 Tried network:n3 as dst.
Warning: Missing rule for supernet rule.
 permit src=network:n1; dst=any:[network:n2]; prt=udp 123; of service:test
 can\'t be effective at interface:r2.t3.
 Tried network:n3 as dst.
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing aggregate from unmanaged interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

router:u = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.1; }
}

router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}

pathrestriction:p = interface:u.n2, interface:r2.n4;

service:s1 = {
 user = interface:u.n2;
 permit src = user; dst = any:[network:n1]; prt = tcp 22;
}

service:s2 = {
 user = interface:u.n3;
 permit src = user; dst = any:[network:n1]; prt = tcp 23;
}
END

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=interface:u.n3; dst=any:[network:n1]; prt=tcp 23; of service:s2
 can\'t be effective at interface:r3.n3.
 Tried network:n4 as dst.
--r1
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit tcp host 10.1.2.2 any eq 22
 permit tcp host 10.1.3.1 any eq 23
 deny ip any any
--r2
ip access-list extended n4_in
 deny ip any host 10.1.1.2
 deny ip any host 10.1.4.1
 permit tcp host 10.1.3.1 any eq 23
 deny ip any any
--r3
ip access-list extended n3_in
 deny ip any host 10.1.3.2
 deny ip any host 10.1.4.2
 permit tcp host 10.1.3.1 any eq 23
 deny ip any any
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing aggregate at destination interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ];
 permit src = user; dst = interface:r2.n3; prt = udp 123;
}
END

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=interface:r2.n3; prt=udp 123; of service:test
 can't be effective at interface:r2.n3.
 Tried network:n3 as src.
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing aggregates for reverse rule';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS; #1
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:trans = { ip = 10.7.7.1; hardware = trans; }
 interface:loop = { ip = 10.7.8.1; loopback; hardware = Lo1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:trans = { ip = 10.7.7.0/24; }

router:r2 = {
 managed;
 model = IOS; #2
 routing = manual;
 interface:trans = { ip = 10.7.7.2; hardware = trans; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ],
        network:trans,
 ;
 permit src = user; dst = network:n4; prt = udp 123;
}
END

$out = <<"END";
Warning: Missing rule for reversed supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 can\'t be effective at interface:r1.n2.
 Tried network:n2 as src.
Warning: Missing rule for reversed supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 can\'t be effective at interface:r2.n3.
 Tried network:n3 as src.
END

test_warn($title, $in, $out);

############################################################
$title = 'Effect of stateful router in reversed direction';
############################################################
# router:r1 sees only reply packets filtered by stateful router:r2
# Hence no warning is shown.

$in =~ s/; [#]2/, FW;/;
$out = <<'END';
--r1
! [ ACL ]
ip access-list extended n1_in
 permit udp 10.0.0.0 0.255.255.255 10.1.4.0 0.0.0.255 eq 123
 deny ip any any
--
ip access-list extended trans_in
 deny ip any host 10.1.1.1
 deny ip any host 10.7.7.1
 deny ip any host 10.7.8.1
 deny ip any host 10.1.2.1
 permit udp 10.1.4.0 0.0.0.255 eq 123 10.0.0.0 0.255.255.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No effect of stateful router in forward direction';
############################################################

$in =~ s/, FW//;
$in =~ s/; [#]1/, FW;/;

$out = <<"END";
Warning: Missing rule for reversed supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=network:n4; prt=udp 123; of service:test
 can\'t be effective at interface:r2.n3.
 Tried network:n3 as src.
END

test_warn($title, $in, $out);

############################################################
$title = 'Managed router will not exploit reverse rule';
############################################################

# Reverse rule at router:r1 would allow router:r2 to access network:n2.
# But since r2 is managed, we assume it will not exploit this permission.
# Hence no warning is printed.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed = secondary;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ],
        network:n3,
 ;
 permit src = user; dst = interface:r2.n3; prt = udp 123;
}
END

$out = <<"END";
-- r1
ip access-list extended n3_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 permit udp host 10.1.3.2 eq 123 10.0.0.0 0.255.255.255
 deny ip any any
-- r2
ip access-list extended n3_in
 permit udp 10.0.0.0 0.255.255.255 host 10.1.3.2 eq 123
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Supernet rule to pathrestricted interface and no_in_acl';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; no_in_acl; }
}

router:u = {
 interface:n2 = { ip = 10.1.2.3; }
}

pathrestriction:p =
 interface:r1.n2,
 interface:u.n2,
;

service:test = {
 user = any:[ network:n1 ];
 permit src = user; dst = interface:u.n2; prt = udp 123;
}
END

$out = <<"END";
Warning: Missing rule for supernet rule.
 permit src=any:[network:n1]; dst=interface:u.n2; prt=udp 123; of service:test
 can't be effective at interface:r3.n4.
 Tried network:n4 as src.
Warning: Missing rule for supernet rule.
 permit src=any:[network:n1]; dst=interface:u.n2; prt=udp 123; of service:test
 can't be effective at interface:r3.n3.
 Tried network:n3 as src.
Warning: Missing rule for reversed supernet rule.
 permit src=any:[network:n1]; dst=interface:u.n2; prt=udp 123; of service:test
 can't be effective at interface:r2.n3.
 Tried network:n3 as src.
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing aggregate for reverse rule in loop';
############################################################

# Don't find network:t1 and network:t2 as missing,
# because both are located in same zone_cluster as dst.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.7.1.1; hardware = t1; }
 interface:t2 = { ip = 10.7.2.1; hardware = t2; }
}

network:t1 = { ip = 10.7.1.0/24; }
network:t2 = { ip = 10.7.2.0/24; }

# router:u is split internally and hence interface:u.n4
# no longer has pathrestriction.
# We have this extra test case for this special situation.
router:u = {
 interface:t1;
 interface:t2;
 interface:n3;
 interface:n4 = { ip = 10.1.4.1; }
}

network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

pathrestriction:p =
 interface:r.t2,
 interface:u.n4,
;

service:test = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ];
 permit src = user; dst = interface:u.n4; prt = udp 123;
}
END

$out = <<"END";
Warning: Missing rule for reversed supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:n1]; dst=interface:u.n4; prt=udp 123; of service:test
 can\'t be effective at interface:r.n2.
 Tried network:n2 as src.
END

test_warn($title, $in, $out);

############################################################
$title = 'Suppress warning about missing aggregate rule';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:sub = { ip = 10.1.1.128/25; subnet_of = network:n1;
# host:h = { ip = 10.1.1.130; }
}

router:u = {
 interface:n1;
 interface:sub;
 interface:t;
}

network:t = { ip = 10.9.2.0/24; }

any:t = {
 link = network:t;
 no_check_supernet_rules;
}

network:n2 = { ip = 10.1.2.0/24; }

router:filter = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:t = { ip = 10.9.2.1; hardware = t; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }

service:s = {
 user = any:[ ip = 10.1.0.0/16 & network:n2 ];
 permit src = network:n3; dst = user; prt = tcp 80;
}
END

$out = <<"END";
END

test_warn($title, $in, $out);

############################################################
$title = 'Must not use no_check_supernet_rules with hosts';
############################################################

$in =~ s/# host:h/ host:h/;

$out = <<"END";
Error: Must not use attribute 'no_check_supernet_rules' at any:[network:t]
 with networks having host definitions:
 - network:sub
END

test_err($title, $in, $out);

############################################################
$title = 'Missing transient rule with multiple protocols';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = any:[network:n2]; prt = icmp 3, tcp 81-85;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = host:h3; prt = icmp 4/4, tcp 80-90;
}
END

$out = <<'END';
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - network:n1
 or add missing dst elements to service:s1:
 - host:h3
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing transient rule with managed interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
}

service:s1 = {
 user = host:h1;
 permit src = user; dst = any:[network:n2]; prt = proto 50;
}
service:s2 = {
 user = interface:r2.n2;
 permit src = any:[user]; dst = user; prt = proto 50;
}
END

$out = <<'END';
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at any:[network:n2].
 Add missing src elements to service:s2:
 - host:h1
 or add missing dst elements to service:s1:
 - interface:r2.n2
END

test_warn($title, $in, $out);

############################################################
$title = 'Missing transient rule with subnet in aggregate';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.3; }
 host:h2 = { ip = 10.1.1.5; }
 host:h3 = { ip = 10.1.1.7; }
 host:h4 = { ip = 10.1.1.9; }
 host:h5 = { ip = 10.1.1.11; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n4sub = { ip = 10.1.4.32/27; subnet_of = network:n4; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:u1 = {
 interface:n2 = { ip = 10.1.2.3; }
 interface:n4;
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; }
}

router:u2 = {
 interface:n3 = { ip = 10.1.3.3; }
 interface:n4sub;
}

service:s1 = {
 user = host:h1, host:h2, host:h3, host:h4, host:h5;
 permit src = user; dst = network:n4; prt = ip;
}
service:s2 = {
 user = any:[ip=10.0.0.0/8 & network:n2], any:[network:n3];
 permit src = user; dst = user; prt = udp;
}

service:s3 = {
 user = network:n4sub;
 permit src = user; dst = any:[ip=10.1.1.0/25 & network:n2]; prt = icmp 4/4, icmp 3;
}

service:s4 = {
 user = network:n4;
 permit src = user; dst = network:n1; prt = icmp 3/13, icmp 4/5;
}
END

# Show matching subnet of dst aggregate.
$out = <<'END';
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s2,
 matching at network:n4, any:[ip=10.0.0.0/8 & network:n2].
 Add missing src elements to service:s2:
 - host:h1
 - host:h2
 - host:h3
 - ...
 or add missing dst elements to service:s1:
 - network:n4sub
Warning: Missing transient supernet rules
 between src of service:s3 and dst of service:s4,
 matching at any:[ip=10.1.1.0/25 & network:n2], network:n4.
 Add missing src elements to service:s4:
 - network:n4sub
 or add missing dst elements to service:s3:
 - network:n1
END

test_warn($title, $in, $out);

############################################################
$title = 'Transient rule together with "foreach"';
############################################################
# Transient rule is not found, because rule with "foreach" is split
# into multiple rules internally.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:tr = { ip = 10.9.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:tr = { ip = 10.9.1.1; hardware = tr; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:tr = { ip = 10.9.1.2; hardware = tr; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

area:a1 = { anchor = network:tr;}

protocol:oneway_IP = ip, oneway;

# Allow unfiltered communication,
# but check src IP of each incoming network:n_i.
service:s1 = {
 user = foreach
        any:[network:tr],
	network:[area:a1] & ! network:tr;

 permit src = user;
	dst = any:[area:a1] &! any:[user];
	prt = protocol:oneway_IP;
}
END

$out = <<'END';
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s1,
 matching at any:[network:tr].
 Add missing src elements to service:s1:
 - network:n1
 or add missing dst elements to service:s1:
 - any:[network:n1]
Warning: Missing transient supernet rules
 between src of service:s1 and dst of service:s1,
 matching at any:[network:tr].
 Add missing src elements to service:s1:
 - network:n2
 or add missing dst elements to service:s1:
 - any:[network:n2]
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 any
access-list n1_in extended deny ip any any
access-group n1_in in interface n1
--
! tr_in
access-list tr_in extended permit ip any any
access-group tr_in in interface tr
-- r2
! tr_in
access-list tr_in extended permit ip any any
access-group tr_in in interface tr
--
! n2_in
access-list n2_in extended permit ip 10.1.2.0 255.255.255.0 any
access-list n2_in extended deny ip any any
access-group n2_in in interface n2
END

test_warn($title, $in, $out);

############################################################
$title = 'No missing transient rule with src/dst in subnet relation';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
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
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = any:[network:n2],
              any:[network:n3],
              ;
        prt = tcp 80;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user;
        dst = network:n3;
        prt = tcp 80;
}

service:s3 = {
 user = host:h1;
 permit src = user;
        dst = any:[network:n2],
              ;
        prt = tcp 81;
}
service:s4 = {
 user = any:[network:n2], network:n1;
 permit src = user;
        dst = network:n3;
        prt = tcp 81 - 89;
}

END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'No missing transient rule for src and dst in same zone';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

service:s1 = {
 user = any:[network:n2];
 permit src = network:n1; dst = user; prt = udp 123;
}

service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n1; prt = udp 100-200;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit udp 10.1.1.0 0.0.0.255 any eq 123
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 permit udp any 10.1.1.0 0.0.0.255 range 100 200
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No missing transient rule for leaf zone';
############################################################
# A leaf security zone has only one connection.
# It can't lead to unwanted rule chains.

$in = <<'END';
router:r0 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

network:n2 = { ip = 10.1.2.0/24; }

network:n3 = { ip = 10.1.3.0/24; }

service:s1 = {
 user = network:n2;
 permit src = user; dst = any:[network:n1]; prt = tcp 80;
}

service:s2 = {
 user = any:[network:n1];
 permit src = user; dst = network:n3; prt = tcp;
}
END

$out = <<'END';
--r1
# [ ACL ]
:n1_self -
-A INPUT -j n1_self -i n1
:n1_n3 -
-A n1_n3 -j ACCEPT -d 10.1.3.0/24 -p tcp
-A FORWARD -j n1_n3 -i n1 -o n3
--
:n2_self -
-A INPUT -j n2_self -i n2
:n2_n1 -
-A n2_n1 -j ACCEPT -s 10.1.2.0/24 -p tcp --dport 80
-A FORWARD -j n2_n1 -i n2 -o n1
--
:n3_self -
-A INPUT -j n3_self -i n3
END

test_run($title, $in, $out);

############################################################
$title = 'No missing transient rule for unenforceable rule';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
any:n1 = { link = network:n1; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24; }

# network:n1 -> any:n1 is unenforceable
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = any:n1, network:n3;
        prt = tcp 445;
}
service:s2 = {
 user = any:n1;
 permit src = user; dst = network:n2; prt = tcp 445;
}
END

$out = <<'END';
Warning: service:s1 has unenforceable rules:
 src=network:n1; dst=any:n1
END

test_warn($title, $in, $out);

############################################################
$title = 'Supernet used as aggregate';
############################################################

$in = <<'END';
network:intern = { ip = 10.1.1.0/24; }

router:asa = {
 model = ASA;
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
! inside_in
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 any eq 80
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = 'Aggregate linked to non-network';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1;
}
any:Trans = { link = router:r1; }
END

$out = <<'END';
Error: any:Trans must not be linked to router:r1
END

test_err($title, $in, $out);

############################################################
$title = 'Aggregate linked to unknown network';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
any:Trans = { link = network:n2; }
END

$out = <<'END';
Error: Referencing undefined network:n2 from any:Trans
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate named aggregate in zone';
############################################################

$in = <<'END';
any:a1 = { link = network:n1; }
any:a2 = { link = network:n2; }

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r = {
 interface:n1;
 interface:n2;
}
END

$out = <<'END';
Error: Duplicate any:a1 and any:a2 in any:[network:n1]
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate named aggregate in zone cluster';
############################################################

$in = <<'END';
any:a1 = { ip = 10.0.0.0/8; link = network:n1; }
any:a2 = { ip = 10.0.0.0/8; link = network:n2; }

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:u = {
 interface:n1;
 interface:n2;
}

pathrestriction:p = interface:u.n1, interface:r1.n1;

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
END

$out = <<'END';
Error: Duplicate any:a1 and any:a2 in any:[network:n2]
END

test_err($title, $in, $out);

############################################################
$title = 'Network and aggregate have same address in zone (1)';
############################################################

$in = <<'END';
any:a1 = { ip = 10.0.0.0/8; link = network:n1; }
network:n1 = { ip = 10.0.0.0/8; }
END

$out = <<'END';
Error: any:a1 and network:n1 have identical IP/mask
 in nat_domain:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Network and aggregate have same address in zone (2)';
############################################################

$in = <<'END';
any:a1 = { ip = 10.0.0.0/8; link = network:n1; }
network:n1 = { ip = 10.0.0.0/8; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
END

$out = <<'END';
Error: any:a1 and network:n1 have identical IP/mask at interface:r1.n1
END

test_err($title, $in, $out);

############################################################
$title = 'Network and aggregate have same address in zone cluster';
############################################################

$in = <<'END';
any:a1 = { ip = 10.1.2.0/24; link = network:n1; }

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:u = {
 interface:n1;
 interface:n2;
}

pathrestriction:p = interface:u.n1, interface:r1.n1;

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
END

$out = <<'END';
Error: any:a1 and network:n2 have identical IP/mask at interface:r2.n2
END

test_err($title, $in, $out);

############################################################
done_testing;
