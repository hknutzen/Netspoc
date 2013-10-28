#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out1, $head1, $out2, $head2, $out3, $head3, $compiled);

############################################################
$title = 'Implicit aggregate over 3 networks';
############################################################

$topo = <<END;
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
 model = IOS_FW;
 routing = manual;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; }
 interface:Customer = { ip = 10.9.9.1; hardware = VLAN2; }
}
network:Customer = { ip = 10.9.9.0/24; }
END

$in = <<END;
$topo

service:test = {
 user = any:[ip=10.0.0.0/8 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
END

$out1 = <<END;
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.0.0.0 0.255.255.255 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.3.3.0 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 permit tcp 10.1.1.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 81
 permit tcp 10.3.3.128 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Implicit aggregate over 2 networks';
############################################################

$in = <<END;
$topo

service:test = {
 user = any:[ip=10.3.3.0/24 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
END

$out1 = <<END;
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.3.3.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.3.3.0 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 permit tcp 10.3.3.128 0.0.0.127 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Implicit aggregate between 2 networks';
############################################################

$in = <<END;
$topo

service:test = {
 user = any:[ip=10.3.3.0/26 & area:test];
 permit src = user; dst = network:Customer; prt = tcp 80;
 permit src = network:[user]; dst = network:Customer; prt = tcp 81;
}
END

$out1 = <<END;
ip access-list extended VLAN1_in
 deny ip any host 10.9.9.1
 permit tcp 10.3.3.0 0.0.0.63 10.9.9.0 0.0.0.255 eq 80
 permit tcp 10.3.3.8 0.0.0.7 10.9.9.0 0.0.0.255 eq 81
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Check aggregate at unnumbered interface';
############################################################

$in = <<END;
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

$out1 = <<END;
Warning: Missing rule for supernet rule.
 permit src=any:[network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 can\'t be effective at interface:filter1.Trans.
 Tried any:Trans as src.
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Permit matching aggregate at non matching interface';
############################################################

$in = <<END;
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

$out1 = <<END;
access-list Vlan2_in extended permit tcp 10.0.0.0 255.0.0.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
END

$out2 = <<END;
access-list Vlan4_in extended permit tcp 10.0.0.0 255.0.0.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan4_in extended deny ip any any
access-group Vlan4_in in interface Vlan4
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = 'Warn on missing src aggregate';
############################################################

$in .= <<END;
router:T = {
 interface:Trans = { ip = 192.168.1.3; }
 interface:N1; 
}

network:N1 = { ip = 10.192.0.0/24; }
END

$out1 = <<END;
Warning: Missing rule for supernet rule.
 permit src=any:[ip=10.0.0.0/8 & network:Kunde]; dst=network:Test; prt=tcp 80; of service:test
 can\'t be effective at interface:filter1.Trans.
 Tried network:N1 as src.
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Loop with no_in_acl and in_zone eq no_in_zone';
############################################################

$in = <<END;
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

$out1 = <<END;
access-list Vlan5_in extended permit tcp any 10.1.1.0 255.255.255.0 eq 80
access-list Vlan5_in extended deny ip any any
access-group Vlan5_in in interface Vlan5
END

$out2 = <<END;
access-list Vlan6_out extended permit tcp any 10.1.1.0 255.255.255.0 eq 80
access-list Vlan6_out extended deny ip any any
access-group Vlan6_out out interface Vlan6
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = 'Nested aggregates';
############################################################

$in = <<END;

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

$out1 = <<END;
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.254.0 10.9.1.0 255.255.255.0 eq 80
access-list Vlan2_in extended permit tcp 10.1.0.0 255.255.252.0 10.9.1.0 255.255.255.0 eq 81
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Redundant nested aggregates';
############################################################

$in .= <<END;
service:test3 = {
 user = any:[ip=10.1.0.0/16 & network:Trans];
 permit src = user; dst = network:Test; prt = tcp 80;
}
END

$out1 = <<END;
Warning: Redundant rules in service:test1 compared to service:test3:
 Files: STDIN STDIN
  permit src=any:[ip=10.1.0.0/23 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test1
< permit src=any:[ip=10.1.0.0/16 & network:Trans]; dst=network:Test; prt=tcp 80; of service:test3
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Redundant nested aggregates without matching network (1)';
############################################################

# Larger aggregate is inserted first.
$in = <<END;
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

$out1 = <<END;
Warning: Redundant rules in service:test compared to service:test:
 Files: STDIN STDIN
  permit src=any:[ip=10.1.0.0/17 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip=10.1.0.0/16 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Redundant nested aggregates without matching network (2)';
############################################################

# Small aggregate is inserted first.
$in = <<END;
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

$out1 = <<END;
Warning: Redundant rules in service:test compared to service:test:
 Files: STDIN STDIN
  permit src=any:[ip=10.1.0.0/17 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
< permit src=any:[ip=10.1.0.0/16 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Redundant matching aggregates as subnet of network';
############################################################

$in = <<END;
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

$out1 = <<END;
Warning: Redundant rules in service:test1 compared to service:test2:
 Files: STDIN STDIN
  permit src=any:[ip=10.9.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip=10.9.1.0/25 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
Warning: Redundant rules in service:test2 compared to service:test1:
 Files: STDIN STDIN
  permit src=any:[ip=10.9.1.0/25 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
< permit src=network:Test; dst=network:Kunde; prt=tcp 80; of service:test1
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Mixed redundant matching aggregates';
############################################################

# Check for sub aggregate, even if sub-network was found
$in = <<END;
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

$out1 = <<END;
Warning: Redundant rules in service:test1 compared to service:test2:
 Files: STDIN STDIN
  permit src=any:[ip=10.1.1.0/26 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test1
< permit src=any:[ip=10.0.0.0/8 & network:Test]; dst=network:Kunde; prt=tcp 80; of service:test2
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Matching aggregate of implicit aggregate';
############################################################

$in = <<END;
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

$out1 = <<END;
access-list Vlan1_in extended permit tcp 10.1.0.0 255.255.0.0 10.1.1.0 255.255.255.0 eq 80
access-list Vlan1_in extended deny ip any any
access-group Vlan1_in in interface Vlan1
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################

done_testing;
