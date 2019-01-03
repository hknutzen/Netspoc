#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Secondary, primary, standard, full';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }

router:sec = {
 managed = secondary;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/30; }

router:pri = {
 managed = primary;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
}
network:t2 = { ip = 10.9.2.0/30; }

router:ful = {
 managed = full;
 model = ASA;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t3 = { ip = 10.9.3.1; hardware = t3; }
}
network:t3 = { ip = 10.9.3.0/30; }

router:std = {
 managed = standard;
 model = ASA;
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:t4 = { ip = 10.9.4.1; hardware = t4; }
}
network:t4 = { ip = 10.9.4.0/30; }

router:hub = {
 managed = secondary;
 model = IOS;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:t2 = { ip = 10.9.2.2; hardware = t2; }
 interface:t3 = { ip = 10.9.3.2; hardware = t3; }
 interface:t4 = { ip = 10.9.4.2; hardware = t4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}

service:s1 = {
 user = host:h1, host:h2;
 permit src = user;
        dst = network:n3, network:n4, network:n5;
        prt = tcp 80, udp 53;
}
END

$out = <<'END';
-- sec
! n1_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object 10.1.4.0 255.255.255.0
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 object-group g0
access-list n1_in extended permit tcp host 10.1.1.10 10.1.5.0 255.255.255.0 eq 80
access-list n1_in extended permit udp host 10.1.1.10 10.1.5.0 255.255.255.0 eq 53
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- pri
! n2_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object 10.1.4.0 255.255.254.0
access-list n2_in extended permit tcp host 10.1.2.10 object-group g0 eq 80
access-list n2_in extended permit udp host 10.1.2.10 object-group g0 eq 53
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
-- ful
! t3_in
object-group network g0
 network-object host 10.1.1.10
 network-object host 10.1.2.10
access-list t3_in extended permit tcp object-group g0 10.1.3.0 255.255.255.0 eq 80
access-list t3_in extended permit udp object-group g0 10.1.3.0 255.255.255.0 eq 53
access-list t3_in extended deny ip any4 any4
access-group t3_in in interface t3
-- std
! t4_in
access-list t4_in extended permit tcp host 10.1.1.10 10.1.4.0 255.255.255.0 eq 80
access-list t4_in extended permit udp host 10.1.1.10 10.1.4.0 255.255.255.0 eq 53
access-list t4_in extended permit ip 10.1.2.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list t4_in extended deny ip any4 any4
access-group t4_in in interface t4
-- hub
! [ ACL ]
ip access-list extended t1_in
 deny ip any host 10.1.5.1
 permit ip 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255
 permit ip 10.1.1.0 0.0.0.255 10.1.4.0 0.0.0.255
 permit tcp host 10.1.1.10 10.1.5.0 0.0.0.255 eq 80
 permit udp host 10.1.1.10 10.1.5.0 0.0.0.255 eq 53
 deny ip any any
--
ip access-list extended t2_in
 deny ip any host 10.1.5.1
 permit ip 10.1.2.0 0.0.0.255 10.1.3.0 0.0.0.255
 permit ip 10.1.2.0 0.0.0.255 10.1.4.0 0.0.0.255
 permit ip 10.1.2.0 0.0.0.255 10.1.5.0 0.0.0.255
 deny ip any any
--
ip access-list extended t3_in
 permit ip 10.1.3.0 0.0.0.255 10.1.1.0 0.0.0.255
 permit ip 10.1.3.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended t4_in
 permit ip 10.1.4.0 0.0.0.255 10.1.1.0 0.0.0.255
 permit ip 10.1.4.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended n5_in
 permit tcp 10.1.5.0 0.0.0.255 host 10.1.1.10 established
 permit udp 10.1.5.0 0.0.0.255 eq 53 host 10.1.1.10
 permit ip 10.1.5.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Secondary optimization to largest safe network';
############################################################

$in = <<'END';
network:all_10 = { ip = 10.0.0.0/8; has_subnets; }
network:super = { ip = 10.1.0.0/16; has_subnets; }
any:10_1_0-1 = { ip = 10.1.0.0/17; link = network:super; }

router:u1 = {
 interface:all_10;
 interface:super;
 interface:sub = { ip = 10.1.2.1; }
}

network:sub = { ip = 10.1.2.0/24; subnet_of = network:super; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:sub = { ip = 10.1.2.241; hardware = Ethernet2; }
 interface:trans = { ip = 10.3.1.17; hardware = Ethernet3; }
}

network:trans = { ip = 10.3.1.16/30; }

router:r2 = {
 managed = secondary;
 model = IOS, FW;
 interface:trans = { ip = 10.3.1.18; hardware = Ethernet5; }
 interface:dst = { ip = 10.9.9.1; hardware = Ethernet4; }
 interface:loop = { ip = 10.0.0.1; hardware = Loopback1; loopback; }
}

network:dst = {
 ip = 10.9.9.0/24;
 subnet_of = network:dst_super;
 host:server = { ip = 10.9.9.9; }
}

router:u2 = {
 interface:dst = { ip = 10.9.9.2; }
 interface:dst_super;
}

network:dst_super = { ip = 10.9.0.0/16; }

service:test = {
 user = network:sub;
 permit src = user;
        dst = host:server, interface:r2.loop;
        prt = tcp 80;
}
END

$out = <<'END';
--r2
ip access-list extended Ethernet5_in
 permit ip 10.1.0.0 0.0.255.255 host 10.0.0.1
 deny ip any host 10.9.9.1
 permit ip 10.1.0.0 0.0.255.255 10.9.0.0 0.0.255.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No optimization if subnet of subnet is outside of zone';
############################################################

$in = <<'END';
network:src = { ip = 10.1.1.0/24; }

# src must not be allowed to access subsub.
router:r1 = {
 managed = secondary;
 model = IOS, FW;
 interface:src = { ip = 10.1.1.1; hardware = Ethernet1; }
 interface:subsub = { ip = 10.9.9.49; hardware = Ethernet2; }
 interface:trans = { ip = 10.3.1.17; hardware = Ethernet3; }
}

network:subsub = { ip = 10.9.9.48/29; subnet_of = network:sub; }
network:trans = { ip = 10.3.1.16/30; }

router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:trans = { ip = 10.3.1.18; hardware = Ethernet5; }
 interface:dst = { ip = 10.9.9.1; hardware = Ethernet4; }
}

network:dst = {
 ip = 10.9.9.0/24;
 host:server = { ip = 10.9.9.9; }
}

router:u = {
 interface:dst;
 interface:sub = { ip = 10.9.9.33; }
}

network:sub = { ip = 10.9.9.32/27;  subnet_of = network:dst; }

service:test = {
 user = network:src;
 permit src = user;
        dst = host:server;
        prt = tcp 80;
}
END

$out = <<'END';
--r1
ip access-list extended Ethernet1_in
 permit ip 10.1.1.0 0.0.0.255 host 10.9.9.9
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No optimization if subnet of subnet is outside of zone (2)';
############################################################

# Must recognize that dst has other subnet, even if subsub is
# processed later.
$in =~ s/router:u/router:r0/;

test_run($title, $in, $out);

############################################################
$title = 'No optimization if subnet of subnet of subnet is outside of zone';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h2 = { ip = 10.1.3.10; } }
network:sub = { ip = 10.1.3.32/27; subnet_of = network:n3; }
network:subsub = { ip = 10.1.3.48/28; subnet_of = network:sub; }
network:subsubsub = { ip = 10.1.3.56/29; subnet_of = network:subsub; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed = secondary;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r3 = {
 interface:n3 = { ip = 10.1.3.3; }
 interface:sub;
}

router:r4 = {
 interface:sub;
 interface:subsub = { ip = 10.1.3.49; }
}

router:r5 = {
 managed;
 model = ASA;
 interface:subsub = { ip = 10.1.3.50; hardware = subsub; }
 interface:subsubsub = { ip = 10.1.3.57; hardware = subsubsub; }
}

service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
END

$out = <<'END';
--r2
! n2_in
access-list n2_in extended permit ip 10.1.1.0 255.255.255.0 host 10.1.3.10
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = "No optimization on supernet, but partly on host";
############################################################

# Optimized rule "A -> B IP" would allow "A -> subB IP" accidently.
$in = <<'END';
network:A = { ip = 10.3.3.0/25; host:a = { ip = 10.3.3.3; } }
network:subB = { ip = 10.8.8.8/29; subnet_of = network:B; }

router:secondary = {
 managed = secondary;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip = 10.3.3.1; hardware = A; }
 interface:subB = { ip = 10.8.8.9; hardware = subB; }
 interface:Trans = { ip = 10.1.1.2; hardware = Trans; }
}

network:Trans = { ip = 10.1.1.0/24; }

router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.1.1.1; hardware = Trans; }
 interface:B = { ip = 10.8.8.1; hardware = B; }
}

network:B = { ip = 10.8.8.0/24; host:B = { ip = 10.8.8.7; } }

service:test1 = {
 user = network:A;
 permit src = user; dst = network:B, network:subB; prt = tcp 80;
}
service:test2 = {
 user = network:A;
 permit src = user; dst = host:B; prt = tcp 22;
}
END

$out = <<'END';
--secondary
! [ ACL ]
ip access-list extended A_in
 deny ip any host 10.8.8.9
 permit tcp 10.3.3.0 0.0.0.127 10.8.8.0 0.0.0.255 eq 80
 permit ip 10.3.3.0 0.0.0.127 host 10.8.8.7
 deny ip any any
-- filter
! Trans_in
access-list Trans_in extended permit tcp 10.3.3.0 255.255.255.128 10.8.8.0 255.255.255.0 eq 80
access-list Trans_in extended permit tcp 10.3.3.0 255.255.255.128 host 10.8.8.7 eq 22
access-list Trans_in extended deny ip any4 any4
access-group Trans_in in interface Trans
END

test_run($title, $in, $out);

############################################################
$title = "Interface of standard router as destination";
############################################################
# interface:r2.n2 must not be otimized
# Optimization of interface:r2.n3 is not implemented.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }

router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24; }

service:n1 = {
 user = interface:r2.n2, interface:r2.n3;
 permit src = host:h1; dst = user; prt = tcp 80;
}
END

$out = <<'END';
--r1
! n1_in
object-group network g0
 network-object host 10.1.2.2
 network-object host 10.1.3.2
access-list n1_in extended permit tcp host 10.1.1.4 object-group g0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = "Don't optimize if aggregate rule starts behind secondary router";
############################################################

$in = <<'END';
network:n1 = { ip = 10.2.1.0/27; host:h1 = { ip = 10.2.1.4; }}

router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27;}

router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
}

network:n3 = { ip = 10.2.3.0/27; }

service:n1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:h1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 22-23;
}
service:any = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 22;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit tcp host 10.2.1.4 10.2.3.0 255.255.255.224 range 22 23
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n2_in
access-list n2_in extended permit tcp any4 10.2.3.0 255.255.255.224 eq 22
access-list n2_in extended permit tcp host 10.2.1.4 10.2.3.0 255.255.255.224 range 22 23
access-list n2_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = "Don't optimize if aggregate rule ends before secondary router";
############################################################

$in = <<'END';
network:n1 = { ip = 10.2.1.0/27; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27;}

router:r2 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
}

network:n3 = { ip = 10.2.3.0/27; host:h3 = { ip = 10.2.3.4; }}

service:n1 = {
 user = network:n1;
 permit src = user; dst = host:h3; prt = tcp 80;
}
service:any = {
 user = network:n1;
 permit src = user; dst = any:[ip = 10.2.0.0/16 & network:n2]; prt = tcp 22;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.0.0 255.255.0.0 eq 22
access-list n1_in extended permit tcp 10.2.1.0 255.255.255.224 host 10.2.3.4 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n2_in
access-list n2_in extended permit tcp 10.2.1.0 255.255.255.224 host 10.2.3.4 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = "Don't optimize with primary router";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24;}

router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24; }

router:r3 = {
 model = ASA;
 managed = primary;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}

network:n4 = { ip = 10.1.4.0/24; }

service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:any = {
 user = any:[ip=10.0.0.0/8 & network:n3];
 permit src = user; dst = network:n4; prt = tcp 22;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.4 10.1.4.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = "Disable secondary optimization for both primary and secondary.";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.2.3.0/24; }

router:r1 = {
 managed = primary;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed = secondary;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.1; hardware = n3; }
}

service:s1 = {
 user = any:[ ip = 10.2.0.0/16 & network:n2 ];
 permit src = user; dst = network:n1; prt = tcp 3128;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<'END';
--r2
ip access-list extended n3_in
 permit tcp 10.2.3.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Still optimize with supernet rule having no_check_supernet_rules";
############################################################

$in = <<'END';
network:n1 = { ip = 10.2.1.0/27; host:h1 = { ip = 10.2.1.4; } }

router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27;}

router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
}

network:n3 = { ip = 10.2.3.0/27; }

protocol:Ping = icmp 8, no_check_supernet_rules;

service:h1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:any = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = protocol:Ping;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit ip 10.2.1.0 255.255.255.224 10.2.3.0 255.255.255.224
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = "Still optimize if supernet is used in same service";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.4; } }

router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24;}

router:r2 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.4; } }

service:n1 = {
 user = host:h1, any:[network:n2];
 permit src = user; dst = host:h3; prt = tcp 80;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit ip host 10.1.1.4 10.1.3.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

Test::More->builder->todo_start("Should optimize protocol and destination");
test_run($title, $in, $out);
Test::More->builder->todo_end;

############################################################
done_testing;
