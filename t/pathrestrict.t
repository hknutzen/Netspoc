#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

my $topo = <<'END';
network:top = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:top = { ip = 10.1.1.1; hardware = Vlan1; }
 interface:lft = { ip = 10.3.1.245; hardware = Ethernet1; }
 interface:dst = { ip = 10.1.2.1; hardware = Vlan2; }
}
network:lft = { ip = 10.3.1.244/30;}

router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:top = { ip = 10.1.1.2; hardware = Vlan3; }
 interface:rgt = { ip = 10.3.1.129; hardware = Ethernet3; }
 interface:dst = { ip = 10.1.2.2; hardware = Vlan4; }
}
network:rgt = { ip = 10.3.1.128/30;}

network:dst = { ip = 10.1.2.0/24;}
END

############################################################
$title = 'Simple duplicate pathrestriction';
############################################################

$in = $topo . <<'END';
pathrestriction:top = 
 interface:r1.top, 
 interface:r2.top, 
;

pathrestriction:dst = 
 interface:r1.dst, 
 interface:r2.dst, 
;

service:test = {
 user = network:lft;
 permit src = user;
        dst = network:rgt;
        prt = tcp 80;
}
END

$out = <<'END';
Error: No valid path
 from any:[network:lft]
 to any:[network:rgt]
 for rule -- src=any:[network:lft]; dst=any:[network:rgt]; prt=--;
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:lft]
 to any:[network:rgt]
 for rule permit src=network:lft; dst=network:rgt; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
END

test_err($title, $in, $out);

############################################################
$title = 'Path starts at pathrestriction inside loop';
############################################################

$in = $topo . <<'END';
pathrestriction:p = 
 interface:r1.top, 
 interface:r2.dst, 
;

service:test = {
 user = interface:r1.top;
 permit src = user;
        dst = network:rgt;
        prt = tcp 80;
}
END

$out = <<'END';
-- r1
ip access-list extended Vlan1_in
 permit tcp 10.3.1.128 0.0.0.3 host 10.1.1.1 established
 deny ip any any
--
ip access-list extended Ethernet1_in
 deny ip any any
--
ip access-list extended Vlan2_in
 deny ip any any
-- r2
ip access-list extended Vlan3_in
 deny ip any host 10.3.1.129
 permit tcp host 10.1.1.1 10.3.1.128 0.0.0.3 eq 80
 deny ip any any
--
ip access-list extended Ethernet3_in
 deny ip any any
--
ip access-list extended Vlan4_in
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Path starts at pathrestriction inside loop (2)';
############################################################

# Must not use path r1.top-r1-r2-top

$in = $topo . <<'END';
pathrestriction:p = 
 interface:r1.top, 
 interface:r2.top, 
;

service:test = {
 user = interface:r1.top;
 permit src = user;
        dst = network:dst, network:top;
        prt = tcp 80;
}
END

$out = <<'END';
-- r1
ip access-list extended Vlan1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.1 established
 deny ip any any
--
ip access-list extended Ethernet1_in
 deny ip any any
--
ip access-list extended Vlan2_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.1.1 established
 deny ip any any
-- r2
ip access-list extended Vlan3_in
 deny ip any any
--
ip access-list extended Ethernet3_in
 deny ip any any
--
ip access-list extended Vlan4_in
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Path ends at pathrestriction inside loop';
############################################################

# Must detect identical path restriction,
# when temporary moving pathrestriction of r1.dst to r1.top.

$in = $topo . <<'END';
pathrestriction:p = 
 interface:r1.top, 
 interface:r1.dst, 
;

service:test = {
 user = network:top;
 permit src = user;
        dst = interface:r1.dst;
        prt = tcp 80;
}
END

$out = <<'END';
-- r1
ip access-list extended Vlan1_in
 deny ip any any
--
ip access-list extended Vlan2_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.1 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Path ends at pathrestriction inside loop (2)';
############################################################

$in = $topo . <<'END';
pathrestriction:p1 =
 interface:r1.top,
 interface:r1.dst,
;
pathrestriction:p2 =
 interface:r1.dst,
 interface:r1.lft,
;

service:test = {
 user = network:top;
 permit src = user;
        dst = interface:r1.lft;
        prt = tcp 80;
}
END

$out = <<'END';
-- r1
ip access-list extended Vlan1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.3.1.245 eq 80
 deny ip any any
--
ip access-list extended Vlan2_in
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Path ends at interface inside network, where path starts';
############################################################

# Must not enter r1 from network dst, even for optimized pathrestriction.

$in = $topo . <<'END';
pathrestriction:p =
 interface:r1.top,
 interface:r2.top,
;

service:test = {
 user = network:top;
 permit src = user;
        dst = interface:r1.top;
        prt = tcp 179;
}
END

$out = <<'END';
-- r1
ip access-list extended Vlan1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.1 eq 179
 deny ip any any
--
ip access-list extended Vlan2_in
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Secondary interface has implicit pathrestriction';
############################################################

$in = <<'END';
network:a = {ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E0;}
 interface:b = {ip = 10.2.2.1,10.2.2.80; hardware = E1;}
}
network:b = { ip = 10.2.2.0/24;}

service:test = {
 user = network:b;
 permit src = user;
        dst = interface:r1.b, interface:r1.b.2;
        prt = udp 69;
}
END

$out = <<'END';
--r1
ip access-list extended E1_in
 permit udp 10.2.2.0 0.0.0.255 host 10.2.2.1 eq 69
 permit udp 10.2.2.0 0.0.0.255 host 10.2.2.80 eq 69
 deny ip any any
--
interface E1
 ip address 10.2.2.1 255.255.255.0
 ip address 10.2.2.80 255.255.255.0 secondary
 ip inspect X in
 ip access-group E1_in in
END

test_run($title, $in, $out);

############################################################
done_testing;
