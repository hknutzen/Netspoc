#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;
use Test_Pathrestrictions;

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
 for rule permit src=any:[network:lft]; dst=any:[network:rgt]; prt=--;
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
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.1.1 established
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
 deny ip any host 10.1.2.2
 permit tcp host 10.1.1.1 10.1.2.0 0.0.0.255 eq 80
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
$title = 'Path starts at pathrestriction inside loop (3)';
############################################################

$in = $topo . <<'END';
pathrestriction:p1 =
 interface:r1.top,
 interface:r1.dst,
 interface:r2.top,
;

service:test = {
 user = interface:r1.dst;
 permit src = user;
        dst = network:top;
        prt = tcp 80;
}
END

$out = <<'END';
-- r1
ip access-list extended Vlan1_in
 deny ip any any
--
ip access-list extended Vlan2_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.1 established
 deny ip any any
-- r2
ip access-list extended Vlan4_in
 deny ip any host 10.1.1.2
 permit tcp host 10.1.2.1 10.1.1.0 0.0.0.255 eq 80
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
$title = 'Pathrestriction located in different loops';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2a = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}

network:t1 = { ip = 10.9.1.0/24; }

router:r2b = {
 model = IOS;
 managed;
 routing = manual;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}

router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

pathrestriction:p1 =
 interface:r2a.n2,
 interface:r2b.n3,
;

service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = udp 123;
}
END

$out = <<'END';
Warning: pathrestriction:p1 must not have elements from different loops:
 - interface:r2a.n2
 - interface:r2b.n3
END

test_err($title, $in, $out);

############################################################
$title = 'Pathrestrictions can not be optimized';
############################################################
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24;}
network:n4 = { ip = 10.1.4.0/24;}
network:n5 = { ip = 10.1.5.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = Ethernet1; }
 interface:n2 = { ip = 10.1.2.1; hardware = Ethernet2; }
 interface:n3 = { ip = 10.1.3.1; hardware = Ethernet3; }
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = Ethernet2; }
 interface:n3 = { ip = 10.1.3.2; hardware = Ethernet3; }
}

router:r3 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.3; hardware = Ethernet2; }
 interface:n4 = { ip = 10.1.4.1; hardware = Ethernet1; }
}

router:r4 = {
 managed;
 model = IOS, FW;
 interface:n3 = { ip = 10.1.3.3; hardware = Ethernet3; }
 interface:n4 = { ip = 10.1.4.2; hardware = Ethernet1; }
 interface:n5 = { ip = 10.1.5.1; hardware = Ethernet2; }

}

pathrestriction:pr1 = 
 interface:r1.n3, 
 interface:r4.n3, 
;

pathrestriction:pr2 = 
 interface:r1.n3, 
 interface:r3.n4,
 interface:r4.n3, 
;
END

$out = <<'END';
2 pathrestriction(s) defined.
2 pathrestriction(s) applied.
Failed to optimize 2 pathrestriction(s).
END

test_pathrestrictions($title, $in, $out);

############################################################
$title = 'Pathrestriction at non-loop node';
############################################################
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n2; }
}

router:r3 = {
 model = IOS;
 managed;
 interface:n3 = { ip = 10.1.3.2; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n2; }
}

pathrestriction:p1 =
 interface:r1.n2,
 interface:r3.n3,
;
END

$out = <<'END';
Warning: Ignoring pathrestriction:p1 at interface:r3.n3
 because it isn't located inside cyclic graph
END

test_err($title, $in, $out);

###########################################################
done_testing;
