#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);


############################################################
$title = 'Path between virtual interfaces';
############################################################

$in = <<'END';
network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.83; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:b = {ip = 10.2.2.83; hardware = e1;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.84; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:b = {ip = 10.2.2.84; hardware = e1;}
}

network:b = { ip = 10.2.2.0/24;}

service:test = {
 user = interface:r1.a, interface:r2.a;
 permit src = user;
        dst = user;
        prt = tcp 22;
}
END

$out = <<'END';
--r1
ip access-list extended e0_in
 permit tcp host 10.1.1.84 host 10.1.1.83 eq 22
 permit tcp host 10.1.1.84 host 10.1.1.83 established
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
--r2
ip access-list extended e0_in
 permit tcp host 10.1.1.83 host 10.1.1.84 eq 22
 permit tcp host 10.1.1.83 host 10.1.1.84 established
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple virtual interface pairs with interface as destination';
############################################################

$in = <<'END';
network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.83; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:c1 = {ip = 10.3.1.2; virtual = {ip = 10.3.1.1;} hardware = v1;}
 interface:c2 = {ip = 10.3.2.2; virtual = {ip = 10.3.2.1;} hardware = v2;}
 interface:b = {ip = 10.2.2.83; virtual = {ip = 10.2.2.2;} hardware = e1;}
}

network:c1 = {ip = 10.3.1.0/24;}
network:c2 = {ip = 10.3.2.0/24;}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.84; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:c1 = {ip = 10.3.1.3; virtual = {ip = 10.3.1.1;} hardware = v1;}
 interface:c2 = {ip = 10.3.2.3; virtual = {ip = 10.3.2.1;} hardware = v2;}
 interface:b = {ip = 10.2.2.84; virtual = {ip = 10.2.2.2;} hardware = e1;}
}

network:b = { ip = 10.2.2.0/24;}

service:test = {
 user = network:a;
 permit src = user;
        dst = interface:r1.b;
        prt = tcp 22;
}
END

$out = <<'END';
--r1
ip access-list extended e0_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.83 eq 22
 deny ip any any
--
ip access-list extended v1_in
 deny ip any any
--
ip access-list extended v2_in
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
--r2
ip access-list extended e0_in
 deny ip any any
--
ip access-list extended v1_in
 deny ip any any
--
ip access-list extended v2_in
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Implicit pathrestriction with 3 virtual interfaces';
############################################################

$in = <<'END';
network:a = { ip = 10.1.1.0/24;}
network:x = { ip = 10.3.3.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:x = {ip = 10.3.3.1; hardware = E3;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}

router:r3 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.3; hardware = E6;}
 interface:b = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E7;}
}

network:b  = { ip = 10.2.2.0/24; }

service:test = {
 user = network:a;
 permit src = user; dst = network:x, network:b; prt = ip;
}
END

$out = <<'END';
--r1
ip access-list extended E1_in
 deny ip any host 10.3.3.1
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.1
 permit ip 10.1.1.0 0.0.0.255 10.3.3.0 0.0.0.255
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
--r2
ip access-list extended E4_in
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.2
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Extra pathrestriction at 2 virtual interface';
############################################################

$in = <<'END';
network:u = { ip = 10.9.9.0/24; }

router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = 10.9.9.1; hardware = F0;}
 interface:a = {ip = 10.1.1.9; hardware = F1;}
}

network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}

network:b  = { ip = 10.2.2.0/24; }

pathrestriction:p = interface:r1.a, interface:r1.b.virtual;

service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
}
END

$out = <<'END';
--g
ip route 10.2.2.0 255.255.255.0 10.1.1.2
--r1
ip access-list extended E1_in
 deny ip any any
--r2
ip access-list extended E4_in
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.2
 permit ip 10.9.9.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No extra pathrestriction with 3 virtual interfaces';
############################################################

$in = <<'END';
network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}

router:r3 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.3; hardware = E6;}
 interface:b = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E7;}
}

network:b  = { ip = 10.2.2.0/24; }

pathrestriction:p = interface:r1.a, interface:r1.b.virtual;
END

$out = <<'END';
Error: Must apply pathrestriction equally to group of routers with virtual IP:
 - router:r1 has pathrestriction:p
 - router:r2
 - router:r3
END

test_err($title, $in, $out);

############################################################
$title = 'Non matching virtual interface groups with interconnect';
############################################################

$in = <<'END';

router:g = {
 managed;
 model = ASA;
 interface:a = {ip = 10.1.1.7; hardware = inside;}
}

network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; virtual = {ip = 10.1.1.9;} hardware = E1;}
 interface:b1 = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; virtual = {ip = 10.1.1.9;} hardware = E4;}
 interface:b1 = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
 interface:t = { ip = 10.0.0.1; hardware = t1; }
}

network:t = { ip = 10.0.0.0/30; }

router:r3 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = 10.0.0.2; hardware = t1; }
 interface:a = {ip = 10.1.1.3; virtual = {ip = 10.1.1.9;} hardware = E6;}
 interface:b2 = {ip = 10.3.3.3; virtual = {ip = 10.3.3.9;} hardware = E7;}
}

router:r4 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.4; virtual = {ip = 10.1.1.9;} hardware = E8;}
 interface:b2 = {ip = 10.3.3.4; virtual = {ip = 10.3.3.9;} hardware = E9;}
}

network:b1 = { ip = 10.2.2.0/24; }
network:b2 = { ip = 10.3.3.0/24; }

service:test = {
 user = interface:g.a;
 permit src = user; dst = network:b1; prt = tcp 80;
}
END

$out = <<'END';
Error: network:b1 is reached via interface:r1.a.virtual
 but not via all related redundancy interfaces
END

test_err($title, $in, $out);

############################################################
$title = 'Non matching virtual interface groups';
############################################################

$in =~ s/(hardware = t1;)/$1 disabled;/g;

$out = <<'END';
Error: Virtual interfaces
 interface:r1.a.virtual, interface:r2.a.virtual, interface:r3.a.virtual, interface:r4.a.virtual
 must all be part of the same cyclic sub-graph
END

test_err($title, $in, $out);

############################################################
$title = 'Follow implicit pathrestriction at unmanaged virtual interface';
############################################################

# Doppelte ACL-Zeile für virtuelle IP vermeiden an
# - Crosslink-Interface zu unmanaged Gerät
# - mit virtueller IP auch an dem unmanged Gerät

$in = <<'END';
network:M = { ip = 10.1.0.0/24;}

router:F = {
 managed;
 model = ASA;
 interface:M = {ip = 10.1.0.1; hardware = inside;}
 interface:A = {ip = 10.2.1.129; hardware = o1; routing = dynamic;}
 interface:B = {ip = 10.2.1.18; hardware = o2; routing = dynamic;}
}

network:A = {ip = 10.2.1.128/30;}

router:Z = {
 interface:A = {ip = 10.2.1.130;}
 interface:c = {ip = 10.2.6.166;}
 interface:K = {ip = 10.9.32.3; virtual = {ip = 10.9.32.1;}}
}

network:B = {ip = 10.2.1.16/30;} 

router:L = {
 managed;
 model = IOS;
 interface:B = {ip = 10.2.1.17; hardware = Ethernet1; 
                no_in_acl; routing = dynamic;}
 interface:c  = {ip = 10.2.6.165; hardware = Ethernet2;}
 interface:K = {ip = 10.9.32.2; virtual = {ip = 10.9.32.1;} 
                hardware = Ethernet0;}
}

network:c  = {ip = 10.2.6.164/30;}
network:K = { ip = 10.9.32.0/21;}

pathrestriction:4 = interface:Z.A, interface:L.B;

service:x = {
 user = interface:L.K.virtual, interface:Z.K.virtual;
 permit src = network:M; dst = user; prt = icmp 17;
}
END

$out = <<'END';
--L
ip access-list extended Ethernet2_in
 permit icmp 10.1.0.0 0.0.0.255 host 10.9.32.1 17
 deny ip any any
END

test_run($title, $in, $out);

############################################################
done_testing;
