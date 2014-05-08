#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Multiple dynamic NAT at ASA';
############################################################

# Soll nur einen nat-Index pro Interface verwenden.

$in = <<END;
network:Test =  { 
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.1/32; dynamic;} 
 nat:D = { ip = 9.9.9.8/30; dynamic;} 
}

router:filter = {
 managed;
 model = ASA;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.2.1; hardware = outside; bind_nat = C;}
 interface:Y = { ip = 10.9.3.1; hardware = DMZ50; bind_nat = C;}
 interface:Z = { ip = 10.9.4.1; hardware = DMZ70; bind_nat = D;}
}

network:X = { ip = 10.9.2.0/24; }
network:Y = { ip = 10.9.3.0/24; }
network:Z = { ip = 10.9.4.0/24; }

protocol:IP = ip;

service:test = {
 user = network:X, network:Y, network:Z;
 permit src = user; 
	dst = network:Test;
	prt = protocol:IP;
}
END

$out = <<END;
! [ NAT ]
global (outside) 1 1.1.1.1 netmask 255.255.255.255
nat (inside) 1 10.9.1.0 255.255.255.0
global (DMZ50) 1 1.1.1.1 netmask 255.255.255.255
global (DMZ70) 1 9.9.9.8-9.9.9.11 netmask 255.255.255.252
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple dynamic NAT at ASA 8.4';
############################################################

# Soll nur einen nat-Index pro Interface verwenden.

$in = <<END;
network:Test =  { 
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.1/32; dynamic;} 
 nat:D = { ip = 9.9.9.8/30; dynamic;} 
}

router:filter = {
 managed;
 model = ASA, 8.4;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.2.1; hardware = outside; bind_nat = C;}
 interface:Y = { ip = 10.9.3.1; hardware = DMZ50; bind_nat = C;}
 interface:Z = { ip = 10.9.4.1; hardware = DMZ70; bind_nat = D;}
}

network:X = { ip = 10.9.2.0/24; }
network:Y = { ip = 10.9.3.0/24; }
network:Z = { ip = 10.9.4.0/24; }

protocol:IP = ip;

service:test = {
 user = network:X, network:Y, network:Z;
 permit src = user; 
	dst = network:Test;
	prt = protocol:IP;
}
END

$out = <<END;
! [ NAT ]
object network 10.9.1.0_255.255.255.0
 subnet 10.9.1.0 255.255.255.0
object network 1.1.1.1
 host 1.1.1.1
nat (inside,outside) source dynamic 10.9.1.0_255.255.255.0 1.1.1.1
nat (inside,DMZ50) source dynamic 10.9.1.0_255.255.255.0 1.1.1.1
object network 9.9.9.8-9.9.9.11
 range 9.9.9.8 9.9.9.11
nat (inside,DMZ70) source dynamic 10.9.1.0_255.255.255.0 9.9.9.8-9.9.9.11
END

test_run($title, $in, $out);

############################################################
$title = 'Dynamic NAT for network with static nat for hosts at ASA';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.16/28; dynamic;}
 host:H = { ip = 10.9.1.33; nat:C = { ip = 1.1.1.23; } }
}

router:filter = {
 managed;
 model = ASA;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.3.1; hardware = outside; bind_nat = C;}
}

network:X = { ip = 10.9.3.0/24; }

service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = ip;
 permit src = host:H; dst = user;         prt = tcp 80;
 permit src = user;   dst = network:Test; prt = tcp 80;
}
END

$out = <<END;
access-list inside_in extended permit tcp host 10.9.1.33 10.9.3.0 255.255.255.0 eq 80
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
--
access-list outside_in extended permit ip 10.9.3.0 255.255.255.0 host 1.1.1.23
access-list outside_in extended permit tcp 10.9.3.0 255.255.255.0 1.1.1.16 255.255.255.240 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
--
! [ NAT ]
static (inside,outside) 1.1.1.23 10.9.1.33 netmask 255.255.255.255
global (outside) 1 1.1.1.16-1.1.1.31 netmask 255.255.255.240
nat (inside) 1 10.9.1.0 255.255.255.0
END

test_run($title, $in, $out);

############################################################
$title = 'NAT at ASA 8.4';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.16/28; dynamic;}
 host:H = { ip = 10.9.1.33; nat:C = { ip = 1.1.1.23; } }
}

router:filter = {
 managed;
 model = ASA, 8.4;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.3.1; hardware = outside; bind_nat = C;}
}

network:X = { ip = 10.9.3.0/24; }

protocol:IP = ip;
protocol:HTTP = tcp 80;

service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = protocol:IP;
 permit src = host:H; dst = user;         prt = protocol:HTTP;
 permit src = user;   dst = network:Test; prt = protocol:HTTP;
}
END

$out = <<END;
! [ NAT ]
object network 10.9.1.33_255.255.255.255
 subnet 10.9.1.33 255.255.255.255
object network 1.1.1.23_255.255.255.255
 subnet 1.1.1.23 255.255.255.255
nat (inside,outside) 1 source static 10.9.1.33_255.255.255.255 1.1.1.23_255.255.255.255
object network 10.9.1.0_255.255.255.0
 subnet 10.9.1.0 255.255.255.0
object network 1.1.1.16-1.1.1.31
 range 1.1.1.16 1.1.1.31
nat (inside,outside) source dynamic 10.9.1.0_255.255.255.0 1.1.1.16-1.1.1.31
END

test_run($title, $in, $out);

############################################################
$title = 'Check rule with any to hidden NAT';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.0.0.0/24; 
 nat:C = { hidden; }
}

router:filter = {
 managed;
 model = ASA, 8.4;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = C; }
}

network:X = { ip = 10.8.3.0/24; }

service:test = {
 user = any:[network:X];
 permit src = user; dst = network:Test; prt = tcp 80;
}
END

$out = <<END;
Error: network:Test is hidden by NAT in rule
 permit src=any:[network:X]; dst=network:Test; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Multiple static NAT';
############################################################

$in = <<END;
network:a1 = { 
 ip = 10.1.1.0/24; 
 nat:b1 = { ip = 10.8.8.0; }
 nat:b2 = { ip = 10.9.9.0; }
}

router:r1  =  {
 managed;
 model = ASA;
 routing = manual;
 interface:a1 = { ip = 10.1.1.1; hardware = e0; }
 interface:b1 = { ip = 10.2.2.1; hardware = e1; bind_nat = b1; }
}
network:b1 = { ip = 10.2.2.0/24; }

router:r2  =  {
 managed;
 model = ASA;
 routing = manual;
 interface:b1 = { ip = 10.2.2.2; hardware = e2; }
 interface:b2 = { ip = 10.3.3.1; hardware = e3; bind_nat = b2; }
}
network:b2 = { ip = 10.3.3.0/24; }

service:test = {
 user = network:a1;
 permit src = network:b2; dst = user; prt = tcp;
}
END

$out = <<END;
! [ NAT ]
static (e0,e1) 10.8.8.0 10.1.1.0 netmask 255.255.255.0
--
! [ NAT ]
static (e2,e3) 10.9.9.0 10.8.8.0 netmask 255.255.255.0
END

test_run($title, $in, $out);

############################################################
$title = 'Must not bind multiple NAT of one network at one place';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.0.0.0/24; 
 nat:C = { ip = 10.8.8.0; }
 nat:D = { ip = 10.9.9.0; }
}

router:filter = {
 managed;
 model = ASA, 8.4;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = C, D; }
}

network:X = { ip = 10.8.3.0/24; }
END

$out = <<END;
Error: Must not bind multiple NAT tags 'C,D' of nat:D(network:Test) at router:filter
END

test_err($title, $in, $out);

############################################################
$title = 'Unused / undefined NAT tag';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.0.0.0/24; 
 nat:C = { ip = 10.8.8.0; }
}

router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = D; }
}

network:X = { ip = 10.8.3.0/24; }
END

$out = <<END;
Warning: nat:C is defined, but not bound to any interface
Warning: Ignoring useless nat:D bound at router:filter
END

test_err($title, $in, $out);

############################################################
$title = 'Check rule with host and dynamic NAT';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.9.2.0; dynamic;}
 host:H = { ip = 10.9.1.33; }
}

router:C = {
 managed; #1
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = inside;}
 interface:Trans = { ip = 10.0.0.1; hardware = outside; bind_nat = C;}
}
network:Trans = { ip = 10.0.0.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = {
  ip = 10.0.0.2;
  hardware = inside;
 }
 interface:X = { ip = 10.8.3.1; hardware = outside; }
}

network:X = { ip = 10.8.3.0/24; }

service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = tcp 80;
 permit src = host:H; dst = user;         prt = tcp 80;
}
END

$out = <<END;
Error: host:H needs static translation for nat:C to be valid in rule
 permit src=network:X; dst=host:H; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

$in =~ s/managed; \#1//;

$out = <<END;
Error: host:H needs static translation for nat:C to be valid in rule
 permit src=network:X; dst=host:H; prt=tcp 80; of service:test
Error: host:H needs static translation for nat:C to be valid in rule
 permit src=host:H; dst=network:X; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'NAT from overlapping areas and aggregates';
############################################################

$in = <<END;
area:A = {
 border = interface:r1.a1;
 nat:d = { ip = 10.99.99.8/30; dynamic; }
}
area:B = {
 border = interface:r2.b1;
 nat:d = { ip = 10.77.77.0/30; dynamic; }
}
any:a2 = { 
 link = network:a2; 
 nat:d = { identity; }
}

network:a1 = { ip = 10.5.5.0/24; }
network:a2 = { ip = 10.4.4.0/24; }
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:a1 = { ip = 10.5.5.1; hardware = vlan2; }
 interface:a2 = { ip = 10.4.4.1; hardware = vlan1; }
 interface:b1 = { ip = 10.2.2.1; hardware = vlan0; }
}
network:b2 = { ip = 10.3.3.0/24; }
router:u = { interface:b2; interface:b1; }
network:b1 = { ip = 10.2.2.0/24; nat:d = { identity; } }
router:r2 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:b1 = { ip = 10.2.2.2; hardware = e0; }
 interface:X = { ip = 10.1.1.2; hardware = e1; bind_nat = d; }
}
network:X = { ip = 10.1.1.0/24; }

service:test = {
 user = network:a1, network:a2, network:b1, network:b2;
 permit src = network:X; dst = user; prt = tcp 80;
}
END

$out = <<END;
object-group network g0
 network-object 10.4.4.0 255.255.255.0
 network-object 10.5.5.0 255.255.255.0
access-list vlan0_in extended permit tcp 10.1.1.0 255.255.255.0 object-group g0 eq 80
access-list vlan0_in extended deny ip any any
access-group vlan0_in in interface vlan0
--
ip access-list extended e1_in
 deny ip any host 10.2.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.99.99.8 0.0.0.3 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.4.4.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.77.77.0 0.0.0.3 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Use hidden NAT from overlapping areas';
############################################################

$in =~ s/ip = 10.77.77.0\/30; dynamic;/hidden;/;
$in =~ s/\Qnat:d = { ip = 10.99.99.8\/30; dynamic; }//;

$out = <<END;
Error: network:a1 is hidden by NAT in rule
 permit src=network:X; dst=network:a1; prt=tcp 80; of service:test
Error: network:b2 is hidden by NAT in rule
 permit src=network:X; dst=network:b2; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Interface with dynamic NAT as destination';
############################################################

$in = <<END;
network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS;
 interface:a = {ip = 10.1.1.1; hardware = E1; bind_nat = b;}
 interface:t = {ip = 10.4.4.1; hardware = E2;}
}
network:t = { ip = 10.4.4.0/30; }
router:r2 = {
 interface:t = {ip = 10.4.4.2;}
 interface:b = {ip = 10.2.2.1;}
}

network:b  = { ip = 10.2.2.0/24; nat:b = { ip = 10.9.9.4/30; dynamic; } }

service:test = {
 user = interface:r2.b;
 permit src = user; dst = network:a; prt = tcp 80;
}
END

$out = <<END;
Error: interface:r2.b needs static translation for nat:b to be valid in rule
 permit src=network:a; dst=interface:r2.b; prt=reverse:TCP_ANY; stateless
END

test_err($title, $in, $out);

############################################################
$title = 'Grouped NAT tags must only be used grouped';
############################################################

$in = <<END;
network:n1 = { 
 ip = 10.1.1.0/24; 
 nat:t1 = { ip = 10.9.1.0; }
 nat:t2 = { ip = 10.9.8.0; }
}

network:n2 = { 
 ip = 10.1.2.0/24; 
 nat:t2 = { ip = 10.9.9.0; }
}

router:r1 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = e0; }
 interface:n2 = { ip = 10.1.2.1; hardware = e0; }
 interface:t  = { ip = 10.2.3.1; hardware = e1; bind_nat = t1; }
}
network:t = { ip = 10.2.3.0/24; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t  = { ip = 10.2.3.2; hardware = e1; }
 interface:k = { ip = 10.2.2.2; hardware = e2; bind_nat = t2; }
}
network:k = { ip = 10.2.2.0/24; }
END

$out = <<END;
Error: If multiple NAT tags are used at one network,
 these NAT tags must be used equally grouped at other networks:
 - network:n2: t2
 - nat:t2(network:n1): t1,t2
END

test_err($title, $in, $out);

############################################################
$title = 'Grouped NAT tags with single hidden allowed';
############################################################

$in =~ s/ip = 10.9.[89].0/hidden/g;

$out = <<END;
END

test_err($title, $in, $out);

############################################################
$title = 'Prevent NAT from hidden back to IP';
############################################################

$in = <<END;
network:U1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { hidden; }
 nat:t2 = { ip = 10.9.9.0; }
}
router:R0 = {
 interface:U1;
 interface:T = { ip = 10.3.3.17; bind_nat = t1;}
}

network:T = { ip = 10.3.3.16/29; }

router:R2 = {
 managed;
 model = ASA;
 interface:T = { ip = 10.3.3.18; hardware = e0;}
 interface:K = { ip = 10.2.2.1; hardware = e2; bind_nat = t2; }
}

network:K = { ip = 10.2.2.0/24; }
END

$out = <<END;
Error: Must not change hidden NAT for nat:t1(network:U1)
 using NAT tag 't2' at router:R2
END

test_err($title, $in, $out);

############################################################
$title = 'Traverse hidden NAT domain in loop';
############################################################

$in = <<END;
network:i1 = {
 ip = 10.1.1.0/24;
 nat:i1 = { ip=10.9.9.0/24; }
 nat:h = { hidden; }
}

router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:i1 = { ip = 10.1.1.1; hardware = v1; }
 interface:tr = { ip = 10.2.2.1; hardware = v3; bind_nat = i1; }
 interface:si = { ip = 10.3.3.1; hardware = v4; }
}

network:tr = { ip = 10.2.2.0/24; }

router:r2 = {
 interface:tr;
 interface:sh;
}
network:sh = { ip = 10.4.4.0/24; }

router:r3 = {
 model = ASA;
 managed;
 routing = manual;
 interface:sh = { ip = 10.4.4.1; hardware = v5; bind_nat = i1; }
 interface:k  = { ip = 10.5.5.1; hardware = v6; bind_nat = h; }
}

network:si = { ip = 10.3.3.0/24; }

router:r4 = {
 interface:si;
 interface:k = { bind_nat = h; }
}

network:k = { ip = 10.5.5.0/24; }

service:test = {
 user = network:i1;
 permit src = user; dst = network:sh; prt = tcp 80;
}
END

$out = <<END;
Error: Must not apply reversed hidden NAT 'h' at interface:r3.k
 for
 permit src=network:i1; dst=network:sh; prt=tcp 80; of service:test
 Add pathrestriction to exclude this path
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'NAT tag at wrong interface in loop';
############################################################

$in = <<END;
network:i1 = {
 ip = 10.1.1.0/24;
 nat:h = { hidden; }
 nat:i1 = { hidden; }
}

router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:i1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:tr = { ip = 10.2.2.1; hardware = vlan2; bind_nat = i1; }
 interface:si = { ip = 10.3.3.1; hardware = vlan3; }
}

network:tr = { ip = 10.2.2.0/24; }

router:r2 = {
 interface:tr = { bind_nat = i2; }
 interface:sh;
}
network:sh = { ip = 10.4.4.0/24; }

router:r3 = {
 interface:sh;
 interface:i2 = { bind_nat = h; }
}

network:si = { ip = 10.3.3.0/24; }

router:r4 = {
 interface:si = { bind_nat = i2; }
 interface:i2 = { bind_nat = h; }
}

network:i2 = { ip = 10.1.1.0/24; nat:i2 = { hidden; } }
END

$out = <<END;
Error: network:i1 is translated by i1,
 but is located inside the translation domain of i1.
 Probably i1 was bound to wrong interface at router:r1.
Error: network:i2 and network:i1 have identical IP/mask
END

Test::More->builder->todo_start(
    "Missing NAT tag isn't recognized, because traversal aborts on first matching tag");
test_err($title, $in, $out);
Test::More->builder->todo_end;

############################################################
done_testing;
