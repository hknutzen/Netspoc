#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Duplicate IP address';
############################################################

$in = <<'END';
network:n1a = { 
 ip = 10.1.1.0/24; 
 nat:t1 = { ip = 10.9.1.0/24; }
}

router:r1 = {
 interface:n1a = { bind_nat = t2; }
 interface:u;
}

network:u = { ip = 10.2.2.0/24; }

router:r2 = {
 interface:u;
 interface:n1b = { bind_nat = t1; }
}

network:n1b = { 
 ip = 10.1.1.0/24; 
 nat:t2 = { ip = 10.9.2.0/24; }
}
END

$out = <<'END';
Error: network:n1b and network:n1a have identical IP/mask
 in nat_domain:u
END

test_err($title, $in, $out);

############################################################
$title = 'Ignore duplicate IP address at unnumbered';
############################################################
# Address conflict is not observable at unnumbered network
# surrounded by unmanged routers.

$in =~ s/ip = 10.2.2.0\/24/unnumbered/;

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'NAT bound in wrong direction';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:x = { hidden; } }
router:r = {
 interface:n1 = { bind_nat = x; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: network:n1 is translated by x,
 but is located inside the translation domain of x.
 Probably x was bound to wrong interface at router:r.
END

test_err($title, $in, $out);

############################################################
$title = 'Dynamic NAT for network with static nat for hosts at ASA';
############################################################

$in = <<'END';
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

$out = <<'END';
--filter
! inside_in
access-list inside_in extended permit tcp host 10.9.1.33 10.9.3.0 255.255.255.0 eq 80
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit ip 10.9.3.0 255.255.255.0 host 1.1.1.23
access-list outside_in extended permit tcp 10.9.3.0 255.255.255.0 1.1.1.16 255.255.255.240 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Check rule with any to hidden NAT';
############################################################

$in = <<'END';
network:Test =  {
 ip = 10.0.1.0/24; 
 nat:C = { hidden; }
}

router:r1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.0.1.2; hardware = inside; }
 interface:t1 = { ip = 10.0.2.1; hardware = outside;}
}

network:t1 = { ip = 10.0.2.0/24; }

router:u = {
 interface:t1 = { ip = 10.0.2.2; }
 interface:X = { ip = 10.8.3.1; bind_nat = C; }
}

network:X = { ip = 10.8.3.0/24; }

router:r2 = {
 managed;
 model = ASA;
 interface:X = { ip = 10.8.3.2; hardware = inside; }
}

service:s1 = {
 user = any:[network:X];
 permit src = user; dst = network:Test; prt = tcp 80;
}
service:s2 = {
 user = network:X;
 permit src = user; dst = network:Test; prt = tcp 81;
}
END

$out = <<'END';
Error: network:Test is hidden by nat:C in rule
 permit src=any:[network:t1]; dst=network:Test; prt=tcp 80; of service:s1
Error: network:Test is hidden by nat:C in rule
 permit src=network:X; dst=network:Test; prt=tcp 81; of service:s2
END

test_err($title, $in, $out);

############################################################
$title = 'NAT network is undeclared subnet';
############################################################

$in = <<'END';
network:Test =  {
 ip = 10.0.0.0/28; 
 nat:C = { ip = 10.8.3.240/28; } #subnet_of = network:X; }
}

router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = C; }
}

network:X = { ip = 10.8.3.0/24; }
END

$out = <<'END';
Warning: nat:C(network:Test) is subnet of network:X
 in nat_domain:X.
 If desired, either declare attribute 'subnet_of' or attribute 'has_subnets'
END

test_warn($title, $in, $out);

############################################################
$title = 'NAT network is subnet';
############################################################

$in =~ s/} #subnet_of/subnet_of/;
$out = '';
test_warn($title, $in, $out);

############################################################
$title = 'Declared NAT network subnet doesn\'t match';
############################################################

$in =~ s/10.8.3.240/10.8.4.240/;
$out = <<'END';
Error: nat:C(network:Test) of network:Test is subnet_of network:X but its IP doesn't match that's IP/mask
END
test_err($title, $in, $out);

############################################################
$title = 'Detect subnet relation when having duplicate IP addresses';
############################################################

# Processing order of networks depends on lexical order of router names.
# Choose a weird order to get n1/n2sub and n2/n1sub to be processed together.
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:h1 = { hidden; } }
network:n1sub = { ip = 10.1.1.64/26; }

router:r1 = {
 interface:n1;
 interface:t1;
}
router:r4 = {
 interface:n1sub;
 interface:t1;
}

network:t1 = { ip = 10.2.1.0/24; }

router:fw =  {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.2.1.1; hardware = t1; bind_nat = h2; }
 interface:t2 = { ip = 10.2.2.1; hardware = t2; bind_nat = h1; }
}
network:t2 = { ip = 10.2.2.0/24; }

router:r2 = {
 interface:n2;
 interface:t2;
}
router:r3 = {
 interface:n2sub;
 interface:t2;
}

network:n2 = { ip = 10.1.1.0/24; nat:h2 = { hidden; } }
network:n2sub = { ip = 10.1.1.64/26; }
END

$out = <<'END';
Warning: network:n1sub is subnet of network:n1
 in nat_domain:t1.
 If desired, either declare attribute 'subnet_of' or attribute 'has_subnets'
Warning: network:n2sub is subnet of network:n2
 in nat_domain:t2.
 If desired, either declare attribute 'subnet_of' or attribute 'has_subnets'
END

test_warn($title, $in, $out);

############################################################
$title = 'Inherit subnet_of from inherited NAT';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24; 
 nat:N = { ip = 10.9.9.0/24; } 
}
network:n1_sub = {
 ip = 10.1.1.64/26; 
 subnet_of = network:n1;
}
router:u = {
 interface:n1;
 interface:n1_sub;
}
network:n2 = { ip = 10.1.2.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_sub = { ip = 10.1.1.65; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = N; }
}

service:s1 = {
    user = network:n1_sub;
    permit src = network:n2; dst = user; prt = tcp 80;
}
service:s2 = {
    user = network:n1;
    permit src = network:n2; dst = user; prt = tcp 81;
}

END

$out = <<'END';
-- asa1
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.9.9.64 255.255.255.192 eq 80
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.9.9.0 255.255.255.0 eq 81
access-list n2_in extended deny ip any any
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Must not bind multiple NAT of one network at one place';
############################################################

$in = <<'END';
network:n1 =  {
 ip = 10.0.1.0/24; 
 nat:C = { ip = 10.8.1.0/24; }
 nat:D = { hidden; }
}
network:n2 =  {
 ip = 10.0.2.0/24; 
 nat:C = { ip = 10.8.2.0/24; }
 nat:D = { hidden; }
}

router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.0.1.2; hardware = n1; }
 interface:n2 = { ip = 10.0.2.2; hardware = n2; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = C, D, E; }
}

network:X = { ip = 10.8.3.0/24; }
END

# Only first error is shown.
$out = <<'END';
Warning: Ignoring useless nat:E bound at router:filter
Error: Must not bind multiple NAT tags 'C,D' of nat:C(network:n1) at router:filter
END

test_err($title, $in, $out);

############################################################
$title = 'Unused / undefined NAT tag';
############################################################

$in = <<'END';
network:Test =  {
 ip = 10.0.0.0/24; 
 nat:C = { ip = 10.8.8.0/24; }
}

router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = D; }
}

network:X = { ip = 10.8.3.0/24; }
END

$out = <<'END';
Warning: Ignoring useless nat:D bound at router:filter
Warning: nat:C is defined, but not bound to any interface
END

test_warn($title, $in, $out);

############################################################
$title = 'Non matching static NAT mask';
############################################################

$in = <<'END';
network:n1 =  { ip = 10.1.1.0/24; nat:x = { ip = 10.8.8.0/23; } }

router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = x; }
}

network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: Mask for non dynamic nat:x(network:n1) must be equal to mask of network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Non matching NAT IP of host and interaface';
############################################################

$in = <<'END';
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/23; dynamic; } 
 host:h1 = { ip = 10.1.1.10; nat:x = { ip = 10.7.7.7; } }
}

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; nat:x = { ip = 10.7.7.1; } }
 interface:n2 = { bind_nat = x; }
}

network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<"END";
Error: nat:x: IP of host:h1 doesn't match IP/mask of network:n1
Error: nat:x: IP of interface:r1.n1 doesn't match IP/mask of network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Useless NAT IP of host and interface with static NAT';
############################################################

$in = <<'END';
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/24; } 
 host:h1 = { ip = 10.1.1.10; nat:x = { ip = 10.8.8.12; } }
}

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; nat:x = { ip = 10.7.7.1; } }
 interface:n2 = { bind_nat = x; }
}

network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<"END";
Warning: Ignoring nat:x at host:h1 because network:n1 has static NAT definition
Warning: Ignoring nat:x at interface:r1.n1 because network:n1 has static NAT definition
END

test_warn($title, $in, $out);

############################################################
$title = 'Must not define NAT for host range.';
############################################################

$in = <<'END';
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/24; dynamic; } 
 host:h1 = { range = 10.1.1.10-10.1.1.15; nat:x = { ip = 10.8.8.12; } }
}

router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = x; }
}

network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<"END";
Error: No NAT supported for host:h1 with 'range'
END

test_err($title, $in, $out);

############################################################
$title = 'Must not define NAT for host range.';
############################################################

$in = <<'END';
network:n1 = { 
 ip = 10.1.1.0/24; 
 nat:d = { ip = 10.9.1.0/28; dynamic; }
 host:h1 = { ip = 10.1.1.10; nat:d = { ip = 10.9.1.10; } }
 host:h2 = { range = 10.1.1.9 - 10.1.1.10; }
 host:h3 = { range = 10.1.1.8 - 10.1.1.15; }
}

router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = d; }
}

network:n2 = { ip = 10.2.2.0/24; }
END

$out = <<'END';
Error: Inconsistent NAT definition for host:h1 and host:h2
Error: Inconsistent NAT definition for host:h3 and host:h1
END

test_err($title, $in, $out);

############################################################
$title = 'NAT for interface with multiple IP addresses';
############################################################

$in = <<'END';
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/28; dynamic; } 
}

router:r1 = {
 interface:n1 = { ip = 10.1.1.1, 10.1.1.2; nat:x = { ip = 10.8.8.1; } }
 interface:t1 = { ip = 10.1.9.1; bind_nat = x; }
}

network:t1 = { ip = 10.1.9.0/24; }

router:filter = {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.1.9.2; hardware = t1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:s = {
 user = interface:r1.[all];
 permit src = user; dst = network:n2; prt = udp 123;
}
END

$out = <<"END";
Error: interface:r1.n1.2 needs static translation for nat:x at router:filter to be valid in rule
 permit src=interface:r1.n1.2; dst=network:n2; prt=udp 123; of service:s
END

test_err($title, $in, $out);

############################################################
$title = 'NAT tag without effect';
############################################################

$in = <<'END';
network:n1 =  { ip = 10.1.1.0/24; nat:x = { ip = 10.9.9.0/24; } }

router:r1 = {
 interface:n1 = { bind_nat = x; }
 interface:n2 = { bind_nat = x; }
}

network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Warning: Ignoring nat:x without effect, bound at every interface of router:r1
Warning: nat:x is defined, but not bound to any interface
END

test_warn($title, $in, $out);

############################################################
$title = 'Check rule with host and dynamic NAT';
############################################################

$in = <<'END';
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.9.2.0/24; dynamic;}
 host:h3 = { ip = 10.9.1.3; }
 host:h4 = { ip = 10.9.1.4; }
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

service:s1 = {
 user = network:X;
 permit src = user;   dst = host:h3;       prt = tcp 80;
 permit src = host:h4; dst = user;         prt = tcp 80;
}
END

$out = <<'END';
Error: host:h3 needs static translation for nat:C at router:C to be valid in rule
 permit src=network:X; dst=host:h3; prt=tcp 80; of service:s1
END

test_err($title, $in, $out);

$in =~ s/managed; \#1//;

$out = <<'END';
Error: host:h4 needs static translation for nat:C at router:filter to be valid in rule
 permit src=host:h4; dst=network:X; prt=tcp 80; of service:s1
Error: host:h3 needs static translation for nat:C at router:filter to be valid in rule
 permit src=network:X; dst=host:h3; prt=tcp 80; of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'No secondary optimization with host and dynamic NAT (1)';
############################################################

# Secondary optimization must be disabled at router:S,
# because router:R can't distinguish between h33 and h34.
$in = <<'END';
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.9.9.9/32; dynamic;}
 host:h33 = { ip = 10.9.1.33; }
 host:h34 = { ip = 10.9.1.34; }
}

router:S = {
 managed = secondary;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = inside;}
 interface:Trans = { ip = 10.0.0.1; hardware = outside; bind_nat = C;}
}
network:Trans = { ip = 10.0.0.0/24; }
router:R = {
 managed;
 model = ASA;
 interface:Trans = {
  ip = 10.0.0.2;
  hardware = inside;
 }
 interface:X = { ip = 10.8.3.1; hardware = outside; }
}

network:X = { ip = 10.8.3.0/24; }

service:s1 = {
 user = network:X;
 permit src = host:h33; dst = user;         prt = tcp 80;
 permit src = host:h34; dst = user;         prt = tcp 22;
}
END

$out = <<'END';
-- S
! inside_in
access-list inside_in extended permit tcp host 10.9.1.33 10.8.3.0 255.255.255.0 eq 80
access-list inside_in extended permit tcp host 10.9.1.34 10.8.3.0 255.255.255.0 eq 22
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
-- R
! inside_in
access-list inside_in extended permit tcp host 1.9.9.9 10.8.3.0 255.255.255.0 eq 80
access-list inside_in extended permit tcp host 1.9.9.9 10.8.3.0 255.255.255.0 eq 22
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = 'No secondary optimization with host and dynamic NAT (2)';
############################################################

# Secondary optimization must be disabled at router:r2.
$in = <<'END';
network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = 10.1.1.1; hardware = a; bind_nat = b;}
 interface:t = {ip = 10.4.4.1; hardware = t;}
}
network:t = { ip = 10.4.4.0/30; }
router:r2 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:t = {ip = 10.4.4.2; hardware = t;}
 interface:b = {ip = 10.2.2.1; hardware = b;}
}

network:b  = {
 ip = 10.2.2.0/24;
 nat:b = { ip = 10.9.9.4/30; dynamic; } 
 host:b10 = { ip = 10.2.2.10; }
}

service:test = {
 user = network:a;
 permit src = user; dst = host:b10; prt = tcp 80;
}
END

$out = <<'END';
-- r1
! [ ACL ]
ip access-list extended a_in
 permit tcp 10.1.1.0 0.0.0.255 10.9.9.4 0.0.0.3 eq 80
 deny ip any any
--
ip access-list extended t_in
 permit tcp host 10.2.2.10 10.1.1.0 0.0.0.255 established
 deny ip any any
-- r2
! t_in
access-list t_in extended permit tcp 10.1.1.0 255.255.255.0 host 10.2.2.10 eq 80
access-list t_in extended deny ip any any
access-group t_in in interface t
END

test_run($title, $in, $out);

############################################################
$title = 'Inherit NAT from overlapping areas and zones';
############################################################

$in = <<'END';
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

$out = <<'END';
--r1
! vlan0_in
object-group network g0
 network-object 10.4.4.0 255.255.255.0
 network-object 10.5.5.0 255.255.255.0
access-list vlan0_in extended permit tcp 10.1.1.0 255.255.255.0 object-group g0 eq 80
access-list vlan0_in extended deny ip any any
access-group vlan0_in in interface vlan0
--r2
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

$out = <<'END';
Error: network:a1 is hidden by nat:d in rule
 permit src=network:X; dst=network:a1; prt=tcp 80; of service:test
Error: network:b2 is hidden by nat:d in rule
 permit src=network:X; dst=network:b2; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Inherit NAT from aggregates and supernets inside zone';
############################################################

$in = <<'END';
# NAT is inherited to all 10.* subnets by default.
network:n   = {
 ip = 10.0.0.0/8;
 nat:d = { ip = 11.0.0.0/8; }
 has_subnets; 
}

# NAT is disabled for 10.0.0.0/16 and 10.1.0.0/16
any:a1 = { 
 ip = 10.0.0.0/15;
 link = network:n; 
 nat:d = { identity; }
}

# NAT is enabled for this network and 
# inherited to 10.1.1.0/24 and 10.1.2.0/24
network:n1 = {
 ip = 10.1.0.0/16;
 nat:d = { ip = 10.99.1.0/24; dynamic; }
 has_subnets; 
}

# NAT is inherited to 10.1.1.0/24;
any:a1x = { 
 ip = 10.1.0.0/23;
 link = network:n1; 
 nat:d = { ip = 10.99.2.0/24; dynamic; }
}

network:n0 = { ip = 10.0.0.0/16; }
network:n11 = { ip = 10.1.1.0/24; }
network:n12 = { ip = 10.1.2.0/24; }
network:n3  = { ip = 10.3.0.0/16; host:h3 = { ip = 10.3.3.10; } }

router:u = {
 interface:n;
 interface:n0;
 interface:n1;
 interface:n11;
 interface:n12;
 interface:n3;
 interface:t1;
}

network:t1 = { ip = 10.9.1.0/24; }

router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:t1 = { ip = 10.9.1.1; hardware = e0; }
 interface:X = { ip = 10.2.1.2; hardware = e1; bind_nat = d; }
}
network:X = { ip = 10.2.1.0/24; }

service:s1 = {
 user = network:X;
# NAT to 11.0.0.0/8
 permit src = user; dst = network:n; prt = tcp 80;
# NAT to 10.99.1.0
 permit src = user; dst = network:n1; prt = tcp 81;
# inherit from any:a1x, 10.99.2.0
 permit src = user; dst = network:n11; prt = tcp 82;
# inherit from network:n1, 10.99.1.0
 permit src = user; dst = network:n12; prt = tcp 83;
# inherit from network:n, 11.3.3.10
 permit src = user; dst = host:h3; prt = tcp 84;
# inherit from any:a1, no NAT, 10.0.0.0/16
 permit src = user; dst = network:n0; prt = tcp 85;
# inherit from network:n, 11.9.1.0
 permit src = user; dst = network:t1; prt = tcp 86;
}
END

$out = <<'END';
--r1
ip access-list extended e1_in
 deny ip any host 11.9.1.1
 permit tcp 10.2.1.0 0.0.0.255 11.0.0.0 0.255.255.255 eq 80
 permit tcp 10.2.1.0 0.0.0.255 10.99.1.0 0.0.0.255 eq 81
 permit tcp 10.2.1.0 0.0.0.255 10.99.2.0 0.0.0.255 eq 82
 permit tcp 10.2.1.0 0.0.0.255 10.99.1.0 0.0.0.255 eq 83
 permit tcp 10.2.1.0 0.0.0.255 host 11.3.3.10 eq 84
 permit tcp 10.2.1.0 0.0.0.255 10.0.0.0 0.0.255.255 eq 85
 permit tcp 10.2.1.0 0.0.0.255 11.9.1.0 0.0.0.255 eq 86
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Warn on useless inherited NAT (1)';
############################################################

$in = <<'END';
area:x = {
 border = interface:filter.x;
 nat:C = { ip = 10.8.8.0/24; dynamic; }
 nat:D = { hidden; }
}
any:x = { 
 link = network:x; 
 nat:C = { ip = 10.8.8.0/24; dynamic; }
}
network:x =  {
 ip = 10.0.0.0/24; 
 nat:C = { ip = 10.8.8.0/24; dynamic; }
 nat:D = { hidden; }
}

router:filter = {
 managed;
 model = ASA;
 interface:x = { ip = 10.0.0.2; hardware = inside; }
 interface:y = { ip = 10.8.3.1; hardware = outside; bind_nat = C; }
}

network:y = { ip = 10.8.3.0/24; }
END

$out = <<'END';
Warning: Useless nat:C(any:x),
 it is already inherited from nat:C(area:x)
Warning: Useless nat:C(network:x),
 it is already inherited from nat:C(any:x)
Warning: Useless nat:D(network:x),
 it is already inherited from nat:D(area:x)
Warning: nat:D is defined, but not bound to any interface
END

test_warn($title, $in, $out);

############################################################
$title = 'Warn on useless inherited NAT (2)';
############################################################

$in = <<'END';
# Don't warn, if other NAT is intermixed.
area:a12 = { border = interface:r2.n2; nat:n = { hidden; } }
area:a1  = { border = interface:r1.n1; nat:n = { identity; } }
any:n1 = { link = network:n1; nat:n = { hidden; } }
network:n1 = { ip = 10.1.1.0/24; nat:n = { identity; } }
network:n1a = { ip = 10.1.1.64/26; nat:n = { hidden; } subnet_of = network:n1; }

router:u1 = {
 interface:n1a;
 interface:n1;
}

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

# Warn on subnet.
any:n2 = { link = network:n2; }
network:n2 = { ip = 10.1.2.0/24; nat:n = { hidden; } }
network:n2a = { ip = 10.1.2.64/26; nat:n = { hidden; } subnet_of = network:n2; }

router:u2 = {
 interface:n2a;
 interface:n2;
}

router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n; }
}

network:n3 = { ip = 10.1.3.0/24; }
END

$out = <<'END';
Warning: Useless nat:n(network:n2a),
 it is already inherited from nat:n(network:n2)
Warning: Useless nat:n(network:n2),
 it is already inherited from nat:n(area:a12)
END

test_warn($title, $in, $out);

############################################################
$title = 'Useless identity NAT';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:n = { identity; } }
network:n1a = { ip = 10.1.1.64/26; nat:n = { hidden; } subnet_of = network:n1; }

router:u1 = {
 interface:n1a;
 interface:n1;
}

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n; }
}

network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Warning: Useless identity nat:n at network:n1
END

test_warn($title, $in, $out);

############################################################
$title = 'Inherit static NAT from area and zone';
############################################################

$in = <<'END';
any:a1 = { link = network:n1; nat:a1 = { ip = 11.0.0.0/8; } }

network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 172.17.2.1; hardware = n2; bind_nat = a1; }
}
network:n2 = { ip = 172.17.2.0/24; }
router:r2 = {
 interface:n2;
 interface:n2a;
}
network:n2a = { ip = 172.17.2.64/26; subnet_of = network:n2; }

area:a2 = { border = interface:r1.n2; nat:a2 = { ip = 192.168.0.0/16; } }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2a; prt = tcp 81;
}
END

$out = <<'END';
-- r1
ip access-list extended n1_in
 deny ip any host 192.168.2.1
 permit tcp 10.1.1.0 0.0.0.255 192.168.2.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 192.168.2.64 0.0.0.63 eq 81
 deny ip any any
--
ip access-list extended n2_in
 permit tcp 172.17.2.0 0.0.0.255 11.1.1.0 0.0.0.255 established
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Duplicate IP from inherited static NAT';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 172.17.2.1; hardware = n2; }
}
network:n2 = { ip = 172.17.2.0/24; }
router:r2 = {
 interface:n2;
 interface:n2a;
}
network:n2a = { ip = 172.18.2.00/24; }

area:a2 = { border = interface:r1.n2; nat:a2 = { ip = 192.168.0.0/16; } }
END

$out = <<'END';
Error: nat:a2(network:n2a) and nat:a2(network:n2) have identical IP/mask
 in nat_domain:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Inherited static NAT network must be larger';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 172.17.2.1; hardware = n2; }
}

network:n2 = { ip = 172.17.2.0/24; }
area:a2 = { border = interface:r1.n2; nat:a2 = { ip = 192.168.1.128/25; } }
END

$out = <<'END';
Error: Must not inherit nat:a2(area:a2) at network:n2
 because NAT network must be larger than translated network
END

test_err($title, $in, $out);

############################################################
$title = 'Interface with dynamic NAT as destination';
############################################################

# Should ignore error in policy_distribution_point,
# because other error message is shown.
$in = <<'END';
network:n2 = { ip = 10.1.2.0/24; nat:dyn = { ip = 10.9.9.9/32; dynamic; }}
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }

router:asa1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:h3;
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; bind_nat = dyn; }
}

service:s = {
 user = interface:asa1.n2;
 permit src = host:h3; dst = user; prt = tcp 22;
}
END

$out = <<'END';
Error: interface:asa1.n2 needs static translation for nat:dyn at router:asa2 to be valid in rule
 permit src=host:h3; dst=interface:asa1.n2; prt=tcp 22; of service:s
END

test_err($title, $in, $out);

############################################################
$title = 'Interface with dynamic NAT as destination in reversed rule';
############################################################

$in = <<'END';
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
 permit src = user; dst = network:a; prt = udp 445;
}
END

$out = <<'END';
Error: interface:r2.b needs static translation for nat:b at router:r1 to be valid in reversed rule for
 permit src=interface:r2.b; dst=network:a; prt=udp 445; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Interface with dynamic NAT applied at same device';
############################################################

$in = <<'END';
network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = 10.1.1.1; hardware = a;}
 interface:t = {ip = 10.4.4.1; hardware = t;}
}
network:t = { ip = 10.4.4.0/30; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t = {ip = 10.4.4.2; hardware = t; bind_nat = b;}
 interface:b = {ip = 10.2.2.1; hardware = b;}
}

network:b  = { ip = 10.2.2.0/24; nat:b = { ip = 10.9.9.4/30; dynamic; } }

service:test = {
 user = network:a;
 permit src = user; dst = interface:r2.b; prt = tcp 80;
}
END

$out = <<'END';
Error: interface:r2.b needs static translation for nat:b at router:r2 to be valid in rule
 permit src=network:a; dst=interface:r2.b; prt=tcp 80; of service:test
END

test_err($title, $in, $out);

############################################################
$title = 'Grouped NAT tags must only be used grouped';
############################################################

# n1 and n2 are translated at interface:r1.t, thus nat1 is active in
# network:t. At interface:r2.k only n1 is translated though, leading
# to ambiguity on which nat tag is active in network k.

$in = <<'END';
network:n1 = { 
 ip = 10.1.1.0/24; 
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:t2 = { ip = 10.9.8.0/24; }
}

network:n2 = { ip = 10.1.2.0/24; nat:t1 = { ip = 10.9.9.0/24; }}

router:r1 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t  = { ip = 10.2.3.1; hardware = t; bind_nat = t1; }
}
network:t = { ip = 10.2.3.0/24; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t  = { ip = 10.2.3.2; hardware = t; }
 interface:k = { ip = 10.2.2.2; hardware = k; bind_nat = t2; }
}
network:k = { ip = 10.2.2.0/24; }
END

$out = <<'END';
Error: If multiple NAT tags are used at one network,
 these NAT tags must be used equally grouped at other networks:
 - network:n2: t1
 - nat:t1(network:n1): t1,t2
END

test_err($title, $in, $out);

############################################################
$title = 'Grouped NAT tags must only be used grouped (2)';
############################################################

# In this case, using ungrouped NAT tags at network:n2 does not lead
# to ambiguities. An error is generated, although in a strict sense no
# error occurs. If a way is found to distinct such cases from real
# error cases, NetSPoC and this test should be adapted.

$in =~ s/network:n2.*\}\}//s;
$in .= "network:n2 = { ip = 10.1.2.0/24; nat:t2 = { ip = 10.9.9.0/24; }}";

$out = <<'END';
Error: If multiple NAT tags are used at one network,
 these NAT tags must be used equally grouped at other networks:
 - network:n2: t2
 - nat:t1(network:n1): t1,t2
END

test_err($title, $in, $out);

############################################################
$title = 'Grouped NAT tags with additional hidden allowed';
############################################################

$in = <<'END';
network:n1 = { 
 ip = 10.1.1.0/24; 
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}

network:n2 = { 
 ip = 10.1.2.0/24; 
 nat:h1 = { hidden; }
 nat:h3 = { hidden; }
}

network:n3 = { 
 ip = 10.1.3.0/24; 
 nat:t3 = { ip = 10.9.3.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}

network:n4 = { 
 ip = 10.1.4.0/24; 
 nat:t4a = { ip = 10.8.1.0/24; }
 nat:t4b = { ip = 10.8.2.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = t4a; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = t4b; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = h3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:t  = { ip = 10.2.3.1; hardware = t; bind_nat = t1, t3; }
}
network:t = { ip = 10.2.3.0/24; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t  = { ip = 10.2.3.2; hardware = t; }
 interface:k1 = { ip = 10.2.1.2; hardware = k1; bind_nat = h1; }
 interface:k2 = { ip = 10.2.2.2; hardware = k2; bind_nat = h2; }
}
network:k1 = { ip = 10.2.1.0/24; }
network:k2 = { ip = 10.2.2.0/24; }
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Combined single hidden allowed';
############################################################

$in = <<'END';
network:n1 = { 
 ip = 10.1.1.0/24; 
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h1 = { hidden; }
}

network:n2 = { 
 ip = 10.1.2.0/24; 
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}

network:n3 = { 
 ip = 10.1.3.0/24; 
 nat:t3 = { ip = 10.9.3.0/24; }
 nat:h2 = { hidden; }
}

router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t  = { ip = 10.2.0.1; hardware = t; bind_nat = t1, t3; }
}
network:t = { ip = 10.2.0.0/24; }
router:r2 =  {
 interface:t;
 interface:k1 = { bind_nat = h1; }
 interface:k2 = { bind_nat = h2; }
}
network:k1 = { ip = 10.2.1.0/24; }
network:k2 = { ip = 10.2.2.0/24; }
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Grouped NAT tags with invalid hidden';
############################################################

$in = <<'END';
network:n1 = { 
 ip = 10.1.1.0/24; 
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}

network:n2 = { 
 ip = 10.1.2.0/24; 
 nat:t1 = { ip = 10.9.2.0/24; }
}

network:n3 = { 
 ip = 10.1.3.0/24; 
 nat:h1 = { hidden; }
}

router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t1 = { ip = 10.2.1.1; hardware = t; bind_nat = t1; }
}
network:t1 = { ip = 10.2.1.0/24; }
# t1 active
router:r2 = {
 interface:t1;
 interface:k1 = { bind_nat = h1; }
 interface:k2 = { bind_nat = h2; }
}
# h1 active
# t1 ambiguous: still active for n2, no longer active for n1
network:k1 = { ip = 10.2.3.0/24; }

# h2 active
# t1 ambiguous: still active for n2, no longer active for n1
network:k2 = { ip = 10.2.2.0/24; }
END

$out = <<'END';
Error: If multiple NAT tags are used at one network,
 these NAT tags must be used equally grouped at other networks:
 - network:n2: t1
 - nat:h1(network:n1): h1,h2,t1
END

test_err($title, $in, $out);

############################################################
$title = 'Grouped NAT tags with invalid hidden (2)';
############################################################

$in = <<'END';
network:n1 = { 
 ip = 10.1.1.0/24; 
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h  = { hidden; }
}

network:n2 = { 
 ip = 10.1.2.0/24; 
 nat:t2 = { ip = 10.9.2.0/24; }
 nat:h  = { hidden; }
}

network:n3 = { 
 ip = 10.1.3.0/24; 
 nat:t1 = { ip = 10.9.3.0/24; }
 nat:t2 = { ip = 10.9.4.0/24; }
 nat:h  = { hidden; }
}

router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t1 = { ip = 10.2.1.1; hardware = t; bind_nat = t1; }
}
# t1 active
network:t1 = { ip = 10.2.1.0/24; }
router:r2 = {
 interface:t1;
 interface:t2 = { bind_nat = t2; }
}
# t2 active
# t1 ambiguous: still active for n1, but no longer active for n3
network:t2 = { ip = 10.2.2.0/24; }
router:r3 = {
 interface:t2;
 interface:k = { bind_nat = h; }
}
network:k = { ip = 10.2.3.0/24; }
END

$out = <<'END';
Error: If multiple NAT tags are used at one network,
 these NAT tags must be used equally grouped at other networks:
 - network:n3: h,t1,t2
 - nat:h(network:n1): h,t1
END

test_err($title, $in, $out);

############################################################
$title = 'Grouped NAT tags from different paths';
############################################################

$in = <<'END';
network:a = {
 ip = 10.1.1.0/24; 
 nat:a1 = { ip = 10.2.1.0/24; } 
 nat:a2 = { ip = 10.2.2.0/24; }
}

router:r11 = {
 interface:a;
 interface:t1 = { bind_nat = a1; }
}

network:t1 = {ip = 10.3.3.0/30;}

router:r12 = {
 interface:t1;
 interface:b = { bind_nat = a2; }
}

router:r21 = {
 interface:a;
 interface:t2 = { bind_nat = a2; }
}

network:t2 = {ip = 10.3.3.4/30;}

router:r22 = {
 interface:t2;
 interface:b = { bind_nat = a1; }
}

network:b = {ip = 10.9.9.0/24;}
END

$out = <<'END';
Error: Grouped NAT tags 'a2' and 'a1' must not both be active inside nat_domain:b
END

test_err($title, $in, $out);

############################################################
$title = 'Must not apply same NAT tag twice';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:n = { ip = 10.9.9.0/24; } }

router:r1 = {
 interface:n1;
 interface:tr = { bind_nat = n; }
}

network:tr = { ip = 10.7.7.0/24; }

router:r2 = {
 interface:tr;
 interface:n2 = { bind_nat = n; }
}

network:n2 = { ip = 10.2.2.0/24; }
END

$out = <<'END';
Error: nat:n is applied twice between router:r1 and router:r2
END

test_err($title, $in, $out);

############################################################
$title = 'Prevent NAT from dynamic to static';
############################################################

$in = <<'END';
network:U1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.8.8.0/23; dynamic; }
 nat:t2 = { ip = 10.9.9.0/24; }
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

$out = <<'END';
Error: Must not change dynamic nat:t1 to static using nat:t2
 for nat:t1(network:U1) at router:R2
END

test_err($title, $in, $out);

############################################################
$title = 'Prevent NAT from hidden back to IP';
############################################################

$in = <<'END';
network:U1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { hidden; }
 nat:t2 = { ip = 10.9.9.0/24; }
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

$out = <<'END';
Error: Must not change hidden nat:t1 using nat:t2
 for nat:t2(network:U1) at router:R2
END

test_err($title, $in, $out);

############################################################
$title = 'Prevent multiple hidden NAT';
############################################################

$in = <<'END';
network:U1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { hidden; }
 nat:t2 = { hidden; }
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

$out = <<'END';
Error: Must not change hidden nat:t1 using nat:t2
 for nat:t2(network:U1) at router:R2
END

test_err($title, $in, $out);

############################################################
$title = 'Two NAT tags share single hidden NAT tag';
############################################################

$in = <<'END';
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 interface:n0 = { bind_nat = F; }
 interface:n1;
}

router:asa = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = h; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; bind_nat = P; }
 interface:n3 = { ip = 10.1.3.1; hardware = vlan3; }
}

router:r2 = {
 interface:n3;
 interface:n4;
}

network:n3 = { 
 ip = 10.1.3.0/24; 
 nat:h = { hidden; } 
 nat:P = { ip = 10.2.3.0/24; } 
}
network:n4 = {
 ip = 10.1.4.0/24;
 nat:h = { hidden; }
 nat:F = { ip = 10.2.4.0/24; } 
}
END

$out = <<'END';
Error: Must not change hidden nat:h using nat:F
 for nat:F(network:n4) at router:r1
END

test_err($title, $in, $out);

############################################################
$title = 'Partially hidden in destination zone';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:h = { hidden; } }

router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:t1 = { ip = 10.5.5.164; hardware = inside; bind_nat = h; }
}
network:t1 = { ip = 10.5.5.160/28; }
router:u1 = {
 interface:t1 = { bind_nat = h; }
 interface:n2;
}

network:n2 = { ip = 10.1.2.0/24; }

service:test = {
 user =	network:n1;
 permit src = user; dst = network:n2; prt = proto 50;
}
END

$out = <<'END';
Error: Must not apply hidden NAT 'h' on path
 of rule
 permit src=network:n1; dst=network:n2; prt=proto 50; of service:test
 NAT 'h' is active at
 - interface:r1.t1
 Add pathrestriction to exclude this path
END

test_err($title, $in, $out);

############################################################
$title = 'Ignore hidden network in static routes';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  routing = OSPF;
  hardware = outside;
 }
 interface:t1 = { ip = 10.5.5.164; hardware = inside; }
}
network:t1 = { ip = 10.5.5.160/28; }
router:u1 = {
 interface:t1 = { ip = 10.5.5.161;  bind_nat = h; }
 interface:n2;
 interface:n3;
}

network:n2 = { ip = 10.1.2.0/24; nat:h = { hidden; } }
network:n3 = { ip = 10.1.3.0/24; }
any:10_1   = { ip = 10.1.0.0/16; link = network:n2; }

service:test = {
 user =	network:n1;
 permit src = user; dst = any:10_1; prt = proto 50;
}
END

$out = <<'END';
-- r1
! [ Routing ]
route inside 10.1.3.0 255.255.255.0 10.5.5.161
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore hidden network in NAT';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  routing = OSPF;
  hardware = outside;
  bind_nat = h;
 }
 interface:t1 = { ip = 10.5.5.164; hardware = inside; }
}
network:t1 = { ip = 10.5.5.160/28; }
router:u1 = {
 interface:t1 = { ip = 10.5.5.161; }
 interface:n2;
 interface:n3;
}

network:n2 = { ip = 10.1.2.0/24; nat:h = { hidden; } }
network:n3 = { ip = 10.1.3.0/24; }
any:10_1   = { ip = 10.1.0.0/16; link = network:n2; }

service:test = {
 user =	network:n1;
 permit src = user; dst = any:10_1; prt = proto 50;
}
END

$out = <<'END';
-- r1
! outside_in
access-list outside_in extended permit 50 10.1.1.0 255.255.255.0 10.1.0.0 255.255.0.0
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Traverse hidden NAT domain in loop';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 nat:h = { hidden; }
}

router:r1 = {
 model = ASA;
 managed; #r1
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.5.5.1; hardware = t1; bind_nat = h; }
}

network:t1 = { ip = 10.5.5.0/24; }

router:r2 = {
 model = ASA;
 managed; #r2
 routing = manual;
 interface:t1 = { ip = 10.5.5.2; hardware = t1; }
 interface:t2 = { ip = 10.4.4.1; hardware = t2; }
}

network:t2 = { ip = 10.4.4.0/24; }

router:r3 = {
 model = ASA;
 managed; #r3
 routing = manual;
 interface:t2 = { ip = 10.4.4.2; hardware = t2; bind_nat = h; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/24; }

router:r4 = {
 model = ASA;
 managed; #r4
 routing = manual;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Error: Must not apply hidden NAT 'h' on path
 of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r1.t1
 - interface:r2.t1
 - interface:r2.t2
 - interface:r3.t2
 Add pathrestriction to exclude this path
END

test_err($title, $in, $out);

############################################################
$title = 'Traverse hidden NAT domain in loop, 1x unmanaged bind_nat';
############################################################
$in =~ s/managed; #r1//;
$out = <<'END';
Error: Must not apply hidden NAT 'h' on path
 of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r2.t1
 - interface:r2.t2
 - interface:r3.t2
 Add pathrestriction to exclude this path
END
test_err($title, $in, $out);

############################################################
$title = 'Traverse hidden NAT domain in loop, 2x unmanaged bind_nat';
############################################################
$in =~ s/managed; #r3//;
$out = <<'END';
Error: Must not apply hidden NAT 'h' on path
 of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r2.t1
 - interface:r2.t2
 Add pathrestriction to exclude this path
END
test_err($title, $in, $out);

############################################################
$title = 'Traverse dynamic NAT domain in loop';
############################################################
$in =~ s/hidden;/ip = 10.9.9.0\/24; dynamic;/;
$out = <<'END';
Error: Must not apply dynamic NAT 'h' on path
 of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r2.t1
 - interface:r2.t2
 Add pathrestriction to exclude this path
END
test_err($title, $in, $out);

############################################################
$title = 'Mixed valid and invalid hidden NAT';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 nat:h = { hidden; }
 nat:d = { ip = 10.9.9.0/27; dynamic; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = d; }
}

router:r2 = {
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = d; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = h; }
}

router:r4 = {
 interface:n4 = { ip = 10.1.4.2; hardware = n4; bind_nat = h; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}

pathrestriction:p = interface:r2.n3, interface:r4.n1;

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}

service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 81;
}
END

$out = <<'END';
Error: Must not apply hidden NAT 'h' on path
 of rule
 permit src=network:n1; dst=network:n3; prt=tcp 81; of service:s2
 NAT 'h' is active at
 - interface:r3.n4
 - interface:r4.n4
 Add pathrestriction to exclude this path
END

test_err($title, $in, $out);

############################################################
$title = 'Mixed valid and invalid dynamic NAT';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 nat:d = { ip = 10.9.9.0/27; dynamic; }
 host:h10 = { ip = 10.1.1.10; nat:d = { ip = 10.9.9.3; } } 
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = d; }
}

router:r4 = {
 interface:n4 = { ip = 10.1.4.2; hardware = n4; bind_nat = d; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}

pathrestriction:p = interface:r2.n3, interface:r4.n1;

service:s1 = {
 user = network:n2;
 permit src = user; dst = host:h10; prt = tcp 80;
}

service:s2 = {
 user = network:n3;
 permit src = user; dst = host:h10; prt = tcp 81;
}
END

$out = <<'END';
Error: Must not apply dynamic NAT 'd' on path
 of reversed rule
 permit src=network:n3; dst=host:h10; prt=tcp 81; of service:s2
 NAT 'd' is active at
 - interface:r3.n4
 - interface:r4.n4
 Add pathrestriction to exclude this path
END

test_err($title, $in, $out);

############################################################
$title = 'Inconsistent NAT in loop (1)';
############################################################

$in = <<'END';
network:a = {ip = 10.1.13.0/24; nat:h = { hidden; }}

router:r1 = {
 interface:a;
 interface:t;
 interface:b = { bind_nat = h; }
}

network:t = {ip = 10.3.103.240/30;}

router:r2 = {
 interface:a;
 interface:t;
 interface:b;
}

network:b = {ip = 10.156.5.160/28;}
END

$out = <<'END';
Error: Inconsistent NAT in loop at router:r1:
 nat:(none) vs. nat:h
Error: network:a is translated by h,
 but is located inside the translation domain of h.
 Probably h was bound to wrong interface at router:r1.
END

test_err($title, $in, $out);

############################################################
$title = 'Inconsistent NAT in loop (2)';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:x = { ip = 10.9.3.0/24; } }
network:n4 = { ip = 10.1.4.0/24; }
 
router:r1 = {
 interface:n2;
 interface:n4;
}
 
router:r2 = {
 interface:n1 = { bind_nat = x; }
 interface:n3;
 interface:n2;
}

router:r3 = {
 interface:n1 = { bind_nat = x; }
 interface:n3;
 interface:n4 = { bind_nat = x; }
}
END

$out = <<'END';
Error: Inconsistent NAT in loop at router:r2:
 nat:(none) vs. nat:x
Error: Inconsistent NAT in loop at router:r3:
 nat:(none) vs. nat:x
Error: network:n3 is translated by x,
 but is located inside the translation domain of x.
 Probably x was bound to wrong interface at router:r2.
END

test_err($title, $in, $out);

############################################################
$title = 'Check recursive NAT in loop';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }

router:r1 = {
 interface:n1;
 interface:t1 = { bind_nat = n1; }
 interface:t2 = { bind_nat = n2; }
}
network:t1 = { ip = 10.7.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }

router:r2 = {
 interface:n2;
 interface:t1;
 interface:t2 = { bind_nat = n2; }
}

network:t2 = { ip = 10.7.2.0/24; }
END

$out = <<'END';
Error: nat:n1 is applied recursively in loop at this path:
 - router:r1
 - router:r2
 - router:r1
END

test_err($title, $in, $out);

############################################################
$title = 'NAT in loop ok';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }

router:r1 = {
 interface:n1;
 interface:t1 = { bind_nat = n1; }
}
network:t1 = { ip = 10.7.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }

router:r2 = {
 interface:n2;
 interface:t1;
 interface:t2;
 interface:t3 = { bind_nat = n2; }
}

network:t2 = { ip = 10.7.2.0/24; }

router:r3 = {
 interface:t2;
 interface:t3 = { bind_nat = n2; }
}

network:t3 = { ip = 10.7.3.0/24; }
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'NAT is applied twice';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }

router:r1 = {
 interface:n1;
 interface:t1 = { bind_nat = n1; }
}
network:t1 = { ip = 10.7.1.0/24; }

router:r2 = {
 interface:t1;
 interface:t2 = { bind_nat = n1; }
}

network:t2 = { ip = 10.7.2.0/24; }
END

$out = <<'END';
Error: nat:n1 is applied twice between router:r1 and router:r2
END

test_err($title, $in, $out);

############################################################
$title = 'Attribute acl_use_real_ip';
############################################################

$in = <<'END';
network:intern =  { ip = 10.1.1.0/24; nat:intern = { ip = 2.2.1.0/24; } }

router:filter = {
 managed;
 model = ASA;
 acl_use_real_ip;
 interface:intern = {
  ip = 10.1.1.1;
  hardware = inside;
  bind_nat = extern;
 }
 interface:extern = {
  ip = 2.2.2.1; 
  hardware = outside;
  bind_nat = intern;
 }
}

network:extern = { ip = 2.2.2.0/24; nat:extern = { ip = 10.1.2.0/24; } }

service:test = {
 user = network:extern;
 permit src = user;           dst = network:intern; prt = tcp 80;
 permit src = network:intern; dst = user;           prt = tcp 22;
}
END

$out = <<'END';
-- filter
! inside_in
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 eq 22
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit tcp 2.2.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'NAT at loopback network';
############################################################

$in = <<'END';
area:n1 = { inclusive_border = interface:r1.n2; nat:N = { hidden; } }
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:lo = {
  ip = 10.1.9.1;
  hardware = Looback0;
  loopback;
  nat:N = { identity; }
  nat:N2 = { ip = 10.1.9.1; }
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = N, N2; }
}

network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }

service:s1 = {
    user = interface:r1.lo;
    permit src = network:n2; dst = user; prt = tcp 80;
}
END

$out = <<'END';
-- r1
ip access-list extended n2_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.9.1 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Hidden NAT at loopback network';
############################################################

$in = <<'END';
router:r1 = {
 managed;
 model = IOS;
 interface:lo = {
  ip = 10.1.9.1;
  hardware = Looback0;
  loopback;
  nat:N = { hidden; }
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = N; }
}

network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }

service:s1 = {
    user = interface:r1.lo;
    permit src = network:n2; dst = user; prt = tcp 80;
}
END

$out = <<'END';
Error: interface:r1.lo is hidden by nat:N in rule
 permit src=network:n2; dst=interface:r1.lo; prt=tcp 80; of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'Only NAT IP at non loopback interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat:N = { hidden; } }
}
END

$out = <<'END';
Error: Must not use 'hidden' in nat:N of interface:r1.n1
END

test_err($title, $in, $out);

############################################################
done_testing;
