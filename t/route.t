#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);


############################################################
$title = 'Missing next hop';
############################################################

$in = <<'END';
network:N = { ip = 10.1.1.0/24; }
router:u = { 
 interface:N;
 interface:Trans; 
}
network:Trans = { ip = 10.9.9.0/24; }

router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.9.9.1; hardware = outside; }
 interface:Kunde = { ip = 10.2.2.1; hardware = inside; }
}

network:Kunde = { ip = 10.2.2.0/24; }

service:test = {
 user = network:N;
 permit src = user; dst = network:Kunde; prt = tcp 80; 
}
END

$out = <<'END';
Error: interface:u.Trans must be defined in more detail, since there is
 a managed interface:asa.Trans with static routing enabled.
END

test_err($title, $in, $out);

############################################################
$title = 'Static route to network in unmanaged loop';
############################################################

$in = <<'END';
network:N = { ip = 10.1.1.0/24; }
router:u1 = { 
 interface:N;
 interface:T1;
}
router:u2 = { 
 interface:N;
 interface:T2;
}
network:T1 = { unnumbered; }
network:T2 = { unnumbered; }
router:u3 = { 
 interface:T1;
 interface:T2;
 interface:Trans = { ip = 10.9.9.2; }
}
network:Trans = { ip = 10.9.9.0/24; }

router:asa = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.9.9.1; hardware = outside; }
 interface:Kunde = { ip = 10.2.2.1; hardware = inside; }
}

network:Kunde = { ip = 10.2.2.0/24; }

service:test = {
 user = network:N;
 permit src = user; dst = network:Kunde; prt = tcp 80; 
}
END

$out = <<'END';
--asa
route outside 10.1.1.0 255.255.255.0 10.9.9.2
END

test_run($title, $in, $out);

############################################################
$title = 'Intermediate network hides subnet';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/28; subnet_of = network:n2; }
network:n2 = { ip = 10.1.1.0/24; subnet_of = network:n3; }
network:n3 = { ip = 10.1.0.0/16; }
network:n4 = { ip = 10.2.0.0/16; }

router:h1 = {
 interface:n1;
 interface:n3;
 interface:n4;
 interface:t1 = { ip = 10.9.1.2; }
}
router:h2 = {
 interface:n2;
 interface:t2 = { ip = 10.9.2.2; }
}

network:t1 = { ip = 10.9.1.0/30; }
network:t2 = { ip = 10.9.2.0/30; }

router:r = {
 model = NX-OS;
 managed;
 interface:t1 = { ip = 10.9.1.1; hardware = vlan1; }
 interface:t2 = { ip = 10.9.2.1; hardware = vlan2; }
}

service:test = {
 user = network:n1;#, network:n4;
 permit src = user; dst = network:n2; prt = icmp 8;
}
END

$out = <<'END';
--r
ip route 10.1.1.0/28 10.9.1.2
ip route 10.1.0.0/16 10.9.1.2
ip route 10.1.1.0/24 10.9.2.2
END

test_run($title, $in, $out);

############################################################
$title = 'Default route with intermediate network hides subnet';
############################################################

$in =~ s/;#,/,/;

$out = <<'END';
--r
ip route 0.0.0.0/0 10.9.1.2
ip route 10.1.1.0/28 10.9.1.2
ip route 10.1.1.0/24 10.9.2.2
END

test_run($title, $in, $out);

############################################################
$title = 'Route for redundant subnet';
############################################################

$in .= <<'END';
service:test2 = {
 user = network:n3;
 permit src = user; dst = network:n2; prt = icmp 8;
}
END

$out = <<'END';
--r
ip route 0.0.0.0/0 10.9.1.2
ip route 10.1.1.0/28 10.9.1.2
ip route 10.1.1.0/24 10.9.2.2
END

Test::More->builder->todo_start("Add all subnets in zone.");
test_run($title, $in, $out, '-check_redundant_rules=0');
Test::More->builder->todo_end;

############################################################
$title = 'Check NAT when finding largest supernet for route.';
############################################################

$in = <<'END';
network:src = { ip = 10.1.1.0/24; }

router:r = {
 model = NX-OS;
 managed;
 interface:src = { ip = 10.1.1.1; hardware = vlan2; }
 interface:t1 = { ip = 10.9.1.1; hardware = vlan1; }
}

network:t1 = { ip = 10.9.1.0/30; }

router:hop = {
 model = NX-OS;
 managed;
 interface:t1 = { ip = 10.9.1.2; hardware = inside; bind_nat = h; }
 interface:t2 = { ip = 10.9.2.1; hardware = outside; }
}

network:t2 = { ip = 10.9.2.0/30; }

router:u = {
 interface:t2 = { ip = 10.9.2.2; }
 interface:n1;
 interface:n2;
 interface:n3;
}

network:n1 = { 
 ip = 10.2.1.0/28;
 subnet_of = network:n2; 
}
network:n2 = {
 ip = 10.2.1.0/24;
 nat:h = { identity; }
 subnet_of = network:n3; 
}
network:n3 = {
 ip = 10.2.0.0/16;
 nat:h = { hidden; } 
}

service:test = {
 user = network:n1;
 permit src = network:src; dst = user; prt = icmp 8;
}

service:test2 = {
 user = network:n3;
 permit src = interface:hop.t2; dst = user; prt = icmp 8;
}
END

$out = <<'END';
--r
! [ Routing ]
ip route 10.2.1.0/24 10.9.1.2
--hop
! [ Routing ]
ip route 10.1.1.0/24 10.9.1.1
ip route 10.2.0.0/16 10.9.2.2
END

test_run($title, $in, $out);

############################################################
done_testing;
