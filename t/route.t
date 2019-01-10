#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Combine adjacent routes to same hop';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}

network:t1 = { ip = 10.9.1.0/24; }

router:u1 = {
 interface:t1 = { ip = 10.9.1.2; }
 interface:n2a;
 interface:n2b;
 interface:n2c;
 interface:n3a;
 interface:n4a;
 interface:n4b;
}
router:u2 = {
 interface:t1 = { ip = 10.9.1.3; }
 interface:n3b;
 interface:n4;
 interface:l5a = { ip = 10.5.0.4; loopback; }
 interface:l5b = { ip = 10.5.0.5; loopback; }
 interface:l5c = { ip = 10.5.0.6; loopback; }
 interface:l5d = { ip = 10.5.0.7; loopback; }
}

network:n2a = { ip = 10.1.2.0/26; }
network:n2b = { ip = 10.1.2.64/26; }
network:n2c = { ip = 10.1.2.128/25; }
network:n3a = { ip = 10.1.3.0/25; }
network:n3b = { ip = 10.1.3.128/25; }
network:n4a = { ip = 10.1.4.0/25; subnet_of = network:n4; }
network:n4b = { ip = 10.1.4.128/25; subnet_of = network:n4; }
network:n4  = { ip = 10.1.4.0/24; }

service:test = {
 user = network:n2a,
        network:n2b,
        network:n2c,
        network:n3a,
        network:n3b,
        network:n4a,
        network:n4b,
        interface:u2.l5a,
        interface:u2.l5b,
        interface:u2.l5c,
        interface:u2.l5d,
 ;
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

$out = <<'END';
--r1
! [ Routing ]
ip route 10.1.3.0/25 10.9.1.2
ip route 10.1.4.0/25 10.9.1.2
ip route 10.1.4.128/25 10.9.1.2
ip route 10.1.2.0/24 10.9.1.2
ip route 10.5.0.4/30 10.9.1.3
ip route 10.1.3.128/25 10.9.1.3
ip route 10.1.4.0/24 10.9.1.3
END

test_run($title, $in, $out, '--noauto_default_route');

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
Error: Can't generate static routes for interface:asa.Trans because IP address is unknown for:
 - interface:u.Trans
END

test_err($title, $in, $out);

############################################################
$title = 'Negotiated interface as next hop';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { negotiated; hardware = n2; }
}

router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

# Error message should only be shown once, even if another interface is defined.
router:r3 = {
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
END

$out = <<'END';
Error: Can't generate static routes for interface:r2.n2 because IP address is unknown for:
 - interface:r1.n2
END

test_err($title, $in, $out);

############################################################
$title = 'Two static unmanaged hops';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}

network:t1 = { ip = 10.9.1.0/29; }

router:h1 = {
 interface:t1 = { ip = 10.9.1.2; }
 interface:n2;
}
router:h2 = {
 interface:t1 = { ip = 10.9.1.3; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Error: Two static routes for network:n2
 at interface:r.t1 via interface:h2.t1 and interface:h1.t1
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
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
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

test_run($title, $in, $out, '--check_redundant_rules=0');

############################################################
$title = 'Check NAT when finding largest supernet for route.';
############################################################

$in = <<'END';
network:src = { ip = 10.1.1.0/24; }

router:r = {
 model = NX-OS;
 managed;
 interface:src = { ip = 10.1.1.1; hardware = src; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
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
$title = 'Networks inside and outside of zone';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 model = NX-OS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}

router:r2 = {
 model = NX-OS;
 managed;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
}

network:t1 = { ip = 10.9.1.0/24; }

router:u = {
 interface:t1 = { ip = 10.9.1.3; }
 interface:n3;
}
service:test = {
 user = network:n2, network:n3;
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

$out = <<'END';
--r1
! [ Routing ]
ip route 10.1.2.0/24 10.9.1.2
ip route 10.1.3.0/24 10.9.1.3
--r2
! [ Routing ]
ip route 10.1.1.0/24 10.9.1.1
END

test_run($title, $in, $out);

############################################################
$title = 'Zone cluster, two directions';
############################################################

# Find route from r1.n2 to n3, even if path from n2 to n3 is reused.
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}

network:n2  = {ip = 10.1.2.0/24;}

router:r2 = {
 managed = routing_only;
 model = ASA;
 interface:n2 = {ip = 10.1.2.2; hardware = n2;}
 interface:n3 = {ip = 10.1.3.1; hardware = n3;}
}

network:n3  = {ip = 10.1.3.0/24;}

router:r3 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 10.1.3.2; hardware = n3;}
}

service:s1 = {
 user = network:n2;
 permit src = user; dst = interface:r3.n3; prt = tcp 80;
}

service:s2 = {
 user = network:n3;
 permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
END

$out = <<'END';
--r1
! [ Routing ]
route n2 10.1.3.0 255.255.255.0 10.1.2.2
--r3
! [ Routing ]
route n3 10.1.2.0 255.255.255.0 10.1.3.1
END

test_run($title, $in, $out);

############################################################
$title = 'Zone cluster reaching multiple interfaces of router';
############################################################

# Generates route for n2, although n2 is directly connected.
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2; routing = OSPF;}
}

router:u1 = {
 interface:n1 = {ip = 10.1.1.2;}
 interface:n2 = {ip = 10.1.2.2;}
}

network:n2  = {ip = 10.1.2.0/24;}

pathrestriction:n1 = interface:u1.n1, interface:r1.n1;

service:ping_local = {
 user = foreach interface:r1.n1, interface:r1.n2;
 permit src = any:[user]; dst = user; prt = icmp 8;
}
END

$out = <<'END';
--r1
! [ Routing ]
ip route 10.1.2.0 255.255.255.0 10.1.1.2
END

test_run($title, $in, $out);

############################################################
$title = 'No route between pair of virtual interfaces';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:u1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.4; }
}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; virtual = { ip = 10.1.2.3; } }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; virtual = { ip = 10.1.3.3; } }
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; virtual = { ip = 10.1.2.3; } }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; virtual = { ip = 10.1.3.3; } }
}

router:u2 = {
 interface:n3 = { ip = 10.1.3.4; }
 interface:n4;
}

# Must not find route for path n1 -> u1.n2 -> r2.n2 -> r2.n3 -> r1.n3
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.n3.virtual; prt = tcp 80;
}

# Must not find route for path r1.n2 -> r2.n2 -> r2.n3 -> u2.n3 -> n3
service:s2 = {
 user = interface:r1.n2.virtual;
 permit src = user; dst = network:n4; prt = tcp 80;
}
END

$out = <<'END';
-- r1
! [ Routing ]
ip route 10.1.1.0 255.255.255.0 10.1.2.4
ip route 10.1.4.0 255.255.255.0 10.1.3.4
-- r2
! [ Routing ]
ip route 10.1.1.0 255.255.255.0 10.1.2.4
ip route 10.1.4.0 255.255.255.0 10.1.3.4
END

test_run($title, $in, $out);

############################################################
done_testing;
