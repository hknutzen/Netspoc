#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'IP header, route';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }

router:r = {
 managed = routing_only;
 model = ASA;
 policy_distribution_point = host:h3;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:asa = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:test = {
 user = host:h3;
 permit src = user; dst = interface:r.[auto]; prt = tcp 22;
}
END

$out = <<'END';
--r
! [ IP = 10.1.2.1 ]
--
! [ Routing ]
route n2 10.1.3.0 255.255.255.0 10.1.2.2
END

test_run($title, $in, $out);

############################################################
$title = 'Unenforceable';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:r = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Warning: service:test is fully unenforceable
END

test_warn($title, $in, $out);

############################################################
$title = 'VRFs';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24;
}
router:r1@v1 = {
 managed = routing_only;
 model = NX-OS;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t1 = { ip = 10.9.1.1; hardware = e1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:r1@v2 = {
 managed = routing_only;
 model = NX-OS;
 interface:t1 = { ip = 10.9.1.2; hardware = e2; }
 interface:t2 = { ip = 10.9.2.1; hardware = e3; }
}
network:t2 = { ip = 10.9.2.0/24; }
router:r2 = {
 managed;
 model = NX-OS;
 interface:t2 = { ip = 10.9.2.2; hardware = e4; }
 interface:n = { ip = 10.1.1.1; hardware = e5; }
}
network:n = { ip = 10.1.1.0/24; }

service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
}
END

$out = <<'END';
-- r1
! [ Routing for router:r1@v1 ]
vrf context v1
 ip route 10.1.1.0/24 10.9.1.2
--
! [ Routing for router:r1@v2 ]
vrf context v2
 ip route 10.2.2.0/24 10.9.1.1
 ip route 10.1.1.0/24 10.9.2.2
END

test_run($title, $in, $out);

############################################################
done_testing;
