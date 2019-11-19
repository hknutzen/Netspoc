#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Split and combine host ranges';
############################################################

$in = <<'END';
network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.15-10.1.1.19; }
 host:b = { range = 10.1.1.20-10.1.1.24; }
 host:c = { range = 10.1.1.25-10.1.1.35; }
}

router:r = {
 model = IOS, FW;
 managed;
 interface:n = { ip = 10.1.1.1; hardware = ethernet0; }
 interface:x = { ip = 192.168.1.1; hardware = ethernet1; }
}

network:x = { ip = 192.168.1.0/24; }

service:test = {
 user = host:a, host:b, host:c;
 permit src = user; dst = network:x; prt = tcp 80;
}
END

$out = <<'END';
--r
ip access-list extended ethernet0_in
 deny ip any host 192.168.1.1
 permit tcp host 10.1.1.15 192.168.1.0 0.0.0.255 eq 80
 permit tcp 10.1.1.32 0.0.0.3 192.168.1.0 0.0.0.255 eq 80
 permit tcp 10.1.1.16 0.0.0.15 192.168.1.0 0.0.0.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Redundant rule from host range and combined ip hosts';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
 host:r4-5 = { range = 10.1.1.4-10.1.1.5; }
}

router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:test = {
 user = host:h4, host:h5, host:r4-5;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h4; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r4-5; dst=network:n2; prt=tcp 80; of service:test
  permit src=host:h5; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r4-5; dst=network:n2; prt=tcp 80; of service:test
--r
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.4 0.0.0.1 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
END

test_warn($title, $in, $out);

############################################################
$title = 'Duplicate host ranges';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.15-10.1.1.19; }
 host:b = { range = 10.1.1.15-10.1.1.19; }
}

END

$out = <<'END';
Error: Duplicate IP address for host:a and host:b
END

test_err($title, $in, $out);

############################################################
$title = 'Host range and interface IP overlap';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.1-10.1.1.19; }
}

router:r = {
 interface:n = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r.n and host:a
END

test_err($title, $in, $out);

############################################################
$title = 'Ignore overlap of subnet range and interface IP';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.0-10.1.1.15; }
}

router:r = {
 interface:n = { ip = 10.1.1.1; }
}
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Duplicate host and interface IP';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { ip = 10.1.1.1; }
}

router:r = {
 interface:n = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r.n and host:a
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate host IPs';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { ip = 10.1.1.1; }
 host:b = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Duplicate IP address for host:a and host:b
END

test_err($title, $in, $out);

############################################################
$title = 'Redundant rule from host range and combined ip hosts';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
 host:h6 = { ip = 10.1.1.6; }
 host:h7 = { ip = 10.1.1.7; }
 host:r6-7 = { range = 10.1.1.6-10.1.1.7; }
}

router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:test = {
 user = host:h4, host:h5, host:h6, host:h7, host:r6-7;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h6; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r6-7; dst=network:n2; prt=tcp 80; of service:test
  permit src=host:h7; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r6-7; dst=network:n2; prt=tcp 80; of service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Must not combine list in place';
############################################################
# List of src objects is referenced from two different path rules.
# If combineSubnets is applied twice on the same list,
# we would get garbadge.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:h20 = { ip = 10.1.1.20; }
 host:h21 = { ip = 10.1.1.21; }
 host:h22 = { ip = 10.1.1.22; }
 host:h23 = { ip = 10.1.1.23; }
 host:h24 = { ip = 10.1.1.24; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n2, network:n3;
 permit src = user; dst = host:h22, host:h23, host:h24; prt = tcp 80;
}
END

$out = <<'END';
-- r1
! n2_in
object-group network g0
 network-object 10.1.1.22 255.255.255.254
 network-object host 10.1.1.24
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 object-group g0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
-- r2
! n3_in
object-group network g0
 network-object 10.1.1.22 255.255.255.254
 network-object host 10.1.1.24
access-list n3_in extended permit tcp 10.1.3.0 255.255.255.0 object-group g0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
END

test_run($title, $in, $out);

############################################################
done_testing;
