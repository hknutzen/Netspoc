#!perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }

router:r1 = {
 managed;
 model = IOS;
 log:a = log-input;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:asa2 = {
 managed;
 model = ASA;
 log:a = errors;
 log:b = debugging;
 log:c = disable;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; }
}
END

############################################################
$title = 'Different log levels and devices; do / don\'t join ranges';
############################################################

$in = $topo . <<'END';
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
 permit src = user; dst = network:n3; prt = tcp 81; log = b;
 permit src = user; dst = network:n3; prt = tcp 82; log = c;
 permit src = user; dst = network:n3; prt = tcp 83; log = c;
 permit src = user; dst = network:n3; prt = tcp 84;
 permit src = user; dst = network:n3; prt = tcp 85; log = a, b, c;
}

END

$out = <<'END';
-- r1
! [ ACL ]
ip access-list extended vlan1_in
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80 log-input
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 range 81 84
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 85 log-input
 deny ip any any
-- asa2
! [ ACL ]
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80 log 3
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 81 log 7
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 range 82 83 log disable
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 84
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 85 log 3
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Unknown log severity at ASA';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = ASA;
 log:a = foo;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
}
END

$out = <<'END';
Error: Invalid 'log:a = foo' at router:r1 of model ASA
 Expected one of: alerts|critical|debugging|disable|emergencies|errors|informational|notifications|warnings
END

test_err($title, $in, $out);

############################################################
$title = 'Unknown log severity at IOS';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = IOS;
 log:a = foo;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
}
END

$out = <<'END';
Error: Invalid 'log:a = foo' at router:r1 of model IOS
 Expected one of: log-input
END

test_err($title, $in, $out);

############################################################
$title = 'Unknown log severity at NX-OS';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = NX-OS;
 log:a = foo;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
}
END

$out = <<'END';
Error: Unexpected 'log:a = foo' at router:r1 of model NX-OS
 Use 'log:a;' only.
END

test_err($title, $in, $out);

############################################################
$title = 'Unknown log tag';
############################################################

$in = $topo . <<'END';
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = d;
}
END

$out = <<'END';
Warning: Referencing unknown 'd' in log of service:t
END

test_err($title, $in, $out);

############################################################
$title = 'Global optimization with log tag';
############################################################

$in = $topo . <<'END';
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}

service:t2 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
END

$out = <<'END';
Warning: Redundant rules in service:t1 compared to service:t2:
  permit src=network:n1; dst=network:n3; prt=tcp 80; of service:t1
< permit src=any:[network:n1]; dst=network:n3; prt=tcp 80; of service:t2
END

test_err($title, $in, $out);

############################################################
$title = 'No global optimization with different log tag';
############################################################

$in = $topo . <<'END';
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}

service:t2 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = b;
}
END

$out = <<'END';
-- r1
! [ ACL ]
ip access-list extended vlan1_in
 permit tcp any 10.1.3.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80 log-input
 deny ip any any
-- asa2
! [ ACL ]
access-list vlan2_in extended permit tcp any 10.1.3.0 255.255.255.0 eq 80 log 7
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80 log 3
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Local optimization with log tag';
############################################################

$in = $topo . <<'END';
service:t = {
 user = network:n1, any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
END

$out = <<'END';
-- r1
! [ ACL ]
ip access-list extended vlan1_in
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80 log-input
 deny ip any any
-- asa2
! [ ACL ]
access-list vlan2_in extended permit tcp any 10.1.3.0 255.255.255.0 eq 80 log 3
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'No local optimization with different log tag';
############################################################

$in = $topo . <<'END';
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}

service:t2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = b;
}
END

$out = <<'END';
-- asa2
! [ ACL ]
access-list vlan2_in extended permit tcp any 10.1.3.0 255.255.255.0 eq 80 log 7
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80 log 3
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Logging at NX-OS and ACE board';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }

router:r1 = {
 managed;
 model = NX-OS;
 log:a;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:r2 = {
 managed;
 model = ACE;
 log:a;
 log:b;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; }
}
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
 permit src = user; dst = network:n3; prt = tcp 81; log = b;
}
END

$out = <<'END';
-- r1
! [ ACL ]
ip access-list vlan1_in
 10 permit tcp 10.1.1.0/24 10.1.3.0/24 eq 80 log
 20 permit tcp 10.1.1.0/24 10.1.3.0/24 eq 81
 30 deny ip any any
-- r2
! [ ACL ]
access-list vlan2_in extended deny ip any host 10.1.3.2
access-list vlan2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 range 80 81 log
access-list vlan2_in extended deny ip any any
END

test_run($title, $in, $out);

############################################################
done_testing;
