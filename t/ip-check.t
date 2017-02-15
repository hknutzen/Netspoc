#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Invalid IP addresses';
############################################################

$in = <<'END';
network:n1 = { ip = 999.1.1.0/24; }
network:n2 = { ip = 10.888.1.0/24; }
network:n3 = { ip = 10.1.777.0/24; }
network:n4 = { ip = 10.1.1.666/32; }

router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
 interface:n4;
}
END

$out = <<'END';
Error: Invalid IP address at line 1 of STDIN
Error: Invalid IP address at line 2 of STDIN
Error: Invalid IP address at line 3 of STDIN
Error: Invalid IP address at line 4 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Interface IP doesn't match network IP/mask";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.2.3; }
}
END

$out = <<'END';
Error: interface:r1.n1's IP doesn't match network:n1's IP/mask
END

test_err($title, $in, $out);

############################################################
$title = "Interface IP has address of its network";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.0; }
}
END

$out = <<'END';
Error: interface:r1.n1 has address of its network
END

test_err($title, $in, $out);

############################################################
$title = "Interface IP has broadcast address";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.255; }
}
END

$out = <<'END';
Error: interface:r1.n1 has broadcast address
END

test_err($title, $in, $out);

############################################################
$title = "Host IP/range don't match network IP/mask";
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/28; 
 host:h1 = { ip = 10.1.2.3; }
 host:r1 = { range = 10.1.1.3-10.1.1.29; }
}
END

$out = <<"END";
Error: IP of host:h1 doesn't match IP/mask of network:n1
Error: IP range of host:r1 doesn't match IP/mask of network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid range';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/28; 
 host:r1 = { range = 10.1.1.9-10.1.1.3; }
}
END

$out = <<"END";
Error: Invalid IP range at line 3 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Range has size of network';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/28; 
 host:r1 = { range = 10.1.1.0-10.1.1.15; }
}

router:r1 = {
  interface:n1;
 interface:t1 = { ip = 10.9.1.1; }
}

network:t1 = { ip = 10.9.1.0/28; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:s1 = {
 user = host:r1;
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<"END";
Warning: Use network:n1 instead of host:r1
 because both have identical address
END

test_warn($title, $in, $out);

############################################################
$title = 'Overlapping host, range, interface';
############################################################
# Overlapping ranges are ok.

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
 host:h2 = { ip = 10.1.1.10; }
 host:h3 = { ip = 10.1.1.11; }
 host:r1 = { range = 10.1.1.2-10.1.1.12; }
 host:r2 = { range = 10.1.1.11-10.1.1.15; }
}

router:r1 = {
 interface:n1 = { ip = 10.1.1.11; }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r1.n1 and host:r1
Error: Duplicate IP address for interface:r1.n1 and host:r2
Error: Duplicate IP address for host:h1 and host:h2
Error: Duplicate IP address for interface:r1.n1 and host:h3
END

test_err($title, $in, $out);

############################################################
$title = 'Overlapping ranges used in rule';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/28; 
 host:r1 = { range = 10.1.1.4-10.1.1.11; }
 host:r2 = { range = 10.1.1.8-10.1.1.11; }
}

router:r2 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:s1 = {
 user = host:r1, host:r2;
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<"END";
Warning: host:r2 and host:r1 overlap in src of service:s1
END

test_warn($title, $in, $out);

############################################################
$title = 'Non matching subnet';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/28; 
 subnet_of = network:n2;
}

router:r1 = {
 interface:n1;
 interface:n2;
}

network:n2 = { ip = 10.2.2.0/24; }

END

$out = <<"END";
Error: network:n1 is subnet_of network:n2 but its IP doesn't match that's IP/mask
END

test_err($title, $in, $out);

############################################################
$title = 'Subnet of unnumbered network';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/28; 
 subnet_of = network:n2;
}

router:r1 = {
 interface:n1;
 interface:n2;
}

network:n2 = { unnumbered; }

END

$out = <<"END";
Error: Unnumbered network:n2 must not be referenced from attribute 'subnet_of'
 of network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Overlapping hosts with subnet';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/28; 
 subnet_of = network:n2;
}

router:r1 = {
  interface:n1;
 interface:n2 = { ip = 10.1.1.1; }
}

network:n2 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
 host:h2 = { range = 10.1.1.11-10.1.1.17; }
}

END

$out = <<"END";
Warning: IP of interface:r1.n2 overlaps with subnet network:n1
Warning: IP of host:h1 overlaps with subnet network:n1
Warning: IP of host:h2 overlaps with subnet network:n1
END

test_warn($title, $in, $out);

############################################################
$title = 'Reference unknown network in subnet_of';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24; 
 subnet_of = network:n2;
}
END

$out = <<"END";
Warning: Ignoring undefined network:n2 from attribute 'subnet_of'
 of network:n1
END

test_warn($title, $in, $out);

############################################################

done_testing;
