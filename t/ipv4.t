#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use utf8;
use Test_Netspoc;

my ($title, $in, $out);


############################################################
$title = 'Invalid IPv4 addresses';
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
Error: invalid CIDR address: 999.1.1.0/24 in 'ip' of network:n1
Error: invalid CIDR address: 10.888.1.0/24 in 'ip' of network:n2
Error: invalid CIDR address: 10.1.777.0/24 in 'ip' of network:n3
Error: invalid CIDR address: 10.1.1.666/32 in 'ip' of network:n4
END

test_err($title, $in, $out);

############################################################
$title = 'Unicode digits in IPv4 address';
############################################################

$in = <<'END';
network:n1 = { ip = १.२.३.४/32; } # 1.2.3.4 in DEVANAGARI
END

$out = <<"END";
Error: invalid CIDR address: \x{967}.\x{968}.\x{969}.\x{96a}/32 in 'ip' of network:n1
END

test_err($title, $in, $out);

#############################################################
$title = 'Simple topology IPv4';
#############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.2.2.1; hardware = n2;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END

$out = <<'END';
-- r1
ip access-list extended n1_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 range 80 90
 deny ip any any
END

test_run($title, $in, $out);

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
$title = "Network and broadcast address ok in /31 network";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/31; }
router:r1 = { interface:n1 = { ip = 10.1.1.0; } }
router:r2 = { interface:n1 = { ip = 10.1.1.1; } }
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = "Must not use icmp protocol as number";
############################################################

$in = <<'END';
protocol:ICMP  = proto 1;

network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = interface:r1.n1;
 prt = protocol:ICMP;
}
END

$out = <<'END';
Error: 'proto 1' must not be used in service:test1, use 'icmp' instead
END

test_err($title, $in, $out);

############################################################
$title = "Must not use icmpv6 with ipv4";
############################################################

$in = <<'END';
protocol:ICMPv6  = icmpv6;

network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = interface:r1.n1;
 prt = protocol:ICMPv6;
}
END

$out = <<'END';
Error: protocol:ICMPv6 must not be used in IPv4 service:test1
END

test_err($title, $in, $out);

############################################################
$title = "Must not use icmpv6 with ipv4 general permit";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.2.2.1; hardware = n2;}
}

area:a = {
 anchor = network:n1;
 router_attributes = { general_permit = icmpv6; }
}
END

$out = <<'END';
Error: icmpv6 must not be used in IPv4 general_permit of router_attributes of area:a
END

test_err($title, $in, $out);

############################################################
done_testing;
