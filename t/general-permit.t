#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'General permit';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmp;
 interface:m = { ip = 10.2.2.2; hardware = e0; }
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
--r
ip access-list e0_in
 10 permit icmp any any
 20 permit tcp any any
 30 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No range permitted';
############################################################

$in = <<'END';
area:all = { anchor = network:n; router_attributes = { general_permit = protocol:ftp-data, tcp 80; } }
network:n = { ip = 10.1.1.0/24; }
protocol:ftp-data = tcp 20:1024-65535;
END

$out = <<'END';
Error: Must not use ports of 'protocol:ftp-data' in general_permit of area:all
Error: Must not use ports of 'tcp 80' in general_permit of area:all
END

test_err($title, $in, $out);

############################################################
$title = 'Check for useless inheritance';
############################################################

$in = <<'END';
area:all = { anchor = network:n; router_attributes = { general_permit = icmp, tcp; } }
network:n = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmp;
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
END
$out = <<'END';
Warning: Useless attribute 'general_permit' at router:r,
 it was already inherited from area:all
END

test_err($title, $in, $out);

############################################################
done_testing;
