#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Global permit';
############################################################

$in = <<END;
network:m = { ip = 10.2.2.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = udp;
 interface:m = { ip = 10.2.2.2; hardware = e0; }
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
network:n = { ip = 10.1.1.0/24; }

global:permit = tcp, icmp;
END

$out = <<END;
--r
ip access-list e0_in
 10 permit icmp any any
 20 permit tcp any any
 30 permit udp any any
 40 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'No range permitted in global permit';
############################################################

$in = <<END;
network:n = { ip = 10.1.1.0/24; }
protocol:ftp-data = tcp 20:1024-65535;
global:permit = protocol:ftp-data, tcp 80;
END

$out = <<END;
Error: Must not use ports in global permit: protocol:ftp-data
Error: Must not use ports in global permit: tcp 80
END

test_err($title, $in, $out);

############################################################
done_testing;
