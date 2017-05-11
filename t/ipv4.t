#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
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
Error: Invalid IP address at line 1 of STDIN
Error: Invalid IP address at line 2 of STDIN
Error: Invalid IP address at line 3 of STDIN
Error: Invalid IP address at line 4 of STDIN
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
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = {ip = 10.2.2.1; hardware = E2;}
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
ip access-list extended E1_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 range 80 90
 deny ip any any
END

test_run($title, $in, $out);

############################################################
done_testing;