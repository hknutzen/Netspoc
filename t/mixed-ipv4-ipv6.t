#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Mixed IPv4 and IPv6';
############################################################

$in = <<'END';
-- file1
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
-- ipv6/file2
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 1000::abcd:1:0 ffff:ffff:ffff:ffff:ffff:ffff:ffff:0 1000::abcd:2:0 ffff:ffff:ffff:ffff:ffff:ffff:ffff:0 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'Mixed IPv6 and IPv4';
############################################################

$in =~ s|file1|ipv4/file1|;
$in =~ s|ipv6/file2|file2|;

test_run($title, $in, $out, '-ipv6');

############################################################
$title = 'Empty IPv6 topology';
############################################################

$in = <<'END';
-- file

-- ipv6/file

END

$out = <<'END';
Error: IPv6 topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Empty IPv4 topology';
############################################################

$in = <<'END';
-- file

-- ipv4

END

$out = <<'END';
Error: IPv4 topology seems to be empty
Aborted
END

test_err($title, $in, $out, '-ipv6');

############################################################
done_testing;
