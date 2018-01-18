#!perl

# Enable printing of diagnostic messages.
use constant SHOW_DIAG => 1;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
END

############################################################
$title = 'Reuse all code files';
############################################################

$in = $topo . <<'END';

service:test = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
END

$out = <<'END';
DIAG: Reused .prev/r1
DIAG: Reused .prev/r2
DIAG: Reused .prev/r3
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r3
! n3_in
access-list n3_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
END

test_reuse_prev($title, $in, $in, $out);

############################################################
$title = 'Reuse some code files';
############################################################

my $in2 = $in . <<'END';
service:test2 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = tcp 80;
}
END

$out = <<'END';
DIAG: Reused .prev/r1
DIAG: Reused .prev/r3
--r2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_reuse_prev($title, $in, $in2, $out);

############################################################
done_testing;
