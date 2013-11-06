#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out1, $head1, $out2, $head2, $out3, $head3, $compiled);

############################################################
$title = 'No admin IP found in any VRFs';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24; 
 host:netspoc = { ip = 10.2.2.222; policy_distribution_point; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t = { ip = 10.9.9.1; hardware = e1; }
}
network:t = { ip = 10.9.9.0/24; }
router:r1@v2 = {
 managed;
 model = NX-OS;
 interface:t = { ip = 10.9.9.2; hardware = e2; }
 interface:n = { ip = 10.1.1.1; hardware = e3; }
}
network:n = { ip = 10.1.1.0/24; }
END

$out1 = <<END;
Warning: Missing rule to reach at least one VRF of r1 from policy_distribution_point
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################

done_testing;
