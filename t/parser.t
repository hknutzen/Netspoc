#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3);

############################################################
$title = "Unknown model for managed router";
############################################################

$in = <<END;
router:R = {
 managed; 
 model = foo;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out1 = <<END;
Error: Unknown router model at line 3 of STDIN
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = "Unknown extension for model";
############################################################

$in = <<END;
router:R = {
 managed; 
 model = PIX, foo, bar;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out1 = <<END;
Error: Unknown extension foo at line 3 of STDIN
Error: Unknown extension bar at line 3 of STDIN
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = "Missing hardware at interface";
############################################################

# Processing of attribute 'no_in_acl' internally uses value of
# hardware.

$in = <<END;
router:R = {
 managed; 
 model = ASA;
 interface:N = { ip = 10.1.1.1; no_in_acl; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out1 = <<END;
Error: Missing 'hardware' for interface:R.N
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
done_testing;
