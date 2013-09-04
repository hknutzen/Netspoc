#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3, $compiled);

############################################################
$title = 'Zone ignoring unenforceable rule';
############################################################

$in = <<END;
any:x = { link = network:y; has_unenforceable; }

network:x = { ip = 10.1.1.0/24; }
router:r = {
 interface:x;
 interface:y;
}
network:y = { ip = 10.2.2.0/24; }

service:test = {
 user = network:y;
 permit src = user; dst = network:x; prt = tcp 80;
}
END

$out1 = '';

eq_or_diff(compile($in), $out1, $title);

############################################################
$title = 'Warning about unenforceable rule';
############################################################

$in =~ s/has_unenforceable;//;

$out1 = <<END;
Warning: service:test is fully unenforceable
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
done_testing;
