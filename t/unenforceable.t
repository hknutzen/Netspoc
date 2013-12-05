#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $in2, $out1, $head1, $compiled);

my $topo =  <<END;
network:x = { ip = 10.1.1.0/24; 
 host:x7 = { ip = 10.1.1.7; } 
 host:x9 = { ip = 10.1.1.9; } 
}
router:r = {
 model = IOS,FW;
 managed;
 interface:x = { ip = 10.1.1.1; hardware = e0; }
 interface:y = { ip = 10.2.2.2; hardware = e1; }
}
network:y = { ip = 10.2.2.0/24; 
 host:y = { ip = 10.2.2.9; } 
}
END

############################################################
$title = 'Unenforceable rule';
############################################################

$in = <<END;
$topo
service:test = {
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
END

$out1 = <<END;
Warning: service:test has unenforceable rules:
 src=host:x9; dst=host:x7
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Zone ignoring unenforceable rule';
############################################################

$in2 = <<END;
$in
any:x = { link = network:x; has_unenforceable; }
END

$out1 = '';

eq_or_diff(compile_err($in2), $out1, $title);

############################################################
$title = 'Service ignoring unenforceable rule';
############################################################

$in = <<END;
$topo
service:test = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
END

$out1 = '';

eq_or_diff(compile_err($in2), $out1, $title);

############################################################
$title = 'Silent unenforceable rules';
############################################################

$in = <<END;
$topo
service:test = {
 user = host:x7, host:y;
 permit src = user; dst = any:[user]; prt = tcp 80;
}
END

$out1 = '';

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Fully unenforceable rule';
############################################################

$in = <<END;
any:x = { 
 link = network:x;
}

network:x = { ip = 10.1.1.0/24; }
router:r = {
 interface:x;
 interface:y;
}
network:y = { ip = 10.2.2.0/24; }

service:test = {
 #1 has_unenforceable;
 user = network:y;
 permit src = user; dst = network:x; prt = tcp 80;
}
END

$out1 = <<END;
Warning: service:test is fully unenforceable
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Useless attribute "has_unenforceable" at service';
############################################################

$in2 = $in;
$in2 =~ s/#1//;

$out1 = <<END;
Warning: Useless attribute 'has_unenforceable' at service:test
Warning: service:test is fully unenforceable
END

eq_or_diff(compile_err($in2), $out1, $title);

############################################################
$title = 'Useless attribute "has_unenforceable" at zone';
############################################################

$in = <<END;
any:x = { 
 has_unenforceable;
 link = network:x;
}
network:x = { ip = 10.1.1.0/24; }
END

$out1 = <<END;
Warning: Useless attribute 'has_unenforceable' at any:x
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
done_testing;
