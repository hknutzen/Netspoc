#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

my $topo =  <<'END';
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

$in = $topo . <<'END';
service:test = {
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
END

$out = <<'END';
Warning: service:test has unenforceable rules:
 src=host:x9; dst=host:x7
END

test_warn($title, $in, $out);

############################################################
$title = 'Zone ignoring unenforceable rule';
############################################################

$in .= <<'END';
any:x = { link = network:x; has_unenforceable; }
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Service ignoring unenforceable rule';
############################################################

$in = $topo . <<'END';
service:test = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Mixed ignoring and reporting unenforceable service';
############################################################
# Must not ignore others, if first is ignored.

$in = $topo . <<'END';
service:test1 = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
service:test2 = {
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 81;
}
END

$out = <<'END';
Warning: service:test2 has unenforceable rules:
 src=host:x9; dst=host:x7
END

test_warn($title, $in, $out);

############################################################
$title = 'Silent unenforceable rules';
############################################################

$in = $topo . <<'END';
service:test = {
 user = host:x7, host:y;
 permit src = user; dst = any:[user]; prt = tcp 80;
}
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Fully unenforceable rule';
############################################################

$in = <<'END';
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

$out = <<'END';
Warning: service:test is fully unenforceable
END

test_warn($title, $in, $out);

############################################################
$title = 'Useless attribute "has_unenforceable" at service';
############################################################

$in =~ s/#1//;

$out = <<'END';
Warning: Useless attribute 'has_unenforceable' at service:test
Warning: service:test is fully unenforceable
END

test_warn($title, $in, $out);

############################################################
$title = 'Useless attribute "has_unenforceable" at zone';
############################################################

$in = <<'END';
any:x = { 
 has_unenforceable;
 link = network:x;
}
network:x = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Warning: Useless attribute 'has_unenforceable' at any:x
END

test_warn($title, $in, $out);

############################################################
done_testing;
