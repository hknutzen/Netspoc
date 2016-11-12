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
 host:range = { range = 10.1.1.6-10.1.1.11; }
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
 src=host:x7; dst=host:x7
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
$title = 'Mixed ignored and reported unenforceable service';
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
 src=host:x7; dst=host:x7
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
 permit src = any:[user]; dst = user; prt = tcp 25;
}
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Silent unenforceable rules with split range';
############################################################

$in = $topo . <<'END';
service:test = {
 user = host:range, host:y;
 permit src = user; dst = user; prt = tcp 80;
}
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Consider aggregates in zone cluster as equal';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}

network:t1 = { ip = 10.9.1.0/24; }

router:r2 = {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

service:s1 = {
 user = any:[network:n1],
        any:[network:n3],
        ;
 permit src = user; dst = user; prt = tcp 80;
}
END

# Warning about unenforceable rules between any:[network:n1] and
# any:[network:n2] is suppressed.
$out = <<'END';
-- r2
! t1_in
access-list t1_in extended permit tcp any any eq 80
access-list t1_in extended deny ip any any
access-group t1_in in interface t1
--
! n3_in
access-list n3_in extended permit tcp any any eq 80
access-list n3_in extended deny ip any any
access-group n3_in in interface n3
END

test_run($title, $in, $out);

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
