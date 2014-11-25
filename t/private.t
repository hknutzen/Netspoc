#!perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Netsted private contexts';
############################################################

$in = <<'END';
-- public
network:n1 = { ip = 10.1.1.0/24; }
-- a.private/n1
router:r1 = { interface:n1; }
-- a.private/b.private/n2
router:r2 = { interface:n1; }
END

$out = <<'END';
Error: Nested private context is not supported:
 a.private/b.private
END

test_err($title, $in, $out);

############################################################
$title = 'Interface connected to network in private subdir';
############################################################

$in = <<'END';
-- subdir/a.private
network:n1 = { ip = 10.1.1.0/24; }
-- b
router:r1 = { interface:n1; }
-- c.private
router:r2 = { interface:n1; }
END

$out = <<'END';
Error: Public interface:r1.n1 must not be connected to a.private network:n1
Error: c.private interface:r2.n1 must not be connected to a.private network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Mixed private / public zone';
############################################################

$in = <<'END';
-- a.private
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 interface:n1;
 interface:n2;
}
-- b
network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: All networks of any:[network:n1] must have identical 'private' status
 - network:n1: a
 - network:n2: public
END

test_err($title, $in, $out);

############################################################
done_testing;
