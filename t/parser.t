#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = "Unknown model for managed router";
############################################################

$in = <<'END';
router:R = {
 managed; 
 model = foo;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Unknown router model at line 3 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Unknown extension for model";
############################################################

$in = <<'END';
router:R = {
 managed; 
 model = PIX, foo, bar;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Unknown extension foo at line 3 of STDIN
Error: Unknown extension bar at line 3 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Missing hardware at interface";
############################################################

# Processing of attribute 'no_in_acl' internally uses value of
# hardware.

$in = <<'END';
router:R = {
 managed; 
 model = ASA;
 interface:N = { ip = 10.1.1.1; no_in_acl; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Missing 'hardware' for interface:R.N
END

test_err($title, $in, $out);

############################################################
$title = "Multiple interfaces with attribute 'no_in_acl'";
############################################################

$in = <<'END';
network:N1 = { ip = 10.1.1.0/24; }
network:N2 = { ip = 10.1.2.0/24; }

router:R = {
 managed; 
 model = ASA;
 interface:N1 = { ip = 10.1.1.1; no_in_acl; hardware = n1; }
 interface:N2 = { ip = 10.1.2.1; no_in_acl; hardware = n2; }
}
END

$out = <<'END';
Error: At most one interface of router:R may use flag 'no_in_acl'
END

test_err($title, $in, $out);

############################################################
$title = "Multiple interfaces with 'no_in_acl' at one hardware";
############################################################

$in = <<'END';
network:N1 = { ip = 10.1.1.0/24; }
network:N2 = { ip = 10.1.2.0/24; }

router:R = {
 managed; 
 model = ASA;
 interface:N1 = { ip = 10.1.1.1; no_in_acl; hardware = x; }
 interface:N2 = { ip = 10.1.2.1; no_in_acl; hardware = x; }
}
END

$out = <<'END';
Error: Only one logical interface allowed at hardware 'x' of router:R
 because of attribute 'no_in_acl'
END

test_err($title, $in, $out);

############################################################
$title = "Short interface at managed router";
############################################################

$in = <<'END';
router:R = {
 managed; 
 model = ASA;
 interface:N = { hardware = inside; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Short definition of interface:R.N not allowed
END

test_err($title, $in, $out);

############################################################
$title = "Equally reference user";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r = {
 managed; 
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s = {
 user = network:n1;
 permit src = user, network:n2; dst = network:n3; prt = ip;
}
END

$out = <<'END';
Error: The sub-expressions of union in src of service:s equally must
 either reference 'user' or must not reference 'user'
END

test_err($title, $in, $out);

############################################################
$title = "Equally reference user with intersection";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r = {
 managed; 
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n1, network:n2;
 permit src = network:n3;
        dst = interface:r.n2,
              interface:[user].[all] &! interface:r.n2;
        prt = tcp 22;
}
END

$out = <<'END';
Error: The sub-expressions of union in dst of service:s1 equally must
 either reference 'user' or must not reference 'user'
END

test_err($title, $in, $out);

############################################################
done_testing;
