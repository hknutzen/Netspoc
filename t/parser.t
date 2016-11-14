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
network:n1 = { ip = 10.1.1.0o/24; }
END

$out = <<'END';
Syntax error: IP address expected at line 1 of STDIN, near "10.1.1.0o/24<--HERE-->; }"
END

test_err($title, $in, $out);

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
 model = ASA, foo, bar;
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
$title = "Bad typed name as attribute of interface";
############################################################

$in = <<'END';
router:R = {
 interface:N = { ip = 10.1.1.1; primary:p = {} }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Expected nat or secondary interface definition at line 2 of STDIN, near "primary:p<--HERE--> = {} }"
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
$title = "Secondary interface without IP";
############################################################

$in = <<'END';
router:R = {
 interface:N = { ip = 10.1.1.1; secondary:second = {} }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Missing IP address at line 2 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Secondary interface with bad attribute";
############################################################

$in = <<'END';
router:R = {
 interface:N = { ip = 10.1.1.1; secondary:second = { foo; } }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Expected attribute 'ip' at line 2 of STDIN, near "foo<--HERE-->; } }"
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
$title = "Typed name expected";
############################################################

$in = <<'END';
network = {
END

$out = <<'END';
Syntax error: Typed name expected at line 1 of STDIN, near "network<--HERE--> = {"
END

test_err($title, $in, $out);

############################################################
$title = "Unknown global definition";
############################################################

$in = <<'END';
networkX:n1 = {
END

$out = <<'END';
Syntax error: Unknown global definition at line 1 of STDIN, near "networkX:n1<--HERE--> = {"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid separator in network";
############################################################

$in = <<'END';
network:n1@vrf123 = {
END

$out = <<'END';
Syntax error: Invalid token at line 1 of STDIN, near "network:n1@vrf123<--HERE--> = {"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid separator in router";
############################################################

$in = <<'END';
router:r1/bridged-part = {
END

$out = <<'END';
Syntax error: Invalid token at line 1 of STDIN, near "router:r1/bridged-part<--HERE--> = {"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid separator in area";
############################################################

$in = <<'END';
area:a1@vrf123 = {
END

$out = <<'END';
Syntax error: Invalid token at line 1 of STDIN, near "area:a1@vrf123<--HERE--> = {"
END

test_err($title, $in, $out);

############################################################
$title = "Unexpected end of file";
############################################################

$in = <<'END';
network:n1
END

$out = <<'END';
Syntax error: Unexpected end of file at line 1 of STDIN, near "network:n1<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = "Identifier expected";
############################################################

$in = <<'END';
network:n1 = { owner = }
END

$out = <<'END';
Syntax error: Identifier expected at line 1 of STDIN, near "owner = <--HERE-->}"
END

test_err($title, $in, $out);

############################################################
$title = "String expected";
############################################################

$in = <<'END';
owner:o1 = { admins = ; }
END

$out = <<'END';
Syntax error: String expected at line 1 of STDIN, near "admins = <--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Comma expected in union of values";
############################################################

$in = <<'END';
group:g1 = host:h1 host:h2;
END

$out = <<'END';
Syntax error: Comma expected in union of values at line 1 of STDIN, near "host:h2<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Comma expected in list of values";
############################################################

$in = <<'END';
owner:o = { admins = a@b.c x@y.z; }
END

$out = <<'END';
Syntax error: Comma expected in list of values at line 1 of STDIN, near "x@y.z<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Typed name expected";
############################################################

$in = <<'END';
group:g1 = host;
END

$out = <<'END';
Syntax error: Typed name expected at line 1 of STDIN, near "host<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Bad hostname";
############################################################

$in = <<'END';
group:g1 = host:id:;
END

$out = <<'END';
Syntax error: Hostname expected at line 1 of STDIN, near "host:id:<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Bad network name";
############################################################

$in = <<'END';
group:g1 = network:n1@vrf;
END

$out = <<'END';
Syntax error: Name or bridged name expected at line 1 of STDIN, near "network:n1@vrf<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Bad interface name";
############################################################

$in = <<'END';
group:g1 = interface:r;
END

$out = <<'END';
Syntax error: Interface name expected at line 1 of STDIN, near "interface:r<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Bad auto interface";
############################################################

$in = <<'END';
group:g1 = interface:r.[foo];
END

$out = <<'END';
Syntax error: Expected [auto|all] at line 1 of STDIN, near "interface:r.[foo<--HERE-->]"
END

test_err($title, $in, $out);

############################################################
$title = "Bad group name";
############################################################

$in = <<'END';
group:g1 = group:a@b;
END

$out = <<'END';
Syntax error: Name expected at line 1 of STDIN, near "group:a@b<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Bad NAT name";
############################################################

$in = <<'END';
network:n = { nat:a+b = { ip = 10.9.9.0/24; } ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Valid name expected at line 1 of STDIN, near "nat:a+b<--HERE--> = { ip"
END

test_err($title, $in, $out);

############################################################
$title = "Bad VPN id";
############################################################

$in = <<'END';
router:r = {
 interface:x = { id = a.b.c; }
}
END

$out = <<'END';
Syntax error: Id expected (a@b.c) at line 2 of STDIN, near "id = <--HERE-->a.b.c"
END

test_err($title, $in, $out);

############################################################
$title = "Must not use 'user' outside of rule";
############################################################

$in = <<'END';
group:g1 = user;
END

$out = <<'END';
Syntax error: Unexpected reference to 'user' at line 1 of STDIN, near "user<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Duplicate network definition";
############################################################

$in = <<'END';
-- file1
network:n1 = { ip = 10.1.1.0/24; }
-- file2
network:n1 = { ip = 10.1.2.0/24; }

router:r = {
 interface:n1;
}
END

$out = <<'END';
Error: Duplicate definition of network:n1 in file1 and file2
END

test_err($title, $in, $out);

############################################################
$title = "Duplicate host definition";
############################################################

$in = <<'END';
-- file1
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
-- file2
network:n2 = { ip = 10.1.2.0/24;
 host:h1 = { ip = 10.1.2.10; }
 host:h1 = { ip = 10.1.2.11; } 
}

router:r = {
 interface:n1;
 interface:n2;
}
END

$out = <<'END';
Error: Duplicate definition of host:h1 in file1 and file2
Error: Duplicate definition of host:h1 in file2
END

test_err($title, $in, $out);

############################################################
done_testing;
