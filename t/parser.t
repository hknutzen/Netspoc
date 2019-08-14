#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

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
$title = "Missing model for managed router";
############################################################

$in = <<'END';
router:R = {
 managed;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Missing 'model' for managed router:R
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
$title = "Unexptected attribute no_check";
############################################################

$in = <<'END';
router:R = {
 managed;
 model = IOS;
 interface:N = { ip = 10.1.1.1; hardware = e0; no_check; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Warning: Ignoring attribute 'no_check' at interface:R.N
END

test_warn($title, $in, $out);

############################################################
$title = "Unknown attribute in router";
############################################################

$in = <<'END';
router:R = {
 managed;
 model = ASA;
 xyz;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Unexpected token at line 4 of STDIN, near "xyz<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Unknown typed name in router";
############################################################

$in = <<'END';
router:R = {
 managed;
 model = ASA;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
 x:y;
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Unexpected token at line 5 of STDIN, near "x:y<--HERE-->;"
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
$title = "Unexpected attribute at interface";
############################################################

$in = <<'END';
router:R = {
 interface:N = { ip = 10.1.1.1; foo }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Unexpected token at line 2 of STDIN, near "foo<--HERE--> }"
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
Syntax error: Unexpected token at line 2 of STDIN, near "primary:p<--HERE--> = {} }"
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
$title = "Unnumbered with secondary interface";
############################################################

$in = <<'END';
router:R = {
 interface:N = { unnumbered; secondary:second = { ip = 10.1.1.1; } }
}
network:N = { unnumbered; }
END

$out = <<'END';
Error: interface:R.N.second must not be linked to unnumbered network:N
END

test_err($title, $in, $out);

############################################################
$title = "Negotiated with secondary interface";
############################################################

$in = <<'END';
router:R = {
 interface:N = { negotiated; secondary:second = { ip = 10.1.1.1; } }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Negotiated interface must not have secondary IP address at line 2 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Single secondary interface";
############################################################

$in = <<'END';
router:R = {
 interface:N = { secondary:second = { ip = 10.1.1.1; } }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Short interface must not have secondary IP address at line 2 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Virtual interface with bad attribute";
############################################################

$in = <<'END';
router:R = {
 interface:N = { ip = 10.1.1.1; virtual = { foo; } }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Unexpected token at line 2 of STDIN, near "foo<--HERE-->; } }"
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
$title = "Invalid separator in network name";
############################################################

$in = <<'END';
network:n1@vrf123 = {
END

$out = <<'END';
Syntax error: Invalid token at line 1 of STDIN, near "network:n1@vrf123<--HERE--> = {"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid separator in router name";
############################################################

$in = <<'END';
router:r1/bridged-part = {
END

$out = <<'END';
Syntax error: Invalid token at line 1 of STDIN, near "router:r1/bridged-part<--HERE--> = {"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid separator in area name";
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
$title = "Bad cert_id";
############################################################

$in = <<'END';
network:n = { ip = 10.1.1.0/24; cert_id = @b.c; }
END

$out = <<'END';
Syntax error: Domain name expected at line 1 of STDIN, near "cert_id = <--HERE-->@b.c"
END

test_err($title, $in, $out);

############################################################
$title = "Bad managed attribute";
############################################################

$in = <<'END';
router:r = {
 managed xxx;
 interface:n;
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Expected ';' or '=' at line 2 of STDIN, near "xxx<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Unexpected managed type";
############################################################

$in = <<'END';
router:r = {
 managed = xxx;
 interface:n;
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Expected value: secondary|standard|full|primary|local|routing_only at line 2 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Bad typed name as attribute of host";
############################################################

$in = <<'END';
network:n = {
 host:h = { ip = 10.1.1.1; xy:z; }
}
END

$out = <<'END';
Syntax error: Unexpected token at line 2 of STDIN, near "xy:z<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Bad token as attribute of host";
############################################################

$in = <<'END';
network:n = {
 host:h = { ip = 10.1.1.1; ; }
}
END

$out = <<'END';
Syntax error: Unexpected token at line 2 of STDIN, near "10.1.1.1; ;<--HERE--> }"
END

test_err($title, $in, $out);

############################################################
$title = "Bad typed name as attribute of network";
############################################################

$in = <<'END';
network:n = { xy:z; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "xy:z<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Bad token as attribute of network";
############################################################

$in = <<'END';
network:n = { ; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "network:n = { ;<--HERE--> }"
END

test_err($title, $in, $out);

############################################################
$title = "Network without IP";
############################################################

$in = <<'END';
network:n = { }
END

$out = <<'END';
Syntax error: Missing network IP at line 1 of STDIN, near "network:n = { }<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = "Duplicate IP in network";
############################################################

$in = <<'END';
network:n = { ip = 10.1.1.0/24; unnumbered; ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: Duplicate IP address at line 1 of STDIN
Error: Duplicate attribute 'ip' at line 1 of STDIN
Error: Duplicate attribute 'mask' at line 1 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "NAT without IP";
############################################################

$in = <<'END';
network:n1 = { nat:n = { } }
END

$out = <<'END';
Syntax error: Missing IP address at line 1 of STDIN, near "nat:n = { }<--HERE--> }"
END

test_err($title, $in, $out);

############################################################
$title = "Bad radius attribute";
############################################################

$in = <<'END';
network:n1 = { radius_attributes = { a = ; } }
END

$out = <<'END';
Syntax error: String expected at line 1 of STDIN, near "a = <--HERE-->; } }"
END

test_err($title, $in, $out);

############################################################
$title = "Unexpected NAT attribute";
############################################################

$in = <<'END';
network:n = {
 nat:n = { ip = 10.1.1.0/24; xyz; }
}
END

$out = <<'END';
Syntax error: Unexpected token at line 2 of STDIN, near "xyz<--HERE-->; }"
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
$title = 'Reference non network in subnet_of';
############################################################

$in = <<'END';
any:n1 = { link = network:n1; }
network:n1 = {
 ip = 10.1.1.0/24;
 subnet_of = any:n1;
}
END

$out = <<"END";
Error: Must only use network name in 'subnet_of' at line 4 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Attribute subnet_of at non loopback interface';
############################################################

$in = <<'END';
network:n = {
 ip = 10.1.1.0/24;
}

router:r = {
 interface:n = { ip = 10.1.1.1; subnet_of = network:n; }
}
END

$out = <<'END';
Error: Attribute 'subnet_of' is only valid for loopback interface at line 6 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in aggregate';
############################################################

$in = <<'END';
any:n = { xyz; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "xyz<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected typed name in aggregate';
############################################################

$in = <<'END';
any:n = { x:yz; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "x:yz<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Aggregate without attribute 'link'";
############################################################

$in = <<'END';
any:n = { }
END

$out = <<'END';
Syntax error: Attribute 'link' must be defined for any:n at line 1 of STDIN, near "any:n = { }<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid atttribute at aggregate with IP";
############################################################

$in = <<'END';
owner:o = { admins = a@b.c; }
any:n = {
 link = network:n;ip = 10.0.0.0/16;
 owner = o; has_unenforceable = restrict;
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Must not use attribute 'has_unenforceable' if IP is set for any:n
Error: Must not use attribute 'owner' if IP is set for any:n
END

test_err($title, $in, $out);

############################################################
$title = "Valid atttribute at aggregate with IP 0.0.0.0";
############################################################

$in = <<'END';
owner:o = { admins = a@b.c; }
any:n = {
 link = network:n;
 ip = 0.0.0.0/0;
 owner = o;
 no_check_supernet_rules;
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = "Invalid attribute in router_attributes";
############################################################

$in = <<'END';
area:n = {
 anchor = network:n;
 router_attributes = { xyz; }
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Unexpected attribute at line 3 of STDIN, near "xyz<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in area';
############################################################

$in = <<'END';
area:n = { xyz; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "xyz<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected typed name in area';
############################################################

$in = <<'END';
area:n = { x:yz; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "x:yz<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in crypto';
############################################################

$in = <<'END';
crypto:c = { xyz; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "xyz<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in owner';
############################################################

$in = <<'END';
owner:o = { xyz; }
END

$out = <<'END';
Syntax error: Unexpected token at line 1 of STDIN, near "xyz<--HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Shared topology";
############################################################

$topo = <<'END';
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
END

############################################################
$title = "Equally reference user";
############################################################

$in = $topo . <<'END';
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

$in = $topo . <<'END';
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
$title = "Invalid attribute at service";
############################################################

$in = <<'END';
service:s1 = {
 xyz;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Syntax error: Expected some valid attribute or definition of 'user' at line 2 of STDIN, near "xyz<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid rule at service";
############################################################

$in = <<'END';
service:s1 = {
 user = network:n1;
 allow src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Syntax error: Expected 'permit' or 'deny' at line 3 of STDIN, near "allow<--HERE--> src"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid rule with 'foreach'";
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = foreach network:n1, network:n2;
 permit src = user; dst = network:n3; prt = tcp 22;
}
END

$out = <<'END';
Warning: Rule of service:s1 should reference 'user' in 'src' and 'dst'
 because service has keyword 'foreach'
-- r
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
END

test_warn($title, $in, $out);

############################################################
$title = "Empty list of elements after 'user', 'src', 'dst'";
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = ;
 permit src = user; dst = network:n3; prt = tcp 22;
}
service:s2= {
 user = network:n1;
 permit src = ; dst = user; prt = tcp 80;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = ; prt = tcp 22;
}
END

$out = <<'END';
Warning: user of service:s1 is empty
Warning: src of service:s2 is empty
Warning: dst of service:s3 is empty
END

test_warn($title, $in, $out);

############################################################
$title = "Empty user and empty rules";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

group:g1 = ;
group:g2 = ;
protocolgroup:p1 = ;

service:s1 = {
 user = group:g1;
 permit src = user; dst = group:g2; prt = tcp 80;
}
service:s2 = {
 user = group:g1;
 permit src = user; dst = network:n1; prt = protocolgroup:p1;
}
service:s3 = {
 disabled;
 user = group:g1;
 permit src = user; dst = group:g2; prt = protocolgroup:p1;
}
END

$out = <<'END';
Warning: Must not define service:s1 with empty users and empty rules
Warning: Must not define service:s2 with empty users and empty rules
Warning: Must not define service:s3 with empty users and empty rules
END

test_warn($title, $in, $out);

############################################################
$title = "Non host as policy_distribution_point";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 managed;
 model = ASA;
 policy_distribution_point = network:n1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
END

$out = <<'END';
Error: Must only use 'host' in 'policy_distribution_point' of router:r
END

test_err($title, $in, $out);

############################################################
$title = "Unknown host as policy_distribution_point";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 managed;
 model = ASA;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
END

$out = <<'END';
Warning: Ignoring undefined host:h1 in 'policy_distribution_point' of router:r
END

test_warn($title, $in, $out);

############################################################
done_testing;
