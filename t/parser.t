#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$title = "Invalid IP address";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0o/24; }
END

$out = <<'END';
Error: invalid CIDR address: 10.1.1.0o/24 in 'ip' of network:n1
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
Error: Unknown model in router:R: foo
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
Error: Unknown extension in 'model' of router:R: foo
Error: Unknown extension in 'model' of router:R: bar
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
Error: Unexpected attribute in router:R: xyz
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
Error: Unexpected attribute in router:R: x:y
END

test_err($title, $in, $out);

############################################################
$title = "Invalid hardware name with comment character";
############################################################

$in = <<'END';
router:R = {
 managed;
 model = ASA;
 interface:N = { ip = 10.1.1.1; hardware = e0#3; }
}
network:N = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Expected ';' at line 5 of STDIN, near "--HERE-->}"
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
Syntax error: Expected '=' at line 2 of STDIN, near "foo --HERE-->}"
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
Error: Unexpected attribute in interface:R.N: primary:p
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
Error: Missing IP in secondary:second of interface:R.N
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
Error: Unexpected attribute in secondary:second of interface:R.N: foo
Error: Missing IP in secondary:second of interface:R.N
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
Error: interface:R.N without IP address must not have secondary address
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
Error: interface:R.N without IP address must not have secondary address
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
Error: interface:R.N without IP address must not have secondary address
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
Error: Unexpected attribute in 'virtual' of interface:R.N: foo
Error: Missing IP in 'virtual' of interface:R.N
END

test_err($title, $in, $out);

############################################################
$title = "Typed name expected";
############################################################

$in = <<'END';
network = {
END

$out = <<'END';
Syntax error: Typed name expected at line 1 of STDIN, near "--HERE-->network"
END

test_err($title, $in, $out);

############################################################
$title = "Unknown global definition";
############################################################

$in = <<'END';
networkX:n1 = {
END

$out = <<'END';
Syntax error: Unknown global definition at line 1 of STDIN, near "--HERE-->networkX:n1"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid character in network name";
############################################################

$in = <<'END';
network:n1@vrf123 = {}
END

$out = <<'END';
Error: Invalid identifier in definition of 'network:n1@vrf123'
Error: Missing IP address for network:n1@vrf123
END

test_err($title, $in, $out);

############################################################
$title = "Invalid character in router name";
############################################################

$in = <<'END';
router:r1/bridged-part = {}
END

$out = <<'END';
Error: Invalid identifier in definition of 'router:r1/bridged-part'
END

test_err($title, $in, $out);

############################################################
$title = "Invalid character in area name";
############################################################

$in = <<'END';
area:a1@vrf123 = {}
END

$out = <<'END';
Error: Invalid identifier in definition of 'area.a1@vrf123'
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a1@vrf123
END

test_err($title, $in, $out);

############################################################
$title = "Unexpected end of file";
############################################################

$in = <<'END';
network:n1
END

$out = <<'END';
Syntax error: Expected '=' at line 1 of STDIN, at EOF
END

test_err($title, $in, $out);

############################################################
$title = "Identifier expected";
############################################################

$in = <<'END';
network:n1 = { owner = }
END

$out = <<'END';
Syntax error: Unexpected separator '}' at line 1 of STDIN, near "owner = --HERE-->}"
END

test_err($title, $in, $out);

############################################################
$title = "String expected";
############################################################

$in = <<'END';
owner:o1 = { admins = ; }
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: List of values expected in 'admins' of owner:o1
END

test_err($title, $in, $out);

############################################################
$title = "Comma expected in union of values (1)";
############################################################

$in = <<'END';
group:g1 = host:h1 host:h2;
END

$out = <<'END';
Syntax error: Expected ';' at line 1 of STDIN, near "host:h1 --HERE-->host:h2"
END

test_err($title, $in, $out);

############################################################
$title = "Comma expected in list of values (2)";
############################################################

$in = <<'END';
owner:o = { admins = a@b.c x@y.z; }
END

$out = <<'END';
Syntax error: Expected ';' at line 1 of STDIN, near "a@b.c --HERE-->x@y.z"
END

test_err($title, $in, $out);

############################################################
$title = "Typed name expected";
############################################################

$in = <<'END';
group:g1 = host;
END

$out = <<'END';
Syntax error: Typed name expected at line 1 of STDIN, near "group:g1 = --HERE-->host"
END

test_err($title, $in, $out);

############################################################
$title = "Bad hostname in definition";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:id: = { ip = 10.1.1.10; } }
END

$out = <<'END';
Error: Invalid name in definition of 'host:id:'
END

test_err($title, $in, $out);

############################################################
$title = "Bad hostname in reference";
############################################################

$in = <<'END';
service:s1 = {
 user = network:n1, host:id:;
 permit src = user; dst = user; prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Can't resolve host:id: in user of service:s1
END

test_err($title, $in, $out);

############################################################
$title = "Bad network name in definition";
############################################################

$in = <<'END';
network:n1@vrf = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Invalid identifier in definition of 'network:n1@vrf'
END

test_err($title, $in, $out);

############################################################
$title = "Bad network name in reference";
############################################################

$in = <<'END';
service:s1 = {
 user = network:n1, network:n1@vrf:;
 permit src = user; dst = user; prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Can't resolve network:n1@vrf: in user of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'Empty interface name';
############################################################

$in = <<'END';
group:g1 = interface:;
END

$out = <<'END';
Syntax error: Interface name expected at line 1 of STDIN, near "group:g1 = --HERE-->interface:"
END

test_err($title, $in, $out);

############################################################
$title = "Bad interface name";
############################################################

$in = <<'END';
group:g1 = interface:r;
END

$out = <<'END';
Syntax error: Interface name expected at line 1 of STDIN, near "group:g1 = --HERE-->interface:r"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid interface names";
############################################################

$in = <<'END';
service:s1 = {
 user = network:n1, interface:r1., interface:r1.n1@vrf2, interface:r.n.123.nn;
 permit src = user; dst = user; prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Can't resolve interface:r1. in user of service:s1
Error: Can't resolve interface:r1.n1@vrf2 in user of service:s1
Error: Can't resolve interface:r.n.123.nn in user of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'Missing [any|all]';
############################################################

$in = <<'END';
group:g1 = interface:r1.[ ;
END

$out = <<'END';
Syntax error: Expected [auto|all] at line 1 of STDIN, near "interface:r1.[ --HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = "Bad auto interface";
############################################################

$in = <<'END';
group:g1 = interface:r.[foo];
END

$out = <<'END';
Syntax error: Expected [auto|all] at line 1 of STDIN, near "interface:r.[--HERE-->foo]"
END

test_err($title, $in, $out);

############################################################
$title = "Unexpected network name in interfaces of network";
############################################################

$in = <<'END';
group:g1 = interface:[network:n1].n2;
END

$out = <<'END';
Syntax error: Expected '.[' at line 1 of STDIN, near "interface:[network:n1]--HERE-->.n2"
END

test_err($title, $in, $out);

############################################################
$title = "Bad group name in definition";
############################################################

$in = <<'END';
group:a@b = ;
END

$out = <<'END';
Error: Invalid identifier in definition of 'group.a@b'
END

test_err($title, $in, $out);

############################################################
$title = "Bad NAT name";
############################################################

$in = <<'END';
network:n = { nat:a+b = { ip = 10.9.9.0/24; } ip = 10.1.1.0/24; }
END

$out = <<'END';
Syntax error: Expected '=' at line 1 of STDIN, near "nat:a--HERE-->+b"
END

test_err($title, $in, $out);

############################################################
$title = "Bad VPN id";
############################################################

$in = <<'END';
router:r = {
 interface:n1 = { id = a.b.c; }
}
network:n1 = { unnumbered; }
END

$out = <<'END';
Error: Invalid 'id' in interface:r.n1: a.b.c
Error: Attribute 'id' is only valid with 'spoke' at interface:r.n1
END

test_err($title, $in, $out);

############################################################
$title = "Ignore cert_id";
############################################################

$in = <<'END';
network:n = { ip = 10.1.1.0/24; cert_id = a.b.c; }
END

$out = <<'END';
Warning: Ignoring 'cert_id' at network:n
END

test_warn($title, $in, $out);

############################################################
$title = "Bad cert_id";
############################################################

$in = <<'END';
network:n = {
 ip = 10.1.1.0/24; cert_id = @b.c;
 host:h = { ip = 10.1.1.1; ldap_id = a@b.c; }
}
END

$out = <<'END';
Error: Attribute 'ldap_Id' must only be used together with IP range at host:h
Error: Domain name expected in attribute 'cert_id' of network:n
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
Syntax error: Expected '=' at line 2 of STDIN, near "managed --HERE-->xxx"
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
Error: Invalid value for 'managed' of router:r: xxx
END

test_err($title, $in, $out);

############################################################
$title = "Bad typed name as attribute of host";
############################################################

$in = <<'END';
network:n = {
 ip = 10.1.1.0/24;
 host:h = { ip = 10.1.1.1; xy:z; }
}
END

$out = <<'END';
Error: Unexpected attribute in host:h: xy:z
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
Syntax error: Unexpected separator ';' at line 2 of STDIN, near "10.1.1.1; --HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Bad typed name as attribute of network";
############################################################

$in = <<'END';
network:n = { xy:z; }
END

$out = <<'END';
Error: Unexpected attribute in network:n: xy:z
Error: Missing IP address for network:n
END

test_err($title, $in, $out);

############################################################
$title = "Bad token as attribute of network";
############################################################

$in = <<'END';
network:n = { ; }
END

$out = <<'END';
Syntax error: Unexpected separator ';' at line 1 of STDIN, near "network:n = { --HERE-->; }"
END

test_err($title, $in, $out);

############################################################
$title = "Network without IP";
############################################################

$in = <<'END';
network:n = { }
END

$out = <<'END';
Error: Missing IP address for network:n
END

test_err($title, $in, $out);

############################################################
$title = "Duplicate IP in network";
############################################################

$in = <<'END';
network:n = { ip = 10.1.1.0/24; unnumbered; ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: Duplicate attribute 'ip' in network:n
Error: Unnumbered network:n must not have attribute 'ip'
Error: Unnumbered network:n must not have attribute 'ip'
END

test_err($title, $in, $out);

############################################################
$title = "NAT without IP";
############################################################

$in = <<'END';
network:n1 = { nat:n = { } }
END

$out = <<'END';
Error: Missing IP address in nat:n of network:n1
Error: Missing IP address for network:n1
END

test_err($title, $in, $out);

############################################################
$title = "Ignoring radius attribute";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; radius_attributes = { a = b; } }
END

$out = <<'END';
Warning: Ignoring 'radius_attributes' at network:n1
END

test_warn($title, $in, $out);

############################################################
$title = "Bad identifier in radius attribute";
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24; radius_attributes = { a.1 = 1; }
 host:id:a@b.c = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Invalid identifier 'a.1' in radius_attributes of network:n1
END

test_err($title, $in, $out);

############################################################
$title = "Bad radius attribute with comment character";
############################################################

$in = <<'END';
network:n1 = { radius_attributes = { banner = Welcome #two; } }
END

$out = <<'END';
Syntax error: Expected ';' at line 1 of STDIN, at EOF
END

test_err($title, $in, $out);

############################################################
$title = "Unexpected NAT attribute";
############################################################

$in = <<'END';
network:n = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 10.9.9.0/24; xyz; }
}
END

$out = <<'END';
Error: Unexpected attribute in nat:n of network:n: xyz
END

test_err($title, $in, $out);

############################################################
$title = 'Service without user';
############################################################

$in = <<'END';
service:s1 = {
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<'END';
Syntax error: Expected '=' at line 2 of STDIN, near "permit --HERE-->src"
END

test_err($title, $in, $out);

############################################################
$title = "Must not use 'user' outside of rule";
############################################################

$in = <<'END';
group:g1 = user;
network:n1 = { ip = 10.1.1.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = group:g1; prt = tcp 80;
}
END

$out = <<'END';
Error: Unexpected reference to 'user' in group:g1
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
Error: Must only use network name in 'subnet_of' of network:n1
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
Error: Attribute 'subnet_of' must not be used at interface:r.n
 It is only valid together with attribute 'loopback'
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in aggregate';
############################################################

$in = <<'END';
any:n = { xyz; x:yz; link = network:n1; }
network:n1 = { ip = 10.1.2.0/24; }

END

$out = <<'END';
Error: Unexpected attribute in any:n: xyz
Error: Unexpected attribute in any:n: x:yz
END

test_err($title, $in, $out);

############################################################
$title = "Aggregate without attribute 'link'";
############################################################

$in = <<'END';
any:n = { }
network:n1 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: Attribute 'link' must be defined for any:n
END

test_err($title, $in, $out);

############################################################
$title = "Invalid attribute at aggregate with IP";
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
END

test_err($title, $in, $out);

############################################################
$title = "Valid attribute at aggregate with IP 0.0.0.0";
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
$title = "Untyped name in anchor";
############################################################

$in = <<'END';
area:n = {
 anchor = n;
}
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Typed name expected in 'anchor' of area:n
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:n
END

test_err($title, $in, $out);

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
Error: Unexpected attribute in router_attributes of area:n: xyz
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in area';
############################################################

$in = <<'END';
area:n = { xyz; anchor = network:n; x:yz; }
network:n = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Unexpected attribute in area:n: xyz
Error: Unexpected attribute in area:n: x:yz
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in crypto';
############################################################

$in = <<'END';
crypto:c = { xyz; }
END

$out = <<'END';
Error: Unexpected attribute in crypto:c: xyz
Error: Missing 'type' for crypto:c
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected token in owner';
############################################################

$in = <<'END';
owner:o = { xyz; }
network:n1 = { ip = 10.1.1.0/24; owner = o; }
END

$out = <<'END';
Error: Unexpected attribute in owner:o: xyz
Error: Missing attribute 'admins' in owner:o of network:n1
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
Error: The sub-expressions of union in 'src' of service:s equally must
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
Error: The sub-expressions of union in 'dst' of service:s1 equally must
 either reference 'user' or must not reference 'user'
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid attribute syntax in service';
############################################################

$in = <<'END';
service:s1 = {
 overlaps = service:s2,,;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<'END';
Syntax error: Unexpected separator ',' at line 2 of STDIN, near "service:s2,--HERE-->,;"
END

test_err($title, $in, $out);

############################################################
$title = "Invalid attribute at service";
############################################################

$in = $topo . <<'END';
service:s1 = {
 xyz;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Error: Unexpected attribute in service:s1: xyz
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
Syntax error: Expected 'permit' or 'deny' at line 3 of STDIN, near " --HERE-->allow"
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
Warning: Each rule of service:s1 should reference 'user' in 'src' and 'dst'
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
Error: Must only use host name in 'policy_distribution_point' of router:r
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
