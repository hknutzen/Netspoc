
############################################################
=TITLE=Invalid IP address
=INPUT=
network:n1 = { ip = 10.1.1.0o/24; }
=END=
=ERROR=
Error: invalid CIDR address: 10.1.1.0o/24 in 'ip' of network:n1
=END=

############################################################
=TITLE=Unknown model for managed router
=INPUT=
router:R = {
 managed;
 model = foo;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unknown model in router:R: foo
=END=

############################################################
=TITLE=Missing model for managed router
=INPUT=
router:R = {
 managed;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Missing 'model' for managed router:R
=END=

############################################################
=TITLE=Unknown extension for model
=INPUT=
router:R = {
 managed;
 model = ASA, foo, bar;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unknown extension in 'model' of router:R: foo
Error: Unknown extension in 'model' of router:R: bar
=END=

############################################################
=TITLE=Unexptected attribute no_check
=INPUT=
router:R = {
 managed;
 model = IOS;
 interface:N = { ip = 10.1.1.1; hardware = e0; no_check; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=WARNING=
Warning: Ignoring attribute 'no_check' at interface:R.N
=END=

############################################################
=TITLE=Unknown attribute in router
=INPUT=
router:R = {
 managed;
 model = ASA;
 xyz;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in router:R: xyz
=END=

############################################################
=TITLE=Unknown typed name in router
=INPUT=
router:R = {
 managed;
 model = ASA;
 interface:N = { ip = 10.1.1.1; hardware = e0; }
 x:y;
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in router:R: x:y
=END=

############################################################
=TITLE=Invalid hardware name with comment character
=INPUT=
router:R = {
 managed;
 model = ASA;
 interface:N = { ip = 10.1.1.1; hardware = e0#3; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Expected ';' at line 5 of STDIN, near "--HERE-->}"
Aborted
=END=

############################################################
=TITLE=Missing hardware at interface
# Processing of attribute 'no_in_acl' internally uses value of
# hardware.
=INPUT=
router:R = {
 managed;
 model = ASA;
 interface:N = { ip = 10.1.1.1; no_in_acl; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Missing 'hardware' for interface:R.N
=END=

############################################################
=TITLE=Multiple interfaces with attribute 'no_in_acl'
=INPUT=
network:N1 = { ip = 10.1.1.0/24; }
network:N2 = { ip = 10.1.2.0/24; }
router:R = {
 managed;
 model = ASA;
 interface:N1 = { ip = 10.1.1.1; no_in_acl; hardware = n1; }
 interface:N2 = { ip = 10.1.2.1; no_in_acl; hardware = n2; }
}
=END=
=ERROR=
Error: At most one interface of router:R may use flag 'no_in_acl'
=END=

############################################################
=TITLE=Multiple interfaces with 'no_in_acl' at one hardware
=INPUT=
network:N1 = { ip = 10.1.1.0/24; }
network:N2 = { ip = 10.1.2.0/24; }
router:R = {
 managed;
 model = ASA;
 interface:N1 = { ip = 10.1.1.1; no_in_acl; hardware = x; }
 interface:N2 = { ip = 10.1.2.1; no_in_acl; hardware = x; }
}
=END=
=ERROR=
Error: Only one logical interface allowed at hardware 'x' of router:R
 because of attribute 'no_in_acl'
=END=

############################################################
=TITLE=Unexpected attribute at interface
=INPUT=
router:R = {
 interface:N = { ip = 10.1.1.1; foo }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Expected '=' at line 2 of STDIN, near "foo --HERE-->}"
Aborted
=END=

############################################################
=TITLE=Bad typed name as attribute of interface
=INPUT=
router:R = {
 interface:N = { ip = 10.1.1.1; primary:p = {} }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in interface:R.N: primary:p
=END=

############################################################
=TITLE=Short interface at managed router
=INPUT=
router:R = {
 managed;
 model = ASA;
 interface:N = { hardware = inside; }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Short definition of interface:R.N not allowed
=END=

############################################################
=TITLE=Secondary interface without IP
=INPUT=
router:R = {
 interface:N = { ip = 10.1.1.1; secondary:second = {} }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Missing IP in secondary:second of interface:R.N
=END=

############################################################
=TITLE=Secondary interface with bad attribute
=INPUT=
router:R = {
 interface:N = { ip = 10.1.1.1; secondary:second = { foo; } }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in secondary:second of interface:R.N: foo
Error: Missing IP in secondary:second of interface:R.N
=END=

############################################################
=TITLE=Unnumbered with secondary interface
=INPUT=
router:R = {
 interface:N = { unnumbered; secondary:second = { ip = 10.1.1.1; } }
}
network:N = { unnumbered; }
=END=
=ERROR=
Error: interface:R.N without IP address must not have secondary address
=END=

############################################################
=TITLE=Negotiated with secondary interface
=INPUT=
router:R = {
 interface:N = { negotiated; secondary:second = { ip = 10.1.1.1; } }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: interface:R.N without IP address must not have secondary address
=END=

############################################################
=TITLE=Single secondary interface
=INPUT=
router:R = {
 interface:N = { secondary:second = { ip = 10.1.1.1; } }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: interface:R.N without IP address must not have secondary address
=END=

############################################################
=TITLE=Virtual interface with bad attribute
=INPUT=
router:R = {
 interface:N = { ip = 10.1.1.1; virtual = { foo; } }
}
network:N = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in 'virtual' of interface:R.N: foo
Error: Missing IP in 'virtual' of interface:R.N
=END=

############################################################
=TITLE=Typed name expected
=INPUT=
network = {
=END=
=ERROR=
Error: Typed name expected at line 1 of STDIN, near "--HERE-->network"
Aborted
=END=

############################################################
=TITLE=Unknown global definition
=INPUT=
networkX:n1 = {
=END=
=ERROR=
Error: Unknown global definition at line 1 of STDIN, near "--HERE-->networkX:n1"
Aborted
=END=

############################################################
=TITLE=Invalid character in network name
=INPUT=
network:n1@vrf123 = {}
=END=
=ERROR=
Error: Invalid identifier in definition of 'network:n1@vrf123'
Error: Missing IP address for network:n1@vrf123
=END=

############################################################
=TITLE=Invalid character in router name
=INPUT=
router:r1/bridged-part = {}
=END=
=ERROR=
Error: Invalid identifier in definition of 'router:r1/bridged-part'
=END=

############################################################
=TITLE=Invalid character in area name
=INPUT=
area:a1@vrf123 = {}
=END=
=ERROR=
Error: Invalid identifier in definition of 'area.a1@vrf123'
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a1@vrf123
=END=

############################################################
=TITLE=Unexpected end of file
=INPUT=
network:n1
=END=
=ERROR=
Error: Expected '=' at line 1 of STDIN, at EOF
Aborted
=END=

############################################################
=TITLE=Identifier expected
=INPUT=
network:n1 = { owner = }
=END=
=ERROR=
Error: Unexpected separator '}' at line 1 of STDIN, near "owner = --HERE-->}"
Aborted
=END=

############################################################
=TITLE=String expected
=INPUT=
owner:o1 = { admins = ; }
network:n1 = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: List of values expected in 'admins' of owner:o1
=END=

############################################################
=TITLE=Comma expected in union of values (1)
=INPUT=
group:g1 = host:h1 host:h2;
=END=
=ERROR=
Error: Expected ';' at line 1 of STDIN, near "host:h1 --HERE-->host:h2"
Aborted
=END=

############################################################
=TITLE=Comma expected in list of values (2)
=INPUT=
owner:o = { admins = a@b.c x@y.z; }
=END=
=ERROR=
Error: Expected ';' at line 1 of STDIN, near "a@b.c --HERE-->x@y.z"
Aborted
=END=

############################################################
=TITLE=Typed name expected
=INPUT=
group:g1 = host;
=END=
=ERROR=
Error: Typed name expected at line 1 of STDIN, near "group:g1 = --HERE-->host"
Aborted
=END=

############################################################
=TITLE=Bad hostname in definition
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:id: = { ip = 10.1.1.10; } }
=END=
=ERROR=
Error: Invalid name in definition of 'host:id:'
=END=

############################################################
=TITLE=Bad hostname in reference
=INPUT=
service:s1 = {
 user = network:n1, host:id:;
 permit src = user; dst = user; prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Can't resolve host:id: in user of service:s1
=END=

############################################################
=TITLE=Bad network name in definition
=INPUT=
network:n1@vrf = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Invalid identifier in definition of 'network:n1@vrf'
=END=

############################################################
=TITLE=Bad network name in reference
=INPUT=
service:s1 = {
 user = network:n1, network:n1@vrf:;
 permit src = user; dst = user; prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Can't resolve network:n1@vrf: in user of service:s1
=END=

############################################################
=TITLE=Empty interface name
=INPUT=
group:g1 = interface:;
=END=
=ERROR=
Error: Interface name expected at line 1 of STDIN, near "group:g1 = --HERE-->interface:"
Aborted
=END=

############################################################
=TITLE=Bad interface name
=INPUT=
group:g1 = interface:r;
=END=
=ERROR=
Error: Interface name expected at line 1 of STDIN, near "group:g1 = --HERE-->interface:r"
Aborted
=END=

############################################################
=TITLE=Invalid interface names
=INPUT=
service:s1 = {
 user = network:n1, interface:r1., interface:r1.n1@vrf2, interface:r.n.123.nn;
 permit src = user; dst = user; prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Can't resolve interface:r1. in user of service:s1
Error: Can't resolve interface:r1.n1@vrf2 in user of service:s1
Error: Can't resolve interface:r.n.123.nn in user of service:s1
=END=

############################################################
=TITLE=Missing [any|all]
=INPUT=
group:g1 = interface:r1.[ ;
=END=
=ERROR=
Error: Expected [auto|all] at line 1 of STDIN, near "interface:r1.[ --HERE-->;"
Aborted
=END=

############################################################
=TITLE=Bad auto interface
=INPUT=
group:g1 = interface:r.[foo];
=END=
=ERROR=
Error: Expected [auto|all] at line 1 of STDIN, near "interface:r.[--HERE-->foo]"
Aborted
=END=

############################################################
=TITLE=Unexpected network name in interfaces of network
=INPUT=
group:g1 = interface:[network:n1].n2;
=END=
=ERROR=
Error: Expected '.[' at line 1 of STDIN, near "interface:[network:n1]--HERE-->.n2"
Aborted
=END=

############################################################
=TITLE=Bad group name in definition
=INPUT=
group:a@b = ;
=END=
=ERROR=
Error: Invalid identifier in definition of 'group.a@b'
=END=

############################################################
=TITLE=Bad NAT name
=INPUT=
network:n = { nat:a+b = { ip = 10.9.9.0/24; } ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Expected '=' at line 1 of STDIN, near "nat:a--HERE-->+b"
Aborted
=END=

############################################################
=TITLE=Bad VPN id
=INPUT=
router:r = {
 interface:n1 = { id = a.b.c; }
}
network:n1 = { unnumbered; }
=END=
=ERROR=
Error: Invalid 'id' in interface:r.n1: a.b.c
Error: Attribute 'id' is only valid with 'spoke' at interface:r.n1
=END=

############################################################
=TITLE=Ignore cert_id
=INPUT=
network:n = { ip = 10.1.1.0/24; cert_id = a.b.c; }
=END=
=WARNING=
Warning: Ignoring 'cert_id' at network:n
=END=

############################################################
=TITLE=Bad cert_id
=INPUT=
network:n = {
 ip = 10.1.1.0/24; cert_id = @b.c;
 host:h = { ip = 10.1.1.1; ldap_id = a@b.c; }
}
=END=
=ERROR=
Error: Attribute 'ldap_Id' must only be used together with IP range at host:h
Error: Domain name expected in attribute 'cert_id' of network:n
=END=

############################################################
=TITLE=Bad managed attribute
=INPUT=
router:r = {
 managed xxx;
 interface:n;
}
network:n = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Expected '=' at line 2 of STDIN, near "managed --HERE-->xxx"
Aborted
=END=

############################################################
=TITLE=Unexpected managed type
=INPUT=
router:r = {
 managed = xxx;
 interface:n;
}
network:n = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Invalid value for 'managed' of router:r: xxx
=END=

############################################################
=TITLE=Bad typed name as attribute of host
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 host:h = { ip = 10.1.1.1; xy:z; }
}
=END=
=ERROR=
Error: Unexpected attribute in host:h: xy:z
=END=

############################################################
=TITLE=Bad token as attribute of host
=INPUT=
network:n = {
 host:h = { ip = 10.1.1.1; ; }
}
=END=
=ERROR=
Error: Unexpected separator ';' at line 2 of STDIN, near "10.1.1.1; --HERE-->; }"
Aborted
=END=

############################################################
=TITLE=Bad typed name as attribute of network
=INPUT=
network:n = { xy:z; }
=END=
=ERROR=
Error: Unexpected attribute in network:n: xy:z
Error: Missing IP address for network:n
=END=

############################################################
=TITLE=Bad token as attribute of network
=INPUT=
network:n = { ; }
=END=
=ERROR=
Error: Unexpected separator ';' at line 1 of STDIN, near "network:n = { --HERE-->; }"
Aborted
=END=

############################################################
=TITLE=Network without IP
=INPUT=
network:n = { }
=END=
=ERROR=
Error: Missing IP address for network:n
=END=

############################################################
=TITLE=Duplicate IP in network
=INPUT=
network:n = { ip = 10.1.1.0/24; unnumbered; ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Duplicate attribute 'ip' in network:n
Error: Unnumbered network:n must not have attribute 'ip'
Error: Unnumbered network:n must not have attribute 'ip'
=END=

############################################################
=TITLE=NAT without IP
=INPUT=
network:n1 = { nat:n = { } }
=END=
=ERROR=
Error: Missing IP address in nat:n of network:n1
Error: Missing IP address for network:n1
=END=

############################################################
=TITLE=Ignoring radius attribute
=INPUT=
network:n1 = { ip = 10.1.1.0/24; radius_attributes = { a = b; } }
=END=
=WARNING=
Warning: Ignoring 'radius_attributes' at network:n1
=END=

############################################################
=TITLE=Bad identifier in radius attribute
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24; radius_attributes = { a.1 = 1; }
 host:id:a@b.c = { ip = 10.1.1.1; }
}
=END=
=ERROR=
Error: Invalid identifier 'a.1' in radius_attributes of network:n1
=END=

############################################################
=TITLE=Bad radius attribute with comment character
=INPUT=
network:n1 = { radius_attributes = { banner = Welcome #two; } }
=END=
=ERROR=
Error: Expected ';' at line 1 of STDIN, at EOF
Aborted
=END=

############################################################
=TITLE=Unexpected NAT attribute
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 10.9.9.0/24; xyz; }
}
=END=
=ERROR=
Error: Unexpected attribute in nat:n of network:n: xyz
=END=

############################################################
=TITLE=Service without user
=INPUT=
service:s1 = {
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=ERROR=
Error: Expected '=' at line 2 of STDIN, near "permit --HERE-->src"
Aborted
=END=

############################################################
=TITLE=Must not use 'user' outside of rule
=INPUT=
group:g1 = user;
network:n1 = { ip = 10.1.1.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = group:g1; prt = tcp 80;
}
=END=
=ERROR=
Error: Unexpected reference to 'user' in group:g1
=END=

############################################################
=TITLE=Duplicate network definition
=INPUT=
-- file1
network:n1 = { ip = 10.1.1.0/24; }
-- file2
network:n1 = { ip = 10.1.2.0/24; }
router:r = {
 interface:n1;
}
=END=
=ERROR=
Error: Duplicate definition of network:n1 in file1 and file2
=END=

############################################################
=TITLE=Duplicate host definition
=INPUT=
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
=END=
=ERROR=
Error: Duplicate definition of host:h1 in file1 and file2
Error: Duplicate definition of host:h1 in file2
=END=

############################################################
=TITLE=Reference non network in subnet_of
=INPUT=
any:n1 = { link = network:n1; }
network:n1 = {
 ip = 10.1.1.0/24;
 subnet_of = any:n1;
}
=END=
=ERROR=
Error: Must only use network name in 'subnet_of' of network:n1
=END=

############################################################
=TITLE=Attribute subnet_of at non loopback interface
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
}
router:r = {
 interface:n = { ip = 10.1.1.1; subnet_of = network:n; }
}
=END=
=ERROR=
Error: Attribute 'subnet_of' must not be used at interface:r.n
 It is only valid together with attribute 'loopback'
=END=

############################################################
=TITLE=Unexpected token in aggregate
=INPUT=
any:n = { xyz; x:yz; link = network:n1; }
network:n1 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in any:n: xyz
Error: Unexpected attribute in any:n: x:yz
=END=

############################################################
=TITLE=Aggregate without attribute 'link'
=INPUT=
any:n = { }
network:n1 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Attribute 'link' must be defined for any:n
=END=

############################################################
=TITLE=Invalid attribute at aggregate with IP
=INPUT=
owner:o = { admins = a@b.c; }
any:n = {
 link = network:n;ip = 10.0.0.0/16;
 owner = o; has_unenforceable = restrict;
}
network:n = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Must not use attribute 'has_unenforceable' if IP is set for any:n
=END=

############################################################
=TITLE=Valid attribute at aggregate with IP 0.0.0.0
=INPUT=
owner:o = { admins = a@b.c; }
any:n = {
 link = network:n;
 ip = 0.0.0.0/0;
 owner = o;
 no_check_supernet_rules;
}
network:n = { ip = 10.1.1.0/24; }
=END=
=WARNING=NONE

############################################################
=TITLE=Untyped name in anchor
=INPUT=
area:n = {
 anchor = n;
}
network:n = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Typed name expected in 'anchor' of area:n
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:n
=END=

############################################################
=TITLE=Invalid attribute in router_attributes
=INPUT=
area:n = {
 anchor = network:n;
 router_attributes = { xyz; }
}
network:n = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in router_attributes of area:n: xyz
=END=

############################################################
=TITLE=Unexpected token in area
=INPUT=
area:n = { xyz; anchor = network:n; x:yz; }
network:n = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Unexpected attribute in area:n: xyz
Error: Unexpected attribute in area:n: x:yz
=END=

############################################################
=TITLE=Unexpected token in crypto
=INPUT=
crypto:c = { xyz; }
=END=
=ERROR=
Error: Unexpected attribute in crypto:c: xyz
Error: Missing 'type' for crypto:c
=END=

############################################################
=TITLE=Unexpected token in owner
=INPUT=
owner:o = { xyz; }
network:n1 = { ip = 10.1.1.0/24; owner = o; }
=END=
=ERROR=
Error: Unexpected attribute in owner:o: xyz
Error: Missing attribute 'admins' in owner:o of network:n1
=END=

############################################################
# Shared topology
=VAR=topo
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
=END=

############################################################
=TITLE=Equally reference user
=INPUT=
${topo}
service:s = {
 user = network:n1;
 permit src = user, network:n2; dst = network:n3; prt = ip;
}
=END=
=ERROR=
Error: The sub-expressions of union in 'src' of service:s equally must
 either reference 'user' or must not reference 'user'
=END=

############################################################
=TITLE=Equally reference user with intersection
=INPUT=
${topo}
service:s1 = {
 user = network:n1, network:n2;
 permit src = network:n3;
        dst = interface:r.n2,
              interface:[user].[all] &! interface:r.n2;
        prt = tcp 22;
}
=END=
=ERROR=
Error: The sub-expressions of union in 'dst' of service:s1 equally must
 either reference 'user' or must not reference 'user'
=END=

############################################################
=TITLE=Invalid attribute syntax in service
=INPUT=
service:s1 = {
 overlaps = service:s2,,;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=ERROR=
Error: Unexpected separator ',' at line 2 of STDIN, near "service:s2,--HERE-->,;"
Aborted
=END=

############################################################
=TITLE=Invalid attribute at service
=INPUT=
${topo}
service:s1 = {
 xyz;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=END=
=ERROR=
Error: Unexpected attribute in service:s1: xyz
=END=

############################################################
=TITLE=Invalid rule at service
=INPUT=
service:s1 = {
 user = network:n1;
 allow src = user; dst = network:n2; prt = tcp 22;
}
=END=
=ERROR=
Error: Expected 'permit' or 'deny' at line 3 of STDIN, near " --HERE-->allow"
Aborted
=END=

############################################################
=TITLE=Invalid rule with 'foreach'
=INPUT=
${topo}
service:s1 = {
 user = foreach network:n1, network:n2;
 permit src = user; dst = network:n3; prt = tcp 22;
}
=END=
=WARNING=
Warning: Each rule of service:s1 should reference 'user' in 'src' and 'dst'
 because service has keyword 'foreach'
=OUTPUT=
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
=END=

############################################################
=TITLE=Empty list of elements after 'user', 'src', 'dst'
=INPUT=
${topo}
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
=END=
=WARNING=
Warning: user of service:s1 is empty
Warning: src of service:s2 is empty
Warning: dst of service:s3 is empty
=END=

############################################################
=TITLE=Empty user and empty rules
=INPUT=
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
=END=
=WARNING=
Warning: Must not define service:s1 with empty users and empty rules
Warning: Must not define service:s2 with empty users and empty rules
Warning: Must not define service:s3 with empty users and empty rules
=END=

############################################################
=TITLE=Non host as policy_distribution_point
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = ASA;
 policy_distribution_point = network:n1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Must only use host name in 'policy_distribution_point' of router:r
=END=

############################################################
=TITLE=Unknown host as policy_distribution_point
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = ASA;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=WARNING=
Warning: Ignoring undefined host:h1 in 'policy_distribution_point' of router:r
=END=

############################################################