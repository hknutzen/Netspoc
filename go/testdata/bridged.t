
############################################################
=TITLE=Unexpected attribute at bridged interface
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside;  no_in_acl; dhcp_server; routing = OSPF; }
 interface:n1/right = { hardware = outside; virtual = { ip = 10.1.1.2; } }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Attribute 'no_in_acl' not supported for bridged interface:bridge.n1/left
Error: Attribute 'dhcp_server' not supported for bridged interface:bridge.n1/left
Error: Attribute 'routing' not supported for bridged interface:bridge.n1/left
Error: No virtual IP supported for bridged interface:bridge.n1/right
=END=

############################################################
=TITLE=No loopback bridged interface
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; loopback; }
 interface:n1/right = { hardware = right; vip; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Attribute 'loopback' not supported for bridged interface:bridge.n1/left
Error: Attribute 'vip' not supported for bridged interface:bridge.n1/right
Error: Must not use attribute 'vip' at interface:bridge.n1/right of managed router
=END=

############################################################
=TITLE=Fixed hardware for layer3 interface at ASA
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Layer3 interface:bridge.n1 must use 'hardware' named 'device' for model 'ASA'
=END=

############################################################
=TITLE=No dynamic routing at bridged interface
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; routing = OSPF; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Attribute 'routing' not supported for bridged interface:bridge.n1/left
=END=

############################################################
=TITLE=No attribute routing at bridge
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; routing = OSPF; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Attribute 'routing' not supported for bridged interface:bridge.n1/left
Error: Attribute 'routing' not supported for bridge router:bridge
=END=

############################################################
=TITLE=Bridged network must not have NAT
=INPUT=
network:n1/left = {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.1.2.0/26; dynamic; }
}
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; bind_nat = x; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Only identity NAT allowed for bridged network:n1/left
=END=

############################################################
=TITLE=Bridged network must not inherit NAT
=INPUT=
any:a = { link = network:n1/left; nat:x = { ip = 10.1.2.0/26; dynamic; } }
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Must not inherit nat:x at bridged network:n1/left from any:a
=END=

############################################################
=TITLE=Bridged network must not have host with range
=INPUT=
network:n1/left = {
 ip = 10.1.1.0/24;
 host:h = { range = 10.1.1.10-10.1.1.20; }
}
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Bridged network:n1/left must not have host:h with range (not implemented)
=END=

############################################################
=TITLE=Other network must not use prefix name of bridged networks
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1/right = { ip = 10.1.1.2; }
 interface:n1;
}
network:n1 = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Must not define network:n1 together with bridged networks of same name
=END=

############################################################
=TITLE=Bridged networks must use identical IP addresses
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: network:n1/left and network:n1/right must have identical ip/mask
=END=

############################################################
=TITLE=Missing layer 3 interface
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Must define interface:n1 at router:bridge for corresponding bridge interfaces
=END=

############################################################
=TITLE=Layer 3 interface must not have secondary IP
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1, 10.1.1.2; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Layer3 interface:bridge.n1 must not have secondary or virtual IP
=END=

############################################################
=TITLE=Layer 3 IP must match bridged network IP/mask
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.2.2.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: interface:bridge.n1's IP doesn't match IP/mask of bridged networks
=END=

############################################################
=TITLE=Bridged networks must be connected by bridge
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1/left = { ip = 10.1.1.1; hardware = inside; }
 interface:n1/right = { ip = 10.1.1.2; hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: network:n1/right and network:n1/left must be connected by bridge
=END=

############################################################
=TITLE=Bridge must connect at least two networks (1)
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
}
router:bridge2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: router:bridge1 can't bridge a single network
=END=

############################################################
=TITLE=Single device can't bridge different networks
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n2/right = { hardware = outside; }
}
network:n2/right = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Must not bridge parts of different networks at router:bridge1:
 - interface:n1/left
 - interface:n2/right
=END=

############################################################
=TITLE=Bridged must not be used solitary
=INPUT=
network:n1/right = { ip = 10.1.1.0/24; }
=END=
=WARNING=
Warning: Bridged network:n1/right must not be used solitary
=END=

############################################################
=TITLE=Bridged network must not be unnumbered
=INPUT=
network:n1/left = { unnumbered; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { unnumbered; hardware = device; }
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { unnumbered; }
=END=
=ERROR=
Error: Unnumbered network:n1/left must not be bridged
Error: Unnumbered network:n1/right must not be bridged
Error: Layer3 interface:bridge.n1 must have IP address
Error: interface:bridge.n1/left must not be linked to unnumbered network:n1/left
Error: interface:bridge.n1/right must not be linked to unnumbered network:n1/right
=END=

############################################################
=TITLE=Duplicate layer 3 IP
=INPUT=
network:n1/a = { ip = 10.1.1.0/24; }
network:n1/b = { ip = 10.1.1.0/24; }
network:n1/c = { ip = 10.1.1.0/24; }
router:bridge1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/a = { hardware = inside; }
 interface:n1/b = { hardware = outside; }
}
router:bridge2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/b = { hardware = inside; }
 interface:n1/c = { hardware = outside; }
}
=END=
=ERROR=
Error: Duplicate IP address for interface:bridge1.n1 and interface:bridge2.n1
=END=

############################################################
=TITLE=Duplicate IP addresses in bridged parts
=INPUT=
router:r1 = {
 interface:n1/left = { ip = 10.1.1.1; }
}
network:n1/left = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; }
 host:h2a = { ip = 10.1.1.2; }
}
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = {
 ip = 10.1.1.0/24;
 host:h2b = { ip = 10.1.1.2; }
}
router:r2 = {
 interface:n1/right = { ip = 10.1.1.1; }
}
=END=
=ERROR=
Error: Duplicate IP address for interface:r1.n1/left and interface:bridge.n1
Error: Duplicate IP address for interface:r1.n1/left and interface:r2.n1/right
Error: Duplicate IP address for interface:r1.n1/left and host:h1
Error: Duplicate IP address for host:h2a and host:h2b
=END=

############################################################
# Shared topology for multiple tests
=TEMPL=topology
network:n1 = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}
network:n2/left = { ip = 10.1.2.0/24; }
network:n2/right = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa = {
 model = IOS;
 {{.m}}managed;
 interface:n1 = { ip = 10.1.1.101; hardware = n1; }
 interface:n2/left = { ip = 10.1.2.101; hardware = n2; }
}
router:bridge = {
 model = ASA;
 managed;
 {{.p}}policy_distribution_point = host:netspoc;
 interface:n2 = { ip = 10.1.2.9; hardware = device; }
 interface:n2/left = { hardware = inside; }
 interface:n2/right = { hardware = outside; }
}
router:r3 = {
 interface:n2/right = { ip = 10.1.2.1; }
 interface:n3;
}
=END=

############################################################
=TITLE=Admin access to bridge
=INPUT=
[[topology {m: "#", p: ""}]]
service:admin = {
 user = interface:bridge.n2;
 permit src = network:n1; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--bridge
! [ IP = 10.1.2.9 ]
=END=

############################################################
=TITLE=Admin access to bridge auto interface
=INPUT=
[[topology {m: "#", p: ""}]]
service:admin = {
 user =  interface:bridge.[auto];
 permit src = network:n1; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--bridge
! [ IP = 10.1.2.9 ]
=END=

############################################################
=TITLE=Admin access to bridge all interfaces
=INPUT=
[[topology {m: "#", p: ""}]]
service:admin = {
 user =  interface:bridge.[all];
 permit src = network:n1; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--bridge
! [ IP = 10.1.2.9 ]
=END=

############################################################
=TITLE=Access to both sides of bridged network
=INPUT=
[[topology {m: "", p: "#"}]]
service:test = {
 user = network:n2/left, network:n2/right;
 permit src = user; dst = host:[network:n1]; prt = tcp 80;
}
=OUTPUT=
--bridge
access-list outside_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Access through bridged ASA
=INPUT=
[[topology {m: "", p: "#"}]]
service:test = {
 user = network:n3;
 permit src = user; dst = host:[network:n1]; prt = tcp 80;
}
# Must not use bridged interface as next hop in static route.
=OUTPUT=
--bridge
access-list outside_in extended permit tcp 10.1.3.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--asa
! [ Routing ]
ip route 10.1.3.0 255.255.255.0 10.1.2.1
=END=

############################################################
=TITLE=Must not use bridged interface in rule
=INPUT=
[[topology {m: "", p: "#"}]]
service:test = {
 user = network:n1;
 permit src = user; dst = interface:bridge.n2/right; prt = tcp 22;
 permit src = interface:bridge.n2/left; dst = user; prt = tcp 22;
}
=WARNING=
Warning: Ignoring bridged interface:bridge.n2/right in dst of rule in service:test
Warning: Ignoring bridged interface:bridge.n2/left in src of rule in service:test
=END=

############################################################
=TITLE=Duplicate auto interface
# Two auto interfaces are found in topology,
# but are combined into a single layer 3 interface.
=INPUT=
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; loopback; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1/left = { ip = 10.1.1.3; hardware = n1; }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1/right = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s = {
 user = interface:bridge.[auto];
 permit src = network:n2; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--r1
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.1 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r2
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.1 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Duplicate static routes behind bridge
=INPUT=
network:n0 = { ip = 10.1.0.0/24; }
router:r0 = {
 managed;
 model = ASA;
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1/center = { ip = 10.1.1.4; hardware = center; }
}
network:n1/center = { ip = 10.1.1.0/24; }
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left    = { hardware = left; }
 interface:n1/center  = { hardware = center; }
 interface:n1/right   = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1/left = { ip = 10.1.1.3; hardware = n1; }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1/right = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s = {
 user = network:n0;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=END=
=ERROR=
Error: Ambiguous static routes for network:n2 at interface:r0.n1/center via
 - interface:r1.n1/left
 - interface:r2.n1/right
=END=

############################################################
=TITLE=Route behind chained bridges
=TEMPL=input
network:n0 = { ip = 10.1.0.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1/left = { ip = 10.1.1.4; hardware = n1; }
}
network:n1/left = { ip = 10.1.1.0/24; }
# Use name, that is sorted behind r1, r2,
# so that we actually test recursion when searching hop with IP address.
router:zbridge1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
 interface:n1/left   = { hardware = left; }
 interface:n1/center = { hardware = center; }
}
network:n1/center = { ip = 10.1.1.0/24; }
router:zbridge2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = device; }
 interface:n1/center = { hardware = center; }
 interface:n1/right  = { hardware = right; }
}
network:n1/right = { ip = 10.1.1.0/24; }
router:r2 = {
 interface:n1/right = { {{.}}; hardware = n1; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:s = {
 user = network:n0;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=INPUT=
[[input "ip = 10.1.1.5"]]
=OUTPUT=
--r1
! [ Routing ]
route n1 10.1.2.0 255.255.255.0 10.1.1.5
=END=

############################################################
=TITLE=Missing hop behind chained bridges
=INPUT=
[[input negotiated]]
=ERROR=
Error: Can't generate static routes for interface:r1.n1/left because IP address is unknown for:
 - interface:r2.n1/right
=END=

############################################################
=TITLE=Rules for hosts in bridged network
=INPUT=
network:n1/left = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; }
}
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.9; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = {
 ip = 10.1.1.0/24;
 host:h2 = { ip = 10.1.1.2; }
}
router:r2 = {
 interface:n1/right = { ip = 10.1.1.10; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
service:s2 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 81;
}
service:s3 = {
 user = host:h1, host:h2;
 permit src = network:n2; dst = user; prt = tcp 82;
}
=END=
=WARNING=
Warning: Some source/destination pairs of service:s3 don't affect any firewall:
 src=network:n2; dst=host:h2
=OUTPUT=
--bridge
! left_in
access-list left_in extended permit tcp host 10.1.1.1 host 10.1.1.2 eq 80
access-list left_in extended permit tcp host 10.1.1.1 10.1.2.0 255.255.255.0 eq 81
access-list left_in extended deny ip any4 any4
access-group left_in in interface left
--
! right_in
access-list right_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.1 eq 82
access-list right_in extended deny ip any4 any4
access-group right_in in interface right
=END=

############################################################
