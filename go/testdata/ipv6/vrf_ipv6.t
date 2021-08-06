
############################################################
=TITLE=VRF sanity checks
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
# Unmanaged device is ignored.
router:r@v1 = {
 interface:n1;
 interface:n2 = { ip = ::a01:201; hardware = n2; } # Hardware is ignored.
}
router:r@v2 = {
 managed;
 model = NX-OS;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r@v3 = {
 managed = routing_only;
 model = IOS;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
=END=
=ERROR=
Error: All instances of router:r must have identical model
Error: Duplicate hardware 'n3' at router:r@v2 and router:r@v3
=END=

############################################################
=TITLE=Combine object-groups from different VRFs
=PARAMS=--ipv6
=INPUT=
network:m = { ip = ::a02:200/120; }
router:r1@v1 = {
 managed;
 model = NX-OS;
 interface:m = { ip = ::a02:201; hardware = e0; }
 interface:t = { ip = ::a09:901; hardware = e1; }
}
network:t = { ip = ::a09:900/120; }
router:r1@v2 = {
 managed;
 model = NX-OS;
 interface:t = { ip = ::a09:902; hardware = e2; }
 interface:n = { ip = ::a01:101; hardware = e3; }
}
network:n = {
 ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a; }
 host:h20 = { ip = ::a01:114; }
 host:h30 = { ip = ::a01:11e; }
}
service:test = {
 user = host:h10, host:h20, host:h30;
 permit src = user; dst = network:m; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
object-group ip address v6g0
 10 ::a01:10a/128
 20 ::a01:114/128
 30 ::a01:11e/128
ipv6 access-list e0_in
 10 permit tcp ::a02:200/120 addrgroup v6g0 established
 20 deny ip any any
--
ipv6 access-list e2_in
 10 permit tcp ::a02:200/120 addrgroup v6g0 established
 20 deny ip any any
=END=

############################################################
=TITLE=Protect interface with different VRFs
=PARAMS=--ipv6
=INPUT=
network:m = { ip = ::a02:200/120; }
router:r1@v1 = {
 managed;
 model = IOS, FW;
 interface:m = { ip = ::a02:201; hardware = e0; }
 interface:t = { ip = ::a09:901; hardware = e1; }
}
network:t = { ip = ::a09:900/120; }
router:r1@v2 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = ::a09:902; hardware = e2; }
 interface:n = { ip = ::a01:101; hardware = e3; }
}
network:n = { ip = ::a01:100/120; }
service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
 permit src = network:n; dst = user; prt = tcp 81;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list e0_in
 permit tcp ::a02:200/120 ::a01:100/120 eq 80
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any host ::a02:201
 permit tcp ::a01:100/120 ::a02:200/120 eq 81
 deny ipv6 any any
--
ipv6 access-list e2_in
 deny ipv6 any host ::a01:101
 permit tcp ::a02:200/120 ::a01:100/120 eq 80
 deny ipv6 any any
--
ipv6 access-list e3_in
 permit tcp ::a01:100/120 ::a02:200/120 eq 81
 deny ipv6 any any
=END=

############################################################
=TITLE=Mixed routing_only and VRFs
=PARAMS=--ipv6
=INPUT=
network:m = { ip = ::a02:200/120; }
router:r1@v1 = {
 managed = routing_only;
 model = IOS, FW;
 interface:m = { ip = ::a02:201; hardware = e0; }
 interface:t = { ip = ::a09:901; hardware = e1; }
}
network:t = { ip = ::a09:900/120; }
router:r1@v2 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = ::a09:902; hardware = e2; }
 interface:n = { ip = ::a01:101; hardware = e3; }
}
network:n = { ip = ::a01:100/120; }
service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
}
=END=
# Code for routing_only device is generated last.
=OUTPUT=
--ipv6/r1
! [ Routing for router:r1@v1 ]
ipv6 route vrf v1 ::a01:100/120 ::a09:902
--
! [ Routing for router:r1@v2 ]
ipv6 route vrf v2 ::a02:200/120 ::a09:901
--
ipv6 access-list e2_in
 deny ipv6 any host ::a01:101
 permit tcp ::a02:200/120 ::a01:100/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=No admin IP found in any VRF
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:netspoc = { ip = ::a01:109; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:101; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:102; hardware = v2; }
}
=END=
=WARNING=
Warning: Missing rules to reach 2 devices from policy_distribution_point:
 - router:r1@v1
 - router:r1@v2
=END=

############################################################
=TITLE=One admin IP for multiple VRFs
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:netspoc = { ip = ::a01:109; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = ::a01:101; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:102; hardware = v2; }
}
service:admin = {
 user = interface:r1@v2.[auto];
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ IP = ::a01:102 ]
=END=

############################################################
=TITLE=Multiple admin IPs found in VRFs
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:netspoc = { ip = ::a01:109; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:101; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:102; hardware = v2; }
}
service:admin = {
 user = interface:r1@v1.[auto], interface:r1@v2.[auto];
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ IP = ::a01:101,::a01:102 ]
=END=

############################################################
=TITLE=Missing policy distribution point at all VRF members
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:netspoc = { ip = ::a01:109; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = ::a01:101; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = ::a01:102; hardware = v2; }
}
=END=
=ERROR=
Error: Missing attribute 'policy_distribution_point' for 1 devices:
 - at least one instance of router:r1
=END=
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Different policy distribution point at VRF members
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:h8 = { ip = ::a01:108; }
 host:h9 = { ip = ::a01:109; }
}
router:r1@v1 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:h8;
 interface:n1 = { ip = ::a01:101; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = NX-OS;
 policy_distribution_point = host:h9;
 interface:n1 = { ip = ::a01:102; hardware = v2; }
}
=END=
=ERROR=
Error: Instances of router:r1 must not use different 'policy_distribution_point':
 -host:h8
 -host:h9
Warning: Missing rules to reach 2 devices from policy_distribution_point:
 - router:r1@v1
 - router:r1@v2
=END=
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Missing interface rule for policy distribution point at VRF members
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1@v1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n2 = { ip = ::a01:202; hardware = n2v2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
service:admin = {
 user = network:n2, network:n3;
 permit src = host:h1; dst = user; prt = tcp 22;
}
=WARNING=
Warning: Missing rules to reach 2 devices from policy_distribution_point:
 - router:r1@v1
 - router:r1@v2
=END=
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Reach policy distribution point from wrong side at VRF members
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1@v1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n2 = { ip = ::a01:202; hardware = n2v2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
service:admin = {
 user = interface:r1@v1.n2, interface:r1@v2.n3;
 permit src = host:h1; dst = user; prt = tcp 22;
}
=OUTPUT=
-- ipv6/r1
! [ IP = ::a01:201,::a01:302 ]
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=VRF not supported by model
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1@v1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = v2; }
}
=END=
=ERROR=
Error: Must not use VRF at router:r1@v1 of model ASA
Error: Must not use VRF at router:r1@v2 of model ASA
=END=

############################################################
