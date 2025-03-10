
############################################################
=TITLE=VRF sanity checks
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
# Unmanaged device is ignored.
router:r@v1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; } # Hardware is ignored.
}
router:r@v2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = IN; }
}
router:r@v3 = {
 managed = routing_only;
 model = NSX, T1;
 interface:n3 = { ip = 10.1.3.2; hardware = IN; }
 interface:n4 = { ip = 10.1.4.1; hardware = OUT; }
}
router:r = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
=ERROR=
Error: All instances of router:r must have identical model
Error: Duplicate hardware 'IN' at router:r@v2 and router:r@v3
=END=

############################################################
=TITLE=Ignore unmanaged VRF member
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1@v1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:test = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n2_in
 deny ip any host 10.1.3.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80
 deny ip any any
--
interface n2
 ip address 10.1.2.2 255.255.255.0
 ip vrf forwarding v2
 ip access-group n2_in in
interface n3
 ip address 10.1.3.1 255.255.255.0
 ip vrf forwarding v2
 ip access-group n3_in in
=END=

############################################################
=TITLE=Protect interface with different VRFs
=INPUT=
network:m = { ip = 10.2.2.0/24; }
router:r1@v1 = {
 managed;
 model = IOS, FW;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t = { ip = 10.9.9.1; hardware = e1; }
}
network:t = { ip = 10.9.9.0/24; }
router:r1@v2 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = 10.9.9.2; hardware = e2; }
 interface:n = { ip = 10.1.1.1; hardware = e3; }
}
network:n = { ip = 10.1.1.0/24; }
service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
 permit src = network:n; dst = user; prt = tcp 81;
}
=OUTPUT=
--r1
ip access-list extended e0_in
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 81
 deny ip any any
--
ip access-list extended e2_in
 deny ip any host 10.1.1.1
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended e3_in
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 81
 deny ip any any
=END=

############################################################
=TITLE=Mixed routing_only and VRFs
=INPUT=
network:m = { ip = 10.2.2.0/24; }
router:r1@v1 = {
 managed = routing_only;
 model = IOS, FW;
 interface:m = { ip = 10.2.2.1; hardware = e0; }
 interface:t = { ip = 10.9.9.1; hardware = e1; }
}
network:t = { ip = 10.9.9.0/24; }
router:r1@v2 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = 10.9.9.2; hardware = e2; }
 interface:n = { ip = 10.1.1.1; hardware = e3; }
}
network:n = { ip = 10.1.1.0/24; }
service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = tcp 80;
}
=END=
# Code for routing_only device is generated last.
=OUTPUT=
--r1
! [ Routing for router:r1@v1 ]
ip route vrf v1 10.1.1.0 255.255.255.0 10.9.9.2
--
! [ Routing for router:r1@v2 ]
ip route vrf v2 10.2.2.0 255.255.255.0 10.9.9.1
--
ip access-list extended e2_in
 deny ip any host 10.1.1.1
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=No admin IP found in any VRF
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
=WARNING=
Warning: Missing rules to reach 2 devices from policy_distribution_point:
 - router:r1@v1
 - router:r1@v2
=END=

############################################################
=TITLE=One admin IP for multiple VRFs
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
service:admin = {
 user = interface:r1@v2.[auto];
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
=OUTPUT=
-- r1.info
{"generated_by":"devel","model":"IOS","ip_list":["10.1.1.2"]}
=END=

############################################################
=TITLE=Multiple admin IPs found in VRFs
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
service:admin = {
 user = interface:r1@v1.[auto], interface:r1@v2.[auto];
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
=OUTPUT=
-- r1.info
{"generated_by":"devel","model":"IOS","ip_list":["10.1.1.1","10.1.1.2"],"policy_distribution_point":"10.1.1.9"}
=END=

############################################################
=TITLE=Missing policy distribution point at all VRF members
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
=ERROR=
Error: Missing attribute 'policy_distribution_point' for 1 devices:
 - at least one instance of router:r1
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Different policy distribution point at VRF members
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:h8 = { ip = 10.1.1.8; }
 host:h9 = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h8;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h9;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
=ERROR=
Error: Instances of router:r1 must not use different 'policy_distribution_point':
 -host:h8
 -host:h9
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1@v1
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Missing interface rule for policy distribution point at VRF members
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1@v1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n2 = { ip = 10.1.2.2; hardware = n2v2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:admin = {
 user = network:n2, network:n3;
 permit src = host:h1; dst = user; prt = tcp 22;
}
=WARNING=
Warning: Missing rules to reach 2 devices from policy_distribution_point:
 - router:r1@v1
 - router:r1@v2
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Reach policy distribution point from wrong side at VRF members
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1@v1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r1@v2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:h1;
 interface:n2 = { ip = 10.1.2.2; hardware = n2v2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:admin = {
 user = interface:r1@v1.n2, interface:r1@v2.n3;
 permit src = host:h1; dst = user; prt = tcp 22;
}
=OUTPUT=
-- r1.info
{"generated_by":"devel","model":"IOS","ip_list":["10.1.2.1","10.1.3.2"],"policy_distribution_point":"10.1.1.10"}
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=VRF not supported by model
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1@v1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = v1; }
}
router:r1@v2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = v2; }
}
=ERROR=
Error: Must not use VRF at router:r1@v1 of model ASA
Error: Must not use VRF at router:r1@v2 of model ASA
=END=

############################################################