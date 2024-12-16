
############################################################
=TITLE=Mixed IPv4 and IPv6
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip6 = 1000::abcd:0001:0/112;}
network:n4 = { ip6 = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=IPv6 network is not subnet of 0.0.0.0/0
=INPUT=
network:Internet = { ip = 0.0.0.0/0; }
network:n1 = { ip = 10.1.1.0/24; subnet_of = network:Internet; }
network:n2 = { ip = 10.1.2.0/24; subnet_of = network:Internet; }
router:inet = {
 interface:n2;
 interface:Internet;
}
network:n3 = { ip6 = 1000::abcd:0001:0/112;}
network:n4 = { ip6 = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
=WARNING=NONE

############################################################
=TITLE=Reference IPv4/6 policy_distribution_point from IPv6/4
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:netspoc = { ip = 10.1.1.11; } }
router:r1@vrf1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:pdp6;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
network:n3 = {
 ip6 = 1000::abcd:0001:0/112;
 host:pdp6 = { ip6 = 1000::abcd:0001:11; }
}
router:r1@vrf2 = {
 managed;
 model = IOS;
 policy_distribution_point = host:netspoc;
 interface:n3 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
}
=ERROR=
Error: Instances of router:r1 must not use different 'policy_distribution_point':
 -host:pdp6
 -host:netspoc
Error: No valid path
 from router:r1@vrf1
 to any:[network:n3]
 while resolving router:r1@vrf1 (destination is host:pdp6).
 Check path restrictions and crypto interfaces.
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1@vrf1
=END=

############################################################
=TITLE=Reference IPv4/6 network from IPv6/4 subnet_of
=INPUT=
network:n1 = { ip = 10.1.1.0/24; subnet_of = network:n2; }
router:r2 = {
 interface:n1 = { ip = 10.1.1.1; }
}

network:n2 = { ip6 = 1000::abcd:0001:0/112; subnet_of = network:n1; }
router:r1 = {
 interface:n2 = { ip6 = 1000::abcd:0001:0001; }
}
=ERROR=
Error: network:n2 is subnet_of network:n1 but its IP doesn't match that's address
Error: network:n1 is subnet_of network:n2 but its IP doesn't match that's address
=END=

############################################################
=TITLE=Check model of IPv4/IPv6 router
=INPUT=
-- file1
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- ipv6
network:n3 = { ip = 1000::abcd:0001:0/112;}
router:r1 = {
 managed;
 model = IOS;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
=ERROR=
Error: All instances of router:r1 must have identical model
=END=

############################################################
=TITLE=Empty IPv6 topology
=INPUT=
-- file
-- ipv6/file
=ERROR=
Warning: Ignoring file 'file' without any content
Warning: Ignoring file 'ipv6/file' without any content
Error: topology seems to be empty
Aborted
=END=

############################################################
=TITLE=Empty IPv4 topology
=INPUT=
-- file
-- ipv4
=ERROR=
Warning: Ignoring file 'file' without any content
Warning: Ignoring file 'ipv4' without any content
Error: topology seems to be empty
Aborted
=OPTIONS=--ipv6

############################################################
=TITLE=Verbose output with progress messages
=TEMPL=input
group:v4 = ;
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }

group:v6 = ;
network:n3 = { ip6 = 1000::abcd:0001:0/112;}
network:n4 = { ip6 = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
service:s1 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp;
 permit src = user; dst = network:n2; prt = ip;
}
service:s2 = {
 overlaps = service:s2;
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=INPUT=[[input]]
=REUSE_PREV=[[input]]
=WARNING=
Netspoc, version TESTING
Read: 1 routers, 4 networks, 1 hosts, 2 services
0s Arranging protocols
0s Preparing security zones and areas
0s Preparing fast path traversal
0s Distributing NAT
0s Normalizing services
0s Converting hosts to subnets
0s Grouping rules
Grouped rule count: 4
0s Finding subnets in 2 NAT domains
0s Checking rules for unstable subnet relation
0s Checking rules with hidden or dynamic NAT
0s Checking supernet rules
0s Checking transient supernet rules
0s Output of background job:
 0s Checking service owner
 0s Checking for services with identical body
Warning: unused group:v4
Warning: unused group:v6
 0s Checking for redundant rules
Expanded rule count: 4; duplicate: 1; redundant: 1
 0s Finished background job
0s Removing simple duplicate rules
0s Combining adjacent subnets
0s Setting policy distribution IP
0s Expanding crypto rules
0s Finding routes
0s Generating reverse rules for stateless routers
0s Marking rules for secondary optimization
0s Distributing rules
0s Printing code
Saving old content of 'out' to subdirectory '.prev'
Reused files for 2 devices from previous run
0s Finished
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=OPTIONS=--quiet=false --concurrency_pass1=2 --time_stamps --check_identical_services=1

############################################################
=TITLE=No partition names for unconnected IPv6 and IPv4 partitions (1)
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip6 = 1000::abcd:0003:0/112;
 {{.}}
}
network:n4 = { ip6 = 1000::abcd:0004:0/112; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = {ip6 = 1000::abcd:0003:0001; hardware = n1;}
 interface:n4 = {ip6 = 1000::abcd:0004:0001; hardware = n2;}
}
=INPUT=[[input "partition = part1;"]]
=WARNING=
Warning: Spare partition name for single partition any:[network:n3]: part1.
=END=

############################################################
=TITLE=No partition names for unconnected IPv6 and IPv4 partitions (2)
=INPUT=[[input ""]]
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Unconnected IPv6 and IPv4 partitions
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip6 = 1000::abcd:0003:0/112; }
network:n4 = { ip6 = 1000::abcd:0004:0/112; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = {ip6 = 1000::abcd:0003:0001; hardware = n1;}
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n4 = {ip6 = 1000::abcd:0004:0001; hardware = n2;}
}
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n3]
 - any:[network:n4]
 Use partition attribute, if intended.
Error: IPv4 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n2]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=No unstable IPv4 subnet with IPv6 topology
# Secondary optimization must still work.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n1_v6 = { ip6 = 1::/64; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n4sub = {
 ip = 10.1.4.0/26;
 nat:h = { hidden; }
 subnet_of = network:n4;
 host:h4 = { ip = 10.1.4.10; }
}
network:n5 = { ip = 10.1.5.0/24; }
router:r1  = {
 managed = secondary;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n1_v6 = { ip6 = 1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; bind_nat = h; }
}
router:r3 = {
 interface:n3 = { ip = 10.1.3.2; }
 interface:n4;
 interface:n4sub;
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h4; prt = tcp;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
