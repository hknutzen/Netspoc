
############################################################
=TITLE=Mixed IPv4 and IPv6
=VAR=input
-- ipv4/topo/net
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
-- ipv4/topo/router
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- ipv4/rules
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
-- ipv4/topo/ipv6
network:n3 = { ip = 1000::abcd:0001:0/112;}
network:n4 = { ip = 1000::abcd:0002:0/112;}
-- ipv6/router
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
-- ipv4/ipv6/rules
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=INPUT=${input}
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
=TITLE=Mixed IPv6 and IPv4
=INPUT=${input}
=SUBST=|ipv4/ipv6|ipv6/ipv6|
=SUBST=|ipv4/topo/ipv6|topo|
=OPTIONS=--ipv6
# Identical output as before
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
-- file1
network:n1 = { ip = 10.1.1.0/24; subnet_of = network:Internet; }
network:n2 = { ip = 10.1.2.0/24; subnet_of = network:Internet; }
network:Internet = { ip = 0.0.0.0/0; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:inet = {
 interface:n2;
 interface:Internet;
}
-- ipv6/file2
network:n3 = { ip = 1000::abcd:0001:0/112;}
network:n4 = { ip = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
=END=
=WARNING=NONE

############################################################
=TITLE=Must not reference IPv4 from IPv6
=INPUT=
-- file1
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
-- ipv6/file2
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=ERROR=
Error: Must not reference IPv4 network:n1 in IPv6 context user of service:s2
Error: Must not reference IPv4 network:n2 in IPv6 context dst of rule in service:s2
=END=

############################################################
=TITLE=Reference IPv6 service from IPv4 and vice versa
=INPUT=
-- topo
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:s1 = {
 overlaps = service:s2, service:s1;
 identical_body = service:s1, service:s2;
 user = network:n1;
 permit src = user; dst = interface:r1.n1; prt = tcp 22;
}
-- ipv6/topo
network:n2 = { ip = 1000::abcd:0001:0/112; }
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 1000::abcd:0001:0001; hardware = n2; }
}
service:s2 = {
 identical_body = service:s1, service:s2;
 user = network:n2;
 permit src = user; dst = interface:r2.n2; prt = tcp 22;
}
=END=
=WARNING=
Warning: Useless attribute 'identical_body' in service:s1
Warning: Useless attribute 'identical_body' in service:s2
Warning: Useless 'overlaps = service:s2' in service:s1
Warning: Useless 'overlaps = service:s1' in service:s1
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Reference IPv4/6 policy_distribution_point from IPv6/4
=INPUT=
-- file1
area:a = {
 anchor = network:n1;
 router_attributes = { policy_distribution_point = host:pdp6; }
}
network:n1 = { ip = 10.1.1.0/24; host:netspoc = { ip = 10.1.1.11; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- ipv6/file2
network:n3 = {
 ip = 1000::abcd:0001:0/112;
 host:pdp6 = { ip = 1000::abcd:0001:11; }
}
router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
=END=
=ERROR=
Error: Must not reference IPv4 host:netspoc in IPv6 context 'policy_distribution_point' of router:r1
Error: Must not reference IPv6 host:pdp6 in IPv4 context 'policy_distribution_point' of router_attributes of area:a
=END=

############################################################
=TITLE=Reference IPv4/6 network from IPv6/4 subnet_of
=INPUT=
-- topo
network:n1 = { ip = 10.1.1.0/24; subnet_of = network:n2; }
router:r2 = {
 interface:n1 = { ip = 10.1.1.1; }
}
-- ipv6/topo
network:n2 = { ip = 1000::abcd:0001:0/112; subnet_of = network:n1; }
router:r1 = {
 interface:n2 = { ip = 1000::abcd:0001:0001; }
}
=END=
=ERROR=
Error: Must not reference IPv4 network:n1 in IPv6 context 'subnet_of' of network:n2
Error: Must not reference IPv6 network:n2 in IPv4 context 'subnet_of' of network:n1
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
=END=
=ERROR=
Error: All instances of router:r1 must have identical model
=END=

############################################################
=TITLE=Empty IPv6 topology
=INPUT=
-- file
-- ipv6/file
=END=
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
=END=
=ERROR=
Warning: Ignoring file 'file' without any content
Warning: Ignoring file 'ipv4' without any content
Error: topology seems to be empty
Aborted
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Raw files for IPv4 and IPv6
=VAR=input
-- ipv4
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- raw/r1
access-list n1_in extended permit icmp any4 any4
access-group n1_in in interface n1
-- ipv6/topo
network:n3 = { ip = 1000::abcd:0001:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
-- raw/ipv6/r1
access-list n1_in extended permit icmp6 any6 any6
access-group n1_in in interface n1
=END=
=INPUT=${input}
=VAR=output
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r1.raw
access-list n1_in extended permit icmp any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r1.raw
access-list n1_in extended permit icmp6 any6 any6
access-group n1_in in interface n1
=END=
=OUTPUT=
${output}
=END=

############################################################
=TITLE=Raw files for IPv6 and IPv4
=INPUT=${input}
=SUBST=|raw/r1|raw/ipv4/r1|
=SUBST=|raw/ipv6/r1|raw/r1|
=OPTIONS=--ipv6
=OUTPUT=
${output}
=END=

############################################################
=TITLE=Invalid file and directory in raw/ipv6
=INPUT=
-- ipv4
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
-- raw/ipv6/r1
access-list n1_in extended permit icmp6 any6 any6
access-group n1_in in interface n1
-- raw/ipv6/ipv6/foo
foo
=END=
=WARNING=
Warning: Ignoring path raw/ipv6/ipv6
Warning: Found unused file raw/ipv6/r1
=OUTPUT=
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Verbose output with progress messages
=VAR=input
--ipv4
group:v4 = ;
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp;
 permit src = user; dst = network:n2; prt = ip;
}
--ipv6
group:v6 = ;
network:n3 = { ip = 1000::abcd:0001:0/112;}
network:n4 = { ip = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
service:s2 = {
 overlaps = service:s2;
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=INPUT=${input}
=REUSE_PREV=${input}
=WARNING=
Netspoc, version TESTING
Read: 2 routers, 4 networks, 1 hosts, 2 services
0s Arranging protocols
0s Preparing security zones and areas
0s Preparing fast path traversal
0s Distributing NAT
0s Finding subnets in zone
0s Normalizing services
0s Checking service owner
0s Converting hosts to subnets
0s Grouping rules
Grouped rule count: 4
0s Finding subnets in 2 NAT domains
0s Checking rules for unstable subnet relation
0s Checking and marking rules with hidden or dynamic NAT
0s Checking supernet rules
0s Checking transient supernet rules
0s Output of background job:
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
Saving 6 old files of 'out' to subdirectory '.prev'
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
=END=
=OPTIONS=--quiet=false --concurrency_pass1=2 --time_stamps --check_identical_services=1

############################################################
=TITLE=No partition names for unconnected IPv6 and IPv4 partitions (1)
=VAR=input
-- ipv4/topo/net
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
-- ipv4/topo/router
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- ipv4/topo/ipv6
network:n3 = {
 ip = 1000::abcd:0003:0/112;
 partition = part1;
}
network:n4 = { ip = 1000::abcd:0004:0/112; }
-- ipv6/router
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0003:0001; hardware = n1;}
 interface:n4 = {ip = 1000::abcd:0004:0001; hardware = n2;}
}
=END=
=INPUT=${input}
=WARNING=
Warning: Spare partition name for single partition any:[network:n3]: part1.
=END=

############################################################
=TITLE=No partition names for unconnected IPv6 and IPv4 partitions (2)
=INPUT=${input}
=SUBST=/partition = part1;//
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
-- topo
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- ipv6
network:n3 = { ip = 1000::abcd:0003:0/112; }
network:n4 = { ip = 1000::abcd:0004:0/112; }
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0003:0001; hardware = n1;}
}
router:r2 = {
 managed;
 model = ASA;
 interface:n4 = {ip = 1000::abcd:0004:0001; hardware = n2;}
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
-- ipv4
network:n1 = { ip = 10.1.1.0/24; }
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
-- ipv6
network:n1_v6 = { ip = 1::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1_v6 = { ip = 1::1; hardware = n1; }
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
