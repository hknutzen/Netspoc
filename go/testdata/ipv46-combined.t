
############################################################
=TITLE=Service from combined v4/v6 to v4/v6 and to v4
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.254.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 2001:db8:1:1::/64 2001:db8:1:2::/64 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Service from v4/v6 and v6 to v4/v6 and v4
=INPUT=
network:n0 = { ip6 = 2001:db8:1:0::/64; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip6 = 2001:db8:1:0::1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n0, network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.254.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n0_in
access-list n0_in extended permit tcp 2001:db8:1::/64 2001:db8:1:2::/64 eq 80
access-list n0_in extended deny ip any6 any6
access-group n0_in in interface n0
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 2001:db8:1:1::/64 2001:db8:1:2::/64 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=ipv4_only / ipv6_only
=INPUT=
network:n0 = { ip6 = 2001:db8:1:0::/64; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip6 = 2001:db8:1:0::1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 ipv4_only;
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
service:s2 = {
 ipv6_only;
 user = network:n0, network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.254.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n0_in
access-list n0_in extended permit tcp 2001:db8:1::/64 2001:db8:1:2::/64 eq 80
access-list n0_in extended deny ip any6 any6
access-group n0_in in interface n0
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 2001:db8:1:1::/64 2001:db8:1:2::/64 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=ipv4_only with IPv6 network / ipv6_only with IPv4 network
=INPUT=
network:n0 = { ip6 = 2001:db8:1:0::/64; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip6 = 2001:db8:1:0::1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 ipv4_only;
 user = network:n0, network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
service:s2 = {
 ipv6_only;
 user = network:n0, network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=ERROR=
Error: Must not use IPv6 network:n0 with 'ipv4_only' of service:s1
Error: Must not use IPv4 network:n3 with 'ipv6_only' of service:s2
=END=

############################################################
=TITLE=ipv4_only / ipv6_only without any combined network
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; ip6 = 2001:db8:1:5::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; ip6 = 2001:db8:1:5::1; hardware = n5; }
}

service:s1 = {
 ipv6_only;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 ipv4_only;
 user = network:n3;
 permit src = user; dst = network:n5; prt = tcp 80;
 permit src = user; dst = network:n4; prt = tcp 81;
}
=WARNING=
Warning: Ignoring 'ipv6_only' in service:s1, because no combined IPv4/IPv6 objects are in use
Warning: Ignoring 'ipv4_only' for rule 2 of service:s2, because no combined IPv4/IPv6 objects are in use
=END=

############################################################
=TITLE=ipv4_only and ipv6_only together
=INPUT=
service:s1 = {
 ipv4_only;
 ipv6_only;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Must not use ipv4_only and ipv6_only together at service:s1
=END=

############################################################
=TITLE=Must not use only v4 part of dual stack network with v6 supernet
=INPUT=
network:sup = { ip6 = 2001:db8:1::/60; has_subnets; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:9:2::/64; }
router:u = {
 interface:sup;
 interface:n1;
}
router:r1 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:9:2::1; hardware = n2; }
}
service:s1 = {
 user = network:[any:[network:sup]] &! network:sup;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=ERROR=
Error: Must not use only IPv4 part of dual stack object network:n1 in service:s1
=END=

############################################################
=TITLE=Must not use only v6 part of dual stack network with v4 supernet
=INPUT=
network:sup = { ip = 10.1.0.0/21; has_subnets; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.9.0/24; ip6 = 2001:db8:9:2::/64; }
router:u = {
 interface:sup;
 interface:n1;
}
router:r1 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.9.1; ip6 = 2001:db8:9:2::1; hardware = n2; }
}
service:s1 = {
 user = network:[any:[network:sup]] &! network:sup;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=ERROR=
Error: Must not use only IPv6 part of dual stack object network:n1 in service:s1
=END=

############################################################
=TITLE=Dual stack aggregates in zone cluster
# Must not show this error message:
# Must not use only IPv4 part of dual stack object any:[network:n1]
=INPUT=
network:n0 = { ip = 10.1.0.0/24; ip6 = 2001:db8:1:0::/64; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:u = {
 managed = routing_only;
 model = IOS;
 interface:n0 = { ip = 10.1.0.1; ip6 = 2001:db8:1:0::1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
}
router:r1 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = any:[network:n0];
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit tcp 10.1.2.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Aggregate from IPv6 network in dual stack zone cluster
=INPUT=
network:sup = { ip6 = 2001:db8:1::/60; has_subnets; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; }
router:u = {
 managed = routing_only;
 model = IOS;
 interface:sup = { ip6 = 2001:db8:1::1; hardware = sup; }
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
}
router:r1 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = any:[network:sup];
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
--r1
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit tcp 10.1.2.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Ignore optimized deletion of v4 subnet in rule if supernet is present
=INPUT=
network:sup0 = { ip = 10.1.0.0/16; }
network:sup1 = { ip = 10.1.1.0/24; subnet_of = network:sup0; }
network:n1 = { ip = 10.1.1.0/28; ip6 = 2001:db8:1::/64; subnet_of = network:sup1;}
network:n2 = { ip = 10.2.2.0/24; ip6 = 2001:db8:2::/64; host:h2 = { ip = 10.2.2.2; ip6 = 2001:db8:2::2; }}

router:u1 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:sup0;
 interface:sup1;
}

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1::1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; ip6 = 2001:db8:2::1; hardware = n2; }
}
service:s1 = {
 user = network:[any:[network:sup0]];
 permit src = user; dst = host:h2; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=Ignore optimized deletion of v6 subnet in rule if supernet is present
=INPUT=
network:sup = { ip6 = 2001:db8:1::/60; has_subnets; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:9:2::/64; }
router:u = {
 interface:sup;
 interface:n1;
}
router:r1 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:9:2::1; hardware = n2; }
}
service:s1 = {
 user = network:[any:[network:sup]];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=Ignore ip /0 in named non matching aggregate
=INPUT=
any:n1 = { ip = ::/0; link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
=WARNING=
Warning: Ignoring "ip" with prefix length 0 in any:n1
=END=

############################################################
=TITLE=Ignore ip6 /0 in named non matching aggregate
=INPUT=
any:n1-6 = { ip6 = ::/0; link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
=WARNING=
Warning: Ignoring "ip6" with prefix length 0 in any:n1-6
=END=

############################################################
=TITLE=Ignore /0 address in unnamed non matching aggregate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = any:[ip = 0.0.0.0/0 & network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Ignoring address with prefix length 0 in any:[ip = 0.0.0.0/0 & ..] of user of service:s1
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp any 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host 2001:db8:1:2::1
 permit tcp any 2001:db8:1:2::/64 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Show warning about ignored /0 address only once
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = foreach interface:r1.[all];
 permit src = any:[ip=0.0.0.0/0 & user]; dst = user; prt = icmp 8, icmpv6 128;
}
=WARNING=
Warning: Ignoring address with prefix length 0 in any:[ip = 0.0.0.0/0 & ..] of src of rule in service:s1
=OUTPUT=
--r1
ip access-list extended n1_in
 permit icmp any host 10.1.1.1 8
 deny ip any any
--
ip access-list extended n2_in
 permit icmp any host 10.1.2.1 8
 deny ip any any
--ipv6/r1
ipv6 access-list n1_in
 permit icmp any host 2001:db8:1:1::1 128
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit icmp any host 2001:db8:1:2::1 128
 deny ipv6 any any
=END=

############################################################
=TITLE=All interfaces of router with v4/v6, v4 and v6
=INPUT=
network:n0 = { ip6 = 2001:db8:1:0::/64; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n0 = { ip6 = 2001:db8:1:0::1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n0, network:n1, network:n3;
 permit src = user; dst = interface:r1.[all]; prt = tcp 22;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.1 eq 22
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.1 eq 22
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.3.1 eq 22
 deny ip any any
--ipv6/r1
! [ ACL ]
ipv6 access-list n0_in
 permit tcp 2001:db8:1::/64 host 2001:db8:1::1 eq 22
 permit tcp 2001:db8:1::/64 host 2001:db8:1:1::1 eq 22
 permit tcp 2001:db8:1::/64 host 2001:db8:1:2::1 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interfaces of router with v4/v6, v4 and v6
=INPUT=
network:n0 = { ip6 = 2001:db8:1:0::/64; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n0 = { ip6 = 2001:db8:1:0::1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n0, network:n1, network:n3;
 permit src = user; dst = interface:r1.[auto]; prt = tcp 22;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.1 eq 22
 deny ip any any
--
ip access-list extended n3_in
 permit tcp 10.1.3.0 0.0.0.255 host 10.1.3.1 eq 22
 deny ip any any
--ipv6/r1
! [ ACL ]
ipv6 access-list n0_in
 permit tcp 2001:db8:1::/64 host 2001:db8:1::1 eq 22
 deny ipv6 any any
--
ipv6 access-list n1_in
 permit tcp 2001:db8:1:1::/64 host 2001:db8:1:1::1 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interfaces of network with v4/v6, v4 and v6
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:u1 = {
 interface:n2;
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; }
}
router:u2 = {
 interface:n2;
 interface:n3 = { ip = 10.1.3.2; }
}
router:u3 = {
 interface:n2;
 interface:n3 = { ip6 = 2001:db8:1:3::3; }
}
service:s1 = {
 user = interface:[network:n3].[auto];
 permit src = network:n1; dst = user; prt = tcp 22;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.3.1 eq 22
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.3.2 eq 22
 deny ip any any
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp 2001:db8:1:1::/64 host 2001:db8:1:3::1 eq 22
 permit tcp 2001:db8:1:1::/64 host 2001:db8:1:3::3 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=v4 part and v6 part connected only by v46 unnumbered network
=INPUT=
any:un = { link = network:un; }
network:n1 = { ip = 10.1.1.0/24; }
network:un = { unnumbered; unnumbered6; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip6 = 2001:db8:1:3::/64; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:un;
 interface:n2;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:1:3::1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = any:un;
 permit src = user; dst = network:n3, network:n4; prt = tcp 80;
}
=OUTPUT=
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp any6 2001:db8:1:3::/64 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--r3
! n1_in
access-list n1_in extended permit tcp any4 10.1.4.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Unconnected v4 part of combined network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; }
}
=ERROR=
Error: IPv4 topology has unconnected parts:
 - any:[network:n2]
 - any:[network:n1]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Partion attribute for unconnected v4 part of combined network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; partition = p1; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; partition = p2; }
router:r1 = {
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; }
}
=ERROR=
Error: Only one partition name allowed in IPv6 zone any:[network:n2], but found:
 - p2
 - p1
Warning: Spare partition name for single IPv6 partition any:[network:n2]: p2.
=END=

############################################################
=TITLE=V4 only partion attribute for unconnected part of combined network
=INPUT=
network:u1 = { unnumbered; partition = p1; }
network:u2 = { unnumbered; partition = p2; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; }
}
router:u1 = {
 interface:u1;
 interface:n1;
}
router:u2 = {
 interface:u2;
 interface:n2;
}
=WARNING=NONE

############################################################
=TITLE=Unconnected v6 part in combined zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; ip6 = 2001:db8:1:4::/64; }
network:n5 = { ip = 10.1.5.0/24; ip6 = 2001:db8:1:5::/64; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:u1 = {
 interface:n2;
 interface:n3;
}
router:u2 = {
 interface:n3;
 interface:n4;
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n4 = { ip = 10.1.4.1; ip6 = 2001:db8:1:4::1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; ip6 = 2001:db8:1:5::1; hardware = n5; }
}
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n4]
 Use partition attribute, if intended.
=END=

############################################################
# Two v4 zones combined with single v6 zone
=TEMPL=INPUT
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n6 = { ip6 = 2001:db8:1:6::/64; }
network:n14 = { ip = 10.1.4.0/24; }
network:n24 = { ip = 10.2.4.0/24; }
router:u1 = {
 interface:n1;
 interface:n14;
 interface:n6;
}
router:u2 = {
 interface:n2;
 interface:n24;
 interface:n6;
}
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n14 = { ip = 10.1.4.1; hardware = n14; }
 interface:n24 = { ip = 10.2.4.1; hardware = n24; }
}

############################################################
=TITLE=Two v4 zones combined with single v6 zone, without aggregate
=INPUT=[[INPUT]]
=WARNING=NONE

############################################################
=TITLE=Two v4 zones combined with single v6 zone, with named aggregate
=INPUT=
[[INPUT]]
any:a1 = { link = network:n1; }
=ERROR=
Error: IPv6 zone "any:[network:n1]" must not be connected to different IPv4 zones:
- any:[network:n1]
- any:[network:n2]
=END=

############################################################
=TITLE=Two v4 zones combined with single v6 zone, with unnnamed aggregate
=INPUT=
[[INPUT]]
service:s1 = {
 user = any:[network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
# Show error message only once.
service:s2 = {
 user = any:[network:n1];
 permit src = user; dst = network:n2; prt = tcp 81;
}
=ERROR=
Error: IPv6 zone "any:[network:n1]" must not be connected to different IPv4 zones:
- any:[network:n1]
- any:[network:n2]
=END=

############################################################
=TITLE=Two v6 zones combined with single v4 zone, with named aggregate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n2 = { ip = 10.1.2.2; }
}
any:a1 = { link = network:n1; }
=ERROR=
Error: IPv4 zone "any:[network:n1]" must not be connected to different IPv6 zones:
- any:[network:n1]
- any:[network:n2]
=END=

############################################################
=TITLE=v4 and v6 zone cluster with different zones
# v4: n2 belongs to zone n1
# v6: n2 belongs to zone n3
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1_4 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; }
}
router:r2_4 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n3 = { ip = 10.1.3.2; }
}
router:r1_6 = {
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; }
}
router:r2_6 = {
 interface:n2 = { ip6 = 2001:db8:1:2::2; }
 interface:n3 = { ip6 = 2001:db8:1:3::2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; ip6 = 2001:db8:1:1::3; hardware = n1; }
 interface:n3 = { ip = 10.1.3.3; ip6 = 2001:db8:1:3::3; hardware = n3; }
}
any:a1 = { link = network:n1; }
pathrestriction:p =
 interface:r2_4.n3,
 interface:r1_6.n1,
 interface:r3.n1,
;
=WARNING=NONE

############################################################
=TITLE=Missing v4, v6 IP at next hop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:u1 = {
 interface:n2;
 interface:n3;
}

=ERROR=
Error: Can't generate static routes for IPv4 interface:r1.n2 because IP address is unknown for:
 - interface:u1.n2
Error: Can't generate static routes for IPv6 interface:r1.n2 because IP address is unknown for:
 - interface:u1.n2
=END=

############################################################
=TITLE=Two static routes only for IPv6
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; ip6 = 2001:db8:9:1::1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/29; ip6 = 2001:db8:9:1::/64; }
router:h1 = {
 interface:t1 = { ip = 10.9.1.2; ip6 = 2001:db8:9:1::2; hardware = t1; }
 interface:n2;
}
router:h2 = {
 interface:t1 = { ip6 = 2001:db8:9:1::3; hardware = t1; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Two static routes for IPv6 network:n2
 at interface:r.t1 via interface:h2.t1 and interface:h1.t1
=END=

############################################################
=TITLE=Rule beween v4 and v6 network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
network:n2 = { ip6 = 1000::abcd:0001:0/112; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = 1000::abcd:0001:0001; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=ERROR=
Error: Must not use IPv4 network:n1 and IPv6 network:n2 together in service:s1
Error: Must not use IPv6 network:n2 and IPv4 network:n1 together in service:s2
=END=

############################################################
=TITLE=filter_only with v4 and v6
=INPUT=
network:n1 = { ip = 10.62.1.32/27; ip6 = 2001:db8:1:1::/64; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only = 10.62.0.0/21, 10.62.241.0/24,
               2001:db8:1:0::/60,
               ;
 interface:n1 = { ip = 10.62.1.33; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.62.241.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
network:n2 = { ip = 10.62.241.0/29; ip6 = 2001:db8:1:2::/64; }
router:d31 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.62.241.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:ext = { ip = 10.125.3.1; ip6 = 2001:db8:1:125::1; hardware = ext; }
}
network:ext = { ip = 10.125.3.0/24; ip6 = 2001:db8:1:125::/64; }

service:Test = {
 user = network:n1;
 permit src = user; dst = network:ext; prt = tcp 80;
}
=OUTPUT=
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--d31
! n2_in
access-list n2_in extended permit tcp 10.62.1.32 255.255.255.224 10.125.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--ipv6/d32
! n1_in
access-list n1_in extended deny ip any6 2001:db8:1::/60
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
--ipv6/d31
! n2_in
access-list n2_in extended permit tcp 2001:db8:1:1::/64 2001:db8:1:125::/64 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Size of v4 and v6 range must be equal
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 host:h1 = {
  range = 10.1.1.10-10.1.1.43;
  range6 = 2001:db8:1:1::11-2001:db8:1:1::32;
 }
 host:h2 = {
  range = 10.1.1.60-10.1.1.70;
  range6 = 2001:db8:1:1::30-2001:db8:1:1::3a;
 }
 host:h1f = {
  range = 10.1.1.11-10.1.1.43;
  range6 = 2001:db8:1:1::11-2001:db8:1:1::32;
 }
 host:h2f = {
  range = 10.1.1.60-10.1.1.70;
  range6 = 2001:db8:1:1::30-2001:db8:1:1:8000::3a;
 }
 host:h3 = {
  range = 10.1.1.10-10.1.1.43;
  ip6 = 2001:db8:1:1::a;
 }
 host:h4 = {
  ip = 10.1.1.10;
  range6 = 2001:db8:1:1::11-2001:db8:1:1::32;
 }
}
=ERROR=
Error: IPv4 and IPv6 ranges of host:h1f must have equal size
Error: IPv4 and IPv6 ranges of host:h2f must have equal size
Error: IPv4 and IPv6 ranges of host:h3 must have equal size
Error: IPv4 and IPv6 ranges of host:h4 must have equal size
=END=

############################################################
=TITLE=Dual stack service with icmp and icmpv6 together
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n1, network:n2;
 permit src = user;
        dst = network:n3, network:n4;
        prt = icmp 8, icmpv6 128;
}
=OUTPUT=
--r1
! n2_in
object-group network g0
 network-object 10.1.3.0 255.255.255.0
 network-object 10.1.4.0 255.255.255.0
access-list n2_in extended permit icmp 10.1.2.0 255.255.255.0 object-group g0 8
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--ipv6/r1
! n1_in
access-list n1_in extended permit icmp6 2001:db8:1:1::/64 2001:db8:1:3::/64 128
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit icmp6 2001:db8:1:2::/64 2001:db8:1:3::/64 128
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Dual stack service with complex icmp and icmpv6 together
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
protocol:ping-net4 = icmp 8, src_net, dst_net;
protocol:ping-net6 = icmpv6 128, src_net, dst_net;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocol:ping-net4, protocol:ping-net6;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit icmp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 8
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended permit icmp6 2001:db8:1:1::/64 2001:db8:1:2::/64 128
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=general_permit with icmp and icmpv6 together
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 general_permit = icmp, icmpv6;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
=OUTPUT=
--r1
! n2_in
access-list n2_in extended permit icmp any4 any4
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit icmp any4 any4
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
--
! n4_in
access-list n4_in extended permit icmp any4 any4
access-list n4_in extended deny ip any4 any4
access-group n4_in in interface n4
--ipv6/r1
! n1_in
access-list n1_in extended permit icmp6 any6 any6
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit icmp6 any6 any6
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit icmp6 any6 any6
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Implicit v6 area is duplicate
=INPUT=
area:a12 = { border = interface:r2.n2; }
area:a2 =  { inclusive_border = interface:r1.n1; border = interface:r2.n2; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
}
=ERROR=
Error: Duplicate IPv6 area:a12 and IPv6 area:a2
=END=

############################################################
=TITLE=Implicit v4 area is duplicate
=INPUT=
area:a12 = { border = interface:r2.n2; }
area:a2 =  { inclusive_border = interface:r1.n1; border = interface:r2.n2; }
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
}
=ERROR=
Error: Duplicate IPv4 area:a12 and IPv4 area:a2
=END=

############################################################
=TITLE=Implicit v6 area is empty
=INPUT=
area:a1 =  { inclusive_border = interface:r1.n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=WARNING=
Warning: IPv6 area:a1 is empty
=END=

############################################################
=TITLE=Unreachable v6 border of dual stack area
=INPUT=
area:a23 =  { border = interface:r1.n2, interface:r3.n3; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
=ERROR=
Error: Unreachable border of IPv6 area:a23:
 - interface:r3.n3
=END=

############################################################
=TITLE=Inconsistent definition of v6 area in loop
=INPUT=
area:a1 = { border = interface:r1.n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = {                ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
}
=ERROR=
Error: Inconsistent definition of IPv6 area:a1 in loop.
 It is reached from outside via this path:
 - interface:r1.n1
 - interface:r2.n1
 - interface:r2.n2
 - interface:r1.n2
 - interface:r1.n1
=END=

############################################################
=TITLE=Overlapping v6 areas
=INPUT=
area:a1 = { inclusive_border = interface:r1.n1; }
area:a2 = { inclusive_border = interface:r2.n3; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = {                   ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n3 = {                ip6 = 2001:db8:1:3::1; hardware = n3; }
}
=ERROR=
Error: Overlapping IPv6 area:a1 and area:a2
 - both areas contain any:[network:n2],
 - only 1. area contains any:[network:n3],
 - only 2. area contains any:[network:n1]
=END=

############################################################
=TITLE=IPv4 policy_distribution_point at pure IPv6 area
=INPUT=
area:a1 = { anchor = network:n2;
 router_attributes = { policy_distribution_point = host:h1; }
}
network:n1 = { ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
}
network:n2 = {  ip6 = 2001:db8:1:2::/64; }
router:u = {
 interface:n1;
 interface:n2;
}
=WARNING=
Warning: Ignoring IPv4 'policy_distribution_point' at IPv6 area:a1
=END=

############################################################
=TITLE=Ignore IPv4 policy_distribution_point at IPv6 part of combined area
=INPUT=
area:a1 = { anchor = network:n1;
 router_attributes = { policy_distribution_point = host:h1; }
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip = 10.1.1.10; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
}
=WARNING=NONE

############################################################
=TITLE=Useless IPv6 policy_distribution_point
=INPUT=
area:all = { anchor = network:n2;
 router_attributes = { policy_distribution_point = host:h1; }
}
area:a1 = { border = interface:r1.n1;
 router_attributes = { policy_distribution_point = host:h1; }
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip6 = 2001:db8:1:1::10; }
}
network:n2 = { ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = interface:r1.n1;
 permit src = host:h1; dst = user; prt = tcp 22;
}
=WARNING=
Warning: Useless 'policy_distribution_point' at IPv6 area:a1,
 it was already inherited from router_attributes of area:all
Warning: Useless 'policy_distribution_point' at IPv6 router:r1,
 it was already inherited from router_attributes of area:all
=END=

############################################################
=TITLE=Use combined46 area in automatic group
=INPUT=
area:a23 = { inclusive_border = interface:r1.n1; }
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
}
network:n2 = {
 ip = 10.1.2.0/24;
 ip6 = 2001:db8:1:2::/64;
}
network:n3 = {
 ip = 10.1.3.0/24;
 ip6 = 2001:db8:1:3::/64;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:[area:a23]; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.254.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp 2001:db8:1:1::/64 2001:db8:1:2::/63 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Named matching v4 aggregate linked to v6 network
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
any:a1 = { ip = 10.1.0.0/16; link = network:n1; }
=ERROR=
Error: Must not link IPv4 address to IPv6 network in any:a1
=END=

############################################################
=TITLE=Named matching v6 aggregate linked to v4 network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
any:a1 = { ip6 = 2001:db8::/32; link = network:n1; }
=ERROR=
Error: Must not link IPv6 address to IPv4 network in any:a1
=END=

############################################################
=TITLE=Named matching v6 aggregate linked to dual stack network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
any:n1-6-48 = { ip6 = 2001:db8:1::/48; link = network:n1; }
=WARNING=NONE

############################################################
=TITLE=Must not use ip and ip6 at named aggregate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
any:a1 = { ip = 10.1.0.0/16; ip6 = 2001:db8::/32; link = network:n1; }
=ERROR=
Error: Must not use both, "ip" and "ip6" in any:a1
=END=

############################################################
=TITLE=Unnamed matching v4 aggregate applied to v6 network
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = any:[ip= 10.1.0.0/16 & network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: IPv4/v6 mismatch for network:n1 in any:[ip = 10.1.0.0/16 & ..] of user of service:s1
=END=

############################################################
=TITLE=Unnanmed matching v6 aggregate applied to v4 area
=INPUT=
area:a1 = { anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = any:[ip6 = 2001:db8::/32 & area:a1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: IPv4/v6 mismatch for area:a1 in any:[ip6 = 2001:db8::/32 & ..] of user of service:s1
=END=

############################################################
=TITLE=Attribute 'ip' with v6 address
=INPUT=
network:n1 = { ip = 2001:db8:1:1::/64; }
=ERROR=
Error: IPv4 address expected in attribute 'ip' of network:n1
=END=

############################################################
=TITLE=Attribute 'ip6' with v4 address
=INPUT=
network:n1 = { ip6 = 10.1.1.0/24; }
=ERROR=
Error: IPv6 address expected in attribute 'ip6' of network:n1
=END=

############################################################
=TITLE=v6 host in v4 network
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip6 = 2001:db8:1:1::10; }
}
=ERROR=
Error: Missing IP address for IPv6 network:n1
=END=

############################################################
=TITLE=v4 host in v6 network
=INPUT=
network:n1 = {
 ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip = 10.1.1.10; }
}
=ERROR=
Error: Missing IP address for IPv4 network:n1
=END=

############################################################
=TITLE=v6 interface at v4 network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
}
=ERROR=
Error: Must not reference IPv4 network:n1 from IPv6 interface:r1.n1
=END=

############################################################
=TITLE=v6 interface with negotiated address at v4 network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { negotiated6; }
}
=ERROR=
Error: Must not reference IPv4 network:n1 from IPv6 interface:r1.n1
=END=

############################################################
=TITLE=Negotiated must equally be used in v4 and v6 part
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 interface:n1 = { negotiated; ip6 = 2001:db8:1:1::1; }
}
=ERROR=
Error: Missing 'negotiated6' in dual stack interface:r1.n1
=END=

############################################################
=TITLE=Unnumbered must equally be used in v4/v6 network
=INPUT=
network:n1 = { unnumbered; ip6 = 2001:db8:1:1::/64; }
network:n2 = { unnumbered6; ip = 10.1.1.0/24; }
network:n3 = { unnumbered; unnumbered6; }
=ERROR=
Error: Unnumbered network:n1 must not have attribute 'ip6'
Error: Unnumbered network:n2 must not have attribute 'ip'
=END=

############################################################
=TITLE=Duplicate v4 and v6 interface with same name
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
}
=ERROR=
Error: Duplicate attribute 'interface:n1' in router:r1
=END=

############################################################
=TITLE=Duplicate v6 interface with same name
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; }
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
}
=ERROR=
Error: Duplicate attribute 'interface:n1' in router:r1
=END=

############################################################
=TITLE=Split v4/v6 router at combined network
=INPUT=
--ipv6/topo
router:r1 = {
 interface:n1 = { ip6 = 2001:db8:1:1::1; }
}
--topo
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
}
=ERROR=
Error: Duplicate definition of router:r1 in ipv6/topo and topo
=END=

############################################################
=TITLE=Different number of IPv4/IPv6 secondary IP addresses at interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { unnumbered; }
network:n4 = { ip6 = 2001:db8:1:4::/64; }
network:n5 = { ip6 = 2001:db8:1:5::/64; }
network:n6 = { ip = 10.1.6.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1, 10.1.1.2; ip6 = 2001:db8:1:1::2; }
 interface:n2 = {
  ip = 10.1.2.1;
  ip6 = 2001:db8:1:2::2;
  virtual = { ip = 10.1.2.9; }
  secondary:snd = { ip6 = 2001:db8:1:2::9; }
  secondary:snd2 = {}
 }
 interface:n3 = {
  unnumbered;
  ip6 = 2001:db8:1:3::1;
 }
 interface:n4 = {
  unnumbered;
  unnumbered6;
  negotiated6;
 }
 interface:n5 = {
  ip6 = 2001:db8:1:5::2;
  virtual = { ip = 10.1.5.1; type = VRRP; id = 123; }
 }
 interface:n6 = {
  ip = 10.1.6.2;
  secondary:snd = { ip6 = 2001:db8:1:6::9; }
 }
}
=ERROR=
Error: Attributes 'ip' and 'ip6' must have same number of values in interface:r1.n1
Error: Missing 'ip' and/or 'ip6' in "secondary:snd2" of interface:r1.n2
Error: Missing 'unnumbered6' in dual stack interface:r1.n3
Error: Must not reference IPv4 network:n3 from IPv6 interface:r1.n3
Error: Must not use both, "negotiated6" and "unnumbered6" in interface:r1.n4
Error: Must not reference IPv6 network:n4 from IPv4 interface:r1.n4
Error: Must not use 'ip' in "virtual" of interface:r1.n5
Error: Missing 'ip6' in "virtual" of interface:r1.n5
Error: Must not use 'ip6' in "secondary:snd" of interface:r1.n6
Error: Missing 'ip' in "secondary:snd" of interface:r1.n6
=OPTIONS=--max_errors 20

############################################################
=TITLE=Dual stack router with v4/v6 only virtual interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = {
  ip = 10.1.1.2;
  ip6 = 2001:db8:1:1::2;
  virtual = { ip6 = 2001:db8:1:1::1; type = VRRP; id = 1; }
  hardware = n1;
 }
 interface:n2 = {
  ip = 10.1.2.2;
  ip6 = 2001:db8:1:2::2;
  virtual = { ip = 10.1.2.1; type = VRRP; id = 2; }
  hardware = n2;
 }
}
service:s1 = {
 user = interface:r1.n1.virtual;
 permit src = network:n1; dst = user; prt = tcp 22;
}
service:s2 = {
 user = interface:r1.n2.virtual;
 permit src = network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
--r1
ip access-list extended n2_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.2.1 eq 22
 permit 112 10.1.2.0 0.0.0.255 host 224.0.0.18
 deny ip any any
--ipv6/r1
ipv6 access-list n1_in
 permit tcp 2001:db8:1:1::/64 host 2001:db8:1:1::1 eq 22
 permit 112 2001:db8:1:1::/64 host ff02::12
 deny ipv6 any any
=END=

############################################################
=TITLE=Dual stack router with v4/v6 only secondary interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = {
  ip = 10.1.1.2;
  ip6 = 2001:db8:1:1::2;
  secondary:snd = { ip = 10.1.1.9; }
  hardware = n1;
 }
 interface:n2 = {
  ip = 10.1.2.2;
  ip6 = 2001:db8:1:2::2;
  secondary:snd = { ip6 = 2001:db8:1:2::9; }
  hardware = n2;
 }
}
service:s1 = {
 user = interface:r1.n1.snd;
 permit src = network:n1; dst = user; prt = tcp 22;
}
service:s2 = {
 user = interface:r1.n2.snd;
 permit src = network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
--r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.9 eq 22
 deny ip any any
--ipv6/r1
ipv6 access-list n2_in
 permit tcp 2001:db8:1:2::/64 host 2001:db8:1:2::9 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestriction with mixed, but not combined interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip6 = 2001:db8:1:2::2; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n2;
=WARNING=
Warning: pathrestriction:p has IPv4 and IPv6 interfaces, but no combined v4/6 interface
Warning: Ignoring IPv4 pathrestriction:p with only interface:r1.n1
Warning: Ignoring IPv6 pathrestriction:p with only interface:r1.n2
=END=

############################################################
=TITLE=Pathrestriction with one combined interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; }
}
pathrestriction:p = interface:r1.n1;
=WARNING=
Warning: Ignoring IPv4 pathrestriction:p with only interface:r1.n1
Warning: Ignoring IPv6 pathrestriction:p with only interface:r1.n1
=END=

############################################################
=TITLE=Ignore pathrestriction with only one interface from combined interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
pathrestriction:p = interface:r1.n1, interface:r2.n2;
=WARNING=NONE

############################################################
=TITLE=IPv6 pathrestriction from combined + extra interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:1:3::1; hardware = n3; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; }
 interface:n2 = { ip = 10.1.2.2; }
}
pathrestriction:p = interface:r1.n1, interface:r2.n1, interface:r1.n3;
=WARNING=
Warning: Ignoring IPv6 pathrestriction:p at interface:r1.n1
 because it isn't located inside cyclic graph
Warning: Ignoring IPv6 pathrestriction:p at interface:r2.n1
 because it isn't located inside cyclic graph
Warning: Ignoring IPv6 pathrestriction:p at interface:r1.n3
 because it isn't located inside cyclic graph
=END=

############################################################
=TITLE=Silently ignore IPv6 pathrestriction outside of loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n2 = { ip = 10.1.2.2; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n2;
=WARNING=NONE

############################################################
=TITLE=Only one v4 or v6 name in combined zone
=INPUT=
any:n1-v4 = { link = network:n1-v4; }
network:n1-v4 = { ip = 10.1.4.0/24; }
any:n1-v6 = { link = network:n1-v6; }
network:n1-v6 = { ip6 = 2001:db8:1:6::/64; }
router:u = {
 interface:n1-v4;
 interface:n1-v6;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
=ERROR=
Error: Duplicate any:n1-v4 and any:n1-v6 in any:[network:n1]
Error: Duplicate any:n1-v4 and any:n1-v6 in any:[network:n1]
=END=

############################################################
=TITLE=Aggregate with NAT linked to v6 network in combined zone
=INPUT=
any:n1-v6 = { link = network:n1-v6; nat:n1 = { ip = 10.9.9.0/24; } }
network:n1-v6 = { ip6 = 2001:db8:1:6::/64; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2-v4 = { ip = 10.1.2.0/24; }
router:u = {
 interface:n1-v6;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n2-v4 = { ip = 10.1.2.1; nat_out = n1; hardware = n2; }
}
service:s1 = {
 user = network:n2-v4;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
--r1
ip access-list extended n2_in
 deny ip any host 10.9.9.2
 permit tcp 10.1.2.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=nat_out at v6 interface
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 nat:n1 = { ip = 10.9.9.0/24; }
}
network:n2 = { ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; nat_out = n1; }
}
=WARNING=
Warning: Ignoring attribute 'nat_out' at interface:r1.n2
Warning: nat:n1 is defined, but not bound to any interface
=END=

############################################################
=TITLE=nat_in at v6 interface
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 nat:n1 = { ip = 10.9.9.0/24; }
}
network:n2 = { ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; nat_in = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
}
=WARNING=
Warning: Ignoring attribute 'nat_in' at interface:r1.n1
Warning: nat:n1 is defined, but not bound to any interface
=END=

############################################################
=TEMPL=INPUT
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip6 = 2001:db8:1:4::/64; }
network:n5 = { ip = 10.1.5.0/24; ip6 = 2001:db8:1:5::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip6 = 2001:db8:1:4::1; hardware = n4; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; }
 interface:n3 = { ip = 10.1.3.2; }
 interface:n4 = { ip6 = 2001:db8:1:4::2; }
 interface:n5;
}
pathrestriction:p1 = interface:r1.n1, interface:r2.n3;
pathrestriction:p2 = interface:r1.n1, interface:r2.n4;
=END=

############################################################
=TITLE=Named non matching aggregate with mixed v4, v4/6, v6 in zone cluster
=INPUT=
[[INPUT]]
any:a2 = { link = network:n2; }
service:s1 = {
 user = any:a2;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
--r1
! n2_in
access-list n2_in extended permit tcp any4 10.1.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp any4 10.1.1.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
--ipv6/r1
! n4_in
access-list n4_in extended permit tcp any6 2001:db8:1:1::/64 eq 80
access-list n4_in extended deny ip any6 any6
access-group n4_in in interface n4
=END=

############################################################
=TITLE=Unnamed non matching aggregate with mixed v4, v4/6, v6 in zone cluster
=INPUT=
[[INPUT]]
service:s1 = {
 user = any:[network:n2];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
--r1
! n2_in
access-list n2_in extended permit tcp any4 10.1.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp any4 10.1.1.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
--ipv6/r1
! n4_in
access-list n4_in extended permit tcp any6 2001:db8:1:1::/64 eq 80
access-list n4_in extended deny ip any6 any6
access-group n4_in in interface n4
=END=

############################################################
=TITLE=Unnamed non matching dual stack aggregate to v4 network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = any:[network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp any4 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Dual stack internet together with unnamed non matching aggregate
=INPUT=
network:Internet = {
 ip = 0.0.0.0/0;
 ip6 = ::/0;
 has_subnets;
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:Internet = {
 interface:Internet;
 interface:n1;
}
router:fw = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = any:[network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--fw
! n1_in
access-list n1_in extended permit tcp any4 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/fw
! n1_in
access-list n1_in extended permit tcp any6 2001:db8:1:2::/64 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Separate v4 and v6 internet together with unnamed non matching aggregate
=INPUT=
network:Internet4 = {
 ip = 0.0.0.0/0;
 has_subnets;
}
network:Internet6 = {
 ip6 = ::/0;
 has_subnets;
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:Internet = {
 interface:Internet4;
 interface:Internet6;
 interface:n1;
}
router:fw = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = any:[network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Must not use IPv4 only network:Internet4 together with dual stack any:[network:n1]
Error: Must not use IPv6 only network:Internet6 together with dual stack any:[network:n1]
=END=


############################################################
=TITLE=v4 internet in dual stack zone cluster with non matching aggregate
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 nat:inet = { ip = 1.1.1.0/24; }
}
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:inet = {
 interface:n2;
 interface:Internet = { nat_out = inet; }
}
network:Internet = { ip = 0.0.0.0/0; has_subnets; }

service:s1 = {
 user = any:[network:n2];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=ERROR=
Error: Must not use IPv4 only network:Internet together with dual stack any:[network:n2]
=END=

############################################################
=TITLE=Bridged network
=INPUT=
network:n1/left = {
 ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
}
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.9; ip6 = 2001:db8:1:1::9; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = {
 ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
}
=WARNING=NONE

############################################################
=TITLE=Bridge with missing IPv6 address
=INPUT=
network:n1/left = {
 ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
}
router:bridge = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.9; hardware = device; }
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
}
network:n1/right = {
 ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
}
=ERROR=
Error: Must define IPv6 interface:bridge.n1 for corresponding bridge interfaces
=END=

############################################################
=TITLE=IPv6 part of unnumbered network has more than two interfaces
=INPUT=
network:u = { unnumbered; unnumbered6; }
router:r1 = { interface:u = { unnumbered6; } }
router:r2 = { interface:u = { unnumbered; unnumbered6; } }
router:r3 = { interface:u = { unnumbered; unnumbered6; } }
=ERROR=
Error: Unnumbered IPv6 network:u is connected to more than two interfaces:
 - interface:r1.u
 - interface:r2.u
 - interface:r3.u
=END=

############################################################
=TITLE=Duplicate IPv6 address of hosts
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; }
 host:h2 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::1; }
}
=ERROR=
Error: Duplicate IP address for host:h1 and IPv6 host:h2
=END=

############################################################
=TITLE=Duplicate IPv4 address of networks
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=ERROR=
Error: IPv4 network:n1 and IPv4 network:n2 have identical address in any:[network:n1]
=END=

############################################################
=TITLE=Useless subnet_of at v6 network
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; subnet_of = network:n2;}
network:n2 = { ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=ERROR=
Error: network:n1 is subnet_of network:n2 but its IP doesn't match that's address
=END=

############################################################
=TITLE=subnet_of at combined network ignored at v6 part
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; subnet_of = network:n2;}
network:n2 = { ip = 10.1.0.0/21; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=WARNING=NONE

############################################################
=TITLE=subnet_of at combined network ignored at v4 part
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; subnet_of = network:n2;}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:0::/48; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=WARNING=NONE

############################################################
=TITLE=subnet_of at combined network matches v6 network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; subnet_of = network:n2;}
network:n2 = { ip6 = 2001:db8:1:0::/48; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=WARNING=NONE

############################################################
=TITLE=One subnet_of at combined network applicable to v4 and v6 part
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; subnet_of = network:n2;}
network:n2 = { ip = 10.1.0.0/21; ip6 = 2001:db8:1:0::/48; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=WARNING=NONE

############################################################
=TITLE=Warning at combined network with has_subnets ignored at v6 part
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 0.0.0.0/0; ip6 = 2001:db8:1:0::/48; has_subnets; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=WARNING=
Warning: IPv6 network:n1 is subnet of IPv6 network:n2
 in nat_domain:[network:n1].
 If desired, split subnet into IPv4 and IPv6 part
 and at IPv6 part declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Attribute has_subnets at combined network is not ignored with /0
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 0.0.0.0/0; ip6 = ::/0; has_subnets; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=WARNING=NONE

############################################################
=TITLE=Missing owner for v6 part
=INPUT=
area:v4 = {
 owner = o1;
 router_attributes = { owner = o1; }
 inclusive_border = interface:r1.n3;
}
owner:o1 = { admins = a1@example.com; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = {
 ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64;
 host:h2 = { ip = 10.1.2.10; ip6 = 2001:db8:1:2::10; }
}
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = host:h2; prt = tcp 81;
 permit src = user; dst = interface:r1.n2; prt = tcp 82;
}
=WARNING=
Warning: Unknown owner for IPv6 host:h2 in service:s1
Warning: Unknown owner for IPv6 interface:r1.n2 in service:s1
Warning: Unknown owner for IPv6 network:n2 in service:s1
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Dual stack objects in service with foreach
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 host:h10 = { ip = 10.1.1.10; ip6 = 2001:db8:1:1::10; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }

service:s1 = {
 user = foreach network:n1;
 permit src = user; dst = interface:[user].[all]; prt = tcp 80;
}
service:s2 = {
 user = foreach host:h10;
 permit src = user; dst = interface:[network:[user]].[all]; prt = tcp 81;
}
service:s3 = {
 user = foreach any:[network:n1];
 permit src = user; dst = interface:[user].[all]; prt = tcp 82;
}
service:s4 = {
 user = foreach interface:r1.n1;
 permit src = network:[user]; dst = user; prt = tcp 22;
}
=WARNING=NONE

############################################################
=TITLE=V4 only and dual stack objects in service with ipv4_only + foreach
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 ipv4_only;
 user = foreach interface:r1.[all];
 permit src = any:[user]; dst = user; prt = icmp 8;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 permit icmp any host 10.1.1.1 8
 deny ip any any
--
ip access-list extended n2_in
 permit icmp any host 10.1.2.1 8
 deny ip any any
--ipv6/r1
! [ ACL ]
ipv6 access-list n2_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Service with ipv4_only + foreach having only v4 objects
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:s1 = {
 ipv4_only;
 user = foreach interface:r1.[all];
 permit src = any:[user]; dst = user; prt = icmp 8;
}
=WARNING=
Warning: Ignoring 'ipv4_only' in service:s1, because no combined IPv4/IPv6 objects are in use
=END=
