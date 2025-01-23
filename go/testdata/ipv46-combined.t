
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
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

service:s1 = {
 ipv6_only;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 ipv4_only;
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=ERROR=
Error: Must not use 'ipv6_only' in service:s1, because no combined IPv4/IPv6 objects are in use
Error: Must not use 'ipv4_only' in service:s2, because no combined IPv4/IPv6 objects are in use
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
=TITLE=Unconnected v4 part of combined network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
=ERROR=
Error: IPv4 topology has unconnected parts:
 - any:[network:n2]
 - any:[network:n1]
 Use partition attribute, if intended.
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
=TITLE=general_permit with icmp and icmpv6 together
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 general_permit = icmp, icmpv6;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
=OUTPUT=
--r1
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
=TITLE=Disabled implicit v6 area
=INPUT=
area:a12 = { border = interface:r2.n2; ipv4_only; }
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
=WARNING=NONE

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
=TITLE=Disabled implicit v4 area
=INPUT=
area:a12 = { border = interface:r2.n2; ipv6_only; }
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
=WARNING=NONE

############################################################
=TITLE=Must use ipv6_only not with only v4 interfaces
=INPUT=
area:a1 = { border = interface:r1.n1; ipv4_only; }
network:n1 = { ip6 = 2001:db8:1:1::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
}
=ERROR=
Error: Must not use IPv6 interface:r1.n1 with 'ipv4_only' of 'border' of area:a1
Error: At least one of attributes 'border', 'inclusive_border' or 'anchor' must be defined for area:a1
=END=

############################################################
=TITLE=Must not use ipv4_only and ipv6_only together at area
=INPUT=
area:a1 = { anchor = network:n1; ipv4_only; ipv6_only; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
=ERROR=
Error: Must not use ipv4_only and ipv6_only together at area:a1
=END=

############################################################
=TITLE=IPv4 policy_distribution_point at IPv6 area
=INPUT=
area:a1 = { anchor = network:n1; ipv6_only;
 router_attributes = { policy_distribution_point = host:h1; }
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip = 10.1.1.10; }
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
=TITLE=Named matching v4 aggregate applied to v6 network
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
any:a1 = { ip = 10.1.0.0/16; link = network:n1; }
=ERROR=
Error: Must not link IPv4 address to IPv6 network in any:a1
=END=

############################################################
=TITLE=Named matching v6 aggregate applied to v4 network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
any:a1 = { ip6 = 2001:db8::/32; link = network:n1; }
=ERROR=
Error: Must not link IPv6 address to IPv4 network in any:a1
=END=

############################################################
=TITLE=Must not use ip and ip6 at named aggregate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
any:a1 = { ip = 10.1.0.0/16; ip6 = 2001:db8::/32; link = network:n1; }
=ERROR=
Error: Must not use both, "ip" and "ip6" in any:a1
=END=

############################################################
=TITLE=Anonymous matching v4 aggregate applied to v6 network
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
=TITLE=Anonymous matching v6 aggregate applied to v4 area
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
=TITLE=Atribute 'ip6' with v4 address
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
Error: Missing IPv6 address for network:n1
=END=

############################################################
=TITLE=v4 host in v6 network
=INPUT=
network:n1 = {
 ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip = 10.1.1.10; }
}
=ERROR=
Error: Missing IPv4 address for network:n1
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
=TITLE=Different number of IPv4/IPv6 secondary IP adresses at interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { unnumbered; }
network:n4 = {  ip6 = 2001:db8:1:4::/64; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1, 10.1.1.2; ip6 = 2001:db8:1:1::2; }
 interface:n2 = {
  ip = 10.1.2.1;
  ip6 = 2001:db8:1:2::2;
  virtual = { ip = 10.1.2.9; }
  secondary:snd = { ip6 = 2001:db8:1:2::9; }
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
}
=ERROR=
Error: interface:r1.n1 must have identical number of IPv4 and IPv6 addresses
Error: Missing 'ip' in secondary:snd of interface:r1.n2
Error: Missing 'ip6' in 'virtual' of interface:r1.n2
Error: Must not reference IPv4 network:n3 from IPv6 interface:r1.n3
Error: interface:r1.n4 must have identical number of IPv4 and IPv6 addresses
Error: Must not reference IPv6 network:n4 from IPv4 interface:r1.n4
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
Error: Duplicate any:n1-v4 and any:n1-v6 in any:[network:n1-v6]
Error: Duplicate any:n1-v4 and any:n1-v6 in any:[network:n1-v4]
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
