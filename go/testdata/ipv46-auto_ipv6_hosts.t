
############################################################
=TITLE=auto_ipv6_hosts = readable
=INPUT=
network:n1 = {
 ip = 172.17.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 auto_ipv6_hosts = readable;
 host:h = { ip = 172.17.1.48; }
 host:r = { range = 172.17.1.188 - 172.17.1.207; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 172.17.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
}
network:n2 = { ip6 = 2001:db8:1:2::/64; }

service:s1 = {
 user = host:h, host:r;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object host 2001:db8:1:1:172:17:1:48
 network-object 2001:db8:1:1:172:17:1:188/125
 network-object 2001:db8:1:1:172:17:1:190/124
 network-object 2001:db8:1:1:172:17:1:1a0/123
 network-object 2001:db8:1:1:172:17:1:1c0/122
 network-object 2001:db8:1:1:172:17:1:200/125
access-list n1_in extended permit tcp object-group v6g0 2001:db8:1:2::/64 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=auto_ipv6_hosts=binary
=INPUT=
network:n1 = {
 ip = 172.17.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 auto_ipv6_hosts = binary;
 host:h = { ip = 172.17.1.48; }
 host:r = { range = 172.17.1.188 - 172.17.1.207; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 172.17.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
}
network:n2 = { ip6 = 2001:db8:1:2::/64; }

service:s1 = {
 user = host:h, host:r;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object host 2001:db8:1:1::ac11:130
 network-object 2001:db8:1:1::ac11:1bc/126
 network-object 2001:db8:1:1::ac11:1c0/124
access-list n1_in extended permit tcp object-group v6g0 2001:db8:1:2::/64 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=auto_ipv6_hosts = invalid
=INPUT=
network:n1 = {
 ip = 172.17.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 auto_ipv6_hosts = invalid;
}
=ERROR=
Error: Expected 'readable|binary|none' in 'auto_ipv6_hosts' of network:n1
=END=

############################################################
=TITLE=auto_ipv6_hosts at host and host already has IPv6 address
=INPUT=
network:n1 = {
 ip = 172.17.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 auto_ipv6_hosts = readable;
 host:h = { ip = 172.17.1.48; auto_ipv6_hosts = binary; }
 host:r = { range = 172.17.1.188 - 172.17.1.207; auto_ipv6_hosts = none; }
 host:h2 = { ip = 172.17.1.101; ip6 = 2001:db8:1:1::101; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 172.17.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }

service:s1 = {
 user = host:h, host:r, host:h2;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
object-group network g0
 network-object host 172.17.1.48
 network-object host 172.17.1.101
 network-object 172.17.1.188 255.255.255.252
 network-object 172.17.1.192 255.255.255.240
access-list n1_in extended permit tcp object-group g0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--ipv6/r1
! n1_in
object-group network v6g0
 network-object host 2001:db8:1:1::101
 network-object host 2001:db8:1:1::ac11:130
access-list n1_in extended permit tcp object-group v6g0 2001:db8:1:2::/64 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=auto_ipv6_hosts at IPv6 host
=INPUT=
network:n1 = {
 ip6 = 2001:db8:1:1::/64;
 host:h = { ip6 = 2001:db8:1:1::1; auto_ipv6_hosts = readable; }
}
=WARNING=
Warning: Ignoring attribute 'auto_ipv6_hosts' in IPv6 host:h
=END=

############################################################
=TITLE=auto_ipv6_hosts at IPv6 network with prefix len > 64
=INPUT=
network:n1 = {
 ip = 172.17.1.0/24;
 ip6 = 2001:db8:1:1:1::/80;
 auto_ipv6_hosts = readable;
 host:h = { ip = 172.17.1.48; }
}
=ERROR=
Error: Can't use 'auto_ipv6_hosts' at network:n1 having prefix len > 64
=END=

############################################################
=TITLE=auto_ipv6_hosts at IPv4 only network
=INPUT=
network:n1 = {
 ip = 172.17.1.0/24;
 auto_ipv6_hosts = readable;
 host:h = { ip = 172.17.1.48; }
}
=WARNING=
Warning: Ignoring 'auto_ipv6_hosts' at IPv4 only network:n1
=END=

############################################################
=TITLE=auto_ipv6_hosts at IPv6 only network
=INPUT=
network:n1 = {
 ip6 = 2001:db8:1:1:1::/80;
 auto_ipv6_hosts = readable;
}
=WARNING=
Warning: Ignoring 'auto_ipv6_hosts' at IPv6 only network:n1
=END=

############################################################
=TITLE=auto_ipv6_hosts at combined46 area having IPv4 only network
=INPUT=
area:all = { anchor = network:n1; auto_ipv6_hosts = readable; }
network:n1 = {
 ip = 172.17.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 host:h = { ip = 172.17.1.48; }
}
router:r1 = {
 interface:n1;
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
=WARNING=NONE

############################################################
=TITLE=Nested inheritance of attribute auto_ipv6_hosts
=INPUT=
area:all = { anchor = network:n1; auto_ipv6_hosts = readable; }
area:a1 = { border = interface:r1.n1; auto_ipv6_hosts = readable; }
area:a2 = { border = interface:r1.n2; auto_ipv6_hosts = binary; }
area:a3 = { border = interface:r1.n3; auto_ipv6_hosts = none; }
network:n1 = {
 ip = 10.1.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 host:h1 = { ip = 10.1.1.10; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 ip6 = 2001:db8:1:2::/64;
 auto_ipv6_hosts = binary;
 host:h2 = { ip = 10.1.2.10; }
}
network:n3 = {
 ip = 10.1.3.0/24;
 ip6 = 2001:db8:1:3::/64;
 host:h3 = { ip = 10.1.3.10; }
}
network:n4 = { ip6 = 2001:db8:1:4::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
 interface:n4 = { ip6 = 2001:db8:1:4::1; hardware = n4; }
}
service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2, host:h3; prt = tcp 80;
}
=WARNING=
Warning: Useless 'auto_ipv6_hosts = readable' at area:a1,
 it was already inherited from area:all
Warning: Useless 'auto_ipv6_hosts = binary' at network:n2,
 it was already inherited from area:a2
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp host 2001:db8:1:1:10:1:1:10 host 2001:db8:1:2::a01:20a eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
