
############################################################
=TITLE=General permit
=TEMPL=input
protocol:unreachable = icmpv6 3;
network:m = { ip = ::a02:200/120; }
router:r = {
 managed;
 model = {{.}};
 general_permit = tcp, icmpv6 0, protocol:unreachable, udp;
 interface:m = { ip = ::a02:202; hardware = e0; }
 interface:n = { ip = ::a01:102, ::a01:103; hardware = e1; }
 interface:lo = { ip = ::a09:902; hardware = lo; loopback; }
}
network:n = { ip = ::a01:100/120; }
service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = icmpv6;
}
=END=
=PARAMS=--ipv6
=INPUT=[[input NX-OS]]
=OUTPUT=
--ipv6/r
ipv6 access-list e0_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 permit udp any any
 50 deny ip any ::a01:102/128
 60 deny ip any ::a01:103/128
 70 permit icmp ::a02:200/120 ::a01:100/120
 80 deny ip any any
--
ipv6 access-list e1_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 permit udp any any
 50 deny ip any any
=END=

############################################################
=TITLE=General permit (Linux)
=PARAMS=--ipv6
=INPUT=[[input Linux]]
=OUTPUT=
--ipv6/r
# [ ACL ]
:c1 -
:c2 -
:c3 -
:c4 -
-A c1 -j ACCEPT -p ipv6-icmp --icmp-type 0
-A c1 -j ACCEPT -p ipv6-icmp --icmp-type 3
-A c2 -j ACCEPT -p ipv6-icmp --icmp-type 0
-A c2 -j ACCEPT -p ipv6-icmp --icmp-type 3
-A c3 -j ACCEPT -p ipv6-icmp --icmp-type 0
-A c3 -j ACCEPT -p ipv6-icmp --icmp-type 3
-A c4 -j ACCEPT -p ipv6-icmp --icmp-type 0
-A c4 -j ACCEPT -p ipv6-icmp --icmp-type 3
--
:e0_self -
-A e0_self -j ACCEPT -p tcp
-A e0_self -j ACCEPT -p udp
-A e0_self -g c1 -p ipv6-icmp
-A INPUT -j e0_self -i e0
--
:e0_e1 -
-A e0_e1 -j ACCEPT -p tcp
-A e0_e1 -j ACCEPT -p udp
-A e0_e1 -j c2 -p ipv6-icmp
-A e0_e1 -j ACCEPT -s ::a02:200/120 -d ::a01:100/120 -p ipv6-icmp
-A FORWARD -j e0_e1 -i e0 -o e1
--
:e1_self -
-A e1_self -j ACCEPT -p tcp
-A e1_self -j ACCEPT -p udp
-A e1_self -g c3 -p ipv6-icmp
-A INPUT -j e1_self -i e1
--
:e1_e0 -
-A e1_e0 -j ACCEPT -p tcp
-A e1_e0 -j ACCEPT -p udp
-A e1_e0 -g c4 -p ipv6-icmp
-A FORWARD -j e1_e0 -i e1 -o e0
=END=

############################################################
=TITLE=General permit with no_in_acl
=PARAMS=--ipv6
=INPUT=
network:m = { ip = ::a02:200/120; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmpv6 0, icmpv6 3;
 interface:m = { ip = ::a02:202; hardware = e0; no_in_acl; }
 interface:n = { ip = ::a01:102, ::a01:103; hardware = e1; }
 interface:lo = { ip = ::a09:902; hardware = lo; loopback; }
}
network:n = { ip = ::a01:100/120; }
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list e0_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any ::a02:202/128
 50 deny ip any ::a01:102/128
 60 deny ip any ::a09:902/128
 70 deny ip any ::a01:103/128
 80 permit ip any any
--
ipv6 access-list e1_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any any
--
ipv6 access-list e1_out
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any any
=END=

############################################################
=TITLE=General permit with udp and named tcp protocol
=PARAMS=--ipv6
=INPUT=
protocol:TCP = tcp;
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r = {
 managed;
 model = IOS;
 general_permit = udp, protocol:TCP;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list n1_in
 permit tcp any any
 permit udp any any
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp any any
 permit udp any any
 deny ipv6 any any
=END=

############################################################
=TITLE=No ports permitted
=PARAMS=--ipv6
=INPUT=
area:all = {
 anchor = network:n;
 router_attributes = { general_permit = protocol:ftp-data, tcp 80, udp 1; }
}
network:n = { ip = ::a01:100/120; }
protocol:ftp-data = tcp 20:1024-65535;
=END=
=ERROR=
Error: Must not use 'protocol:ftp-data' with ports in general_permit of router_attributes of area:all
Error: Must not use 'tcp 80' with ports in general_permit of router_attributes of area:all
Error: Must not use 'udp 1' with ports in general_permit of router_attributes of area:all
=END=

############################################################
=TITLE=No modifiers permitted
=PARAMS=--ipv6
=INPUT=
area:all = { anchor = network:n; router_attributes = { general_permit = protocol:ping-net; } }
network:n = { ip = ::a01:100/120; }
protocol:ping-net = icmpv6 8, src_net, dst_net;
=END=
=ERROR=
Error: Must not use 'protocol:ping-net' with modifiers in general_permit of router_attributes of area:all
=END=

############################################################
=TITLE=Ignore duplicates
=PARAMS=--ipv6
=INPUT=
protocol:UDP = udp;
area:all = {
 anchor = network:n;
 router_attributes = { general_permit = icmpv6 3, udp, protocol:UDP, icmpv6 3; }
 }
network:n = { ip = ::a01:100/120; }
=END=
=WARNING=
Warning: Ignoring duplicate 'udp' in general_permit of router_attributes of area:all
Warning: Ignoring duplicate 'icmpv6 3' in general_permit of router_attributes of area:all
=END=

############################################################
=TITLE=Check for useless inheritance
=PARAMS=--ipv6
=INPUT=
area:all = {
 anchor = network:n;
 router_attributes = { general_permit = icmpv6, tcp; }
}
network:n = { ip = ::a01:100/120; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmpv6;
 interface:n = { ip = ::a01:102; hardware = e1; }
}
=END=
=WARNING=
Warning: Useless attribute 'general_permit' at router:r,
 it was already inherited from router_attributes of area:all
=END=

############################################################
=TITLE=Redundant at nested areas
=PARAMS=--ipv6
=INPUT=
# a1 < all
area:all = { router_attributes = { general_permit = icmpv6; } anchor = network:n1; }
area:a1 =  { router_attributes = { general_permit = icmpv6; } inclusive_border = interface:asa1.n2; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
=END=
=WARNING=
Warning: Useless attribute 'general_permit' at area:a1,
 it was already inherited from router_attributes of area:all
=END=

############################################################
=TITLE=Check for ignored inheritance (1)
=PARAMS=--ipv6
=INPUT=
area:all = {
 anchor = network:n;
 router_attributes = { general_permit = icmpv6 3, icmpv6 13; }
}
network:n = { ip = ::a01:100/120; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = icmpv6;
 interface:n = { ip = ::a01:102; hardware = e1; }
}
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list e1_in
 10 permit icmp any any
 20 deny ip any any
=END=

############################################################
=TITLE=Check for ignored inheritance (2)
=PARAMS=--ipv6
=INPUT=
area:all = {
 anchor = network:n;
 router_attributes = { general_permit = icmpv6 3, icmpv6 13; }
}
network:n = { ip = ::a01:100/120; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = icmpv6 3, icmpv6 4;
 interface:n = { ip = ::a01:102; hardware = e1; }
}
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list e1_in
 10 permit icmp any any 3
 20 permit icmp any any 4
 30 deny ip any any
=END=

############################################################
