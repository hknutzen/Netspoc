
############################################################
=TITLE=Simple topology IPv6
=INPUT=
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = E2;}
}
group:g1 = network:n1;
service:test1 = {
 user = group:g1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
=END=
=OUTPUT=
-- ipv6/r1
ipv6 access-list E1_in
 deny ipv6 any host 1000::abcd:2:1
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 range 80 90
 deny ipv6 any any
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Too large IPv6 range
=INPUT=
network:n1 = { ip = 1000::0/16;
 host:h1 = { range = 1000::FFFF:FFFF:FFFF:FF00 - 1000::0001:0:0:0:0; }
}
=END=
=ERROR=
Error: IP range doesn't fit into /64 network in host:h1
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Split IPv6 ranges
=INPUT=
network:n1 = { ip = 1000::0/16;
 host:h1 = { range = 1000::FFFF:FFFF:FF00 - 1000::0001:0:0:B; }
 host:h2 = { range = 1000::FFFF:FFF0 - 1000::0001:0000:0000; }
 host:h3 = { range = 1000::fff0 - 1000::1:4; }
}
network:n2 = { ip = 2000::0/80;
 host:h = {
  range = 2000::FFF0 - 2000::FFFF;
 }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::0001; hardware = n1;}
 interface:n2 = {ip = 2000::0001; hardware = n2;}
}
service:test1 = {
 user = host:h1, host:h2, host:h3;
 permit src = user;
 dst = host:h;
 prt = tcp 80-90;
}
=END=
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 permit tcp 1000::ffff:ffff:ff00/120 2000::fff0/124 range 80 90
 permit tcp 1000::1:0:0:0/125 2000::fff0/124 range 80 90
 permit tcp 1000::1:0:0:8/126 2000::fff0/124 range 80 90
 permit tcp 1000::ffff:fff0/124 2000::fff0/124 range 80 90
 permit tcp host 1000::1:0:0 2000::fff0/124 range 80 90
 permit tcp 1000::fff0/124 2000::fff0/124 range 80 90
 permit tcp 1000::1:0/126 2000::fff0/124 range 80 90
 permit tcp host 1000::1:4 2000::fff0/124 range 80 90
 deny ipv6 any any
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=IPv6 with host ranges
=INPUT=
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = {
 ip = 1000::abcd:0002:0000/112;
 host:a = { range = 1000::abcd:0002:0012-1000::abcd:0002:0022; }
 host:b = { range = 1000::abcd:0002:0060-1000::abcd:0002:0240; }
}
router:r1 = {
 managed;
 model = NX-OS;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = E2;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = host:a, host:b;
 prt = tcp 80-90;
}
=END=
=OUTPUT=
-- ipv6/r1
object-group ip address v6g0
 10 1000::abcd:2:12/127
 20 1000::abcd:2:14/126
 30 1000::abcd:2:18/125
 40 1000::abcd:2:20/127
 50 1000::abcd:2:22/128
 60 1000::abcd:2:60/123
 70 1000::abcd:2:80/121
 80 1000::abcd:2:100/120
 90 1000::abcd:2:200/122
 100 1000::abcd:2:240/128
--
ipv6 access-list E1_in
 10 permit tcp 1000::abcd:1:0/112 addrgroup v6g0 range 80 90
 20 deny ip any any
--
interface E1
 ipv6 address 1000::abcd:1:1/112
 ipv6 traffic-filter E1_in in
interface E2
 ipv6 address 1000::abcd:2:1/112
 ipv6 traffic-filter E2_in in
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=OSPF, EIGRP, HSRP, VRRP, DHCP
=INPUT=
network:n1 = { ip = 1000::abcd:0001:0/112; }
network:n2 = { ip = 1000::abcd:0002:0000/112; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {
  ip = 1000::abcd:0001:0002;
  virtual = { ip = 1000::abcd:0001:0001; type = VRRP; id = 6; }
  hardware = n1;
  routing = OSPF;
  dhcp_server;
 }
 interface:n2 = {
  ip = 1000::abcd:0002:0002;
  virtual = { ip = 1000::abcd:0002:0001; type = HSRP; id = 7; }
  hardware = n2;
  routing = EIGRP;
  dhcp_client;
 }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n1 = {
  ip = 1000::abcd:0001:0003;
  virtual = { ip = 1000::abcd:0001:0001; type = VRRP; id = 6; }
  hardware = n1;
  routing = OSPF;
 }
 interface:n2 = {
  ip = 1000::abcd:0002:0003;
  virtual = { ip = 1000::abcd:0002:0001; type = HSRP; id = 7; }
  hardware = n2;
  routing = EIGRP;
 }
}
=END=
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 permit 89 1000::abcd:1:0/112 host ff02::5
 permit 89 1000::abcd:1:0/112 host ff02::6
 permit 89 1000::abcd:1:0/112 1000::abcd:1:0/112
 permit 112 1000::abcd:1:0/112 host ff02::12
 permit udp any any eq 67
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit 88 1000::abcd:2:0/112 host ff02::a
 permit 88 1000::abcd:2:0/112 1000::abcd:2:0/112
 permit udp 1000::abcd:2:0/112 host ::e000:2 eq 1985
 permit udp any any eq 68
 deny ipv6 any any
--
interface n1
 ipv6 address 1000::abcd:1:2/112
 ip inspect X in
 ipv6 traffic-filter n1_in in
--
interface n2
 ipv6 address 1000::abcd:2:2/112
 ip inspect X in
 ipv6 traffic-filter n2_in in
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Static routes
=INPUT=
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}
network:n3 = { ip = 1000::abcd:0003:0/112;}
network:n4 = { ip = 1000::abcd:0004:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
router:r2 = {
 managed;
 model = NX-OS;
 interface:n2 = {ip = 1000::abcd:0002:0002; hardware = n2;}
 interface:n3 = {ip = 1000::abcd:0003:0001; hardware = n3;}
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = {ip = 1000::abcd:0003:0002; hardware = n3;}
 interface:n4 = {ip = 1000::abcd:0004:0001; hardware = n4;}
}
service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
! [ Routing ]
ipv6 route 1000::abcd:4:0/112 1000::abcd:2:2
--ipv6/r2
! [ Routing ]
ipv6 route 1000::abcd:1:0/112 1000::abcd:2:1
ipv6 route 1000::abcd:4:0/112 1000::abcd:3:2
--ipv6/r3
! [ Routing ]
ipv6 route n3 1000::abcd:1:0/112 1000::abcd:3:1
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Crypto tunnel to directly connected software clients
=INPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn = {
 type = ipsec:aes256SHA;
}
network:n1 = { ip = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = {
  spoke = crypto:vpn;
  ip = ::a01:102;
 }
 interface:clients;
}
network:clients = {
 ip = ::a09:100/120;
 host:id:foo@domain.x = {  ip = ::a09:10a; }
}
service:s1 = {
 user = host:id:foo@domain.x.clients;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=OUTPUT=
-- ipv6/asavpn
! [ Routing ]
ipv6 route n1 ::a09:100/120 ::a01:102
--
! n1_in
access-list n1_in extended permit tcp host ::a09:10a ::a01:100/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=IPv6 network and interface in IPv4 topology
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:1; hardware = E2;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
=END=
=ERROR=
Error: IPv4 address expected in 'ip' of network:n2
Error: IPv4 address expected in 'ip' of interface:r1.n2
=END=

############################################################
=TITLE=IPv4 network and interface in IPv6 topology
=INPUT=
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 10.2.2.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 10.2.2.1; hardware = E2;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
=END=
=ERROR=
Error: IPv6 address expected in 'ip' of network:n2
Error: IPv6 address expected in 'ip' of interface:r1.n2
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Must not use icmpv6 protocol as number
=INPUT=
protocol:ICMPv6  = proto 58;
network:n1 = { ip = 1000::abcd:0001:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = interface:r1.n1;
 prt = protocol:ICMPv6;
}
=END=
=ERROR=
Error: 'proto 58' must not be used in service:test1, use 'icmpv6' instead
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Must not use icmp with ipv6
=INPUT=
protocol:ICMP = icmp;
network:n1 = { ip = 1000::abcd:0001:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = interface:r1.n1;
 prt = protocol:ICMP;
}
=END=
=ERROR=
Error: protocol:ICMP must not be used in IPv6 service:test1
=END=
=OPTIONS=--ipv6

############################################################
=TITLE=Use icmpv6 in general_permit of router_attributes of area
=INPUT=
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = E2;}
}
area:a = {
 anchor = network:n1;
 router_attributes = { general_permit = icmpv6; }
}
=END=
=OUTPUT=
-- ipv6/r1
ipv6 access-list E1_in
 permit icmp any any
 deny ipv6 any any
=END=
=OPTIONS=--ipv6
