
############################################################
=TITLE=Simple topology IPv6
=INPUT=
network:n1 = { ip6 = 1000::abcd:0001:0/112;}
network:n2 = { ip6 = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
group:g1 = network:n1;
service:test1 = {
 user = group:g1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90, icmpv6 128;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 range 80 90
access-list n1_in extended permit icmp6 1000::abcd:1:0/112 1000::abcd:2:0/112 128
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Large IPv6 range
=INPUT=
network:n1 = { ip6 = 1000::0/16;
 host:h1 = { range6 = 1000::FFFF:FFFF:FFFF:FF00 - 1000::A:0:0:0:0; }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip6 = 1000::1; hardware = n1;}
}
service:test1 = {
 user = host:h1;
 permit src = user;
 dst = interface:r1.n1;
 prt = tcp 22;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 permit tcp 1000::ffff:ffff:ffff:ff00/120 host 1000::1 eq 22
 permit tcp 1000:0:0:1::/64 host 1000::1 eq 22
 permit tcp 1000:0:0:2::/63 host 1000::1 eq 22
 permit tcp 1000:0:0:4::/62 host 1000::1 eq 22
 permit tcp 1000:0:0:8::/63 host 1000::1 eq 22
 permit tcp host 1000:0:0:a:: host 1000::1 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Split IPv6 ranges
=INPUT=
network:n1 = { ip6 = 1000::0/16;
 host:h1 = { range6 = 1000::FFFF:FFFF:FF00 - 1000::0001:0:0:B; }
 host:h2 = { range6 = 1000::FFFF:FFF0 - 1000::0001:0000:0000; }
 host:h3 = { range6 = 1000::fff0 - 1000::1:4; }
}
network:n2 = { ip6 = 2000::0/80;
 host:h = {
  range6 = 2000::FFF0 - 2000::FFFF;
 }
}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip6 = 1000::0001; hardware = n1;}
 interface:n2 = {ip6 = 2000::0001; hardware = n2;}
}
service:test1 = {
 user = host:h1, host:h2, host:h3;
 permit src = user;
 dst = host:h;
 prt = tcp 80-90;
}
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

############################################################
=TITLE=IPv6 with host ranges
=INPUT=
network:n1 = { ip6 = 1000::abcd:0001:0/112;}
network:n2 = {
 ip6 = 1000::abcd:0002:0000/112;
 host:a = { range6 = 1000::abcd:0002:0012-1000::abcd:0002:0022; }
 host:b = { range6 = 1000::abcd:0002:0060-1000::abcd:0002:0240; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip6 = 1000::abcd:0002:0001; hardware = E2;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = host:a, host:b;
 prt = tcp 80-90;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list E1_in
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:12/127 range 80 90
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:14/126 range 80 90
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:18/125 range 80 90
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:20/127 range 80 90
 permit tcp 1000::abcd:1:0/112 host 1000::abcd:2:22 range 80 90
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:60/123 range 80 90
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:80/121 range 80 90
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:100/120 range 80 90
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:200/122 range 80 90
 permit tcp 1000::abcd:1:0/112 host 1000::abcd:2:240 range 80 90
 deny ipv6 any any
--
interface E1
 ipv6 address 1000::abcd:1:1/112
 ipv6 traffic-filter E1_in in
interface E2
 ipv6 address 1000::abcd:2:1/112
 ipv6 traffic-filter E2_in in
=END=

############################################################
=TITLE=OSPF, EIGRP, HSRP, VRRP, DHCP
=INPUT=
network:n1 = { ip6 = 1000::abcd:0001:0/112; }
network:n2 = { ip6 = 1000::abcd:0002:0000/112; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {
  ip6 = 1000::abcd:0001:0002;
  virtual = { ip6 = 1000::abcd:0001:0001; type = VRRP; id = 6; }
  hardware = n1;
  routing = OSPF;
  dhcp_server;
 }
 interface:n2 = {
  ip6 = 1000::abcd:0002:0002;
  virtual = { ip6 = 1000::abcd:0002:0001; type = HSRP; id = 7; }
  hardware = n2;
  routing = EIGRP;
  dhcp_client;
 }
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:n1 = {
  ip6 = 1000::abcd:0001:0003;
  virtual = { ip6 = 1000::abcd:0001:0001; type = VRRP; id = 6; }
  hardware = n1;
  routing = OSPF;
 }
 interface:n2 = {
  ip6 = 1000::abcd:0002:0003;
  virtual = { ip6 = 1000::abcd:0002:0001; type = HSRP; id = 7; }
  hardware = n2;
  routing = EIGRP;
 }
}
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

############################################################
=TITLE=Static routes
=INPUT=
network:n1 = { ip6 = 1000::abcd:0001:0/112;}
network:n2 = { ip6 = 1000::abcd:0002:0/112;}
network:n3 = { ip6 = 1000::abcd:0003:0/112;}
network:n4 = { ip6 = 1000::abcd:0004:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = {ip6 = 1000::abcd:0002:0002; hardware = n2;}
 interface:n3 = {ip6 = 1000::abcd:0003:0001; hardware = n3;}
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = {ip6 = 1000::abcd:0003:0002; hardware = n3;}
 interface:n4 = {ip6 = 1000::abcd:0004:0001; hardware = n4;}
}
service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
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
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = {
  spoke = crypto:vpn;
  ip6 = ::a01:102;
 }
 interface:clients;
}
network:clients = {
 ip6 = ::a09:100/120;
 host:id:foo@domain.x = {  ip6 = ::a09:10a; }
}
service:s1 = {
 user = host:id:foo@domain.x.clients;
 permit src = user; dst = network:n1; prt = tcp 80;
}
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

############################################################
=TITLE=Must not use icmpv6 protocol as number
=INPUT=
protocol:ICMPv6  = proto 58;
network:n1 = { ip6 = 1000::abcd:0001:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = interface:r1.n1;
 prt = protocol:ICMPv6;
}
=ERROR=
Error: 'proto 58' must not be used in service:test1, use 'icmpv6' instead
=END=

############################################################
=TITLE=Must not use icmp with ipv6
=INPUT=
protocol:ICMP = icmp;
network:n1 = { ip6 = 1000::abcd:0001:0/112; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip6 = 1000::abcd:0001:0001; hardware = n1; }
}
service:test1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.n1; prt = protocol:ICMP;
}
=ERROR=
Error: 'icmp' must not be used in service:test1, use 'icmpv6' instead
=END=

############################################################
=TITLE=Use icmpv6 in general_permit of router_attributes of area
=INPUT=
network:n1 = { ip6 = 1000::abcd:0001:0/112;}
network:n2 = { ip6 = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
area:a = {
 anchor = network:n1;
 router_attributes = { general_permit = icmpv6; }
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 permit icmp any any
 deny ipv6 any any
=END=

############################################################
=TITLE=Ignore ICMP reply messages
=INPUT=
network:n1 = { ip6 = 1000::abcd:0001:0/112;}
network:n2 = {
 ip6 = 1000::abcd:0002:0/112;
 host:h2 = { ip6 = 1000::abcd:0002:0002; }
 host:h3 = { ip6 = 1000::abcd:0002:0003; }
}
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = icmpv6 1/0, icmpv6 1/1, icmpv6 129/0, icmpv6 3/1;
 permit src = user;
        dst = host:h2;
        prt = icmpv6 3, icmpv6 129, icmpv6 1;
 permit src = user;
        dst = host:h3;
        prt = icmpv6;
}
=OUTPUT=
--ipv6/r1
:n1_n2 -
-A n1_n2 -j ACCEPT -s 1000::abcd:1:0/112 -d 1000::abcd:2:3 -p ipv6-icmp
-A FORWARD -j n1_n2 -i n1 -o n2
=OPTIONS=--ipv6

############################################################
=TITLE=Reuse code file
=SHOW_DIAG=
=TEMPL=input
network:n1 = { ip6 = 1000::abcd:0001:0/112;}
network:n2 = { ip6 = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip6 = 1000::abcd:0002:0001; hardware = n2;}
}
service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=INPUT=[[input]]
=REUSE_PREV=[[input]]
=WARNING=
DIAG: Reused .prev/ipv6/r1
=WITH_OUTDIR=
=OPTIONS=--ipv6

############################################################
=TITLE=Can't create ipv6/ directory
=SETUP=
mkdir -p out/.prev
touch out/ipv6
chmod u-w out/ipv6
=INPUT=
network:n1 = { ip6 = 1000::abcd:0001:0/112; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip6 = 1000::abcd:0001:0001; hardware = n1;}
}
=WITH_OUTDIR=
=ERROR=
Error: Can't mkdir out/ipv6: file exists
Aborted
=END=
