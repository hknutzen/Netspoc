
############################################################
=TITLE=Interface with DHCP server
=PARAMS=--ipv6
=INPUT=
network:U = { ip = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = ::a01:101; hardware = e0; dhcp_server; }
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 permit udp any any eq 67
 deny ipv6 any any
=END=

############################################################
=TITLE=Interface as DHCP client
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; dhcp_client; }
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit udp any any eq 68
 deny ipv6 any any
=END=

############################################################
=TITLE=Interface with OSPF
=PARAMS=--ipv6
=INPUT=
network:U = { ip = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = ::a01:101; hardware = e0; routing = OSPF; }
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 permit 89 ::a01:100/120 host ff02::5
 permit 89 ::a01:100/120 host ff02::6
 permit 89 ::a01:100/120 ::a01:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Interface with EIGRP
=PARAMS=--ipv6
=INPUT=
network:U = { ip = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = ::a01:101; hardware = e0; routing = EIGRP; }
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 permit 88 ::a01:100/120 host ff02::a
 permit 88 ::a01:100/120 ::a01:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Interface with RIPv2
=PARAMS=--ipv6
=INPUT=
network:U = { ip = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = ::a01:101; hardware = e0; routing = RIPv2; }
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 permit udp ::a01:100/120 host ff02::9 eq 520
 permit udp ::a01:100/120 ::a01:100/120 eq 520
 deny ipv6 any any
=END=

############################################################
=TITLE=Interface with HSRP
=PARAMS=--ipv6
=INPUT=
network:U = { ip = ::a01:100/120; }
network:V = { ip = ::a02:200/120; }
router:R1 = {
 managed;
 model = IOS;
 interface:U = {
  ip = ::a01:102;
  virtual = { ip = ::a01:101; type = HSRP; }
  hardware = e0;
 }
 interface:V = { ip = ::a02:201; hardware = e1;}
}
router:R2 = {
 managed;
 model = IOS;
 interface:U = {
  ip = ::a01:103;
  virtual = { ip = ::a01:101; type = HSRP; }
  hardware = e0;
 }
 interface:V = { ip = ::a02:202; hardware = e1;}
}
=OUTPUT=
--ipv6/R1
ipv6 access-list e0_in
 permit udp ::a01:100/120 host ::e000:2 eq 1985
 deny ipv6 any any
--
interface e0
 ipv6 address ::a01:102/120
 ipv6 traffic-filter e0_in in
interface e1
 ipv6 address ::a02:201/120
 ipv6 traffic-filter e1_in in
--ipv6/R2
ipv6 access-list e0_in
 permit udp ::a01:100/120 host ::e000:2 eq 1985
 deny ipv6 any any
--
interface e0
 ipv6 address ::a01:103/120
 ipv6 traffic-filter e0_in in
interface e1
 ipv6 address ::a02:202/120
 ipv6 traffic-filter e1_in in
=END=

############################################################
=TITLE=Interface with HSRPv2
=PARAMS=--ipv6
=INPUT=
network:U = { ip = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = {
  ip = ::a01:102;
  virtual = { ip = ::a01:101; type = HSRPv2; }
  hardware = e0;
 }
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 permit udp ::a01:100/120 host ff02::66 eq 1985
 deny ipv6 any any
=END=

############################################################
