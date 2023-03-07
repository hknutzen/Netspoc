
############################################################
=TITLE=Interface with DHCP server
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; dhcp_server; }
}
=OUTPUT=
--R
ip access-list extended e0_in
 permit udp any any eq 67
 deny ip any any
=END=

############################################################
=TITLE=Interface as DHCP client
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; dhcp_client; }
}
=OUTPUT=
--r1
ip access-list extended n1_in
 permit udp any any eq 68
 deny ip any any
=END=

############################################################
=TITLE=Interface with OSPF
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; routing = OSPF; }
}
=OUTPUT=
--R
ip access-list extended e0_in
 permit 89 10.1.1.0 0.0.0.255 host 224.0.0.5
 permit 89 10.1.1.0 0.0.0.255 host 224.0.0.6
 permit 89 10.1.1.0 0.0.0.255 10.1.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Interface with EIGRP
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; routing = EIGRP; }
}
=OUTPUT=
--R
ip access-list extended e0_in
 permit 88 10.1.1.0 0.0.0.255 host 224.0.0.10
 permit 88 10.1.1.0 0.0.0.255 10.1.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Interface with RIPv2
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; routing = RIPv2; }
}
=OUTPUT=
--R
ip access-list extended e0_in
 permit udp 10.1.1.0 0.0.0.255 host 224.0.0.9 eq 520
 permit udp 10.1.1.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 520
 deny ip any any
=END=

############################################################
=TITLE=Interface with HSRP
=INPUT=
network:U = { ip = 10.1.1.0/24; }
network:V = { ip = 10.2.2.0/24; }
router:R1 = {
 managed;
 model = IOS;
 interface:U = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = HSRP; }
  hardware = e0;
 }
 interface:V = { ip = 10.2.2.1; hardware = e1;}
}
router:R2 = {
 managed;
 model = IOS;
 interface:U = {
  ip = 10.1.1.3;
  virtual = { ip = 10.1.1.1; type = HSRP; }
  hardware = e0;
 }
 interface:V = { ip = 10.2.2.2; hardware = e1;}
}
=OUTPUT=
--R1
ip access-list extended e0_in
 permit udp 10.1.1.0 0.0.0.255 host 224.0.0.2 eq 1985
 deny ip any any
--
interface e0
 ip address 10.1.1.2 255.255.255.0
 ip access-group e0_in in
interface e1
 ip address 10.2.2.1 255.255.255.0
 ip access-group e1_in in
--R2
ip access-list extended e0_in
 permit udp 10.1.1.0 0.0.0.255 host 224.0.0.2 eq 1985
 deny ip any any
--
interface e0
 ip address 10.1.1.3 255.255.255.0
 ip access-group e0_in in
interface e1
 ip address 10.2.2.2 255.255.255.0
 ip access-group e1_in in
=END=

############################################################
=TITLE=Interface with HSRPv2
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = HSRPv2; }
  hardware = e0;
 }
}
=OUTPUT=
--R
ip access-list extended e0_in
 permit udp 10.1.1.0 0.0.0.255 host 224.0.0.102 eq 1985
 deny ip any any
=END=

############################################################
