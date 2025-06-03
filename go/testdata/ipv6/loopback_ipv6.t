
############################################################
=TITLE=Unexpected attribute at loopback interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:l = {
  ip6 = ::a01:102; loopback; no_in_acl; dhcp_server; routing = OSPF;
 }
}
=ERROR=
Error: Attribute 'no_in_acl' not supported for loopback interface:r.l
Error: Attribute 'dhcp_server' not supported for loopback interface:r.l
Error: Attribute 'routing' not supported for loopback interface:r.l
=END=

############################################################
=TITLE=Loopback interface without IP
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:l = { loopback; }
}
=ERROR=
Error: loopback interface:r.l must have IP address
=END=

############################################################
=TITLE=Unnumbered loopback interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:l = {
  unnumbered6; loopback;
 }
}
=ERROR=
Error: Attribute 'unnumbered6' not supported for loopback interface:r.l
=END=

############################################################
=TITLE=Negotiated loopback interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:l = {
  negotiated6; loopback;
 }
}
=ERROR=
Error: Attribute 'negotiated6' not supported for loopback interface:r.l
=END=

############################################################
=TITLE=Secondary IP at loopback interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:l = {
  ip6 = ::a01:102, ::a01:103; loopback;
 }
}
=ERROR=
Error: Secondary or virtual IP not supported for loopback interface:r.l
=END=

############################################################
=TITLE=Virtual IP at loopback interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r = {
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:l = {
  ip6 = ::a01:102; loopback; virtual = { ip6 = ::a01:109; }
 }
}
=ERROR=
Error: Secondary or virtual IP not supported for loopback interface:r.l
=END=

############################################################
=TITLE=Network connected to loopback interface
=INPUT=
router:r = {
 interface:l = { ip6 = ::a01:102; loopback; }
}
network:l = { ip6 = ::a01:102/128; }
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[interface:r.l]
 - any:[network:l]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Network with /32 mask should be loopback
=INPUT=
router:r = {
 interface:l = { ip6 = ::a01:102; }
}
network:l = { ip6 = ::a01:102/128; }
=WARNING=
Warning: interface:r.l has address of its network.
 Remove definition of network:l and
 add attribute 'loopback' at interface definition.
=END=

############################################################
=TITLE=Ignore loopback of managed router in automatic group
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:lb = { ip6 = ::a09:909; hardware = lb; loopback; }
}
service:s1 = {
 user = network:[interface:r1.lb];
 permit src = network:n1; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Ignore zone of loopback interface at mixed hardware
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:lo = { ip6 = ::a00:1; hardware = n1; loopback; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
service:s1 = {
 user = any:[interface:r1.lo], network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:202
 permit tcp ::a01:100/120 ::a01:200/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Suppress warning for loopback subnet at border of zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; has_subnets; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:lo = { ip6 = ::a01:102; hardware = lo; loopback; }
}
=WARNING=NONE

############################################################
=TITLE=Show warning for loopback subnet not at border of zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; has_subnets; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:lo = { ip6 = ::a01:102; hardware = lo; loopback; }
}
=WARNING=
Warning: interface:r2.lo is subnet of network:n1
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Loopback is subnet
=INPUT=
network:n = {
 ip6 = ::a01:100/120;
}
router:r = {
 interface:n = { ip6 = ::a01:101; }
 interface:l = { ip6 = ::a01:102; loopback; subnet_of = network:n; }
 interface:m = { ip6 = ::a01:103; loopback; }
}
=WARNING=
Warning: interface:r.m is subnet of network:n
 in nat_domain:[network:n].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Dynamic NAT to multiple virtual loopback interfaces (secondary)
=TODO= No IPv6
#
# Soll bei local_optimization loopback interfaces und NAT network als
# identisch erkennen.
=TEMPL=input
network:customer = { ip6 = ::a01:700/120; }
router:gw = {
 managed {{.}};
 model = ASA;
 interface:customer = { ip6 = ::a01:701;    hardware = outside;}
 interface:trans    = { ip6 = ::a01:301;   hardware = inside;}
}
network:trans = { ip6 = ::a01:300/120; }
router:b1 = {
 managed;
 model = Linux;
 interface:trans = {
  ip6 = ::a01:303;
  virtual = { ip6 = ::a01:302; type = VRRP; }
  nat_out = extern;
  hardware = eth0;
 }
 interface:extern = {
  virtual = { ip6 = f000::c101:102; type = VRRP; }
  loopback;
  hardware = eth1;
 }
 interface:server = {
  virtual = { ip6 = ::a01:211; type = VRRP; }
  hardware = eth1;
 }
}
router:b2 = {
 managed;
 model = Linux;
 interface:trans = {
  ip6 = ::a01:304;
  virtual = { ip6 = ::a01:302; type = VRRP; }
  nat_out = extern;
  hardware = eth0;
 }
 interface:extern = {
  virtual = { ip6 = f000::c101:102; type = VRRP; }
  loopback;
  hardware = eth1;
 }
 interface:server = {
  virtual = { ip6 = ::a01:211; type = VRRP; }
  hardware = eth1;
 }
}
network:server = {
 ip6 = ::a01:210/124;
 nat:extern = { ip6 = f000::c101:102/128; dynamic; }
}
protocol:Echo = icmpv6 8;
service:p1 = {
 user = network:customer;
 permit src = user;
        dst = interface:b1.extern.virtual, interface:b2.extern.virtual;
        prt = protocol:Echo;
}
service:p2 = {
 user = network:customer;
 permit src = user; dst = network:server; prt = protocol:Echo;
}
=INPUT=[[input =secondary]]
=OUTPUT=
--ipv6/gw
! outside_in
access-list outside_in extended permit ip ::a01:700/120 host f000::c101:102
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Dynamic NAT to multiple virtual loopback interfaces
=TODO= No IPv6
=INPUT=[[input ""]]
=OUTPUT=
--ipv6/gw
! outside_in
access-list outside_in extended permit icmp6 ::a01:700/120 host f000::c101:102 8
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Dynamic NAT to loopback interface
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; nat:extern = { ip6 = f000::c101:102/128; dynamic; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:lo = { ip6 = f000::c101:102; hardware = lo; loopback; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; nat_out = extern; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2;}
 interface:n3 = { ip6 = ::a01:301; hardware = n3;}
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp host f000::c101:102 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Illegal NAT to loopback interface (1)
=TODO= No IPv6
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120; nat:extern = { ip6 = f000::c101:102/128; dynamic; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:{{.}} = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; nat_out = extern; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:lo = { ip6 = f000::c101:102; hardware = lo; loopback; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2;}
 interface:n3 = { ip6 = ::a01:301; hardware = n3;}
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=INPUT=[[input r1]]
=ERROR=
Error: interface:r2.lo and nat:extern of network:n1 have identical address
 in nat_domain:[network:n2]
=END=

############################################################
=TITLE=Illegal NAT to loopback interface (2)
=TODO= No IPv6
=INPUT=[[input r3]]
=ERROR=
Error: nat:extern of network:n1 and interface:r2.lo have identical address
 in nat_domain:[interface:r2.lo]
=END=

############################################################
=TITLE=Routing via managed virtual interfaces to loopback
# Loopback interface is reached only via physical interface.
# Don't use virtual IP but physical IP as next hop.
=TEMPL=input
network:intern = { ip6 = ::a01:100/120; }
router:asa = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern1 = {
 model = IOS,FW;
 {{.}}
 interface:dmz = {
  ip6 = f000::c0a8:b;
  virtual = { ip6 = f000::c0a8:1; }
  hardware = Eth0;
 }
 interface:sync = { ip6 = f000::ac11:10b; hardware = Loopback0; loopback; }
 interface:internet = {
  ip6 = ::102:30b;
  virtual = { ip6 = ::102:301; }
  hardware = Eth1;
 }
}
router:extern2 = {
 model = IOS,FW;
 {{.}}
 interface:dmz = {
  ip6 = f000::c0a8:c;
  virtual = { ip6 = f000::c0a8:1; }
  hardware = Eth2;
 }
 interface:sync = { ip6 = f000::ac11:10c; hardware = Loopback0; loopback; }
 interface:internet = {
  ip6 = ::102:30c;
  virtual = { ip6 = ::102:301; }
  hardware = Eth3;
 }
}
network:internet = { ip6 = ::/0; has_subnets; }
service:test = {
 user = network:intern;
 permit src = user; dst = interface:extern1.sync; prt = tcp 22;
}
=INPUT=[[input managed;]]
=OUTPUT=
--ipv6/asa
ipv6 route outside f000::ac11:10b/128 f000::c0a8:b
--
! inside_in
access-list inside_in extended permit tcp ::a01:100/120 host f000::ac11:10b eq 22
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--ipv6/extern1
ipv6 route ::a01:100/120 f000::c0a8:65
--
ipv6 access-list Eth0_in
 permit tcp ::a01:100/120 host f000::ac11:10b eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Routing via unmanaged virtual interfaces to loopback
# Redundancy interfaces at unmanaged device have no implicit
# pathrestriction.  A zone which contains network ::/0 uses this
# address for optimized routing.
=INPUT=[[input ""]]
=OUTPUT=
--ipv6/asa
! [ Routing ]
ipv6 route outside ::/0 f000::c0a8:1
--
! inside_in
access-list inside_in extended permit tcp ::a01:100/120 host f000::ac11:10b eq 22
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
