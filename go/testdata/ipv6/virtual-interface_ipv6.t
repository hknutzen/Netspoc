
############################################################
=TITLE=Virtual interface with negotiated IP
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  negotiated6;
  virtual = { ip6 = ::a01:101; }
 }
}
=ERROR=
Error: No virtual IP supported for negotiated interface:r1.n1
=END=

############################################################
=TITLE=Unknown redundancy protocol
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  ip6 = ::a01:102;
  virtual = { ip6 = ::a01:101; type = XYZ; id = ff; }
 }
}
=ERROR=
Error: Unknown redundancy protocol in 'virtual' of interface:r1.n1
Error: Redundancy ID must be numeric in 'virtual' of interface:r1.n1
Error: Redundancy ID is given without redundancy protocol in 'virtual' of interface:r1.n1
=END=

############################################################
=TITLE=Too large redundancy ID
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  ip6 = ::a01:102;
  virtual = { ip6 = ::a01:101; type = HSRP; id = 1000; }
 }
}
=ERROR=
Error: Redundancy ID must be > 0, < 256 in 'virtual' of interface:r1.n1
=END=

############################################################
=TITLE=Negative redundancy ID
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  ip6 = ::a01:102;
  virtual = { ip6 = ::a01:101; type = HSRP; id = -999; }
 }
}
=ERROR=
Error: Redundancy ID must be > 0, < 256 in 'virtual' of interface:r1.n1
=END=

############################################################
=TITLE=Virtual interface with NAT
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; nat:n = { ip6 = ::a09:900/121; dynamic; }}
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip6 = ::a01:101;
  nat:n = { ip6 = ::a09:901; }
  virtual = { ip6 = ::a01:10b; }
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; nat_out = n; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip6 = ::a01:102;
  nat:n = { ip6 = ::a09:902; }
  virtual = { ip6 = ::a01:10b; }
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; nat_out = n; }
}
=ERROR=
Error: interface:r1.n1 with virtual interface must not use attribute 'nat'
Error: interface:r2.n1 with virtual interface must not use attribute 'nat'
=END=

############################################################
=TITLE=Virtual interface in non cyclic sub-graph at border of loop
=INPUT=
# Virtual interface outside of loop, but at border of other loop.
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; virtual = { ip6 = ::a01:101; } hardware = n1; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:103; virtual = { ip6 = ::a01:101; } hardware = n1; }
}
network:n1 = { ip6 = ::a01:100/120; }
# Add loop. This isn't needed to get warnings.
# But the virtual interfaces are located at border of this loop and hence
# the automatically created pathrestriction is valid.
network:n2 = { ip6 = ::a01:200/120; }
router:r3 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:104; hardware = n1; }
 interface:n2 = { ip6 = ::a01:204; hardware = n2; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:105; hardware = n1; }
 interface:n2 = { ip6 = ::a01:205; hardware = n2; }
}
service:s1 = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = user; dst = network:n2; prt = udp 123;
}
=WARNING=
Warning: interface:r1.n1.virtual must be located inside cyclic sub-graph
Warning: interface:r2.n1.virtual must be located inside cyclic sub-graph
=END=

############################################################
=TITLE=Virtual interfaces in non cyclic sub-graph with static routes
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n3 = { ip6 = ::a01:302; virtual = { ip6 = ::a01:301; } hardware = n3; }
}

router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:303; virtual = { ip6 = ::a01:301; }  hardware = n3; }
}

router:r3 = {
 model = IOS;
 managed;
 interface:n3 = { ip6 = ::a01:304; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}

service:s1 = {
 user = network:n4;
 permit src = user; dst = network:n1, network:n2; prt = tcp 80;
}
=WARNING=
Warning: interface:r1.n3.virtual must be located inside cyclic sub-graph
Warning: interface:r2.n3.virtual must be located inside cyclic sub-graph
=OUTPUT=
--ipv6/r3
! [ Routing ]
ipv6 route ::a01:100/120 ::a01:302
ipv6 route ::a01:200/120 ::a01:303
=END=

############################################################
=TITLE=Virtual interfaces prevent valid path
# Implicit pathrestriction would permit path,
# but virtual interfaces let path be pruned later.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; virtual = { ip6 = ::a01:201; } hardware = n2; }
}

router:r2 = {
 interface:n2 = { ip6 = ::a01:203; virtual = { ip6 = ::a01:201; } }
 interface:n3;
}

router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
}

pathrestriction:r3 =
 interface:r3.n1,
 interface:r3.n3,
;

service:s1 = {
 user = network:n3;
 permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=ERROR=
Error: No valid path
 from any:[network:n3]
 to interface:r1.n2.virtual
 for rule permit src=network:n3; dst=interface:r1.n2; prt=tcp 22; of service:s1
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Different protocol / id at related virtual interfaces
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip6 = ::a01:102;
  virtual = { ip6 = ::a01:101; type = HSRP; }
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip6 = ::a01:103;
  virtual = { ip6 = ::a01:101; type = VRRP; id = 123; }
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
=ERROR=
Error: Must use identical redundancy protocol at
 - interface:r1.n1.virtual
 - interface:r2.n1.virtual
Error: Must use identical ID at
 - interface:r1.n1.virtual
 - interface:r2.n1.virtual
=END=

############################################################
=TITLE=Identical id at unrelated virtual interfaces
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip6 = ::a01:101;
  virtual = { ip6 = ::a01:10b; type = HSRP; id = 11;}
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip6 = ::a01:102;
  virtual = { ip6 = ::a01:10b; type = HSRP; id = 11; }
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip6 = ::a01:103;
  virtual = { ip6 = ::a01:11f; type = HSRP; id = 11; }
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:203; hardware = n2; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip6 = ::a01:104;
  virtual = { ip6 = ::a01:129; type = VRRP; id = 11; } # no conflict with HSRP
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:204; hardware = n2; }
}
=ERROR=
Error: Must use different ID at unrelated
 - interface:r1.n1.virtual
 - interface:r3.n1.virtual
=END=

############################################################
=TITLE=Routers connecting networks with virtual interfaces
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = { ip6 = ::a02:200/120;}
network:n3 = { ip6 = ::a03:300/120;}
network:n4 = { ip6 = ::a04:400/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip6 = ::a01:101; hardware = E1;}
 interface:n2 = {ip6 = ::a02:201; hardware = E2;}
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = {ip6 = ::a02:202; virtual = {ip6 = ::a02:209;} hardware = E3;}
 interface:n3 = {ip6 = ::a03:301; {{.v1}} hardware = E4;}
}
router:r3 = {
 managed;
 model = ASA;
 interface:n2 = {ip6 = ::a02:203; virtual = {ip6 = ::a02:209;} hardware = E5;}
 interface:n3 = {ip6 = ::a03:302; {{.v2}} hardware = E6;}
}
router:r4 = {
 model = ASA;
 managed;
 interface:n3 = {ip6 = ::a03:303; hardware = E7;}
 interface:n4 = {ip6 = ::a04:401; hardware = E8;}
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=INPUT=
[[input
v1: "virtual = {ip6 = ::a03:309;}"
v2: "virtual = {ip6 = ::a03:309;}"
]]
=OUTPUT=
--ipv6/r1
ipv6 route E2 ::a04:400/120 ::a02:209
--ipv6/r4
ipv6 route E7 ::a01:100/120 ::a03:309
=END=

############################################################
=TITLE=Missing virtual interfaces on backward path
=INPUT=[[input {v1: "", v2: ""}]]
=ERROR=
Error: Ambiguous static routes for network:n1 at interface:r4.n3 via
 - interface:r2.n3
 - interface:r3.n3
=END=

############################################################
=TITLE=One missing virtual interface on backward path
=INPUT=[[input {v1: "virtual = {ip6 = ::a03:309;}", v2: ""}]]
=ERROR=
Error: Ambiguous static routes for network:n1 at interface:r4.n3 via
 - interface:r2.n3.virtual
 - interface:r3.n3
=END=

############################################################
