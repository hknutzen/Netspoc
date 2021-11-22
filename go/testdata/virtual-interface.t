
############################################################
=TITLE=Virtual interface with negotiated IP
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = {
  negotiated;
  virtual = { ip = 10.1.1.1; }
 }
}
=END=
=ERROR=
Error: No virtual IP supported for negotiated interface:r1.n1
=END=

############################################################
=TITLE=Unknown redundancy protocol
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = XYZ; id = ff; }
 }
}
=END=
=ERROR=
Error: Unknown redundancy protocol in 'virtual' of interface:r1.n1
Error: Redundancy ID must be numeric in 'virtual' of interface:r1.n1
Error: Redundancy ID is given without redundancy protocol in 'virtual' of interface:r1.n1
=END=

############################################################
=TITLE=Too large redundancy ID
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = HSRP; id = 1000; }
 }
}
=END=
=ERROR=
Error: Redundancy ID must be < 256 in 'virtual' of interface:r1.n1
=END=

############################################################
=TITLE=Virtual interface with NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n = { ip = 10.9.9.0/25; dynamic; }}
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.1;
  nat:n = { ip = 10.9.9.1; }
  virtual = { ip = 10.1.1.11; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.2;
  nat:n = { ip = 10.9.9.2; }
  virtual = { ip = 10.1.1.11; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; bind_nat = n; }
}
=END=
=ERROR=
Error: interface:r1.n1 with virtual interface must not use attribute 'nat'
Error: interface:r2.n1 with virtual interface must not use attribute 'nat'
=END=

############################################################
=TITLE=Virtual interface in non cyclic sub-graph
=INPUT=
# Virtual interface outside of loop, but at border of other loop.
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; virtual = { ip = 10.1.1.1; } hardware = n1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; virtual = { ip = 10.1.1.1; } hardware = n1; }
}
network:n1 = { ip = 10.1.1.0/24; }
# Add loop. This isn't needed to get the error messages.
# But the virtual interfaces are located at border of this loop.
# With this test we also check, that automatically created
# pathrestrictions at virtual interfaces are removed correctly in this
# situation.
network:n2 = { ip = 10.1.2.0/24; }
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.4; hardware = n1; }
 interface:n2 = { ip = 10.1.2.4; hardware = n2; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.5; hardware = n1; }
 interface:n2 = { ip = 10.1.2.5; hardware = n2; }
}
service:s1 = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = user; dst = network:n2; prt = udp 123;
}
=END=
=ERROR=
Error: interface:r1.n1.virtual must be located inside cyclic sub-graph
Error: interface:r2.n1.virtual must be located inside cyclic sub-graph
=END=

############################################################
=TITLE=Virtual interfaces prevent valid path
# Implicit pathrestriction would permit path,
# but virtual interfaces let path be pruned later.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; virtual = { ip = 10.1.2.1; } hardware = n2; }
}

router:r2 = {
 interface:n2 = { ip = 10.1.2.3; virtual = { ip = 10.1.2.1; } }
 interface:n3;
}

router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}

pathrestriction:r3 =
 interface:r3.n1,
 interface:r3.n3,
;

service:s1 = {
 user = network:n3;
 permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=END=
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = HSRP; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.3;
  virtual = { ip = 10.1.1.1; type = VRRP; id = 123; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
=END=
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
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  virtual = { ip = 10.1.1.11; type = HSRP; id = 11;}
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.11; type = HSRP; id = 11; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.3;
  virtual = { ip = 10.1.1.31; type = HSRP; id = 11; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.4;
  virtual = { ip = 10.1.1.41; type = VRRP; id = 11; } # no conflict with HSRP
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.4; hardware = n2; }
}
=END=
=ERROR=
Error: Must use different ID at unrelated
 - interface:r1.n1.virtual
 - interface:r3.n1.virtual
=END=

############################################################
=TITLE=Routers connecting networks with virtual interfaces
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}
network:n3 = { ip = 10.3.3.0/24;}
network:n4 = { ip = 10.4.4.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = {ip = 10.2.2.1; hardware = E2;}
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E3;}
 interface:n3 = {ip = 10.3.3.1; {{.v1}} hardware = E4;}
}
router:r3 = {
 managed;
 model = ASA;
 interface:n2 = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E5;}
 interface:n3 = {ip = 10.3.3.2; {{.v2}} hardware = E6;}
}
router:r4 = {
 model = ASA;
 managed;
 interface:n3 = {ip = 10.3.3.3; hardware = E7;}
 interface:n4 = {ip = 10.4.4.1; hardware = E8;}
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=
=INPUT=
[[input
v1: "virtual = {ip = 10.3.3.9;}"
v2: "virtual = {ip = 10.3.3.9;}"
]]
=OUTPUT=
--r1
route E2 10.4.4.0 255.255.255.0 10.2.2.9
--r4
route E7 10.1.1.0 255.255.255.0 10.3.3.9
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
=INPUT=[[input {v1: "virtual = {ip = 10.3.3.9;}", v2: ""}]]
=ERROR=
Error: Ambiguous static routes for network:n1 at interface:r4.n3 via
 - interface:r2.n3.virtual
 - interface:r3.n3
=END=

############################################################
