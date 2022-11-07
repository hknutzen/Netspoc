
############################################################
=TITLE=Path between virtual interfaces
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:153; virtual = {ip = ::a01:102;} hardware = e0;}
 interface:b = {ip = ::a02:253; hardware = e1;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:154; virtual = {ip = ::a01:102;} hardware = e0;}
 interface:b = {ip = ::a02:254; hardware = e1;}
}
network:b = { ip = ::a02:200/120;}
service:test = {
 user = interface:r1.a, interface:r2.a;
 permit src = user;
        dst = user;
        prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list e0_in
 permit tcp host ::a01:154 host ::a01:153 eq 22
 permit tcp host ::a01:154 host ::a01:153 established
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any any
--ipv6/r2
ipv6 access-list e0_in
 permit tcp host ::a01:153 host ::a01:154 eq 22
 permit tcp host ::a01:153 host ::a01:154 established
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Multiple virtual interface pairs with interface as destination
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:153; virtual = {ip = ::a01:102;} hardware = e0;}
 interface:c1 = {ip = ::a03:102; virtual = {ip = ::a03:101;} hardware = v1;}
 interface:c2 = {ip = ::a03:202; virtual = {ip = ::a03:201;} hardware = v2;}
 interface:b = {ip = ::a02:253; virtual = {ip = ::a02:202;} hardware = e1;}
}
network:c1 = {ip = ::a03:100/120;}
network:c2 = {ip = ::a03:200/120;}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:154; virtual = {ip = ::a01:102;} hardware = e0;}
 interface:c1 = {ip = ::a03:103; virtual = {ip = ::a03:101;} hardware = v1;}
 interface:c2 = {ip = ::a03:203; virtual = {ip = ::a03:201;} hardware = v2;}
 interface:b = {ip = ::a02:254; virtual = {ip = ::a02:202;} hardware = e1;}
}
network:b = { ip = ::a02:200/120;}
service:test = {
 user = network:a;
 permit src = user;
        dst = interface:r1.b;
        prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list e0_in
 permit tcp ::a01:100/120 host ::a02:253 eq 22
 deny ipv6 any any
--
ipv6 access-list v1_in
 deny ipv6 any any
--
ipv6 access-list v2_in
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any any
--ipv6/r2
ipv6 access-list e0_in
 deny ipv6 any any
--
ipv6 access-list v1_in
 deny ipv6 any any
--
ipv6 access-list v2_in
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Implicit pathrestriction with 3 virtual interfaces
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120;}
network:x = { ip = ::a03:300/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:101; hardware = E1;}
 interface:x = {ip = ::a03:301; hardware = E3;}
 interface:b = {ip = ::a02:201; virtual = {ip = ::a02:209;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:102; hardware = E4;}
 interface:b = {ip = ::a02:202; virtual = {ip = ::a02:209;} hardware = E5;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:103; hardware = E6;}
 interface:b = {ip = ::a02:203; virtual = {ip = ::a02:209;} hardware = E7;}
}
network:b  = { ip = ::a02:200/120; }
service:test = {
 user = network:a;
 permit src = user; dst = network:x, network:b; prt = ip;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list E1_in
 deny ipv6 any host ::a03:301
 deny ipv6 any host ::a02:209
 deny ipv6 any host ::a02:201
 permit ipv6 ::a01:100/120 ::a03:300/120
 permit ipv6 ::a01:100/120 ::a02:200/120
 deny ipv6 any any
--ipv6/r2
ipv6 access-list E4_in
 deny ipv6 any host ::a02:209
 deny ipv6 any host ::a02:202
 permit ipv6 ::a01:100/120 ::a02:200/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Different paths to virtual interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
network:n6 = { ip = ::a01:600/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; virtual = { ip = ::a01:101; } }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:103; hardware = n1; virtual = { ip = ::a01:101; } }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n3 = { ip = ::a01:303; hardware = n3; }
 interface:n4 = { ip = ::a01:403; hardware = n4; }
 interface:n5 = { ip = ::a01:503; hardware = n5; }
}
router:r4 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip = ::a01:204; hardware = n2; }
 interface:n4 = { ip = ::a01:404; hardware = n4; }
 interface:n6 = { ip = ::a01:604; hardware = n6; virtual = { ip = ::a01:601; } }
}
router:r5 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n5 = { ip = ::a01:505; hardware = n5; }
 interface:n6 = { ip = ::a01:605; hardware = n6; virtual = { ip = ::a01:601; } }
}
service:s = {
 user = network:n1;
 permit src = user; dst = interface:r4.n6.virtual; prt = udp 123;
}
=OUTPUT=
--ipv6/r4
ipv6 access-list n2_in
 permit udp ::a01:100/120 host ::a01:601 eq 123
 deny ipv6 any any
--
ipv6 access-list n4_in
 permit udp ::a01:100/120 host ::a01:601 eq 123
 deny ipv6 any any
--ipv6/r5
ipv6 access-list n5_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Extra pathrestriction at 2 virtual interface
=PARAMS=--ipv6
=INPUT=
network:u = { ip = ::a09:900/120; }
router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = ::a09:901; hardware = F0;}
 interface:a = {ip = ::a01:109; hardware = F1;}
}
network:a = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:101; hardware = E1;}
 interface:b = {ip = ::a02:201; virtual = {ip = ::a02:209;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:102; hardware = E4;}
 interface:b = {ip = ::a02:202; virtual = {ip = ::a02:209;} hardware = E5;}
}
network:b  = { ip = ::a02:200/120; }
pathrestriction:p = interface:r1.a, interface:r1.b.virtual;
service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
}
=END=
=OUTPUT=
--ipv6/g
ipv6 route ::a02:200/120 ::a01:102
--ipv6/r1
ipv6 access-list E1_in
 deny ipv6 any any
--ipv6/r2
ipv6 access-list E4_in
 deny ipv6 any host ::a02:209
 deny ipv6 any host ::a02:202
 permit ipv6 ::a09:900/120 ::a02:200/120
 deny ipv6 any any
=END=

############################################################
=TITLE=
Conceal invalid extra pathrestriction if routing is not required - no router
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120;}
network:b = { ip = ::a02:200/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:101;
               virtual = {ip = ::a01:109; type = HSRP;} hardware = E1;}
 interface:b = {ip = ::a02:201; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:102;
               virtual = {ip = ::a01:109; type = HSRP;} hardware = E4;}
 interface:b = {ip = ::a02:202; hardware = E5;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:103;
               virtual = {ip = ::a01:109; type = HSRP;} hardware = E6;}
 interface:b = {ip = ::a02:203; hardware = E7;}
}
pathrestriction:p =
 interface:r1.a.virtual,
 interface:r1.b
;
service:test = {
 user = network:a;
 permit src = user;
        dst = network:b;
        prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list E1_in
 permit udp ::a01:100/120 host ::e000:2 eq 1985
 deny ipv6 any any
--ipv6/r2
ipv6 access-list E4_in
 permit udp ::a01:100/120 host ::e000:2 eq 1985
 deny ipv6 any host ::a02:202
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 deny ipv6 any any
--ipv6/r3
ipv6 access-list E6_in
 permit udp ::a01:100/120 host ::e000:2 eq 1985
 deny ipv6 any host ::a02:203
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Non matching virtual interface groups with interconnect
=TEMPL=topo
network:a = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:101; virtual = {ip = ::a01:109;} hardware = E1;}
 interface:b1 = {ip = ::a02:201; virtual = {ip = ::a02:209;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:102; virtual = {ip = ::a01:109;} hardware = E4;}
 interface:b1 = {ip = ::a02:202; virtual = {ip = ::a02:209;} hardware = E5;}
 interface:t = { ip = ::a00:1; hardware = t1; }
}
network:t = { ip = ::a00:0/126; }
router:r3 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = ::a00:2; hardware = t1; }
 interface:a = {ip = ::a01:103; virtual = {ip = ::a01:109;} hardware = E6;}
 interface:b2 = {ip = ::a03:303; virtual = {ip = ::a03:309;} hardware = E7;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:104; virtual = {ip = ::a01:109;} hardware = E8;}
 interface:b2 = {ip = ::a03:304; virtual = {ip = ::a03:309;} hardware = E9;}
}
network:b1 = { ip = ::a02:200/120; }
network:b2 = { ip = ::a03:300/120; }
=END=
=PARAMS=--ipv6
=INPUT=
[[topo]]
router:g = {
 managed;
 model = ASA;
 interface:a = {ip = ::a01:107; hardware = inside;}
}
service:test1 = {
 user = interface:g.a;
 permit src = user; dst = network:b1; prt = tcp 80;
}
service:test2 = {
 user = interface:g.a;
 permit src = user; dst = network:b2; prt = tcp 80;
}
=END=
=ERROR=
Error: Pathrestriction ambiguously affects generation of static routes
       to interfaces with virtual IP ::a01:109:
 network:b1 is reached via
 - interface:r1.a.virtual
 - interface:r2.a.virtual
 - interface:r3.a.virtual
 But 1 interface(s) of group are missing.
 Remaining paths must traverse
 - all interfaces or
 - exactly one interface
 of this group.
Error: Pathrestriction ambiguously affects generation of static routes
       to interfaces with virtual IP ::a01:109:
 network:b2 is reached via
 - interface:r2.a.virtual
 - interface:r3.a.virtual
 - interface:r4.a.virtual
 But 1 interface(s) of group are missing.
 Remaining paths must traverse
 - all interfaces or
 - exactly one interface
 of this group.
=END=

############################################################
=TITLE=
Conceal non matching virtual interface groups with interconnect if no routing required
=PARAMS=--ipv6
=INPUT=
[[topo]]

service:test1 = {
 user = network:a;
 permit src = user; dst = network:b1; prt = tcp 80;
}
service:test2 = {
 user = network:a;
 permit src = user; dst = network:b2; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list E1_in
 deny ipv6 any host ::a02:209
 deny ipv6 any host ::a02:201
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 deny ipv6 any any
--ipv6/r2
! [ Routing ]
ipv6 route ::a01:100/120 ::a00:2
ipv6 route ::a03:300/120 ::a00:2
--ipv6/r2
ipv6 access-list E4_in
 deny ipv6 any host ::a02:209
 deny ipv6 any host ::a02:202
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 permit tcp ::a01:100/120 ::a03:300/120 eq 80
 deny ipv6 any any
--ipv6/r3
! [ Routing ]
ipv6 route ::a01:100/120 ::a00:1
ipv6 route ::a02:200/120 ::a00:1
--ipv6/r4
ipv6 access-list E8_in
 deny ipv6 any host ::a03:309
 deny ipv6 any host ::a03:304
 permit tcp ::a01:100/120 ::a03:300/120 eq 80
 deny ipv6 any any
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Follow implicit pathrestriction at unmanaged virtual interface
# Doppelte ACL-Zeile für virtuelle IP vermeiden an
# - Crosslink-Interface zu unmanaged Gerät
# - mit virtueller IP auch an dem unmanged Gerät
=PARAMS=--ipv6
=INPUT=
network:M = { ip = ::a01:0/120;}
router:F = {
 managed;
 model = ASA;
 interface:M = {ip = ::a01:1; hardware = inside;}
 interface:A = {ip = ::a02:181; hardware = o1; routing = dynamic;}
 interface:B = {ip = ::a02:112; hardware = o2; routing = dynamic;}
}
network:A = {ip = ::a02:180/126;}
router:Z = {
 interface:A = {ip = ::a02:182;}
 interface:c = {ip = ::a02:6a6;}
 interface:K = {ip = ::a09:2003; virtual = {ip = ::a09:2001;}}
}
network:B = {ip = ::a02:110/126;}
router:L = {
 managed;
 model = IOS;
 interface:B = {ip = ::a02:111; hardware = Ethernet1;
                no_in_acl; routing = dynamic;}
 interface:c  = {ip = ::a02:6a5; hardware = Ethernet2;}
 interface:K = {ip = ::a09:2002; virtual = {ip = ::a09:2001;}
                hardware = Ethernet0;}
}
network:c  = {ip = ::a02:6a4/126;}
network:K = { ip = ::a09:2000/117;}
pathrestriction:4 = interface:Z.A, interface:L.B;
service:x = {
 user = interface:L.K.virtual, interface:Z.K.virtual;
 permit src = network:M; dst = user; prt = icmpv6 17;
}
=END=
=OUTPUT=
--ipv6/L
ipv6 access-list Ethernet2_in
 permit icmp ::a01:0/120 host ::a09:2001 17
 deny ipv6 any any
--
ipv6 access-list Ethernet2_out
 permit icmp ::a01:0/120 host ::a09:2001 17
 deny ipv6 any any
--
ipv6 access-list Ethernet0_in
 deny ipv6 any any
--
ipv6 access-list Ethernet0_out
 deny ipv6 any any
=END=

############################################################
=TITLE=3 virtual interfaces with valid extra pathrestriction
=TEMPL=input
network:a = { ip = ::a01:100/120;}
network:b = { ip = ::a02:200/120;}
network:c = { ip = ::a03:300/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:101; hardware = E1;}
 interface:b = {ip = ::a02:201; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:202; virtual = {ip = ::a02:209;} hardware = E4;}
 interface:c = {ip = ::a03:301; hardware = E5;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:203; virtual = {ip = ::a02:209;} hardware = E6;}
 interface:c = {ip = ::a03:302; hardware = E7;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:204; virtual = {ip = ::a02:209;} hardware = E6;}
 interface:c = {ip = ::a03:303; hardware = E7;}
}
service:test = {
 user = network:a;
 permit src = user;
        dst = network:c;
        prt = tcp 80;
}
=END=
=TEMPL=router5
router:r5 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:102; hardware = E8;}
 interface:b = {ip = ::a02:205; hardware = E9;}
}
=END=
=PARAMS=--ipv6
=INPUT=
[[input]]
[[router5]]
pathrestriction:p =
 interface:r1.b,
 interface:r2.b.virtual,
 interface:r3.b.virtual,
 interface:r4.b.virtual
;
=OUTPUT=
--ipv6/r5
ipv6 route ::a03:300/120 ::a02:209
--ipv6/r1
ipv6 access-list E1_in
 deny ipv6 any any
=END=

############################################################
=TITLE=3 virtual interfaces with extra pathrestriction allowing 2 routes
=PARAMS=--ipv6
=INPUT=
[[input]]
[[router5]]
pathrestriction:p =
 interface:r1.b,
 interface:r2.b.virtual,
 interface:r3.b.virtual,
;
=ERROR=
Error: Ambiguous static routes for network:a at interface:r4.b.virtual via
 - interface:r1.b
 - interface:r5.b
=END=

############################################################
=TITLE=3 virtual interfaces with extra pathrestriction valid for all-1
=PARAMS=--ipv6
=INPUT=
[[input]]
pathrestriction:p =
 interface:r1.b,
 interface:r2.b.virtual,
 interface:r3.b.virtual,
;
=OUTPUT=
--ipv6/r1
ipv6 route ::a03:300/120 ::a02:204
=END=

############################################################
=TITLE=3 virtual interfaces with invalid extra pathrestriction
=PARAMS=--ipv6
=INPUT=
[[input]]
pathrestriction:p =
 interface:r1.b,
 interface:r2.b.virtual,
;
# es wäre schick, wenn man hier den Namen der PR hätte!
=ERROR=
Error: Pathrestriction ambiguously affects generation of static routes
       to interfaces with virtual IP ::a02:209:
 network:c is reached via
 - interface:r3.b.virtual
 - interface:r4.b.virtual
 But 1 interface(s) of group are missing.
 Remaining paths must traverse
 - all interfaces or
 - exactly one interface
 of this group.
=END=

############################################################
=TITLE=
3 virtual interfaces, dst network directly connected to 1 only -
extra pathrestriction causing routing via physical interface
=TEMPL=input
network:a = { ip = ::a01:100/120;}
network:b = { ip = ::a02:200/120;}
network:c = { ip = ::a03:300/120;}
network:x = { ip = ::a04:400/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = ::a01:101; hardware = E1;}
 interface:b = {ip = ::a02:201; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:202; virtual = {ip = ::a02:209;} hardware = E4;}
 interface:c = {ip = ::a03:301; hardware = E5;}
 interface:x = {ip = ::a04:401; hardware = E6;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:203; virtual = {ip = ::a02:209;} hardware = E7;}
 interface:c = {ip = ::a03:302; hardware = E8;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:204; virtual = {ip = ::a02:209;} hardware = E9;}
 interface:c = {ip = ::a03:303; hardware = E10;}
}
pathrestriction:p =
 interface:r2.c,
 {{.}}
 interface:r4.c
;
service:test = {
 user = network:a;
 permit src = user;
        dst = network:x;
        prt = tcp 80;
}
=END=
=PARAMS=--ipv6
=INPUT=[[input "interface:r3.c,"]]
=OUTPUT=
--ipv6/r1
ipv6 route ::a04:400/120 ::a02:202
=END=

############################################################
=TITLE=
3 virtual interfaces, dst network directly connected to 1 only -
invalid extra pathrestriction
=PARAMS=--ipv6
=INPUT=[[input ""]]
=ERROR=
Error: Pathrestriction ambiguously affects generation of static routes
       to interfaces with virtual IP ::a02:209:
 network:x is reached via
 - interface:r2.b.virtual
 - interface:r3.b.virtual
 But 1 interface(s) of group are missing.
 Remaining paths must traverse
 - all interfaces or
 - exactly one interface
 of this group.
Error: Two static routes for network:a
 via interface:r2.c and interface:r2.b.virtual
=END=

############################################################
=TITLE=
Conceal invalid extra pathrestriction if routing is not required - no service
=TEMPL=input
network:a = { ip = ::a01:100/120;}
network:b = { ip = ::a02:200/120;}
network:c = { ip = ::a03:300/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:a = {ip = ::a01:101; hardware = E1;}
 interface:b = {ip = ::a02:201; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:202; virtual = {ip = ::a02:209;} hardware = E3;}
 interface:c = {ip = ::a03:301; hardware = E4;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:203; virtual = {ip = ::a02:209;} hardware = E4;}
 interface:c = {ip = ::a03:302; hardware = E5;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = ::a02:204; virtual = {ip = ::a02:209;} hardware = E6;}
 interface:c = {ip = ::a03:303; hardware = E7;}
}
pathrestriction:p =
 interface:r1.b,
 interface:r3.c,
;
=END=
=PARAMS=--ipv6
=INPUT=[[input]]
=OUTPUT=
--ipv6/r2
ipv6 access-list E3_in
 deny ipv6 any any
--ipv6/r3
ipv6 access-list E4_in
 deny ipv6 any any
--ipv6/r4
ipv6 access-list E6_in
 deny ipv6 any any
=END=

############################################################
=TITLE=
Conceal invalid extra pathrestriction if routing is not required - manual routing
=PARAMS=--ipv6
=INPUT=
[[input]]
service:test = {
 user = network:a;
 permit src = user;
        dst = network:c;
        prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list E1_in
 permit tcp ::a01:100/120 ::a03:300/120 eq 80
 deny ipv6 any any
--ipv6/r2
ipv6 route ::a01:100/120 ::a02:201
--ipv6/r2
ipv6 access-list E3_in
 deny ipv6 any host ::a03:301
 permit tcp ::a01:100/120 ::a03:300/120 eq 80
 deny ipv6 any any
--ipv6/r3
ipv6 access-list E4_in
 deny ipv6 any any
--ipv6/r4
ipv6 route ::a01:100/120 ::a02:201
--ipv6/r4
ipv6 access-list E6_in
 deny ipv6 any host ::a03:303
 permit tcp ::a01:100/120 ::a03:300/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Find invalid pathrestrictions although next hop count equals size of redundancy group
=PARAMS=--ipv6
=INPUT=
network:n1 = {ip = ::a01:100/120;}
network:n2 = {ip = ::a02:200/120;}
network:n3 = {ip = ::a03:300/120;}
network:n4 = {ip = ::a04:400/120;}
network:n5 = {ip = ::a05:500/120;}
router:r1 = {
 managed;
 model=IOS;
 interface:n1 = {ip = ::a01:101;hardware = E1;}
 interface:n2 = {ip = ::a02:201;hardware = E2;}
}
router:r2 = {
 managed;
 model=IOS;
 interface:n2 = {ip = ::a02:202; virtual = {ip = ::a02:20a;} hardware = E1;}
 interface:n3 = {ip = ::a03:301; hardware = E2;}
 interface:n5 = {ip = ::a05:501; hardware = E3;}
}
router:r3 = {
 managed;
 model=IOS;
 interface:n2 = {ip = ::a02:203; virtual = {ip = ::a02:20a;} hardware = E1;}
 interface:n3 = {ip = ::a03:302; hardware = E2;}
}
router:r4 = {
 managed;
 model=IOS;
 interface:n2 = {ip = ::a02:204; virtual = {ip = ::a02:20a;} hardware = E1;}
 interface:n3 = {ip = ::a03:303; hardware = E2;}
}
router:r5 = {
 managed;
 model=IOS;
 interface:n2 = {ip = ::a02:205; virtual = {ip = ::a02:20b;} hardware = E1;}
 interface:n4 = {ip = ::a04:401; hardware = E2;}
}
router:r6 = {
 managed;
 model=IOS;
 interface:n2 = {ip = ::a02:206; virtual = {ip = ::a02:20b;} hardware = E1;}
 interface:n4 = {ip = ::a04:402; hardware = E2;}
}
router:r7 = {
 managed;
 model=IOS;
 interface:n2 = {ip = ::a02:207; virtual = {ip = ::a02:20b;} hardware = E1;}
 interface:n4 = {ip = ::a04:403; hardware = E2;}
 interface:n5 = {ip = ::a05:502; hardware = E3;}
}
pathrestriction:p1 =
 interface:r2.n5,
 interface:r4.n3;
pathrestriction:p2 =
 interface:r5.n4,
 interface:r6.n4,
 interface:r7.n4;
service:test1 = {
 user = network:n1;
 permit src = user;
        dst = network:n5;
        prt = tcp 80;
}
=END=
=ERROR=
Error: Ambiguous static routes for network:n5 at interface:r1.n2 via
 - interface:r2.n2.virtual
 - interface:r3.n2.virtual
 - interface:r7.n2.virtual
Error: Two static routes for network:n1
 via interface:r2.n3 and interface:r2.n2.virtual
=END=

############################################################
