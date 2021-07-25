
############################################################
=TITLE=Path between virtual interfaces
=INPUT=
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.83; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:b = {ip = 10.2.2.83; hardware = e1;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.84; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:b = {ip = 10.2.2.84; hardware = e1;}
}
network:b = { ip = 10.2.2.0/24;}
service:test = {
 user = interface:r1.a, interface:r2.a;
 permit src = user;
        dst = user;
        prt = tcp 22;
}
=END=
=OUTPUT=
--r1
ip access-list extended e0_in
 permit tcp host 10.1.1.84 host 10.1.1.83 eq 22
 permit tcp host 10.1.1.84 host 10.1.1.83 established
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
--r2
ip access-list extended e0_in
 permit tcp host 10.1.1.83 host 10.1.1.84 eq 22
 permit tcp host 10.1.1.83 host 10.1.1.84 established
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
=END=

############################################################
=TITLE=Multiple virtual interface pairs with interface as destination
=INPUT=
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.83; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:c1 = {ip = 10.3.1.2; virtual = {ip = 10.3.1.1;} hardware = v1;}
 interface:c2 = {ip = 10.3.2.2; virtual = {ip = 10.3.2.1;} hardware = v2;}
 interface:b = {ip = 10.2.2.83; virtual = {ip = 10.2.2.2;} hardware = e1;}
}
network:c1 = {ip = 10.3.1.0/24;}
network:c2 = {ip = 10.3.2.0/24;}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.84; virtual = {ip = 10.1.1.2;} hardware = e0;}
 interface:c1 = {ip = 10.3.1.3; virtual = {ip = 10.3.1.1;} hardware = v1;}
 interface:c2 = {ip = 10.3.2.3; virtual = {ip = 10.3.2.1;} hardware = v2;}
 interface:b = {ip = 10.2.2.84; virtual = {ip = 10.2.2.2;} hardware = e1;}
}
network:b = { ip = 10.2.2.0/24;}
service:test = {
 user = network:a;
 permit src = user;
        dst = interface:r1.b;
        prt = tcp 22;
}
=END=
=OUTPUT=
--r1
ip access-list extended e0_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.83 eq 22
 deny ip any any
--
ip access-list extended v1_in
 deny ip any any
--
ip access-list extended v2_in
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
--r2
ip access-list extended e0_in
 deny ip any any
--
ip access-list extended v1_in
 deny ip any any
--
ip access-list extended v2_in
 deny ip any any
--
ip access-list extended e1_in
 deny ip any any
=END=

############################################################
=TITLE=Implicit pathrestriction with 3 virtual interfaces
=INPUT=
network:a = { ip = 10.1.1.0/24;}
network:x = { ip = 10.3.3.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:x = {ip = 10.3.3.1; hardware = E3;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.3; hardware = E6;}
 interface:b = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E7;}
}
network:b  = { ip = 10.2.2.0/24; }
service:test = {
 user = network:a;
 permit src = user; dst = network:x, network:b; prt = ip;
}
=END=
=OUTPUT=
--r1
ip access-list extended E1_in
 deny ip any host 10.3.3.1
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.1
 permit ip 10.1.1.0 0.0.0.255 10.3.3.0 0.0.0.255
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
--r2
ip access-list extended E4_in
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.2
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Different paths to virtual interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; virtual = { ip = 10.1.1.1; } }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; virtual = { ip = 10.1.1.1; } }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
 interface:n5 = { ip = 10.1.5.3; hardware = n5; }
}
router:r4 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip = 10.1.2.4; hardware = n2; }
 interface:n4 = { ip = 10.1.4.4; hardware = n4; }
 interface:n6 = { ip = 10.1.6.4; hardware = n6; virtual = { ip = 10.1.6.1; } }
}
router:r5 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n5 = { ip = 10.1.5.5; hardware = n5; }
 interface:n6 = { ip = 10.1.6.5; hardware = n6; virtual = { ip = 10.1.6.1; } }
}
service:s = {
 user = network:n1;
 permit src = user; dst = interface:r4.n6.virtual; prt = udp 123;
}
=OUTPUT=
--r4
ip access-list extended n2_in
 permit udp 10.1.1.0 0.0.0.255 host 10.1.6.1 eq 123
 deny ip any any
--
ip access-list extended n4_in
 permit udp 10.1.1.0 0.0.0.255 host 10.1.6.1 eq 123
 deny ip any any
--r5
ip access-list extended n5_in
 deny ip any any
=END=

############################################################
=TITLE=Extra pathrestriction at 2 virtual interface
=INPUT=
network:u = { ip = 10.9.9.0/24; }
router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = 10.9.9.1; hardware = F0;}
 interface:a = {ip = 10.1.1.9; hardware = F1;}
}
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}
network:b  = { ip = 10.2.2.0/24; }
pathrestriction:p = interface:r1.a, interface:r1.b.virtual;
service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
}
=END=
=OUTPUT=
--g
ip route 10.2.2.0 255.255.255.0 10.1.1.2
--r1
ip access-list extended E1_in
 deny ip any any
--r2
ip access-list extended E4_in
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.2
 permit ip 10.9.9.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=
Conceal invalid extra pathrestriction if routing is not required - no router
=INPUT=
network:a = { ip = 10.1.1.0/24;}
network:b = { ip = 10.2.2.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1;
               virtual = {ip = 10.1.1.9; type = HSRP;} hardware = E1;}
 interface:b = {ip = 10.2.2.1; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2;
               virtual = {ip = 10.1.1.9; type = HSRP;} hardware = E4;}
 interface:b = {ip = 10.2.2.2; hardware = E5;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.3;
               virtual = {ip = 10.1.1.9; type = HSRP;} hardware = E6;}
 interface:b = {ip = 10.2.2.3; hardware = E7;}
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
--r1
ip access-list extended E1_in
 permit udp 10.1.1.0 0.0.0.255 host 224.0.0.2 eq 1985
 deny ip any any
--r2
ip access-list extended E4_in
 permit udp 10.1.1.0 0.0.0.255 host 224.0.0.2 eq 1985
 deny ip any host 10.2.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
--r3
ip access-list extended E6_in
 permit udp 10.1.1.0 0.0.0.255 host 224.0.0.2 eq 1985
 deny ip any host 10.2.2.3
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Non matching virtual interface groups with interconnect
=VAR=topo
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; virtual = {ip = 10.1.1.9;} hardware = E1;}
 interface:b1 = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; virtual = {ip = 10.1.1.9;} hardware = E4;}
 interface:b1 = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
 interface:t = { ip = 10.0.0.1; hardware = t1; }
}
network:t = { ip = 10.0.0.0/30; }
router:r3 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = 10.0.0.2; hardware = t1; }
 interface:a = {ip = 10.1.1.3; virtual = {ip = 10.1.1.9;} hardware = E6;}
 interface:b2 = {ip = 10.3.3.3; virtual = {ip = 10.3.3.9;} hardware = E7;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.4; virtual = {ip = 10.1.1.9;} hardware = E8;}
 interface:b2 = {ip = 10.3.3.4; virtual = {ip = 10.3.3.9;} hardware = E9;}
}
network:b1 = { ip = 10.2.2.0/24; }
network:b2 = { ip = 10.3.3.0/24; }
=END=
=INPUT=
${topo}
router:g = {
 managed;
 model = ASA;
 interface:a = {ip = 10.1.1.7; hardware = inside;}
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
       to interfaces with virtual IP 10.1.1.9:
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
       to interfaces with virtual IP 10.1.1.9:
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
=TITLE=Non matching virtual interface groups
=INPUT=${topo}
=SUBST=/hardware = t1;/hardware = t1; disabled;/
=ERROR=
Error: Virtual interfaces
 - interface:r1.a.virtual
 - interface:r2.a.virtual
 - interface:r3.a.virtual
 - interface:r4.a.virtual
 must all be part of the same cyclic sub-graph
=END=

############################################################
=TITLE=
Conceal non matching virtual interface groups with interconnect if no routing required
=INPUT=
${topo}

service:test1 = {
 user = network:a;
 permit src = user; dst = network:b1; prt = tcp 80;
}
service:test2 = {
 user = network:a;
 permit src = user; dst = network:b2; prt = tcp 80;
}
=OUTPUT=
--r1
ip access-list extended E1_in
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
--r2
! [ Routing ]
ip route 10.1.1.0 255.255.255.0 10.0.0.2
ip route 10.3.3.0 255.255.255.0 10.0.0.2
--r2
ip access-list extended E4_in
 deny ip any host 10.2.2.9
 deny ip any host 10.2.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.3.3.0 0.0.0.255 eq 80
 deny ip any any
--r3
! [ Routing ]
ip route 10.1.1.0 255.255.255.0 10.0.0.1
ip route 10.2.2.0 255.255.255.0 10.0.0.1
--r4
ip access-list extended E8_in
 deny ip any host 10.3.3.9
 deny ip any host 10.3.3.4
 permit tcp 10.1.1.0 0.0.0.255 10.3.3.0 0.0.0.255 eq 80
 deny ip any any
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Follow implicit pathrestriction at unmanaged virtual interface
# Doppelte ACL-Zeile für virtuelle IP vermeiden an
# - Crosslink-Interface zu unmanaged Gerät
# - mit virtueller IP auch an dem unmanged Gerät
=INPUT=
network:M = { ip = 10.1.0.0/24;}
router:F = {
 managed;
 model = ASA;
 interface:M = {ip = 10.1.0.1; hardware = inside;}
 interface:A = {ip = 10.2.1.129; hardware = o1; routing = dynamic;}
 interface:B = {ip = 10.2.1.18; hardware = o2; routing = dynamic;}
}
network:A = {ip = 10.2.1.128/30;}
router:Z = {
 interface:A = {ip = 10.2.1.130;}
 interface:c = {ip = 10.2.6.166;}
 interface:K = {ip = 10.9.32.3; virtual = {ip = 10.9.32.1;}}
}
network:B = {ip = 10.2.1.16/30;}
router:L = {
 managed;
 model = IOS;
 interface:B = {ip = 10.2.1.17; hardware = Ethernet1;
                no_in_acl; routing = dynamic;}
 interface:c  = {ip = 10.2.6.165; hardware = Ethernet2;}
 interface:K = {ip = 10.9.32.2; virtual = {ip = 10.9.32.1;}
                hardware = Ethernet0;}
}
network:c  = {ip = 10.2.6.164/30;}
network:K = { ip = 10.9.32.0/21;}
pathrestriction:4 = interface:Z.A, interface:L.B;
service:x = {
 user = interface:L.K.virtual, interface:Z.K.virtual;
 permit src = network:M; dst = user; prt = icmp 17;
}
=END=
=OUTPUT=
--L
ip access-list extended Ethernet2_in
 permit icmp 10.1.0.0 0.0.0.255 host 10.9.32.1 17
 deny ip any any
--
ip access-list extended Ethernet2_out
 permit icmp 10.1.0.0 0.0.0.255 host 10.9.32.1 17
 deny ip any any
--
ip access-list extended Ethernet0_in
 deny ip any any
--
ip access-list extended Ethernet0_out
 deny ip any any
=END=

############################################################
=TITLE=3 virtual interfaces with valid extra pathrestriction
=VAR=input
network:a = { ip = 10.1.1.0/24;}
network:b = { ip = 10.2.2.0/24;}
network:c = { ip = 10.3.3.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E4;}
 interface:c = {ip = 10.3.3.1; hardware = E5;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E6;}
 interface:c = {ip = 10.3.3.2; hardware = E7;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.4; virtual = {ip = 10.2.2.9;} hardware = E6;}
 interface:c = {ip = 10.3.3.3; hardware = E7;}
}
service:test = {
 user = network:a;
 permit src = user;
        dst = network:c;
        prt = tcp 80;
}
=END=
=VAR=router5
router:r5 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E8;}
 interface:b = {ip = 10.2.2.5; hardware = E9;}
}
=END=
=INPUT=
${input}
${router5}
pathrestriction:p =
 interface:r1.b,
 interface:r2.b.virtual,
 interface:r3.b.virtual,
 interface:r4.b.virtual
;
=OUTPUT=
--r5
ip route 10.3.3.0 255.255.255.0 10.2.2.9
--r1
ip access-list extended E1_in
 deny ip any any
=END=

############################################################
=TITLE=3 virtual interfaces with extra pathrestriction allowing 2 routes
=INPUT=
${input}
${router5}
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
=INPUT=
${input}
pathrestriction:p =
 interface:r1.b,
 interface:r2.b.virtual,
 interface:r3.b.virtual,
;
=OUTPUT=
--r1
ip route 10.3.3.0 255.255.255.0 10.2.2.4
=END=

############################################################
=TITLE=3 virtual interfaces with invalid extra pathrestriction
=INPUT=
${input}
pathrestriction:p =
 interface:r1.b,
 interface:r2.b.virtual,
;
# es wäre schick, wenn man hier den Namen der PR hätte!
=ERROR=
Error: Pathrestriction ambiguously affects generation of static routes
       to interfaces with virtual IP 10.2.2.9:
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
=VAR=input
network:a = { ip = 10.1.1.0/24;}
network:b = { ip = 10.2.2.0/24;}
network:c = { ip = 10.3.3.0/24;}
network:x = { ip = 10.4.4.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E4;}
 interface:c = {ip = 10.3.3.1; hardware = E5;}
 interface:x = {ip = 10.4.4.1; hardware = E6;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E7;}
 interface:c = {ip = 10.3.3.2; hardware = E8;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.4; virtual = {ip = 10.2.2.9;} hardware = E9;}
 interface:c = {ip = 10.3.3.3; hardware = E10;}
}
pathrestriction:p =
 interface:r2.c,
 interface:r3.c,
 interface:r4.c
;
service:test = {
 user = network:a;
 permit src = user;
        dst = network:x;
        prt = tcp 80;
}
=END=
=INPUT=${input}
=OUTPUT=
--r1
ip route 10.4.4.0 255.255.255.0 10.2.2.2
=END=

############################################################
=TITLE=
3 virtual interfaces, dst network directly connected to 1 only -
invalid extra pathrestriction
=INPUT=${input}
=SUBST=/interface:r3.c,//
=ERROR=
Error: Pathrestriction ambiguously affects generation of static routes
       to interfaces with virtual IP 10.2.2.9:
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
=VAR=input
network:a = { ip = 10.1.1.0/24;}
network:b = { ip = 10.2.2.0/24;}
network:c = { ip = 10.3.3.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E3;}
 interface:c = {ip = 10.3.3.1; hardware = E4;}
}
router:r3 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E4;}
 interface:c = {ip = 10.3.3.2; hardware = E5;}
}
router:r4 = {
 managed;
 model = IOS, FW;
 interface:b = {ip = 10.2.2.4; virtual = {ip = 10.2.2.9;} hardware = E6;}
 interface:c = {ip = 10.3.3.3; hardware = E7;}
}
pathrestriction:p =
 interface:r1.b,
 interface:r3.c,
;
=END=
=INPUT=${input}
=OUTPUT=
--r2
ip access-list extended E3_in
 deny ip any any
--r3
ip access-list extended E4_in
 deny ip any any
--r4
ip access-list extended E6_in
 deny ip any any
=END=

############################################################
=TITLE=
Conceal invalid extra pathrestriction if routing is not required - manual routing
=INPUT=
${input}
service:test = {
 user = network:a;
 permit src = user;
        dst = network:c;
        prt = tcp 80;
}
=END=
=OUTPUT=
--r1
ip access-list extended E1_in
 permit tcp 10.1.1.0 0.0.0.255 10.3.3.0 0.0.0.255 eq 80
 deny ip any any
--r2
ip route 10.1.1.0 255.255.255.0 10.2.2.1
--r2
ip access-list extended E3_in
 deny ip any host 10.3.3.1
 permit tcp 10.1.1.0 0.0.0.255 10.3.3.0 0.0.0.255 eq 80
 deny ip any any
--r3
ip access-list extended E4_in
 deny ip any any
--r4
ip route 10.1.1.0 255.255.255.0 10.2.2.1
--r4
ip access-list extended E6_in
 deny ip any host 10.3.3.3
 permit tcp 10.1.1.0 0.0.0.255 10.3.3.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Find invalid pathrestrictions although next hop count equals size of redundancy group
=INPUT=
network:n1 = {ip = 10.1.1.0/24;}
network:n2 = {ip = 10.2.2.0/24;}
network:n3 = {ip = 10.3.3.0/24;}
network:n4 = {ip = 10.4.4.0/24;}
network:n5 = {ip = 10.5.5.0/24;}
router:r1 = {
 managed;
 model=IOS;
 interface:n1 = {ip = 10.1.1.1;hardware = E1;}
 interface:n2 = {ip = 10.2.2.1;hardware = E2;}
}
router:r2 = {
 managed;
 model=IOS;
 interface:n2 = {ip = 10.2.2.2; virtual = {ip = 10.2.2.10;} hardware = E1;}
 interface:n3 = {ip = 10.3.3.1; hardware = E2;}
 interface:n5 = {ip = 10.5.5.1; hardware = E3;}
}
router:r3 = {
 managed;
 model=IOS;
 interface:n2 = {ip = 10.2.2.3; virtual = {ip = 10.2.2.10;} hardware = E1;}
 interface:n3 = {ip = 10.3.3.2; hardware = E2;}
}
router:r4 = {
 managed;
 model=IOS;
 interface:n2 = {ip = 10.2.2.4; virtual = {ip = 10.2.2.10;} hardware = E1;}
 interface:n3 = {ip = 10.3.3.3; hardware = E2;}
}
router:r5 = {
 managed;
 model=IOS;
 interface:n2 = {ip = 10.2.2.5; virtual = {ip = 10.2.2.11;} hardware = E1;}
 interface:n4 = {ip = 10.4.4.1; hardware = E2;}
}
router:r6 = {
 managed;
 model=IOS;
 interface:n2 = {ip = 10.2.2.6; virtual = {ip = 10.2.2.11;} hardware = E1;}
 interface:n4 = {ip = 10.4.4.2; hardware = E2;}
}
router:r7 = {
 managed;
 model=IOS;
 interface:n2 = {ip = 10.2.2.7; virtual = {ip = 10.2.2.11;} hardware = E1;}
 interface:n4 = {ip = 10.4.4.3; hardware = E2;}
 interface:n5 = {ip = 10.5.5.2; hardware = E3;}
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
