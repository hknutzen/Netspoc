
############################################################
=TITLE=Pathrestriction must only reference real interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = {
  ip = 10.1.1.1;
  secondary:s = { ip = 10.1.1.99; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
group:g1 =
 interface:r1.n1,
 network:n2,
 interface:r2.[auto],
 interface:r1.n1.s,
;
pathrestriction:p = network:n1, group:g1, interface:r2.n2;
=END=
=ERROR=
Error: pathrestriction:p must not reference network:n1
Error: pathrestriction:p must not reference network:n2
Error: pathrestriction:p must not reference interface:r2.[auto]
Error: pathrestriction:p must not reference secondary interface:r1.n1.s
=END=

############################################################
=TITLE=Pathrestriction with only 0 or 1 interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
group:g1 =;
pathrestriction:p1 = group:g1;
pathrestriction:p2 = interface:r1.n1;
=END=
=WARNING=
Warning: Ignoring pathrestriction:p1 without elements
Warning: Ignoring pathrestriction:p2 with only interface:r1.n1
=END=

############################################################
# Shared topology for multiple tests.

############################################################
=VAR=topo
network:top = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:top = { ip = 10.1.1.1; hardware = top; }
 interface:lft = { ip = 10.3.1.245; hardware = lft; }
 interface:dst = { ip = 10.1.2.1; hardware = dst; }
}
network:lft = { ip = 10.3.1.244/30;}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:top = { ip = 10.1.1.2; hardware = top; }
 interface:rgt = { ip = 10.3.1.129; hardware = rgt; }
 interface:dst = { ip = 10.1.2.2; hardware = dst; }
}
network:rgt = { ip = 10.3.1.128/30;}
network:dst = { ip = 10.1.2.0/24;}
=END=

############################################################
=TITLE=Simple duplicate pathrestriction
=INPUT=
${topo}
pathrestriction:top =
 interface:r1.top,
 interface:r2.top,
;
pathrestriction:dst =
 interface:r1.dst,
 interface:r2.dst,
;
service:test = {
 user = network:lft;
 permit src = user;
        dst = network:rgt;
        prt = tcp 80;
}
=END=
=ERROR=
Error: No valid path
 from any:[network:lft]
 to any:[network:rgt]
 for rule permit src=network:lft; dst=network:rgt; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Path starts at pathrestriction inside loop
=INPUT=
${topo}
pathrestriction:p =
 interface:r1.top,
 interface:r2.dst,
;
service:test = {
 user = interface:r1.top;
 permit src = user;
        dst = network:rgt;
        prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended top_in
 permit tcp 10.3.1.128 0.0.0.3 host 10.1.1.1 established
 deny ip any any
--
ip access-list extended lft_in
 deny ip any any
--
ip access-list extended dst_in
 deny ip any any
-- r2
ip access-list extended top_in
 deny ip any host 10.3.1.129
 permit tcp host 10.1.1.1 10.3.1.128 0.0.0.3 eq 80
 deny ip any any
--
ip access-list extended rgt_in
 deny ip any any
--
ip access-list extended dst_in
 deny ip any any
=END=

############################################################
=TITLE=Path starts at pathrestriction inside loop (2)
# Must not use path r1.top-r1-r2-top
=INPUT=
${topo}
pathrestriction:p =
 interface:r1.top,
 interface:r2.top,
;
service:test = {
 user = interface:r1.top;
 permit src = user;
        dst = network:dst, network:top;
        prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended top_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.1.1 established
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.1 established
 deny ip any any
--
ip access-list extended lft_in
 deny ip any any
--
ip access-list extended dst_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.1.1 established
 deny ip any any
-- r2
ip access-list extended top_in
 deny ip any host 10.1.2.2
 permit tcp host 10.1.1.1 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended rgt_in
 deny ip any any
--
ip access-list extended dst_in
 deny ip any any
=END=

############################################################
=TITLE=Path starts at pathrestriction inside loop (3)
=INPUT=
${topo}
pathrestriction:p1 =
 interface:r1.top,
 interface:r1.dst,
 interface:r2.top,
;
service:test = {
 user = interface:r1.dst;
 permit src = user;
        dst = network:top;
        prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended top_in
 deny ip any any
--
ip access-list extended dst_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.1 established
 deny ip any any
-- r2
ip access-list extended dst_in
 deny ip any host 10.1.1.2
 permit tcp host 10.1.2.1 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Path ends at pathrestriction inside loop
# Must detect identical path restriction,
# when temporary moving pathrestriction of r1.dst to r1.top.
=INPUT=
${topo}
pathrestriction:p =
 interface:r1.top,
 interface:r1.dst,
;
service:test = {
 user = network:top;
 permit src = user;
        dst = interface:r1.dst;
        prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended top_in
 deny ip any any
--
ip access-list extended dst_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.1 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Path ends at pathrestriction inside loop (2)
=INPUT=
${topo}
pathrestriction:p1 =
 interface:r1.top,
 interface:r1.dst,
;
pathrestriction:p2 =
 interface:r1.dst,
 interface:r1.lft,
;
service:test = {
 user = network:top;
 permit src = user;
        dst = interface:r1.lft;
        prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended top_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.3.1.245 eq 80
 deny ip any any
--
ip access-list extended dst_in
 deny ip any any
=END=

############################################################
=TITLE=Path ends at interface inside network, where path starts
# Must not enter r1 from network dst, even for optimized pathrestriction.
=INPUT=
${topo}
pathrestriction:p =
 interface:r1.top,
 interface:r2.top,
;
service:test = {
 user = network:top;
 permit src = user;
        dst = interface:r1.top;
        prt = tcp 179;
}
=END=
=OUTPUT=
-- r1
ip access-list extended top_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.1.1 eq 179
 deny ip any any
--
ip access-list extended dst_in
 deny ip any any
=END=

############################################################
=TITLE=Path starts at pathrestriction inside loop (4)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2 = {
 managed = secondary;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; routing = dynamic; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; routing = OSPF;}
 interface:n4 = { ip = 10.1.4.2; hardware = n4; virtual = { ip = 10.1.4.1; type = HSRP; } }
}
router:r3 = {
 interface:n2;
 interface:n3;
 interface:n4 = { ip = 10.1.4.3; virtual = { ip = 10.1.4.1; type = HSRP; } }
}
service:s1 = {
 user = foreach interface:r2.[all];
 permit src = any:[user]; dst = user; prt = icmp 8;
}
=END=
=OUTPUT=
-- r2
ip access-list extended n1_in
 permit icmp any host 10.1.1.1 8
 permit icmp any host 10.1.3.1 8
 permit icmp any host 10.1.4.1 8
 permit icmp any host 10.1.4.2 8
 deny ip any host 10.1.1.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 deny ip any host 10.1.4.2
 permit ip any any
--
ip access-list extended n3_in
 permit icmp any host 10.1.1.1 8
 permit icmp any host 10.1.3.1 8
 permit icmp any host 10.1.4.1 8
 permit icmp any host 10.1.4.2 8
 permit 89 10.1.3.0 0.0.0.255 host 224.0.0.5
 permit 89 10.1.3.0 0.0.0.255 host 224.0.0.6
 permit 89 10.1.3.0 0.0.0.255 10.1.3.0 0.0.0.255
 deny ip any any
--
ip access-list extended n3_out
 deny ip any any
--
ip access-list extended n4_in
 permit icmp any host 10.1.1.1 8
 permit icmp any host 10.1.3.1 8
 permit icmp any host 10.1.4.1 8
 permit icmp any host 10.1.4.2 8
 permit udp 10.1.4.0 0.0.0.255 host 224.0.0.2 eq 1985
 deny ip any any
--
ip access-list extended n4_out
 deny ip any any
=END=

############################################################
=TITLE=Pathrestriction located in different loops
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2a = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:r2b = {
 model = IOS;
 managed;
 routing = manual;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
pathrestriction:p1 =
 interface:r2a.n2,
 interface:r2b.n3,
;
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = udp 123;
}
=END=
=WARNING=
Warning: Ignoring pathrestriction:p1 having elements from different loops:
 - interface:r2a.n2
 - interface:r2b.n3
=END=

############################################################
=TITLE=Pathrestriction located in different loops (2)
# Ignored pathrestriction must be fully disabled internally.
# Otherwise we got a non terminating program.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r3 = {
 interface:n2;
 interface:n3;
 interface:n5;
}
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r4 = {
 model = Linux;
 managed;
 routing = manual;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; }
 interface:n7 = { ip = 10.1.7.1; hardware = n7; }
}
network:n6 = { ip = 10.1.6.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
router:r5 = {
 interface:n6;
 interface:n7;
}
pathrestriction:p =
 interface:r4.n6,
 interface:r3.n5,
;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n5; prt = udp 500;
}
=END=
=WARNING=
Warning: Ignoring pathrestriction:p having elements from different loops:
 - interface:r4.n6
 - interface:r3.n5
=END=

############################################################
=TITLE=Pathrestriction at non-loop node
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 model = IOS;
 managed;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
pathrestriction:p1 =
 interface:r1.n2,
 interface:r3.n3,
;
=END=
=WARNING=
Warning: Ignoring pathrestriction:p1 at interface:r3.n3
 because it isn't located inside cyclic graph
=END=

############################################################
=TITLE=Pathrestriction at internally split router outside of loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
# r2 is split internally into two parts
# r2 with n3, n4
# r2' with n2
# both connected internally by unnumbered network.
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
 interface:n4;
}
# Pathrestriction is ignored outside of cyclic graph.
# Internally, pathrestriction is removed from both interfaces,
# to prevent further errors.
# We must get the rigth interface, while it is moved from r2 to r2'.
pathrestriction:p1 =
 interface:r1.n2,
 interface:r2.n2,
;
=END=
=WARNING=
Warning: Ignoring pathrestriction:p1 at interface:r1.n2
 because it isn't located inside cyclic graph
Warning: Ignoring pathrestriction:p1 at interface:r2.n2
 because it isn't located inside cyclic graph
=END=

############################################################
=TITLE=Pathrestricted destination in complex loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n3;
service:s = {
 user = network:n1;
 permit src = user; dst = interface:r1.n3; prt = tcp 22;
}
=END=
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any any
--
ip access-list extended n2_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.3.1 eq 22
 deny ip any any
--
ip access-list extended n3_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.3.1 eq 22
 deny ip any any
--r2
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.3.1 eq 22
 deny ip any any
--
ip access-list extended n2_in
 permit tcp host 10.1.3.1 10.1.1.0 0.0.0.255 established
 deny ip any any
--
ip access-list extended n3_in
 permit tcp host 10.1.3.1 10.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Pathrestricted source in complex loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n3;
pathrestriction:p2 = interface:r2.n1, interface:r2.n3;
service:s = {
 user = interface:r1.n1;
 permit src = user; dst = network:n3; prt = udp 123;
}
=END=
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any any
--
ip access-list extended n2_in
 permit udp 10.1.3.0 0.0.0.255 eq 123 host 10.1.1.1
 deny ip any any
--
ip access-list extended n3_in
 deny ip any any
--r2
ip access-list extended n1_in
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.3.2
 permit udp host 10.1.1.1 10.1.3.0 0.0.0.255 eq 123
 deny ip any any
--
ip access-list extended n3_in
 permit udp 10.1.3.0 0.0.0.255 eq 123 host 10.1.1.1
 deny ip any any
=END=

############################################################
=TITLE=Pathrestricted src and dst in complex loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r3 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.3; hardware = n3; virtual = { ip = 10.1.3.1; } }
}
router:r4 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip = 10.1.2.4; hardware = n2; }
 interface:n3 = { ip = 10.1.3.4; hardware = n3; virtual = { ip = 10.1.3.1; } }
}
pathrestriction:p = interface:r1.n4, interface:r1.n1;
service:s = {
 user = network:n4;
 permit src = user; dst = interface:r3.n3.virtual; prt = udp 123;
}
=END=
=OUTPUT=
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n4_in
access-list n4_in extended permit udp 10.1.4.0 255.255.255.0 host 10.1.3.1 eq 123
access-list n4_in extended deny ip any4 any4
access-group n4_in in interface n4
--r2
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r3
ip access-list extended n2_in
 permit udp 10.1.4.0 0.0.0.255 host 10.1.3.1 eq 123
 deny ip any any
--
ip access-list extended n3_in
 deny ip any any
--r4
ip access-list extended n2_in
 deny ip any any
--
ip access-list extended n3_in
 deny ip any any
=END=

############################################################
=TITLE=Pathrestricted path must not enter dst router twice
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
  interface:n3 = { ip = 10.1.3.1; hardware = n3; }
  interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n4 = { ip = 10.1.4.2; hardware = n4; }
  interface:n5 = { ip = 10.1.5.2; hardware = n5; }
}
router:r3 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n2 = { ip = 10.1.2.2; hardware = n2; }
  interface:n3 = { ip = 10.1.3.2; hardware = n3; }
  interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n2;
service:s1 = {
  user = network:n1;
  permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=END=
=OUTPUT=
--r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.1.2.1 eq 22
 deny ip any any
--
ip access-list extended n2_in
 deny ip any any
--
ip access-list extended n3_in
 deny ip any any
--
ip access-list extended n4_in
 deny ip any any
--r2
ip access-list extended n4_in
 deny ip any any
--
ip access-list extended n5_in
 deny ip any any
--r3
ip access-list extended n2_in
 deny ip any any
--
ip access-list extended n3_in
 deny ip any any
--
ip access-list extended n5_in
 deny ip any any
=END=

############################################################
=TITLE=Pathrestricted src and dst in same zone
# Should we find additional paths through network:n2?
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
pathrestriction:p1 = interface:r1.n1, interface:r1.n3;
pathrestriction:p2 = interface:r2.n1, interface:r2.n3;
service:s = {
 user = interface:r1.n1;
 permit src = user; dst = interface:r2.n1; prt = tcp 22;
}
=END=
=OUTPUT=
--r2
ip access-list extended n1_in
 permit tcp host 10.1.1.1 host 10.1.1.2 eq 22
 deny ip any any
--
ip access-list extended n2_in
 deny ip any any
--
ip access-list extended n3_in
 deny ip any any
=END=

############################################################
=TITLE=Find all networks in zone split by pathrestriction
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
pathrestriction:p = interface:u.n1, interface:r1.n2;
service:s1 = {
 user = network:[any:[network:n1]];
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s2 = {
 user = network:[any:[network:n2]];
 permit src = user; dst = network:n4; prt = tcp 81;
}
=END=
=OUTPUT=
--r1
ip access-list extended n2_in
 deny ip any host 10.1.4.1
 permit tcp 10.1.2.0 0.0.1.255 10.1.4.0 0.0.0.255 range 80 81
 deny ip any any
--r2
ip access-list extended n3_in
 deny ip any host 10.1.4.2
 permit tcp 10.1.2.0 0.0.1.255 10.1.4.0 0.0.0.255 range 80 81
 permit tcp 10.1.1.0 0.0.0.255 10.1.4.0 0.0.0.255 range 80 81
 deny ip any any
=END=

############################################################
=TITLE=Use all parts of aggregate in zone split by pathrestriction
# Aggregate must be permitted at both r1 and r2, although n1 only passes r2.
=INPUT=
any:n1-10-1-1 = { link = network:n1; ip = 10.1.0.0/23; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
pathrestriction:p = interface:u.n1, interface:r1.n2;
service:s1 = {
 user = any:n1-10-1-1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=OUTPUT=
--r1
ip access-list extended n2_in
 deny ip any host 10.1.4.1
 permit tcp 10.1.0.0 0.0.1.255 10.1.4.0 0.0.0.255 eq 80
 deny ip any any
--r2
ip access-list extended n3_in
 deny ip any host 10.1.4.2
 permit tcp 10.1.0.0 0.0.1.255 10.1.4.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Pathrestriction at both borders of loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3;
}
pathrestriction:p = interface:u.n1, interface:r3.n4;
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
router:r3 = {
 interface:n4 = { ip = 10.1.4.3; hardware = n4; }
 interface:n5= { ip = 10.1.5.1; hardware = n1; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n5; prt = ip;
}
=END=
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n5]
 for rule permit src=network:n1; dst=network:n5; prt=ip; of service:s1
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Pathrestriction at disabled interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; disabled; }
}
pathrestriction:p1 =
 interface:r1.n2,
 interface:r2.n3,
;
=END=
=WARNING=
Warning: Ignoring pathrestriction:p1 with only interface:r1.n2
=END=

############################################################
=TITLE=Show 'no valid path' for both services
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
}
pathrestriction:p1 =
 interface:r3.n3,
 interface:r3.n4,
 interface:r3.n5,
;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n5;
        prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user;
        dst = network:n5;
        prt = tcp 90;
}
=END=
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n5]
 for rule permit src=network:n1; dst=network:n5; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n1]
 to any:[network:n5]
 for rule permit src=network:n1; dst=network:n5; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n1]
 to any:[network:n5]
 for rule permit src=network:n1; dst=network:n5; prt=tcp 90; of service:s2
 Check path restrictions and crypto interfaces.
=END=
=WITH_OUTDIR=true

############################################################
=TITLE=Show 'no valid path' for both sources
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:t1 = { ip = 10.9.1.0/24; }
network:t2 = { ip = 10.9.2.0/24; }
network:t3 = { ip = 10.5.6.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:t2 = { ip = 10.9.2.3; hardware = t2; }
}
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
 interface:t3 = { ip = 10.5.6.1; hardware = t3; }
}
router:filter2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t2 = { ip = 10.9.2.2; hardware = t2; }
 interface:t3 = { ip = 10.5.6.2; hardware = t3; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t3 = { ip = 10.5.6.7; hardware = t3; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
pathrestriction:restrict1 =
 interface:filter1.t2,
 interface:r3.t3,
;
pathrestriction:restrict2 =
 interface:filter2.t2,
 interface:r3.t3,
;
service:test = {
 user = network:n1, network:n2;
 permit src = user; dst = interface:r3.n3; prt = tcp 80;
}
=END=
=ERROR=
Error: No valid path
 from any:[network:n1]
 to router:r3
 for rule permit src=network:n1; dst=interface:r3.n3; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n2]
 to router:r3
 for rule permit src=network:n2; dst=interface:r3.n3; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n1]
 to router:r3
 for rule permit src=network:n1; dst=interface:r3.n3; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n2]
 to router:r3
 for rule permit src=network:n2; dst=interface:r3.n3; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
=END=
=WITH_OUTDIR=true

############################################################
=TITLE=Show 'no valid path' for sources in different loops
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:t1 = { ip = 10.9.1.0/24; }
network:t2 = { ip = 10.9.2.0/24; }
network:t3 = { ip = 10.9.3.0/24; }
network:t4 = { ip = 10.9.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:t2 = { ip = 10.9.2.2; hardware = t2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:t3 = { ip = 10.9.3.2; hardware = t1; }
 interface:t4 = { ip = 10.9.4.2; hardware = t2; }
}
# Zone1 for path-walk is selected from this router.
router:r0 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t3 = { ip = 10.9.3.1; hardware = t1; }
 interface:t4 = { ip = 10.9.4.1; hardware = t2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
pathrestriction:p1 =
 interface:r0.t3,
 interface:r0.t4,
 interface:r0.n3,
;
service:s1 = {
 user = network:n1, network:n2;
 permit src = user;
        dst = network:n3;
        prt = tcp 80;
}
=END=
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n3]
 for rule permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n2]
 to any:[network:n3]
 for rule permit src=network:n2; dst=network:n3; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n1]
 to any:[network:n3]
 for rule permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n2]
 to any:[network:n3]
 for rule permit src=network:n2; dst=network:n3; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
=END=
=WITH_OUTDIR=true

############################################################
