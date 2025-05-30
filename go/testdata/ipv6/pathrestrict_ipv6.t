
############################################################
=TITLE=Pathrestriction must only reference real interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = {
  ip6 = ::a01:101;
  secondary:s = { ip6 = ::a01:163; }
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
group:g1 =
 interface:r1.n1,
 network:n2,
 interface:r2.[auto],
 interface:r1.n1.s,
;
pathrestriction:p = network:n1, group:g1, interface:r2.n2;
=ERROR=
Error: pathrestriction:p must not reference network:n1
Error: pathrestriction:p must not reference network:n2
Error: pathrestriction:p must not reference interface:r2.[auto]
Error: pathrestriction:p must not reference secondary interface:r1.n1.s
=END=

############################################################
=TITLE=Pathrestriction with only 0 or 1 interface
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
group:g1 =;
pathrestriction:p1 = group:g1;
pathrestriction:p2 = interface:r1.n1;
=WARNING=
Warning: Ignoring pathrestriction:p1 without elements
Warning: Ignoring pathrestriction:p2 with only interface:r1.n1
=END=

############################################################
# Shared topology for multiple tests.

############################################################
=TEMPL=topo
network:top = { ip6 = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:top = { ip6 = ::a01:101; hardware = top; }
 interface:lft = { ip6 = ::a03:1f5; hardware = lft; }
 interface:dst = { ip6 = ::a01:201; hardware = dst; }
}
network:lft = { ip6 = ::a03:1f4/126;}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:top = { ip6 = ::a01:102; hardware = top; }
 interface:rgt = { ip6 = ::a03:181; hardware = rgt; }
 interface:dst = { ip6 = ::a01:202; hardware = dst; }
}
network:rgt = { ip6 = ::a03:180/126;}
network:dst = { ip6 = ::a01:200/120;}
=END=

############################################################
=TITLE=Simple pathrestrictions leaving no valid path
=INPUT=
[[topo]]
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
[[topo]]
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
=OUTPUT=
-- ipv6/r1
ipv6 access-list top_in
 permit tcp ::a03:180/126 host ::a01:101 established
 deny ipv6 any any
--
ipv6 access-list lft_in
 deny ipv6 any any
--
ipv6 access-list dst_in
 deny ipv6 any any
-- ipv6/r2
ipv6 access-list top_in
 deny ipv6 any host ::a03:181
 permit tcp host ::a01:101 ::a03:180/126 eq 80
 deny ipv6 any any
--
ipv6 access-list rgt_in
 deny ipv6 any any
--
ipv6 access-list dst_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Path starts at pathrestriction inside loop (2)
# Must not use path r1.top-r1-r2-top
=INPUT=
[[topo]]
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
=OUTPUT=
-- ipv6/r1
ipv6 access-list top_in
 permit tcp ::a01:200/120 host ::a01:101 established
 permit tcp ::a01:100/120 host ::a01:101 established
 deny ipv6 any any
--
ipv6 access-list lft_in
 deny ipv6 any any
--
ipv6 access-list dst_in
 permit tcp ::a01:200/120 host ::a01:101 established
 deny ipv6 any any
-- ipv6/r2
ipv6 access-list top_in
 deny ipv6 any host ::a01:202
 permit tcp host ::a01:101 ::a01:200/120 eq 80
 deny ipv6 any any
--
ipv6 access-list rgt_in
 deny ipv6 any any
--
ipv6 access-list dst_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Path starts at pathrestriction inside loop (3)
=INPUT=
[[topo]]
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
=OUTPUT=
-- ipv6/r1
ipv6 access-list top_in
 deny ipv6 any any
--
ipv6 access-list dst_in
 permit tcp ::a01:100/120 host ::a01:201 established
 deny ipv6 any any
-- ipv6/r2
ipv6 access-list dst_in
 deny ipv6 any host ::a01:102
 permit tcp host ::a01:201 ::a01:100/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Path ends at pathrestriction inside loop
# Must detect identical path restriction,
# when temporary moving pathrestriction of r1.dst to r1.top.
=INPUT=
[[topo]]
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
=OUTPUT=
-- ipv6/r1
ipv6 access-list top_in
 deny ipv6 any any
--
ipv6 access-list dst_in
 permit tcp ::a01:100/120 host ::a01:201 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Path ends at pathrestriction inside loop (2)
=INPUT=
[[topo]]
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
=OUTPUT=
-- ipv6/r1
ipv6 access-list top_in
 permit tcp ::a01:100/120 host ::a03:1f5 eq 80
 deny ipv6 any any
--
ipv6 access-list dst_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Path ends at interface inside network, where path starts
# Must not enter r1 from network dst, even for optimized pathrestriction.
=INPUT=
[[topo]]
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
=OUTPUT=
-- ipv6/r1
ipv6 access-list top_in
 permit tcp ::a01:100/120 host ::a01:101 eq 179
 deny ipv6 any any
--
ipv6 access-list dst_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Path starts at pathrestriction inside loop (4)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2 = {
 managed = secondary;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; no_in_acl; routing = dynamic; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; routing = OSPF;}
 interface:n4 = { ip6 = ::a01:402; hardware = n4; virtual = { ip6 = ::a01:401; type = HSRP; } }
}
router:r3 = {
 interface:n2;
 interface:n3;
 interface:n4 = { ip6 = ::a01:403; virtual = { ip6 = ::a01:401; type = HSRP; } }
}
service:s1 = {
 user = foreach interface:r2.[all];
 permit src = any:[user]; dst = user; prt = icmpv6 8;
}
=OUTPUT=
-- ipv6/r2
ipv6 access-list n1_in
 permit icmp any host ::a01:101 8
 permit icmp any host ::a01:301 8
 permit icmp any host ::a01:401 8
 permit icmp any host ::a01:402 8
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:301
 deny ipv6 any host ::a01:401
 deny ipv6 any host ::a01:402
 permit ipv6 any any
--
ipv6 access-list n3_in
 permit icmp any host ::a01:101 8
 permit icmp any host ::a01:301 8
 permit icmp any host ::a01:401 8
 permit icmp any host ::a01:402 8
 permit 89 ::a01:300/120 host ff02::5
 permit 89 ::a01:300/120 host ff02::6
 permit 89 ::a01:300/120 ::a01:300/120
 deny ipv6 any any
--
ipv6 access-list n3_out
 deny ipv6 any any
--
ipv6 access-list n4_in
 permit icmp any host ::a01:101 8
 permit icmp any host ::a01:301 8
 permit icmp any host ::a01:401 8
 permit icmp any host ::a01:402 8
 permit udp ::a01:400/120 host ::e000:2 eq 1985
 deny ipv6 any any
--
ipv6 access-list n4_out
 deny ipv6 any any
=END=

############################################################
=TITLE=Ignore redundant pathrestriction
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; virtual = { ip6 = ::a01:101; } hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:103; virtual = { ip6 = ::a01:101; } hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 interface:n2;
 interface:n3;
 interface:n4;
}
pathrestriction:p1 =
 interface:r1.n1.virtual, interface:r2.n1.virtual, interface:r3.n2;
pathrestriction:p2 =
 interface:r1.n1.virtual,                          interface:r3.n2;
pathrestriction:p3 =
                          interface:r2.n1.virtual, interface:r3.n2;
pathrestriction:p4 =
 interface:r1.n1.virtual, interface:r2.n1.virtual;
=WARNING=
DIAG: Removed pathrestriction:p2; is subset of pathrestriction:p1
DIAG: Removed pathrestriction:p3; is subset of pathrestriction:p1
DIAG: Removed pathrestriction:p4; is subset of pathrestriction:p1
DIAG: Removed auto-virtual:::a01:101; is subset of pathrestriction:p1
=SHOW_DIAG=

############################################################
=TITLE=Pathrestriction located in different loops
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2a = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
network:t1 = { ip6 = ::a09:100/120; }
router:r2b = {
 model = IOS;
 managed;
 routing = manual;
 interface:t1 = { ip6 = ::a09:102; hardware = t1; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
pathrestriction:p1 =
 interface:r2a.n2,
 interface:r2b.n3,
;
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = udp 123;
}
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
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r3 = {
 interface:n2;
 interface:n3;
 interface:n5;
}
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
router:r4 = {
 model = Linux;
 managed;
 routing = manual;
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
 interface:n6 = { ip6 = ::a01:601; hardware = n6; }
 interface:n7 = { ip6 = ::a01:701; hardware = n7; }
}
network:n6 = { ip6 = ::a01:600/120; }
network:n7 = { ip6 = ::a01:700/120; }
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
=WARNING=
Warning: Ignoring pathrestriction:p having elements from different loops:
 - interface:r4.n6
 - interface:r3.n5
=END=

############################################################
=TITLE=Pathrestriction located in different loops (3)
# Ignored pathrestriction at unmanaged router at zone in loop
# was not handled correctly, leading to panic.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }

router:r0 = {
 interface:n1 = { ip6 = ::a01:103; }
 interface:n3 = { ip6 = ::a01:303; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r4 = {
 managed;
 model = IOS;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}

pathrestriction:p = interface:r1.n1, interface:r0.n3;

service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=WARNING=
Warning: Ignoring pathrestriction:p having elements from different loops:
 - interface:r1.n1
 - interface:r0.n3
=END=

############################################################
=TITLE=Pathrestriction at non-loop node
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 model = IOS;
 managed;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
pathrestriction:p1 =
 interface:r1.n2,
 interface:r3.n3,
;
=WARNING=
Warning: Ignoring pathrestriction:p1 at interface:r3.n3
 because it isn't located inside cyclic graph
=END=

############################################################
=TITLE=Pathrestriction at internally split router outside of loop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
# r2 is split internally into two parts
# r2 with n3, n4
# r2' with n2
# both connected internally by unnumbered network.
router:r2 = {
 interface:n2 = { ip6 = ::a01:202; }
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
=WARNING=
Warning: Ignoring pathrestriction:p1 at interface:r1.n2
 because it isn't located inside cyclic graph
Warning: Ignoring pathrestriction:p1 at interface:r2.n2
 because it isn't located inside cyclic graph
=END=

############################################################
=TITLE=Pathrestricted destination in complex loop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n3;
service:s = {
 user = network:n1;
 permit src = user; dst = interface:r1.n3; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp ::a01:100/120 host ::a01:301 eq 22
 deny ipv6 any any
--
ipv6 access-list n3_in
 permit tcp ::a01:100/120 host ::a01:301 eq 22
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:301 eq 22
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp host ::a01:301 ::a01:100/120 established
 deny ipv6 any any
--
ipv6 access-list n3_in
 permit tcp host ::a01:301 ::a01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestricted source in complex loop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n3;
pathrestriction:p2 = interface:r2.n1, interface:r2.n3;
service:s = {
 user = interface:r1.n1;
 permit src = user; dst = network:n3; prt = udp 123;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit udp ::a01:300/120 eq 123 host ::a01:101
 deny ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n1_in
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any host ::a01:302
 permit udp host ::a01:101 ::a01:300/120 eq 123
 deny ipv6 any any
--
ipv6 access-list n3_in
 permit udp ::a01:300/120 eq 123 host ::a01:101
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestricted src and dst in complex loop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
router:r3 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip6 = ::a01:203; hardware = n2; }
 interface:n3 = { ip6 = ::a01:303; hardware = n3; virtual = { ip6 = ::a01:301; } }
}
router:r4 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n2 = { ip6 = ::a01:204; hardware = n2; }
 interface:n3 = { ip6 = ::a01:304; hardware = n3; virtual = { ip6 = ::a01:301; } }
}
pathrestriction:p = interface:r1.n4, interface:r1.n1;
service:s = {
 user = network:n4;
 permit src = user; dst = interface:r3.n3.virtual; prt = udp 123;
}
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n4_in
access-list n4_in extended permit udp ::a01:400/120 host ::a01:301 eq 123
access-list n4_in extended deny ip any6 any6
access-group n4_in in interface n4
--ipv6/r2
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--ipv6/r3
ipv6 access-list n2_in
 permit udp ::a01:400/120 host ::a01:301 eq 123
 deny ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any any
--ipv6/r4
ipv6 access-list n2_in
 deny ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestricted path must not enter dst router twice
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
router:r1 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n1 = { ip6 = ::a01:101; hardware = n1; }
  interface:n2 = { ip6 = ::a01:201; hardware = n2; }
  interface:n3 = { ip6 = ::a01:301; hardware = n3; }
  interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n4 = { ip6 = ::a01:402; hardware = n4; }
  interface:n5 = { ip6 = ::a01:502; hardware = n5; }
}
router:r3 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n2 = { ip6 = ::a01:202; hardware = n2; }
  interface:n3 = { ip6 = ::a01:302; hardware = n3; }
  interface:n5 = { ip6 = ::a01:501; hardware = n5; }
}
pathrestriction:p = interface:r1.n1, interface:r1.n2;
service:s1 = {
  user = network:n1;
  permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:201 eq 22
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any any
--
ipv6 access-list n4_in
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n4_in
 deny ipv6 any any
--
ipv6 access-list n5_in
 deny ipv6 any any
--ipv6/r3
ipv6 access-list n2_in
 deny ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any any
--
ipv6 access-list n5_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestricted src and dst in same zone
# Should we find additional paths through network:n2?
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
pathrestriction:p1 = interface:r1.n1, interface:r1.n3;
pathrestriction:p2 = interface:r2.n1, interface:r2.n3;
service:s = {
 user = interface:r1.n1;
 permit src = user; dst = interface:r2.n1; prt = tcp 22;
}
=OUTPUT=
--ipv6/r2
ipv6 access-list n1_in
 permit tcp host ::a01:101 host ::a01:102 eq 22
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Find all networks in zone split by pathrestriction
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
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
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 deny ipv6 any host ::a01:401
 permit tcp ::a01:200/119 ::a01:400/120 range 80 81
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n3_in
 deny ipv6 any host ::a01:402
 permit tcp ::a01:200/119 ::a01:400/120 range 80 81
 permit tcp ::a01:100/120 ::a01:400/120 range 80 81
 deny ipv6 any any
=END=

############################################################
=TITLE=Use all parts of aggregate in zone split by pathrestriction
# Aggregate must be permitted at both r1 and r2, although n1 only passes r2.
=INPUT=
any:n1-10-1-1 = { link = network:n1; ip6 = ::a01:0/119; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
pathrestriction:p = interface:u.n1, interface:r1.n2;
service:s1 = {
 user = any:n1-10-1-1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 deny ipv6 any host ::a01:401
 permit tcp ::a01:0/119 ::a01:400/120 eq 80
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n3_in
 deny ipv6 any host ::a01:402
 permit tcp ::a01:0/119 ::a01:400/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Add aggregates and networks from all zones of cluster
=INPUT=
any:10_1_0-24 = { link = network:n1; ip6 = ::a01:0/120; }
network:big = { ip6 = ::a01:0/119; has_subnets; }
network:n0a = { ip6 = ::a01:0/121; }
network:n0b = { ip6 = ::a01:80/121; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
network:n6 = { ip6 = ::a01:600/120; }
router:u1 = {
 interface:n0a;
 interface:n0b;
 interface:big;
 interface:n2;
 interface:n3;
}
router:u2 = {
 interface:n0a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n5 = { ip6 = ::a01:501; hardware = n4; }
}
router:u4 = {
 interface:n4;
 interface:n5;
 interface:n6;
}
# Unrelated pathrestriction must not terminate analysis early.
pathrestriction:p0 = interface:r1.n4, interface:u4.n6;

pathrestriction:p1 = interface:u1.n0a, interface:r2.n3;
pathrestriction:p2 = interface:u1.n0b, interface:r1.n2;
pathrestriction:p3 = interface:u1.big, interface:u1.n2;
service:s1 = {
 user = any:10_1_0-24;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s2 = {
 user = network:big;
 permit src = user; dst = network:n4; prt = tcp 81;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 deny ipv6 any host ::a01:401
 permit tcp ::a01:0/120 ::a01:400/120 eq 80
 permit tcp ::a01:0/121 ::a01:400/120 eq 81
 permit tcp ::a01:100/120 ::a01:400/120 eq 81
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n3_in
 permit tcp ::a01:0/120 ::a01:400/120 eq 80
 permit tcp ::a01:0/119 ::a01:400/120 eq 81
 deny ipv6 any any
=END=

############################################################
=TITLE=Pathrestriction at both borders of loop
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
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
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
router:r3 = {
 interface:n4 = { ip6 = ::a01:403; hardware = n4; }
 interface:n5 = { ip6 = ::a01:501; hardware = n5; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n5; prt = ip;
}
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n5]
 for rule permit src=network:n1; dst=network:n5; prt=ip; of service:s1
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Show 'no valid path' for both services
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
router:r2 = {
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
 interface:n5 = { ip6 = ::a01:502; hardware = n5; }
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
=WITH_OUTDIR=true

############################################################
=TITLE=Show 'no valid path' for both sources
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:t1 = { ip6 = ::a09:100/120; }
network:t2 = { ip6 = ::a09:200/120; }
network:t3 = { ip6 = ::a05:600/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:t1 = { ip6 = ::a09:102; hardware = t1; }
 interface:t2 = { ip6 = ::a09:203; hardware = t2; }
}
router:filter1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t2 = { ip6 = ::a09:201; hardware = t2; }
 interface:t3 = { ip6 = ::a05:601; hardware = t3; }
}
router:filter2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t2 = { ip6 = ::a09:202; hardware = t2; }
 interface:t3 = { ip6 = ::a05:602; hardware = t3; }
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t3 = { ip6 = ::a05:607; hardware = t3; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
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
=WITH_OUTDIR=true

############################################################
=TITLE=Show 'no valid path' for sources in different loops
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:t1 = { ip6 = ::a09:100/120; }
network:t2 = { ip6 = ::a09:200/120; }
network:t3 = { ip6 = ::a09:300/120; }
network:t4 = { ip6 = ::a09:400/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
 interface:t2 = { ip6 = ::a09:201; hardware = t2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip6 = ::a09:102; hardware = t1; }
 interface:t2 = { ip6 = ::a09:202; hardware = t2; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:t3 = { ip6 = ::a09:302; hardware = t1; }
 interface:t4 = { ip6 = ::a09:402; hardware = t2; }
}
# Zone1 for path-walk is selected from this router.
router:r0 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t3 = { ip6 = ::a09:301; hardware = t1; }
 interface:t4 = { ip6 = ::a09:401; hardware = t2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
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
=WITH_OUTDIR=true

############################################################
