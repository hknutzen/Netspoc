
############################################################
=TITLE=Leave order unchanged when combining addresses
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:h2 = { ip6 = ::a01:102; }
 host:h3 = { ip6 = ::a01:103; }
 host:h4 = { ip6 = ::a01:104; }
 host:h6 = { ip6 = ::a01:106; }
 host:h7 = { ip6 = ::a01:107; }
 host:h8 = { ip6 = ::a01:108; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
service:test = {
 user = host:h2, host:h4, host:h3, host:h7, host:h8, host:h6;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--ipv6/r
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit tcp ::a01:102/127 ::a01:200/120 eq 80
 permit tcp host ::a01:104 ::a01:200/120 eq 80
 permit tcp host ::a01:108 ::a01:200/120 eq 80
 permit tcp ::a01:106/127 ::a01:200/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Split and combine host ranges
=INPUT=
network:n = {
 ip6 = ::a01:100/120;
 host:a = { range6 = ::a01:10f-::a01:113; }
 host:b = { range6 = ::a01:114-::a01:118; }
 host:c = { range6 = ::a01:119-::a01:123; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n = { ip6 = ::a01:101; hardware = ethernet0; }
 interface:x = { ip6 = f000::c0a8:101; hardware = ethernet1; }
}
network:x = { ip6 = f000::c0a8:100/120; }
service:test = {
 user = host:a, host:b, host:c;
 permit src = user; dst = network:x; prt = tcp 80;
}
=OUTPUT=
--ipv6/r
ipv6 access-list ethernet0_in
 deny ipv6 any host f000::c0a8:101
 permit tcp host ::a01:10f f000::c0a8:100/120 eq 80
 permit tcp ::a01:110/124 f000::c0a8:100/120 eq 80
 permit tcp ::a01:120/126 f000::c0a8:100/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Combine host ranges  into network and ignore it in 2. step
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:h4 = { ip6 = ::a01:104; }
 host:h5 = { ip6 = ::a01:105; }
 host:r6-7 = { range6 = ::a01:106-::a01:107; }
}
router:u = {
 interface:n1;
 interface:n2;
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:r0-127 = { range6 = ::a01:200-::a01:27f; }
 host:r128-255 = { range6 = ::a01:280-::a01:2ff; }
}
router:r = {
 model = IOS, FW;
 managed;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n3 = { ip6 = ::a01:300/120; }
service:test = {
 user = host:h4, host:h5, host:r6-7, host:r0-127, host:r128-255;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--ipv6/r
ipv6 access-list n1_in
 deny ipv6 any host ::a01:301
 permit tcp ::a01:104/126 ::a01:300/120 eq 80
 permit tcp ::a01:200/120 ::a01:300/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Large host ranges for non private addresses
=TODO=No IPv6
=INPUT=
network:inet = {
 ip6 = ::/0;
 host:r1 = { range6 = :: - ::9ff:ffff; }
 host:r2 = { range6 = ::b00:0 - f000::ac0f:ffff; }
 host:r3 = { range6 = f000::ac20:0 - f000::c0a7:ffff; }
 host:r4 = { range6 = f000::c0a9:0 - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff; }
}

router:r = {
 managed;
 model = IOS;
 interface:inet = { ip6 = ::a09:901;  hardware = inet; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}

network:n1 = {
 ip6 = ::a01:100/120;
 subnet_of = network:inet;
}

service:s1 = {
 user = host:[network:inet];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r
! [ ACL ]
ipv6 access-list inet_in
 deny ipv6 any host ::a01:101
 permit tcp ::/101 ::a01:100/120 eq 80
 permit tcp ::800:0/103 ::a01:100/120 eq 80
 permit tcp ::b00:0/104 ::a01:100/120 eq 80
 permit tcp ::c00:0/102 ::a01:100/120 eq 80
 permit tcp ::1000:0/100 ::a01:100/120 eq 80
 permit tcp ::2000:0/99 ::a01:100/120 eq 80
 permit tcp ::4000:0/98 ::a01:100/120 eq 80
 permit tcp f000::8000:0/99 ::a01:100/120 eq 80
 permit tcp f000::a000:0/101 ::a01:100/120 eq 80
 permit tcp f000::a800:0/102 ::a01:100/120 eq 80
 permit tcp f000::ac00:0/108 ::a01:100/120 eq 80
 permit tcp f000::ac20:0/107 ::a01:100/120 eq 80
 permit tcp f000::ac40:0/106 ::a01:100/120 eq 80
 permit tcp f000::ac80:0/105 ::a01:100/120 eq 80
 permit tcp f000::ad00:0/104 ::a01:100/120 eq 80
 permit tcp f000::ae00:0/103 ::a01:100/120 eq 80
 permit tcp f000::b000:0/100 ::a01:100/120 eq 80
 permit tcp f000::c000:0/105 ::a01:100/120 eq 80
 permit tcp f000::c080:0/107 ::a01:100/120 eq 80
 permit tcp f000::c0a0:0/109 ::a01:100/120 eq 80
 permit tcp f000::c0a9:0/112 ::a01:100/120 eq 80
 permit tcp f000::c0aa:0/111 ::a01:100/120 eq 80
 permit tcp f000::c0ac:0/110 ::a01:100/120 eq 80
 permit tcp f000::c0b0:0/108 ::a01:100/120 eq 80
 permit tcp f000::c0c0:0/106 ::a01:100/120 eq 80
 permit tcp f000::c100:0/104 ::a01:100/120 eq 80
 permit tcp f000::c200:0/103 ::a01:100/120 eq 80
 permit tcp f000::c400:0/102 ::a01:100/120 eq 80
 permit tcp f000::c800:0/101 ::a01:100/120 eq 80
 permit tcp f000::d000:0/100 ::a01:100/120 eq 80
 permit tcp ::e000:0/99 ::a01:100/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Redundant rule from host range and combined ip hosts
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:h4 = { ip6 = ::a01:104; }
 host:h5 = { ip6 = ::a01:105; }
 host:h6 = { ip6 = ::a01:106; }
 host:h7 = { ip6 = ::a01:107; }
 host:r4-5 = { range6 = ::a01:104-::a01:105; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
service:test = {
 user = host:h4, host:h5, host:r4-5;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h4; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r4-5; dst=network:n2; prt=tcp 80; of service:test
  permit src=host:h5; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r4-5; dst=network:n2; prt=tcp 80; of service:test
=OUTPUT=
--ipv6/r
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit tcp ::a01:104/127 ::a01:200/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Duplicate host ranges
=INPUT=
network:n = {
 ip6 = ::a01:100/120;
 host:a = { range6 = ::a01:10f-::a01:113; }
 host:b = { range6 = ::a01:10f-::a01:113; }
}
=ERROR=
Error: Duplicate IP address for host:a and host:b
=END=

############################################################
=TITLE=Host range and interface IP overlap
=INPUT=
network:n = {
 ip6 = ::a01:100/120;
 host:a = { range6 = ::a01:101-::a01:113; }
}
router:r = {
 interface:n = { ip6 = ::a01:101; }
}
=ERROR=
Error: Duplicate IP address for interface:r.n and host:a
=END=

############################################################
=TITLE=Ignore overlap of subnet range and interface IP
=INPUT=
network:n = {
 ip6 = ::a01:100/120;
 host:a = { range6 = ::a01:100-::a01:10f; }
}
router:r = {
 interface:n = { ip6 = ::a01:101; }
}
=WARNING=NONE

############################################################
=TITLE=Duplicate host and interface IP
=INPUT=
network:n = {
 ip6 = ::a01:100/120;
 host:a = { ip6 = ::a01:101; }
}
router:r = {
 interface:n = { ip6 = ::a01:101; }
}
=ERROR=
Error: Duplicate IP address for interface:r.n and host:a
=END=

############################################################
=TITLE=Duplicate host IPs
=INPUT=
network:n = {
 ip6 = ::a01:100/120;
 host:a = { ip6 = ::a01:101; }
 host:b = { ip6 = ::a01:101; }
}
=ERROR=
Error: Duplicate IP address for host:a and host:b
=END=

############################################################
=TITLE=Redundant rule from host range and combined ip hosts
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:h4 = { ip6 = ::a01:104; }
 host:h5 = { ip6 = ::a01:105; }
 host:h6 = { ip6 = ::a01:106; }
 host:h7 = { ip6 = ::a01:107; }
 host:r6-7 = { range6 = ::a01:106-::a01:107; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
service:test = {
 user = host:h4, host:h5, host:h6, host:h7, host:r6-7;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h6; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r6-7; dst=network:n2; prt=tcp 80; of service:test
  permit src=host:h7; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r6-7; dst=network:n2; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Must not combine list in place
# List of src objects is referenced from two different path rules.
# If combineSubnets is applied twice on the same list,
# we would get garbage.
=INPUT=
network:n1 = { ip6 = ::a01:100/120;
 host:h20 = { ip6 = ::a01:114; }
 host:h21 = { ip6 = ::a01:115; }
 host:h22 = { ip6 = ::a01:116; }
 host:h23 = { ip6 = ::a01:117; }
 host:h24 = { ip6 = ::a01:118; }
}
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
service:s1 = {
 user = network:n2, network:n3;
 permit src = user; dst = host:h22, host:h23, host:h24; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n2_in
object-group network v6g0
 network-object ::a01:116/127
 network-object host ::a01:118
access-list n2_in extended permit tcp ::a01:200/120 object-group v6g0 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
-- ipv6/r2
! n3_in
object-group network v6g0
 network-object ::a01:116/127
 network-object host ::a01:118
access-list n3_in extended permit tcp ::a01:300/120 object-group v6g0 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
