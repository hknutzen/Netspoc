
############################################################
=TITLE=Access named and positional secondary interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = ::a01:101; secondary:5th = { ip = ::a01:105; } hardware = n1; }
 interface:n2 = { ip = ::a01:201, ::a01:209; hardware = n2; }
}
router:r2 = {
 managed;
 model = NX-OS;
 interface:n1 = { ip = ::a01:10b,::a01:10c;  hardware = n1; }
}
service:t1 = {
 user = network:n1, network:n2;
 permit src = user; dst = interface:r1.n1.5th; prt = tcp 22;
 permit src = user; dst = interface:r1.n2.2; prt = tcp 23;
}
service:t2 = {
 user = network:n1;
 permit src = user; dst = interface:r2.n1.2; prt = tcp 21;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:105 eq 22
 permit tcp ::a01:100/120 host ::a01:209 eq 23
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp ::a01:200/120 host ::a01:105 eq 22
 permit tcp ::a01:200/120 host ::a01:209 eq 23
 deny ipv6 any any
--
interface n1
 ipv6 address ::a01:101/120
 ipv6 address ::a01:105/120
 ipv6 traffic-filter n1_in in
interface n2
 ipv6 address ::a01:201/120
 ipv6 address ::a01:209/120
 ipv6 traffic-filter n2_in in
-- ipv6/r2
ipv6 access-list n1_in
 10 permit tcp ::a01:100/120 ::a01:10c/128 eq 21
 20 deny ip any any
--
interface n1
 ipv6 address ::a01:10b/120
 ipv6 address ::a01:10c/120 secondary
 ipv6 traffic-filter n1_in in
=END=

############################################################
=TITLE=Outgoing traffic from secondary interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = ::a01:101; secondary:5th = { ip = ::a01:105; } hardware = n1; }
 interface:n2 = { ip = ::a01:201, ::a01:209; hardware = n2; }
}
service:t1 = {
 user = network:n1, network:n2;
 permit src = interface:r1.n1.5th; dst = user; prt = udp 123;
 permit src = interface:r1.n2.2; dst = user; prt = udp 69;
}
=END=
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit udp ::a01:100/120 eq 123 host ::a01:105
 permit udp ::a01:100/120 eq 69 host ::a01:209
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit udp ::a01:200/120 eq 123 host ::a01:105
 permit udp ::a01:200/120 eq 69 host ::a01:209
 deny ipv6 any any
=END=

############################################################
=TITLE=Secondary IP from multiple networks at same hardware
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n2; }
}
service:t1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.n2, interface:r1.n3; prt = tcp 22;
}
=END=
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:201 eq 22
 permit tcp ::a01:100/120 host ::a01:301 eq 22
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any any
--
interface n1
 ipv6 address ::a01:101/120
 ipv6 traffic-filter n1_in in
interface n2
 ipv6 address ::a01:201/120
 ipv6 address ::a01:301/120
 ipv6 traffic-filter n2_in in
=END=

############################################################
=TITLE=Duplicate named secondary interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  ip = ::a01:101;
  secondary:5th = { ip = ::a01:105; }
  secondary:5th = { ip = ::a01:106; }
 }
}
=END=
=ERROR=
Error: Duplicate attribute 'secondary:5th' in interface:n1 of router:r1
Error: Duplicate definition of interface:r1.n1.5th in router:r1
=END=

############################################################
=TITLE=Name clash for named and positional secondary interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  ip = ::a01:101, ::a01:104;
  secondary:2 = { ip = ::a01:106; }
 }
}
=END=
=ERROR=
Error: Duplicate definition of interface:r1.n1.2 in router:r1
=END=

############################################################
=TITLE=Name clash for secondary and virtual interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  ip = ::a01:101;
  secondary:virtual = { ip = ::a01:106; }
  virtual = { ip = ::a01:109; }
 }
}
=END=
=ERROR=
Error: Duplicate definition of interface:r1.n1.virtual in router:r1
=END=

############################################################
=TITLE=Identical IP at host and secondary interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h = { ip = ::a01:102; } }
router:r1 = {
 interface:n1 = {
  ip = ::a01:101, ::a01:102;
 }
}
=END=
=ERROR=
Error: Duplicate IP address for interface:r1.n1.2 and host:h
=END=

############################################################
=TITLE=Identical IP at named and positional secondary interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1 = {
  ip = ::a01:101, ::a01:102;
  secondary:s = { ip = ::a01:102; }
 }
}
=END=
=ERROR=
Error: Duplicate IP address for interface:r1.n1.2 and interface:r1.n1.s
=END=

############################################################
=TITLE=Move secondary interface of internally split router
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
# r1 is split internally into two parts
# r1 connected with n1, n2
# r1' connected with n3
# both connected by unnumbered network.
router:r1 = {
 interface:n1 = { ip = ::a01:101; }
 interface:n2 = { ip = ::a01:201; }
 interface:n3 = { ip = ::a01:301; secondary:s = { ip = ::a01:363; } }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
pathrestriction:r =
 interface:r1.n3,
 interface:r2.n3,
;
service:s = {
 user = network:n4;
 # Find secondary  interface r1.n3.s of split interface r1.n3.
 permit src = user; dst = interface:r1.n3.s; prt = tcp 22;
}
=END=
=OUTPUT=
--ipv6/r2
ipv6 access-list n1_in
 permit tcp host ::a01:363 ::a01:400/120 established
 deny ipv6 any any
--
ipv6 access-list n4_in
 permit tcp ::a01:400/120 host ::a01:363 eq 22
 deny ipv6 any any
--
ipv6 access-list n3_in
 permit tcp host ::a01:363 ::a01:400/120 established
 deny ipv6 any any
=END=

############################################################
