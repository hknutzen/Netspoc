
############################################################
=TITLE=Only use network
=PARAMS=--ipv6
=INPUT=
group:g =
 interface:r1.n1,
 interface:r1.[auto],
 any:n1,
 any:[ip=::a00:0/104 & network:n1]
;
any:n1 = { link = network:n1; }
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = ::a01:101;
  hardware = n1;
  reroute_permit = host:h1, group:g, network:n2;
 }
}
=ERROR=
Error: Expected type 'network:' in 'reroute_permit' of interface:r1.n1
Error: Expected type 'network:' in 'reroute_permit' of interface:r1.n1
Warning: Ignoring undefined network:n2 in 'reroute_permit' of interface:r1.n1
=END=

############################################################
=TITLE=Not at unmanaged
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
router:r1 = {
 interface:n1 = { ip = ::a01:101; reroute_permit = network:n1; }
}
=WARNING=
Warning: Ignoring attribute 'reroute_permit' at unmanaged interface:r1.n1
=END=

############################################################
=TITLE=Check zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = ::a01:101;
  hardware = n1;
  reroute_permit = network:n2;
 }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: Invalid reroute_permit for network:n2 at interface:r1.n1: different security zones
=END=

############################################################
=TITLE=Directly and indirectly connected network
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a01:0/120; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r0 = {
 interface:n0;
 interface:n1 = { ip = ::a01:101; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = ::a01:102;
  hardware = n1;
  reroute_permit = network:n1, network:n0;
 }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:102
 permit ipv6 any ::a01:0/119
 deny ipv6 any any
=END=

############################################################
=TITLE=With Linux
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = ::a01:101;
  hardware = n1;
  reroute_permit = network:n1;
 }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
=OUTPUT=
--ipv6/r1
:n1_n1 -
-A n1_n1 -j ACCEPT -d ::a01:100/120
-A FORWARD -j n1_n1 -i n1 -o n1
=END=

############################################################
=TITLE=Forbidden with outgoing ACL
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:u = {
 interface:n1;
 interface:n2 = { ip = ::a01:201; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n2 = {
  ip = ::a01:202;
  hardware = n2;
  reroute_permit = network:n2;
 }
 interface:n3 = { ip = ::a01:301; hardware = n3; no_in_acl; }
}
network:n3 = { ip = ::a01:300/120; }
=ERROR=
Error: Must not use attributes no_in_acl and reroute_permit together at router:r1
 Add incoming and outgoing ACL line in raw file instead.
=END=

############################################################
=TITLE=Forbidden at no_in_acl interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; reroute_permit = network:n2;
 no_in_acl; }
}
network:n2 = { ip = ::a01:200/120; }
=WARNING=
Warning: Useless 'reroute_permit' together with 'no_in_acl' at interface:r1.n2
=END=

############################################################
