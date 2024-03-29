
############################################################
=TITLE=Only use network
=INPUT=
group:g =
 interface:r1.n1,
 interface:r1.[auto],
 any:n1,
 any:[ip=10.0.0.0/8 & network:n1]
;
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; reroute_permit = network:n1; }
}
=WARNING=
Warning: Ignoring attribute 'reroute_permit' at unmanaged interface:r1.n1
=END=

############################################################
=TITLE=Check zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  reroute_permit = network:n2;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
=ERROR=
Error: Invalid reroute_permit for network:n2 at interface:r1.n1: different security zones
=END=

############################################################
=TITLE=Directly and indirectly connected network
=INPUT=
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r0 = {
 interface:n0;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = 10.1.1.2;
  hardware = n1;
  reroute_permit = network:n1, network:n0;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any host 10.1.1.2
 permit ip any 10.1.0.0 0.0.1.255
 deny ip any any
=END=

############################################################
=TITLE=With Linux
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  reroute_permit = network:n1;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
=OUTPUT=
--r1
:n1_n1 -
-A n1_n1 -j ACCEPT -d 10.1.1.0/24
-A FORWARD -j n1_n1 -i n1 -o n1
=END=

############################################################
=TITLE=Forbidden with outgoing ACL
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:u = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.1; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n2 = {
  ip = 10.1.2.2;
  hardware = n2;
  reroute_permit = network:n2;
 }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; no_in_acl; }
}
network:n3 = { ip = 10.1.3.0/24; }
=ERROR=
Error: Must not use attributes no_in_acl and reroute_permit together at router:r1
 Add incoming and outgoing ACL line in raw file instead.
=END=

############################################################
=TITLE=Forbidden at no_in_acl interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; reroute_permit = network:n2;
 no_in_acl; }
}
network:n2 = { ip = 10.1.2.0/24; }
=WARNING=
Warning: Useless 'reroute_permit' together with 'no_in_acl' at interface:r1.n2
=END=

############################################################
