=TITLE=Pathrestriction on same side of loop
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip6 = 2001:db8:1:3::/64; }
network:n4 = { ip6 = 2001:db8:1:4::/64; }
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:1:3::1; hardware = n3; }
 interface:n4 = { ip6 = 2001:db8:1:4::1; hardware = n4; }
}
pathrestriction:p1 = interface:r2.n3, interface:r2.n4;
service:s1 = {
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=ERROR=
Error: No valid path
 from any:[network:n3]
 to any:[network:n4]
 for rule permit src=network:n3; dst=network:n4; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:p1 (blocked 1 path attempt)
=END=

############################################################
=TITLE=Pathrestriction with alternative path
=INPUT=
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip6 = 2001:db8:1:3::/64; }
network:n4 = { ip6 = 2001:db8:1:4::/64; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:1:3::1; hardware = n3; }
 interface:n4 = { ip6 = 2001:db8:1:4::1; hardware = n4; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:1:3::2; hardware = n3; }
}
pathrestriction:pr1 = interface:r1.n1, interface:r1.n4;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s2 = {
 user = network:n4;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n4]
 for rule permit src=network:n1; dst=network:n4; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:pr1 (blocked 1 path attempt)
Error: No valid path
 from any:[network:n4]
 to any:[network:n1]
 for rule permit src=network:n4; dst=network:n1; prt=tcp 80; of service:s2
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:pr1 (blocked 1 path attempt)
=END=