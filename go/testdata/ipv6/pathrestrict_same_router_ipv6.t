=TITLE=Pathrestriction on same side of loop
=INPUT=
network:n1 = { ip6 = 2001:db8:1::/64; }
network:n2 = { ip6 = 2001:db8:2::/64; }
network:n3 = { ip6 = 2001:db8:3::/64; }
network:n4 = { ip6 = 2001:db8:4::/64; }
router:A = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = 2001:db8:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:2::1; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:3::1; hardware = n3; }
 interface:n4 = { ip6 = 2001:db8:4::1; hardware = n4; }
}
router:B = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = 2001:db8:2::2; hardware = n2; }
 interface:n3 = { ip6 = 2001:db8:3::2; hardware = n3; }
}

pathrestriction:pr1 = interface:A.n1, interface:A.n4;

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
