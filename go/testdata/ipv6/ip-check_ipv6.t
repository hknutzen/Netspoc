
############################################################
=TITLE=Invalid network IP together with hosts and interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/154;
 host:h1 = { ip = ::a01:203; }
 host:r1 = { range = ::a01:103-::a01:11d; }
}
router:r1 = {
 interface:n1 = { ip = ::a01:203; }
}
=ERROR=
Error: Invalid CIDR address: ::a01:100/154 in 'ip' of network:n1
=END=

############################################################
=TITLE=Invalid interface IP
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1 = { ip = ::a01:203.4.5; }
}
=ERROR=
Error: Invalid IP address in 'ip' of interface:r1.n1
=END=

############################################################
=TITLE=Interface IP doesn't match network IP/mask
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1 = { ip = ::a01:203; }
}
=ERROR=
Error: interface:r1.n1's IP doesn't match network:n1's IP/mask
=END=

############################################################
=TITLE=Host IP/range don't match network IP/mask
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 host:h1 = { ip = ::a01:203; }
 host:r1 = { range = ::a01:103-::a01:11d; }
}
=ERROR=
Error: IP of host:h1 doesn't match IP/mask of network:n1
Error: IP range of host:r1 doesn't match IP/mask of network:n1
=END=

############################################################
=TITLE=Expect IP range
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 host:r2 = { range = ::a01:101-::a01:103-::a01:105; }
 host:r3 = { range = ::a01:102; }
}
=ERROR=
Error: Invalid IP range in host:r2
Error: Invalid IP range in host:r3
=END=

############################################################
=TITLE=Invalid IP range
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 host:r1 = { range = ::a01:109-::a01:103; }
}
=ERROR=
Error: Invalid IP range in host:r1
=END=

############################################################
=TITLE=Range has size of network
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 host:r1 = { range = ::a01:100-::a01:10f; }
}
router:r1 = {
  interface:n1;
 interface:t1 = { ip = ::a09:101; }
}
network:t1 = { ip = ::a09:100/124; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = host:r1;
 permit src = user; dst = network:n2; prt = ip;
}
# Show warning only once
service:s2 = {
 user = host:r1;
 permit src = user; dst = interface:r2.t1; prt = tcp 22;
}
=WARNING=
Warning: Use network:n1 instead of host:r1
 because both have identical address
=END=

############################################################
=TITLE=Overlapping host, range, interface
# Overlapping ranges are ok.
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 host:h1 = { ip = ::a01:10a; }
 host:h2 = { ip = ::a01:10a; }
 host:h3 = { ip = ::a01:10b; }
 host:r1 = { range = ::a01:102-::a01:10c; }
 host:r2 = { range = ::a01:10b-::a01:10f; }
}
router:r1 = {
 interface:n1 = { ip = ::a01:10b; }
}
=ERROR=
Error: Duplicate IP address for interface:r1.n1 and host:r1
Error: Duplicate IP address for interface:r1.n1 and host:r2
Error: Duplicate IP address for host:h1 and host:h2
Error: Duplicate IP address for interface:r1.n1 and host:h3
=END=

############################################################
=TITLE=Non virtual interface has IP of virtual interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }

router:r0 = {
 interface:n1 = { ip = ::a01:101; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:102; virtual = { ip = ::a01:101; } hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:103; virtual = { ip = ::a01:101; } hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
=ERROR=
Error: Duplicate IP address for interface:r0.n1 and interface:r1.n1.virtual
Error: Duplicate IP address for interface:r0.n1 and interface:r2.n1.virtual
=END=

############################################################
=TITLE=Overlapping ranges used in rule
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 host:r1 = { range = ::a01:104-::a01:10b; }
 host:r2 = { range = ::a01:108-::a01:10b; }
}
router:r2 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = host:r1, host:r2;
 permit src = user; dst = network:n2; prt = ip;
}
=WARNING=
Warning: host:r2 and host:r1 overlap in src of service:s1
=END=

############################################################
=TITLE=Non matching subnet
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 subnet_of = network:n2;
}
router:r1 = {
 interface:n1;
 interface:n2;
}
network:n2 = { ip = ::a02:200/120; }
=ERROR=
Error: network:n1 is subnet_of network:n2 but its IP doesn't match that's IP/mask
=END=

############################################################
=TITLE=Subnet of unnumbered network
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 subnet_of = network:n2;
}
router:r1 = {
 interface:n1;
 interface:n2;
}
network:n2 = { unnumbered; }
=ERROR=
Error: Unnumbered network:n2 must not be referenced from attribute 'subnet_of'
 of network:n1
=END=

############################################################
=TITLE=Overlapping hosts with subnet
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/124;
 subnet_of = network:n3;
}
network:n2 = {
 ip = ::a01:120/124;
 subnet_of = network:n3;
}
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = ::a01:101; }
}
network:n3 = {
 ip = ::a01:100/120;
 host:h1 = { ip = ::a01:10a; }
 host:h2 = { range = ::a01:10b-::a01:111; }
 host:h3 = { range = ::a01:11e-::a01:132; }
 host:h4 = { range = ::a01:123-::a01:12d; }
}
=WARNING=
Warning: IP of interface:r1.n3 overlaps with subnet network:n1
Warning: IP of host:h1 overlaps with subnet network:n1
Warning: IP of host:h2 overlaps with subnet network:n1
Warning: IP of host:h3 overlaps with subnet network:n2
Warning: IP of host:h4 overlaps with subnet network:n2
=END=

############################################################
=TITLE=Reference unknown network in subnet_of
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 subnet_of = network:n2;
}
=WARNING=
Warning: Referencing undefined network:n2 in 'subnet_of' of network:n1
=END=

############################################################
