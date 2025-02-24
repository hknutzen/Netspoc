
############################################################
=TITLE=Invalid network IP together with hosts and interfaces
=INPUT=
network:n1 = {
 ip = 10.1.1.0/58;
 host:h1 = { ip = 10.1.2.3; }
 host:r1 = { range = 10.1.1.3-10.1.1.29; }
}
router:r1 = {
 interface:n1 = { ip = 10.1.2.3; }
}
=ERROR=
Error: Invalid CIDR address: 10.1.1.0/58 in 'ip' of network:n1
=END=

############################################################
=TITLE=Invalid interface IP
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.2.3.4.5; }
}
=ERROR=
Error: Invalid IP address in 'ip' of interface:r1.n1
=END=

############################################################
=TITLE=Interface IP doesn't match network address
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.2.3; }
}
=ERROR=
Error: IPv4 address of interface:r1.n1 doesn't match network:n1
=END=

############################################################
=TITLE=Host IP or range don't match network address
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 host:h1 = { ip = 10.1.2.3; }
 host:r1 = { range = 10.1.1.3-10.1.1.29; }
}
=ERROR=
Error: IP of host:h1 doesn't match address of network:n1
Error: IP range of host:r1 doesn't match address of network:n1
=END=

############################################################
=TITLE=Expect IP range
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 host:r2 = { range = 10.1.1.1-10.1.1.3-10.1.1.5; }
 host:r3 = { range = 10.1.1.2; }
}
=ERROR=
Error: Invalid IP range in host:r2
Error: Invalid IP range in host:r3
=END=

############################################################
=TITLE=Invalid IP range
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 host:r1 = { range = 10.1.1.9-10.1.1.3; }
}
=ERROR=
Error: Invalid IP range in host:r1
=END=

############################################################
=TITLE=Range has size of network
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 host:r1 = { range = 10.1.1.0-10.1.1.15; }
}
router:r1 = {
  interface:n1;
 interface:t1 = { ip = 10.9.1.1; }
}
network:t1 = { ip = 10.9.1.0/28; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
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
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
 host:h2 = { ip = 10.1.1.10; }
 host:h3 = { ip = 10.1.1.11; }
 host:r1 = { range = 10.1.1.2-10.1.1.12; }
 host:r2 = { range = 10.1.1.11-10.1.1.15; }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.11; }
}
=ERROR=
Error: Duplicate IP address for interface:r1.n1 and host:r1
Error: Duplicate IP address for interface:r1.n1 and host:r2
Error: Duplicate IP address for host:h1 and host:h2
Error: Duplicate IP address for interface:r1.n1 and host:h3
=END=

############################################################
=TITLE=Non virtual interface has IP of virtual interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r0 = {
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.2; virtual = { ip = 10.1.1.1; } hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.3; virtual = { ip = 10.1.1.1; } hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
=ERROR=
Error: Duplicate IP address for interface:r0.n1 and interface:r1.n1.virtual
Error: Duplicate IP address for interface:r0.n1 and interface:r2.n1.virtual
=END=

############################################################
=TITLE=Overlapping ranges used in rule
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 host:r1 = { range = 10.1.1.4-10.1.1.11; }
 host:r2 = { range = 10.1.1.8-10.1.1.11; }
}
router:r2 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = host:r1, host:r2;
 permit src = user; dst = network:n2; prt = ip;
}
=WARNING=
Warning: host:r2 and host:r1 overlap in src of service:s1
=END=

############################################################
=TITLE=Non matching subnet
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 subnet_of = network:n2;
}
router:r1 = {
 interface:n1;
 interface:n2;
}
network:n2 = { ip = 10.2.2.0/24; }
=ERROR=
Error: network:n1 is subnet_of network:n2 but its IP doesn't match that's address
=END=

############################################################
=TITLE=Subnet of unnumbered network
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
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
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 subnet_of = network:n3;
}
network:n2 = {
 ip = 10.1.1.32/28;
 subnet_of = network:n3;
}
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = 10.1.1.1; }
}
network:n3 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
 host:h2 = { range = 10.1.1.11-10.1.1.17; }
 host:h3 = { range = 10.1.1.30-10.1.1.50; }
 host:h4 = { range = 10.1.1.35-10.1.1.45; }
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
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 subnet_of = network:n2;
}
=WARNING=
Warning: Referencing undefined network:n2 in 'subnet_of' of network:n1
=END=

############################################################
