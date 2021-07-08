
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
=END=
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
=END=
=ERROR=
Error: Invalid IP address in 'ip' of interface:r1.n1
=END=

############################################################
=TITLE=Interface IP doesn't match network IP/mask
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.2.3; }
}
=END=
=ERROR=
Error: interface:r1.n1's IP doesn't match network:n1's IP/mask
=END=

############################################################
=TITLE=Host IP/range don't match network IP/mask
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 host:h1 = { ip = 10.1.2.3; }
 host:r1 = { range = 10.1.1.3-10.1.1.29; }
}
=END=
=ERROR=
Error: IP of host:h1 doesn't match IP/mask of network:n1
Error: IP range of host:r1 doesn't match IP/mask of network:n1
=END=

############################################################
=TITLE=Invalid range
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 host:r1 = { range = 10.1.1.9-10.1.1.3; }
 host:r2 = { range = 10.1.1.1-10.1.1.3-10.1.1.5; }
 host:r3 = { range = 10.1.1.2; }
}
=END=
=ERROR=
Error: Invalid IP range in host:r1
Error: Expected IP range in host:r2
Error: Expected IP range in host:r3
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
=END=
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
=END=
=ERROR=
Error: Duplicate IP address for interface:r1.n1 and host:r1
Error: Duplicate IP address for interface:r1.n1 and host:r2
Error: Duplicate IP address for host:h1 and host:h2
Error: Duplicate IP address for interface:r1.n1 and host:h3
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
=END=
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
=END=
=ERROR=
Error: network:n1 is subnet_of network:n2 but its IP doesn't match that's IP/mask
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
=END=
=ERROR=
Error: Unnumbered network:n2 must not be referenced from attribute 'subnet_of'
 of network:n1
=END=

############################################################
=TITLE=Overlapping hosts with subnet
=INPUT=
network:n1 = {
 ip = 10.1.1.0/28;
 subnet_of = network:n2;
}
router:r1 = {
  interface:n1;
 interface:n2 = { ip = 10.1.1.1; }
}
network:n2 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
 host:h2 = { range = 10.1.1.11-10.1.1.17; }
}
=END=
=WARNING=
Warning: IP of interface:r1.n2 overlaps with subnet network:n1
Warning: IP of host:h1 overlaps with subnet network:n1
Warning: IP of host:h2 overlaps with subnet network:n1
=END=

############################################################
=TITLE=Reference unknown network in subnet_of
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 subnet_of = network:n2;
}
=END=
=WARNING=
Warning: Referencing undefined network:n2 in 'subnet_of' of network:n1
=END=

############################################################
