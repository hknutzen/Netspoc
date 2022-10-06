
############################################################
=TITLE=Duplicate NAT definition
=INPUT=
area:n1 = {
 border = interface:r.n1;
 nat:n = { ip = 10.7.0.0/16; }
 nat:n = { ip = 10.6.0.0/16; }
}
any:n1 = {
 link = network:n1;
 nat:n = { ip = 10.9.0.0/16; }
 nat:n = { ip = 10.8.0.0/16; }
}
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 10.9.9.0/24; }
 nat:n = { ip = 10.8.8.0/24; dynamic;}
 host:h1 = {
  ip = 10.1.1.10;
  nat:n = { ip = 10.9.9.9; }
  nat:n = { ip = 10.8.8.8; }
 }
}
router:r = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = 10.1.1.1; hardware = n1;
  nat:n = { ip = 10.9.9.1; }
  nat:n = { ip = 10.8.8.1; }
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Duplicate attribute 'nat:n' in network:n1
Error: Duplicate attribute 'nat:n' in host:h1
Error: Duplicate attribute 'nat:n' in any:n1
Error: Duplicate attribute 'nat:n' in interface:n1 of router:r
Error: Duplicate attribute 'nat:n' in area:n1
=END=

############################################################
=TITLE=Other NAT attribute together with hidden
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 10.9.9.0/24; hidden; dynamic; identity; }
}
router:r = {
 interface:n1;
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Hidden NAT must not use attribute 'ip' in nat:n of network:n1
Error: Hidden NAT must not use attribute 'dynamic' in nat:n of network:n1
Error: Hidden NAT must not use attribute 'identity' in nat:n of network:n1
=END=

############################################################
=TITLE=Other NAT attribute together with identity
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 10.9.9.0/24; dynamic; identity; }
}
router:r = {
 interface:n1;
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Identity NAT must not use attribute 'ip' in nat:n of network:n1
Error: Identity NAT must not use attribute 'dynamic' in nat:n of network:n1
=END=

############################################################
=TITLE=NAT at short interface
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 10.9.9.0/24; dynamic; }
}
router:r = {
 interface:n1 = { nat:n = { ip = 10.9.9.1; } }
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: No NAT supported for interface:r.n1 without IP
=END=

############################################################
=TITLE=Duplicate IP address
=INPUT=
network:n1a = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/24; }
}
router:r1 = {
 interface:n1a = { bind_nat = t2; }
 interface:u;
}
network:u = { ip = 10.2.2.0/24; }
router:r2 = {
 interface:u;
 interface:n1b = { bind_nat = t1; }
}
network:n1b = {
 ip = 10.1.1.0/24;
 nat:t2 = { ip = 10.9.2.0/24; }
}
=END=
=ERROR=
Error: network:n1a and network:n1b have identical IP/mask in any:[network:n1a]
=END=

############################################################
=TITLE=NAT bound in wrong direction
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:x = { hidden; } }
router:r = {
 interface:n1 = { bind_nat = x; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: network:n1 is translated by nat:x,
 but is located inside the translation domain of x.
 Probably x was bound to wrong interface at
 - router:r
=END=

############################################################
=TITLE=Dynamic NAT for network with static nat for hosts at ASA
=INPUT=
network:Test =  {
 ip = 10.9.1.0/24;
 nat:C = { ip = 1.1.1.16/28; dynamic;}
 host:H = { ip = 10.9.1.33; nat:C = { ip = 1.1.1.23; } }
}
router:filter = {
 managed;
 model = ASA;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.3.1; hardware = outside; bind_nat = C;}
}
network:X = { ip = 10.9.3.0/24; }
service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = ip;
 permit src = host:H; dst = user;         prt = tcp 80;
 permit src = user;   dst = network:Test; prt = tcp 80;
}
=END=
=OUTPUT=
--filter
! inside_in
access-list inside_in extended permit tcp host 10.9.1.33 10.9.3.0 255.255.255.0 eq 80
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit ip 10.9.3.0 255.255.255.0 host 10.9.1.33
access-list outside_in extended permit tcp 10.9.3.0 255.255.255.0 10.9.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Masquerading
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:m = { ip = 10.1.2.1/32; dynamic; subnet_of = network:n2; }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = m; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
-- r2
! n2_in
access-list n2_in extended permit tcp host 10.1.2.1 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Invalid masquerading
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:m = { ip = 10.1.2.0/31; dynamic; subnet_of = network:n2; }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = m; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=WARNING=
Warning: IP of interface:r1.n2 overlaps with subnet network:n1 in nat_domain:[network:n2]
=END=

############################################################
=TITLE=NAT to subnet
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:m = { ip = 10.1.2.16/28; dynamic; subnet_of = network:n2; }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = m; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
-- r2
! n2_in
access-list n2_in extended permit tcp 10.1.2.16 255.255.255.240 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=subnet_of at inherited NAT
=INPUT=
area:n1-2 = {
 nat:m = { ip = 10.1.3.16/28; dynamic; subnet_of = network:n3; }
 inclusive_border = interface:r1.n3;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = m; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n1, network:n2;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=OUTPUT=
-- r2
! n3_in
access-list n3_in extended permit tcp 10.1.3.16 255.255.255.240 10.1.4.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Inherit NAT to subnet in other part of zone cluster
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; nat:h1 = { hidden; } }
network:n7 = { ip = 10.1.7.0/24; nat:h1 = { hidden; } }
network:n7s = { ip = 10.1.7.64/26; subnet_of = network:n7; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = h1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r3 = {
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
 interface:n7 = { ip = 10.1.7.1; hardware = n7; }
}
router:r4 = {
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; }
 interface:n7s = { ip = 10.1.7.65; hardware = n7s; }
}

pathrestriction:p1 = interface:r1.n3, interface:r4.n5;
pathrestriction:p2 = interface:r2.n4, interface:r3.n5;

service:s1 = {
 user = network:n6, network:n7;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n7s;
 permit src = user; dst = network:n1; prt = tcp 81;
}
=ERROR=
Error: network:n6 is hidden by nat:h1 in rule
 permit src=network:n6; dst=network:n2; prt=tcp 80; of service:s1
Error: network:n7s is hidden by nat:h1 in rule
 permit src=network:n7s; dst=network:n2; prt=tcp 80; of service:s1
Error: network:n7 is hidden by nat:h1 in rule
 permit src=network:n7; dst=network:n2; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Check rule with aggregate to hidden NAT
=INPUT=
network:Test =  {
 ip = 10.0.1.0/24;
 nat:C = { hidden; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.0.1.2; hardware = inside; }
 interface:t1 = { ip = 10.0.2.1; hardware = outside;}
}
network:t1 = { ip = 10.0.2.0/24; }
router:u = {
 interface:t1 = { ip = 10.0.2.2; }
 interface:X = { ip = 10.8.3.1; bind_nat = C; }
}
network:X = { ip = 10.8.3.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:X = { ip = 10.8.3.2; hardware = inside; }
}
service:s1 = {
 user = any:[network:X];
 permit src = user; dst = network:Test; prt = tcp 80;
}
service:s2 = {
 user = network:X;
 permit src = user; dst = network:Test; prt = tcp 81;
}
=END=
# Only first error is shown.
=ERROR=
Error: network:Test is hidden by nat:C in rule
 permit src=any:[network:X]; dst=network:Test; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Multiple hosts in hidden network
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { hidden; }
 host:h13 = { ip = 10.1.1.3; }
 host:h14 = { ip = 10.1.1.4; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = {
 ip = 10.1.4.0/24;
 nat:n4 = { hidden; }
 host:h43 = { ip = 10.1.4.3; }
 host:h44 = { ip = 10.1.4.4; }
}

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; bind_nat = n1;
 }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 interface:n3 = { ip = 10.1.3.2; bind_nat = n4; }
 interface:n4 = { ip = 10.1.4.1; }
}
service:s1 = {
 user = host:h13;
 permit src = user; dst = host:h43; prt = tcp 82;
}
service:s2 = {
 user = host:h13;
 permit src = user; dst = host:h43; prt = tcp 83;
}
service:s3 = {
 user = host:h14;
 permit src = user; dst = host:h44; prt = tcp 84;
}
=END=
# Only first error is shown.
=ERROR=
Error: host:h13 is hidden by nat:n1 in rule
 permit src=host:h13; dst=host:h43; prt=tcp 82; of service:s1
Error: host:h43 is hidden by nat:n4 in rule
 permit src=host:h13; dst=host:h43; prt=tcp 82; of service:s1
=END=

############################################################
=TITLE=NAT network is undeclared subnet
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { hidden; }
 host:h65 = { ip = 10.1.1.65; }
 host:h66 = { ip = 10.1.1.66; }
}
network:n1sub = {
 ip = 10.1.1.64/26;
 subnet_of = network:n1;
 nat:n1sub = { ip = 10.1.2.64/26; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; bind_nat = n1sub; hardware = n1; }
 interface:l = { ip = 10.1.9.9; loopback; hardware = l; }
 interface:n1sub = { ip = 10.1.1.126; bind_nat = n1;  hardware = n1sub; }
}
=END=
=WARNING=
Warning: IP of host:h65 overlaps with subnet network:n1sub in nat_domain:[interface:r1.l]
Warning: IP of host:h66 overlaps with subnet network:n1sub in nat_domain:[interface:r1.l]
=END=

############################################################
=TITLE=NAT network is undeclared subnet
=TEMPL=input
network:Test =  {
 ip = 10.0.0.0/28;
 nat:C = { ip = {{.ip}}; {{.sub}} }
}
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = C; }
}
network:X = { ip = 10.8.3.0/24; }
=END=
=INPUT=[[input {ip: "10.8.3.240/28", sub: ""}]]
=WARNING=
Warning: nat:C of network:Test is subnet of network:X
 in nat_domain:[network:X].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=NAT network is subnet
=INPUT=[[input {ip: "10.8.3.240/28", sub: "subnet_of = network:X;"}]]
=WARNING=NONE

############################################################
=TITLE=Declared NAT network subnet doesn't match
=INPUT=[[input  {ip: "10.8.4.240/28", sub: "subnet_of = network:X;"}]]
=ERROR=
Error: nat:C of network:Test is subnet_of network:X but its IP doesn't match that's IP/mask
=END=

############################################################
=TITLE=Detect subnet relation when having duplicate IP addresses
# Processing order of networks depends on lexical order of router names.
# Choose a weird order to get n1/n2sub and n2/n1sub to be processed together.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:h1 = { hidden; } }
network:n1sub = { ip = 10.1.1.64/26; }
router:r1 = {
 interface:n1;
 interface:t1;
}
router:r4 = {
 interface:n1sub;
 interface:t1;
}
network:t1 = { ip = 10.2.1.0/24; }
router:fw =  {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.2.1.1; hardware = t1; bind_nat = h2; }
 interface:t2 = { ip = 10.2.2.1; hardware = t2; bind_nat = h1; }
}
network:t2 = { ip = 10.2.2.0/24; }
router:r2 = {
 interface:n2;
 interface:t2;
}
router:r3 = {
 interface:n2sub;
 interface:t2;
}
network:n2 = { ip = 10.1.1.0/24; nat:h2 = { hidden; } }
network:n2sub = { ip = 10.1.1.64/26; }
=END=
=WARNING=
Warning: network:n1sub is subnet of network:n1
 in nat_domain:[network:t1].
 If desired, declare attribute 'subnet_of'
Warning: network:n2sub is subnet of network:n2
 in nat_domain:[network:t2].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Copy subnet_of from network to inherited NAT
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:N = { ip = 10.9.9.0/24; }
}
network:n1_sub = {
 ip = 10.1.1.64/26;
 subnet_of = network:n1;
}
router:u = {
 interface:n1;
 interface:n1_sub;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_sub = { ip = 10.1.1.65; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = N; }
}
service:s1 = {
    user = network:n1_sub;
    permit src = network:n2; dst = user; prt = tcp 80;
}
service:s2 = {
    user = network:n1;
    permit src = network:n2; dst = user; prt = tcp 81;
}
=END=
=OUTPUT=
-- asa1
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.64 255.255.255.192 eq 80
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 81
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not bind multiple NAT of one network at one place
=INPUT=
network:n1 =  {
 ip = 10.0.1.0/24;
 nat:C = { ip = 10.8.1.0/24; }
 nat:D = { hidden; }
}
network:n2 =  {
 ip = 10.0.2.0/24;
 nat:C = { ip = 10.8.2.0/24; }
 nat:D = { hidden; }
}
router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.0.1.2; hardware = n1; }
 interface:n2 = { ip = 10.0.2.2; hardware = n2; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = C, D, E; }
}
network:X = { ip = 10.8.3.0/24; }
=END=
# Only first error is shown.
=ERROR=
Warning: Ignoring useless nat:E bound at interface:filter.X
Error: Grouped NAT tags 'C, D' of network:n1 must not both be active at
 - interface:filter.X
=END=

############################################################
=TITLE=Check bind_nat at hardware interface
=INPUT=
network:n1a =  { ip = 10.0.1.0/26; }
network:n1b =  { ip = 10.0.1.64/26; }
network:n1c =  { ip = 10.0.1.128/26; }
network:n2 =  { ip = 10.0.2.0/24; nat:n2 = { ip = 10.8.2.0/24; } }
router:r = {
 managed;
 model = ASA;
 interface:n1a = { ip = 10.0.1.1; hardware = n1; bind_nat = n2; }
 interface:n1b = { ip = 10.0.1.65; hardware = n1; }
 interface:n1c = { ip = 10.0.1.129; hardware = n1; }
 interface:n2 = { ip = 10.0.2.1; hardware = n2; }
}
=END=
=ERROR=
Error: interface:r.n1a and interface:r.n1b using identical 'hardware = n1'
 must also use identical NAT binding
Error: interface:r.n1a and interface:r.n1c using identical 'hardware = n1'
 must also use identical NAT binding
=END=

############################################################
=TITLE=Unused / undefined / duplicate NAT tag
=INPUT=
network:Test =  {
 ip = 10.0.0.0/24;
 nat:C = { ip = 10.8.8.0/24; }
}
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = D, E/F, D; }
}
network:X = { ip = 10.8.3.0/24; }
=END=
=WARNING=
Warning: Duplicate 'D' in 'bind_nat' of interface:filter.X
Warning: Ignoring useless nat:D bound at interface:filter.X
Warning: Ignoring useless nat:E/F bound at interface:filter.X
Warning: nat:C is defined, but not bound to any interface
=END=

############################################################
=TITLE=No further errors on useless NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = i; }
}
router:r2 = {
 interface:n2;
 interface:n3 = { bind_nat = h; }
}
router:r3 = {
 interface:n3 = { bind_nat = h; }
 interface:n1;
}
=END=
=WARNING=
Warning: Ignoring useless nat:i bound at interface:r1.n2
Warning: Ignoring useless nat:h bound at interface:r2.n3
Warning: Ignoring useless nat:h bound at interface:r3.n3
=END=

############################################################
=TITLE=Non matching static NAT mask
=INPUT=
network:n1 =  { ip = 10.1.1.0/24; nat:x = { ip = 10.8.8.0/23; } }
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: Mask for non dynamic nat:x must be equal to mask of network:n1
=END=

############################################################
=TITLE=Non matching NAT IP of host and interface
=INPUT=
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/23; dynamic; }
 host:h1 = { ip = 10.1.1.10; nat:x = { ip = 10.7.7.7; } }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; nat:x = { ip = 10.7.7.1; } }
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: nat:x: IP of host:h1 doesn't match IP/mask of network:n1
Error: nat:x: IP of interface:r1.n1 doesn't match IP/mask of network:n1
=END=

############################################################
=TITLE=Useless NAT IP of host and interface with static NAT
=INPUT=
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/24; }
 host:h1 = { ip = 10.1.1.10; nat:x = { ip = 10.8.8.12; } }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; nat:x = { ip = 10.7.7.1; } }
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=WARNING=
Warning: Ignoring nat:x at host:h1 because network:n1 has static NAT definition
Warning: Ignoring nat:x at interface:r1.n1 because network:n1 has static NAT definition
=END=

############################################################
=TITLE=Must not define NAT for host range.
=INPUT=
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/24; dynamic; }
 host:h1 = { range = 10.1.1.10-10.1.1.15; nat:x = { ip = 10.8.8.12; } }
}
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=ERROR=
Error: No NAT supported for host:h1 with 'range'
=END=

############################################################
=TITLE=Inconsistent NAT for host vs. host range.
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:d = { ip = 10.9.1.0/28; dynamic; }
 host:h1 = { ip = 10.1.1.10; nat:d = { ip = 10.9.1.10; } }
 host:h2 = { range = 10.1.1.9 - 10.1.1.10; }
 host:h3 = { range = 10.1.1.8 - 10.1.1.15; }
}
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = d; }
}
network:n2 = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Inconsistent NAT definition for host:h1 and host:h2
Error: Inconsistent NAT definition for host:h3 and host:h1
=END=

############################################################
=TITLE=NAT for interface with multiple IP addresses
=INPUT=
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/28; dynamic; }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.1, 10.1.1.2; nat:x = { ip = 10.8.8.1; } }
 interface:t1 = { ip = 10.1.9.1; bind_nat = x; }
}
network:t1 = { ip = 10.1.9.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.1.9.2; hardware = t1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s = {
 user = interface:r1.[all];
 permit src = user; dst = network:n2; prt = udp 123;
}
=END=
=ERROR=
Error: interface:r1.n1.2 needs static translation for nat:x at router:filter to be valid in rule
 permit src=interface:r1.n1.2; dst=network:n2; prt=udp 123; of service:s
=END=

############################################################
=TITLE=NAT tag without effect (1)
=INPUT=
network:n1 =  { ip = 10.1.1.0/24; nat:x = { ip = 10.9.9.0/24; } }
router:r1 = {
 interface:n1 = { bind_nat = x; }
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=WARNING=
Warning: Ignoring nat:x without effect, bound at every interface of router:r1
=END=

############################################################
=TITLE=NAT tag without effect (2)
=INPUT=
network:n1 =  { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
router:u = {
 interface:n1;
 interface:n2 = { bind_nat = n1; }
}
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
router:r1 = {
 interface:n2 = { bind_nat = n1; }
 interface:n3 = { bind_nat = n1, n2; }
}
network:n3 = { ip = 10.1.3.0/24; }
=END=
=WARNING=
Warning: Ignoring nat:n1 without effect, bound at every interface of router:r1
=END=

############################################################
=TITLE=Check rule with host and dynamic NAT (managed)
=TEMPL=input
network:Test =  {
 ip = 10.9.1.0/24;
 nat:C = { ip = 1.9.2.0/24; dynamic;}
 host:h3 = { ip = 10.9.1.3; }
 host:h4 = { ip = 10.9.1.4; }
 host:h5 = { ip = 10.9.1.5; nat:C = { ip = 1.9.2.55; } }
}
router:C = {
 {{.}}
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = inside;}
 interface:Trans = { ip = 10.0.0.1; hardware = outside; bind_nat = C;}
}
network:Trans = { ip = 10.0.0.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = {
  ip = 10.0.0.2;
  hardware = inside;
 }
 interface:X = { ip = 10.8.3.1; hardware = outside; }
}
network:X = { ip = 10.8.3.0/24; }
service:s1 = {
 user = network:X;
 permit src = user;    dst = host:h3, host:h5; prt = tcp 80;
 permit src = host:h4; dst = user;             prt = tcp 80;
}
=END=
=INPUT=[[input managed;]]
=ERROR=
Error: host:h3 needs static translation for nat:C at router:C to be valid in rule
 permit src=network:X; dst=host:h3; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Check rule with host and dynamic NAT (unmanaged)
=INPUT=[[input ""]]
=ERROR=
Error: host:h3 needs static translation for nat:C at router:filter to be valid in rule
 permit src=network:X; dst=host:h3; prt=tcp 80; of service:s1
Error: host:h4 needs static translation for nat:C at router:filter to be valid in rule
 permit src=host:h4; dst=network:X; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Check rule with host and dynamic NAT but filtered static address
=INPUT=
network:n1 =  {
 ip =  10.1.1.0/24;
 nat:S = { ip = 1.9.1.0/24; dynamic; }
 nat:D = { ip = 1.9.2.0/28; dynamic; }
 host:h5 = { ip = 10.1.1.5; nat:S = { ip = 1.9.1.5; } }
}
network:n2 =  { ip =  10.1.2.0/24; }
network:n3 =  { ip =  10.1.3.0/24; }
network:n4 =  { ip =  10.1.4.0/24; }

router:S = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = S; }
}
router:C = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n1;}
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = D; }
}
router:filter = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

service:s1 = {
 user = network:n4;
 permit src = user; dst = host:h5; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=No secondary optimization with host and dynamic NAT (1)
# Secondary optimization must be disabled at router:S,
# because router:R can't distinguish between h33 and h34.
=INPUT=
network:Test =  {
 ip = 10.9.1.0/24;
 nat:C = { ip = 1.9.9.9/32; dynamic;}
 host:h33 = { ip = 10.9.1.33; }
 host:h34 = { ip = 10.9.1.34; }
}
router:S = {
 managed = secondary;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = inside;}
 interface:Trans = { ip = 10.0.0.1; hardware = outside; bind_nat = C;}
}
network:Trans = { ip = 10.0.0.0/24; }
router:R = {
 managed;
 model = ASA;
 interface:Trans = {
  ip = 10.0.0.2;
  hardware = inside;
 }
 interface:X = { ip = 10.8.3.1; hardware = outside; }
}
network:X = { ip = 10.8.3.0/24; }
service:s1 = {
 user = network:X;
 permit src = host:h33; dst = user;         prt = tcp 80;
 permit src = host:h34; dst = user;         prt = tcp 22;
}
=END=
=OUTPUT=
-- S
! inside_in
access-list inside_in extended permit tcp host 10.9.1.33 10.8.3.0 255.255.255.0 eq 80
access-list inside_in extended permit tcp host 10.9.1.34 10.8.3.0 255.255.255.0 eq 22
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
-- R
! inside_in
access-list inside_in extended permit tcp host 1.9.9.9 10.8.3.0 255.255.255.0 eq 80
access-list inside_in extended permit tcp host 1.9.9.9 10.8.3.0 255.255.255.0 eq 22
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=No secondary optimization with host and dynamic NAT (2)
# Secondary optimization must be disabled at router:r2.
=INPUT=
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = 10.1.1.1; hardware = a; bind_nat = b;}
 interface:t = {ip = 10.4.4.1; hardware = t;}
}
network:t = { ip = 10.4.4.0/30; }
router:r2 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:t = {ip = 10.4.4.2; hardware = t;}
 interface:b = {ip = 10.2.2.1; hardware = b;}
}
network:b  = {
 ip = 10.2.2.0/24;
 nat:b = { ip = 10.9.9.4/30; dynamic; }
 host:b10 = { ip = 10.2.2.10; }
}
service:test = {
 user = network:a;
 permit src = user; dst = host:b10; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
! [ ACL ]
ip access-list extended a_in
 permit tcp 10.1.1.0 0.0.0.255 10.9.9.4 0.0.0.3 eq 80
 deny ip any any
--
ip access-list extended t_in
 permit tcp host 10.2.2.10 10.1.1.0 0.0.0.255 established
 deny ip any any
-- r2
! t_in
access-list t_in extended permit tcp 10.1.1.0 255.255.255.0 host 10.2.2.10 eq 80
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
=END=

############################################################
=TITLE=No secondary optimization with host and dynamic NAT (3)
=INPUT=
network:a = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = 10.1.1.1; hardware = a; }
 interface:t = {ip = 10.4.4.1; hardware = t;}
}
network:c = { ip = 10.3.3.0/24; }
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:c = {ip = 10.3.3.1; hardware = c; bind_nat = b; }
 interface:t = {ip = 10.4.4.3; hardware = t;}
}
network:t = { ip = 10.4.4.0/24; }
router:r2 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:t = {ip = 10.4.4.2; hardware = t;}
 interface:b = {ip = 10.2.2.1; hardware = b;}
}
network:b  = {
 ip = 10.2.2.0/24;
 nat:b = { ip = 10.9.9.4/30; dynamic; }
 host:b10 = { ip = 10.2.2.10; }
}
service:s1 = {
 user = network:a, network:c;
 permit src = user; dst = host:b10; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended a_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.10 eq 80
 deny ip any any
--
ip access-list extended t_in
 permit tcp host 10.2.2.10 10.1.1.0 0.0.0.255 established
 deny ip any any
-- r3
ip access-list extended c_in
 permit tcp 10.3.3.0 0.0.0.255 10.9.9.4 0.0.0.3 eq 80
 deny ip any any
--
ip access-list extended t_in
 permit tcp host 10.2.2.10 10.3.3.0 0.0.0.255 established
 deny ip any any
-- r2
! t_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.3.3.0 255.255.255.0
access-list t_in extended permit tcp object-group g0 host 10.2.2.10 eq 80
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
=END=

############################################################
=TITLE=Optimize secondary if dynamic NAT is not applied
# Dynamic NAT does't influence network:b at router:r2,
# because it isn't applied at any rule for network:b
=INPUT=
network:a = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = 10.1.1.1; hardware = a; }
 interface:t = {ip = 10.4.4.1; hardware = t; }
}
network:t = { ip = 10.4.4.0/24; }
router:r2 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:t = {ip = 10.4.4.2; hardware = t; }
 interface:b = {ip = 10.2.2.1; hardware = b; }
 interface:c = {ip = 10.3.3.1; hardware = b; }
}
network:b  = {
 ip = 10.2.2.0/24;
 nat:b = { ip = 10.9.9.4/30; dynamic; }
 host:b10 = { ip = 10.2.2.10; }
}
network:c = { ip = 10.3.3.0/24; nat:b = { ip = 10.9.9.4/30; dynamic; } }
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:c = {ip = 10.3.3.2; hardware = c; }
 interface:d = {ip = 10.5.5.1; hardware = d; bind_nat = b; }
}
network:d = { ip = 10.5.5.0/24; }
service:s1 = {
 user = network:a;
 permit src = user; dst = host:b10; prt = tcp 80;
}
service:s2 = {
 user = network:d;
 permit src = user; dst = network:c; prt = tcp 81;
}
=END=
=OUTPUT=
-- r1
ip access-list extended a_in
 permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.10 eq 80
 deny ip any any
--
ip access-list extended t_in
 permit tcp host 10.2.2.10 10.1.1.0 0.0.0.255 established
 deny ip any any
-- r2
! t_in
access-list t_in extended permit ip 10.1.1.0 255.255.255.0 10.2.2.0 255.255.255.0
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
-- r3
! d_in
access-list d_in extended permit tcp 10.5.5.0 255.255.255.0 10.3.3.0 255.255.255.0 eq 81
access-list d_in extended deny ip any4 any4
access-group d_in in interface d
=END=

############################################################
=TITLE=Optimize secondary if other router filters original address
# Still apply secondary optimization at r1, because r2 filters
# original address.
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { ip = 10.9.9.4/30; dynamic; }
 host:h1 = { ip = 10.1.1.4; }
}
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24;}
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = n1; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- r2
ip access-list extended n2_in
 deny ip any host 10.1.3.2
 permit tcp host 10.1.1.4 10.1.3.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=No secondary optimization with primary router
# No secondary optimization at r1, because detailed filtering at r2 is
# disabled by primary r3. r3 only sees NAT address.
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { ip = 10.9.9.4/30; dynamic; }
 host:h1 = { ip = 10.1.1.4; }
}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = n1; }
}
router:r3 = {
 model = ASA;
 managed = primary;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.4 10.1.4.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- r2
ip access-list extended n2_in
 permit ip 10.1.1.0 0.0.0.255 10.1.4.0 0.0.0.255
 deny ip any any
-- r3
! n3_in
access-list n3_in extended permit tcp 10.9.9.4 255.255.255.252 10.1.4.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=No secondary optimization with other filter in loop
# No secondary optimization at r1, because detailed filtering occurs
# in loop, which isn't fully analyzed.
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { ip = 10.9.9.4/30; dynamic; }
 host:h1 = { ip = 10.1.1.4; }
}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = 10.1.2.2; virtual = { ip = 10.1.2.9; } hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = n1; }
}
router:r3 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = 10.1.2.3; virtual = { ip = 10.1.2.9; } hardware = n2; }
 interface:n3 = { ip = 10.1.3.3; hardware = n3; bind_nat = n1; }
}
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.4 10.1.3.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=No secondary optimization with primary in loop
# No secondary optimization at r1, because primary router is located
# in loop, which isn't fully analyzed.
=TEMPL=input
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { ip = 10.9.9.4/30; dynamic; }
 host:h1 = { ip = 10.1.1.4; }
}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed{{.}};
 routing = manual;
 interface:n2 = { ip = 10.1.2.2;  hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r3 = {
 model = ASA;
 managed = primary;
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
 interface:n4 = { ip = 10.1.4.3; hardware = n4; bind_nat = n1; }
}
router:r4 = {
 model = ASA;
 managed;
 interface:n3 = { ip = 10.1.3.4; hardware = n3; }
 interface:n4 = { ip = 10.1.4.4; hardware = n4; bind_nat = n1; }
}
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=INPUT=[[input ""]]
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.4 10.1.4.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Optimize secondary with full filter
=INPUT=[[input "= full"]]
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=No route for supernet for unstable subnet relation
=INPUT=
network:n1 = {ip = 10.1.1.0/24;}
router:r1 = {
 interface:n1;
 interface:n1sub = { ip = 10.1.1.130; }
}
network:n1sub = {
 ip = 10.1.1.128/25;
 nat:N = { ip = 10.9.9.9/32; dynamic; }
 subnet_of = network:n1;
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1sub = { ip = 10.1.1.129; hardware = outside; }
 interface:n2    = { ip = 10.1.2.1;   hardware = inside; bind_nat = N; }
}
network:n2 = { ip = 10.1.2.0/24;}
router:r3 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.1.2.2; hardware = inside; }
 interface:n3 = { ip = 10.1.3.2; hardware = outside; routing = dynamic; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = network:n1sub;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
--r3
! [ Routing ]
route inside 10.9.9.9 255.255.255.255 10.1.2.1
--
! inside_in
access-list inside_in extended permit ip host 10.9.9.9 10.1.3.0 255.255.255.0
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Inherit NAT from overlapping areas and zones
=TEMPL=input
area:A = {
 border = interface:r1.a1;
 {{.d1}}
}
area:B = {
 border = interface:r2.b1;
 nat:d = { {{.n2}} }
}
any:a2 = {
 link = network:a2;
 nat:d = { identity; }
}
network:a1 = { ip = 10.5.5.0/24; }
network:a2 = { ip = 10.4.4.0/24; }
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:a1 = { ip = 10.5.5.1; hardware = a1; }
 interface:a2 = { ip = 10.4.4.1; hardware = a2; }
 interface:b1 = { ip = 10.2.2.1; hardware = b1; }
}
network:b2 = { ip = 10.3.3.0/24; }
router:u = { interface:b2; interface:b1; }
network:b1 = { ip = 10.2.2.0/24; nat:d = { identity; } }
router:r2 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:b1 = { ip = 10.2.2.2; hardware = b1; }
 interface:X = { ip = 10.1.1.2; hardware = X; bind_nat = d; }
}
network:X = { ip = 10.1.1.0/24; }
service:test = {
 user = network:a1, network:a2, network:b1, network:b2;
 permit src = network:X; dst = user; prt = tcp 80;
}
=END=
=INPUT=
[[input
d1: "nat:d = { ip = 10.99.99.8/30; dynamic; }"
n2: "ip = 10.77.77.0/30; dynamic;"
]]
=OUTPUT=
--r1
! b1_in
object-group network g0
 network-object 10.4.4.0 255.255.255.0
 network-object 10.5.5.0 255.255.255.0
access-list b1_in extended permit tcp 10.1.1.0 255.255.255.0 object-group g0 eq 80
access-list b1_in extended deny ip any4 any4
access-group b1_in in interface b1
--r2
ip access-list extended X_in
 deny ip any host 10.2.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.99.99.8 0.0.0.3 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.4.4.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.77.77.0 0.0.0.3 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Use hidden NAT from overlapping areas
=INPUT=[[input {d1: "", n2: hidden;}]]
=ERROR=
Error: network:a1 is hidden by nat:d in rule
 permit src=network:X; dst=network:a1; prt=tcp 80; of service:test
Error: network:b2 is hidden by nat:d in rule
 permit src=network:X; dst=network:b2; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Inherit NAT from supernets inside zone
=INPUT=
# NAT is inherited to all 10.* subnets by default.
network:n   = {
 ip = 10.0.0.0/8;
 nat:d = { ip = 11.0.0.0/8; }
 has_subnets;
}
# NAT is enabled for this network and
# inherited to 10.1.1.0/24 and 10.1.2.0/24
network:n1 = {
 ip = 10.1.0.0/16;
 nat:d = { ip = 11.17.0.0/16; }
 has_subnets;
}
network:n0 = { ip = 10.0.0.0/16; }
network:n11 = { ip = 10.1.1.0/24; }
network:n3  = { ip = 10.3.0.0/16; host:h3 = { ip = 10.3.3.10; } }
router:u = {
 interface:n;
 interface:n0;
 interface:n1;
 interface:n11;
 interface:n3;
 interface:t1;
}
network:t1 = { ip = 10.9.1.0/24; }
router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
 interface:X = { ip = 10.2.1.2; hardware = X; bind_nat = d; }
}
network:X = { ip = 10.2.1.0/24; subnet_of = network:n; }
service:s1 = {
 user = network:X;
# NAT to 11.0.0.0/8
 permit src = user; dst = network:n; prt = tcp 80;
# NAT to 11.17.0.0
 permit src = user; dst = network:n1; prt = tcp 81;
# inherit from network:n1, 11.17.1.0
 permit src = user; dst = network:n11; prt = tcp 82;
# inherit from network:n, 11.17.3.10
 permit src = user; dst = host:h3; prt = tcp 83;
# inherit from network:n, 11.0.0.0/16
 permit src = user; dst = network:n0; prt = tcp 84;
# inherit from network:n, 11.9.1.0/24
 permit src = user; dst = network:t1; prt = tcp 85;
}
=END=
=OUTPUT=
--r1
ip access-list extended X_in
 deny ip any host 11.9.1.1
 permit tcp 10.2.1.0 0.0.0.255 11.0.0.0 0.255.255.255 eq 80
 permit tcp 10.2.1.0 0.0.0.255 11.17.0.0 0.0.255.255 eq 81
 permit tcp 10.2.1.0 0.0.0.255 11.17.1.0 0.0.0.255 eq 82
 permit tcp 10.2.1.0 0.0.0.255 host 11.3.3.10 eq 83
 permit tcp 10.2.1.0 0.0.0.255 11.0.0.0 0.0.255.255 eq 84
 permit tcp 10.2.1.0 0.0.0.255 11.9.1.0 0.0.0.255 eq 85
 deny ip any any
=END=

############################################################
=TITLE=Inherit NAT from aggregates inside zone
=INPUT=
# NAT is inherited to 10.1.1.0/24;
any:a1-23 = {
 ip = 10.1.0.0/23;
 link = network:n1;
 nat:n = { ip = 10.8.8.0/23; }
}
any:a1-24 = {
 ip = 10.1.1.0/24;
 link = network:n1;
 nat:n = { ip = 10.9.9.0/24; }
}
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.64/26; }
router:u1 = {
 interface:n0;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.65; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:n1 = {
 user = network:n0, network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--r1
ip access-list extended n2_in
 deny ip any host 10.9.9.65
 permit tcp 10.1.2.0 0.0.0.255 10.8.8.0 0.0.0.255 eq 80
 permit tcp 10.1.2.0 0.0.0.255 10.9.9.64 0.0.0.63 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Warn on useless inherited NAT (1)
=INPUT=
area:x = {
 border = interface:filter.x;
 nat:C = { ip = 10.8.8.0/24; dynamic; }
 nat:D = { hidden; }
}
any:x = {
 link = network:x;
 nat:C = { ip = 10.8.8.0/24; dynamic; }
}
network:x =  {
 ip = 10.0.0.0/24;
 nat:C = { ip = 10.8.8.0/24; dynamic; }
 nat:D = { hidden; }
}
router:filter = {
 managed;
 model = ASA;
 interface:x = { ip = 10.0.0.2; hardware = inside; }
 interface:y = { ip = 10.8.3.1; hardware = outside; bind_nat = C; }
}
network:y = { ip = 10.8.3.0/24; }
=END=
=WARNING=
Warning: Useless nat:C of any:x,
 it was already inherited from area:x
Warning: Useless nat:C of network:x,
 it was already inherited from any:x
Warning: Useless nat:D of network:x,
 it was already inherited from area:x
Warning: nat:D is defined, but not bound to any interface
=END=

############################################################
=TITLE=Warn on useless inherited NAT (2)
=INPUT=
# Don't warn, if other NAT is intermixed.
area:a12 = { border = interface:r2.n2; nat:n = { hidden; } }
area:a1  = { border = interface:r1.n1; nat:n = { identity; } }
any:n1 = { link = network:n1; nat:n = { hidden; } }
network:n1 = { ip = 10.1.1.0/24; nat:n = { identity; } }
network:n1a = { ip = 10.1.1.64/26; nat:n = { hidden; } subnet_of = network:n1; }
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
# Warn on subnet.
any:n2 = { link = network:n2; }
network:n2 = { ip = 10.1.2.0/24; nat:n = { hidden; } }
network:n2a = { ip = 10.1.2.64/26; nat:n = { hidden; } subnet_of = network:n2; }
router:u2 = {
 interface:n2a;
 interface:n2;
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n; }
}
network:n3 = { ip = 10.1.3.0/24; }
=END=
=WARNING=
Warning: Useless nat:n of network:n2,
 it was already inherited from area:a12
Warning: Useless nat:n of network:n2a,
 it was already inherited from network:n2
=END=

############################################################
=TITLE=Useless inheritance from multiple areas
=INPUT=
area:a1234 = {
 inclusive_border = interface:r1.n5;
 nat:n = { hidden; }
}
area:a123 = {
 inclusive_border = interface:r1.n4, interface:r1.n5;
}
area:a12 = {
 inclusive_border = interface:r1.n3, interface:r1.n4, interface:r1.n5;
 nat:n = { hidden; }
}
area:a1  = {
 border = interface:r1.n1;
 nat:n = { hidden; }
}
any:n1 = { link = network:n1; nat:n = { hidden; } }
any:n2 = { link = network:n2; nat:n = { identity; } }
network:n1 = { ip = 10.1.1.0/24; nat:n = { hidden; } }
network:n2 = { ip = 10.1.2.0/24; nat:n = { identity; } }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; bind_nat = n; }
}
=END=
=WARNING=
Warning: Useless nat:n of any:n1,
 it was already inherited from area:a1
Warning: Useless nat:n of area:a1,
 it was already inherited from area:a12
Warning: Useless nat:n of area:a12,
 it was already inherited from area:a1234
Warning: Useless nat:n of network:n1,
 it was already inherited from any:n1
Warning: Useless nat:n of network:n2,
 it was already inherited from any:n2
=END=

############################################################
=TITLE=No useless NAT in zone cluster
# Warning would be shown, if NAT map was shared between zones of cluster.
=INPUT=
area:a12 = { border = interface:r1.n2; nat:h1 = { hidden; } }
any:n1 = { link = network:n1; nat:h2 = { hidden; } }
network:n1 = { ip = 10.1.1.0/24; nat:n = { ip = 10.9.9.0/24; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:u = {
 interface:n1;
 interface:n2 = { bind_nat = n; }
}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = h2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = h1; }
}
=END=
=WARNING=NONE

############################################################
=TITLE=Inherit NAT to all networks in zone cluster
=INPUT=
any:n2 = { ip = 10.1.0.0/16; link = network:n2; nat:h = { hidden; } }
network:n1 = { ip = 10.1.1.0/24; nat:h = { hidden; } }
network:n2 = { ip = 10.2.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2= { ip = 10.2.2.2; }
 interface:n3 = { bind_nat = h; }
}
=END=
=WARNING=
Warning: Useless nat:h of network:n1,
 it was already inherited from any:n2
=END=

############################################################
=TITLE=Inherit NAT from network to subnet in zone cluster
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:h = { hidden; } }
network:n2 = { ip = 10.1.1.0/26; nat:h = { hidden; } subnet_of = network:n1; }
network:n3 = { ip = 10.3.3.0/24; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.65; hardware = n1; }
 interface:n2 = { ip = 10.1.1.1; hardware = n2; }
}
router:r2 = {
 interface:n2= { ip = 10.1.1.2; }
 interface:n3 = { bind_nat = h; }
}
=END=
=WARNING=
Warning: Useless nat:h of network:n2,
 it was already inherited from network:n1
=END=

############################################################
=TITLE=Useless identity NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n = { identity; } }
network:n1a = { ip = 10.1.1.64/26; nat:n = { hidden; } subnet_of = network:n1; }
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=
=WARNING=
Warning: Useless identity nat:n of network:n1
=END=

############################################################
=TITLE=Inherit static NAT from area and zone
=INPUT=
network:n0 = { ip = 192.0.0.0/8; }
any:a1 = { link = network:n1; nat:a1 = { ip = 11.0.0.0/8; } }
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n0 = { ip = 192.0.0.1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 172.17.2.1; hardware = n2; bind_nat = a1; }
}
network:n2 = { ip = 172.17.2.0/24; }
router:r2 = {
 interface:n2;
 interface:n2a;
}
network:n2a = { ip = 172.17.2.64/26; subnet_of = network:n2; }
area:a2 = {
 border = interface:r1.n2;
 nat:a2 = { ip = 192.168.0.0/16; subnet_of = network:n0; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2a; prt = tcp 81;
}
=END=
=OUTPUT=
-- r1
ip access-list extended n1_in
 deny ip any host 192.168.2.1
 permit tcp 10.1.1.0 0.0.0.255 192.168.2.0 0.0.0.255 eq 80
 permit tcp 10.1.1.0 0.0.0.255 192.168.2.64 0.0.0.63 eq 81
 deny ip any any
--
ip access-list extended n2_in
 permit tcp 172.17.2.0 0.0.0.255 11.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Inherit dynamic NAT to networks in subnet_of relation
=INPUT=
network:n0 = { ip = 192.168.0.0/16; }
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n0 = { ip = 192.168.0.1; hardware = n0; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n0 = { ip = 192.168.0.2; hardware = n0; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r0 = {
 interface:n2a;
 interface:n2;
}
network:n2a = { ip = 10.1.2.64/26; subnet_of = network:n2; }
area:a2 = {
 border = interface:r2.n2;
 nat:a2 = { ip = 192.168.1.8/29; dynamic; subnet_of = network:n0; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2a; prt = tcp 81;
}
=END=
=OUTPUT=
-- r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 192.168.1.8 0.0.0.7 range 80 81
 deny ip any any
--
ip access-list extended n0_in
 permit tcp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Duplicate IP from inherited static NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 172.17.2.1; hardware = n2; }
}
network:n2 = { ip = 172.17.2.0/24; }
router:r2 = {
 interface:n2;
 interface:n2a;
}
network:n2a = { ip = 172.18.2.0/24; }
area:a2 = { border = interface:r1.n2; nat:a2 = { ip = 192.168.0.0/16; } }
=END=
=ERROR=
Error: nat:a2 of network:n2a and nat:a2 of network:n2 have identical IP/mask
 in nat_domain:[network:n1]
=END=

############################################################
=TITLE=Inherited static NAT network must be larger
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 172.17.2.1; hardware = n2; }
}
network:n2 = { ip = 172.17.2.0/24; }
area:a2 = { border = interface:r1.n2; nat:a2 = { ip = 192.168.1.128/25; } }
=END=
=ERROR=
Error: Must not inherit nat:a2 of area:a2 at network:n2
 because NAT network must be larger than translated network
=END=

############################################################
=TITLE=Interface with dynamic NAT as destination
# Should ignore error in policy_distribution_point,
# because other error message is shown.
=INPUT=
network:n2 = { ip = 10.1.2.0/24; nat:dyn = { ip = 10.9.9.9/32; dynamic; }}
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:asa1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:h3;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = dyn; }
}
service:s = {
 user = interface:asa1.n2;
 permit src = host:h3; dst = user; prt = tcp 22;
}
=END=
=ERROR=
Error: interface:asa1.n2 needs static translation for nat:dyn at router:asa2 to be valid in rule
 permit src=host:h3; dst=interface:asa1.n2; prt=tcp 22; of service:s
=END=

############################################################
=TITLE=Interface with dynamic NAT as destination in reversed rule
=INPUT=
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS;
 interface:a = {ip = 10.1.1.1; hardware = E1; bind_nat = b;}
 interface:t = {ip = 10.4.4.1; hardware = E2;}
}
network:t = { ip = 10.4.4.0/30; }
router:r2 = {
 interface:t = {ip = 10.4.4.2;}
 interface:b = {ip = 10.2.2.1;}
}
network:b  = { ip = 10.2.2.0/24; nat:b = { ip = 10.9.9.4/30; dynamic; } }
service:test = {
 user = interface:r2.b;
 permit src = user; dst = network:a; prt = udp 445;
}
=END=
=ERROR=
Error: interface:r2.b needs static translation for nat:b at router:r1 to be valid in reversed rule for
 permit src=interface:r2.b; dst=network:a; prt=udp 445; of service:test
=END=

############################################################
=TITLE=Combined hidden and dynamic NAT error in destination aggregate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:d1 = { ip = 1.1.1.1/32; dynamic; }
 host:h1 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; nat:h2 = { hidden; } }
network:n3 = { ip = 10.1.3.0/24; nat:h3 = { hidden; } }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = d1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r3 = {
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; bind_nat = h2; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; bind_nat = h3; }
}
service:s1 = {
 user = host:h1, network:n2, network:n3;
 permit src = user; dst = any:[network:n4]; prt = tcp 80;
}
=END=
# Duplicate error messages from zone cluster.
=ERROR=
Error: host:h1 needs static translation for nat:d1 at router:r2 to be valid in rule
 permit src=host:h1; dst=any:[network:n4]; prt=tcp 80; of service:s1
Error: host:h1 needs static translation for nat:d1 at router:r2 to be valid in rule
 permit src=host:h1; dst=any:[network:n4]; prt=tcp 80; of service:s1
Error: network:n2 is hidden by nat:h2 in rule
 permit src=network:n2; dst=any:[network:n4]; prt=tcp 80; of service:s1
Error: host:h1 needs static translation for nat:d1 at router:r2 to be valid in rule
 permit src=host:h1; dst=any:[network:n4]; prt=tcp 80; of service:s1
Error: network:n3 is hidden by nat:h3 in rule
 permit src=network:n3; dst=any:[network:n4]; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Multiple rules and objects with dynamic NAT
# Check correct caching of results.
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { ip = 1.9.2.0/27; dynamic; }
 host:h13 = { ip = 10.1.1.3; }
 host:h14 = { ip = 10.1.1.4; }
 host:h15 = { ip = 10.1.1.5; nat:n1 = { ip = 1.9.2.25; } }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = {
 ip = 10.1.4.0/24;
 nat:n4 = { ip = 1.9.4.0/27; dynamic; }
 host:h43 = { ip = 10.1.4.3; }
 host:h44 = { ip = 10.1.4.4; }
}

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; bind_nat = n1;
 }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 interface:n3 = { ip = 10.1.3.2; bind_nat = n4; }
 interface:n4 = { ip = 10.1.4.1; nat:n4 = { ip = 1.9.4.21; } }
}
service:s1 = {
 user = host:h15;
 permit src = user; dst = interface:r3.n4; prt = tcp 81;
}
service:s2 = {
 user = host:h13;
 permit src = user; dst = host:h43; prt = tcp 82;
}
service:s3 = {
 user = host:h13;
 permit src = user; dst = host:h43; prt = tcp 83;
}
service:s4 = {
 user = host:h14;
 permit src = user; dst = host:h44; prt = tcp 84;
}
=END=
=ERROR=
Error: host:h13 needs static translation for nat:n1 at router:r2 to be valid in rule
 permit src=host:h13; dst=host:h43; prt=tcp 82; of service:s2
Error: host:h43 needs static translation for nat:n4 at router:r2 to be valid in rule
 permit src=host:h13; dst=host:h43; prt=tcp 82; of service:s2
Error: host:h14 needs static translation for nat:n1 at router:r2 to be valid in rule
 permit src=host:h14; dst=host:h44; prt=tcp 84; of service:s4
Error: host:h44 needs static translation for nat:n4 at router:r2 to be valid in rule
 permit src=host:h14; dst=host:h44; prt=tcp 84; of service:s4
=END=

############################################################
=TITLE=Interface with dynamic NAT applied at same device
=INPUT=
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = 10.1.1.1; hardware = a;}
 interface:t = {ip = 10.4.4.1; hardware = t;}
}
network:t = { ip = 10.4.4.0/30; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t = {ip = 10.4.4.2; hardware = t; bind_nat = b;}
 interface:b = {ip = 10.2.2.1; hardware = b;}
}
network:b  = { ip = 10.2.2.0/24; nat:b = { ip = 10.9.9.4/30; dynamic; } }
service:test = {
 user = network:a;
 permit src = user; dst = interface:r2.b; prt = tcp 80;
}
=END=
=ERROR=
Error: interface:r2.b needs static translation for nat:b at router:r2 to be valid in rule
 permit src=network:a; dst=interface:r2.b; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Interface with dynamic NAT as source of managed device
# No need to check interface of managed device.
=INPUT=
network:n1 =  {
 ip = 10.1.1.0/24;
 nat:x = { ip = 10.8.8.0/28; dynamic; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.1.9.1; hardware = t1; bind_nat = x; }
}
network:t1 = { ip = 10.1.9.0/24; }
router:filter = {
 interface:t1 = { ip = 10.1.9.2; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:s = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2; prt = udp 123;
}
=WARNING=NONE

############################################################
=TITLE=Grouped NAT tags must only be used grouped
# n1 and n2 are translated at interface:r1.t, thus nat1 is active in
# network:t. At interface:r2.k only n1 is translated though, leading
# to ambiguity on which nat tag is active in network k.
=TEMPL=input
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:t2 = { ip = 10.9.8.0/24; }
}
network:n2 = { ip = 10.1.2.0/24; {{.}} = { ip = 10.9.9.0/24; }}
router:r1 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t  = { ip = 10.2.3.1; hardware = t; bind_nat = t1; }
}
network:t = { ip = 10.2.3.0/24; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t  = { ip = 10.2.3.2; hardware = t; }
 interface:k = { ip = 10.2.2.2; hardware = k; bind_nat = t2; }
}
network:k = { ip = 10.2.2.0/24; }
=END=
=INPUT=[[input nat:t1]]
=ERROR=
Error: Invalid transition from nat:t1 to nat:t2 at router:r2.
 Reason: Both NAT tags are used grouped at network:n1
 but nat:t2 is missing at network:n2
=END=

############################################################
=TITLE=Mixed grouped and single NAT tag ok
# In this case, using ungrouped NAT tag at network:n2 isn't
# ambiguous, because t2 isn't changed again.
=INPUT=[[input nat:t2]]
=WARNING=NONE

############################################################
=TITLE=Grouped NAT tags with additional hidden allowed
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:h1 = { hidden; }
 nat:h3 = { hidden; }
}
network:n3 = {
 ip = 10.1.3.0/24;
 nat:t3 = { ip = 10.9.3.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n4 = {
 ip = 10.1.4.0/24;
 nat:t4a = { ip = 10.8.1.0/24; }
 nat:t4b = { ip = 10.8.2.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = t4a; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = t4b; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = h3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:t  = { ip = 10.2.3.1; hardware = t; bind_nat = t1, t3; }
}
network:t = { ip = 10.2.3.0/24; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t  = { ip = 10.2.3.2; hardware = t; }
 interface:k1 = { ip = 10.2.1.2; hardware = k1; bind_nat = h1; }
 interface:k2 = { ip = 10.2.2.2; hardware = k2; bind_nat = h2; }
}
network:k1 = { ip = 10.2.1.0/24; }
network:k2 = { ip = 10.2.2.0/24; }
=END=
=WARNING=NONE

############################################################
=TITLE=Combined single hidden allowed
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h1 = { hidden; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n3 = {
 ip = 10.1.3.0/24;
 nat:t3 = { ip = 10.9.3.0/24; }
 nat:h2 = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t  = { ip = 10.2.0.1; hardware = t; bind_nat = t1, t3; }
}
network:t = { ip = 10.2.0.0/24; }
router:r2 =  {
 interface:t;
 interface:k1 = { bind_nat = h1; }
 interface:k2 = { bind_nat = h2; }
}
network:k1 = { ip = 10.2.1.0/24; }
network:k2 = { ip = 10.2.2.0/24; }
=END=
=WARNING=NONE

############################################################
=TITLE=Grouped NAT tags with invalid hidden
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:t1 = { ip = 10.9.2.0/24; }
}
network:n3 = {
 ip = 10.1.3.0/24;
 nat:h1 = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t1 = { ip = 10.2.1.1; hardware = t; bind_nat = t1; }
}
network:t1 = { ip = 10.2.1.0/24; }
# t1 active
router:r2 = {
 interface:t1;
 interface:k1 = { bind_nat = h1; }
 interface:k2 = { bind_nat = h2; }
}
# h1 active
# t1 ambiguous: still active for n2, no longer active for n1
network:k1 = { ip = 10.2.3.0/24; }
# h2 active
# t1 ambiguous: still active for n2, no longer active for n1
network:k2 = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Invalid transition from nat:t1 to nat:h1 at router:r2.
 Reason: Both NAT tags are used grouped at network:n1
 but nat:h1 is missing at network:n2
Error: Invalid transition from nat:t1 to nat:h2 at router:r2.
 Reason: Both NAT tags are used grouped at network:n1
 but nat:h2 is missing at network:n2
=END=

############################################################
=TITLE=Grouped NAT tags with invalid hidden (2)
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h  = { hidden; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:t2 = { ip = 10.9.2.0/24; }
 nat:h  = { hidden; }
}
network:n3 = {
 ip = 10.1.3.0/24;
 nat:t1 = { ip = 10.9.3.0/24; }
 nat:t2 = { ip = 10.9.4.0/24; }
 nat:h  = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:t1 = { ip = 10.2.1.1; hardware = t; bind_nat = t1; }
}
# t1 active
network:t1 = { ip = 10.2.1.0/24; }
router:r2 = {
 interface:t1;
 interface:t2 = { bind_nat = t2; }
}
# t2 active
# t1 ambiguous: still active for n1, but no longer active for n3
network:t2 = { ip = 10.2.2.0/24; }
router:r3 = {
 interface:t2;
 interface:k = { bind_nat = h; }
}
network:k = { ip = 10.2.3.0/24; }
=END=
=ERROR=
Error: Invalid transition from nat:t1 to nat:t2 at router:r2.
 Reason: Both NAT tags are used grouped at network:n3
 but nat:t2 is missing at network:n1
=END=

############################################################
=TITLE=Grouped NAT tags from different paths
=INPUT=
network:a = {
 ip = 10.1.1.0/24;
 nat:a1 = { ip = 10.2.1.0/24; }
 nat:a2 = { ip = 10.2.2.0/24; }
}
router:r11 = {
 interface:a;
 interface:t1 = { bind_nat = a1; }
}
network:t1 = {ip = 10.3.3.0/30;}
router:r12 = {
 interface:t1;
 interface:b = { bind_nat = a2; }
}
router:r21 = {
 interface:a;
 interface:t2 = { bind_nat = a2; }
}
network:t2 = {ip = 10.3.3.4/30;}
router:r22 = {
 interface:t2;
 interface:b = { bind_nat = a1; }
}
network:b = {ip = 10.9.9.0/24;}
=END=
=ERROR=
Error: Grouped NAT tags 'a1, a2' of network:a must not both be active at
 - interface:r12.b
 - interface:r22.b
=END=

############################################################
=TITLE=Groupd NAT tags with multiple NAT domains
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1a = { ip = 10.8.1.0/24; }
 nat:n1b = { ip = 10.9.1.0/24; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; nat:n4 = { ip = 10.9.4.0/24; } }
network:n5 = { ip = 10.1.5.0/24; nat:n5 = { ip = 10.9.5.0/24; } }
network:n6 = { ip = 10.1.6.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24;
 nat:n1a = { ip = 10.8.8.0/24; }
 nat:n1b = { ip = 10.9.8.0/24; }
}
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = n1a; }
}
router:r2 = {
 interface:n1;
 interface:n3 = { bind_nat = n1b; }
}
router:r3 = {
 interface:n2;
 interface:n4 = { bind_nat = n1b; }
}
router:r4 = {
 interface:n3;
 interface:n5 = { bind_nat = n1a; }
}
router:r5 = {
 interface:n4;
 interface:n6 = { bind_nat = n4, n5; }
}
router:r6 = {
 interface:n5;
 interface:n6 = { bind_nat = n4, n5; }
}
router:r7 = {
 interface:n6 = { bind_nat = n1a; }
 interface:n7;
}
router:r8 = {
 interface:n7 = { bind_nat = n1b; }
 interface:n8;
}
=ERROR=
Error: Grouped NAT tags 'n1a, n1b' of network:n1 must not both be active at
 - interface:r3.n4
 - interface:r4.n5
 - interface:r7.n6
=END=

############################################################
=TITLE=Must not apply same NAT tag twice
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n = { ip = 10.9.9.0/24; } }
router:r1 = {
 interface:n1;
 interface:tr = { bind_nat = n; }
}
network:tr = { ip = 10.7.7.0/24; }
router:r2 = {
 interface:tr;
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Incomplete 'bind_nat = n' at
 - interface:r1.tr
 Possibly 'bind_nat = n' is missing at these interfaces:
 - interface:r2.tr
=END=

############################################################
=TITLE=Prevent NAT from dynamic to static
=INPUT=
network:U1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.8.8.0/23; dynamic; }
 nat:t2 = { ip = 10.9.9.0/24; }
}
router:R0 = {
 interface:U1;
 interface:T = { ip = 10.3.3.17; bind_nat = t1;}
}
network:T = { ip = 10.3.3.16/29; }
router:R2 = {
 managed;
 model = ASA;
 interface:T = { ip = 10.3.3.18; hardware = T;}
 interface:K = { ip = 10.2.2.1; hardware = K; bind_nat = t2; }
}
network:K = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Must not change dynamic nat:t1 to static using nat:t2
 for network:U1 at router:R2
=END=

############################################################
=TITLE=Prevent NAT from hidden back to IP
=INPUT=
network:U1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { hidden; }
 nat:t2 = { ip = 10.9.9.0/24; }
}
router:R0 = {
 interface:U1;
 interface:T = { ip = 10.3.3.17; bind_nat = t1;}
}
network:T = { ip = 10.3.3.16/29; }
router:R2 = {
 managed;
 model = ASA;
 interface:T = { ip = 10.3.3.18; hardware = T;}
 interface:K = { ip = 10.2.2.1; hardware = K; bind_nat = t2; }
}
network:K = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Must not change hidden nat:t1 using nat:t2
 for network:U1 at router:R2
=END=

############################################################
=TITLE=Prevent multiple hidden NAT
=INPUT=
network:U1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { hidden; }
 nat:t2 = { hidden; }
}
router:R0 = {
 interface:U1;
 interface:T = { ip = 10.3.3.17; bind_nat = t1;}
}
network:T = { ip = 10.3.3.16/29; }
router:R2 = {
 managed;
 model = ASA;
 interface:T = { ip = 10.3.3.18; hardware = T;}
 interface:K = { ip = 10.2.2.1; hardware = K; bind_nat = t2; }
}
network:K = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Must not change hidden nat:t1 using nat:t2
 for network:U1 at router:R2
=END=

############################################################
=TITLE=Two NAT tags share single hidden NAT tag
=INPUT=
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 interface:n0 = { bind_nat = F; }
 interface:n1;
}
router:asa = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = h; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = P; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
}
network:n3 = {
 ip = 10.1.3.0/24;
 nat:h = { hidden; }
 nat:P = { ip = 10.2.3.0/24; }
}
network:n4 = {
 ip = 10.1.4.0/24;
 nat:h = { hidden; }
 nat:F = { ip = 10.2.4.0/24; }
}
=END=
=ERROR=
Error: Must not change hidden nat:h using nat:F
 for network:n4 at router:r1
=END=

############################################################
=TITLE=Partially hidden in destination zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:h = { hidden; } }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:t1 = { ip = 10.5.5.164; hardware = inside; bind_nat = h; }
}
network:t1 = { ip = 10.5.5.160/28; }
router:u1 = {
 interface:t1 = { bind_nat = h; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:test = {
 user =	network:n1;
 permit src = user; dst = network:n2; prt = proto 50;
}
=END=
=ERROR=
Error: Must not apply hidden NAT 'h' to src of rule
 permit src=network:n1; dst=network:n2; prt=proto 50; of service:test
 NAT 'h' is active at
 - interface:r1.t1
 - interface:u1.t1
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Ignore hidden network in static routes
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  routing = OSPF;
  hardware = outside;
 }
 interface:t1 = { ip = 10.5.5.164; hardware = inside; }
}
network:t1 = { ip = 10.5.5.160/28; }
router:u1 = {
 interface:t1 = { ip = 10.5.5.161;  bind_nat = h; }
 interface:n2;
 interface:n3;
}
network:n2 = { ip = 10.1.2.0/24; nat:h = { hidden; } }
network:n3 = { ip = 10.1.3.0/24; }
any:10_1   = { ip = 10.1.0.0/16; link = network:n2; }
service:test = {
 user =	network:n1;
 permit src = user; dst = any:10_1; prt = proto 50;
}
=END=
=OUTPUT=
-- r1
! [ Routing ]
route inside 10.1.3.0 255.255.255.0 10.5.5.161
=END=

############################################################
=TITLE=Ignore hidden network in NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  routing = OSPF;
  hardware = outside;
  bind_nat = h;
 }
 interface:t1 = { ip = 10.5.5.164; hardware = inside; }
}
network:t1 = { ip = 10.5.5.160/28; }
router:u1 = {
 interface:t1 = { ip = 10.5.5.161; }
 interface:n2;
 interface:n3;
}
network:n2 = { ip = 10.1.2.0/24; nat:h = { hidden; } }
network:n3 = { ip = 10.1.3.0/24; }
any:10_1   = { ip = 10.1.0.0/16; link = network:n2; }
service:test = {
 user =	network:n1;
 permit src = user; dst = any:10_1; prt = proto 50;
}
=END=
=OUTPUT=
-- r1
! outside_in
access-list outside_in extended permit 50 10.1.1.0 255.255.255.0 10.1.0.0 255.255.0.0
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Mixed hidden and IP NAT in loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 nat:i = { ip = 10.9.1.0/24; }
 nat:h = { hidden; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = i; }
}
router:r2 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = h; }
}
router:r3 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = h; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
pathrestriction:p = interface:r3.n3, interface:r2.n3;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended n2_in
 permit tcp 10.1.2.0 0.0.0.255 10.9.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Traverse hidden NAT domain in loop
=TEMPL=input
network:n1 = {
 ip = 10.1.1.0/24;
 nat:h = { {{.h}} }
}
router:r1 = {
 model = ASA;
 {{.r1}}
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t1 = { ip = 10.5.5.1; hardware = t1; bind_nat = h; }
}
network:t1 = { ip = 10.5.5.0/24; }
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:t1 = { ip = 10.5.5.2; hardware = t1; }
 interface:t2 = { ip = 10.4.4.1; hardware = t2; }
}
network:t2 = { ip = 10.4.4.0/24; }
router:r3 = {
 model = ASA;
 {{.r3}}
 routing = manual;
 interface:t2 = { ip = 10.4.4.2; hardware = t2; bind_nat = h; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/24; }
router:r4 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=INPUT=[[input {h: hidden;, r1: managed;, r3: managed;}]]
=ERROR=
Error: Must not apply hidden NAT 'h' to src of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r1.t1
 - interface:r2.t1
 - interface:r2.t2
 - interface:r3.t2
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Traverse hidden NAT domain in loop, 1x unmanaged bind_nat
=INPUT=[[input {h: hidden;, r1: "", r3: managed;}]]
=ERROR=
Error: Must not apply hidden NAT 'h' to src of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r1.t1
 - interface:r2.t1
 - interface:r2.t2
 - interface:r3.t2
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Traverse hidden NAT domain in loop, 2x unmanaged bind_nat
=INPUT=[[input {h: hidden;, r1: "", r3: ""}]]
=ERROR=
Error: Must not apply hidden NAT 'h' to src of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r1.t1
 - interface:r2.t1
 - interface:r2.t2
 - interface:r3.t2
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Traverse dynamic NAT domain in loop
=INPUT=[[input {h: "ip = 10.9.9.0/24; dynamic;", r1: managed;, r3: managed;}]]
=ERROR=
Error: Must not apply dynamic NAT 'h' to src of rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test
 NAT 'h' is active at
 - interface:r1.t1
 - interface:r2.t1
 - interface:r2.t2
 - interface:r3.t2
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Mixed valid and invalid hidden NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 nat:h = { hidden; }
 nat:d = { ip = 10.9.9.0/27; dynamic; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = d; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = d; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = h; }
}
router:r4 = {
 interface:n4 = { ip = 10.1.4.2; hardware = n4; bind_nat = h; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
pathrestriction:p = interface:r2.n3, interface:r4.n1;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 81;
}
=END=
=ERROR=
Error: Must not apply hidden NAT 'h' to src of rule
 permit src=network:n1; dst=network:n3; prt=tcp 81; of service:s2
 NAT 'h' is active at
 - interface:r3.n4
 - interface:r4.n4
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Mixed valid and invalid dynamic NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 nat:d = { ip = 10.9.9.0/27; dynamic; }
 host:h10 = { ip = 10.1.1.10; nat:d = { ip = 10.9.9.10; } }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat:d = { ip = 10.9.9.1; } }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = d; }
}
router:r4 = {
 interface:n4 = { ip = 10.1.4.2; hardware = n4; bind_nat = d; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; nat:d = { ip = 10.9.9.2; } }
}
pathrestriction:p = interface:r2.n3, interface:r4.n1;

service:s1 = {
 user = network:n3;
 permit src = user; dst = host:h10; prt = tcp 81;
 }
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = tcp 82;
}
service:s3 = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 83;
}
=END=
=ERROR=
Error: Must not apply dynamic NAT 'd' to dst of rule
 permit src=network:n3; dst=network:n1; prt=tcp 83; of service:s3
 NAT 'd' is active at
 - interface:r3.n4
 - interface:r4.n4
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Inconsistent NAT in loop (1)
=INPUT=
network:a = {ip = 10.1.13.0/24; nat:h = { hidden; }}
router:r1 = {
 interface:b = { bind_nat = h; }
 interface:a;
 interface:t;
}
network:t = {ip = 10.3.103.240/30;}
router:r2 = {
 interface:a;
 interface:t;
 interface:b;
}
network:b = {ip = 10.156.5.160/28;}
=END=
=ERROR=
Error: Inconsistent NAT in loop at router:r1:
 nat:(none) vs. nat:h
=END=

############################################################
=TITLE=Inconsistent NAT in loop (2)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:x = { ip = 10.9.3.0/24; } }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n2;
 interface:n4;
}
router:r2 = {
 interface:n1 = { bind_nat = x; }
 interface:n3;
 interface:n2;
}
router:r3 = {
 interface:n1 = { bind_nat = x; }
 interface:n3;
 interface:n4 = { bind_nat = x; }
}
=END=
=ERROR=
Error: Inconsistent NAT in loop at router:r2:
 nat:(none) vs. nat:x
Error: Inconsistent NAT in loop at router:r3:
 nat:(none) vs. nat:x
=END=

############################################################
=TITLE=Check recursive NAT in loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
router:r1 = {
 interface:n1;
 interface:t1 = { bind_nat = n1; }
 interface:t2 = { bind_nat = n2; }
}
network:t1 = { ip = 10.7.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
router:r2 = {
 interface:n2;
 interface:t1;
 interface:t2 = { bind_nat = n2; }
}
network:t2 = { ip = 10.7.2.0/24; }
=END=
=ERROR=
Error: Incomplete 'bind_nat = n1' at
 - interface:r1.t1
 Possibly 'bind_nat = n1' is missing at these interfaces:
 - interface:r2.n2
 - interface:r2.t1
=END=

############################################################
=TITLE=NAT in simple loop ok
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
router:r1 = {
 interface:n1;
 interface:t1 = { bind_nat = n1; }
}
network:t1 = { ip = 10.7.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
router:r2 = {
 interface:n2;
 interface:t1;
 interface:t2;
 interface:t3 = { bind_nat = n2; }
}
network:t2 = { ip = 10.7.2.0/24; }
router:r3 = {
 interface:t2;
 interface:t3 = { bind_nat = n2; }
}
network:t3 = { ip = 10.7.3.0/24; }
=END=
=WARNING=NONE

############################################################
=TITLE=NAT in complex loop ok
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; nat:n4 = { ip = 10.9.4.0/24; } }
network:n5 = { ip = 10.1.5.0/24; nat:n5 = { ip = 10.9.5.0/24; } }
router:r1 = {
 interface:n1 = { bind_nat = n5; }
 interface:n5;
}
router:r2 = {
 interface:n1 = {
  {{.b}}
 }
 interface:n4 = { bind_nat = n2; }
}
router:r3 = {
 interface:n1;
 interface:n2 = { bind_nat = n4; }
 interface:n3 = { bind_nat = n1; }
}
router:r4 = {
 interface:n2 = {
  bind_nat =
   n4,
   n5,
  ;
 }
 interface:n4 = { bind_nat = n2; }
}
router:r5 = {
 interface:n3 = {
  bind_nat =
   n1,
   {{.n}}
  ;
 }
 interface:n4 = { bind_nat = n2; }
}
router:r6 = {
 interface:n4 = { bind_nat = n2; }
 interface:n5;
}
router:r7 = {
 interface:n4 = { bind_nat = n2; }
 interface:n5;
}
=END=
=INPUT=[[input {b: "bind_nat = n5;", n: n5}]]
=WARNING=NONE

############################################################
=TITLE=Complex loop with 1 missing NAT behind domain
=INPUT=[[input {b: "", n: n5}]]
=ERROR=
Error: Incomplete 'bind_nat = n5' at
 - interface:r1.n1
 - interface:r4.n2
 - interface:r5.n3
 Possibly 'bind_nat = n5' is missing at these interfaces:
 - interface:r2.n1
=END=

############################################################
=TITLE=Complex loop with 1 missing NAT behind router
=INPUT=[[input {b: "bind_nat = n5;", n: ""}]]
=ERROR=
Error: Incomplete 'bind_nat = n5' at
 - interface:r1.n1
 - interface:r2.n1
 - interface:r4.n2
 Possibly 'bind_nat = n5' is missing at these interfaces:
 - interface:r3.n1
 - interface:r3.n2
=END=

############################################################
=TITLE=Complex loop with 2 missing NAT
=INPUT=[[input {b: "", n: ""}]]
=ERROR=
Error: Incomplete 'bind_nat = n5' at
 - interface:r1.n1
 - interface:r4.n2
 Possibly 'bind_nat = n5' is missing at these interfaces:
 - interface:r4.n4
 - interface:r6.n4
 - interface:r7.n4
=END=

############################################################
=TITLE=Nested loop with 2 missing NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; nat:n5 = { ip = 10.9.5.0/24; } }
router:r1 = {
 interface:n1 = { bind_nat = n5; }
 interface:n5;
}
router:r2 = {
 interface:n1 = { bind_nat = n5; }
 interface:n2 = { bind_nat = n5; }
 interface:n4 = { bind_nat = n2; }
}
router:r3 = {
 interface:n2; # = { bind_nat = n5; }
 interface:n3 = { bind_nat = n1; }
}
router:r4 = {
 interface:n2; # = { bind_nat = n5; }
 interface:n3 = { bind_nat = n1; }
}
router:r5 = {
 interface:n3 = { bind_nat = n1; }
 interface:n4 = { bind_nat = n2; }
}
router:r6 = {
 interface:n4 = { bind_nat = n2; }
 interface:n5;
}
=END=
=ERROR=
Error: Incomplete 'bind_nat = n5' at
 - interface:r1.n1
 - interface:r2.n1
 - interface:r2.n2
 Possibly 'bind_nat = n5' is missing at these interfaces:
 - interface:r5.n3
=END=

############################################################
=TITLE=Missing NAT with multi NAT tags.
# Ignore paths with corresponding multi NAT tags.
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1a = { ip = 10.9.1.0/25; dynamic; }
 nat:n1b = { ip = 10.9.1.128/25; dynamic; }
}
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; nat:n3 = { ip = 10.9.3.0/24; } }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = n1a, n3; }
}
router:r2 = {
 interface:n2 = { bind_nat = n3; }
 interface:n3;
}
router:r3 = {
 interface:n1;
 interface:n3 = { bind_nat = n1a; }
}
router:r4 = {
 interface:n1;
 interface:n2 = { bind_nat = n3; }
 interface:n4 = { bind_nat = n2; }
}
router:r5 = {
 interface:n4 = { bind_nat = n2; }
 interface:n5;
 interface:n6 = { bind_nat = n1b; }
}
router:r6 = {
 interface:n1;
 interface:n5 = { bind_nat = n1a; }
}
router:r7 = {
 interface:n1;
 interface:n6 = { bind_nat = n1b; }
}
=END=
=ERROR=
Error: Incomplete 'bind_nat = n1a' at
 - interface:r1.n2
 - interface:r3.n3
 - interface:r6.n5
 Possibly 'bind_nat = n1a' is missing at these interfaces:
 - interface:r4.n2
 - interface:r4.n4
=END=

############################################################
=TITLE=Cache path results when finding NAT errors
# For test coverage.
=INPUT=
network:n0 = { ip = 10.1.0.0/24; nat:n0 = { ip = 10.9.0.0/24; } }
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; nat:n3 = { ip = 10.9.3.0/24; } }
network:n4 = { ip = 10.1.4.0/24; nat:n4 = { ip = 10.9.4.0/24; } }
network:n5 = { ip = 10.1.5.0/24; nat:n5 = { ip = 10.9.5.0/24; } }
network:n6 = { ip = 10.1.6.0/24; nat:n6 = { ip = 10.9.6.0/24; } }
network:n7 = { ip = 10.1.7.0/24; nat:n7 = { ip = 10.9.7.0/24; } }
network:n8 = { ip = 10.1.8.0/24; }
router:r1 = {
 interface:n0;
 interface:n1 = { bind_nat = n0; }
 interface:n2 = { bind_nat = n0, n1; }
}
router:r2 = {
 interface:n1;
 interface:n3 = { bind_nat = n2; }
}
router:r3 = {
 interface:n2 = { bind_nat = n1; }
 interface:n3 = { bind_nat = n2; }
 interface:n4 = { bind_nat = n3; }
 interface:n5 = { bind_nat = n4; }
}
router:r4 = {
 interface:n4 = { bind_nat = n3; }
 interface:n6 = { bind_nat = n5; }
 interface:n7 = { bind_nat = n6; }
}
router:r5 = {
 interface:n5 = { bind_nat = n0, n4; }
 interface:n6 = { bind_nat = n5; }
 interface:n8 = { bind_nat = n7; }
}
router:r6 = {
 interface:n6 = { bind_nat = n5; }
 interface:n7 = { bind_nat = n6; }
}
router:r7 = {
 interface:n6 = { bind_nat = n5; }
 interface:n8 = { bind_nat = n7; }
}
=END=
=ERROR=
Error: Incomplete 'bind_nat = n0' at
 - interface:r1.n1
 - interface:r1.n2
 - interface:r5.n5
 Possibly 'bind_nat = n0' is missing at these interfaces:
 - interface:r3.n2
 - interface:r3.n3
 - interface:r3.n5
=END=

############################################################
=TITLE=Incomplete NAT at split router
=INPUT=
network:n0 = { ip = 10.1.0.0/24; nat:h = { hidden; } }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:hx = { hidden; } }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
 interface:n0;
 interface:n2;
 interface:n3;
}
# Router will internally be split into 3 parts (n1)(n2)(n4,n5)
router:r2 = {
 interface:n1 = { bind_nat = hx; }
 interface:n2;
 interface:n4;
 interface:n5;
}
router:r3 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; bind_nat = h; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
pathrestriction:p1 = interface:r2.n2, interface:r3.n3;
=END=
=ERROR=
Error: Incomplete 'bind_nat = hx' at
 - interface:r2.n1
 Possibly 'bind_nat = hx' is missing at these interfaces:
 - interface:r3.n1
=END=

############################################################
=TITLE=ASA uses real IP
=INPUT=
network:intern =  { ip = 10.1.1.0/24; nat:intern = { ip = 2.2.1.0/24; } }
router:filter = {
 managed;
 model = ASA;
 interface:intern = {
  ip = 10.1.1.1;
  hardware = inside;
  bind_nat = extern;
 }
 interface:extern = {
  ip = 2.2.2.1;
  hardware = outside;
  bind_nat = intern;
 }
}
network:extern = { ip = 2.2.2.0/24; nat:extern = { ip = 10.1.2.0/24; } }
service:test = {
 user = network:extern;
 permit src = user;           dst = network:intern; prt = tcp 80;
 permit src = network:intern; dst = user;           prt = tcp 22;
}
=END=
=OUTPUT=
-- filter
! inside_in
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 eq 22
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit tcp 2.2.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA uses real IP, more than 2 effective NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 2.2.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 2.2.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = n2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n1, n2; }
}

service:test = {
 user = network:n2, network:n3;
 permit src = network:n1; dst = user; prt = tcp 80;
 permit src = user; dst = network:n1; prt = tcp 25;
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.254.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 25
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp 10.1.3.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 25
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=ASA uses real IP with multi NAT tags
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1a = { ip = 2.2.1.0/24; }
 nat:n1b = { ip = 3.2.1.0/24; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = {
 ip = 10.1.4.0/24;
 nat:n4a = { ip = 2.2.2.0/24; }
 nat:n4b = { ip = 3.2.2.0/24; }
}

router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = n1a; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n4b; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n1b; }
}
router:r3 = {
 interface:n3 = { bind_nat = n4a; }
 interface:n4;
}
service:test = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 25;
 permit src = network:n4; dst = user; prt = tcp 80;
 }
=END=
=OUTPUT=
-- r2
! n2_in
access-list n2_in extended permit tcp 2.2.1.0 255.255.255.0 2.2.2.0 255.255.255.0 eq 25
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp 2.2.2.0 255.255.255.0 2.2.1.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=ASA uses real IP, in loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 2.2.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 2.2.2.0/24; } }

router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = n2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n1; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; bind_nat = n2; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; bind_nat = n1; }
}
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 25;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 25
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
-- r2
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 25
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=ASA uses real ip, with outgoing ACL
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:intern = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = intern; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = intern; no_in_acl; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = tcp 22;
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.254.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n1_out
access-list n1_out extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 22
access-list n1_out extended deny ip any4 any4
access-group n1_out out interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n2_out
access-list n2_out extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n2_out extended deny ip any4 any4
access-group n2_out out interface n2
=END=

############################################################
=TITLE=ASA uses real IP, 3 interfaces, identical NAT ip, hidden
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:intern = { ip = 2.2.0.0/23; dynamic; } }
network:n2 = { ip = 10.1.2.0/24; nat:intern = { ip = 2.2.0.0/23; dynamic; } }
network:n3 = { ip = 10.1.3.0/24; nat:hide_n3 = { hidden; } }
router:u = {
 interface:n3;
 interface:n1;
}
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = extern; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = extern, hide_n3; }
 interface:t = { ip = 10.9.1.1; hardware = t; bind_nat = intern; }
}
network:t = { ip = 10.9.1.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:t = { ip = 10.9.1.2; hardware = t; }
 interface:extern = { ip = 2.2.2.2; hardware = outside; }
}
network:extern = { ip = 2.2.2.0/24; nat:extern = { ip = 10.2.2.0/24; } }
service:test = {
 user = network:n1, network:n2, network:n3;
 permit src = network:extern; dst = user; prt = tcp 80;
 permit src = user; dst = network:extern; prt = tcp 22;
}
=END=
=OUTPUT=
-- r1
! n1_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.3.0 255.255.255.0
access-list n1_in extended permit tcp object-group g0 2.2.2.0 255.255.255.0 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 2.2.2.0 255.255.255.0 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! t_in
object-group network g1
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.254.0
access-list t_in extended permit tcp 2.2.2.0 255.255.255.0 object-group g1 eq 80
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
-- r2
! t_in
object-group network g0
 network-object 2.2.0.0 255.255.254.0
 network-object 10.1.3.0 255.255.255.0
access-list t_in extended permit tcp object-group g0 2.2.2.0 255.255.255.0 eq 22
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
--
! outside_in
access-list outside_in extended permit tcp 2.2.2.0 255.255.255.0 object-group g0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA uses real IP, 3 interfaces, identical real IP
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:intern1 = { ip = 2.1.1.0/24; } nat:h1 = { hidden; } }
network:n2 = { ip = 10.1.1.0/24; nat:intern2 = { ip = 2.1.2.0/24; } nat:h2 = { hidden; } }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = extern, h2; }
 interface:n2 = { ip = 10.1.1.1; hardware = n2; bind_nat = extern, h1; }
 interface:t = { ip = 10.9.1.1; hardware = t; bind_nat = intern1, intern2; }
}
network:t = { ip = 10.9.1.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:t = { ip = 10.9.1.2; hardware = t; }
 interface:extern = { ip = 2.2.2.2; hardware = outside; }
}
network:extern = { ip = 2.2.2.0/24; nat:extern = { ip = 10.2.2.0/24; } }
service:test = {
 user = network:extern;
 permit src = user; dst = network:n1, network:n2; prt = tcp 80;
 permit src = network:n1, network:n2; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 eq 22
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! t_in
access-list t_in extended permit tcp 2.2.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
-- r2
! t_in
object-group network g0
 network-object 2.1.1.0 255.255.255.0
 network-object 2.1.2.0 255.255.255.0
access-list t_in extended permit tcp object-group g0 2.2.2.0 255.255.255.0 eq 22
access-list t_in extended deny ip any4 any4
access-group t_in in interface t
--
! outside_in
access-list outside_in extended permit tcp 2.2.2.0 255.255.255.0 object-group g0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA uses real IP, with secondary optimization
=INPUT=
network:n1 =  { ip = 10.1.1.0/24; nat:n1 = { ip = 10.2.1.0/24; } }
router:r1 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; bind_nat = n1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:n2 = { ip = 10.2.2.0/24; }
 host:h2 = { ip = 10.1.2.10; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=NAT at loopback network (1)
=TEMPL=input
area:n1 = { inclusive_border = interface:r1.n2; nat:N = { hidden; } }
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:lo = {
  ip = 10.1.9.1;
  hardware = Looback0;
  loopback;
  nat:N = { identity; }
  nat:N2 = { ip = {{.}}; }
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = N, N2; }
}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
service:s1 = {
    user = interface:r1.lo;
    permit src = network:n2; dst = user; prt = tcp 80;
}
=END=
=INPUT=[[input "10.1.99.99"]]
=OUTPUT=
-- r1
ip access-list extended n2_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.99.99 eq 80
 deny ip any any
=END=

############################################################
=TITLE=NAT at loopback network (2)
# NAT to original address.
=INPUT=[[input "10.1.9.1"]]
=OUTPUT=
-- r1
ip access-list extended n2_in
 permit tcp 10.1.2.0 0.0.0.255 host 10.1.9.1 eq 80
 deny ip any any
=END=


############################################################
=TITLE=Hidden NAT at loopback network
=INPUT=
router:r1 = {
 managed;
 model = IOS;
 interface:lo = {
  ip = 10.1.9.1;
  hardware = Looback0;
  loopback;
  nat:N = { hidden; }
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = N; }
}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
service:s1 = {
    user = interface:r1.lo;
    permit src = network:n2; dst = user; prt = tcp 80;
}
=END=
=ERROR=
Error: interface:r1.lo is hidden by nat:N in rule
 permit src=network:n2; dst=interface:r1.lo; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Duplicate NAT at loopback network
=INPUT=
router:r1 = {
 managed;
 model = IOS;
 interface:lo = {
  ip = 10.1.9.1;
  hardware = Looback0;
  loopback;
  nat:N = { hidden; }
  nat:N2 = { ip = 10.1.99.99; }
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = N, N2; }
}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
=END=
=ERROR=
Error: Grouped NAT tags 'N, N2' of interface:r1.lo must not both be active at
 - interface:r1.n2
=END=

############################################################
=TITLE=Only NAT IP at non loopback interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat:N = { hidden; } }
}
=END=
=ERROR=
Error: Only 'ip' allowed in nat:N of interface:r1.n1
=END=

############################################################
=TITLE=Broken NAT for supernet
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n1a = {
 ip = 10.1.1.64/26;
 nat:n = { ip = 10.9.1.64/26; }
 subnet_of = network:n1;
}
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=ERROR=
Error: Must not use network:n1 in rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s1,
 because it is no longer supernet of
 - network:n1a
 at interface:r1.n2
=END=

############################################################
=TITLE=Identical IP from dynamic NAT is valid as subnet relation
=INPUT=
network:n1  = { ip = 10.1.1.0/24; nat:t2 = { ip = 10.9.2.64/26; dynamic; } }
network:n1a = { ip = 10.1.1.64/26; subnet_of = network:n1; }
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = t2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--r1
! n2_in
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Broken NAT for aggregate as supernet
=INPUT=
network:n1 = { ip = 10.1.1.0/26; }
network:n1a = {
 ip = 10.1.1.64/26;
 nat:n = { ip = 10.9.1.64/26; }
}
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = any:[ip = 10.1.1.0/24 & network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=ERROR=
Error: Must not use any:[ip=10.1.1.0/24 & network:n1] in rule
 permit src=any:[ip=10.1.1.0/24 & network:n1]; dst=network:n2; prt=tcp 80; of service:s1,
 because it is no longer supernet of
 - network:n1a
 at interface:r1.n2
=END=

############################################################
=TITLE=Broken NAT for aggregate as subnet
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:d = { ip = 10.9.9.0/24; }
}
any:a1x = {
 ip = 10.1.1.64/26;
 link = network:n1;
}
router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = d; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=END=
=ERROR=
Error: Must not use network:n1 in rule
 permit src=network:n2; dst=network:n1; prt=tcp 80; of service:s1,
 because it is no longer supernet of
 - any:a1x
 at interface:r1.n2
=END=

############################################################
=TITLE=Detect subnet relation at unnumbered network
# For both subnets no error must be shown:
# network:n2 is no longer supernet of network:n2-sub1 / network:n2-sub2
# This would occur, if subnet relation isn't detected at NAT domain
# consisting only of unnumbered network.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { hidden; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n2-sub1 = { ip = 10.1.2.64/27; subnet_of = network:n2; }
network:n2-sub2 = { ip = 10.1.2.128/27; }
network:n3 = { ip = 10.1.3.0/24; nat:n3 = { hidden; } }
network:n4 = { ip = 10.1.4.0/24; }
network:t1 = { ip = 10.2.1.0/24; }
network:t2 = { ip = 10.2.2.0/24; }
network:t3 = { unnumbered; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n2-sub1;
 interface:n2-sub2;
 interface:t1;
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:t1 = { ip = 10.2.1.1; hardware = t1; }
 interface:t2 = { ip = 10.2.2.1; hardware = t2; }
}
router:r3 = {
 interface:t2;
 interface:t3 = { bind_nat = n1; }
}
# Use name 'r0' to get network:t3(split Network) get processed first.
# Check if name of zone and nat_domain is changed to network:n3 later.
router:r0 = {
 interface:t3 = { bind_nat = n3; }
 interface:n3;
 interface:n4;
}
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=WARNING=
Warning: network:n2-sub2 is subnet of network:n2
 in nat_domain:[network:n3].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Direct subnet relation changed by NAT
# network:n is direct subnet of any:a in NAT domain of network:n2,
# but is only indirect subnet at its own NAT domain.
# But this ok and not an error.
=INPUT=
network:n = { ip = 10.1.0.0/16; }
network:n1 = {
 ip = 10.1.1.0/24;
 nat:d = { ip = 10.9.9.0/24; }
 subnet_of = network:n;
}
any:a = {
 ip = 0.0.0.0/0;
 link = network:n1;
}
router:u = {
 interface:n;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; bind_nat = d; }
}
network:n2 = { ip = 10.2.2.0/24; }
service:s1 = {
 user = any:a;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
-- r1
ip access-list extended n2_in
 deny ip any host 10.9.9.1
 deny ip any host 10.2.2.1
 permit tcp 10.2.2.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Multiple subnets with identical NAT IP
# Must not show warning for network:n2.
# Both subnets must be marked as subnet although they have identical
# IP addresses in NAT domain n4.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:a = { ip = 10.127.8.0/24; dynamic; } }
network:n2 = { ip = 10.1.2.0/24; nat:a = { ip = 10.127.8.0/24; dynamic; } }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3;
}
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = a; }
}
network:n4 = { ip = 10.1.4.0/24; }
service:s1 = {
 user = any:[ ip = 10.0.0.0/8 & network:n1 ];
 permit src = user; dst = network:n4; prt = tcp;
}
=END=
=WARNING=NONE

############################################################
=TITLE=NAT definitions with different type.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:x = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:x = { ip = 10.9.2.2/31; dynamic; } }
network:n3 = { ip = 10.1.3.0/24; nat:x = { hidden; } }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
 interface:lo = { ip = 10.1.5.0; loopback; nat:x = { hidden; } }
 interface:n4 = { bind_nat = x; }
}
=END=
=ERROR=
Error: All definitions of nat:x must have equal type.
 But found
 - static for network:n1
 - dynamic for network:n2
Error: All definitions of nat:x must have equal type.
 But found
 - static for network:n1
 - hidden for network:n3
Error: All definitions of nat:x must have equal type.
 But found
 - static for network:n1
 - hidden for interface:r1.lo
=END=

############################################################
=TITLE=Identical subnets invisible to supernet
# No subnet relation should be found.
# Test is only relevant to increase test coverage.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:extern = { ip = 193.1.1.2/32; dynamic; } }
network:n2 = { ip = 10.1.2.0/24; nat:extern = { ip = 193.1.1.2/32; dynamic; } }
network:x  = { ip = 193.1.1.0/24; nat:hidden = { hidden; } }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:x;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2;}
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = extern, hidden; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=END=
=OUTPUT=
-- r2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Aggregate has IP of network with NAT
# Special handling is only needed for implicit aggregate.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:a = { ip = 10.1.8.0/24; } }
any:n1     = { ip = 10.1.1.0/24; link = network:n1; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = a; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = any:n1;
 permit src = user; dst = network:n2; prt = tcp;
}
=END=
=ERROR=
Error: any:n1 and network:n1 have identical IP/mask in any:[network:n1]
=END=

############################################################
=TITLE=Implicit aggregate has IP of network with NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:a = { ip = 10.1.8.0/24; } }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = a; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = any:[ ip = 10.1.1.0/24 & network:n1 ];
 permit src = user; dst = network:n2; prt = tcp;
}
=END=
=ERROR=
Error: Must not use any:[ip = 10.1.1.0/24 & ..] in user of service:s1
 because it has address of network:n1 which is translated by nat:a
=END=

############################################################
=TITLE=Invisible implicit aggregate has IP of network with NAT
# Aggregate is only used intermediately for automatic group of networks.
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; nat:a = { ip = 10.1.8.0/24; } }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = a; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:[any:[ ip = 10.1.1.0/24 & network:n1 ]];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=INPUT=[[input]]
=WARNING=NONE

############################################################
=TITLE=Implicit aggregate has IP of network with NAT (2)
# Show error also for cached implicit aggregate.
=INPUT=
[[input]]
service:s2 = {
 user = any:[ ip = 10.1.1.0/24 & network:n1 ];
 permit src = user; dst = network:n2; prt = tcp 81;
}
=END=
=ERROR=
Error: Must not use any:[ip = 10.1.1.0/24 & ..] in user of service:s2
 because it has address of network:n1 which is translated by nat:a
=END=

############################################################
=TITLE=Implicit aggregate is subnet of network with NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:a = { ip = 192.168.1.1/32; dynamic; } }
network:n1s = { ip = 10.1.1.0/26; subnet_of = network:n1; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 interface:n1;
 interface:n1s;
 interface:n2 = { ip = 10.1.2.1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = a; }
}

service:s1 = {
 user = any:[ ip = 10.1.1.0/26 & network:n1 ];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=ERROR=
Error: Must not use any:[ip = 10.1.1.0/26 & ..] in user of service:s1
 because it is subnet of network:n1 which is translated by nat:a
=END=

############################################################
=TITLE=Must not compare networks of other partition
# network:n1a and :n1b would have identical IP in network:n3.
=INPUT=
network:n1a = { ip = 10.1.1.0/24;
 nat:h1a = { hidden; }
 partition = part1;
}
network:n1b = { ip = 10.1.1.0/24;
 nat:h1b = { hidden; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1a = { ip = 10.1.1.1; hardware = n1a; bind_nat = h1b; }
 interface:n1b = { ip = 10.1.1.1; hardware = n1b; bind_nat = h1a; }
}
network:n3 = { ip = 10.1.3.0/24; partition = part2; }
router:r2 = {
 interface:n3;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Useless subnet_of
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:h1 = { hidden; }
 nat:h2 = { identity; }
 subnet_of = network:n2;
}
network:n2 = {
 ip = 10.1.0.0/21;
 nat:h2 = { hidden; }
}
router:r1 = {
 interface:n1 = { bind_nat = h2; }
 interface:n2 = { bind_nat = h1; }
}
=END=
=WARNING=
Warning: Useless 'subnet_of = network:n2' at network:n1
=END=

############################################################
=TITLE=Network is subnet of different networks
=INPUT=
network:n1 = { ip = 10.1.0.0/21; }
network:n2 = {
 ip = 10.1.1.0/24;
 nat:h2 = { hidden; }
 subnet_of = network:n1;
}
network:n3 = {
 ip = 10.1.1.16/28;
 subnet_of = network:n1;
}
network:n4 = {
 ip = 10.1.1.32/28;
 subnet_of = network:n2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.0.1; bind_nat = h2; hardware = n1; }
 interface:n2 = { ip = 10.1.1.1; hardware = n2; }
 interface:n3 = { ip = 10.1.1.17; bind_nat = h2; hardware = n3; }
 interface:n4 = { ip = 10.1.1.33; bind_nat = h2; hardware = n4; }
}
=END=
=WARNING=
Warning: network:n3 is subnet of network:n2
 in nat_domain:[network:n2].
 If desired, declare attribute 'subnet_of'
Warning: network:n4 is subnet of network:n1
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
