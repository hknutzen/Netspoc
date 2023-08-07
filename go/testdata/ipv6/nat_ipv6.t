
############################################################
=TITLE=Duplicate NAT definition
=PARAMS=--ipv6
=INPUT=
area:n1 = {
 border = interface:r.n1;
 nat:n = { ip = ::a07:0/112; }
 nat:n = { ip = ::a06:0/112; }
}
any:n1 = {
 link = network:n1;
 nat:n = { ip = ::a09:0/112; }
 nat:n = { ip = ::a08:0/112; }
}
network:n1 = {
 ip = ::a01:100/120;
 nat:n = { ip = ::a09:900/120; }
 nat:n = { ip = ::a08:800/120; dynamic;}
 host:h1 = {
  ip = ::a01:10a;
  nat:n = { ip = ::a09:909; }
  nat:n = { ip = ::a08:808; }
 }
}
router:r = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = ::a01:101; hardware = n1;
  nat:n = { ip = ::a09:901; }
  nat:n = { ip = ::a08:801; }
 }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: Duplicate attribute 'nat:n' in network:n1
Error: Duplicate attribute 'nat:n' in host:h1
Error: Duplicate attribute 'nat:n' in any:n1
Error: Duplicate attribute 'nat:n' in interface:n1 of router:r
Error: Duplicate attribute 'nat:n' in area:n1
=END=

############################################################
=TITLE=Other NAT attribute together with hidden
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n = { ip = ::a09:900/120; hidden; dynamic; identity; }
}
router:r = {
 interface:n1;
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: Hidden NAT must not use other attributes in nat:n of network:n1
Error: Identity NAT must not use other attributes in nat:n of network:n1
=END=

############################################################
=TITLE=Other NAT attribute together with identity
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n = { ip = ::a09:900/120; dynamic; identity; }
}
router:r = {
 interface:n1;
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: Identity NAT must not use other attributes in nat:n of network:n1
=END=

############################################################
=TITLE=NAT at short interface
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n = { ip = ::a09:900/120; dynamic; }
}
router:r = {
 interface:n1 = { nat:n = { ip = ::a09:901; } }
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: No NAT supported for interface:r.n1 without IP
=END=

############################################################
=TITLE=Duplicate IP address
=PARAMS=--ipv6
=INPUT=
network:n1a = {
 ip = ::a01:100/120;
 nat:t1 = { ip = ::a09:100/120; }
}
router:r1 = {
 interface:n1a = { bind_nat = t2; }
 interface:u;
}
network:u = { ip = ::a02:200/120; }
router:r2 = {
 interface:u;
 interface:n1b = { bind_nat = t1; }
}
network:n1b = {
 ip = ::a01:100/120;
 nat:t2 = { ip = ::a09:200/120; }
}
=ERROR=
Error: network:n1a and network:n1b have identical IP/mask in any:[network:n1a]
=END=

############################################################
=TITLE=NAT bound in wrong direction
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:x = { hidden; } }
router:r = {
 interface:n1 = { bind_nat = x; }
 interface:n2;
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: network:n1 is translated by nat:x,
 but is located inside the translation domain of x.
 Probably x was bound to wrong interface at
 - router:r
=END=

############################################################
=TITLE=Dynamic NAT for network with static nat for hosts at ASA
=PARAMS=--ipv6
=INPUT=
network:Test =  {
 ip = ::a09:100/120;
 nat:C = { ip = ::101:110/124; dynamic;}
 host:H = { ip = ::a09:121; nat:C = { ip = ::101:117; } }
}
router:filter = {
 managed;
 model = ASA;
 interface:Test = {
  ip = ::a09:101;
  hardware = inside;
 }
 interface:X = { ip = ::a09:301; hardware = outside; bind_nat = C;}
}
network:X = { ip = ::a09:300/120; }
service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = ip;
 permit src = host:H; dst = user;         prt = tcp 80;
 permit src = user;   dst = network:Test; prt = tcp 80;
}
=OUTPUT=
--ipv6/filter
! inside_in
access-list inside_in extended permit tcp host ::a09:121 ::a09:300/120 eq 80
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit ip ::a09:300/120 host ::a09:121
access-list outside_in extended permit tcp ::a09:300/120 ::a09:100/120 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Masquerading
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:m = { ip = ::a01:201/128; dynamic; subnet_of = network:n2; }
}
router:r1 = {
 interface:n1 = { ip = ::a01:101; hardware = n1;}
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = m; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r2
! n2_in
access-list n2_in extended permit tcp host ::a01:201 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Invalid masquerading
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:m = { ip = ::a01:200/127; dynamic; subnet_of = network:n2; }
}
router:r1 = {
 interface:n1 = { ip = ::a01:101; hardware = n1;}
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = m; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=WARNING=
Warning: IP of interface:r1.n2 overlaps with subnet network:n1 in nat_domain:[network:n2]
=END=

############################################################
=TITLE=NAT to subnet
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:m = { ip = ::a01:210/124; dynamic; subnet_of = network:n2; }
}
router:r1 = {
 interface:n1 = { ip = ::a01:101; hardware = n1;}
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = m; }
}
network:n2 = { ip = ::a01:200/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a01:210/124 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=subnet_of at inherited NAT
=TEMPL=input
area:n1-2 = {
 nat:m = { ip = {{.}}; dynamic; subnet_of = network:n3; }
 inclusive_border = interface:r1.n3;
}
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = m; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
service:s1 = {
 user = network:n1, network:n2;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=PARAMS=--ipv6
=INPUT=[[input ::a01:310/124]]
=OUTPUT=
-- ipv6/r2
! n3_in
access-list n3_in extended permit tcp ::a01:310/124 ::a01:400/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Declared subnet of NAT network in area doesn't match
=PARAMS=--ipv6
=INPUT=[[input ::a0b:310/124]]
=ERROR=
Error: nat:m of area:n1-2 is subnet_of network:n3 but its IP doesn't match that's IP/mask
=END=

############################################################
=TITLE=Inherit NAT to subnet in other part of zone cluster
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
network:n6 = { ip = ::a01:600/120; nat:h1 = { hidden; } }
network:n7 = { ip = ::a01:700/120; nat:h1 = { hidden; } }
network:n7s = { ip = ::a01:740/122; subnet_of = network:n7; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = h1; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r3 = {
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n5 = { ip = ::a01:501; hardware = n5; }
 interface:n7 = { ip = ::a01:701; hardware = n7; }
}
router:r4 = {
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n5 = { ip = ::a01:502; hardware = n5; }
 interface:n6 = { ip = ::a01:601; hardware = n6; }
 interface:n7s = { ip = ::a01:741; hardware = n7s; }
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
=PARAMS=--ipv6
=INPUT=
network:Test =  {
 ip = ::a00:100/120;
 nat:C = { hidden; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:Test = { ip = ::a00:102; hardware = inside; }
 interface:t1 = { ip = ::a00:201; hardware = outside;}
}
network:t1 = { ip = ::a00:200/120; }
router:u = {
 interface:t1 = { ip = ::a00:202; }
 interface:X = { ip = ::a08:301; bind_nat = C; }
}
network:X = { ip = ::a08:300/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:X = { ip = ::a08:302; hardware = inside; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1 = { hidden; }
 host:h13 = { ip = ::a01:103; }
 host:h14 = { ip = ::a01:104; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = {
 ip = ::a01:400/120;
 nat:n4 = { hidden; }
 host:h43 = { ip = ::a01:403; }
 host:h44 = { ip = ::a01:404; }
}
network:n5 = { ip = ::a01:500/120; nat:n4 = { hidden; } }

router:r1 = {
 managed = routing_only; # Kill mutation test.
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n1; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 interface:n3 = { ip = ::a01:302; bind_nat = n4; }
 interface:n4;
 interface:n5;
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
 permit src = user; dst = host:h44, network:n5; prt = tcp 84;
}
=END=
# Only first error is shown.
=ERROR=
Error: host:h13 is hidden by nat:n1 in rule
 permit src=host:h13; dst=host:h43; prt=tcp 82; of service:s1
Error: host:h43 is hidden by nat:n4 in rule
 permit src=host:h13; dst=host:h43; prt=tcp 82; of service:s1
Error: network:n5 is hidden by nat:n4 in rule
 permit src=host:h14; dst=network:n5; prt=tcp 84; of service:s3
=END=

############################################################
=TITLE=Show NAT domain if host overlaps with network in other zone
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1 = { hidden; }
 host:h65 = { ip = ::a01:141; }
 host:h66 = { ip = ::a01:142; }
}
network:n1sub = {
 ip = ::a01:140/122;
 subnet_of = network:n1;
 nat:n1sub = { ip = ::a01:240/122; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; bind_nat = n1sub; hardware = n1; }
 interface:l = { ip = ::a01:909; loopback; hardware = l; }
 interface:n1sub = { ip = ::a01:17e; bind_nat = n1;  hardware = n1sub; }
}
=WARNING=
Warning: IP of host:h65 overlaps with subnet network:n1sub in nat_domain:[interface:r1.l]
Warning: IP of host:h66 overlaps with subnet network:n1sub in nat_domain:[interface:r1.l]
=END=

############################################################
=TITLE=NAT network is undeclared subnet
=TEMPL=input
network:Test =  {
 ip = ::a00:0/124;
 nat:C = { ip = {{.ip}}; {{.sub}} }
}
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = ::a00:2; hardware = inside; }
 interface:X = { ip = ::a08:301; hardware = outside; bind_nat = C; }
}
network:X = { ip = ::a08:300/120; }
=PARAMS=--ipv6
=INPUT=[[input {ip: "::a08:3f0/124", sub: ""}]]
=WARNING=
Warning: nat:C of network:Test is subnet of network:X
 in nat_domain:[network:X].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=NAT network is subnet
=PARAMS=--ipv6
=INPUT=[[input {ip: "::a08:3f0/124", sub: "subnet_of = network:X;"}]]
=WARNING=NONE

############################################################
=TITLE=Declared NAT network subnet doesn't match
=PARAMS=--ipv6
=INPUT=[[input  {ip: "::a08:4f0/124", sub: "subnet_of = network:X;"}]]
=ERROR=
Error: nat:C of network:Test is subnet_of network:X but its IP doesn't match that's IP/mask
=END=

############################################################
=TITLE=Detect subnet relation when having duplicate IP addresses
# Processing order of networks depends on lexical order of router names.
# Choose a weird order to get n1/n2sub and n2/n1sub to be processed together.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:h1 = { hidden; } }
network:n1sub = { ip = ::a01:140/122; }
router:r1 = {
 interface:n1;
 interface:t1;
}
router:r4 = {
 interface:n1sub;
 interface:t1;
}
network:t1 = { ip = ::a02:100/120; }
router:fw =  {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = ::a02:101; hardware = t1; bind_nat = h2; }
 interface:t2 = { ip = ::a02:201; hardware = t2; bind_nat = h1; }
}
network:t2 = { ip = ::a02:200/120; }
router:r2 = {
 interface:n2;
 interface:t2;
}
router:r3 = {
 interface:n2sub;
 interface:t2;
}
network:n2 = { ip = ::a01:100/120; nat:h2 = { hidden; } }
network:n2sub = { ip = ::a01:140/122; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:N = { ip = ::a09:900/120; }
}
network:n1_sub = {
 ip = ::a01:140/122;
 subnet_of = network:n1;
}
router:u = {
 interface:n1;
 interface:n1_sub;
}
network:n2 = { ip = ::a01:200/120; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_sub = { ip = ::a01:141; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = N; }
}
service:s1 = {
    user = network:n1_sub;
    permit src = network:n2; dst = user; prt = tcp 80;
}
service:s2 = {
    user = network:n1;
    permit src = network:n2; dst = user; prt = tcp 81;
}
=OUTPUT=
-- ipv6/asa1
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 ::a01:140/122 eq 80
access-list n2_in extended permit tcp ::a01:200/120 ::a01:100/120 eq 81
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not bind multiple NAT of one network at one place
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip = ::a00:100/120;
 nat:C = { ip = ::a08:100/120; }
 nat:D = { hidden; }
}
network:n2 =  {
 ip = ::a00:200/120;
 nat:C = { ip = ::a08:200/120; }
 nat:D = { hidden; }
}
router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a00:102; hardware = n1; }
 interface:n2 = { ip = ::a00:202; hardware = n2; }
 interface:X = { ip = ::a08:301; hardware = outside; bind_nat = C, D, E; }
}
network:X = { ip = ::a08:300/120; }
=END=
# Only first error is shown.
=ERROR=
Warning: Ignoring useless nat:E bound at interface:filter.X
Error: Grouped NAT tags 'C, D' of network:n1 must not both be active at
 - interface:filter.X
=END=

############################################################
=TITLE=Check bind_nat at hardware interface
=PARAMS=--ipv6
=INPUT=
network:n1a =  { ip = ::a00:100/122; }
network:n1b =  { ip = ::a00:140/122; }
network:n1c =  { ip = ::a00:180/122; }
network:n2 =  { ip = ::a00:200/120; nat:n2 = { ip = ::a08:200/120; } }
router:r = {
 managed;
 model = ASA;
 interface:n1a = { ip = ::a00:101; hardware = n1; bind_nat = n2; }
 interface:n1b = { ip = ::a00:141; hardware = n1; }
 interface:n1c = { ip = ::a00:181; hardware = n1; }
 interface:n2 = { ip = ::a00:201; hardware = n2; }
}
=ERROR=
Error: interface:r.n1a and interface:r.n1b using identical 'hardware = n1'
 must also use identical NAT binding
Error: interface:r.n1a and interface:r.n1c using identical 'hardware = n1'
 must also use identical NAT binding
=END=

############################################################
=TITLE=Unused / undefined / duplicate NAT tag
=PARAMS=--ipv6
=INPUT=
network:Test =  {
 ip = ::a00:0/120;
 nat:C = { ip = ::a08:800/120; }
}
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = ::a00:2; hardware = inside; }
 interface:X = { ip = ::a08:301; hardware = outside; bind_nat = D, E/F, D; }
}
network:X = { ip = ::a08:300/120; }
=WARNING=
Warning: Ignoring duplicate element in 'bind_nat' of interface:filter.X
Warning: Ignoring useless nat:D bound at interface:filter.X
Warning: Ignoring useless nat:E/F bound at interface:filter.X
Warning: nat:C is defined, but not bound to any interface
=END=

############################################################
=TITLE=No further errors on useless NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
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
=WARNING=
Warning: Ignoring useless nat:i bound at interface:r1.n2
Warning: Ignoring useless nat:h bound at interface:r2.n3
Warning: Ignoring useless nat:h bound at interface:r3.n3
=END=

############################################################
=TITLE=Non matching static NAT mask
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; nat:x = { ip = ::a08:800/119; } }
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: Mask for non dynamic nat:x must be equal to mask of network:n1
=END=

############################################################
=TITLE=Non matching NAT IP of host and interface
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip = ::a01:100/120;
 nat:x = { ip = ::a08:800/119; dynamic; }
 host:h1 = { ip = ::a01:10a; nat:x = { ip = ::a07:707; } }
}
router:r1 = {
 interface:n1 = { ip = ::a01:101; nat:x = { ip = ::a07:701; } }
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: nat:x: IP of host:h1 doesn't match IP/mask of network:n1
Error: nat:x: IP of interface:r1.n1 doesn't match IP/mask of network:n1
=END=

############################################################
=TITLE=Useless NAT IP of host and interface with static NAT
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip = ::a01:100/120;
 nat:x = { ip = ::a08:800/120; }
 host:h1 = { ip = ::a01:10a; nat:x = { ip = ::a08:80c; } }
}
router:r1 = {
 interface:n1 = { ip = ::a01:101; nat:x = { ip = ::a07:701; } }
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = ::a01:200/120; }
=WARNING=
Warning: Ignoring nat:x at host:h1 because network:n1 has static NAT definition
Warning: Ignoring nat:x at interface:r1.n1 because network:n1 has static NAT definition
=END=

############################################################
=TITLE=Missing IP in NAT of host
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip = ::a01:100/120;
 nat:x = { ip = ::a08:800/120; }
 host:h1 = { ip = ::a01:10a; nat:x = {} }
}
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: Expecting exactly one attribute 'ip' in nat:x of host:h1
=END=

############################################################
=TITLE=Must not define NAT for host range.
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip = ::a01:100/120;
 nat:x = { ip = ::a08:800/120; dynamic; }
 host:h1 = { range = ::a01:10a-::a01:10f; nat:x = { ip = ::a08:80c; } }
}
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = ::a01:200/120; }
=ERROR=
Error: No NAT supported for host:h1 with 'range'
=END=

############################################################
=TITLE=Inconsistent NAT for host vs. host range.
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:d = { ip = ::a09:100/124; dynamic; }
 host:h1 = { ip = ::a01:10a; nat:d = { ip = ::a09:10a; } }
 host:h2 = { range = ::a01:109 - ::a01:10a; }
 host:h3 = { range = ::a01:108 - ::a01:10f; }
}
router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = d; }
}
network:n2 = { ip = ::a02:200/120; }
=ERROR=
Error: Inconsistent NAT definition for host:h1 and host:h2
Error: Inconsistent NAT definition for host:h3 and host:h1
=END=

############################################################
=TITLE=NAT for interface with multiple IP addresses
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip = ::a01:100/120;
 nat:x = { ip = ::a08:800/124; dynamic; }
}
router:r1 = {
 interface:n1 = { ip = ::a01:101, ::a01:102; nat:x = { ip = ::a08:801; } }
 interface:t1 = { ip = ::a01:901; bind_nat = x; }
}
network:t1 = { ip = ::a01:900/120; }
router:filter = {
 managed;
 model = ASA;
 interface:t1 = { ip = ::a01:902; hardware = t1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
service:s = {
 user = interface:r1.[all];
 permit src = user; dst = network:n2; prt = udp 123;
}
=ERROR=
Error: interface:r1.n1.2 needs static translation for nat:x at router:filter to be valid in rule
 permit src=interface:r1.n1.2; dst=network:n2; prt=udp 123; of service:s
=END=

############################################################
=TITLE=NAT tag without effect (1)
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; nat:x = { ip = ::a09:900/120; } }
router:r1 = {
 interface:n1 = { bind_nat = x; }
 interface:n2 = { bind_nat = x; }
}
network:n2 = { ip = ::a01:200/120; }
=WARNING=
Warning: Ignoring nat:x without effect, bound at every interface of router:r1
=END=

############################################################
=TITLE=NAT tag without effect (2)
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; nat:n1 = { ip = ::a09:100/120; } }
router:u = {
 interface:n1;
 interface:n2 = { bind_nat = n1; }
}
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::a09:200/120; } }
router:r1 = {
 interface:n2 = { bind_nat = n1; }
 interface:n3 = { bind_nat = n1, n2; }
}
network:n3 = { ip = ::a01:300/120; }
=WARNING=
Warning: Ignoring nat:n1 without effect, bound at every interface of router:r1
=END=

############################################################
=TITLE=Check rule with host and dynamic NAT (managed)
=TEMPL=input
network:Test =  {
 ip = ::a09:100/120;
 nat:C = { ip = ::109:200/120; dynamic;}
 host:h3 = { ip = ::a09:103; }
 host:h4 = { ip = ::a09:104; }
 host:h5 = { ip = ::a09:105; nat:C = { ip = ::109:237; } }
}
router:C = {
 {{.}}
 model = ASA;
 interface:Test = { ip = ::a09:101; hardware = inside;}
 interface:Trans = { ip = ::a00:1; hardware = outside; bind_nat = C;}
}
network:Trans = { ip = ::a00:0/120; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = {
  ip = ::a00:2;
  hardware = inside;
 }
 interface:X = { ip = ::a08:301; hardware = outside; }
}
network:X = { ip = ::a08:300/120; }
service:s1 = {
 user = network:X;
 permit src = user;    dst = host:h3, host:h5; prt = tcp 80;
 permit src = host:h4; dst = user;             prt = tcp 80;
}
=PARAMS=--ipv6
=INPUT=[[input managed;]]
=ERROR=
Error: host:h3 needs static translation for nat:C at router:C to be valid in rule
 permit src=network:X; dst=host:h3; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Check rule with host and dynamic NAT (unmanaged)
=PARAMS=--ipv6
=INPUT=[[input ""]]
=ERROR=
Error: host:h3 needs static translation for nat:C at router:filter to be valid in rule
 permit src=network:X; dst=host:h3; prt=tcp 80; of service:s1
Error: host:h4 needs static translation for nat:C at router:filter to be valid in rule
 permit src=host:h4; dst=network:X; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Check rule with host and dynamic NAT but filtered static address
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip =  ::a01:100/120;
 nat:S = { ip = ::109:100/120; dynamic; }
 nat:D = { ip = ::109:200/124; dynamic; }
 host:h5 = { ip = ::a01:105; nat:S = { ip = ::109:105; } }
}
network:n2 =  { ip =  ::a01:200/120; }
network:n3 =  { ip =  ::a01:300/120; }
network:n4 =  { ip =  ::a01:400/120; }

router:S = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1;}
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = S; }
}
router:C = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n1;}
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = D; }
}
router:filter = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
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
=PARAMS=--ipv6
=INPUT=
network:Test =  {
 ip = ::a09:100/120;
 nat:C = { ip = ::109:909/128; dynamic;}
 host:h33 = { ip = ::a09:121; }
 host:h34 = { ip = ::a09:122; }
}
router:S = {
 managed = secondary;
 model = ASA;
 interface:Test = { ip = ::a09:101; hardware = inside;}
 interface:Trans = { ip = ::a00:1; hardware = outside; bind_nat = C;}
}
network:Trans = { ip = ::a00:0/120; }
router:R = {
 managed;
 model = ASA;
 interface:Trans = {
  ip = ::a00:2;
  hardware = inside;
 }
 interface:X = { ip = ::a08:301; hardware = outside; }
}
network:X = { ip = ::a08:300/120; }
service:s1 = {
 user = network:X;
 permit src = host:h33; dst = user;         prt = tcp 80;
 permit src = host:h34; dst = user;         prt = tcp 22;
}
=OUTPUT=
-- ipv6/S
! inside_in
access-list inside_in extended permit tcp host ::a09:121 ::a08:300/120 eq 80
access-list inside_in extended permit tcp host ::a09:122 ::a08:300/120 eq 22
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
-- ipv6/R
! inside_in
access-list inside_in extended permit tcp host ::109:909 ::a08:300/120 eq 80
access-list inside_in extended permit tcp host ::109:909 ::a08:300/120 eq 22
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=No secondary optimization with host and dynamic NAT (2)
# Secondary optimization must be disabled at router:r2.
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = ::a01:101; hardware = a; bind_nat = b;}
 interface:t = {ip = ::a04:401; hardware = t;}
}
network:t = { ip = ::a04:400/126; }
router:r2 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:t = {ip = ::a04:402; hardware = t;}
 interface:b = {ip = ::a02:201; hardware = b;}
}
network:b  = {
 ip = ::a02:200/120;
 nat:b = { ip = ::a09:904/126; dynamic; }
 host:b10 = { ip = ::a02:20a; }
}
service:test = {
 user = network:a;
 permit src = user; dst = host:b10; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list a_in
 permit tcp ::a01:100/120 ::a09:904/126 eq 80
 deny ipv6 any any
--
ipv6 access-list t_in
 permit tcp host ::a02:20a ::a01:100/120 established
 deny ipv6 any any
-- ipv6/r2
! t_in
access-list t_in extended permit tcp ::a01:100/120 host ::a02:20a eq 80
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
=END=

############################################################
=TITLE=No secondary optimization with host and dynamic NAT (3)
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = ::a01:101; hardware = a; }
 interface:t = {ip = ::a04:401; hardware = t;}
}
network:c = { ip = ::a03:300/120; }
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:c = {ip = ::a03:301; hardware = c; bind_nat = b; }
 interface:t = {ip = ::a04:403; hardware = t;}
}
network:t = { ip = ::a04:400/120; }
router:r2 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:t = {ip = ::a04:402; hardware = t;}
 interface:b = {ip = ::a02:201; hardware = b;}
}
network:b  = {
 ip = ::a02:200/120;
 nat:b = { ip = ::a09:904/126; dynamic; }
 host:b10 = { ip = ::a02:20a; }
}
service:s1 = {
 user = network:a, network:c;
 permit src = user; dst = host:b10; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list a_in
 permit tcp ::a01:100/120 host ::a02:20a eq 80
 deny ipv6 any any
--
ipv6 access-list t_in
 permit tcp host ::a02:20a ::a01:100/120 established
 deny ipv6 any any
-- ipv6/r3
ipv6 access-list c_in
 permit tcp ::a03:300/120 ::a09:904/126 eq 80
 deny ipv6 any any
--
ipv6 access-list t_in
 permit tcp host ::a02:20a ::a03:300/120 established
 deny ipv6 any any
-- ipv6/r2
! t_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a03:300/120
access-list t_in extended permit tcp object-group v6g0 host ::a02:20a eq 80
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
=END=

############################################################
=TITLE=Optimize secondary if dynamic NAT is not applied
# Dynamic NAT does't influence network:b at router:r2,
# because it isn't applied at any rule for network:b
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = ::a01:101; hardware = a; }
 interface:t = {ip = ::a04:401; hardware = t; }
}
network:t = { ip = ::a04:400/120; }
router:r2 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:t = {ip = ::a04:402; hardware = t; }
 interface:b = {ip = ::a02:201; hardware = b; }
 interface:c = {ip = ::a03:301; hardware = b; }
}
network:b  = {
 ip = ::a02:200/120;
 nat:b = { ip = ::a09:904/126; dynamic; }
 host:b10 = { ip = ::a02:20a; }
}
network:c = { ip = ::a03:300/120; nat:b = { ip = ::a09:904/126; dynamic; } }
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:c = {ip = ::a03:302; hardware = c; }
 interface:d = {ip = ::a05:501; hardware = d; bind_nat = b; }
}
network:d = { ip = ::a05:500/120; }
service:s1 = {
 user = network:a;
 permit src = user; dst = host:b10; prt = tcp 80;
}
service:s2 = {
 user = network:d;
 permit src = user; dst = network:c; prt = tcp 81;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list a_in
 permit tcp ::a01:100/120 host ::a02:20a eq 80
 deny ipv6 any any
--
ipv6 access-list t_in
 permit tcp host ::a02:20a ::a01:100/120 established
 deny ipv6 any any
-- ipv6/r2
! t_in
access-list t_in extended permit ip ::a01:100/120 ::a02:200/120
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
-- ipv6/r3
! d_in
access-list d_in extended permit tcp ::a05:500/120 ::a03:300/120 eq 81
access-list d_in extended deny ip any6 any6
access-group d_in in interface d
=END=

############################################################
=TITLE=Optimize secondary if other router filters original address
# Still apply secondary optimization at r1, because r2 filters
# original address.
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1 = { ip = ::a09:904/126; dynamic; }
 host:h1 = { ip = ::a01:104; }
}
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120;}
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = n1; }
}
network:n3 = { ip = ::a01:300/120; }
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a01:100/120 ::a01:300/120
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
-- ipv6/r2
ipv6 access-list n2_in
 deny ipv6 any host ::a01:302
 permit tcp host ::a01:104 ::a01:300/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=No secondary optimization with primary router
# No secondary optimization at r1, because detailed filtering at r2 is
# disabled by primary r3. r3 only sees NAT address.
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1 = { ip = ::a09:904/126; dynamic; }
 host:h1 = { ip = ::a01:104; }
}
network:n2 = { ip = ::a01:200/120;}
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = n1; }
}
router:r3 = {
 model = ASA;
 managed = primary;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp host ::a01:104 ::a01:400/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
-- ipv6/r2
ipv6 access-list n2_in
 permit ipv6 ::a01:100/120 ::a01:400/120
 deny ipv6 any any
-- ipv6/r3
! n3_in
access-list n3_in extended permit tcp ::a09:904/126 ::a01:400/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=No secondary optimization with other filter in loop
# No secondary optimization at r1, because detailed filtering occurs
# in loop, which isn't fully analyzed.
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1 = { ip = ::a09:904/126; dynamic; }
 host:h1 = { ip = ::a01:104; }
}
network:n2 = { ip = ::a01:200/120;}
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = ::a01:202; virtual = { ip = ::a01:209; } hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = n1; }
}
router:r3 = {
 model = IOS, FW;
 managed;
 interface:n2 = { ip = ::a01:203; virtual = { ip = ::a01:209; } hardware = n2; }
 interface:n3 = { ip = ::a01:303; hardware = n3; bind_nat = n1; }
}
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp host ::a01:104 ::a01:300/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=No secondary optimization with primary in loop
# No secondary optimization at r1, because primary router is located
# in loop, which isn't fully analyzed.
=TEMPL=input
network:n1 = {
 ip = ::a01:100/120;
 nat:n1 = { ip = ::a09:904/126; dynamic; }
 host:h1 = { ip = ::a01:104; }
}
network:n2 = { ip = ::a01:200/120;}
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 model = ASA;
 managed = secondary;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS, FW;
 managed{{.}};
 routing = manual;
 interface:n2 = { ip = ::a01:202;  hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
router:r3 = {
 model = ASA;
 managed = primary;
 interface:n3 = { ip = ::a01:303; hardware = n3; }
 interface:n4 = { ip = ::a01:403; hardware = n4; bind_nat = n1; }
}
router:r4 = {
 model = ASA;
 managed;
 interface:n3 = { ip = ::a01:304; hardware = n3; }
 interface:n4 = { ip = ::a01:404; hardware = n4; bind_nat = n1; }
}
service:n1 = {
 user = host:h1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=PARAMS=--ipv6
=INPUT=[[input ""]]
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp host ::a01:104 ::a01:400/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Optimize secondary with full filter
=PARAMS=--ipv6
=INPUT=[[input "= full"]]
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a01:100/120 ::a01:400/120
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=No route for supernet for unstable subnet relation
=PARAMS=--ipv6
=INPUT=
network:n1 = {ip = ::a01:100/120;}
router:r1 = {
 interface:n1;
 interface:n1sub = { ip = ::a01:182; }
}
network:n1sub = {
 ip = ::a01:180/121;
 nat:N = { ip = ::a09:909/128; dynamic; }
 subnet_of = network:n1;
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1sub = { ip = ::a01:181; hardware = outside; }
 interface:n2    = { ip = ::a01:201;   hardware = inside; bind_nat = N; }
}
network:n2 = { ip = ::a01:200/120;}
router:r3 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = ::a01:202; hardware = inside; }
 interface:n3 = { ip = ::a01:302; hardware = outside; routing = dynamic; }
}
network:n3 = { ip = ::a01:300/120; }
service:s1 = {
 user = network:n1sub;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--ipv6/r3
! [ Routing ]
ipv6 route inside ::a09:909/128 ::a01:201
--
! inside_in
access-list inside_in extended permit ip host ::a09:909 ::a01:300/120
access-list inside_in extended deny ip any6 any6
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
network:a1 = { ip = ::a05:500/120; }
network:a2 = { ip = ::a04:400/120; }
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:a1 = { ip = ::a05:501; hardware = a1; }
 interface:a2 = { ip = ::a04:401; hardware = a2; }
 interface:b1 = { ip = ::a02:201; hardware = b1; }
}
network:b2 = { ip = ::a03:300/120; }
router:u = { interface:b2; interface:b1; }
network:b1 = { ip = ::a02:200/120; nat:d = { identity; } }
router:r2 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:b1 = { ip = ::a02:202; hardware = b1; }
 interface:X = { ip = ::a01:102; hardware = X; bind_nat = d; }
}
network:X = { ip = ::a01:100/120; }
service:test = {
 user = network:a1, network:a2, network:b1, network:b2;
 permit src = network:X; dst = user; prt = tcp 80;
}
=PARAMS=--ipv6
=INPUT=
[[input
d1: "nat:d = { ip = ::a63:6308/126; dynamic; }"
n2: "ip = ::a4d:4d00/126; dynamic;"
]]
=OUTPUT=
--ipv6/r1
! b1_in
object-group network v6g0
 network-object ::a04:400/120
 network-object ::a05:500/120
access-list b1_in extended permit tcp ::a01:100/120 object-group v6g0 eq 80
access-list b1_in extended deny ip any6 any6
access-group b1_in in interface b1
--ipv6/r2
ipv6 access-list X_in
 deny ipv6 any host ::a02:202
 permit tcp ::a01:100/120 ::a63:6308/126 eq 80
 permit tcp ::a01:100/120 ::a04:400/120 eq 80
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 permit tcp ::a01:100/120 ::a4d:4d00/126 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Use hidden NAT from overlapping areas
=PARAMS=--ipv6
=INPUT=[[input {d1: "", n2: hidden;}]]
=ERROR=
Error: network:a1 is hidden by nat:d in rule
 permit src=network:X; dst=network:a1; prt=tcp 80; of service:test
Error: network:b2 is hidden by nat:d in rule
 permit src=network:X; dst=network:b2; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Inherit NAT from supernets inside zone
=PARAMS=--ipv6
=INPUT=
# NAT is inherited to all 10.* subnets by default.
network:n   = {
 ip = ::a00:0/104;
 nat:d = { ip = ::b00:0/104; }
 has_subnets;
}
# NAT is enabled for this network and
# inherited to ::a01:100/120 and ::a01:200/120
network:n1 = {
 ip = ::a01:0/112;
 nat:d = { ip = ::b11:0/112; }
 has_subnets;
}
network:n0 = { ip = ::a00:0/112; }
network:n11 = { ip = ::a01:100/120; }
network:n3  = { ip = ::a03:0/112; host:h3 = { ip = ::a03:30a; } }
router:u = {
 interface:n;
 interface:n0;
 interface:n1;
 interface:n11;
 interface:n3;
 interface:t1;
}
network:t1 = { ip = ::a09:100/120; }
router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:t1 = { ip = ::a09:101; hardware = t1; }
 interface:X = { ip = ::a02:102; hardware = X; bind_nat = d; }
}
network:X = { ip = ::a02:100/120; subnet_of = network:n; }
service:s1 = {
 user = network:X;
# NAT to ::b00:0/104
 permit src = user; dst = network:n; prt = tcp 80;
# NAT to ::b11:0
 permit src = user; dst = network:n1; prt = tcp 81;
# inherit from network:n1, ::b11:100
 permit src = user; dst = network:n11; prt = tcp 82;
# inherit from network:n, ::b11:30a
 permit src = user; dst = host:h3; prt = tcp 83;
# inherit from network:n, ::b00:0/112
 permit src = user; dst = network:n0; prt = tcp 84;
# inherit from network:n, ::b09:100/120
 permit src = user; dst = network:t1; prt = tcp 85;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list X_in
 deny ipv6 any host ::b09:101
 permit tcp ::a02:100/120 ::b00:0/104 eq 80
 permit tcp ::a02:100/120 ::b11:0/112 eq 81
 permit tcp ::a02:100/120 ::b11:100/120 eq 82
 permit tcp ::a02:100/120 host ::b03:30a eq 83
 permit tcp ::a02:100/120 ::b00:0/112 eq 84
 permit tcp ::a02:100/120 ::b09:100/120 eq 85
 deny ipv6 any any
=END=

############################################################
=TITLE=Inherit NAT from aggregates inside zone
=PARAMS=--ipv6
=INPUT=
# NAT is inherited to ::a01:100/120;
any:a1-23 = {
 ip = ::a01:0/119;
 link = network:n1;
 nat:n = { ip = ::a08:800/119; }
}
any:a1-24 = {
 ip = ::a01:100/120;
 link = network:n1;
 nat:n = { ip = ::a09:900/120; }
}
network:n0 = { ip = ::a01:0/120; }
network:n1 = { ip = ::a01:140/122; }
router:u1 = {
 interface:n0;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:n1 = { ip = ::a01:141; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
service:n1 = {
 user = network:n0, network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n2_in
 deny ipv6 any host ::a09:941
 permit tcp ::a01:200/120 ::a08:800/120 eq 80
 permit tcp ::a01:200/120 ::a09:940/122 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Warn on useless inherited NAT (1)
=PARAMS=--ipv6
=INPUT=
area:x = {
 border = interface:filter.x;
 nat:C = { ip = ::a08:800/120; dynamic; }
 nat:D = { hidden; }
}
any:x = {
 link = network:x;
 nat:C = { ip = ::a08:800/120; dynamic; }
}
network:x =  {
 ip = ::a00:0/120;
 nat:C = { ip = ::a08:800/120; dynamic; }
 nat:D = { hidden; }
}
router:filter = {
 managed;
 model = ASA;
 interface:x = { ip = ::a00:2; hardware = inside; }
 interface:y = { ip = ::a08:301; hardware = outside; bind_nat = C; }
}
network:y = { ip = ::a08:300/120; }
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
=PARAMS=--ipv6
=INPUT=
# Don't warn, if other NAT is intermixed.
area:a12 = { border = interface:r2.n2; nat:n = { hidden; } }
area:a1  = { border = interface:r1.n1; nat:n = { identity; } }
any:n1 = { link = network:n1; nat:n = { hidden; } }
network:n1 = { ip = ::a01:100/120; nat:n = { identity; } }
network:n1a = { ip = ::a01:140/122; nat:n = { hidden; } subnet_of = network:n1; }
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
# Warn on subnet.
any:n2 = { link = network:n2; }
network:n2 = { ip = ::a01:200/120; nat:n = { hidden; } }
network:n2a = { ip = ::a01:240/122; nat:n = { hidden; } subnet_of = network:n2; }
router:u2 = {
 interface:n2a;
 interface:n2;
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = n; }
}
network:n3 = { ip = ::a01:300/120; }
=WARNING=
Warning: Useless nat:n of network:n2,
 it was already inherited from area:a12
Warning: Useless nat:n of network:n2a,
 it was already inherited from network:n2
=END=

############################################################
=TITLE=Useless inheritance from multiple areas
=PARAMS=--ipv6
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
network:n1 = { ip = ::a01:100/120; nat:n = { hidden; } }
network:n2 = { ip = ::a01:200/120; nat:n = { identity; } }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
 interface:n5 = { ip = ::a01:501; hardware = n5; bind_nat = n; }
}
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
=PARAMS=--ipv6
=INPUT=
area:a12 = { border = interface:r1.n2; nat:h1 = { hidden; } }
any:n1 = { link = network:n1; nat:h2 = { hidden; } }
network:n1 = { ip = ::a01:100/120; nat:n = { ip = ::a09:900/120; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:u = {
 interface:n1;
 interface:n2 = { bind_nat = n; }
}
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = h2; }
 interface:n4 = { ip = ::a01:401; hardware = n4; bind_nat = h1; }
}
=WARNING=NONE

############################################################
=TITLE=Inherit NAT to all networks in zone cluster
=PARAMS=--ipv6
=INPUT=
any:n2 = { ip = ::a01:0/112; link = network:n2; nat:h = { hidden; } }
network:n1 = { ip = ::a01:100/120; nat:h = { hidden; } }
network:n2 = { ip = ::a02:200/120; }
network:n3 = { ip = ::a03:300/120; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
router:r2 = {
 interface:n2= { ip = ::a02:202; }
 interface:n3 = { bind_nat = h; }
}
=WARNING=
Warning: Useless nat:h of network:n1,
 it was already inherited from any:n2
=END=

############################################################
=TITLE=Inherit NAT from network to subnet in zone cluster
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:h = { hidden; } }
network:n2 = { ip = ::a01:100/122; nat:h = { hidden; } subnet_of = network:n1; }
network:n3 = { ip = ::a03:300/120; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = ::a01:141; hardware = n1; }
 interface:n2 = { ip = ::a01:101; hardware = n2; }
}
router:r2 = {
 interface:n2= { ip = ::a01:102; }
 interface:n3 = { bind_nat = h; }
}
=WARNING=
Warning: Useless nat:h of network:n2,
 it was already inherited from network:n1
=END=

############################################################
=TITLE=Useless identity NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n = { identity; } }
network:n1a = { ip = ::a01:140/122; nat:n = { hidden; } subnet_of = network:n1; }
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
=WARNING=
Warning: Useless identity nat:n of network:n1
=END=

############################################################
=TITLE=Inherit static NAT from area and zone
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = f000::c000:0/104; }
any:a1 = { link = network:n1; nat:a1 = { ip = ::b00:0/104; } }
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n0 = { ip = f000::c000:1; hardware = n0; }
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = f000::ac11:201; hardware = n2; bind_nat = a1; }
}
network:n2 = { ip = f000::ac11:200/120; }
router:r2 = {
 interface:n2;
 interface:n2a;
}
network:n2a = { ip = f000::ac11:240/122; subnet_of = network:n2; }
area:a2 = {
 border = interface:r1.n2;
 nat:a2 = { ip = f000::c0a8:0/112; subnet_of = network:n0; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2a; prt = tcp 81;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host f000::c0a8:201
 permit tcp ::a01:100/120 f000::c0a8:200/120 eq 80
 permit tcp ::a01:100/120 f000::c0a8:240/122 eq 81
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp f000::ac11:200/120 ::b01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Inherit dynamic NAT to networks in subnet_of relation
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = f000::c0a8:0/112; }
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = a2; }
 interface:n0 = { ip = f000::c0a8:1; hardware = n0; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n0 = { ip = f000::c0a8:2; hardware = n0; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
router:r0 = {
 interface:n2a;
 interface:n2;
}
network:n2a = { ip = ::a01:240/122; subnet_of = network:n2; }
area:a2 = {
 border = interface:r2.n2;
 nat:a2 = { ip = f000::c0a8:108/125; dynamic; subnet_of = network:n0; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2a; prt = tcp 81;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/120 f000::c0a8:108/125 range 80 81
 deny ipv6 any any
--
ipv6 access-list n0_in
 permit tcp ::a01:200/120 ::a01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Duplicate IP from inherited static NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = f000::ac11:201; hardware = n2; }
}
network:n2 = { ip = f000::ac11:200/120; }
router:r2 = {
 interface:n2;
 interface:n2a;
}
network:n2a = { ip = f000::ac12:200/120; }
area:a2 = { border = interface:r1.n2; nat:a2 = { ip = f000::c0a8:0/112; } }
=ERROR=
Error: nat:a2 of network:n2a and nat:a2 of network:n2 have identical IP/mask
 in nat_domain:[network:n1]
=END=

############################################################
=TITLE=Inherited static NAT network must be larger
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = f000::ac11:201; hardware = n2; }
}
network:n2 = { ip = f000::ac11:200/120; }
area:a2 = { border = interface:r1.n2; nat:a2 = { ip = f000::c0a8:180/121; } }
=ERROR=
Error: Must not inherit nat:a2 of area:a2 at network:n2
 because NAT network must be larger than translated network
=END=

############################################################
=TITLE=Interface with dynamic NAT as destination
# Should ignore error in policy_distribution_point,
# because other error message is shown.
=PARAMS=--ipv6
=INPUT=
network:n2 = { ip = ::a01:200/120; nat:dyn = { ip = ::a09:909/128; dynamic; }}
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:30a; } }
router:asa1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:h3;
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = dyn; }
}
service:s = {
 user = interface:asa1.n2;
 permit src = host:h3; dst = user; prt = tcp 22;
}
=ERROR=
Error: interface:asa1.n2 needs static translation for nat:dyn at router:asa2 to be valid in rule
 permit src=host:h3; dst=interface:asa1.n2; prt=tcp 22; of service:s
=END=

############################################################
=TITLE=Interface with dynamic NAT as destination in reversed rule
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS;
 interface:a = {ip = ::a01:101; hardware = E1; bind_nat = b;}
 interface:t = {ip = ::a04:401; hardware = E2;}
}
network:t = { ip = ::a04:400/126; }
router:r2 = {
 interface:t = {ip = ::a04:402;}
 interface:b = {ip = ::a02:201;}
}
network:b  = { ip = ::a02:200/120; nat:b = { ip = ::a09:904/126; dynamic; } }
service:test = {
 user = interface:r2.b;
 permit src = user; dst = network:a; prt = udp 445;
}
=ERROR=
Error: interface:r2.b needs static translation for nat:b at router:r1 to be valid in reversed rule for
 permit src=interface:r2.b; dst=network:a; prt=udp 445; of service:test
=END=

############################################################
=TITLE=Combined hidden and dynamic NAT error in destination aggregate
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:d1 = { ip = ::101:101/128; dynamic; }
 host:h1 = { ip = ::a01:10a; }
}
network:n2 = { ip = ::a01:200/120; nat:h2 = { hidden; } }
network:n3 = { ip = ::a01:300/120; nat:h3 = { hidden; } }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
network:n6 = { ip = ::a01:600/120; }
router:r1 = {
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = d1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r3 = {
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n5 = { ip = ::a01:501; hardware = n5; bind_nat = h2; }
 interface:n6 = { ip = ::a01:601; hardware = n6; bind_nat = h3; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1 = { ip = ::109:200/123; dynamic; }
 host:h13 = { ip = ::a01:103; }
 host:h14 = { ip = ::a01:104; }
 host:h15 = { ip = ::a01:105; nat:n1 = { ip = ::109:219; } }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = {
 ip = ::a01:400/120;
 nat:n4 = { ip = ::109:400/123; dynamic; }
 host:h43 = { ip = ::a01:403; }
 host:h44 = { ip = ::a01:404; }
}

router:r1 = {
 interface:n1 = { ip = ::a01:101; }
 interface:n2 = { ip = ::a01:201; bind_nat = n1;
 }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 interface:n3 = { ip = ::a01:302; bind_nat = n4; }
 interface:n4 = { ip = ::a01:401; nat:n4 = { ip = ::109:415; } }
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
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:a = {ip = ::a01:101; hardware = a;}
 interface:t = {ip = ::a04:401; hardware = t;}
}
network:t = { ip = ::a04:400/126; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t = {ip = ::a04:402; hardware = t; bind_nat = b;}
 interface:b = {ip = ::a02:201; hardware = b;}
}
network:b  = { ip = ::a02:200/120; nat:b = { ip = ::a09:904/126; dynamic; } }
service:test = {
 user = network:a;
 permit src = user; dst = interface:r2.b; prt = tcp 80;
}
=ERROR=
Error: interface:r2.b needs static translation for nat:b at router:r2 to be valid in rule
 permit src=network:a; dst=interface:r2.b; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Interface with dynamic NAT as source of managed device
# No need to check interface of managed device.
=PARAMS=--ipv6
=INPUT=
network:n1 =  {
 ip = ::a01:100/120;
 nat:x = { ip = ::a08:800/124; dynamic; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a01:901; hardware = t1; bind_nat = x; }
}
network:t1 = { ip = ::a01:900/120; }
router:filter = {
 interface:t1 = { ip = ::a01:902; }
 interface:n2;
}
network:n2 = { ip = ::a01:200/120; }
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
 ip = ::a01:100/120;
 nat:t1 = { ip = ::a09:100/120; }
 nat:t2 = { ip = ::a09:800/120; }
}
network:n2 = { ip = ::a01:200/120; {{.}} = { ip = ::a09:900/120; }}
router:r1 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:t  = { ip = ::a02:301; hardware = t; bind_nat = t1; }
}
network:t = { ip = ::a02:300/120; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t  = { ip = ::a02:302; hardware = t; }
 interface:k = { ip = ::a02:202; hardware = k; bind_nat = t2; }
}
network:k = { ip = ::a02:200/120; }
=PARAMS=--ipv6
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
=PARAMS=--ipv6
=INPUT=[[input nat:t2]]
=WARNING=NONE

############################################################
=TITLE=Grouped NAT tags with additional hidden allowed
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:t1 = { ip = ::a09:100/120; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n2 = {
 ip = ::a01:200/120;
 nat:h1 = { hidden; }
 nat:h3 = { hidden; }
}
network:n3 = {
 ip = ::a01:300/120;
 nat:t3 = { ip = ::a09:300/120; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n4 = {
 ip = ::a01:400/120;
 nat:t4a = { ip = ::a08:100/120; }
 nat:t4b = { ip = ::a08:200/120; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = t4a; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = t4b; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = h3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
 interface:t  = { ip = ::a02:301; hardware = t; bind_nat = t1, t3; }
}
network:t = { ip = ::a02:300/120; }
router:r2 =  {
 managed;
 model = ASA;
 interface:t  = { ip = ::a02:302; hardware = t; }
 interface:k1 = { ip = ::a02:102; hardware = k1; bind_nat = h1; }
 interface:k2 = { ip = ::a02:202; hardware = k2; bind_nat = h2; }
}
network:k1 = { ip = ::a02:100/120; }
network:k2 = { ip = ::a02:200/120; }
=WARNING=NONE

############################################################
=TITLE=Combined single hidden allowed
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:t1 = { ip = ::a09:100/120; }
 nat:h1 = { hidden; }
}
network:n2 = {
 ip = ::a01:200/120;
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n3 = {
 ip = ::a01:300/120;
 nat:t3 = { ip = ::a09:300/120; }
 nat:h2 = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:t  = { ip = ::a02:1; hardware = t; bind_nat = t1, t3; }
}
network:t = { ip = ::a02:0/120; }
router:r2 =  {
 interface:t;
 interface:k1 = { bind_nat = h1; }
 interface:k2 = { bind_nat = h2; }
}
network:k1 = { ip = ::a02:100/120; }
network:k2 = { ip = ::a02:200/120; }
=WARNING=NONE

############################################################
=TITLE=Grouped NAT tags with invalid hidden
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:t1 = { ip = ::a09:100/120; }
 nat:h1 = { hidden; }
 nat:h2 = { hidden; }
}
network:n2 = {
 ip = ::a01:200/120;
 nat:t1 = { ip = ::a09:200/120; }
}
network:n3 = {
 ip = ::a01:300/120;
 nat:h1 = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:t1 = { ip = ::a02:101; hardware = t; bind_nat = t1; }
}
network:t1 = { ip = ::a02:100/120; }
# t1 active
router:r2 = {
 interface:t1;
 interface:k1 = { bind_nat = h1; }
 interface:k2 = { bind_nat = h2; }
}
# h1 active
# t1 ambiguous: still active for n2, no longer active for n1
network:k1 = { ip = ::a02:300/120; }
# h2 active
# t1 ambiguous: still active for n2, no longer active for n1
network:k2 = { ip = ::a02:200/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:t1 = { ip = ::a09:100/120; }
 nat:h  = { hidden; }
}
network:n2 = {
 ip = ::a01:200/120;
 nat:t2 = { ip = ::a09:200/120; }
 nat:h  = { hidden; }
}
network:n3 = {
 ip = ::a01:300/120;
 nat:t1 = { ip = ::a09:300/120; }
 nat:t2 = { ip = ::a09:400/120; }
 nat:h  = { hidden; }
}
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:t1 = { ip = ::a02:101; hardware = t; bind_nat = t1; }
}
# t1 active
network:t1 = { ip = ::a02:100/120; }
router:r2 = {
 interface:t1;
 interface:t2 = { bind_nat = t2; }
}
# t2 active
# t1 ambiguous: still active for n1, but no longer active for n3
network:t2 = { ip = ::a02:200/120; }
router:r3 = {
 interface:t2;
 interface:k = { bind_nat = h; }
}
network:k = { ip = ::a02:300/120; }
=ERROR=
Error: Invalid transition from nat:t1 to nat:t2 at router:r2.
 Reason: Both NAT tags are used grouped at network:n3
 but nat:t2 is missing at network:n1
=END=

############################################################
=TITLE=Grouped NAT tags from different paths
=PARAMS=--ipv6
=INPUT=
network:a = {
 ip = ::a01:100/120;
 nat:a1 = { ip = ::a02:100/120; }
 nat:a2 = { ip = ::a02:200/120; }
}
router:r11 = {
 interface:a;
 interface:t1 = { bind_nat = a1; }
}
network:t1 = {ip = ::a03:300/126;}
router:r12 = {
 interface:t1;
 interface:b = { bind_nat = a2; }
}
router:r21 = {
 interface:a;
 interface:t2 = { bind_nat = a2; }
}
network:t2 = {ip = ::a03:304/126;}
router:r22 = {
 interface:t2;
 interface:b = { bind_nat = a1; }
}
network:b = {ip = ::a09:900/120;}
=ERROR=
Error: Grouped NAT tags 'a1, a2' of network:a must not both be active at
 - interface:r12.b
 - interface:r22.b
=END=

############################################################
=TITLE=Show interfaces preferred where both NAT tags are bound
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a01:0/120; }
router:r1 = {
 interface:n0 = { bind_nat = a1, a2; }
 interface:a;
}
network:a = {
 ip = ::a01:100/120;
 nat:a1 = { ip = ::a02:100/120; }
 nat:a2 = { ip = ::a02:200/120; }
}
router:r11 = {
 interface:a;
 interface:t1 = { bind_nat = a1; }
}
network:t1 = {ip = ::a03:300/126;}
router:r12 = {
 interface:t1;
 interface:b = { bind_nat = a2; }
}
router:r21 = {
 interface:a;
 interface:t2 = { bind_nat = a2; }
}
network:t2 = {ip = ::a03:304/126;}
router:r22 = {
 interface:t2;
 interface:b = { bind_nat = a1; }
}
network:b = {ip = ::a09:900/120;}
=ERROR=
Error: Grouped NAT tags 'a1, a2' of network:a must not both be active at
 - interface:r1.n0
=END=

############################################################
=TITLE=Groupd NAT tags with multiple NAT domains
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1a = { ip = ::a08:100/120; }
 nat:n1b = { ip = ::a09:100/120; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; nat:n4 = { ip = ::a09:400/120; } }
network:n5 = { ip = ::a01:500/120; nat:n5 = { ip = ::a09:500/120; } }
network:n6 = { ip = ::a01:600/120; }
network:n7 = { ip = ::a01:700/120; }
network:n8 = { ip = ::a01:800/120;
 nat:n1a = { ip = ::a08:800/120; }
 nat:n1b = { ip = ::a09:800/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n = { ip = ::a09:900/120; } }
router:r1 = {
 interface:n1;
 interface:tr = { bind_nat = n; }
}
network:tr = { ip = ::a07:700/120; }
router:r2 = {
 interface:tr;
 interface:n2 = { bind_nat = n; }
}
network:n2 = { ip = ::a02:200/120; }
=ERROR=
Error: Incomplete 'bind_nat = n' at
 - interface:r1.tr
 Possibly 'bind_nat = n' is missing at these interfaces:
 - interface:r2.tr
=END=

############################################################
=TITLE=Prevent NAT from dynamic to static
=PARAMS=--ipv6
=INPUT=
network:U1 = {
 ip = ::a01:100/120;
 nat:t1 = { ip = ::a08:800/119; dynamic; }
 nat:t2 = { ip = ::a09:900/120; }
}
router:R0 = {
 interface:U1;
 interface:T = { ip = ::a03:311; bind_nat = t1;}
}
network:T = { ip = ::a03:310/125; }
router:R2 = {
 managed;
 model = ASA;
 interface:T = { ip = ::a03:312; hardware = T;}
 interface:K = { ip = ::a02:201; hardware = K; bind_nat = t2; }
}
network:K = { ip = ::a02:200/120; }
=ERROR=
Error: Must not change dynamic nat:t1 to static using nat:t2
 for network:U1 at router:R2
=END=

############################################################
=TITLE=Prevent NAT from hidden back to IP
=PARAMS=--ipv6
=INPUT=
network:U1 = {
 ip = ::a01:100/120;
 nat:t1 = { hidden; }
 nat:t2 = { ip = ::a09:900/120; }
}
router:R0 = {
 interface:U1;
 interface:T = { ip = ::a03:311; bind_nat = t1;}
}
network:T = { ip = ::a03:310/125; }
router:R2 = {
 managed;
 model = ASA;
 interface:T = { ip = ::a03:312; hardware = T;}
 interface:K = { ip = ::a02:201; hardware = K; bind_nat = t2; }
}
network:K = { ip = ::a02:200/120; }
=ERROR=
Error: Must not change hidden nat:t1 using nat:t2
 for network:U1 at router:R2
=END=

############################################################
=TITLE=Prevent multiple hidden NAT
=PARAMS=--ipv6
=INPUT=
network:U1 = {
 ip = ::a01:100/120;
 nat:t1 = { hidden; }
 nat:t2 = { hidden; }
}
router:R0 = {
 interface:U1;
 interface:T = { ip = ::a03:311; bind_nat = t1;}
}
network:T = { ip = ::a03:310/125; }
router:R2 = {
 managed;
 model = ASA;
 interface:T = { ip = ::a03:312; hardware = T;}
 interface:K = { ip = ::a02:201; hardware = K; bind_nat = t2; }
}
network:K = { ip = ::a02:200/120; }
=ERROR=
Error: Must not change hidden nat:t1 using nat:t2
 for network:U1 at router:R2
=END=

############################################################
=TITLE=Two NAT tags share single hidden NAT tag
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a01:0/120; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 interface:n0 = { bind_nat = F; }
 interface:n1;
}
router:asa = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = h; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = P; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r2 = {
 interface:n3;
 interface:n4;
}
network:n3 = {
 ip = ::a01:300/120;
 nat:h = { hidden; }
 nat:P = { ip = ::a02:300/120; }
}
network:n4 = {
 ip = ::a01:400/120;
 nat:h = { hidden; }
 nat:F = { ip = ::a02:400/120; }
}
=ERROR=
Error: Must not change hidden nat:h using nat:F
 for network:n4 at router:r1
=END=

############################################################
=TITLE=Partially hidden in destination zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:h = { hidden; } }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = outside; }
 interface:t1 = { ip = ::a05:5a4; hardware = inside; bind_nat = h; }
}
network:t1 = { ip = ::a05:5a0/124; }
router:u1 = {
 interface:t1 = { bind_nat = h; }
 interface:n2;
}
network:n2 = { ip = ::a01:200/120; }
service:test = {
 user =	network:n1;
 permit src = user; dst = network:n2; prt = proto 50;
}
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = ::a01:101;
  routing = OSPF;
  hardware = outside;
 }
 interface:t1 = { ip = ::a05:5a4; hardware = inside; }
}
network:t1 = { ip = ::a05:5a0/124; }
router:u1 = {
 interface:t1 = { ip = ::a05:5a1;  bind_nat = h; }
 interface:n2;
 interface:n3;
}
network:n2 = { ip = ::a01:200/120; nat:h = { hidden; } }
network:n3 = { ip = ::a01:300/120; }
any:10_1   = { ip = ::a01:0/112; link = network:n2; }
service:test = {
 user =	network:n1;
 permit src = user; dst = any:10_1; prt = proto 50;
}
=OUTPUT=
-- ipv6/r1
! [ Routing ]
ipv6 route inside ::a01:300/120 ::a05:5a1
=END=

############################################################
=TITLE=Ignore hidden network in NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = ::a01:101;
  routing = OSPF;
  hardware = outside;
  bind_nat = h;
 }
 interface:t1 = { ip = ::a05:5a4; hardware = inside; }
}
network:t1 = { ip = ::a05:5a0/124; }
router:u1 = {
 interface:t1 = { ip = ::a05:5a1; }
 interface:n2;
 interface:n3;
}
network:n2 = { ip = ::a01:200/120; nat:h = { hidden; } }
network:n3 = { ip = ::a01:300/120; }
any:10_1   = { ip = ::a01:0/112; link = network:n2; }
service:test = {
 user =	network:n1;
 permit src = user; dst = any:10_1; prt = proto 50;
}
=OUTPUT=
-- ipv6/r1
! outside_in
access-list outside_in extended permit 50 ::a01:100/120 ::a01:0/112
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Mixed hidden and IP NAT in loop
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 nat:i = { ip = ::a09:100/120; }
 nat:h = { hidden; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = i; }
}
router:r2 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = h; }
}
router:r3 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = h; }
 interface:n1 = { ip = ::a01:102; hardware = n1; }
}
pathrestriction:p = interface:r3.n3, interface:r2.n3;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit tcp ::a01:100/120 ::a01:200/120 eq 80
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit tcp ::a01:200/120 ::a09:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Traverse hidden NAT domain in loop
=TEMPL=input
network:n1 = {
 ip = ::a01:100/120;
 nat:h = { {{.h}} }
}
router:r1 = {
 model = ASA;
 {{.r1}}
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a05:501; hardware = t1; bind_nat = h; }
}
network:t1 = { ip = ::a05:500/120; }
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:t1 = { ip = ::a05:502; hardware = t1; }
 interface:t2 = { ip = ::a04:401; hardware = t2; }
}
network:t2 = { ip = ::a04:400/120; }
router:r3 = {
 model = ASA;
 {{.r3}}
 routing = manual;
 interface:t2 = { ip = ::a04:402; hardware = t2; bind_nat = h; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/120; }
router:r4 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n2 = { ip = ::a02:202; hardware = n2; }
 interface:n1 = { ip = ::a01:102; hardware = n1; }
}
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
=INPUT=[[input {h: "ip = ::a09:900/120; dynamic;", r1: managed;, r3: managed;}]]
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 nat:h = { hidden; }
 nat:d = { ip = ::a09:900/123; dynamic; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = d; }
}
router:r2 = {
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = d; }
 interface:n4 = { ip = ::a01:401; hardware = n4; bind_nat = h; }
}
router:r4 = {
 interface:n4 = { ip = ::a01:402; hardware = n4; bind_nat = h; }
 interface:n1 = { ip = ::a01:102; hardware = n1; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 nat:d = { ip = ::a09:900/123; dynamic; }
 host:h10 = { ip = ::a01:10a; nat:d = { ip = ::a09:90a; } }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; nat:d = { ip = ::a09:901; } }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; bind_nat = d; }
}
router:r4 = {
 interface:n4 = { ip = ::a01:402; hardware = n4; bind_nat = d; }
 interface:n1 = { ip = ::a01:102; hardware = n1; nat:d = { ip = ::a09:902; } }
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
=ERROR=
Error: Must not apply dynamic NAT 'd' to dst of rule
 permit src=network:n3; dst=network:n1; prt=tcp 83; of service:s3
 NAT 'd' is active at
 - interface:r3.n4
 - interface:r4.n4
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Mixed static and dynamic NAT with same tag
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:d = { ip = ::a09:100/120; } }
network:n2 = { ip = ::a01:200/120; nat:d = { ip = ::a09:200/123; dynamic; } }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; bind_nat = d; }
}
router:r4 = {
 interface:n4 = { ip = ::a01:402; hardware = n4; bind_nat = d; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
pathrestriction:p = interface:r2.n3, interface:r4.n2;

service:s1 = {
 user = network:n1, network:n2;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=ERROR=
Error: Must not apply dynamic NAT 'd' to src of rule
 permit src=network:n2; dst=network:n3; prt=tcp 80; of service:s1
 NAT 'd' is active at
 - interface:r3.n4
 - interface:r4.n4
 Add pathrestriction to exclude this path
=END=

############################################################
=TITLE=Inconsistent NAT in loop (1)
=PARAMS=--ipv6
=INPUT=
network:a = {ip = ::a01:d00/120; nat:h = { hidden; }}
router:r1 = {
 interface:b = { bind_nat = h; }
 interface:a;
 interface:t;
}
network:t = {ip = ::a03:67f0/126;}
router:r2 = {
 interface:a;
 interface:t;
 interface:b;
}
network:b = {ip = ::a9c:5a0/124;}
=ERROR=
Error: Inconsistent NAT in loop at router:r1:
 nat:(none) vs. nat:h
=END=

############################################################
=TITLE=Inconsistent NAT in loop (2)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; nat:x = { ip = ::a09:300/120; } }
network:n4 = { ip = ::a01:400/120; }
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
=ERROR=
Error: Inconsistent NAT in loop at router:r2:
 nat:(none) vs. nat:x
Error: Inconsistent NAT in loop at router:r3:
 nat:(none) vs. nat:x
=END=

############################################################
=TITLE=Check recursive NAT in loop
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::a09:100/120; } }
router:r1 = {
 interface:n1;
 interface:t1 = { bind_nat = n1; }
 interface:t2 = { bind_nat = n2; }
}
network:t1 = { ip = ::a07:100/120; }
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::a09:200/120; } }
router:r2 = {
 interface:n2;
 interface:t1;
 interface:t2 = { bind_nat = n2; }
}
network:t2 = { ip = ::a07:200/120; }
=ERROR=
Error: Incomplete 'bind_nat = n1' at
 - interface:r1.t1
 Possibly 'bind_nat = n1' is missing at these interfaces:
 - interface:r2.n2
 - interface:r2.t1
=END=

############################################################
=TITLE=NAT in simple loop ok
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::a09:100/120; } }
router:r1 = {
 interface:n1;
 interface:t1 = { bind_nat = n1; }
}
network:t1 = { ip = ::a07:100/120; }
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::a09:200/120; } }
router:r2 = {
 interface:n2;
 interface:t1;
 interface:t2;
 interface:t3 = { bind_nat = n2; }
}
network:t2 = { ip = ::a07:200/120; }
router:r3 = {
 interface:t2;
 interface:t3 = { bind_nat = n2; }
}
network:t3 = { ip = ::a07:300/120; }
=WARNING=NONE

############################################################
=TITLE=NAT in complex loop ok
=TEMPL=input
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::a09:100/120; } }
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::a09:200/120; } }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; nat:n4 = { ip = ::a09:400/120; } }
network:n5 = { ip = ::a01:500/120; nat:n5 = { ip = ::a09:500/120; } }
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
=PARAMS=--ipv6
=INPUT=[[input {b: "bind_nat = n5;", n: n5}]]
=WARNING=NONE

############################################################
=TITLE=Complex loop with 1 missing NAT behind domain
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::a09:100/120; } }
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::a09:200/120; } }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; nat:n5 = { ip = ::a09:500/120; } }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1a = { ip = ::a09:100/121; dynamic; }
 nat:n1b = { ip = ::a09:180/121; dynamic; }
}
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::a09:200/120; } }
network:n3 = { ip = ::a01:300/120; nat:n3 = { ip = ::a09:300/120; } }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
network:n6 = { ip = ::a01:600/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a01:0/120; nat:n0 = { ip = ::a09:0/120; } }
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::a09:100/120; } }
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::a09:200/120; } }
network:n3 = { ip = ::a01:300/120; nat:n3 = { ip = ::a09:300/120; } }
network:n4 = { ip = ::a01:400/120; nat:n4 = { ip = ::a09:400/120; } }
network:n5 = { ip = ::a01:500/120; nat:n5 = { ip = ::a09:500/120; } }
network:n6 = { ip = ::a01:600/120; nat:n6 = { ip = ::a09:600/120; } }
network:n7 = { ip = ::a01:700/120; nat:n7 = { ip = ::a09:700/120; } }
network:n8 = { ip = ::a01:800/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a01:0/120; nat:h = { hidden; } }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; nat:hx = { hidden; } }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
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
 interface:n1 = { ip = ::a01:102; hardware = n1; bind_nat = h; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
pathrestriction:p1 = interface:r2.n2, interface:r3.n3;
=ERROR=
Error: Incomplete 'bind_nat = hx' at
 - interface:r2.n1
 Possibly 'bind_nat = hx' is missing at these interfaces:
 - interface:r3.n1
=END=

############################################################
=TITLE=ASA uses real IP
=PARAMS=--ipv6
=INPUT=
network:intern =  { ip = ::a01:100/120; nat:intern = { ip = ::202:100/120; } }
router:filter = {
 managed;
 model = ASA;
 interface:intern = {
  ip = ::a01:101;
  hardware = inside;
  bind_nat = extern;
 }
 interface:extern = {
  ip = ::202:201;
  hardware = outside;
  bind_nat = intern;
 }
}
network:extern = { ip = ::202:200/120; nat:extern = { ip = ::a01:200/120; } }
service:test = {
 user = network:extern;
 permit src = user;           dst = network:intern; prt = tcp 80;
 permit src = network:intern; dst = user;           prt = tcp 22;
}
=OUTPUT=
-- ipv6/filter
! inside_in
access-list inside_in extended permit tcp ::a01:100/120 ::202:200/120 eq 22
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit tcp ::202:200/120 ::a01:100/120 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA uses real IP, more than 2 effective NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::202:100/120; } }
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::202:200/120; } }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = n2; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n1; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = n1, n2; }
}

service:test = {
 user = network:n2, network:n3;
 permit src = network:n1; dst = user; prt = tcp 80;
 permit src = user; dst = network:n1; prt = tcp 25;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/119 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 ::a01:100/120 eq 25
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp ::a01:300/120 ::a01:100/120 eq 25
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=ASA uses real IP with multi NAT tags
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:n1a = { ip = ::202:100/120; }
 nat:n1b = { ip = ::302:100/120; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = {
 ip = ::a01:400/120;
 nat:n4a = { ip = ::202:200/120; }
 nat:n4b = { ip = ::302:200/120; }
}

router:r1 = {
 interface:n1;
 interface:n2 = { bind_nat = n1a; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n4b; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = n1b; }
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
=OUTPUT=
-- ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::202:100/120 ::202:200/120 eq 25
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n3_in
access-list n3_in extended permit tcp ::202:200/120 ::202:100/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=ASA uses real IP, in loop
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::202:100/120; } }
network:n2 = { ip = ::a01:200/120; nat:n2 = { ip = ::202:200/120; } }

router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = n2; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n1; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = n1; bind_nat = n2; }
 interface:n2 = { ip = ::a01:202; hardware = n2; bind_nat = n1; }
}
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 25;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 25
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 ::a01:100/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
-- ipv6/r2
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 25
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 ::a01:100/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=ASA uses real ip, with outgoing ACL
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:intern = { ip = ::a09:100/120; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = intern; }
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = intern; no_in_acl; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = tcp 22;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/119 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n1_out
access-list n1_out extended permit tcp ::a01:200/120 ::a01:100/120 eq 22
access-list n1_out extended deny ip any6 any6
access-group n1_out out interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 ::a01:100/120 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! n2_out
access-list n2_out extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list n2_out extended deny ip any6 any6
access-group n2_out out interface n2
=END=

############################################################
=TITLE=ASA uses real IP, 3 interfaces, identical NAT ip, hidden
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:intern = { ip = ::202:0/119; dynamic; } }
network:n2 = { ip = ::a01:200/120; nat:intern = { ip = ::202:0/119; dynamic; } }
network:n3 = { ip = ::a01:300/120; nat:hide_n3 = { hidden; } }
router:u = {
 interface:n3;
 interface:n1;
}
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = extern; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = extern, hide_n3; }
 interface:t = { ip = ::a09:101; hardware = t; bind_nat = intern; }
}
network:t = { ip = ::a09:100/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:t = { ip = ::a09:102; hardware = t; }
 interface:extern = { ip = ::202:202; hardware = outside; }
}
network:extern = { ip = ::202:200/120; nat:extern = { ip = ::a02:200/120; } }
service:test = {
 user = network:n1, network:n2, network:n3;
 permit src = network:extern; dst = user; prt = tcp 80;
 permit src = user; dst = network:extern; prt = tcp 22;
}
=OUTPUT=
-- ipv6/r1
! n1_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:300/120
access-list n1_in extended permit tcp object-group v6g0 ::202:200/120 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 ::202:200/120 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! t_in
object-group network v6g1
 network-object ::a01:100/120
 network-object ::a01:200/119
access-list t_in extended permit tcp ::202:200/120 object-group v6g1 eq 80
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
-- ipv6/r2
! t_in
object-group network v6g0
 network-object ::202:0/119
 network-object ::a01:300/120
access-list t_in extended permit tcp object-group v6g0 ::202:200/120 eq 22
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
--
! outside_in
access-list outside_in extended permit tcp ::202:200/120 object-group v6g0 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA uses real IP, 3 interfaces, identical real IP
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:intern1 = { ip = ::201:100/120; } nat:h1 = { hidden; } }
network:n2 = { ip = ::a01:100/120; nat:intern2 = { ip = ::201:200/120; } nat:h2 = { hidden; } }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = extern, h2; }
 interface:n2 = { ip = ::a01:101; hardware = n2; bind_nat = extern, h1; }
 interface:t = { ip = ::a09:101; hardware = t; bind_nat = intern1, intern2; }
}
network:t = { ip = ::a09:100/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:t = { ip = ::a09:102; hardware = t; }
 interface:extern = { ip = ::202:202; hardware = outside; }
}
network:extern = { ip = ::202:200/120; nat:extern = { ip = ::a02:200/120; } }
service:test = {
 user = network:extern;
 permit src = user; dst = network:n1, network:n2; prt = tcp 80;
 permit src = network:n1, network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::202:200/120 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::202:200/120 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--
! t_in
access-list t_in extended permit tcp ::202:200/120 ::a01:100/120 eq 80
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
-- ipv6/r2
! t_in
object-group network v6g0
 network-object ::201:100/120
 network-object ::201:200/120
access-list t_in extended permit tcp object-group v6g0 ::202:200/120 eq 22
access-list t_in extended deny ip any6 any6
access-group t_in in interface t
--
! outside_in
access-list outside_in extended permit tcp ::202:200/120 object-group v6g0 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA uses real IP, with secondary optimization
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; nat:n1 = { ip = ::a02:100/120; } }
router:r1 = {
 managed = secondary;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; bind_nat = n2; }
 interface:t1 = { ip = ::a09:101; hardware = t1; bind_nat = n1; }
}
network:t1 = { ip = ::a09:100/120; }
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 nat:n2 = { ip = ::a02:200/120; }
 host:h2 = { ip = ::a01:20a; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit ip ::a01:100/120 ::a01:200/120
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=NAT at loopback network (1)
=TEMPL=input
area:n1 = { inclusive_border = interface:r1.n2; nat:N = { hidden; } }
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:lo = {
  ip = ::a01:901;
  hardware = Looback0;
  loopback;
  nat:N = { identity; }
  nat:N2 = { ip = {{.}}; }
 }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = N, N2; }
}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:20a; } }
service:s1 = {
    user = interface:r1.lo;
    permit src = network:n2; dst = user; prt = tcp 80;
}
=PARAMS=--ipv6
=INPUT=[[input "::a01:6363"]]
=OUTPUT=
-- ipv6/r1
ipv6 access-list n2_in
 permit tcp ::a01:200/120 host ::a01:6363 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=NAT at loopback network (2)
# NAT to original address.
=PARAMS=--ipv6
=INPUT=[[input "::a01:901"]]
=OUTPUT=
-- ipv6/r1
ipv6 access-list n2_in
 permit tcp ::a01:200/120 host ::a01:901 eq 80
 deny ipv6 any any
=END=


############################################################
=TITLE=Hidden NAT at loopback network
=PARAMS=--ipv6
=INPUT=
router:r1 = {
 managed;
 model = IOS;
 interface:lo = {
  ip = ::a01:901;
  hardware = Looback0;
  loopback;
  nat:N = { hidden; }
 }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = N; }
}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:20a; } }
service:s1 = {
    user = interface:r1.lo;
    permit src = network:n2; dst = user; prt = tcp 80;
}
=ERROR=
Error: interface:r1.lo is hidden by nat:N in rule
 permit src=network:n2; dst=interface:r1.lo; prt=tcp 80; of service:s1
=END=

############################################################
=TITLE=Duplicate NAT at loopback network
=PARAMS=--ipv6
=INPUT=
router:r1 = {
 managed;
 model = IOS;
 interface:lo = {
  ip = ::a01:901;
  hardware = Looback0;
  loopback;
  nat:N = { hidden; }
  nat:N2 = { ip = ::a01:6363; }
 }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = N, N2; }
}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:20a; } }
=ERROR=
Error: Grouped NAT tags 'N, N2' of interface:r1.lo must not both be active at
 - interface:r1.n2
=END=

############################################################
=TITLE=Only NAT IP allowed at non loopback interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 interface:n1 = { ip = ::a01:101; nat:N = { hidden; } }
}
router:r2 = {
 interface:n1 = { ip = ::a01:101; nat:N = { identity; } }
}
router:r3 = {
 interface:n1 = { ip = ::a01:101; nat:N = { ip = ::909:909; dynamic; } }
}
=ERROR=
Error: Only 'ip' allowed in nat:N of interface:r1.n1
Error: Only 'ip' allowed in nat:N of interface:r2.n1
Error: Only 'ip' allowed in nat:N of interface:r3.n1
=END=

############################################################
=TITLE=Broken NAT for supernet
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n1a = {
 ip = ::a01:140/122;
 nat:n = { ip = ::a09:140/122; }
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
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Must not use network:n1 in rule
 permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s1,
 because it is no longer supernet of
 - network:n1a
 at interface:r1.n2
=END=

############################################################
=TITLE=Valid NAT for supernet with hidden transient network
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; has_subnets; }
network:n1a = {
 ip = ::a01:180/121;
 nat:n = { hidden; }
}
network:n1b = {
 ip = ::a01:1c0/122;
 nat:n = { identity; }
 subnet_of = network:n1a;
}
router:u1 = {
 interface:n1a;
 interface:n1b;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1b;
 permit src = user; dst = network:n2; prt = tcp 81;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit tcp ::a01:100/120 ::a01:200/120 eq 80
 permit tcp ::a01:1c0/122 ::a01:200/120 eq 81
 deny ipv6 any any
=END=

############################################################
=TITLE=Identical IP from dynamic NAT is valid as subnet relation
=PARAMS=--ipv6
=INPUT=
network:n1  = { ip = ::a01:100/120; nat:t2 = { ip = ::a09:240/122; dynamic; } }
network:n1a = { ip = ::a01:140/122; subnet_of = network:n1; }
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = t2; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n2_in
access-list n2_in extended permit tcp ::a01:200/120 ::a01:100/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Broken NAT for aggregate as supernet
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/122; }
network:n1a = {
 ip = ::a01:140/122;
 nat:n = { ip = ::a09:140/122; }
}
router:u1 = {
 interface:n1a;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = n; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = any:[ip = ::a01:100/120 & network:n1];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Must not use any:[ip=::a01:100/120 & network:n1] in rule
 permit src=any:[ip=::a01:100/120 & network:n1]; dst=network:n2; prt=tcp 80; of service:s1,
 because it is no longer supernet of
 - network:n1a
 at interface:r1.n2
=END=

############################################################
=TITLE=Broken NAT for aggregate as subnet
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:d = { ip = ::a09:900/120; }
}
any:a1x = {
 ip = ::a01:140/122;
 link = network:n1;
}
router:r1 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = d; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n1 = { hidden; } }
network:n2 = { ip = ::a01:200/120; }
network:n2-sub1 = { ip = ::a01:240/123; subnet_of = network:n2; }
network:n2-sub2 = { ip = ::a01:280/123; }
network:n3 = { ip = ::a01:300/120; nat:n3 = { hidden; } }
network:n4 = { ip = ::a01:400/120; }
network:t1 = { ip = ::a02:100/120; }
network:t2 = { ip = ::a02:200/120; }
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
 interface:t1 = { ip = ::a02:101; hardware = t1; }
 interface:t2 = { ip = ::a02:201; hardware = t2; }
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
=PARAMS=--ipv6
=INPUT=
network:n = { ip = ::a01:0/112; }
network:n1 = {
 ip = ::a01:100/120;
 nat:d = { ip = ::a09:900/120; }
 subnet_of = network:n;
}
any:a = {
 ip = ::/0;
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
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; bind_nat = d; }
}
network:n2 = { ip = ::a02:200/120; }
service:s1 = {
 user = any:a;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
ipv6 access-list n2_in
 deny ipv6 any host ::a09:901
 deny ipv6 any host ::a02:201
 permit tcp ::a02:200/120 any eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Multiple subnets with identical NAT IP
# Must not show warning for network:n2.
# Both subnets must be marked as subnet although they have identical
# IP addresses in NAT domain n4.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:a = { ip = ::a7f:800/120; dynamic; } }
network:n2 = { ip = ::a01:200/120; nat:a = { ip = ::a7f:800/120; dynamic; } }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3;
}
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 routing = manual;
 model = IOS;
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; bind_nat = a; }
}
network:n4 = { ip = ::a01:400/120; }
service:s1 = {
 user = any:[ ip = ::a00:0/104 & network:n1 ];
 permit src = user; dst = network:n4; prt = tcp;
}
=WARNING=NONE

############################################################
=TITLE=Mixed hidden and non hidden.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:x = { ip = ::a09:100/120; } }
network:n2 = { ip = ::a01:200/120; nat:y = { ip = ::a09:202/127; dynamic; } }
network:n3 = { ip = ::a01:300/120; nat:x = { hidden; } }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
 interface:lo = { ip = ::a01:500; loopback; nat:y = { hidden; } }
 interface:n4 = { bind_nat = x, y; }
}
=ERROR=
Error: Must not mix hidden and real NAT at nat:x.
 Check network:n1 and network:n3
Error: Must not mix hidden and real NAT at nat:y.
 Check network:n2 and interface:r1.lo
=END=

############################################################
=TITLE=Identical subnets invisible to supernet
# No subnet relation should be found.
# Test is only relevant to increase test coverage.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:extern = { ip = f000::c101:102/128; dynamic; } }
network:n2 = { ip = ::a01:200/120; nat:extern = { ip = f000::c101:102/128; dynamic; } }
network:x  = { ip = f000::c101:100/120; nat:hidden = { hidden; } }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:x;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2;}
 interface:n3 = { ip = ::a01:301; hardware = n3; bind_nat = extern, hidden; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Aggregate has IP of network with NAT
# Special handling is only needed for implicit aggregate.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:a = { ip = ::a01:800/120; } }
any:n1     = { ip = ::a01:100/120; link = network:n1; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = a; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = any:n1;
 permit src = user; dst = network:n2; prt = tcp;
}
=ERROR=
Error: any:n1 and network:n1 have identical IP/mask in any:[network:n1]
=END=

############################################################
=TITLE=Implicit aggregate has IP of network with NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:a = { ip = ::a01:800/120; } }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = a; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = any:[ ip = ::a01:100/120 & network:n1 ];
 permit src = user; dst = network:n2; prt = tcp;
}
=ERROR=
Error: Must not use any:[ip = ::a01:100/120 & ..] in user of service:s1
 because it has address of network:n1 which is translated by nat:a
=END=

############################################################
=TITLE=Invisible implicit aggregate has IP of network with NAT
# Aggregate is only used intermediately for automatic group of networks.
=TEMPL=input
network:n1 = { ip = ::a01:100/120; nat:a = { ip = ::a01:800/120; } }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; bind_nat = a; }
}
network:n2 = { ip = ::a01:200/120; }
service:s1 = {
 user = network:[any:[ ip = ::a01:100/120 & network:n1 ]];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=PARAMS=--ipv6
=INPUT=[[input]]
=WARNING=NONE

############################################################
=TITLE=Implicit aggregate has IP of network with NAT (2)
# Show error also for cached implicit aggregate.
=PARAMS=--ipv6
=INPUT=
[[input]]
service:s2 = {
 user = any:[ ip = ::a01:100/120 & network:n1 ];
 permit src = user; dst = network:n2; prt = tcp 81;
}
=ERROR=
Error: Must not use any:[ip = ::a01:100/120 & ..] in user of service:s2
 because it has address of network:n1 which is translated by nat:a
=END=

############################################################
=TITLE=Implicit aggregate is subnet of network with NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:a = { ip = f000::c0a8:101/128; dynamic; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }

router:r1 = {
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = a; }
}

service:s1 = {
 user = any:[ ip = ::a01:100/122 & network:n1 ];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=ERROR=
Error: Must not use any:[ip = ::a01:100/122 & ..] in user of service:s1
 because it is subnet of network:n1 which is translated by nat:a
=END=

############################################################
=TITLE=Implicit aggregate has address of subnet of network with NAT
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:a = { ip = f000::c0a8:101/128; dynamic; } }
network:n1s = { ip = ::a01:100/122; subnet_of = network:n1; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }

router:r1 = {
 managed = routing_only;
 model = IOS;
 interface:n1 = { ip = ::a01:180; hardware = n1; }
 interface:n1s = { ip = ::a01:101; hardware = n2; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; bind_nat = a; }
}

service:s1 = {
 user = any:[ ip = ::a01:100/122 & network:n1 ];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=ERROR=
Error: Must not use any:[ip = ::a01:100/122 & ..] in user of service:s1
 because it has address of network:n1s which is translated by nat:a
=END=

############################################################
=TITLE=Must not compare networks of other partition
# network:n1a and :n1b would have identical IP in network:n3.
=PARAMS=--ipv6
=INPUT=
network:n1a = { ip = ::a01:100/120;
 nat:h1a = { hidden; }
 partition = part1;
}
network:n1b = { ip = ::a01:100/120;
 nat:h1b = { hidden; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1a = { ip = ::a01:101; hardware = n1a; bind_nat = h1b; }
 interface:n1b = { ip = ::a01:101; hardware = n1b; bind_nat = h1a; }
}
network:n3 = { ip = ::a01:300/120; partition = part2; }
router:r2 = {
 interface:n3;
}
=WARNING=NONE

############################################################
=TITLE=Useless subnet_of
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 nat:h1 = { hidden; }
 nat:h2 = { identity; }
 subnet_of = network:n2;
}
network:n2 = {
 ip = ::a01:0/117;
 nat:h2 = { hidden; }
}
router:r1 = {
 interface:n1 = { bind_nat = h2; }
 interface:n2 = { bind_nat = h1; }
}
=WARNING=
Warning: Useless 'subnet_of = network:n2' at network:n1
=END=

############################################################
=TITLE=Must find subnet relation even with intermediate aggregate and NAT
=PARAMS=--ipv6
=INPUT=
network:n0 = { ip = ::a00:0/120; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:0/112; nat:h2 = { hidden; } }
any:n1 = { ip = ::a01:0/118; link = network:n1; }
router:r1 = {
 managed;
 model = ASA;
 interface:n0 = { ip = ::a00:1; hardware = n0; bind_nat = h2; }
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:1; hardware = n2; }
}
=WARNING=
Warning: network:n1 is subnet of network:n2
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
=TITLE=Network is subnet of different networks
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:0/117; }
network:n2 = {
 ip = ::a01:100/120;
 nat:h2 = { hidden; }
 subnet_of = network:n1;
}
network:n3 = {
 ip = ::a01:110/124;
 subnet_of = network:n1;
}
network:n4 = {
 ip = ::a01:120/124;
 subnet_of = network:n2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:1; bind_nat = h2; hardware = n1; }
 interface:n2 = { ip = ::a01:101; hardware = n2; }
 interface:n3 = { ip = ::a01:111; bind_nat = h2; hardware = n3; }
 interface:n4 = { ip = ::a01:121; bind_nat = h2; hardware = n4; }
}
=WARNING=
Warning: network:n3 is subnet of network:n2
 in nat_domain:[network:n2].
 If desired, declare attribute 'subnet_of'
Warning: network:n4 is subnet of network:n1
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
=END=

############################################################
