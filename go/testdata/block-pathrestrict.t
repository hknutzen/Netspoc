=TITLE=Show blocking pathrestrictions with 2 paths

=INPUT=
# Simple topology: 2 routers with 2 paths, both blocked

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed; model = IOS, FW; routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.1.1; hardware = n2; }
 interface:n3 = { ip = 10.3.1.1; hardware = n3; }
}

network:n2 = { ip = 10.2.1.0/30; }
network:n3 = { ip = 10.3.1.0/30; }

router:r2 = {
 managed; model = IOS, FW; routing = manual;
 interface:n2 = { ip = 10.2.1.2; hardware = n2; }
 interface:n3 = { ip = 10.3.1.2; hardware = n3; }
 interface:n4 = { ip = 10.4.1.1; hardware = n4; }
}

network:n4 = { ip = 10.4.1.0/24; }

pathrestriction:block_n2 = interface:r1.n2, interface:r2.n2, ;
pathrestriction:block_n3 = interface:r1.n3, interface:r2.n3, ;

service:test = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}

=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n4]
 for rule permit src=network:n1; dst=network:n4; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:block_n2 (blocked 1 path attempt)
  - pathrestriction:block_n3 (blocked 1 path attempt)
=END=

############################################################
=TITLE=Show only blocking pathrestrictions when all paths blocked

=INPUT=
# Topology: 3 parallel paths between r1 and r2
# All 3 paths are blocked by pathrestrictions

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed; model = IOS, FW; routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.1.1; hardware = n2; }
 interface:n3 = { ip = 10.3.1.1; hardware = n3; }
 interface:n4 = { ip = 10.4.1.1; hardware = n4; }
}

network:n2 = { ip = 10.2.1.0/30; }
network:n3 = { ip = 10.3.1.0/30; }
network:n4 = { ip = 10.4.1.0/30; }

router:r2 = {
 managed; model = IOS, FW; routing = manual;
 interface:n2 = { ip = 10.2.1.2; hardware = n2; }
 interface:n3 = { ip = 10.3.1.2; hardware = n3; }
 interface:n4 = { ip = 10.4.1.2; hardware = n4; }
 interface:n5 = { ip = 10.5.1.1; hardware = n5; }
}

network:n5 = { ip = 10.5.1.0/24; }

# Block ALL 3 paths
pathrestriction:block_path_n2 = interface:r1.n2, interface:r2.n2, ;
pathrestriction:block_path_n3 = interface:r1.n3, interface:r2.n3, ;
pathrestriction:block_path_n4 = interface:r1.n4, interface:r2.n4, ;

service:test = {
 user = network:n1;
 permit src = user; dst = network:n5; prt = tcp 80;
}

=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n5]
 for rule permit src=network:n1; dst=network:n5; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:block_path_n2 (blocked 1 path attempt)
  - pathrestriction:block_path_n3 (blocked 1 path attempt)
  - pathrestriction:block_path_n4 (blocked 1 path attempt)
=END=

############################################################
=TITLE=Show blocking pathrestrictions with 3 routers in chain

=INPUT=
# Topology: 3 routers in chain
# Multiple paths between r1-r2 and r2-r3
# Pathrestrictions block all possible routes

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed; model = IOS, FW; routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.1.1; hardware = n2; }
 interface:n3 = { ip = 10.3.1.1; hardware = n3; }
}

network:n2 = { ip = 10.2.1.0/30; }
network:n3 = { ip = 10.3.1.0/30; }

router:r2 = {
 managed; model = IOS, FW; routing = manual;
 interface:n2 = { ip = 10.2.1.2; hardware = n2; }
 interface:n3 = { ip = 10.3.1.2; hardware = n3; }
 interface:n4 = { ip = 10.4.1.1; hardware = n4; }
 interface:n5 = { ip = 10.5.1.1; hardware = n5; }
}

network:n4 = { ip = 10.4.1.0/30; }
network:n5 = { ip = 10.5.1.0/30; }

router:r3 = {
 managed; model = IOS, FW; routing = manual;
 interface:n4 = { ip = 10.4.1.2; hardware = n4; }
 interface:n5 = { ip = 10.5.1.2; hardware = n5; }
 interface:n6 = { ip = 10.6.1.1; hardware = n6; }
}

network:n6 = { ip = 10.6.1.0/24; }

# Block path r1-r2 via n2
pathrestriction:block_r1_r2_n2 = interface:r1.n2, interface:r2.n2, ;
# Block path r1-r2 via n3
pathrestriction:block_r1_r2_n3 = interface:r1.n3, interface:r2.n3, ;
# Block path r2-r3 via n4
pathrestriction:block_r2_r3_n4 = interface:r2.n4, interface:r3.n4, ;
# Block path r2-r3 via n5
pathrestriction:block_r2_r3_n5 = interface:r2.n5, interface:r3.n5, ;

service:test = {
 user = network:n1;
 permit src = user; dst = network:n6; prt = tcp 80;
}

=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n6]
 for rule permit src=network:n1; dst=network:n6; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:block_r1_r2_n2 (blocked 1 path attempt)
  - pathrestriction:block_r1_r2_n3 (blocked 1 path attempt)
=END=

############################################################
=TITLE=Show pathrestrictions at different hops in chain

=INPUT=
# Topology: 3 routers in chain with 4 paths
# Block one path at r1-r2, all paths at r2-r3
# This should show restrictions from both hops

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed; model = IOS, FW; routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.1.1; hardware = n2; }
 interface:n3 = { ip = 10.3.1.1; hardware = n3; }
 interface:n7 = { ip = 10.7.1.1; hardware = n7; }
}

network:n2 = { ip = 10.2.1.0/30; }
network:n3 = { ip = 10.3.1.0/30; }
network:n7 = { ip = 10.7.1.0/30; }

router:r2 = {
 managed; model = IOS, FW; routing = manual;
 interface:n2 = { ip = 10.2.1.2; hardware = n2; }
 interface:n3 = { ip = 10.3.1.2; hardware = n3; }
 interface:n7 = { ip = 10.7.1.2; hardware = n7; }
 interface:n4 = { ip = 10.4.1.1; hardware = n4; }
 interface:n5 = { ip = 10.5.1.1; hardware = n5; }
}

network:n4 = { ip = 10.4.1.0/30; }
network:n5 = { ip = 10.5.1.0/30; }

router:r3 = {
 managed; model = IOS, FW; routing = manual;
 interface:n4 = { ip = 10.4.1.2; hardware = n4; }
 interface:n5 = { ip = 10.5.1.2; hardware = n5; }
 interface:n6 = { ip = 10.6.1.1; hardware = n6; }
}

network:n6 = { ip = 10.6.1.0/24; }

# Block only ONE path at r1-r2 (so path via n3 and n7 can reach r2)
pathrestriction:block_r1_r2_n2 = interface:r1.n2, interface:r2.n2, ;
# Block ALL paths at r2-r3
pathrestriction:block_r2_r3_n4 = interface:r2.n4, interface:r3.n4, ;
pathrestriction:block_r2_r3_n5 = interface:r2.n5, interface:r3.n5, ;

service:test = {
 user = network:n1;
 permit src = user; dst = network:n6; prt = tcp 80;
}

=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n6]
 for rule permit src=network:n1; dst=network:n6; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:block_r1_r2_n2 (blocked 1 path attempt)
  - pathrestriction:block_r2_r3_n4 (blocked 2 path attempts)
  - pathrestriction:block_r2_r3_n5 (blocked 2 path attempts)
=END=

############################################################
=TITLE=Show sorted pathrestrictions across 5 router chain

=INPUT=
# Topology: 5 routers in chain (r1 → r2 → r3 → r4 → r5)
# Multiple paths at each hop with selective blocking
# This tests sorting by specificity (fewer blocks = more specific = shown first)

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed; model = IOS, FW; routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.1.1; hardware = n2; }
 interface:n3 = { ip = 10.3.1.1; hardware = n3; }
 interface:n4 = { ip = 10.4.1.1; hardware = n4; }
}

network:n2 = { ip = 10.2.1.0/30; }
network:n3 = { ip = 10.3.1.0/30; }
network:n4 = { ip = 10.4.1.0/30; }

router:r2 = {
 managed; model = IOS, FW; routing = manual;
 interface:n2 = { ip = 10.2.1.2; hardware = n2; }
 interface:n3 = { ip = 10.3.1.2; hardware = n3; }
 interface:n4 = { ip = 10.4.1.2; hardware = n4; }
 interface:n5 = { ip = 10.5.1.1; hardware = n5; }
 interface:n6 = { ip = 10.6.1.1; hardware = n6; }
 interface:n7 = { ip = 10.7.1.1; hardware = n7; }
}

network:n5 = { ip = 10.5.1.0/30; }
network:n6 = { ip = 10.6.1.0/30; }
network:n7 = { ip = 10.7.1.0/30; }

router:r3 = {
 managed; model = IOS, FW; routing = manual;
 interface:n5 = { ip = 10.5.1.2; hardware = n5; }
 interface:n6 = { ip = 10.6.1.2; hardware = n6; }
 interface:n7 = { ip = 10.7.1.2; hardware = n7; }
 interface:n8 = { ip = 10.8.1.1; hardware = n8; }
 interface:n9 = { ip = 10.9.1.1; hardware = n9; }
}

network:n8 = { ip = 10.8.1.0/30; }
network:n9 = { ip = 10.9.1.0/30; }

router:r4 = {
 managed; model = IOS, FW; routing = manual;
 interface:n8 = { ip = 10.8.1.2; hardware = n8; }
 interface:n9 = { ip = 10.9.1.2; hardware = n9; }
 interface:n10 = { ip = 10.10.1.1; hardware = n10; }
 interface:n11 = { ip = 10.11.1.1; hardware = n11; }
}

network:n10 = { ip = 10.10.1.0/30; }
network:n11 = { ip = 10.11.1.0/30; }

router:r5 = {
 managed; model = IOS, FW; routing = manual;
 interface:n10 = { ip = 10.10.1.2; hardware = n10; }
 interface:n11 = { ip = 10.11.1.2; hardware = n11; }
 interface:n99 = { ip = 10.99.1.1; hardware = n99; }
}

network:n99 = { ip = 10.99.1.0/24; }

# Block ONE path at r1-r2 (so paths via n3 and n4 can proceed)
pathrestriction:block_r1_r2 = interface:r1.n2, interface:r2.n2, ;

# Block TWO paths at r2-r3 (so path via n7 can proceed)
pathrestriction:block_r2_r3_a = interface:r2.n5, interface:r3.n5, ;
pathrestriction:block_r2_r3_b = interface:r2.n6, interface:r3.n6, ;

# Block ONE path at r3-r4 (so path via n9 can proceed)
pathrestriction:block_r3_r4 = interface:r3.n8, interface:r4.n8, ;

# Block ALL paths at r4-r5
pathrestriction:block_r4_r5_a = interface:r4.n10, interface:r5.n10, ;
pathrestriction:block_r4_r5_b = interface:r4.n11, interface:r5.n11, ;

service:test = {
 user = network:n1;
 permit src = user; dst = network:n99; prt = tcp 80;
}

=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n99]
 for rule permit src=network:n1; dst=network:n99; prt=tcp 80; of service:test
 Check path restrictions and crypto interfaces.
 Possible blocking pathrestrictions:
  - pathrestriction:block_r1_r2 (blocked 1 path attempt)
  - pathrestriction:block_r2_r3_a (blocked 2 path attempts)
  - pathrestriction:block_r2_r3_b (blocked 2 path attempts)
  - pathrestriction:block_r3_r4 (blocked 2 path attempts)
  - pathrestriction:block_r4_r5_a (blocked 2 path attempts)
  - pathrestriction:block_r4_r5_b (blocked 2 path attempts)
=END=