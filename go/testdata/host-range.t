
############################################################
=TITLE=Leave order unchanged when combining addresses
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h2 = { ip = 10.1.1.2; }
 host:h3 = { ip = 10.1.1.3; }
 host:h4 = { ip = 10.1.1.4; }
 host:h6 = { ip = 10.1.1.6; }
 host:h7 = { ip = 10.1.1.7; }
 host:h8 = { ip = 10.1.1.8; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:test = {
 user = host:h2, host:h4, host:h3, host:h7, host:h8, host:h6;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--r
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.2 0.0.0.1 10.1.2.0 0.0.0.255 eq 80
 permit tcp host 10.1.1.4 10.1.2.0 0.0.0.255 eq 80
 permit tcp host 10.1.1.8 10.1.2.0 0.0.0.255 eq 80
 permit tcp 10.1.1.6 0.0.0.1 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Split and combine host ranges
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.15-10.1.1.19; }
 host:b = { range = 10.1.1.20-10.1.1.24; }
 host:c = { range = 10.1.1.25-10.1.1.35; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n = { ip = 10.1.1.1; hardware = ethernet0; }
 interface:x = { ip = 192.168.1.1; hardware = ethernet1; }
}
network:x = { ip = 192.168.1.0/24; }
service:test = {
 user = host:a, host:b, host:c;
 permit src = user; dst = network:x; prt = tcp 80;
}
=OUTPUT=
--r
ip access-list extended ethernet0_in
 deny ip any host 192.168.1.1
 permit tcp host 10.1.1.15 192.168.1.0 0.0.0.255 eq 80
 permit tcp 10.1.1.16 0.0.0.15 192.168.1.0 0.0.0.255 eq 80
 permit tcp 10.1.1.32 0.0.0.3 192.168.1.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Combine host ranges  into network and ignore it in 2. step
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
 host:r6-7 = { range = 10.1.1.6-10.1.1.7; }
}
router:u = {
 interface:n1;
 interface:n2;
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:r0-127 = { range = 10.1.2.0-10.1.2.127; }
 host:r128-255 = { range = 10.1.2.128-10.1.2.255; }
}
router:r = {
 model = IOS, FW;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
service:test = {
 user = host:h4, host:h5, host:r6-7, host:r0-127, host:r128-255;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r
ip access-list extended n1_in
 deny ip any host 10.1.3.1
 permit tcp 10.1.1.4 0.0.0.3 10.1.3.0 0.0.0.255 eq 80
 permit tcp 10.1.2.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Large host ranges for non private addresses
#No IPv6
=INPUT=
network:inet = {
 ip = 0.0.0.0/0;
 host:r1 = { range = 0.0.0.0 - 9.255.255.255; }
 host:r2 = { range = 11.0.0.0 - 172.15.255.255; }
 host:r3 = { range = 172.32.0.0 - 192.167.255.255; }
 host:r4 = { range = 192.169.0.0 - 255.255.255.255; }
}

router:r = {
 managed;
 model = NX-OS;
 interface:inet = { ip = 10.9.9.1;  hardware = inet; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}

network:n1 = {
 ip = 10.1.1.0/24;
 subnet_of = network:inet;
}

service:s1 = {
 user = host:[network:inet];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
-- r
! [ ACL ]
object-group ip address g0
 10 0.0.0.0/5
 20 8.0.0.0/7
 30 11.0.0.0/8
 40 12.0.0.0/6
 50 16.0.0.0/4
 60 32.0.0.0/3
 70 64.0.0.0/2
 80 128.0.0.0/3
 90 160.0.0.0/5
 100 168.0.0.0/6
 110 172.0.0.0/12
 120 172.32.0.0/11
 130 172.64.0.0/10
 140 172.128.0.0/9
 150 173.0.0.0/8
 160 174.0.0.0/7
 170 176.0.0.0/4
 180 192.0.0.0/9
 190 192.128.0.0/11
 200 192.160.0.0/13
 210 192.169.0.0/16
 220 192.170.0.0/15
 230 192.172.0.0/14
 240 192.176.0.0/12
 250 192.192.0.0/10
 260 193.0.0.0/8
 270 194.0.0.0/7
 280 196.0.0.0/6
 290 200.0.0.0/5
 300 208.0.0.0/4
 310 224.0.0.0/3
ip access-list inet_in
 10 deny ip any 10.1.1.1/32
 20 permit tcp addrgroup g0 10.1.1.0/24 eq 80
 30 deny ip any any
=END=

############################################################
=TITLE=Redundant rule from host range and combined ip hosts
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
 host:h6 = { ip = 10.1.1.6; }
 host:h7 = { ip = 10.1.1.7; }
 host:r4-5 = { range = 10.1.1.4-10.1.1.5; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:test = {
 user = host:h4, host:h5, host:r4-5;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h4; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r4-5; dst=network:n2; prt=tcp 80; of service:test
  permit src=host:h5; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r4-5; dst=network:n2; prt=tcp 80; of service:test
=OUTPUT=
--r
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.4 0.0.0.1 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Duplicate host ranges
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.15-10.1.1.19; }
 host:b = { range = 10.1.1.15-10.1.1.19; }
}
=ERROR=
Error: Duplicate IP address for host:a and host:b
=END=

############################################################
=TITLE=Host range and interface IP overlap
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.1-10.1.1.19; }
}
router:r = {
 interface:n = { ip = 10.1.1.1; }
}
=ERROR=
Error: Duplicate IP address for interface:r.n and host:a
=END=

############################################################
=TITLE=Ignore overlap of subnet range and interface IP
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.0-10.1.1.15; }
}
router:r = {
 interface:n = { ip = 10.1.1.1; }
}
=WARNING=NONE

############################################################
=TITLE=Duplicate host and interface IP
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 host:a = { ip = 10.1.1.1; }
}
router:r = {
 interface:n = { ip = 10.1.1.1; }
}
=ERROR=
Error: Duplicate IP address for interface:r.n and host:a
=END=

############################################################
=TITLE=Duplicate host IPs
=INPUT=
network:n = {
 ip = 10.1.1.0/24;
 host:a = { ip = 10.1.1.1; }
 host:b = { ip = 10.1.1.1; }
}
=ERROR=
Error: Duplicate IP address for host:a and host:b
=END=

############################################################
=TITLE=Redundant rule from host range and combined ip hosts
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
 host:h6 = { ip = 10.1.1.6; }
 host:h7 = { ip = 10.1.1.7; }
 host:r6-7 = { range = 10.1.1.6-10.1.1.7; }
}
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:test = {
 user = host:h4, host:h5, host:h6, host:h7, host:r6-7;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h6; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r6-7; dst=network:n2; prt=tcp 80; of service:test
  permit src=host:h7; dst=network:n2; prt=tcp 80; of service:test
< permit src=host:r6-7; dst=network:n2; prt=tcp 80; of service:test
=END=

############################################################
=TITLE=Must not combine list in place
# List of src objects is referenced from two different path rules.
# If combineSubnets is applied twice on the same list,
# we would get garbage.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:h20 = { ip = 10.1.1.20; }
 host:h21 = { ip = 10.1.1.21; }
 host:h22 = { ip = 10.1.1.22; }
 host:h23 = { ip = 10.1.1.23; }
 host:h24 = { ip = 10.1.1.24; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n2, network:n3;
 permit src = user; dst = host:h22, host:h23, host:h24; prt = tcp 80;
}
=OUTPUT=
-- r1
! n2_in
object-group network g0
 network-object 10.1.1.22 255.255.255.254
 network-object host 10.1.1.24
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 object-group g0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
-- r2
! n3_in
object-group network g0
 network-object 10.1.1.22 255.255.255.254
 network-object host 10.1.1.24
access-list n3_in extended permit tcp 10.1.3.0 255.255.255.0 object-group g0 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
