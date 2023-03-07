
############################################################
=TITLE=Invalid IPv4 addresses
=INPUT=
network:n1 = { ip = 999.1.1.0/24; }
network:n2 = { ip = 10.888.1.0/24; }
network:n3 = { ip = 10.1.777.0/24; }
network:n4 = { ip = 10.1.1.666/32; }
network:n5 = { ip = 10.1.one.six/32; }
network:n6 = { ip = ip-address/32; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
 interface:n4;
 interface:n5;
 interface:n6;
}
=ERROR=
Error: Invalid CIDR address: 999.1.1.0/24 in 'ip' of network:n1
Error: Invalid CIDR address: 10.888.1.0/24 in 'ip' of network:n2
Error: Invalid CIDR address: 10.1.777.0/24 in 'ip' of network:n3
Error: Invalid CIDR address: 10.1.1.666/32 in 'ip' of network:n4
Error: Invalid CIDR address: 10.1.one.six/32 in 'ip' of network:n5
Error: Invalid CIDR address: ip-address/32 in 'ip' of network:n6
=END=

############################################################
=TITLE=Unicode digits in IPv4 address
=INPUT=
network:n1 = { ip = १.२.३.४/32; } # 1.2.3.4 in DEVANAGARI
=ERROR=
Error: Invalid CIDR address: १.२.३.४/32 in 'ip' of network:n1
=END=

############################################################
=TITLE=Simple topology IPv4
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.2.2.1; hardware = n2;}
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
=OUTPUT=
-- r1
ip access-list extended n1_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 range 80 90
 deny ip any any
=END=

############################################################
=TITLE=Interface IP has address of its network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.0; }
}
=ERROR=
Error: interface:r1.n1 has address of its network
=END=

############################################################
=TITLE=Interface IP has broadcast address
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.255; }
}
=ERROR=
Error: interface:r1.n1 has broadcast address
=END=

############################################################
=TITLE=Network and broadcast address ok in /31 network
=INPUT=
network:n1 = { ip = 10.1.1.0/31; }
router:r1 = { interface:n1 = { ip = 10.1.1.0; } }
router:r2 = { interface:n1 = { ip = 10.1.1.1; } }
=WARNING=NONE

############################################################
=TITLE=Must not use icmp protocol as number
=INPUT=
protocol:ICMP  = proto 1;
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = interface:r1.n1;
 prt = protocol:ICMP;
}
=ERROR=
Error: 'proto 1' must not be used in service:test1, use 'icmp' instead
=END=

############################################################
=TITLE=Must not use icmpv6 with ipv4
=INPUT=
protocol:ICMPv6  = icmpv6;
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:test1 = {
 user = network:n1;
 permit src = user;
 dst = interface:r1.n1;
 prt = protocol:ICMPv6;
}
=ERROR=
Error: protocol:ICMPv6 must not be used in IPv4 service:test1
=END=

############################################################
=TITLE=Must not use icmpv6 with ipv4 general permit
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.2.2.1; hardware = n2;}
}
area:a = {
 anchor = network:n1;
 router_attributes = { general_permit = icmpv6; }
}
=ERROR=
Error: icmpv6 must not be used in IPv4 general_permit of router_attributes of area:a
=END=

############################################################
