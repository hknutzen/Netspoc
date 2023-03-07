# Input for pass1
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-90, icmp 3/3;
}

############################################################
=TITLE=Option '-h'
=INPUT=[[input]]
=PARAMS=r1 n1_in -h
=ERROR=
Usage: PROGRAM [-f file] code/router ACL-NAME ['ip1 ip2 tcp|udp port']...
  -f, --file string   Read packet descriptions from file
=END=

############################################################
=TITLE=Unknown option
=INPUT=[[input]]
=PARAMS=r1 n1_in --abc
=ERROR=
Error: unknown flag: --abc
=END=

############################################################
=TITLE=Read packets from unknown file
=INPUT=[[input]]
=PARAMS=r1 n1_in -f unknown
=ERROR=
Error: Can't open unknown: no such file or directory
=END=

############################################################
=TITLE=Permitted packet
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.1.2.12 tcp   85
=OUTPUT=
permit 10.1.1.11 10.1.2.12 tcp 85
=END=

############################################################
=TITLE=Denied packet
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0 tcp 85
=OUTPUT=
deny   10.1.1.11 10.0.0.0 tcp 85
=END=

############################################################
=TITLE=Packets from file
=INPUT=[[input]]
=PARAMS= r1 n1_in
=FOPTION=
10.1.1.11 10.1.2.12 tcp 85
10.1.1.11 10.0.0.0 udp 123
10.1.1.11 10.1.2.12 icmp 3/3
10.1.1.11 10.1.2.12 icmp 3/13
=OUTPUT=
permit 10.1.1.11 10.1.2.12 tcp 85
deny   10.1.1.11 10.0.0.0 udp 123
permit 10.1.1.11 10.1.2.12 icmp 3/3
deny   10.1.1.11 10.1.2.12 icmp 3/13
=END=

############################################################
=TITLE=Duplicate packets from file
=INPUT=[[input]]
=PARAMS= r1 n1_in
=FOPTION=
10.1.1.11 10.1.2.12 tcp 085
10.1.1.11 10.1.2.12 tcp 85
10.1.1.11 10.0.0.0 tcp 85
10.1.1.11 10.0.0.0 tcp 85
=OUTPUT=
permit 10.1.1.11 10.1.2.12 tcp 85
deny   10.1.1.11 10.0.0.0 tcp 85
=END=

############################################################
=TITLE=Missing packet parameter
=INPUT=[[input]]
=PARAMS= r1 n1_in
=ERROR=
Usage: PROGRAM [-f file] code/router ACL-NAME ['ip1 ip2 tcp|udp port']...
  -f, --file string   Read packet descriptions from file
=END=

############################################################
=TITLE=Unknown device
=INPUT=[[input]]
=PARAMS= r77 n1_in
=PARAM= 10.1.1.11 10.1.2.12 tcp 85
=ERROR=
Error: Can't find file out/r77.rules
=END=

############################################################
=TITLE=Unknown ACL
=INPUT=[[input]]
=PARAMS= r1 n77_in
=PARAM= 10.1.1.11 10.1.2.12 tcp 85
=ERROR=
Error: Unknown ACL: n77_in
=END=

############################################################
=TITLE=Missing protocol
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0
=WARNING=
Warning: Ignored packet, must have exactly 4 words: 10.1.1.11 10.0.0.0
=END=

############################################################
=TITLE=Incomplete protocol
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0 tcp
=WARNING=
Warning: Ignored packet, must have exactly 4 words: 10.1.1.11 10.0.0.0 tcp
=END=

############################################################
=TITLE=Unknown protocol
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0 foo 77
=WARNING=
Warning: Ignored packet with unexpected protocol: 10.1.1.11 10.0.0.0 foo 77
=END=

############################################################
=TITLE=Bad port
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0 tcp 99999
=WARNING=
Warning: Ignored packet with invalid protocol number: 99999
=END=

############################################################
=TITLE=Bad icmp: without code
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0 icmp 8
=WARNING=
Warning: Ignored icmp packet with invalid type/code: 10.1.1.11 10.0.0.0 icmp 8
=END=

############################################################
=TITLE=Bad icmp: invalid type and code
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0 icmp foo/-1
=WARNING=
Warning: Ignored packet with invalid protocol number: foo
Warning: Ignored packet with invalid protocol number: -1
=END=

############################################################
=TITLE=Bad proto
=INPUT=[[input]]
=PARAMS= r1 n1_in
=PARAM= 10.1.1.11 10.0.0.0 proto 999
=WARNING=
Warning: Ignored packet with invalid protocol number: 999
=END=

############################################################
=TITLE=Bad packets from file
=INPUT=[[input]]
=PARAMS= r1 n1_in
=FOPTION=
# Comment, then empty line

10.1.1.11 10.1.2.12 tcp 85
tcp 80 udp 90
10.1.1.11 10.0.0.0 tcp 85
10.1.1.11 10.01.02.12 tcp 85
010.001.001.011 10.0.0.0 tcp 85
=WARNING=
Warning: Ignored packet, must have exactly 4 words: # comment, then empty line
Warning: Ignored packet with invalid IP address: tcp
Warning: Ignored packet with invalid IP address: 80
Warning: Ignored packet with invalid IP address: 10.01.02.12
Warning: Ignored packet with invalid IP address: 010.001.001.011
=OUTPUT=
permit 10.1.1.11 10.1.2.12 tcp 85
deny   10.1.1.11 10.0.0.0 tcp 85
=END=

############################################################
=TITLE=IPv6
=INPUT=
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = n1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = n2;}
}
service:s1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
=OPTIONS=-6
=PARAMS=ipv6/r1 n1_in
=PARAM=
1000::abcd:0001:11 1000::abcd:0002:12 tcp 85
=OUTPUT=
permit 1000::abcd:1:11 1000::abcd:2:12 tcp 85
=END=
