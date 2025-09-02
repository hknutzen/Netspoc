
############################################################
=TEMPL=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
=END=

############################################################
=TITLE=Unfinished protocol definition
=INPUT=
protocol:p = tcp
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Unknown protocol
=INPUT=
protocol:test = xyz;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Unknown protocol in protocol:test: xyz
=END=

############################################################
=TITLE=Invalid ip protocol
=INPUT=
protocol:test = ip v6;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Unexpected details after protocol:test
=END=

############################################################
=TITLE=Missing port range
=INPUT=
protocol:test = tcp 80 -
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Invalid ports and port ranges (1)
=INPUT=
protocol:p1 = tcp 0 - 10;
protocol:p2 = udp 60000 - 99999;
protocol:p3 = udp 100100 - 100102;
protocol:p4 = tcp 90 - 80;
protocol:p5 = tcp 0 - 0;
protocol:p6 = tcp - 2 -;
protocol:p7 = tcp 1 - 2 -;
protocol:p8 = tcp 1 - 2 - 3;
protocol:p9 = tcp 1 - 2 : 3 : 4;
protocol:p10 = tcp 1 . 2 . 3 - 4;
protocol:p11 = tcp -;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Expected port number > 0 in protocol:p1
Error: Expected port number < 65536 in protocol:p2
Error: Expected port number < 65536 in protocol:p3
Error: Expected port number < 65536 in protocol:p3
Error: Invalid port range in protocol:p4
Error: Expected port number > 0 in protocol:p5
Error: Expected port number > 0 in protocol:p5
Error: Unknown protocol in protocol:p6: tcp-2-
Error: Expected number in protocol:p7: 2-
Error: Expected number in protocol:p8: 2-3
Error: Expected number in protocol:p9: 3:4
Error: Expected number in protocol:p10: 1 . 2 . 3
Error: Unknown protocol in protocol:p11: tcp-
=OPTIONS=--max_errors=20

############################################################
=TITLE=Invalid ports and port ranges (2)
=INPUT=
protocolgroup:g1 = tcp 77777, udp -1, udp 0, icmp 3 13;
network:n1 = { ip = 10.1.1.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = user; prt = protocolgroup:g1;
}
=ERROR=
Error: Expected port number < 65536 in 'tcp 77777' of protocolgroup:g1
Error: Unknown protocol in 'udp-1' of protocolgroup:g1
Error: Expected port number > 0 in 'udp 0' of protocolgroup:g1
Error: Expected single number in 'icmp 3 13' of protocolgroup:g1: 3 13
=END=

############################################################
=TITLE=Valid port ranges
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 1-1023, udp 1024-65535;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 lt 1024
 permit udp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 gt 1023
 deny ip any any
=END=

############################################################
=TITLE=Invalid source port in unnamed protocol
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 20:1024-48000, udp 2000-2050 : 2020;
}
=ERROR=
Error: Must not use source port in 'tcp 20:1024-48000' of service:test.
 Source port is only valid in named protocol
Error: Must not use source port in 'udp 2000-2050:2020' of service:test.
 Source port is only valid in named protocol
=END=

############################################################
=TITLE=Invalid protocol modifier
=INPUT=
protocol:test = tcp 80, src_xyz;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Unknown modifier 'src_xyz' in protocol:test
=END=

############################################################
=TITLE=Different protocol modifiers
=INPUT=
[[topo]]
protocolgroup:tftp = protocol:tftp-request,
		     protocol:tftp-server-answer,
		     protocol:tftp-client-answer,
;
protocol:tftp-request= udp 69, oneway;
protocol:tftp-server-answer = udp 1024-65535, stateless, reversed, oneway;
protocol:tftp-client-answer = udp 1024-65535, stateless, oneway;
protocolgroup:Ping_Net_both =
 protocol:Ping_Net,
 protocol:Ping_Net_Reply,
;
protocol:Ping_Net       = icmp 8, src_net, dst_net, overlaps, no_check_supernet_rules;
protocol:Ping_Net_Reply = icmp 8, src_net, dst_net, overlaps, reversed, no_check_supernet_rules;
service:test = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = protocolgroup:tftp, udp 123;
 permit src = user; dst = network:n3; prt = icmp 3, protocolgroup:Ping_Net_both;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 permit udp host 10.1.1.10 10.1.2.0 0.0.0.255 eq 123
 permit udp host 10.1.1.10 10.1.2.0 0.0.0.255 eq 69
 permit udp host 10.1.1.10 10.1.2.0 0.0.0.255 gt 1023
 permit icmp host 10.1.1.10 10.1.3.0 0.0.0.255 3
 permit icmp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 8
 deny ip any any
--
ip access-list extended n2_in
 permit udp 10.1.2.0 0.0.0.255 host 10.1.1.10 gt 1023
 permit udp 10.1.2.0 0.0.0.255 eq 123 host 10.1.1.10
 deny ip any any
--
ip access-list extended n3_in
 deny ip any host 10.1.1.1
 permit icmp 10.1.3.0 0.0.0.255 10.1.1.0 0.0.0.255 8
 deny ip any any
=END=

############################################################
=TITLE=Overlapping TCP ranges and modifier "reversed"
# Split port 21 from range 21-22 must not accidently use
# protocol:TCP_21_Reply
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 21 - 22;
 permit src = user; dst = network:n3; prt = tcp 20 - 21;
 permit src = user; dst = network:n4; prt = tcp 21;
}
protocol:TCP_21_Reply = tcp 21, reversed;
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 range 21 22
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 range 20 21
 permit tcp 10.1.1.0 0.0.0.255 10.1.4.0 0.0.0.255 eq 21
 deny ip any any
=END=

############################################################
=TITLE=Split part of TCP range is larger than other at same position
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 70 - 89;
 permit src = user; dst = network:n3; prt = tcp 80 - 85;
# is split to 80 - 89, 90 - 95 and joined in pass2.
 permit src = user; dst = network:n4; prt = tcp 80 - 95;
# is joined in pass2.
 permit src = user; dst = network:n2; prt = tcp 90 - 94;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 range 80 85
 permit tcp 10.1.1.0 0.0.0.255 10.1.4.0 0.0.0.255 range 80 95
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 range 70 94
 deny ip any any
=END=

############################################################
=TITLE=Too large ICMP type
=INPUT=
protocol:test = icmp 3000;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Expected number < 256 in protocol:test
=END=

############################################################
=TITLE=Missing ICMP code
=INPUT=
protocol:test = icmp 3 /
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Invalid separator in ICMP
=INPUT=
protocol:p1 = icmp 3 - 4;
protocol:p2 = icmp 3@4;
protocol:p3 = icmp 3.4;
=ERROR=
Error: Expected number in protocol:p1: 3-4
Error: Expected number in protocol:p2: 3@4
Error: Expected number in protocol:p3: 3.4
=END=

############################################################
=TITLE=Too large ICMP code
=INPUT=
protocol:test = icmp 3 / 999;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Expected number < 256 in protocol:test
=END=

############################################################
=TITLE=ICMP type with different codes
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = icmp 3/2, icmp 3/1, icmp 3/0, icmp 3/13, icmp 3/3;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 2
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 1
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 0
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 13
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 3
 deny ip any any
=END=

############################################################
=TITLE=Missing number of protocol 'proto'
=INPUT=
protocol:test = proto
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Single number for protocol 'proto'
=INPUT=
protocol:test = proto 1 2;
=ERROR=
Error: Expected single number in protocol:test: 1 2
=END=

############################################################
=TITLE=Invalid protocol number
=INPUT=
protocol:test1 = proto 0;
protocol:test2 = proto 300;
protocol:test3 = proto foo;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Invalid protocol number '0' in protocol:test1
Error: Expected number < 256 in protocol:test2
Error: Expected number in protocol:test3: foo
=END=

############################################################
=TITLE=Valid protocol number
=INPUT=
[[topo]]
protocol:test = proto 123;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = proto 50, protocol:test;
}
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit 50 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255
 permit 123 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Numbered protocol is part of 'ip'
=INPUT=
[[topo]]
protocol:test = proto 123;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocol:test, ip;
}
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s1:
  permit src=network:n1; dst=network:n2; prt=protocol:test; of service:s1
< permit src=network:n1; dst=network:n2; prt=ip; of service:s1
=END=

############################################################
=TITLE=Must not use standard protocol as number
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
protocol:TCP  = proto 4;
protocol:UDP  = proto 17;
=ERROR=
Error: Must not use 'proto 4', use 'tcp' instead in protocol:TCP
Error: Must not use 'proto 17', use 'udp' instead in protocol:UDP
=END=

############################################################
=TITLE=Overlapping udp oneway
=INPUT=
[[topo]]
protocol:tftp-request= udp 69, oneway;
service:s1 = {
 user = network:n1;
 permit src = network:n2;
        dst = user;
        prt = protocol:tftp-request;
}
service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = network:n2;
        dst = user;
        prt = udp 69;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit udp 10.1.1.0 0.0.0.255 eq 69 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 permit udp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 69
 deny ip any any
=END=

############################################################
=TITLE=Modifier src_net to interface with pathrestriction
# Implicit pathrestriction from virtual interface.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:t1 = {ip = 10.254.1.12; hardware = t1; }
}
network:t1 = {ip = 10.254.1.8/29;}
router:u1 = {
 interface:t1 = {ip = 10.254.1.9;}
 interface:n2 = {ip = 10.1.2.254; virtual = {ip = 10.1.2.1; }}
}
router:r2 = {
 managed;
 routing = manual;
 model = IOS;
 interface:t1 = {ip = 10.254.1.10; hardware = t1;}
 interface:n2 = {ip = 10.1.2.253; virtual = {ip = 10.1.2.1; } hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
protocol:Ping_Netz = icmp 8/0, src_net, dst_net;
service:s1 = {
 user =  interface:u1.n2;
 permit src = user; dst = network:n1; prt = protocol:Ping_Netz;
}
=OUTPUT=
--r2
ip access-list extended n2_in
 permit icmp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 8 0
 deny ip any any
=END=

############################################################
=TITLE=Must not apply dst_net to managed or loopback interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}
router:u = {
 interface:n2;
 interface:lo = {ip = 10.9.9.9; loopback; }
}
protocol:Ping_Netz = icmp 8, src_net, dst_net;
service:s1 = {
 user = interface:u.lo, interface:r1.n2;
 permit src = network:n1; dst = user; prt = protocol:Ping_Netz;
}
=OUTPUT=
--r1
ip access-list extended n1_in
 permit icmp 10.1.1.0 0.0.0.255 host 10.1.2.1 8
 permit icmp 10.1.1.0 0.0.0.255 host 10.9.9.9 8
 deny ip any any
=END=

############################################################
=TITLE=src_net with complex protocol
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24;
 host:h2 = { range = 10.1.2.4 - 10.1.2.6; }
}
protocol:tftp_net = udp 69:69, src_net, dst_net, oneway;
service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = protocol:tftp_net, udp 68;
}
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit udp host 10.1.1.10 10.1.2.4 0.0.0.1 eq 68
 permit udp host 10.1.1.10 host 10.1.2.6 eq 68
 permit udp 10.1.1.0 0.0.0.255 eq 69 10.1.2.0 0.0.0.255 eq 69
 deny ip any any
--
ip access-list extended n2_in
 permit udp 10.1.2.4 0.0.0.1 eq 68 host 10.1.1.10
 permit udp host 10.1.2.6 eq 68 host 10.1.1.10
 deny ip any any
=END=

############################################################
=TITLE=Unused protocol
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
protocol:http = tcp 80;
protocol:ping = icmp 8;
=WARNING=
Warning: unused protocol:http
Warning: unused protocol:ping
=OPTIONS=--check_unused_protocols=warn

############################################################
=TITLE=Unused protocolgroup
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
protocolgroup:g1 = tcp 80, icmp 8, protocolgroup:g2;
protocolgroup:g2 = udp 123, udp 69;
=WARNING=
Warning: unused protocolgroup:g1
Warning: unused protocolgroup:g2
=OPTIONS=--check_unused_groups=warn

############################################################
=TITLE=Duplicate elements in protocolgroup
=INPUT=
protocol:NTP = udp 123;
protocol:NTPx = udp 123;
protocolgroup:g1 = tcp 80, protocol:NTP, tcp 80, protocol:NTPx;
protocolgroup:g2 = udp 123, protocol:NTP;
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
 permit src = user; dst = network:n2; prt = protocolgroup:g1, protocolgroup:g2;
}
=WARNING=
Warning: Ignoring duplicate 'tcp 80' in protocolgroup:g1
Warning: Ignoring duplicate 'udp 123' in protocolgroup:g1
Warning: Ignoring duplicate 'udp 123' in protocolgroup:g2
Warning: Ignoring duplicate 'udp 123' in service:s1
=END=

############################################################
=TITLE=Unknown protocol and protocolgroup
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
protocolgroup:g1 = protocol:p1, protocolgroup:g2, foo:bar;
service:s1 = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = protocolgroup:g1, protocol:p1;
}
=ERROR=
Error: Can't resolve reference to protocol:p1 in protocolgroup:g1
Error: Can't resolve reference to protocolgroup:g2 in protocolgroup:g1
Error: Unknown protocol in 'foo:bar' of protocolgroup:g1
Error: Can't resolve reference to protocol:p1 in service:s1
=END=

############################################################
=TITLE=Recursive protocolgroup
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
protocolgroup:g1 = tcp 80, protocolgroup:g2;
protocolgroup:g2 = tcp 90, protocolgroup:g1;
service:s1 = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = protocolgroup:g1;
}
=ERROR=
Error: Found recursion in definition of protocolgroup:g2
=END=

############################################################
=TITLE=Missing rule with tcp 22 from policy_distribution_point
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:pdp = { ip = 10.1.1.111; } }
router:r1 = {
 managed;
 model = IOS;
 policy_distribution_point = host:pdp;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
}
service:s1 = {
    user = interface:r1.[auto];
    permit src = host:pdp; dst = user; prt = tcp 80-90;
}
=WARNING=
Warning: Missing rules to reach 1 devices from policy_distribution_point:
 - router:r1
=OPTIONS=--check_policy_distribution_point=warn

############################################################
