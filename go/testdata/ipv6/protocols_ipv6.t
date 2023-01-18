
############################################################
=TEMPL=topo
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
=END=

############################################################
=TITLE=Unfinished protocol definition
=PARAMS=--ipv6
=INPUT=
protocol:p = tcp
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Unknown protocol
=PARAMS=--ipv6
=INPUT=
protocol:test = xyz;
network:n1 = { ip = ::a01:100/120; }
=ERROR=
Error: Unknown protocol in protocol:test
=END=

############################################################
=TITLE=Invalid ip protocol
=PARAMS=--ipv6
=INPUT=
protocol:test = ip v6;
network:n1 = { ip = ::a01:100/120; }
=ERROR=
Error: Unexpected details after protocol:test
=END=

############################################################
=TITLE=Missing port range
=PARAMS=--ipv6
=INPUT=
protocol:test = tcp 80 -
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Invalid ports and port ranges (1)
=PARAMS=--ipv6
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
protocol:p10 = tcp -;
network:n1 = { ip = ::a01:100/120; }
=ERROR=
Error: Expected port number > 0 in protocol:p1
Error: Expected port number < 65536 in protocol:p2
Error: Expected port number < 65536 in protocol:p3
Error: Expected port number < 65536 in protocol:p3
Error: Invalid port range in protocol:p4
Error: Expected port number > 0 in protocol:p5
Error: Expected port number > 0 in protocol:p5
Error: Invalid port range in protocol:p6
Error: Invalid port range in protocol:p7
Error: Invalid port range in protocol:p8
Error: Invalid port range in protocol:p9
Error: Expected number in protocol:p10: -
=OPTIONS=--max_errors=20

############################################################
=TITLE=Invalid ports and port ranges (2)
=PARAMS=--ipv6
=INPUT=
protocolgroup:g1 = tcp 77777, udp -1, udp 0, icmpv6 -3;
network:n1 = { ip = ::a01:100/120; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = user; prt = protocolgroup:g1;
}
=ERROR=
Error: Expected port number < 65536 in 'tcp 77777' of protocolgroup:g1
Error: Invalid port range in 'udp - 1' of protocolgroup:g1
Error: Expected port number > 0 in 'udp 0' of protocolgroup:g1
Error: Expected [TYPE [ / CODE]] in 'icmpv6 - 3' of protocolgroup:g1
=END=

############################################################
=TITLE=Valid port ranges
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 1-1023, udp 1024-65535;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit tcp ::a01:100/120 ::a01:200/120 lt 1024
 permit udp ::a01:100/120 ::a01:200/120 gt 1023
 deny ipv6 any any
=END=

############################################################
=TITLE=Invalid source port in unnamed protocol
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 20:1024-48000, udp 2000-2050 : 2020;
}
=ERROR=
Error: Must not use source port in 'tcp 20 : 1024 - 48000' of service:test.
 Source port is only valid in named protocol
Error: Must not use source port in 'udp 2000 - 2050 : 2020' of service:test.
 Source port is only valid in named protocol
=END=

############################################################
=TITLE=Invalid protocol modifier
=PARAMS=--ipv6
=INPUT=
protocol:test = tcp 80, src_xyz;
network:n1 = { ip = ::a01:100/120; }
=ERROR=
Error: Unknown modifier 'src_xyz' in protocol:test
=END=

############################################################
=TITLE=Different protocol modifiers
=PARAMS=--ipv6
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
protocol:Ping_Net       = icmpv6 8, src_net, dst_net, overlaps, no_check_supernet_rules;
protocol:Ping_Net_Reply = icmpv6 8, src_net, dst_net, overlaps, reversed, no_check_supernet_rules;
service:test = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = protocolgroup:tftp, udp 123;
 permit src = user; dst = network:n3; prt = icmpv6 3, protocolgroup:Ping_Net_both;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 permit udp host ::a01:10a ::a01:200/120 eq 123
 permit udp host ::a01:10a ::a01:200/120 eq 69
 permit udp host ::a01:10a ::a01:200/120 gt 1023
 permit icmp host ::a01:10a ::a01:300/120 3
 permit icmp ::a01:100/120 ::a01:300/120 8
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit udp ::a01:200/120 host ::a01:10a gt 1023
 permit udp ::a01:200/120 eq 123 host ::a01:10a
 deny ipv6 any any
--
ipv6 access-list n3_in
 deny ipv6 any host ::a01:101
 permit icmp ::a01:300/120 ::a01:100/120 8
 deny ipv6 any any
=END=

############################################################
=TITLE=Overlapping TCP ranges and modifier "reversed"
# Split port 21 from range 21-22 must not accidently use
# protocol:TCP_21_Reply
=PARAMS=--ipv6
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
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 deny ipv6 any host ::a01:401
 permit tcp ::a01:100/120 ::a01:200/120 range 21 22
 permit tcp ::a01:100/120 ::a01:300/120 range 20 21
 permit tcp ::a01:100/120 ::a01:400/120 eq 21
 deny ipv6 any any
=END=

############################################################
=TITLE=Split part of TCP range is larger than other at same position
=PARAMS=--ipv6
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
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 deny ipv6 any host ::a01:301
 deny ipv6 any host ::a01:401
 permit tcp ::a01:100/120 ::a01:300/120 range 80 85
 permit tcp ::a01:100/120 ::a01:400/120 range 80 95
 permit tcp ::a01:100/120 ::a01:200/120 range 70 94
 deny ipv6 any any
=END=

############################################################
=TITLE=Too large ICMP type
=PARAMS=--ipv6
=INPUT=
protocol:test = icmpv6 3000;
network:n1 = { ip = ::a01:100/120; }
=ERROR=
Error: Expected number < 256 in protocol:test
=END=

############################################################
=TITLE=Missing ICMP code
=PARAMS=--ipv6
=INPUT=
protocol:test = icmpv6 3 /
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Invalid separator in ICMP
=PARAMS=--ipv6
=INPUT=
protocol:p1 = icmpv6 3 - 4;
protocol:p2 = icmpv6 3@4;
protocol:p3 = icmpv6 3.4;
=ERROR=
Error: Expected [TYPE [ / CODE]] in protocol:p1
Error: Expected number in protocol:p2: 3@4
Error: Expected number in protocol:p3: 3.4
=END=

############################################################
=TITLE=Too large ICMP code
=PARAMS=--ipv6
=INPUT=
protocol:test = icmpv6 3 / 999;
network:n1 = { ip = ::a01:100/120; }
=ERROR=
Error: Expected number < 256 in protocol:test
=END=

############################################################
=TITLE=ICMP type with different codes
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = icmpv6 3/2, icmpv6 3/1, icmpv6 3/0, icmpv6 3/13, icmpv6 3/3;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit icmp ::a01:100/120 ::a01:200/120 3 2
 permit icmp ::a01:100/120 ::a01:200/120 3 1
 permit icmp ::a01:100/120 ::a01:200/120 3 0
 permit icmp ::a01:100/120 ::a01:200/120 3 13
 permit icmp ::a01:100/120 ::a01:200/120 3 3
 deny ipv6 any any
=END=

############################################################
=TITLE=Missing number of protocol 'proto'
=PARAMS=--ipv6
=INPUT=
protocol:test = proto
=ERROR=
Error: Expected ';' at line 1 of INPUT, at EOF
Aborted
=END=

############################################################
=TITLE=Single number for protocol 'proto'
=PARAMS=--ipv6
=INPUT=
protocol:test = proto -1;
=ERROR=
Error: Expected single protocol number in protocol:test
=END=

############################################################
=TITLE=Invalid protocol number
=PARAMS=--ipv6
=INPUT=
protocol:test1 = proto 0;
protocol:test2 = proto 300;
protocol:test3 = proto foo;
network:n1 = { ip = ::a01:100/120; }
=ERROR=
Error: Invalid protocol number '0' in protocol:test1
Error: Expected number < 256 in protocol:test2
Error: Expected number in protocol:test3: foo
=END=

############################################################
=TITLE=Valid protocol number
=PARAMS=--ipv6
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
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit 50 ::a01:100/120 ::a01:200/120
 permit 123 ::a01:100/120 ::a01:200/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Numbered protocol is part of 'ip'
=PARAMS=--ipv6
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
protocol:TCP  = proto 4;
protocol:UDP  = proto 17;
=ERROR=
Error: Must not use 'proto 4', use 'tcp' instead in protocol:TCP
Error: Must not use 'proto 17', use 'udp' instead in protocol:UDP
=END=

############################################################
=TITLE=Overlapping udp oneway
=PARAMS=--ipv6
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
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit udp ::a01:100/120 eq 69 ::a01:200/120
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any host ::a01:101
 permit udp ::a01:200/120 ::a01:100/120 eq 69
 deny ipv6 any any
=END=

############################################################
=TITLE=Modifier src_net to interface with pathrestriction
# Implicit pathrestriction from virtual interface.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = {ip = ::a01:101; hardware = n1; }
 interface:t1 = {ip = ::afe:10c; hardware = t1; }
}
network:t1 = {ip = ::afe:108/125;}
router:u1 = {
 interface:t1 = {ip = ::afe:109;}
 interface:n2 = {ip = ::a01:2fe; virtual = {ip = ::a01:201; }}
}
router:r2 = {
 managed;
 routing = manual;
 model = IOS;
 interface:t1 = {ip = ::afe:10a; hardware = t1;}
 interface:n2 = {ip = ::a01:2fd; virtual = {ip = ::a01:201; } hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
protocol:Ping_Netz = icmpv6 8, src_net, dst_net;
service:s1 = {
 user =  interface:u1.n2;
 permit src = user; dst = network:n1; prt = protocol:Ping_Netz;
}
=OUTPUT=
--ipv6/r2
ipv6 access-list n2_in
 permit icmp ::a01:200/120 ::a01:100/120 8
 deny ipv6 any any
=END=

############################################################
=TITLE=Must not apply dst_net to managed or loopback interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n1 = {ip = ::a01:101; hardware = n1; }
 interface:n2 = {ip = ::a01:201; hardware = n2; }
}
router:u = {
 interface:n2;
 interface:lo = {ip = ::a09:909; loopback; }
}
protocol:Ping_Netz = icmpv6 8, src_net, dst_net;
service:s1 = {
 user = interface:u.lo, interface:r1.n2;
 permit src = network:n1; dst = user; prt = protocol:Ping_Netz;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit icmp ::a01:100/120 host ::a01:201 8
 permit icmp ::a01:100/120 host ::a09:909 8
 deny ipv6 any any
=END=

############################################################
=TITLE=src_net with complex protocol
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 host:h1 = { ip = ::a01:10a; }
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = ::a01:101; hardware = n1; }
 interface:n2 = {ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120;
 host:h2 = { range = ::a01:204 - ::a01:206; }
}
protocol:tftp_net = udp 69:69, src_net, dst_net, oneway;
service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = protocol:tftp_net, udp 68;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit udp host ::a01:10a ::a01:204/127 eq 68
 permit udp host ::a01:10a host ::a01:206 eq 68
 permit udp ::a01:100/120 eq 69 ::a01:200/120 eq 69
 deny ipv6 any any
--
ipv6 access-list n2_in
 permit udp ::a01:204/127 eq 68 host ::a01:10a
 permit udp host ::a01:206 eq 68 host ::a01:10a
 deny ipv6 any any
=END=

############################################################
=TITLE=Unused protocol
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
protocol:http = tcp 80;
protocol:ping = icmpv6 8;
=WARNING=
Warning: unused protocol:http
Warning: unused protocol:ping
=OPTIONS=--check_unused_protocols=warn

############################################################
=TITLE=Unused protocolgroup
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
protocolgroup:g1 = tcp 80, icmpv6 8, protocolgroup:g2;
protocolgroup:g2 = udp 123, udp 69;
=WARNING=
Warning: unused protocolgroup:g1
Warning: unused protocolgroup:g2
=OPTIONS=--check_unused_groups=warn

############################################################
=TITLE=Duplicate elements in protocolgroup
=PARAMS=--ipv6
=INPUT=
protocol:NTP = udp 123;
protocol:NTPx = udp 123;
protocolgroup:g1 = tcp 80, protocol:NTP, tcp 80, protocol:NTPx;
protocolgroup:g2 = udp 123, protocol:NTP;
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = ::a01:101; hardware = n1; }
 interface:n2 = {ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = ::a01:101; hardware = n1; }
 interface:n2 = {ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
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
