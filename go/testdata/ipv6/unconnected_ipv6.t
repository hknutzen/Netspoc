
############################################################
=TITLE=Single router
=INPUT=
router:r = {}
=ERROR=
Error: router:r isn't connected to any network
=END=

############################################################
=TITLE=Router references unknown network
=INPUT=
router:r = { interface:n2; }
network:n1 = { ip6 = ::a01:100/120; }
=ERROR=
Error: Referencing undefined network:n2 from interface:r.n2
=END=

############################################################
=TITLE=Single network
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
=WARNING=NONE

############################################################
=TITLE=Unconnected
=INPUT=
router:r1 = { interface:n1; }
network:n1 = { ip6 = ::a01:100/120; }
router:r2 = { interface:n2; }
network:n2 = { ip6 = ::a01:200/120; }
router:r3 = { interface:n3; }
network:n3 = { ip6 = ::a01:300/120; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n2]
 - any:[network:n3]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Unconnected with managed
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n2]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Unconnected with crypto
=TEMPL=input
isakmp:x = {
 authentication = preshare;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
ipsec:x = {
 key_exchange = isakmp:x;
 esp_encryption = aes256;
 esp_authentication = sha;
 lifetime = 3600 sec;
}
crypto:x = {
 type = ipsec:x;
}
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:t  = { ip6 = ::a09:101; hub = crypto:x; hardware = t; }
}
network:t = { ip6 = ::a09:100/120; }
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:t  = { ip6 = ::a09:102; spoke = crypto:x; hardware = t; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n3 = { ip6 = ::a01:300/120; }
=INPUT=[[input]]
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n3]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Partition name at crypto parts
=INPUT=
[[input]]
network:t0 = { ip6 = ::a09:0/120; partition = INET; }
router:rt = {
 interface:t0;
 interface:t;
}
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n3]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Different partition names at crypto parts
=INPUT=
[[input]]
network:n0 = { ip6 = ::a01:0/120; partition = LAN; }
router:r0 = {
 interface:n0;
 interface:n1;
}

network:t0 = { ip6 = ::a09:0/120; partition = INET; }
router:rt = {
 interface:t0;
 interface:t;
}
=ERROR=
Error: Several partition names in partition any:[network:n0]:
 - LAN
 - INET
Error: IPv6 topology has unconnected parts:
 - any:[network:n3]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Unconnected with connected crypto part
=TEMPL=input2
[[input]]
router:fw = {
 managed;
 model = ASA;
 interface:t  = { ip6 = ::a09:103; hardware = t; }
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
}
=INPUT=[[input2]]
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:t]
 - any:[network:n3]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Unconnected with auto interface to other part
=INPUT=
[[input2]]
service:test = {
 user = interface:r1.[auto], interface:r3.[auto];
 permit src = user; dst = network:n2; prt = ip;
}
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:t]
 - any:[network:n3]
 Use partition attribute, if intended.
Error: No valid path
 from router:r3
 to any:[network:n2]
 while resolving interface:r3.[auto] (destination is network:n2).
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Path between different crypto parts
=INPUT=
isakmp:x = {
 authentication = preshare;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
ipsec:x = {
 key_exchange = isakmp:x;
 esp_encryption = aes256;
 esp_authentication = sha;
 lifetime = 3600 sec;
}
crypto:x1 = {
 type = ipsec:x;
}
crypto:x2 = {
 type = ipsec:x;
}
network:n0 = { ip6 = ::a00:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n0 = { ip6 = ::a00:101; hardware = n0; }
 interface:t1  = { ip6 = ::a01:901; hub = crypto:x1; hardware = t1; }
}
network:t1 = { ip6 = ::a01:900/120; partition = t1; }
router:vpn1 = {
 managed;
 model = IOS;
 interface:t1  = { ip6 = ::a01:902; spoke = crypto:x1; hardware = t1; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
network:n1 = { ip6 = ::a01:100/120; }
router:r2 = {
 managed;
 model = IOS;
 interface:n0 = { ip6 = ::a00:102; hardware = n0; }
 interface:t2  = { ip6 = ::a02:901; hub = crypto:x2; hardware = t2; }
}
network:t2 = { ip6 = ::a02:900/120; }
router:vpn0 = {
 managed;
 model = IOS;
 interface:t2  = { ip6 = ::a02:902; spoke = crypto:x2; hardware = t2; }
 interface:n2 = { ip6 = ::a02:101; hardware = n2; }
}
network:n2 = { ip6 = ::a02:100/120; }
service:s1 = {
 user = network:t1;
 permit src = user; dst = network:t2; prt = tcp;
}
=ERROR=
Warning: Spare partition name for single partition any:[network:n0]: t1.
Error: No valid path
 from any:[network:t1]
 to any:[network:t2]
 for rule permit src=network:t1; dst=network:t2; prt=tcp; of service:s1
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Cyclic reference between split crypto parts
=INPUT=
isakmp:x = {
 authentication = preshare;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
ipsec:x = {
 key_exchange = isakmp:x;
 esp_encryption = aes256;
 esp_authentication = sha;
 lifetime = 3600 sec;
}

# First partition
crypto:x1 = {
 type = ipsec:x;
}
crypto:x2 = {
 type = ipsec:x;
}
router:r1 = {
 managed;
 model = IOS;
 interface:t2 = { ip6 = ::a02:903; hardware = t2; }
 interface:t1  = { ip6 = ::a01:901; hub = crypto:x1; hardware = t1; }
}
network:t1 = { ip6 = ::a01:900/120; }
router:vpn1 = {
 managed;
 model = IOS;
 interface:t1  = { ip6 = ::a01:902; spoke = crypto:x1; hardware = t1; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
network:n1 = { ip6 = ::a01:100/120; }
router:r2 = {
 managed;
 model = IOS;
 interface:t1 = { ip6 = ::a01:903; hardware = t1; }
 interface:t2  = { ip6 = ::a02:901; hub = crypto:x2; hardware = t2; }
}
network:t2 = { ip6 = ::a02:900/120; }
router:vpn2 = {
 managed;
 model = IOS;
 interface:t2  = { ip6 = ::a02:902; spoke = crypto:x2; hardware = t2; }
 interface:n2 = { ip6 = ::a02:101; hardware = n2; }
}
network:n2 = { ip6 = ::a02:100/120; }

# Second partition
crypto:x1b = {
 type = ipsec:x;
}
crypto:x2b = {
 type = ipsec:x;
}
router:r1b = {
 managed;
 model = IOS;
 interface:t2b = { ip6 = ::a02:903; hardware = t2; }
 interface:t1b  = { ip6 = ::a01:901; hub = crypto:x1b; hardware = t1; }
}
network:t1b = { ip6 = ::a01:900/120; }
router:vpn1b = {
 managed;
 model = IOS;
 interface:t1b  = { ip6 = ::a01:902; spoke = crypto:x1b; hardware = t1; }
 interface:n1b = { ip6 = ::a01:101; hardware = n1; }
}
network:n1b = { ip6 = ::a01:100/120; }
router:r2b = {
 managed;
 model = IOS;
 interface:t1b = { ip6 = ::a01:903; hardware = t1; }
 interface:t2b  = { ip6 = ::a02:901; hub = crypto:x2b; hardware = t2; }
}
network:t2b = { ip6 = ::a02:900/120; }
router:vpn2b = {
 managed;
 model = IOS;
 interface:t2b  = { ip6 = ::a02:902; spoke = crypto:x2b; hardware = t2; }
 interface:n2b = { ip6 = ::a02:101; hardware = n2; }
}
network:n2b = { ip6 = ::a02:100/120; }
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:t2]
 - any:[network:t2b]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Intentionally unconnected, too many partition definitions
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = {
 ip6 = ::a01:200/120;
 {{.p1}}
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n3 = {
 ip6 = ::a01:300/120;
 partition = part2;
}
network:n4 = {
 ip6 = ::a01:400/120;
 {{.p3}}
}
network:n5 = {
 ip6 = ::a01:500/120;
 {{.p4}}
}
router:r2 = {
 model = ASA;
 managed;
 interface:n3 = { ip6 = ::a01:301; hardware = n1; }
 interface:n4 = { ip6 = ::a01:401; hardware = n2; }
 interface:n5 = { ip6 = ::a01:501; hardware = n3; }
}
service:s = {
 user = network:n1;
 permit src = user; dst = network:{{.d}}; prt = tcp 80;
}
=INPUT=
[[input
p1: "partition = part1;"
p3: "partition = part3;"
p4: "partition = part4;"
d: "n2"]]
=ERROR=
Error: Several partition names in partition any:[network:n3]:
 - part2
 - part3
 - part4
=END=

############################################################
=TITLE=Intentionally unconnected, named partitions
=INPUT=[[input {p1: "partition = part1;", p3: "", p4: "", d: "n2"}]]
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Intentionally unconnected, service between partitions
=INPUT=[[input {p1: "partition = part1;", p3: "", p4: "", d: "n3"}]]
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n3]
 for rule permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s
 Source and destination objects are located in different topology partitions: part1, part2.
=END=

############################################################
=TITLE=Unconnected, partition attribute missing
=INPUT=[[input {p1: "", p3: "", p4: "", d: "n2"}]]
=ERROR=
Error: IPv6 topology has unconnected parts:
 - any:[network:n1]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Intentionally unconnected with more than one network in zone.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; partition = part1; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; partition = part2; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2 = {
 interface:n3;
 interface:n4;
}
service:s = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n3]
 for rule permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s
 Source and destination objects are located in different topology partitions: part1, part2.
=END=

############################################################
=TITLE=Rule from/to interface between unconnected partitions
# zone1 is at network0,
# interface is at other zone at border of loop.
=INPUT=
network:n0 = { ip6 = ::a01:0/120; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; partition = part1; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 model = ASA;
 managed;
 interface:n0 = { ip6 = ::a01:1; hardware = n0; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
network:n4 = { ip6 = ::a01:400/120; partition = part2; }
router:r3 = {
 interface:n4;
}
pathrestriction:p = interface:r1.n1, interface:r2.n3;
service:s1 = {
 user = interface:r2.n3;
 permit src = user; dst = network:n4; prt = tcp 80;
 permit src = network:n4; dst = user; prt = tcp 80 ;
}
=ERROR=
Error: No valid path
 from interface:r2.n3
 to any:[network:n4]
 for rule permit src=interface:r2.n3; dst=network:n4; prt=tcp 80; of service:s1
 Source and destination objects are located in different topology partitions: part1, part2.
Error: No valid path
 from any:[network:n4]
 to interface:r2.n3
 for rule permit src=network:n4; dst=interface:r2.n3; prt=tcp 80; of service:s1
 Source and destination objects are located in different topology partitions: part2, part1.
=END=

############################################################
=TITLE=Valid path, intentionally unconnected, with loops (1)
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = {
 ip6 = ::a01:200/120;
 partition = part1;
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
network:n5 = { ip6 = ::a01:500/120; }
network:n6 = { ip6 = ::a01:600/120; }
network:n7 = { ip6 = ::a01:700/120; }
network:n8 = {
 ip6 = ::a01:800/120;
 partition = part2;
}
router:r2 = {
 model = ASA;
 managed;
 interface:n3 = { ip6 = ::a01:301; hardware = n1; }
 interface:n4 = { ip6 = ::a01:401; hardware = n2; }
 interface:n6 = { ip6 = ::a01:601; hardware = n3; }
}
router:r3 = {
 model = ASA;
 managed;
 interface:n3 = { ip6 = ::a01:302; hardware = n1; }
 interface:n5 = { ip6 = ::a01:501; hardware = n2; }
}
router:r4 = {
 model = ASA;
 managed;
 interface:n6 = { ip6 = ::a01:602; hardware = n1; }
 interface:n7 = { ip6 = ::a01:701; hardware = n2; }
}
router:r5 = {
 model = ASA;
 managed;
 interface:n5 = { ip6 = ::a01:502; hardware = n1; }
 interface:n7 = { ip6 = ::a01:702; hardware = n2; }
 interface:n8 = { ip6 = ::a01:801; hardware = n2; }
}
=TEMPL=output
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=INPUT=
[[input]]
service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Invalid path, intentionally unconnected, with loops (1)
=INPUT=
[[input]]
service:s = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
 permit src = network:n3; dst = user; prt = tcp 81;
}
=ERROR=
Error: No valid path
 from any:[network:n1]
 to any:[network:n3]
 for rule permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s
 Source and destination objects are located in different topology partitions: part1, part2.
Error: No valid path
 from any:[network:n3]
 to any:[network:n1]
 for rule permit src=network:n3; dst=network:n1; prt=tcp 81; of service:s
 Source and destination objects are located in different topology partitions: part2, part1.
=END=

############################################################
=TITLE=Valid path, intentionally unconnected, with loops (2)
=INPUT=
[[input]]
network:n0 = { ip6 = ::a01:0/120; }
router:r0 = {
 model = ASA;
 managed;
 interface:n0 = { ip6 = ::a01:1; hardware = n1; }
 interface:n3 = { ip6 = ::a01:303; hardware = n2; }
}
service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Single partition with partition name
=TEMPL=input
network:n1 = { ip6 = ::a01:100/120;}
network:n2 = {
 ip6 = ::a01:200/120;
 partition = part1;
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
=INPUT=[[input]]
=WARNING=
Warning: Spare partition name for single partition any:[network:n1]: part1.
=END=

############################################################
=TITLE=Too many partition definitions in one zone
=INPUT=
[[input]]
network:n3 = {
 ip6 = ::a01:300/120;
 partition = part4;
}
router:r2 = {
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n1; }
 interface:n3 = { ip6 = ::a01:301; hardware = n2; }
}
=ERROR=
Error: Only one partition name allowed in zone any:[network:n2], but found:
 - part4
 - part1
Warning: Spare partition name for single partition any:[network:n1]: part4.
=END=

############################################################
=TITLE=Partitions with own policy_distribution_point
=INPUT=
network:n1 = { ip6 = ::a01:100/120; partition = part1; host:h1 = {ip6 = ::a01:10a;} }
router:r1 = {
 model = IOS;
 managed;
 policy_distribution_point = host:h1;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
service:s1 = {
 user = interface:r1.[auto];
 permit src = host:h1; dst = user; prt = tcp 22;
}
network:n2 = { ip6 = ::a01:200/120; partition = part2; host:h2 = {ip6 = ::a01:20a;} }
router:r2 = {
 model = IOS;
 managed;
 policy_distribution_point = host:h2;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:s2 = {
 user = interface:r2.[auto];
 permit src = host:h2; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit tcp host ::a01:10a host ::a01:101 eq 22
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n2_in
 permit tcp host ::a01:20a host ::a01:201 eq 22
 deny ipv6 any any
=END=

############################################################
