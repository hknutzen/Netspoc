
############################################################
=TITLE=Find redundant rules
=PARAMS=--ipv6
=INPUT=
network:n1-sub = {
 ip = ::a01:180/121;
 subnet_of = network:n1;
 host:h1 = { ip = ::a01:182; }
}
router:u = {
 interface:n1-sub;
 interface:n1;
}
network:n1 = { ip = ::a01:100/120; }
any:a1 = { link = network:n1; }
router:filter = {
 managed;
 model = Linux;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
 interface:n3 = { ip = ::a03:301; hardware = n3; }
}
network:n2 = {
 ip = ::a02:200/120;
 host:h2 = { ip = ::a02:20a; }
}
any:a2 = { link = network:n2; }
network:n3 = {
 ip = ::a03:300/120;
 host:h3 = { ip = ::a03:30a; }
}
any:a3 = { link = network:n3; }
# permit < deny
# h1 < n1-sub < n1 < a1
# h2 < n2 < a2
# h3 < n3 < a3
# tcp 80 < tcp 80-90 < tcp < ip
# rule1 <= rule2 if and only if
# rule1[src] <= rule2[src] &&
# rule1[dst] <= rule2[dst] &&
# rule1[prt] <= rule2[prt] &&
# 1a < 1b, 1a < 1e
service:1a = {
 user = host:h1;
 permit src = user;
        dst = network:n2;
        prt = ip;
}
# non redundant
service:1b = {
 user = any:a1;
 permit src = user;
        dst = network:n2;
        prt = ip;
}
# non redundant
service:1c = {
 user = host:h1;
 permit src = user;
        dst = any:a2;
        prt = tcp 80;
}
# 1d < 1b, 1d < 1e
service:1d = {
 user = network:n1;
 permit src = user;
        dst = host:h2;
        prt = tcp;
}
# non redundant
service:1e = {
 user = network:n1;
 deny   src = user;
        dst = network:n2;
        prt = ip;
}
# 2a < 2b < 2c
service:2a = {
 user = host:h1;
 permit src = user;
        dst = host:h3;
        prt = tcp 80;
}
service:2b = {
 user = network:n1-sub;
 permit src = user;
        dst = network:n3;
        prt = tcp 80-90;
}
# non redundant
service:2c = {
 user = network:n1;
 permit src = user;
        dst = any:a3;
        prt = tcp;
}
=END=
=WARNING=
Warning: Redundant rules in service:1a compared to service:1b:
  permit src=host:h1; dst=network:n2; prt=ip; of service:1a
< permit src=any:a1; dst=network:n2; prt=ip; of service:1b
Warning: Redundant rules in service:1a compared to service:1e:
  permit src=host:h1; dst=network:n2; prt=ip; of service:1a
< deny src=network:n1; dst=network:n2; prt=ip; of service:1e
Warning: Redundant rules in service:1d compared to service:1b:
  permit src=network:n1; dst=host:h2; prt=tcp; of service:1d
< permit src=any:a1; dst=network:n2; prt=ip; of service:1b
Warning: Redundant rules in service:1d compared to service:1e:
  permit src=network:n1; dst=host:h2; prt=tcp; of service:1d
< deny src=network:n1; dst=network:n2; prt=ip; of service:1e
Warning: Redundant rules in service:2a compared to service:2b:
  permit src=host:h1; dst=host:h3; prt=tcp 80; of service:2a
< permit src=network:n1-sub; dst=network:n3; prt=tcp 80-90; of service:2b
Warning: Redundant rules in service:2a compared to service:2c:
  permit src=host:h1; dst=host:h3; prt=tcp 80; of service:2a
< permit src=network:n1; dst=any:a3; prt=tcp; of service:2c
Warning: Redundant rules in service:2b compared to service:2c:
  permit src=network:n1-sub; dst=network:n3; prt=tcp 80-90; of service:2b
< permit src=network:n1; dst=any:a3; prt=tcp; of service:2c
Warning: service:1a is fully redundant
Warning: service:1d is fully redundant
Warning: service:2a is fully redundant
Warning: service:2b is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Duplicate protocol in rule
=PARAMS=--ipv6
=INPUT=
protocol:NTP = udp 123;
network:n1 = { ip = ::a01:100/120;}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:202; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = protocol:NTP, tcp 80, udp 123;
}
=WARNING=
Warning: Ignoring duplicate 'udp 123' in service:s1
=END=

############################################################
=TITLE=Redundant protocol in rule
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:202; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = udp 123, ip;
}
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s1:
  permit src=network:n1; dst=network:n2; prt=udp 123; of service:s1
< permit src=network:n1; dst=network:n2; prt=ip; of service:s1
=END=

############################################################
=TITLE=Redundant rules having protocols with and without modifiers
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:202; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
protocol:Ping_Net = icmpv6 8, src_net, dst_net, overlaps;
protocol:NTP = udp 123;
protocol:NTP-sl = udp 123, stateless;
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = protocol:NTP;
}
service:s1-sl = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = protocol:NTP-sl;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = udp 123, protocol:Ping_Net;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
=END=
=WARNING=
Warning: Redundant rules in service:s1-sl compared to service:s1:
  permit src=network:n2; dst=network:n1; prt=protocol:NTP-sl; stateless of service:s1-sl
< permit src=network:n2; dst=network:n1; prt=protocol:NTP; of service:s1
Warning: Redundant rules in service:s2 compared to service:s3:
  permit src=network:n1; dst=network:n2; prt=protocol:Ping_Net; of service:s2
< permit src=network:n1; dst=network:n2; prt=ip; of service:s3
  permit src=network:n1; dst=network:n2; prt=udp 123; of service:s2
< permit src=network:n1; dst=network:n2; prt=ip; of service:s3
Warning: service:s1-sl is fully redundant
Warning: service:s2 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Find fully redundant rules even if protocol suppresses warning
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:102; }}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:202; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
protocol:Ping_Net = icmpv6 8, src_net, dst_net, overlaps;
service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = protocol:Ping_Net;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = protocol:Ping_Net;
}
=END=
=WARNING=
Warning: service:s1 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Show all redundant rules, not only the smallest one
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;}
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:202; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp;
}
service:s2a = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2b = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
=END=
=WARNING=
Warning: Redundant rules in service:s2a compared to service:s1:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s2a
< permit src=network:n1; dst=network:n2; prt=tcp; of service:s1
Warning: Redundant rules in service:s2b compared to service:s1:
  permit src=network:n1; dst=host:h2; prt=tcp; of service:s2b
< permit src=network:n1; dst=network:n2; prt=tcp; of service:s1
Warning: Redundant rules in service:s3 compared to service:s1:
  permit src=network:n1; dst=host:h2; prt=tcp 80; of service:s3
< permit src=network:n1; dst=network:n2; prt=tcp; of service:s1
Warning: Redundant rules in service:s3 compared to service:s2a:
  permit src=network:n1; dst=host:h2; prt=tcp 80; of service:s3
< permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s2a
Warning: Redundant rules in service:s3 compared to service:s2b:
  permit src=network:n1; dst=host:h2; prt=tcp 80; of service:s3
< permit src=network:n1; dst=host:h2; prt=tcp; of service:s2b
Warning: service:s2a is fully redundant
Warning: service:s2b is fully redundant
Warning: service:s3 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: multi redundant and duplicate (1)
=PARAMS=--ipv6
=INPUT=
any:n1 = { link = network:n1; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 overlaps = service:s2, service:s3;
 user = network:n1;
 # duplicate
 permit src = user; dst = network:n2; prt = tcp 80;
 # redundant
 permit src = user; dst = network:n2; prt = tcp 81;
 # redundant with log
 permit src = user; dst = network:n2; prt = tcp 82; log = a;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 90;
}
service:s3 = {
 user = any:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 81;
 permit src = user; dst = network:n2; prt = tcp 82; log = a;
}
=END=
=WARNING=
Warning: service:s1 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: multi redundant and duplicate (2)
=PARAMS=--ipv6
=INPUT=
any:n1 = { link = network:n1; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 90;
}
service:s2 = {
 overlaps = service:s1, service:s3;
 user = network:n1;
 # duplicate
 permit src = user; dst = network:n2; prt = tcp 80;
 # redundant
 permit src = user; dst = network:n2; prt = tcp 81;
 # redundant with log
 permit src = user; dst = network:n2; prt = tcp 82; log = a;
}
service:s3 = {
 user = any:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 81;
 permit src = user; dst = network:n2; prt = tcp 82; log = a;
}
=END=
=WARNING=
Warning: service:s2 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: mixed redundant and duplicate
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; host:h2 = { ip = ::a01:20a; } }
router:R1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 overlaps = service:s2;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = icmpv6 8;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80, icmpv6 8;
}
=END=
=WARNING=
Warning: service:s1 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: simple duplicates
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 # duplicate, but not found first
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: service:s1 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule with reversed overlaps
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 # duplicate, but not found first
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = tcp 90;
}
=END=
=WARNING=
Warning: service:s1 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule without overlaps
=TEMPL=input
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=PARAMS=--ipv6
=INPUT=[[input]]
=WARNING=
Warning: Duplicate rules in service:s2 and service:s1:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s2
Warning: service:s1 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Don't check for duplicate rules
=OPTIONS=--check_duplicate_rules=0
=PARAMS=--ipv6
=INPUT=[[input]]
=WARNING=NONE

############################################################
=TITLE=Redundant rule with multiple duplicates
# Must not count duplicate rule multiple times at s1,
# otherwise s1 would accidently be marked as fully redundant.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 overlaps = service:s2, service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81, icmpv6 8;
}
service:s2 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 82, icmpv6 8;
}
service:s3 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 83, icmpv6 8;
}
=END=
=WARNING=NONE
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Useless overlaps with duplicate rules
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81, icmpv6 8;
}
service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 82, icmpv6 8;
}
service:s3 = {
 overlaps = service:s4;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 83, icmpv6 0;
}
service:s4 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 84, icmpv6 0;
}
=WARNING=
Warning: Useless 'overlaps = service:s3' in service:s1
Warning: Useless 'overlaps = service:s4' in service:s3
=END=

############################################################
=TITLE=Service with duplicate rules and/or attribute overlaps.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81;
 permit src = user;
        dst = network:n2;
        prt = tcp 81;
}
service:s3 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81;
}
=WARNING=
Warning: Duplicate rules in service:s2 and service:s2:
  permit src=network:n1; dst=network:n2; prt=tcp 81; of service:s2
Warning: Duplicate rules in service:s3 and service:s2:
  permit src=network:n1; dst=network:n2; prt=tcp 81; of service:s3
Warning: Useless 'overlaps = service:s3' in service:s3
=END=

############################################################
=TITLE=Empty service is not shown as fully redundant
=OPTIONS=--check_fully_redundant_rules=warn
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
group:g1 = ;
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Relation between UDP src and dst ranges
# p1 < p2 and p1 < p3
=PARAMS=--ipv6
=INPUT=
protocol:p1 = udp 123:123;
protocol:p2 = udp 100-65535:123;
protocol:p3 = udp 123:1-1000;
protocol:p4 = udp 90-126:1-65535;
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
  model = IOS, FW;
  managed;
  interface:n1 = { ip = ::a01:101; hardware = n1; }
  interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
service:t1 = {
  user = network:n1;
  permit src = user;
         dst = network:n2;
         prt = protocol:p1, protocol:p2, protocol:p3, protocol:p4;
}
service:t2 = {
  user = network:n1;
  permit src = network:n2; dst = user; prt = protocol:p1, udp 123;
}
=END=
# Adjacent src ranges are not joined currently.
=WARNING=
Warning: Redundant rules in service:t1 compared to service:t1:
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p3; of service:t1
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p4; of service:t1
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:t1
< permit src=network:n1; dst=network:n2; prt=udp 100-126:123; of service:t1
  permit src=network:n1; dst=network:n2; prt=protocol:p3; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p4; of service:t1
  permit src=network:n1; dst=network:n2; prt=udp 100-126:123; of service:t1
< permit src=network:n1; dst=network:n2; prt=protocol:p4; of service:t1
Warning: Redundant rules in service:t2 compared to service:t2:
  permit src=network:n2; dst=network:n1; prt=protocol:p1; of service:t2
< permit src=network:n2; dst=network:n1; prt=udp 123; of service:t2
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit udp ::a01:100/120 range 127 1000 ::a01:200/120 eq 123
 permit udp ::a01:100/120 gt 1000 ::a01:200/120 eq 123
 permit udp ::a01:100/120 range 90 126 ::a01:200/120
 deny ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any host ::a01:101
 permit udp ::a01:200/120 ::a01:100/120 eq 123
 deny ipv6 any any
=END=

############################################################
=TITLE=Relation between overlapping TCP ranges
# p1 < p2 and p1 < p3
=PARAMS=--ipv6
=INPUT=
protocol:p1 = tcp 85-89;
protocol:p2 = tcp 80-90;
protocol:p3 = tcp 84-94; # split into 84-90,91-94
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
  model = IOS, FW;
  managed;
  interface:n1 = { ip = ::a01:101; hardware = n1; }
  interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:s1 = {
  user = network:n1;
  permit src = user;
         dst = network:n2;
         prt = protocol:p1, protocol:p2, protocol:p3;
}
=END=
# Adjacent src ranges are not joined currently.
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s1:
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:s1
< permit src=network:n1; dst=network:n2; prt=protocol:p2; of service:s1
  permit src=network:n1; dst=network:n2; prt=protocol:p1; of service:s1
< permit src=network:n1; dst=network:n2; prt=tcp 84-90; of service:s1
  permit src=network:n1; dst=network:n2; prt=tcp 84-90; of service:s1
< permit src=network:n1; dst=network:n2; prt=protocol:p2; of service:s1
=OUTPUT=
-- ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201
 permit tcp ::a01:100/120 ::a01:200/120 range 80 94
 deny ipv6 any any
=END=

############################################################
=TITLE=Range spans whole network
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 host:range  = { range = ::a01:100 - ::a01:1ff; }
}
router:u = {
 interface:n1;
 interface:t1 = { ip = ::a09:101; }
}
network:t1 = { ip = ::a09:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:test2 = {
 user = host:range;
 permit src = user; dst = network:n2; prt = tcp 80-90;
}
=END=
=WARNING=
Warning: Use network:n1 instead of host:range
 because both have identical address
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test1
< permit src=network:n1; dst=network:n2; prt=tcp 80-90; of service:test2
Warning: service:test1 is fully redundant
=END=
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Redundancy in enclosed port range
# Redundancy should be recognized, even if service:s3 isn not defined.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n3; prt = tcp 80 - 81;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
#service:s3 = {
# user = network:n2;
# permit src = user; dst = network:n3; prt = tcp 10 - 80;
#}
=END=
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s2:
  permit src=host:h1; dst=network:n3; prt=tcp 80; of service:s1
< permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s2
=END=
=TODO=Split port ranges before compare

############################################################
