
############################################################
=TITLE=Find redundant rules
=INPUT=
network:n1-sub = {
 ip = 10.1.1.128/25;
 subnet_of = network:n1;
 host:h1 = { ip = 10.1.1.130; }
}
router:u = {
 interface:n1-sub;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
any:a1 = { link = network:n1; }
router:filter = {
 managed;
 model = Linux;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:n3 = { ip = 10.3.3.1; hardware = n3; }
}
network:n2 = {
 ip = 10.2.2.0/24;
 host:h2 = { ip = 10.2.2.10; }
}
any:a2 = { link = network:n2; }
network:n3 = {
 ip = 10.3.3.0/24;
 host:h3 = { ip = 10.3.3.10; }
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
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Duplicate protocol in rule
=INPUT=
protocol:NTP = udp 123;
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
protocol:Ping_Net = icmp 8, src_net, dst_net, overlaps;
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
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Find fully redundant rules even if protocol suppresses warning
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.2; }}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
protocol:Ping_Net = icmp 8, src_net, dst_net, overlaps;
service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = protocol:Ping_Net;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = protocol:Ping_Net;
}
=WARNING=
Warning: service:s1 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Show all redundant rules, not only the smallest one
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: multi redundant and duplicate (1)
=INPUT=
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=WARNING=
Warning: service:s1 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: multi redundant and duplicate (2)
=INPUT=
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=WARNING=
Warning: service:s2 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: mixed redundant and duplicate
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
router:R1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 overlaps = service:s2;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = icmp 8;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80, icmp 8;
}
=WARNING=
Warning: service:s1 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule: simple duplicates
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=WARNING=
Warning: service:s1 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule with reversed overlaps
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=WARNING=
Warning: service:s1 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Fully redundant rule without overlaps
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:R1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=INPUT=[[input]]
=WARNING=
Warning: Duplicate rules in service:s2 and service:s1:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s2
Warning: service:s1 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Don't check for duplicate rules
=OPTIONS=--check_duplicate_rules=0
=INPUT=[[input]]
=WARNING=NONE

############################################################
=TITLE=Redundant rule with multiple duplicates
# Must not count duplicate rule multiple times at s1,
# otherwise s1 would accidently be marked as fully redundant.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 overlaps = service:s2, service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81, icmp 8;
}
service:s2 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 82, icmp 8;
}
service:s3 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 83, icmp 8;
}
=WARNING=NONE
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Useless overlaps with duplicate rules
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81, icmp 8;
}
service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 82, icmp 8;
}
service:s3 = {
 overlaps = service:s4;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 83, icmp 0;
}
service:s4 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 84, icmp 0;
}
=WARNING=
Warning: Useless 'overlaps = service:s3' in service:s1
Warning: Useless 'overlaps = service:s4' in service:s3
=END=

############################################################
=TITLE=Service with duplicate rules and/or attribute overlaps.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
group:g1 = ;
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=Relation between UDP src and dst ranges
# p1 < p2 and p1 < p3
=INPUT=
protocol:p1 = udp 123:123;
protocol:p2 = udp 100-65535:123;
protocol:p3 = udp 123:1-1000;
protocol:p4 = udp 90-126:1-65535;
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
  model = IOS, FW;
  managed;
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
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
-- r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit udp 10.1.1.0 0.0.0.255 range 127 1000 10.1.2.0 0.0.0.255 eq 123
 permit udp 10.1.1.0 0.0.0.255 gt 1000 10.1.2.0 0.0.0.255 eq 123
 permit udp 10.1.1.0 0.0.0.255 range 90 126 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 permit udp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 123
 deny ip any any
=END=

############################################################
=TITLE=Relation between overlapping TCP ranges
# p1 < p2 and p1 < p3
=INPUT=
protocol:p1 = tcp 85-89;
protocol:p2 = tcp 80-90;
protocol:p3 = tcp 84-94; # split into 84-90,91-94
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
  model = IOS, FW;
  managed;
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
-- r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 range 80 94
 deny ip any any
=END=

############################################################
=TITLE=Range spans whole network
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:range  = { range = 10.1.1.0 - 10.1.1.255; }
}
router:u = {
 interface:n1;
 interface:t1 = { ip = 10.9.1.1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:test2 = {
 user = host:range;
 permit src = user; dst = network:n2; prt = tcp 80-90;
}
=WARNING=
Warning: Use network:n1 instead of host:range
 because both have identical address
Warning: Redundant rules in service:test1 compared to service:test2:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:test1
< permit src=network:n1; dst=network:n2; prt=tcp 80-90; of service:test2
Warning: service:test1 is fully redundant
=OPTIONS=--check_fully_redundant_rules=warn

############################################################
=TITLE=Redundancy in enclosed port range
# Redundancy should be recognized, even if service:s3 isn not defined.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
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
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s2:
  permit src=host:h1; dst=network:n3; prt=tcp 80; of service:s1
< permit src=network:n1; dst=network:n3; prt=tcp 80; of service:s2
=TODO=Split port ranges before compare

############################################################
