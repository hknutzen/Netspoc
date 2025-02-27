=TEMPL=topo
network:x = { ip6 = ::a01:100/120;
 host:x7 = { ip6 = ::a01:107; }
 host:x9 = { ip6 = ::a01:109; }
 host:rg = { range6 = ::a01:106-::a01:10b; }
}
router:r = {
 model = IOS,FW;
 managed;
 interface:x = { ip6 = ::a01:101; hardware = e0; }
 interface:y = { ip6 = ::a02:202; hardware = e1; }
}
network:y = { ip6 = ::a02:200/120;
 host:y = { ip6 = ::a02:209; }
}
=END=

############################################################
=TITLE=Unenforceable rule
=TEMPL=input
[[topo]]
service:test = {
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
=INPUT=[[input]]
=WARNING=
Warning: Some source/destination pairs of service:test don't affect any firewall:
 src=host:x7; dst=host:x7
 src=host:x9; dst=host:x7
=END=

############################################################
=TITLE=Zone ignoring unenforceable rule
=INPUT=
[[input]]
any:x = { link = network:x; has_unenforceable = ok; }
=WARNING=NONE

############################################################
=TITLE=Disable check for unenforceable rule
=INPUT=
[[input]]
=OPTIONS=--check_unenforceable=0
=WARNING=NONE

############################################################
=TITLE=Service ignoring unenforceable rule
=INPUT=
[[topo]]
service:test = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=Restrict attribute 'has_unenforceable'
=INPUT=
[[topo]]
any:x = { link = network:x; has_unenforceable = restrict; }
service:test = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
=WARNING=
Warning: Attribute 'has_unenforceable' is blocked at service:test
Warning: Some source/destination pairs of service:test don't affect any firewall:
 src=host:x7; dst=host:x7
 src=host:x9; dst=host:x7
=END=

############################################################
=TITLE=Restrict + enable attribute 'has_unenforceable'
=INPUT=
[[topo]]
area:all = { anchor = network:x; has_unenforceable = restrict; }
any:x = { link = network:x; has_unenforceable = enable; }
service:s1 = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
service:s2 = {
 has_unenforceable;
 user = host:y;
 permit src = user; dst = network:y, host:x7; prt = tcp 80;
}
=WARNING=
Warning: Attribute 'has_unenforceable' is blocked at service:s2
Warning: Some source/destination pairs of service:s2 don't affect any firewall:
 src=host:y; dst=network:y
=END=

############################################################
=TITLE=Mixed ignored and reported unenforceable service
# Must not ignore others, if first is ignored.
=INPUT=
[[topo]]
service:test1 = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
service:test2 = {
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 81;
}
=WARNING=
Warning: Some source/destination pairs of service:test2 don't affect any firewall:
 src=host:x7; dst=host:x7
 src=host:x9; dst=host:x7
=END=

############################################################
=TITLE=Silent unenforceable rules
=INPUT=
[[topo]]
service:test = {
 user = host:x7, host:y;
 permit src = user; dst = any:[user]; prt = tcp 80;
 permit src = any:[user]; dst = user; prt = tcp 25;
}
=WARNING=NONE

############################################################
=TITLE=Silent unenforceable rules with split range
=INPUT=
[[topo]]
service:test = {
 user = host:rg, host:y;
 permit src = user; dst = user; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=Silent unenforceable user-user rule
=INPUT=
[[topo]]
service:test = {
 user = host:x7, host:x9, host:y;
 permit src = user; dst = user; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=Unenforceable foreach rule
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
router:r2 = {
 interface:n1 = { ip6 = ::a01:102; }
}
service:ping-local = {
 user = foreach interface:r1.n1, interface:r2.n1;
 permit src = any:[user]; dst = user; prt = icmpv6 8;
}
=WARNING=
Warning: Some source/destination pairs of service:ping-local don't affect any firewall:
 src=any:[network:n1]; dst=interface:r2.n1
=END=

############################################################
=TITLE=Useless has_unenforceable at silent unenforceable user-user rule
=INPUT=
[[topo]]
service:test = {
 has_unenforceable;
 user = host:x7, host:x9, host:y;
 permit src = user; dst = user; prt = tcp 80;
}
=WARNING=
Warning: Useless 'has_unenforceable' at service:test
=END=

############################################################
=TITLE=Fully unenforceable user-user rule
=INPUT=
[[topo]]
service:test = {
 user = host:x7, host:x9;
 permit src = user; dst = user; prt = tcp 80;
}
=WARNING=
Warning: No firewalls found between all source/destination pairs of service:test
=END=

############################################################
=TITLE=Consider aggregates in zone cluster as equal
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
}
network:t1 = { ip6 = ::a09:100/120; }
router:r2 = {
 managed;
 model = ASA;
 interface:t1 = { ip6 = ::a09:102; hardware = t1; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 user = any:[ip6 = ::a00:0/104 & network:n1],
        any:[ip6 = ::a00:0/104 & network:n3],
        ;
 permit src = user; dst = user; prt = tcp 80;
}
=END=
# Warning about unenforceable rules between any:[network:n1] and
# any:[network:n2] is suppressed.
=OUTPUT=
-- ipv6/r2
! t1_in
access-list t1_in extended permit tcp ::a00:0/104 ::a00:0/104 eq 80
access-list t1_in extended deny ip any6 any6
access-group t1_in in interface t1
--
! n3_in
access-list n3_in extended permit tcp ::a00:0/104 ::a00:0/104 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Fully unenforceable rule
=TEMPL=input
any:x = {
 link = network:x;
}
network:x = { ip6 = ::a01:100/120; }
router:r = {
 interface:x;
 interface:y;
}
network:y = { ip6 = ::a02:200/120; }
service:test = {
 {{.}}
 user = network:y;
 permit src = user; dst = network:x; prt = tcp 80;
}
=INPUT=[[input ""]]
=WARNING=
Warning: No firewalls found between all source/destination pairs of service:test
=END=

############################################################
=TITLE=Useless attribute "has_unenforceable" at service
=INPUT=[[input has_unenforceable;]]
=WARNING=
Warning: Useless 'has_unenforceable' at service:test
Warning: No firewalls found between all source/destination pairs of service:test
=END=

############################################################
=TITLE=Restrict has_unenforceable and ignore unenforceable at owner
=INPUT=
owner:o7 = { admins = a7@example.com; has_unenforceable = restrict; }
owner:o8 = { admins = a8@example.com; has_unenforceable = ok; }
owner:o11-14 = { admins = range@example.com; has_unenforceable = ok; }
network:x = { ip6 = ::a01:100/120;
 host:x7 = { ip6 = ::a01:107; owner = o7; }
 host:x8 = { ip6 = ::a01:108; owner = o8; }
 host:x9 = { ip6 = ::a01:109; }
 host:r11-14 = { range6 = ::a01:10b-::a01:10e; owner = o11-14; }
}
router:r = {
 model = IOS,FW;
 managed;
 interface:x = { ip6 = ::a01:101; hardware = e0; }
 interface:y = { ip6 = ::a02:202; hardware = e1; }
}
network:y = { ip6 = ::a02:200/120;
 host:y = { ip6 = ::a02:209; }
}
service:s1 = {
 has_unenforceable;
 user = host:x7, host:x8;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
service:s2 = {
 user = host:x8, host:x9;
 permit src = user; dst = host:x8, host:y; prt = tcp 81;
}
service:s3 = {
 user = host:r11-14;
 permit src = user; dst = host:x8, host:y; prt = tcp 82;
}
=WARNING=
Warning: Attribute 'has_unenforceable' is blocked at service:s1
Warning: Some source/destination pairs of service:s1 don't affect any firewall:
 src=host:x7; dst=host:x7
=END=

############################################################
=TITLE=Inherit attribute 'has_unenforceable' from nested areas
=INPUT=
area:all = { anchor = network:n1; has_unenforceable = restrict; }
area:a23 = { inclusive_border = interface:r1.n1; }
area:a2 = { border = interface:r1.n2; }
area:a3 = { border = interface:r1.n3; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
service:s1 = {
 has_unenforceable;
 user = network:n2, network:n3;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=END=
# Warning about unenforceable rules between any:[network:n1] and
# any:[network:n2] is suppressed.
=WARNING=
Warning: Attribute 'has_unenforceable' is blocked at service:s1
Warning: Some source/destination pairs of service:s1 don't affect any firewall:
 src=network:n2; dst=network:n2
 src=network:n3; dst=network:n3
=END=

############################################################
