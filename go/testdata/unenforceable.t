=VAR=topo
network:x = { ip = 10.1.1.0/24;
 host:x7 = { ip = 10.1.1.7; }
 host:x9 = { ip = 10.1.1.9; }
 host:range = { range = 10.1.1.6-10.1.1.11; }
}
router:r = {
 model = IOS,FW;
 managed;
 interface:x = { ip = 10.1.1.1; hardware = e0; }
 interface:y = { ip = 10.2.2.2; hardware = e1; }
}
network:y = { ip = 10.2.2.0/24;
 host:y = { ip = 10.2.2.9; }
}
=END=

############################################################
=TITLE=Unenforceable rule
=VAR=input
${topo}
service:test = {
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
=END=
=INPUT=${input}
=WARNING=
Warning: service:test has unenforceable rules:
 src=host:x7; dst=host:x7
 src=host:x9; dst=host:x7
=END=

############################################################
=TITLE=Zone ignoring unenforceable rule
=INPUT=
${input}
any:x = { link = network:x; has_unenforceable = ok; }
=END=
=WARNING=NONE

############################################################
=TITLE=Service ignoring unenforceable rule
=INPUT=
${topo}
service:test = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Restrict attribute 'has_unenforceable'
=INPUT=
${topo}
any:x = { link = network:x; has_unenforceable = restrict; }
service:test = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
=END=
=WARNING=
Warning: Must not use attribute 'has_unenforceable' at service:test
Warning: service:test has unenforceable rules:
 src=host:x7; dst=host:x7
 src=host:x9; dst=host:x7
=END=

############################################################
=TITLE=Restrict + enable attribute 'has_unenforceable'
=INPUT=
${topo}
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
=END=
=WARNING=
Warning: Must not use attribute 'has_unenforceable' at service:s2
Warning: service:s2 has unenforceable rules:
 src=host:y; dst=network:y
=END=

############################################################
=TITLE=Mixed ignored and reported unenforceable service
# Must not ignore others, if first is ignored.
=INPUT=
${topo}
service:test1 = {
 has_unenforceable;
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 80;
}
service:test2 = {
 user = host:x7, host:x9;
 permit src = user; dst = host:x7, host:y; prt = tcp 81;
}
=END=
=WARNING=
Warning: service:test2 has unenforceable rules:
 src=host:x7; dst=host:x7
 src=host:x9; dst=host:x7
=END=

############################################################
=TITLE=Silent unenforceable rules
=INPUT=
${topo}
service:test = {
 user = host:x7, host:y;
 permit src = user; dst = any:[user]; prt = tcp 80;
 permit src = any:[user]; dst = user; prt = tcp 25;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Silent unenforceable rules with split range
=INPUT=
${topo}
service:test = {
 user = host:range, host:y;
 permit src = user; dst = user; prt = tcp 80;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Consider aggregates in zone cluster as equal
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
}
network:t1 = { ip = 10.9.1.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:t1 = { ip = 10.9.1.2; hardware = t1; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = any:[network:n1],
        any:[network:n3],
        ;
 permit src = user; dst = user; prt = tcp 80;
}
=END=
# Warning about unenforceable rules between any:[network:n1] and
# any:[network:n2] is suppressed.
=OUTPUT=
-- r2
! t1_in
access-list t1_in extended permit tcp any4 any4 eq 80
access-list t1_in extended deny ip any4 any4
access-group t1_in in interface t1
--
! n3_in
access-list n3_in extended permit tcp any4 any4 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Fully unenforceable rule
=VAR=input
any:x = {
 link = network:x;
}
network:x = { ip = 10.1.1.0/24; }
router:r = {
 interface:x;
 interface:y;
}
network:y = { ip = 10.2.2.0/24; }
service:test = {
 #1 has_unenforceable;
 user = network:y;
 permit src = user; dst = network:x; prt = tcp 80;
}
=END=
=INPUT=${input}
=WARNING=
Warning: service:test is fully unenforceable
=END=

############################################################
=TITLE=Useless attribute "has_unenforceable" at service
=INPUT=${input}
=SUBST=/#1//
=WARNING=
Warning: Useless attribute 'has_unenforceable' at service:test
Warning: service:test is fully unenforceable
=END=

############################################################
