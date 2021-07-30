
############################################################
=TITLE=Combine adjacent ranges to whole network
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:range1 = { range = 10.1.1.0 - 10.1.1.127; }
 host:range2 = { range = 10.1.1.128 - 10.1.1.255; }
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
 user = host:range1, host:range2;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- r1
! t1_in
access-list t1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list t1_in extended deny ip any4 any4
access-group t1_in in interface t1
=END=

############################################################
=TITLE=Redundant combined hosts
# Must recognize combined subnet as redundant.
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:h1 = {ip = 10.1.2.50;}
 host:h2 = {ip = 10.1.2.51;}
}
service:s1 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user; dst = host:h1; prt = tcp 80;
}
service:s2 = {
 overlaps = service:s3;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Combine adjacent networks
=INPUT=
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3a = { ip = 10.1.3.0/25; }
network:n3b = { ip = 10.1.3.128/25; }
network:n4 = { ip = 10.4.0.0/16; }
network:n5 = { ip = 10.5.0.0/16; }
router:u1 = {
 interface:n0;
 interface:n1;
 interface:n2;
 interface:n3a;
 interface:n3b;
 interface:l0 = { ip = 10.2.1.0; loopback; }
 interface:l1 = { ip = 10.2.1.1; loopback; }
 interface:t1;
}
network:t1 = { ip = 10.9.1.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
}
network:t2 = { ip = 10.9.2.0/24; }
router:u2 = {
 interface:t2;
# Don't create group with one element.
 interface:n4;
 interface:n5;
}
service:t = {
 user = network:n0,
        network:n2,
        network:n1,
        interface:u1.l0,
        interface:u1.l1,
        network:n3b,
        network:n3a,
        ;
 permit src = user;
        dst = network:n4, network:n5;
        prt = tcp 80;
}
=OUTPUT=
-- asa1
! t1_in
object-group network g0
 network-object 10.1.0.0 255.255.252.0
 network-object 10.2.1.0 255.255.255.254
access-list t1_in extended permit tcp object-group g0 10.4.0.0 255.254.0.0 eq 80
access-list t1_in extended deny ip any4 any4
access-group t1_in in interface t1
=END=

############################################################
=TITLE=Must not reuse combined group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = 10.1.3.1; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
network:n4 = {
 ip = 10.1.4.0/24;
 host:h1 = { ip = 10.1.4.10; }
 host:h2 = { ip = 10.1.4.12; }
}
group:g1 = network:n1, network:n2;
service:s1 = {
 user = group:g1, network:n3;
 permit src = user; dst = host:h1; prt = tcp 80;
}
service:s2 = {
 user = group:g1;
 permit src = user; dst = host:h2; prt = tcp 80;
}
=OUTPUT=
--r1
! n3_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.254.0
object-group network g1
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
access-list n3_in extended permit tcp object-group g0 host 10.1.4.10 eq 80
access-list n3_in extended permit tcp object-group g1 host 10.1.4.12 eq 80
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Reuse group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = 10.1.3.1; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
network:n4 = {
 ip = 10.1.4.0/24;
 host:h1 = { ip = 10.1.4.10; }
 host:h2 = { ip = 10.1.4.12; }
 host:h3 = { ip = 10.1.4.14; }
}
service:s1 = {
 user = network:n3, network:n2, network:n1;
 permit src = user; dst = host:h1; prt = tcp 81;
}
service:s2 = {
 user = network:n2, network:n1, network:n3;
 permit src = user; dst = host:h2; prt = tcp 82;
}
service:s3 = {
 user = network:n1, network:n2, network:n3;
 permit src = user; dst = host:h3; prt = tcp 83;
}
=OUTPUT=
--r1
! n3_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.254.0
access-list n3_in extended permit tcp object-group g0 host 10.1.4.10 eq 81
access-list n3_in extended permit tcp object-group g0 host 10.1.4.12 eq 82
access-list n3_in extended permit tcp object-group g0 host 10.1.4.14 eq 83
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Don't use object-groups
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h20 = { ip = 10.1.1.20; }
 host:h30 = { ip = 10.1.1.30; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 no_group_code;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
group:g1 = host:h10, host:h20, host:h30;
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.10 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended permit tcp host 10.1.1.20 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended permit tcp host 10.1.1.30 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=
