
############################################################
=TITLE=Combine adjacent ranges to whole network
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:range1 = { range6 = ::a01:100 - ::a01:17f; }
 host:range2 = { range6 = ::a01:180 - ::a01:1ff; }
}
router:u = {
 interface:n1;
 interface:t1 = { ip6 = ::a09:101; }
}
network:t1 = { ip6 = ::a09:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:t1 = { ip6 = ::a09:102; hardware = t1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
service:test1 = {
 user = host:range1, host:range2;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! t1_in
access-list t1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list t1_in extended deny ip any6 any6
access-group t1_in in interface t1
=END=

############################################################
=TITLE=Redundant combined hosts
# Must recognize combined subnet as redundant.
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1;}
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = {ip6 = ::a01:232;}
 host:h2 = {ip6 = ::a01:233;}
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
-- ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Combine adjacent networks
=INPUT=
network:n0 = { ip6 = ::a01:0/120; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3a = { ip6 = ::a01:300/121; }
network:n3b = { ip6 = ::a01:380/121; }
network:n4 = { ip6 = ::a04:0/112; }
network:n5 = { ip6 = ::a05:0/112; }
router:u1 = {
 interface:n0;
 interface:n1;
 interface:n2;
 interface:n3a;
 interface:n3b;
 interface:l0 = { ip6 = ::a02:100; loopback; }
 interface:l1 = { ip6 = ::a02:101; loopback; }
 interface:t1;
}
network:t1 = { ip6 = ::a09:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:t1 = { ip6 = ::a09:101; hardware = t1; }
 interface:t2 = { ip6 = ::a09:201; hardware = t2; }
}
network:t2 = { ip6 = ::a09:200/120; }
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
-- ipv6/asa1
! t1_in
object-group network v6g0
 network-object ::a01:0/118
 network-object ::a02:100/127
access-list t1_in extended permit tcp object-group v6g0 ::a04:0/111 eq 80
access-list t1_in extended deny ip any6 any6
access-group t1_in in interface t1
=END=

############################################################
=TITLE=Must not reuse combined group
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip6 = ::a01:301; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
network:n4 = {
 ip6 = ::a01:400/120;
 host:h1 = { ip6 = ::a01:40a; }
 host:h2 = { ip6 = ::a01:40c; }
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
--ipv6/r1
! n3_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:200/119
object-group network v6g1
 network-object ::a01:100/120
 network-object ::a01:200/120
access-list n3_in extended permit tcp object-group v6g0 host ::a01:40a eq 80
access-list n3_in extended permit tcp object-group v6g1 host ::a01:40c eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Reuse group
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:u = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip6 = ::a01:301; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
network:n4 = {
 ip6 = ::a01:400/120;
 host:h1 = { ip6 = ::a01:40a; }
 host:h2 = { ip6 = ::a01:40c; }
 host:h3 = { ip6 = ::a01:40e; }
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
--ipv6/r1
! n3_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a01:200/119
access-list n3_in extended permit tcp object-group v6g0 host ::a01:40a eq 81
access-list n3_in extended permit tcp object-group v6g0 host ::a01:40c eq 82
access-list n3_in extended permit tcp object-group v6g0 host ::a01:40e eq 83
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Don't use object-groups
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:h10 = { ip6 = ::a01:10a; }
 host:h20 = { ip6 = ::a01:114; }
 host:h30 = { ip6 = ::a01:11e; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 no_group_code;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
group:g1 = host:h10, host:h20, host:h30;
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp host ::a01:10a ::a01:200/120 eq 80
access-list n1_in extended permit tcp host ::a01:114 ::a01:200/120 eq 80
access-list n1_in extended permit tcp host ::a01:11e ::a01:200/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
