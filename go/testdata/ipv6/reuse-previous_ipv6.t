
############################################################
=TEMPL=topo
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
=END=

############################################################
=TITLE=Reuse all code files
=SHOW_DIAG=
=TEMPL=input
[[topo]]
service:test = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=INPUT=[[input]]
=REUSE_PREV=[[input]]
=WARNING=
DIAG: Reused .prev/ipv6/r1
DIAG: Reused .prev/ipv6/r2
DIAG: Reused .prev/ipv6/r3
=OUTPUT=
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:400/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:400/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--ipv6/r3
! n3_in
access-list n3_in extended permit tcp ::a01:100/120 ::a01:400/120 eq 80
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Reuse some code files
=SHOW_DIAG=
=INPUT=[[input]]
=REUSE_PREV=
[[input]]
service:test2 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=WARNING=
DIAG: Reused .prev/ipv6/r1
DIAG: Reused .prev/ipv6/r3
=OUTPUT=
--ipv6/r2
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:400/120 eq 80
access-list n2_in extended permit tcp ::a01:200/120 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Can't reuse new code file
=SHOW_DIAG=
=TEMPL=extended
[[input]]
=INPUT=[[input]]
=REUSE_PREV=
[[input]]
network:n5 = { ip6 = ::a01:500/120; }
router:r4 = {
 managed;
 model = ASA;
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
 interface:n5 = { ip6 = ::a01:501; hardware = n5; }
}
service:test2 = {
 user = network:n4;
 permit src = user; dst = network:n5; prt = tcp 80;
}
=WARNING=
DIAG: Reused .prev/ipv6/r1
DIAG: Reused .prev/ipv6/r2
DIAG: Reused .prev/ipv6/r3
=OUTPUT=
--ipv6/r4
! n4_in
access-list n4_in extended permit tcp ::a01:400/120 ::a01:500/120 eq 80
access-list n4_in extended deny ip any6 any6
access-group n4_in in interface n4
=END=

############################################################
=TITLE=.prev is file
=SETUP=
mkdir out/
touch out/.prev
=INPUT=
-- topology
network:n1 = { ip6 = ::a01:100/120; }
=WITH_OUTDIR=
=WARNING=NONE

############################################################
=TITLE=Can't create link to reused file
=TODO= No IPv6
=SETUP=
mkdir old
mkdir out
ln -s ../old out/.prev
cat <<END > old/r1.info
{"generated_by":"devel","model":"ASA","name_list":["r1"]}
END
cat <<END > old/r1.config
END
cat <<END > old/r1.rules
{"model":"ASA","acls":null,"do_objectgroup":true}
END
cp old/r1.config old/r1
mkdir out/r1
touch out/r1/foo
=INPUT=
-- topology
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
=WITH_OUTDIR=
=ERROR=
panic: link out/.prev/r1 out/r1: file exists
=END=
