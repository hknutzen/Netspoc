
############################################################
=TEMPL=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
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
DIAG: Reused .prev/r1
DIAG: Reused .prev/r2
DIAG: Reused .prev/r3
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--r2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--r3
! n3_in
access-list n3_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n3_in extended deny ip any4 any4
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
DIAG: Reused .prev/r1
DIAG: Reused .prev/r3
=OUTPUT=
--r2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 80
access-list n2_in extended permit tcp 10.1.2.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
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
network:n5 = { ip = 10.1.5.0/24; }
router:r4 = {
 managed;
 model = ASA;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
service:test2 = {
 user = network:n4;
 permit src = user; dst = network:n5; prt = tcp 80;
}
=WARNING=
DIAG: Reused .prev/r1
DIAG: Reused .prev/r2
DIAG: Reused .prev/r3
=OUTPUT=
--r4
! n4_in
access-list n4_in extended permit tcp 10.1.4.0 255.255.255.0 10.1.5.0 255.255.255.0 eq 80
access-list n4_in extended deny ip any4 any4
access-group n4_in in interface n4
=END=

############################################################
=TITLE=.prev is file
=SETUP=
mkdir out/
touch out/.prev
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=
=WARNING=NONE

############################################################
=TITLE=Can't create link to reused file
# No IPv6
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
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WITH_OUTDIR=
=ERROR=
panic: link out/.prev/r1 out/r1: file exists
=END=
