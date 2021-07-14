
############################################################
=TITLE=Pass 2: 3 devices with up to 8 jobs
=VAR=input
network:n1 = { ip = 10.1.1.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
}
=END=
# Expect normal operation with concurrency enabled.
=VAR=output
-- asa1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- asa2
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- asa3
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=
=INPUT=${input}
=OUTPUT=
${output}
=OPTIONS=--concurrency_pass2=8

############################################################
=TITLE=Pass 2: 3 devices with up to 2 jobs
=INPUT=${input}
=OUTPUT=
${output}
=OPTIONS=--concurrency_pass2=2

############################################################