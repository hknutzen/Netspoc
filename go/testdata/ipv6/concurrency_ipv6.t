
############################################################
=TITLE=Pass 2: 3 devices with up to 8 jobs
=VAR=input
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:103; hardware = n1; }
}
=END=
# Expect normal operation with concurrency enabled.
=VAR=output
-- ipv6/asa1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
-- ipv6/asa2
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
-- ipv6/asa3
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=PARAMS=--ipv6
=INPUT=${input}
=OUTPUT=
${output}
=OPTIONS=--concurrency_pass2=8

############################################################
=TITLE=Pass 2: 3 devices with up to 2 jobs
=PARAMS=--ipv6
=INPUT=${input}
=OUTPUT=
${output}
=OPTIONS=--concurrency_pass2=2

############################################################