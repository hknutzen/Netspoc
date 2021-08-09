
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
=TITLE=Abort early, if backgroud job has too many errors, with following error
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.1.0/25; }
router:r1 = {
 interface:n1;
 interface:n2;
}

group:g1 = network:n1;
group:g2 = network:n1;
=ERROR=
Error: network:n2 is subnet of network:n1
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
Error: unused group:g1
Error: unused group:g2
Aborted after 2 errors
=OPTIONS=--concurrency_pass1=2 --check_unused_groups=1 --check_subnets=1  --max_errors=2

############################################################
=TITLE=Abort early, if backgroud job has too many errors, with previous error
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.1.0/25; subnet_of = network:n1; }
router:r1 = {
 interface:n1;
 interface:n2;
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
group:g1 = network:n1;
=ERROR=
Error: service:s1 is fully unenforceable
Error: unused group:g1
Aborted after 2 errors
=OPTIONS=--concurrency_pass1=2 --check_unused_groups=1 --check_unenforceable=1 --max_errors=2

############################################################