
############################################################
=TITLE=Pass 2: 3 devices with up to 8 jobs
=TEMPL=input
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
=TEMPL=output
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
=INPUT=[[input]]
=OUTPUT=
[[output]]
=OPTIONS=--concurrency_pass2=8

############################################################
=TITLE=Pass 2: 3 devices with up to 2 jobs
=PARAMS=--ipv6
=INPUT=[[input]]
=OUTPUT=
[[output]]
=OPTIONS=--concurrency_pass2=2

############################################################
=TITLE=Abort early, if backgroud job has too many errors, with following error
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:100/121; }
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:100/121; subnet_of = network:n1; }
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
Error: No firewalls found between all source/destination pairs of service:s1
Error: unused group:g1
Aborted after 2 errors
=OPTIONS=--concurrency_pass1=2 --check_unused_groups=1 --check_unenforceable=1 --max_errors=2

############################################################