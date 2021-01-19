
############################################################
=TITLE=Pass 1
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=END=
# No errors expected.
=OUTPUT=
-- asa1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.10 10.1.2.0 255.255.255.0 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=
=OPTION=--concurrency_pass1=2

############################################################
=TITLE=Warning from background job
=VAR=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
=END=
=INPUT=${input}
# Output is indented
=WARNING=
Warning: Redundant rules in service:s1 compared to service:s2:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s1
< permit src=network:n1; dst=network:n2; prt=ip; of service:s2
=END=
=OPTION=--concurrency_pass1=2

############################################################
=TITLE=Error from background job
=OPTION=--concurrency_pass1=2 --check_redundant_rules=err
=INPUT=${input}
=ERROR=
Error: Redundant rules in service:s1 compared to service:s2:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s1
< permit src=network:n1; dst=network:n2; prt=ip; of service:s2
=END=

############################################################
=TITLE=Abort from background job
=OPTION=--max_errors=1 --concurrency_pass1=2 --check_redundant_rules=err
=INPUT=${input}
=ERROR=
Error: Redundant rules in service:s1 compared to service:s2:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s1
< permit src=network:n1; dst=network:n2; prt=ip; of service:s2
Aborted after 1 errors
=END=

############################################################
=TITLE=Abort in foreground job
# Don't wait for background job, but exit immediately.
=INPUT=
network:n1  = { ip = 10.1.1.0/24; }
network:sub = { ip = 10.1.1.8/29; }
router:r1 = {
 interface:n1;
 interface:sub;
}
=END=
=ERROR=
Error: network:sub is subnet of network:n1
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
Aborted after 1 errors
=END=
=OPTION=--max_errors=1 --check_subnets=err --concurrency_pass1=2

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
=OUTPUT=${output}
=OPTION=--concurrency_pass2=8

############################################################
=TITLE=Pass 2: 3 devices with 2 jobs
=INPUT=${input}
=OUTPUT=${output}
=OPTION=--concurrency_pass2=2


############################################################
=TITLE=Netspoc script with pipe from pass1 to pass2
=INPUT=${input}
=WARNING=NONE
# Adapt content of netspoc script
# - insert arguments and
# - add Perl options for testing.
    # Only check for existence of generated files.
    # Content has already been checked above.
=TODO=
=END=
