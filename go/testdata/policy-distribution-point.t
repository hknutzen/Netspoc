
############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (1)
=INPUT=
network:a = { ip = 10.0.0.0/24; host:netspoc = { ip = 10.0.0.10; } }
router:r1 =  {
 managed;
 model = IOS,FW;
 policy_distribution_point = host:netspoc;
 routing = manual;
 interface:a = { ip = 10.0.0.1; hardware = e1; }
 interface:b1 = { ip = 10.1.1.1; hardware = e0; }
}
router:r2 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = 10.0.0.2; hardware = e1; }
 interface:b1 = { ip = 10.1.1.2; hardware = e0; }
}
network:b1 = { ip = 10.1.1.0/24; }
service:test = {
 user = interface:r1.[auto];
 permit src = network:a; dst = user; prt = tcp 22;
}
=OUTPUT=
--r1.info
{"generated_by":"devel","model":"IOS","ip_list":["10.0.0.1","10.1.1.1"],"policy_distribution_point":"10.0.0.10"}
=END=

############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (2)
# No IPv6 NAT
#
# Find interfaces in given order n3, n4,
# even if reversed path was already found previously while
# "Checking and marking rules with hidden or dynamic NAT"
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.111; } }
network:n2 = { ip = 10.1.2.0/30; }
network:n3 = { ip = 10.1.3.0/30; }
network:n4 = { ip = 10.1.4.0/30; }
network:n5 = { ip = 10.1.5.0/27; nat:h = { hidden; } }
network:n6 = { ip = 10.1.6.0/27; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; nat_out = h; }
}
router:r2 = {
 model = IOS;
 managed;
 routing = manual;
 policy_distribution_point = host:h1;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r2.n3, interface:r2.n4; prt = tcp 22;
 permit src = user; dst = interface:r2.n5;                  prt = tcp 80;
}
=OUTPUT=
--r2.info
{"generated_by":"devel","model":"IOS","ip_list":["10.1.3.2","10.1.4.1"],"policy_distribution_point":"10.1.1.111"}
=END=

############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (3)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.111; } }
network:n2 = { ip = 10.1.2.0/30; }
network:n3 = { ip = 10.1.3.0/30; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:r1.[all] &! interface:r1.n1;
        prt = tcp 22;
}
=OUTPUT=
--r1.info
{"generated_by":"devel","model":"ASA","ip_list":["10.1.2.1","10.1.3.1"],"policy_distribution_point":"10.1.1.111"}
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Only one interface in loop talks to policy_distribution_point
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; virtual = { ip = 10.1.1.1; } }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; virtual = { ip = 10.1.2.1; } }
}
router:r2 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; virtual = { ip = 10.1.1.1; } }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; virtual = { ip = 10.1.2.1; } }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r3 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.9; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; host:netspoc = { ip = 10.1.3.9; } }
service:s = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = network:n3; dst = user; prt = tcp 22;
}
=OUTPUT=
--r1.info
{"generated_by":"devel","model":"ASA","ip_list":["10.1.2.3"],"policy_distribution_point":"10.1.3.9"}
--r2.info
{"generated_by":"devel","model":"ASA","ip_list":["10.1.2.2"],"policy_distribution_point":"10.1.3.9"}
=END=

############################################################
=TITLE=Select loopback interface for talking with policy_distribution_point
# Even if router is located in cycle.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:pdp = { ip = 10.1.1.13; } }
network:n2 = { ip = 10.2.2.0/24; }

router:r1 = {
 policy_distribution_point = host:pdp;
 model = ASA;
 managed;
 routing = dynamic;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:lo = { ip = 10.0.0.1; loopback; hardware = lo; }
}

router:r2 = {
 policy_distribution_point = host:pdp;
 model = ASA;
 managed;
 routing = dynamic;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
}

service:s1 = {
 user = interface:r1.n2, interface:r1.lo,
        interface:r2.n2, interface:r2.n1,
        ;
 permit src = host:pdp; dst = user; prt = tcp 22;
}
=OUTPUT=
--r1.info
{"generated_by":"devel","model":"ASA","ip_list":["10.0.0.1"],"policy_distribution_point":"10.1.1.13"}
--r2.info
{"generated_by":"devel","model":"ASA","ip_list":["10.1.1.2","10.2.2.2"],"policy_distribution_point":"10.1.1.13"}
=END=
