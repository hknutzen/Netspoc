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
