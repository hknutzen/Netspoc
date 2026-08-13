############################################################
=TITLE=Select loopback interface for talking with policy_distribution_point
# Even if router is located in cycle.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:pdp = { ip6 = ::a01:10d; } }
network:n2 = { ip6 = ::a02:200/120; }

router:r1 = {
 policy_distribution_point = host:pdp;
 model = ASA;
 managed;
 routing = dynamic;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a02:201; hardware = n2; }
 interface:lo = { ip6 = ::a00:1; loopback; hardware = lo; }
}

router:r2 = {
 policy_distribution_point = host:pdp;
 model = ASA;
 managed;
 routing = dynamic;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a02:202; hardware = n2; }
}

service:s1 = {
 user = interface:r1.n2, interface:r1.lo,
        interface:r2.n2, interface:r2.n1,
        ;
 permit src = host:pdp; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"ASA","ip_list":["::a00:1"],"policy_distribution_point":"::a01:10d"}
--ipv6/r2.info
{"generated_by":"devel","model":"ASA","ip_list":["::a01:102","::a02:202"],"policy_distribution_point":"::a01:10d"}
=END=
