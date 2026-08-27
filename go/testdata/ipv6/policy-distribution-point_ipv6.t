
############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (1)
=INPUT=
network:a = { ip6 = ::a00:0/120; host:netspoc = { ip6 = ::a00:a; } }
router:r1 =  {
 managed;
 model = IOS,FW;
 policy_distribution_point = host:netspoc;
 routing = manual;
 interface:a = { ip6 = ::a00:1; hardware = e1; }
 interface:b1 = { ip6 = ::a01:101; hardware = e0; }
}
router:r2 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip6 = ::a00:2; hardware = e1; }
 interface:b1 = { ip6 = ::a01:102; hardware = e0; }
}
network:b1 = { ip6 = ::a01:100/120; }
service:test = {
 user = interface:r1.[auto];
 permit src = network:a; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"IOS","ip_list":["::a00:1","::a01:101"],"policy_distribution_point":"::a00:a"}
=END=

############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (2)
=TODO= No IPv6
#
# Find interfaces in given order n3, n4,
# even if reversed path was already found previously while
# "Checking and marking rules with hidden or dynamic NAT"
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:16f; } }
network:n2 = { ip6 = ::a01:200/126; }
network:n3 = { ip6 = ::a01:300/126; }
network:n4 = { ip6 = ::a01:400/126; }
network:n5 = { ip6 = ::a01:500/123; nat:h = { hidden; } }
network:n6 = { ip6 = ::a01:600/123; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n6 = { ip6 = ::a01:601; hardware = n6; nat_out = h; }
}
router:r2 = {
 model = IOS;
 managed;
 routing = manual;
 policy_distribution_point = host:h1;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
 interface:n5 = { ip6 = ::a01:501; hardware = n5; }
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r2.n3, interface:r2.n4; prt = tcp 22;
 permit src = user; dst = interface:r2.n5;                  prt = tcp 80;
}
=OUTPUT=
--ipv6/r2.info
{"generated_by":"devel","model":"IOS","ip_list":["::a01:302","::a01:401"],"policy_distribution_point":"::a01:16f"}
=END=

############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (3)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:16f; } }
network:n2 = { ip6 = ::a01:200/126; }
network:n3 = { ip6 = ::a01:300/126; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 policy_distribution_point = host:h1;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:r1.[all] &! interface:r1.n1;
        prt = tcp 22;
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"ASA","ip_list":["::a01:201","::a01:301"],"policy_distribution_point":"::a01:16f"}
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Only one interface in loop talks to policy_distribution_point
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip6 = ::a01:103; hardware = n1; virtual = { ip6 = ::a01:101; } }
 interface:n2 = { ip6 = ::a01:203; hardware = n2; virtual = { ip6 = ::a01:201; } }
}
router:r2 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; virtual = { ip6 = ::a01:101; } }
 interface:n2 = { ip6 = ::a01:202; hardware = n2; virtual = { ip6 = ::a01:201; } }
}
network:n2 = { ip6 = ::a01:200/120; }
router:r3 = {
 managed;
 model = IOS;
 interface:n2 = { ip6 = ::a01:209; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n3 = { ip6 = ::a01:300/120; host:netspoc = { ip6 = ::a01:309; } }
service:s = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = network:n3; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"ASA","ip_list":["::a01:203"],"policy_distribution_point":"::a01:309"}
--ipv6/r2.info
{"generated_by":"devel","model":"ASA","ip_list":["::a01:202"],"policy_distribution_point":"::a01:309"}
=END=

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
