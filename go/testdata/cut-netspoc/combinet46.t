
############################################################
=TITLE=Service from combined v4/v6 to v4/v6 and to v4
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2,
              network:n3,
              ;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Service from combined v4/v6 to v4
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n3;
        prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n3;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Retain dual stack management_instance of dual stack router
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1@v1 = {
 model = NSX, T0;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = OUT; }
}
router:u = {
 interface:n2;
 interface:n3;
}
router:r1 = {
 model = NSX;
 management_instance;
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Retain v6 management_instance of dual stack router
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1@v1 = {
 model = NSX, T0;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = OUT; }
}
router:u = {
 interface:n2;
 interface:n3;
}
router:r1 = {
 model = NSX;
 management_instance;
 interface:n3 = { ip6 = 2001:db8:1:3::1; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Process dual stack pathrestriction only once
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip6 = 2001:db8:1:4::/64; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip6 = 2001:db8:1:4::2; hardware = n4; }
}
pathrestriction:r1 =
 interface:r1.n1,
 interface:r2.n3,
 interface:r2.n4,
;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2,
              network:n3,
              network:n4,
              ;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Put dual stack object into expanded intersection only once
=INPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; ip6 = 2001:db8:1:4::/64; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; ip6 = 2001:db8:1:4::2; hardware = n4; }
}
group:g =
 interface:r2.n3,
 interface:r2.n4,
 interface:r2.[auto],
 interface:r1.[auto],
;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = group:g &! interface:r2.n3,
              ;
        prt = tcp 22;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n4 = { ip = 10.1.4.0/24; ip6 = 2001:db8:1:4::/64; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; ip6 = 2001:db8:1:1::2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; ip6 = 2001:db8:1:4::2; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:r1.[auto],
              interface:r2.[auto],
              interface:r2.n4,
              ;
        prt = tcp 22;
}
=END=

############################################################
=TITLE=Dual stack aggregates from area with intersection
=INPUT=
area:a = { anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
service:s1 = {
 user = any:[area:a] &! any:[network:n1];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
service:s1 = {
 user = any:[network:n2],
        any:[network:n3],
        ;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=END=
