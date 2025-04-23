
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
