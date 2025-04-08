
############################################################
=TITLE=Automatic owner at nested aggregates
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
any:a20 = { ip = 10.1.0.0/20; link = network:n1; owner = o1; }
network:n1 = { ip = 10.1.1.0/24; owner = o2; }
=OUTPUT=
any:[ip=10.1.0.0/16 & network:n1]	owner:o1
=OPTIONS=--owner --name
=PARAM=any:[ip = 10.1.0.0/16 & network:n1]

############################################################
=TITLE=Inherit owner from supernet in zone cluster
=INPUT=
owner:o1 = { admins = a1@b.c; }
network:n1 = { ip = 10.1.1.0/25; subnet_of = network:n2; }
network:n2 = { ip = 10.1.1.0/24; owner = o1; }
router:r1 = {
 managed = routing_only;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.1.129; hardware = n2; }
}
=OUTPUT=
network:n1	owner:o1
=OPTIONS=--owner --name
=PARAM=network:n1

############################################################
=TITLE=Automatic owner at implicit aggregate in zone cluster
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
any:a16 = { ip = 10.1.0.0/16; link = network:n1; owner = o2; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
network:n2 = { ip = 10.1.2.0/24; owner = o1; nat:n2 = { ip = 10.1.12.0/24; } }
router:r1 = {
 interface:n1 = { bind_nat = n2; }
 interface:n2 = { ip = 10.1.2.1; }
}
=OUTPUT=
any:[ip=10.1.0.0/20 & network:n1]	owner:o1
=OPTIONS=--owner --name
=PARAM=any:[ip = 10.1.0.0/20 & network:n1]

############################################################
=TITLE=No automatic owner at explicit aggregate
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
any:a16 = { ip = 10.1.0.0/16; link = network:n1; owner = o2; }
any:a20 = { ip = 10.1.0.0/20; link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
network:n2 = { ip = 10.1.2.0/24; owner = o1; nat:n2 = { ip = 10.1.12.0/24; } }
router:r1 = {
 interface:n1 = { bind_nat = n2; }
 interface:n2 = { ip = 10.1.2.1; }
}
=OUTPUT=
any:a20	owner:o2
=OPTIONS=--owner --name
=PARAM=any:a20

############################################################
=TITLE=Inherit from smallest matching network at aggregate in zone cluster
=INPUT=
any:a26 = { ip = 10.1.1.64/26; link = network:n1; }
network:n1 = { ip = 10.1.0.0/23; owner = a; }
network:n2 = { ip = 10.1.1.0/24; owner = b; subnet_of = network:n1; }
network:n3 = { ip = 10.1.1.0/25; owner = c; subnet_of = network:n2; }
router:r1 = {
 managed = routing_only;
 model = IOS;
 interface:n1 = { ip = 10.1.0.1; hardware = n1; }
 interface:n2 = { ip = 10.1.1.128; hardware = n2; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip = 10.1.1.129; hardware = n2; }
 interface:n3 = { ip = 10.1.1.2; hardware = n3; }
}
owner:a = { admins = a@example.com; }
owner:b = { admins = b@example.com; }
owner:c = { admins = c@example.com; }
=OUTPUT=
any:a26	owner:c
=OPTIONS=--owner --name
=PARAM=any:a26

############################################################
=TITLE=Inherit owner from area at implicit aggregate
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
area:all = { anchor = network:n1; owner = o1; }
network:n1 = { ip = 10.1.1.0/24; owner = o2; }
network:n2 = { ip = 10.1.2.0/24; owner = o3; }
router:r1 = {
 interface:n1;
 interface:n2;
}
=OUTPUT=
any:[ip=10.1.0.0/20 & network:n1]	owner:o1
=OPTIONS=--owner --name
=PARAM=any:[ip = 10.1.0.0/20 & network:n1]

############################################################
=TITLE=Inherit owner from dual stack aggregate to IPv4 and IPv6 part
=INPUT=
owner:o1 = { admins = a1@b.c; }
any:n1 = { link = network:n1; owner = o1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:u1 = {
 interface:n1;
 interface:n2;
 interface:lo = { ip = 10.1.9.9; ip6 = 2001:db8:1:9::9; loopback; }
}
=OUTPUT=
10.1.1.0/24	network:n1	owner:o1
10.1.2.0/24	network:n2	owner:o1
10.1.9.9	interface:u1.lo	owner:o1
2001:db8:1:1::/64	network:n1	owner:o1
2001:db8:1:2::/64	network:n2	owner:o1
2001:db8:1:9::9	interface:u1.lo	owner:o1
=OPTIONS=--owner
=PARAM=network:[any:n1]
