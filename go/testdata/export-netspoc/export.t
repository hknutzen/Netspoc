
=VAR=topo
owner:x = { admins = x@b.c; }
owner:y = { admins = y@b.c; hide_from_outer_owners; }
owner:z = { admins = z@b.c; hide_from_outer_owners; }
area:all = { owner = x; anchor = network:Big; }
any:Big  = { owner = y; link = network:Big; }
any:Sub1 = { ip = 10.1.0.0/23; link = network:Big; }
any:Sub2 = { ip = 10.1.1.0/25; link = network:Big; }
network:Sub = { ip = 10.1.1.0/24; owner = z; subnet_of = network:Big; }
router:u = {
 interface:Sub;
 interface:Big;
}
network:Big = {
 ip = 10.1.0.0/16;
 host:B10 = { ip = 10.1.0.10; owner = z; }
}
router:asa = {
 managed;
 model = ASA;
 routing = manual;
 interface:Big = { ip = 10.1.0.1; hardware = outside; }
 interface:Kunde = { ip = 10.2.2.1; hardware = inside; }
}
network:Kunde = { ip = 10.2.2.0/24; }
=END=

############################################################
=TITLE=Owner of area, subnet
=INPUT=
${topo}
service:test = {
 user = network:Sub;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=END=
=OUTPUT=
--owner/x/assets
{
 "anys": {
  "any:[network:Kunde]": {
   "networks": {
    "network:Kunde": [
     "interface:asa.Kunde"
    ]
   }
  }
 }
}
--owner/y/assets
{
 "anys": {
  "any:Big": {
   "networks": {
    "network:Big": [
     "host:B10",
     "interface:asa.Big",
     "interface:u.Big"
    ]
   }
  }
 }
}
--owner/z/assets
{
 "anys": {
  "any:Big": {
   "networks": {
    "network:Big": [
     "host:B10"
    ],
    "network:Sub": [
     "interface:u.Sub"
    ]
   }
  }
 }
}
--owner/x/service_lists
{
 "owner": [
  "test"
 ],
 "user": [],
 "visible": []
}
--owner/y/service_lists
{
 "owner": [],
 "user": [],
 "visible": []
}
--owner/z/service_lists
{
 "owner": [],
 "user": [
  "test"
 ],
 "visible": []
}
=END=

############################################################
=TITLE=Owner of larger matching aggregate
=INPUT=
${topo}
service:test = {
 user = any:Sub1;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=END=
=OUTPUT=
--owner/y/service_lists
{
 "owner": [],
 "user": [],
 "visible": []
}
--owner/z/service_lists
{
 "owner": [],
 "user": [
  "test"
 ],
 "visible": []
}
=END=

############################################################
=TITLE=Owner of smaller matching aggregate
=INPUT=
${topo}
service:test = {
 user = any:Sub2;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
=END=
=OUTPUT=
--owner/z/service_lists
{
 "owner": [],
 "user": [
  "test"
 ],
 "visible": []
}
=END=

############################################################
=TITLE=Network and host as user having different owner
=INPUT=
${topo}
service:test = {
 user = host:B10;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
service:test2 = {
 user = network:Big;
 permit src = user; dst = network:Kunde; prt = tcp 88;
}
=END=
=OUTPUT=
--owner/y/service_lists
{
 "owner": [],
 "user": [
  "test2"
 ],
 "visible": []
}
--owner/z/service_lists
{
 "owner": [],
 "user": [
  "test",
  "test2"
 ],
 "visible": []
}
=END=

############################################################
=TITLE=Network and host in rule having different owner
=INPUT=
${topo}
service:test = {
 user = network:Kunde;
 permit src = host:B10; dst = user; prt = tcp 80;
}
service:test2 = {
 user = network:Kunde;
 permit src = network:Big; dst = user; prt = tcp 88;
}
=END=
=OUTPUT=
--owner/y/service_lists
{
 "owner": [
  "test2"
 ],
 "user": [],
 "visible": []
}
--owner/z/service_lists
{
 "owner": [
  "test",
  "test2"
 ],
 "user": [],
 "visible": []
}
=END=

############################################################
=TITLE=Aggregate, network and subnet have different owner
=INPUT=
${topo}
service:test = {
 user = any:Sub1;
 permit src = user; dst = network:Kunde; prt = tcp 80;
}
service:test2 = {
 user = network:Big;
 permit src = user; dst = network:Kunde; prt = tcp 88;
}
=END=
=SUBST=/host:B10 =/#host:B10 =/
=OUTPUT=
--owner/y/service_lists
{
 "owner": [],
 "user": [
  "test2"
 ],
 "visible": []
}
--owner/z/service_lists
{
 "owner": [],
 "user": [
  "test",
  "test2"
 ],
 "visible": []
}
=END=

############################################################
=TITLE=Inversed inheritance for zone
# any:a inherits owner:a from enclosing networks n1, n2.
# Unnumbered network is ignored.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = a; }
network:n2 = { ip = 10.1.2.0/24; owner = a; }
network:n3 = { unnumbered; }
any:a = { link = network:n3; }
router:r = {
 interface:n1;
 interface:n2;
 interface:n3;
}
owner:a = { admins = a@example.com; }
=END=
=OUTPUT=
-- objects
{
 "any:a": {
  "ip": "0.0.0.0/0.0.0.0",
  "owner": "a",
  "zone": "any:a"
 },
 "interface:r.n1": {
  "ip": "short",
  "owner": "a"
 },
 "interface:r.n2": {
  "ip": "short",
  "owner": "a"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "a",
  "zone": "any:a"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "owner": "a",
  "zone": "any:a"
 }
}
=END=

############################################################
=TITLE=Must not inhert inversed inherited owner
# Inherit real owner to empty aggregate.
=INPUT=
owner:a = { admins = a@example.com; }
owner:b = { admins = b@example.com; }
network:n1 = { ip = 10.1.1.0/24; owner = a; }
any:a1-23 = { ip = 10.1.0.0/23; link = network:n1; }
any:empty-23 = { ip = 10.2.0.0/23; link = network:n1; }
any:a-14 = { ip = 10.0.0.0/14; link = network:n1; }
any:a-8 = { ip = 10.0.0.0/8; link = network:n1; owner = b; }
router:r = {
 interface:n1;
}
=END=
=OUTPUT=
-- objects
{
 "any:a-14": {
  "ip": "10.0.0.0/255.252.0.0",
  "owner": "a",
  "zone": "any:[network:n1]"
 },
 "any:a-8": {
  "ip": "10.0.0.0/255.0.0.0",
  "owner": "b",
  "zone": "any:[network:n1]"
 },
 "any:a1-23": {
  "ip": "10.1.0.0/255.255.254.0",
  "owner": "a",
  "zone": "any:[network:n1]"
 },
 "any:empty-23": {
  "ip": "10.2.0.0/255.255.254.0",
  "owner": "b",
  "zone": "any:[network:n1]"
 },
 "interface:r.n1": {
  "ip": "short",
  "owner": "a"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "a",
  "zone": "any:[network:n1]"
 }
}
=END=

############################################################
=TITLE=No inversed inheritance for zone
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = a; }
network:n2 = { ip = 10.1.2.0/24; owner = a; }
network:n3 = { ip = 10.1.3.0/24; owner = b; }
any:a = { link = network:n3; }
router:r = {
 interface:n1;
 interface:n2;
 interface:n3;
}
owner:a = { admins = a@example.com; }
owner:b = { admins = b@example.com; }
=END=
=OUTPUT=
-- objects
{
 "any:a": {
  "ip": "0.0.0.0/0.0.0.0",
  "zone": "any:a"
 },
 "interface:r.n1": {
  "ip": "short",
  "owner": "a"
 },
 "interface:r.n2": {
  "ip": "short",
  "owner": "a"
 },
 "interface:r.n3": {
  "ip": "short",
  "owner": "b"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "a",
  "zone": "any:a"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "owner": "a",
  "zone": "any:a"
 },
 "network:n3": {
  "ip": "10.1.3.0/255.255.255.0",
  "owner": "b",
  "zone": "any:a"
 }
}
=END=

############################################################
=TITLE=No inversed inheritance for zone cluster
=INPUT=
any:a = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; owner = a; }
network:n2 = { ip = 10.1.2.0/24; owner = b; }
network:n3 = { ip = 10.1.3.0/24; }
router:u = {
 interface:n1;
 interface:n2;
}
pathrestriction:p = interface:u.n1, interface:r1.n1;
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
owner:a = { admins = a@example.com; }
owner:b = { admins = b@example.com; }
=END=
=OUTPUT=
-- objects
{
 "any:a": {
  "ip": "0.0.0.0/0.0.0.0",
  "is_supernet": 1,
  "zone": "any:a"
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1"
 },
 "interface:r2.n2": {
  "ip": "10.1.2.2"
 },
 "interface:u.n1": {
  "ip": "short",
  "owner": "a"
 },
 "interface:u.n2": {
  "ip": "short",
  "owner": "b"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "a",
  "zone": "any:a"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "owner": "b",
  "zone": "any:a"
 }
}
=END=

############################################################
=TITLE=Owner at nested areas
=INPUT=
owner:x = { admins = x@b.c; watchers = w@b.c; }
owner:y = { admins = y@b.c; }
owner:z = { admins = z@b.c; }
area:all = { anchor = network:n2; router_attributes = { owner = x; } }
area:a1 = { border = interface:asa2.n2; owner = x;
 router_attributes = { owner = y; }
}
area:a2 = { border = interface:asa1.n1; owner = y; }
network:n1 = {  ip = 10.1.1.0/24; owner = z; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/24; }
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.2.2.2; hardware = n2; }
 interface:n3 = { ip = 10.3.3.1; hardware = n1; }
}
network:n3 = { ip = 10.3.3.0/24; owner = y; }
=END=
=OUTPUT=
--owner/x/extended_by
[]
--owner/y/extended_by
[]
--owner/z/extended_by
[
 {
  "name": "x"
 },
 {
  "name": "y"
 }
]
--email
{
 "w@b.c": [
  "x",
  "z"
 ],
 "x@b.c": [
  "x",
  "z"
 ],
 "y@b.c": [
  "y",
  "z"
 ],
 "z@b.c": [
  "z"
 ]
}
--objects
{
 "interface:asa1.n1": {
  "ip": "10.1.1.1",
  "owner": "y"
 },
 "interface:asa1.n2": {
  "ip": "10.2.2.1",
  "owner": "y"
 },
 "interface:asa2.n2": {
  "ip": "10.2.2.2",
  "owner": "x"
 },
 "interface:asa2.n3": {
  "ip": "10.3.3.1",
  "owner": "x"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "z",
  "zone": "any:[network:n1]"
 },
 "network:n2": {
  "ip": "10.2.2.0/255.255.255.0",
  "owner": "x",
  "zone": "any:[network:n2]"
 },
 "network:n3": {
  "ip": "10.3.3.0/255.255.255.0",
  "owner": "y",
  "zone": "any:[network:n3]"
 }
}
=END=

############################################################
=TITLE=Services of nested objects visible for outer owners
=INPUT=
owner:all = { admins = all@example.com; }
owner:a2  = { admins = a2@example.com; }
owner:n2  = { admins = n2@example.com; }
owner:n3  = { admins = n3@example.com; }
owner:h3  = { admins = h3@example.com; }
area:all  = { anchor = network:n1; owner = all; }
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = inside; }
 interface:n2 = { ip = 10.1.2.1; hardware = outside; }
}
any:a2 = { link =  network:n2; owner = a2; }
network:n2 = { ip = 10.1.2.0/24; owner = n2;}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
network:n3 = {
 ip = 10.1.2.128/25;
 subnet_of = network:n2;
 owner = n3;
 host:h3 = { ip = 10.1.2.130; owner = h3; }
}
service:a2 = {
 user = network:n1;
 permit src = user; dst = any:a2; prt = tcp 80;
}
service:agg16 = {
 user = network:n1;
 permit src = user; dst = any:[ip = 10.1.0.0/16 & network:n2]; prt = tcp 81;
}
service:n2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 82;
}
service:n3 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 83;
}
service:h3 = {
 user = network:n1;
 permit src = user; dst = host:h3; prt = tcp 84;
}
=END=
=OUTPUT=
--owner/all/service_lists
{
 "owner": [
  "a2",
  "agg16",
  "h3",
  "n2",
  "n3"
 ],
 "user": [],
 "visible": []
}
--owner/a2/service_lists
{
 "owner": [
  "a2",
  "agg16",
  "h3",
  "n2",
  "n3"
 ],
 "user": [],
 "visible": []
}
--owner/n2/service_lists
{
 "owner": [
  "a2",
  "agg16",
  "h3",
  "n2",
  "n3"
 ],
 "user": [],
 "visible": []
}
--owner/n3/service_lists
{
 "owner": [
  "a2",
  "agg16",
  "h3",
  "n2",
  "n3"
 ],
 "user": [],
 "visible": []
}
--owner/h3/service_lists
{
 "owner": [
  "a2",
  "agg16",
  "h3",
  "n2",
  "n3"
 ],
 "user": [],
 "visible": []
}
=END=

############################################################
=TITLE=Visible services
=INPUT=
owner:x1 = { admins = x1@example.com; }
owner:x2 = { admins = x2@example.com; }
owner:x3 = { admins = x3@example.com; }
owner:x4 = { admins = x4@example.com; }
owner:DA_1 = { admins = DA_1@example.com; }
owner:DA_2 = { admins = DA_2@example.com; }
owner:DA_3 = { admins = DA_3@example.com; }
owner:DA_4 = { admins = DA_4@example.com; }
network:n1 = { ip = 10.1.1.0/24;
 host:x1 = { ip = 10.1.1.1; owner = x1; }
 host:x2 = { ip = 10.1.1.2; owner = x2; }
 host:x3 = { ip = 10.1.1.3; owner = x3; }
 host:x4 = { ip = 10.1.1.4; owner = x4; }
}
network:n2 = { ip = 10.1.2.0/24;
 host:DA_1 = { ip = 10.1.2.1; owner = DA_1; }
 host:DA_2 = { ip = 10.1.2.2; owner = DA_2; }
 host:DA_3 = { ip = 10.1.2.3; owner = DA_3; }
 host:DA_4 = { ip = 10.1.2.4; owner = DA_4; }
}
router:r = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.99; hardware = n1; }
 interface:n2 = { ip = 10.1.2.99; hardware = n2; }
}
service:s1 = {
 user = host:x1, host:x2, host:x3;
 permit src = user; dst = host:DA_1; prt = tcp 80;
}
service:s2 = {
 user = host:DA_1, host:DA_2, host:DA_3;
 permit src = user; dst = host:x1; prt = tcp 80;
}
service:s3 = {
 user = host:DA_1, host:DA_2, host:x3;
 permit src = user; dst = host:x1; prt = tcp 80;
}
=END=
=OUTPUT=
--owner/x1/service_lists
{
 "owner": [
  "s2",
  "s3"
 ],
 "user": [
  "s1"
 ],
 "visible": []
}
--owner/x4/service_lists
{
 "owner": [],
 "user": [],
 "visible": [
  "s1"
 ]
}
--owner/DA_1/service_lists
{
 "owner": [
  "s1"
 ],
 "user": [
  "s2",
  "s3"
 ],
 "visible": []
}
--owner/DA_4/service_lists
{
 "owner": [],
 "user": [],
 "visible": [
  "s1",
  "s2"
 ]
}
=END=

############################################################
=TITLE=Aggregates and networks in zone cluster
# Checks deterministic values of attribute zone of aggregates.
=INPUT=
network:n1 = { ip = 10.1.54.0/24;}
router:asa = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.54.163; hardware = inside; }
 interface:t1 = { ip = 10.9.1.1; hardware = t1; }
 interface:t2 = { ip = 10.9.2.1; hardware = t2; }
}
network:t1 = { ip = 10.9.1.0/24; }
network:t2 = { ip = 10.9.2.0/24; }
network:link1 = { ip = 10.8.1.0/24; }
network:link2 = { ip = 10.8.2.0/24; }
router:l12 = {
 model = IOS;
 managed;
 routing = manual;
 interface:link1 = { ip = 10.8.1.1; hardware = e1; }
 interface:link2 = { ip = 10.8.2.1; hardware = e2; }
}
router:r1 = {
 interface:t1;
 interface:link1;
 interface:c1a;
 interface:c1b;
}
router:r2 = {
 interface:t2;
 interface:link2;
 interface:c2;
}
network:c1a = { ip = 10.0.100.16/28;}
network:c1b = { ip = 10.0.101.16/28;}
network:c2 = { ip = 10.137.15.0/24;}
any:c2   = { ip = 10.140.0.0/16; link = network:c2; }
pathrestriction:r1 =
 interface:r1.t1, interface:r1.c1a, interface:r1.c1b
;
pathrestriction:r2 =
 interface:r2.t2, interface:r2.c2
;
owner:o = { admins = o@b.c; }
service:test = {
 sub_owner = o;
 user = any:[ip=10.140.0.0/16 & network:t1],
    any:[ip=10.140.0.0/16 & network:t2],
 ;
 permit src = user;
    dst = network:n1;
    prt = tcp 80;
}
=END=
=OUTPUT=
--objects
{
 "any:[ip=10.140.0.0/16 & network:t1]": {
  "ip": "10.140.0.0/255.255.0.0",
  "is_supernet": 1,
  "zone": "any:[network:t1]"
 },
 "any:c2": {
  "ip": "10.140.0.0/255.255.0.0",
  "is_supernet": 1,
  "zone": "any:[network:t2]"
 },
 "network:n1": {
  "ip": "10.1.54.0/255.255.255.0",
  "zone": "any:[network:n1]"
 }
}
--owner/o/users
{
 "test": [
  "any:[ip=10.140.0.0/16 & network:t1]",
  "any:c2"
 ]
}
=END=

############################################################
=TITLE=Aggregates and network0/0 in zone cluster
# Use unique value of attribute zone for aggregates and network0/0.
=INPUT=
owner:x = { admins = guest; show_all; }
area:all = { owner = x; anchor = network:DMZ; }
network:Big = {
 ip = 10.1.0.0/16;
 nat:inet = { ip = 1.1.0.0/16; }
}
router:asa = {
 managed;
 model = ASA;
 routing = manual;
 interface:Big = { ip = 10.1.0.1; hardware = outside; }
 interface:DMZ = { ip = 10.9.9.1; hardware = dmz; }
}
network:DMZ = { ip = 10.9.9.0/24; }
router:inet = {
 interface:DMZ;
 interface:Internet = { bind_nat = inet; }
}
network:Internet = { ip = 0.0.0.0/0; has_subnets; }
=END=
=OUTPUT=
-- objects
{
 "interface:asa.Big": {
  "ip": "10.1.0.1",
  "nat": {
   "inet": "1.1.0.1"
  }
 },
 "interface:asa.DMZ": {
  "ip": "10.9.9.1"
 },
 "interface:inet.DMZ": {
  "ip": "short",
  "owner": "x"
 },
 "interface:inet.Internet": {
  "ip": "short",
  "owner": "x"
 },
 "network:Big": {
  "ip": "10.1.0.0/255.255.0.0",
  "nat": {
   "inet": "1.1.0.0/255.255.0.0"
  },
  "owner": "x",
  "zone": "any:[network:Big]"
 },
 "network:DMZ": {
  "ip": "10.9.9.0/255.255.255.0",
  "owner": "x",
  "zone": "any:[network:DMZ]"
 },
 "network:Internet": {
  "ip": "0.0.0.0/0.0.0.0",
  "is_supernet": 1,
  "owner": "x",
  "zone": "any:[network:DMZ]"
 }
}
=END=

############################################################
=TITLE=Nested only_watch
=INPUT=
owner:all  = { admins = all@b.c; only_watch; }
owner:a123 = { admins = a123@b.c; }
owner:a12  = { admins = a12@b.c; only_watch; }
owner:a1   = { admins = a1@b.c; }
owner:n2   = { admins = n2@b.c; }
area:all  = { owner = all; anchor = network:n1; }
area:a123 = { owner = a123; inclusive_border = interface:r2.n4; }
area:a12  = { owner = a12; border = interface:r2.n2; }
area:a1   = { owner = a1; border = interface:r1.n1; }
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = {
 owner = n2;
 ip = 10.1.2.0/24;
 host:h10 = { ip = 10.1.2.10; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
=END=
=OUTPUT=
--owner/a1/assets
{
 "anys": {
  "any:[network:n1]": {
   "networks": {
    "network:n1": [
     "interface:r1.n1"
    ]
   }
  }
 }
}
--owner/n2/assets
{
 "anys": {
  "any:[network:n2]": {
   "networks": {
    "network:n2": [
     "host:h10",
     "interface:r1.n2",
     "interface:r2.n2"
    ]
   }
  }
 }
}
--owner/a12/assets
{
 "anys": {
  "any:[network:n1]": {
   "networks": {
    "network:n1": [
     "interface:r1.n1"
    ]
   }
  },
  "any:[network:n2]": {
   "networks": {
    "network:n2": [
     "host:h10",
     "interface:r1.n2",
     "interface:r2.n2"
    ]
   }
  }
 }
}
--owner/a123/assets
{
 "anys": {
  "any:[network:n1]": {
   "networks": {
    "network:n1": [
     "interface:r1.n1"
    ]
   }
  },
  "any:[network:n2]": {
   "networks": {
    "network:n2": [
     "host:h10",
     "interface:r1.n2",
     "interface:r2.n2"
    ]
   }
  },
  "any:[network:n3]": {
   "networks": {
    "network:n3": [
     "interface:r2.n3"
    ]
   }
  }
 }
}
--owner/all/assets
{
 "anys": {
  "any:[network:n1]": {
   "networks": {
    "network:n1": [
     "interface:r1.n1"
    ]
   }
  },
  "any:[network:n2]": {
   "networks": {
    "network:n2": [
     "host:h10",
     "interface:r1.n2",
     "interface:r2.n2"
    ]
   }
  },
  "any:[network:n3]": {
   "networks": {
    "network:n3": [
     "interface:r2.n3"
    ]
   }
  },
  "any:[network:n4]": {
   "networks": {
    "network:n4": [
     "interface:r2.n4"
    ]
   }
  }
 }
}
--owner/a123/extended_by
[
 {
  "name": "all"
 }
]
--owner/a12/extended_by
[]
--owner/a1/extended_by
[
 {
  "name": "a12"
 },
 {
  "name": "a123"
 },
 {
  "name": "all"
 }
]
--owner/all/extended_by
[]
--owner/n2/extended_by
[
 {
  "name": "a12"
 },
 {
  "name": "a123"
 },
 {
  "name": "all"
 }
]
=END=

############################################################
=TITLE=only_watch part of inner owner
=INPUT=
owner:all = { admins = all@b.c; only_watch; }
owner:a1 = { admins = a1@b.c; only_watch; }
owner:a2 = { admins = a2@b.c; only_watch; }
owner:a3 = { admins = a3@b.c; only_watch; }
owner:a12 = { admins = a12@b.c; only_watch; }
owner:n1 = { admins = n1@b.c; }
owner:n2 = { admins = n2@b.c; }
owner:h3 = { admins = h3@b.c; }
area:a1 = { owner = a1; border = interface:asa1.n1; }
area:a2 = { owner = a2; border = interface:asa1.n2; }
area:a3 = { owner = a3; border = interface:asa1.n3; }
area:a12 = { owner = a12; inclusive_border = interface:asa1.n3; }
area:all = { owner = all; anchor = network:n1; }
network:n1 = { ip = 10.1.1.0/24; owner = n1;
 host:h1 = { ip = 10.1.1.9; owner = n2; }
}
network:n2 = { ip = 10.1.2.0/24; owner = n2;
 host:h2 = { ip = 10.1.2.9; owner = n1; }
}
network:n3 = { ip = 10.1.3.0/24;
 host:h3 = { ip = 10.1.3.9; owner = h3; }
 host:h3x = { ip = 10.1.3.10; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
=END=
=OUTPUT=
--owner/n1/extended_by
[
 {
  "name": "a12"
 },
 {
  "name": "all"
 }
]
--owner/n2/extended_by
[
 {
  "name": "a12"
 },
 {
  "name": "all"
 }
]
--owner/h3/extended_by
[
 {
  "name": "a3"
 },
 {
  "name": "all"
 }
]
=END=

############################################################
=TITLE=Managed interface inherits from area with show_all
=INPUT=
owner:all = { admins = all@example.com; only_watch; show_all; }
owner:n1 = { admins = n1@example.com; }
owner:r1 = { admins = r1@example.com; }
area:all = {owner = all; anchor = network:n1;}
any:n1 = { owner = n1; link = network:n1; }
network:n1 = {ip = 10.1.1.0/24;}
router:r1 = {
 owner = r1;
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = eth0; }
}
service:s1 = {
 user = interface:r1.n1;
 permit src = user; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--owner/all/service_lists
{
 "owner": [
  "s1"
 ],
 "user": [],
 "visible": []
}
--owner/all/assets
{
 "anys": {
  "any:n1": {
   "networks": {
    "network:n1": [
     "interface:r1.n1"
    ]
   }
  }
 }
}
--objects
{
 "any:n1": {
  "ip": "0.0.0.0/0.0.0.0",
  "owner": "n1",
  "zone": "any:n1"
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1",
  "owner": "r1"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "n1",
  "zone": "any:n1"
 }
}
=END=

############################################################
=TITLE=Owner of aggregate at tunnel of unmanaged device
# Must not take the undefined owner of tunnel.
=INPUT=
owner:Extern_VPN = { admins = abc@d.com; }
isakmp:ikeaes256SHA = {
 authentication = preshare;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
ipsec:ipsecaes256SHA = {
 key_exchange = isakmp:ikeaes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 3600 sec;
}
crypto:vpn = { type = ipsec:ipsecaes256SHA; }
network:n1 = { ip = 10.1.1.0/24;}
router:r = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = inside; }
 interface:n2 = { ip = 192.168.1.2; hardware = outside; hub = crypto:vpn; }
}
area:vpn = { owner = Extern_VPN; inclusive_border = interface:r.n1; }
network:n2 = { ip = 192.168.1.0/28;}
router:dmz = {
 interface:n2 = { ip = 192.168.1.1; }
 interface:Internet;
}
network:Internet = { ip = 0.0.0.0/0; has_subnets; }
router:VPN1 = {
 interface:Internet = { ip = 1.1.1.1; spoke = crypto:vpn; }
 interface:v1;
}
network:v1 = { ip = 10.9.1.0/24; }
router:VPN2 = {
 interface:Internet = { ip = 1.1.1.2; spoke = crypto:vpn; }
 interface:v2;
}
network:v2 = { ip = 10.9.2.0/24; }
router:VPN3 = {
 interface:Internet = { ip = 1.1.1.3; spoke = crypto:vpn; }
 interface:v3;
}
network:v3 = { ip = 10.9.3.0/24; }
service:Test = {
 user = network:[any:[ip=10.9.0.0/21 & area:vpn]];
 permit src = network:n1; dst = user; prt = udp 53;
}
=END=
=OUTPUT=
--objects
{
 "any:[ip=10.9.0.0/21 & network:v1]": {
  "ip": "10.9.0.0/255.255.248.0",
  "is_supernet": 1,
  "owner": "Extern_VPN",
  "zone": "any:[network:v1]"
 },
 "any:[ip=10.9.0.0/21 & network:v2]": {
  "ip": "10.9.0.0/255.255.248.0",
  "is_supernet": 1,
  "owner": "Extern_VPN",
  "zone": "any:[network:v2]"
 },
 "any:[ip=10.9.0.0/21 & network:v3]": {
  "ip": "10.9.0.0/255.255.248.0",
  "is_supernet": 1,
  "owner": "Extern_VPN",
  "zone": "any:[network:v3]"
 },
 "interface:VPN1.v1": {
  "ip": "short",
  "owner": "Extern_VPN"
 },
 "interface:VPN2.v2": {
  "ip": "short",
  "owner": "Extern_VPN"
 },
 "interface:VPN3.v3": {
  "ip": "short",
  "owner": "Extern_VPN"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "zone": "any:[network:n1]"
 },
 "network:v1": {
  "ip": "10.9.1.0/255.255.255.0",
  "owner": "Extern_VPN",
  "zone": "any:[network:v1]"
 },
 "network:v2": {
  "ip": "10.9.2.0/255.255.255.0",
  "owner": "Extern_VPN",
  "zone": "any:[network:v2]"
 },
 "network:v3": {
  "ip": "10.9.3.0/255.255.255.0",
  "owner": "Extern_VPN",
  "zone": "any:[network:v3]"
 }
}
--services
{
 "Test": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "dst",
    "prt": [
     "udp 53"
    ],
    "src": [
     "network:n1"
    ]
   }
  ]
 }
}
--owner/Extern_VPN/users
{
 "Test": [
  "network:v1",
  "network:v2",
  "network:v3"
 ]
}
=END=

############################################################
=TITLE=Split service and multi owner from auto interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = a; }
network:n2 = { ip = 10.1.2.0/24; owner = b; }
network:n3 = { ip = 10.1.3.0/24; owner = c; }
network:n4 = { ip = 10.1.4.0/24; owner = d; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
owner:a = { admins = a@example.com; }
owner:b = { admins = b@example.com; }
owner:c = { admins = c@example.com; }
owner:d = { admins = d@example.com; }
service:s1 = {
 multi_owner;
 user = network:n1, network:n4;
 permit src = user; dst = interface:r.[auto]; prt = tcp 22;
}
service:s2 = {
 user = network:n1, network:n4, interface:r.[auto];
 permit src = user; dst = user; prt = tcp 23;
}
=END=
=OUTPUT=
--services
{
 "s1(OlWkR_nb)": {
  "details": {
   "owner": [
    "c"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r.n3"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 },
 "s1(aZ1_3Qf8)": {
  "details": {
   "owner": [
    "b"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r.n2"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 },
 "s2(6J6zzaOm)": {
  "details": {
   "owner": [
    "d"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n4"
    ],
    "has_user": "src",
    "prt": [
     "tcp 23"
    ],
    "src": []
   }
  ]
 },
 "s2(6w6A9_c5)": {
  "details": {
   "owner": [
    "a"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n1"
    ],
    "has_user": "src",
    "prt": [
     "tcp 23"
    ],
    "src": []
   }
  ]
 },
 "s2(VzSrSJ63)": {
  "details": {
   "owner": [
    "a",
    "d"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "both",
    "prt": [
     "tcp 23"
    ],
    "src": []
   }
  ]
 },
 "s2(en0TO5Ls)": {
  "details": {
   "owner": [
    "b"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r.n2"
    ],
    "has_user": "src",
    "prt": [
     "tcp 23"
    ],
    "src": []
   }
  ]
 },
 "s2(fOSUGYLe)": {
  "details": {
   "owner": [
    "c"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r.n3"
    ],
    "has_user": "src",
    "prt": [
     "tcp 23"
    ],
    "src": []
   }
  ]
 }
}
--owner/a/users
{
 "s1(aZ1_3Qf8)": [
  "network:n1"
 ],
 "s2(6w6A9_c5)": [
  "interface:r.n2"
 ],
 "s2(VzSrSJ63)": [
  "network:n1",
  "network:n4"
 ],
 "s2(en0TO5Ls)": [
  "network:n1"
 ]
}
--owner/b/users
{
 "s1(aZ1_3Qf8)": [
  "network:n1"
 ],
 "s2(6w6A9_c5)": [
  "interface:r.n2"
 ],
 "s2(en0TO5Ls)": [
  "network:n1"
 ]
}
--owner/c/users
{
 "s1(OlWkR_nb)": [
  "network:n4"
 ],
 "s2(6J6zzaOm)": [
  "interface:r.n3"
 ],
 "s2(fOSUGYLe)": [
  "network:n4"
 ]
}
--owner/d/users
{
 "s1(OlWkR_nb)": [
  "network:n4"
 ],
 "s2(6J6zzaOm)": [
  "interface:r.n3"
 ],
 "s2(VzSrSJ63)": [
  "network:n1",
  "network:n4"
 ],
 "s2(fOSUGYLe)": [
  "network:n4"
 ]
}
=END=

############################################################
=TITLE=Owner of service with reversed rule
=INPUT=
owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2@b.c; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; owner = o2; }
protocol:echo = icmp 8;
protocol:echo-reply = icmp 0, reversed;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocol:echo, protocol:echo-reply;
}
=END=
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "o2"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n2"
    ],
    "has_user": "src",
    "prt": [
     "icmp 0, reversed",
     "icmp 8"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=Owner without any assets
=INPUT=
owner:o = { admins = o@example.com; }
owner:all = { admins = all@example.com; only_watch; show_all; }
area:all = { anchor = network:n1; owner = all; }
network:n1 = { ip = 10.1.1.0/24; }
=END=
=OUTPUT=
-- email
{
 "all@example.com": [
  "all",
  "o"
 ],
 "o@example.com": [
  "o"
 ]
}
-- owner/o/assets
{}
=END=

############################################################
=TITLE=only_watch owner visible by show_all
=INPUT=
owner:all = { watchers = all@example.com; only_watch; show_all; }
owner:n1 = { admins = n1@example.com; only_watch; }
area:all = { anchor = network:n1; owner = all; }
area:n1 = { border = interface:r1.n1; owner = n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=END=
=OUTPUT=
-- email
{
 "all@example.com": [
  "all",
  "n1"
 ],
 "n1@example.com": [
  "n1"
 ]
}
=END=

############################################################
=TITLE=Wildcard address as watcher
=INPUT=
owner:all_ex = { only_watch; watchers = [all]@example.com; }
owner:o1 = { admins = o1@example.com; }
owner:o2 = { admins = o2@example.com; }
owner:o2s1 = { admins = o2s1@example.com; }
owner:o2s2 = { admins = o2s2@other; }
owner:o3 = { admins = o3@sub.example.com; }
owner:o4 = { admins = o4@example.com; }
owner:all = { admins = all@example.com; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; owner = o2; }
network:n2s1 = { ip = 10.1.2.64/26; owner = o2s1; subnet_of = network:n2; }
network:n2s2 = { ip = 10.1.2.128/26; owner = o2s2; subnet_of = network:n2; }
network:n3 = { ip = 10.1.3.0/24; owner = o3; }
network:n4 = { ip = 10.1.4.0/24; owner = o4; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:u = {
 interface:n2;
 interface:n2s1;
 interface:n2s2;
}
area:all = { anchor = network:n1; owner = all; }
area:a12 = { inclusive_border = interface:r1.n3; owner = all_ex; }
area:a1 = { border = interface:r1.n1; owner = o1; }
=END=
=OUTPUT=
-- email
{
 "[all]@example.com": [
  "all_ex",
  "o1",
  "o2",
  "o2s1",
  "o2s2",
  "o4"
 ],
 "all@example.com": [
  "all",
  "o3"
 ],
 "o1@example.com": [],
 "o2@example.com": [],
 "o2s1@example.com": [],
 "o2s2@other": [
  "o2s2"
 ],
 "o3@sub.example.com": [
  "o3"
 ],
 "o4@example.com": []
}
=END=

############################################################
=TITLE=Remove auto interface in rule
# Auto interface of group and auto interface of rule must be
# identical, when rule is exported.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
group:g = network:n2, interface:asa1.[auto];
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = group:g &! interface:asa1.[auto];
        prt = tcp 22;
}
=END=
=OUTPUT=
-- services
{
 "s1": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n2"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=Service with empty rule
=INPUT=
owner:all = { admins = all@example.com; only_watch; show_all; }
owner:a = { admins = a@example.com; }
area:all = {owner = all; anchor = network:n1;}
network:n1 = { ip = 10.1.1.0/24; owner = a; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
group:g = ;
service:s1 = {
 description = test; test, test;# With comment
 user = network:n1;
 permit src = user; dst = group:g; prt = udp 162;
}
=END=
=OUTPUT=
-- owner/all/service_lists
{
 "owner": [],
 "user": [
  "s1"
 ],
 "visible": []
}
-- owner/all/users
{
 "s1": [
  "network:n1"
 ]
}
-- owner/a/service_lists
{
 "owner": [],
 "user": [
  "s1"
 ],
 "visible": []
}
-- owner/a/users
{
 "s1": [
  "network:n1"
 ]
}
-- services
{
 "s1": {
  "details": {
   "description": "test; test, test",
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "src",
    "prt": [
     "udp 162"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=Split service with "foreach"
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2; routing = OSPF;}
}
network:n2  = {ip = 10.1.2.0/24;}
service:ping_local = {
 user = foreach interface:r1.[all];
 permit src = any:[user]; dst = user; prt = icmp 8;
}
=END=
=OUTPUT=
--services
{
 "ping_local(82hHHn8T)": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r1.n1"
    ],
    "has_user": "src",
    "prt": [
     "icmp 8"
    ],
    "src": []
   }
  ]
 },
 "ping_local(x8vMymBh)": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r1.n2"
    ],
    "has_user": "src",
    "prt": [
     "icmp 8"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=Reference different parts of zone cluster
=INPUT=
owner:o = {admins = a@b.c;}
network:n1 = {ip = 10.1.1.0/24; owner = o;}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2;}
}
router:r2 = {
 interface:n1 = {ip = 10.1.1.2;}
 interface:n2 = {ip = 10.1.2.2;}
}
network:n2 = { ip = 10.1.2.0/24; owner = o;}
pathrestriction:p = interface:r1.n2, interface:r2.n2;
service:s1 = {
 user = any:[network:n1];
 permit src = user; dst = interface:r1.n1; prt = tcp 80;
}
service:s2 = {
 user = any:[network:n2];
 permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=END=
# any:[network:n1] and any:[network:n2] both reference the same zone.
# Deterministically use one of them in output.
=OUTPUT=
-- objects
{
 "any:[network:n1]": {
  "ip": "0.0.0.0/0.0.0.0",
  "is_supernet": 1,
  "owner": "o",
  "zone": "any:[network:n1]"
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1"
 },
 "interface:r1.n2": {
  "ip": "10.1.2.1"
 },
 "interface:r2.n1": {
  "ip": "10.1.1.2",
  "owner": "o"
 },
 "interface:r2.n2": {
  "ip": "10.1.2.2",
  "owner": "o"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "o",
  "zone": "any:[network:n1]"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "owner": "o",
  "zone": "any:[network:n1]"
 }
}
--owner/o/users
{
 "s1": [
  "any:[network:n1]"
 ],
 "s2": [
  "any:[network:n1]"
 ]
}
=END=

############################################################
=TITLE=Protocol modifiers
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2; routing = OSPF;}
 interface:n3 = {ip = 10.1.3.1; hardware = n3;}
}
protocolgroup:ping_net_both = protocol:ping_net, protocol:ping_net_reply;
protocol:ping_net = icmp 8, src_net, dst_net, overlaps, no_check_supernet_rules;
protocol:ping_net_reply = icmp 8, src_net, dst_net, overlaps, reversed, no_check_supernet_rules;
protocol:oneway_IP = ip, oneway;
protocol:syslog = udp 514, stateless;
service:ping = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = protocolgroup:ping_net_both;
}
service:syslog = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = protocol:syslog;
}
service:coupling = {
 user = network:n1, network:n3;
 permit src = user; dst = user; prt = protocol:oneway_IP;
}
=END=
=OUTPUT=
--services
{
 "coupling": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "both",
    "prt": [
     "ip, oneway"
    ],
    "src": []
   }
  ]
 },
 "ping": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "host:h2"
    ],
    "has_user": "src",
    "prt": [
     "icmp 8, dst_net, reversed, src_net",
     "icmp 8, dst_net, src_net"
    ],
    "src": []
   }
  ]
 },
 "syslog": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "host:h2"
    ],
    "has_user": "src",
    "prt": [
     "udp 514, stateless"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=Dynamic NAT
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:D1 = { ip = 10.9.9.0/26; dynamic; }
 nat:D2 = { ip = 10.9.9.0/26; dynamic; }
 nat:H = { hidden; }
 nat:S = { ip = 10.8.8.0/24; }
 host:h1 = { ip = 10.1.1.10; nat:D1 = { ip = 10.9.9.10; } }
 host:h2 = { ip = 10.1.1.11; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat:D1 = { ip = 10.9.9.1; } }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = D1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = D2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = H; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; bind_nat = S; }
}
service:s1 = {
 user = host:h1, host:h2;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = interface:r1.n1; prt = tcp 22;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 81;
}
=END=
=OUTPUT=
--objects
{
 "host:h1": {
  "ip": "10.1.1.10",
  "nat": {
   "D1": "10.9.9.10",
   "D2": "10.9.9.0/255.255.255.192",
   "H": "hidden",
   "S": "10.8.8.10"
  }
 },
 "host:h2": {
  "ip": "10.1.1.11",
  "nat": {
   "D1": "10.9.9.0/255.255.255.192",
   "D2": "10.9.9.0/255.255.255.192",
   "H": "hidden",
   "S": "10.8.8.11"
  }
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1",
  "nat": {
   "D1": "10.9.9.1",
   "D2": "10.9.9.0/255.255.255.192",
   "H": "hidden",
   "S": "10.8.8.1"
  }
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "nat": {
   "D1": "10.9.9.0/255.255.255.192",
   "D2": "10.9.9.0/255.255.255.192",
   "H": "hidden",
   "S": "10.8.8.0/255.255.255.0"
  },
  "zone": "any:[network:n1]"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "zone": "any:[network:n2]"
 }
}
=END=

############################################################
=TITLE=Static NAT for
=INPUT=
network:n1 = {
 ip = 192.168.1.0/24;
 nat:n1 = { ip = 10.1.1.0/24; }
 host:h10 = { ip = 192.168.1.10; }
 host:h11-16 = { range = 192.168.1.11-192.168.1.16; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 192.168.1.1, 192.168.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n1; }
}

service:s1 = {
 user = host:h10, host:h11-16, interface:r1.n1, interface:r1.n1.2;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 81;
}
=OUTPUT=
--objects
{
 "host:h10": {
  "ip": "192.168.1.10",
  "nat": {
   "n1": "10.1.1.10"
  }
 },
 "host:h11-16": {
  "ip": "192.168.1.11-192.168.1.16",
  "nat": {
   "n1": "10.1.1.11-10.1.1.16"
  }
 },
 "interface:r1.n1": {
  "ip": "192.168.1.1",
  "nat": {
   "n1": "10.1.1.1"
  }
 },
 "interface:r1.n1.2": {
  "ip": "192.168.1.2",
  "nat": {
   "n1": "10.1.1.2"
  }
 },
 "network:n1": {
  "ip": "192.168.1.0/255.255.255.0",
  "nat": {
   "n1": "10.1.1.0/255.255.255.0"
  },
  "zone": "any:[network:n1]"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "zone": "any:[network:n2]"
 }
}
=END=

############################################################
=TITLE=Negotiated interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { negotiated; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
--objects
{
 "interface:r1.n1": {
  "ip": "10.1.1.0/255.255.255.0"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "zone": "any:[network:n2]"
 }
}
=END=

############################################################
=TITLE=Host range
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { range = 10.1.1.10-10.1.1.17; } }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { negotiated; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
--objects
{
 "host:h1": {
  "ip": "10.1.1.10-10.1.1.17"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "zone": "any:[network:n2]"
 }
}
=END=

############################################################
=TITLE=hide_from_outer_owners, show_hidden_owners
=INPUT=
owner:a =  { admins = a@example.com; }
owner:n1 = { admins = n1@example.com; hide_from_outer_owners; show_hidden_owners; }
owner:h1 = { admins = h1@example.com; hide_from_outer_owners; }
owner:n2 = { admins = n2@example.com; }
owner:h2 = { admins = h2@example.com; hide_from_outer_owners; }
any:a = { link = network:n1;   owner = a; }
network:n1 = { ip = 10.1.1.0/24; owner = n1;
 host:h1 = { ip = 10.1.1.10; owner = h1; }
}
network:n2 = { ip = 10.1.2.0/24; owner = n2;
 host:h2 = { ip = 10.1.2.10; owner = h2; }
}
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2;
 interface:n3;
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1  = { ip = 10.1.1.2; hardware = n1; }
 interface:dst = { ip = 10.2.1.2; hardware = dst; }
}
network:dst = { ip = 10.2.1.0/24; }
service:a = {
 user = any:a;
 permit src = user; dst = network:dst; prt = tcp 80;
}
service:n1 = {
 user = network:n1;
 permit src = user; dst = network:dst; prt = tcp 81;
}
service:h1 = {
 user = host:h1;
 permit src = user; dst = network:dst; prt = tcp 82;
}
service:n2 = {
 user = network:n2;
 permit src = user; dst = network:dst; prt = tcp 83;
}
service:h2 = {
 user = host:h2;
 permit src = user; dst = network:dst; prt = tcp 84;
}
service:n3 = {
 user = network:n3;
 permit src = user; dst = network:dst; prt = tcp 85;
}
=END=
=OUTPUT=
--owner/a/service_lists
{
 "owner": [],
 "user": [
  "a",
  "n2",
  "n3"
 ],
 "visible": []
}
--owner/n1/service_lists
{
 "owner": [],
 "user": [
  "a",
  "h1",
  "n1"
 ],
 "visible": []
}
--owner/n2/service_lists
{
 "owner": [],
 "user": [
  "a",
  "n2"
 ],
 "visible": []
}
--owner/h1/service_lists
{
 "owner": [],
 "user": [
  "a",
  "h1",
  "n1"
 ],
 "visible": []
}
=END=

############################################################
=TITLE=unnumbered
=INPUT=
owner:all = { admins = all@example.com; }
owner:a1 = { admins = a1@example.com; }
area:all = { anchor = network:n1; owner = all; }
any:a1 = { link = network:n2; owner = a1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { unnumbered; }
network:n3 = { unnumbered; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
}
router:r2 = {
 managed;
 model = IOS;
 interface:l1 = { ip = 10.9.9.9; loopback; hardware = Loopback0; }
 interface:n2 = { unnumbered; hardware = n2; }
 interface:n3 = { unnumbered; hardware = n3; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { unnumbered; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = any:[ip = 10.1.3.0/24 & network:n3];
 permit src = user; dst = network:n4; prt = tcp 80;
}
=END=
=OUTPUT=
--objects
{
 "any:[ip=10.1.3.0/24 & network:n3]": {
  "ip": "10.1.3.0/255.255.255.0",
  "is_supernet": 1,
  "owner": "all",
  "zone": "any:[network:n3]"
 },
 "any:a1": {
  "ip": "0.0.0.0/0.0.0.0",
  "is_supernet": 1,
  "owner": "a1",
  "zone": "any:a1"
 },
 "interface:r1.n1": {
  "ip": "short",
  "owner": "a1"
 },
 "interface:r2.l1": {
  "ip": "10.9.9.9",
  "zone": "any:[interface:r2.l1]"
 },
 "interface:r3.n4": {
  "ip": "10.1.4.1"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "a1",
  "zone": "any:a1"
 },
 "network:n4": {
  "ip": "10.1.4.0/255.255.255.0",
  "owner": "all",
  "zone": "any:[network:n4]"
 }
}
--owner/all/assets
{
 "anys": {
  "any:[interface:r2.l1]": {
   "networks": {
    "interface:r2.l1": []
   }
  },
  "any:[network:n4]": {
   "networks": {
    "network:n4": [
     "interface:r3.n4"
    ]
   }
  },
  "any:a1": {
   "networks": {
    "network:n1": [
     "interface:r1.n1"
    ]
   }
  }
 }
}
=END=

############################################################
=TITLE=Managed and unmanaged loopback interface
=INPUT=
owner:all = { admins = all@example.com; }
area:all = { anchor = network:n1; owner = all; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:l1 = { ip = 10.9.9.1; loopback; hardware = Loopback1; }
 interface:l2 = { ip = 10.9.9.2; loopback; hardware = Loopback2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:l3 = { ip = 10.9.9.3; loopback; hardware = Loopback3; }
 interface:l4 = { ip = 10.9.9.4; loopback; hardware = Loopback4; }
}
service:s1 = {
 user = interface:r1.l1,
        interface:r2.l3,
        network:[interface:r1.l2],
        network:[interface:r2.l4],
        ;
 permit src = network:n1; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--owner/all/assets
{
 "anys": {
  "any:[interface:r1.l1]": {
   "networks": {
    "interface:r1.l1": []
   }
  },
  "any:[interface:r1.l2]": {
   "networks": {
    "interface:r1.l2": []
   }
  },
  "any:[network:n1]": {
   "networks": {
    "network:n1": [
     "interface:r1.n1"
    ]
   }
  },
  "any:[network:n2]": {
   "networks": {
    "interface:r2.l3": [],
    "interface:r2.l4": [],
    "network:n2": [
     "interface:r1.n2",
     "interface:r2.n2"
    ]
   }
  }
 }
}
--objects
{
 "interface:r1.l1": {
  "ip": "10.9.9.1",
  "zone": "any:[interface:r1.l1]"
 },
 "interface:r1.l2": {
  "ip": "10.9.9.2",
  "zone": "any:[interface:r1.l2]"
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1"
 },
 "interface:r1.n2": {
  "ip": "10.1.2.1"
 },
 "interface:r2.l3": {
  "ip": "10.9.9.3",
  "owner": "all",
  "zone": "any:[network:n2]"
 },
 "interface:r2.l4": {
  "ip": "10.9.9.4",
  "owner": "all",
  "zone": "any:[network:n2]"
 },
 "interface:r2.n2": {
  "ip": "10.1.2.2",
  "owner": "all"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "all",
  "zone": "any:[network:n1]"
 },
 "network:n2": {
  "ip": "10.1.2.0/255.255.255.0",
  "owner": "all",
  "zone": "any:[network:n2]"
 }
}
=END=

############################################################
=TITLE=Redundant loopback interfaces
=INPUT=
owner:all = { admins = all@example.com; }
owner:nms = { admins = nms@example.com; }
area:all = { anchor = network:n1; owner = all; }
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 owner = nms;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:l1 = { virtual = { ip = 10.9.9.1; } loopback; hardware = Loopback1; }
}
router:r2 = {
 managed;
 model = IOS;
 owner = nms;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:l1 = { virtual = { ip = 10.9.9.1; } loopback; hardware = Loopback1; }
}
service:s1 = {
 user = interface:r1.l1.virtual, interface:r2.l1.virtual;
 permit src = network:n1; dst = user; prt = tcp 22;
}
=END=
=OUTPUT=
--owner/all/assets
{
 "anys": {
  "any:[network:n1]": {
   "networks": {
    "network:n1": [
     "interface:r1.n1",
     "interface:r2.n1"
    ]
   }
  },
  "any:[network:virtual:l1]": {
   "networks": {
    "interface:r1.l1.virtual": [],
    "interface:r2.l1.virtual": []
   }
  }
 }
}
--owner/nms/assets
{
 "anys": {
  "any:[network:virtual:l1]": {
   "networks": {
    "interface:r1.l1.virtual": [],
    "interface:r2.l1.virtual": []
   }
  }
 }
}
--objects
{
 "interface:r1.l1.virtual": {
  "ip": "10.9.9.1",
  "owner": "nms",
  "zone": "any:[network:virtual:l1]"
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1",
  "owner": "nms"
 },
 "interface:r2.l1.virtual": {
  "ip": "10.9.9.1",
  "owner": "nms",
  "zone": "any:[network:virtual:l1]"
 },
 "interface:r2.n1": {
  "ip": "10.1.1.2",
  "owner": "nms"
 },
 "network:n1": {
  "ip": "10.1.1.0/255.255.255.0",
  "owner": "all",
  "zone": "any:[network:n1]"
 }
}
=END=

############################################################
=TITLE=Recognize unmanaged interface as part of aggregate
=INPUT=
owner:o0 = { admins = a0@example.com; }
owner:o1 = { admins = a1@example.com; }
any:a = { ip = 10.0.0.0/8; link = network:n1; }
router:u = {
 interface:lo = { ip = 10.1.9.1; owner = o0; loopback; }
 interface:n1 = { ip = 10.1.1.1; owner = o1; }
}
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = any:a;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
--owner/o0/users
{
 "s1": [
  "any:a"
 ]
}
--owner/o1/users
{
 "s1": [
  "any:a"
 ]
}
=END=

############################################################
=TITLE=Disabled user, disabled in rule, disabled service
=INPUT=
owner:all = { admins = all@example.com; }
area:all = { anchor = network:n1; owner = all; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; disabled; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:n1; prt = tcp 81;
}
service:s2 = {
 user = host:h2, interface:r1.n2;
 permit src = user; dst = network:n1; prt = tcp 82;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 83;
}
service:s4 = {
 disabled;
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 84;
}
service:s5 = {
 disable_at = 3000-12-31;
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 85;
}
service:s6 = {
 disable_at = 1999-12-31;
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 86;
}
=END=
=OUTPUT=
--owner/all/users
{
 "s1": [],
 "s2": [],
 "s3": [
  "network:n1"
 ],
 "s4": [
  "network:n1"
 ],
 "s5": [
  "network:n1"
 ],
 "s6": [
  "network:n1"
 ]
}
--services
{
 "s1": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n1"
    ],
    "has_user": "src",
    "prt": [
     "tcp 81"
    ],
    "src": []
   }
  ]
 },
 "s2": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n1"
    ],
    "has_user": "src",
    "prt": [
     "tcp 82"
    ],
    "src": []
   }
  ]
 },
 "s3": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "src",
    "prt": [
     "tcp 83"
    ],
    "src": []
   }
  ]
 },
 "s4": {
  "details": {
   "disabled": 1,
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n3"
    ],
    "has_user": "src",
    "prt": [
     "tcp 84"
    ],
    "src": []
   }
  ]
 },
 "s5": {
  "details": {
   "disable_at": "3000-12-31",
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n3"
    ],
    "has_user": "src",
    "prt": [
     "tcp 85"
    ],
    "src": []
   }
  ]
 },
 "s6": {
  "details": {
   "disable_at": "1999-12-31",
   "disabled": 1,
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n3"
    ],
    "has_user": "src",
    "prt": [
     "tcp 86"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=Protocols
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
protocol:ntp = udp 123:123;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80-90, protocol:ntp, icmp 0, icmp 3/13, proto 54;
}
service:s2 = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp, udp, icmp;
}
=END=
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n2"
    ],
    "has_user": "src",
    "prt": [
     "54",
     "icmp 0",
     "icmp 3/13",
     "tcp 80-90",
     "udp 123:123"
    ],
    "src": []
   }
  ]
 },
 "s2": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n1"
    ],
    "has_user": "src",
    "prt": [
     "icmp",
     "tcp",
     "udp"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=Split service with user in src and dst
=INPUT=
owner:all = { admins = all@example.com; }
area:all = { anchor = network:n1; owner = all; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2;
 interface:n3;
}
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n1, network:n2, network:n3;
 permit src = user; dst = any:[user]; prt = tcp 80;
 permit src = any:[user]; dst = user; prt = tcp 81;
}
# Internally, this is rewritten to
# "user = network:n1, network:n2, network:n3;"
# because number of networks is larger than number of aggregates.
service:s2 = {
 user = any:[network:n1, network:n2];
 permit src = user; dst = network:[user]; prt = tcp 82;
 permit src = network:[user]; dst = user; prt = tcp 83;
}
service:s3 = {
 user = network:n1, network:n2, network:n3;
 permit src = user; dst = any:[user]; prt = tcp 84;
 permit src = user &! network:n1; dst = network:n1; prt = tcp 85;
}
service:s4 = {
 user = network:n1, network:n2, network:n3;
 permit src = user; dst = any:[user]; prt = tcp 86;
 permit src = network:n1; dst = user &! network:n1; prt = tcp 87;
}
service:s5 = {
 user = foreach interface:r1.n1, interface:r3.n3;
 permit src = any:[interface:[user].[all]];
        dst = any:[interface:[user].[all]];
        prt = tcp 179;
}
=END=
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "any:[network:n1]",
     "any:[network:n2]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 80"
    ],
    "src": []
   },
   {
    "action": "permit",
    "dst": [],
    "has_user": "dst",
    "prt": [
     "tcp 81"
    ],
    "src": [
     "any:[network:n1]",
     "any:[network:n2]"
    ]
   }
  ]
 },
 "s2": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "dst",
    "prt": [
     "tcp 82"
    ],
    "src": [
     "any:[network:n1]",
     "any:[network:n2]"
    ]
   },
   {
    "action": "permit",
    "dst": [
     "any:[network:n1]",
     "any:[network:n2]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 83"
    ],
    "src": []
   }
  ]
 },
 "s3(9S8D_GxA)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "any:[network:n1]",
     "any:[network:n2]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 84"
    ],
    "src": []
   }
  ]
 },
 "s3(POpjDd32)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n1"
    ],
    "has_user": "src",
    "prt": [
     "tcp 85"
    ],
    "src": []
   }
  ]
 },
 "s4(8QEgcJW-)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "any:[network:n1]",
     "any:[network:n2]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 86"
    ],
    "src": []
   }
  ]
 },
 "s4(avp-zO-c)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "dst",
    "prt": [
     "tcp 87"
    ],
    "src": [
     "network:n1"
    ]
   }
  ]
 },
 "s5(Lg5S4o3m)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "any:[network:n2]",
     "any:[network:n4]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 179"
    ],
    "src": []
   }
  ]
 },
 "s5(iIo0gt2o)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "any:[network:n1]",
     "any:[network:n2]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 179"
    ],
    "src": []
   }
  ]
 }
}
--owner/all/users
{
 "s1": [
  "network:n1",
  "network:n2",
  "network:n3"
 ],
 "s2": [
  "network:n1",
  "network:n2",
  "network:n3"
 ],
 "s3(9S8D_GxA)": [
  "network:n1",
  "network:n2",
  "network:n3"
 ],
 "s3(POpjDd32)": [
  "network:n2",
  "network:n3"
 ],
 "s4(8QEgcJW-)": [
  "network:n1",
  "network:n2",
  "network:n3"
 ],
 "s4(avp-zO-c)": [
  "network:n2",
  "network:n3"
 ],
 "s5(Lg5S4o3m)": [
  "any:[network:n2]",
  "any:[network:n4]"
 ],
 "s5(iIo0gt2o)": [
  "any:[network:n1]",
  "any:[network:n2]"
 ]
}
=END=

############################################################
=TITLE=Re-join split parts from auto interfaces
=INPUT=
area:all = { owner = all; anchor = network:n1;}
owner:all = { admins = a@b.c; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24;}
network:n4 = { ip = 10.1.4.0/24;}
router:r1 = {
 routing = manual;
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 routing = manual;
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
}
router:r4 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.4; hardware = n1; }
 interface:n4 = { ip = 10.1.4.4; hardware = n2;  }
}
pathrestriction:p1 = interface:r1.n1, interface:r1.n2;
pathrestriction:p2 = interface:r2.n1, interface:r2.n2;
pathrestriction:p3 = interface:r3.n1, interface:r3.n2;
service:s1 = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = user;
        dst = network:n3, network:n4;
        prt = tcp 49;
}
=END=
=OUTPUT=
--services
{
 "s1(CbJX20AY)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n4"
    ],
    "has_user": "src",
    "prt": [
     "tcp 49"
    ],
    "src": []
   }
  ]
 },
 "s1(se22rxX1)": {
  "details": {
   "owner": [
    "all"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n3"
    ],
    "has_user": "src",
    "prt": [
     "tcp 49"
    ],
    "src": []
   }
  ]
 }
}
--owner/all/users
{
 "s1(CbJX20AY)": [
  "interface:r1.n2",
  "interface:r2.n2"
 ],
 "s1(se22rxX1)": [
  "interface:r1.n1",
  "interface:r1.n2",
  "interface:r2.n1",
  "interface:r2.n2"
 ]
}
=END=

############################################################
=TITLE=Copy POLICY file
=INPUT=
-- POLICY
# p1234
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=END=
=OUTPUT=
--objects
{}
-- POLICY
# p1234
=END=

############################################################
=TITLE=Invalid option
=INPUT=NONE
=OPTIONS=--foo
=ERROR=
Error: unknown flag: --foo
=END=

############################################################
=TITLE=Mising output directory
=INPUT=network:n1 = { ip = 10.1.1.0/24; }
=VAR=usage
Usage: PROGRAM [options] netspoc-data out-directory
  -6, --ipv6    Expect IPv6 definitions
  -q, --quiet   Don't print progress messages
=END=
=ERROR=
${usage}
=END=

############################################################
=TITLE=Invalid argument
=INPUT=network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=
=PARAMS= a
=ERROR=
${usage}
=END=

############################################################
=TITLE=Many invalid arguments
=INPUT=network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=
=PARAMS= a b c
=ERROR=
${usage}
=END=

############################################################
=TITLE=Ignore max_errors
=INPUT=
-- config
max_errors = 1;
-- topology
any:n1 = { link = network:n1; }
any:n1a = { link = network:n1; }
any:n1b = { link = network:n1; }
any:n1c = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=true
=ERROR=
Error: Duplicate any:n1 and any:n1a in any:[network:n1]
Error: Duplicate any:n1a and any:n1b in any:[network:n1]
Error: Duplicate any:n1b and any:n1c in any:[network:n1]
=END=

############################################################
=TITLE=Preserve real NAT together with hidden NAT
# Must preserve nat:n2 when combined with hidden nat:n3
# in nat_set of owner:n23.
# But nat:n2a isn't preserved when combined with non hidden nat:n3a.
=INPUT=
owner:all = { admins = all@example.com; }
owner:n23 = { admins = n23@example.com; }
owner:n4  = { admins = n4@example.com; }
owner:h2  = { admins = h2@example.com; }
owner:h3  = { admins = h3@example.com; }
area:all = { anchor = network:n1; owner = all; }
network:n0 = {
 ip = 10.1.0.0/24;
 nat:n2a = { ip = 10.2.0.0/24; }
 nat:n3a = { ip = 10.3.0.0/24; }
}
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n2 = { ip = 10.2.1.0/24; }
 nat:n3 = { hidden; }
 nat:n4 = { ip = 10.4.1.0/24; }
}
network:n2 = { ip = 10.1.2.0/24; owner = n23; host:h2 = { ip = 10.1.2.2; owner = h2; } }
network:n3 = { ip = 10.1.3.0/24; owner = n23; host:h3 = { ip = 10.1.3.3; owner = h3; } }
network:n4 = { ip = 10.1.4.0/24; owner = n4;}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n2, n2a; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n3, n3a; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = n4; }
}
=END=
=OUTPUT=
--owner/all/nat_set
[]
--owner/n23/nat_set
[
 "n2"
]
--owner/n4/nat_set
[
 "n4"
]
--owner/h2/nat_set
[
 "n2",
 "n2a"
]
--owner/h3/nat_set
[
 "n3",
 "n3a"
]
=END=

############################################################
=TITLE=Remove hidden NAT tags in combined nat-set
=INPUT=
owner:all = { admins = all@example.com; }
area:all = { anchor = network:n1; owner = all; }
network:n1 = { ip = 10.1.1.0/24; nat:h1 = { hidden; } }
network:n2 = { ip = 10.1.2.0/24; nat:h2 = { hidden; } }
router:r1 = {
 routing = manual;
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = h2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = h1; }
}
=END=
=OUTPUT=
--owner/all/nat_set
[]
=END=

############################################################
=TITLE=Remove NAT tag used in two multi NAT sets
=INPUT=
owner:o = { admins = o@example.com; }
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n1 = { ip = 10.9.1.0/24; } nat:h1 = { hidden; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:n1 = { ip = 10.9.2.0/24; } nat:h2 = { hidden; }
}
network:n3 = { ip = 10.1.3.0/24; owner = o; } # n1 of [n1,h1], n1 of [n1,h2]
network:n4 = { ip = 10.1.4.0/24; owner = o; } # h1 of [n1,h1], h2 of [n1,h2]
network:n5 = { ip = 10.1.5.0/24; owner = o; } # {} of [n1,h1], h2 of [n1,h2]
# combined of [n1,h1] = {}, combined of [n1,h2] = n1
# must be combined to {}, not to n1
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = h1, h2; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; bind_nat = h2; }
}
=END=
=OUTPUT=
--owner/o/nat_set
[]
=END=

############################################################
=TITLE=Remove NAT tag used in two multi NAT sets (2)
=INPUT=
owner:o1 = { admins = a1@example.com; }
owner:o2 = { admins = a2@example.com; }
network:n1 = {
 ip = 10.1.1.0/24;
 nat:t1 = { ip = 10.9.1.0/24; }
 nat:h1 = { hidden; }
 owner = o1;
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:t1 = { ip = 10.9.2.0/24; }
 nat:h2 = { hidden; }
 owner = o2;
}
network:n3 = {
 ip = 10.1.3.0/24;
 owner = o1;
}
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = h2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = h1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = t1; }
}
=END=
=OUTPUT=
--owner/o1/nat_set
[]
--owner/o2/nat_set
[
 "h1"
]
=END=

############################################################
=TITLE=Ignore IPv6 in combined NAT for owner
=INPUT=
-- ipv4
owner:o = { admins = o@example.com; }
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; owner = o; }
router:r1  = {
 managed = secondary;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = n1; }
}
-- ipv6
network:n1_v6 = { ip = 1::/64; owner = o; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1_v6 = { ip = 1::1; hardware = n1; }
}
=END=
=OUTPUT=
--owner/o/nat_set
[
 "n1"
]
=END=

############################################################
=TITLE=Must not mark as is_supernet, if invisible identical subnet
=INPUT=
owner:all = { admins = all@example.com; }
area:all = { anchor = network:n1a; owner = all; }
network:n1a = {
 ip = 10.1.1.0/24;
 nat:hide_a = { hidden; }
}
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1a = { ip = 10.1.1.1; hardware = n1a; bind_nat = hide_b; }
 interface:n1b = { ip = 10.1.1.2; hardware = n1b; bind_nat = hide_a; }
}
network:n1b = {
 ip = 10.1.1.0/24;
 subnet_of = network:n1-super;
}
router:u = {
 interface:n1b;
 interface:n1-super;
}
network:n1-super = {
 ip = 10.1.0.0/16;
 nat:hide_b = { hidden; }
}
=END=
=OUTPUT=
--objects
{
 "interface:r1.n1a": {
  "ip": "10.1.1.1",
  "nat": {
   "hide_a": "hidden"
  }
 },
 "interface:r1.n1b": {
  "ip": "10.1.1.2",
  "nat": {
   "hide_b": "hidden"
  }
 },
 "interface:u.n1-super": {
  "ip": "short",
  "nat": {
   "hide_b": "hidden"
  },
  "owner": "all"
 },
 "interface:u.n1b": {
  "ip": "short",
  "nat": {
   "hide_b": "hidden"
  },
  "owner": "all"
 },
 "network:n1-super": {
  "ip": "10.1.0.0/255.255.0.0",
  "nat": {
   "hide_b": "hidden"
  },
  "owner": "all",
  "zone": "any:[network:n1b]"
 },
 "network:n1a": {
  "ip": "10.1.1.0/255.255.255.0",
  "nat": {
   "hide_a": "hidden"
  },
  "owner": "all",
  "zone": "any:[network:n1a]"
 },
 "network:n1b": {
  "ip": "10.1.1.0/255.255.255.0",
  "nat": {
   "hide_b": "hidden"
  },
  "owner": "all",
  "zone": "any:[network:n1b]"
 }
}
=END=

############################################################
