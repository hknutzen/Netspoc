
############################################################
=TITLE=Unused owners
=TEMPL=input
owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2@b.c; }
owner:a1 = { admins = a1@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o2; }
router:r1 = {
 interface:n1;
}
=INPUT=[[input]]
=WARNING=
Warning: Unused owner:a1
Warning: Unused owner:o1
=END=

############################################################
=TITLE=Error on unused owners
=OPTIONS=--check_unused_owners=1
=INPUT=[[input]]
=ERROR=
Error: Unused owner:a1
Error: Unused owner:o1
=END=

############################################################
=TITLE=No warning if owner is used at aggregate
=INPUT=
owner:o = { admins = a@b.c; }
network:n1 = { ip6 = ::a01:100/120; }
any:n1 = { link = network:n1; owner = o; }
=WARNING=NONE

############################################################
=TITLE=Duplicates in admins/watchers
=INPUT=
owner:x = {
 admins = a@b.c, b@b.c, a@b.c;
 watchers = b@b.c, c@b.c, b@b.c;
}
owner:y = {
 admins = a@b.c;
 watchers = b@b.c;
}
=ERROR=
Error: Duplicates in admins of owner:x: a@b.c
Error: Duplicates in watchers of owner:x: b@b.c
Error: Duplicates in admins/watchers of owner:x: b@b.c
=END=

############################################################
=TITLE=Owner at bridged network
=TEMPL=input
owner:xx = {
 admins = a@b.c;
}
area:all = { owner = xx; anchor = network:VLAN_40_41/40; }
network:VLAN_40_41/40 = { ip6 = ::a02:160/124; }
router:asa = {
 managed;
 model = ASA;
 interface:VLAN_40_41/40 = { hardware = outside; }
 interface:VLAN_40_41/41 = { hardware = inside; }
 interface:VLAN_40_41 = { ip6 = ::a02:163; hardware = device; }
}
network:VLAN_40_41/41 = { ip6 = ::a02:160/124; {{.}}}
service:test = {
 user = network:VLAN_40_41/40;
 permit src = user;
        dst = interface:asa.VLAN_40_41;
        prt = ip;
}
=INPUT=[[input ""]]
=WARNING=NONE

############################################################
=TITLE=Redundant owner at bridged network
=INPUT=[[input "owner = xx;"]]
=WARNING=
Warning: Useless owner:xx at network:VLAN_40_41/41,
 it was already inherited from area:all
=END=

############################################################
=TITLE=Redundant owner at nested areas
=INPUT=
owner:x = {
 admins = a@b.c;
}
# a3 < a2 < all, a1 < all
area:all = { owner = x; anchor = network:n1; }
area:a1 = { owner = x; border = interface:asa1.n1; }
area:a2 = { owner = x; border = interface:asa1.n2; }
area:a3 = { owner = x; border = interface:asa2.n3; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
=WARNING=
Warning: Useless owner:x at area:a1,
 it was already inherited from area:all
Warning: Useless owner:x at area:a2,
 it was already inherited from area:all
Warning: Useless owner:x at area:a3,
 it was already inherited from area:a2
=END=

############################################################
=TITLE=Owner at vip interface
=INPUT=
owner:x = { admins = x@a.b; }
owner:y = { admins = y@a.b; }
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:R = {
 interface:n2 = { ip6 = ::a01:202; owner = x; }
 interface:V = { ip6 = ::a03:303; vip; owner = y; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = interface:R.V, interface:R.n2; prt = tcp 80;
}
=WARNING=
Warning: service:test has multiple owners:
 x, y
=END=

############################################################
=TITLE=Owner at interface of managed router
=INPUT=
owner:y = { admins = y@a.b; }
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; owner = y; }
 interface:V = { ip6 = ::a03:303; loopback; hardware = lo1; owner = y; }
}
=WARNING=
Warning: Ignoring attribute 'owner' at managed interface:r1.n1
Warning: Ignoring attribute 'owner' at managed interface:r1.V
=END=

############################################################
=TITLE=vip interface at managed router
=INPUT=
owner:y = { admins = y@a.b; }
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = e0; }
 interface:V  = { ip6 = ::a03:303; hardware = lo; vip; }
}
=ERROR=
Error: Must not use attribute 'vip' at interface:r1.V of managed router
=END=

############################################################
=TITLE=Inherit owner from router to interface and secondary interface
=INPUT=
owner:y = { admins = y@a.b; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 owner = y;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = {
  ip6 = ::a01:201, ::a01:202;
  secondary:other = { ip6 = ::a01:263; }
  hardware = n2;
 }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.n2.2, interface:r1.n2.other; prt = icmpv6;
}
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Owner at router with managed = routing_only
=INPUT=
owner:y = { admins = y@a.b; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 owner = y;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed = routing_only;
 model = IOS;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; owner = y; }
}
router:r3 = {
 managed = routing_only;
 model = IOS;
 owner = y;
 interface:n2 = { ip6 = ::a01:203; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r2.n2, interface:r3.n2; prt = icmpv6;
}
=WARNING=
Warning: Ignoring attribute 'owner' at managed interface:r2.n2
Warning: Unknown owner for interface:r2.n2 in service:s1
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Owner with only watchers
=INPUT=
owner:x = { watchers = x@a.b; }
owner:y = { watchers = y@a.b; }
area:all = { owner = x; anchor = network:n1; }
network:n1 = { owner = y; ip6 = ::a01:100/120; }
=ERROR=
Error: Missing attribute 'admins' in owner:y of network:n1
=END=

############################################################
=TITLE=Wildcard address not valid as admin
=INPUT=
owner:o1 = { admins = [all]@example.com; }
network:n1 = { ip6 = ::a01:100/120; owner = o1; }
=ERROR=
Error: Invalid email address (ASCII only) in admins of owner:o1: [all]@example.com
=END=

############################################################
=TITLE=Invalid email address
=INPUT=
owner:o1 = { watchers = abc.example.com; }
=ERROR=
Error: Invalid email address (ASCII only) in watchers of owner:o1: abc.example.com
=END=

############################################################
=TITLE=Wildcard address with invalid domain
=INPUT=
owner:o1 = { admins = abc@example.com; watchers = [all]@...; }
network:n1 = { ip6 = ::a01:100/120; owner = o1; }
=ERROR=
Error: Invalid email address (ASCII only) in watchers of owner:o1: [all]@...
=END=

############################################################
=TITLE=Owner with attribute only_watch only usable at area
=INPUT=
owner:x = { admins = a@a.b; watchers = x@a.b; only_watch; }
owner:y = { admins = b@a.b; watchers = y@a.b; only_watch; }
owner:z = { watchers = z@a.b; only_watch; }
any:a1 = { owner = x; link = network:n1; }
network:n1 = {
 owner = y; ip6 = ::a01:100/120;
 host:h1 = { owner = z; ip6 = ::a01:101; }
}
=ERROR=
Error: owner:y with attribute 'only_watch' must only be used at area,
 not at network:n1
Error: Missing attribute 'admins' in owner:z of host:h1
Error: owner:z with attribute 'only_watch' must only be used at area,
 not at host:h1
Error: owner:x with attribute 'only_watch' must only be used at area,
 not at any:a1
=END=

############################################################
=TITLE=Missing part in owner with attribute "show_all"
=INPUT=
owner:a1 = { admins = a1@b.c; show_all; }
area:a1 = { owner = a1; border = interface:asa1.n1; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; owner = a1; }
network:n4 = { ip6 = ::a01:400/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
=ERROR=
Error: owner:a1 has attribute 'show_all', but doesn't own whole topology.
 Missing:
 - network:n2
 - network:n4
=END=

############################################################
=TITLE=Owner with "show_all" must also own VPN transfer area
=TEMPL=input
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
network:n1 = { ip6 = ::a01:100/120;}
router:r = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = inside; }
 interface:n2 = { ip6 = f000::c0a8:102; hardware = outside; hub = crypto:vpn; }
}
network:n2 = { ip6 = f000::c0a8:100/124;}
router:dmz = {
 interface:n2 = { ip6 = f000::c0a8:101; }
 interface:Internet;
}
network:Internet = { ip6 = ::/0; has_subnets; }
router:VPN1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:Internet = { ip6 = ::101:101; spoke = crypto:vpn; hardware = Internet; }
 interface:v1 = { ip6 = ::a09:101; hardware = v1; }
}
network:v1 = { ip6 = ::a09:100/120; }
=INPUT=
[[input]]
owner:all = { admins = a@example.com; show_all; }
area:all = { anchor = network:n1; owner = all; }
=ERROR=
Error: owner:all has attribute 'show_all', but doesn't own whole topology.
 Missing:
 - network:Internet
 - network:n2
=END=

############################################################
=TITLE=Owner with "show_all" must not only own VPN transfer area
=INPUT=
[[input]]
owner:all = { admins = a@example.com; show_all; }
area:all = { anchor = network:Internet; owner = all; }
=ERROR=
Error: owner:all has attribute 'show_all', but doesn't own whole topology.
 Missing:
 - network:v1
 - network:n1
=END=

############################################################
=TITLE=Invalid owner in area and router_attributes of area
=INPUT=
area:a1 = {
 border = interface:asa1.n1;
 owner = xx;
 router_attributes = { owner = xx; }
}
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
=WARNING=
Warning: Ignoring undefined owner:xx of area:a1
Warning: Ignoring undefined owner:xx of router_attributes of area:a1
=END=

############################################################
=TITLE=Inherit owner from router_attributes of area
=INPUT=
area:all = {
 anchor = network:n1;
 router_attributes = { owner = o1; }
}
area:a2 = {
 border = interface:r1.n2;
 router_attributes = { owner = o2; }
}
owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2@b.c; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 owner = o1;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 owner = o2;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
}
=WARNING=
Warning: Useless 'owner' at router:r2,
 it was already inherited from router_attributes of area:a2
Warning: Useless 'owner' at router:r1,
 it was already inherited from router_attributes of area:all
=END=

############################################################
=TITLE=Useless inheritance from nested areas
=INPUT=
owner:o = { admins = a@example.com; }
area:a1234 = {
 anchor = network:n4;
 owner = o;
}
area:a123 = {
 inclusive_border = interface:r1.n4;
}
area:a12 = {
 inclusive_border = interface:r1.n3, interface:r1.n4;
 owner = o;
}
area:a1  = {
 border = interface:r1.n1;
 owner = o;
}
area:a2  = {
 border = interface:r1.n2;
 owner = o;
}
area:a3  = {
 border = interface:r1.n3;
 owner = o;
}
any:n1 = { link = network:n1; owner = o; }
network:n1 = { ip6 = ::a01:100/120; owner = o; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120; owner = o; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
=WARNING=
Warning: Useless owner:o at any:n1,
 it was already inherited from area:a1
Warning: Useless owner:o at area:a1,
 it was already inherited from area:a12
Warning: Useless owner:o at area:a12,
 it was already inherited from area:a1234
Warning: Useless owner:o at area:a2,
 it was already inherited from area:a12
Warning: Useless owner:o at area:a3,
 it was already inherited from area:a1234
Warning: Useless owner:o at network:n1,
 it was already inherited from any:n1
Warning: Useless owner:o at network:n4,
 it was already inherited from area:a1234
=END=

############################################################
=TITLE=Owner mismatch of overlapping hosts
=INPUT=
owner:a1 = { admins = a1@b.c; }
owner:a2 = { admins = a2@b.c; }
owner:a3 = { admins = a3@b.c; }
network:n1 = { ip6 = ::a01:100/120;
 host:h1 = { range6 = ::a01:107-::a01:10f; owner = a1; }
 host:h2 = { range6 = ::a01:107-::a01:110; owner = a2; }
 host:h3 = { ip6 = ::a01:107; owner = a3; }
 host:h4 = { ip6 = ::a01:110; owner = a3; }
 host:h5 = { range6 = ::a01:108-::a01:10b; owner = a3; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
=WARNING=
Warning: Inconsistent owner definition for host:h1 and host:h2
Warning: Inconsistent owner definition for host:h1 and host:h2
Warning: Inconsistent owner definition for host:h1 and host:h3
Warning: Inconsistent owner definition for host:h2 and host:h4
Warning: Inconsistent owner definition for host:h1 and host:h5
=END=

############################################################
=TITLE=Useless multi_owner, unknown_owner
=INPUT=
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; owner = o2; }
service:s1 = {
 unknown_owner;
 multi_owner;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Useless 'multi_owner' at service:s1
Warning: Useless 'unknown_owner' at service:s1
=END=

############################################################
=TITLE=Unknown service owner
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; }
 host:h2 = { ip6 = ::a01:20b; }
}
protocol:print = tcp 514, reversed;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80, protocol:print;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 82;
 permit src = user; dst = host:h1; prt = tcp 83;
}
service:s3 = {
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp 83;
}
=WARNING=
Warning: Unknown owner for host:h1 in service:s2
Warning: Unknown owner for host:h2 in service:s3
Warning: Unknown owner for network:n2 in service:s1, service:s2
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Unknown owner in simple coupling rule
=INPUT=
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
service:s1 = {
 user = network:n1, host:h1, host:h2;
 permit src = user; dst = user; prt = tcp 80;
}
=WARNING=
Warning: Unknown owner for host:h1 in service:s1
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Restrict attribute 'unknown_owner'
=INPUT=
owner:o2 = { admins = a2@example.com; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; owner = o2; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
area:a23 = { inclusive_border = interface:r1.n1; unknown_owner = restrict; }
service:s1 = {
 unknown_owner;
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=WARNING=
Warning: Attribute 'unknown_owner' is blocked at service:s1
Warning: Unknown owner for network:n3 in service:s1
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Ignore useless 'unknown_owner = restrict'
=INPUT=
owner:o2 = { admins = a2@example.com; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; owner = o2; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
any:a2 = { link = network:n2; unknown_owner = restrict; }
service:s1 = {
 unknown_owner;
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Ignore unknown owners in zone
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
any:n2 = { link = network:n2; unknown_owner = ok; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Inherit owner
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
any:10_1-16 = { ip6 = ::a01:0/112; link = network:n1; owner = o1; }
network:n1 = {
 ip6 = ::a01:100/120;
 host:h5 = { ip6 = ::a01:105; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120; owner = o2;
 host:h10 = { ip6 = ::a01:20a; }
 host:h11 = { ip6 = ::a01:20b; owner = o3; }
}
service:s1 = {
 user = interface:asa1.n1;
 permit src = user; dst = host:h5, host:h10, host:h11; prt = tcp 80;
}
=WARNING=
Warning: service:s1 has multiple owners:
 o1, o2, o3
=END=

############################################################
=TITLE=Automatic owner at implicit aggregate
=INPUT=
owner:o1 = { admins = a1@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o1; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
service:s1 = {
 user = interface:asa1.n1;
 permit src = any:[network:n1]; dst = user; prt = icmpv6 8;
}
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Automatic owner at implicit aggregate in zone cluster
=TODO= No IPv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o1; }
network:n2 = { ip6 = ::a01:200/120; owner = o1; nat:n2 = { ip6 = ::a01:c00/120; } }
router:r1 = {
 interface:n1 = { nat_out = n2; }
 interface:n2 = { ip6 = ::a01:201; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
service:s1 = {
 user = interface:r2.n2;
 permit src = any:[network:n1]; dst = user; prt = icmpv6 8;
}
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=No automatic owner at implicit aggregate in zone cluster
=TODO= No IPv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o1; }
network:n2 = { ip6 = ::a01:200/120; owner = o2; nat:n2 = { ip6 = ::a01:c00/120; } }
router:r1 = {
 interface:n1 = { nat_out = n2; }
 interface:n2 = { ip6 = ::a01:201; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:202; hardware = n2; }
}
service:s1 = {
 user = interface:r2.n2;
 permit src = any:[network:n1]; dst = user; prt = icmpv6 8;
}
=WARNING=
Warning: Unknown owner for any:[network:n1] in service:s1
Warning: Unknown owner for any:[network:n1] in service:s1
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Invalid attribute 'unknown_owner' at owner
=INPUT=
owner:o1 = { admins = a1@b.c; unknown_owner = restrict; }
network:n1 = { ip6 = ::a01:100/120; owner = o1; }
=WARNING=
Warning: Ignoring attribute 'unknown_owner' in owner:o1
=END=

############################################################
=TITLE=Multiple service owners
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=WARNING=
Warning: service:s1 has multiple owners:
 o1, o2
=END=

############################################################
=TITLE=Multiple service owners can be avoided
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=WARNING=
Warning: service:s1 has multiple owners:
 o1, o2
 This should be avoided.
 All 'user' objects belong to single owner:o3.
 Either swap objects of 'user' and objects of rules,
 or split service into multiple parts, one for each owner.
=END=

############################################################
=TITLE=Must not swap user and rules, if rules have different objects.
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
 permit src = user; dst = host:h1; prt = tcp 81;
}
=WARNING=
Warning: service:s1 has multiple owners:
 o1, o2
=END=

############################################################
=TITLE=Useless multi_owner when expanded user objects have single owner
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = {
 ip6 = ::a01:100/120;
 owner = o3;
 host:h11 = { ip6 = ::a01:10a; owner = o1; }
 host:h12 = { ip6 = ::a01:10b; owner = o2; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h21 = { ip6 = ::a01:20a; owner = o1; }
 host:h22 = { ip6 = ::a01:20b; owner = o2; }
}
group:g1 = host:h11, host:h12;
service:s1 = {
 multi_owner;
 user = group:g1;
 permit src = network:[user]; dst = host:h21, host:h22; prt = tcp 80;
 permit src = host:h21, host:h22; dst = network:[user]; prt = tcp 81;
}
=WARNING=
Warning: Unnecessary 'multi_owner' at service:s1
 All 'user' objects belong to single owner:o3.
 Either swap objects of 'user' and objects of rules,
 or split service into multiple parts, one for each owner.
=END=

############################################################
=TITLE=Useless multi_owner when user objects have single owner
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
group:g1 = host:h1, host:h2;
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
 permit src = group:g1; dst = user; prt = tcp 82;
}
=WARNING=
Warning: Unnecessary 'multi_owner' at service:s1
 All 'user' objects belong to single owner:o3.
 Either swap objects of 'user' and objects of rules,
 or split service into multiple parts, one for each owner.
=END=

############################################################
=TITLE=Need multi_owner even though user seems to have single owner
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = {
 ip6 = ::a01:100/120;
 owner = o3;
 host:h11 = { ip6 = ::a01:10a; owner = o1; }
 host:h12 = { ip6 = ::a01:10b; owner = o2; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h21 = { ip6 = ::a01:20a; owner = o1; }
 host:h22 = { ip6 = ::a01:20b; owner = o2; }
}
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = host:[user]; dst = host:h21, host:h22; prt = tcp 80;
 permit src = host:h21, host:h22; dst = user; prt = tcp 81;
}
# No Warning: Unnecessary 'multi_owner' at service:s1
=WARNING=NONE

############################################################
=TITLE=multi_owner ok with empty user objects
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
group:g1 = ;
service:s1 = {
 multi_owner;
 user = group:g1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=multi_owner ok with multiple owners in user objects
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip6 = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 owner = o1;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
service:s1 = {
 multi_owner;
 user = network:n1, interface:asa1.n2;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
}
=WARNING=NONE

############################################################
=TITLE=multi_owner ok with missing owner in user objects
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 owner = o1;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
}
=WARNING=NONE

############################################################
=TITLE=Restrict attribute 'multi_owner'
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
any:n2 = { link = network:n2; multi_owner = restrict; }
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=WARNING=
Warning: Attribute 'multi_owner' is blocked at service:s1
Warning: service:s1 has multiple owners:
 o1, o2
=END=

############################################################
=TITLE=Ignore multiple owners in zone
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip6 = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
}
any:n2 = { link = network:n2; multi_owner = ok; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=WARNING=NONE

############################################################
=TITLE=Ignore multiple owners with attribute from owner
=INPUT=
owner:o1 = { admins = a1@b.c; multi_owner = ok; }
owner:o2 = { admins = a2@b.c; multi_owner = ok; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip6 = ::a01:100/120; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}

network:n2 = {
 ip6 = ::a01:200/120;
 host:h1 = { ip6 = ::a01:20a; owner = o1; }
 host:h2 = { ip6 = ::a01:20b; owner = o2; }
 host:h3 = { ip6 = ::a01:20c; owner = o3; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h3; prt = tcp 81;
}
=WARNING=
Warning: service:s2 has multiple owners:
 o1, o3
=END=

############################################################
