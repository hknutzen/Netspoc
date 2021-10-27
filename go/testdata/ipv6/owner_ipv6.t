
############################################################
=TITLE=Unused owners
=TEMPL=input
owner:o1 = { admins = o1@b.c; }
owner:o2 = { admins = o2@b.c; }
owner:a1 = { admins = a1@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o2; }
router:r1 = {
 interface:n1;
}
=END=
=PARAMS=--ipv6
=INPUT=[[input]]
=WARNING=
Warning: Unused owner:a1
Warning: Unused owner:o1
=END=

############################################################
=TITLE=Error on unused owners
=OPTIONS=--check_unused_owners=1
=PARAMS=--ipv6
=INPUT=[[input]]
=ERROR=
Error: Unused owner:a1
Error: Unused owner:o1
=END=

############################################################
=TITLE=No warning if owner is used at aggregate
=PARAMS=--ipv6
=INPUT=
owner:o = { admins = a@b.c; }
network:n1 = { ip = ::a01:100/120; }
any:n1 = { link = network:n1; owner = o; }
=END=
=WARNING=NONE

############################################################
=TITLE=Duplicates in admins/watchers
=PARAMS=--ipv6
=INPUT=
owner:x = {
 admins = a@b.c, b@b.c, a@b.c;
 watchers = b@b.c, c@b.c, b@b.c;
}
owner:y = {
 admins = a@b.c;
 watchers = b@b.c;
}
=END=
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
network:VLAN_40_41/40 = { ip = ::a02:160/124; }
router:asa = {
 managed;
 model = ASA;
 interface:VLAN_40_41/40 = { hardware = outside; }
 interface:VLAN_40_41/41 = { hardware = inside; }
 interface:VLAN_40_41 = { ip = ::a02:163; hardware = device; }
}
network:VLAN_40_41/41 = { ip = ::a02:160/124; {{.o}}}
service:test = {
 user = network:VLAN_40_41/40;
 permit src = user;
        dst = interface:asa.VLAN_40_41;
        prt = ip;
}
=END=
=PARAMS=--ipv6
=INPUT=[[input {o: ""}]]
=WARNING=NONE

############################################################
=TITLE=Redundant owner at bridged network
=PARAMS=--ipv6
=INPUT=[[input {o: "owner = xx;"}]]
=WARNING=
Warning: Useless owner:xx at network:VLAN_40_41/41,
 it was already inherited from area:all
=END=

############################################################
=TITLE=Redundant owner at nested areas
=PARAMS=--ipv6
=INPUT=
owner:x = {
 admins = a@b.c;
}
# a3 < a2 < all, a1 < all
area:all = { owner = x; anchor = network:n1; }
area:a1 = { owner = x; border = interface:asa1.n1; }
area:a2 = { owner = x; border = interface:asa1.n2; }
area:a3 = { owner = x; border = interface:asa2.n3; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
=END=
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
=PARAMS=--ipv6
=INPUT=
owner:x = { admins = x@a.b; }
owner:y = { admins = y@a.b; }
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
router:R = {
 interface:n2 = { ip = ::a01:202; owner = x; }
 interface:V = { ip = ::a03:303; vip; owner = y; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = interface:R.V, interface:R.n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: service:test has multiple owners:
 x, y
=END=

############################################################
=TITLE=Owner at interface of managed router
=PARAMS=--ipv6
=INPUT=
owner:y = { admins = y@a.b; }
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; owner = y; }
 interface:V = { ip = ::a03:303; loopback; hardware = lo1; owner = y; }
}
=END=
=WARNING=
Warning: Ignoring attribute 'owner' at managed interface:r1.n1
Warning: Ignoring attribute 'owner' at managed interface:r1.V
Warning: Unused owner:y
=END=

############################################################
=TITLE=vip interface at managed router
=PARAMS=--ipv6
=INPUT=
owner:y = { admins = y@a.b; }
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = e0; }
 interface:V  = { ip = ::a03:303; hardware = lo; vip; }
}
=END=
=ERROR=
Error: Must not use attribute 'vip' at interface:r1.V of managed router
=END=

############################################################
=TITLE=Owner with only watchers
=PARAMS=--ipv6
=INPUT=
owner:x = { watchers = x@a.b; }
owner:y = { watchers = y@a.b; }
area:all = { owner = x; anchor = network:n1; }
network:n1 = { owner = y; ip = ::a01:100/120; }
=END=
=ERROR=
Error: Missing attribute 'admins' in owner:y of network:n1
=END=

############################################################
=TITLE=Wildcard address not valid as admin
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = [all]@example.com; }
network:n1 = { ip = ::a01:100/120; owner = o1; }
=END=
=ERROR=
Error: Invalid email address (ASCII only) in admins of owner:o1: [all]@example.com
=END=

############################################################
=TITLE=Invalid email address
=PARAMS=--ipv6
=INPUT=
owner:o1 = { watchers = abc.example.com; }
=END=
=ERROR=
Error: Invalid email address (ASCII only) in watchers of owner:o1: abc.example.com
=END=

############################################################
=TITLE=Owner with attribute only_watch only usable at area
=PARAMS=--ipv6
=INPUT=
owner:x = { admins = a@a.b; watchers = x@a.b; only_watch; }
owner:y = { admins = b@a.b; watchers = y@a.b; only_watch; }
owner:z = { watchers = z@a.b; only_watch; }
any:a1 = { owner = x; link = network:n1; }
network:n1 = {
 owner = y; ip = ::a01:100/120;
 host:h1 = { owner = z; ip = ::a01:101; }
}
=END=
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
=PARAMS=--ipv6
=INPUT=
owner:a1 = { admins = a1@b.c; show_all; }
area:a1 = { owner = a1; border = interface:asa1.n1; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
=END=
=ERROR=
Error: owner:a1 has attribute 'show_all', but doesn't own whole topology.
 Missing:
 - network:n2
 - network:n3
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
network:n1 = { ip = ::a01:100/120;}
router:r = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = inside; }
 interface:n2 = { ip = f000::c0a8:102; hardware = outside; hub = crypto:vpn; }
}
network:n2 = { ip = f000::c0a8:100/124;}
router:dmz = {
 interface:n2 = { ip = f000::c0a8:101; }
 interface:Internet;
}
network:Internet = { ip = ::/0; has_subnets; }
router:VPN1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:Internet = { ip = ::101:101; spoke = crypto:vpn; hardware = Internet; }
 interface:v1 = { ip = ::a09:101; hardware = v1; }
}
network:v1 = { ip = ::a09:100/120; }
=PARAMS=--ipv6
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
=PARAMS=--ipv6
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
=PARAMS=--ipv6
=INPUT=
area:a1 = {
 border = interface:asa1.n1;
 owner = xx;
 router_attributes = { owner = xx; }
}
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=END=
=WARNING=
Warning: Ignoring undefined owner:xx of area:a1
Warning: Ignoring undefined owner:xx of router_attributes of area:a1
=END=

############################################################
=TITLE=Inherit owner from router_attributes of area
=PARAMS=--ipv6
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
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = ASA;
 owner = o1;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 owner = o2;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
=END=
=WARNING=
Warning: Useless owner:o1 at router:r1,
 it was already inherited from router_attributes of area:all
Warning: Useless owner:o2 at router:r2,
 it was already inherited from router_attributes of area:a2
=END=

############################################################
=TITLE=Owner mismatch of overlapping hosts
=PARAMS=--ipv6
=INPUT=
owner:a1 = { admins = a1@b.c; }
owner:a2 = { admins = a2@b.c; }
owner:a3 = { admins = a3@b.c; }
network:n1 = { ip = ::a01:100/120;
 host:h1 = { range = ::a01:107-::a01:10f; owner = a1; }
 host:h2 = { range = ::a01:107-::a01:110; owner = a2; }
 host:h3 = { ip = ::a01:107; owner = a3; }
 host:h4 = { ip = ::a01:110; owner = a3; }
 host:h5 = { range = ::a01:108-::a01:10b; owner = a3; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=END=
=WARNING=
Warning: Inconsistent owner definition for host:h1 and host:h2
Warning: Inconsistent owner definition for host:h1 and host:h2
Warning: Inconsistent owner definition for host:h1 and host:h3
Warning: Inconsistent owner definition for host:h2 and host:h4
Warning: Inconsistent owner definition for host:h1 and host:h5
=END=

############################################################
=TITLE=Useless sub_owner, multi_owner, unknown_owner
=PARAMS=--ipv6
=INPUT=
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; owner = o2; }
service:s1 = {
 unknown_owner;
 multi_owner;
 sub_owner = o2;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: Useless owner:o2 at service:s1
Warning: Useless use of attribute 'multi_owner' at service:s1
Warning: Useless use of attribute 'unknown_owner' at service:s1
=END=

############################################################
=TITLE=Unknown service owner
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; }
 host:h2 = { ip = ::a01:20b; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = host:h1; prt = tcp 81;
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
=END=
=WARNING=
Warning: Unknown owner for host:h1 in service:s1, service:s2
Warning: Unknown owner for host:h2 in service:s3
Warning: Unknown owner for network:n2 in service:s1, service:s2
=END=
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Restrict attribute 'unknown_owner'
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
any:n2 = { link = network:n2; unknown_owner = restrict; }
service:s1 = {
 unknown_owner;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: Must not use attribute 'unknown_owner' at service:s1
=END=
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Ignore unknown owners in zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
any:n2 = { link = network:n2; unknown_owner = ok; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Inherit owner
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
any:10_1-16 = { ip = ::a01:0/112; link = network:n1; owner = o1; }
network:n1 = {
 ip = ::a01:100/120;
 host:h5 = { ip = ::a01:105; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120; owner = o2;
 host:h10 = { ip = ::a01:20a; }
 host:h11 = { ip = ::a01:20b; owner = o3; }
}
service:s1 = {
 user = interface:asa1.n1;
 permit src = user; dst = host:h5, host:h10, host:h11; prt = tcp 80;
}
=END=
=WARNING=
Warning: service:s1 has multiple owners:
 o1, o2, o3
=END=

############################################################
=TITLE=Automatic owner at implicit aggregate
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o1; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
service:s1 = {
 user = interface:asa1.n1;
 permit src = any:[network:n1]; dst = user; prt = icmpv6 8;
}
=END=
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Automatic owner at implicit aggregate in zone cluster
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o1; }
network:n2 = { ip = ::a01:200/120; owner = o1; nat:n2 = { ip = ::a01:c00/120; } }
router:r1 = {
 interface:n1 = { bind_nat = n2; }
 interface:n2 = { ip = ::a01:201; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
service:s1 = {
 user = interface:r2.n2;
 permit src = any:[network:n1]; dst = user; prt = icmpv6 8;
}
=END=
=WARNING=NONE
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=No automatic owner at implicit aggregate in zone cluster
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o1; }
network:n2 = { ip = ::a01:200/120; owner = o2; nat:n2 = { ip = ::a01:c00/120; } }
router:r1 = {
 interface:n1 = { bind_nat = n2; }
 interface:n2 = { ip = ::a01:201; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
service:s1 = {
 user = interface:r2.n2;
 permit src = any:[network:n1]; dst = user; prt = icmpv6 8;
}
=END=
=WARNING=
Warning: Unknown owner for any:[network:n1] in service:s1
Warning: Unknown owner for any:[network:n1] in service:s1
=END=
=OPTIONS=--check_service_unknown_owner=warn

############################################################
=TITLE=Invalid attribute 'unknown_owner' at owner
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; unknown_owner = restrict; }
network:n1 = { ip = ::a01:100/120; owner = o1; }
=WARNING=
Warning: Ignoring attribute 'unknown_owner' in owner:o1
=END=

############################################################
=TITLE=Multiple service owners
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=END=
=WARNING=
Warning: service:s1 has multiple owners:
 o1, o2
=END=

############################################################
=TITLE=multi_owner with mixed coupling rules
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = user; prt = tcp 80;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
}
=END=
=WARNING=
Warning: service:s1 has multiple owners:
 o1, o2, o3
=END=

############################################################
=TITLE=Useless multi_owner when user objects have single owner
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
group:g1 = host:h1, host:h2;
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
 permit src = group:g1; dst = user; prt = tcp 82;
}
=END=
=WARNING=
Warning: Useless use of attribute 'multi_owner' at service:s1
 All 'user' objects belong to single owner:o3.
 Either swap objects of 'user' and objects of rules,
 or split service into multiple parts, one for each owner.
=END=

############################################################
=TITLE=multi_owner ok with empty user objects
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
group:g1 = ;
service:s1 = {
 multi_owner;
 user = group:g1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=END=
=WARNING=NONE

############################################################
=TITLE=multi_owner ok with multiple owners in user objects
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 owner = o1;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
service:s1 = {
 multi_owner;
 user = network:n1, interface:asa1.n2;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
}
=END=
=WARNING=NONE

############################################################
=TITLE=multi_owner ok with missing owner in user objects
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 owner = o1;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
}
=END=
=WARNING=NONE

############################################################
=TITLE=multi_owner with mixed coupling rules
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip = ::a01:100/120; owner = o3; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = user; dst = user; prt = tcp 80;
 permit src = host:h1, host:h2; dst = user; prt = tcp 81;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Restrict attribute 'multi_owner'
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
any:n2 = { link = network:n2; multi_owner = restrict; }
service:s1 = {
 multi_owner;
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=END=
=WARNING=
Warning: Must not use attribute 'multi_owner' at service:s1
=END=

############################################################
=TITLE=Ignore multiple owners in zone
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; }
owner:o2 = { admins = a2@b.c; }
network:n1 = { ip = ::a01:100/120; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
}
any:n2 = { link = network:n2; multi_owner = ok; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = host:h1, host:h2; prt = tcp 80;
}
=END=
=WARNING=NONE

############################################################
=TITLE=Ignore multiple owners with attribute from owner
=PARAMS=--ipv6
=INPUT=
owner:o1 = { admins = a1@b.c; multi_owner = ok; }
owner:o2 = { admins = a2@b.c; multi_owner = ok; }
owner:o3 = { admins = a3@b.c; }
network:n1 = { ip = ::a01:100/120; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}

network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; owner = o1; }
 host:h2 = { ip = ::a01:20b; owner = o2; }
 host:h3 = { ip = ::a01:20c; owner = o3; }
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
