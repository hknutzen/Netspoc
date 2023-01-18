=TEMPL=topo
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed = {{.a}};
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = NX-OS;
 managed = {{.b}};
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
=END=

############################################################
=TITLE=Crosslink primary and full
=PARAMS=--ipv6
=INPUT=[[topo {a: primary, b: full}]]
=OUTPUT=
-ipv6/r1
access-list cr_in extended permit ip any6 any6
access-group cr_in in interface cr
-ipv6/r2
interface cr
 ipv6 address ::a03:302/125
interface n2
 ipv6 address ::a02:201/123
 ipv6 traffic-filter n2_in in
=END=

############################################################
=TITLE=Crosslink standard and secondary
=PARAMS=--ipv6
=INPUT=[[topo {a: standard, b: secondary}]]
=OUTPUT=
-ipv6/r1
access-list cr_in extended deny ip any6 any6
access-group cr_in in interface cr
-ipv6/r2
interface cr
 ipv6 address ::a03:302/125
interface n2
 ipv6 address ::a02:201/123
 ipv6 traffic-filter n2_in in
=END=

############################################################
=TITLE=Crosslink secondary and local
=PARAMS=--ipv6
=INPUT=[[topo {a: secondary, b: "local; filter_only =  ::a02:0/111"}]]
=ERROR=
Error: Must not use 'managed=local' and 'managed=secondary' together
 at crosslink network:cr
=END=

############################################################
=TITLE=Crosslink and virtual IP
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; virtual = {ip = ::a03:303;} hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
=OUTPUT=
-ipv6/r1
access-list cr_in extended permit ip any6 any6
access-group cr_in in interface cr
-ipv6/r2
interface cr
 ipv6 address ::a03:302/125
interface n2
 ipv6 address ::a02:201/123
 ipv6 traffic-filter n2_in in
=END=

############################################################
=TITLE=Crosslink standard, local, local
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed = standard;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = NX-OS;
 managed = local;
 filter_only =  ::a02:0/111;
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
router:r3 = {
 model = IOS;
 managed = local;
 filter_only =  ::a02:0/111;
 interface:cr = { ip = ::a03:303; hardware = cr; }
 interface:n3 = { ip = ::a02:221; hardware = n3; }
}
network:n3 = { ip = ::a02:220/123; }
=OUTPUT=
-ipv6/r1
access-list cr_in extended deny ip any6 any6
access-group cr_in in interface cr
-ipv6/r2
interface cr
 ipv6 address ::a03:302/125
interface n2
 ipv6 address ::a02:201/123
 ipv6 traffic-filter n2_in in
-ipv6/r3
interface cr
 ipv6 address ::a03:303/125
interface n3
 ipv6 address ::a02:221/123
 ipv6 traffic-filter n3_in in
=END=

############################################################
=TITLE=Crosslink network must not have hosts
=PARAMS=--ipv6
=INPUT=
network:cr = {
 ip = ::a03:300/125;
 crosslink;
 host:h = { ip = ::a03:303; }
}
=ERROR=
Error: Crosslink network:cr must not have host definitions
=END=

############################################################
=TITLE=Interface of crosslink network must use hardware only once
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed = standard;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; hardware = n1; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
=ERROR=
Error: Crosslink network:cr must be the only network connected to hardware 'n1' of router:r1
=END=

############################################################
=TITLE=Crosslink network must not have unmanaged interface
=PARAMS=--ipv6
=INPUT=
network:cr = { ip = ::a03:300/125; crosslink; }
router:r = { interface:cr; }
=ERROR=
Error: Crosslink network:cr must not be connected to unmanged router:r
=END=

############################################################
=TITLE=Different no_in_acl at crosslink routers
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; no_in_acl; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
=ERROR=
Error: All interfaces must equally use or not use outgoing ACLs at crosslink network:cr
=END=

############################################################
=TITLE=no_in_acl outside of crosslink routers
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; no_in_acl; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n2 = { ip = ::a02:201; hardware = n2; no_in_acl; }
}
network:n2 = { ip = ::a02:200/123; }
=ERROR=
Error: All interfaces with attribute 'no_in_acl' at routers connected by
 crosslink network:cr must be border of the same security zone
=END=

############################################################
=TITLE=no_in_acl at crosslink routers at same zone
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; no_in_acl; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n1 = { ip = ::a01:102; hardware = n1; no_in_acl; }
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 host ::a03:302
access-list n1_in extended deny ip any6 host ::a01:102
access-list n1_in extended permit ip any6 any6
access-group n1_in in interface n1
-ipv6/r2
interface cr
 ipv6 address ::a03:302/125
interface n1
 ipv6 address ::a01:102/123
 ipv6 traffic-filter n1_in in
=END=

############################################################
=TITLE=no_in_acl at crosslink interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; hardware = cr; no_in_acl; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; no_in_acl; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 host ::a02:201
access-list n1_in extended permit tcp ::a01:100/123 ::a02:200/123 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n1_out
access-list n1_out extended deny ip any6 any6
access-group n1_out out interface n1
-- ipv6/r2
ipv6 access-list n2_in
 10 permit tcp ::a02:200/123 ::a01:100/123 established
 20 deny ip any any
--
ipv6 access-list n2_out
 10 permit tcp ::a01:100/123 ::a02:200/123 eq 80
 20 deny ip any any
--
interface cr
 ipv6 address ::a03:302/125
interface n2
 ipv6 address ::a02:201/123
 ipv6 traffic-filter n2_in in
 ipv6 traffic-filter n2_out out
=END=

############################################################
=TITLE=crosslink between Linux routers
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = Linux;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = Linux;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
:n1_self -
-A INPUT -j n1_self -i n1
--
:n1_cr -
-A n1_cr -j ACCEPT -s ::a01:100/123 -d ::a02:200/123 -p tcp --dport 80
-A FORWARD -j n1_cr -i n1 -o cr
--
:cr_self -
-A cr_self -j ACCEPT
-A INPUT -j cr_self -i cr
--
:cr_n1 -
-A cr_n1 -j ACCEPT
-A FORWARD -j cr_n1 -i cr -o n1
-- ipv6/r2
:cr_self -
-A cr_self -j ACCEPT
-A INPUT -j cr_self -i cr
--
:cr_n2 -
-A cr_n2 -j ACCEPT
-A FORWARD -j cr_n2 -i cr -o n2
--
:n2_self -
-A INPUT -j n2_self -i n2
=END=

############################################################
=TITLE=Must not use crosslink network in rule
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; crosslink; }
router:r = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; crosslink; }
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=WARNING=
Warning: Ignoring crosslink network:n1 in src of rule in service:test
Warning: Ignoring crosslink network:n2 in dst of rule in service:test
=END=

############################################################
=TITLE=Ignore from automatic group
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = ASA;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; no_in_acl; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
area:n1-cr = {
 border = interface:r2.cr;
}
service:s1 = {
 user = network:[area:n1-cr];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-ipv6/r2
! n2_out
access-list n2_out extended permit tcp ::a01:100/123 ::a02:200/123 eq 80
access-list n2_out extended deny ip any6 any6
access-group n2_out out interface n2
=END=

############################################################
=TITLE=Use intermediately in automatic group
=PARAMS=--ipv6
=INPUT=
area:n1-cr = { border = interface:r2.cr; }
network:n1 = { ip = ::a01:100/123; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:cr = { ip = ::a03:301; hardware = cr; }
}
network:cr = { ip = ::a03:300/125; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = ::a03:302; hardware = cr; }
 interface:n2 = { ip = ::a02:201; hardware = n2; }
}
network:n2 = { ip = ::a02:200/123; }
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:[network:[area:n1-cr] &! network:n1].[all];
        prt = tcp 22;
}
=OUTPUT=
-ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/123 host ::a03:301 eq 22
 permit tcp ::a01:100/123 host ::a03:302 eq 22
 deny ipv6 any any
=END=

############################################################
