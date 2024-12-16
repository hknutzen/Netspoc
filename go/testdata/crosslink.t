=TEMPL=topo
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed = {{.a}};
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed = {{.b}};
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
=END=

############################################################
=TITLE=Crosslink primary and full
=INPUT=[[topo {a: primary, b: full}]]
=OUTPUT=
-r1
access-list cr_in extended permit ip any4 any4
access-group cr_in in interface cr
-r2
interface cr
 ip address 10.3.3.2 255.255.255.248
interface n2
 ip address 10.2.2.1 255.255.255.224
 ip access-group n2_in in
=END=

############################################################
=TITLE=Crosslink standard and secondary
=INPUT=[[topo {a: standard, b: secondary}]]
=OUTPUT=
-r1
access-list cr_in extended deny ip any4 any4
access-group cr_in in interface cr
-r2
interface cr
 ip address 10.3.3.2 255.255.255.248
interface n2
 ip address 10.2.2.1 255.255.255.224
 ip access-group n2_in in
=END=

############################################################
=TITLE=Crosslink secondary and local
=INPUT=[[topo {a: secondary, b: "local; filter_only =  10.2.0.0/15"}]]
=ERROR=
Error: Must not use 'managed=local' and 'managed=secondary' together
 at crosslink network:cr
=END=

############################################################
=TITLE=Crosslink and virtual IP
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; virtual = {ip = 10.3.3.3;} hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
=OUTPUT=
-r1
access-list cr_in extended permit ip any4 any4
access-group cr_in in interface cr
-r2
interface cr
 ip address 10.3.3.2 255.255.255.248
interface n2
 ip address 10.2.2.1 255.255.255.224
 ip access-group n2_in in
=END=

############################################################
=TITLE=Crosslink standard, local, local
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed = standard;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed = local;
 filter_only =  10.2.0.0/15;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
router:r3 = {
 model = IOS;
 managed = local;
 filter_only =  10.2.0.0/15;
 interface:cr = { ip = 10.3.3.3; hardware = cr; }
 interface:n3 = { ip = 10.2.2.33; hardware = n3; }
}
network:n3 = { ip = 10.2.2.32/27; }
=OUTPUT=
-r1
access-list cr_in extended deny ip any4 any4
access-group cr_in in interface cr
-r2
interface cr
 ip address 10.3.3.2 255.255.255.248
interface n2
 ip address 10.2.2.1 255.255.255.224
 ip access-group n2_in in
-r3
interface cr
 ip address 10.3.3.3 255.255.255.248
interface n3
 ip address 10.2.2.33 255.255.255.224
 ip access-group n3_in in
=END=

############################################################
=TITLE=Crosslink network must not have hosts
=INPUT=
network:cr = {
 ip = 10.3.3.0/29;
 crosslink;
 host:h = { ip = 10.3.3.3; }
}
=ERROR=
Error: Crosslink network:cr must not have host definitions
=END=

############################################################
=TITLE=Interface of crosslink network must use hardware only once
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed = standard;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = n1; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
=ERROR=
Error: Crosslink network:cr must be the only network connected to hardware 'n1' of router:r1
=END=

############################################################
=TITLE=Crosslink network must not have unmanaged interface
=INPUT=
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r = { interface:cr; }
=ERROR=
Error: Crosslink network:cr must not be connected to unmanged router:r
=END=

############################################################
=TITLE=Different no_in_acl at crosslink routers
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
=ERROR=
Error: All interfaces must equally use or not use outgoing ACLs at crosslink network:cr
=END=

############################################################
=TITLE=no_in_acl outside of crosslink routers
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; no_in_acl; }
}
network:n2 = { ip = 10.2.2.0/27; }
=ERROR=
Error: All interfaces with attribute 'no_in_acl' at routers connected by
 crosslink network:cr must be border of the same security zone
=END=

############################################################
=TITLE=no_in_acl at crosslink routers at same zone
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; no_in_acl; }
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended deny ip any4 host 10.3.3.2
access-list n1_in extended deny ip any4 host 10.1.1.2
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
-r2
interface cr
 ip address 10.3.3.2 255.255.255.248
interface n1
 ip address 10.1.1.2 255.255.255.224
 ip access-group n1_in in
=END=

############################################################
=TITLE=no_in_acl at crosslink interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; no_in_acl; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; no_in_acl; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended deny ip any4 host 10.2.2.1
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.224 10.2.2.0 255.255.255.224 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n1_out
access-list n1_out extended deny ip any4 any4
access-group n1_out out interface n1
-- r2
ip access-list extended n2_in
 permit tcp 10.2.2.0 0.0.0.31 10.1.1.0 0.0.0.31 established
 deny ip any any
--
ip access-list extended n2_out
 permit tcp 10.1.1.0 0.0.0.31 10.2.2.0 0.0.0.31 eq 80
 deny ip any any
--
interface cr
 ip address 10.3.3.2 255.255.255.248
interface n2
 ip address 10.2.2.1 255.255.255.224
 ip access-group n2_in in
 ip access-group n2_out out
=END=

############################################################
=TITLE=crosslink between Linux routers
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = Linux;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = Linux;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- r1
:n1_self -
-A INPUT -j n1_self -i n1
--
:n1_cr -
-A n1_cr -j ACCEPT -s 10.1.1.0/27 -d 10.2.2.0/27 -p tcp --dport 80
-A FORWARD -j n1_cr -i n1 -o cr
--
:cr_self -
-A cr_self -j ACCEPT
-A INPUT -j cr_self -i cr
--
:cr_n1 -
-A cr_n1 -j ACCEPT
-A FORWARD -j cr_n1 -i cr -o n1
-- r2
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; crosslink; }
router:r = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; crosslink; }
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
=INPUT=
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = ASA;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; no_in_acl; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
area:n1-cr = {
 border = interface:r2.cr;
}
service:s1 = {
 user = network:[area:n1-cr];
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-r2
! n2_out
access-list n2_out extended permit tcp 10.1.1.0 255.255.255.224 10.2.2.0 255.255.255.224 eq 80
access-list n2_out extended deny ip any4 any4
access-group n2_out out interface n2
=END=

############################################################
=TITLE=Use intermediately in automatic group
=INPUT=
area:n1-cr = { border = interface:r2.cr; }
network:n1 = { ip = 10.1.1.0/27; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
network:n2 = { ip = 10.2.2.0/27; }
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:[network:[area:n1-cr] &! network:n1].[all];
        prt = tcp 22;
}
=OUTPUT=
-r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.31 host 10.3.3.1 eq 22
 permit tcp 10.1.1.0 0.0.0.31 host 10.3.3.2 eq 22
 deny ip any any
=END=

############################################################
