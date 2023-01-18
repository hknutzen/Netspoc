
############################################################
=TITLE=All interfaces at router at network with virtual and secondary interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {
  ip = ::a01:103, ::a01:104;
  hardware = n1;
  virtual = { ip = ::a01:101; }
 }
 interface:n2 = { ip = ::a01:203; hardware = n2; virtual = { ip = ::a01:201; } }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:102; hardware = n1; virtual = { ip = ::a01:101; } }
 interface:n2 = { ip = ::a01:202; hardware = n2; virtual = { ip = ::a01:201; } }
}
network:n2 = { ip = ::a01:200/120; }

service:s1 = {
 user = interface:[interface:[managed & network:n1].[all]].[all];
 permit src = network:n1; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:101 eq 22
 permit tcp ::a01:100/120 host ::a01:201 eq 22
 permit tcp ::a01:100/120 host ::a01:104 eq 22
 permit tcp ::a01:100/120 host ::a01:103 eq 22
 permit tcp ::a01:100/120 host ::a01:203 eq 22
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:101 eq 22
 permit tcp ::a01:100/120 host ::a01:201 eq 22
 permit tcp ::a01:100/120 host ::a01:102 eq 22
 permit tcp ::a01:100/120 host ::a01:202 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=All interfaces of aggregate in zone cluster
# Must not add
# - interface of unmanaged router with bind_nat,
# - managed interface of unnumbered network.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; nat:n1 = { ip = ::a09:900/120; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:un = { unnumbered; }
any:n2-3 = { link = network:n2; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = ::a01:202; }
 interface:n3 = { bind_nat = n1; }
 interface:un = { bind_nat = n1; }
}
router:r3 = {
 model = IOS;
 managed;
 interface:un = { unnumbered; hardware = un; }
}
service:s = {
 user = interface:[any:n2-3].[all];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:201 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Ignore managed interface of unnumbered network
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:un = { unnumbered; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:un = { unnumbered; hardware = un; }
}
service:s = {
 user = interface:[managed & network:un, network:n1].[all];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:101 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Ignore interfaces of unnumbered network
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:un = { unnumbered; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:un = { unnumbered; hardware = un; }
}
router:r2 = {
 interface:un = { unnumbered; }
}
service:s = {
 user = interface:[network:un, network:n1].[all];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:101 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Add managed interfaces of network at routing_only
# Must add interface of router with routing_only.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 model = IOS;
 managed = routing_only;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
}
service:s = {
 user = interface:[managed & network:n2].[all];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:201 eq 80
 permit tcp ::a01:100/120 host ::a01:202 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interface of network
=TEMPL=topo
network:a = { ip = ::a00:0/120; }
router:r1 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = ::a00:1; hardware = e1; }
 interface:b1 = { ip = ::a01:101; hardware = e0; }
}
router:r2 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = ::a00:2; hardware = f1; }
 interface:b2 = { ip = ::a01:201; hardware = f0; }
}
network:b1 = { ip = ::a01:100/120; }
network:b2 = { ip = ::a01:200/120; }
router:u = {
 interface:b1 = { ip = ::a01:102; }
 interface:b2 = { ip = ::a01:202; }
 interface:b3 = { ip = ::a01:301; }
}
network:b3 = { ip = ::a01:300/120; }
any:b = { link = network:b1; }
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test1 = {
 user = interface:[network:b1].[auto],
        interface:[managed & network:b2].[auto],
        interface:[network:b3].[auto];
 permit src = network:a; dst = user; prt = tcp 22;
}
service:test2 = {
 user = interface:[network:b3].[auto];
 permit src = user; dst = interface:[network:a].[auto]; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:101 eq 22
 permit tcp host ::a01:301 host ::a00:1 eq 23
 permit tcp ::a00:0/120 host ::a01:102 eq 22
 permit tcp ::a00:0/120 host ::a01:201 eq 22
 permit tcp ::a00:0/120 host ::a01:301 eq 22
 deny ipv6 any any
--
ipv6 access-list e0_in
 permit tcp ::a00:0/120 host ::a01:101 eq 22
 permit tcp host ::a01:301 host ::a00:1 eq 23
 permit tcp host ::a01:301 host ::a00:2 eq 23
 deny ipv6 any any
--ipv6/r2
ipv6 access-list f1_in
 permit tcp ::a00:0/120 host ::a01:201 eq 22
 permit tcp host ::a01:301 host ::a00:2 eq 23
 permit tcp ::a00:0/120 host ::a01:101 eq 22
 permit tcp ::a00:0/120 host ::a01:102 eq 22
 permit tcp ::a00:0/120 host ::a01:301 eq 22
 deny ipv6 any any
--
ipv6 access-list f0_in
 permit tcp ::a00:0/120 host ::a01:201 eq 22
 permit tcp host ::a01:301 host ::a00:2 eq 23
 permit tcp host ::a01:301 host ::a00:1 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interface of router
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test2 = {
 user = interface:u.[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:102 eq 23
 permit tcp ::a00:0/120 host ::a01:202 eq 23
 deny ipv6 any any
--ipv6/r2
! [ ACL ]
ipv6 access-list f1_in
 permit tcp ::a00:0/120 host ::a01:102 eq 23
 permit tcp ::a00:0/120 host ::a01:202 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Managed auto interface of unmanaged interface
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test2 = {
 user = interface:[managed & interface:u.b2, interface:r2.b2].[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a00:2 eq 23
 permit tcp ::a00:0/120 host ::a01:201 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=All interfaces of aggregate
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[any:b].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:101 eq 23
 permit tcp ::a00:0/120 host ::a01:201 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=All interfaces of implicit aggregate
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[any:[network:b3]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:101 eq 23
 permit tcp ::a00:0/120 host ::a01:201 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Managed interfaces of implicit aggregate
# Border interfaces of zone are managed by definition.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[managed & any:[network:b3]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:101 eq 23
 permit tcp ::a00:0/120 host ::a01:201 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Interfaces of matching implicit aggregate
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[any:[ip = ::a01:0/112 & network:b3]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=ERROR=
Error: Must not use interface:[..].[all]
 with any:[ip=::a01:0/112 & network:b1] having ip/mask
 in user of service:s
=END=

############################################################
=TITLE=Auto interfaces of aggregate
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[any:b].[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
=ERROR=
Error: Must not use interface:[any:..].[auto] in user of service:s
=END=

############################################################
=TITLE=All interfaces of network
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[network:b1].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:101 eq 23
 permit tcp ::a00:0/120 host ::a01:102 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Managed interfaces of network
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[managed & network:b1].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:101 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Ignore short interface of network
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[network:b1].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=SUBST=/interface:b1 = { ip = ::a01:102; }/interface:b1;/
=WARNING=
Warning: Ignoring interface:u.b1 without IP address in dst of rule in service:s
=OUTPUT=
--ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:101 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=All interfaces from auto interface of network
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[interface:[network:b1].[auto]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=ERROR=
Error: Can't use interface:[network:b1].[auto] inside interface:[..].[all] of user of service:s
=END=

############################################################
=TITLE=All interfaces from auto interface of router
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[interface:u.[auto]].[all];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:102 eq 23
 permit tcp ::a00:0/120 host ::a01:202 eq 23
 permit tcp ::a00:0/120 host ::a01:301 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interface from auto interface of router
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[interface:u.[auto]].[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list e1_in
 permit tcp ::a00:0/120 host ::a01:102 eq 23
 permit tcp ::a00:0/120 host ::a01:202 eq 23
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interface from auto interface
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 user = interface:[interface:[network:b1].[auto]].[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
=ERROR=
Error: Can't use interface:[network:b1].[auto] inside interface:[..].[auto] of user of service:s
=END=

############################################################
=TITLE=Auto interfaces in nested loop
=PARAMS=--ipv6
=INPUT=
network:Serv = {ip = ::a0a:0/116;}
router:ZT45 = {
 interface:Serv = {ip = ::a0a:3; virtual = {ip = ::a0a:102;}}
 interface:ZT45 = {ip = ::a15:70e;}
}
network:ZT45 = {ip = ::a15:70c/126;}
router:LV41 = {
 interface:Serv = {ip = ::a0a:2; virtual = {ip = ::a0a:102;}}
 interface:LV41 = {ip = ::a16:801;}
}
network:LV41 = {ip = ::a16:800/126;}
network:Trns = {ip = ::a18:114/126;}
network:Crss = {ip = ::a18:214/126;}
router:LV96 = {
 interface:Trns = {ip = ::a18:116;}
 interface:Crss = {ip = ::a18:216;}
 interface:LV96 = {ip = ::a16:816;}
}
router:ZT21 = {
 interface:Trns = {ip = ::a18:115;}
 interface:Crss = {ip = ::a18:215;}
 interface:ZT21 = {ip = ::a15:715;}
}
network:LV96 = {ip = ::a16:814/126;}
network:ZT21 = {ip = ::a15:714/126;}
router:Plus = {
 interface:LV41 = {ip = ::a16:802;}
 interface:LV96 = {ip = ::a16:815;}
 interface:Plus = {ip = ::a17:806;}
}
router:Base = {
 interface:ZT45	= {ip = ::a15:70d;}
 interface:ZT21 = {ip = ::a15:716;}
 interface:Base = {ip = ::a17:706;}
}
network:Plus = {ip = ::a17:804/126;}
network:Base = {ip = ::a17:704/126;}
router:R5 = {
 interface:Plus = {ip = ::a17:805;}
 interface:Base = {ip = ::a17:705;}
 interface:G112 = {ip = ::a17:605;}
}
network:G112 = {ip = ::a17:604/126;}
router:FW = {
 managed;
 model = ASA;
 interface:G112 = {ip = ::a17:606; hardware = outside; }
 interface:Mgmt = {ip = ::a0b:b0d; hardware = inside;}
}
network:Mgmt = {ip = ::a0b:b00/120;}
service:IPSEC = {
 user = interface:R5.[auto],
        interface:Base.[auto],
        interface:Plus.[auto],
        interface:ZT21.[auto],
        interface:LV96.[auto],
        interface:ZT45.[auto],
        interface:LV41.[auto],
        ;
 permit	src = network:Mgmt;
	dst = user;
	prt = tcp 22;
}
=END=
# Expect
# only interface:G112 of router:R5
# and all interfaces of other routers.
=OUTPUT=
--ipv6/FW
object-group network v6g0
 network-object ::a0a:2/127
 network-object host ::a15:70d
 network-object host ::a15:70e
 network-object host ::a15:715
 network-object host ::a15:716
 network-object host ::a16:801
 network-object host ::a16:802
 network-object host ::a16:815
 network-object host ::a16:816
 network-object host ::a17:605
 network-object host ::a17:706
 network-object host ::a17:806
 network-object host ::a18:115
 network-object host ::a18:116
 network-object host ::a18:215
 network-object host ::a18:216
access-list inside_in extended permit tcp ::a0b:b00/120 object-group v6g0 eq 22
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Different paths to auto interface with same result
=PARAMS=--ipv6
=INPUT=
network:n1 = {ip = ::a01:100/120;}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = {ip = ::a01:101;hardware = n1;}
 interface:n2 = {ip = ::a01:201;hardware = n2;}
}
network:n2 = {
 ip = ::a01:200/120;
 host:h2 = { ip = ::a01:20a;}
}
router:r2 = {
 model = Linux;
 managed;
 interface:n2 = {ip = ::a01:202; hardware = n2;}
}
service:s1 = {
 user = host:h2, network:n1;
 permit src = user;
	dst = interface:r2.[auto];
	prt = udp 161;
}
=OUTPUT=
--ipv6/r2
# [ ACL ]
:c1 -
-A c1 -j ACCEPT -s ::a01:20a
-A c1 -j ACCEPT -s ::a01:100/120
--
:n2_self -
-A n2_self -g c1 -s ::a01:0/118 -d ::a01:202 -p udp --dport 161
-A INPUT -j n2_self -i n2
=END=

############################################################
=TITLE=Different paths to auto interface with different result
=PARAMS=--ipv6
=INPUT=
network:n1 = {ip = ::a01:100/120;}
router:r1 = {
 model = Linux;
 managed;
 interface:n1 = {ip = ::a01:101;hardware = n1;}
 interface:n2 = {ip = ::a01:201;hardware = n2;}
}
network:n2 = {
 ip = ::a01:200/120;
 host:h2 = { ip = ::a01:20a;}
}
service:s1 = {
 user = host:h2, network:n1;
 permit src = user;
	dst = interface:r1.[auto];
	prt = udp 161;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:n1_self -
-A n1_self -j ACCEPT -s ::a01:100/120 -d ::a01:101 -p udp --dport 161
-A INPUT -j n1_self -i n1
--
:n2_self -
-A n2_self -j ACCEPT -s ::a01:20a -d ::a01:201 -p udp --dport 161
-A INPUT -j n2_self -i n2
=END=

############################################################
=TITLE=Auto interface with pathrestriction
# Would not find result if search starts at router.
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = Vlan20; }
 interface:n2 = { ip = ::a01:201; hardware = G0/1;
 }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = Vlan20; }
 interface:n2 = { ip = ::a01:202; hardware = G0/1;  }
}
network:n2 = { ip = ::a01:200/120; }
router:r3 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = ::a01:246; hardware = E0; }
 interface:n3 = { ip = ::a01:301; hardware = E1; }
}
network:n3 = { ip = ::a01:300/120; }
pathrestriction:restrict1 =
 interface:r1.n1,
 interface:r3.n2,
;
pathrestriction:restrict2 =
 interface:r2.n1,
 interface:r3.n2,
;
service:test = {
 user = network:n1;
 permit src = user; dst = interface:r3.[auto]; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! Vlan20_in
access-list Vlan20_in extended permit tcp ::a01:100/120 host ::a01:246 eq 80
access-list Vlan20_in extended deny ip any6 any6
access-group Vlan20_in in interface Vlan20
--ipv6/r2
! [ ACL ]
ipv6 access-list Vlan20_in
 permit tcp ::a01:100/120 host ::a01:246 eq 80
 deny ipv6 any any
--ipv6/r3
! [ ACL ]
ipv6 access-list E0_in
 permit tcp ::a01:100/120 host ::a01:246 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Ignore interface with pathrestriction at border of loop (1)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:t1 = { ip = ::a09:102; hardware = t1; }
 interface:t2 = { ip = ::a09:202; hardware = t2; }
}
network:t1 = { ip = ::a09:100/120; }
network:t2 = { ip = ::a09:200/120; }
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:t1 = { ip = ::a09:101; hardware = t1; }
 interface:t2 = { ip = ::a09:201; hardware = t2; }
 interface:n2 = { ip = ::a01:201; hardware = n2 ;}
}
network:n2 = { ip = ::a01:200/120; }
pathrestriction:p =
 interface:r1.n1,
 interface:r1.t2,
;
service:test = {
 user = interface:r1.[auto];
 permit src = network:n2; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r2
! n2_in
object-group network v6g0
 network-object host ::a09:102
 network-object host ::a09:202
access-list n2_in extended permit tcp ::a01:200/120 object-group v6g0 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Ignore interface with pathrestriction at border of loop (2)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r3  = {
 managed;
 model = IOS;
 interface:n2 = { ip = ::a01:203; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
pathrestriction:p1 = interface:r1.n2, interface:r2.n2;
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.[auto]; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/120 host ::a01:101 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Find auto interface with pathrestriction in loop
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3;}
}
network:n3 = { ip = ::a01:300/120; }
pathrestriction:p =
 interface:r1.n2,
 interface:r2.n2,
;
service:s = {
 user = interface:r1.[auto];
 permit src = network:n3; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r2
! n3_in
object-group network v6g0
 network-object host ::a01:101
 network-object host ::a01:201
access-list n3_in extended permit tcp ::a01:300/120 object-group v6g0 eq 22
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Find auto interface with pathrestriction at border of loop at zone
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2;
 }
}
router:r2 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:202; hardware = n2;  }
}
network:n2 = { ip = ::a01:200/120; }
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:203; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
pathrestriction:restrict1 =
 interface:r2.n1,
 interface:r3.n2,
;
service:s1 = {
 user = interface:r3.[auto];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
--ipv6/r2
ipv6 access-list n2_in
 deny ipv6 any host ::a01:102
 permit tcp host ::a01:203 ::a01:100/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Multiple auto interfaces in src and dst
=TEMPL=input
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r4 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
service:s = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = user;
        dst = interface:r3.[auto], interface:r4.[auto];
        prt = tcp 22;
}
=PARAMS=--ipv6
=INPUT=[[input]]
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object host ::a01:102
 network-object host ::a01:201
object-group network v6g1
 network-object host ::a01:202
 network-object host ::a01:301
 network-object host ::a01:302
 network-object host ::a01:401
access-list n1_in extended permit tcp object-group v6g0 object-group v6g1 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
-- ipv6/r2
! n1_in
object-group network v6g0
 network-object host ::a01:101
 network-object host ::a01:402
object-group network v6g1
 network-object host ::a01:202
 network-object host ::a01:301
 network-object host ::a01:302
 network-object host ::a01:401
access-list n1_in extended permit tcp object-group v6g0 object-group v6g1 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r3
! n2_in
object-group network v6g0
 network-object host ::a01:101
 network-object host ::a01:102
 network-object host ::a01:201
 network-object host ::a01:402
object-group network v6g1
 network-object host ::a01:302
 network-object host ::a01:401
access-list n2_in extended permit tcp object-group v6g0 object-group v6g1 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
-- ipv6/r4
ipv6 access-list n3_in
 permit tcp host ::a01:101 host ::a01:302 eq 22
 permit tcp host ::a01:101 host ::a01:401 eq 22
 permit tcp host ::a01:402 host ::a01:302 eq 22
 permit tcp host ::a01:402 host ::a01:401 eq 22
 permit tcp host ::a01:102 host ::a01:302 eq 22
 permit tcp host ::a01:102 host ::a01:401 eq 22
 permit tcp host ::a01:201 host ::a01:302 eq 22
 permit tcp host ::a01:201 host ::a01:401 eq 22
 deny ipv6 any any
--
ipv6 access-list n4_in
 permit tcp host ::a01:101 host ::a01:302 eq 22
 permit tcp host ::a01:101 host ::a01:401 eq 22
 permit tcp host ::a01:402 host ::a01:302 eq 22
 permit tcp host ::a01:402 host ::a01:401 eq 22
 permit tcp host ::a01:102 host ::a01:302 eq 22
 permit tcp host ::a01:102 host ::a01:401 eq 22
 permit tcp host ::a01:201 host ::a01:302 eq 22
 permit tcp host ::a01:201 host ::a01:401 eq 22
 permit tcp host ::a01:101 host ::a01:202 eq 22
 permit tcp host ::a01:101 host ::a01:301 eq 22
 permit tcp host ::a01:402 host ::a01:202 eq 22
 permit tcp host ::a01:402 host ::a01:301 eq 22
 permit tcp host ::a01:102 host ::a01:202 eq 22
 permit tcp host ::a01:102 host ::a01:301 eq 22
 permit tcp host ::a01:201 host ::a01:202 eq 22
 permit tcp host ::a01:201 host ::a01:301 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Multiple auto interfaces in src and dst with pathrestriction
# pathrestriction leads to more complicated expansion of auto interfaces,
# because result is different for different destinations.
=PARAMS=--ipv6
=INPUT=
[[input]]
pathrestriction:r = interface:r1.n4, interface:r3.n3;
=OUTPUT=
--ipv6/r1
! n1_in
object-group network v6g0
 network-object host ::a01:102
 network-object host ::a01:201
object-group network v6g1
 network-object host ::a01:301
 network-object host ::a01:302
 network-object host ::a01:401
access-list n1_in extended permit tcp object-group v6g0 object-group v6g1 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r2
! n1_in
object-group network v6g0
 network-object host ::a01:101
 network-object host ::a01:402
object-group network v6g1
 network-object host ::a01:301
 network-object host ::a01:302
 network-object host ::a01:401
access-list n1_in extended permit tcp object-group v6g0 host ::a01:202 eq 22
access-list n1_in extended permit tcp host ::a01:101 object-group v6g1 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--ipv6/r3
! n2_in
object-group network v6g0
 network-object host ::a01:101
 network-object host ::a01:102
 network-object host ::a01:201
object-group network v6g1
 network-object host ::a01:302
 network-object host ::a01:401
access-list n2_in extended permit tcp object-group v6g0 object-group v6g1 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
--ipv6/r4
! [ ACL ]
ipv6 access-list n3_in
 permit tcp host ::a01:102 host ::a01:302 eq 22
 permit tcp host ::a01:102 host ::a01:401 eq 22
 permit tcp host ::a01:201 host ::a01:302 eq 22
 permit tcp host ::a01:201 host ::a01:401 eq 22
 permit tcp host ::a01:101 host ::a01:302 eq 22
 permit tcp host ::a01:101 host ::a01:401 eq 22
 deny ipv6 any any
--
ipv6 access-list n4_in
 permit tcp host ::a01:102 host ::a01:302 eq 22
 permit tcp host ::a01:102 host ::a01:401 eq 22
 permit tcp host ::a01:201 host ::a01:302 eq 22
 permit tcp host ::a01:201 host ::a01:401 eq 22
 permit tcp host ::a01:101 host ::a01:302 eq 22
 permit tcp host ::a01:101 host ::a01:401 eq 22
 permit tcp host ::a01:402 host ::a01:401 eq 22
 permit tcp host ::a01:101 host ::a01:301 eq 22
 permit tcp host ::a01:402 host ::a01:202 eq 22
 permit tcp host ::a01:402 host ::a01:301 eq 22
 permit tcp host ::a01:201 host ::a01:301 eq 22
 permit tcp host ::a01:102 host ::a01:301 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Auto interface of internally split router with pathrestriction (1)
=PARAMS=--ipv6
=INPUT=
network:n1 =  { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
# r1 is split internally into two parts
# r1 with n1,n2
# r1' with n3
# both connected by unnumbered network.
router:r1 = {
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:102; hardware = n1; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
pathrestriction:r =
 interface:r1.n3,
 interface:r2.n3,
;
service:s = {
 user = network:n4;
 # Find split interface r1.n3 from original router:r1
 permit src = user; dst = interface:r1.[auto]; prt = tcp 22;
 # Find original router:r1 from split interface:r1.n3
 permit src = user; dst = interface:[interface:r1.n3].[auto]; prt = tcp 23;
 # Check that all interfaces are found.
 permit src = user; dst = interface:r1.[all]; prt = tcp 24;
 permit src = user; dst = interface:[interface:r1.n3].[all]; prt = tcp 25;
}
=OUTPUT=
--ipv6/r2
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
--
! n4_in
object-group network v6g0
 network-object host ::a01:101
 network-object host ::a01:301
access-list n4_in extended permit tcp ::a01:400/120 object-group v6g0 range 22 25
access-list n4_in extended permit tcp ::a01:400/120 host ::a01:201 range 24 25
access-list n4_in extended deny ip any6 any6
access-group n4_in in interface n4
--
! n3_in
access-list n3_in extended deny ip any6 any6
access-group n3_in in interface n3
=END=

############################################################
=TITLE=Auto interface of internally split router with pathrestriction (2)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 interface:n1 = { ip = ::a01:102; }
 interface:n4 = { ip = ::a01:402; loopback; }
 interface:n3 = { ip = ::a01:302; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n2 = { ip = ::a01:209; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n5 = { ip = ::a01:501; hardware = n5; }
}
network:n5 = { ip = ::a01:500/120; }
pathrestriction:r =
 interface:r1.n2,
 interface:r2.n3,
;
service:s = {
 user = interface:r2.[auto];
 permit src = network:n5; dst = user; prt = tcp 22;
}
=END=
# Don't accidently assume, that interface:r2.n3 is located in zone of
# original unmanaged router:r2.
# In this case we would get a path to interface:r2.n3 through router:r1.
=OUTPUT=
--ipv6/r1
! n2_in
access-list n2_in extended permit tcp ::a01:500/120 host ::a01:102 eq 22
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Auto interface of internally split router with pathrestriction (3)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n4 = { ip = ::a01:400/120; }
router:r2 = {
 interface:n1 = { ip = ::a01:102; }
 interface:n4 = { ip = ::a01:402; }
 interface:n3 = { ip = ::a01:302; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r3 = {
 interface:n2;
 interface:n3;
 interface:n5;
}
network:n5 = { ip = ::a01:500/120; }
router:r4 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n5 = { ip = ::a01:501; hardware = n5; }
 interface:n6 = { ip = ::a01:601; hardware = n6; }
}
network:n6 = { ip = ::a01:600/120; }
pathrestriction:r =
 interface:r1.n2,
 interface:r2.n3,
;
service:s = {
 user = interface:r2.[auto];
 permit src = network:n6; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r4
object-group network v6g0
 network-object host ::a01:102
 network-object host ::a01:302
access-list n6_in extended permit tcp ::a01:600/120 object-group v6g0 eq 22
access-list n6_in extended deny ip any6 any6
access-group n6_in in interface n6
=END=

############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (1)
=PARAMS=--ipv6
=INPUT=
network:a = { ip = ::a00:0/120; host:netspoc = { ip = ::a00:a; } }
router:r1 =  {
 managed;
 model = IOS,FW;
 policy_distribution_point = host:netspoc;
 routing = manual;
 interface:a = { ip = ::a00:1; hardware = e1; }
 interface:b1 = { ip = ::a01:101; hardware = e0; }
}
router:r2 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = ::a00:2; hardware = e1; }
 interface:b1 = { ip = ::a01:102; hardware = e0; }
}
network:b1 = { ip = ::a01:100/120; }
service:test = {
 user = interface:r1.[auto];
 permit src = network:a; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
! [ IP = ::a00:1,::a01:101 ]
=END=

############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (2)
# Find interfaces in given order n3, n4,
# even if reversed path was already found previously while
# "Checking and marking rules with hidden or dynamic NAT"
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:16f; } }
network:n2 = { ip = ::a01:200/126; }
network:n3 = { ip = ::a01:300/126; }
network:n4 = { ip = ::a01:400/126; }
network:n5 = { ip = ::a01:500/123; nat:h = { hidden; } }
network:n6 = { ip = ::a01:600/123; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n6 = { ip = ::a01:601; hardware = n6; bind_nat = h; }
}
router:r2 = {
 model = IOS;
 managed;
 routing = manual;
 policy_distribution_point = host:h1;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
 interface:n5 = { ip = ::a01:501; hardware = n5; }
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n4 = { ip = ::a01:402; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r2.n3, interface:r2.n4; prt = tcp 22;
 permit src = user; dst = interface:r2.n5;                  prt = tcp 80;
}
=OUTPUT=
--ipv6/r2
! [ IP = ::a01:302,::a01:401 ]
=END=

############################################################
=TITLE=Multiple interfaces talk to policy_distribution_point (3)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:16f; } }
network:n2 = { ip = ::a01:200/126; }
network:n3 = { ip = ::a01:300/126; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:r1.[all] &! interface:r1.n1;
        prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
! [ IP = ::a01:201,::a01:301 ]
=OPTIONS=--check_policy_distribution_point=1

############################################################
=TITLE=Only one interface in loop talks to policy_distribution_point
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:103; hardware = n1; virtual = { ip = ::a01:101; } }
 interface:n2 = { ip = ::a01:203; hardware = n2; virtual = { ip = ::a01:201; } }
}
router:r2 = {
 managed;
 model = ASA;
 policy_distribution_point = host:netspoc;
 interface:n1 = { ip = ::a01:102; hardware = n1; virtual = { ip = ::a01:101; } }
 interface:n2 = { ip = ::a01:202; hardware = n2; virtual = { ip = ::a01:201; } }
}
network:n2 = { ip = ::a01:200/120; }
router:r3 = {
 managed;
 model = IOS;
 interface:n2 = { ip = ::a01:209; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n3 = { ip = ::a01:300/120; host:netspoc = { ip = ::a01:309; } }
service:s = {
 user = interface:r1.[auto], interface:r2.[auto];
 permit src = network:n3; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
! [ IP = ::a01:203 ]
--ipv6/r2
! [ IP = ::a01:202 ]
=END=

############################################################
# Topology for multiple tests.

############################################################
=TEMPL=topo
network:x = { ip = ::a01:100/120; }
router:r = {
 model = IOS, FW;
 managed;
 interface:x = { ip = ::a01:101; hardware = e0; }
 interface:y = { ip = ::a01:202; hardware = e1; }
}
network:y = { ip = ::a01:200/120; }
=END=

############################################################
=TITLE=Interface and auto interface in intersection
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = interface:r.[auto] &! interface:r.x;
 permit src = user; dst = network:y; prt = tcp 80;
}
=WARNING=
Warning: Useless delete of interface:r.x in user of service:test
=END=

############################################################
=TITLE=Interface and auto interface in union
=PARAMS=--ipv6
=INPUT=
[[topo]]
group:g = interface:r.[auto], interface:r.x, network:y;
service:test = {
 user = group:g &! network:y;
 permit src = user; dst = network:y; prt = tcp 80;
}
=END=
# Must not trigger error message.
=WARNING=NONE

############################################################
=TITLE=Interface and auto network interface
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = interface:[network:x].[auto] &! interface:r.x;
 permit src = user; dst = network:y; prt = tcp 80;
}
=WARNING=
Warning: Useless delete of interface:r.x in user of service:test
=END=

############################################################
=TITLE=Auto interface and auto network interface
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = interface:[network:x].[auto] &! interface:r.[auto];
 permit src = user; dst = network:y; prt = tcp 80;
}
=WARNING=
Warning: Useless delete of interface:r.[auto] in user of service:test
=END=

############################################################
=TITLE=Non conflicting auto network interfaces
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = interface:[network:x].[auto] &! interface:[network:y].[auto];
 permit src = user; dst = network:y; prt = tcp 80;
}
=WARNING=
Warning: Useless delete of interface:[network:y].[auto] in user of service:test
=END=

############################################################
=TITLE=Non conflicting auto network interface with interface
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 user = interface:[network:x].[auto] &! interface:r.y;
 permit src = user; dst = network:y; prt = tcp 80;
}
=WARNING=
Warning: Useless delete of interface:r.y in user of service:test
=END=

############################################################
=TITLE=Find interfaces of subnet in area, incl. loopback
=TEMPL=input
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3Sup = { ip = ::a01:300/120; }
network:n3 = { ip = ::a01:300/121; subnet_of = network:n3Sup; }
network:n4Sup = { ip = ::a01:400/120; }
network:n4 = { ip = ::a01:400/121; subnet_of = network:n4Sup; }
network:trans = { unnumbered; }
area:a3-4 = { inclusive_border = interface:r2.n2; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:lo = { ip = ::a09:901; hardware = lo; loopback; }
 interface:n3Sup = { ip = ::a01:381; hardware = n3Sup; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r3 = {
 interface:n3Sup = { ip = ::a01:382; hardware = n3Sup; }
 interface:trans = { unnumbered; }
}
router:r4 = {
 interface:trans = { unnumbered; }
 interface:lo = { ip = ::a09:902; hardware = lo; loopback; }
 interface:n3 = { ip = ::a01:301; }
}
router:r5 = {
 interface:n4 = { ip = ::a01:402; }
 interface:n4Sup = { ip = ::a01:481; hardware = n4Sup; }
}
=PARAMS=--ipv6
=INPUT=
[[input]]
service:test = {
 user = interface:[area:a3-4].[all] ;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n2_in
object-group network v6g0
 network-object host ::a01:202
 network-object host ::a01:301
 network-object host ::a01:381
 network-object host ::a01:382
 network-object host ::a01:401
 network-object host ::a01:402
 network-object host ::a01:481
 network-object host ::a09:901
 network-object host ::a09:902
access-list n2_in extended permit tcp object-group v6g0 ::a01:100/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Find interfaces of subnet in area, no managed loopback
=PARAMS=--ipv6
=INPUT=
[[input]]
service:test = {
 user = interface:[network:[area:a3-4]].[all] ;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
! n2_in
object-group network v6g0
 network-object host ::a01:301
 network-object host ::a01:381
 network-object host ::a01:382
 network-object host ::a01:401
 network-object host ::a01:402
 network-object host ::a01:481
 network-object host ::a09:902
access-list n2_in extended permit tcp object-group v6g0 ::a01:100/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not use auto interface of host
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
service:test = {
 user = interface:[host:h1].[auto] ;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=ERROR=
Error: Unexpected 'host:h1' in interface:[..].[auto] of user of service:test
=END=

############################################################
=TITLE=Unresolvable auto interface and interface
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
service:test = {
 user = interface:r99.[auto], interface:88.n1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=ERROR=
Error: Can't resolve interface:r99.[auto] in user of service:test
Error: Can't resolve interface:88.n1 in user of service:test
=END=

############################################################
=TITLE=Auto interface in wrong context
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:103; hardware = n1; }
}
service:s = {
 user = host:[interface:r1.[auto]],
        network:[interface:r1.[auto]],
        any:[interface:r1.[auto]],
 ;
 permit src = network:n1; dst = user; prt = tcp 22;
}
=ERROR=
Error: Unexpected 'interface:r1.[auto]' in host:[..] of user of service:s
Error: Unexpected 'interface:r1.[auto]' in network:[..] of user of service:s
Error: Unexpected 'interface:r1.[auto]' in any:[..] of user of service:s
=END=

############################################################
