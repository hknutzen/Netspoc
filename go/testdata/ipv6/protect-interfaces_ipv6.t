
############################################################
=TITLE=Protect interface if network behind is accessed
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip6 = ::a01:101; hardware = e0; }
 interface:N = { ip6 = ::a02:201; hardware = e1; }
}
network:N = { ip6 = ::a02:200/120; }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 deny ipv6 any host ::a02:201
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 deny ipv6 any any
--
ipv6 access-list e1_in
 permit tcp ::a02:200/120 ::a01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Disable protection with attribute 'no_protect_self'
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 no_protect_self;
 interface:U = { ip6 = ::a01:101; hardware = e0; }
 interface:N = { ip6 = ::a02:201; hardware = e1; }
}
network:N = { ip6 = ::a02:200/120; }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 deny ipv6 any any
--
ipv6 access-list e1_in
 permit tcp ::a02:200/120 ::a01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Unsupported 'no_protect_self'
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R = {
 managed;
 model = ASA;
 no_protect_self;
 interface:U = { ip6 = ::a01:101; hardware = e0; }
 interface:N = { ip6 = ::a02:201; hardware = e1; }
}
network:N = { ip6 = ::a02:200/120; }
=ERROR=
Error: Must not use attribute 'no_protect_self' at router:R of model ASA
=END=

############################################################
=TITLE=Protect all interfaces
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip6 = ::a01:101, ::a01:102; hardware = e0; }
 interface:N = { ip6 = ::a02:201; hardware = e1; }
}
network:N = { ip6 = ::a02:200/120; }
service:test = {
    user = network:U;
    permit src = user; dst = any:[network:N]; prt = tcp 80;
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a02:201
 deny ipv6 any host ::a01:102
 permit tcp ::a01:100/120 any eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Protect interfaces matching aggregate
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip6 = ::a01:101; hardware = e0; }
 interface:N = { ip6 = ::a02:201; hardware = e1; }
}
network:N = { ip6 = ::a02:200/120; }
service:test = {
    user = network:U;
    permit src = user; dst = any:[ip6=::a02:0/112 & network:N]; prt = tcp 80;
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 deny ipv6 any host ::a02:201
 permit tcp ::a01:100/120 ::a02:0/112 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Skip protection if permit any to interface
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip6 = ::a01:101; hardware = e0; }
 interface:N = { ip6 = ::a02:201; hardware = e1; }
}
network:N = { ip6 = ::a02:200/120; }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
service:any = {
 user = any:[network:U];
 permit src = user; dst = interface:R.N; prt = ip;
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 permit ipv6 any host ::a02:201
 permit tcp ::a01:100/120 ::a02:200/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Optimize interface rules, ignore loopback
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:lo = { ip6 = ::a01:901; loopback; hardware = lo; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
service:any = {
 user = any:[network:n1];
 permit src = user;
        dst = interface:r.n1, interface:r.n2, interface:r.lo;
        prt = ip;
 permit src = user; dst = interface:r.n3; prt = tcp 22;
 permit src = user; dst = any:[network:n2], network:n3; prt = ip;
}
service:deny = {
 user = host:h1;
 deny src = user; dst = interface:r.n3; prt = tcp 22;
}
=OUTPUT=
--ipv6/r
ipv6 access-list n1_in
 deny tcp host ::a01:10a host ::a01:301 eq 22
 permit tcp any host ::a01:301 eq 22
 deny ipv6 any host ::a01:301
 permit ipv6 any any
--
ipv6 access-list n2_in
 deny ipv6 any any
=END=

############################################################
=TITLE=Protect interfaces of crosslink cluster
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R1 = {
 managed;
 model = IOS;
 interface:U = { ip6 = ::a01:101, ::a01:102; hardware = e0; }
 interface:C = { ip6 = ::a09:901; hardware = e1; }
}
network:C = { ip6 = ::a09:900/125; crosslink; }
router:R2 = {
 managed;
 model = IOS;
 interface:C = { ip6 = ::a09:902, ::a09:903; hardware = e2; }
 interface:N = { ip6 = ::a02:201; hardware = e3; }
}
network:N = { ip6 = ::a02:200/120; }
service:test = {
    user = network:U;
    permit src = user;
           dst = any:[network:N], any:[network:C];
           prt = tcp 80;
}
=OUTPUT=
--ipv6/R1
ipv6 access-list e0_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a09:901
 deny ipv6 any host ::a01:102
 deny ipv6 any host ::a09:902
 deny ipv6 any host ::a02:201
 deny ipv6 any host ::a09:903
 permit tcp ::a01:100/120 any eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Protect interfaces of mixed crosslink cluster
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R1 = {
 managed;
 model = ASA;
 interface:U = { ip6 = ::a01:101; hardware = e0; }
 interface:C = { ip6 = ::a09:901; hardware = e1; }
}
area:CLN = { border = interface:R1.C; }
network:C = { ip6 = ::a09:900/125; crosslink; }
router:R2 = {
 managed;
 model = IOS;
 interface:C = { ip6 = ::a09:902; hardware = e2; }
 interface:L = { ip6 = ::a03:303; hardware = lo; loopback; }
 interface:N = { ip6 = ::a02:201; hardware = e3; }
}
network:N = { ip6 = ::a02:200/120; }
service:test = {
    user = network:U;
    permit src = user;
    dst = any:[area:CLN];
           prt = tcp 80;
}
=OUTPUT=
--ipv6/R1
access-list e0_in extended deny ip any6 host ::a09:902
access-list e0_in extended deny ip any6 host ::a03:303
access-list e0_in extended deny ip any6 host ::a02:201
access-list e0_in extended permit tcp ::a01:100/120 any6 eq 80
access-list e0_in extended deny ip any6 any6
access-group e0_in in interface e0
--ipv6/R2
ipv6 access-list e3_in
 permit tcp any ::a01:100/120 established
 deny ipv6 any any
=END=

############################################################
=TITLE=Protect NAT interface
=TODO= No IPv6
=INPUT=
network:U = { ip6 = ::a01:100/120; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip6 = ::a01:101; hardware = e0; nat_out = N; }
 interface:N = { ip6 = ::a02:201; hardware = e1; }
}
network:N = { ip6 = ::a02:200/120; nat:N = { ip6 = ::a09:900/120; } }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
=OUTPUT=
--ipv6/R
ipv6 access-list e0_in
 deny ipv6 any host ::a09:901
 permit tcp ::a01:100/120 ::a09:900/120 eq 80
 deny ipv6 any any
=END=

############################################################
=TITLE=Interface has dynamic NAT address
=TODO= No IPv6
# Address for protect self rules is unknown.
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; nat_out = d; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip6 = ::a01:200/120;
 nat:d = { ip6 = ::a09:900/121; dynamic; }
}
service:s = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Must not apply dynamic nat:d to interface:r1.n2 at interface:r1.n1 of same device.
 This isn't supported for model IOS.
=END=

############################################################
=TITLE=Interface has negotiated address
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; nat:n2 = { ip6 = ::a09:900/120; } }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { negotiated6; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; nat_out = n2; }
}
service:s = {
    user = network:n1, network:n3;
    permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 permit tcp ::a01:100/120 ::a01:200/120 eq 22
 deny ipv6 any any
--ipv6/r2
ipv6 access-list n3_in
 deny ipv6 any host ::a09:901
 permit tcp ::a01:300/120 ::a09:900/120 eq 22
 deny ipv6 any any
=END=

############################################################
