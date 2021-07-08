
############################################################
=TITLE=Protect interface if network behind is accessed
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
=END=
=OUTPUT=
--R
ip access-list extended e0_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended e1_in
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Disable protection with attribute 'no_protect_self'
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 no_protect_self;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
=END=
=OUTPUT=
--R
ip access-list extended e0_in
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended e1_in
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Unsupported 'no_protect_self'
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = ASA;
 no_protect_self;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }
=END=
=ERROR=
Error: Must not use attribute 'no_protect_self' at router:R of model ASA
=END=

############################################################
=TITLE=Protect all interfaces
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }
service:test = {
    user = network:U;
    permit src = user; dst = any:[network:N]; prt = tcp 80;
}
=END=
=OUTPUT=
--R
ip access-list extended e0_in
 deny ip any host 10.1.1.1
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Protect interfaces matching object group
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = NX-OS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:l4 = { ip = 10.2.2.4; loopback; subnet_of = network:N2; hardware = lo4; }
 interface:l5 = { ip = 10.2.3.4; loopback; subnet_of = network:N3; hardware = lo5; }
 interface:l6 = { ip = 10.2.4.4; loopback; subnet_of = network:N4; hardware = lo6; }
 interface:N2 = { ip = 10.2.2.1; hardware = e1; }
 interface:N3 = { ip = 10.2.3.1; hardware = e1; }
 interface:N4 = { ip = 10.2.4.1; hardware = e1; }
}
network:N2 = { ip = 10.2.2.0/24; }
network:N3 = { ip = 10.2.3.0/24; }
network:N4 = { ip = 10.2.4.0/24; }
service:test = {
    user = network:N2, network:N3, network:N4;
    permit src = network:U; dst = user; prt = tcp 80;
}
=END=
=OUTPUT=
--R
object-group ip address g0
 10 10.2.2.0/23
 20 10.2.4.0/24
ip access-list e0_in
 10 deny ip any 10.2.2.4/32
 20 deny ip any 10.2.3.4/32
 30 deny ip any 10.2.4.4/32
 40 deny ip any 10.2.2.1/32
 50 deny ip any 10.2.3.1/32
 60 deny ip any 10.2.4.1/32
 70 permit tcp 10.1.1.0/24 addrgroup g0 eq 80
 80 deny ip any any
=END=

############################################################
=TITLE=Protect interfaces matching aggregate
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }
service:test = {
    user = network:U;
    permit src = user; dst = any:[ip=10.2.0.0/16 & network:N]; prt = tcp 80;
}
=END=
=OUTPUT=
--R
ip access-list extended e0_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.0.0 0.0.255.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Skip protection if permit any to interface
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
service:any = {
 user = any:[network:U];
 permit src = user; dst = interface:R.N; prt = ip;
}
=END=
=OUTPUT=
--R
ip access-list extended e0_in
 permit ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Skip protection of loopback interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:lo = { ip = 10.1.3.3; loopback; hardware = Loopback0; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
service:any = {
 user = any:[network:n1];
 permit src = user; dst = interface:r.[all]; prt = ip;
 permit src = user; dst = any:[network:n2]; prt = ip;
}
=END=
=OUTPUT=
--r
ip access-list extended n1_in
 permit ip any any
=END=

############################################################
=TITLE=Protect interfaces of crosslink cluster
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R1 = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:C = { ip = 10.9.9.1; hardware = e1; }
}
network:C = { ip = 10.9.9.0/29; crosslink; }
router:R2 = {
 managed;
 model = IOS;
 interface:C = { ip = 10.9.9.2; hardware = e2; }
 interface:N = { ip = 10.2.2.1; hardware = e3; }
}
network:N = { ip = 10.2.2.0/24; }
service:test = {
    user = network:U;
    permit src = user;
           dst = any:[network:N], any:[network:C];
           prt = tcp 80;
}
=END=
=OUTPUT=
--R1
ip access-list extended e0_in
 deny ip any host 10.1.1.1
 deny ip any host 10.9.9.1
 deny ip any host 10.9.9.2
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 any eq 80
 deny ip any any
=END=

############################################################
=TITLE=Protect interfaces of mixed crosslink cluster
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R1 = {
 managed;
 model = ASA;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:C = { ip = 10.9.9.1; hardware = e1; }
}
area:CLN = { border = interface:R1.C; }
network:C = { ip = 10.9.9.0/29; crosslink; }
router:R2 = {
 managed;
 model = IOS;
 interface:C = { ip = 10.9.9.2; hardware = e2; }
 interface:L = { ip = 10.3.3.3; hardware = lo; loopback; }
 interface:N = { ip = 10.2.2.1; hardware = e3; }
}
network:N = { ip = 10.2.2.0/24; }
service:test = {
    user = network:U;
    permit src = user;
    dst = any:[area:CLN];
           prt = tcp 80;
}
=END=
=OUTPUT=
--R1
access-list e0_in extended deny ip any4 host 10.9.9.2
access-list e0_in extended deny ip any4 host 10.3.3.3
access-list e0_in extended deny ip any4 host 10.2.2.1
access-list e0_in extended permit tcp 10.1.1.0 255.255.255.0 any4 eq 80
access-list e0_in extended deny ip any4 any4
access-group e0_in in interface e0
--R2
ip access-list extended e3_in
 permit tcp any 10.1.1.0 0.0.0.255 established
 deny ip any any
=END=

############################################################
=TITLE=Protect NAT interface
=INPUT=
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed;
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; bind_nat = N; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; nat:N = { ip = 10.9.9.0/24; } }
service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
=END=
=OUTPUT=
--R
ip access-list extended e0_in
 deny ip any host 10.9.9.1
 permit tcp 10.1.1.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 80
 deny ip any any
=END=

############################################################
=TITLE=Interface has dynamic NAT address
# Address for protect self rules is unknown.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = d; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 nat:d = { ip = 10.9.9.0/25; dynamic; }
}
service:s = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=ERROR=
Error: Must not apply dynamic nat:d to interface:r1.n2 at interface:r1.n1 of same device.
 This isn't supported for model IOS.
=END=

############################################################
=TITLE=Interface has negotiated address
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.9.0/24; } }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { negotiated; hardware = n2; }
}
router:r2 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n2; }
}
service:s = {
    user = network:n1, network:n3;
    permit src = user; dst = interface:r1.n2; prt = tcp 22;
}
=END=
=OUTPUT=
--r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 eq 22
 deny ip any any
--r2
ip access-list extended n3_in
 deny ip any host 10.9.9.1
 permit tcp 10.1.3.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 22
 deny ip any any
=END=

############################################################
