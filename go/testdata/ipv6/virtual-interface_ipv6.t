
############################################################
=TITLE=Routers connecting networks with virtual interfaces
=TEMPL=input
network:n1 = { ip = ::a01:100/120;}
network:n2 = { ip = ::a02:200/120;}
network:n3 = { ip = ::a03:300/120;}
network:n4 = { ip = ::a04:400/120;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = ::a01:101; hardware = E1;}
 interface:n2 = {ip = ::a02:201; hardware = E2;}
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = {ip = ::a02:202; virtual = {ip = ::a02:209;} hardware = E3;}
 interface:n3 = {ip = ::a03:301; {{.v1}} hardware = E4;}
}
router:r3 = {
 managed;
 model = ASA;
 interface:n2 = {ip = ::a02:203; virtual = {ip = ::a02:209;} hardware = E5;}
 interface:n3 = {ip = ::a03:302; {{.v2}} hardware = E6;}
}
router:r4 = {
 model = ASA;
 managed;
 interface:n3 = {ip = ::a03:303; hardware = E7;}
 interface:n4 = {ip = ::a04:401; hardware = E8;}
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=
=PARAMS=--ipv6
=INPUT=
[[input
v1: "virtual = {ip = ::a03:309;}"
v2: "virtual = {ip = ::a03:309;}"
]]
=OUTPUT=
--ipv6/r1
ipv6 route E2 ::a04:400/120 ::a02:209
--ipv6/r4
ipv6 route E7 ::a01:100/120 ::a03:309
=END=

############################################################
=TITLE=Missing virtual interfaces on backward path
=PARAMS=--ipv6
=INPUT=[[input {v1: "", v2: ""}]]
=ERROR=
Error: Ambiguous static routes for network:n1 at interface:r4.n3 via
 - interface:r2.n3
 - interface:r3.n3
=END=

############################################################
=TITLE=One missing virtual interface on backward path
=PARAMS=--ipv6
=INPUT=[[input {v1: "virtual = {ip = ::a03:309;}", v2: ""}]]
=ERROR=
Error: Ambiguous static routes for network:n1 at interface:r4.n3 via
 - interface:r2.n3.virtual
 - interface:r3.n3
=END=

############################################################
