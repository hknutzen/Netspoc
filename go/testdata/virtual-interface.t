
############################################################
=TITLE=Routers connecting networks with virtual interfaces
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}
network:n3 = { ip = 10.3.3.0/24;}
network:n4 = { ip = 10.4.4.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = {ip = 10.2.2.1; hardware = E2;}
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E3;}
 interface:n3 = {ip = 10.3.3.1; {{.v1}} hardware = E4;}
}
router:r3 = {
 managed;
 model = ASA;
 interface:n2 = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E5;}
 interface:n3 = {ip = 10.3.3.2; {{.v2}} hardware = E6;}
}
router:r4 = {
 model = ASA;
 managed;
 interface:n3 = {ip = 10.3.3.3; hardware = E7;}
 interface:n4 = {ip = 10.4.4.1; hardware = E8;}
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=
=INPUT=
[[input
v1: "virtual = {ip = 10.3.3.9;}"
v2: "virtual = {ip = 10.3.3.9;}"
]]
=OUTPUT=
--r1
route E2 10.4.4.0 255.255.255.0 10.2.2.9
--r4
route E7 10.1.1.0 255.255.255.0 10.3.3.9
=END=

############################################################
=TITLE=Missing virtual interfaces on backward path
=INPUT=[[input {v1: "", v2: ""}]]
=ERROR=
Error: Ambiguous static routes for network:n1 at interface:r4.n3 via
 - interface:r2.n3
 - interface:r3.n3
=END=

############################################################
=TITLE=One missing virtual interface on backward path
=INPUT=[[input {v1: "virtual = {ip = 10.3.3.9;}", v2: ""}]]
=ERROR=
Error: Ambiguous static routes for network:n1 at interface:r4.n3 via
 - interface:r2.n3.virtual
 - interface:r3.n3
=END=

############################################################
