
############################################################
=TEMPL=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Secondary interface as area border
=INPUT=
[[topo]]
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = {
  ip = 10.1.2.3; secondary:2 = { ip = 10.1.2.4; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
area:a1 = { border = interface:asa3.n2.2; }
group:g1 = network:[area:a1];
=END=
=OUTPUT=
10.1.2.0/24	network:n2
10.1.1.0/24	network:n1
10.1.3.0/24	network:n3
=END=
=PARAM=group:g1

############################################################
=TITLE=Secondary interface with name = virtual as border
=INPUT=
[[topo]]
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = {
  ip = 10.1.2.3; secondary:virtual = { ip = 10.1.2.4; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
area:a1 = { border = interface:asa3.n2.virtual; }
group:g1 = network:[area:a1];
=END=
=OUTPUT=
10.1.2.0/24	network:n2
10.1.1.0/24	network:n1
10.1.3.0/24	network:n3
=END=
=PARAM=group:g1

############################################################
=TITLE=Virtual interface as border
=INPUT=
[[topo]]
network:n4 = { ip = 10.1.4.0/24; }
router:asa3 = {
 managed;
 model = ASA;
 interface:n2 = {
   ip = 10.1.2.3; virtual = { ip = 10.1.2.10; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:asa4 = {
 managed;
 model = ASA;
 interface:n2 = {
   ip = 10.1.2.4; virtual = { ip = 10.1.2.10; } hardware = n2; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
area:a1 = {
  border = interface:asa3.n2.virtual,
           interface:asa4.n2.virtual;
}
group:g1 = network:[area:a1];
=END=
=OUTPUT=
10.1.2.0/24	network:n2
10.1.1.0/24	network:n1
10.1.3.0/24	network:n3
=END=
=PARAM=group:g1
