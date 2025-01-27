############################################################
=TITLE=Need VRF
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = Checkpoint;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=ERROR=
Error: Must use VRF ('@...' in name) at router:r1 of model Checkpoint
=END=

############################################################
=TITLE=Need management_instance
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@v1 = {
 model = Checkpoint;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
router:r1@v2 = {
 model = Checkpoint;
 managed;
 interface:n1 = { ip = 10.1.1.3; hardware = IN; }
 interface:n2 = { ip = 10.1.2.3; hardware = OUT; }
}
=ERROR=
Error: Must define unmanaged router:r1
 with attribute 'management_instance'
 for router:r1@v1
=END=

############################################################
=TITLE=Info file, IP header, 2 routes
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 management_instance;
 model = Checkpoint;
 interface:n2 = { ip = 10.1.2.1; }
}
router:r1@v1 = {
 managed;
 model = Checkpoint;
 interface:n2 = { ip = 10.1.2.2; hardware = n2v1; }
}
router:r1@v2 = {
 managed;
 model = Checkpoint;
 interface:n2 = { ip = 10.1.2.3; hardware = n2v2; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1v2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.4; }
 interface:n3 = { ip = 10.1.3.2; }
}
service:test = {
 user = host:h3;
 permit src = user; dst = interface:r1@v1.n2,interface:r1@v2.n2; prt = tcp 22;
}
=OUTPUT=
--r1.info
{"generated_by":"devel","model":"Checkpoint","ip_list":["10.1.2.1"],"name_list":["r1"]}
--r1
{
 "GatewayRoutes": {
  "v1": [
   {
    "address": "10.1.3.0",
    "mask-length": 24,
    "type": "gateway",
    "next-hop": [
     {
      "gateway": "10.1.2.4"
     }
    ]
   }
  ],
  "v2": [
   {
    "address": "10.1.3.0",
    "mask-length": 24,
    "type": "gateway",
    "next-hop": [
     {
      "gateway": "10.1.2.4"
     }
    ]
   }
  ]
 }
}
=END=
