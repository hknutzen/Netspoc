############################################################
=TITLE=Need VRF
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = CHECKPOINT;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=ERROR=
Error: Must use VRF ('@...' in name) at router:r1 of model CHECKPOINT
=END=

############################################################
=TITLE=Need management_instance
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@v1 = {
 model = CHECKPOINT;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
router:r1@v2 = {
 model = CHECKPOINT;
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
=TITLE=Info file, IP header, 2 routes, single service
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 host:h3 = { ip = 10.1.3.10; }
}
network:mgmt = { ip = 10.0.0.0/24; }

router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:mgmt = { ip = 10.0.0.10; }
}

router:r1@v2 = {
 managed;
 model = CHECKPOINT;
 interface:mgmt      = { ip = 10.0.0.1; hardware = mgmt; }
 interface:Loopback0 = { ip = 10.250.2.250; loopback; hardware = loopback; }
 interface:n2        = { ip = 10.1.2.1; hardware = n2v2; }
}

router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:mgmt     = { ip = 10.0.0.2; hardware = mgmt; }
 interface:n1       = { ip = 10.1.1.1; hardware = n1v1; }
}

router:u1 = {
 interface:n1 = { ip = 10.1.1.2; }
}

router:u2 = {
 interface:n2 = { ip = 10.1.2.4; }
 interface:n3 = { ip = 10.1.3.2; }
}

service:test = {
 user = host:h3;
 permit src = user;
        dst = interface:r1@v1.n1,
              interface:r1@v2.n2,
              ;
        prt = tcp 22 - 24;
 deny   src = user;
        dst = interface:u1.n1;
        prt = tcp 81;
}

=OUTPUT=
--r1.info
{"generated_by":"devel","model":"CHECKPOINT","ip_list":["10.0.0.10"],"name_list":["r1"]}
--r1
{
 "Rules": [
  {
   "name": "test",
   "action": "Drop",
   "source": [
    "host_h3"
   ],
   "destination": [
    "interface_u1.n1"
   ],
   "service": [
    "tcp 81"
   ],
   "install-on": [
    "v1"
   ]
  },
  {
   "name": "test",
   "action": "Drop",
   "source": [
    "host_h3"
   ],
   "destination": [
    "interface_u1.n1"
   ],
   "service": [
    "tcp 81"
   ],
   "install-on": [
    "v2"
   ]
  },
  {
   "name": "test-2",
   "action": "Allow",
   "source": [
    "host_h3"
   ],
   "destination": [
    "interface_r1@v1.n1"
   ],
   "service": [
    "tcp 22-24"
   ],
   "install-on": [
    "v2"
   ]
  }
 ],
 "Networks": null,
 "Hosts": [
  {
   "name": "host_h3",
   "ipv4-address": "10.1.3.10"
  },
  {
   "name": "interface_r1@v1.n1",
   "ipv4-address": "10.1.1.1"
  },
  {
   "name": "interface_u1.n1",
   "ipv4-address": "10.1.1.2"
  }
 ],
 "Groups": null,
 "TCP": [
  {
   "name": "tcp 22-24",
   "port": "22-24"
  },
  {
   "name": "tcp 81",
   "port": "81"
  }
 ],
 "UDP": null,
 "GatewayRoutes": {
  "v1": [
   {
    "address": "10.1.3.0",
    "mask-length": 24,
    "type": "gateway",
    "next-hop": [
     {
      "gateway": "10.0.0.1"
     }
    ]
   }
  ],
  "v2": [
   {
    "address": "10.1.1.0",
    "mask-length": 24,
    "type": "gateway",
    "next-hop": [
     {
      "gateway": "10.0.0.2"
     }
    ]
   },
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

############################################################
=TITLE=2 routes with same address but different mask length
=INPUT=
network:n1 = { ip = 10.1.0.0/23; }
network:n2 = { ip = 10.1.0.0/24; subnet_of = network:n1; }
network:n3 = { ip = 10.3.0.0/24; }
network:n4 = { ip = 10.4.0.0/24; }
router:u1 = {
 interface:n1;
 interface:n3 = { ip = 10.3.0.1; }
}
router:u2 = {
 interface:n2;
 interface:n3 = { ip = 10.3.0.2; }
}
router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n3 = { ip = 10.3.0.3; }
}
router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:n3 = { ip = 10.3.0.4; hardware = n3v1; }
 interface:n4 = { ip = 10.4.0.1; hardware = n4v1; }
}
service:s1 = {
 user = network:n4;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:s2 = {
 user = network:n4;
 permit src = user; dst = network:n2; prt = tcp 23;
}
=OUTPUT=
--r1
{
 "Rules":[{"name":"s1","action":"Allow","source":["network_n4"],"destination":["network_n1"],"service":["tcp 22"],"install-on":["v1"]},{"name":"s2","action":"Allow","source":["network_n4"],"destination":["network_n2"],"service":["tcp 23"],"install-on":["v1"]}],
 "Networks": [
   {
     "name": "network_n1",
     "subnet4": "10.1.0.0",
     "mask-length4": 23
   },
   {
     "name": "network_n2",
     "subnet4": "10.1.0.0",
     "mask-length4": 24
   },
   {
     "name": "network_n4",
     "subnet4": "10.4.0.0",
     "mask-length4": 24
   }
 ],
 "Hosts":null,
 "Groups":null,
 "TCP":[{"name":"tcp 22","port":"22"},{"name":"tcp 23","port":"23"}],
 "UDP":null,
 "GatewayRoutes": {
    "v1": [
      {
        "address": "10.1.0.0",
        "mask-length": 23,
        "type": "gateway",
        "next-hop": [
          {
            "gateway": "10.3.0.1"
          }
        ]
      },
      {
        "address": "10.1.0.0",
        "mask-length": 24,
        "type": "gateway",
        "next-hop": [
          {
            "gateway": "10.3.0.2"
          }
        ]
      }
    ]
  }
 }
=END=

############################################################
=TEMPL=topology
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n2 = { ip = 10.1.2.1; }
}
router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:n1 = { ip = 10.1.1.1; hardware = n1v1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2v1; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.4; }
 interface:n3 = { ip = 10.1.3.2; }
}
=END=

############################################################
=TITLE=Can't write output file
=SETUP=
mkdir -p out/.prev
mkdir out/r1
=INPUT=
[[topology]]
=WITH_OUTDIR=
=ERROR=
Error: Can't open out/r1: is a directory
Aborted
=END=

############################################################
=TITLE=single service
=INPUT=
[[topology]]
service:test = {
 user = host:h3;
 permit src = user; dst = network:n1; prt = udp 22, tcp 22;
 deny src = user; dst = host:h1; prt = tcp 23, tcp 24;
}
=OUTPUT=
--r1
{
 "Rules": [
  {
    "name": "test",
    "action": "Drop",
    "source": [
      "host_h3"
    ],
    "destination": [
      "host_h1"
    ],
    "service": [
      "tcp 23",
      "tcp 24"
    ],
    "install-on": [
      "v1"
    ]
  },
  {
   "name": "test-2",
   "action": "Allow",
   "source": [
    "host_h3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "udp 22",
    "tcp 22"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": [
  {
   "name": "network_n1",
   "subnet4": "10.1.1.0",
   "mask-length4": 24
  }
 ],
 "Hosts": [
  {
   "name": "host_h1",
   "ipv4-address": "10.1.1.10"
  },
  {
   "name": "host_h3",
   "ipv4-address": "10.1.3.10"
  }
 ],
 "Groups": null,
 "TCP": [
  {
   "name": "tcp 22",
   "port": "22"
  },
  {
   "name": "tcp 23",
   "port": "23"
  },
  {
   "name": "tcp 24",
   "port": "24"
  }
 ],
 "UDP": [
  {
   "name": "udp 22",
   "port": "22"
  }
 ],
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
  ]
 }
}
=END=

############################################################
=TITLE=two services
=INPUT=
[[topology]]
service:test = {
 user = host:h3;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h3;
 deny src = user; dst = host:h1; prt = tcp 23;
}
=OUTPUT=
--r1
{
 "Rules": [
  {
   "name": "test",
   "action": "Allow",
   "source": [
    "host_h3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "tcp 22"
   ],
   "install-on": [
    "v1"
   ]
  },
  {
   "name": "test2",
   "action": "Drop",
   "source": [
    "host_h3"
   ],
   "destination": [
    "host_h1"
   ],
   "service": [
    "tcp 23"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": [
  {
   "name": "network_n1",
   "subnet4": "10.1.1.0",
   "mask-length4": 24
  }
 ],
 "Hosts": [
  {
   "name": "host_h1",
   "ipv4-address": "10.1.1.10"
  },
  {
   "name": "host_h3",
   "ipv4-address": "10.1.3.10"
  }
 ],
 "Groups": null,
 "TCP": [
  {
   "name": "tcp 22",
   "port": "22"
  },
  {
   "name": "tcp 23",
   "port": "23"
  }
 ],
 "UDP": null,
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
  ]
 }
}
=END=
############################################################
=TITLE=icmp service
=INPUT=
[[topology]]
service:test = {
 user = host:h3;
 permit src = user;
        dst = network:n1;
        prt = icmp 0,
              icmp 3,
              icmp 4,
              icmp 5,
              icmp 8,
              icmp 11,
              icmp 12,
              icmp 13,
              icmp 14,
              icmp 15,
              icmp 16,
              icmp 17,
              icmp 18,
              ;
}
=OUTPUT=
--r1
{
 "Rules": [
  {
   "name": "test",
   "action": "Allow",
   "source": [
    "host_h3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "source-quench",
    "redirect",
    "echo-request",
    "param-prblm",
    "timestamp",
    "timestamp-reply",
    "info-req",
    "info-reply",
    "mask-request",
    "mask-reply"
   ],
   "install-on": [
    "v1"
   ]
  },
  {
   "name": "test-2",
   "action": "Allow",
   "source": [
    "host_h3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "echo-reply"
   ],
   "install-on": [
    "v1"
   ]
  },
  {
   "name": "test-3",
   "action": "Allow",
   "source": [
    "host_h3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "dest-unreach"
   ],
   "install-on": [
    "v1"
   ]
  },
  {
   "name": "test-4",
   "action": "Allow",
   "source": [
    "host_h3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "time-exceeded"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": [
  {
   "name": "network_n1",
   "subnet4": "10.1.1.0",
   "mask-length4": 24
  }
 ],
 "Hosts": [
  {
   "name": "host_h3",
   "ipv4-address": "10.1.3.10"
  }
 ],
 "Groups": null,
 "TCP": null,
 "UDP": null,
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
  ]
 }
}
=END=

############################################################
=TITLE= service with 100 members in rule
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h01 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
  host:h1 = { ip = 10.1.3.12; } host:h2 = { ip = 10.1.3.14; } host:h3 = { ip = 10.1.3.16; } host:h4 = { ip = 10.1.3.18; } host:h5 = { ip = 10.1.3.20; } host:h6 = { ip = 10.1.3.22; } host:h7 = { ip = 10.1.3.24; } host:h8 = { ip = 10.1.3.26; } host:h9 = { ip = 10.1.3.28; } host:h10 = { ip = 10.1.3.30; } host:h11 = { ip = 10.1.3.32; } host:h12 = { ip = 10.1.3.34; } host:h13 = { ip = 10.1.3.36; } host:h14 = { ip = 10.1.3.38; } host:h15 = { ip = 10.1.3.40; } host:h16 = { ip = 10.1.3.42; } host:h17 = { ip = 10.1.3.44; } host:h18 = { ip = 10.1.3.46; } host:h19 = { ip = 10.1.3.48; } host:h20 = { ip = 10.1.3.50; } host:h21 = { ip = 10.1.3.52; } host:h22 = { ip = 10.1.3.54; } host:h23 = { ip = 10.1.3.56; } host:h24 = { ip = 10.1.3.58; } host:h25 = { ip = 10.1.3.60; } host:h26 = { ip = 10.1.3.62; } host:h27 = { ip = 10.1.3.64; } host:h28 = { ip = 10.1.3.66; } host:h29 = { ip = 10.1.3.68; } host:h30 = { ip = 10.1.3.70; } host:h31 = { ip = 10.1.3.72; } host:h32 = { ip = 10.1.3.74; } host:h33 = { ip = 10.1.3.76; } host:h34 = { ip = 10.1.3.78; } host:h35 = { ip = 10.1.3.80; } host:h36 = { ip = 10.1.3.82; } host:h37 = { ip = 10.1.3.84; } host:h38 = { ip = 10.1.3.86; } host:h39 = { ip = 10.1.3.88; } host:h40 = { ip = 10.1.3.90; } host:h41 = { ip = 10.1.3.92; } host:h42 = { ip = 10.1.3.94; } host:h43 = { ip = 10.1.3.96; } host:h44 = { ip = 10.1.3.98; } host:h45 = { ip = 10.1.3.100; } host:h46 = { ip = 10.1.3.102; } host:h47 = { ip = 10.1.3.104; } host:h48 = { ip = 10.1.3.106; } host:h49 = { ip = 10.1.3.108; } host:h50 = { ip = 10.1.3.110; } host:h51 = { ip = 10.1.3.112; } host:h52 = { ip = 10.1.3.114; } host:h53 = { ip = 10.1.3.116; } host:h54 = { ip = 10.1.3.118; } host:h55 = { ip = 10.1.3.120; } host:h56 = { ip = 10.1.3.122; } host:h57 = { ip = 10.1.3.124; } host:h58 = { ip = 10.1.3.126; } host:h59 = { ip = 10.1.3.128; } host:h60 = { ip = 10.1.3.130; } host:h61 = { ip = 10.1.3.132; } host:h62 = { ip = 10.1.3.134; } host:h63 = { ip = 10.1.3.136; } host:h64 = { ip = 10.1.3.138; } host:h65 = { ip = 10.1.3.140; } host:h66 = { ip = 10.1.3.142; } host:h67 = { ip = 10.1.3.144; } host:h68 = { ip = 10.1.3.146; } host:h69 = { ip = 10.1.3.148; } host:h70 = { ip = 10.1.3.150; } host:h71 = { ip = 10.1.3.152; } host:h72 = { ip = 10.1.3.154; } host:h73 = { ip = 10.1.3.156; } host:h74 = { ip = 10.1.3.158; } host:h75 = { ip = 10.1.3.160; } host:h76 = { ip = 10.1.3.162; } host:h77 = { ip = 10.1.3.164; } host:h78 = { ip = 10.1.3.166; } host:h79 = { ip = 10.1.3.168; } host:h80 = { ip = 10.1.3.170; } host:h81 = { ip = 10.1.3.172; } host:h82 = { ip = 10.1.3.174; } host:h83 = { ip = 10.1.3.176; } host:h84 = { ip = 10.1.3.178; } host:h85 = { ip = 10.1.3.180; } host:h86 = { ip = 10.1.3.182; } host:h87 = { ip = 10.1.3.184; } host:h88 = { ip = 10.1.3.186; } host:h89 = { ip = 10.1.3.188; } host:h90 = { ip = 10.1.3.190; } host:h91 = { ip = 10.1.3.192; } host:h92 = { ip = 10.1.3.194; } host:h93 = { ip = 10.1.3.196; } host:h94 = { ip = 10.1.3.198; } host:h95 = { ip = 10.1.3.200; } host:h96 = { ip = 10.1.3.202; } host:h97 = { ip = 10.1.3.204; } host:h98 = { ip = 10.1.3.206; } host:h99 = { ip = 10.1.3.208; } host:h100 = { ip = 10.1.3.210; }
}

router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n2 = { ip = 10.1.2.1; }
}
router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:n1 = { ip = 10.1.1.1; hardware = n1v1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2v1; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.4; }
 interface:n3 = { ip = 10.1.3.2; }
}
service:test = {
 user = host:[network:n3];
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
-- r1
{
 "Rules": [
  {
   "name": "test",
   "action": "Allow",
   "source": [
    "SrcGrp_test"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "tcp 80"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": [
  {
   "name": "network_n1",
   "subnet4": "10.1.1.0",
   "mask-length4": 24
  }
 ],
 "Hosts": [{"name":"host_h1","ipv4-address":"10.1.3.12"},{"name":"host_h10","ipv4-address":"10.1.3.30"},{"name":"host_h100","ipv4-address":"10.1.3.210"},{"name":"host_h11","ipv4-address":"10.1.3.32"},{"name":"host_h12","ipv4-address":"10.1.3.34"},{"name":"host_h13","ipv4-address":"10.1.3.36"},{"name":"host_h14","ipv4-address":"10.1.3.38"},{"name":"host_h15","ipv4-address":"10.1.3.40"},{"name":"host_h16","ipv4-address":"10.1.3.42"},{"name":"host_h17","ipv4-address":"10.1.3.44"},{"name":"host_h18","ipv4-address":"10.1.3.46"},{"name":"host_h19","ipv4-address":"10.1.3.48"},{"name":"host_h2","ipv4-address":"10.1.3.14"},{"name":"host_h20","ipv4-address":"10.1.3.50"},{"name":"host_h21","ipv4-address":"10.1.3.52"},{"name":"host_h22","ipv4-address":"10.1.3.54"},{"name":"host_h23","ipv4-address":"10.1.3.56"},{"name":"host_h24","ipv4-address":"10.1.3.58"},{"name":"host_h25","ipv4-address":"10.1.3.60"},{"name":"host_h26","ipv4-address":"10.1.3.62"},{"name":"host_h27","ipv4-address":"10.1.3.64"},{"name":"host_h28","ipv4-address":"10.1.3.66"},{"name":"host_h29","ipv4-address":"10.1.3.68"},{"name":"host_h3","ipv4-address":"10.1.3.16"},{"name":"host_h30","ipv4-address":"10.1.3.70"},{"name":"host_h31","ipv4-address":"10.1.3.72"},{"name":"host_h32","ipv4-address":"10.1.3.74"},{"name":"host_h33","ipv4-address":"10.1.3.76"},{"name":"host_h34","ipv4-address":"10.1.3.78"},{"name":"host_h35","ipv4-address":"10.1.3.80"},{"name":"host_h36","ipv4-address":"10.1.3.82"},{"name":"host_h37","ipv4-address":"10.1.3.84"},{"name":"host_h38","ipv4-address":"10.1.3.86"},{"name":"host_h39","ipv4-address":"10.1.3.88"},{"name":"host_h4","ipv4-address":"10.1.3.18"},{"name":"host_h40","ipv4-address":"10.1.3.90"},{"name":"host_h41","ipv4-address":"10.1.3.92"},{"name":"host_h42","ipv4-address":"10.1.3.94"},{"name":"host_h43","ipv4-address":"10.1.3.96"},{"name":"host_h44","ipv4-address":"10.1.3.98"},{"name":"host_h45","ipv4-address":"10.1.3.100"},{"name":"host_h46","ipv4-address":"10.1.3.102"},{"name":"host_h47","ipv4-address":"10.1.3.104"},{"name":"host_h48","ipv4-address":"10.1.3.106"},{"name":"host_h49","ipv4-address":"10.1.3.108"},{"name":"host_h5","ipv4-address":"10.1.3.20"},{"name":"host_h50","ipv4-address":"10.1.3.110"},{"name":"host_h51","ipv4-address":"10.1.3.112"},{"name":"host_h52","ipv4-address":"10.1.3.114"},{"name":"host_h53","ipv4-address":"10.1.3.116"},{"name":"host_h54","ipv4-address":"10.1.3.118"},{"name":"host_h55","ipv4-address":"10.1.3.120"},{"name":"host_h56","ipv4-address":"10.1.3.122"},{"name":"host_h57","ipv4-address":"10.1.3.124"},{"name":"host_h58","ipv4-address":"10.1.3.126"},{"name":"host_h59","ipv4-address":"10.1.3.128"},{"name":"host_h6","ipv4-address":"10.1.3.22"},{"name":"host_h60","ipv4-address":"10.1.3.130"},{"name":"host_h61","ipv4-address":"10.1.3.132"},{"name":"host_h62","ipv4-address":"10.1.3.134"},{"name":"host_h63","ipv4-address":"10.1.3.136"},{"name":"host_h64","ipv4-address":"10.1.3.138"},{"name":"host_h65","ipv4-address":"10.1.3.140"},{"name":"host_h66","ipv4-address":"10.1.3.142"},{"name":"host_h67","ipv4-address":"10.1.3.144"},{"name":"host_h68","ipv4-address":"10.1.3.146"},{"name":"host_h69","ipv4-address":"10.1.3.148"},{"name":"host_h7","ipv4-address":"10.1.3.24"},{"name":"host_h70","ipv4-address":"10.1.3.150"},{"name":"host_h71","ipv4-address":"10.1.3.152"},{"name":"host_h72","ipv4-address":"10.1.3.154"},{"name":"host_h73","ipv4-address":"10.1.3.156"},{"name":"host_h74","ipv4-address":"10.1.3.158"},{"name":"host_h75","ipv4-address":"10.1.3.160"},{"name":"host_h76","ipv4-address":"10.1.3.162"},{"name":"host_h77","ipv4-address":"10.1.3.164"},{"name":"host_h78","ipv4-address":"10.1.3.166"},{"name":"host_h79","ipv4-address":"10.1.3.168"},{"name":"host_h8","ipv4-address":"10.1.3.26"},{"name":"host_h80","ipv4-address":"10.1.3.170"},{"name":"host_h81","ipv4-address":"10.1.3.172"},{"name":"host_h82","ipv4-address":"10.1.3.174"},{"name":"host_h83","ipv4-address":"10.1.3.176"},{"name":"host_h84","ipv4-address":"10.1.3.178"},{"name":"host_h85","ipv4-address":"10.1.3.180"},{"name":"host_h86","ipv4-address":"10.1.3.182"},{"name":"host_h87","ipv4-address":"10.1.3.184"},{"name":"host_h88","ipv4-address":"10.1.3.186"},{"name":"host_h89","ipv4-address":"10.1.3.188"},{"name":"host_h9","ipv4-address":"10.1.3.28"},{"name":"host_h90","ipv4-address":"10.1.3.190"},{"name":"host_h91","ipv4-address":"10.1.3.192"},{"name":"host_h92","ipv4-address":"10.1.3.194"},{"name":"host_h93","ipv4-address":"10.1.3.196"},{"name":"host_h94","ipv4-address":"10.1.3.198"},{"name":"host_h95","ipv4-address":"10.1.3.200"},{"name":"host_h96","ipv4-address":"10.1.3.202"},{"name":"host_h97","ipv4-address":"10.1.3.204"},{"name":"host_h98","ipv4-address":"10.1.3.206"},{"name":"host_h99","ipv4-address":"10.1.3.208"}],
 "Groups":[
   {
     "name": "SrcGrp_test",
     "members": ["host_h1", "host_h10", "host_h100", "host_h11", "host_h12", "host_h13", "host_h14", "host_h15", "host_h16", "host_h17", "host_h18", "host_h19", "host_h2", "host_h20", "host_h21", "host_h22", "host_h23", "host_h24", "host_h25", "host_h26", "host_h27", "host_h28", "host_h29", "host_h3", "host_h30", "host_h31", "host_h32", "host_h33", "host_h34", "host_h35", "host_h36", "host_h37", "host_h38", "host_h39", "host_h4", "host_h40", "host_h41", "host_h42", "host_h43", "host_h44", "host_h45", "host_h46", "host_h47", "host_h48", "host_h49", "host_h5", "host_h50", "host_h51", "host_h52", "host_h53", "host_h54", "host_h55", "host_h56", "host_h57", "host_h58", "host_h59", "host_h6", "host_h60", "host_h61", "host_h62", "host_h63", "host_h64", "host_h65", "host_h66", "host_h67", "host_h68", "host_h69", "host_h7", "host_h70", "host_h71", "host_h72", "host_h73", "host_h74", "host_h75", "host_h76", "host_h77", "host_h78", "host_h79", "host_h8", "host_h80", "host_h81", "host_h82", "host_h83", "host_h84", "host_h85", "host_h86", "host_h87", "host_h88", "host_h89", "host_h9", "host_h90", "host_h91", "host_h92", "host_h93", "host_h94", "host_h95", "host_h96", "host_h97", "host_h98", "host_h99"]
   }
 ],
 "TCP": [
  {
   "name": "tcp 80",
   "port": "80"
  }
 ],
 "UDP": null,
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
  ]
 }
}
=END=

############################################################
=TITLE= service with range host
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { range = 10.1.1.10-10.1.1.30; } }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }
router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n2 = { ip = 10.1.2.1; }
}
router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:n1 = { ip = 10.1.1.1; hardware = n1v1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2v1; }
}
service:test = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = tcp 22;
}
=OUTPUT=
-- r1
{
 "Rules": [
  {
   "name": "test",
   "action": "Allow",
   "source": [
    "host_h1",
    "host_h1_part-2",
    "host_h1_part-3",
    "host_h1_part-4",
    "host_h1_part-5",
    "host_h1_part-6"
   ],
   "destination": [
    "host_h2"
   ],
   "service": [
    "tcp 22"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": [
  {
   "name": "host_h1",
   "subnet4": "10.1.1.10",
   "mask-length4": 31
  },
  {
   "name": "host_h1_part-2",
   "subnet4": "10.1.1.12",
   "mask-length4": 30
  },
  {
   "name": "host_h1_part-3",
   "subnet4": "10.1.1.16",
   "mask-length4": 29
  },
  {
   "name": "host_h1_part-4",
   "subnet4": "10.1.1.24",
   "mask-length4": 30
  },
  {
   "name": "host_h1_part-5",
   "subnet4": "10.1.1.28",
   "mask-length4": 31
  }
 ],
 "Hosts": [
  {
   "name": "host_h1_part-6",
   "ipv4-address": "10.1.1.30"
  },
  {
   "name": "host_h2",
   "ipv4-address": "10.1.2.10"
  }
 ],
 "Groups": null,
 "TCP": [
  {
   "name": "tcp 22",
   "port": "22"
  }
 ],
 "UDP": null,
 "GatewayRoutes": {
  "v1": null
 }
}
=END=

############################################################
=TITLE= overlapping port ranges
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
}

network:n2 = {
 ip = 10.1.2.0/24;
 host:h2 = { ip = 10.1.2.10; }
 host:h3 = { ip = 10.1.2.20; }
}

router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n2 = { ip = 10.1.2.1; }
}

router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:n1 = { ip = 10.1.1.1; hardware = n1v1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2v1; }
}

service:a = {
 user = host:h1;
 permit src = user;
        dst = host:h2;
        prt = tcp 22 - 30;
}

service:b = {
 user = host:h1;
 permit src = user;
        dst = host:h3;
        prt = tcp 28 - 36;
}
=OUTPUT=
--r1
{
 "Rules": [
  {
   "name": "a",
   "action": "Allow",
   "source": [
    "host_h1"
   ],
   "destination": [
    "host_h2"
   ],
   "service": [
    "tcp 22-30"
   ],
   "install-on": [
    "v1"
   ]
  },
  {
   "name": "b",
   "action": "Allow",
   "source": [
    "host_h1"
   ],
   "destination": [
    "host_h3"
   ],
   "service": [
    "tcp 28-30",
    "tcp 31-36"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": null,
 "Hosts": [
  {
   "name": "host_h1",
   "ipv4-address": "10.1.1.10"
  },
  {
   "name": "host_h2",
   "ipv4-address": "10.1.2.10"
  },
  {
   "name": "host_h3",
   "ipv4-address": "10.1.2.20"
  }
 ],
 "Groups": null,
 "TCP": [
  {
   "name": "tcp 22-30",
   "port": "22-30"
  },
  {
   "name": "tcp 28-30",
   "port": "28-30"
  },
  {
   "name": "tcp 31-36",
   "port": "31-36"
  }
 ],
 "UDP": null,
 "GatewayRoutes": {
  "v1": null
 }
}
=END=

############################################################
=TITLE=Don't print route if routing = manual
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n2 = { ip = 10.1.2.1; }
}
router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1v1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2v1; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.4; }
 interface:n3 = { ip = 10.1.3.2; }
}
service:test = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 22;
}
=OUTPUT=
-- r1
{
 "Rules": [
  {
   "name": "test",
   "action": "Allow",
   "source": [
    "network_n3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "tcp 22"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": [
  {
   "name": "network_n1",
   "subnet4": "10.1.1.0",
   "mask-length4": 24
  },
  {
   "name": "network_n3",
   "subnet4": "10.1.3.0",
   "mask-length4": 24
  }
 ],
 "Hosts": null,
 "Groups": null,
 "TCP": [
  {
   "name": "tcp 22",
   "port": "22"
  }
 ],
 "UDP": null,
 "GatewayRoutes": {
  "v1": null
 }
}

=END=

############################################################
=TITLE=Don't print route if network is hidden by nat
#This testcase generates two times the same rule, because
#bind_nat on interface:r2.n2 devides the zonecluster of
#r2,n2 and n3 into two different zones.
#That creates one rule for each zone.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 nat:h = { hidden; }
}

router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n2 = { ip = 10.1.2.1; }
}

router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:n1 = { ip = 10.1.1.1; hardware = n1v1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2v1; }
}

router:r2 = {
 interface:n2 = { ip = 10.1.2.4; nat_out = h; }
 interface:n3 = { ip = 10.1.3.2; }
}

any:10_1 = { ip = 10.1.0.0/16; link = network:n3; }

service:test = {
 user =	network:n1;
 permit src = user; dst = any:10_1; prt = tcp 80;
}
=OUTPUT=
-- r1
{
 "Rules": [
  {
   "name": "test",
   "action": "Allow",
   "source": [
    "network_n1"
   ],
   "destination": [
    "any_10_1"
   ],
   "service": [
    "tcp 80"
   ],
   "install-on": [
    "v1"
   ]
  },
  {
   "name": "test-2",
   "action": "Allow",
   "source": [
    "network_n1"
   ],
   "destination": [
    "any_10_1"
   ],
   "service": [
    "tcp 80"
   ],
   "install-on": [
    "v1"
   ]
  }
 ],
 "Networks": [
  {
   "name": "any_10_1",
   "subnet4": "10.1.0.0",
   "mask-length4": 16
  },
  {
   "name": "network_n1",
   "subnet4": "10.1.1.0",
   "mask-length4": 24
  }
 ],
 "Hosts": null,
 "Groups": null,
 "TCP": [
  {
   "name": "tcp 80",
   "port": "80"
  }
 ],
 "UDP": null,
 "GatewayRoutes": {
  "v1": null
 }
}
=END=