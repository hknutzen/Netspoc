############################################################
=TITLE=Need VRF
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=ERROR=
Error: Must use VRF ('@...' in name) at router:r1 of model NSX
=END=

############################################################
=TITLE=Need tier specified by extension
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@vrf = {
 model = NSX;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=ERROR=
Error: Must add extension 'Tier-0' or 'Tier-1' at router:r1@vrf of model NSX
=END=

############################################################
=TITLE=Invalid extension
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@vrf = {
 model = NSX, T1;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=ERROR=
Error: Unknown extension in 'model' of router:r1@vrf: T1
Error: Must add extension 'Tier-0' or 'Tier-1' at router:r1@vrf of model NSX
=END=

############################################################
=TITLE=Need management_instance
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
router:r1@v2 = {
 model = NSX, Tier-1;
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
=TITLE=management_instance has wrong model
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, Tier-1;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=ERROR=
Error: router:r1@v1 and router:r1 must have identical model
=END=

############################################################
=TITLE=backup_of has wrong model
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = 10.1.1.99; }
}
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
=ERROR=
Error: router:r1 and router:r2 must have identical model
=END=

############################################################
=TITLE=Multiple interfaces with same hardware
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
 interface:n3 = { ip = 10.1.3.1; hardware = IN; }
}
=ERROR=
Error: Different interfaces must not share same hardware 'IN' at router:r1@v1 of model NSX
=END=

############################################################
=TITLE=Wrong number of interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
}
router:r1@v2 = {
 model = NSX, Tier-1;
 managed;
 interface:n1 = { ip = 10.1.1.3; hardware = IN; }
 interface:n2 = { ip = 10.1.2.3; hardware = OUT; }
 interface:n3 = { ip = 10.1.3.3; hardware = DMZ; }
}
=ERROR=
Error: router:r1@v1 of model NSX must have exactly 2 interfaces with hardware IN and OUT
Error: router:r1@v2 of model NSX must have exactly 2 interfaces with hardware IN and OUT
=END=

############################################################
=TITLE=Wrong hardware of interfaces
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = I; }
 interface:n2 = { ip = 10.1.2.3; hardware = O; }
}
=ERROR=
Error: router:r1@v1 of model NSX must have exactly 2 interfaces with hardware IN and OUT
=END=

############################################################
=TITLE=Simple rules, use backup_of
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h20 = { ip = 10.1.1.20; }
}
network:n2 = { ip = 10.1.2.0/24;
 host:h30 = { ip = 10.1.2.30; }
 host:h40 = { ip = 10.1.2.40; }
}
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r2 = {
 model = NSX;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = 10.1.1.9; }
}
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
router:r1@v2 = {
 model = NSX, Tier-1;
 managed;
 interface:n1 = { ip = 10.1.1.3; hardware = IN; }
 interface:n3 = { ip = 10.1.3.1; hardware = OUT; }
}
service:s1 = {
 user = host:h10, host:h20;
 deny src = user; dst = any:[network:n2]; prt = tcp 22;
 permit src = user; dst = host:h30; prt = tcp;
}
protocol:NTP = udp 123:123;
protocol:sPort = udp 123:1-65535;
service:s2 = {
 user = host:h10;
 permit src = user; dst = network:n3; prt = protocol:NTP;
 permit src = user; dst = network:n3; prt = tcp 80, tcp 8080;
}
service:s3 = {
 user = host:h20;
 permit src = user; dst = network:n3; prt = protocol:sPort;
}
service:s4 = {
 user = host:h30, host:h40;
 permit src = user; dst = network:n3; prt = tcp 81;
}
=OUTPUT=
--r1
Generated by Netspoc, version devel
--
[ BEGIN r1, r2 ]
[ Model = NSX ]
[ IP = 10.1.1.1, 10.1.1.9 ]
--
[
 {
  "expression": [
   {
    "ip_addresses": [
     "10.1.1.10",
     "10.1.1.20"
    ],
    "resource_type": "IPAddressExpression"
   }
  ],
  "path": "/infra/domains/default/groups/Netspoc-g0"
 },
 {
  "expression": [
   {
    "ip_addresses": [
     "10.1.2.30",
     "10.1.2.40"
    ],
    "resource_type": "IPAddressExpression"
   }
  ],
  "path": "/infra/domains/default/groups/Netspoc-g1"
 },
 {
  "display_name": "Netspoc-tcp",
  "path": "/infra/services/Netspoc-tcp",
  "service_entries": [
   {
    "l4_protocol": "TCP",
    "resource_type": "L4PortSetServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-tcp 22",
  "path": "/infra/services/Netspoc-tcp 22",
  "service_entries": [
   {
    "destination_ports": [
     "22"
    ],
    "l4_protocol": "TCP",
    "resource_type": "L4PortSetServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-tcp 80",
  "path": "/infra/services/Netspoc-tcp 80",
  "service_entries": [
   {
    "destination_ports": [
     "80"
    ],
    "l4_protocol": "TCP",
    "resource_type": "L4PortSetServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-tcp 8080",
  "path": "/infra/services/Netspoc-tcp 8080",
  "service_entries": [
   {
    "destination_ports": [
     "8080"
    ],
    "l4_protocol": "TCP",
    "resource_type": "L4PortSetServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-tcp 81",
  "path": "/infra/services/Netspoc-tcp 81",
  "service_entries": [
   {
    "destination_ports": [
     "81"
    ],
    "l4_protocol": "TCP",
    "resource_type": "L4PortSetServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-udp 123:1-65535",
  "path": "/infra/services/Netspoc-udp 123:1-65535",
  "service_entries": [
   {
    "l4_protocol": "UDP",
    "resource_type": "L4PortSetServiceEntry",
    "source_ports": [
     "123"
    ]
   }
  ]
 },
 {
  "display_name": "Netspoc-udp 123:123",
  "path": "/infra/services/Netspoc-udp 123:123",
  "service_entries": [
   {
    "destination_ports": [
     "123"
    ],
    "l4_protocol": "UDP",
    "resource_type": "L4PortSetServiceEntry",
    "source_ports": [
     "123"
    ]
   }
  ]
 },
 {
  "display_name": "Netspoc-v1",
  "id": "Netspoc-v1",
  "path": "/infra/domains/default/gateway-policies/Netspoc-v1",
  "resource_type": "GatewayPolicy",
  "rules": [
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "OUT",
    "id": "Netspoc-1",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 10,
    "services": [
     "Netspoc-tcp 22"
    ],
    "source_groups": [
     "Netspoc-g0"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.2.30"
    ],
    "direction": "OUT",
    "id": "Netspoc-2",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-tcp"
    ],
    "source_groups": [
     "Netspoc-g0"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "OUT",
    "id": "Netspoc-3",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.3.0/24"
    ],
    "direction": "IN",
    "id": "Netspoc-4",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-tcp 81"
    ],
    "source_groups": [
     "Netspoc-g1"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "IN",
    "id": "Netspoc-5",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   }
  ]
 },
 {
  "display_name": "Netspoc-v2",
  "id": "Netspoc-v2",
  "path": "/infra/domains/default/gateway-policies/Netspoc-v2",
  "resource_type": "GatewayPolicy",
  "rules": [
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.3.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-6",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v2"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-udp 123:123"
    ],
    "source_groups": [
     "10.1.1.10"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.3.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-7",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v2"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-tcp 80"
    ],
    "source_groups": [
     "10.1.1.10"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.3.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-8",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v2"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-tcp 8080"
    ],
    "source_groups": [
     "10.1.1.10"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.3.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-9",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v2"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-udp 123:1-65535"
    ],
    "source_groups": [
     "10.1.1.20"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.3.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-10",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v2"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-tcp 81"
    ],
    "source_groups": [
     "Netspoc-g1"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "OUT",
    "id": "Netspoc-11",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v2"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "IN",
    "id": "Netspoc-12",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v2"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   }
  ]
 }
]
=END=

############################################################
=TITLE=Expand group that is used only once
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h20 = { ip = 10.1.1.20; }
}
network:n2 = { ip = 10.1.2.0/24;
 host:h30 = { ip = 10.1.2.30; }
 host:h40 = { ip = 10.1.2.40; }
}
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
service:s1 = {
 user = host:h10, host:h20;
 permit src = user; dst = host:h30, host:h40; prt = tcp 80;
}
=OUTPUT=
--r1
[
 {
  "display_name": "Netspoc-tcp 80",
  "path": "/infra/services/Netspoc-tcp 80",
  "service_entries": [
   {
    "destination_ports": [
     "80"
    ],
    "l4_protocol": "TCP",
    "resource_type": "L4PortSetServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-v1",
  "id": "Netspoc-v1",
  "path": "/infra/domains/default/gateway-policies/Netspoc-v1",
  "resource_type": "GatewayPolicy",
  "rules": [
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.2.30",
     "10.1.2.40"
    ],
    "direction": "OUT",
    "id": "Netspoc-1",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-tcp 80"
    ],
    "source_groups": [
     "10.1.1.10",
     "10.1.1.20"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "OUT",
    "id": "Netspoc-2",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "IN",
    "id": "Netspoc-3",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   }
  ]
 }
]
=END=

############################################################
=TITLE=Without rules
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, Tier-1;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
=OUTPUT=
--r1
[
 {
  "display_name": "Netspoc-v1",
  "id": "Netspoc-v1",
  "path": "/infra/domains/default/gateway-policies/Netspoc-v1",
  "resource_type": "GatewayPolicy",
  "rules": [
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "OUT",
    "id": "Netspoc-1",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "IN",
    "id": "Netspoc-2",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-1s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   }
  ]
 }
]
=END=

############################################################
=TITLE=ICMP and numeric protocol
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, Tier-0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = icmp 8, icmp 5/0, proto 52;
}
=OUTPUT=
--r1
[
 {
  "display_name": "Netspoc-icmp 5/0",
  "path": "/infra/services/Netspoc-icmp 5/0",
  "service_entries": [
   {
    "icmp_code": 0,
    "icmp_type": 5,
    "protocol": "ICMPv4",
    "resource_type": "IcmpTypeServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-icmp 8",
  "path": "/infra/services/Netspoc-icmp 8",
  "service_entries": [
   {
    "icmp_type": 8,
    "protocol": "ICMPv4",
    "resource_type": "IcmpTypeServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-proto 52",
  "path": "/infra/services/Netspoc-proto 52",
  "service_entries": [
   {
    "protocol_number": 52,
    "resource_type": "IpProtocolServiceEntry"
   }
  ]
 },
 {
  "display_name": "Netspoc-v1",
  "id": "Netspoc-v1",
  "path": "/infra/domains/default/gateway-policies/Netspoc-v1",
  "resource_type": "GatewayPolicy",
  "rules": [
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.2.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-1",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-icmp 8"
    ],
    "source_groups": [
     "10.1.1.0/24"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.2.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-2",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-icmp 5/0"
    ],
    "source_groups": [
     "10.1.1.0/24"
    ]
   },
   {
    "action": "ALLOW",
    "destination_groups": [
     "10.1.2.0/24"
    ],
    "direction": "OUT",
    "id": "Netspoc-3",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 20,
    "services": [
     "Netspoc-proto 52"
    ],
    "source_groups": [
     "10.1.1.0/24"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "OUT",
    "id": "Netspoc-4",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   },
   {
    "action": "DROP",
    "destination_groups": [
     "ANY"
    ],
    "direction": "IN",
    "id": "Netspoc-5",
    "resource_type": "Rule",
    "scope": [
     "/infra/tier-0s/v1"
    ],
    "sequence_number": 30,
    "services": [
     "ANY"
    ],
    "source_groups": [
     "ANY"
    ]
   }
  ]
 }
]
=END=