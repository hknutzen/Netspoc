############################################################
=TITLE=Need VRF
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX, T0;
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
Error: Must add extension 'T0' or 'T1' at router:r1@vrf of model NSX
=END=

############################################################
=TITLE=Invalid extension
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@vrf = {
 model = NSX, Tier-1;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=ERROR=
Error: Unknown extension in 'model' of router:r1@vrf: Tier-1
Error: Must add extension 'T0' or 'T1' at router:r1@vrf of model NSX
=END=

############################################################
=TITLE=Need management_instance
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
router:r1@v2 = {
 model = NSX, T1;
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
=TITLE=Only one IPv4 management_instance
# No IPv6
=INPUT=
-- z_sort_after_ipv6
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
 interface:n1v6 = { ip6 = ::a01:102; hardware = IN; }
 interface:n2v6 = { ip6 = ::a01:201; hardware = OUT; }
}
-- ipv6
network:n1v6 = { ip6 = ::a01:100/120; }
network:n2v6 = { ip6 = ::a01:200/120; }
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"NSX","ip_list":["10.1.1.1"],"name_list":["r1"]}
--r1.info
{"generated_by":"devel","model":"NSX","ip_list":["10.1.1.1"],"name_list":["r1"]}
=END=

############################################################
=TITLE=Only one IPv6 management_instance
# No IPv6
=INPUT=
-- z_sort_after_ipv6
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
 interface:n1v6 = { ip6 = ::a01:102; hardware = IN; }
 interface:n2v6 = { ip6 = ::a01:201; hardware = OUT; }
}
-- ipv6
network:n1v6 = { ip6 = ::a01:100/120; }
network:n2v6 = { ip6 = ::a01:200/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1v6 = { ip6 = ::a01:101; }
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"NSX","ip_list":["::a01:101"],"name_list":["r1"]}
--r1.info
{"generated_by":"devel","model":"NSX","ip_list":["::a01:101"],"name_list":["r1"]}
=END=

############################################################
=TITLE=IPv4 and IPv6 management_instance
# No IPv6
=INPUT=
-- z_sort_after_ipv6
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
-- ipv6
network:n1v6 = { ip6 = ::a01:100/120; }
network:n2v6 = { ip6 = ::a01:200/120; }
router:r1-6 = {
 model = NSX;
 management_instance;
 backup_of = router:r1;
 interface:n1v6 = { ip6 = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
 interface:n1v6 = { ip6 = ::a01:102; hardware = IN; }
 interface:n2v6 = { ip6 = ::a01:201; hardware = OUT; }
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"NSX","ip_list":["10.1.1.1","::a01:101"],"name_list":["r1","r1-6"]}
--r1.info
{"generated_by":"devel","model":"NSX","ip_list":["10.1.1.1","::a01:101"],"name_list":["r1","r1-6"]}
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
 model = NSX, T1;
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
 model = NSX, T0;
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
 model = NSX, T0;
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
 model = NSX, T0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
}
router:r1@v2 = {
 model = NSX, T1;
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
 model = NSX, T0;
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
 model = NSX, T0;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
router:r1@v2 = {
 model = NSX, T1;
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
--r1.info
{"generated_by":"devel","model":"NSX","ip_list":["10.1.1.1","10.1.1.9"],"name_list":["r1","r2"]}
--r1
{
 "groups": [
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "10.1.1.10",
      "10.1.1.20"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-g0"
  },
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "10.1.2.30",
      "10.1.2.40"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-g1"
  }
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 10,
     "services": [
      "/infra/services/Netspoc-tcp_22"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "10.1.2.30"
     ],
     "direction": "OUT",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
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
     "id": "r4",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_81"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g1"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r5",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
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
   "id": "Netspoc-v2",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "ALLOW",
     "destination_groups": [
      "10.1.3.0/24"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/v2"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-udp_123:123"
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
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/v2"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
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
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/v2"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_8080"
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
     "id": "r4",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/v2"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-udp_123:1-65535"
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
     "id": "r5",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/v2"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_81"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g1"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r6",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
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
     "id": "r7",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
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
 ],
 "services": [
  {
   "id": "Netspoc-tcp",
   "service_entries": [
    {
     "destination_ports": [],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  },
  {
   "id": "Netspoc-tcp_22",
   "service_entries": [
    {
     "destination_ports": [
      "22"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  },
  {
   "id": "Netspoc-tcp_80",
   "service_entries": [
    {
     "destination_ports": [
      "80"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  },
  {
   "id": "Netspoc-tcp_8080",
   "service_entries": [
    {
     "destination_ports": [
      "8080"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  },
  {
   "id": "Netspoc-tcp_81",
   "service_entries": [
    {
     "destination_ports": [
      "81"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  },
  {
   "id": "Netspoc-udp_123:1-65535",
   "service_entries": [
    {
     "destination_ports": [],
     "id": "id",
     "l4_protocol": "UDP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": [
      "123"
     ]
    }
   ]
  },
  {
   "id": "Netspoc-udp_123:123",
   "service_entries": [
    {
     "destination_ports": [
      "123"
     ],
     "id": "id",
     "l4_protocol": "UDP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": [
      "123"
     ]
    }
   ]
  }
 ]
}
=END=

############################################################
=TITLE=Define group even if used only once
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
 model = NSX, T0;
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
{
 "groups": [
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "10.1.1.10",
      "10.1.1.20"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-g0"
  },
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "10.1.2.30",
      "10.1.2.40"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-g1"
  }
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "ALLOW",
     "destination_groups": [
      "/infra/domains/default/groups/Netspoc-g1"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
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
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
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
 ],
 "services": [
  {
   "id": "Netspoc-tcp_80",
   "service_entries": [
    {
     "destination_ports": [
      "80"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  }
 ]
}
=END=

############################################################
=TITLE=Without rules but log_deny with tag
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, T1;
 managed;
 log_deny = tag:r1@v1;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
=OUTPUT=
--r1
{
 "groups": null,
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "r1@v1"
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r2",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "r1@v1"
    }
   ]
  }
 ],
 "services": null
}
=END=

############################################################
=TITLE=Log Deny for multiple vrfs
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, T1;
 managed;
 log_deny = tag:r1@v1;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
router:r1@v2 = {
 model = NSX, T1;
 managed;
 log_deny = tag:r1@v2;
 interface:n1 = { ip = 10.1.1.3; hardware = IN; }
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
}
=OUTPUT=
--r1
{
 "groups": null,
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "r1@v1"
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r2",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "r1@v1"
    }
   ]
  },
  {
   "id": "Netspoc-v2",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "r1@v2"
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r2",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "r1@v2"
    }
   ]
  }
 ],
 "services": null
}
=END=

############################################################
=TITLE=ICMP and numeric protocol with mixed logging
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.2; } }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 log_default;
 log_deny = tag:T0;
 log:x = tag:x;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
service:s1 = {
 user = network:n1;
 deny   src = user; dst = host:h2; prt = ip; log = x;
 permit src = user; dst = network:n2; prt = icmp 8, proto 52;
 permit src = user; dst = network:n2; prt = icmp 5/0; log = x;
}
=OUTPUT=
--r1
{
 "groups": null,
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "10.1.2.2"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 10,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "10.1.1.0/24"
     ],
     "tag": "x"
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "10.1.2.0/24"
     ],
     "direction": "OUT",
     "id": "r2",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-icmp_8"
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
     "id": "r3",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-proto_52"
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
     "id": "r4",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-icmp_5/0"
     ],
     "source_groups": [
      "10.1.1.0/24"
     ],
     "tag": "x"
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r5",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "T0"
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r6",
     "ip_protocol": "IPV4",
     "logged": true,
     "profiles": [
      "ANY"
     ],
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
     ],
     "tag": "T0"
    }
   ]
  }
 ],
 "services": [
  {
   "id": "Netspoc-icmp_5/0",
   "service_entries": [
    {
     "icmp_code": 0,
     "icmp_type": 5,
     "id": "id",
     "protocol": "ICMPv4",
     "resource_type": "ICMPTypeServiceEntry"
    }
   ]
  },
  {
   "id": "Netspoc-icmp_8",
   "service_entries": [
    {
     "icmp_type": 8,
     "id": "id",
     "protocol": "ICMPv4",
     "resource_type": "ICMPTypeServiceEntry"
    }
   ]
  },
  {
   "id": "Netspoc-proto_52",
   "service_entries": [
    {
     "id": "id",
     "protocol_number": 52,
     "resource_type": "IPProtocolServiceEntry"
    }
   ]
  }
 ]
}
=END=

############################################################
=TITLE=Optimize duplicate IP address
=INPUT=
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.1; }
}

network:n1 = { ip = 10.1.1.0/24; }

router:r1@T0 = {
 model = NSX, T0;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = OUT; }
 interface:n2 = { ip = 10.1.2.1; hardware = IN; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:T0-T1 = {
 interface:n2;
 interface:n3;
 interface:n4;
}

router:r1@T1 = {
 model = NSX, T1;
 managed;
 routing = manual;
 interface:n4 = { ip = 10.1.4.1; hardware = OUT; }
 interface:n5 = { ip = 10.1.5.1; hardware = IN; }
}

network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }

service:s1 = {
 user = any:[network:n3],
        any:[network:n5],
        ;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=OUTPUT=
--r1
{
 "groups": null,
 "policies": [
  {
   "id": "Netspoc-T0",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
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
      "10.1.1.0/24"
     ],
     "direction": "OUT",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
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
     "direction": "OUT",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
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
   "id": "Netspoc-T1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/T1"
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
      "10.1.1.0/24"
     ],
     "direction": "OUT",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/T1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
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
     "direction": "OUT",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/T1"
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
 ],
 "services": [
  {
   "id": "Netspoc-tcp_80",
   "service_entries": [
    {
     "destination_ports": [
      "80"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  }
 ]
}
=END=

############################################################
=TITLE=Add policy distribution point to info file
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24;
 host:netspoc = { ip = 10.1.3.9; }
}
router:r1@vrf = {
 managed;
 model = NSX,T0;
 interface:n1 = { ip = 10.1.1.11; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
router:r1 = {
 management_instance;
 policy_distribution_point = host:netspoc;
 model = NSX;
 interface:n1 = { ip = 10.1.1.1; hardware = device; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:admin = {
 user = interface:r1.n1;
 permit src = host:netspoc; dst = user; prt = tcp 22;
}
=OUTPUT=
-- r1.info
{"generated_by":"devel","model":"NSX","ip_list":["10.1.1.1"],"name_list":["r1"],"policy_distribution_point":"10.1.3.9"}
=END=

############################################################
=TITLE=managed = local
=INPUT=
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.62.1.34; }
}

network:n1 = { ip = 10.62.1.32/27; }
router:r1@T0 = {
 model = NSX, T0;
 managed = local;
 routing = manual;
 filter_only = 10.62.0.0/21, 10.62.241.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = IN; }
 interface:n2 = { ip = 10.62.241.1; hardware = OUT; }
}
network:n2 = { ip = 10.62.241.0/29; }
router:d31 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.62.241.2; hardware = inside; }
 interface:extern = { ip = 10.125.3.1; hardware = outside; }
}
network:extern = { ip = 10.125.3.0/24; }
service:Test = {
 user = network:extern, network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=OUTPUT=
--r1
{
 "groups": [
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "10.62.0.0/21",
      "10.62.241.0/24"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-g0"
  }
 ],
 "policies": [
  {
   "id": "Netspoc-T0",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ],
     "direction": "OUT",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 10,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 20,
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
      "10.62.1.32/27"
     ],
     "direction": "IN",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
     ],
     "source_groups": [
      "10.62.241.0/29"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ],
     "direction": "IN",
     "id": "r4",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 30,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r5",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 40,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "ANY"
     ]
    }
   ]
  }
 ],
 "services": [
  {
   "id": "Netspoc-tcp_80",
   "service_entries": [
    {
     "destination_ports": [
      "80"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  }
 ]
}
=END=

############################################################
=TITLE=VRF members with mixed managed and managed=local
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = 10.1.1.34; }
}

router:r1@T0 = {
 model = NSX, T0;
 managed = local;
 filter_only = 10.1.0.0/16;
 interface:n1 = { ip = 10.1.1.2; hardware = OUT; }
 interface:n2 = { ip = 10.1.2.1; hardware = IN; }
}
router:r1@T1 = {
 model = NSX, T1;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = OUT; }
 interface:n3 = { ip = 10.1.3.2; hardware = IN; }
}
service:test = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--r1
{
 "groups": null,
 "policies": [
  {
   "id": "Netspoc-T0",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "ALLOW",
     "destination_groups": [
      "10.1.3.0/24"
     ],
     "direction": "IN",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
     ],
     "source_groups": [
      "10.1.1.0/24"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "10.1.0.0/16"
     ],
     "direction": "IN",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 30,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "10.1.0.0/16"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 40,
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
      "10.1.0.0/16"
     ],
     "direction": "OUT",
     "id": "r4",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 10,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "10.1.0.0/16"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r5",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/T0"
     ],
     "sequence_number": 20,
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
   "id": "Netspoc-T1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "ALLOW",
     "destination_groups": [
      "10.1.3.0/24"
     ],
     "direction": "IN",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/T1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
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
     "direction": "IN",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/T1"
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
     "direction": "OUT",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-1s/T1"
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
 ],
 "services": [
  {
   "id": "Netspoc-tcp_80",
   "service_entries": [
    {
     "destination_ports": [
      "80"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  }
 ]
}
=END=

############################################################
=TITLE=VRF members with different value of filter_only
=INPUT=
network:n11 = { ip = 10.1.1.0/24; }
network:n12 = { ip = 10.1.2.0/24; }
network:n21 = { ip = 10.2.1.0/24; }
network:n22 = { ip = 10.2.2.0/24; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n11 = { ip = 10.1.1.34; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed = local;
 filter_only = 10.1.1.0/24, 10.1.2.0/24;
 interface:n11 = { ip = 10.1.1.2; hardware = OUT; }
 interface:n12 = { ip = 10.1.2.1; hardware = IN; }
}
router:d32 = {
 model = ASA;
 managed;
 interface:n12 = { ip = 10.1.2.2; hardware = n12; }
 interface:n21 = { ip = 10.2.1.2; hardware = n21; }
}
router:r1@v2 = {
 model = NSX, T0;
 managed = local;
 filter_only = 10.2.1.0/24, 10.2.2.0/24;
 interface:n21 = { ip = 10.2.1.1; hardware = OUT; }
 interface:n22 = { ip = 10.2.2.1; hardware = IN; }
}
service:test = {
 user = network:n11, network:n21;
 permit src = user; dst = network:n22; prt = tcp 80;
}
=OUTPUT=
--r1
{
 "groups": [
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "10.1.1.0/24",
      "10.1.2.0/24"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-g0"
  },
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "10.2.1.0/24",
      "10.2.2.0/24"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-g1"
  }
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "DROP",
     "destination_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ],
     "direction": "IN",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 10,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
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
      "/infra/domains/default/groups/Netspoc-g0"
     ],
     "direction": "OUT",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 10,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g0"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "r4",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
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
   "id": "Netspoc-v2",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "ALLOW",
     "destination_groups": [
      "10.2.2.0/24"
     ],
     "direction": "IN",
     "id": "r1",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v2"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-tcp_80"
     ],
     "source_groups": [
      "10.2.1.0/24"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "/infra/domains/default/groups/Netspoc-g1"
     ],
     "direction": "IN",
     "id": "r2",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v2"
     ],
     "sequence_number": 30,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "/infra/domains/default/groups/Netspoc-g1"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "r3",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v2"
     ],
     "sequence_number": 40,
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
      "/infra/domains/default/groups/Netspoc-g1"
     ],
     "direction": "OUT",
     "id": "r4",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v2"
     ],
     "sequence_number": 10,
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
      "ANY"
     ],
     "direction": "OUT",
     "id": "r5",
     "ip_protocol": "IPV4",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v2"
     ],
     "sequence_number": 20,
     "services": [
      "ANY"
     ],
     "source_groups": [
      "ANY"
     ]
    }
   ]
  }
 ],
 "services": [
  {
   "id": "Netspoc-tcp_80",
   "service_entries": [
    {
     "destination_ports": [
      "80"
     ],
     "id": "id",
     "l4_protocol": "TCP",
     "resource_type": "L4PortSetServiceEntry",
     "source_ports": []
    }
   ]
  }
 ]
}
=END=

############################################################
