############################################################
=TITLE=Need VRF
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:202; hardware = OUT; }
}
=ERROR=
Error: Must use VRF ('@...' in name) at router:r1 of model NSX
=END=

############################################################
=TITLE=Need tier specified by extension
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1@vrf = {
 model = NSX;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:202; hardware = OUT; }
}
=ERROR=
Error: Must add extension 'T0' or 'T1' at router:r1@vrf of model NSX
=END=

############################################################
=TITLE=Invalid extension
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1@vrf = {
 model = NSX, Tier-1;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:202; hardware = OUT; }
}
=ERROR=
Error: Unknown extension in 'model' of router:r1@vrf: Tier-1
Error: Must add extension 'T0' or 'T1' at router:r1@vrf of model NSX
=END=

############################################################
=TITLE=Need management_instance
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:202; hardware = OUT; }
}
router:r1@v2 = {
 model = NSX, T1;
 managed;
 interface:n1 = { ip = ::a01:103; hardware = IN; }
 interface:n2 = { ip = ::a01:203; hardware = OUT; }
}
=ERROR=
Error: Must define unmanaged router:r1
 with attribute 'management_instance'
 for router:r1@v1
=END=

############################################################
=TITLE=management_instance has wrong model
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = PAN-OS;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T1;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:202; hardware = OUT; }
}
=ERROR=
Error: router:r1@v1 and router:r1 must have identical model
=END=

############################################################
=TITLE=backup_of has wrong model
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r2 = {
 model = PAN-OS;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = ::a01:163; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:201; hardware = OUT; }
}
=ERROR=
Error: router:r1 and router:r2 must have identical model
=END=

############################################################
=TITLE=Multiple interfaces with same hardware
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:201; hardware = OUT; }
 interface:n3 = { ip = ::a01:301; hardware = IN; }
}
=ERROR=
Error: Different interfaces must not share same hardware 'IN' at router:r1@v1 of model NSX
=END=

############################################################
=TITLE=Wrong number of interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
}
router:r1@v2 = {
 model = NSX, T1;
 managed;
 interface:n1 = { ip = ::a01:103; hardware = IN; }
 interface:n2 = { ip = ::a01:203; hardware = OUT; }
 interface:n3 = { ip = ::a01:303; hardware = DMZ; }
}
=ERROR=
Error: router:r1@v1 of model NSX must have exactly 2 interfaces with hardware IN and OUT
Error: router:r1@v2 of model NSX must have exactly 2 interfaces with hardware IN and OUT
=END=

############################################################
=TITLE=Wrong hardware of interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = I; }
 interface:n2 = { ip = ::a01:203; hardware = O; }
}
=ERROR=
Error: router:r1@v1 of model NSX must have exactly 2 interfaces with hardware IN and OUT
=END=

############################################################
=TITLE=Simple rules, use backup_of
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a; }
 host:h20 = { ip = ::a01:114; }
}
network:n2 = { ip = ::a01:200/120;
 host:h30 = { ip = ::a01:21e; }
 host:h40 = { ip = ::a01:228; }
}
network:n3 = { ip = ::a01:300/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r2 = {
 model = NSX;
 management_instance;
 backup_of = router:r1;
 interface:n1 = { ip = ::a01:109; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:201; hardware = OUT; }
}
router:r1@v2 = {
 model = NSX, T1;
 managed;
 interface:n1 = { ip = ::a01:103; hardware = IN; }
 interface:n3 = { ip = ::a01:301; hardware = OUT; }
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
--ipv6/r1
Generated by Netspoc, version devel
--
[ BEGIN r1, r2 ]
[ Model = NSX ]
[ IP = ::a01:101, ::a01:109 ]
--
{
 "groups": [
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "::a01:10a",
      "::a01:114"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-v6g0"
  },
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "::a01:21e",
      "::a01:228"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-v6g1"
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
     "id": "v6r1",
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
      "/infra/domains/default/groups/Netspoc-v6g0"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:21e"
     ],
     "direction": "OUT",
     "id": "v6r2",
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
      "/infra/domains/default/groups/Netspoc-v6g0"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "v6r3",
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
      "::a01:300/120"
     ],
     "direction": "IN",
     "id": "v6r4",
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
      "/infra/domains/default/groups/Netspoc-v6g1"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "v6r5",
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
      "::a01:300/120"
     ],
     "direction": "OUT",
     "id": "v6r1",
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
      "::a01:10a"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:300/120"
     ],
     "direction": "OUT",
     "id": "v6r2",
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
      "::a01:10a"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:300/120"
     ],
     "direction": "OUT",
     "id": "v6r3",
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
      "::a01:10a"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:300/120"
     ],
     "direction": "OUT",
     "id": "v6r4",
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
      "::a01:114"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:300/120"
     ],
     "direction": "OUT",
     "id": "v6r5",
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
      "/infra/domains/default/groups/Netspoc-v6g1"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "v6r6",
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
     "id": "v6r7",
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
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a; }
 host:h20 = { ip = ::a01:114; }
}
network:n2 = { ip = ::a01:200/120;
 host:h30 = { ip = ::a01:21e; }
 host:h40 = { ip = ::a01:228; }
}
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:201; hardware = OUT; }
}
service:s1 = {
 user = host:h10, host:h20;
 permit src = user; dst = host:h30, host:h40; prt = tcp 80;
}
=OUTPUT=
--ipv6/r1
{
 "groups": [
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "::a01:10a",
      "::a01:114"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-v6g0"
  },
  {
   "expression": [
    {
     "id": "id",
     "ip_addresses": [
      "::a01:21e",
      "::a01:228"
     ],
     "resource_type": "IPAddressExpression"
    }
   ],
   "id": "Netspoc-v6g1"
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
      "/infra/domains/default/groups/Netspoc-v6g1"
     ],
     "direction": "OUT",
     "id": "v6r1",
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
      "/infra/domains/default/groups/Netspoc-v6g0"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "v6r2",
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
     "id": "v6r3",
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
=TITLE=Without rules
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T1;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:201; hardware = OUT; }
}
=OUTPUT=
--ipv6/r1
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
     "id": "v6r1",
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
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "IN",
     "id": "v6r2",
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
     ]
    }
   ]
  }
 ],
 "services": null
}
=END=

############################################################
=TITLE=ICMP and numeric protocol
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 model = NSX;
 management_instance;
 interface:n1 = { ip = ::a01:101; }
}
router:r1@v1 = {
 model = NSX, T0;
 managed;
 interface:n1 = { ip = ::a01:102; hardware = IN; }
 interface:n2 = { ip = ::a01:201; hardware = OUT; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = icmpv6 8, icmpv6 5/0, proto 52;
}
=OUTPUT=
--ipv6/r1
{
 "groups": null,
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:200/120"
     ],
     "direction": "OUT",
     "id": "v6r1",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-icmpv6_8"
     ],
     "source_groups": [
      "::a01:100/120"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:200/120"
     ],
     "direction": "OUT",
     "id": "v6r2",
     "profiles": [
      "ANY"
     ],
     "resource_type": "Rule",
     "scope": [
      "/infra/tier-0s/v1"
     ],
     "sequence_number": 20,
     "services": [
      "/infra/services/Netspoc-icmpv6_5/0"
     ],
     "source_groups": [
      "::a01:100/120"
     ]
    },
    {
     "action": "ALLOW",
     "destination_groups": [
      "::a01:200/120"
     ],
     "direction": "OUT",
     "id": "v6r3",
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
      "::a01:100/120"
     ]
    },
    {
     "action": "DROP",
     "destination_groups": [
      "ANY"
     ],
     "direction": "OUT",
     "id": "v6r4",
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
     "id": "v6r5",
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
   "id": "Netspoc-icmpv6_5/0",
   "service_entries": [
    {
     "icmp_code": 0,
     "icmp_type": 5,
     "id": "id",
     "protocol": "ICMPv6",
     "resource_type": "IcmpTypeServiceEntry"
    }
   ]
  },
  {
   "id": "Netspoc-icmpv6_8",
   "service_entries": [
    {
     "icmp_type": 8,
     "id": "id",
     "protocol": "ICMPv6",
     "resource_type": "IcmpTypeServiceEntry"
    }
   ]
  },
  {
   "id": "Netspoc-proto_52",
   "service_entries": [
    {
     "id": "id",
     "protocol_number": 52,
     "resource_type": "IpProtocolServiceEntry"
    }
   ]
  }
 ]
}
=END=
