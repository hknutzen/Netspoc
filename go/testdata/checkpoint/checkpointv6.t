=TEMPL=topology
network:n1 = { ip6 = 2001:0db8:1::/64; host:h1 = { ip6 = 2001:0db8:1::1; } }
network:n2 = { ip6 = 2001:0db8:2::/64; }
network:n3 = { ip6 = 2001:0db8:3::/64; host:h3 = { ip6 = 2001:0db8:3::1; } }
router:r1 = {
 management_instance;
 model = Checkpoint;
 interface:n2 = { ip6 = 2001:0db8:2::1; }
}
router:r1@v1 = {
 managed;
 model = Checkpoint;
 interface:n1 = { ip6 = 2001:0db8:1::2; hardware = n1v1; }
 interface:n2 = { ip6 = 2001:0db8:2::2; hardware = n2v1; }
}
router:r2 = {
 interface:n2 = { ip6 = 2001:0db8:2::3; }
 interface:n3 = { ip6 = 2001:0db8:3::3; }
}
=END=

=TEMPL=cleanup
{
 "action": "Drop",
 "destination": [
  "Any"
 ],
 "install-on": [
  "Policy Targets"
 ],
 "name": "Cleanup rule",
 "service": [
  "Any"
 ],
 "source": [
  "Any"
 ]
}
=END=


############################################################
=TITLE=single Service
=INPUT=
[[topology]]
service:test = {
 user = host:h3;
 permit src = user; dst = network:n1; prt = udp 22, tcp 22;
 deny src = user; dst = host:h1; prt = tcp 23, tcp 24;
}
=OUTPUT=
--ipv6/r1
{
 "TargetPolicy": {
  "v1": {
   "Layer": "Network",
   "Name": "v1"
  }
 },
 "TargetRules": {"v1": [
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
      "tcp_23",
      "tcp_24"
    ],
    "install-on": [
      "Policy Targets"
    ]
  },
  {
   "name": "test-2",
   "action": "Accept",
   "source": [
    "host_h3"
   ],
   "destination": [
    "network_n1"
   ],
   "service": [
    "udp_22",
    "tcp_22"
   ],
   "install-on": [
    "Policy Targets"
   ]
  },
  [[cleanup]]
 ]},
 "Networks": [
  {
   "name": "network_n1",
   "subnet6": "2001:db8:1::",
   "mask-length6": 64
  }
 ],
 "Hosts": [
  {
   "name": "host_h1",
   "ipv6-address": "2001:db8:1::1"
  },
  {
   "name": "host_h3",
   "ipv6-address": "2001:db8:3::1"
  }
 ],
 "Groups": null,
 "TCP": [
  {
   "name": "tcp_22",
   "port": "22"
  },
  {
   "name": "tcp_23",
   "port": "23"
  },
  {
   "name": "tcp_24",
   "port": "24"
  }
 ],
 "UDP": [
  {
   "name": "udp_22",
   "port": "22"
  }
 ],
 "ICMP": null,
 "ICMP6": null,
 "GatewayRoutes": {
  "v1": [
   {
    "address": "2001:db8:3::",
    "mask-length": 64,
    "type": "gateway",
    "next-hop": [
     {
      "gateway": "2001:db8:2::3"
     }
    ]
   }
  ]
 }
}
=END=

############################################################
=TITLE=icmpv6 Service
=INPUT=
[[topology]]
service:test = {
 user = host:h3;
 permit src = user;
        dst = network:n1;
        prt = icmpv6 1,
              icmpv6 2,
              icmpv6 3,
              icmpv6 4,
              icmpv6 128,
              icmpv6 129,
              icmpv6 130,
              icmpv6 131,
              icmpv6 132,
              icmpv6 133,
              icmpv6 134,
              icmpv6 135,
              icmpv6 136,
              icmpv6 137,
              icmpv6 138,
              icmpv6 139,
              icmpv6 140,
              icmpv6 141,
              icmpv6 142,
              icmpv6 144,
              icmpv6 145,
              icmpv6 146,
              icmpv6 147,
              icmpv6 160,
              icmpv6 161/2,
              ;
}
=OUTPUT=
--ipv6/r1
{
 "TargetPolicy": {
  "v1": {
   "Layer": "Network",
   "Name": "v1"
  }
 },
 "TargetRules": {"v1": [
  {
    "name": "test",
    "action": "Accept",
    "source": [
      "host_h3"
    ],
    "destination": [
      "network_n1"
    ],
    "service": [
      "echo-request6",
      "multicast-listener-query",
      "multicast-listener-report",
      "multicast-listener-done",
      "router-solicitation",
      "router-advertisement",
      "neighbor-solicitation",
      "neighbor-advertisement",
      "redirect6",
      "router-renumbering",
      "ICMP-node-information-query",
      "ICMP-node-information-response",
      "inverse-neighbor-discovery",
      "inverse-neighbor-discovery2",
      "home-agent-address-discovery",
      "home-agent-address-discovery2",
      "mobile-prefix-solicitation",
      "mobile-prefix-advertisement",
      "icmpv6_160",
      "icmpv6_161/2"
    ],
    "install-on": [
      "Policy Targets"
    ]
  },
  {
    "name": "test-2",
    "action": "Accept",
    "source": [
      "host_h3"
    ],
    "destination": [
      "network_n1"
    ],
    "service": [
      "destination-unreachable"
    ],
    "install-on": [
      "Policy Targets"
    ]
  },
  {
    "name": "test-3",
    "action": "Accept",
    "source": [
      "host_h3"
    ],
    "destination": [
      "network_n1"
    ],
    "service": [
      "packet_too-big"
    ],
    "install-on": [
      "Policy Targets"
    ]
  },
  {
    "name": "test-4",
    "action": "Accept",
    "source": [
      "host_h3"
    ],
    "destination": [
      "network_n1"
    ],
    "service": [
      "time-exceeded6"
    ],
    "install-on": [
      "Policy Targets"
    ]
  },
  {
    "name": "test-5",
    "action": "Accept",
    "source": [
      "host_h3"
    ],
    "destination": [
      "network_n1"
    ],
    "service": [
      "parameter-problem"
    ],
    "install-on": [
      "Policy Targets"
    ]
  },
  {
    "name": "test-6",
    "action": "Accept",
    "source": [
      "host_h3"
    ],
    "destination": [
      "network_n1"
    ],
    "service": [
      "echo-reply6"
    ],
    "install-on": [
      "Policy Targets"
    ]
  },
  [[cleanup]]
 ]},
 "Networks": [
  {
   "name": "network_n1",
   "subnet6": "2001:db8:1::",
   "mask-length6": 64
  }
 ],
 "Hosts": [
  {
   "name": "host_h3",
   "ipv6-address": "2001:db8:3::1"
  }
 ],
 "Groups": null,
 "TCP": null,
 "UDP": null,
 "ICMP": null,
 "ICMP6": [
   {
   "name": "icmpv6_160",
   "icmp-type": 160
   },
   {
   "name": "icmpv6_161/2",
   "icmp-type": 161,
   "icmp-code": 2
   }
 ],
 "GatewayRoutes": {
  "v1": [
   {
    "address": "2001:db8:3::",
    "mask-length": 64,
    "type": "gateway",
    "next-hop": [
     {
      "gateway": "2001:db8:2::3"
     }
    ]
   }
  ]
 }
}
=END=