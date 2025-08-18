=TITLE=single Service
=INPUT=
network:n1 = { ip6 = 2001:0db8:1::/64; host:h1 = { ip6 = 2001:0db8:1::1; } }
network:n2 = { ip6 = 2001:0db8:2::/64; }
network:n3 = { ip6 = 2001:0db8:3::/64; host:h3 = { ip6 = 2001:0db8:3::1; } }
router:r1 = {
 management_instance;
 model = CHECKPOINT;
 interface:n2 = { ip6 = 2001:0db8:2::1; }
}
router:r1@v1 = {
 managed;
 model = CHECKPOINT;
 interface:n1 = { ip6 = 2001:0db8:1::2; hardware = n1v1; }
 interface:n2 = { ip6 = 2001:0db8:2::2; hardware = n2v1; }
}
router:r2 = {
 interface:n2 = { ip6 = 2001:0db8:2::3; }
 interface:n3 = { ip6 = 2001:0db8:3::3; }
}
service:test = {
 user = host:h3;
 permit src = user; dst = network:n1; prt = udp 22, tcp 22;
 deny src = user; dst = host:h1; prt = tcp 23, tcp 24;
}
=OUTPUT=
--ipv6/r1
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
      "tcp_23",
      "tcp_24"
    ],
    "install-on": [
      "v1"
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
    "v1"
   ]
  }
 ],
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