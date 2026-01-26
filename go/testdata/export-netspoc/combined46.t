
############################################################
=TITLE=auto_ipv6_hosts and different IPv4, IPv6 rules
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }
network:n1 = {
 ip = 172.17.1.0/24;
 ip6 = 2001:db8:1:1::/64;
 auto_ipv6_hosts = readable;
 host:h = { ip = 172.17.1.48; }
 host:h6 = { ip6 = 2001:db8:1:1::6; }
 host:r = { range = 172.17.1.188 - 172.17.1.207; }
}
network:n2 = { ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 172.17.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 172.17.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 172.17.3.1; hardware = n3; }
}

service:s1 = {
 user = host:h, host:h6, host:r;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=OUTPUT=
--objects
{
 "host:h": {
  "ip": "172.17.1.48",
  "ip6": "2001:db8:1:1:172:17:1:48",
  "owner": "o",
  "zone": "any:[network:n1]"
 },
 "host:h6": {
  "ip": "2001:db8:1:1::6",
  "owner": "o", "zone":
  "any:[network:n1]"
 },
 "host:r": {
  "ip": "172.17.1.188-172.17.1.207",
  "ip6": "2001:db8:1:1:172:17:1:188-2001:db8:1:1:172:17:1:207",
  "owner": "o",
  "zone": "any:[network:n1]"
 },
 "interface:r1.n1": {
  "ip": "172.17.1.1",
  "ip6": "2001:db8:1:1::1",
  "zone": "any:[network:n1]"
 },
 "interface:r1.n2": { "ip": "2001:db8:1:2::1", "zone": "any:[network:n2]" },
 "interface:r1.n3": { "ip": "172.17.3.1", "zone": "any:[network:n3]" },
 "network:n1": {
  "ip": "172.17.1.0/24",
  "ip6": "2001:db8:1:1::/64",
  "owner": "o",
  "zone": "any:[network:n1]"
 },
 "network:n2": {
  "ip": "2001:db8:1:2::/64",
  "zone": "any:[network:n2]",
  "owner": "o"
 },
 "network:n3": {
  "ip": "172.17.3.0/24",
  "owner": "o",
  "zone": "any:[network:n3]"
 }
}
--services
{
 "s1": {
  "details": {
   "owner": [
    "o"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n2",
     "network:n3"
    ],
    "has_user": "src",
    "prt": [
     "tcp 80"
    ],
    "src": []
   }
  ]
 }
}
--owner/o/assets
{
 "anys": {
  "any:[network:n1]": {
   "networks": {
    "network:n1": [ "host:h", "host:h6", "host:r", "interface:r1.n1" ]
   }
  },
  "any:[network:n2]": {
   "networks": {
    "network:n2": [ "interface:r1.n2" ]
   }
  },
  "any:[network:n3]": {
   "networks": {
    "network:n3": [ "interface:r1.n3" ]
   }
  }
 }
}
--owner/o/users
{
 "s1": [
  "host:h",
  "host:h6",
  "host:r"
 ]
}
=END=

############################################################
=TITLE=Service from auto interface, identical for IPv4, IPv6
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = interface:r1.[auto];
 permit src = network:n1; dst = user; prt = tcp 22;
}
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "o"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "dst",
    "prt": [
     "tcp 22"
    ],
    "src": [
     "network:n1"
    ]
   }
  ]
 }
}
=END=

############################################################
=TITLE=Split service from auto interface, identical for IPv4, IPv6
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = network:n1, network:n2;
 permit src = user; dst = interface:r1.[auto]; prt = tcp 22;
}
=OUTPUT=
--services
{
 "s1(jQ4ZMju4)": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r1.n2"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 },
 "s1(wE9zkFMz)": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r1.n1"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 }
}
--owner/o/users
{
 "s1(jQ4ZMju4)": [
  "network:n2"
 ],
 "s1(wE9zkFMz)": [
  "network:n1"
 ]
}
=END=

############################################################
=TITLE=Split service from auto interface, different for IPv4, IPv6
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip6 = 2001:db8:1:3::/64; }
router:u0 = {
 interface:n0;
 interface:n1;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:u3 = {
 interface:n2;
 interface:n3;
}
service:s1 = {
 user = network:n0, network:n3;
 permit src = user; dst = interface:r1.[auto]; prt = tcp 22;
}
=OUTPUT=
--services
{
 "s1(jQ4ZMju4)": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r1.n2"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 },
 "s1(wE9zkFMz)": {
  "details": {
   "owner": [
    ":unknown"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "interface:r1.n1"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 }
}
--owner/o/users
{
 "s1(jQ4ZMju4)": [
  "network:n3"
 ],
 "s1(wE9zkFMz)": [
  "network:n0"
 ]
}
=END=

############################################################
=TITLE=V4 only network to dual stack network
=INPUT=
area:all = { anchor = network:n2; owner = o; }
owner:o = { admins = a1@example.com; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "o"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n2"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=V6 only network to dual stack network
=INPUT=
area:all = { anchor = network:n2; owner = o; }
owner:o = { admins = a1@example.com; }
network:n1 = { ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip6 = 2001:db8:1:1::1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "o"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "network:n2"
    ],
    "has_user": "src",
    "prt": [
     "tcp 22"
    ],
    "src": []
   }
  ]
 }
}
=END=

############################################################
=TITLE=IPv4 only network to dual stack auto interface
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }
network:n1 = { ip = 10.1.1.0/24; }
router:r0 = {
 interface:n1;
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = interface:r1.[auto];
 permit src = network:n1; dst = user; prt = tcp 22;
}
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "o"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [],
    "has_user": "dst",
    "prt": [
     "tcp 22"
    ],
    "src": [
     "network:n1"
    ]
   }
  ]
 }
}
=END=

############################################################
=TITLE=Combined non matching aggregates in rule
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
}
service:s1 = {
 user = any:n1;
 permit src = user; dst = any:[network:n2]; prt = tcp 80;
}
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "o"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "any:[network:n2]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 80"
    ],
    "src": []
   }
  ]
 }
}
--owner/o/users
{
 "s1": [
  "any:n1"
 ]
}
=END=

############################################################
=TITLE=Multiple combined non matching aggregates in rule
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
network:n4 = { ip = 10.1.4.0/24; ip6 = 2001:db8:1:4::/64; }
network:n5 = { ip = 10.1.5.0/24; ip6 = 2001:db8:1:5::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; ip6 = 2001:db8:1:4::1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; ip6 = 2001:db8:1:5::1; hardware = n5; }
}
service:s1 = {
 user = any:[network:n1, network:n2];
 permit src = user;
        dst = any:[network:n3],
              any:[network:n4],
              any:[network:n5],
              ;
        prt = tcp 80;
}
=OUTPUT=
--services
{
 "s1": {
  "details": {
   "owner": [
    "o"
   ]
  },
  "rules": [
   {
    "action": "permit",
    "dst": [
     "any:[network:n3]",
     "any:[network:n4]",
     "any:[network:n5]"
    ],
    "has_user": "src",
    "prt": [
     "tcp 80"
    ],
    "src": []
   }
  ]
 }
}
--owner/o/users
{
 "s1": [
  "any:[network:n2]",
  "any:n1"
 ]
}
=END=

############################################################
=TITLE=Combined non matching aggregate in mixed v4, v46 zone cluster
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }

network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip6 = 2001:db8:1:4::/64; }
network:n5 = { ip = 10.1.5.0/24; ip6 = 2001:db8:1:5::/64; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip6 = 2001:db8:1:4::1; hardware = n4; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; ip6 = 2001:db8:1:2::2; }
 interface:n3 = { ip = 10.1.3.2; }
 interface:n4 = { ip6 = 2001:db8:1:4::2; }
 interface:n5;
}
pathrestriction:p1 = interface:r1.n1, interface:r2.n3;
pathrestriction:p2 = interface:r1.n1, interface:r2.n4;

any:a2 = { link = network:n2; }
service:s1 = {
 user = any:a2;
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
--objects
{
 "any:a2": {
  "ip": "0.0.0.0/0",
  "ip6": "::/0",
  "is_supernet": 1,
  "owner": "o",
  "zone": "any:a2"
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1",
  "ip6": "2001:db8:1:1::1",
  "zone": "any:[network:n1]"
 },
 "interface:r1.n2": {
  "ip": "10.1.2.1",
  "ip6": "2001:db8:1:2::1",
  "zone": "any:a2"
 },
 "interface:r1.n3": {
  "ip": "10.1.3.1",
  "zone": "any:a2"
 },
 "interface:r1.n4": {
  "ip": "2001:db8:1:4::1",
  "zone": "any:a2"
 },
 "interface:r2.n2": {
  "ip": "10.1.2.2",
  "ip6": "2001:db8:1:2::2",
  "owner": "o",
  "zone": "any:a2"
 },
 "interface:r2.n3": {
  "ip": "10.1.3.2",
  "owner": "o",
  "zone": "any:a2"
 },
 "interface:r2.n4": {
  "ip": "2001:db8:1:4::2",
  "owner": "o",
  "zone": "any:a2"
 },
 "interface:r2.n5": {
  "ip": "short",
  "ip6": "short",
  "owner": "o",
  "zone": "any:a2"
 },
 "network:n1": {
  "ip": "10.1.1.0/24",
  "ip6": "2001:db8:1:1::/64",
  "owner": "o",
  "zone": "any:[network:n1]"
 },
 "network:n2": {
  "ip": "10.1.2.0/24",
  "ip6": "2001:db8:1:2::/64",
  "owner": "o",
  "zone": "any:a2"
 },
 "network:n3": {
  "ip": "10.1.3.0/24",
  "owner": "o",
  "zone": "any:a2"
 },
 "network:n4": {
  "ip": "2001:db8:1:4::/64",
  "owner": "o",
  "zone": "any:a2"
 },
 "network:n5": {
  "ip": "10.1.5.0/24",
  "ip6": "2001:db8:1:5::/64",
  "owner": "o",
  "zone": "any:a2"
 }
}
=END=

############################################################
=TITLE=Combined non matching aggregates with v4/v6 names
=INPUT=
area:all = { anchor = network:n1; owner = o; }
owner:o = { admins = a1@example.com; }

any:n1-v4 = { link = network:n7; }
network:n7 = { ip = 10.1.7.0/24; }
router:u7 = {
 interface:n7;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; ip6 = 2001:db8:1:1::/64; }

any:n2-v6 = { link = network:n8; }
network:n8 = {  ip6 = 2001:db8:1:8::/64; }
router:u8 = {
 interface:n8;
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; ip6 = 2001:db8:1:2::/64; }

network:n3 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; ip6 = 2001:db8:1:2::1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; ip6 = 2001:db8:1:3::1; hardware = n3; }
}
service:s1 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
--objects
{
 "any:n1-v4": {
  "ip": "0.0.0.0/0",
  "ip6": "::/0",
  "is_supernet": 1,
  "owner": "o",
  "zone": "any:n1-v4"
 },
 "any:n2-v6": {
  "ip": "0.0.0.0/0",
  "ip6": "::/0",
  "is_supernet": 1,
  "owner": "o",
  "zone": "any:n2-v6"
 },
 "interface:r1.n1": {
  "ip": "10.1.1.1",
  "ip6": "2001:db8:1:1::1",
  "zone": "any:n1-v4"
 },
 "interface:r1.n2": {
  "ip": "10.1.2.1",
  "ip6": "2001:db8:1:2::1",
  "zone": "any:n2-v6"
 },
 "interface:r1.n3": {
  "ip": "10.1.3.1",
  "ip6": "2001:db8:1:3::1",
  "zone": "any:[network:n3]"
 },
 "interface:u7.n1": {
  "ip": "short",
  "ip6": "short",
  "owner": "o",
  "zone": "any:n1-v4"
 },
 "interface:u7.n7": {
  "ip": "short",
  "owner": "o",
  "zone": "any:n1-v4"
 },
 "interface:u8.n2": {
  "ip": "short",
  "ip6": "short",
  "owner": "o",
  "zone": "any:n2-v6"
 },
 "interface:u8.n8": {
  "ip": "short",
  "owner": "o",
  "zone": "any:n2-v6"
 },
 "network:n1": {
  "ip": "10.1.1.0/24",
  "ip6": "2001:db8:1:1::/64",
  "owner": "o",
  "zone": "any:n1-v4"
 },
 "network:n2": {
  "ip": "10.1.2.0/24",
  "ip6": "2001:db8:1:2::/64",
  "owner": "o",
  "zone": "any:n2-v6"
 },
 "network:n3": {
  "ip": "10.1.3.0/24",
  "ip6": "2001:db8:1:3::/64",
  "owner": "o",
  "zone": "any:[network:n3]"
 },
 "network:n7": {
  "ip": "10.1.7.0/24",
  "owner": "o",
  "zone": "any:n1-v4"
 },
 "network:n8": {
  "ip": "2001:db8:1:8::/64",
  "owner": "o",
  "zone": "any:n2-v6"
 }
}
--owner/o/users
{
 "s1": [
  "any:n1-v4",
  "any:n2-v6"
 ]
}
=END=

############################################################
=TITLE=Show v4 and v6 areas for combined zone
=INPUT=
owner:o = { admins = a1@example.com; }
area:all-v4 = { anchor = network:n1_4; owner = o; }
area:all-v6 = { anchor = network:n1_6; owner = o; }
area:a1-v4 = { border = interface:r1.n1_4; }

network:n1_4 = { ip = 10.1.1.0/24; }
network:n2_4 = { ip = 10.1.2.0/24; }
network:n1_6 = { ip6 = 2001:db8:1:1::/64; }
network:n2_6 = { ip6 = 2001:db8:1:2::/64; }
network:n3_46 = { ip = 10.1.3.0/24; ip6 = 2001:db8:1:3::/64; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_4 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2_4 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_6 = { ip6 = 2001:db8:1:1::1; hardware = n1; }
 interface:n2_6 = { ip6 = 2001:db8:1:2::1; hardware = n2; }
}
router:u1 = {
 interface:n1_4;
 interface:n1_6;
 interface:n3_46;
}
router:u2 = {
 interface:n2_4;
 interface:n2_6;
}
=OUTPUT=
--zone2areas
{
 "any:[network:n2_4]": [ "all-v4" ],
 "any:[network:n2_6]": [ "all-v6" ],
 "any:[network:n3_46]": [ "a1-v4", "all-v4", "all-v6" ]
}
--owner/o/assets
{
 "anys": {
  "any:[network:n2_4]": {
   "networks": {
    "network:n2_4": [ "interface:r1.n2_4", "interface:u2.n2_4" ]
   }
  },
  "any:[network:n2_6]": {
   "networks": {
    "network:n2_6": [ "interface:r2.n2_6", "interface:u2.n2_6" ]
   }
  },
  "any:[network:n3_46]": {
   "networks": {
    "network:n1_4": [ "interface:r1.n1_4", "interface:u1.n1_4" ],
    "network:n1_6": [ "interface:r2.n1_6", "interface:u1.n1_6" ],
    "network:n3_46": [ "interface:u1.n3_46" ]
   }
  }
 }
}
=END=
