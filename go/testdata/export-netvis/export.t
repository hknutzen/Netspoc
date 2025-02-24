############################################################
=TITLE=Option '-h'
=INPUT=#
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR
  -q, --quiet   Don't print progress messages
=END=

############################################################
=TITLE=Unknown option
=INPUT=#
=PARAMS=--abc
=ERROR=
Error: unknown flag: --abc
=END=

############################################################
=TITLE=No input file
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR
  -q, --quiet   Don't print progress messages
=END=

############################################################
=TITLE=Invalid input
=INPUT=
foo
=ERROR=
Error: Typed name expected at line 1 of INPUT, near "--HERE-->foo"
Aborted
=END=

############################################################
=TITLE=Empty input
=INPUT=

=WARNING=
Warning: Ignoring file 'INPUT' without any content
=OUTPUT=
{"network":{},"router":{}}
=END=

############################################################
=TITLE=One Network One Managed Router
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.5; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=OUTPUT=
{
 "network": {
  "network:n1":  {
   "address": "10.1.1.0/24", "hosts": ["host:h1"],
   "id": "network:n1", "neighbors": [{"id":"router:r1","neighbor_count":1}],
   "type": "network"
  }
 },
 "router": {
  "router:r1": {
   "id":"router:r1", "neighbors": [{"id":"network:n1","neighbor_count":1}],
   "type": "router: standard"
  }
 }
}
=END=

############################################################
=TITLE=One Network One Router in One Area
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.5; }
}
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
}
area:a1 = {
 anchor = network:n1;
}
=OUTPUT=
{
 "network": {
  "network:n1":  {
   "address": "10.1.1.0/24", "hosts": ["host:h1"],
   "id": "network:n1", "in_area": "area:a1",
   "neighbors": [{"id":"router:r1","neighbor_count":1}], "type": "network"
  }
 },
 "router": {
  "router:r1": {
   "id":"router:r1", "in_area": "area:a1",
   "neighbors": [{"id":"network:n1","neighbor_count":1}], "type": "router"
  }
 }
}
=END=

############################################################
=TITLE=Tunnelconnection
=INPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA; esp_encryption = aes256;
 esp_authentication = sha; pfs_group = 2; lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig; encryption = aes256;
 hash = sha; group = 2; lifetime = 86400 sec;
}
crypto:vpn = {type = ipsec:aes256SHA;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = {
 ip = 0.0.0.0/0;
 has_subnets;
}
router:softclients = {
 interface:internet = {
  spoke = crypto:vpn;
 }
}
=OUTPUT=
{
 "network": {"network:dmz":{"id":"network:dmz","type":"network","address":"192.168.0.0/24","neighbors":[{"id":"router:asavpn","neighbor_count":1},{"id":"router:extern","neighbor_count":2}],"hosts":null},"network:internet":{"id":"network:internet","type":"network","address":"0.0.0.0/0","neighbors":[{"id":"router:extern","neighbor_count":2},{"id":"router:softclients","neighbor_count":1}],"hosts":null}},
 "router": {
    "router:asavpn": {
      "id": "router:asavpn",
      "type": "router: standard",
            "neighbors": [
        {
          "id": "network:dmz",
          "neighbor_count": 2
        },
        {
          "id": "router:softclients",
          "neighbor_count": 1,
          "is_tunnel": true
        }
      ]
    },
    "router:extern": {"id":"router:extern","type":"router","neighbors":[{"id":"network:dmz","neighbor_count":2},{"id":"network:internet","neighbor_count":2}]},
    "router:softclients": {
      "id": "router:softclients",
      "type": "router",
            "neighbors": [
        {
          "id": "network:internet",
          "neighbor_count": 2
        },
        {
          "id": "router:asavpn",
          "neighbor_count": 1,
          "is_tunnel": true
        }
      ]
    }
  }
 }
=END=

############################################################
=TITLE=One Router Two Areas
=INPUT=
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

area:a1 = {
 border = interface:r1.n1;
}

area:a2 = {
 border = interface:r1.n2;
}
=OUTPUT=
{
  "network": {
    "network:n1": {
      "id": "network:n1",
      "type": "network",
            "in_area": "area:a1",
      "address": "10.1.1.0/24",
      "neighbors": [
        {
          "id": "router:r1",
          "neighbor_count": 2
        }
      ],
      "hosts": null
    },
    "network:n2": {
      "id": "network:n2",
      "type": "network",
            "in_area": "area:a2",
      "address": "10.1.2.0/24",
      "neighbors": [
        {
          "id": "router:r1",
          "neighbor_count": 2
        }
      ],
      "hosts": null
    }
  },
  "router": {
    "router:r1": {
      "id": "router:r1",
      "type": "router: standard",
            "neighbors": [
        {
          "id": "network:n1",
          "neighbor_count": 1
        },
        {
          "id": "area:a1",
          "neighbor_count": 1
        },
        {
          "id": "network:n2",
          "neighbor_count": 1
        },
        {
          "id": "area:a2",
          "neighbor_count": 1
        }
      ]
    }
  }
}

=END=

############################################################
=TITLE=One Router routing only
=INPUT=
router:r1 = {
 managed = routing_only;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
network:n1 = { ip = 10.1.1.0/24; }
=OUTPUT=
{
  "network": {
    "network:n1": {
      "id": "network:n1",
      "type": "network",
            "address": "10.1.1.0/24",
      "neighbors": [
        {
          "id": "router:r1",
          "neighbor_count": 1
        }
      ],
      "hosts": null
    }
  },
  "router": {
    "router:r1": {
      "id": "router:r1",
      "type": "router: routing_only",
            "neighbors": [
        {
          "id": "network:n1",
          "neighbor_count": 1
        }
      ]
    }
  }
}
=END=