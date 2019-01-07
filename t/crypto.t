#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $crypto_vpn, $crypto_sts, $topo, $in, $out);


############################################################
# Shared crypto definitions
############################################################

$crypto_vpn = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}

isakmp:aes256SHA = {
 identity = address;
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}

crypto:vpn = {
 type = ipsec:aes256SHA;
}
END

$crypto_sts = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 1 hour 100000 kilobytes;
}

isakmp:aes256SHA = {
 identity = address;
 nat_traversal = additional;
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 43200 sec;
 trust_point =  ASDM_TrustPoint3;
}

crypto:sts = {
 type = ipsec:aes256SHA;
}
END

############################################################
$title = 'Missing ISAKMP attributes';
############################################################

$in = <<'END';
isakmp:aes256SHA = {
 group = 2;
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Missing 'authentication' for isakmp:aes256SHA
Error: Missing 'encryption' for isakmp:aes256SHA
Error: Missing 'hash' for isakmp:aes256SHA
Error: Missing 'lifetime' for isakmp:aes256SHA
END

test_err($title, $in, $out);

############################################################
$title = 'Missing IPSec attributes';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 esp_encryption = aes256;
}
END

$out = <<'END';
Error: Missing 'lifetime' for ipsec:aes256SHA
Syntax error: Missing 'key_exchange' for ipsec:aes256SHA at line 3 of STDIN, near "}<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = 'Bad IPSec lifetime type';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = 100 foo;
}
}
END

$out = <<'END';
Syntax error: Time unit or 'kilobytes' expected at line 3 of STDIN, near "foo<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = 'Bad key_exchange attribute';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = xyz:aes256SHA;
 esp_encryption = aes256;
 lifetime = 600 sec;
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Unknown key_exchange type 'xyz' for ipsec:aes256SHA
END

test_err($title, $in, $out);

############################################################
$title = 'Unknown key_exchange';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:abc;
 esp_encryption = aes256;
 lifetime = 600 sec;
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Can't resolve reference to isakmp:abc for ipsec:aes256SHA
END

test_err($title, $in, $out);

############################################################
$title = 'Missing type of crypto definition';
############################################################

$in = <<'END';
crypto:c = {}
END

$out = <<'END';
Syntax error: Missing 'type' for crypto:c at line 1 of STDIN, near "crypto:c = {}<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = 'Unknown type in crypto definition';
############################################################

$in = <<'END';
crypto:c = { type = xyz:abc; }
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Unknown type 'xyz' for crypto:c
END

test_err($title, $in, $out);

############################################################
$title = 'Unknown ipsec referenced in crypto definition';
############################################################

$in = <<'END';
crypto:c = { type = ipsec:abc; }
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Can't resolve reference to ipsec:abc for crypto:c
END

test_err($title, $in, $out);

############################################################
$title = 'No hub defined for crypto';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Warning: No hub has been defined for crypto:vpn
END

test_warn($title, $in, $out);

############################################################
$title = 'Unnumbered crypto interface';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { unnumbered; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  unnumbered;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}

router:softclients = {
 interface:n1 = { spoke = crypto:vpn; }
 interface:clients;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
}
END

$out = <<'END';
Error: Crypto hub must not be unnumbered interface at line 34 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Need authentication rsasig';
############################################################

($in = $crypto_vpn) =~ s/rsasig/preshare/;
$in .=  <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}

router:softclients = {
 interface:n1 = { spoke = crypto:vpn; }
 interface:clients;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}
END

$out = <<'END';
Error: router:asavpn needs authentication=rsasig in isakmp:aes256SHA
END

test_err($title, $in, $out);

############################################################
$title = 'Missing ID hosts at software client';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}

router:softclients = {
 interface:n1 = { ip = 10.1.1.2; spoke = crypto:vpn; }
 interface:other;
}

network:other = { ip = 10.99.9.0/24; }
END

$out = <<'END';
Error: Networks need to have ID hosts because router:asavpn has attribute 'do_auth':
 - network:other
END

test_err($title, $in, $out);

############################################################
$title = 'Mixed ID hosts and non ID hosts at software client';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}

router:softclients = {
 interface:n1 = { ip = 10.1.1.2; spoke = crypto:vpn; }
 interface:clients;
 interface:other;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}

network:other = { ip = 10.99.9.0/24; }
END

$out = <<'END';
Error: Must not use networks having ID hosts and other networks having no ID hosts
 together at router:softclients:
 - network:clients
 - network:other
END

test_err($title, $in, $out);

############################################################
$title = 'Non ID hosts behind ID hosts';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}

router:softclients = {
 interface:n1 = { ip = 10.1.1.2; spoke = crypto:vpn; }
 interface:clients;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}

router:u = {
 interface:clients;
 interface:other;
}

network:other = { ip = 10.99.9.0/24; }
END

$out = <<'END';
Error: Exactly one network must be located behind unmanaged interface:softclients.clients of crypto router
END

test_err($title, $in, $out);

############################################################
$title = 'no_in_acl at crypto interface';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  hardware = n1;
  no_in_acl;
 }
}

router:softclients = {
 interface:n1 = { spoke = crypto:vpn; }
 interface:clients;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}
END

$out = <<'END';
Error: Don't use attribute 'no_in_acl' together with crypto tunnel at router:asavpn
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate crypto hub';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.2.0/24; }

router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip = 10.1.2.1; hardware = e0; }
 interface:trans = { ip = 10.9.9.1; hardware = e1; }
}
network:trans = { ip = 10.9.9.0/24; }
router:gw = {
 interface:trans = { ip = 10.9.9.2; }
 interface:dmz = { ip = 192.168.0.2; }
}

router:asavpn1 = {
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
  no_check;
 }
}

router:asavpn2 = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip = 192.168.0.102;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip = 10.9.9.3; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:id:long-first-name.long-second-name@long-domain.xyz = {
  ip = 10.99.1.11;
  radius_attributes = { banner = Willkommen zu Hause; }
 }
}
END

$out = <<'END';
Error: Must use hub = crypto:vpn exactly once, not at both
 - interface:asavpn1.dmz
 - interface:asavpn2.dmz
END

test_err($title, $in, $out);

############################################################
$title = 'Crypto spoke with secondary IP';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.2.0/24; }

router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip = 10.1.2.1; hardware = e0; }
 interface:trans = { ip = 10.9.9.1; hardware = e1; }
}
network:trans = { ip = 10.9.9.0/24; }
router:gw = {
 interface:trans = { ip = 10.9.9.2; }
 interface:dmz = { ip = 192.168.0.2; }
}

router:asavpn1 = {
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
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip = 10.9.9.3, 10.9.9.9; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:id:long-first-name.long-second-name@long-domain.xyz = {
  ip = 10.99.1.11;
  radius_attributes = { banner = Willkommen zu Hause; }
 }
}
END

$out = <<'END';
Error: Interface with attribute 'spoke' must not have secondary interfaces at line 53 of STDIN
END

test_err($title, $in, $out);


############################################################
$title = 'Duplicate crypto spoke';
############################################################

$in = $crypto_vpn . <<'END';
network:intern1 = { ip = 10.1.1.0/24;}

router:gw1 = {
 interface:intern1;
 interface:dmz = { ip = 192.168.0.1; }
}

router:asavpn1 = {
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
  no_check;
 }
}

crypto:vpn2 = {
 type = ipsec:aes256SHA;
}
network:intern2 = { ip = 10.1.2.0/24;}

router:gw2 = {
 interface:intern2;
 interface:dmz = { ip = 192.168.0.2; }
}

router:asavpn2 = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint2;
 }
 interface:dmz = {
  ip = 192.168.0.102;
  hub = crypto:vpn2;
  hardware = outside;
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:intern1 = { spoke = crypto:vpn; }
 interface:intern2 = { spoke = crypto:vpn2; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}
END

$out = <<'END';
Error: Only 1 crypto spoke allowed.
 Ignoring spoke at softclients.tunnel:softclients.
Warning: No spokes have been defined for crypto:vpn2
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate crypto spoke to same device';
############################################################

$in = $crypto_vpn . <<'END';
network:intern1 = { ip = 10.1.1.0/24;}
network:intern2 = { ip = 10.1.2.0/24;}

router:gw = {
 interface:intern1;
 interface:intern2;
 interface:dmz = { ip = 192.168.0.2; }
}

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
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:intern1 = { spoke = crypto:vpn; }
 interface:intern2 = { spoke = crypto:vpn; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}
END

$out = <<'END';
Error: Only 1 crypto spoke allowed.
 Ignoring spoke at softclients.tunnel:softclients.
END

test_err($title, $in, $out);

############################################################
$title = 'ID of host must match ip/range';
############################################################

$in = <<'END';
network:n = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:id:@domain.x    = { ip = 10.99.1.11; }
 host:id:domain.x     = { ip = 10.99.1.12; }
 host:id:@domain.y    = { range = 10.99.1.16-10.99.1.17; }
 host:id:domain.y     = { range = 10.99.1.18-10.99.1.19; }
 host:id:bar@domain.y = { range = 10.99.1.20-10.99.1.23; }
 host:id:boo@domain.y = { range = 10.99.1.1-10.99.1.63; }
 host:id:b1@domain.y = { range = 10.99.1.1-10.99.1.1; }
}
END

$out = <<'END';
Error: ID of host:id:@domain.x.n must not start with character '@'
Error: ID of host:id:domain.x.n must contain character '@'
Error: ID of host:id:bar@domain.y.n must start with character '@' or have no '@' at all
Error: Range of host:id:boo@domain.y.n with ID must expand to exactly one subnet
Error: host:id:b1@domain.y.n with ID must not have single IP
END

test_err($title, $in, $out);

############################################################
$title = 'Unkown crypto at hub and spoke';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}

router:softclients = {
 interface:n1 = { spoke = crypto:vpn; }
 interface:clients;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}
END

$out = <<'END';
Error: interface:asavpn.n1 references unknown crypto:vpn
Error: interface:softclients.n1 references unknown crypto:vpn
Error: IPv4 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:clients]
 Use partition attribute, if intended.
END

test_err($title, $in, $out);

############################################################
# Shared topology
############################################################

$topo = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
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

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
 interface:customers2;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 radius_attributes = {
  banner = Willkommen;
 }
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
  radius_attributes = { split-tunnel-policy = tunnelspecified; }
 }
 host:id:bar@domain.x = {
  ip = 10.99.1.11;
  radius_attributes = { split-tunnel-policy = tunnelall;
                        banner = Willkommen zu Hause; }
 }
 host:id:unused@domain.x = {
  ip = 10.99.1.254;
  radius_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}

network:customers2 = {
 ip = 10.99.2.0/24;
 radius_attributes = {
  vpn-idle-timeout = 120;
  trust-point = ASDM_TrustPoint2;
  }

 host:id:domain.x = {
  range = 10.99.2.0 - 10.99.2.63;
  radius_attributes = { split-tunnel-policy = tunnelspecified;
                        check-subject-name = ou;
                        authorization-server-group = LDAP_1;
                        username-from-certificate = CN;
                        authorization-required; }
 }
 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  radius_attributes = { vpn-idle-timeout = 40;
                        trust-point = ASDM_TrustPoint3; }
 }
 host:id:zzz = {
  range = 10.99.2.128 - 10.99.2.191;
  radius_attributes = { split-tunnel-policy = tunnelspecified;
                        check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2;
                        check-subject-name = ou; }
 }
}
END

############################################################
$title = 'VPN ASA with software clients';
############################################################

$in = $topo . <<'END';
network:work1 = { ip = 10.0.1.0/24; }
network:work2 = { ip = 10.0.2.0/24; }
network:work3 = { ip = 10.0.3.0/24; }
network:work4 = { ip = 10.0.4.0/24; }

router:u = {
 interface:work1;
 interface:work2;
 interface:work3;
 interface:work4;
 interface:intern = { ip = 10.1.1.1; }
}

group:g1 =
 network:work1,
 network:work2,
 network:work3,
;
group:g2 =
 network:work2,
 network:work3,
 network:work4,
;

service:test1 = {
 user = host:id:foo@domain.x.customers1, host:id:@domain.y.customers2;
 permit src = user; dst = group:g1; prt = tcp 80;
}
service:test2 = {
 user = host:id:bar@domain.x.customers1, host:id:domain.x.customers2;
 permit src = user; dst = group:g2; prt = tcp 81;
}
service:test3 = {
 user = host:id:domain.x.customers2, host:id:zzz.customers2;
 permit src = user; dst = group:g2; prt = tcp 82;
}
END

$out = <<'END';
--asavpn
! [ Routing ]
route inside 10.0.1.0 255.255.255.0 10.1.1.1
route inside 10.0.4.0 255.255.255.0 10.1.1.1
route inside 10.0.2.0 255.255.254.0 10.1.1.1
route outside 0.0.0.0 0.0.0.0 192.168.0.1
--
no sysopt connection permit-vpn
group-policy global internal
group-policy global attributes
 pfs enable
--
tunnel-group VPN-single type remote-access
tunnel-group VPN-single general-attributes
 authorization-server-group LOCAL
 default-group-policy global
 authorization-required
 username-from-certificate EA
tunnel-group VPN-single ipsec-attributes
 chain
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
--
! vpn-filter-@domain.y
access-list vpn-filter-@domain.y extended permit ip 10.99.2.64 255.255.255.192 any4
access-list vpn-filter-@domain.y extended deny ip any4 any4
crypto ca certificate map ca-map-@domain.y 10
 subject-name attr ea co @domain.y
ip local pool pool-@domain.y 10.99.2.64-10.99.2.127 mask 255.255.255.192
group-policy VPN-group-@domain.y internal
group-policy VPN-group-@domain.y attributes
 address-pools value pool-@domain.y
 vpn-filter value vpn-filter-@domain.y
 vpn-idle-timeout 40
tunnel-group VPN-tunnel-@domain.y type remote-access
tunnel-group VPN-tunnel-@domain.y general-attributes
 default-group-policy VPN-group-@domain.y
tunnel-group VPN-tunnel-@domain.y ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
tunnel-group VPN-tunnel-@domain.y webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-@domain.y 10 VPN-tunnel-@domain.y
--
! vpn-filter-bar@domain.x
access-list vpn-filter-bar@domain.x extended permit ip host 10.99.1.11 any4
access-list vpn-filter-bar@domain.x extended deny ip any4 any4
group-policy VPN-group-bar@domain.x internal
group-policy VPN-group-bar@domain.x attributes
 banner value Willkommen zu Hause
username bar@domain.x nopassword
username bar@domain.x attributes
 vpn-framed-ip-address 10.99.1.11 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-bar@domain.x
 vpn-group-policy VPN-group-bar@domain.x
--
! split-tunnel-1
access-list split-tunnel-1 standard permit 10.0.2.0 255.255.255.0
access-list split-tunnel-1 standard permit 10.0.3.0 255.255.255.0
access-list split-tunnel-1 standard permit 10.0.4.0 255.255.255.0
--
! vpn-filter-domain.x
access-list vpn-filter-domain.x extended permit ip 10.99.2.0 255.255.255.192 any4
access-list vpn-filter-domain.x extended deny ip any4 any4
crypto ca certificate map ca-map-domain.x 10
 subject-name attr ou co domain.x
ip local pool pool-domain.x 10.99.2.0-10.99.2.63 mask 255.255.255.192
group-policy VPN-group-domain.x internal
group-policy VPN-group-domain.x attributes
 address-pools value pool-domain.x
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-domain.x
 vpn-idle-timeout 120
tunnel-group VPN-tunnel-domain.x type remote-access
tunnel-group VPN-tunnel-domain.x general-attributes
 default-group-policy VPN-group-domain.x
 authorization-required
 authorization-server-group LDAP_1
 username-from-certificate CN
tunnel-group VPN-tunnel-domain.x ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint2
 ikev1 user-authentication none
tunnel-group VPN-tunnel-domain.x webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-domain.x 10 VPN-tunnel-domain.x
--
! split-tunnel-2
access-list split-tunnel-2 standard permit 10.0.1.0 255.255.255.0
access-list split-tunnel-2 standard permit 10.0.2.0 255.255.255.0
access-list split-tunnel-2 standard permit 10.0.3.0 255.255.255.0
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host 10.99.1.10 any4
access-list vpn-filter-foo@domain.x extended deny ip any4 any4
group-policy VPN-group-foo@domain.x internal
group-policy VPN-group-foo@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-2
 split-tunnel-policy tunnelspecified
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ip-address 10.99.1.10 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
 vpn-group-policy VPN-group-foo@domain.x
--
! split-tunnel-3
access-list split-tunnel-3 standard deny any4
--
! vpn-filter-unused@domain.x
access-list vpn-filter-unused@domain.x extended permit ip host 10.99.1.254 any4
access-list vpn-filter-unused@domain.x extended deny ip any4 any4
group-policy VPN-group-unused@domain.x internal
group-policy VPN-group-unused@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-3
 split-tunnel-policy tunnelspecified
username unused@domain.x nopassword
username unused@domain.x attributes
 vpn-framed-ip-address 10.99.1.254 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-unused@domain.x
 vpn-group-policy VPN-group-unused@domain.x
--
! vpn-filter-zzz
access-list vpn-filter-zzz extended permit ip 10.99.2.128 255.255.255.192 any4
access-list vpn-filter-zzz extended deny ip any4 any4
crypto ca certificate map ca-map-zzz 10
 subject-name attr ou co zzz
 extended-key-usage co 1.3.6.1.4.1.311.20.2.2
ip local pool pool-zzz 10.99.2.128-10.99.2.191 mask 255.255.255.192
group-policy VPN-group-zzz internal
group-policy VPN-group-zzz attributes
 address-pools value pool-zzz
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-zzz
 vpn-idle-timeout 120
tunnel-group VPN-tunnel-zzz type remote-access
tunnel-group VPN-tunnel-zzz general-attributes
 default-group-policy VPN-group-zzz
tunnel-group VPN-tunnel-zzz ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint2
 ikev1 user-authentication none
tunnel-group VPN-tunnel-zzz webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-zzz 10 VPN-tunnel-zzz
--
! inside_in
access-list inside_in extended permit icmp any4 any4 3
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--
! outside_in
object-group network g0
 network-object 10.99.1.10 255.255.255.254
 network-object host 10.99.1.254
 network-object 10.99.2.0 255.255.255.128
 network-object 10.99.2.128 255.255.255.192
object-group network g1
 network-object host 10.99.1.10
 network-object 10.99.2.64 255.255.255.192
object-group network g2
 network-object 10.0.1.0 255.255.255.0
 network-object 10.0.2.0 255.255.254.0
object-group network g3
 network-object 10.0.2.0 255.255.254.0
 network-object 10.0.4.0 255.255.255.0
access-list outside_in extended permit icmp object-group g0 any4 3
access-list outside_in extended permit tcp object-group g1 object-group g2 eq 80
access-list outside_in extended permit tcp host 10.99.1.11 object-group g3 eq 81
access-list outside_in extended permit tcp 10.99.2.0 255.255.255.192 object-group g3 range 81 82
access-list outside_in extended permit tcp 10.99.2.128 255.255.255.192 object-group g3 eq 82
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Missing radius_attribute check-subject-name';
############################################################

$in =~ s/check-subject-name = ou;//;

$out = <<'END';
Error: Missing radius_attribute 'check-subject-name'
 for host:id:domain.x.customers2
END

test_err($title, $in, $out);

############################################################
$title = 'Permit all ID hosts in network';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = network:customers1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
service:s2 = {
 user = host:id:bar@domain.x.customers1, network:customers2;
 permit src = user; dst = network:intern; prt = tcp 81;
}
END

$out = <<'END';
--asavpn
! VPN traffic is filtered at interface ACL
no sysopt connection permit-vpn
group-policy global internal
group-policy global attributes
 pfs enable
--
tunnel-group VPN-single type remote-access
tunnel-group VPN-single general-attributes
 authorization-server-group LOCAL
 default-group-policy global
 authorization-required
 username-from-certificate EA
tunnel-group VPN-single ipsec-attributes
 chain
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
--
! vpn-filter-bar@domain.x
access-list vpn-filter-bar@domain.x extended permit ip host 10.99.1.11 any4
access-list vpn-filter-bar@domain.x extended deny ip any4 any4
group-policy VPN-group-bar@domain.x internal
group-policy VPN-group-bar@domain.x attributes
 banner value Willkommen zu Hause
username bar@domain.x nopassword
username bar@domain.x attributes
 vpn-framed-ip-address 10.99.1.11 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-bar@domain.x
 vpn-group-policy VPN-group-bar@domain.x
--
! split-tunnel-1
access-list split-tunnel-1 standard permit 10.1.1.0 255.255.255.0
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host 10.99.1.10 any4
access-list vpn-filter-foo@domain.x extended deny ip any4 any4
group-policy VPN-group-foo@domain.x internal
group-policy VPN-group-foo@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ip-address 10.99.1.10 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
 vpn-group-policy VPN-group-foo@domain.x
--
! outside_in
object-group network g0
 network-object 10.99.1.10 255.255.255.254
 network-object host 10.99.1.254
 network-object 10.99.2.0 255.255.255.128
 network-object 10.99.2.128 255.255.255.192
object-group network g1
 network-object host 10.99.1.10
 network-object host 10.99.1.254
object-group network g2
 network-object 10.99.2.0 255.255.255.128
 network-object 10.99.2.128 255.255.255.192
access-list outside_in extended permit icmp object-group g0 any4 3
access-list outside_in extended permit tcp object-group g1 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended permit tcp object-group g2 10.1.1.0 255.255.255.0 eq 81
access-list outside_in extended permit tcp host 10.99.1.11 10.1.1.0 255.255.255.0 range 80 81
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'ASA, VPN in CONTEXT';
############################################################
# This line is missing from config:
#  ikev1 user-authentication none

($in = $topo) =~ s/ASA, VPN/ASA, VPN, CONTEXT/;

$out = <<'END';
--asavpn
tunnel-group VPN-single type remote-access
tunnel-group VPN-single general-attributes
 authorization-server-group LOCAL
 default-group-policy global
 authorization-required
 username-from-certificate EA
tunnel-group VPN-single ipsec-attributes
 chain
 ikev1 trust-point ASDM_TrustPoint1
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
END

test_run($title, $in, $out);

############################################################
$title = 'Bad check-extended-key-usage';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.2.0/24; }

router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip = 10.1.2.1; hardware = e0; }
 interface:trans = { ip = 10.9.9.1; hardware = e1; }
}
network:trans = { ip = 10.9.9.0/24; }
router:gw = {
 interface:trans = { ip = 10.9.9.2; }
 interface:dmz = { ip = 192.168.0.2; }
}

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
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip = 10.9.9.3; }
 interface:customers1;
 interface:customers2;
 interface:customers3;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 radius_attributes = { check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2; }

 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:id:bar@domain.x = { ip = 10.99.1.11;
  radius_attributes = { check-extended-key-usage = bar; }}
 host:id:@domain.x = { range = 10.99.1.12-10.99.1.15; }
 host:id:@domain.y = { range = 10.99.1.16-10.99.1.31; }
}
network:customers2 = {
 ip = 10.99.2.0/24;
 radius_attributes = { check-extended-key-usage = foo; }

 host:id:foo@domain.y = { ip = 10.99.2.10; }
}
network:customers3 = {
 ip = 10.99.3.0/24;
 host:id:foo@domain.z = { ip = 10.99.3.10;
  radius_attributes = { check-extended-key-usage = foo; }}
 host:id:bar@domain.z = { ip = 10.99.3.11;
  radius_attributes = { check-extended-key-usage = foo; }}
}
END

$out = <<'END';
Error: All ID hosts having domain '@domain.x' must use identical value from 'check_expanded_key_usage'
Error: All ID hosts having domain '@domain.y' must use identical value from 'check_expanded_key_usage'
END

test_err($title, $in, $out, '--noauto_default_route');

############################################################
$title = 'VPN ASA with internal software clients';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.2.0/24; }

router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip = 10.1.2.1; hardware = e0; }
 interface:trans = { ip = 10.9.9.1; hardware = e1; }
}
network:trans = { ip = 10.9.9.0/24; }
router:gw = {
 interface:trans = { ip = 10.9.9.2; }
 interface:dmz = { ip = 192.168.0.2; }
}

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
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip = 10.9.9.3; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 radius_attributes = { check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2; }

 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:id:long-first-name.long-second-name@long-domain.xyz = {
  ip = 10.99.1.11;
  radius_attributes = { banner = Willkommen zu Hause; }
 }
}

# Protocol modifiers src_net, dst_net must leave id-hosts unchanged.
protocol:ping_net = icmp 8, src_net, dst_net;

service:test1 = {
 user = host:id:foo@domain.x.customers1,
        host:id:long-first-name.long-second-name@long-domain.xyz.customers1;
 permit src = user; dst = network:intern; prt = tcp 80, protocol:ping_net;
 permit src = network:intern; dst = user; prt = protocol:ping_net;
}

END

$out = <<'END';
--r
! [ Routing ]
ip route 10.99.1.0 255.255.255.0 10.9.9.2
--asavpn
! [ Routing ]
route outside 10.1.2.0 255.255.255.0 192.168.0.2
route outside 10.9.9.0 255.255.255.0 192.168.0.2
route outside 10.99.1.0 255.255.255.0 192.168.0.2
--
tunnel-group VPN-single type remote-access
tunnel-group VPN-single general-attributes
 authorization-server-group LOCAL
 default-group-policy global
 authorization-required
 username-from-certificate EA
tunnel-group VPN-single ipsec-attributes
 chain
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host 10.99.1.10 any4
access-list vpn-filter-foo@domain.x extended deny ip any4 any4
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ip-address 10.99.1.10 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
--
! vpn-filter-1
access-list vpn-filter-1 extended permit ip host 10.99.1.11 any4
access-list vpn-filter-1 extended deny ip any4 any4
group-policy VPN-group-1 internal
group-policy VPN-group-1 attributes
 banner value Willkommen zu Hause
username long-first-name.long-second-name@long-domain.xyz nopassword
username long-first-name.long-second-name@long-domain.xyz attributes
 vpn-framed-ip-address 10.99.1.11 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-1
 vpn-group-policy VPN-group-1
--
crypto ca certificate map ca-map-@domain.x 10
 subject-name attr ea co @domain.x
 extended-key-usage co 1.3.6.1.4.1.311.20.2.2
crypto ca certificate map ca-map-@long-domain.xyz 10
 subject-name attr ea co @long-domain.xyz
 extended-key-usage co 1.3.6.1.4.1.311.20.2.2
webvpn
 certificate-group-map ca-map-@domain.x 10 VPN-single
 certificate-group-map ca-map-@long-domain.xyz 10 VPN-single
--
! outside_in
access-list outside_in extended permit icmp any4 any4 3
access-list outside_in extended permit icmp 10.1.2.0 255.255.255.0 10.99.1.10 255.255.255.254 8
access-list outside_in extended permit tcp 10.99.1.10 255.255.255.254 10.1.2.0 255.255.255.0 eq 80
access-list outside_in extended permit icmp 10.99.1.10 255.255.255.254 10.1.2.0 255.255.255.0 8
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out, '--noauto_default_route');

############################################################
$title = 'Missing route for VPN ASA with internal software clients';
############################################################

$in .= <<'END';
router:gw2 = {
 interface:trans = { ip = 10.9.9.4; }
 interface:dmz = { ip = 192.168.0.4; }
}
END

$out = <<END;
Error: Can\'t determine next hop to reach network:trans while moving routes
 of interface:asavpn.tunnel:softclients to interface:asavpn.dmz.
 Exactly one route is needed, but 2 candidates were found:
 - interface:gw.dmz
 - interface:gw2.dmz
Error: Two static routes for network:intern
 at interface:asavpn.dmz via interface:gw2.dmz and interface:gw.dmz
Error: Two static routes for network:trans
 at interface:asavpn.dmz via interface:gw2.dmz and interface:gw.dmz
Error: Two static routes for network:customers1
 at interface:r.trans via interface:gw2.trans and interface:gw.trans
END

test_err($title, $in, $out);

############################################################
$title = 'NAT with VPN ASA';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.2.0/24; nat:E = { ip = 192.168.2.0/24; } }

network:trans = { ip = 10.9.9.0/24; }
router:gw = {
 interface:intern = { ip = 10.1.2.1; hardware = e0; }
 interface:trans = { ip = 10.9.9.2; }
 interface:dmz = { ip = 192.168.0.2; }
}

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = { trust-point = ASDM_TrustPoint1; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn;
  hardware = outside;
  bind_nat = I;
  no_check;
 }
 interface:extern = {
  ip = 192.168.1.1;
  hardware = extern;
  bind_nat = E;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip = 10.9.9.3; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 nat:E = { ip = 192.168.99.0/24; }
 host:id:foo@domain.x = { ip = 10.99.1.10; }
}

network:extern = { ip = 192.168.1.0/24; nat:I = { ip = 10.7.7.0/24; }}

service:test1 = {
 user = host:id:foo@domain.x.customers1;
 permit src = user; dst = network:intern; prt = tcp 80;
 permit src = user; dst = network:extern; prt = tcp 81;
}

service:test2 = {
 user = network:extern;
 permit src = user; dst = network:intern; prt = tcp 82;
 permit src = user; dst = network:customers1; prt = tcp 83;
 permit src = network:intern; dst = user; prt = tcp 84;
}
END

$out = <<'END';
-- asavpn
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host 10.99.1.10 any4
access-list vpn-filter-foo@domain.x extended deny ip any4 any4
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ip-address 10.99.1.10 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
--
! outside_in
access-list outside_in extended permit tcp 10.1.2.0 255.255.255.0 10.7.7.0 255.255.255.0 eq 84
access-list outside_in extended permit tcp host 10.99.1.10 10.1.2.0 255.255.255.0 eq 80
access-list outside_in extended permit tcp host 10.99.1.10 10.7.7.0 255.255.255.0 eq 81
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--
! extern_in
access-list extern_in extended permit tcp 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0 eq 82
access-list extern_in extended permit tcp 192.168.1.0 255.255.255.0 192.168.99.0 255.255.255.0 eq 83
access-list extern_in extended deny ip any4 any4
access-group extern_in in interface extern
END

test_run($title, $in, $out);

############################################################
$title = 'Mixed NAT at ASA crypto interface (1)';
############################################################

# Must use NAT ip of internal network, not NAT ip of internet
# at crypto interface for network:n2.
# Ignore hidden NAT tag from internet.

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.101;
  hardware = inside;
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

network:internet = { ip = 0.0.0.0/0; has_subnets; host:X = { ip = 1.2.3.4; } }

router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:soft1;
}

network:soft1 = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
  radius_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}

router:Firewall = {
 managed;
 model = Linux;
 interface:internet = { negotiated; hardware = internet; bind_nat = h; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24;}

router:r1 = {
 interface:n1 = { ip = 10.1.1.2; bind_nat = n2; }
 interface:n3 = { ip = 10.1.3.2; bind_nat = x; }
 interface:n2 = { ip = 172.17.0.1; }
}

network:n2 = {
 ip = 172.17.0.0/16;
 nat:n2 = { ip = 10.1.2.0/24; dynamic; }
 nat:x = { ip = 10.1.99.0/24; dynamic; }
 nat:h = { hidden; }
}

service:s1 = {
 user = host:id:foo@domain.x.soft1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
-- asavpn
! [ Routing ]
route inside 10.1.2.0 255.255.255.0 10.1.1.2
route outside 0.0.0.0 0.0.0.0 192.168.0.1
--
! split-tunnel-1
access-list split-tunnel-1 standard permit 10.1.2.0 255.255.255.0
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host 10.99.1.10 any4
access-list vpn-filter-foo@domain.x extended deny ip any4 any4
group-policy VPN-group-foo@domain.x internal
group-policy VPN-group-foo@domain.x attributes
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ip-address 10.99.1.10 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
 vpn-group-policy VPN-group-foo@domain.x
--
! outside_in
access-list outside_in extended permit tcp host 10.99.1.10 10.1.2.0 255.255.255.0 eq 22
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Mixed NAT at ASA crypto interface (2)';
############################################################
# No error, because NAT isn't applicable for encrypted packets.

$in =~ s/hidden/ip = 10.2.2.0\/24; dynamic/;

$out = <<'END';
-- asavpn
! [ Routing ]
route inside 10.1.2.0 255.255.255.0 10.1.1.2
route outside 0.0.0.0 0.0.0.0 192.168.0.1
END

test_run($title, $in, $out);

############################################################
$title = 'Mixed NAT at ASA crypto interface (3)';
############################################################

# Must use NAT IP of internal network, not NAT IP of internet
# at crypto interface for network:n2.
# Ignore hidden NAT tag from internal network.

$in = $crypto_sts . <<'END';
network:n1 = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:sts;
  hardware = outside;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern = {
 interface:dmz = { ip = 192.168.0.1; bind_nat = n; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }


router:fw-extern = {
 managed;
 model = ASA;
 interface:internet = {
  ip = 1.1.1.1;
  bind_nat = x;
  routing = dynamic;
  hardware = outside;
 }
 interface:dmz1 = { ip = 10.254.254.144; hardware = inside; }
}

network:dmz1 = {
 ip = 10.254.254.0/24;
 nat:x = { ip = 1.2.3.129/32; dynamic; }
 nat:n = { ip = 1.2.3.4/32; dynamic; }
 nat:h = { hidden; }
}

router:vpn1 = {
 interface:dmz1 = {
  ip = 10.254.254.6;
  id = cert@example.com;
  spoke = crypto:sts;
  bind_nat = lan1;
 }
 interface:lan1;
}

network:lan1 = {
 ip = 10.99.1.0/24;
 nat:lan1 = { ip = 10.10.10.0/24; }
}

router:Firewall = {
 managed;
 model = Linux;
 interface:internet = { negotiated; hardware = internet; bind_nat = x; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; bind_nat = h; }
}

network:n3 = { ip = 10.1.3.0/24;}
network:n4 = { ip = 10.1.4.0/24;}

router:r1 = {
 interface:n1 = { ip = 10.1.1.2; bind_nat = h; }
 interface:n2 = { ip = 172.17.0.1; }
 interface:n3 = { ip = 10.1.3.2; bind_nat = n; }
}

network:n2 = {
 ip = 172.17.0.0/16;
 nat:h = { hidden; }
 nat:n = { ip = 10.1.2.0/24; dynamic; }
 nat:x = { ip = 99.99.99.0/24; dynamic; }
}
END

$out = <<'END';
-- asavpn
! [ Routing ]
route outside 1.2.3.4 255.255.255.255 192.168.0.1
END

test_run($title, $in, $out);

############################################################
$title = 'Directly connected software clients';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed;
# routing = manual;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}

router:softclients = {
 interface:n1 = {
  spoke = crypto:vpn;
  ip = 10.1.1.2;
 }
 interface:clients;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}

service:s1 = {
 user = host:id:foo@domain.x.clients;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<END;
-- asavpn
! [ Routing ]
route n1 10.99.1.0 255.255.255.0 10.1.1.2
--
! n1_in
access-list n1_in extended permit tcp host 10.99.1.10 10.1.1.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'Directly connected software clients; peer without IP';
############################################################

$in =~ s/ip = 10.1.1.2;//;

$out = <<END;
Error: interface:softclients.n1 used to reach software clients
 must not be directly connected to interface:asavpn.n1
 Connect it to some network behind next hop
END

test_err($title, $in, $out);

############################################################
$title = 'Directly connected software clients; without routing';
############################################################

$in =~ s/# routing = manual/ routing = manual/;

$out = <<END;
-- asavpn
! n1_in
access-list n1_in extended permit tcp host 10.99.1.10 10.1.1.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'No secondary optimization for incoming ID host';
############################################################

$in = $crypto_vpn . <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:asavpn = {
 model = ASA, VPN;
 managed = secondary;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n2 = {
  ip = 10.1.2.2;
  hub = crypto:vpn;
  hardware = n2;
  no_check;
 }
}

router:softclients = {
 interface:n2 = {
  spoke = crypto:vpn;
  ip = 10.1.2.3;
 }
 interface:clients;
}

network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}

service:s1 = {
 user = host:id:foo@domain.x.clients;
 permit src = user; dst = host:h1; prt = tcp 80;
 permit src = host:h1; dst = user; prt = tcp 22;
}
END

$out = <<END;
-- asavpn
! n2_in
access-list n2_in extended permit ip 10.1.1.0 255.255.255.0 host 10.99.1.10
access-list n2_in extended permit ip host 10.99.1.10 10.1.1.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Empty software clients';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.2.0/24; }

network:trans = { ip = 10.9.9.0/24; }
router:gw = {
 interface:intern = { ip = 10.1.2.1; hardware = e0; }
 interface:trans = { ip = 10.9.9.2; }
 interface:dmz = { ip = 192.168.0.2; }
}

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = { trust-point = ASDM_TrustPoint1; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip = 10.9.9.3; }
}
END

$out = <<END;
-- asavpn
! outside_in
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Must not use aggregate with software clients';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.2.0/24;}

router:gw = {
 interface:intern;
 interface:dmz = { ip = 192.168.0.2; }
}

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
  no_check;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:softclients = {
 interface:intern = { spoke = crypto:vpn; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}

service:test1 = {
 user = any:[network:customers1];
 permit src = user; dst = network:intern; prt = tcp 80;
}
END

$out = <<END;
Warning: Ignoring any:[network:tunnel:softclients] with software clients in src of rule in service:test1
END

test_warn($title, $in, $out);

############################################################
$title = 'Duplicate ID-hosts';
############################################################

$in = $crypto_vpn . <<'END';
crypto:vpn2 = {
 type = ipsec:aes256SHA;
}

network:intern = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz1 = {
  ip = 192.168.1.1;
  hub = crypto:vpn;
  hardware = dmz1;
 }
 interface:dmz2 = {
  ip = 192.168.2.1;
  hub = crypto:vpn2;
  hardware = dmz2;
 }
}

network:dmz1 = { ip = 192.168.1.0/24; }

router:extern = {
 interface:dmz1 = { ip = 192.168.1.2; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:softclients1 = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
 interface:customers2;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
}

network:customers2 = {
 ip = 10.99.2.0/24;
 host:id:foo@domain.x = { ip = 10.99.2.10; }
}

network:dmz2 = { ip = 192.168.2.0/24; }

router:gw = {
 interface:dmz2 = { ip = 192.168.2.2; }
 interface:trans = { ip = 10.9.9.2; }
}

network:trans = { ip = 10.9.9.0/24; }

router:softclients2 = {
 interface:trans = { spoke = crypto:vpn2; ip = 10.9.9.3; }
 interface:customers3;
}

network:customers3 = {
 ip = 10.99.3.0/24;
 host:id:foo@domain.x = { ip = 10.99.3.10; }
}

service:test1 = {
 user = host:id:foo@domain.x.customers1,
        host:id:foo@domain.x.customers2,
        host:id:foo@domain.x.customers3,
 ;
 permit src = user; dst = network:intern; prt = tcp 80;
}
END

$out = <<'END';
Error: Duplicate ID-host foo@domain.x from network:customers1 and network:customers2 at router:asavpn
Error: Duplicate ID-host foo@domain.x from network:customers3 and network:customers1 at router:asavpn
END

test_err($title, $in, $out);

############################################################
$title = 'ASA with two crypto spokes and NAT';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha384;
 pfs_group = 15;
 lifetime = 3600 sec;
}

isakmp:aes256SHA = {
 ike_version = 1;
 identity = address;
 nat_traversal = additional;
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 15;
 lifetime = 43200 sec;
 trust_point = ASDM_TrustPoint3;
}

ipsec:3desSHA = {
 key_exchange = isakmp:3desSHA;
 esp_encryption = 3des;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}

isakmp:3desSHA = {
 ike_version = 1;
 identity = address;
 authentication = preshare;
 encryption = 3des;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}

crypto:sts1 = {
 type = ipsec:aes256SHA;
}

crypto:sts2 = {
 type = ipsec:3desSHA;
 detailed_crypto_acl;
}

network:intern = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  bind_nat = lan2a;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:sts1, crypto:sts2;
  hardware = outside;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:vpn1 = {
 interface:internet = {
  ip = 172.16.1.2;
  id = cert@example.com;
  spoke = crypto:sts1;
 }
 interface:lan1 = {
  ip = 10.99.1.1;
 }
}

network:lan1 = { ip = 10.99.1.0/24; }

router:vpn2 = {
 interface:internet = {
  ip = 172.16.2.2;
  spoke = crypto:sts2;
 }
 interface:lan2 = {
  ip = 10.99.2.1;
 }
 interface:lan2a = {
  ip = 192.168.22.1;
 }
}

network:lan2 = { ip = 10.99.2.0/24; }

network:lan2a = {
 ip = 192.168.22.0/24;
 nat:lan2a = { ip = 10.99.22.0/24;}
}

protocol:http = tcp 80;
service:test = {
 user = network:lan1, network:lan2, network:lan2a;
 permit src = user; dst = host:netspoc; prt = protocol:http;
}
END

$out = <<'END';
--asavpn
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec ikev1 transform-set Trans2 esp-aes-256 esp-sha384-hmac
--
! crypto-172.16.1.2
access-list crypto-172.16.1.2 extended permit ip any4 10.99.1.0 255.255.255.0
crypto map crypto-outside 1 set peer 172.16.1.2
crypto map crypto-outside 1 match address crypto-172.16.1.2
crypto map crypto-outside 1 set ikev1 transform-set Trans2
crypto map crypto-outside 1 set pfs group15
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group 172.16.1.2 type ipsec-l2l
tunnel-group 172.16.1.2 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 172.16.1.2
--
! crypto-172.16.2.2
access-list crypto-172.16.2.2 extended permit ip 10.1.1.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-172.16.2.2 extended permit ip 10.1.1.0 255.255.255.0 192.168.22.0 255.255.255.0
crypto map crypto-outside 2 set peer 172.16.2.2
crypto map crypto-outside 2 match address crypto-172.16.2.2
crypto map crypto-outside 2 set ikev1 transform-set Trans1
crypto map crypto-outside 2 set pfs group2
crypto map crypto-outside 2 set security-association lifetime seconds 600
tunnel-group 172.16.2.2 type ipsec-l2l
tunnel-group 172.16.2.2 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside interface outside
--
! outside_in
object-group network g0
 network-object 10.99.1.0 255.255.255.0
 network-object 10.99.2.0 255.255.255.0
 network-object 192.168.22.0 255.255.255.0
access-list outside_in extended permit tcp object-group g0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'ASA with two crypto spokes and NAT (IKEv2)';
############################################################

$in =~ s/ike_version = 1/ike_version = 2/g;

$out = <<'END';
--asavpn
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption 3des
 protocol esp integrity sha-1
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
--
! crypto-172.16.1.2
access-list crypto-172.16.1.2 extended permit ip any4 10.99.1.0 255.255.255.0
crypto map crypto-outside 1 set peer 172.16.1.2
crypto map crypto-outside 1 match address crypto-172.16.1.2
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 1 set pfs group15
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group 172.16.1.2 type ipsec-l2l
tunnel-group 172.16.1.2 ipsec-attributes
 ikev2 local-authentication certificate ASDM_TrustPoint3
 ikev2 remote-authentication certificate
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 172.16.1.2
--
! crypto-172.16.2.2
access-list crypto-172.16.2.2 extended permit ip 10.1.1.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-172.16.2.2 extended permit ip 10.1.1.0 255.255.255.0 192.168.22.0 255.255.255.0
crypto map crypto-outside 2 set peer 172.16.2.2
crypto map crypto-outside 2 match address crypto-172.16.2.2
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans1
crypto map crypto-outside 2 set pfs group2
crypto map crypto-outside 2 set security-association lifetime seconds 600
tunnel-group 172.16.2.2 type ipsec-l2l
tunnel-group 172.16.2.2 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside interface outside
--
! outside_in
object-group network g0
 network-object 10.99.1.0 255.255.255.0
 network-object 10.99.2.0 255.255.255.0
 network-object 192.168.22.0 255.255.255.0
access-list outside_in extended permit tcp object-group g0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'IOS with two crypto spokes and NAT (IKEv2)';
############################################################

$in =~ s/ASA/IOS/g;

$out = <<'END';
--asavpn
! [ Crypto ]
crypto isakmp policy 1
 authentication pre-share
 encryption 3des
 hash sha
 group 2
crypto isakmp policy 2
 encryption aes 256
 hash sha
 group 15
 lifetime 43200
crypto ipsec transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec transform-set Trans2 esp-aes 256 esp-sha384-hmac
ip access-list extended crypto-172.16.1.2
 permit ip any 10.99.1.0 0.0.0.255
ip access-list extended crypto-filter-172.16.1.2
 permit tcp 10.99.1.0 0.0.0.255 host 10.1.1.111 eq 80
 deny ip any any
crypto map crypto-outside 1 ipsec-isakmp
 set peer 172.16.1.2
 match address crypto-172.16.1.2
 set ip access-group crypto-filter-172.16.1.2 in
 set transform-set Trans2
 set pfs group15
ip access-list extended crypto-172.16.2.2
 permit ip 10.1.1.0 0.0.0.255 10.99.2.0 0.0.0.255
 permit ip 10.1.1.0 0.0.0.255 192.168.22.0 0.0.0.255
ip access-list extended crypto-filter-172.16.2.2
 permit tcp 10.99.2.0 0.0.0.255 host 10.1.1.111 eq 80
 permit tcp 192.168.22.0 0.0.0.255 host 10.1.1.111 eq 80
 deny ip any any
crypto map crypto-outside 2 ipsec-isakmp
 set peer 172.16.2.2
 match address crypto-172.16.2.2
 set ip access-group crypto-filter-172.16.2.2 in
 set transform-set Trans1
 set pfs group2
 set security-association lifetime seconds 600
END

test_run($title, $in, $out);

############################################################
$title = 'ASA with two dynamic crypto spokes';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha384;
 pfs_group = 15;
 lifetime = 3600 sec;
}

isakmp:aes256SHA = {
 ike_version = 2;
 identity = address;
 nat_traversal = additional;
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 15;
 lifetime = 43200 sec;
 trust_point = ASDM_TrustPoint3;
}

ipsec:3desSHA = {
 key_exchange = isakmp:3desSHA;
 esp_encryption = 3des;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}

isakmp:3desSHA = {
 ike_version = 1;
 identity = address;
 authentication = rsasig;
 encryption = 3des;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
 trust_point = ASDM_TrustPoint1;
}

crypto:sts1 = {
 type = ipsec:aes256SHA;
}

crypto:sts2 = {
 type = ipsec:3desSHA;
 detailed_crypto_acl;
}

network:intern = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  bind_nat = lan2a;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:sts1, crypto:sts2;
  hardware = outside;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:vpn1 = {
 interface:internet = {
  negotiated;
  spoke = crypto:sts1;
  id = vpn1@example.com;
 }
 interface:lan1 = {
  ip = 10.99.2.1;
 }
}

network:lan1 = { ip = 10.99.2.0/24; }

router:vpn2 = {
 interface:internet = {
  negotiated;
  spoke = crypto:sts2;
  id = vpn2@example.com;
 }
 interface:lan2 = {
  ip = 10.99.3.1;
 }
 interface:lan2a = {
  ip = 192.168.22.1;
 }
}

network:lan2 = { ip = 10.99.3.0/24; }

network:lan2a = {
 ip = 192.168.22.0/24;
 nat:lan2a = { ip = 10.99.22.0/24;}
}

protocol:http = tcp 80;
service:test = {
 user = network:lan1, network:lan2, network:lan2a;
 permit src = user; dst = host:netspoc; prt = protocol:http;
}
END

# Use individual routes to VPN peers, even if all have same next hop.
$out = <<'END';
--asavpn
! [ Routing ]
route outside 10.99.2.0 255.255.255.0 192.168.0.1
route outside 10.99.3.0 255.255.255.0 192.168.0.1
route outside 192.168.22.0 255.255.255.0 192.168.0.1
route outside 0.0.0.0 0.0.0.0 192.168.0.1
--
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
--
! crypto-vpn1@example.com
access-list crypto-vpn1@example.com extended permit ip any4 10.99.2.0 255.255.255.0
crypto dynamic-map vpn1@example.com 10 match address crypto-vpn1@example.com
crypto dynamic-map vpn1@example.com 10 set ikev2 ipsec-proposal Trans2
crypto dynamic-map vpn1@example.com 10 set pfs group15
crypto dynamic-map vpn1@example.com 10 set security-association lifetime seconds 3600
crypto map crypto-outside 65535 ipsec-isakmp dynamic vpn1@example.com
tunnel-group vpn1@example.com type ipsec-l2l
tunnel-group vpn1@example.com ipsec-attributes
 ikev2 local-authentication certificate ASDM_TrustPoint3
 ikev2 remote-authentication certificate
crypto ca certificate map vpn1@example.com 10
 subject-name attr ea eq vpn1@example.com
tunnel-group-map vpn1@example.com 10 vpn1@example.com
--
! crypto-vpn2@example.com
access-list crypto-vpn2@example.com extended permit ip 10.1.1.0 255.255.255.0 10.99.3.0 255.255.255.0
access-list crypto-vpn2@example.com extended permit ip 10.1.1.0 255.255.255.0 192.168.22.0 255.255.255.0
crypto dynamic-map vpn2@example.com 10 match address crypto-vpn2@example.com
crypto dynamic-map vpn2@example.com 10 set ikev1 transform-set Trans1
crypto dynamic-map vpn2@example.com 10 set pfs group2
crypto dynamic-map vpn2@example.com 10 set security-association lifetime seconds 600
crypto map crypto-outside 65534 ipsec-isakmp dynamic vpn2@example.com
tunnel-group vpn2@example.com type ipsec-l2l
tunnel-group vpn2@example.com ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
crypto ca certificate map vpn2@example.com 10
 subject-name attr ea eq vpn2@example.com
tunnel-group-map vpn2@example.com 10 vpn2@example.com
crypto map crypto-outside interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Must not reuse crypto id';
############################################################

$in =~ s/vpn2[@]/vpn1@/;

$out = <<'END';
Error: Must not reuse 'id = vpn1@example.com' at different crypto spokes of 'router:asavpn':
 - interface:vpn1.tunnel:vpn1
 - interface:vpn2.tunnel:vpn2
END

test_err($title, $in, $out);

############################################################
$title = 'Unexpected dynamic crypto spoke';
############################################################

$in = <<'END';
crypto:psk-detailed = {
 type = ipsec:aes256_sha256_ikev2_psk;
 detailed_crypto_acl;
}
ipsec:aes256_sha256_ikev2_psk = {
 key_exchange = isakmp:aes256_sha256_ikev2_psk;
 esp_encryption = aes256;
 esp_authentication = sha256;
 pfs_group = 19;
 lifetime = 3600 sec;
}
isakmp:aes256_sha256_ikev2_psk = {
 ike_version = 2;
 identity = address;
 nat_traversal = additional;
 authentication = preshare;
 encryption = aes256;
 hash = sha256;
 group = 19;
 lifetime = 86400 sec;
}

network:n1 = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:dmz = { ip = 192.168.1.4; hardware = dmz;
                   hub = crypto:psk-detailed; }
}
network:dmz = { ip = 192.168.1.0/27;}

router:r1 = {
 interface:dmz = { ip = 192.168.1.2; spoke = crypto:psk-detailed; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24;}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
--asavpn
! crypto-192.168.1.2
access-list crypto-192.168.1.2 extended permit ip 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0
crypto map crypto-dmz 1 set peer 192.168.1.2
crypto map crypto-dmz 1 match address crypto-192.168.1.2
crypto map crypto-dmz 1 set ikev2 ipsec-proposal Trans1
crypto map crypto-dmz 1 set pfs group19
crypto map crypto-dmz 1 set security-association lifetime seconds 3600
tunnel-group 192.168.1.2 type ipsec-l2l
tunnel-group 192.168.1.2 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-dmz interface dmz
--
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 22
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'Unexpected dynamic crypto spoke';
############################################################

$in = $crypto_sts . <<'END';
network:intern = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:asavpn = {
 model = IOS;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:sts;
  hardware = outside;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:vpn1 = {
 interface:internet = {
  negotiated;
  spoke = crypto:sts;
  id = vpn1@example.com;
 }
 interface:lan1 = {
  ip = 10.99.2.1;
 }
}

network:lan1 = { ip = 10.99.2.0/24; }
END

$out = <<'END';
Error: router:asavpn can't establish crypto tunnel to interface:vpn1.internet with unknown IP
END

test_err($title, $in, $out);

############################################################
$title = 'VPN ASA to EZVPN router with two local networks';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint3;
  banner = Welcome at VPN service;
  dns-server = 10.1.1.10 10.1.1.11;
  wins-server = 10.1.1.20;
 }
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
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

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:vpn = {
 managed;
 model = IOS, EZVPN;
 interface:internet = {
  negotiated;
  spoke = crypto:vpn;
  id = abc@123.45;
  hardware = e1;
 }
 interface:lan2 = {
  ip = 10.99.2.1;
  hardware = e2;
 }
 interface:lan3 = {
  ip = 10.99.3.1;
  hardware = e3;
 }
}

network:lan2 = { ip = 10.99.2.0/24; }
network:lan3 = { ip = 10.99.3.0/24; }

service:test = {
 user = network:lan2, network:lan3;
 permit src = user; dst = network:intern; prt = tcp 80;
 permit src = network:intern; dst = user; prt = udp 123;
}
END

$out = <<'END';
--asavpn
tunnel-group VPN-single type remote-access
tunnel-group VPN-single general-attributes
 authorization-server-group LOCAL
 default-group-policy global
 authorization-required
 username-from-certificate EA
tunnel-group VPN-single ipsec-attributes
 chain
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
--
! vpn-filter-abc@123.45
access-list vpn-filter-abc@123.45 extended permit ip 10.99.2.0 255.255.254.0 any4
access-list vpn-filter-abc@123.45 extended deny ip any4 any4
group-policy VPN-router-abc@123.45 internal
group-policy VPN-router-abc@123.45 attributes
 banner value Welcome at VPN service
 dns-server value 10.1.1.10 10.1.1.11
 wins-server value 10.1.1.20
username abc@123.45 nopassword
username abc@123.45 attributes
 service-type remote-access
 vpn-filter value vpn-filter-abc@123.45
 vpn-group-policy VPN-router-abc@123.45
--
! outside_in
access-list outside_in extended permit icmp 10.99.2.0 255.255.254.0 any4 3
access-list outside_in extended permit tcp 10.99.2.0 255.255.254.0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--vpn
crypto ipsec client ezvpn vpn
 connect auto
 mode network-extension
 peer 192.168.0.101
 acl ACL-Split-Tunnel
 virtual-interface 1
 username test pass test
 xauth userid mode local
ip access-list extended ACL-Split-Tunnel
 permit ip 10.99.2.0 0.0.0.255 any
 permit ip 10.99.3.0 0.0.0.255 any
ip access-list extended ACL-crypto-filter
 deny ip any host 10.99.2.1
 deny ip any host 10.99.3.1
 permit udp 10.1.1.0 0.0.0.255 10.99.2.0 0.0.0.255 eq 123
 permit udp 10.1.1.0 0.0.0.255 10.99.3.0 0.0.0.255 eq 123
 permit tcp 10.1.1.0 0.0.0.255 10.99.2.0 0.0.0.255 established
 permit tcp 10.1.1.0 0.0.0.255 10.99.3.0 0.0.0.255 established
 deny ip any any
interface Virtual-Template1 type tunnel
 ip access-group ACL-crypto-filter in
--
ip access-list extended e1_in
 permit 50 host 192.168.0.101 any
 permit udp host 192.168.0.101 eq 500 any eq 500
 deny ip any any
--
ip access-list extended e2_in
 permit tcp 10.99.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 permit udp 10.99.2.0 0.0.0.255 eq 123 10.1.1.0 0.0.0.255
 deny ip any any
--
interface e1
 ip address negotiated
 crypto ipsec client ezvpn vpn
 ip access-group e1_in in
interface e2
 ip address 10.99.2.1 255.255.255.0
 crypto ipsec client ezvpn vpn inside
 ip access-group e2_in in
interface e3
 ip address 10.99.3.1 255.255.255.0
 crypto ipsec client ezvpn vpn inside
 ip access-group e3_in in
END

test_run($title, $in, $out);

############################################################
$title = 'VPN ASA to EZVPN ASA with two local networks';
############################################################

$in =~ s/IOS/ASA/;

$out = <<'END';
--vpn
! [ Routing ]
route e1 0.0.0.0 0.0.0.0 e1
--
! VPN traffic is filtered at interface ACL
no sysopt connection permit-vpn
--
! e1_in
access-list e1_in extended permit udp 10.1.1.0 255.255.255.0 10.99.2.0 255.255.254.0 eq 123
access-list e1_in extended deny ip any4 any4
access-group e1_in in interface e1
--
! e2_in
access-list e2_in extended permit tcp 10.99.2.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list e2_in extended deny ip any4 any4
access-group e2_in in interface e2
--
! e3_in
access-list e3_in extended permit tcp 10.99.3.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list e3_in extended deny ip any4 any4
access-group e3_in in interface e3
END

test_run($title, $in, $out);

############################################################
$title = 'Missing ID at EZVPN router to VPN ASA ';
############################################################

$in =~ s/id =/#id/;

$out = <<'END';
Error: interface:vpn.tunnel:vpn needs attribute 'id', because isakmp:aes256SHA has authentication=rsasig
END

test_err($title, $in, $out);

############################################################
$title = 'ASA as managed VPN spoke';
############################################################

$in = $crypto_sts . <<'END';
network:intern = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.1.1;
  hub = crypto:sts;
  hardware = outside;
 }
}

network:dmz = { ip = 192.168.1.0/24; }

router:vpn1 = {
 managed;
 model = ASA;
 interface:dmz = {
  ip = 192.168.1.2;
  id = cert@example.com;
  spoke = crypto:sts;
  hardware = GigabitEthernet0;
 }
 interface:lan1 = {
  ip = 10.99.1.1;
  hardware = Fastethernet8;
 }
}

network:lan1 = { ip = 10.99.1.0/24; }

service:test = {
 user = network:lan1;
 permit src = user; dst = network:intern; prt = tcp 80;
 permit src = network:intern; dst = user; prt = udp 123;
}
END

$out = <<'END';
--vpn1
! [ Routing ]
route GigabitEthernet0 10.1.1.0 255.255.255.0 192.168.1.1
--
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-aes-256 esp-sha-hmac
--
! crypto-192.168.1.1
access-list crypto-192.168.1.1 extended permit ip 10.99.1.0 255.255.255.0 any4
crypto map crypto-GigabitEthernet0 1 set peer 192.168.1.1
crypto map crypto-GigabitEthernet0 1 match address crypto-192.168.1.1
crypto map crypto-GigabitEthernet0 1 set ikev1 transform-set Trans1
crypto map crypto-GigabitEthernet0 1 set pfs group2
crypto map crypto-GigabitEthernet0 1 set security-association lifetime seconds 3600 kilobytes 100000
tunnel-group 192.168.1.1 type ipsec-l2l
tunnel-group 192.168.1.1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto map crypto-GigabitEthernet0 interface GigabitEthernet0
--
! GigabitEthernet0_in
access-list GigabitEthernet0_in extended permit udp 10.1.1.0 255.255.255.0 10.99.1.0 255.255.255.0 eq 123
access-list GigabitEthernet0_in extended deny ip any4 any4
access-group GigabitEthernet0_in in interface GigabitEthernet0
--
! Fastethernet8_in
access-list Fastethernet8_in extended permit tcp 10.99.1.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list Fastethernet8_in extended deny ip any4 any4
access-group Fastethernet8_in in interface Fastethernet8
END

test_run($title, $in, $out);

############################################################
$title = 'Missing trust_point in isakmp for spoke and hub';
############################################################

$in =~ s/trust_point/#trust_point/;

$out = <<"END";
Error: Missing attribute 'trust_point' in isakmp:aes256SHA for router:vpn1
Error: Missing attribute 'trust_point' in isakmp:aes256SHA for router:asavpn
END

test_err($title, $in, $out);

############################################################
# Shared topology for multiple tests.
############################################################

$topo = $crypto_sts . <<'END';
network:intern = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 1.2.3.2;
  hub = crypto:sts;
  hardware = outside;
 }
}

network:dmz = { ip = 1.2.3.0/25; }

router:extern = {
 interface:dmz = { ip = 1.2.3.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:firewall = {
 managed;
 model = ASA;
 interface:internet = {
  ip = 1.1.1.1;
  bind_nat = vpn1;
  routing = dynamic;
  hardware = outside;
 }
 interface:dmz1 = { ip = 10.254.254.144; hardware = inside; }
}

network:dmz1 = {
 ip = 10.254.254.0/24;
 nat:vpn1 = { ip = 1.2.3.129/32; dynamic; }
}

router:vpn1 = {
 managed;
 model = IOS;
 interface:dmz1 = {
  ip = 10.254.254.6;
id = cert@example.com;
  nat:vpn1 = { ip = 1.2.3.129; }
  spoke = crypto:sts;
  bind_nat = lan1;
  hardware = GigabitEthernet0;
 }
 interface:lan1 = {
  ip = 10.99.1.1, 10.99.1.253;
  hardware = Fastethernet8;
 }
}

network:lan1 = {
 ip = 10.99.1.0/24;
 nat:lan1 = { ip = 10.10.10.0/24; }
}
END

############################################################
$title = 'Create crypto ACL even if no rule is defined';
############################################################

$in = $topo . <<'END';
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
 permit src = host:netspoc; dst = user; prt = udp 123;
}
END

$out = <<'END';
--asavpn
! crypto-1.2.3.129
access-list crypto-1.2.3.129 extended permit ip any4 10.10.10.0 255.255.255.0
crypto map crypto-outside 1 set peer 1.2.3.129
crypto map crypto-outside 1 match address crypto-1.2.3.129
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600 kilobytes 100000
tunnel-group 1.2.3.129 type ipsec-l2l
tunnel-group 1.2.3.129 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 1.2.3.129
crypto map crypto-outside interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'NAT of IPSec traffic at ASA and NAT of VPN network at IOS';
############################################################

$in = $topo . <<'END';
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
 permit src = host:netspoc; dst = user; prt = udp 123;
}
END

$out = <<'END';
--asavpn
! crypto-1.2.3.129
access-list crypto-1.2.3.129 extended permit ip any4 10.10.10.0 255.255.255.0
crypto map crypto-outside 1 set peer 1.2.3.129
crypto map crypto-outside 1 match address crypto-1.2.3.129
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600 kilobytes 100000
tunnel-group 1.2.3.129 type ipsec-l2l
tunnel-group 1.2.3.129 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 1.2.3.129
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp 10.10.10.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--vpn1
ip access-list extended crypto-1.2.3.2
 permit ip 10.10.10.0 0.0.0.255 any
ip access-list extended crypto-filter-1.2.3.2
 deny ip any host 10.10.10.1
 deny ip any host 10.10.10.253
 permit udp host 10.1.1.111 10.10.10.0 0.0.0.255 eq 123
 permit tcp host 10.1.1.111 10.10.10.0 0.0.0.255 established
 deny ip any any
crypto map crypto-GigabitEthernet0 1 ipsec-isakmp
 set peer 1.2.3.2
 match address crypto-1.2.3.2
 set ip access-group crypto-filter-1.2.3.2 in
 set transform-set Trans1
 set pfs group2
 set security-association lifetime kilobytes 100000
--
ip access-list extended GigabitEthernet0_in
 permit 50 host 1.2.3.2 host 10.254.254.6
 permit udp host 1.2.3.2 eq 500 host 10.254.254.6 eq 500
 permit udp host 1.2.3.2 eq 4500 host 10.254.254.6 eq 4500
 deny ip any any
--firewall
! outside_in
access-list outside_in extended permit 50 host 1.2.3.2 host 1.2.3.129
access-list outside_in extended permit udp host 1.2.3.2 eq 500 host 1.2.3.129 eq 500
access-list outside_in extended permit udp host 1.2.3.2 eq 4500 host 1.2.3.129 eq 4500
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended permit 50 host 10.254.254.6 host 1.2.3.2
access-list inside_in extended permit udp host 10.254.254.6 eq 500 host 1.2.3.2 eq 500
access-list inside_in extended permit udp host 10.254.254.6 eq 4500 host 1.2.3.2 eq 4500
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = 'Create crypto ACL even no rule is defined';
############################################################

$in = $topo . <<'END';
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
 permit src = host:netspoc; dst = user; prt = udp 123;
}
END

$out = <<'END';
--asavpn
! crypto-1.2.3.129
access-list crypto-1.2.3.129 extended permit ip any4 10.10.10.0 255.255.255.0
crypto map crypto-outside 1 set peer 1.2.3.129
crypto map crypto-outside 1 match address crypto-1.2.3.129
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600 kilobytes 100000
tunnel-group 1.2.3.129 type ipsec-l2l
tunnel-group 1.2.3.129 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 1.2.3.129
crypto map crypto-outside interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'detailed_crypto_acl at managed spoke';
############################################################

($in = $topo) =~ s/(crypto:sts .*)/$1 detailed_crypto_acl;/;

$out = <<"END";
Error: Attribute 'detailed_crypto_acl' is not allowed for managed spoke router:vpn1
END

test_err($title, $in, $out);

############################################################
$title = "Don't add hidden network to crypto ACL";
############################################################

$in = $topo;
$in =~ s/(interface:lan1)/interface:lan2={ip=10.99.2.1;hardware=lan2;}$1/;
$in =~ s/bind_nat = lan1;/bind_nat = h, lan1; /;
$in .= <<'END';
network:lan2 = {
 ip = 10.99.2.0/24;
 nat:h = { hidden; }
}
END


$out = <<'END';
--asavpn
! crypto-1.2.3.129
access-list crypto-1.2.3.129 extended permit ip any4 10.10.10.0 255.255.255.0
crypto map crypto-outside 1 set peer 1.2.3.129
crypto map crypto-outside 1 match address crypto-1.2.3.129
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600 kilobytes 100000
tunnel-group 1.2.3.129 type ipsec-l2l
tunnel-group 1.2.3.129 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 1.2.3.129
crypto map crypto-outside interface outside
END

test_run($title, $in, $out);

############################################################
# Changed topology
############################################################

# Run next tests with changed group and default SA lifetime.
($topo = $crypto_sts) =~ s/group = 2/group = 15/g;
$topo =~ s/100000 kilobytes/4608000 kilobytes/;

$topo .= <<'END';
network:intern = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:vpn = {
 model = IOS;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = intern;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:sts;
  hardware = dmz;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:vpn1 = {
 interface:internet = {
  ip = 172.16.1.2;
  id = cert@example.com;
  spoke = crypto:sts;
 }
 interface:lan1 = {
  ip = 10.99.1.1;
 }
}

network:lan1 = { ip = 10.99.1.0/24; }
END

############################################################
$title = 'IOS router as VPN hub';
############################################################

$in = $topo . <<END;
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
}
END

$out = <<"END";
--vpn
crypto isakmp policy 1
 encryption aes 256
 hash sha
 group 15
 lifetime 43200
crypto ipsec transform-set Trans1 esp-aes 256 esp-sha-hmac
ip access-list extended crypto-172.16.1.2
 permit ip any 10.99.1.0 0.0.0.255
ip access-list extended crypto-filter-172.16.1.2
 permit tcp 10.99.1.0 0.0.0.255 host 10.1.1.111 eq 80
 deny ip any any
crypto map crypto-dmz 1 ipsec-isakmp
 set peer 172.16.1.2
 match address crypto-172.16.1.2
 set ip access-group crypto-filter-172.16.1.2 in
 set transform-set Trans1
 set pfs group15
--
ip access-list extended intern_in
 permit tcp host 10.1.1.111 10.99.1.0 0.0.0.255 established
 deny ip any any
--
ip access-list extended dmz_in
 permit 50 host 172.16.1.2 host 192.168.0.101
 permit udp host 172.16.1.2 eq 500 host 192.168.0.101 eq 500
 permit udp host 172.16.1.2 eq 4500 host 192.168.0.101 eq 4500
 deny ip any any
--
interface intern
 ip address 10.1.1.101 255.255.255.0
 ip access-group intern_in in
interface dmz
 ip address 192.168.0.101 255.255.255.0
 crypto map crypto-dmz
 ip access-group dmz_in in
END

test_run($title, $in, $out);

############################################################
$title = 'Must not use EZVPN as hub';
############################################################

($in = $topo) =~ s/IOS/IOS, EZVPN/;

$out = <<"END";
Error: Must not use router:vpn of model 'IOS, EZVPN' as crypto hub
END

test_err($title, $in, $out);

############################################################
$title = 'Unmanaged VPN spoke with unknown ID';
############################################################

$in = $crypto_sts . <<'END';
network:intern = { ip = 10.1.1.0/24; }

router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 1.2.3.2;
  hub = crypto:sts;
  hardware = outside;
 }
}

network:dmz = { ip = 1.2.3.0/25; }

router:extern = {
 interface:dmz = { ip = 1.2.3.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:vpn1 = {
 interface:internet = {
    ip = 1.1.1.1;
#  id = cert@example.com;
  spoke = crypto:sts;
 }
 interface:lan1;
}

network:lan1 = { ip = 10.99.1.0/24; }
END


$out = <<"END";
Error: interface:vpn1.tunnel:vpn1 needs attribute \'id\', because isakmp:aes256SHA has authentication=rsasig
END

test_err($title, $in, $out);

############################################################
$title = 'Unmanaged VPN spoke with known ID';
############################################################

$in =~ s/#  id/  id/;

$out = <<'END';
--asavpn
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-aes-256 esp-sha-hmac
--
! crypto-1.1.1.1
access-list crypto-1.1.1.1 extended permit ip any4 10.99.1.0 255.255.255.0
crypto map crypto-outside 1 set peer 1.1.1.1
crypto map crypto-outside 1 match address crypto-1.1.1.1
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600 kilobytes 100000
tunnel-group 1.1.1.1 type ipsec-l2l
tunnel-group 1.1.1.1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 1.1.1.1
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Must not traverse crypto interface';
############################################################

$in .= <<END;
service:t = {
 user = network:intern;
 permit src = user; dst = network:dmz; prt = tcp 80;
}
END

$out = <<'END';
Error: No valid path
 from any:[network:intern]
 to any:[network:dmz]
 for rule permit src=network:intern; dst=network:dmz; prt=tcp 80; of service:t
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:intern]
 to any:[network:dmz]
 for rule permit src=network:intern; dst=network:dmz; prt=tcp 80; of service:t
 Check path restrictions and crypto interfaces.
END

test_err($title, $in, $out);

############################################################
$title = 'Silently ignore auto interface at crypto tunnel';
############################################################

$in = $crypto_vpn . <<'END';
network:intern = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip = 10.1.1.102;
  hardware = inside;
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

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
}

network:customers1 = {
 ip = 10.99.1.0/24;
 radius_attributes = {
  banner = Willkommen;
 }
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
 }
}

service:mgmt = {
 user = interface:softclients.[auto];
 permit src = network:intern; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--asavpn
! inside_in
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = 'Sort crypto rules in ACL';
############################################################

$in = <<'END';
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

network:n0-sub = { ip = 10.1.0.0/26; subnet_of = network:n0; }
network:n2-sub = { ip = 10.1.2.0/25; subnet_of = network:n2; }

router:u1 = {
 interface:n0-sub;
 interface:n0;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n0 = { ip = 10.1.0.65;  hardware = n0; }
 interface:n1 = { ip = 10.1.1.1;   hardware = n1; }
 interface:n2 = { ip = 10.1.2.129; hardware = n2; }
}
router:u2 = {
 interface:n2;
 interface:n2-sub;
}

service:s1 = {
 user = network:n0, network:n1;
 permit src = user;
        dst = network:n2-sub;
        prt = proto 51, tcp 22, proto 50;
}
service:s2 = {
 user = network:n0-sub;
 permit src = user;
        dst = network:n2, network:n1;
        prt = proto 50, proto 51;
 deny   src = user;
        dst = network:n2-sub;
        prt = ip;
}
END

$out = <<'END';
--r1
ip access-list extended n0_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.129
 deny ip 10.1.0.0 0.0.0.63 10.1.2.0 0.0.0.127
 permit 50 10.1.0.0 0.0.0.255 10.1.2.0 0.0.0.127
 permit 50 10.1.0.0 0.0.0.63 10.1.1.0 0.0.0.255
 permit 50 10.1.0.0 0.0.0.63 10.1.2.0 0.0.0.255
 permit 51 10.1.0.0 0.0.0.255 10.1.2.0 0.0.0.127
 permit 51 10.1.0.0 0.0.0.63 10.1.1.0 0.0.0.255
 permit 51 10.1.0.0 0.0.0.63 10.1.2.0 0.0.0.255
 permit tcp 10.1.0.0 0.0.0.255 10.1.2.0 0.0.0.127 eq 22
 deny ip any any
--
ip access-list extended n1_in
 permit 50 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.127
 permit 51 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.127
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.127 eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'ASA with unencrypted spoke using AH';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 ah = sha256;
 lifetime = 20000 kilobytes;
}

isakmp:aes256SHA = {
 ike_version = 1;
 identity = address;
 nat_traversal = additional;
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 15;
 lifetime = 43200 sec;
 trust_point = ASDM_TrustPoint3;
}

crypto:sts1 = {
 type = ipsec:aes256SHA;
}

network:intern = {
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:sts1;
  hardware = outside;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

router:vpn1 = {
 interface:internet = {
  ip = 172.16.1.2;
  id = cert@example.com;
  spoke = crypto:sts1;
 }
 interface:lan1 = {
  ip = 10.99.1.1;
 }
}

network:lan1 = { ip = 10.99.1.0/24; }

service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
}
END

$out = <<'END';
--asavpn
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 ah-sha256-hmac esp-null
--
! crypto-172.16.1.2
access-list crypto-172.16.1.2 extended permit ip any4 10.99.1.0 255.255.255.0
crypto map crypto-outside 1 set peer 172.16.1.2
crypto map crypto-outside 1 match address crypto-172.16.1.2
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set security-association lifetime kilobytes 20000
tunnel-group 172.16.1.2 type ipsec-l2l
tunnel-group 172.16.1.2 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 172.16.1.2
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp 10.99.1.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'ASA with unencrypted spoke using AH  (IKEv2)';
############################################################

$in =~ s/ike_version = 1/ike_version = 2/g;

$out = <<'END';
--asavpn
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol ah sha256
 protocol esp encryption null
--
! crypto-172.16.1.2
access-list crypto-172.16.1.2 extended permit ip any4 10.99.1.0 255.255.255.0
crypto map crypto-outside 1 set peer 172.16.1.2
crypto map crypto-outside 1 match address crypto-172.16.1.2
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans1
crypto map crypto-outside 1 set security-association lifetime kilobytes 20000
tunnel-group 172.16.1.2 type ipsec-l2l
tunnel-group 172.16.1.2 ipsec-attributes
 ikev2 local-authentication certificate ASDM_TrustPoint3
 ikev2 remote-authentication certificate
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 172.16.1.2
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp 10.99.1.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
done_testing;
