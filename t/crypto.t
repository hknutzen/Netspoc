#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

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
}
END

$out = <<'END';
Error: ID of host:id:@domain.x.n must not start with character '@'
Error: ID of host:id:domain.x.n must contain character '@'
Error: ID of host:id:bar@domain.y.n must start with character '@' or have no '@' at all
END

test_err($title, $in, $out);

############################################################
$title = 'VPN ASA with software clients';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
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
 tunnel_all;
}

network:intern = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 no_crypto_filter;
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
 }
 host:id:bar@domain.x = { 
  ip = 10.99.1.11; 
  radius_attributes = { banner = Willkommen zu Hause; }
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
                        check-subject-name = ou; }
 }
 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  radius_attributes = { vpn-idle-timeout = 40; trust-point = ASDM_TrustPoint3; } }
}

service:test1 = {
 user = host:id:foo@domain.x.customers1, host:id:@domain.y.customers2;
 permit src = user; dst = network:intern; prt = tcp 80; 
}

service:test2 = {
 user = host:id:bar@domain.x.customers1, host:id:domain.x.customers2;
 permit src = user; dst = network:intern; prt = tcp 81; 
}
END

$out = <<'END';
--asavpn
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
 trust-point ASDM_TrustPoint1
 isakmp ikev1-user-authentication none
tunnel-group-map default-group VPN-single
--asavpn
access-list vpn-filter-1 extended permit ip 10.99.2.64 255.255.255.192 any
access-list vpn-filter-1 extended deny ip any any
crypto ca certificate map ca-map-1 10
 subject-name attr ea co @domain.y
ip local pool pool-1 10.99.2.64-10.99.2.127 mask 255.255.255.192
group-policy VPN-group-1 internal
group-policy VPN-group-1 attributes
 address-pools value pool-1
 vpn-filter value vpn-filter-1
 vpn-idle-timeout 40
tunnel-group VPN-tunnel-1 type remote-access
tunnel-group VPN-tunnel-1 general-attributes
 default-group-policy VPN-group-1
tunnel-group VPN-tunnel-1 ipsec-attributes
 trust-point ASDM_TrustPoint3
 isakmp ikev1-user-authentication none
tunnel-group-map ca-map-1 10 VPN-tunnel-1
--asavpn
access-list vpn-filter-2 extended permit ip host 10.99.1.11 any
access-list vpn-filter-2 extended deny ip any any
group-policy VPN-group-2 internal
group-policy VPN-group-2 attributes
 banner value Willkommen zu Hause
username bar@domain.x nopassword
username bar@domain.x attributes
 vpn-framed-ip-address 10.99.1.11 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-2
 vpn-group-policy VPN-group-2
--
access-list split-tunnel-3 standard permit 10.1.1.0 255.255.255.0
access-list vpn-filter-3 extended permit ip 10.99.2.0 255.255.255.192 any
access-list vpn-filter-3 extended deny ip any any
crypto ca certificate map ca-map-3 10
 subject-name attr ou co domain.x
ip local pool pool-3 10.99.2.0-10.99.2.63 mask 255.255.255.192
group-policy VPN-group-3 internal
group-policy VPN-group-3 attributes
 address-pools value pool-3
 split-tunnel-network-list value split-tunnel-3
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-3
 vpn-idle-timeout 120
tunnel-group VPN-tunnel-3 type remote-access
tunnel-group VPN-tunnel-3 general-attributes
 default-group-policy VPN-group-3
tunnel-group VPN-tunnel-3 ipsec-attributes
 trust-point ASDM_TrustPoint2
 isakmp ikev1-user-authentication none
tunnel-group-map ca-map-3 10 VPN-tunnel-3
--
access-list vpn-filter-4 extended permit ip host 10.99.1.10 any
access-list vpn-filter-4 extended deny ip any any
group-policy VPN-group-4 internal
group-policy VPN-group-4 attributes
 banner value Willkommen
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ip-address 10.99.1.10 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-4
 vpn-group-policy VPN-group-4
--
! [ ACL ]
access-list inside_in extended permit icmp any any 3
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
--
object-group network g0
 network-object host 10.99.1.10
 network-object host 10.99.1.11
 network-object 10.99.2.0 255.255.255.192
 network-object 10.99.2.64 255.255.255.192
object-group network g1
 network-object host 10.99.1.10
 network-object 10.99.2.64 255.255.255.192
object-group network g2
 network-object host 10.99.1.11
 network-object 10.99.2.0 255.255.255.192
access-list outside_in extended permit icmp object-group g0 any 3
access-list outside_in extended permit tcp object-group g1 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended permit tcp object-group g2 10.1.1.0 255.255.255.0 eq 81
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'VPN ASA with internal software clients';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
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
 tunnel_all;
}

network:intern = { ip = 10.1.2.0/24;}

router:gw = {
 interface:intern;
 interface:dmz = { ip = 192.168.0.2; }
}

router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 no_crypto_filter;
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
 interface:dmz = { spoke = crypto:vpn; }
 interface:customers1;
}

network:customers1 = { 
 ip = 10.99.1.0/24; 
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}


service:test1 = {
 user = host:id:foo@domain.x.customers1;
 permit src = user; dst = network:intern; prt = tcp 80; 
}
END

$out = <<'END';
--asavpn
! [ Routing ]
route outside 10.1.2.0 255.255.255.0 192.168.0.2
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
 trust-point ASDM_TrustPoint1
 isakmp ikev1-user-authentication none
tunnel-group-map default-group VPN-single
--
access-list vpn-filter-1 extended permit ip host 10.99.1.10 any
access-list vpn-filter-1 extended deny ip any any
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ip-address 10.99.1.10 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-1
--
access-list outside_in extended permit icmp any any 3
access-list outside_in extended permit tcp host 10.99.1.10 10.1.2.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

test_run($title, $in, $out, '-noauto_default_route');

############################################################
$title = 'Missing route for VPN ASA with internal software clients';
############################################################

$in .= <<'END';
network:x = { ip = 10.1.1.0/24;}

router:gw_x = {
 interface:x;
 interface:dmz = { ip = 192.168.0.3; }
}
END

$out = <<END;
Error: Can\'t determine next hop while moving routes
 of interface:asavpn.tunnel:softclients to interface:asavpn.dmz.
 Exactly one default route is needed, but 2 candidates were found:
 - router:gw
 - router:gw_x
END

test_err($title, $in, $out);

############################################################
$title = 'Must not use aggregate with software clients';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
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
 tunnel_all;
}

network:intern = { ip = 10.1.2.0/24;}

router:gw = {
 interface:intern;
 interface:dmz = { ip = 192.168.0.2; }
}

router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 no_crypto_filter;
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
 interface:dmz = { spoke = crypto:vpn; }
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
Warning: Ignoring any:[network:customers1] with software clients in src of rule in service:test1
END

test_err($title, $in, $out);

############################################################
$title = 'ASA with two crypto hubs and NAT';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
 pfs_group = 2;
 lifetime = 3600 sec;
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

ipsec:3desSHA = {
 key_exchange = isakmp:3desSHA;
 esp_encryption = 3des;
 esp_authentication = sha_hmac;
 pfs_group = 2;
 lifetime = 600 sec;
}

isakmp:3desSHA = {
 identity = address;
 authentication = preshare;
 encryption = 3des;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}

crypto:sts1 = {
 type = ipsec:aes256SHA;
 tunnel_all;
}

crypto:sts2 = {
 type = ipsec:3desSHA;
 tunnel_all;
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
crypto isakmp policy 1
 authentication pre-share
 encryption 3des
 hash sha
 group 2
 lifetime 86400
crypto isakmp policy 2
 authentication rsa-sig
 encryption aes-256
 hash sha
 group 2
 lifetime 43200
crypto ipsec transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec transform-set Trans2 esp-aes-256 esp-sha-hmac
access-list crypto-outside-1 extended permit ip any 10.99.1.0 255.255.255.0
crypto map crypto-outside 1 match address crypto-outside-1
crypto map crypto-outside 1 set peer 172.16.1.2
crypto map crypto-outside 1 set transform-set Trans2
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group 172.16.1.2 type ipsec-l2l
tunnel-group 172.16.1.2 ipsec-attributes
 chain
 trust-point ASDM_TrustPoint3
 isakmp ikev1-user-authentication none
access-list crypto-outside-2 extended permit ip 10.1.1.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-2 extended permit ip 10.1.1.0 255.255.255.0 192.168.22.0 255.255.255.0
crypto map crypto-outside 2 match address crypto-outside-2
crypto map crypto-outside 2 set peer 172.16.2.2
crypto map crypto-outside 2 set transform-set Trans1
crypto map crypto-outside 2 set pfs group2
crypto map crypto-outside 2 set security-association lifetime seconds 600
tunnel-group 172.16.2.2 type ipsec-l2l
tunnel-group 172.16.2.2 ipsec-attributes
 pre-shared-key *****
 peer-id-validate nocheck
crypto map crypto-outside interface outside
crypto isakmp enable outside
--
object-group network g0
 network-object 10.99.1.0 255.255.255.0
 network-object 10.99.2.0 255.255.255.0
 network-object 192.168.22.0 255.255.255.0
access-list outside_in extended permit tcp object-group g0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
--
static (outside,inside) 10.99.22.0 192.168.22.0 netmask 255.255.255.0
END

test_run($title, $in, $out);

############################################################
$title = 'VPN ASA to EZVPN router with two local networks';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
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
 tunnel_all;
}

network:intern = { ip = 10.1.1.0/24;}

router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 no_crypto_filter;
 radius_attributes = {
  trust-point = ASDM_TrustPoint3;
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
 trust-point ASDM_TrustPoint3
 isakmp ikev1-user-authentication none
tunnel-group-map default-group VPN-single
--
object-group network g0
 network-object 10.99.2.0 255.255.255.0
 network-object 10.99.3.0 255.255.255.0
access-list vpn-filter-1 extended permit ip object-group g0 any
access-list vpn-filter-1 extended deny ip any any
username abc@123.45 nopassword
username abc@123.45 attributes
 service-type remote-access
 vpn-filter value vpn-filter-1
--
access-list outside_in extended permit icmp object-group g0 any 3
access-list outside_in extended permit tcp object-group g0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any any
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
$title = 'NAT of IPSec traffic at ASA 8.4 and NAT of VPN network at IOS';
############################################################

$in = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
 pfs_group = 2;
 lifetime = 3600 sec;
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
 tunnel_all;
}

network:intern = { 
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}

router:asavpn = {
 model = ASA, 8.4;
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
 interface:internet = { bind_nat = vpn1; }
 interface:dmz1 = { ip = 10.254.254.144; }
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
  nat:vpn1 = { ip = 1.2.3.129; }
  spoke = crypto:sts;
  bind_nat = lan1;
  hardware = GigabitEthernet0;
 }
 interface:lan1 = {
  ip = 10.99.1.1;
  hardware = Fastethernet8;
 }
}

network:lan1 = { 
 ip = 10.99.1.0/24; 
 nat:lan1 = { ip = 10.10.10.0/24; }
}

protocol:http = tcp 80;
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = protocol:http; 
}
END

$out = <<'END';
--asavpn
access-list crypto-outside-1 extended permit ip any 10.10.10.0 255.255.255.0
crypto map crypto-outside 1 match address crypto-outside-1
crypto map crypto-outside 1 set peer 1.2.3.129
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group 1.2.3.129 type ipsec-l2l
tunnel-group 1.2.3.129 ipsec-attributes
 chain
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto map crypto-outside interface outside
crypto isakmp enable outside
--
access-list outside_in extended permit tcp 10.10.10.0 255.255.255.0 host 10.1.1.111 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
--vpn1
ip access-list extended crypto-GigabitEthernet0-1
 permit ip 10.10.10.0 0.0.0.255 any
ip access-list extended crypto-filter-GigabitEthernet0-1
 permit tcp host 10.1.1.111 10.10.10.0 0.0.0.255 established
 deny ip any any
crypto map crypto-GigabitEthernet0 1 ipsec-isakmp
 match address crypto-GigabitEthernet0-1
 set ip access-group crypto-filter-GigabitEthernet0-1 in
 set peer 1.2.3.2
 set transform-set Trans1
 set pfs group2
--
ip access-list extended GigabitEthernet0_in
 permit 50 host 1.2.3.2 host 1.2.3.129
 permit udp host 1.2.3.2 eq 500 host 1.2.3.129 eq 500
 permit udp host 1.2.3.2 eq 4500 host 1.2.3.129 eq 4500
 deny ip any any
END

test_run($title, $in, $out);

############################################################
done_testing;
