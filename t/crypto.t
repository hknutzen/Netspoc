#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, @out);

############################################################
$title = 'ASA with two crypto hubs and NAT';
############################################################

$in = <<END;

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

network:internet = { ip = 0.0.0.0/0; route_hint; }

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
 permit src = user; dst = network:intern; prt = protocol:http; 
}
END

my $out1 = <<END;
isakmp identity address
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
access-list crypto-outside-2 extended permit ip any 10.99.2.0 255.255.255.0
access-list crypto-outside-2 extended permit ip any 192.168.22.0 255.255.255.0
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
END

my $out2 = <<END;
object-group network g0
 network-object 10.99.1.0 255.255.255.0
 network-object 10.99.2.0 255.255.255.0
 network-object 192.168.22.0 255.255.255.0
access-list outside_in extended permit tcp object-group g0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

my $out3 = <<END;
static (outside,inside) 10.99.22.0 192.168.22.0 netmask 255.255.255.0
END

my $head1 = (split /\n/, $out1)[0];
my $head2 = (split /\n/, $out2)[0];
my $head3 = (split /\n/, $out3)[0];

my $compiled = compile($in);
eq_or_diff(get_block($compiled, $head1), $out1, "$title: Crypto");
eq_or_diff(get_block($compiled, $head2), $out2, "$title: ACL");
eq_or_diff(get_block($compiled, $head3), $out3, "$title: NAT");

############################################################
$title = 'VPN ASA to EZVPN router with two local networks';
############################################################

$in = <<END;

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

network:internet = { ip = 0.0.0.0/0; route_hint; }

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

@out =  ();
$out[0] = <<END;
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
END

$out[1] = <<END;
object-group network g0
 network-object 10.99.2.0 255.255.255.0
 network-object 10.99.3.0 255.255.255.0
access-list vpn-filter-1 extended permit ip object-group g0 any
access-list vpn-filter-1 extended deny ip any any
username abc@123.45 nopassword
username abc@123.45 attributes
 service-type remote-access
 vpn-filter value vpn-filter-1
END

$out[2] = <<END;
access-list outside_in extended permit tcp object-group g0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

$out[3] = <<END;
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
 permit tcp 10.1.1.0 0.0.0.255 10.99.2.0 0.0.0.255 established
 permit tcp 10.1.1.0 0.0.0.255 10.99.3.0 0.0.0.255 established
 deny ip any any
interface Virtual-Template1 type tunnel
 ip access-group ACL-crypto-filter in
END

$out[4] = <<END;
ip access-list extended e1_in
 permit 50 host 192.168.0.101 any
 permit udp host 192.168.0.101 eq 500 any eq 500
 deny ip any any
END

$out[5] = <<END;
ip access-list extended e2_in
 permit tcp 10.99.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 80
 deny ip any any
END

$out[6] = <<END;
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

my $compiled = compile($in);
for my $i (0 .. $#out) {
    my $out = $out[$i];
    my $head = (split /\n/, $out)[0];
    eq_or_diff(get_block($compiled, $head), $out, "$title: $i");
}

############################################################
done_testing;
