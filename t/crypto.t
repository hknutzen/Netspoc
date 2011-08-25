#!/usr/bin/perl

use strict;
use Test::More;
use lib 't';
use Test_Netspoc;

############################################################
my $title = 'ASA with two crypto hubs and NAT';
############################################################

my $in = <<END;

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
 host:netspoc = { ip = 10.1.1.111; policy_distribution_point; }
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

service:http = tcp 80;
policy:test = {
 user = network:lan1, network:lan2, network:lan2a;
 permit src = user; dst = network:intern; srv = service:http; 
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
is_deeply(get_block($compiled, $head1), $out1, "$title: Crypto");
is_deeply(get_block($compiled, $head2), $out2, "$title: ACL");
is_deeply(get_block($compiled, $head3), $out3, "$title: NAT");

############################################################
done_testing;
