
############################################################
=TEMPL=crypto_vpn
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn = {
 type = ipsec:aes256SHA;
}
=END=

=TEMPL=crypto_sts
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 1 hour 100000 kilobytes;
}
isakmp:aes256SHA = {
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
=END=

############################################################
=TEMPL=topo
[[crypto_vpn]]
network:intern = { ip = 10.1.1.0/24;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 vpn_attributes = {
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
 vpn_attributes = {
  banner = Willkommen;
 }
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
 host:id:bar@domain.x = {
  ip = 10.99.1.11;
  vpn_attributes = { split-tunnel-policy = tunnelall;
                        banner = Willkommen zu Hause; }
 }
 host:id:baz@domain.x = {
  ip = 10.99.1.12;
  vpn_attributes = { anyconnect-custom_perapp = SomeName; }
 }
 host:id:unused@domain.x = {
  ip = 10.99.1.254;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}
network:customers2 = {
 ip = 10.99.2.0/24;
 vpn_attributes = {
  vpn-idle-timeout = 120;
  trust-point = ASDM_TrustPoint2;
  }
 host:id:domain.x = {
  range = 10.99.2.0 - 10.99.2.63;
  vpn_attributes = { split-tunnel-policy = tunnelspecified;
                        check-subject-name = ou;#
                        authorization-server-group = LDAP_1;
                        username-from-certificate = CN;
                        authorization-required;
                        password-management_password-expire-in-days = 91; }
 }
 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  vpn_attributes = { vpn-idle-timeout = 40;
                        trust-point = ASDM_TrustPoint3; }
 }
 host:id:zzz = {
  range = 10.99.2.128 - 10.99.2.191;
  vpn_attributes = { split-tunnel-policy = tunnelspecified;
                        check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2;
                        check-subject-name = ou; }
 }
}
=END=

############################################################
=TITLE=Mark ID hosts as used even if only network is used (1)
=INPUT=
[[topo]]
service:s1 = {
 user = network:customers1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
area:all = { anchor = network:intern; }
=OUTPUT=
10.99.2.0-10.99.2.63	host:id:domain.x.customers2
10.99.2.64-10.99.2.127	host:id:@domain.y.customers2
10.99.2.128-10.99.2.191	host:id:zzz.customers2
=OPTIONS=--unused
=PARAM=host:[area:all]
# No IPv6 test

############################################################
=TITLE=Mark ID hosts as used even if only network is used (2)
=INPUT=
[[topo]]
service:s2 = {
 user = host:id:bar@domain.x.customers1, network:customers2;
 permit src = user; dst = network:intern; prt = tcp 81;
}
area:all = { anchor = network:intern; }
=OUTPUT=
10.99.1.10	host:id:foo@domain.x.customers1
10.99.1.12	host:id:baz@domain.x.customers1
10.99.1.254	host:id:unused@domain.x.customers1
=OPTIONS=--unused
=PARAM=host:[area:all]

############################################################
=TITLE=Only get encrypted interfaces from area
=INPUT=
[[crypto_sts]]
area:encrypted = { inclusive_border = interface:asavpn.intern; }
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
router:vpn1 = {
 managed;
 model = IOS;
 interface:internet = {
  ip = 1.1.1.1;
  id = cert@example.com;
  spoke = crypto:sts;
  hardware = internet;
 }
 interface:lan1 = {
  ip = 10.99.1.1;
  hardware = Fastethernet8;
 }
}
network:lan1 = { ip = 10.99.1.0/24; }
=OUTPUT=
10.99.1.1	interface:vpn1.lan1
=PARAM=interface:[area:encrypted].[all]
