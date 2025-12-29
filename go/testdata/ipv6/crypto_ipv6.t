
############################################################
# Shared crypto definitions

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
 trust_point = ASDM_TrustPoint3;
}
crypto:sts = {
 type = ipsec:aes256SHA;
}
=END=

############################################################
=TITLE=Missing ISAKMP attributes
=INPUT=
isakmp:aes256SHA = {
 nat_traversal = additional;
}
=ERROR=
Error: Missing 'authentication' for isakmp:aes256SHA
Error: Missing 'encryption' for isakmp:aes256SHA
Error: Missing 'hash' for isakmp:aes256SHA
Error: Missing 'group' for isakmp:aes256SHA
Error: Missing 'lifetime' for isakmp:aes256SHA
=END=

############################################################
=TITLE=Bad ISAKMP attribute
=INPUT=
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 500 hours;
 foo;
}
=ERROR=
Error: Unexpected attribute in isakmp:aes256SHA: foo
=END=

############################################################
=TITLE=Bad ISAKMP value
=INPUT=
isakmp:aes256SHA = {
 authentication = rsa-signature;
 encryption = aes;
 hash = sha;
 group = 3;
 lifetime = 500 hours;
}
=ERROR=
Error: Invalid value in 'authentication' of isakmp:aes256SHA: rsa-signature
Error: Invalid value in 'group' of isakmp:aes256SHA: 3
=END=

############################################################
=TITLE=Bad ISAKMP lifetime (1)
=INPUT=
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 500;
}
=ERROR=
Error: Expected 'NUM sec|min|hour|day' in 'lifetime' of isakmp:aes256SHA
=END=

############################################################
=TITLE=Bad ISAKMP lifetime (2)
=INPUT=
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = many sec;
}
=ERROR=
Error: Expected 'NUM sec|min|hour|day' in 'lifetime' of isakmp:aes256SHA
=END=

############################################################
=TITLE=Bad ISAKMP lifetime (3)
=INPUT=
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 500 years;
}
=ERROR=
Error: Expected 'NUM sec|min|hour|day' in 'lifetime' of isakmp:aes256SHA
=END=

############################################################
=TITLE=Bad ISAKMP lifetime (4)
=INPUT=
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = -9 sec;
}
=ERROR=
Error: Expected 'NUM sec|min|hour|day' in 'lifetime' of isakmp:aes256SHA
=END=

############################################################
=TITLE=Missing IPSec attributes
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
}
=ERROR=
Error: Missing 'lifetime' for ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec attribute
=INPUT=
ipsec:aes256SHA = {
 lifetime = 100 sec;
 foo = 21;
}
=ERROR=
Error: Unexpected attribute in ipsec:aes256SHA: foo
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec lifetime type (1)
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = 100 foo;
}
=ERROR=
Error: Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in 'lifetime' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec lifetime type (2)
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = many seconds;
}
=ERROR=
Error: Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in 'lifetime' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec lifetime type (3)
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = 3 hours many kilobytes;
}
=ERROR=
Error: Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in 'lifetime' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec lifetime type (4)
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = 3 hours 1000000 bytes;
}
=ERROR=
Error: Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in 'lifetime' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec lifetime type (5)
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = 1;
}
=ERROR=
Error: Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in 'lifetime' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec lifetime type (6)
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = -99 seconds;
}
=ERROR=
Error: Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in 'lifetime' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad IPSec lifetime type (7)
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
 lifetime = 3 hours -999 kilobytes;
}
=ERROR=
Error: Expected '[NUM sec|min|hour|day] [NUM kilobytes]' in 'lifetime' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Bad key_exchange attribute
=INPUT=
ipsec:aes256SHA = {
 key_exchange = xyz:aes256SHA;
 esp_encryption = aes256;
 lifetime = 600 sec;
}
network:n1 = { ip6 = ::a01:100/120; }
=ERROR=
Error: Expected type 'isakmp:' in 'key_exchange' of ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Unknown key_exchange
=INPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:abc;
 esp_encryption = aes256;
 lifetime = 600 sec;
}
network:n1 = { ip6 = ::a01:100/120; }
=ERROR=
Error: Can't resolve reference to isakmp:abc in ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Missing type of crypto definition
=INPUT=
crypto:c = {}
=ERROR=
Error: Missing 'type' for crypto:c
=END=

############################################################
=TITLE=Unknown type in crypto definition
=INPUT=
crypto:c = { type = xyz:abc; }
network:n1 = { ip6 = ::a01:100/120; }
=ERROR=
Error: Expected type 'ipsec:' in 'type' of crypto:c
Error: Missing 'type' for crypto:c
=END=

############################################################
=TITLE=Unknown ipsec referenced in crypto definition
=INPUT=
crypto:c = { type = ipsec:abc; }
network:n1 = { ip6 = ::a01:100/120; }
=ERROR=
Error: Can't resolve reference to ipsec:abc in crypto:c
Error: Missing 'type' for crypto:c
=END=

############################################################
=TITLE=No hub defined for crypto
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
=WARNING=
Warning: No hub has been defined for crypto:vpn
=END=

############################################################
=TITLE=No spokes defined for crypto
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
 }
}
=WARNING=
Warning: No spokes have been defined for crypto:vpn
=END=

############################################################
=TITLE=No nat_out allowed at hub
=TODO= No IPv6
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; nat:n1 = { ip6 = ::a02:200/120; } }

router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  nat_out = n1;
  hardware = n1;
 }
}
=ERROR=
Error: Must not use 'nat_out' at crypto hub interface:asavpn.n1
 Move it as 'nat_out' to crypto definition instead
=END=

############################################################
=TITLE=Must not apply nat_in to hub
=TODO= No IPv6
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; nat:n1 = { ip6 = ::a02:200/120; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  nat_in = n1;
  hardware = n1;
 }
 interface:n2 = {
  ip6 = ::a01:201;
  nat_in = n1;
  hardware = n2;
 }
 interface:n3 = {
  ip6 = ::a01:301;
  hub = crypto:vpn;
  hardware = n3;
 }
}
=ERROR=
Error: Must not apply NAT tag "n1" (from 'nat_in') to crypto hub interface:asavpn.n3
 Move it as 'nat_out' to crypto definition instead
=END=

############################################################
=TITLE=Crypto must not share hardware
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }

router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
 }
 interface:n2 = { ip6 = ::a01:201; hardware = n1; }
}
=ERROR=
Error: Crypto interface:asavpn.n1 must not share hardware with other interface:asavpn.n2
=END=

############################################################
=TITLE=Unnumbered crypto interface
=INPUT=
[[crypto_vpn]]
network:n1 = { unnumbered6; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  unnumbered6;
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
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
}
=ERROR=
Error: Crypto hub interface:asavpn.n1 must have IP address
=END=

############################################################
=TITLE=Need authentication rsasig
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = { ip6 = ::a01:102; spoke = crypto:vpn; }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
}
=SUBST=/rsasig/preshare/
=ERROR=
Error: router:asavpn needs authentication=rsasig in isakmp:aes256SHA
=END=

############################################################
=TITLE=Missing ID hosts at software client
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = { ip6 = ::a01:102; spoke = crypto:vpn; }
 interface:other;
}
network:other = { ip6 = ::a63:900/120; }
=ERROR=
Error: Networks behind crypto tunnel to router:asavpn of model 'ASA, VPN' need to have ID hosts:
 - network:other
=END=

############################################################
=TITLE=Mixed ID hosts and non ID hosts in network
=INPUT=
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
 host:bar = { ip6 = ::a63:10b; }
}
=ERROR=
Error: All hosts must have ID in network:clients
=END=

############################################################
=TITLE=Mixed ldap_id and ID hosts
=INPUT=
network:clients = {
 ip6 = ::a63:100/120;
 cert_id = cert1;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
 host:bar = {
  range6 = ::a63:110 - ::a63:11f;
  ldap_id = CN=example3,OU=VPN,DC=example,DC=com;
 }
}
=ERROR=
Error: All hosts must have attribute 'ldap_id' in network:clients
=END=

############################################################
=TITLE=ID host without crypto router
=INPUT=
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
}
=ERROR=
Error: network:clients having ID hosts must be connected to router with crypto spoke
=END=


############################################################
=TITLE=Mixed ID hosts and non ID hosts at software client
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = { ip6 = ::a01:102; spoke = crypto:vpn; }
 interface:clients;
 interface:other;
}
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
network:other = { ip6 = ::a63:900/120; }
=ERROR=
Error: Must not use networks having ID hosts and other networks having no ID hosts
 together at router:softclients:
 - network:clients
 - network:other
=END=

############################################################
=TITLE=Non ID hosts behind ID hosts
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = { ip6 = ::a01:102; spoke = crypto:vpn; }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
router:u = {
 interface:clients;
 interface:other;
}
network:other = { ip6 = ::a63:900/120; }
=ERROR=
Error: Exactly one network must be located behind unmanaged interface:softclients.clients of crypto router
=END=

############################################################
=TITLE=Invalid vpn attributes
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
  unknown = unknown;
  split-tunnel-policy = whatever;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = { ip6 = ::a01:102; spoke = crypto:vpn; }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
 vpn_attributes = {
  invalid;
 }
 host:id:foo@domain.x = {
  ip6 = ::a63:10a;
  vpn_attributes = { trust-point = ASDM_TrustPoint1; }
 }
}
=ERROR=
Error: Invalid vpn_attribute 'invalid' at network:clients
Error: Must not use vpn_attribute 'trust-point' at host:id:foo@domain.x.clients
Error: Unsupported value in vpn_attribute of router:asavpn 'split-tunnel-policy = whatever'
Error: Invalid vpn_attribute 'unknown' at router:asavpn
=END=

############################################################
=TITLE=Use authentication-server-group only with ldap_id (1)
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = { ip6 = ::a01:102; spoke = crypto:vpn; }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
 vpn_attributes = {
  authentication-server-group = LDAP_1;
 }
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
=ERROR=
Error: Attribute 'authentication-server-group' at network:clients must only be used together with attribute 'ldap_id' at host
=END=

############################################################
=TITLE=Use authentication-server-group only with ldap_id (2)
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
  authentication-server-group = LDAP_1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = { ip6 = ::a01:102; spoke = crypto:vpn; }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
=ERROR=
Error: Attribute 'authentication-server-group' at router:asavpn must only be used together with attribute 'ldap_id' at host
=END=

############################################################
=TITLE=Must not use ldap_id at ID host
=INPUT=
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {
  ip6 = ::a63:10a;
  ldap_id = CN=example1,OU=VPN,DC=example,DC=com;
 }
}
=ERROR=
Warning: Ignoring attribute 'ldap_id' at host:id:foo@domain.x.clients
Error: network:clients having ID hosts must be connected to router with crypto spoke
=END=

############################################################
=TITLE=cert_id and ldap_append only together with ldap_id
=INPUT=
network:clients = {
 ip6 = ::a63:100/120;
 cert_id = cert99;
 ldap_append = ,OU=VPN,DC=example,DC=com;
}
=WARNING=
Warning: Ignoring 'ldap_append' at network:clients
Warning: Ignoring 'cert_id' at network:clients
=END=

############################################################
=TITLE=Ignore vpn_attributes without ID hosts
=INPUT=
network:clients = {
 ip6 = ::a63:100/120;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
}
=WARNING=
Warning: Ignoring 'vpn_attributes' at network:clients
=END=

############################################################
=TITLE=no_in_acl at crypto interface
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
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
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
=ERROR=
Error: Don't use attribute 'no_in_acl' together with crypto tunnel at router:asavpn
=END=

############################################################
=TITLE=Duplicate crypto hub
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:200/120; }
router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip6 = ::a01:201; hardware = e0; }
 interface:trans = { ip6 = ::a09:901; hardware = e1; }
}
network:trans = { ip6 = ::a09:900/120; }
router:gw = {
 interface:trans = { ip6 = ::a09:902; }
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn1 = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
router:asavpn2 = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:66;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip6 = ::a09:903; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
 host:id:long-first-name.long-second-name@long-domain.xyz = {
  ip6 = ::a63:10b;
  vpn_attributes = { banner = Willkommen zu Hause; }
 }
}
=ERROR=
Error: Must use 'hub = crypto:vpn' exactly once, not at both
 - interface:asavpn1.dmz
 - interface:asavpn2.dmz
=END=

############################################################
=TITLE=Crypto spoke with secondary IP
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:200/120; }
router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip6 = ::a01:201; hardware = e0; }
 interface:trans = { ip6 = ::a09:901; hardware = e1; }
}
network:trans = { ip6 = ::a09:900/120; }
router:gw = {
 interface:trans = { ip6 = ::a09:902; }
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn1 = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip6 = ::a09:903, ::a09:909; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
 host:id:long-first-name.long-second-name@long-domain.xyz = {
  ip6 = ::a63:10b;
  vpn_attributes = { banner = Willkommen zu Hause; }
 }
}
=ERROR=
Error: interface:softclients.trans with attribute 'spoke' must not have secondary interfaces
=END=

############################################################
=TITLE=Missing hub at ASA, VPN
=INPUT=
network:n = { ip6 = ::a01:100/120; }
router:r = {
 managed;
 model = ASA, VPN;
 interface:n = { ip6 = ::a01:101; hardware = n; }
}
=WARNING=
Warning: Attribute 'hub' needs to be defined at some interface of router:r of model ASA, VPN
=END=

############################################################
=TITLE=Ignoring vpn_attributes at non ASA, VPN
=INPUT=
network:n = { ip6 = ::a01:100/120; }
router:r = {
 managed;
 model = ASA;
 vpn_attributes = { banner = Welcome; }
 interface:n = { ip6 = ::a01:101; hardware = n; }
}
=WARNING=
Warning: Ignoring 'vpn_attributes' at router:r
=END=

############################################################
=TITLE=Ignoring merge_tunnelspecified at non ASA, VPN
=INPUT=
network:n = { ip6 = ::a01:100/120; }
router:r = {
 managed;
 model = ASA;
 merge_tunnelspecified = ::a01:0/113, ::a09:900/120;
 interface:n = { ip6 = ::a01:101; hardware = n; }
}
=WARNING=
Warning: Ignoring 'merge_tunnelspecified' at router:r
=END=

############################################################
=TITLE=Crypto not supported
=INPUT=
[[crypto_sts]]
network:n = { ip6 = ::a01:100/120; }
router:r = {
 managed;
 model = Linux;
 interface:n = { ip6 = ::a01:101; hardware = n; hub = crypto:sts; }
}
=ERROR=
Error: Crypto not supported for router:r of model Linux
=END=

############################################################
=TITLE=Virtual interface must not be hub
=INPUT=
[[crypto_vpn]]
router:asavpn1 = {
 model = ASA, VPN;
 managed;
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  virtual = { ip6 = f000::c0a8:1; }
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
=ERROR=
Error: interface:asavpn1.dmz with virtual interface must not use attribute 'hub'
=END=

############################################################
=TITLE=Crypto hub can't be spoke
=INPUT=
[[crypto_vpn]]
router:asavpn1 = {
 model = ASA, VPN;
 managed;
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  spoke = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
=ERROR=
Error: interface:asavpn1.dmz with attribute 'spoke' must not have attribute 'hub'
=END=

############################################################
=TITLE=Duplicate crypto spoke
=INPUT=
[[crypto_vpn]]
network:intern1 = { ip6 = ::a01:100/120;}
router:gw1 = {
 interface:intern1;
 interface:dmz = { ip6 = f000::c0a8:1; }
}
router:asavpn1 = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
crypto:vpn2 = {
 type = ipsec:aes256SHA;
}
network:intern2 = { ip6 = ::a01:200/120;}
router:gw2 = {
 interface:intern2;
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn2 = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint2;
 }
 interface:dmz = {
  ip6 = f000::c0a8:66;
  hub = crypto:vpn2;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:intern1 = { spoke = crypto:vpn; }
 interface:intern2 = { spoke = crypto:vpn2; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
=ERROR=
Error: Must not define crypto spoke at more than one interface:
 - interface:softclients.intern1
 - interface:softclients.intern2
=END=

############################################################
=TITLE=Duplicate crypto spoke to same device
=INPUT=
[[crypto_vpn]]
network:intern1 = { ip6 = ::a01:100/120;}
network:intern2 = { ip6 = ::a01:200/120;}
router:gw = {
 interface:intern1;
 interface:intern2;
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:intern1 = { spoke = crypto:vpn; }
 interface:intern2 = { spoke = crypto:vpn; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
=ERROR=
Error: Must not define crypto spoke at more than one interface:
 - interface:softclients.intern1
 - interface:softclients.intern2
=END=

############################################################
=TITLE=ID of host must match ip/range
=INPUT=
network:n = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
 host:id:@domain.x    = { ip6 = ::a63:10b; }
 host:id:domain.x     = { ip6 = ::a63:10c; }
 host:id:@domain.y    = { range6 = ::a63:110-::a63:111; }
 host:id:domain.y     = { range6 = ::a63:112-::a63:113; }
 host:id:bar@domain.y = { range6 = ::a63:114-::a63:117; }
 host:id:boo@domain.y = { range6 = ::a63:101-::a63:13f; }
 host:id:b1@domain.y = { range6 = ::a63:101-::a63:101; }
}
=ERROR=
Error: ID of host:id:@domain.x.n must not start with character '@'
Error: ID of host:id:domain.x.n must contain character '@'
Error: ID of host:id:bar@domain.y.n must start with character '@' or have no '@' at all
Error: Range of host:id:boo@domain.y.n with ID must expand to exactly one subnet
Error: host:id:b1@domain.y.n with ID must not have single IP
Error: network:n having ID hosts must be connected to router with crypto spoke
=END=

############################################################
=TITLE=Unkown crypto at hub and spoke
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
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
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
=ERROR=
Error: Can't resolve reference to crypto:vpn in 'hub' of interface:asavpn.n1
Error: Can't resolve reference to crypto:vpn in 'spoke' of interface:softclients.n1
=END=

############################################################
# Shared topology

############################################################
=TEMPL=topo
[[crypto_vpn]]
network:intern = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
 interface:customers2;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 vpn_attributes = {
  banner = Willkommen;
 }
 host:id:foo@domain.x = {
  ip6 = ::a63:10a;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
 host:id:bar@domain.x = {
  ip6 = ::a63:10b;
  vpn_attributes = { split-tunnel-policy = tunnelall;
                        banner = Willkommen zu Hause; }
 }
 host:id:baz@domain.x = {
  ip6 = ::a63:10c;
  vpn_attributes = { anyconnect-custom_perapp = SomeName;
                        anyconnect-custom_dynamic-split-exclude-domains =
                        a.dom b.dom c.sub.dom;
  }
 }
 host:id:unused@domain.x = {
  ip6 = ::a63:1fe;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}
network:customers2 = {
 ip6 = ::a63:200/120;
 vpn_attributes = {
  vpn-idle-timeout = 120;
  trust-point = ASDM_TrustPoint2;
  }
 host:id:domain.x = {
  range6 = ::a63:200 - ::a63:23f;
  vpn_attributes = { split-tunnel-policy = tunnelspecified;
                        check-subject-name = ou;#
                        authorization-server-group = LDAP_1;
                        username-from-certificate = CN;
                        authorization-required;
                        group-lock;#
                        password-management_password-expire-in-days = 91; }
 }
 host:id:@domain.y = {
  range6 = ::a63:240 - ::a63:27f;
  vpn_attributes = { vpn-idle-timeout = 40;
                        trust-point = ASDM_TrustPoint3;
                        group-lock; }
 }
 host:id:zzz = {
  range6 = ::a63:280 - ::a63:2bf;
  vpn_attributes = { split-tunnel-policy = tunnelspecified;
                        check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2;
                        check-subject-name = ou;
                        client-bypass-protocol = enable; }
 }
}
=END=

############################################################
=TITLE=VPN ASA with software clients
=TEMPL=input
[[topo]]
network:work1 = { ip6 = ::a00:100/120; host:h1 = { ip6 = ::a00:10a; } }
network:work2 = { ip6 = ::a00:200/120; host:h2 = { ip6 = ::a00:20a; } }
network:work3 = { ip6 = ::a00:300/120; host:h3 = { ip6 = ::a00:30a; } }
network:work4 = { ip6 = ::a00:400/120; }
router:u = {
 interface:work1;
 interface:work2;
 interface:work3;
 interface:work4;
 interface:intern = { ip6 = ::a01:101; }
}
group:g1 =
 network:work1,
 host:h2,
 network:work3,
;
group:g2 =
 host:h2,
 host:h3,
 network:work4,
;
service:test1 = {
 user = host:id:foo@domain.x.customers1, host:id:@domain.y.customers2;
 deny   src = user; dst = host:h1; prt = tcp 80;
 permit src = user; dst = group:g1; prt = tcp 80;
}
service:test2 = {
 user = host:id:bar@domain.x.customers1,
        host:id:baz@domain.x.customers1,
        host:id:domain.x.customers2;
 permit src = user; dst = group:g2; prt = tcp 81;
}
service:test3 = {
 user = host:id:domain.x.customers2, host:id:zzz.customers2;
 permit src = user; dst = group:g2; prt = tcp 82;
}
=INPUT=[[input]]
=SUBST=/type = ipsec:aes256SHA;/type = ipsec:aes256SHA;detailed_crypto_acl;/
=OUTPUT=
--ipv6/asavpn
! [ Routing ]
ipv6 route outside ::/0 f000::c0a8:1
ipv6 route inside ::a00:100/120 ::a01:101
ipv6 route inside ::a00:400/120 ::a01:101
ipv6 route inside ::a00:200/119 ::a01:101
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
access-list vpn-filter-@domain.y extended permit ip ::a63:240/122 any6
access-list vpn-filter-@domain.y extended deny ip any6 any6
ipv6 local pool pool-@domain.y ::a63:240/122 64
crypto ca certificate map ca-map-@domain.y 10
 subject-name attr ea co @domain.y
tunnel-group VPN-tunnel-@domain.y type remote-access
tunnel-group VPN-tunnel-@domain.y general-attributes
 default-group-policy VPN-group-@domain.y
tunnel-group VPN-tunnel-@domain.y ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
tunnel-group VPN-tunnel-@domain.y webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-@domain.y 10 VPN-tunnel-@domain.y
group-policy VPN-group-@domain.y internal
group-policy VPN-group-@domain.y attributes
 address-pools value pool-@domain.y
 group-lock value VPN-tunnel-@domain.y
 vpn-filter value vpn-filter-@domain.y
 vpn-idle-timeout 40
--
! vpn-filter-bar@domain.x
access-list vpn-filter-bar@domain.x extended permit ip host ::a63:10b any6
access-list vpn-filter-bar@domain.x extended deny ip any6 any6
group-policy VPN-group-bar@domain.x internal
group-policy VPN-group-bar@domain.x attributes
 banner value Willkommen zu Hause
username bar@domain.x nopassword
username bar@domain.x attributes
 vpn-framed-ipv6-address ::a63:10b/120
 service-type remote-access
 vpn-filter value vpn-filter-bar@domain.x
 vpn-group-policy VPN-group-bar@domain.x
--
! vpn-filter-baz@domain.x
access-list vpn-filter-baz@domain.x extended permit ip host ::a63:10c any6
access-list vpn-filter-baz@domain.x extended deny ip any6 any6
group-policy VPN-group-baz@domain.x internal
group-policy VPN-group-baz@domain.x attributes
 anyconnect-custom dynamic-split-exclude-domains value a.dom b.dom c.sub.dom
 anyconnect-custom perapp value SomeName
 banner value Willkommen
username baz@domain.x nopassword
username baz@domain.x attributes
 vpn-framed-ipv6-address ::a63:10c/120
 service-type remote-access
 vpn-filter value vpn-filter-baz@domain.x
 vpn-group-policy VPN-group-baz@domain.x
--
! split-tunnel-1
access-list split-tunnel-1 standard permit ::a00:200/120
access-list split-tunnel-1 standard permit ::a00:300/120
access-list split-tunnel-1 standard permit ::a00:400/120
--
! vpn-filter-domain.x
access-list vpn-filter-domain.x extended permit ip ::a63:200/122 any6
access-list vpn-filter-domain.x extended deny ip any6 any6
ipv6 local pool pool-domain.x ::a63:200/122 64
crypto ca certificate map ca-map-domain.x 10
 subject-name attr ou co domain.x
tunnel-group VPN-tunnel-domain.x type remote-access
tunnel-group VPN-tunnel-domain.x general-attributes
 default-group-policy VPN-group-domain.x
 authorization-required
 authorization-server-group LDAP_1
 password-management password-expire-in-days 91
 username-from-certificate CN
tunnel-group VPN-tunnel-domain.x ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint2
 ikev1 user-authentication none
tunnel-group VPN-tunnel-domain.x webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-domain.x 10 VPN-tunnel-domain.x
group-policy VPN-group-domain.x internal
group-policy VPN-group-domain.x attributes
 address-pools value pool-domain.x
 group-lock value VPN-tunnel-domain.x
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-domain.x
 vpn-idle-timeout 120
--
! split-tunnel-2
access-list split-tunnel-2 standard permit ::a00:100/120
access-list split-tunnel-2 standard permit ::a00:200/120
access-list split-tunnel-2 standard permit ::a00:300/120
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host ::a63:10a any6
access-list vpn-filter-foo@domain.x extended deny ip any6 any6
group-policy VPN-group-foo@domain.x internal
group-policy VPN-group-foo@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-2
 split-tunnel-policy tunnelspecified
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ipv6-address ::a63:10a/120
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
 vpn-group-policy VPN-group-foo@domain.x
--
! split-tunnel-3
access-list split-tunnel-3 standard deny any6
--
! vpn-filter-unused@domain.x
access-list vpn-filter-unused@domain.x extended permit ip host ::a63:1fe any6
access-list vpn-filter-unused@domain.x extended deny ip any6 any6
group-policy VPN-group-unused@domain.x internal
group-policy VPN-group-unused@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-3
 split-tunnel-policy tunnelspecified
username unused@domain.x nopassword
username unused@domain.x attributes
 vpn-framed-ipv6-address ::a63:1fe/120
 service-type remote-access
 vpn-filter value vpn-filter-unused@domain.x
 vpn-group-policy VPN-group-unused@domain.x
--
! vpn-filter-zzz
access-list vpn-filter-zzz extended permit ip ::a63:280/122 any6
access-list vpn-filter-zzz extended deny ip any6 any6
ipv6 local pool pool-zzz ::a63:280/122 64
crypto ca certificate map ca-map-zzz 10
 subject-name attr ou co zzz
 extended-key-usage co 1.3.6.1.4.1.311.20.2.2
tunnel-group VPN-tunnel-zzz type remote-access
tunnel-group VPN-tunnel-zzz general-attributes
 default-group-policy VPN-group-zzz
tunnel-group VPN-tunnel-zzz ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint2
 ikev1 user-authentication none
tunnel-group VPN-tunnel-zzz webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-zzz 10 VPN-tunnel-zzz
group-policy VPN-group-zzz internal
group-policy VPN-group-zzz attributes
 address-pools value pool-zzz
 client-bypass-protocol enable
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-zzz
 vpn-idle-timeout 120
--
! inside_in
access-list inside_in extended permit icmp6 any6 any6 3
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--
! outside_in
object-group network v6g0
 network-object host ::a63:10a
 network-object ::a63:240/122
object-group network v6g1
 network-object ::a63:10a/127
 network-object host ::a63:10c
 network-object host ::a63:1fe
 network-object ::a63:200/121
 network-object ::a63:280/122
object-group network v6g2
 network-object host ::a63:10b
 network-object host ::a63:10c
object-group network v6g3
 network-object ::a00:100/120
 network-object host ::a00:20a
 network-object ::a00:300/120
object-group network v6g4
 network-object host ::a00:20a
 network-object host ::a00:30a
 network-object ::a00:400/120
access-list outside_in extended deny tcp object-group v6g0 host ::a00:10a eq 80
access-list outside_in extended permit icmp6 object-group v6g1 any6 3
access-list outside_in extended permit tcp object-group v6g0 object-group v6g3 eq 80
access-list outside_in extended permit tcp object-group v6g2 object-group v6g4 eq 81
access-list outside_in extended permit tcp ::a63:200/122 object-group v6g4 range 81 82
access-list outside_in extended permit tcp ::a63:280/122 object-group v6g4 eq 82
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Missing vpn_attribute check-subject-name at host
=INPUT=[[input]]
=SUBST=/check-subject-name = ou;#//
=ERROR=
Error: Missing vpn_attribute 'check-subject-name'
 for host:id:domain.x.customers2
=END=

############################################################
=TITLE=Ignoring value of vpn_attribute group-lock
=INPUT=[[input]]
=SUBST=/group-lock;#/group-lock = enabled;/
=WARNING=
Warning: Ignoring value at vpn_attribute 'group-lock' of host:id:domain.x.customers2 (will be set automatically)
=END=

############################################################
=TITLE=Missing trust-point
=INPUT=[[input]]
=SUBST=/trust-point = ASDM_TrustPoint1;//
=ERROR=
Error: Missing 'trust-point' in vpnAttributes of router:asavpn
=END=

############################################################
=TITLE=Permit all ID hosts in network
=INPUT=
[[topo]]
service:s1 = {
 user = network:customers1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
service:s2 = {
 user = host:id:bar@domain.x.customers1, network:customers2;
 permit src = user; dst = network:intern; prt = tcp 81;
}
=OUTPUT=
--ipv6/asavpn
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
access-list vpn-filter-bar@domain.x extended permit ip host ::a63:10b any6
access-list vpn-filter-bar@domain.x extended deny ip any6 any6
group-policy VPN-group-bar@domain.x internal
group-policy VPN-group-bar@domain.x attributes
 banner value Willkommen zu Hause
username bar@domain.x nopassword
username bar@domain.x attributes
 vpn-framed-ipv6-address ::a63:10b/120
 service-type remote-access
 vpn-filter value vpn-filter-bar@domain.x
 vpn-group-policy VPN-group-bar@domain.x
--
! vpn-filter-baz@domain.x
access-list vpn-filter-baz@domain.x extended permit ip host ::a63:10c any6
access-list vpn-filter-baz@domain.x extended deny ip any6 any6
group-policy VPN-group-baz@domain.x internal
group-policy VPN-group-baz@domain.x attributes
 anyconnect-custom dynamic-split-exclude-domains value a.dom b.dom c.sub.dom
 anyconnect-custom perapp value SomeName
 banner value Willkommen
username baz@domain.x nopassword
username baz@domain.x attributes
 vpn-framed-ipv6-address ::a63:10c/120
 service-type remote-access
 vpn-filter value vpn-filter-baz@domain.x
 vpn-group-policy VPN-group-baz@domain.x
--
! split-tunnel-1
access-list split-tunnel-1 standard permit ::a01:100/120
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host ::a63:10a any6
access-list vpn-filter-foo@domain.x extended deny ip any6 any6
group-policy VPN-group-foo@domain.x internal
group-policy VPN-group-foo@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ipv6-address ::a63:10a/120
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
 vpn-group-policy VPN-group-foo@domain.x
--
! outside_in
object-group network v6g0
 network-object ::a63:10a/127
 network-object host ::a63:10c
 network-object host ::a63:1fe
 network-object ::a63:200/121
 network-object ::a63:280/122
object-group network v6g1
 network-object host ::a63:10a
 network-object host ::a63:10c
 network-object host ::a63:1fe
object-group network v6g2
 network-object ::a63:200/121
 network-object ::a63:280/122
access-list outside_in extended permit icmp6 object-group v6g0 any6 3
access-list outside_in extended permit tcp object-group v6g1 ::a01:100/120 eq 80
access-list outside_in extended permit tcp object-group v6g2 ::a01:100/120 eq 81
access-list outside_in extended permit tcp host ::a63:10b ::a01:100/120 range 80 81
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA, VPN in CONTEXT
# This line is missing from config:
#  ikev1 user-authentication none
=INPUT=[[topo]]
=SUBST=/ASA, VPN/ASA, VPN, CONTEXT/
=OUTPUT=
--ipv6/asavpn
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
=END=

############################################################
=TITLE=Merge split tunnel lists
=INPUT=
[[crypto_vpn]]
network:work1 = { ip6 = ::a00:100/120; host:h1 = { ip6 = ::a00:10a; } }
network:work2 = { ip6 = ::a00:200/120; host:h2 = { ip6 = ::a00:20a; } }
network:work3 = { ip6 = ::a00:300/120; host:h3 = { ip6 = ::a00:30a; } }
network:work4 = { ip6 = ::a09:400/120; host:h4 = { ip6 = ::a09:40a; } }
router:u = {
 interface:work1;
 interface:work2;
 interface:work3;
 interface:work4;
 interface:intern = { ip6 = ::a01:101; }
}
network:intern = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 merge_tunnelspecified = ::a00:0/112, ::a09:400/118;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 vpn_attributes = {
  banner = Willkommen;
 }
 host:id:u1@domain.x = {
  ip6 = ::a63:10a;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
 host:id:u2@domain.x = {
  ip6 = ::a63:10b;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
 host:id:u3@domain.x = {
  ip6 = ::a63:10c;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
 host:id:u4@domain.x = {
  ip6 = ::a63:1fe;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}
service:s1 = {
 user = host:id:u1@domain.x.customers1;
 permit src = user; dst = host:h1; prt = tcp 80;
}
service:s2 = {
 user = host:id:u1@domain.x.customers1,
        host:id:u2@domain.x.customers1;
 permit src = user; dst = network:work2; prt = tcp 80;
}
service:s3 = {
 user = host:id:u1@domain.x.customers1,
        host:id:u3@domain.x.customers1;
 permit src = user; dst = host:h3; prt = tcp 80;
}
service:s4 = {
 user = host:id:u3@domain.x.customers1;
 permit src = user; dst = host:h4; prt = tcp 80;
}
=OUTPUT=
--ipv6/asavpn
! split-tunnel-1
access-list split-tunnel-1 standard permit ::a00:0/112
--
! vpn-filter-u1@domain.x
access-list vpn-filter-u1@domain.x extended permit ip host ::a63:10a any6
access-list vpn-filter-u1@domain.x extended deny ip any6 any6
group-policy VPN-group-u1@domain.x internal
group-policy VPN-group-u1@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
username u1@domain.x nopassword
username u1@domain.x attributes
 vpn-framed-ipv6-address ::a63:10a/120
 service-type remote-access
 vpn-filter value vpn-filter-u1@domain.x
 vpn-group-policy VPN-group-u1@domain.x
--
! vpn-filter-u2@domain.x
access-list vpn-filter-u2@domain.x extended permit ip host ::a63:10b any6
access-list vpn-filter-u2@domain.x extended deny ip any6 any6
group-policy VPN-group-u2@domain.x internal
group-policy VPN-group-u2@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
username u2@domain.x nopassword
username u2@domain.x attributes
 vpn-framed-ipv6-address ::a63:10b/120
 service-type remote-access
 vpn-filter value vpn-filter-u2@domain.x
 vpn-group-policy VPN-group-u2@domain.x
--
! split-tunnel-2
access-list split-tunnel-2 standard permit ::a00:0/112
access-list split-tunnel-2 standard permit ::a09:400/118
--
! vpn-filter-u3@domain.x
access-list vpn-filter-u3@domain.x extended permit ip host ::a63:10c any6
access-list vpn-filter-u3@domain.x extended deny ip any6 any6
group-policy VPN-group-u3@domain.x internal
group-policy VPN-group-u3@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-2
 split-tunnel-policy tunnelspecified
username u3@domain.x nopassword
username u3@domain.x attributes
 vpn-framed-ipv6-address ::a63:10c/120
 service-type remote-access
 vpn-filter value vpn-filter-u3@domain.x
 vpn-group-policy VPN-group-u3@domain.x
--
! split-tunnel-3
access-list split-tunnel-3 standard deny any6
--
! vpn-filter-u4@domain.x
access-list vpn-filter-u4@domain.x extended permit ip host ::a63:1fe any6
access-list vpn-filter-u4@domain.x extended deny ip any6 any6
group-policy VPN-group-u4@domain.x internal
group-policy VPN-group-u4@domain.x attributes
 banner value Willkommen
 split-tunnel-network-list value split-tunnel-3
 split-tunnel-policy tunnelspecified
username u4@domain.x nopassword
username u4@domain.x attributes
 vpn-framed-ipv6-address ::a63:1fe/120
 service-type remote-access
 vpn-filter value vpn-filter-u4@domain.x
 vpn-group-policy VPN-group-u4@domain.x
=END=

############################################################
=TITLE=Missing authentication-server-group at network with ldap_id
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 cert_id = cert1;
 vpn_attributes = {
  check-subject-name = cn;
 }
 host:example1 = {
  ldap_id = CN=example1,OU=VPN,DC=example,DC=com;
  range6 = ::a63:108 - ::a63:10f;
  vpn_attributes = {
   authentication-server-group = LDAP_1;
  }
 }
 host:example2 = {
  ldap_id = CN=example2,OU=VPN,DC=example,DC=com;
  range6 = ::a63:110 - ::a63:11f;
 }
 host:example3 = {
  ldap_id = CN=example3,OU=VPN,DC=example,DC=com;
  range6 = ::a63:120 - ::a63:12f;
 }
}
=ERROR=
Error: Attribute 'authentication-server-group' must not be used directly at host:example1
Error: Missing attribute 'authentication-server-group' at network:customers1 having host with 'ldap_id'
=END=

############################################################
# Changed topology für tests with ldap_id

############################################################
=TEMPL=topo
[[crypto_vpn]]
network:intern = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
 interface:customers2;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 cert_id = cert1;
 vpn_attributes = {
  check-subject-name = cn;
  authentication-server-group = LDAP_1;
 }
 host:example1 = {
  ldap_id = CN=example1,OU="my" VPN,DC=example,DC=com;
  range6 = ::a63:108 - ::a63:10f;
 }
}
network:customers2 = {
 ip6 = ::a63:200/120;
 cert_id = cert2;
 ldap_append = ,OU=VPN,DC=example,DC=com;
 vpn_attributes = {
  check-subject-name = ou;
  authentication-server-group = LDAP_2;
  group-lock;
 }
 host:example2a = {
  ldap_id = CN=example2a;
  range6 = ::a63:200 - ::a63:23f;
  vpn_attributes = { username-from-certificate = CN;
                        authorization-required; }
 }
 host:example2b = {
  ldap_id = CN=example2b;
  range6 = ::a63:280 - ::a63:2bf;
  vpn_attributes = { check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2; }
 }
}
=END=

############################################################
=TITLE=Missing vpn_attribute check-subject-name at network
=INPUT=[[topo]]
=SUBST=/check-subject-name = ou;//
=ERROR=
Error: Missing vpn_attribute 'check-subject-name'
 for network:customers2
=END=

############################################################
=TITLE=VPN ASA with ldap_id
=INPUT=
[[topo]]
service:test1 = {
 user = host:example1, host:example2a;
 permit src = user; dst = network:intern; prt = tcp 80;
}
service:test2 = {
 user = host:example2a, host:example2b;
 permit src = user; dst = network:intern; prt = tcp 81;
}
=OUTPUT=
--ipv6/asavpn
! vpn-filter-1
access-list vpn-filter-1 extended permit ip ::a63:108/125 any6
access-list vpn-filter-1 extended deny ip any6 any6
ipv6 local pool pool-1 ::a63:108/125 8
crypto ca certificate map ca-map-cert1 10
 subject-name attr cn co cert1
tunnel-group VPN-tunnel-cert1 type remote-access
tunnel-group VPN-tunnel-cert1 general-attributes
 authentication-server-group LDAP_1
tunnel-group VPN-tunnel-cert1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-cert1 webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map-cert1 10 VPN-tunnel-cert1
group-policy VPN-group-1 internal
group-policy VPN-group-1 attributes
 address-pools value pool-1
 vpn-filter value vpn-filter-1
--
! vpn-filter-2
access-list vpn-filter-2 extended permit ip ::a63:200/122 any6
access-list vpn-filter-2 extended deny ip any6 any6
ipv6 local pool pool-2 ::a63:200/122 64
crypto ca certificate map ca-map-cert2 10
 subject-name attr ou co cert2
tunnel-group VPN-tunnel-cert2 type remote-access
tunnel-group VPN-tunnel-cert2 general-attributes
 authentication-server-group LDAP_2
tunnel-group VPN-tunnel-cert2 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-cert2 webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map-cert2 10 VPN-tunnel-cert2
group-policy VPN-group-2 internal
group-policy VPN-group-2 attributes
 address-pools value pool-2
 group-lock value VPN-tunnel-cert2
 vpn-filter value vpn-filter-2
--
! vpn-filter-3
access-list vpn-filter-3 extended permit ip ::a63:280/122 any6
access-list vpn-filter-3 extended deny ip any6 any6
ipv6 local pool pool-3 ::a63:280/122 64
group-policy VPN-group-3 internal
group-policy VPN-group-3 attributes
 address-pools value pool-3
 group-lock value VPN-tunnel-cert2
 vpn-filter value vpn-filter-3
--
webvpn
 certificate-group-map ca-map-cert1 10 VPN-tunnel-cert1
 certificate-group-map ca-map-cert2 10 VPN-tunnel-cert2
--
ldap attribute-map LDAP_1
 map-name memberOf Group-Policy
 map-value memberOf "CN=example1,OU=\"my\" VPN,DC=example,DC=com" VPN-group-1
aaa-server LDAP_2 protocol ldap
aaa-server LDAP_2 host X
 ldap-attribute-map LDAP_2
ldap attribute-map LDAP_2
 map-name memberOf Group-Policy
 map-value memberOf "CN=example2a,OU=VPN,DC=example,DC=com" VPN-group-2
 map-value memberOf "CN=example2b,OU=VPN,DC=example,DC=com" VPN-group-3
=END=

############################################################
=TITLE=Bad check-extended-key-usage
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:200/120; }
router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip6 = ::a01:201; hardware = e0; }
 interface:trans = { ip6 = ::a09:901; hardware = e1; }
}
network:trans = { ip6 = ::a09:900/120; }
router:gw = {
 interface:trans = { ip6 = ::a09:902; }
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip6 = ::a09:903; }
 interface:customers1;
 interface:customers2;
 interface:customers3;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 vpn_attributes = { check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2; }
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
 host:id:bar@domain.x = { ip6 = ::a63:10b;
  vpn_attributes = { check-extended-key-usage = bar; }}
 host:id:@domain.x = { range6 = ::a63:10c-::a63:10f; }
 host:id:@domain.y = { range6 = ::a63:110-::a63:11f; }
}
network:customers2 = {
 ip6 = ::a63:200/120;
 vpn_attributes = { check-extended-key-usage = foo; }
 host:id:foo@domain.y = { ip6 = ::a63:20a; }
}
network:customers3 = {
 ip6 = ::a63:300/120;
 host:id:foo@domain.z = { ip6 = ::a63:30a;
  vpn_attributes = { check-extended-key-usage = foo; }}
 host:id:bar@domain.z = { ip6 = ::a63:30b;
  vpn_attributes = { check-extended-key-usage = foo; }}
}
=ERROR=
Error: All ID hosts having domain '@domain.x' must use identical value from 'check-extended-key-usage'
Error: All ID hosts having domain '@domain.y' must use identical value from 'check-extended-key-usage'
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=VPN ASA with internal software clients
=TEMPL=input
[[crypto_vpn]]
network:intern = { ip6 = ::a01:200/120; }
router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip6 = ::a01:201; hardware = e0; }
 interface:trans = { ip6 = ::a09:901; hardware = e1; }
}
network:trans = { ip6 = ::a09:900/120; }
router:gw = {
 model = IOS;
 managed;
 routing = manual;
 interface:trans = { ip6 = ::a09:902; hardware = e0; }
 interface:dmz = { ip6 = f000::c0a8:2; hardware = e1; }
}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip6 = ::a09:903; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 vpn_attributes = { check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2; }
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
 host:id:long-first-name.long-second-name@long-domain.xyz = {
  ip6 = ::a63:10b;
  vpn_attributes = { banner = Willkommen zu Hause; }
 }
}
# Protocol modifiers src_net, dst_net must leave id-hosts unchanged.
protocol:ping_net = icmpv6 8, src_net, dst_net;
service:test1 = {
 user = host:id:foo@domain.x.customers1,
        host:id:long-first-name.long-second-name@long-domain.xyz.customers1;
 permit src = user; dst = network:intern; prt = tcp 80, protocol:ping_net;
 permit src = network:intern; dst = user; prt = protocol:ping_net;
}
=INPUT=[[input]]
=OUTPUT=
--ipv6/r
! [ Routing ]
ipv6 route ::a63:100/120 ::a09:902
--ipv6/asavpn
! [ Routing ]
ipv6 route outside ::a01:200/120 f000::c0a8:2
ipv6 route outside ::a09:900/120 f000::c0a8:2
ipv6 route outside ::a63:100/120 f000::c0a8:2
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
access-list vpn-filter-foo@domain.x extended permit ip host ::a63:10a any6
access-list vpn-filter-foo@domain.x extended deny ip any6 any6
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ipv6-address ::a63:10a/120
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
--
! vpn-filter-1
access-list vpn-filter-1 extended permit ip host ::a63:10b any6
access-list vpn-filter-1 extended deny ip any6 any6
group-policy VPN-group-1 internal
group-policy VPN-group-1 attributes
 banner value Willkommen zu Hause
username long-first-name.long-second-name@long-domain.xyz nopassword
username long-first-name.long-second-name@long-domain.xyz attributes
 vpn-framed-ipv6-address ::a63:10b/120
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
access-list outside_in extended permit icmp6 any6 any6 3
access-list outside_in extended permit icmp6 ::a01:200/120 ::a63:10a/127 8
access-list outside_in extended permit tcp ::a63:10a/127 ::a01:200/120 eq 80
access-list outside_in extended permit icmp6 ::a63:10a/127 ::a01:200/120 8
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Missing route for VPN ASA with internal software clients
=INPUT=
[[input]]
router:gw2 = {
 model = IOS;
 managed;
 routing = manual;
 interface:trans = { ip6 = ::a09:904; hardware = e0; }
 interface:dmz = { ip6 = f000::c0a8:4; hardware = e1; }
}
=ERROR=
Error: Can't determine next hop to reach network:trans while moving routes
 of interface:asavpn.tunnel:softclients to interface:asavpn.dmz.
 Exactly one route is needed, but 2 candidates were found:
 - interface:gw.dmz
 - interface:gw2.dmz
Error: Ambiguous static routes for network:intern at interface:asavpn.dmz via
 - interface:gw.dmz
 - interface:gw2.dmz
Error: Ambiguous static routes for network:trans at interface:asavpn.dmz via
 - interface:gw.dmz
 - interface:gw2.dmz
Error: Ambiguous static routes for network:customers1 at interface:r.trans via
 - interface:gw.trans
 - interface:gw2.trans
=END=

############################################################
=TITLE=NAT with VPN ASA
=TODO= No IPv6
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:200/120; nat:E = { ip6 = f000::c0a8:200/120; } }
network:trans = { ip6 = ::a09:900/120; }
router:gw = {
 interface:intern = { ip6 = ::a01:201; hardware = e0; }
 interface:trans = { ip6 = ::a09:902; }
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = { trust-point = ASDM_TrustPoint1; }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
 interface:extern = {
  ip6 = f000::c0a8:101;
  hardware = extern;
  nat_out = E;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip6 = ::a09:903; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 nat:E = { ip6 = f000::c0a8:6300/120; }
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
}
network:extern = { ip6 = f000::c0a8:100/120; nat:I = { ip6 = ::a07:700/120; }}
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
=SUBST=/type = ipsec:/nat_out = I;type = ipsec:/
=OUTPUT=
-- ipv6/asavpn
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host ::a63:10a any6
access-list vpn-filter-foo@domain.x extended deny ip any6 any6
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ipv6-address ::a63:10a/120
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
--
! outside_in
access-list outside_in extended permit tcp ::a01:200/120 f000::c0a8:100/120 eq 84
access-list outside_in extended permit tcp host ::a63:10a ::a01:200/120 eq 80
access-list outside_in extended permit tcp host ::a63:10a f000::c0a8:100/120 eq 81
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
--
! extern_in
access-list extern_in extended permit tcp f000::c0a8:100/120 ::a01:200/120 eq 82
access-list extern_in extended permit tcp f000::c0a8:100/120 ::a63:100/120 eq 83
access-list extern_in extended deny ip any6 any6
access-group extern_in in interface extern
=END=

############################################################
=TITLE=Mixed NAT at ASA crypto interface (1)
=TODO= No IPv6
#
# Must use NAT ip of internal network, not NAT ip of internet
# at crypto interface for network:n2.
# Ignore hidden NAT tag from internet.
=TEMPL=input
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; host:X = { ip6 = ::102:304; } }
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:soft1;
}
network:soft1 = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {
  ip6 = ::a63:10a;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}
router:Firewall = {
 managed;
 model = Linux;
 interface:internet = { negotiated6; hardware = internet; nat_out = h; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
network:n3 = { ip6 = ::a01:300/120;}
router:r1 = {
 interface:n1 = { ip6 = ::a01:102; nat_out = n2; }
 interface:n3 = { ip6 = ::a01:302; nat_out = x; }
 interface:n2 = { ip6 = f000::ac11:1; }
}
network:n2 = {
 ip6 = f000::ac11:0/112;
 nat:n2 = { ip6 = ::a01:200/120; dynamic; }
 nat:x = { ip6 = ::a01:6300/120; dynamic; }
 nat:h = { hidden; }
}
service:s1 = {
 user = host:id:foo@domain.x.soft1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=INPUT=[[input]]
=OUTPUT=
-- ipv6/asavpn
! [ Routing ]
ipv6 route outside ::/0 f000::c0a8:1
ipv6 route inside ::a01:200/120 ::a01:102
--
! split-tunnel-1
access-list split-tunnel-1 standard permit ::a01:200/120
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host ::a63:10a any6
access-list vpn-filter-foo@domain.x extended deny ip any6 any6
group-policy VPN-group-foo@domain.x internal
group-policy VPN-group-foo@domain.x attributes
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ipv6-address ::a63:10a/120
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
 vpn-group-policy VPN-group-foo@domain.x
--
! outside_in
access-list outside_in extended permit tcp host ::a63:10a ::a01:200/120 eq 22
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Mixed NAT at ASA crypto interface (2)
=TODO= No IPv6
#
# No error, because NAT isn't applicable for encrypted packets.
=INPUT=[[input]]
=SUBST=|hidden|ip6 = ::a02:200/120; dynamic|
=OUTPUT=
-- ipv6/asavpn
! [ Routing ]
ipv6 route outside ::/0 f000::c0a8:1
ipv6 route inside ::a01:200/120 ::a01:102
=END=

############################################################
=TITLE=Mixed NAT at ASA crypto interface (3)
=TODO= No IPv6
#
# Must use NAT IP of internal network, not NAT IP of internet
# at crypto interface for network:n2.
# Ignore hidden NAT tag from internal network.
=INPUT=
[[crypto_sts]]
network:n1 = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; nat_out = n; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:fw-extern = {
 managed;
 model = ASA;
 interface:internet = {
  ip6 = ::101:101;
  nat_out = x;
  routing = dynamic;
  hardware = outside;
 }
 interface:dmz1 = { ip6 = ::afe:fe90; hardware = inside; }
}
network:dmz1 = {
 ip6 = ::afe:fe00/120;
 nat:x = { ip6 = ::102:381/128; dynamic; }
 nat:n = { ip6 = ::102:304/128; dynamic; }
 nat:h = { hidden; }
}
router:vpn1 = {
 interface:dmz1 = {
  ip6 = ::afe:fe06;
  id = cert@example.com;
  spoke = crypto:sts;
  nat_out = lan1;
 }
 interface:lan1;
}
network:lan1 = {
 ip6 = ::a63:100/120;
 nat:lan1 = { ip6 = ::a0a:a00/120; }
}
router:Firewall = {
 managed;
 model = Linux;
 interface:internet = { negotiated6; hardware = internet; nat_out = x; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; nat_out = h; }
}
network:n3 = { ip6 = ::a01:300/120;}
network:n4 = { ip6 = ::a01:400/120;}
router:r1 = {
 interface:n1 = { ip6 = ::a01:102; nat_out = h; }
 interface:n2 = { ip6 = f000::ac11:1; }
 interface:n3 = { ip6 = ::a01:302; nat_out = n; }
}
network:n2 = {
 ip6 = f000::ac11:0/112;
 nat:h = { hidden; }
 nat:n = { ip6 = ::a01:200/120; dynamic; }
 nat:x = { ip6 = ::6363:6300/120; dynamic; }
}
=OUTPUT=
-- ipv6/asavpn
! [ Routing ]
ipv6 route outside ::102:304/128 f000::c0a8:1
=END=

############################################################
=TITLE=Route to internet at internal interface
=INPUT=
[[crypto_sts]]

network:n1 = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA;
 managed;
 interface:n1 = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  negotiated6;
  id = cert@example.com;
  spoke = crypto:sts;
 }
 interface:lan1;
}
network:lan1 = {
 ip6 = ::a63:100/120;
}

router:Firewall = {
 managed;
 model = Linux;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:internet = { ip6 = ::101:102; hardware = internet; }
}
router:internet = {
 interface:internet;
 interface:n2;
}

network:n2 = { ip6 = ::101:200/120; }

service:s1 = {
 user = network:lan1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Two static routes for network:internet
 via interface:asavpn.dmz and interface:asavpn.n1
=END=

############################################################
=TITLE=Use real ip in ACL but NAT IP in crypto ACL
=TODO= No IPv6
=INPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 1 hour 100000 kilobytes;
}

isakmp:aes256SHA = {
 nat_traversal = additional;
 authentication = preshare;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 43200 sec;
 trust_point =  ASDM_TrustPoint3;
}

crypto:sts = {
 type = ipsec:aes256SHA;
 detailed_crypto_acl;
 nat_out = intern;
}
network:intern = {
 ip6 = ::a01:100/120;
 nat:intern = { ip6 = f000::c0a8:200/120; }
}

router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = ::102:302;
  hub = crypto:sts;
  hardware = outside;
 }
}

network:dmz = { ip6 = ::102:300/121; }

router:extern = {
 interface:dmz = { ip6 = ::102:301; }
 interface:internet;
}

network:internet = { ip6 = ::/0; has_subnets; }

router:vpn1 = {
 interface:internet = { ip6 = ::101:101; spoke = crypto:sts; }
 interface:lan1 = {  ip6 = ::a63:101; }
}
network:lan1 = { ip6 = ::a63:100/120; }
service:test = {
 user = network:lan1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
=OUTPUT=
-- ipv6/asavpn
! crypto-::101:101
access-list crypto-::101:101 extended permit ip f000::c0a8:200/120 ::a63:100/120
crypto map crypto-outside 1 set peer ::101:101
crypto map crypto-outside 1 match address crypto-::101:101
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600
crypto map crypto-outside 1 set security-association lifetime kilobytes 100000
tunnel-group ::101:101 type ipsec-l2l
tunnel-group ::101:101 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp ::a63:100/120 ::a01:100/120 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Directly connected software clients
=TEMPL=input
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA, VPN;
 managed;
# routing = manual;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip6 = ::a01:101;
  hub = crypto:vpn;
  hardware = n1;
  no_check;
 }
}
router:softclients = {
 interface:n1 = {
  spoke = crypto:vpn;
  ip6 = ::a01:102;
 }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
service:s1 = {
 user = host:id:foo@domain.x.clients;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
-- ipv6/asavpn
! [ Routing ]
ipv6 route n1 ::a63:100/120 ::a01:102
--
! n1_in
access-list n1_in extended permit tcp host ::a63:10a ::a01:100/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Directly connected software clients; peer without IP
=INPUT=[[input]]
=SUBST=/ip6 = ::a01:102;//
=ERROR=
Error: interface:softclients.n1 used to reach software clients
 must not be directly connected to interface:asavpn.n1
 Connect it to some network behind next hop
=END=

############################################################
=TITLE=Directly connected software clients; without routing
=INPUT=[[input]]
=SUBST=/ip6 = ::a01:102;//
=SUBST=/# routing = manual/ routing = manual/
=OUTPUT=
-- ipv6/asavpn
! n1_in
access-list n1_in extended permit tcp host ::a63:10a ::a01:100/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Attribute nat_in at unmanged spoke
=TODO= No IPv6
=INPUT=
[[crypto_sts]]
network:n1 = { ip6 = ::a01:100/120; nat:n1 = { ip6 = ::a09:900/120; } }
router:asavpn = {
 model = ASA;
 managed;
 interface:n1 = {
  ip6 = ::a01:101;
  hardware = n1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts;
  hardware = dmz;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  negotiated6;
  nat_in = n1;
  spoke = crypto:sts;
  id = cert@example.com;
 }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
}
service:s1 = {
 user = network:clients;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=OUTPUT=
-- ipv6/asavpn
! dmz_in
access-list dmz_in extended permit tcp ::a63:100/120 ::a01:100/120 eq 80
access-list dmz_in extended deny ip any6 any6
access-group dmz_in in interface dmz
=END=

############################################################
# Changed topology
=TEMPL=topo
[[crypto_sts]]
crypto:sts2 = {
 type = ipsec:aes256SHA;
 detailed_crypto_acl;
}
network:n1 = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA;
 managed;
 interface:n1 = {
  ip6 = ::a01:101;
  hardware = n1;
 }
 interface:internet = {
  ip6 = f000::ac10:1;
  hub = crypto:sts, crypto:sts2;
  hardware = internet;
 }
}
network:internet = { ip6 = ::/0; }
router:vpn1 = {
 interface:internet = {
  ip6 = f000::ac10:102;
  id = cert1@example.com;
  spoke = crypto:sts;
 }
 interface:lan1 = {
  ip6 = ::a63:101;
 }
}
network:lan1 = { ip6 = ::a63:100/120; }
router:vpn2 = {
 interface:internet = {
  ip6 = f000::ac10:201;
  id = cert2@example.com;
  spoke = crypto:sts2;
 }
 interface:loop = {
  ip6 = ::a01:181;
  loopback;
  subnet_of = network:n1;
 }
}
service:s1 = {
 user = network:lan1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
service:s2 = {
 user = interface:vpn2.loop;
 permit src = user; dst = network:n1; prt = udp 123;
}
=END=

############################################################
=TITLE=Zone cluster with crypto tunnel and detailed_crypto_acl
=TODO= No IPv6
# Zone of tunnel with attribute detailed_crypto_acl
# needs not to be checked for supernet rules.
=INPUT=
[[topo]]
=WARNING=NONE
=OUTPUT=
-- ipv6/asavpn
! crypto-f000::ac10:201
access-list crypto-f000::ac10:201 extended permit ip ::a01:100/120 host ::a01:181
crypto map crypto-internet 2 set peer f000::ac10:201
crypto map crypto-internet 2 match address crypto-f000::ac10:201
crypto map crypto-internet 2 set ikev1 transform-set Trans1
crypto map crypto-internet 2 set pfs group2
crypto map crypto-internet 2 set security-association lifetime seconds 3600
crypto map crypto-internet 2 set security-association lifetime kilobytes 100000
tunnel-group f000::ac10:201 type ipsec-l2l
tunnel-group f000::ac10:201 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert2@example.com 10
 subject-name attr ea eq cert2@example.com
tunnel-group-map cert2@example.com 10 f000::ac10:201
crypto map crypto-internet interface internet
--
! internet_in
access-list internet_in extended permit tcp ::a63:100/120 ::a01:100/120 eq 80
access-list internet_in extended permit udp host ::a01:181 ::a01:100/120 eq 123
access-list internet_in extended deny ip any6 any6
access-group internet_in in interface internet
=END=

############################################################
=TITLE=Zone cluster with crypto tunnel and unexpected access
=TODO= No IPv6
# Zone of tunnel must be checked for supernet rules.
=INPUT=
[[topo]]
=SUBST=/detailed_crypto_acl;//
=WARNING=
Warning: This supernet rule would permit unexpected access:
  permit src=network:lan1; dst=network:n1; prt=tcp 80; of service:s1
 Generated ACL at interface:asavpn.tunnel:vpn1 would permit access to additional networks:
 - interface:vpn2.loop
 Either replace network:n1 by smaller networks that are not supernet
 or add above-mentioned networks to dst of rule.
=OUTPUT=
-- ipv6/asavpn
! crypto-f000::ac10:201
access-list crypto-f000::ac10:201 extended permit ip any6 host ::a01:181
crypto map crypto-internet 2 set peer f000::ac10:201
crypto map crypto-internet 2 match address crypto-f000::ac10:201
crypto map crypto-internet 2 set ikev1 transform-set Trans1
crypto map crypto-internet 2 set pfs group2
crypto map crypto-internet 2 set security-association lifetime seconds 3600
crypto map crypto-internet 2 set security-association lifetime kilobytes 100000
tunnel-group f000::ac10:201 type ipsec-l2l
tunnel-group f000::ac10:201 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert2@example.com 10
 subject-name attr ea eq cert2@example.com
tunnel-group-map cert2@example.com 10 f000::ac10:201
crypto map crypto-internet interface internet
--
! internet_in
access-list internet_in extended permit tcp ::a63:100/120 ::a01:100/120 eq 80
access-list internet_in extended permit udp host ::a01:181 ::a01:100/120 eq 123
access-list internet_in extended deny ip any6 any6
access-group internet_in in interface internet
=END=

############################################################
=TITLE=Unchecked supernet at crypto tunnel with detailed_crypto_acl
=TODO= No IPv6
# Zone of tunnel with attribute detailed_crypto_acl.
# Generated crypto ACL doesn't prevent unexpected access,
# but no warning is shown.
=INPUT=
[[topo]]
service:s3 = {
 user = interface:vpn2.loop;
 permit src = user; dst = network:lan1; prt = udp 123;
}
=WARNING=NONE
=OUTPUT=
-- ipv6/asavpn
! crypto-f000::ac10:201
access-list crypto-f000::ac10:201 extended permit ip ::a01:100/120 host ::a01:181
access-list crypto-f000::ac10:201 extended permit ip ::a63:100/120 host ::a01:181
crypto map crypto-internet 2 set peer f000::ac10:201
crypto map crypto-internet 2 match address crypto-f000::ac10:201
crypto map crypto-internet 2 set ikev1 transform-set Trans1
crypto map crypto-internet 2 set pfs group2
crypto map crypto-internet 2 set security-association lifetime seconds 3600
crypto map crypto-internet 2 set security-association lifetime kilobytes 100000
tunnel-group f000::ac10:201 type ipsec-l2l
tunnel-group f000::ac10:201 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert2@example.com 10
 subject-name attr ea eq cert2@example.com
tunnel-group-map cert2@example.com 10 f000::ac10:201
crypto map crypto-internet interface internet
--
! internet_in
object-group network v6g0
 network-object ::a01:100/120
 network-object ::a63:100/120
access-list internet_in extended permit tcp ::a63:100/120 ::a01:100/120 eq 80
access-list internet_in extended permit udp host ::a01:181 object-group v6g0 eq 123
access-list internet_in extended deny ip any6 any6
access-group internet_in in interface internet
=END=

############################################################
=TITLE=No secondary optimization for incoming ID host
=INPUT=
[[crypto_vpn]]
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
router:asavpn = {
 model = ASA, VPN;
 managed = secondary;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n2 = {
  ip6 = ::a01:202;
  hub = crypto:vpn;
  hardware = n2;
  no_check;
 }
}
router:softclients = {
 interface:n2 = {
  spoke = crypto:vpn;
  ip6 = ::a01:203;
 }
 interface:clients;
}
network:clients = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
service:s1 = {
 user = host:id:foo@domain.x.clients;
 permit src = user; dst = host:h1; prt = tcp 80;
 permit src = host:h1; dst = user; prt = tcp 22;
}
=OUTPUT=
-- ipv6/asavpn
! n2_in
access-list n2_in extended permit ip ::a01:100/120 host ::a63:10a
access-list n2_in extended permit ip host ::a63:10a ::a01:100/120
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Empty software clients
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:200/120; }
network:trans = { ip6 = ::a09:900/120; }
router:gw = {
 interface:intern = { ip6 = ::a01:201; hardware = e0; }
 interface:trans = { ip6 = ::a09:902; }
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = { trust-point = ASDM_TrustPoint1; }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:trans = { spoke = crypto:vpn; ip6 = ::a09:903; }
}
=OUTPUT=
-- ipv6/asavpn
! outside_in
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Must not use aggregate with software clients
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:200/120;}
router:gw = {
 interface:intern;
 interface:dmz = { ip6 = f000::c0a8:2; }
}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
  no_check;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:softclients = {
 interface:intern = { spoke = crypto:vpn; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = {  ip6 = ::a63:10a; }
}
service:test1 = {
 user = any:[network:customers1];
 permit src = user; dst = network:intern; prt = tcp 80;
}
=WARNING=
Warning: Ignoring any:[network:customers1] with software clients in src of rule in service:test1
=END=

############################################################
=TITLE=Duplicate ID-hosts
=INPUT=
[[crypto_vpn]]
crypto:vpn2 = {
 type = ipsec:aes256SHA;
}
network:intern = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz1 = {
  ip6 = f000::c0a8:101;
  hub = crypto:vpn;
  hardware = dmz1;
 }
 interface:dmz2 = {
  ip6 = f000::c0a8:201;
  hub = crypto:vpn2;
  hardware = dmz2;
 }
}
network:dmz1 = { ip6 = f000::c0a8:100/120; }
router:extern = {
 interface:dmz1 = { ip6 = f000::c0a8:102; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:softclients1 = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
 interface:customers2;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 host:id:foo@domain.x = { ip6 = ::a63:10a; }
}
network:customers2 = {
 ip6 = ::a63:200/120;
 host:id:foo@domain.x = { ip6 = ::a63:20a; }
}
network:dmz2 = { ip6 = f000::c0a8:200/120; }
router:gw = {
 interface:dmz2 = { ip6 = f000::c0a8:202; }
 interface:trans = { ip6 = ::a09:902; }
}
network:trans = { ip6 = ::a09:900/120; }
router:softclients2 = {
 interface:trans = { spoke = crypto:vpn2; ip6 = ::a09:903; }
 interface:customers3;
}
network:customers3 = {
 ip6 = ::a63:300/120;
 host:id:foo@domain.x = { ip6 = ::a63:30a; }
}
service:test1 = {
 user = host:id:foo@domain.x.customers1,
        host:id:foo@domain.x.customers2,
        host:id:foo@domain.x.customers3,
 ;
 permit src = user; dst = network:intern; prt = tcp 80;
}
=ERROR=
Error: Duplicate ID-host foo@domain.x from network:customers1 and network:customers2 at router:asavpn
Error: Duplicate ID-host foo@domain.x from network:customers3 and network:customers1 at router:asavpn
=END=

############################################################
=TITLE=ASA with two crypto spokes and NAT
=TODO= No IPv6
=TEMPL=input
ipsec:aes192SHA = {
 key_exchange = isakmp:aes192SHA;
 esp_encryption = aes192;
 esp_authentication = sha384;
 pfs_group = 15;
 lifetime = 3600 sec;
}
isakmp:aes192SHA = {
 ike_version = 1;
 nat_traversal = additional;
 authentication = rsasig;
 encryption = aes192;
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
 authentication = preshare;
 encryption = 3des;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:sts1 = {
 type = ipsec:aes192SHA;
}
crypto:sts2 = {
 type = ipsec:3desSHA;
 detailed_crypto_acl;
}
network:intern = {
 ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:16f; }
}
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  nat_out = lan2a;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts1, crypto:sts2;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  ip6 = f000::ac10:102;
  id = cert@example.com;
  spoke = crypto:sts1;
 }
 interface:lan1 = {
  ip6 = ::a63:101;
 }
}
network:lan1 = { ip6 = ::a63:100/120; }
router:vpn2 = {
 interface:internet = {
  ip6 = f000::ac10:202;
  spoke = crypto:sts2;
 }
 interface:lan2 = {
  ip6 = ::a63:201;
 }
 interface:lan2a = {
  ip6 = f000::c0a8:1601;
 }
}
network:lan2 = { ip6 = ::a63:200/120; }
network:lan2a = {
 ip6 = f000::c0a8:1600/120;
 nat:lan2a = { ip6 = ::a63:1600/120;}
}
protocol:http = tcp 80;
service:test = {
 user = network:lan1, network:lan2, network:lan2a;
 permit src = user; dst = host:netspoc; prt = protocol:http;
}
=INPUT=[[input]]
=OUTPUT=
--ipv6/asavpn
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec ikev1 transform-set Trans2 esp-aes-192 esp-sha384-hmac
--
! crypto-f000::ac10:102
access-list crypto-f000::ac10:102 extended permit ip any6 ::a63:100/120
crypto map crypto-outside 1 set peer f000::ac10:102
crypto map crypto-outside 1 match address crypto-f000::ac10:102
crypto map crypto-outside 1 set ikev1 transform-set Trans2
crypto map crypto-outside 1 set pfs group15
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group f000::ac10:102 type ipsec-l2l
tunnel-group f000::ac10:102 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 f000::ac10:102
--
! crypto-f000::ac10:202
access-list crypto-f000::ac10:202 extended permit ip ::a01:100/120 ::a63:200/120
access-list crypto-f000::ac10:202 extended permit ip ::a01:100/120 f000::c0a8:1600/120
crypto map crypto-outside 2 set peer f000::ac10:202
crypto map crypto-outside 2 match address crypto-f000::ac10:202
crypto map crypto-outside 2 set ikev1 transform-set Trans1
crypto map crypto-outside 2 set pfs group2
crypto map crypto-outside 2 set security-association lifetime seconds 600
tunnel-group f000::ac10:202 type ipsec-l2l
tunnel-group f000::ac10:202 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside interface outside
--
! outside_in
object-group network v6g0
 network-object ::a63:100/120
 network-object ::a63:200/120
 network-object f000::c0a8:1600/120
access-list outside_in extended permit tcp object-group v6g0 host ::a01:16f eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA with two crypto spokes and NAT (IKEv2)
=TODO= No IPv6
=INPUT=[[input]]
=SUBST=/ike_version = 1/ike_version = 2/
=OUTPUT=
--ipv6/asavpn
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption 3des
 protocol esp integrity sha-1
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-192
 protocol esp integrity sha-384
--
! crypto-f000::ac10:102
access-list crypto-f000::ac10:102 extended permit ip any6 ::a63:100/120
crypto map crypto-outside 1 set peer f000::ac10:102
crypto map crypto-outside 1 match address crypto-f000::ac10:102
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 1 set pfs group15
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group f000::ac10:102 type ipsec-l2l
tunnel-group f000::ac10:102 ipsec-attributes
 ikev2 local-authentication certificate ASDM_TrustPoint3
 ikev2 remote-authentication certificate
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 f000::ac10:102
--
! crypto-f000::ac10:202
access-list crypto-f000::ac10:202 extended permit ip ::a01:100/120 ::a63:200/120
access-list crypto-f000::ac10:202 extended permit ip ::a01:100/120 f000::c0a8:1600/120
crypto map crypto-outside 2 set peer f000::ac10:202
crypto map crypto-outside 2 match address crypto-f000::ac10:202
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans1
crypto map crypto-outside 2 set pfs group2
crypto map crypto-outside 2 set security-association lifetime seconds 600
tunnel-group f000::ac10:202 type ipsec-l2l
tunnel-group f000::ac10:202 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside interface outside
--
! outside_in
object-group network v6g0
 network-object ::a63:100/120
 network-object ::a63:200/120
 network-object f000::c0a8:1600/120
access-list outside_in extended permit tcp object-group v6g0 host ::a01:16f eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=IOS with two crypto spokes and NAT (IKEv2)
=TODO= No IPv6
=INPUT=[[input]]
=SUBST=/ike_version = 1/ike_version = 2/
=SUBST=/ASA/IOS/
=SUBST=/aes192/aes/
=OUTPUT=
--ipv6/asavpn
! [ Crypto ]
crypto isakmp policy 1
 authentication pre-share
 encryption 3des
 hash sha
 group 2
crypto isakmp policy 2
 encryption aes
 hash sha
 group 15
 lifetime 43200
crypto ipsec transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec transform-set Trans2 esp-aes esp-sha384-hmac
ipv6 access-list crypto-f000::ac10:102
 permit ipv6 any ::a63:100/120
ipv6 access-list crypto-filter-f000::ac10:102
 permit tcp ::a63:100/120 host ::a01:16f eq 80
 deny ipv6 any any
crypto map crypto-outside 1 ipsec-isakmp
 set peer f000::ac10:102
 match address crypto-f000::ac10:102
 set ip access-group crypto-filter-f000::ac10:102 in
 set transform-set Trans2
 set pfs group15
ipv6 access-list crypto-f000::ac10:202
 permit ipv6 ::a01:100/120 ::a63:200/120
 permit ipv6 ::a01:100/120 f000::c0a8:1600/120
ipv6 access-list crypto-filter-f000::ac10:202
 permit tcp ::a63:200/120 host ::a01:16f eq 80
 permit tcp f000::c0a8:1600/120 host ::a01:16f eq 80
 deny ipv6 any any
crypto map crypto-outside 2 ipsec-isakmp
 set peer f000::ac10:202
 match address crypto-f000::ac10:202
 set ip access-group crypto-filter-f000::ac10:202 in
 set transform-set Trans1
 set pfs group2
 set security-association lifetime seconds 600
=END=

############################################################
=TITLE=ASA with two dynamic crypto spokes, same ipsec at different tunnels
=TODO= No IPv6
=TEMPL=input
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha384;
 pfs_group = 15;
 lifetime = 3600 sec;
}
isakmp:aes256SHA = {
 ike_version = 2;
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
crypto:sts2 = {
 type = ipsec:aes256SHA;
 detailed_crypto_acl;
}
network:intern = {
 ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:16f; }
}
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  nat_out = lan2a;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts1, crypto:sts2;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  negotiated6;
  spoke = crypto:sts1;
  id = vpn1@example.com;
 }
 interface:lan1 = {
  ip6 = ::a63:201;
 }
}
network:lan1 = { ip6 = ::a63:200/120; }
router:vpn2 = {
 interface:internet = {
  negotiated6;
  spoke = crypto:sts2;
  id = vpn2@example.com;
 }
 interface:lan2 = {
  ip6 = ::a63:301;
 }
 interface:lan2a = {
  ip6 = f000::c0a8:1601;
 }
}
network:lan2 = { ip6 = ::a63:300/120; }
network:lan2a = {
 ip6 = f000::c0a8:1600/120;
 nat:lan2a = { ip6 = ::a63:1600/120;}
}
protocol:http = tcp 80;
service:test = {
 user = network:lan1, network:lan2, network:lan2a;
 permit src = user; dst = host:netspoc; prt = protocol:http;
}
=INPUT=[[input]]
# Use individual routes to VPN peers, even if all have same next hop.
=OUTPUT=
--ipv6/asavpn
! [ Routing ]
ipv6 route outside ::a63:200/120 f000::c0a8:1
ipv6 route outside ::a63:300/120 f000::c0a8:1
ipv6 route outside f000::c0a8:1600/120 f000::c0a8:1
ipv6 route outside ::/0 f000::c0a8:1
--
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption aes-256
 protocol esp integrity sha-384
--
! crypto-vpn1@example.com
access-list crypto-vpn1@example.com extended permit ip any6 ::a63:200/120
crypto dynamic-map vpn1@example.com 10 match address crypto-vpn1@example.com
crypto dynamic-map vpn1@example.com 10 set ikev2 ipsec-proposal Trans1
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
access-list crypto-vpn2@example.com extended permit ip ::a01:100/120 ::a63:300/120
access-list crypto-vpn2@example.com extended permit ip ::a01:100/120 f000::c0a8:1600/120
crypto dynamic-map vpn2@example.com 10 match address crypto-vpn2@example.com
crypto dynamic-map vpn2@example.com 10 set ikev2 ipsec-proposal Trans1
crypto dynamic-map vpn2@example.com 10 set pfs group15
crypto dynamic-map vpn2@example.com 10 set security-association lifetime seconds 3600
crypto map crypto-outside 65534 ipsec-isakmp dynamic vpn2@example.com
tunnel-group vpn2@example.com type ipsec-l2l
tunnel-group vpn2@example.com ipsec-attributes
 ikev2 local-authentication certificate ASDM_TrustPoint3
 ikev2 remote-authentication certificate
crypto ca certificate map vpn2@example.com 10
 subject-name attr ea eq vpn2@example.com
tunnel-group-map vpn2@example.com 10 vpn2@example.com
crypto map crypto-outside interface outside
=END=

############################################################
=TITLE=Generate individual routes even if no ::/0
=TODO= No IPv6
=INPUT=[[input]]
=SUBST=,::/0,::100:0/8,
# Use individual routes to VPN peers, even if all have same next hop
# and even if no route to ::/0 is added.
=WARNING=
Warning: Useless 'has_subnets' at network:internet
=OUTPUT=
--ipv6/asavpn
! [ Routing ]
ipv6 route outside ::a63:200/120 f000::c0a8:1
ipv6 route outside ::a63:300/120 f000::c0a8:1
ipv6 route outside f000::c0a8:1600/120 f000::c0a8:1
ipv6 route outside ::100:0/104 f000::c0a8:1
=END=

############################################################
=TITLE=Must not reuse crypto id
=TODO= No IPv6
=INPUT=[[input]]
=SUBST=/vpn2@/vpn1@/
=ERROR=
Error: Must not reuse 'id = vpn1@example.com' at different crypto spokes of 'router:asavpn':
 - interface:vpn1.tunnel:vpn1
 - interface:vpn2.tunnel:vpn2
=END=

############################################################
=TITLE=id only valid with spoke
=INPUT=
network:n1 = { unnumbered6; }
router:r1 = { interface:n1 = { id = a.b.c; } }
=WARNING=
Warning: Ignoring attribute 'id' only valid with 'spoke' at interface:r1.n1
=END=

############################################################
=TITLE=detailed_crypto_acl
=INPUT=
crypto:psk-detailed = {
 type = ipsec:aes256_sha256_ikev2_psk;
 detailed_crypto_acl;
}
ipsec:aes256_sha256_ikev2_psk = {
 key_exchange = isakmp:aes256_sha256_ikev2_psk;
# not given: esp_encryption = aes256; becomes "null"
 esp_authentication = sha256;
 pfs_group = 19;
 lifetime = 3600 sec;
}
isakmp:aes256_sha256_ikev2_psk = {
 ike_version = 2;
 nat_traversal = additional;
 authentication = preshare;
 encryption = aes256;
 hash = sha256;
 group = 19;
 lifetime = 86400 sec;
}
network:n1 = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:dmz = { ip6 = f000::c0a8:104; hardware = dmz;
                   hub = crypto:psk-detailed; }
}
network:dmz = { ip6 = f000::c0a8:100/123;}
router:r1 = {
 interface:dmz = { ip6 = f000::c0a8:102; spoke = crypto:psk-detailed; }
 interface:n2;
}
network:n2 = { ip6 = ::a01:200/120;}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
=OUTPUT=
--ipv6/asavpn
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption null
 protocol esp integrity sha-256
--
! crypto-f000::c0a8:102
access-list crypto-f000::c0a8:102 extended permit ip ::a01:100/120 ::a01:200/120
crypto map crypto-dmz 1 set peer f000::c0a8:102
crypto map crypto-dmz 1 match address crypto-f000::c0a8:102
crypto map crypto-dmz 1 set ikev2 ipsec-proposal Trans1
crypto map crypto-dmz 1 set pfs group19
crypto map crypto-dmz 1 set security-association lifetime seconds 3600
tunnel-group f000::c0a8:102 type ipsec-l2l
tunnel-group f000::c0a8:102 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-dmz interface dmz
--
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 22
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Unexpected dynamic crypto spoke
=INPUT=
[[crypto_sts]]
network:intern = {
 ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:16f; }
}
router:asavpn = {
 model = IOS;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  negotiated6;
  spoke = crypto:sts;
  id = vpn1@example.com;
 }
 interface:lan1 = {
  ip6 = ::a63:201;
 }
}
network:lan1 = { ip6 = ::a63:200/120; }
=ERROR=
Error: router:asavpn can't establish crypto tunnel to interface:vpn1.internet with unknown IP
=END=

############################################################
=TITLE=VPN ASA to VPN router with two local networks
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmpv6 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint3;
  banner = Welcome at VPN service;
  dns-server = ::a01:10a ::a01:10b;
  wins-server = ::a01:114;
 }
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn = {
 managed;
 model = IOS;
 interface:internet = {
  negotiated6;
  spoke = crypto:vpn;
  id = abc@123.45;
  hardware = e1;
 }
 interface:lan2 = {
  ip6 = ::a63:201;
  hardware = e2;
 }
 interface:lan3 = {
  ip6 = ::a63:301;
  hardware = e3;
 }
}
network:lan2 = { ip6 = ::a63:200/120; }
network:lan3 = { ip6 = ::a63:300/120; }
service:test = {
 user = network:lan2, network:lan3;
 permit src = user; dst = network:intern; prt = tcp 80;
 permit src = network:intern; dst = user; prt = udp 123;
}
=OUTPUT=
--ipv6/asavpn
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
access-list vpn-filter-abc@123.45 extended permit ip ::a63:200/119 any6
access-list vpn-filter-abc@123.45 extended deny ip any6 any6
group-policy VPN-router-abc@123.45 internal
group-policy VPN-router-abc@123.45 attributes
 banner value Welcome at VPN service
 dns-server value ::a01:10a ::a01:10b
 wins-server value ::a01:114
username abc@123.45 nopassword
username abc@123.45 attributes
 service-type remote-access
 vpn-filter value vpn-filter-abc@123.45
 vpn-group-policy VPN-router-abc@123.45
--
! outside_in
access-list outside_in extended permit icmp6 ::a63:200/119 any6 3
access-list outside_in extended permit tcp ::a63:200/119 ::a01:100/120 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
--ipv6/vpn
ipv6 access-list e1_in
 permit 50 host f000::c0a8:65 any
 permit udp host f000::c0a8:65 eq 500 any eq 500
 deny ipv6 any any
--
ipv6 access-list e2_in
 permit tcp ::a63:200/120 ::a01:100/120 eq 80
 permit udp ::a63:200/120 eq 123 ::a01:100/120
 deny ipv6 any any
--
interface e1
 ip address negotiated
 crypto map crypto-e1
 ipv6 traffic-filter e1_in in
interface e2
 ipv6 address ::a63:201/120
 ipv6 traffic-filter e2_in in
interface e3
 ipv6 address ::a63:301/120
 ipv6 traffic-filter e3_in in
=END=

############################################################
=TITLE=ASA as managed VPN spoke
=TEMPL=input
[[crypto_sts]]
network:intern = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:101;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:100/120; }
router:vpn1 = {
 managed;
 model = ASA;
 interface:dmz = {
  ip6 = f000::c0a8:102;
  id = cert@example.com;
  spoke = crypto:sts;
  hardware = GigabitEthernet0;
 }
 interface:lan1 = {
  ip6 = ::a63:101;
  hardware = Fastethernet8;
 }
}
network:lan1 = { ip6 = ::a63:100/120; }
service:test = {
 user = network:lan1;
 permit src = user; dst = network:intern; prt = tcp 80;
 permit src = network:intern; dst = user; prt = udp 123;
}
=INPUT=[[input]]
=OUTPUT=
--ipv6/vpn1
! [ Routing ]
ipv6 route GigabitEthernet0 ::a01:100/120 f000::c0a8:101
--
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-aes-256 esp-sha-hmac
--
! crypto-f000::c0a8:101
access-list crypto-f000::c0a8:101 extended permit ip ::a63:100/120 any6
crypto map crypto-GigabitEthernet0 1 set peer f000::c0a8:101
crypto map crypto-GigabitEthernet0 1 match address crypto-f000::c0a8:101
crypto map crypto-GigabitEthernet0 1 set ikev1 transform-set Trans1
crypto map crypto-GigabitEthernet0 1 set pfs group2
crypto map crypto-GigabitEthernet0 1 set security-association lifetime seconds 3600
crypto map crypto-GigabitEthernet0 1 set security-association lifetime kilobytes 100000
tunnel-group f000::c0a8:101 type ipsec-l2l
tunnel-group f000::c0a8:101 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto map crypto-GigabitEthernet0 interface GigabitEthernet0
--
! GigabitEthernet0_in
access-list GigabitEthernet0_in extended permit udp ::a01:100/120 ::a63:100/120 eq 123
access-list GigabitEthernet0_in extended deny ip any6 any6
access-group GigabitEthernet0_in in interface GigabitEthernet0
--
! Fastethernet8_in
access-list Fastethernet8_in extended permit tcp ::a63:100/120 ::a01:100/120 eq 80
access-list Fastethernet8_in extended deny ip any6 any6
access-group Fastethernet8_in in interface Fastethernet8
=END=

############################################################
=TITLE=Missing trust_point in isakmp for spoke and hub (1)
=INPUT=[[input]]
=SUBST=/trust_point/#trust_point/
=ERROR=
Error: Missing attribute 'trust_point' in isakmp:aes256SHA for router:vpn1
Error: Missing attribute 'trust_point' in isakmp:aes256SHA for router:asavpn
=END=

############################################################
=TITLE=Missing trust_point in isakmp for spoke and hub (2)
=INPUT=[[input]]
=SUBST=/trust_point = ASDM_TrustPoint3;/trust_point = none;/
=ERROR=
Error: Missing attribute 'trust_point' in isakmp:aes256SHA for router:vpn1
Error: Missing attribute 'trust_point' in isakmp:aes256SHA for router:asavpn
=END=

############################################################
# Shared topology for multiple tests.

############################################################
=TEMPL=topo
[[crypto_sts]]
network:intern = {
 ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:16f; }
}
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = ::102:302;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = ::102:300/121; }
router:extern = {
 interface:dmz = { ip6 = ::102:301; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:firewall = {
 managed;
 model = ASA;
 interface:internet = {
  ip6 = ::101:101;
  nat_out = vpn1;
  routing = dynamic;
  hardware = outside;
 }
 interface:dmz1 = { ip6 = ::afe:fe90; hardware = inside; }
}
network:dmz1 = {
 ip6 = ::afe:fe00/120;
 nat:vpn1 = { ip6 = ::102:381/128; dynamic; }
}
router:vpn1 = {
 managed;#
 model = IOS;
 interface:dmz1 = {
  ip6 = ::afe:fe06;
id = cert@example.com;#
  nat:vpn1 = { ip6 = ::102:381; }
  spoke = crypto:sts;
  nat_out = lan1;
  hardware = GigabitEthernet0;
 }
 interface:lan1 = {
  ip6 = ::a63:101, ::a63:1fd;
  hardware = Fastethernet8;
 }
}
network:lan1 = {
 ip6 = ::a63:100/120;
 nat:lan1 = { ip6 = ::a0a:a00/120; }
 #host:id:h1@example.com = { ip6 = ::a63:182; }
}
=END=

############################################################
=TITLE=Create crypto ACL even if no rule is defined
=TODO= No IPv6
=INPUT=
[[topo]]
=OUTPUT=
--ipv6/asavpn
! crypto-::102:381
access-list crypto-::102:381 extended permit ip any6 ::a0a:a00/120
crypto map crypto-outside 1 set peer ::102:381
crypto map crypto-outside 1 match address crypto-::102:381
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600
crypto map crypto-outside 1 set security-association lifetime kilobytes 100000
tunnel-group ::102:381 type ipsec-l2l
tunnel-group ::102:381 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 ::102:381
crypto map crypto-outside interface outside
=END=

############################################################
=TITLE=Access VPN interface
=TODO= No IPv6
=INPUT=
[[topo]]
service:test = {
 user = host:netspoc;
 permit src = user; dst = interface:vpn1.lan1; prt = tcp 22;
}
=OUTPUT=
--ipv6/vpn1
ipv6 access-list crypto-::102:302
 permit ipv6 ::a0a:a00/120 any
ipv6 access-list crypto-filter-::102:302
 permit tcp host ::a01:16f host ::a0a:a01 eq 22
 deny ipv6 any any
crypto map crypto-GigabitEthernet0 1 ipsec-isakmp
 set peer ::102:302
 match address crypto-::102:302
 set ip access-group crypto-filter-::102:302 in
 set transform-set Trans1
 set pfs group2
 set security-association lifetime kilobytes 100000
=END=

############################################################
=TITLE=NAT of IPSec traffic at ASA and NAT of VPN network at IOS
=TODO= No IPv6
=INPUT=
[[topo]]
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
 permit src = host:netspoc; dst = user; prt = udp 123;
}
=OUTPUT=
--ipv6/asavpn
! crypto-::102:381
access-list crypto-::102:381 extended permit ip any6 ::a0a:a00/120
crypto map crypto-outside 1 set peer ::102:381
crypto map crypto-outside 1 match address crypto-::102:381
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600
crypto map crypto-outside 1 set security-association lifetime kilobytes 100000
tunnel-group ::102:381 type ipsec-l2l
tunnel-group ::102:381 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 ::102:381
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp ::a0a:a00/120 host ::a01:16f eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
--ipv6/vpn1
ipv6 access-list crypto-::102:302
 permit ipv6 ::a0a:a00/120 any
ipv6 access-list crypto-filter-::102:302
 deny ipv6 any host ::a0a:a01
 deny ipv6 any host ::a0a:afd
 permit udp host ::a01:16f ::a0a:a00/120 eq 123
 permit tcp host ::a01:16f ::a0a:a00/120 established
 deny ipv6 any any
crypto map crypto-GigabitEthernet0 1 ipsec-isakmp
 set peer ::102:302
 match address crypto-::102:302
 set ip access-group crypto-filter-::102:302 in
 set transform-set Trans1
 set pfs group2
 set security-association lifetime kilobytes 100000
--
ipv6 access-list GigabitEthernet0_in
 permit 50 host ::102:302 host ::afe:fe06
 permit udp host ::102:302 eq 500 host ::afe:fe06 eq 500
 permit udp host ::102:302 eq 4500 host ::afe:fe06 eq 4500
 deny ipv6 any any
--ipv6/firewall
! outside_in
access-list outside_in extended permit 50 host ::102:302 host ::afe:fe06
access-list outside_in extended permit udp host ::102:302 eq 500 host ::afe:fe06 eq 500
access-list outside_in extended permit udp host ::102:302 eq 4500 host ::afe:fe06 eq 4500
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended permit 50 host ::afe:fe06 host ::102:302
access-list inside_in extended permit udp host ::afe:fe06 eq 500 host ::102:302 eq 500
access-list inside_in extended permit udp host ::afe:fe06 eq 4500 host ::102:302 eq 4500
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=detailed_crypto_acl at managed spoke
=TODO= No IPv6
=INPUT=[[topo]]
=SUBST=/type = ipsec:/detailed_crypto_acl; type = ipsec:/
=ERROR=
Error: Attribute 'detailed_crypto_acl' is not allowed for managed spoke router:vpn1
=END=

############################################################
=TITLE=Don't add hidden network to crypto ACL
=TODO= No IPv6
=INPUT=
[[topo]]
network:lan2 = {
 ip6 = ::a63:200/120;
 nat:h = { hidden; }
}
=SUBST=/interface:lan1/interface:lan2={ip6=::a63:201;hardware=lan2;}interface:lan1/
=SUBST=/nat_out = lan1;/nat_out = h, lan1; /
=OUTPUT=
--ipv6/asavpn
! crypto-::102:381
access-list crypto-::102:381 extended permit ip any6 ::a0a:a00/120
crypto map crypto-outside 1 set peer ::102:381
crypto map crypto-outside 1 match address crypto-::102:381
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600
crypto map crypto-outside 1 set security-association lifetime kilobytes 100000
tunnel-group ::102:381 type ipsec-l2l
tunnel-group ::102:381 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 ::102:381
crypto map crypto-outside interface outside
=END=

############################################################
=TITLE=Multiple zones behind managed crypto router
=TODO= No IPv6
=INPUT=
[[topo]]
router:r1 = {
 managed;
 model = IOS;
 interface:lan1 = { ip6 = ::a63:102; hardware = lan1; }
 interface:x = { ip6 = ::a63:181; hardware = x; }
}
network:x = { ip6 = ::a63:180/122; subnet_of = network:lan1; }
=ERROR=
Error: Exactly one security zone must be located behind managed interface:vpn1.lan1 of crypto router
=END=

############################################################
=TITLE=ID hosts behind managed crypto router
=TODO= No IPv6
=INPUT=
[[topo]]
=SUBST=/#host/host/
=ERROR=
Error: network:lan1 having ID hosts can't be checked by router:asavpn
Error: network:lan1 having ID hosts must not be located behind managed router:vpn1
=END=

############################################################
=TITLE=ID hosts behind unmanaged crypto router
=TODO= No IPv6
=INPUT=
[[topo]]
=SUBST=/#host/host/
=SUBST=/managed;#//
=ERROR=
Error: network:lan1 having ID hosts can't be checked by router:asavpn
=END=

############################################################
=TITLE=Attribute 'id' with wrong authentication
=TODO= No IPv6
=INPUT=
[[topo]]
=SUBST=/rsasig/preshare/
=ERROR=
Error: Invalid attribute 'id' at interface:vpn1.tunnel:vpn1.
 Set authentication=rsasig at isakmp:aes256SHA
=END=

############################################################
# Changed topology
=TEMPL=topo
[[crypto_sts]]
network:intern = {
 ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:16f; }
}
router:vpn = {
 model = IOS;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = intern;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts;
  hardware = dmz;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  ip6 = f000::ac10:102;
  id = cert@example.com;
  spoke = crypto:sts;
 }
 interface:lan1 = {
  ip6 = ::a63:101;
 }
}
network:lan1 = { ip6 = ::a63:100/120; }
=END=

############################################################
=TITLE=IOS router as VPN hub
=INPUT=
[[topo]]
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
}
=SUBST=/group = 2/group = 15/
=SUBST=/100000 kilobytes/4608000 kilobytes/

=OUTPUT=
--ipv6/vpn
crypto isakmp policy 1
 encryption aes 256
 hash sha
 group 15
 lifetime 43200
crypto ipsec transform-set Trans1 esp-aes 256 esp-sha-hmac
ipv6 access-list crypto-f000::ac10:102
 permit ipv6 any ::a63:100/120
ipv6 access-list crypto-filter-f000::ac10:102
 permit tcp ::a63:100/120 host ::a01:16f eq 80
 deny ipv6 any any
crypto map crypto-dmz 1 ipsec-isakmp
 set peer f000::ac10:102
 match address crypto-f000::ac10:102
 set ip access-group crypto-filter-f000::ac10:102 in
 set transform-set Trans1
 set pfs group15
--
ipv6 access-list intern_in
 permit tcp host ::a01:16f ::a63:100/120 established
 deny ipv6 any any
--
ipv6 access-list dmz_in
 permit 50 host f000::ac10:102 host f000::c0a8:65
 permit udp host f000::ac10:102 eq 500 host f000::c0a8:65 eq 500
 permit udp host f000::ac10:102 eq 4500 host f000::c0a8:65 eq 4500
 deny ipv6 any any
--
interface intern
 ipv6 address ::a01:165/120
 ipv6 traffic-filter intern_in in
interface dmz
 ipv6 address f000::c0a8:65/120
 crypto map crypto-dmz
 ipv6 traffic-filter dmz_in in
=END=

############################################################
=TITLE=Unmanaged VPN spoke with unknown ID
=TEMPL=input
[[crypto_sts]]
network:intern = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = ::102:302;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = ::102:300/121; }
router:extern = {
 interface:dmz = { ip6 = ::102:301; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
    ip6 = ::101:101;
#  id = cert@example.com;
  spoke = crypto:sts;
 }
 interface:lan1;
}
network:lan1 = { ip6 = ::a63:100/120; }
=INPUT=[[input]]
=ERROR=
Error: interface:vpn1.tunnel:vpn1 needs attribute 'id', because isakmp:aes256SHA has authentication=rsasig
=END=

############################################################
=TITLE=Unmanaged VPN spoke with known ID
=INPUT=[[input]]
=SUBST=/#  id/  id/
=OUTPUT=
--ipv6/asavpn
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-aes-256 esp-sha-hmac
--
! crypto-::101:101
access-list crypto-::101:101 extended permit ip any6 ::a63:100/120
crypto map crypto-outside 1 set peer ::101:101
crypto map crypto-outside 1 match address crypto-::101:101
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
crypto map crypto-outside 1 set security-association lifetime seconds 3600
crypto map crypto-outside 1 set security-association lifetime kilobytes 100000
tunnel-group ::101:101 type ipsec-l2l
tunnel-group ::101:101 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 ::101:101
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Must not traverse crypto interface
=INPUT=
[[input]]
service:t = {
 user = network:intern;
 permit src = user; dst = network:dmz; prt = tcp 80;
}
=SUBST=/#  id/  id/
=ERROR=
Error: No valid path
 from any:[network:intern]
 to any:[network:dmz]
 for rule permit src=network:intern; dst=network:dmz; prt=tcp 80; of service:t
 Check path restrictions and crypto interfaces.
=END=

############################################################
=TITLE=Must not use ID-host at model=ASA;
=INPUT=
[[crypto_sts]]
network:intern = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = ::102:302;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = ::102:300/121; }
router:extern = {
 interface:dmz = { ip6 = ::102:301; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  ip6 = ::101:101;
  spoke = crypto:sts;
 }
 interface:lan1;
}
network:lan1 = {
 ip6 = ::a63:100/120;
 host:id:@example.com = { range6 = ::a63:120 - ::a63:13f; }
}
=ERROR=
Error: network:lan1 having ID hosts can't be checked by router:asavpn
=END=

############################################################
=TITLE=Virtual interface must not be spoke
=INPUT=
[[crypto_sts]]
network:intern = { ip6 = ::a01:100/120; }
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = ::102:302;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = ::102:300/121; }
router:extern = {
 interface:dmz = { ip6 = ::102:301; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  ip6 = ::101:102;
  virtual = { ip6 = ::a01:101; }
  spoke = crypto:sts;
 }
 interface:lan1;
}
network:lan1 = {
 ip6 = ::a63:100/120;
}
=ERROR=
Error: interface:vpn1.internet with virtual interface must not use attribute 'spoke'
=END=

############################################################
=TITLE=Silently ignore auto interface at crypto tunnel
=INPUT=
[[crypto_vpn]]
network:intern = { ip6 = ::a01:100/120;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip6 = ::a01:166;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
}
network:customers1 = {
 ip6 = ::a63:100/120;
 vpn_attributes = {
  banner = Willkommen;
 }
 host:id:foo@domain.x = {
  ip6 = ::a63:10a;
 }
}
service:mgmt = {
 user = interface:softclients.[auto];
 permit src = network:intern; dst = user; prt = tcp 22;
}
=OUTPUT=
--ipv6/asavpn
! inside_in
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Sort crypto rules in ACL
=INPUT=
network:n0 = { ip6 = ::a01:0/120; }
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; }
network:n0-sub = { ip6 = ::a01:0/122; subnet_of = network:n0; }
network:n2-sub = { ip6 = ::a01:200/121; subnet_of = network:n2; }
router:u1 = {
 interface:n0-sub;
 interface:n0;
}
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n0 = { ip6 = ::a01:41;  hardware = n0; }
 interface:n1 = { ip6 = ::a01:101;   hardware = n1; }
 interface:n2 = { ip6 = ::a01:281; hardware = n2; }
}
router:u2 = {
 interface:n2;
 interface:n2-sub;
}
service:s1 = {
 user = network:n0, network:n1;
 permit src = user;
        dst = network:n2-sub;
        prt = tcp 22, proto 50;
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
service:s3 = {
 user = network:n0, network:n1;
 permit src = user;
        dst = network:n2-sub;
        prt = proto 51;
}
service:s4 = {
 user = host:h1;
 deny   src = user;
        dst = network:n2-sub;
        prt = tcp 22, proto 50;
}
service:s5 = {
 user = host:h1;
 permit src = user;
        dst = interface:r1.n1;
        prt = tcp 22, proto 50;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n0_in
 deny ipv6 any host ::a01:101
 deny ipv6 any host ::a01:281
 deny ipv6 ::a01:0/122 ::a01:200/121
 permit 50 ::a01:0/120 ::a01:200/121
 permit 50 ::a01:0/122 ::a01:100/120
 permit 50 ::a01:0/122 ::a01:200/120
 permit 51 ::a01:0/120 ::a01:200/121
 permit 51 ::a01:0/122 ::a01:100/120
 permit 51 ::a01:0/122 ::a01:200/120
 permit tcp ::a01:0/120 ::a01:200/121 eq 22
 deny ipv6 any any
--
ipv6 access-list n1_in
 permit 50 host ::a01:10a host ::a01:101
 permit tcp host ::a01:10a host ::a01:101 eq 22
 deny tcp host ::a01:10a ::a01:200/121 eq 22
 deny 50 host ::a01:10a ::a01:200/121
 permit 50 ::a01:100/120 ::a01:200/121
 permit 51 ::a01:100/120 ::a01:200/121
 permit tcp ::a01:100/120 ::a01:200/121 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Sort AH rules only
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101;   hardware = n1; }
 interface:n2 = { ip6 = ::a01:281; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80, tcp 22, proto 50;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:281
 permit 50 ::a01:100/120 ::a01:200/120
 permit tcp ::a01:100/120 ::a01:200/120 eq 80
 permit tcp ::a01:100/120 ::a01:200/120 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=Sort ESP rules only
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip6 = ::a01:101;   hardware = n1; }
 interface:n2 = { ip6 = ::a01:281; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80, proto 51, tcp 22;
}
=OUTPUT=
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:281
 permit 51 ::a01:100/120 ::a01:200/120
 permit tcp ::a01:100/120 ::a01:200/120 eq 80
 permit tcp ::a01:100/120 ::a01:200/120 eq 22
 deny ipv6 any any
=END=

############################################################
=TITLE=ASA with unencrypted spoke using AH
=TEMPL=input
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 ah = sha256;
 lifetime = 20000 kilobytes;
}
isakmp:aes256SHA = {
 ike_version = 1;
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
 ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:16f; }
}
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts1;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  ip6 = f000::ac10:102;
  id = cert@example.com;
  spoke = crypto:sts1;
 }
 interface:lan1 = {
  ip6 = ::a63:101;
 }
}
network:lan1 = { ip6 = ::a63:100/120; }
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
--ipv6/asavpn
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 ah-sha256-hmac esp-null
--
! crypto-f000::ac10:102
access-list crypto-f000::ac10:102 extended permit ip any6 ::a63:100/120
crypto map crypto-outside 1 set peer f000::ac10:102
crypto map crypto-outside 1 match address crypto-f000::ac10:102
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set security-association lifetime kilobytes 20000
tunnel-group f000::ac10:102 type ipsec-l2l
tunnel-group f000::ac10:102 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint3
 ikev1 user-authentication none
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 f000::ac10:102
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp ::a63:100/120 host ::a01:16f eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA with unencrypted spoke using AH  (IKEv2)
=INPUT=[[input]]
=SUBST=/ike_version = 1/ike_version = 2/
=OUTPUT=
--ipv6/asavpn
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol ah sha256
 protocol esp encryption null
 protocol esp integrity null
--
! crypto-f000::ac10:102
access-list crypto-f000::ac10:102 extended permit ip any6 ::a63:100/120
crypto map crypto-outside 1 set peer f000::ac10:102
crypto map crypto-outside 1 match address crypto-f000::ac10:102
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans1
crypto map crypto-outside 1 set security-association lifetime kilobytes 20000
tunnel-group f000::ac10:102 type ipsec-l2l
tunnel-group f000::ac10:102 ipsec-attributes
 ikev2 local-authentication certificate ASDM_TrustPoint3
 ikev2 remote-authentication certificate
crypto ca certificate map cert@example.com 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert@example.com 10 f000::ac10:102
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp ::a63:100/120 host ::a01:16f eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=ASA crypto with aes-gcm-256
=TEMPL=input
ipsec:aes-gcm-256 = {
 key_exchange = isakmp:aes-gcm-256-sha-256;
 esp_encryption = aes-gcm-256;
 # not given: esp_authentication; becomes "null"
 pfs_group = 21;
 lifetime = 1 hour;
}
isakmp:aes-gcm-256-sha-256 = {
 ike_version = 2;
 authentication = rsasig;
 encryption = aes-gcm-256;
 hash = sha256;
 group = 14;
 lifetime = 43200 sec;
 trust_point = ASDM_TrustPoint3;
}
crypto:sts = {
 type = ipsec:aes-gcm-256;
}

network:intern = {
 ip6 = ::a01:100/120;
 host:netspoc = { ip6 = ::a01:16f; }
}
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip6 = ::a01:165;
  hardware = inside;
 }
 interface:dmz = {
  ip6 = f000::c0a8:65;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = { ip6 = f000::c0a8:0/120; }
router:extern = {
 interface:dmz = { ip6 = f000::c0a8:1; }
 interface:internet;
}
network:internet = { ip6 = ::/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  ip6 = f000::ac10:102;
  id = f000::ac10:102;
  spoke = crypto:sts;
 }
 interface:lan1 = {
  ip6 = ::a63:101;
 }
}
network:lan1 = { ip6 = ::a63:100/120; }
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
--ipv6/asavpn
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption aes-gcm-256
 protocol esp integrity null
--
! crypto-f000::ac10:102
access-list crypto-f000::ac10:102 extended permit ip any6 ::a63:100/120
crypto map crypto-outside 1 set peer f000::ac10:102
crypto map crypto-outside 1 match address crypto-f000::ac10:102
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans1
crypto map crypto-outside 1 set pfs group21
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group f000::ac10:102 type ipsec-l2l
tunnel-group f000::ac10:102 ipsec-attributes
 ikev2 local-authentication certificate ASDM_TrustPoint3
 ikev2 remote-authentication certificate
crypto ca certificate map f000::ac10:102 10
 subject-name attr cn eq f000::ac10:102
tunnel-group-map f000::ac10:102 10 f000::ac10:102
crypto map crypto-outside interface outside
--
! outside_in
access-list outside_in extended permit tcp ::a63:100/120 host ::a01:16f eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=IOS crypto with aes-gcm-256
=INPUT=
[[input]]
=SUBST=/ASA/IOS/
=OUTPUT=
--ipv6/asavpn
! [ Crypto ]
--
crypto isakmp policy 1
 encryption aes-gcm 256
 hash sha256
 group 14
 lifetime 43200
crypto ipsec transform-set Trans1 esp-aes-gcm 256
ipv6 access-list crypto-f000::ac10:102
 permit ipv6 any ::a63:100/120
ipv6 access-list crypto-filter-f000::ac10:102
 permit tcp ::a63:100/120 host ::a01:16f eq 80
 deny ipv6 any any
crypto map crypto-outside 1 ipsec-isakmp
 set peer f000::ac10:102
 match address crypto-f000::ac10:102
 set ip access-group crypto-filter-f000::ac10:102 in
 set transform-set Trans1
 set pfs group21
--
ipv6 access-list outside_in
 permit 50 host f000::ac10:102 host f000::c0a8:65
 permit udp host f000::ac10:102 eq 500 host f000::c0a8:65 eq 500
 deny ipv6 any any
--
interface inside
 ipv6 address ::a01:165/120
 ipv6 traffic-filter inside_in in
interface outside
 ipv6 address f000::c0a8:65/120
 crypto map crypto-outside
 ipv6 traffic-filter outside_in in
=END=

############################################################
