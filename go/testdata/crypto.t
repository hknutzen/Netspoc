
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
=END=
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
=END=
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
=END=
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
=END=
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
=END=
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
=END=
=ERROR=
Error: Expected 'NUM sec|min|hour|day' in 'lifetime' of isakmp:aes256SHA
=END=

############################################################
=TITLE=Missing IPSec attributes
=INPUT=
ipsec:aes256SHA = {
 esp_encryption = aes256;
}
=END=
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
=END=
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
=END=
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
=END=
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
=END=
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
=END=
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
=END=
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
network:n1 = { ip = 10.1.1.0/24; }
=END=
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
network:n1 = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Can't resolve reference to isakmp:abc in ipsec:aes256SHA
Error: Missing 'key_exchange' for ipsec:aes256SHA
=END=

############################################################
=TITLE=Missing type of crypto definition
=INPUT=
crypto:c = {}
=END=
=ERROR=
Error: Missing 'type' for crypto:c
=END=

############################################################
=TITLE=Unknown type in crypto definition
=INPUT=
crypto:c = { type = xyz:abc; }
network:n1 = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Expected type 'ipsec:' in 'type' of crypto:c
Error: Missing 'type' for crypto:c
=END=

############################################################
=TITLE=Unknown ipsec referenced in crypto definition
=INPUT=
crypto:c = { type = ipsec:abc; }
network:n1 = { ip = 10.1.1.0/24; }
=END=
=ERROR=
Error: Can't resolve reference to ipsec:abc in crypto:c
Error: Missing 'type' for crypto:c
=END=

############################################################
=TITLE=No hub defined for crypto
=INPUT=
[[crypto_vpn]]
network:n1 = { ip = 10.1.1.0/24; }
=END=
=WARNING=
Warning: No hub has been defined for crypto:vpn
=END=

############################################################
=TITLE=No spokes defined for crypto
=INPUT=
[[crypto_vpn]]
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
 }
}
=WARNING=
Warning: No spokes have been defined for crypto:vpn
=END=

############################################################
=TITLE=No bind_nat allowed at hub
=INPUT=
[[crypto_vpn]]
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.2.2.0/24; } }

router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:n1 = {
  ip = 10.1.1.1;
  hub = crypto:vpn;
  bind_nat = n1;
  hardware = n1;
 }
}
=ERROR=
Error: Must not use 'bind_nat' at crypto hub interface:asavpn.n1
 Move 'bind_nat' to crypto definition instead
=END=

############################################################
=TITLE=Crypto must not share hardware
=INPUT=
[[crypto_vpn]]
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

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
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n1; }
}
=ERROR=
Error: Crypto interface:asavpn.n1 must not share hardware with other interface:asavpn.n2
=END=

############################################################
=TITLE=Unnumbered crypto interface
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: Crypto hub interface:asavpn.n1 must have IP address
=END=

############################################################
=TITLE=Need authentication rsasig
=INPUT=
[[crypto_vpn]]
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
 host:id:foo@domain.x = { ip = 10.99.1.10; }
}
=SUBST=/rsasig/preshare/
=ERROR=
Error: router:asavpn needs authentication=rsasig in isakmp:aes256SHA
=END=

############################################################
=TITLE=Missing ID hosts at software client
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: Networks behind crypto tunnel to router:asavpn of model 'ASA, VPN' need to have ID hosts:
 - network:other
=END=

############################################################
=TITLE=Mixed ID hosts and non ID hosts in network
=INPUT=
network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:bar = { ip = 10.99.1.11; }
}
=ERROR=
Error: All hosts must have ID in network:clients
=END=

############################################################
=TITLE=Mixed ldap_id and ID hosts
=INPUT=
network:clients = {
 ip = 10.99.1.0/24;
 cert_id = cert1;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:bar = {
  range = 10.99.1.16 - 10.99.1.31;
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
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = { ip = 10.99.1.10; }
}
=ERROR=
Error: network:clients having ID hosts must be connected to router with crypto spoke
=END=


############################################################
=TITLE=Mixed ID hosts and non ID hosts at software client
=INPUT=
[[crypto_vpn]]
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
=END=
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
=END=
=ERROR=
Error: Exactly one network must be located behind unmanaged interface:softclients.clients of crypto router
=END=

############################################################
=TITLE=Invalid radius attributes
=INPUT=
[[crypto_vpn]]
network:n1 = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
  unknown = unknown;
  split-tunnel-policy = whatever;
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
 radius_attributes = {
  invalid;
 }
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
  radius_attributes = { trust-point = ASDM_TrustPoint1; }
 }
}
=END=
=ERROR=
Error: Invalid radius_attribute 'invalid' at network:clients
Error: Must not use radius_attribute 'trust-point' at host:id:foo@domain.x.clients
Error: Unsupported value in radius_attribute of router:asavpn 'split-tunnel-policy = whatever'
Error: Invalid radius_attribute 'unknown' at router:asavpn
=END=

############################################################
=TITLE=Use authentication-server-group only with ldap_id (1)
=INPUT=
[[crypto_vpn]]
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
 radius_attributes = {
  authentication-server-group = LDAP_1;
 }
 host:id:foo@domain.x = {  ip = 10.99.1.10; }
}
=END=
=ERROR=
Error: Attribute 'authentication-server-group' at network:clients must only be used together with attribute 'ldap_id' at host
=END=

############################################################
=TITLE=Use authentication-server-group only with ldap_id (2)
=INPUT=
[[crypto_vpn]]
network:n1 = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
  authentication-server-group = LDAP_1;
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
=END=
=ERROR=
Error: Attribute 'authentication-server-group' at router:asavpn must only be used together with attribute 'ldap_id' at host
=END=

############################################################
=TITLE=Must not use ldap_id at ID host
=INPUT=
network:clients = {
 ip = 10.99.1.0/24;
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
  ldap_id = CN=example1,OU=VPN,DC=example,DC=com;
 }
}
=END=
=ERROR=
Warning: Ignoring attribute 'ldap_id' at host:id:foo@domain.x.clients
Error: network:clients having ID hosts must be connected to router with crypto spoke
=END=

############################################################
=TITLE=cert_id and ldap_append only together with ldap_id
=INPUT=
network:clients = {
 ip = 10.99.1.0/24;
 cert_id = cert99;
 ldap_append = ,OU=VPN,DC=example,DC=com;
}
=END=
=WARNING=
Warning: Ignoring 'ldap_append' at network:clients
Warning: Ignoring 'cert_id' at network:clients
=END=

############################################################
=TITLE=Ignore radius_attributes without ID hosts
=INPUT=
network:clients = {
 ip = 10.99.1.0/24;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
}
=END=
=WARNING=
Warning: Ignoring 'radius_attributes' at network:clients
=END=

############################################################
=TITLE=no_in_acl at crypto interface
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: Don't use attribute 'no_in_acl' together with crypto tunnel at router:asavpn
=END=

############################################################
=TITLE=Duplicate crypto hub
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: Must use 'hub = crypto:vpn' exactly once, not at both
 - interface:asavpn1.dmz
 - interface:asavpn2.dmz
=END=

############################################################
=TITLE=Crypto spoke with secondary IP
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: interface:softclients.trans with attribute 'spoke' must not have secondary interfaces
=END=

############################################################
=TITLE=Missing hub at ASA, VPN
=INPUT=
network:n = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = ASA, VPN;
 interface:n = { ip = 10.1.1.1; hardware = n; }
}
=WARNING=
Warning: Attribute 'hub' needs to be defined at some interface of router:r of model ASA, VPN
=END=

############################################################
=TITLE=Ignoring radius_attributes at non ASA, VPN
=INPUT=
network:n = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = ASA;
 radius_attributes = { banner = Welcome; }
 interface:n = { ip = 10.1.1.1; hardware = n; }
}
=WARNING=
Warning: Ignoring 'radius_attributes' at router:r
=END=

############################################################
=TITLE=Crypto not supported
=INPUT=
[[crypto_sts]]
network:n = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = NX-OS;
 interface:n = { ip = 10.1.1.1; hardware = n; hub = crypto:sts; }
}
=ERROR=
Error: Crypto not supported for router:r of model NX-OS
=END=

############################################################
=TITLE=Virtual interface must not be hub
=INPUT=
[[crypto_vpn]]
router:asavpn1 = {
 model = ASA, VPN;
 managed;
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn;
  virtual = { ip = 192.168.0.1; }
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
=END=
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
  ip = 192.168.0.101;
  hub = crypto:vpn;
  spoke = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
=END=
=ERROR=
Error: interface:asavpn1.dmz with attribute 'spoke' must not have attribute 'hub'
=END=

############################################################
=TITLE=Duplicate crypto spoke
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: Must not define crypto spoke at more than one interface:
 - interface:softclients.intern1
 - interface:softclients.intern2
=END=

############################################################
=TITLE=Duplicate crypto spoke to same device
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: Must not define crypto spoke at more than one interface:
 - interface:softclients.intern1
 - interface:softclients.intern2
=END=

############################################################
=TITLE=ID of host must match ip/range
=INPUT=
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
=END=
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
=END=
=ERROR=
Error: Can't resolve reference to crypto:vpn in 'hub' of interface:asavpn.n1
Error: Can't resolve reference to crypto:vpn in 'spoke' of interface:softclients.n1
=END=

############################################################
# Shared topology

############################################################
=TEMPL=topo
[[crypto_vpn]]
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
 host:id:baz@domain.x = {
  ip = 10.99.1.12;
  radius_attributes = { anyconnect-custom_perapp = SomeName; }
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
                        check-subject-name = ou;#
                        authorization-server-group = LDAP_1;
                        username-from-certificate = CN;
                        authorization-required;
                        group-lock;#
                        password-management_password-expire-in-days = 91; }
 }
 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  radius_attributes = { vpn-idle-timeout = 40;
                        trust-point = ASDM_TrustPoint3;
                        group-lock; }
 }
 host:id:zzz = {
  range = 10.99.2.128 - 10.99.2.191;
  radius_attributes = { split-tunnel-policy = tunnelspecified;
                        check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2;
                        check-subject-name = ou; }
 }
}
=END=

############################################################
=TITLE=VPN ASA with software clients
=TEMPL=input
[[topo]]
network:work1 = { ip = 10.0.1.0/24; host:h1 = { ip = 10.0.1.10; } }
network:work2 = { ip = 10.0.2.0/24; host:h2 = { ip = 10.0.2.10; } }
network:work3 = { ip = 10.0.3.0/24; host:h3 = { ip = 10.0.3.10; } }
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
=OUTPUT=
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
ip local pool pool-@domain.y 10.99.2.64-10.99.2.127 mask 255.255.255.192
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
! vpn-filter-baz@domain.x
access-list vpn-filter-baz@domain.x extended permit ip host 10.99.1.12 any4
access-list vpn-filter-baz@domain.x extended deny ip any4 any4
group-policy VPN-group-baz@domain.x internal
group-policy VPN-group-baz@domain.x attributes
 anyconnect-custom perapp value SomeName
 banner value Willkommen
username baz@domain.x nopassword
username baz@domain.x attributes
 vpn-framed-ip-address 10.99.1.12 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-baz@domain.x
 vpn-group-policy VPN-group-baz@domain.x
--
! split-tunnel-1
access-list split-tunnel-1 standard permit 10.0.2.0 255.255.255.0
access-list split-tunnel-1 standard permit 10.0.3.0 255.255.255.0
access-list split-tunnel-1 standard permit 10.0.4.0 255.255.255.0
--
! vpn-filter-domain.x
access-list vpn-filter-domain.x extended permit ip 10.99.2.0 255.255.255.192 any4
access-list vpn-filter-domain.x extended deny ip any4 any4
ip local pool pool-domain.x 10.99.2.0-10.99.2.63 mask 255.255.255.192
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
ip local pool pool-zzz 10.99.2.128-10.99.2.191 mask 255.255.255.192
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
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-zzz
 vpn-idle-timeout 120
--
! inside_in
access-list inside_in extended permit icmp any4 any4 3
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--
! outside_in
object-group network g0
 network-object host 10.99.1.10
 network-object 10.99.2.64 255.255.255.192
object-group network g1
 network-object 10.99.1.10 255.255.255.254
 network-object host 10.99.1.12
 network-object host 10.99.1.254
 network-object 10.99.2.0 255.255.255.128
 network-object 10.99.2.128 255.255.255.192
object-group network g2
 network-object host 10.99.1.11
 network-object host 10.99.1.12
object-group network g3
 network-object 10.0.1.0 255.255.255.0
 network-object host 10.0.2.10
 network-object 10.0.3.0 255.255.255.0
object-group network g4
 network-object host 10.0.2.10
 network-object host 10.0.3.10
 network-object 10.0.4.0 255.255.255.0
access-list outside_in extended deny tcp object-group g0 host 10.0.1.10 eq 80
access-list outside_in extended permit icmp object-group g1 any4 3
access-list outside_in extended permit tcp object-group g0 object-group g3 eq 80
access-list outside_in extended permit tcp object-group g2 object-group g4 eq 81
access-list outside_in extended permit tcp 10.99.2.0 255.255.255.192 object-group g4 range 81 82
access-list outside_in extended permit tcp 10.99.2.128 255.255.255.192 object-group g4 eq 82
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Missing radius_attribute check-subject-name at host
=INPUT=[[input]]
=SUBST=/check-subject-name = ou;#//
=ERROR=
Error: Missing radius_attribute 'check-subject-name'
 for host:id:domain.x.customers2
=END=

############################################################
=TITLE=Ignoring value of radius_attribute group-lock
=INPUT=[[input]]
=SUBST=/group-lock;#/group-lock = enabled;/
=WARNING=
Warning: Ignoring value at radius_attribute 'group-lock' of host:id:domain.x.customers2 (will be set automatically)
=END=

############################################################
=TITLE=Missing trust-point
=INPUT=[[input]]
=SUBST=/trust-point = ASDM_TrustPoint1;//
=ERROR=
Error: Missing 'trust-point' in radiusAttributes of router:asavpn
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
=END=
=OUTPUT=
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
! vpn-filter-baz@domain.x
access-list vpn-filter-baz@domain.x extended permit ip host 10.99.1.12 any4
access-list vpn-filter-baz@domain.x extended deny ip any4 any4
group-policy VPN-group-baz@domain.x internal
group-policy VPN-group-baz@domain.x attributes
 anyconnect-custom perapp value SomeName
 banner value Willkommen
username baz@domain.x nopassword
username baz@domain.x attributes
 vpn-framed-ip-address 10.99.1.12 255.255.255.0
 service-type remote-access
 vpn-filter value vpn-filter-baz@domain.x
 vpn-group-policy VPN-group-baz@domain.x
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
 network-object host 10.99.1.12
 network-object host 10.99.1.254
 network-object 10.99.2.0 255.255.255.128
 network-object 10.99.2.128 255.255.255.192
object-group network g1
 network-object host 10.99.1.10
 network-object host 10.99.1.12
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
=END=

############################################################
=TITLE=ASA, VPN in CONTEXT
# This line is missing from config:
#  ikev1 user-authentication none
=INPUT=[[topo]]
=SUBST=/ASA, VPN/ASA, VPN, CONTEXT/
=OUTPUT=
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
=END=

############################################################
=TITLE=Missing authentication-server-group at network with ldap_id
=INPUT=
[[crypto_vpn]]
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
}
network:customers1 = {
 ip = 10.99.1.0/24;
 cert_id = cert1;
 radius_attributes = {
  check-subject-name = cn;
 }
 host:example1 = {
  ldap_id = CN=example1,OU=VPN,DC=example,DC=com;
  range = 10.99.1.8 - 10.99.1.15;
  radius_attributes = {
   authentication-server-group = LDAP_1;
  }
 }
 host:example2 = {
  ldap_id = CN=example2,OU=VPN,DC=example,DC=com;
  range = 10.99.1.16 - 10.99.1.31;
 }
 host:example3 = {
  ldap_id = CN=example3,OU=VPN,DC=example,DC=com;
  range = 10.99.1.32 - 10.99.1.47;
 }
}
=END=
=ERROR=
Error: Attribute 'authentication-server-group' must not be used directly at host:example1
Error: Missing attribute 'authentication-server-group' at network:customers1 having host with 'ldap_id'
=END=

############################################################
# Changed topology für tests with ldap_id

############################################################
=TEMPL=topo
[[crypto_vpn]]
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
 cert_id = cert1;
 radius_attributes = {
  check-subject-name = cn;
  authentication-server-group = LDAP_1;
 }
 host:example1 = {
  ldap_id = CN=example1,OU="my" VPN,DC=example,DC=com;
  range = 10.99.1.8 - 10.99.1.15;
 }
}
network:customers2 = {
 ip = 10.99.2.0/24;
 cert_id = cert2;
 ldap_append = ,OU=VPN,DC=example,DC=com;
 radius_attributes = {
  check-subject-name = ou;
  authentication-server-group = LDAP_2;
  group-lock;
 }
 host:example2a = {
  ldap_id = CN=example2a;
  range = 10.99.2.0 - 10.99.2.63;
  radius_attributes = { username-from-certificate = CN;
                        authorization-required; }
 }
 host:example2b = {
  ldap_id = CN=example2b;
  range = 10.99.2.128 - 10.99.2.191;
  radius_attributes = { check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2; }
 }
}
=END=

############################################################
=TITLE=Missing radius_attribute check-subject-name at network
=INPUT=[[topo]]
=SUBST=/check-subject-name = ou;//
=ERROR=
Error: Missing radius_attribute 'check-subject-name'
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
=END=
=OUTPUT=
--asavpn
! vpn-filter-1
access-list vpn-filter-1 extended permit ip 10.99.1.8 255.255.255.248 any4
access-list vpn-filter-1 extended deny ip any4 any4
ip local pool pool-1 10.99.1.8-10.99.1.15 mask 255.255.255.248
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
access-list vpn-filter-2 extended permit ip 10.99.2.0 255.255.255.192 any4
access-list vpn-filter-2 extended deny ip any4 any4
ip local pool pool-2 10.99.2.0-10.99.2.63 mask 255.255.255.192
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
access-list vpn-filter-3 extended permit ip 10.99.2.128 255.255.255.192 any4
access-list vpn-filter-3 extended deny ip any4 any4
ip local pool pool-3 10.99.2.128-10.99.2.191 mask 255.255.255.192
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
=END=
=ERROR=
Error: All ID hosts having domain '@domain.x' must use identical value from 'check-extended-key-usage'
Error: All ID hosts having domain '@domain.y' must use identical value from 'check-extended-key-usage'
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=VPN ASA with internal software clients
=TEMPL=input
[[crypto_vpn]]
network:intern = { ip = 10.1.2.0/24; }
router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip = 10.1.2.1; hardware = e0; }
 interface:trans = { ip = 10.9.9.1; hardware = e1; }
}
network:trans = { ip = 10.9.9.0/24; }
router:gw = {
 model = IOS;
 managed;
 routing = manual;
 interface:trans = { ip = 10.9.9.2; hardware = e0; }
 interface:dmz = { ip = 192.168.0.2; hardware = e1; }
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
=END=
=INPUT=[[input]]
=OUTPUT=
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
=END=
=OPTIONS=--auto_default_route=0

############################################################
=TITLE=Missing route for VPN ASA with internal software clients
=INPUT=
[[input]]
router:gw2 = {
 model = IOS;
 managed;
 routing = manual;
 interface:trans = { ip = 10.9.9.4; hardware = e0; }
 interface:dmz = { ip = 192.168.0.4; hardware = e1; }
}
=END=
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
=INPUT=
[[crypto_vpn]]
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
=SUBST=/type = ipsec:/bind_nat = I;type = ipsec:/
=OUTPUT=
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
access-list outside_in extended permit tcp 10.1.2.0 255.255.255.0 192.168.1.0 255.255.255.0 eq 84
access-list outside_in extended permit tcp host 10.99.1.10 10.1.2.0 255.255.255.0 eq 80
access-list outside_in extended permit tcp host 10.99.1.10 192.168.1.0 255.255.255.0 eq 81
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--
! extern_in
access-list extern_in extended permit tcp 192.168.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 82
access-list extern_in extended permit tcp 192.168.1.0 255.255.255.0 10.99.1.0 255.255.255.0 eq 83
access-list extern_in extended deny ip any4 any4
access-group extern_in in interface extern
=END=

############################################################
=TITLE=Mixed NAT at ASA crypto interface (1)
# Must use NAT ip of internal network, not NAT ip of internet
# at crypto interface for network:n2.
# Ignore hidden NAT tag from internet.
=TEMPL=input
[[crypto_vpn]]
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
=END=
=INPUT=[[input]]
=OUTPUT=
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
=END=

############################################################
=TITLE=Mixed NAT at ASA crypto interface (2)
# No error, because NAT isn't applicable for encrypted packets.
=INPUT=[[input]]
=SUBST=|hidden|ip = 10.2.2.0/24; dynamic|
=OUTPUT=
-- asavpn
! [ Routing ]
route inside 10.1.2.0 255.255.255.0 10.1.1.2
route outside 0.0.0.0 0.0.0.0 192.168.0.1
=END=

############################################################
=TITLE=Mixed NAT at ASA crypto interface (3)
# Must use NAT IP of internal network, not NAT IP of internet
# at crypto interface for network:n2.
# Ignore hidden NAT tag from internal network.
=INPUT=
[[crypto_sts]]
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
=END=
=OUTPUT=
-- asavpn
! [ Routing ]
route outside 1.2.3.4 255.255.255.255 192.168.0.1
=END=

############################################################
=TITLE=Route to internet at internal interface
=INPUT=
[[crypto_sts]]

network:n1 = { ip = 10.1.1.0/24;}
router:asavpn = {
 model = ASA;
 managed;
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
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = { ip = 0.0.0.0/0; has_subnets; }
router:vpn1 = {
 interface:internet = {
  negotiated;
  id = cert@example.com;
  spoke = crypto:sts;
 }
 interface:lan1;
}
network:lan1 = {
 ip = 10.99.1.0/24;
}

router:Firewall = {
 managed;
 model = Linux;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:internet = { ip = 1.1.1.2; hardware = internet; }
}
router:internet = {
 interface:internet;
 interface:n2;
}

network:n2 = { ip = 1.1.2.0/24; }

service:s1 = {
 user = network:lan1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=ERROR=
Error: Two static routes for network:internet
 via interface:asavpn.dmz and interface:asavpn.n1
=END=

############################################################
=TITLE=acl_use_real_ip for crypto tunnel of ASA
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
 bind_nat = intern;
}
network:intern = {
 ip = 10.1.1.0/24;
 nat:intern = { ip = 192.168.2.0/24; }
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
 interface:internet = { ip = 1.1.1.1; spoke = crypto:sts; }
 interface:lan1 = {  ip = 10.99.1.1; }
}
network:lan1 = { ip = 10.99.1.0/24; }
service:test = {
 user = network:lan1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
=END=
=OUTPUT=
-- asavpn
! outside_in
access-list outside_in extended permit tcp 10.99.1.0 255.255.255.0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Directly connected software clients
=TEMPL=input
[[crypto_vpn]]
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
=END=
=INPUT=[[input]]
=OUTPUT=
-- asavpn
! [ Routing ]
route n1 10.99.1.0 255.255.255.0 10.1.1.2
--
! n1_in
access-list n1_in extended permit tcp host 10.99.1.10 10.1.1.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Directly connected software clients; peer without IP
=INPUT=[[input]]
=SUBST=/ip = 10.1.1.2;//
=ERROR=
Error: interface:softclients.n1 used to reach software clients
 must not be directly connected to interface:asavpn.n1
 Connect it to some network behind next hop
=END=

############################################################
=TITLE=Directly connected software clients; without routing
=INPUT=[[input]]
=SUBST=/ip = 10.1.1.2;//
=SUBST=/# routing = manual/ routing = manual/
=OUTPUT=
-- asavpn
! n1_in
access-list n1_in extended permit tcp host 10.99.1.10 10.1.1.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=No secondary optimization for incoming ID host
=INPUT=
[[crypto_vpn]]
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
=END=
=OUTPUT=
-- asavpn
! n2_in
access-list n2_in extended permit ip 10.1.1.0 255.255.255.0 host 10.99.1.10
access-list n2_in extended permit ip host 10.99.1.10 10.1.1.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Empty software clients
=INPUT=
[[crypto_vpn]]
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
=END=
=OUTPUT=
-- asavpn
! outside_in
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Must not use aggregate with software clients
=INPUT=
[[crypto_vpn]]
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
=END=
=WARNING=
Warning: Ignoring any:[network:tunnel:softclients] with software clients in src of rule in service:test1
=END=

############################################################
=TITLE=Duplicate ID-hosts
=INPUT=
[[crypto_vpn]]
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
=END=
=ERROR=
Error: Duplicate ID-host foo@domain.x from network:customers1 and network:customers2 at router:asavpn
Error: Duplicate ID-host foo@domain.x from network:customers3 and network:customers1 at router:asavpn
=END=

############################################################
=TITLE=ASA with two crypto spokes and NAT
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
=END=
=INPUT=[[input]]
=OUTPUT=
--asavpn
no sysopt connection permit-vpn
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec ikev1 transform-set Trans2 esp-aes-192 esp-sha384-hmac
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
=END=

############################################################
=TITLE=ASA with two crypto spokes and NAT (IKEv2)
=INPUT=[[input]]
=SUBST=/ike_version = 1/ike_version = 2/
=OUTPUT=
--asavpn
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption 3des
 protocol esp integrity sha-1
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-192
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
=END=

############################################################
=TITLE=IOS with two crypto spokes and NAT (IKEv2)
=INPUT=[[input]]
=SUBST=/ike_version = 1/ike_version = 2/
=SUBST=/ASA/IOS/
=OUTPUT=
--asavpn
! [ Crypto ]
crypto isakmp policy 1
 authentication pre-share
 encryption 3des
 hash sha
 group 2
crypto isakmp policy 2
 encryption aes 192
 hash sha
 group 15
 lifetime 43200
crypto ipsec transform-set Trans1 esp-3des esp-sha-hmac
crypto ipsec transform-set Trans2 esp-aes 192 esp-sha384-hmac
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
=END=

############################################################
=TITLE=ASA with two dynamic crypto spokes, same ipsec at different tunnels
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
=END=
=INPUT=[[input]]
# Use individual routes to VPN peers, even if all have same next hop.
=OUTPUT=
--asavpn
! [ Routing ]
route outside 10.99.2.0 255.255.255.0 192.168.0.1
route outside 10.99.3.0 255.255.255.0 192.168.0.1
route outside 192.168.22.0 255.255.255.0 192.168.0.1
route outside 0.0.0.0 0.0.0.0 192.168.0.1
--
no sysopt connection permit-vpn
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption aes-256
 protocol esp integrity sha-384
--
! crypto-vpn1@example.com
access-list crypto-vpn1@example.com extended permit ip any4 10.99.2.0 255.255.255.0
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
access-list crypto-vpn2@example.com extended permit ip 10.1.1.0 255.255.255.0 10.99.3.0 255.255.255.0
access-list crypto-vpn2@example.com extended permit ip 10.1.1.0 255.255.255.0 192.168.22.0 255.255.255.0
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
=TITLE=Must not reuse crypto id
=INPUT=[[input]]
=SUBST=/vpn2@/vpn1@/
=ERROR=
Error: Must not reuse 'id = vpn1@example.com' at different crypto spokes of 'router:asavpn':
 - interface:vpn1.tunnel:vpn1
 - interface:vpn2.tunnel:vpn2
=END=

############################################################
=TITLE=Unexpected dynamic crypto spoke
=INPUT=
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
=END=
=OUTPUT=
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
=END=

############################################################
=TITLE=Unexpected dynamic crypto spoke
=INPUT=
[[crypto_sts]]
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
=END=
=ERROR=
Error: router:asavpn can't establish crypto tunnel to interface:vpn1.internet with unknown IP
=END=

############################################################
=TITLE=VPN ASA to EZVPN router with two local networks
=TEMPL=input
[[crypto_vpn]]
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
=END=
=INPUT=[[input]]
=OUTPUT=
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
 permit udp 10.1.1.0 0.0.0.255 10.99.2.0 0.0.1.255 eq 123
 permit tcp 10.1.1.0 0.0.0.255 10.99.2.0 0.0.1.255 established
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
=END=

############################################################
=TITLE=VPN ASA to EZVPN ASA with two local networks
=INPUT=[[input]]
=SUBST=/IOS/ASA/
=OUTPUT=
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
=END=

############################################################
=TITLE=Missing ID at EZVPN router to VPN ASA
=INPUT=[[input]]
=SUBST=/IOS/ASA/
=SUBST=/id =/#id/
=ERROR=
Error: interface:vpn.tunnel:vpn needs attribute 'id', because isakmp:aes256SHA has authentication=rsasig
=END=

############################################################
=TITLE=ASA as managed VPN spoke
=TEMPL=input
[[crypto_sts]]
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
=END=
=INPUT=[[input]]
=OUTPUT=
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
 managed;#
 model = IOS;
 interface:dmz1 = {
  ip = 10.254.254.6;
id = cert@example.com;#
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
 #host:id:h1@example.com = { ip = 10.99.1.130; }
}
=END=

############################################################
=TITLE=Create crypto ACL even if no rule is defined
=INPUT=
[[topo]]
=END=
=OUTPUT=
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
=END=

############################################################
=TITLE=Access VPN interface
=INPUT=
[[topo]]
service:test = {
 user = host:netspoc;
 permit src = user; dst = interface:vpn1.lan1; prt = tcp 22;
}
=END=
=OUTPUT=
--vpn1
ip access-list extended crypto-1.2.3.2
 permit ip 10.10.10.0 0.0.0.255 any
ip access-list extended crypto-filter-1.2.3.2
 permit tcp host 10.1.1.111 host 10.10.10.1 eq 22
 deny ip any any
crypto map crypto-GigabitEthernet0 1 ipsec-isakmp
 set peer 1.2.3.2
 match address crypto-1.2.3.2
 set ip access-group crypto-filter-1.2.3.2 in
 set transform-set Trans1
 set pfs group2
 set security-association lifetime kilobytes 100000
=END=

############################################################
=TITLE=NAT of IPSec traffic at ASA and NAT of VPN network at IOS
=INPUT=
[[topo]]
service:test = {
 user = network:lan1;
 permit src = user; dst = host:netspoc; prt = tcp 80;
 permit src = host:netspoc; dst = user; prt = udp 123;
}
=END=
=OUTPUT=
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
access-list outside_in extended permit 50 host 1.2.3.2 host 10.254.254.6
access-list outside_in extended permit udp host 1.2.3.2 eq 500 host 10.254.254.6 eq 500
access-list outside_in extended permit udp host 1.2.3.2 eq 4500 host 10.254.254.6 eq 4500
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended permit 50 host 10.254.254.6 host 1.2.3.2
access-list inside_in extended permit udp host 10.254.254.6 eq 500 host 1.2.3.2 eq 500
access-list inside_in extended permit udp host 10.254.254.6 eq 4500 host 1.2.3.2 eq 4500
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=detailed_crypto_acl at managed spoke
=INPUT=[[topo]]
=SUBST=/type = ipsec:/detailed_crypto_acl; type = ipsec:/
=ERROR=
Error: Attribute 'detailed_crypto_acl' is not allowed for managed spoke router:vpn1
=END=

############################################################
=TITLE=Don't add hidden network to crypto ACL
=INPUT=
[[topo]]
network:lan2 = {
 ip = 10.99.2.0/24;
 nat:h = { hidden; }
}
=SUBST=/interface:lan1/interface:lan2={ip=10.99.2.1;hardware=lan2;}interface:lan1/
=SUBST=/bind_nat = lan1;/bind_nat = h, lan1; /
=OUTPUT=
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
=END=

############################################################
=TITLE=Multiple zones behind managed crypto router
=INPUT=
[[topo]]
router:r1 = {
 managed;
 model = IOS;
 interface:lan1 = { ip = 10.99.1.2; hardware = lan1; }
 interface:x = { ip = 10.99.1.129; hardware = x; }
}
network:x = { ip = 10.99.1.128/26; subnet_of = network:lan1; }
=ERROR=
Error: Exactly one security zone must be located behind managed interface:vpn1.lan1 of crypto router
=END=

############################################################
=TITLE=ID hosts behind managed crypto router
=INPUT=
[[topo]]
=SUBST=/#host/host/
=ERROR=
Error: network:lan1 having ID hosts can't be checked by router:asavpn
Error: network:lan1 having ID hosts must not be located behind managed router:vpn1
=END=

############################################################
=TITLE=ID hosts behind unmanaged crypto router
=INPUT=
[[topo]]
=SUBST=/#host/host/
=SUBST=/managed;#//
=ERROR=
Error: network:lan1 having ID hosts can't be checked by router:asavpn
=END=

############################################################
=TITLE=Attribute 'id' with wrong authentication
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
=END=

############################################################
=TITLE=Must not use EZVPN as hub
=INPUT=[[topo]]
=SUBST=/IOS/IOS, EZVPN/
=ERROR=
Error: Must not use router:vpn of model 'IOS, EZVPN' as crypto hub
=END=

############################################################
=TITLE=Unmanaged VPN spoke with unknown ID
=TEMPL=input
[[crypto_sts]]
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
=END=
=INPUT=[[input]]
=ERROR=
Error: interface:vpn1.tunnel:vpn1 needs attribute 'id', because isakmp:aes256SHA has authentication=rsasig
=END=

############################################################
=TITLE=Unmanaged VPN spoke with known ID
=INPUT=[[input]]
=SUBST=/#  id/  id/
=OUTPUT=
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
  spoke = crypto:sts;
 }
 interface:lan1;
}
network:lan1 = {
 ip = 10.99.1.0/24;
 host:id:@example.com = { range = 10.99.1.32 - 10.99.1.63; }
}
=ERROR=
Error: network:lan1 having ID hosts can't be checked by router:asavpn
=END=

############################################################
=TITLE=Virtual interface must not be spoke
=INPUT=
[[crypto_sts]]
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
  ip = 1.1.1.2;
  virtual = { ip = 10.1.1.1; }
  spoke = crypto:sts;
 }
 interface:lan1;
}
network:lan1 = {
 ip = 10.99.1.0/24;
}
=ERROR=
Error: interface:vpn1.internet with virtual interface must not use attribute 'spoke'
=END=

############################################################
=TITLE=Silently ignore auto interface at crypto tunnel
=INPUT=
[[crypto_vpn]]
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
=END=
=OUTPUT=
--asavpn
! inside_in
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=END=

############################################################
=TITLE=Sort crypto rules in ACL
=INPUT=
network:n0 = { ip = 10.1.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
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
=END=
=OUTPUT=
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
 permit 50 host 10.1.1.10 host 10.1.1.1
 permit tcp host 10.1.1.10 host 10.1.1.1 eq 22
 deny tcp host 10.1.1.10 10.1.2.0 0.0.0.127 eq 22
 deny 50 host 10.1.1.10 10.1.2.0 0.0.0.127
 permit 50 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.127
 permit 51 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.127
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.127 eq 22
 deny ip any any
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
=END=
=INPUT=[[input]]
=OUTPUT=
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
=END=

############################################################
=TITLE=ASA with unencrypted spoke using AH  (IKEv2)
=INPUT=[[input]]
=SUBST=/ike_version = 1/ike_version = 2/
=OUTPUT=
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
=END=

############################################################
=TITLE=Must not disable crypto
=INPUT=
[[crypto_vpn]]
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
 interface:dmz = { disabled;
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
 interface:internet = { spoke = crypto:vpn;  disabled; }
 interface:customers1;
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
}
service:test1 = {
 user = host:id:foo@domain.x.customers1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
=END=
=WARNING=
Warning: Ignoring attribute 'disabled' at interface:asavpn.dmz of crypto router
Warning: Ignoring attribute 'disabled' at interface:softclients.internet of crypto router
=END=

############################################################
