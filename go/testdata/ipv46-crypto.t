=TEMPL=topo
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

network:intern = { ip = 10.1.1.0/24; ip6 = 1:1::/64; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 vpn_attributes = { trust-point = ASDM_TrustPoint1; }
 interface:intern = {
  ip = 10.1.1.101; ip6 = 1:1::101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.101; ip6 = 192:168::101;
  hub = crypto:vpn;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; ip6 = 192:168::/64; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; ip6 = 192:168::1; }
 interface:internet;
}
network:internet = { ip = 0.0.0.0/0; ip6 = ::/0; has_subnets; }
=END=

############################################################
=TITLE=VPN ASA with dual stack software clients
=INPUT=
[[topo]]
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
 interface:customers2;
}
network:customers1 = {
 ip = 10.99.1.0/24; ip6 = 99:1::/64;
 host:id:foo@domain.x = {
  ip = 10.99.1.10; ip6 = 99:1::10;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}
network:customers2 = {
 ip = 10.99.2.0/24; ip6 = 99:2::/64;
 host:id:domain.x = {
  range = 10.99.2.0 - 10.99.2.63;
  range6 = 99:2::0 - 99:2::3f;
  vpn_attributes = { split-tunnel-policy = tunnelspecified;
                     check-subject-name = ou;
                   }
 }
}
service:test1 = {
 user = host:id:foo@domain.x.customers1,host:id:domain.x.customers2;
 permit src = user; dst = network:intern; prt = tcp 80;
}
=OUTPUT=
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
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
--
! split-tunnel-1
access-list split-tunnel-1 standard permit 10.1.1.0 255.255.255.0
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
tunnel-group VPN-tunnel-domain.x ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-domain.x webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-domain.x 10 VPN-tunnel-domain.x
group-policy VPN-group-domain.x internal
group-policy VPN-group-domain.x attributes
 address-pools value pool-domain.x
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-domain.x
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
crypto ca certificate map ca-map-@domain.x 10
 subject-name attr ea co @domain.x
webvpn
 certificate-group-map ca-map-@domain.x 10 VPN-single
 certificate-group-map ca-map-domain.x 10 VPN-tunnel-domain.x
--
! inside_in
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--
! outside_in
object-group network g0
 network-object host 10.99.1.10
 network-object 10.99.2.0 255.255.255.192
access-list outside_in extended permit tcp object-group g0 10.1.1.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--ipv6/asavpn
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
! split-tunnel-1
access-list split-tunnel-1 standard permit 1:1::/64
--
! vpn-filter-domain.x
access-list vpn-filter-domain.x extended permit ip 99:2::/122 any6
access-list vpn-filter-domain.x extended deny ip any6 any6
ipv6 local pool pool-domain.x 99:2::1/122 63
crypto ca certificate map ca-map-domain.x 10
 subject-name attr ou co domain.x
tunnel-group VPN-tunnel-domain.x type remote-access
tunnel-group VPN-tunnel-domain.x general-attributes
 default-group-policy VPN-group-domain.x
tunnel-group VPN-tunnel-domain.x ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-domain.x webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-domain.x 10 VPN-tunnel-domain.x
group-policy VPN-group-domain.x internal
group-policy VPN-group-domain.x attributes
 ipv6-address-pools value pool-domain.x
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-domain.x
--
! vpn-filter-foo@domain.x
access-list vpn-filter-foo@domain.x extended permit ip host 99:1::10 any6
access-list vpn-filter-foo@domain.x extended deny ip any6 any6
group-policy VPN-group-foo@domain.x internal
group-policy VPN-group-foo@domain.x attributes
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
username foo@domain.x nopassword
username foo@domain.x attributes
 vpn-framed-ipv6-address 99:1::10/64
 service-type remote-access
 vpn-filter value vpn-filter-foo@domain.x
 vpn-group-policy VPN-group-foo@domain.x
--
crypto ca certificate map ca-map-@domain.x 10
 subject-name attr ea co @domain.x
webvpn
 certificate-group-map ca-map-@domain.x 10 VPN-single
 certificate-group-map ca-map-domain.x 10 VPN-tunnel-domain.x
--
! inside_in
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--
! outside_in
object-group network v6g0
 network-object host 99:1::10
 network-object 99:2::/122
access-list outside_in extended permit tcp object-group v6g0 1:1::/64 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Range and auto_ipv6_hosts = readable
=INPUT=
[[topo]]
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers2;
}
network:customers2 = {
 ip = 10.99.2.0/24; ip6 = 99:2::/64;
 auto_ipv6_hosts = readable;
 host:id:domain.x = {
  range = 10.99.2.0 - 10.99.2.63;
  vpn_attributes = { split-tunnel-policy = tunnelspecified;
                     check-subject-name = ou;
                   }
 }
}
service:test1 = {
 user = host:id:domain.x.customers2;
 permit src = user; dst = network:intern; prt = tcp 80;
}
=ERROR=
Error: Range of IPv6 host:id:domain.x.customers2 with ID must expand to exactly one subnet
=END=

############################################################
=TITLE=Range and auto_ipv6_hosts = binary
=INPUT=
[[topo]]
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers2;
}
network:customers2 = {
 ip = 10.99.2.0/24; ip6 = 99:2::/64;
 auto_ipv6_hosts = binary;
 host:id:domain.x = {
  range = 10.99.2.0 - 10.99.2.63;
  vpn_attributes = { split-tunnel-policy = tunnelspecified;
                     check-subject-name = ou;
                   }
 }
}
service:test1 = {
 user = host:id:domain.x.customers2;
 permit src = user; dst = network:intern; prt = tcp 80;
}
=OUTPUT=
--ipv6/asavpn
! split-tunnel-1
access-list split-tunnel-1 standard permit 1:1::/64
--
! vpn-filter-domain.x
access-list vpn-filter-domain.x extended permit ip 99:2::a63:200/122 any6
access-list vpn-filter-domain.x extended deny ip any6 any6
ipv6 local pool pool-domain.x 99:2::a63:201/122 63
crypto ca certificate map ca-map-domain.x 10
 subject-name attr ou co domain.x
tunnel-group VPN-tunnel-domain.x type remote-access
tunnel-group VPN-tunnel-domain.x general-attributes
 default-group-policy VPN-group-domain.x
tunnel-group VPN-tunnel-domain.x ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-domain.x webvpn-attributes
 authentication certificate
tunnel-group-map ca-map-domain.x 10 VPN-tunnel-domain.x
group-policy VPN-group-domain.x internal
group-policy VPN-group-domain.x attributes
 ipv6-address-pools value pool-domain.x
 split-tunnel-network-list value split-tunnel-1
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter-domain.x
--
! outside_in
access-list outside_in extended permit tcp 99:2::a63:200/122 1:1::/64 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
=TITLE=Missing IPv6 crypto hub
=INPUT=
[[topo]]
router:softclients = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24; ip6 = 99:1::/64;
 host:id:foo@domain.x = {
  ip = 10.99.1.10; ip6 = 99:1::10;
  vpn_attributes = { split-tunnel-policy = tunnelspecified; }
 }
}
=SUBST=/ip6 = 192:168::101;//
=ERROR=
Warning: Attribute 'hub' needs to be defined at some interface of IPv6 router:asavpn of model ASA, VPN
Error: IPv6 topology has unconnected parts:
 - any:[network:intern]
 - any:[network:dmz]
 Use partition attribute, if intended.
=END=

############################################################
=TITLE=Duplicate crypto hub at dual stack routers
=INPUT=
[[topo]]
router:asa2 = {
 model = ASA, VPN;
 managed;
 vpn_attributes = { trust-point = ASDM_TrustPoint1; }
 interface:intern = {
  ip = 10.1.1.102; ip6 = 1:1::102;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.102; ip6 = 192:168::102;
  hub = crypto:vpn;
  hardware = outside;
 }
}
=ERROR=
Error: Must use 'hub = crypto:vpn' exactly once, not at both
 - interface:asavpn.dmz
 - interface:asa2.dmz
=END=
