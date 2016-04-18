#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$title = 'Reference private object from public service';
############################################################

$in = <<'END';
-- n1.private
network:n1 = {
 ip = 10.1.1.0/24;

 # Detect private status, even if hosts are combined to range internally.
 host:h1 = { ip = 10.1.1.10; }
 host:h2 = { ip = 10.1.1.11; }
}
router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- public
network:n2 = { ip = 10.1.2.0/24; }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h1, host:h2, interface:filter.n1;
 permit src = user; dst = network:n2; prt = tcp 81;
}
END

$out = <<'END';
Error: Rule of public service:s1 must not reference
 - network:n1 of n1.private
Error: Rule of public service:s2 must not reference
 - host:h1 of n1.private
 - host:h2 of n1.private
 - interface:filter.n1 of n1.private
END

test_err($title, $in, $out);

############################################################
$title = 'Must reference private object from private service';
############################################################

$in = <<'END';
-- public
network:n1 = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
-- s1.private
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Error: Rule of s1.private service:s1 must reference at least one object out of s1.private
END

test_err($title, $in, $out);

############################################################
$title = 'Nested private contexts';
############################################################

$in = <<'END';
-- public
network:n1 = { ip = 10.1.1.0/24; }
-- a.private/n1
router:r1 = { interface:n1; }
-- a.private/b.private/n2
router:r2 = { interface:n1; }
END

$out = <<'END';
Error: Nested private context is not supported:
 a.private/b.private
END

test_err($title, $in, $out);

############################################################
$title = 'Interface connected to network in private subdir';
############################################################

$in = <<'END';
-- subdir/a.private
network:n1 = { ip = 10.1.1.0/24; }
-- b
router:r1 = { interface:n1; }
-- c.private
router:r2 = { interface:n1; }
END

$out = <<'END';
Error: public interface:r1.n1 must not be connected to a.private network:n1
Error: c.private interface:r2.n1 must not be connected to a.private network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Public aggregate linked to private network';
############################################################

$in = <<'END';
-- subdir/a.private
network:n1 = { ip = 10.1.1.0/24; }
-- b
any:n1 = { link = network:n1; }
END

$out = <<'END';
Error: public any:n1 must not be linked to a.private network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Mixed private / public zone';
############################################################

$in = <<'END';
-- a.private
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 interface:n1;
 interface:n2;
}
-- b
network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: Networks of any:[network:n1] all must have identical 'private' status
 - network:n1: a.private
 - network:n2: public
END

test_err($title, $in, $out);

############################################################
$title = 'Mixed private / public zone cluster';
############################################################

$in = <<'END';
-- a.private
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 model = ASA;
 managed = routing_only;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- b
network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
Error: Zones connected by router:r must all have identical 'private' status
 - any:[network:n1]: a.private
 - any:[network:n2]: public
END

test_err($title, $in, $out);

############################################################
# Common topology for public / private tests.
############################################################
$topo = <<'END';
-- crypto-def
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
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
}
-- intra
network:intern = { 
 ip = 10.1.1.0/24;
 host:netspoc = { ip = 10.1.1.111; }
}
--hub
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
-- internet
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
-- spoke
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
  ip = 10.99.1.1;
  hardware = Fastethernet8;
 }
}

network:lan1 = { 
 ip = 10.99.1.0/24; 
 nat:lan1 = { ip = 10.10.10.0/24; }
}
END

############################################################
$title = 'Private crypto hub';
############################################################

$in = $topo;
$in =~ s/hub/hub.private/;

$out = <<'END';
Error: Tunnel of public crypto:sts must not reference interface:asavpn.dmz of hub.private
END

test_err($title, $in, $out);

############################################################
$title = 'Private crypto spocke';
############################################################

$in = $topo;
$in =~ s/spoke/spoke.private/;

$out = <<'END';
Error: Tunnel of public crypto:sts must not reference interface:vpn1.dmz1 of spoke.private
END

test_err($title, $in, $out);

############################################################
$title = 'Private crypto definition';
############################################################

$in = $topo;
$in =~ s/crypto-def/crypto-def.private/;

$out = <<'END';
Error: Tunnel interface:vpn1.dmz1 to interface:asavpn.dmz of crypto-def.private crypto:sts must reference at least one object out of crypto-def.private
END

test_err($title, $in, $out);

############################################################
done_testing;
