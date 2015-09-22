#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

sub test_run {
    my ($title, $input, $expected) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';

    my $cmd = "$^X $perl_opt -I lib bin/cut-netspoc --quiet $filename";
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    local $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

my ($title, $in, $out, $topo);
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
END

############################################################
$title = 'Simple service';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Named aggregate behind unmanaged';
############################################################

$in = $topo . <<'END';
any:n3 = { link = network:n3; }
service:test = {
    user = network:n1;
    permit src = user; dst = any:n3; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
any:n3 = { link = network:n3; }
service:test = {
    user = network:n1;
    permit src = user; dst = any:n3; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Unnamed aggregate behind unmanaged';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n1;
    permit src = user; dst = any:[ip=10.0.0.0/8 & network:n3]; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
service:test = {
    user = network:n1;
    permit src = user; dst = any:[ip=10.0.0.0/8 & network:n3]; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore area with owner';
############################################################

$in = $topo . <<'END';
area:n2 = { border = interface:asa1.n2;  owner = foo; }
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Area with NAT';
############################################################

$in = $topo . <<'END';
area:n2 = { border = interface:asa1.n2; nat:a2 = { ip = 10.9.9.9/32; dynamic; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
area:n2 = { border = interface:asa1.n2; nat:a2 = { ip = 10.9.9.9/32; dynamic; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Useless aggregate';
############################################################

$in = $topo . <<'END';
any:a2 = { link = network:n2; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Aggregate with NAT and owner';
############################################################

$in = $topo . <<'END';
any:a2 = { 
 link = network:n2; 
 nat:a2 = { ip = 10.9.9.9/32; dynamic; }
 owner = foo;
}
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
any:a2 = { 
 link = network:n2; 
 nat:a2 = { ip = 10.9.9.9/32; dynamic; }
 owner = foo;
}
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Used aggregate with owner';
############################################################

$in = <<'END';
any:n1 = { owner = o; link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
owner:o = { admins = a@example.com; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = any:n1; prt = tcp;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Owner as watcher';
############################################################

$in = <<'END';
owner:o1 = { admins = a@example.com; watchers = owner:o2; }
owner:o2 = { admins = b@example.com; watchers = owner:o3; }
owner:o3 = { admins = c@example.com; }
owner:o4 = { admins = d@example.com; watchers = e@example.com; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

($out = $in) =~ s/owner:o4 .* \n//x;

test_run($title, $in, $out);

############################################################
$title = 'Router with reroute_permit';
############################################################

$in = <<'END';
network:n1a = { ip = 10.1.1.64/26; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; reroute_permit = network:n1a; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Bridged network';
############################################################

$in = <<'END';
network:n1a = { ip = 10.1.1.64/26; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; reroute_permit = network:n1a; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $in);

############################################################
# Shared topology for crypto tests
############################################################

$topo = <<'END';
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
END

my $clients1 = <<'END';
router:softclients1 = {
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
 host:id:bar@domain.x = { 
  ip = 10.99.1.11; 
  radius_attributes = { banner = Willkommen zu Hause; }
 }
}
END

my $clients2 = <<'END';
router:softclients2 = {
 interface:internet = { spoke = crypto:vpn; }
 interface:customers2;
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
  radius_attributes = { vpn-idle-timeout = 40; trust-point = ASDM_TrustPoint3; } 
 }
}
END

############################################################
$title = 'Crypto definitions with router fragments';
############################################################

$in = $topo . $clients1 . $clients2 . <<'END';
service:test1 = {
 user = host:id:foo@domain.x.customers1, host:id:@domain.y.customers2;
 permit src = user; dst = network:intern; prt = tcp 80; 
}
service:test2 = {
 user = host:id:bar@domain.x.customers1, host:id:domain.x.customers2;
 permit src = user; dst = network:intern; prt = tcp 81; 
}
END

test_run($title, $in, $in);

############################################################
$title = 'Take one of multiple crypto networks';
############################################################

my $service = <<'END';
service:test1 = {
 user = host:id:foo@domain.x.customers1;
 permit src = user; dst = network:intern; prt = tcp 80; 
}
END

$in = $topo . $clients1 . $clients2 . $service;
$out = $topo . $clients1 . $service;
test_run($title, $in, $out);

############################################################
done_testing;
