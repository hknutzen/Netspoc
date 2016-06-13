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
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
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
$title = 'Simple service, remove all hosts';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
}
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
$title = 'Simple service, remove one host';
############################################################

$in = $topo . <<'END';
service:test = {
    user = host:h11, host:h12;
    permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = host:h11, host:h12;
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
network:n1 = { ip = 10.1.1.0/24;
}
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
    user = host:h10;
    permit src = user; dst = any:[ip=10.0.0.0/8 & network:n3]; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
}
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
    user = host:h10;
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
network:n1 = { ip = 10.1.1.0/24;
}
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
network:n1 = { ip = 10.1.1.0/24;
}
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
network:n1 = { ip = 10.1.1.0/24;
}
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
network:n1 = { ip = 10.1.1.0/24;
}
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
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Mark supernet having identity NAT';
############################################################

$in = <<'END';
any:n1 = { 
 nat:N = { ip = 10.9.9.0/24; dynamic; } 
 link = network:n1;
}
network:n1 = {
 ip = 10.1.1.0/24; 
 nat:N = { identity; } 
}
network:n1_sub = {
 ip = 10.1.1.64/26; 
 subnet_of = network:n1;
}
network:n1_subsub = {
 ip = 10.1.1.96/27;
 subnet_of = network:n1_sub; 
}
router:u = {
 interface:n1;
 interface:n1_sub;
 interface:n1_subsub;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_subsub = { ip = 10.1.1.97; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; } #bind_nat = N; }
}
service:s1 = {
    user = network:n1_subsub;
    permit src = network:n2; dst = user; prt = tcp 80;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Remove interface with multiple IP addresses';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.16/28;}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
}
network:t1 = { ip = 10.9.1.80/28; }
network:t2 = { ip = 10.9.2.80/28; }

router:r2 = {
 interface:t1 = { ip = 10.9.1.83; }
 interface:t2 = { ip = 10.9.2.83, 10.9.2.85; }
 interface:n2;
}

network:n2 = { ip = 10.1.2.0/24; }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.16/28;}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
}
network:t1 = { ip = 10.9.1.80/28; }
router:r2 = {
 interface:t1 = { ip = 10.9.1.83; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Mark interface, if only virtual is used';
############################################################

$in = <<'END';
network:u = { ip = 10.9.9.0/24; }

router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = 10.9.9.1; hardware = F0;}
 interface:a = {ip = 10.1.1.9; hardware = F1;}
}
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}
network:b  = { ip = 10.2.2.0/24; }
pathrestriction:p = interface:r1.a, interface:r1.b.virtual;
service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
}
END

$out = <<'END';
network:u = { ip = 10.9.9.0/24; }
router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = 10.9.9.1; hardware = F0;}
 interface:a = {ip = 10.1.1.9; hardware = F1;}
}
network:a = { ip = 10.1.1.0/24;}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}
network:b  = { ip = 10.2.2.0/24; }
service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
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

$out = <<'END';
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
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

test_run($title, $in, $out);

############################################################
$title = 'Owner at network and host';
############################################################

$in = <<'END';
owner:o1 = { admins = a@example.com; watchers = owner:o2; }
owner:o2 = { admins = b@example.com; watchers = owner:o3; }
owner:o3 = { admins = c@example.com; }
owner:o4 = { admins = d@example.com; watchers = e@example.com; }
network:n1 = { ip = 10.1.1.0/24; owner = o1;
 host:h10 = { ip = 10.1.1.10; owner = o2;}
 host:h11 = { ip = 10.1.1.11;
 # owner =
 owner = o3;
 }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = host:h11;
    permit src = user; dst = network:n2; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h11 = { ip = 10.1.1.11;
 # owner =
 }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = host:h11;
    permit src = user; dst = network:n2; prt = tcp;
}
END


test_run($title, $in, $out);

############################################################
$title = 'Cleanup reroute_permit';
############################################################

$in = <<'END';
network:n1a = { ip = 10.1.1.64/27; subnet_of = network:n1; }
network:n1b = { ip = 10.1.1.96/27; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; reroute_permit = network:n1a, network:n1b; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n1b;
    permit src = user; dst = network:n2; prt = tcp;
}
END

$out = <<'END';
network:n1b = { ip = 10.1.1.96/27; subnet_of = network:n1; }
router:u = {
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; reroute_permit = network:n1b; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n1b;
    permit src = user; dst = network:n2; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Remove router_attributes';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

area:a = {
 inclusive_border = interface:r1.n2;
 router_attributes = {
  general_permit = icmp 0, icmp 3, icmp 11;
 }
 nat:h = { ip = 10.9.9.9/32; dynamic; }
}

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.1.2.1; hardware = inside; bind_nat = h; }
}

service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
area:a = {
 inclusive_border = interface:r1.n2;
 nat:h = { ip = 10.9.9.9/32; dynamic; }
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.1.2.1; hardware = inside; bind_nat = h; }
}
service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Remove router_attributes (2)';
############################################################

$in =~ s/general_permit/#general_permit/;

test_run($title, $in, $out);

############################################################
$title = 'Bridged network';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 managed;
 model = ASA;
 interface:n1/left = { hardware = left; }
 interface:n1/right = { hardware = right; }
 interface:n1 = { ip = 10.1.1.2; hardware = device; }
}
network:n1/right = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1/right = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n1/right;
    permit src = user; dst = network:n2; prt = tcp 80;
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
crypto:vpn1 = {
 type = ipsec:aes256SHA;
}
crypto:vpn2 = {
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
  hub = crypto:vpn1, crypto:vpn2;
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
 interface:internet = { spoke = crypto:vpn1; }
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
 interface:internet = { spoke = crypto:vpn2; }
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
$out = $topo . <<'END'
router:softclients1 = {
 interface:internet = { spoke = crypto:vpn1; }
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
END
. $service;
test_run($title, $in, $out);

############################################################
done_testing;
