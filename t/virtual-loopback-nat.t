#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, @out, $head, $compiled);

############################################################
$title = 'Dynamic NAT to multiple virtual loopback interfaces (secondary)';
############################################################

# Soll bei local_optimization loopback interfaces und NAT network als
# identisch erkennen.

$in = <<END;
network:customer = { ip = 10.1.7.0/24; }

router:gw = {
 managed = secondary;
 model = ASA;
 interface:customer = { ip = 10.1.7.1;    hardware = outside;}
 interface:trans    = { ip = 10.1.3.1;   hardware = inside;}
}

network:trans = { ip = 10.1.3.0/24; }

router:b1 = {
 managed;
 model = Linux;
 interface:trans = {
  ip = 10.1.3.3;
  virtual = { ip = 10.1.3.2; type = VRRP; }
  bind_nat = extern;
  hardware = eth0;
 }
 interface:extern = { 
  virtual = { ip = 193.1.1.2; type = VRRP; }
  loopback;
  hardware = eth1;
 }
 interface:server = {
  virtual = { ip = 10.1.2.17; type = VRRP; }
  hardware = eth1;
 }
}

router:b2 = {
 managed;
 model = Linux;
 interface:trans = {
  ip = 10.1.3.4;
  virtual = { ip = 10.1.3.2; type = VRRP; }
  bind_nat = extern;
  hardware = eth0;
 }
 interface:extern = { 
  virtual = { ip = 193.1.1.2; type = VRRP; }
  loopback;
  hardware = eth1;
 }
 interface:server = {
  virtual = { ip = 10.1.2.17; type = VRRP; }
  hardware = eth1;
 }
}

network:server = {
 ip = 10.1.2.16/28;
 nat:extern = { ip = 193.1.1.2/32; dynamic; }
}

protocol:Echo = icmp 8;

service:p1 = {
 user = network:customer;
 permit src = user;
        dst = interface:b1.extern.virtual, interface:b2.extern.virtual;
        prt = protocol:Echo;
}

service:p2 = {
 user = network:customer;
 permit src = user; dst = network:server; prt = protocol:Echo;
}
END

$out = <<END;
! [ ACL ]
access-list outside_in extended permit ip 10.1.7.0 255.255.255.0 host 193.1.1.2
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

$head = (split /\n/, $out)[0];

eq_or_diff(get_block(compile($in), $head), $out, $title);

############################################################
$title = 'Dynamic NAT to multiple virtual loopback interfaces';
############################################################

$in =~ s/managed = secondary/managed/ms;

$out = <<END;
! [ ACL ]
access-list outside_in extended permit icmp 10.1.7.0 255.255.255.0 host 193.1.1.2 8
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

$head = (split /\n/, $out)[0];

eq_or_diff(get_block(compile($in), $head), $out, $title);


############################################################
$title = 'Routing via managed virtual interfaces to loopback';
############################################################

# Loopback interface is reached only via physical interface.
# Don't use virtual IP but physical IP as next hop.

$in = <<END;
network:intern = { ip = 10.1.1.0/24; }

router:asa = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101; 
  hardware = inside;
 }
 interface:dmz = { 
  ip = 192.168.0.101; 
  hardware = outside; 
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern1 = {
 model = IOS,FW;
 managed; #remove
 interface:dmz = { 
  ip = 192.168.0.11;
  virtual = { ip = 192.168.0.1; }
  hardware = Eth0;
 }
 interface:sync = { ip = 172.17.1.11; hardware = Loopback0; loopback; }
 interface:internet = { 
  ip = 1.2.3.11;
  virtual = { ip = 1.2.3.1; }
  hardware = Eth1;
 }
}

router:extern2 = {
 model = IOS,FW;
 managed; #remove
 interface:dmz = { 
  ip = 192.168.0.12; 
  virtual = { ip = 192.168.0.1; }
  hardware = Eth2;
 }
 interface:sync = { ip = 172.17.1.12; hardware = Loopback0; loopback; }
 interface:internet = {
  ip = 1.2.3.12;
  virtual = { ip = 1.2.3.1; }
  hardware = Eth3;
 }
}

network:internet = { ip = 0.0.0.0/0; has_subnets; }

service:test = {
 user = network:intern;
 permit src = user; dst = interface:extern1.sync; prt = tcp 22; 
}
END

@out = ();
$out[0] = <<END;
ip route 10.1.1.0 255.255.255.0 192.168.0.101
END

$out[1] = <<END;
ip access-list extended Eth0_in
 permit tcp 10.1.1.0 0.0.0.255 host 172.17.1.11 eq 22
 deny ip any any
END

$out[2] = <<END;
route outside 172.17.1.11 255.255.255.255 192.168.0.11
END

$out[2] = <<END;
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 host 172.17.1.11 eq 22
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

$compiled = compile($in);
for my $i (0 .. $#out) {
    my $out = $out[$i];
    my $head = (split /\n/, $out)[0];
    eq_or_diff(get_block($compiled, $head), $out, "$title: $i");
}
############################################################
$title = 'Routing via unmanaged virtual interfaces to loopback';
############################################################

# Redundancy interfaces at unmanaged device have no implicit
# pathrestriction.  A zone which contains network 0.0.0.0/0 uses this
# address for optimized routing.

$in =~ s/managed; #remove//msg;

@out = ();
$out[0] = <<END;
! [ Routing ]
route outside 0.0.0.0 0.0.0.0 192.168.0.1
END

$out[1] = <<END;
! [ ACL ]
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 host 172.17.1.11 eq 22
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

$compiled = compile($in);
for my $i (0 .. $#out) {
    my $out = $out[$i];
    my $head = (split /\n/, $out)[0];
    eq_or_diff(get_block($compiled, $head), $out, "$title: $i");
}
############################################################
done_testing;
