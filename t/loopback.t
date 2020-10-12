#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Unexpected attribute at loopback interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:l = {
  ip = 10.1.1.2; loopback; no_in_acl; dhcp_server; routing = OSPF; disabled;
 }
}

END

$out =  <<"END";
Error: Attribute 'no_in_acl' not supported for loopback interface:r.l
Error: Attribute 'dhcp_server' not supported for loopback interface:r.l
Error: Attribute 'routing' not supported for loopback interface:r.l
END

test_err($title, $in, $out);

############################################################
$title = 'Unnumbered loopback interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:l = {
  unnumbered; loopback;
 }
}

END

$out =  <<"END";
Error: Attribute 'unnumbered' not supported for loopback interface:r.l
END

test_err($title, $in, $out);

############################################################
$title = 'Secondary IP at loopback interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:l = {
  ip = 10.1.1.2, 10.1.1.3; loopback;
 }
}
END

$out =  <<"END";
Error: Secondary or virtual IP not supported for loopback interface:r.l
END

test_err($title, $in, $out);

############################################################
$title = 'Virtual IP at loopback interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:l = {
  ip = 10.1.1.2; loopback; virtual = { ip = 10.1.1.9; }
 }
}
END

$out =  <<"END";
Error: Secondary or virtual IP not supported for loopback interface:r.l
END

test_err($title, $in, $out);

############################################################
$title = 'Network connected to loopback interface';
############################################################

$in = <<'END';
router:r = {
 interface:l = { ip = 10.1.1.2; loopback; }
}

network:l = { ip = 10.1.1.2/32; }
END

$out =  <<"END";
Error: network:l isn\'t connected to any router
END

test_err($title, $in, $out);

############################################################
$title = 'Network with /32 mask should be loopback';
############################################################

$in = <<'END';
router:r = {
 interface:l = { ip = 10.1.1.2; }
}

network:l = { ip = 10.1.1.2/32; }
END

$out = <<'END';
Warning: interface:r.l has address of its network.
 Remove definition of network:l and
 add attribute 'loopback' at interface definition.
END

test_warn($title, $in, $out);

############################################################
$title = 'Ignore loopback of managed router in automatic group';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:lb = { ip = 10.9.9.9; hardware = lb; loopback; }
}

service:s1 = {
 user = network:[interface:r1.lb];
 permit src = network:n1; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--r1
ip access-list extended n1_in
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore zone of loopback interface at mixed hardware';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:lo = { ip = 10.0.0.1; hardware = n1; loopback; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

service:s1 = {
 user = any:[interface:r1.lo], network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
--r1
ip access-list extended n1_in
 deny ip any host 10.1.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Loopback is subnet';
############################################################

$in = <<'END';
network:n = {
 ip = 10.1.1.0/24;
}

router:r = {
 interface:n = { ip = 10.1.1.1; }
 interface:l = { ip = 10.1.1.2; loopback; subnet_of = network:n; }
 interface:m = { ip = 10.1.1.3; loopback; }
}
END

$out = <<'END';
Warning: interface:r.m is subnet of network:n
 in nat_domain:[network:n].
 If desired, declare attribute 'subnet_of'
END

test_warn($title, $in, $out);

############################################################
$title = 'Dynamic NAT to multiple virtual loopback interfaces (secondary)';
############################################################

# Soll bei local_optimization loopback interfaces und NAT network als
# identisch erkennen.

$in = <<'END';
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

$out = <<'END';
--gw
! outside_in
access-list outside_in extended permit ip 10.1.7.0 255.255.255.0 host 193.1.1.2
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Dynamic NAT to multiple virtual loopback interfaces';
############################################################

$in =~ s/managed = secondary/managed/ms;

$out = <<'END';
--gw
! outside_in
access-list outside_in extended permit icmp 10.1.7.0 255.255.255.0 host 193.1.1.2 8
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = 'Dynamic NAT to loopback interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:extern = { ip = 193.1.1.2/32; dynamic; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = Linux;
 interface:lo = { ip = 193.1.1.2; hardware = lo; loopback; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = extern; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2;}
 interface:n3 = { ip = 10.1.3.1; hardware = n3;}
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
END

$out = <<'END';
--r2
! n2_in
access-list n2_in extended permit tcp host 193.1.1.2 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Illegal NAT to loopback interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:extern = { ip = 193.1.1.2/32; dynamic; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; bind_nat = extern; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:lo = { ip = 193.1.1.2; hardware = lo; loopback; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2;}
 interface:n3 = { ip = 10.1.3.1; hardware = n3;}
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
END

$out = <<'END';
Error: interface:r2.lo and nat:extern of network:n1 have identical IP/mask
 in nat_domain:[network:n2]
END

test_err($title, $in, $out);

############################################################
$title = 'Routing via managed virtual interfaces to loopback';
############################################################

# Loopback interface is reached only via physical interface.
# Don't use virtual IP but physical IP as next hop.

$in = <<'END';
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

$out = <<'END';
--asa
route outside 172.17.1.11 255.255.255.255 192.168.0.11
--
! inside_in
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 host 172.17.1.11 eq 22
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--extern1
ip route 10.1.1.0 255.255.255.0 192.168.0.101
--
ip access-list extended Eth0_in
 permit tcp 10.1.1.0 0.0.0.255 host 172.17.1.11 eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Routing via unmanaged virtual interfaces to loopback';
############################################################

# Redundancy interfaces at unmanaged device have no implicit
# pathrestriction.  A zone which contains network 0.0.0.0/0 uses this
# address for optimized routing.

$in =~ s/managed; #remove//msg;

$out = <<'END';
--asa
! [ Routing ]
route outside 0.0.0.0 0.0.0.0 192.168.0.1
--
! inside_in
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.0 host 172.17.1.11 eq 22
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
done_testing;
