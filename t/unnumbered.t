#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Unnumbered network must not have attributes';
############################################################

$in = <<'END';
network:u = {
 unnumbered;
 nat:x = { ip = 10.1.2.0/24; }
 host:h = { ip = 10.1.1.10; }
 has_subnets;
}
END

$out = <<'END';
Error: Unnumbered network:u must not have attribute 'nat:x'
Error: Unnumbered network:u must not have attribute 'has_subnets'
Error: Unnumbered network:u must not have host definition
END

test_err($title, $in, $out);

############################################################
$title = 'Unnumbered network to interface with IP';
############################################################

$in = <<'END';
network:u = {
 unnumbered;
}
router:r1 = {
  interface:u = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: interface:r1.u must not be linked to unnumbered network:u
END

test_err($title, $in, $out);

############################################################
$title = 'Unnumbered interface to network with IP';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
  interface:n1 = { unnumbered; }
}
END

$out = <<'END';
Error: Unnumbered interface:r1.n1 must not be linked to network:n1
END

test_err($title, $in, $out);

############################################################
$title = 'Unnumbered network to more than two interfaces';
############################################################

$in = <<'END';
network:u = { unnumbered; }
router:r1 = { interface:u = { unnumbered; } }
router:r2 = { interface:u = { unnumbered; } }
router:r3 = { interface:u = { unnumbered; } }
END

$out = <<'END';
Error: Unnumbered network:u is connected to more than two interfaces:
 - interface:r1.u
 - interface:r2.u
 - interface:r3.u
END

test_err($title, $in, $out);

############################################################
$title = 'Must not use unnumbered network in rule';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:un = { unnumbered; hardware = un; }
}

network:un = { unnumbered; }

service:test = {
 user = network:n1;
 permit src = user; dst = network:un; prt = tcp 80;
}
END

$out = <<'END';
Warning: Ignoring unnumbered network:un in dst of rule in service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Zone cluster with unnumbered network';
############################################################

$in = <<'END';
network:servers = { ip = 10.1.7.32/27; }

router:r = {
 managed;
 model = IOS, FW;
 interface:servers = { ip = 10.1.7.33; hardware = e0; }
 interface:clients = { ip = 10.1.2.1; hardware = eth1; }
 interface:unn = { unnumbered; hardware = eth2; }
}

network:unn = { unnumbered; }

router:s = {
 interface:unn;
 interface:clients = { ip = 10.1.2.2; }
}

network:clients = { ip = 10.1.2.0/24; }

pathrestriction:clients = interface:s.clients, interface:r.clients;

service:test = {
 user = any:[network:clients];
 permit src = user; dst = network:servers;
 prt = tcp 80;
}
END

$out = <<'END';
--r
ip access-list extended eth2_in
 deny ip any host 10.1.7.33
 permit tcp any 10.1.7.32 0.0.0.31 eq 80
 deny ip any any
END

test_run($title, $in, $out);


$in =~ s/\[network:clients\]/[network:unn]/msx;

test_run($title, $in, $out);

############################################################
$title = 'Auto aggregate in zone cluster with unnumbered';
############################################################

$in = <<'END';
router:Z = {
 interface:c = { unnumbered; }
 interface:L = { ip = 10.1.1.4; }
}
router:L = {
 managed;
 model = IOS;
 interface:c = { unnumbered; hardware = G2; }
 interface:L = { ip = 10.1.1.3; hardware = G0; }
}

network:c = {unnumbered;}
network:L = {ip = 10.1.1.0/24;}

pathrestriction:x = interface:Z.L, interface:L.L;

service:Test = {
 user = interface:L.[all];
 permit src = any:[user];
        dst = user;
        prt = icmp 8;
}
END

$out = <<'END';
--L
ip access-list extended G2_in
 permit icmp any host 10.1.1.3 8
 deny ip any any
--
ip access-list extended G0_in
 permit icmp any host 10.1.1.3 8
 deny ip any any
END

test_run($title, $in, $out);


$in =~ s|\[user\]|[ip=10.0.0.0/8 & user]|;

$out = <<'END';
--L
ip access-list extended G2_in
 permit icmp 10.0.0.0 0.255.255.255 host 10.1.1.3 8
 deny ip any any
--
ip access-list extended G0_in
 permit icmp 10.0.0.0 0.255.255.255 host 10.1.1.3 8
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface expands to short interface';
############################################################

$in = <<'END';
router:u1 = {
 model = IOS;
 interface:dummy;
}

network:dummy = { unnumbered; }

router:u2 = {
 interface:dummy = { unnumbered; }
 interface:n1 = { ip = 10.1.1.2; }
}

network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

service:s1 = {
 user = interface:u1.[auto];
 permit src = network:n2;
        dst = user;
	prt = tcp 22;
}
END

$out = <<'END';
Error: interface:u1.dummy without IP address (from .[auto])
 must not be used in rule of service:s1
END

test_err($title, $in, $out);

############################################################
$title = 'Auto interface expands to unnumbered interface';
############################################################
# and this unnumbered interface is silently ignored.

$in =~ s/interface:dummy;/interface:dummy = { unnumbered; }/;

$out = <<'END';
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'Auto interface to unnumbered with different destination';
############################################################
# Must not internally create rule with empty src-list from auto interface.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2;}
 interface:n3 = {ip = 10.1.3.1; hardware = n3;}
}

network:n3 = {ip = 10.1.3.0/24;}

router:r2 = {
 interface:n3 = {ip = 10.1.3.2;}
 interface:u  = {unnumbered;}
}

network:u = {unnumbered;}

router:r3 = {
 interface:u = {unnumbered;}
}

service:s1  = {
 user = interface:r3.[auto], interface:r2.n3;
 permit src = user;
        dst = network:n1, network:n2;
        prt = tcp 49;
}
END

$out = <<'END';
--r1
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
--
! n3_in
object-group network g0
 network-object 10.1.1.0 255.255.255.0
 network-object 10.1.2.0 255.255.255.0
access-list n3_in extended permit tcp host 10.1.3.2 object-group g0 eq 49
access-list n3_in extended deny ip any4 any4
access-group n3_in in interface n3
END

test_run($title, $in, $out);

############################################################

done_testing;
