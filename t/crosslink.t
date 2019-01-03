#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

$topo = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed = _1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed = _2;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }
END

############################################################
$title = 'Crosslink primary and full';
############################################################

$in = $topo;
$in =~ s/_1/primary/;
$in =~ s/_2/full/;

$out = <<'END';
-r1
access-list cr_in extended permit ip any4 any4
access-group cr_in in interface cr
END

test_run($title, $in, $out);

############################################################
$title = 'Crosslink standard and secondary';
############################################################

$in = $topo;
$in =~ s/_1/standard/;
$in =~ s/_2/secondary/;

$out = <<'END';
-r1
access-list cr_in extended deny ip any4 any4
access-group cr_in in interface cr
END

test_run($title, $in, $out);

############################################################
$title = 'Crosslink secondary and local';
############################################################

$in = $topo;
$in =~ s/_1/secondary/;
$in =~ s|_2;|local; filter_only =  10.2.0.0/15;|;

$out = <<'END';
Error: Must not use 'managed=local' and 'managed=secondary' together
 at crosslink network:cr
END

test_err($title, $in, $out);

############################################################
$title = 'Crosslink and virtual IP';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; virtual = {ip = 10.3.3.3;} hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Crosslink standard, local, local';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed = standard;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.2.0.0/15;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }

router:r3 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.2.0.0/15;
 interface:cr = { ip = 10.3.3.3; hardware = vlan5; }
 interface:n3 = { ip = 10.2.2.33; hardware = vlan6; }
}

network:n3 = { ip = 10.2.2.32/27; }
END

$out = <<'END';
-r1
access-list cr_in extended deny ip any4 any4
access-group cr_in in interface cr
END

test_run($title, $in, $out);

############################################################
$title = 'Crosslink network must not have hosts';
############################################################
$in = <<'END';
network:cr = {
 ip = 10.3.3.0/29;
 crosslink;
 host:h = { ip = 10.3.3.3; }
}
END

$out = <<'END';
Error: Crosslink network:cr must not have host definitions
END

test_err($title, $in, $out);

############################################################
$title = 'Crosslink network must not have unmanaged interface';
############################################################
$in = <<'END';
network:cr = { ip = 10.3.3.0/29; crosslink; }
router:r = { interface:cr; }
END

$out = <<'END';
Error: Crosslink network:cr must not be connected to unmanged router:r
END

test_err($title, $in, $out);

############################################################
$title = 'different no_in_acl at crosslink routers';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }
END

$out = <<'END';
Error: All interfaces must equally use or not use outgoing ACLs at crosslink network:cr
END

test_err($title, $in, $out);

############################################################
$title = 'no_in_acl outside of crosslink routers';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; no_in_acl; }
}

network:n2 = { ip = 10.2.2.0/27; }
END

$out = <<'END';
Error: All interfaces with attribute 'no_in_acl' at routers connected by
 crosslink network:cr must be border of the same security zone
END

test_err($title, $in, $out);

############################################################
$title = 'no_in_acl at crosslink routers at same zone';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; no_in_acl; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; no_in_acl; }
}
END

$out = <<'END';
-- r1
! n1_in
access-list n1_in extended deny ip any4 host 10.3.3.2
access-list n1_in extended deny ip any4 host 10.1.1.2
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = 'no_in_acl inside of crosslink routers';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; no_in_acl; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; no_in_acl; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
-- r1
! n1_in
access-list n1_in extended deny ip any4 host 10.2.2.1
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.224 10.2.2.0 255.255.255.224 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
--
! n1_out
access-list n1_out extended deny ip any4 any4
access-group n1_out out interface n1
-- r2
ip access-list n2_in
 10 permit tcp 10.2.2.0/27 10.1.1.0/27 established
 20 deny ip any any
--
ip access-list n2_out
 10 permit tcp 10.1.1.0/27 10.2.2.0/27 eq 80
 20 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'crosslink between Linux routers';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = Linux;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = Linux;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
-- r1
:n1_self -
-A INPUT -j n1_self -i n1
:n1_cr -
-A n1_cr -j ACCEPT -s 10.1.1.0/27 -d 10.2.2.0/27 -p tcp --dport 80
-A FORWARD -j n1_cr -i n1 -o cr
--
:cr_self -
-A cr_self -j ACCEPT
-A INPUT -j cr_self -i cr
:cr_n1 -
-A cr_n1 -j ACCEPT
-A FORWARD -j cr_n1 -i cr -o n1
-- r2
:cr_self -
-A cr_self -j ACCEPT
-A INPUT -j cr_self -i cr
:cr_n2 -
-A cr_n2 -j ACCEPT
-A FORWARD -j cr_n2 -i cr -o n2
--
:n2_self -
-A INPUT -j n2_self -i n2
END

test_run($title, $in, $out);

############################################################
$title = 'Must not use crosslink network in rule';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; crosslink; }

router:r = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; crosslink; }

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Warning: Ignoring crosslink network:n1 in src of rule in service:test
Warning: Ignoring crosslink network:n2 in dst of rule in service:test
END

test_warn($title, $in, $out);

############################################################
$title = 'Ignore from automatic group';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = ASA;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; no_in_acl; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }

area:n1-cr = {
 border = interface:r2.cr;
}

service:s1 = {
 user = network:[area:n1-cr];
 permit src = user; dst = network:n2; prt = tcp 80;
}

END

$out = <<'END';
-r2
! n2_out
access-list n2_out extended permit tcp 10.1.1.0 255.255.255.224 10.2.2.0 255.255.255.224 eq 80
access-list n2_out extended deny ip any4 any4
access-group n2_out out interface n2
END

test_run($title, $in, $out);

############################################################
$title = 'Use intermediately in automatic group';
############################################################

$in = <<'END';
area:n1-cr = { border = interface:r2.cr; }
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:cr = { ip = 10.3.3.1; hardware = cr; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = IOS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = cr; }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}

network:n2 = { ip = 10.2.2.0/27; }

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:[network:[area:n1-cr] &! network:n1].[all];
        prt = tcp 22;
}
END

$out = <<'END';
-r1
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.31 host 10.3.3.1 eq 22
 permit tcp 10.1.1.0 0.0.0.31 host 10.3.3.2 eq 22
 deny ip any any
END

test_run($title, $in, $out);

############################################################
done_testing;
