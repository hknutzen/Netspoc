#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
$title = 'Non matching mask of filter_only attribute';
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/8;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
}
END

$out = <<"END";
Error: IP and mask don\'t match at line 5 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Missing attribute 'filter_only'";
############################################################

$in =~ s/filter_only/#filter_only/;

$out = <<"END";
Error: Missing attribute 'filter_only' for router:d32
END

test_err($title, $in, $out);

############################################################
$title = "Local network doesn't match filter_only attribute";
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.1.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.2.33; hardware = n2; }
}
network:n2 = { ip = 10.62.2.32/27; }
router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.1.0/24;
 interface:n2 = { ip = 10.62.2.34; hardware = n2; }
 interface:n3 = { ip = 10.62.1.1; hardware = n3; }
}
network:n3 = { ip = 10.62.1.0/27; }
END

# Show message only once.
$out = <<"END";
Error: network:n2 doesn\'t match attribute 'filter_only' of router:r1
END

test_err($title, $in, $out);

############################################################
$title = 'Unused filter_only attribute';
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; }
router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.1.0/24, 10.62.2.0/24, 10.62.3.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.2.33; hardware = n2; }
}
network:n2 = { ip = 10.62.2.32/27; }
END

$out = <<'END';
Warning: Useless 10.62.3.0/24 in attribute 'filter_only' of router:r1
END

test_warn($title, $in, $out);

############################################################
$title = 'NAT not allowed';
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; nat:n1 = { ip = 10.62.3.0/27; } }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.2.1; hardware = n2; bind_nat = n1;}
}
network:n2 = { ip = 10.62.2.0/27; }
END

$out = <<'END';
Error: Attribute 'bind_nat' is not allowed at interface of router:d32 with 'managed = local'
END

test_err($title, $in, $out);

############################################################
$title = "Cluster must have identical values in attribute 'filter_only'";
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.240.0/22, 10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n14 = { ip = 10.62.242.1; hardware = outside; }
}

network:n14 = { ip = 10.62.242.0/29; }

router:d12 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.62.240.0/21, 10.62.0.0/19,;
 interface:n14 = { ip = 10.62.242.2; hardware = n14; }
  interface:n2 = { ip = 10.62.2.1; hardware = n2; }
}

network:n2 = { ip = 10.62.2.0/27; }
END

$out = <<'END';
Error: router:d12 and router:d32 must have identical values in attribute 'filter_only'
END

test_err($title, $in, $out);

############################################################
# Shared topology
############################################################

$topo = <<'END';
network:n1 = { ip = 10.62.1.32/27; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only = 10.62.0.0/21, 10.62.241.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:n2 = { ip = 10.62.241.1; hardware = n2; }
}

network:n2 = { ip = 10.62.241.0/29; }

router:d31 = {
 model = ASA;
 managed;
 interface:n2 = { ip = 10.62.241.2; hardware = inside; }
 interface:extern = { ip = 10.125.3.1; hardware = outside; }
}

network:extern = { ip = 10.125.3.0/24; }

router:r1 = {
 interface:extern = { ip = 10.125.3.2; }
 interface:ex_match;
}

network:ex_match = { ip = 10.62.7.0/24; }
END

############################################################
$title = 'Reuse object groups for deny rules';
############################################################

$in = $topo;

$out = <<'END';
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = "External rules are not filtered";
############################################################

$in = $topo . <<'END';
service:Test = {
 user = network:n1;
 permit src = user; dst = network:extern; prt = tcp 80;
}
END

$out = <<'END';
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--d31
! inside_in
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 10.125.3.0 255.255.255.0 eq 80
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = "Mixed matching and non matching external rules";
############################################################

$in = $topo . <<'END';
service:Test = {
 user = network:extern, network:ex_match;
 permit src = network:n1; dst = user; prt = tcp 80;
 permit src = user; dst = network:n1; prt = tcp 81;
}
END

$out = <<'END';
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended permit tcp 10.62.1.32 255.255.255.224 10.62.7.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.62.7.0 255.255.255.0 10.62.1.32 255.255.255.224 eq 81
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
--d31
! inside_in
object-group network g0
 network-object 10.62.7.0 255.255.255.0
 network-object 10.125.3.0 255.255.255.0
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 object-group g0 eq 80
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--
! outside_in
access-list outside_in extended permit tcp object-group g0 10.62.1.32 255.255.255.224 eq 81
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
$title = "Aggregate to extern";
############################################################

$in = $topo . <<'END';
service:Test = {
 user = any:[ip = 10.60.0.0/14 & network:n1, network:n2];
 permit src = user;
        dst = network:extern;
        prt = tcp 80;
}
END

$out = <<'END';
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = "Aggregate to local";
############################################################

$in = $topo . <<'END';
service:Test = {
 user = any:[ip = 10.60.0.0/14 & network:n1];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
END

$out = <<'END';
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended permit tcp 10.60.0.0 255.252.0.0 10.62.241.0 255.255.255.248 eq 80
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = "Ignore non matching local aggregate";
############################################################

$in = $topo . <<'END';
service:Test = {
 user = any:[ip = 10.99.0.0/16 & network:n1];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
END

$out = <<'END';
--d32
! n1_in
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list n1_in extended deny ip any4 object-group g0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out);

############################################################
$title = "External supernet of local network";
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.0/24; subnet_of = network:extern; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/16, 10.9.0.0/16;
 interface:n1 = { ip = 10.62.1.1; hardware = n1; }
 interface:n2 = { ip = 10.9.1.1; hardware = n2; }
}

network:n2 = { ip = 10.9.1.0/29; }

router:d31 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.9.1.2; hardware = inside; }
 interface:extern = { ip = 10.62.0.1; hardware = outside; }
}

network:extern = { ip = 10.62.0.0/17; }

service:Test = {
 user = network:n1;
 permit src = network:extern;
        dst = user;
        prt = tcp 80;
}
END

$out = <<'END';
--d32
! n2_in
access-list n2_in extended permit tcp 10.62.0.0 255.255.128.0 10.62.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = "Subnet of external supernet";
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.0/24; subnet_of = network:extern; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/16, 10.9.0.0/16;
 interface:n1 = { ip = 10.62.1.1; hardware = n1; }
 interface:n2 = { ip = 10.9.1.1; hardware = n2; }
}

network:n2 = { ip = 10.9.1.0/29; }

router:d31 = {
 model = ASA;
 managed = secondary;
 interface:n2 = { ip = 10.9.1.2; hardware = inside; }
 interface:extern = { ip = 10.62.0.1; hardware = outside; }
}

network:extern = { ip = 10.62.0.0/15; }
router:u = {
 interface:extern = { ip = 10.62.0.2; }
 interface:sub;
}
network:sub = { ip = 10.62.2.0/24; subnet_of = network:extern; }

service:Test = {
 user = network:n1;
 permit src = network:sub;
        dst = user;
        prt = tcp 80;
}
END

$out = <<'END';
--d32
! n2_in
access-list n2_in extended permit tcp 10.62.2.0 255.255.255.0 10.62.1.0 255.255.255.0 eq 80
access-list n2_in extended deny ip object-group g0 object-group g0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = "Internal / external network exactly match filter_only";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.4.2.0/24; subnet_of = network:extern; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16, 10.2.0.0/16, 10.4.0.0/16;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.4.2.1; hardware = n2; }
 interface:intern = { ip = 10.2.0.1; hardware = intern; }
}

network:intern = { ip = 10.2.0.0/16; }

router:d31 = {
 model = ASA;
 managed;
 interface:intern = { ip = 10.2.0.2; hardware = inside; }
 interface:extern = { ip = 10.4.0.1; hardware = outside; }
}

network:extern = { ip = 10.4.0.0/16; }

service:Test = {
 user = network:extern, network:intern;
 permit src = user;
        dst = network:n1, network:n2;
        prt = tcp 80;
}
END

$out = <<'END';
--d32
! intern_in
object-group network g1
 network-object 10.2.0.0 255.255.0.0
 network-object 10.4.0.0 255.255.0.0
object-group network g2
 network-object 10.1.1.0 255.255.255.0
 network-object 10.4.2.0 255.255.255.0
access-list intern_in extended permit tcp object-group g1 object-group g2 eq 80
access-list intern_in extended deny ip object-group g0 object-group g0
access-list intern_in extended permit ip any4 any4
access-group intern_in in interface intern
END

test_run($title, $in, $out);

############################################################
$title = "Secondary filter near local filter filters fully";
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/16;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; }
 interface:trans = { ip = 10.62.241.1; hardware = trans; }
}

network:trans = { ip = 10.62.241.0/29; }

router:d31 = {
 model = ASA;
 managed = secondary;
 interface:trans = { ip = 10.62.241.2; hardware = inside; }
 interface:extern = { ip = 10.125.3.1; hardware = outside; }
}

network:extern = { ip = 10.125.3.0/24; }

service:Mail = {
 user = network:n1;
 permit src = user;
        dst = network:extern;
        prt = tcp 25;
}
END

$out = <<'END';
--d31
! inside_in
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 10.125.3.0 255.255.255.0 eq 25
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = "Different deny rules";
############################################################

# Reuse $in of previous test.

$out = <<'END';
--d32
! n1_in
access-list n1_in extended deny ip any4 10.62.0.0 255.255.0.0
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! trans_in
access-list trans_in extended deny ip 10.62.0.0 255.255.0.0 10.62.0.0 255.255.0.0
access-list trans_in extended permit ip any4 any4
access-group trans_in in interface trans
END

test_run($title, $in, $out);

############################################################
$title = "Outgoing ACL";
############################################################

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = n1; no_in_acl;}
 interface:n2 = { ip = 10.62.2.1; hardware = n2; }
}
network:n2 = { ip = 10.62.2.0/27; }

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = network:n2; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--d32
! n1_in
access-list n1_in extended permit ip any4 any4
access-group n1_in in interface n1
--
! n2_in
access-list n2_in extended permit tcp 10.62.2.0 255.255.255.224 10.62.1.32 255.255.255.224 eq 22
access-list n2_in extended deny ip any4 10.62.0.0 255.255.224.0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
--
! n2_out
access-list n2_out extended permit tcp 10.62.1.32 255.255.255.224 10.62.2.0 255.255.255.224 eq 80
access-list n2_out extended deny ip 10.62.0.0 255.255.224.0 10.62.0.0 255.255.224.0
access-list n2_out extended permit ip any4 any4
access-group n2_out out interface n2
END

test_run($title, $in, $out);

############################################################
$title = "Loop, virtual interfaces (1)";
############################################################

# Zone with virtual interfaces is recognized as leaf zone.
# Zone with other loop is handled as intermediate zone with
# possible connection to extern.

$in = <<'END';
network:n1 = { ip = 10.62.1.32/27; }
router:d1 = {
 model = IOS;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = {
  ip = 10.62.1.34;
  virtual = { ip = 10.62.1.33; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.62.2.1; hardware = n2; }
}
router:d2 = {
 model = IOS;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = {
  ip = 10.62.1.35;
  virtual = { ip = 10.62.1.33; }
  hardware = n21;
 }
 interface:trans = { ip = 10.62.3.1; hardware = n22; }
}
network:trans = { ip = 10.62.3.0/27; }
router:loop = {
 model = ASA;
 managed;
 interface:trans = { ip = 10.62.3.2; hardware = inside; }
 interface:n2 = { ip = 10.62.2.2; hardware = outside; }
}
network:n2 = { ip = 10.62.2.0/27; }

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = network:n2; dst = user; prt = tcp 22;
}
END

$out = <<'END';
--d1
ip access-list extended n1_in
 deny ip any host 10.62.2.1
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 eq 80
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 established
 deny ip any 10.62.0.0 0.0.31.255
 permit ip any any
--d1
ip access-list extended n2_in
 deny ip any host 10.62.1.33
 deny ip any host 10.62.1.34
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 eq 22
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 established
 deny ip 10.62.0.0 0.0.31.255 10.62.0.0 0.0.31.255
 permit ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Loop, secondary at border";
############################################################

$in = <<'END';
network:n1 = { ip = 10.2.1.0/27; }

router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n1 = { ip = 10.2.1.1; hardware = n1; }
 interface:tr = { ip = 10.2.9.1; hardware = tr; }
}

network:n2 = { ip = 10.2.2.0/27;}

router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
 interface:tr = { ip = 10.2.9.2; hardware = tr; }
}

network:tr = { ip = 10.2.9.0/29; }

router:ex = {
 model = ASA;
 managed = secondary;
 interface:tr = { ip = 10.2.9.6; hardware = inside; }
 interface:extern = { ip = 10.5.3.1; hardware = outside; }
}

network:extern = { ip = 10.5.3.0/24; }

service:Mail = {
 user = network:n2;
 permit src = user;
        dst = network:extern, network:n1;
        prt = tcp 25;
}
END

$out = <<'END';
--ex
! inside_in
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.224 10.5.3.0 255.255.255.0 eq 25
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--r1
! tr_in
access-list tr_in extended permit tcp 10.2.2.0 255.255.255.224 10.2.1.0 255.255.255.224 eq 25
access-list tr_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list tr_in extended permit ip any4 any4
access-group tr_in in interface tr
--r2
! n2_in
access-list n2_in extended permit tcp 10.2.2.0 255.255.255.224 10.2.1.0 255.255.255.224 eq 25
access-list n2_in extended deny ip any4 10.2.0.0 255.255.0.0
access-list n2_in extended permit ip any4 any4
access-group n2_in in interface n2
END

test_run($title, $in, $out);

############################################################
$title = "Don't check external aggregate rules";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
any:any1 = { link = network:n1; }

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.2.9.6; hardware = inside; }
}

network:n2 = { ip = 10.2.9.0/29; }

router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 interface:n2 = { ip = 10.2.9.1; hardware = outside; }
 interface:dst = { ip = 10.2.1.1; hardware = inside; }
}

network:dst = { ip = 10.2.1.0/27; }

service:t1 = {
 user = any:any1;
 permit src = user;
        dst = network:dst;
        prt = tcp 25;
}

service:t2 = {
 user = any:any1;
 permit src = network:dst;
        dst = user;
        prt = tcp 110;
}
END

$out = <<'END';
--r2
! outside_in
access-list outside_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list outside_in extended permit ip any4 any4
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended deny ip any4 10.2.0.0 255.255.0.0
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = "Check external aggregate covering filter_only network";
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
any:any1 = { link = network:n1; }

router:u = {
  interface:n1;
 interface:t1 =  { ip = 10.2.9.9; }
}

network:t1 = { ip = 10.2.9.8/29; }

router:r1 = {
 model = ASA;
 managed;
 interface:t1 = { ip = 10.2.9.10; hardware = outside; }
 interface:t2 = { ip = 10.2.9.6; hardware = inside; }
}

network:t2 = { ip = 10.2.9.0/29; }

router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 interface:t2 = { ip = 10.2.9.1; hardware = outside; }
 interface:dst = { ip = 10.2.1.1; hardware = inside; }
}

network:dst = { ip = 10.2.1.0/27; }

service:t1 = {
 user = any:any1, any:[network:t2];
 permit src = user;
        dst = network:dst;
        prt = tcp 25;
}

service:t2 = {
 user = any:any1, any:[network:t2];
 permit src = network:dst;
        dst = user;
        prt = tcp 110;
}
END

$out = <<'END';
--r2
! outside_in
access-list outside_in extended permit tcp any4 10.2.1.0 255.255.255.224 eq 25
access-list outside_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list outside_in extended permit ip any4 any4
access-group outside_in in interface outside
--
! inside_in
access-list inside_in extended permit tcp 10.2.1.0 255.255.255.224 any4 eq 110
access-list inside_in extended deny ip any4 10.2.0.0 255.255.0.0
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = "general_permit";
############################################################

# Must not ignore general_permit rules at local filter.
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.1.0.0/16;
 general_permit = icmp;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.1.2.1; hardware = inside; }
}

network:n2 = { ip = 10.1.2.0/24; }
END

$out = <<'END';
--r1
! outside_in
access-list outside_in extended permit icmp any4 any4
access-list outside_in extended deny ip any4 10.1.0.0 255.255.0.0
access-list outside_in extended permit ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
done_testing;
