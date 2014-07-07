#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
$title = 'Non matching mask of filter_only attribute';
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/8;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
}
END

$out = <<END;
Error: IP and mask don\'t match at line 5 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Missing attribute 'filter_only'";
############################################################

$in =~ s/filter_only/#filter_only/;

$out = <<END;
Error: Missing attribut 'filter_only' for router:d32
Error: network:n1 doesn\'t match attribute 'filter_only' of router:d32
END

test_err($title, $in, $out);

############################################################
$title = 'Local network doesn\'t match filter_only attribute';
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }
network:n2 = { ip = 10.62.2.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.1.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
 interface:n2 = { ip = 10.62.2.33; hardware = vlan2; }
}
END

$out = <<END;
Error: network:n2 doesn\'t match attribute 'filter_only' of router:d32
END

test_err($title, $in, $out);

############################################################
$title = 'Unused filter_only attribute';
############################################################

$in =~ s#10.62.1.0/24#10.62.1.0/24, 10.62.2.0/24, 10.62.3.0/24#;

$out = <<END;
Warning: Useless 10.62.3.0/24 in attribute 'filter_only' of router:d32
END

test_err($title, $in, $out);

############################################################
$title = 'NAT not allowed';
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; nat:n1 = { ip = 10.62.3.0/27; } }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
 interface:n2 = { ip = 10.62.2.1; hardware = vlan2; bind_nat = n1;}
}
network:n2 = { ip = 10.62.2.0/27; }
END

$out = <<END;
Error: Attribute 'bind_nat' is not allowed at interface of router:d32 with 'managed = local'
END

test_err($title, $in, $out);

############################################################
$title = "Cluster must have identical values in attribute 'filter_only'";
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.240.0/22, 10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
 interface:vlan14 = { ip = 10.62.242.1; hardware = outside; }
}

network:vlan14 = { ip = 10.62.242.0/29; }

router:d12 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.62.240.0/21, 10.62.0.0/19,;
 interface:vlan14 = { ip = 10.62.242.2; hardware = vlan14; }
  interface:n2 = { ip = 10.62.2.1; hardware = vlan2; }
}

network:n2 = { ip = 10.62.2.0/27; }
END

$out = <<END;
Error: router:d12 and router:d32 must have identical values in attribute 'filter_only'
END

test_err($title, $in, $out);

############################################################
$title = "Aggregates must match attribute 'filter_only'";
############################################################

# aggregate 0/0 is ignored, because it is available in every zone.

$in = <<END;
any:n1 = { link = network:n1; }
any:n1_10_62 = { ip = 10.62.0.0/16; link = network:n1; }
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
}
END

$out = <<END;
Error: any:n1_10_62 doesn\'t match attribute \'filter_only\' of router:d32
END

test_err($title, $in, $out);

############################################################
$title = 'Reuse object groups for deny rules';
############################################################

$topo = <<END;
network:n1 = { ip = 10.62.1.32/27; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only = 10.62.0.0/21, 10.62.241.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
 interface:trans = { ip = 10.62.241.1; hardware = vlan2; }
}

network:trans = { ip = 10.62.241.0/29; }

router:d31 = {
 model = ASA;
 managed;
 interface:trans = { ip = 10.62.241.2; hardware = inside; }
 interface:extern = { ip = 10.125.3.1; hardware = outside; }
}

network:extern = { ip = 10.125.3.0/24; }
END

$in = $topo;

$out = <<END;
--d32
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list vlan1_in extended deny ip any object-group g0
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
--
access-list vlan2_in extended deny ip object-group g0 object-group g0
access-list vlan2_in extended permit ip any any
access-group vlan2_in in interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = "Supernet to extern";
############################################################

$in = <<END;
$topo
service:Test = {
 user = any:[ip = 10.60.0.0/14 & network:n1, network:trans];
 permit src = user;
        dst = network:extern;
        prt = tcp 80;
}
END

$out = <<END;
--d32
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list vlan1_in extended deny ip any object-group g0
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
END

test_run($title, $in, $out);

############################################################
$title = "Supernet to local";
############################################################

$in = <<END;
$topo
service:Test = { 
 user = any:[ip = 10.60.0.0/14 & network:n1];
 permit src = user;
        dst = network:trans;
        prt = tcp 80;
}
END

$out = <<END;
--d32
object-group network g0
 network-object 10.62.0.0 255.255.248.0
 network-object 10.62.241.0 255.255.255.0
access-list vlan1_in extended permit tcp 10.60.0.0 255.252.0.0 10.62.241.0 255.255.255.248 eq 80
access-list vlan1_in extended deny ip any object-group g0
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
END

test_run($title, $in, $out);

############################################################
$title = "Secondary filter near local filter filters fully";
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/16;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
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

$out = <<END;
--d31
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 10.125.3.0 255.255.255.0 eq 25
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

test_run($title, $in, $out);

############################################################
$title = "Different deny rules";
############################################################

# Reuse $in of previous test.

$out = <<END;
--d32
access-list vlan1_in extended deny ip any 10.62.0.0 255.255.0.0
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
--
access-list trans_in extended deny ip 10.62.0.0 255.255.0.0 10.62.0.0 255.255.0.0
access-list trans_in extended permit ip any any
access-group trans_in in interface trans
END

test_run($title, $in, $out);

############################################################
$title = "Outgoing ACL";
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; no_in_acl;}
 interface:n2 = { ip = 10.62.2.1; hardware = vlan2; }
}
network:n2 = { ip = 10.62.2.0/27; }

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = network:n2; dst = user; prt = tcp 22;
}
END

$out = <<END;
--d32
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
--
access-list vlan2_in extended permit tcp 10.62.2.0 255.255.255.224 10.62.1.32 255.255.255.224 eq 22
access-list vlan2_in extended deny ip any 10.62.0.0 255.255.224.0
access-list vlan2_in extended permit ip any any
access-group vlan2_in in interface vlan2
--
access-list vlan2_out extended permit tcp 10.62.1.32 255.255.255.224 10.62.2.0 255.255.255.224 eq 80
access-list vlan2_out extended deny ip 10.62.0.0 255.255.224.0 10.62.0.0 255.255.224.0
access-list vlan2_out extended permit ip any any
access-group vlan2_out out interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = "Loop, virtual interfaces (1)";
############################################################

# Zone with virtual interfaces is recognized as leaf zone.
# Zone with other loop is handled as intermediate zone with 
# possible connection to extern.

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }
router:d1 = {
 model = IOS;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { 
  ip = 10.62.1.34; 
  virtual = { ip = 10.62.1.33; } 
  hardware = vlan1; 
 }
 interface:n2 = { ip = 10.62.2.1; hardware = vlan2; }
}
router:d2 = {
 model = IOS;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { 
  ip = 10.62.1.35; 
  virtual = { ip = 10.62.1.33; } 
  hardware = vlan21; 
 }
 interface:trans = { ip = 10.62.3.1; hardware = vlan22; }
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

$out = <<END;
--d1
ip access-list extended vlan1_in
 deny ip any host 10.62.2.1
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 eq 80
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 established
 deny ip any 10.62.0.0 0.0.31.255
 permit ip any any
--d1
ip access-list extended vlan2_in
 deny ip any host 10.62.1.33
 deny ip any host 10.62.1.34
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 eq 22
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 established
 deny ip 10.62.0.0 0.0.31.255 10.62.0.0 0.0.31.255
 permit ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Loop, virtual interfaces (2)";
############################################################

$in = <<END;
network:n1 = { ip = 10.2.1.0/27; host:h1 = { ip = 10.2.1.4; }}

router:r1 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n1 = { ip = 10.2.1.1; hardware = vlan1; }
 interface:n3 = { ip = 10.2.3.2; hardware = vlan2; }
 interface:tr = { ip = 10.2.9.1; hardware = vlan4; }
}

network:n2 = { ip = 10.2.2.0/27;}

router:r2 = {
 model = ASA;
 managed = local_secondary;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n2 = { ip = 10.2.2.1; hardware = vlan5; }
 interface:tr = { ip = 10.2.9.2; hardware = vlan6; }
}

network:n3 = { ip = 10.2.3.0/27; host:h3 = { ip = 10.2.3.4; }}

router:r3 = {
 model = ASA;
 managed = local_secondary;
 filter_only =  10.2.0.0/16;
 interface:n3 = { ip = 10.2.3.1; hardware = vlan7; }
 interface:tr = { ip = 10.2.9.3; hardware = vlan8; }
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
        dst = network:extern, host:h1, host:h3;
        prt = tcp 25;
}
END

$out = <<END;
--ex
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.224 10.5.3.0 255.255.255.0 eq 25
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
--r1
object-group network g0
 network-object host 10.2.1.4
 network-object host 10.2.3.4
access-list vlan4_in extended permit tcp 10.2.2.0 255.255.255.224 object-group g0 eq 25
access-list vlan4_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list vlan4_in extended permit ip any any
access-group vlan4_in in interface vlan4
--r3
access-list vlan8_in extended permit ip 10.2.2.0 255.255.255.224 10.2.1.0 255.255.255.224
access-list vlan8_in extended permit tcp 10.2.2.0 255.255.255.224 host 10.2.3.4 eq 25
access-list vlan8_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list vlan8_in extended permit ip any any
access-group vlan8_in in interface vlan8
END

test_run($title, $in, $out);


############################################################
$title = "Multiple local_secondary with unrelated local filter";
############################################################
# Must not assume, that n2 is located beween n1 and n3.

$in = <<END;
network:n1 = { ip = 10.2.1.0/27; host:h1 = { ip = 10.2.1.4; }}

router:r1 = {
 model = ASA;
 managed = local_secondary;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n1 = { ip = 10.2.1.1; hardware = vlan1; }
 interface:tr = { ip = 10.2.9.1; hardware = vlan4; }
}

network:n2 = { ip = 10.2.2.0/27;}

router:r2 = {
 model = ASA;
 managed = local;
 filter_only =  10.2.0.0/16;
 routing = manual;
 interface:n2 = { ip = 10.2.2.1; hardware = vlan5; }
 interface:tr = { ip = 10.2.9.2; hardware = vlan6; }
}

network:tr = { ip = 10.2.9.0/29; }

router:r3 = {
 model = ASA;
 managed = local_secondary;
 filter_only =  10.2.0.0/16;
 interface:tr = { ip = 10.2.9.6; hardware = inside; }
 interface:n3 = { ip = 10.2.8.1; hardware = outside; }
}

network:n3 = { ip = 10.2.8.0/24; }

service:Mail = {
 user = network:n1;
 permit src = user;
        dst = network:n3;
        prt = tcp 25;
}
END

$out = <<END;
--r1
access-list vlan1_in extended permit tcp 10.2.1.0 255.255.255.224 10.2.8.0 255.255.255.0 eq 25
access-list vlan1_in extended deny ip any 10.2.0.0 255.255.0.0
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
END

test_run($title, $in, $out);

############################################################
$title = "Optimize external aggregate rule";
############################################################

$in = <<END;
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

service:Test = {
 user = any:any1;
 permit src = user;
        dst = network:dst;
        prt = tcp 25;
}
END

$out = <<END;
! [ ACL ]
access-list outside_in extended deny ip 10.2.0.0 255.255.0.0 10.2.0.0 255.255.0.0
access-list outside_in extended permit ip any any
access-group outside_in in interface outside
END

Test::More->builder->todo_start(
    "Aggregate rule should be recognized as non local");
test_err($title, $in, $out);
Test::More->builder->todo_end;

############################################################
done_testing;
