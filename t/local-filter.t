#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3);

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

$out1 = <<END;
Error: IP and mask don\'t match at line 5 of STDIN
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = "Missing attribute 'filter_only'";
############################################################

$in =~ s/filter_only/#filter_only/;

$out1 = <<END;
Error: Missing attribut 'filter_only' for router:d32
Error: network:n1 doesn\'t match attribute 'filter_only' of router:d32
END

eq_or_diff(compile_err($in), $out1, $title);

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

$out1 = <<END;
Error: network:n2 doesn\'t match attribute 'filter_only' of router:d32
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Unused filter_only attribute';
############################################################

$in =~ s#10.62.1.0/24#10.62.1.0/24, 10.62.2.0/24, 10.62.3.0/24#;

$out1 = <<END;
Warning: Useless 10.62.3.0/24 in attribute 'filter_only' of router:d32
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Reuse object groups for deny rules';
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only = 10.62.1.0/24, 10.62.2.0/24;#, 10.62.3.0/24;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
 interface:n2 = { ip = 10.62.2.1; hardware = vlan2; }
}
network:n2 = { ip = 10.62.2.0/27; }
END

$out1 = <<END;
object-group network g0
 network-object 10.62.1.0 255.255.255.0
 network-object 10.62.2.0 255.255.255.0
access-list vlan1_in extended deny ip any object-group g0
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
END

$out2 = <<END;
access-list vlan2_in extended deny ip any object-group g0
access-list vlan2_in extended permit ip any any
access-group vlan2_in in interface vlan2
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = 'NAT not allowed';
############################################################

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; nat:n1 = { ip = 10.62.3.0; } }
router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
 interface:n2 = { ip = 10.62.2.1; hardware = vlan2; bind_nat = n1;}
}
network:n2 = { ip = 10.62.2.0/27; }
END

$out1 = <<END;
Error: Attribute 'bind_nat' is not allowed at interface of router:d32 with 'managed = local'
END

eq_or_diff(compile_err($in), $out1, $title);

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

$out1 = <<END;
Error: router:d12 and router:d32 must have identical values in attribute 'filter_only'
END

eq_or_diff(compile_err($in), $out1, $title);

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

$out1 = <<END;
Error: any:n1_10_62 doesn\'t match attribute \'filter_only\' of router:d32
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = "Crosslink";
############################################################

# Crosslink network needs not to match filter_only.
# No deny of filter_only networks at crosslink interface.

$in = <<END;
network:n1 = { ip = 10.62.1.32/27; }

router:d32 = {
 model = ASA;
 managed = local;
 filter_only =  10.62.0.0/19;
 interface:n1 = { ip = 10.62.1.33; hardware = vlan1; }
 interface:crosslink = { ip = 10.0.0.1; hardware = outside; }
}

network:crosslink = { ip = 10.0.0.0/29; crosslink; }

router:crosslink = {
 model = NX-OS;
 managed = local;
 filter_only =  10.62.0.0/19,;
 interface:crosslink = { ip = 10.0.0.2; hardware = vlan14; }
  interface:n2 = { ip = 10.62.2.1; hardware = vlan2; }
}

network:n2 = { ip = 10.62.2.0/27; }
END

$out1 = <<END;
ip access-list vlan14_in
 10 permit ip any any
END

$out2 = <<END;
access-list outside_in extended permit ip any any
access-group outside_in in interface outside
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

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

$out1 = <<END;
access-list inside_in extended permit tcp 10.62.1.32 255.255.255.224 10.125.3.0 255.255.255.0 eq 25
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = "Different deny rules";
############################################################

# Reuse $in of previous test.

$out1 = <<END;
access-list vlan1_in extended deny ip any 10.62.0.0 255.255.0.0
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
END

$out2 = <<END;
access-list trans_in extended deny ip 10.62.0.0 255.255.0.0 10.62.0.0 255.255.0.0
access-list trans_in extended permit ip any any
access-group trans_in in interface trans
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

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


$out1 = <<END;
access-list vlan1_in extended permit ip any any
access-group vlan1_in in interface vlan1
END

$out2 = <<END;
access-list vlan2_in extended permit tcp 10.62.2.0 255.255.255.224 10.62.1.32 255.255.255.224 eq 22
access-list vlan2_in extended deny ip any 10.62.0.0 255.255.224.0
access-list vlan2_in extended permit ip any any
access-group vlan2_in in interface vlan2
END

$out3 = <<END;
access-list vlan2_out extended permit tcp 10.62.1.32 255.255.255.224 10.62.2.0 255.255.255.224 eq 80
access-list vlan2_out extended deny ip 10.62.0.0 255.255.224.0 10.62.0.0 255.255.224.0
access-list vlan2_out extended permit ip any any
access-group vlan2_out out interface vlan2
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];
$head3 = (split /\n/, $out3)[0];

eq_or_diff(get_block(compile($in), $head1, $head2, $head3), $out1.$out2.$out3, $title);

############################################################
$title = "Loop, virtual interfaces";
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

$out1 = <<END;
ip access-list extended vlan1_in
 deny ip any host 10.62.1.33
 deny ip any host 10.62.1.34
 deny ip any host 10.62.2.1
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 eq 80
 permit tcp 10.62.1.32 0.0.0.31 10.62.2.0 0.0.0.31 established
 deny ip any 10.62.0.0 0.0.31.255
 permit ip any any
END

$out2 = <<END;
ip access-list extended vlan2_in
 deny ip any host 10.62.1.33
 deny ip any host 10.62.1.34
 deny ip any host 10.62.2.1
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 eq 22
 permit tcp 10.62.2.0 0.0.0.31 10.62.1.32 0.0.0.31 established
 deny ip 10.62.0.0 0.0.31.255 10.62.0.0 0.0.31.255
 permit ip any any
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
done_testing;
