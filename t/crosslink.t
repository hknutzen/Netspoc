#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out1, $head1, $out2, $head2, $out3, $head3);

$topo = <<END;
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed = _1;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:cr = { ip = 10.0.0.1; hardware = vlan2; }
}

network:cr = { ip = 10.0.0.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed = _2;
 interface:cr = { ip = 10.0.0.2; hardware = vlan3; }
 interface:n2 = { ip = 10.2.2.1; hardware = vlan4; }
}

network:n2 = { ip = 10.2.2.0/27; }
END

############################################################
$title = 'Crosslink primary and full';
############################################################

$in = $topo; 
$in =~ s/_1/primary/;
$in =~ s/_2/full/;

$out1 = <<END;
access-list vlan2_in extended permit ip any any
access-group vlan2_in in interface vlan2
END

$out2 = <<END;
ip access-list vlan3_in
 10 permit ip any any
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = 'Crosslink standard and secondary';
############################################################

$in = $topo; 
$in =~ s/_1/standard/;
$in =~ s/_2/secondary/;

$out1 = <<END;
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

$out2 = <<END;
ip access-list vlan3_in
 10 permit ip any any
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = 'Crosslink secondary and local_secondary';
############################################################

$in = $topo; 
$in =~ s/_1/secondary/;
$in =~ s|_2;|local_secondary; filter_only =  10.2.0.0/19;|;

$out1 = <<END;
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

$out2 = <<END;
ip access-list vlan3_in
 10 permit ip any any
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = 'Crosslink secondary and local';
############################################################

$in = $topo; 
$in =~ s/_1/secondary/;
$in =~ s|_2;|local; filter_only =  10.2.0.0/19;|;

$out1 = <<END;
Error: Must not use 'managed=local' and 'managed=secondary' together
 at crosslink network:cr
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Crosslink standard, local, local';
############################################################

$in = <<END;
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed = standard;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:cr = { ip = 10.0.0.1; hardware = vlan2; }
}

network:cr = { ip = 10.0.0.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.2.0.0/19,;
 interface:cr = { ip = 10.0.0.2; hardware = vlan3; }
 interface:n2 = { ip = 10.2.2.1; hardware = vlan4; }
}

network:n2 = { ip = 10.2.2.0/27; }

router:r3 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.2.0.0/19,;
 interface:cr = { ip = 10.0.0.3; hardware = vlan5; }
 interface:n3 = { ip = 10.2.2.33; hardware = vlan6; }
}

network:n3 = { ip = 10.2.2.32/27; }
END

$out1 = <<END;
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

$out2 = <<END;
ip access-list vlan3_in
 10 permit ip any any
END

$out3 = <<END;
ip access-list vlan5_in
 10 permit ip any any
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];
$head3 = (split /\n/, $out3)[0];

eq_or_diff(get_block(compile($in), $head1, $head2, $head3), $out1.$out2.$out3, $title);

############################################################
done_testing;
