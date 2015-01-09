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
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:cr = { ip = 10.3.3.1; hardware = vlan2; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed = _2;
 interface:cr = { ip = 10.3.3.2; hardware = vlan3; }
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

$out = <<'END';
-r1
access-list vlan2_in extended permit ip any any
access-group vlan2_in in interface vlan2
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
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Crosslink secondary and local_secondary';
############################################################

$in = $topo; 
$in =~ s/_1/secondary/;
$in =~ s|_2;|local_secondary; filter_only =  10.2.0.0/15;|;

$out = <<'END';
-r1
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
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
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:cr = { ip = 10.3.3.1; virtual = {ip = 10.3.3.3;} hardware = vlan2; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed;
 interface:cr = { ip = 10.3.3.2; hardware = vlan3; }
 interface:n2 = { ip = 10.2.2.1; hardware = vlan4; }
}

network:n2 = { ip = 10.2.2.0/27; }
END

$out = '';

test_err($title, $in, $out);

############################################################
$title = 'Crosslink standard, local, local';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/27; }

router:r1 = {
 model = ASA;
 managed = standard;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:cr = { ip = 10.3.3.1; hardware = vlan2; }
}

network:cr = { ip = 10.3.3.0/29; crosslink; }

router:r2 = {
 model = NX-OS;
 managed = local;
 filter_only =  10.2.0.0/15;
 interface:cr = { ip = 10.3.3.2; hardware = vlan3; }
 interface:n2 = { ip = 10.2.2.1; hardware = vlan4; }
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
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
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
Error: Crosslink network must not have host definitions at line 5 of STDIN
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
done_testing;
