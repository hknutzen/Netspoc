#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Group;

my ($title, $in, $out, $topo);

############################################################
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; }
}
END

############################################################
$title = 'Intersection';
############################################################

$in = $topo . <<'END';
group:g1 = network:n1, network:n2;
group:g2 = network:n2, network:n3;
END

$out = <<'END';
10.1.2.0/24	network:n2
END

test_group($title, $in, 'group:g1 & group:g2', $out);

############################################################
$title = 'Intersection with complement';
############################################################

$in = $topo . <<'END';
group:g1 = network:n1, network:n2;
END

$out = <<'END';
10.1.1.0/24	network:n1
END

test_group($title, $in, 'group:g1 &! network:n2', $out);

############################################################
done_testing;
