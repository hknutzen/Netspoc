#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Group;
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; 
 host:h3a = { range = 10.1.3.10-10.1.3.15; } 
 host:h3b = { ip = 10.1.3.26; } 
}

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
$title = 'Find unused hosts';
############################################################

$in = $topo . <<'END';
service:s = {
 user = host:h3a;
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

$out = <<'END';
10.1.1.10	host:h1
10.1.3.26	host:h3b
END

test_group($title, $in, 'host:[network:n1, network:n3]', $out, '-unused');

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
$title = 'Umlaut in group name';
############################################################

$in = $topo . <<'END';
group:Über = network:n1;
END

$out = <<'END';
10.1.1.0/24	network:n1
END

test_group($title, $in, 'group:Über', $out);

############################################################
$title = 'Mark group in empty rule as used';
############################################################
# Don't show warning "unused group:g2 
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = ;
group:g2 = network:n;

service:s1 = {
 user = group:g1;
 permit src = user; dst = group:g2; prt = tcp 22;
}
END

$out = <<'END';
END

test_run($title, $in, $out);

############################################################
$title = 'Mark group in disabled rule as used';
############################################################
# Don't show warning "unused group:g2 
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = ;
group:g2 = network:n;

service:s1 = {
 disabled;
 user = group:g2;
 permit src = user; dst = group:g2; prt = tcp 22;
}
END

$out = <<'END';
Warning: unused group:g1
END

test_warn($title, $in, $out);

############################################################
done_testing;
