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
 host:h3m = { managed; model = Linux; ip = 10.1.3.33; hardware = eth0; }
}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
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
10.1.3.33	host:h3m
END

test_group($title, $in, 'host:[network:n1, network:n3]', $out, '-unused');

############################################################
$title = 'Automatic hosts';
############################################################

$in = $topo;

$out = <<'END';
10.1.1.10	host:h1
10.1.3.10-10.1.3.15	host:h3a
10.1.3.33	host:h3m
END

test_group($title, $in, 'host:[network:n1, host:h3a, host:h3m]', $out);

############################################################
$title = 'Unexpected interface in automatic host';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = host:[interface:r1.n1];
permit src = user; dst = network:n1; prt = ip;
}
END

$out = <<'END';
Error: Unexpected interface in host:[..] of user of service:s1
END

test_err($title, $in, $out);

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
$title = 'Complement without intersection';
############################################################

$in = $topo . <<'END';
service:s1 = {
 user = ! network:n1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

$out = <<'END';
Error: Complement (!) is only supported as part of intersection in user of service:s1
END

test_err($title, $in, $out);

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
$title = 'Find unused network that is referenced in argument';
############################################################

$in = $topo;

$out = <<'END';
10.1.1.0/24	network:n1
END

test_group($title, $in, 'network:[any:[network:n1]]', $out, '-unused');

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

test_warn($title, $in, $out);

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
$title = 'Recursive definition of group';
############################################################
$in = <<'END';
network:n = { ip = 10.1.1.0/24; }

group:g1 = group:g2;
group:g2 = network:n, group:g1;

service:s1 = {
 user = network:n;
 permit src = user; dst = group:g1; prt = tcp 22;
}

END

$out = <<'END';
Error: Found recursion in definition of group:g2
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate elements in group';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

group:g1 = network:n1, network:n2, network:n2, network:n1, network:n2;

service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n3; prt = tcp 22;
}

END

$out = <<'END';
Warning: Duplicate elements in group:g1:
 network:n2
 network:n1
 network:n2
END

test_warn($title, $in, $out);

############################################################
done_testing;
