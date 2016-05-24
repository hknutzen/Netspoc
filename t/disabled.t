#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$topo = <<END;
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; disabled; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
END

############################################################
$title = 'Ignore disabled host, network, interface in rule';
############################################################

$in = $topo . <<'END';
service:test = {
    user = host:h1, network:n2, interface:r1.n1, interface:r1.[auto];
 permit src = user; dst = network:n3; prt = tcp 22;
}
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Ignore disabled aggregate in rule';
############################################################

$in = $topo . <<'END';
any:n1 = { link = network:n1; }
service:test = {
 user = any:n1;
 permit src = user; dst = network:n3; prt = tcp 22;
}
END

$out = '';

test_warn($title, $in, $out);

############################################################
$title = 'Only warn on unknown network at disabled interface';
############################################################

$in = <<'END';
#network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; disabled; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
END

$out = <<END;
Warning: Referencing undefined network:n1 from interface:r1.n1
END

test_warn($title, $in, $out);

############################################################
$title = 'Internally disable hosts of unconnected network';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
}

network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }

protocol:Ping_Netz = icmp 8, src_net, dst_net;

service:s = {
 user = network:n1;
 permit src = host:h2; dst = user; prt = protocol:Ping_Netz;
}
END

$out = <<"END";
Error: network:n2 isn\'t connected to any router
END

test_err($title, $in, $out);

############################################################
done_testing;
