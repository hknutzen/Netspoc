#!/usr/bin/perl

# Enable printing of diagnostic messages.
use constant SHOW_DIAG => 1;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
# Common topology for multiple tests
############################################################

$topo =  <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:h1 = { ip = 10.1.2.10; }
 host:h2 = { ip = 10.1.2.11; }
}
END

############################################################
$title = 'Warn on duplicate and redundant rule';
############################################################

$in = $topo . <<'END';
service:test1a = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test1b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
Warning: Duplicate rules in service:test1b and service:test1a:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
Warning: Redundant rules in service:test1a compared to service:test2:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1a
< permit src=host:h1; dst=network:n1; prt=tcp; of service:test2
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
--filter
access-list n2_in extended permit tcp host 10.1.2.10 10.1.1.0 255.255.255.0
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
END

test_warn($title, $in, $out);

############################################################
$title = 'Suppressed warning';
############################################################

$in = $topo . <<'END';
service:test1a = {
 overlaps = service:test2;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test1b = {
 # Mark second of duplicate services
 overlaps = service:test1a;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
service:test3a = {
 # Mark first of duplicate services
 overlaps = service:test3b;
 user = host:h1;
 permit src = user; dst = network:n1; prt = udp 123;
}
service:test3b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = udp 123;
}
END

$out = <<'END';
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=udp 123; of service:test3b
END

test_warn($title, $in, $out);

############################################################
$title = 'Reference unknown service';
############################################################

$in = $topo . <<'END';
service:test1a = {
 overlaps = service:test2, serv:abc;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
END

$out = <<"END";
Warning: Unknown service:test2 in attribute 'overlaps' of service:test1a
Error: Unexpected type 'serv' in attribute 'overlaps' of service:test1a
END

test_err($title, $in, $out);

############################################################
$title = 'Suppressed warning by protocol modifier';
############################################################

$in = $topo . <<'END';
protocol:ssh = tcp 22, overlaps;
protocol:tcp = tcp, overlaps;
service:test1a = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:ssh;
}
service:test1b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:ssh;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:tcp;
}
END

$out = <<'END';
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=protocol:ssh; of service:test1b
END

test_warn($title, $in, $out);

############################################################
$title = "Single protocol won't suppress warning";
############################################################

$in = $topo . <<'END';
protocol:ssh = tcp 22, overlaps;
service:test1a = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:ssh;
}
service:test1b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
Warning: Duplicate rules in service:test1b and service:test1a:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
Warning: Redundant rules in service:test1a compared to service:test2:
  permit src=host:h1; dst=network:n1; prt=protocol:ssh; of service:test1a
< permit src=host:h1; dst=network:n1; prt=tcp; of service:test2
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
END

test_warn($title, $in, $out);

############################################################
$title = 'Show useless overlap, if warning was suppressed by modifier';
############################################################

$in = $topo . <<'END';
protocol:Ping_Net = icmp 8, src_net, dst_net, overlaps;

service:s1 = {
 overlaps = service:s2;
 user = network:n1;
 permit src = user;
        dst = host:h1;
        prt = tcp 80, protocol:Ping_Net;
}

service:s2 = {
 user = network:n1;
 permit src = user;
	dst = host:h2;
	prt = tcp 80, protocol:Ping_Net;
}
END

$out = <<'END';
Warning: Useless 'overlaps = service:s2' in service:s1
DIAG: Removed duplicate permit src=network:n1; dst=network:n2; prt=protocol:Ping_Net; of service:s2
END

test_warn($title, $in, $out);

############################################################
$title = 'Multiple larger rules, one suppressed';
############################################################

$in = $topo . <<'END';
service:test = {
 overlaps = service:test2;
 user = host:h1, network:n2;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test
< permit src=network:n2; dst=network:n1; prt=tcp 22; of service:test
END

test_warn($title, $in, $out);

############################################################

done_testing;
