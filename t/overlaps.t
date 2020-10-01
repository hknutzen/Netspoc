#!/usr/bin/perl

# Enable printing of diagnostic messages.
$ENV{SHOW_DIAG} = 1;

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
Warning: Unknown 'service:test2' in attribute 'overlaps' of service:test1a
Error: Expected type 'service:' in attribute 'overlaps' of service:test1a
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
$title = 'Inherited overlaps = restrict, enable, ok';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
network:n7 = { ip = 10.1.7.0/24; overlaps = ok; }
network:n8 = { ip = 10.1.8.0/24; overlaps = restrict; }

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
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; }
 interface:n7 = { ip = 10.1.7.1; hardware = n7; }
 interface:n8 = { ip = 10.1.8.1; hardware = n8; }
}

area:all = { anchor = network:n1; overlaps = restrict; }
area:a1234 = { inclusive_border = interface:r2.n5; overlaps = enable; }
area:a1 = { border = interface:r1.n1; overlaps = ok; }
area:a34 = { border = interface:r2.n3; overlaps = ok; }
area:a4 = { border = interface:r3.n4; overlaps = restrict; }
any:a6 = { link = network:n6; overlaps = enable; }
any:a8 = { link = network:n8; overlaps = enable; }

# n1: restrict, enable, ok
# n2: restrict, enable
# n3: restrict, ok
# n4: restrict, ok, restrict
# n5: restrict
# n6: restrict, enable
# n7: restrict, network:ok
# n8: restrict, enable, network:restrict

# ok -> ok: no warning
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp;
}

# enable -> enable: suppressable warning
service:s3 = {
 overlaps = service:s4;
 user = interface:r1.n2;
 permit src = user; dst = network:n6; prt = tcp 80;
}
service:s4 = {
 user = interface:r1.n2;
 permit src = user; dst = network:n6; prt = tcp;
}

# restrict -> restrict: can't suppress warning
service:s5 = {
 overlaps = service:s6;
 user = network:n4;
 permit src = user; dst = network:n5; prt = tcp 80;
}
service:s6 = {
 user = network:n4;
 permit src = user; dst = network:n5; prt = tcp;
}

# ok -> restrict: is like ok -> ok
service:s7 = {
 overlaps = service:s8;
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s8 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp;
}

# enable -> restrict: is like enable -> enable
service:s9 = {
 overlaps = service:s10;
 user = network:n2;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s10 = {
 user = network:n2;
 permit src = user; dst = network:n4; prt = tcp;
}

# ok -> network:ok: no warning
service:s11 = {
 user = network:n3;
 permit src = user; dst = network:n7; prt = tcp 80;
}
service:s12 = {
 user = network:n3;
 permit src = user; dst = network:n7; prt = tcp;
}

# ok -> network:restrict: no warning
service:s13 = {
 overlaps = service:s14;
 user = network:n3;
 permit src = user; dst = network:n8; prt = tcp 80;
}
service:s14 = {
 user = network:n3;
 permit src = user; dst = network:n8; prt = tcp;
}
# network:restrict -> resrict: can't suppress warning
service:s15 = {
 overlaps = service:s16;
 user = network:n8;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s16 = {
 user = network:n8;
 permit src = user; dst = network:n4; prt = tcp;
}

END

$out = <<'END';
Warning: Must not use attribute 'overlaps' at service:s15
Warning: Must not use attribute 'overlaps' at service:s5
Warning: Redundant rules in service:s15 compared to service:s16:
  permit src=network:n8; dst=network:n4; prt=tcp 80; of service:s15
< permit src=network:n8; dst=network:n4; prt=tcp; of service:s16
Warning: Redundant rules in service:s5 compared to service:s6:
  permit src=network:n4; dst=network:n5; prt=tcp 80; of service:s5
< permit src=network:n4; dst=network:n5; prt=tcp; of service:s6
END

test_warn($title, $in, $out);

############################################################

done_testing;
