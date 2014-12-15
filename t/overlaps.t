#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
$title = 'Warn on redundant rule';
############################################################

$topo =  <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:N = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:N = {
 ip = 10.1.1.0/24; 
 host:h1 = {   ip = 10.1.1.10;  }
}
END

$in = $topo . <<'END';
service:test = {
 user = host:h1;
 permit src = user; dst = network:Test; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:Test; prt = tcp;
}
END

$out = <<'END';
Warning: Redundant rules in service:test compared to service:test2:
  permit src=host:h1; dst=network:Test; prt=tcp 22; of service:test
< permit src=host:h1; dst=network:Test; prt=tcp; of service:test2
END

test_err($title, $in, $out);

############################################################
$title = 'Suppressed warning';
############################################################

$in = $topo . <<'END';
service:test = {
 overlaps = service:test2;
 user = host:h1;
 permit src = user; dst = network:Test; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:Test; prt = tcp;
}
END

$out = <<'END';
--filter
access-list Vlan2_in extended permit tcp host 10.1.1.10 10.9.1.0 255.255.255.0
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Multiple larger rules, one suppressed';
############################################################

$in = $topo . <<'END';
service:test = {
 overlaps = service:test2;
 user = host:h1, network:N;
 permit src = user; dst = network:Test; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:Test; prt = tcp;
}
END

$out = <<'END';
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h1; dst=network:Test; prt=tcp 22; of service:test
< permit src=network:N; dst=network:Test; prt=tcp 22; of service:test
END

test_err($title, $in, $out);

############################################################

done_testing;
