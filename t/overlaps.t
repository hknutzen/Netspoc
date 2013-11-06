#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out1, $head1, $out2, $head2, $out3, $head3, $compiled);

############################################################
$title = 'Warn on redundant rule';
############################################################

$topo =  <<END;
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

$in = <<END;
$topo
service:test = {
 user = host:h1;
 permit src = user; dst = network:Test; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:Test; prt = tcp;
}
END

$out1 = <<END;
Warning: Redundant rules in service:test compared to service:test2:
 Files: STDIN STDIN
  permit src=host:h1; dst=network:Test; prt=tcp 22; of service:test
< permit src=host:h1; dst=network:Test; prt=tcp; of service:test2
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Suppressed warning';
############################################################

$in = <<END;
$topo
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

$out1 = <<END;
access-list Vlan2_in extended permit tcp host 10.1.1.10 10.9.1.0 255.255.255.0
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Multiple larger rules, one suppressed';
############################################################

# A warning should be printed for redundant rules of service:test

$in = <<END;
$topo
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

$out1 = <<END;
Warning: Redundant rules in service:test compared to service:test:
 Files: STDIN STDIN
  permit src=host:h1; dst=network:Test; prt=tcp 22; of service:test
< permit src=network:N; dst=network:Test; prt=tcp 22; of service:test
END

TODO: {
    local $TODO = "Redundant rules inside service:test aren't recognizedognized";
    eq_or_diff(compile_err($in), $out1, $title);
}
############################################################

done_testing;
