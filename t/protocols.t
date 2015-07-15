#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.1; hardware = vlan3; }
 interface:n4 = { ip = 10.1.4.1; hardware = vlan4; }
}
END

############################################################
$title = 'Overlapping TCP ranges and modifier "reversed"';
############################################################

# Split port 21 from range 21-22 must not accidently use 
# protocol:TCP_21_Reply
$in = $topo . <<'END';
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 21 - 22;
 permit src = user; dst = network:n3; prt = tcp 20 - 21;
 permit src = user; dst = network:n4; prt = tcp 21;
}

protocol:TCP_21_Reply = tcp 21, reversed;
END

$out = <<'END';
--asa1
! [ ACL ]
access-list vlan1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 range 21 22
access-list vlan1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 range 20 21
access-list vlan1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.4.0 255.255.255.0 eq 21
access-list vlan1_in extended deny ip any any
access-group vlan1_in in interface vlan1
END

test_run($title, $in, $out);

############################################################
done_testing;
