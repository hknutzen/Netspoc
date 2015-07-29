#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;
use Test_Group;

my ($title, $in, $out, $topo);

############################################################
$title = 'Many nested loops';
############################################################

$in = '';
my $count = 100;

sub two_bytes {
    my ($n) = @_;
    my $low = $n % 256;
    my $high = $n >> 8;
    return ($high, $low);
}

my $hub = '';

for my $i (1 .. $count) {
    my ($b2a, $b3a) = two_bytes($i);
    my $other = $count - $i + 1;

    $in .= <<"END";
network:n${i} = { ip = 10.$b2a.$b3a.0/25; }
router:r${i}a = {
 model = ASA;
 managed;
 interface:n${i}  = { ip = 10.$b2a.$b3a.1; hardware = n; }
 interface:n${i}a = { ip = 10.$b2a.$b3a.130; hardware = a; }
}
network:n${i}a = { ip = 10.$b2a.$b3a.128/30; }
router:r${i}b = {
 model = ASA;
 managed;
 interface:n${i}  = { ip = 10.$b2a.$b3a.2; hardware = n; }
 interface:n${i}b = { ip = 10.$b2a.$b3a.134; hardware = b; }
}
network:n${i}b = { ip = 10.$b2a.$b3a.132/30; }

service:s${i} = {
 user = network:n${i};
 permit src = user; dst = network:n${other}; prt = tcp 80;
}
END

    $hub .= " interface:n${i}a = { ip = 10.$b2a.$b3a.129; hardware = a$i; }\n";
    $hub .= " interface:n${i}b = { ip = 10.$b2a.$b3a.133; hardware = b$i; }\n";
}

$in .= <<"END";
router:r = {
$hub
}
END

$out = <<'END';
--r1a
! [ Routing ]
route a 10.0.100.0 255.255.255.128 10.0.1.129
--
! [ ACL ]
access-list n_in extended permit tcp 10.0.1.0 255.255.255.128 10.0.100.0 255.255.255.128 eq 80
access-list n_in extended deny ip any any
access-group n_in in interface n
--
access-list a_in extended permit tcp 10.0.100.0 255.255.255.128 10.0.1.0 255.255.255.128 eq 80
access-list a_in extended deny ip any any
access-group a_in in interface a
END

test_run($title, $in, $out);

############################################################
done_testing;
