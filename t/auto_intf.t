#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3, $compiled);

############################################################
$title = 'Auto interface of network';
############################################################

my $topo = <<END;
network:a = { ip = 10.0.0.0/24; }
router:r1 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = 10.0.0.1; hardware = e1; }
 interface:b1 = { ip = 10.1.1.1; hardware = e0; }
}
router:r2 =  {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:a = { ip = 10.0.0.2; hardware = f1; }
 interface:b2 = { ip = 10.2.2.1; hardware = f0; }
}
network:b1 = { ip = 10.1.1.0/24; }
network:b2 = { ip = 10.2.2.0/24; }
router:u = { 
 interface:b1 = { ip = 10.1.1.2; }
 interface:b2 = { ip = 10.2.2.2; } 
 interface:b3 = { ip = 10.3.3.1; } 
}
network:b3 = { ip = 10.3.3.0/24; }
END

$in = <<END;
$topo
service:test1 = {
 user = interface:[network:b1].[auto],
        interface:[network:b3].[auto];
 permit src = network:a; dst = user; prt = tcp 22;
}
END

$out1 = <<END;
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.3.3.1 eq 22
 deny ip any any
! [ ACL ]
ip access-list extended f1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 22
 permit tcp 10.0.0.0 0.0.0.255 host 10.3.3.1 eq 22
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Auto interface of router';
############################################################

$in = <<END;
$topo
service:test2 = {
 user = interface:u.[auto];
 permit src = network:a; dst = user; prt = tcp 23;
}
END

$out1 = <<END;
! [ ACL ]
ip access-list extended e1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.2.2.2 eq 23
 deny ip any any
! [ ACL ]
ip access-list extended f1_in
 permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.2 eq 23
 permit tcp 10.0.0.0 0.0.0.255 host 10.2.2.2 eq 23
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
done_testing;
