#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3);

############################################################
$title = 'Redundant port';
############################################################

$in = <<END;
network:A = { ip = 10.3.3.120/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
network:B = { ip = 10.3.3.128/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}

router:ras = {
 managed;
 model = Linux;
 interface:A = { ip = 10.3.3.121; hardware = Fe0; }
 interface:B = { ip = 10.3.3.129; hardware = Fe1; }
 interface:Trans = { ip = 10.1.1.2; bind_nat = C; hardware = Fe2; }
}

network:Trans = { ip = 10.1.1.0/24;}

router:nak = {
 managed;
 model = IOS_FW;
 interface:Trans    = { ip = 10.1.1.1; hardware = eth0; }
 interface:Hosting  = { ip = 10.4.4.1; hardware = br0; }
}

network:Hosting = { ip = 10.4.4.0/24; }

service:A = {
 user = network:A;
 permit src = user; 
	dst = network:Hosting;
	prt = tcp 55;
}

service:B = {
 user = network:B;
 permit src = user;
        dst = network:Hosting;
        prt = tcp 50-60;
}
END

$out1 = <<END;
! [ ACL ]
ip access-list extended eth0_in
 deny ip any host 10.4.4.1
 permit tcp 10.2.2.0 0.0.0.255 10.4.4.0 0.0.0.255 range 50 60
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

TODO: {
    local $TODO = 'Upper ports are missing from %hash, see {is_supernet}';
    eq_or_diff(get_block(compile($in), $head1), $out1, $title);
}

############################################################
done_testing;
