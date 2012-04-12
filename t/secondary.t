#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3);

############################################################
$title = 'Secondary optimization to largest safe network';
############################################################

$in = <<END;
network:all_10 = { ip = 10.0.0.0/8; has_subnets; }
network:super = { ip = 10.1.0.0/16;}

router:u = {
 interface:all_10;
 interface:super;
 interface:sub = { ip = 10.1.2.1; }
}

network:sub = { ip = 10.1.2.0/24; subnet_of = network:super; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:sub = { ip = 10.1.2.241; hardware = Ethernet2; }
 interface:trans = { ip = 10.3.1.17; hardware = Ethernet3; }
}

network:trans = { ip = 10.3.1.16/30; }

router:r2 = {
 managed = secondary;
 model = IOS, FW;
 interface:trans = { ip = 10.3.1.18; hardware = Ethernet5; }
 interface:dst = { ip = 10.9.9.1; hardware = Ethernet4; }
 interface:loop = { ip = 10.0.0.1; hardware = Loopback1; loopback; }
}

network:dst = { 
 ip = 10.9.9.0/24; 
 host:server = { ip = 10.9.9.9; }
}

service:test = {
 user = network:sub;
 permit src = user;
        dst = host:server, interface:r2.loop;
        prt = tcp 80;
}
END

$out1 = <<END;
ip access-list extended Ethernet5_in
 permit ip 10.1.0.0 0.0.255.255 host 10.0.0.1
 deny ip any host 10.9.9.1
 permit ip 10.1.0.0 0.0.255.255 10.9.9.0 0.0.0.255
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
done_testing;
