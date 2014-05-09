#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Optimize reverse rules';
############################################################

$in = <<'END';
network:x = { ip = 10.1.1.0/24; 
}
router:r = {
 model = IOS;
 managed;
 interface:x = { ip = 10.1.1.1; hardware = e0; }
 interface:y = { ip = 10.2.2.2; hardware = e1; }
}
network:y = { ip = 10.2.2.0/24; 
 host:y = { ip = 10.2.2.9; } 
}

service:test1 = {
 user = network:x;
 permit src = user; dst = network:y; prt = ip;
}
service:test2 = {
 overlaps = service:test1;
 user = network:x;
 # globally redundant to rule of service:test1
 permit src = user; dst = host:y; prt = ip;
 # locally redundant at router:r,
 # after reverse rule has been generated for rule of service:test1
 permit src = host:y; dst = user; prt = ip;
 # a reverse rule will be generated internally:
 # permit src = user; dst = host:y; prt = ip; stateless;
 # This internal rule is globally redundant to rule of service:test1
}
END

$out = <<END;
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit ip 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255
 deny ip any any
END

test_run($title, $in, $out);

############################################################

done_testing;
