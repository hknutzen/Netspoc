#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Zone cluster with unnumbered network';
############################################################

$in = <<END;
network:servers = { ip = 10.1.7.32/27; }

router:r = {
 managed;
 model = IOS, FW;
 interface:servers = { ip = 10.1.7.33; hardware = e0; } 
 interface:clients = { ip = 10.1.2.1; hardware = eth1; }
 interface:unn = { unnumbered; hardware = eth2; }
}

network:unn = { unnumbered; }

router:s = {
 interface:unn;
 interface:clients = { ip = 10.1.2.2; }
}

network:clients = { ip = 10.1.2.0/24; }

pathrestriction:clients = interface:s.clients, interface:r.clients;

service:test = {
 user = any:[network:clients];
 permit src = user; dst = network:servers;
 prt = tcp 80;
}
END

$out = <<END;
--r
ip access-list extended eth2_in
 deny ip any host 10.1.7.33
 permit tcp any 10.1.7.32 0.0.0.31 eq 80
 deny ip any any
END

test_run($title, $in, $out);


$in =~ s/\[network:clients\]/[network:unn]/msx;

test_run($title, $in, $out);

############################################################
$title = 'Auto aggregate in zone cluster with unnumbered';
############################################################

$in = <<END;
router:Z = {
 interface:c = { unnumbered; }
 interface:L = { ip = 10.1.1.4; }
}
router:L = {
 managed;
 model = IOS;
 interface:c = { unnumbered; hardware = G2; }
 interface:L = { ip = 10.1.1.3; hardware = G0; }
}

network:c = {unnumbered;}
network:L = {ip = 10.1.1.0/24;}

pathrestriction:x = interface:Z.L, interface:L.L;

service:Test = {
 user = interface:L.[all];
 permit src = any:[user];
        dst = user;
        prt = icmp 8;
}
END

$out = <<END;
--L
ip access-list extended G2_in
 permit icmp any host 10.1.1.3 8
 deny ip any any
--
ip access-list extended G0_in
 permit icmp any host 10.1.1.3 8
 deny ip any any
END

test_run($title, $in, $out);


$in =~ s|\[user\]|[ip=10.0.0.0/8 & user]|;

$out = <<END;
--L
ip access-list extended G2_in
 permit icmp 10.0.0.0 0.255.255.255 host 10.1.1.3 8
 deny ip any any
--
ip access-list extended G0_in
 permit icmp 10.0.0.0 0.255.255.255 host 10.1.1.3 8
 deny ip any any
END

test_run($title, $in, $out);

############################################################

done_testing;
