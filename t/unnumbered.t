#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, @out, $head, $compiled);

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
ip access-list extended eth2_in
 deny ip any host 10.1.7.33
 permit tcp any 10.1.7.32 0.0.0.31 eq 80
 deny ip any any
END

$head = (split /\n/, $out)[0];

eq_or_diff(get_block(compile($in), $head), $out, $title);

############################################################
$title = 'Zone with unnumbered network';
############################################################

$in =~ s/\Q [network:clients] \E/[network:unn]/msx;

eq_or_diff(get_block(compile($in), $head), $out, $title);
############################################################

done_testing;
