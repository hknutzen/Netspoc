#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, @out, $head, $compiled);

############################################################
$title = 'Follow implicit pathrestriction at unmanaged virtual interface';
############################################################

# Doppelte ACL-Zeile für virtuelle IP vermeiden an
# - Crosslink-Interface zu unmanaged Gerät
# - mit virtueller IP auch an dem unmanged Gerät

$in = <<END;
network:M = { ip = 10.1.0.0/24;}

router:F = {
 managed;
 model = ASA;
 interface:M = {ip = 10.1.0.1; hardware = inside;}
 interface:A = {ip = 10.2.1.129; hardware = o1; routing = manual;}
 interface:B = {ip = 10.2.1.18; hardware = o2; routing = manual;}
}

network:A = {ip = 10.2.1.128/30;}

router:Z = {
 interface:A = {ip = 10.2.1.130;}
 interface:c = {ip = 10.2.6.166;}
 interface:K = {ip = 10.9.32.3; virtual = {ip = 10.9.32.1;}}
}

network:B = {ip = 10.2.1.16/30;} 

router:L = {
 managed;
 model = IOS;
 interface:B = {ip = 10.2.1.17; hardware = Ethernet1; no_in_acl; routing = manual;}
 interface:c  = {ip = 10.2.6.165; hardware = Ethernet2;}
 interface:K = {ip = 10.9.32.2; virtual = {ip = 10.9.32.1;} 
                hardware = Ethernet0;}
}

network:c  = {ip = 10.2.6.164/30;}
network:K = { ip = 10.9.32.0/21;}

pathrestriction:4 = interface:Z.A, interface:L.B;

service:x = {
 user = interface:L.K.virtual, interface:Z.K.virtual;
 permit src = network:M; dst = user; prt = icmp 17;
}
END

$out = <<END;
ip access-list extended Ethernet2_in
 permit icmp 10.1.0.0 0.0.0.255 host 10.9.32.1 17
 deny ip any any
END

$head = (split /\n/, $out)[0];

eq_or_diff(get_block(compile($in), $head), $out, $title);

############################################################
done_testing;
