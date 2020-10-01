#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = "Owner at unmanaged router";
############################################################

$in = <<'END';
owner:o = { admins = a@example.com; }
router:r = {
 owner = o;
 interface:n1 = { ip = 10.1.1.1; }
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Warning: Ignoring attribute 'owner' at unmanaged router:r
Warning: Unused owner:o
END

test_warn($title, $in, $out);

############################################################
$title = "Crypto hub at unmanaged router";
############################################################

$in = <<'END';
ipsec:i = {
 key_exchange = isakmp:i;
 lifetime = 600 sec;
}

isakmp:i = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}

crypto:c = {
 type = ipsec:i;
}
router:r = {
 interface:n1 = { ip = 10.1.1.1; hub = crypto:c; }
}
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Unmanaged interface:r.n1 must not use attribute 'hub'
END

test_err($title, $in, $out);

############################################################
$title = 'Unmanaged bridge interfaces';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }

router:bridge = {
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: network:n1/right and network:n1/left must be connected by bridge
Error: network:n1/right and network:n1/left have identical IP/mask in any:[network:n1/left]
END

test_err($title, $in, $out);

############################################################
$title = "Unmanaged interfaces inside area";
############################################################

# Prevent duplicate interfaces in complicated unmanaged loop.

$in = <<'END';
network:C1 = { ip = 10.1.0.0/21;}
network:C2 = { ip = 10.2.0.0/21;}
network:C3 = { ip = 10.3.0.0/21;}
network:cross = {ip = 10.9.5.0/30;}

router:u1 = {
 interface:C1 = {ip = 10.1.0.3;   virtual = {ip = 10.1.0.1; }}
 interface:C2 = {ip = 10.2.0.3; virtual = {ip = 10.2.0.1; }}
 interface:C3 = {ip = 10.3.0.3; virtual = {ip = 10.3.0.1; }}
 interface:cross = {ip = 10.9.5.2;}
 interface:u1n = {ip = 10.241.210.98;}
}
router:u2 = {
 interface:C2   = {ip = 10.2.0.2; virtual = {ip = 10.2.0.1;} }
 interface:cross = {ip = 10.9.5.1; }
 interface:u2n = {ip = 10.241.114.25; }
}
router:u3 = {
 interface:C1 = {ip = 10.1.0.2; virtual = {ip = 10.1.0.1; } }
 interface:C3 = {ip = 10.3.0.2; virtual = {ip = 10.3.0.1; } }
 interface:u3n = {ip = 10.241.114.17; }
}

network:u1n = {ip = 10.241.210.96/30;}
network:u2n = {ip = 10.241.114.24/30;}
network:u3n = {ip = 10.241.114.16/30;}

router:b1 = {
 interface:u2n = {ip = 10.241.114.26;}
 interface:u3n = {ip = 10.241.114.18;}
 interface:b = {ip = 10.9.16.117;}
}
router:b2 = {
 interface:u1n = {ip = 10.241.210.97;}
 interface:b = {ip = 10.9.16.118;}
}
network:b = {ip = 10.9.16.112/29; }
router:FW = {
 managed;
 routing = manual;
 model = ASA;
 interface:b = {ip = 10.9.16.116; hardware = outside;}
 interface:D = {ip = 10.1.11.1; hardware = inside;}
}
network:D = { ip = 10.1.11.0/24;}

area:g1 = { border = interface:FW.b;}

service:test = {
 user = interface:[area:g1].[all];
 permit src = user; dst = network:D; prt = tcp 80;
}
END

$out = <<'END';
--FW
object-group network g0
 network-object host 10.1.0.1
 network-object 10.1.0.2 255.255.255.254
 network-object host 10.2.0.1
 network-object 10.2.0.2 255.255.255.254
 network-object host 10.3.0.1
 network-object 10.3.0.2 255.255.255.254
 network-object host 10.9.5.1
 network-object host 10.9.5.2
 network-object host 10.9.16.117
 network-object host 10.9.16.118
 network-object host 10.241.114.17
 network-object host 10.241.114.18
 network-object host 10.241.114.25
 network-object host 10.241.114.26
 network-object host 10.241.210.97
 network-object host 10.241.210.98
access-list outside_in extended permit tcp object-group g0 10.1.11.0 255.255.255.0 eq 80
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END

test_run($title, $in, $out);

############################################################
done_testing;
