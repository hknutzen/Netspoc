#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Single router';
############################################################

$in = <<'END';
router:r = {}
END

$out = <<"END";
Error: router:r isn\'t connected to any network
Error: topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Router references unknown network';
############################################################

$in = <<'END';
router:r = { interface:n2; }
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: Referencing undefined network:n2 from interface:r.n2
Error: router:r isn't connected to any network
Error: network:n1 isn't connected to any router
Error: topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Single network';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
END

test_warn($title, $in, $out);

############################################################
$title = 'Unconnected';
############################################################

$in = <<'END';
router:r1 = { interface:n1; }
network:n1 = { ip = 10.1.1.0/24; }

router:r2 = { interface:n2; }
network:n2 = { ip = 10.1.2.0/24; }

router:r3 = { interface:n3; }
network:n3 = { ip = 10.1.3.0/24; }

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
Error: IPv4 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n2]
 - any:[network:n3]
END

test_err($title, $in, $out);

############################################################
$title = 'Unconnected with managed';
############################################################
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}

router:r2 = {
 model = IOS;
 managed;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
Error: IPv4 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n2]
END

test_err($title, $in, $out);

############################################################
$title = 'Unconnected with crypto';
############################################################

$in = <<'END';
isakmp:x = {
 identity = address;
 authentication = preshare;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
ipsec:x = {
 key_exchange = isakmp:x;
 esp_encryption = aes256;
 esp_authentication = sha_hmac;
 lifetime = 3600 sec;
}
crypto:x = {
 type = ipsec:x;
}

network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:t  = { ip = 10.9.1.1; hub = crypto:x; hardware = t; }
}

network:t = { ip = 10.9.1.0/24; }

router:r2 = {
 managed;
 model = IOS;
 interface:t  = { ip = 10.9.1.2; spoke = crypto:x; hardware = t; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n3 = { ip = 10.1.3.0/24; }
END

$out = <<'END';
Error: IPv4 topology has unconnected parts:
 - any:[network:n1]
 - any:[network:n3]
END

test_err($title, $in, $out);

############################################################
$title = 'Unconnected with connected crypto part';
############################################################

$in .= <<'END';
router:fw = {
 managed;
 model = ASA;
 interface:t  = { ip = 10.9.1.3; hardware = t; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
END

$out = <<'END';
Error: IPv4 topology has unconnected parts:
 - any:[network:t]
 - any:[network:n3]
END

test_err($title, $in, $out);

############################################################
$title = 'Unconnected with auto interface to other part';
############################################################

$in .= <<'END';
service:test = {
 user = interface:r1.[auto], interface:r3.[auto];
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
Error: IPv4 topology has unconnected parts:
 - any:[network:t]
 - any:[network:n3]
Error: No valid path
 from router:r3
 to any:[network:n2]
 while resolving interface:r3.[auto] (destination is any:[network:n2]).
 Check path restrictions and crypto interfaces.
END

test_err($title, $in, $out);

############################################################
done_testing;
