#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Split and combine host ranges';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.15-10.1.1.19; }
 host:b = { range = 10.1.1.20-10.1.1.24; }
 host:c = { range = 10.1.1.25-10.1.1.35; }
}

router:r = {
 model = IOS, FW;
 managed;
 interface:n = { ip = 10.1.1.1; hardware = ethernet0; }
 interface:x = { ip = 192.168.1.1; hardware = ethernet1; }
}

network:x = { ip = 192.168.1.0/24; }

service:test = {
 user = host:a, host:b, host:c;
 permit src = user; dst = network:x; prt = tcp 80; 
}
END

$out = <<'END';
--r
ip access-list extended ethernet0_in
 deny ip any host 192.168.1.1
 permit tcp 10.1.1.16 0.0.0.15 192.168.1.0 0.0.0.255 eq 80
 permit tcp 10.1.1.32 0.0.0.3 192.168.1.0 0.0.0.255 eq 80
 permit tcp host 10.1.1.15 192.168.1.0 0.0.0.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Duplicate host ranges';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.15-10.1.1.19; }
 host:b = { range = 10.1.1.15-10.1.1.19; }
}

END

$out = <<'END';
Error: Duplicate IP range for host:a and host:b
END

test_err($title, $in, $out);

############################################################
$title = 'Host range and interface IP overlap';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { range = 10.1.1.1-10.1.1.19; }
}

router:r = {
 interface:n = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r.n and host:a
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate host and interface IP';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { ip = 10.1.1.1; }
}

router:r = {
 interface:n = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Duplicate IP address for interface:r.n and host:a
END

test_err($title, $in, $out);

############################################################
$title = 'Duplicate host IPs';
############################################################

$in = <<'END';

network:n = {
 ip = 10.1.1.0/24;
 host:a = { ip = 10.1.1.1; }
 host:b = { ip = 10.1.1.1; }
}
END

$out = <<'END';
Error: Duplicate IP address for host:a and host:b
END

test_err($title, $in, $out);

############################################################
done_testing;
