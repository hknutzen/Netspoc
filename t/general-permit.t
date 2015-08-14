#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'General permit';
############################################################

$in = <<'END';
network:m = { ip = 10.2.2.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmp 0, icmp 3;
 interface:m = { ip = 10.2.2.2; hardware = e0; }
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
network:n = { ip = 10.1.1.0/24; }

service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = icmp;
}
END

$out = <<'END';
--r
ip access-list e0_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any 10.1.1.2/32
 50 permit icmp 10.2.2.0/24 10.1.1.0/24
 60 deny ip any any
--
ip access-list e1_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'General permit (Linux)';
############################################################

$in =~ s/NX-OS/Linux/;
$out = <<'END';
--r
# [ ACL ]
:c1 -
:c2 -
:c3 -
:c4 -
:c5 -
-A c1 -j ACCEPT -p icmp --icmp-type 0
-A c1 -j ACCEPT -p icmp --icmp-type 3
-A c2 -j c1 -p icmp
-A c2 -j ACCEPT -s 10.2.2.0/24 -d 10.1.1.0/24 -p icmp
-A c3 -j ACCEPT -p icmp --icmp-type 0
-A c3 -j ACCEPT -p icmp --icmp-type 3
-A c4 -j ACCEPT -p icmp --icmp-type 0
-A c4 -j ACCEPT -p icmp --icmp-type 3
-A c5 -j ACCEPT -p icmp --icmp-type 0
-A c5 -j ACCEPT -p icmp --icmp-type 3
--
:e0_self -
-A e0_self -j ACCEPT -p tcp
-A e0_self -g c3 -p icmp
-A INPUT -j e0_self -i e0
:e0_e1 -
-A e0_e1 -j ACCEPT -p tcp
-A e0_e1 -g c2 -p icmp
-A FORWARD -j e0_e1 -i e0 -o e1
--
:e1_self -
-A e1_self -j ACCEPT -p tcp
-A e1_self -g c5 -p icmp
-A INPUT -j e1_self -i e1
:e1_e0 -
-A e1_e0 -j ACCEPT -p tcp
-A e1_e0 -g c4 -p icmp
-A FORWARD -j e1_e0 -i e1 -o e0
END

test_run($title, $in, $out);

############################################################
$title = 'No range permitted';
############################################################

$in = <<'END';
area:all = { anchor = network:n; router_attributes = { general_permit = protocol:ftp-data, tcp 80; } }
network:n = { ip = 10.1.1.0/24; }
protocol:ftp-data = tcp 20:1024-65535;
END

$out = <<'END';
Error: Must not use 'protocol:ftp-data' with ports in general_permit of router_attributes of area:all
Error: Must not use 'tcp 80' with ports in general_permit of router_attributes of area:all
END

test_err($title, $in, $out);

############################################################
$title = 'Check for useless inheritance';
############################################################

$in = <<'END';
area:all = { anchor = network:n; router_attributes = { general_permit = icmp, tcp; } }
network:n = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmp;
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
END
$out = <<'END';
Warning: Useless attribute 'general_permit' at router:r,
 it was already inherited from router_attributes of area:all
END

test_err($title, $in, $out);

############################################################
$title = 'Managed host';
############################################################

$in = <<'END';
area:all = {
 anchor = network:n1;
 auto_border;
 router_attributes = { general_permit = icmp; }
}

network:n1 = {
 ip = 10.1.1.160/27;

 host:h1 = { ip = 10.1.1.166;
  managed; model = Linux;
  hardware = eth0;
 }
}

service:test = {
 user = host:h1;
 permit src =   network:n1;
        dst =   user;
        prt =   tcp 111;
}
END

$out = <<'END';
--host:h1
:eth0_self -
-A eth0_self -j ACCEPT -s 10.1.1.160/27 -d 10.1.1.166 -p tcp --dport 111
-A eth0_self -j ACCEPT -p icmp
-A INPUT -j eth0_self -i eth0
END

test_run($title, $in, $out);

############################################################
done_testing;
