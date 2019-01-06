#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Access managed host from enclosing network';
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.11; hardware = eth0; }
}

service:test = {
 user = network:N;
 permit src = user; dst = host:h1; prt = tcp 80;
}
END

$out = <<'END';
--host:h1
:eth0_self -
-A eth0_self -j ACCEPT -s 10.1.1.0/24 -d 10.1.1.11 -p tcp --dport 80
-A INPUT -j eth0_self -i eth0
END

test_run($title, $in, $out);

############################################################
$title = 'Access from managed host to managed host';
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
 host:h2 = { managed; model = Linux; ip = 10.1.1.11; hardware = eth1; }
}

service:test = {
 user = host:h2;
 permit src = user; dst = host:h1; prt = tcp 80;
}
END

$out = <<'END';
--host:h1
:eth0_self -
-A eth0_self -j ACCEPT -s 10.1.1.11 -d 10.1.1.10 -p tcp --dport 80
-A INPUT -j eth0_self -i eth0
--host:h2
:eth1_self -
-A INPUT -j eth1_self -i eth1
END

test_run($title, $in, $out);

############################################################
$title = 'Automatically add managed host to destination network';
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
}

service:test = {
 user = network:N;
 permit src = user; dst = user; prt = tcp 80;
}
END

$out = <<'END';
--host:h1
:eth0_self -
-A eth0_self -j ACCEPT -s 10.1.1.0/24 -d 10.1.1.10 -p tcp --dport 80
-A INPUT -j eth0_self -i eth0
END

test_run($title, $in, $out);

############################################################
$title = 'Detect duplicate automatic and manual managed host';
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
}

service:test = {
 user = network:N, host:h1;
 permit src = user; dst = user; prt = tcp 80;
}
END

$out = <<'END';
Warning: Duplicate elements in dst of rule in service:test:
 - host:h1
END

test_warn($title, $in, $out);

############################################################
$title = 'Automatically add managed host to destination aggregate ';
############################################################

$in = <<'END';
any:10 = { ip=10.0.0.0/8; link = network:N; }
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
}

service:test1 = {
 user = any:10;
 permit src = user; dst = user; prt = tcp 80;
}
service:test2 = {
 user = any:[ip=10.1.0.0/16 & network:N];
 permit src = user; dst = user; prt = tcp 81;
}

# Test also with non user-user rule
service:test3 = {
 user = any:[ip=10.1.0.0/16 & network:N];
 permit src = network:N; dst = user; prt = tcp 82;
}
END

$out = <<'END';
--host:h1
-A c1 -j ACCEPT -s 10.1.1.0/24 -p tcp --dport 82
-A c1 -j ACCEPT -s 10.1.0.0/16 -p tcp --dport 81
-A c1 -j ACCEPT -s 10.0.0.0/8 -p tcp --dport 80
--
:eth0_self -
-A eth0_self -g c1 -d 10.1.1.10 -p tcp --dport 80:82
-A INPUT -j eth0_self -i eth0
END

test_run($title, $in, $out);

############################################################
$title = 'Filter managed host in destination aggregate ';
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10;  hardware = eth0; }
 host:h2 = { managed; model = Linux; ip = 10.1.1.222; hardware = eth1; }
}

service:test = {
 user = any:[ip=10.1.1.0/28 & network:N];
 permit src = user; dst = user; prt = tcp 80;
}
END

$out = <<'END';
--host:h1
:eth0_self -
-A eth0_self -j ACCEPT -s 10.1.1.0/28 -d 10.1.1.10 -p tcp --dport 80
-A INPUT -j eth0_self -i eth0
END

test_run($title, $in, $out);

############################################################
$title = 'NAT with managed host';
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; bind_nat = dyn;}
 interface:N = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:N = {
 ip = 10.1.1.0/24;
 nat:dyn = { ip = 10.99.99.64/28; dynamic; }
 host:h1 = {
  ip = 10.1.1.10;
  nat:dyn = { ip = 10.99.99.69; }
  managed; model = Linux; hardware = eth0; }
}
service:test = {
 user = network:Test;
 permit src = user; dst = host:h1; prt = tcp 22;
}
END

$out = <<'END';
--host:h1
:eth0_self -
-A eth0_self -j ACCEPT -s 10.9.1.0/24 -d 10.1.1.10 -p tcp --dport 22
-A INPUT -j eth0_self -i eth0
--filter
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.99.99.69 eq 22
access-list Vlan1_in extended deny ip any4 any4
access-group Vlan1_in in interface Vlan1
END

test_run($title, $in, $out);

############################################################
$title = "Automatic managed and unmanaged hosts from network";
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed = secondary;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:N = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
 host:h2 = {          model = Linux; ip = 10.1.1.11; hardware = eth0; }
}
service:test1 = {
 user = host:[network:N];
 permit src = network:Test; dst = user; prt = tcp 81;
}
service:test2 = {
 user = host:[managed & network:N];
 permit src = network:Test; dst = user; prt = tcp 82;
}
service:test3 = {
 user =  host:[network:N] &! host:[managed & network:N];
 permit src = network:Test; dst = user; prt = tcp 83;
}
END

$out = <<'END';
--filter
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.1.1.11 eq 81
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.1.1.10 range 81 82
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.1.1.11 eq 83
access-list Vlan1_in extended deny ip any4 any4
access-group Vlan1_in in interface Vlan1
END

test_run($title, $in, $out);

############################################################
$title = "Managed host doesn't count as full filter";
############################################################

$in = <<'END';
network:Test = { ip = 10.9.1.0/24; }
router:filter = {
 managed = secondary;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:N = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
 host:h2 = { managed; model = Linux; ip = 10.1.1.11; hardware = eth0; }
}
service:test = {
 user = host:h1, host:h2;
 permit src = user; dst = network:Test; prt = tcp 22;
}
END

$out = <<'END';
--filter
! Vlan2_in
access-list Vlan2_in extended permit tcp 10.1.1.10 255.255.255.254 10.9.1.0 255.255.255.0 eq 22
access-list Vlan2_in extended deny ip any4 any4
access-group Vlan2_in in interface Vlan2
END

test_run($title, $in, $out);

############################################################
$title = "Managed host must use standard filter";
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed = secondary; model = Linux; ip = 10.1.1.11; hardware = eth0; }
}
END

$out = <<'END';
Error: Only 'managed=standard' is supported at line 3 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = "Missing model at managed host";
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; ip = 10.1.1.11; hardware = eth0; }
}
END

$out = <<'END';
Error: Missing 'model' for managed host:h1
END

test_err($title, $in, $out);

############################################################
$title = "Missing hardware at managed host";
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.11; }
}
END

$out = <<'END';
Error: Missing 'hardware' for host:h1
END

test_err($title, $in, $out);

############################################################
$title = "Unsupported model at managed host";
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = IOS; ip = 10.1.1.11; hardware = eth0; }
}
END

$out = <<'END';
Error: Must not use model IOS at managed host:h1
END

test_err($title, $in, $out);

############################################################
$title = "Missing IP address";
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; hardware = eth0; }
}
END

$out = <<'END';
Error: host:h1 needs exactly one of attributes 'ip' and 'range'
END

test_err($title, $in, $out);

############################################################
$title = "Unexpected IP range";
############################################################

$in = <<'END';
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { range = 10.1.1.7-10.1.1.17;
             managed; model = Linux; hardware = eth0; }
}
END

$out = <<'END';
Error: Managed host:h1 must not have attribute 'range'
END

test_err($title, $in, $out);

############################################################
$title = "Duplicate IP address";
############################################################

$in = <<'END';
router:R = {
 interface:N = { ip = 10.1.1.10; }
}
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
 host:h2 = { ip = 10.1.1.10; }
 host:h3 = { range = 10.1.1.8 - 10.1.1.15; }
}
END
$out = <<'END';
Error: Duplicate IP address for host:h1 and interface:R.N
Error: Duplicate IP address for host:h1 and host:h3
Error: Duplicate IP address for host:h1 and host:h2
END

test_err($title, $in, $out);

############################################################
$title = "Multi homed managed host";
############################################################

$in = <<'END';
network:Test = {
 ip = 10.9.1.0/24;
 host:t10 = { ip = 10.9.1.10; }
 host:t20 = { ip = 10.9.1.20; }
 host:t30 = { ip = 10.9.1.30; }
 host:s = {
  ip = 10.9.1.9;
  managed; model = Linux; hardware = eth0; server_name = hugo; }
}
router:filter = {
 managed;
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = Vlan1; }
 interface:N = { ip = 10.1.1.1; hardware = Vlan2; }
}
network:N = {
 ip = 10.1.1.0/24;
 host:h1 = {
  ip = 10.1.1.10;
  managed; model = Linux; hardware = eth1; server_name = hugo; }
}
service:test = {
 user = host:t10, host:t20, host:t30;
 permit src = user; dst = host:s, host:h1; prt = tcp 22;
}
END

$out = <<'END';
--host:hugo
:c1 -
:c2 -
:c3 -
:c4 -
-A c1 -j ACCEPT -s 10.9.1.30
-A c1 -j ACCEPT -s 10.9.1.20
-A c2 -g c1 -s 10.9.1.16/28
-A c2 -j ACCEPT -s 10.9.1.10
-A c3 -j ACCEPT -s 10.9.1.30
-A c3 -j ACCEPT -s 10.9.1.20
-A c4 -g c3 -s 10.9.1.16/28
-A c4 -j ACCEPT -s 10.9.1.10
--
:eth0_self -
-A eth0_self -g c2 -s 10.9.1.0/27 -d 10.9.1.9 -p tcp --dport 22
-A INPUT -j eth0_self -i eth0
--
END

test_run($title, $in, $out);

############################################################
done_testing;
