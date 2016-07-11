#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

############################################################
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
END

############################################################
$title = 'Invalid ports and port ranges';
############################################################

$in = <<'END';
protocol:p1 = tcp 0 - 10;
protocol:p2 = udp 60000 - 99999;
protocol:p3 = udp 100100 - 100102;
protocol:p4 = tcp 90 - 80;
protocolgroup:g1 = udp 0, tcp 77777;
END

$out = <<'END';
Error: Invalid port number '0' at line 1 of STDIN
Error: Too large port number 99999 at line 2 of STDIN
Error: Too large port number 100100 at line 3 of STDIN
Error: Too large port number 100102 at line 3 of STDIN
Error: Invalid port range 90-80 at line 4 of STDIN
Error: Invalid port number '0' at line 5 of STDIN
Error: Too large port number 77777 at line 5 of STDIN
END

test_err($title, $in, $out);

############################################################
$title = 'Valid port ranges';
############################################################

$in = $topo . <<'END';

service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 1-1023, udp 1024-65535;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 lt 1024
 permit udp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 gt 1023
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Different protocol modifiers';
############################################################

$in = $topo . <<'END';
protocolgroup:tftp = protocol:tftp-request, 
		     protocol:tftp-server-answer, 
		     protocol:tftp-client-answer,
;
protocol:tftp-request= udp 69, oneway;
protocol:tftp-server-answer = udp 1024-65535, stateless, reversed, oneway;
protocol:tftp-client-answer = udp 1024-65535, stateless, oneway;

protocolgroup:Ping_Net_both =
 protocol:Ping_Net,
 protocol:Ping_Net_Reply,
;
protocol:Ping_Net       = icmp 8, src_net, dst_net, overlaps, no_check_supernet_rules;
protocol:Ping_Net_Reply = icmp 8, src_net, dst_net, overlaps, reversed, no_check_supernet_rules;

service:test = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = protocolgroup:tftp, udp 123;
 permit src = user; dst = network:n3; prt = icmp 3, protocolgroup:Ping_Net_both;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 permit udp host 10.1.1.10 10.1.2.0 0.0.0.255 eq 123
 permit udp host 10.1.1.10 10.1.2.0 0.0.0.255 eq 69
 permit udp host 10.1.1.10 10.1.2.0 0.0.0.255 gt 1023
 permit icmp host 10.1.1.10 10.1.3.0 0.0.0.255 3
 permit icmp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 8
 deny ip any any
--
ip access-list extended n2_in
 permit udp 10.1.2.0 0.0.0.255 host 10.1.1.10 gt 1023
 permit udp 10.1.2.0 0.0.0.255 eq 123 host 10.1.1.10
 deny ip any any
--
ip access-list extended n3_in
 deny ip any host 10.1.1.1
 permit icmp 10.1.3.0 0.0.0.255 10.1.1.0 0.0.0.255 8
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Overlapping TCP ranges and modifier "reversed"';
############################################################

# Split port 21 from range 21-22 must not accidently use 
# protocol:TCP_21_Reply
$in = $topo . <<'END';
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 21 - 22;
 permit src = user; dst = network:n3; prt = tcp 20 - 21;
 permit src = user; dst = network:n4; prt = tcp 21;
}

protocol:TCP_21_Reply = tcp 21, reversed;
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 deny ip any host 10.1.3.1
 deny ip any host 10.1.4.1
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 range 21 22
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 range 20 21
 permit tcp 10.1.1.0 0.0.0.255 10.1.4.0 0.0.0.255 eq 21
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'icmp type with different codes';
############################################################

$in = $topo . <<'END';
service:test = {
 user = network:n1;
 permit src = user; 
        dst = network:n2; 
        prt = icmp 3/2, icmp 3/1, icmp 3/0, icmp 3/13, icmp 3/3;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 2
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 1
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 0
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 13
 permit icmp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 3 3
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Overlapping udp oneway';
############################################################

$in = $topo . <<'END';
protocol:tftp-request= udp 69, oneway;

service:s1 = {
 user = network:n1;
 permit src = network:n2;
        dst = user;
        prt = protocol:tftp-request;
}
service:s2 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = network:n2;
        dst = user;
        prt = udp 69;
}
END

$out = <<'END';
--r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit udp 10.1.1.0 0.0.0.255 eq 69 10.1.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 permit udp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 69
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Modifier src_net to interface with pathrestriction';
############################################################
# Implicit pathrestriction from virtual interface.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:t1 = {ip = 10.254.1.12; hardware = t1; }
}
network:t1 = {ip = 10.254.1.8/29;}

router:u1 = {
 interface:t1 = {ip = 10.254.1.9;}
 interface:n2 = {ip = 10.1.2.254; virtual = {ip = 10.1.2.1; }}
}
router:r2 = {
 managed;
 routing = manual;
 model = IOS;
 interface:t1 = {ip = 10.254.1.10; hardware = t1;}
 interface:n2 = {ip = 10.1.2.253; virtual = {ip = 10.1.2.1; } hardware = n2; }	
}
network:n2 = { ip = 10.1.2.0/24; }

protocol:Ping_Netz = icmp 8, src_net, dst_net;

service:s1 = {
 user =  interface:u1.n2;
 permit src = user; dst = network:n1; prt = protocol:Ping_Netz;
}
END

$out = <<'END';
--r2
ip access-list extended n2_in
 permit icmp 10.1.2.0 0.0.0.255 10.1.1.0 0.0.0.255 8
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'src_net with complex protocol';
############################################################

$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24; 
 host:h1 = { ip = 10.1.1.10; }
}

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }	
}
network:n2 = { ip = 10.1.2.0/24; 
 host:h2 = { range = 10.1.2.4 - 10.1.2.6; }
}

protocol:tftp_net = udp 69:69, src_net, dst_net, oneway;

service:s1 = {
 user = host:h1;
 permit src = user; dst = host:h2; prt = protocol:tftp_net, udp 68;
}
END

$out = <<'END';
--r1
ip access-list extended n1_in
 deny ip any host 10.1.2.1
 permit udp host 10.1.1.10 10.1.2.4 0.0.0.1 eq 68
 permit udp host 10.1.1.10 host 10.1.2.6 eq 68
 permit udp 10.1.1.0 0.0.0.255 eq 69 10.1.2.0 0.0.0.255 eq 69
 deny ip any any
--
ip access-list extended n2_in
 permit udp 10.1.2.4 0.0.0.1 eq 68 host 10.1.1.10
 permit udp host 10.1.2.6 eq 68 host 10.1.1.10
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Recursive protocolgroup';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = {ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {ip = 10.1.2.1; hardware = n2; }	
}
network:n2 = { ip = 10.1.2.0/24; }

protocolgroup:g1 = tcp 80, protocolgroup:g2;
protocolgroup:g2 = tcp 90, protocolgroup:g1;
service:s1 = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = protocolgroup:g1;
}
END

$out = <<'END';
Error: Found recursion in definition of protocolgroup:g2
END

test_err($title, $in, $out);

############################################################
done_testing;
