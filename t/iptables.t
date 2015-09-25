#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);
############################################################
$title = 'Merge port range with sub-range for iptables';
############################################################

$in = <<'END';
network:RAS      = { ip = 10.2.2.0/24; }
network:Hoernum  = { ip = 10.3.3.128/29; }
network:StPeter  = { ip = 10.3.3.120/29; }
network:Firewall = { ip = 193.1.1.0/24; }

router:ras = {
 interface:Trans    = { ip = 10.1.1.2;}
 interface:Firewall = { ip = 193.1.1.1; }
 interface:RAS      = { ip = 10.2.2.1;}
 interface:StPeter  = { ip = 10.3.3.121;}
 interface:Hoernum  = { ip = 10.3.3.129;}
}

network:Trans = { ip = 10.1.1.0/24;}

router:nak = {
 managed;
 model = Linux;
 interface:Trans    = { ip = 10.1.1.1; hardware = eth0; }
 interface:Hosting  = { ip = 10.4.4.1; hardware = br0; }
}

network:Hosting = { ip = 10.4.4.0/24; }

service:p40-47 = {
 user = network:Firewall, network:RAS;
 permit src = user; 
	dst = network:Hosting;
	prt = tcp 30-37, tcp 51-53;
}

service:p10-60 = {
 user = network:Trans, network:StPeter, network:Hoernum;
 permit src = user;
        dst = network:Hosting;
        prt = tcp 10-49, tcp 50-60;
}
END

$out = <<'END';
--nak
-A c1 -j ACCEPT -s 10.3.3.128/29
-A c1 -j ACCEPT -s 10.3.3.120/29
-A c2 -g c1 -s 10.3.3.0/24
-A c2 -j ACCEPT -s 10.1.1.0/24
-A c3 -j ACCEPT -s 193.1.1.0/24
-A c3 -j ACCEPT -s 10.2.2.0/24
-A c4 -j c2 -s 10.0.0.0/14 -p tcp --dport 10:60
-A c4 -g c3 -p tcp --dport 51:53
-A c4 -g c3 -p tcp --dport 30:37
---
:eth0_br0 -
-A eth0_br0 -g c4 -d 10.4.4.0/24 -p tcp --dport 10:60
-A FORWARD -j eth0_br0 -i eth0 -o br0
END

test_run($title, $in, $out);

############################################################
$title = 'Un-merged port range with sub-range for iptables';
############################################################

# Ranges 10-49 and 50-60 can't be merged,
# because they have three childs 30-37,40-47,51-53
# and a merged range can have at most two childs.
$in =~ s/(tcp 30-37,) (tcp 51-53)/$1 tcp 40-47, $2/;

$out = <<'END';
--nak
-A c1 -j ACCEPT -s 10.3.3.128/29
-A c1 -j ACCEPT -s 10.3.3.120/29
-A c2 -g c1 -s 10.3.3.0/24
-A c2 -j ACCEPT -s 10.1.1.0/24
-A c3 -j ACCEPT -s 193.1.1.0/24
-A c3 -j ACCEPT -s 10.2.2.0/24
-A c4 -j c2 -s 10.0.0.0/14 -p tcp --dport 50:60
-A c4 -g c3 -p tcp --dport 51:53
-A c5 -g c4 -p tcp --dport 50:60
-A c5 -j c2 -s 10.0.0.0/14 -p tcp --dport 10:49
-A c5 -g c3 -p tcp --dport 40:47
-A c5 -g c3 -p tcp --dport 30:37
---
:eth0_br0 -
-A eth0_br0 -g c5 -d 10.4.4.0/24 -p tcp --dport 10:60
-A FORWARD -j eth0_br0 -i eth0 -o br0
END

test_run($title, $in, $out);

############################################################
$title = 'Optimize redundant port for iptables';
############################################################

# Port isn't already optimized during global optimization if rule is
# applied to different objects which got the same IP from NAT.

$in = <<'END';
network:A = { ip = 10.3.3.120/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
network:B = { ip = 10.3.3.128/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}

router:ras = {
 managed;
 model = ASA;
 interface:A = { ip = 10.3.3.121; hardware = Fe0; }
 interface:B = { ip = 10.3.3.129; hardware = Fe1; }
 interface:Trans = { ip = 10.1.1.2; bind_nat = C; hardware = Fe2; }
}

network:Trans = { ip = 10.1.1.0/24;}

router:nak = {
 managed;
 model = Linux;
 interface:Trans    = { ip = 10.1.1.1; hardware = eth0; }
 interface:Hosting  = { ip = 10.4.4.1; hardware = br0; }
}

network:Hosting = { ip = 10.4.4.0/24; }

service:A = {
 user = network:A;
 permit src = user; 
	dst = network:Hosting;
	prt = tcp 55;
}

service:B = {
 user = network:B;
 permit src = user;
        dst = network:Hosting;
        prt = tcp 50-60;
}
END

$out = <<'END';
--nak
:eth0_br0 -
-A eth0_br0 -j ACCEPT -s 10.2.2.0/24 -d 10.4.4.0/24 -p tcp --dport 50:60
-A FORWARD -j eth0_br0 -i eth0 -o br0
END

test_run($title, $in, $out);

############################################################
$title = 'Loopback at Linux passes other managed device';
############################################################

# Loopback interface and loopback network have identical IP address.
# Linux would abort when generating binary trees of IP addresses,
# where the same IP address comes from two different objects:
# loopback ip vs.loopback network.
# This test case would fail, if the loopback interface is 
# changed to loopback network at r1, but left unchanged at r2
# or vice versa.

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = {ip = 10.1.1.1; hardware = n1;}
 interface:n2 = {ip = 10.1.2.1; hardware = n2;}
}

network:n2 = { ip = 10.1.2.0/24;}

router:r2 = {
 managed;
 model = Linux;
 routing = manual;
 interface:n2 = {
  ip = 10.1.2.2;
  hardware = eth0;
 }
 interface:Mail = {
  ip = 10.1.3.1;
  loopback;
  hardware = eth1;
 }
}

service:test = {
 user =  network:n1, network:n2;
 permit src = user;
	dst = interface:r2.Mail;
	prt = tcp 25;
}
END

$out = <<'END';
--r2
:c1 -
-A c1 -j ACCEPT -s 10.1.2.0/24
-A c1 -j ACCEPT -s 10.1.1.0/24
--
:eth0_self -
-A eth0_self -g c1 -s 10.1.0.0/22 -d 10.1.3.1 -p tcp --dport 25
-A INPUT -j eth0_self -i eth0
END

test_run($title, $in, $out);

############################################################
$title = 'loopback interface, loopback network and NAT with same IP';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = {
 ip = 10.1.2.0/24;
 host:h = {ip = 10.1.2.11;}
}

router:u = {
 interface:n2;
 interface:n1;
 interface:n3 = { ip = 10.1.3.1;}
}

network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = Linux;
 interface:n3 = { ip = 10.1.3.2; hardware = eth1; }
 interface:n4 = { ip = 10.1.4.1; hardware = eth0; }
}

network:n4 = { ip = 10.1.4.0/24; }

router:r2 = {
 managed;
 model = Linux;
 interface:n4 = { ip = 10.1.4.2; hardware = eth0; bind_nat = nat1; }
 interface:lo = { ip = 1.1.1.1; hardware = eth1; loopback; }
 interface:n5 = { ip = 10.1.5.17; hardware = eth1; }
}

network:n5 = {
 ip = 10.1.5.16/28;
 nat:nat1 = { ip = 1.1.1.1/32; dynamic; }
}

protocol:Ping_Net = icmp 8, src_net, dst_net;

service:t1 = {
 user = network:n5;
 permit src = user; dst = network:n1; prt = icmp 8;
}
service:t2 = {
 user = interface:r2.lo;
 permit src = user; dst = host:h; prt = tcp 2200, protocol:Ping_Net;
}
END

$out = <<'END';
-- r1
# [ ACL ]
:c1 -
:c2 -
-A c1 -j ACCEPT -d 10.1.2.0/24
-A c1 -j ACCEPT -d 10.1.1.0/24
-A c2 -j ACCEPT -d 10.1.2.11 -p tcp --dport 2200
-A c2 -g c1 -d 10.1.0.0/22 -p icmp --icmp-type 8
--
:eth1_self -
-A INPUT -j eth1_self -i eth1
--
:eth0_self -
-A INPUT -j eth0_self -i eth0
:eth0_eth1 -
-A eth0_eth1 -g c2 -s 1.1.1.1
-A FORWARD -j eth0_eth1 -i eth0 -o eth1
END

test_run($title, $in, $out);

############################################################
$title = 'Different chains for pairs of input/ouptut interfaces';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 =  {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:k1 = { ip = 10.2.1.1; hardware = k1; }
 interface:k2 = { ip = 10.2.2.1; hardware = k2; }
}
network:k1 = { ip = 10.2.1.0/24; }
network:k2 = { ip = 10.2.2.0/24; }

service:t1 = {
 user = network:n1;
 permit src = user; dst = network:k1, network:k2; prt = tcp 80, tcp 82;
}
END

$out = <<'END';
-- r1
# [ ACL ]
:c1 -
:c2 -
-A c1 -j ACCEPT -p tcp --dport 82
-A c1 -j ACCEPT -p tcp --dport 80
-A c2 -j ACCEPT -p tcp --dport 82
-A c2 -j ACCEPT -p tcp --dport 80
--
:n1_self -
-A INPUT -j n1_self -i n1
:n1_k1 -
-A n1_k1 -g c1 -s 10.1.1.0/24 -d 10.2.1.0/24 -p tcp --dport 80:82
-A FORWARD -j n1_k1 -i n1 -o k1
:n1_k2 -
-A n1_k2 -g c2 -s 10.1.1.0/24 -d 10.2.2.0/24 -p tcp --dport 80:82
-A FORWARD -j n1_k2 -i n1 -o k2
--
END

test_run($title, $in, $out);

############################################################
$title = 'Check udp/tcp early and combine adjacent networks';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip = 10.1.1.1; hardware = eth1; }
 interface:n2 = { ip = 10.1.2.1; hardware = eth1; }
 interface:n3 = { ip = 10.1.3.1; hardware = eth1; }
}

service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22, tcp 25;
}
service:test2 = {
 user = network:n2, network:n3;
 permit src = user; dst = network:n1; prt = udp 53, tcp 53;
}
service:test3 = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 21;
}
END

$out = <<'END';
-- r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
:c4 -
-A c1 -j ACCEPT -p tcp --dport 25
-A c1 -j ACCEPT -p tcp --dport 22
-A c2 -j ACCEPT -p tcp --dport 53
-A c2 -j ACCEPT -p tcp --dport 21
-A c3 -g c2 -s 10.1.3.0/24 -p tcp --dport 21:53
-A c3 -j ACCEPT -s 10.1.2.0/24 -p tcp --dport 53
-A c4 -g c1 -s 10.1.1.0/24 -d 10.1.2.0/24 -p tcp --dport 22:25
-A c4 -g c3 -s 10.1.2.0/23 -d 10.1.1.0/24
--
:eth1_eth1 -
-A eth1_eth1 -g c4 -d 10.1.0.0/22 -p tcp
-A eth1_eth1 -j ACCEPT -s 10.1.2.0/23 -d 10.1.1.0/24 -p udp --dport 53
-A FORWARD -j eth1_eth1 -i eth1 -o eth1
END

test_run($title, $in, $out);

############################################################
$title = 'Check icmp early ';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}

router:u = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; }
}

network:n2 = { ip = 10.1.2.0/24;}

router:r1 = {
 managed;
 model = Linux;
 interface:n2 = { ip = 10.1.2.2; hardware = eth0;}
 interface:n3 = { ip = 10.1.3.1; hardware = eth1; }
}
network:n3 = { ip = 10.1.3.0/24;}

service:t1 = {
 user = network:n1, network:n2;
 permit src = network:n3; dst = user; prt = tcp 80, icmp 8;
}
END

$out = <<'END';
-- r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -d 10.1.2.0/24 -p tcp --dport 80
-A c1 -j ACCEPT -d 10.1.1.0/24 -p tcp --dport 80
-A c2 -j ACCEPT -d 10.1.2.0/24 -p icmp --icmp-type 8
-A c2 -j ACCEPT -d 10.1.1.0/24 -p icmp --icmp-type 8
-A c3 -g c1 -d 10.1.0.0/22 -p tcp
-A c3 -g c2 -d 10.1.0.0/22 -p icmp
--
:eth1_eth0 -
-A eth1_eth0 -g c3 -s 10.1.3.0/24
-A FORWARD -j eth1_eth0 -i eth1 -o eth0
END

test_run($title, $in, $out);

############################################################
done_testing;
