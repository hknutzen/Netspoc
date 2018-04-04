#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

#############################################################
$title = 'Simple topology IPv6';
#############################################################

$in = <<'END';
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = E2;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END

$out = <<'END';
-- ipv6/r1
ip access-list extended E1_in
 deny ip any host 1000::abcd:2:1
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 range 80 90
 deny ip any any
END

test_run($title, $in, $out, '-ipv6');

#############################################################
$title = 'Check IPv6 increment_ip';
#############################################################

$in = <<'END';
network:n1 = { ip = 1000::0/16;
 host:host1 = {
  range = 1000::FFFF:FFFF:FFFF:FFFF:FFFF:FFF0 - 1000:0001::0;
 }
}

network:n2 = { ip = 2000::0/48;
 host:host2 = {
  range = 2000::FFFF:FFFF:FFFF:FFF0 - 2000::0001:0000:0000:0000:0000;
 }
}

network:n3 = { ip = 3000::0/80;
 host:host3 = {
  range = 3000::FFFF:FFF0 - 3000::0001:0000:0000;
 }
}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::0001; hardware = E1;}
 interface:n2 = {ip = 2000::0001; hardware = E2;}
 interface:n3 = {ip = 3000::0001; hardware = E3;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END

$out = <<'END';
-- ipv6/r1
ip access-list extended E1_in
 deny ip any host 2000::1
 permit tcp 1000::/16 2000::/48 range 80 90
 deny ip any any
END

test_run($title, $in, $out, '-ipv6');

#############################################################
$title = 'IPv6 with host ranges';
#############################################################

$in = <<'END';
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = {
 ip = 1000::abcd:0002:0000/112;
 host:a = { range = 1000::abcd:0002:0012-1000::abcd:0002:0022; }
 host:b = { range = 1000::abcd:0002:0060-1000::abcd:0002:0240; }
}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = E2;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END

$out = <<'END';
-- ipv6/r1
ip access-list extended E1_in
 deny ip any host 1000::abcd:2:1
 permit tcp 1000::abcd:1:0/112 1000::abcd:2:0/112 range 80 90
 deny ip any any
END

test_run($title, $in, $out, '-ipv6');

#############################################################
$title = 'OSPF, EIGRP, HSRP, VRRP, DHCP';
#############################################################

$in = <<'END';
network:n1 = { ip = 1000::abcd:0001:0/112; }
network:n2 = { ip = 1000::abcd:0002:0000/112; }

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {
  ip = 1000::abcd:0001:0002;
  virtual = { ip = 1000::abcd:0001:0001; type = VRRP; id = 6; }
  hardware = n1;
  routing = OSPF;
  dhcp_server;
 }
 interface:n2 = {
  ip = 1000::abcd:0002:0002;
  virtual = { ip = 1000::abcd:0002:0001; type = HSRP; id = 7; }
  hardware = n2;
  routing = EIGRP;
  dhcp_client;
 }
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:n1 = {
  ip = 1000::abcd:0001:0003;
  virtual = { ip = 1000::abcd:0001:0001; type = VRRP; id = 6; }
  hardware = n1;
  routing = OSPF;
 }
 interface:n2 = {
  ip = 1000::abcd:0002:0003;
  virtual = { ip = 1000::abcd:0002:0001; type = HSRP; id = 7; }
  hardware = n2;
  routing = EIGRP;
 }
}

END

$out = <<'END';
-- ipv6/r1
ip access-list extended n1_in
 permit 89 1000::abcd:1:0/112 host ff02::5
 permit 89 1000::abcd:1:0/112 host ff02::6
 permit 89 1000::abcd:1:0/112 1000::abcd:1:0/112
 permit 112 1000::abcd:1:0/112 host ff02::12
 permit udp any any eq 67
 deny ip any any
--
ip access-list extended n2_in
 permit 88 1000::abcd:2:0/112 host ff02::a
 permit 88 1000::abcd:2:0/112 1000::abcd:2:0/112
 permit udp 1000::abcd:2:0/112 host ::e000:2 eq 1985
 permit udp any any eq 68
 deny ip any any
END

test_run($title, $in, $out, '-ipv6');

############################################################
$title = 'Access managed host from enclosing network';
############################################################

$in = <<'END';
network:N = {
 ip = ::a01:100/120;
 host:h1 = { managed; model = Linux; ip = ::a01:10b; hardware = eth0; }
}

service:test = {
 user = network:N;
 permit src = user; dst = host:h1; prt = tcp 80;
}
END

$out = <<'END';
--ipv6/host:h1
:eth0_self -
-A eth0_self -j ACCEPT -s ::a01:100/120 -d ::a01:10b -p tcp --dport 80
-A INPUT -j eth0_self -i eth0
END

test_run($title, $in, $out, '-ipv6');

#############################################################
$title = 'IPv6 interface in IPv4 topology';
#############################################################


$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:1; hardware = E2;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END
$out = <<'END';
Syntax error: IP address expected at line 8 of STDIN, near "1000::abcd:0002:1<--HERE-->; hardware"
END

test_err($title, $in, $out);

#############################################################
$title = 'IPv4 interface in IPv6 topology';
#############################################################

$in = <<'END';
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 1000::abcd:0002:0/112;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 10.2.2.1; hardware = E2;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END
$out = <<'END';
Syntax error: IPv6 address expected at line 8 of STDIN, near "10.2.2.1<--HERE-->; hardware"
END

test_err($title, $in, $out, '-ipv6');

#############################################################
$title = 'IPv6 network in IPv4 topology';
#############################################################


$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 1000::abcd:0002:0000/112;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = {ip = 10.2.2.1; hardware = E2;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END
$out = <<'END';
Syntax error: IP address expected at line 2 of STDIN, near "1000::abcd:0002:0000/112<--HERE-->;}"
END

test_err($title, $in, $out);

#############################################################
$title = 'IPv4 network in IPv6 topology';
#############################################################

$in = <<'END';
network:n1 = { ip = 1000::abcd:0001:0/112;}
network:n2 = { ip = 10.2.2.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = {ip = 1000::abcd:0001:0001; hardware = E1;}
 interface:n2 = {ip = 1000::abcd:0002:0001; hardware = E2;}
}

service:test1 = {
 user = network:n1;
 permit src = user;
 dst = network:n2;
 prt = tcp 80-90;
}
END
$out = <<'END';
Syntax error: IPv6 address expected at line 2 of STDIN, near "10.2.2.0/24<--HERE-->;}"
END

test_err($title, $in, $out, '-ipv6');

############################################################
$title = "Must not use icmpv6 protocol as number";
############################################################

$in = <<'END';
network:n1 = { ip = 1000::abcd:0001:0/112;}
protocol:ICMPv6  = proto 58;
END

$out = <<'END';
Error: Must not use 'proto 58', use 'icmpv6' instead at line 2 of STDIN
END

test_err($title, $in, $out, '-ipv6');

############################################################
$title = "Must not use icmp with ipv6";
############################################################

$in = <<'END';
network:n1 = { ip = 1000::abcd:0001:0/112;}
protocol:ICMP  = icmp;
END

$out = <<'END';
Error: Must use 'icmp' only with ipv4 at line 2 of STDIN
END

test_err($title, $in, $out, '-ipv6');

############################################################
 $title = 'Convert and check IPv4 tests';
############################################################

#check_converted_tests($title);
############################################################
done_testing;
