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
 permit tcp 1000::abcd:1:0 ::ffff 1000::abcd:2:0 ::ffff range 80 90
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
 permit tcp 1000:: 0:ffff:ffff:ffff:ffff:ffff:ffff:ffff 2000:: ::ffff:ffff:ffff:ffff:ffff range 80 90
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
 permit tcp 1000::abcd:1:0 ::ffff 1000::abcd:2:0 ::ffff range 80 90
 deny ip any any
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
 $title = 'Convert and check IPv4 tests';
############################################################

#check_converted_tests($title);
############################################################
done_testing;
