#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
$title = "Protect interface if network behind is accessed";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
END

$out = <<END;
ip access-list extended e0_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit tcp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 established
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Protect all interfaces";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; dst = any:[network:N]; prt = tcp 80;
}
END

$out = <<END;
ip access-list extended e0_in
 deny ip any host 10.1.1.1
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 any eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Protect interfaces matching object group";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = NX-OS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:l4 = { ip = 10.2.2.4; loopback; subnet_of = network:N2; hardware = lo4; }
 interface:l5 = { ip = 10.2.3.4; loopback; subnet_of = network:N3; hardware = lo5; }
 interface:l6 = { ip = 10.2.4.4; loopback; subnet_of = network:N4; hardware = lo6; }
 interface:N2 = { ip = 10.2.2.1; hardware = e1; }
 interface:N3 = { ip = 10.2.3.1; hardware = e1; }
 interface:N4 = { ip = 10.2.4.1; hardware = e1; }
}
network:N2 = { ip = 10.2.2.0/24; }
network:N3 = { ip = 10.2.3.0/24; }
network:N4 = { ip = 10.2.4.0/24; }

service:test = {
    user = network:N2, network:N3, network:N4;
    permit src = network:U; dst = user; prt = tcp 80;
}
END

$out = <<END;
object-group ip address g0
 10 10.2.2.0/24
 20 10.2.3.0/24
 30 10.2.4.0/24
ip access-list e0_in
 10 deny ip any host 10.2.2.4
 20 deny ip any host 10.2.3.4
 30 deny ip any host 10.2.4.4
 40 deny ip any host 10.2.2.1
 50 deny ip any host 10.2.3.1
 60 deny ip any host 10.2.4.1
 70 permit tcp 10.1.1.0/24 addrgroup g0 eq 80
 80 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Protect interfaces matching aggregate";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; dst = any:[ip=10.2.0.0/16 & network:N]; prt = tcp 80;
}
END

$out = <<END;
ip access-list extended e0_in
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.0.0 0.0.255.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Skip protection if permit any to interface";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}

service:any = {
 user = any:[network:U];
 permit src = user; dst = interface:R.N; prt = ip;
}
END

$out = <<END;
ip access-list extended e0_in
 permit ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "VIP doesn't need protection";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = ACE;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:V = { ip = 10.3.3.3; vip; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = any:[network:N], any:[interface:R.V];
    permit src = network:U; dst = user; prt = tcp 80;
}
END

$out = <<END;
access-list e0_in extended deny ip any host 10.1.1.1
access-list e0_in extended deny ip any host 10.2.2.1
access-list e0_in extended permit tcp 10.1.1.0 255.255.255.0 any eq 80
access-list e0_in extended deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Protect interfaces of crosslink cluster";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R1 = {
 managed; 
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:C = { ip = 10.9.9.1; hardware = e1; }
}
network:C = { ip = 10.9.9.0/29; crosslink; }
router:R2 = {
 managed; 
 model = IOS;
 interface:C = { ip = 10.9.9.2; hardware = e2; }
 interface:N = { ip = 10.2.2.1; hardware = e3; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; 
           dst = any:[network:N], any:[network:C]; 
           prt = tcp 80;
}
END

$out = <<END;
ip access-list extended e0_in
 deny ip any host 10.1.1.1
 deny ip any host 10.9.9.1
 deny ip any host 10.9.9.2
 deny ip any host 10.2.2.1
 permit tcp 10.1.1.0 0.0.0.255 any eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Protect interfaces of mixed crosslink cluster";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R1 = {
 managed; 
 model = ASA;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:C = { ip = 10.9.9.1; hardware = e1; }
}
area:CVN = { border = interface:R1.C; }
network:C = { ip = 10.9.9.0/29; crosslink; }
router:R2 = {
 managed; 
 model = ACE;
 interface:C = { ip = 10.9.9.2; hardware = e2; }
 interface:V = { ip = 10.3.3.3; vip; }
 interface:N = { ip = 10.2.2.1; hardware = e3; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; 
    dst = any:[area:CVN];
           prt = tcp 80;
}
END

$out = <<END;
access-list e0_in extended deny ip any host 10.9.9.2
access-list e0_in extended deny ip any host 10.2.2.1
access-list e0_in extended permit tcp 10.1.1.0 255.255.255.0 any eq 80
access-list e0_in extended deny ip any any
access-group e0_in in interface e0
--
access-list e3_in extended deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = "Protect NAT interface";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; bind_nat = N; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; nat:N = { ip = 10.9.9.0/24; } }

service:test = {
    user = network:U;
    permit src = user; dst = network:N; prt = tcp 80;
}
END

$out = <<END;
ip access-list extended e0_in
 deny ip any host 10.9.9.1
 permit tcp 10.1.1.0 0.0.0.255 10.9.9.0 0.0.0.255 eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
done_testing;
