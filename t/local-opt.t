#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Aggregates with identcal IP';
############################################################

$in = <<'END';
network:N1 = { ip = 10.4.6.0/24;}

router:R1 = {
 managed;
 model = IOS, FW;
 interface:N1 = {ip = 10.4.6.3;hardware = Vlan1;}
 interface:T1 = {ip = 10.6.8.46;hardware = Vlan2;}
}
network:T1 = { ip = 10.6.8.44/30;}

router:U = {
 interface:T1 = {ip = 10.6.8.45;}
 interface:T2 = {ip = 10.6.8.1;}
}
network:T2 = { ip = 10.6.8.0/30;}

router:R2 = {
 managed;
 model = IOS, FW;
 interface:T2 = {ip = 10.6.8.2;hardware = Vlan3;}
 interface:N2 = {ip = 10.5.1.1;hardware = Vlan4;}
}
network:N2 = {ip = 10.5.1.0/30;}

any:ANY_G27 = {ip = 0.0.0.0/0; link = network:T1;}

service:Test = {
 user = network:N1;
 permit src = user;	
	dst = any:ANY_G27, any:[ip = 0.0.0.0/0 & network:N2];
	prt = tcp 80;
}
END

$out = <<'END';
--R1
ip access-list extended Vlan1_in
 deny ip any host 10.4.6.3
 deny ip any host 10.6.8.46
 permit tcp 10.4.6.0 0.0.0.255 any eq 80
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Aggregates in subnet relation';
############################################################

$in =~ s|ip = 0.0.0.0/0 &|ip = 10.0.0.0/8 &|;

test_run($title, $in, $out);

############################################################
$title = 'Redundant port';
############################################################

$in = <<'END';
network:A = { ip = 10.3.3.120/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}
network:B = { ip = 10.3.3.128/29; nat:C = { ip = 10.2.2.0/24; dynamic; }}

router:ras = {
 managed;
 model = Linux;
 interface:A = { ip = 10.3.3.121; hardware = Fe0; }
 interface:B = { ip = 10.3.3.129; hardware = Fe1; }
 interface:Trans = { ip = 10.1.1.2; bind_nat = C; hardware = Fe2; }
}

network:Trans = { ip = 10.1.1.0/24;}

router:nak = {
 managed;
 model = IOS, FW;
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
! [ ACL ]
ip access-list extended eth0_in
 deny ip any host 10.4.4.1
 permit tcp 10.2.2.0 0.0.0.255 10.4.4.0 0.0.0.255 range 50 60
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Redundant tcp established';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n2-sub = { ip = 10.1.2.129; hardware = n2-sub; }
}

network:n2-sub = { ip = 10.1.2.128/25; subnet_of = network:n2; }

service:s1 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n2-sub; prt = tcp 80;
}

service:s2 = {
 user = network:n2;
 permit src = user; dst = any:[network:n1]; prt = tcp;
}
END

$out = <<'END';
-- r1
ip access-list extended n1_in
 permit tcp any 10.1.2.128 0.0.0.127 eq 80
 permit tcp any 10.1.2.0 0.0.0.255 established
 deny ip any any
--
ip access-list extended n2_in
 deny ip any host 10.1.1.1
 deny ip any host 10.1.2.1
 permit tcp 10.1.2.0 0.0.0.255 any
 deny ip any any
END

test_run($title, $in, $out);

############################################################
$title = 'Redundant host';
############################################################

$in = <<'END';
network:A = { ip = 10.3.3.0/25; host:a = { ip = 10.3.3.3; } }
network:sub = { ip = 10.3.3.8/29; subnet_of = network:A; }

router:secondary = {
 managed = secondary;
 model = IOS, FW;
 routing = manual;
 interface:A = { ip = 10.3.3.1; hardware = VLAN1; }
 interface:sub = { ip = 10.3.3.9; hardware = VLAN9; }
 interface:Trans = { ip = 10.1.1.2; hardware = VLAN2; no_in_acl;}
}

network:Trans = { ip = 10.1.1.0/24; }

router:filter = {
 managed;
 model = ASA;
 interface:Trans = { ip = 10.1.1.1; hardware = VLAN1; bind_nat = dyn; }
 interface:Customer1 = { ip = 10.8.8.1; hardware = VLAN8; }
 interface:Customer2 = { ip = 10.9.9.1; hardware = VLAN9; }
}

network:Customer1 = { ip = 10.8.8.0/24; nat:dyn = { ip = 10.7.7.0/24; dynamic; } }
network:Customer2 = { ip = 10.9.9.0/24; nat:dyn = { ip = 10.7.7.0/24; dynamic; } }

service:test1 = {
 user = host:a;
 permit src = network:Customer1; dst = user; prt = tcp 80;
}

service:test2 = {
 user = network:A;
 permit src = network:Customer2; dst = user; prt = tcp 81;
}
END

$out = <<'END';
--secondary
ip access-list extended VLAN1_out
 permit ip 10.7.7.0 0.0.0.255 10.3.3.0 0.0.0.127
 deny ip any any
END

test_run($title, $in, $out);

# Change order of rules.
$in =~ s/test2/test0/;
test_run($title, $in, $out);

############################################################
$title = 'Join adjacent and overlapping ports';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-82;
 permit src = user; dst = network:n2; prt = tcp 83-86;
}

service:t2 = {
 user = host:h1;
 permit src = network:n2; dst = user; prt = tcp 70-81;
 permit src = network:n2; dst = user; prt = tcp 82-85;
}
END

$out = <<'END';
-- asa
! [ ACL ]
access-list vlan1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 range 80 86
access-list vlan1_in extended deny ip any any
access-group vlan1_in in interface vlan1
--
access-list vlan2_in extended permit tcp 10.1.2.0 255.255.255.0 host 10.1.1.10 range 70 85
access-list vlan2_in extended deny ip any any
access-group vlan2_in in interface vlan2
END

test_run($title, $in, $out);

############################################################
$title = 'Join multiple adjacent ranges';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-82;
 permit src = user; dst = network:n2; prt = tcp 83-86;
}

service:t2 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 83-90;
}
END

$out = <<'END';
-- asa
! [ ACL ]
access-list vlan1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 range 80 86
access-list vlan1_in extended permit tcp host 10.1.1.10 10.1.2.0 255.255.255.0 range 83 90
access-list vlan1_in extended deny ip any any
access-group vlan1_in in interface vlan1
END

test_run($title, $in, $out);

############################################################
$title = 'Don\'t join adjacent TCP and UDP ports';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:asa = {
 managed;
 model = ASA;
 log:a = warnings;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
 permit src = user; dst = network:n2; prt = udp 81;
}

service:t2 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = udp 80;
 permit src = user; dst = network:n2; prt = tcp 81;
}
END

$out = <<'END';
-- asa
! [ ACL ]
access-list vlan1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list vlan1_in extended permit udp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 81
access-list vlan1_in extended permit udp host 10.1.1.10 10.1.2.0 255.255.255.0 eq 80
access-list vlan1_in extended permit tcp host 10.1.1.10 10.1.2.0 255.255.255.0 eq 81
access-list vlan1_in extended deny ip any any
access-group vlan1_in in interface vlan1
END

test_run($title, $in, $out);

############################################################
done_testing;
