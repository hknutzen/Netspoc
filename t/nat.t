#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3, $compiled);

############################################################
$title = 'Multiple dynamic NAT at ASA';
############################################################

# Soll nur einen nat-Index pro Interface verwenden.

$in = <<END;
network:Test =  { 
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.1/32; dynamic;} 
 nat:D = { ip = 9.9.9.8/30; dynamic;} 
}

router:filter = {
 managed;
 model = ASA;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.2.1; hardware = outside; bind_nat = C;}
 interface:Y = { ip = 10.9.3.1; hardware = DMZ50; bind_nat = C;}
 interface:Z = { ip = 10.9.4.1; hardware = DMZ70; bind_nat = D;}
}

network:X = { ip = 10.9.2.0/24; }
network:Y = { ip = 10.9.3.0/24; }
network:Z = { ip = 10.9.4.0/24; }

protocol:IP = ip;

service:test = {
 user = network:X, network:Y, network:Z;
 permit src = user; 
	dst = network:Test;
	prt = protocol:IP;
}
END

$out1 = <<END;
! [ NAT ]
global (outside) 1 1.1.1.1 netmask 255.255.255.255
nat (inside) 1 10.9.1.0 255.255.255.0
global (DMZ50) 1 1.1.1.1 netmask 255.255.255.255
global (DMZ70) 1 9.9.9.8-9.9.9.11 netmask 255.255.255.252
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Multiple dynamic NAT at ASA 8.4';
############################################################

# Soll nur einen nat-Index pro Interface verwenden.

$in = <<END;
network:Test =  { 
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.1/32; dynamic;} 
 nat:D = { ip = 9.9.9.8/30; dynamic;} 
}

router:filter = {
 managed;
 model = ASA, 8.4;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.2.1; hardware = outside; bind_nat = C;}
 interface:Y = { ip = 10.9.3.1; hardware = DMZ50; bind_nat = C;}
 interface:Z = { ip = 10.9.4.1; hardware = DMZ70; bind_nat = D;}
}

network:X = { ip = 10.9.2.0/24; }
network:Y = { ip = 10.9.3.0/24; }
network:Z = { ip = 10.9.4.0/24; }

protocol:IP = ip;

service:test = {
 user = network:X, network:Y, network:Z;
 permit src = user; 
	dst = network:Test;
	prt = protocol:IP;
}
END

$out1 = <<END;
! [ NAT ]
object network 10.9.1.0_255.255.255.0
 subnet 10.9.1.0 255.255.255.0
object network 1.1.1.1
 host 1.1.1.1
nat (inside,outside) source dynamic 10.9.1.0_255.255.255.0 1.1.1.1
nat (inside,DMZ50) source dynamic 10.9.1.0_255.255.255.0 1.1.1.1
object network 9.9.9.8-9.9.9.11
 range 9.9.9.8 9.9.9.11
nat (inside,DMZ70) source dynamic 10.9.1.0_255.255.255.0 9.9.9.8-9.9.9.11
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Dynamic NAT for network with static nat for hosts at ASA';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.16/28; dynamic;}
 host:H = { ip = 10.9.1.33; nat:C = { ip = 1.1.1.23; } }
}

router:filter = {
 managed;
 model = ASA;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.3.1; hardware = outside; bind_nat = C;}
}

network:X = { ip = 10.9.3.0/24; }

service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = ip;
 permit src = host:H; dst = user;         prt = tcp 80;
 permit src = user;   dst = network:Test; prt = tcp 80;
}
END

$out1 = <<END;
access-list inside_in extended permit tcp host 10.9.1.33 10.9.3.0 255.255.255.0 eq 80
access-list inside_in extended deny ip any any
access-group inside_in in interface inside
END

$out2 = <<END;
access-list outside_in extended permit ip 10.9.3.0 255.255.255.0 host 1.1.1.23
access-list outside_in extended permit tcp 10.9.3.0 255.255.255.0 1.1.1.16 255.255.255.240 eq 80
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

$out3 = <<END;
! [ NAT ]
static (inside,outside) 1.1.1.23 10.9.1.33 netmask 255.255.255.255
global (outside) 1 1.1.1.16-1.1.1.31 netmask 255.255.255.240
nat (inside) 1 10.9.1.0 255.255.255.0
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];
$head3 = (split /\n/, $out3)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);
eq_or_diff(get_block(compile($in), $head2), $out2, $title);
eq_or_diff(get_block(compile($in), $head3), $out3, $title);

############################################################
$title = 'NAT at ASA 8.4';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.1.1.16/28; dynamic;}
 host:H = { ip = 10.9.1.33; nat:C = { ip = 1.1.1.23; } }
}

router:filter = {
 managed;
 model = ASA, 8.4;
 interface:Test = {
  ip = 10.9.1.1;
  hardware = inside;
 }
 interface:X = { ip = 10.9.3.1; hardware = outside; bind_nat = C;}
}

network:X = { ip = 10.9.3.0/24; }

protocol:IP = ip;
protocol:HTTP = tcp 80;

service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = protocol:IP;
 permit src = host:H; dst = user;         prt = protocol:HTTP;
 permit src = user;   dst = network:Test; prt = protocol:HTTP;
}
END

$out1 = <<END;
! [ NAT ]
object network 10.9.1.33_255.255.255.255
 subnet 10.9.1.33 255.255.255.255
object network 1.1.1.23_255.255.255.255
 subnet 1.1.1.23 255.255.255.255
nat (inside,outside) 1 source static 10.9.1.33_255.255.255.255 1.1.1.23_255.255.255.255
object network 10.9.1.0_255.255.255.0
 subnet 10.9.1.0 255.255.255.0
object network 1.1.1.16-1.1.1.31
 range 1.1.1.16 1.1.1.31
nat (inside,outside) source dynamic 10.9.1.0_255.255.255.0 1.1.1.16-1.1.1.31
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Check rule with any to hidden NAT';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.0.0.0/24; 
 nat:C = { hidden; }
}

router:filter = {
 managed;
 model = ASA, 8.4;
 interface:Test = { ip = 10.0.0.2; hardware = inside; }
 interface:X = { ip = 10.8.3.1; hardware = outside; bind_nat = C; }
}

network:X = { ip = 10.8.3.0/24; }

service:test = {
 user = any:[network:X];
 permit src = user; dst = network:Test; prt = tcp 80;
}
END

$out1 = <<END;
Error: network:Test is hidden by NAT in rule
 permit src=any:[network:X]; dst=network:Test; prt=tcp 80; of service:test
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Check rule with host and dynamic NAT';
############################################################

$in = <<END;
network:Test =  {
 ip = 10.9.1.0/24; 
 nat:C = { ip = 1.9.2.0; dynamic;}
 host:H = { ip = 10.9.1.33; }
}

router:C = {
 managed; #1
 model = ASA;
 interface:Test = { ip = 10.9.1.1; hardware = inside;}
 interface:Trans = { ip = 10.0.0.1; hardware = outside; bind_nat = C;}
}
network:Trans = { ip = 10.0.0.0/24; }
router:filter = {
 managed;
 model = ASA;
 interface:Trans = {
  ip = 10.0.0.2;
  hardware = inside;
 }
 interface:X = { ip = 10.8.3.1; hardware = outside; }
}

network:X = { ip = 10.8.3.0/24; }

service:test = {
 user = network:X;
 permit src = user;   dst = host:H;       prt = tcp 80;
 permit src = host:H; dst = user;         prt = tcp 80;
}
END

$out1 = <<END;
Error: host:H needs static translation for nat:C to be valid in rule
 permit src=network:X; dst=host:H; prt=tcp 80; of service:test
END

eq_or_diff(compile_err($in), $out1, $title);

$in =~ s/managed; \#1//;
$out1 = <<END;
Error: host:H needs static translation for nat:C to be valid in rule
 permit src=network:X; dst=host:H; prt=tcp 80; of service:test
Error: host:H needs static translation for nat:C to be valid in rule
 permit src=host:H; dst=network:X; prt=tcp 80; of service:test
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'NAT from overlapping areas';
############################################################

$in = <<END;
area:A = {
 border = interface:r1.a1;
 nat:hide = { ip = 10.99.99.8/30; dynamic; }
}
area:B = {
 border = interface:r2.b1;
 nat:hide = { hidden; }
}

network:a1 = { ip = 10.4.4.0/24; }
router:r1 =  {
 managed;
 model = ASA;
 routing = manual;
 interface:a1 = { ip = 10.4.4.1; hardware = e1; }
 interface:b1 = { ip = 10.2.2.1; hardware = e0; }
}
network:b2 = { ip = 10.3.3.0/24; }
router:u = { interface:b2; interface:b1; }
network:b1 = { ip = 10.2.2.0/24; nat:hide = { identity; } }
router:r2 = {
 managed;
 model = IOS,FW;
 routing = manual;
 interface:b1 = { ip = 10.2.2.2; hardware = e0; }
 interface:X = { ip = 10.1.1.2; hardware = e1; bind_nat = hide; }
}
network:X = { ip = 10.1.1.0/24; }

service:test = {
 user = network:a1, network:b1; #, network:b2;
 permit src = network:X; dst = user; prt = tcp 80;
}
END

$out1 = <<END;
access-list e0_in extended permit tcp 10.1.1.0 255.255.255.0 10.4.4.0 255.255.255.0 eq 80
access-list e0_in extended deny ip any any
access-group e0_in in interface e0
END

$out2 = <<END;
ip access-list extended e1_in
 deny ip any host 10.2.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.99.99.8 0.0.0.3 eq 80
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 80
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

$compiled = compile($in);
eq_or_diff(get_block($compiled, $head1), $out1, $title);
eq_or_diff(get_block($compiled, $head2), $out2, $title);

############################################################
$title = 'Use hidden NAT from overlapping areas';
############################################################

$in =~ s/; #//;

$out1 = <<END;
Error: network:b2 is hidden by NAT in rule
 permit src=network:X; dst=network:b2; prt=tcp 80; of service:test
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Interface with dynamic NAT as destination';
############################################################

$in = <<END;
network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS;
 interface:a = {ip = 10.1.1.1; hardware = E1; bind_nat = b;}
 interface:t = {ip = 10.4.4.1; hardware = E2;}
}
network:t = { ip = 10.4.4.0/30; }
router:r2 = {
 interface:t = {ip = 10.4.4.2;}
 interface:b = {ip = 10.2.2.1;}
}

network:b  = { ip = 10.2.2.0/24; nat:b = { ip = 10.9.9.4/30; dynamic; } }

service:test = {
 user = interface:r2.b;
 permit src = user; dst = network:a; prt = tcp 80;
}
END

$out1 = <<END;
Error: interface:r2.b needs static translation for nat:b to be valid in rule
 permit src=network:a; dst=interface:r2.b; prt=reverse:TCP_ANY; stateless
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
done_testing;
