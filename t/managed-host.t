#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out1, $head1, $out2, $head2, $out3, $head3);

############################################################
$title = 'Access managed host from enclosing network';
############################################################

$in = <<END;
network:N = {
 ip = 10.1.1.0/24; 
 host:h1 = { managed; model = Linux; ip = 10.1.1.11; hardware = eth0; }
}

service:test = {
 user = network:N;
 permit src = user; dst = host:h1; prt = tcp 80;
}
END

$out1 = <<END;
:eth0_self -
-A INPUT -j eth0_self -i eth0
-A eth0_self -j ACCEPT -s 10.1.1.0/24 -d 10.1.1.11 -p tcp --dport 80
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Access from managed host to managed host';
############################################################

$in = <<END;
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

$out1 = <<END;
:eth0_self -
-A INPUT -j eth0_self -i eth0
-A eth0_self -j ACCEPT -s 10.1.1.11 -d 10.1.1.10 -p tcp --dport 80
END

$out2 = <<END;
:eth1_self -
-A INPUT -j eth1_self -i eth1
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = 'Automatically add managed host to destination network';
############################################################

$in = <<END;
network:N = {
 ip = 10.1.1.0/24; 
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
}

service:test = {
 user = network:N;
 permit src = user; dst = user; prt = tcp 80;
}
END

$out1 = <<END;
:eth0_self -
-A INPUT -j eth0_self -i eth0
-A eth0_self -j ACCEPT -s 10.1.1.0/24 -d 10.1.1.10 -p tcp --dport 80
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Detect duplicate automatic and manual managed host';
############################################################

$in = <<END;
network:N = {
 ip = 10.1.1.0/24; 
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
}

service:test = {
 user = network:N, host:h1;
 permit src = user; dst = user; prt = tcp 80;
}
END

$out1 = <<END;
Warning: Duplicate elements in dst of rule in service:test:
 host:h1
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = 'Automatically add managed host to destination aggregate ';
############################################################

$in = <<END;
network:N = {
 ip = 10.1.1.0/24; 
 host:h1 = { managed; model = Linux; ip = 10.1.1.10; hardware = eth0; }
}

service:test = {
 user = any:[ip=10.0.0.0/8 & network:N];
 permit src = user; dst = user; prt = tcp 80;
}
END

$out1 = <<END;
:eth0_self -
-A INPUT -j eth0_self -i eth0
-A eth0_self -j ACCEPT -s 10.0.0.0/8 -d 10.1.1.10 -p tcp --dport 80
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'Filter managed host in destination aggregate ';
############################################################

$in = <<END;
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

$out1 = <<END;
:eth0_self -
-A INPUT -j eth0_self -i eth0
-A eth0_self -j ACCEPT -s 10.1.1.0/28 -d 10.1.1.10 -p tcp --dport 80
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = 'NAT with managed host';
############################################################

$in = <<END;
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

$out1 = <<END;
:eth0_self -
-A INPUT -j eth0_self -i eth0
-A eth0_self -j ACCEPT -s 10.9.1.0/24 -d 10.1.1.10 -p tcp --dport 22
END

$out2 = <<END;
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.99.99.69 eq 22
access-list Vlan1_in extended deny ip any any
access-group Vlan1_in in interface Vlan1
END

$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

eq_or_diff(get_block(compile($in), $head1, $head2), $out1.$out2, $title);

############################################################
$title = "Automatic managed and unmanaged hosts from network";
############################################################

$in = <<END;
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
$out1 = <<END;
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.1.1.11 eq 81
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.1.1.10 range 81 82
access-list Vlan1_in extended permit tcp 10.9.1.0 255.255.255.0 host 10.1.1.11 eq 83
access-list Vlan1_in extended deny ip any any
access-group Vlan1_in in interface Vlan1
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = "Managed host doesn't count as full filter";
############################################################

$in = <<END;
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

# Interface addresses aren't optimized into subnet currently.
$out1 = <<END;
object-group network g0
 network-object host 10.1.1.10
 network-object host 10.1.1.11
access-list Vlan2_in extended permit tcp object-group g0 10.9.1.0 255.255.255.0 eq 22
access-list Vlan2_in extended deny ip any any
access-group Vlan2_in in interface Vlan2
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = "Managed host must use standard filter";
############################################################

$in = <<END;
network:N = {
 ip = 10.1.1.0/24; 
 host:h1 = { managed = secondary; model = Linux; ip = 10.1.1.11; hardware = eth0; }
}
END

$out1 = <<END;
Error: Only \'managed=standard\' is supported at line 3 of STDIN
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
$title = "Duplicate IP address";
############################################################

$in = <<END;
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
$out1 = <<END;
Error: Duplicate IP address for host:h1 and interface:R.N
Error: Duplicate IP address for host:h1 and host:h2
Error: Duplicate IP address for host:h1 and host:h3
END

eq_or_diff(compile_err($in), $out1, $title);

############################################################
done_testing;
