#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

############################################################
my $title = 'Merge port range with sub-range for iptables';
############################################################

my $in = <<END;
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

service:TCP_30-37 = tcp 30-37;
service:TCP_40-47 = tcp 40-47;
service:TCP_51-53 = tcp 51-53;
policy:p40-47 = {
 user = network:Firewall, network:RAS;
 permit src = user; 
	dst = network:Hosting;
	srv = service:TCP_30-37, service:TCP_51-53;
}

service:TCP_10-49 = tcp 10-49;
service:TCP_50-60 = tcp 50-60;
policy:p10-60 = {
 user = network:Trans, network:StPeter, network:Hoernum;
 permit src = user;
        dst = network:Hosting;
        srv = service:TCP_10-49, service:TCP_50-60;
}
END

my $out1 = <<END;
-A droplog -j LOG --log-level debug
-A droplog -j DROP
-A c1 -j ACCEPT -s 10.3.3.128/29
-A c1 -j ACCEPT -s 10.3.3.120/29
-A c2 -g c1 -s 10.3.3.0/24
-A c2 -j ACCEPT -s 10.1.1.0/24
-A c3 -j ACCEPT -s 193.1.1.0/24
-A c3 -j ACCEPT -s 10.2.2.0/24
-A c4 -j c2 -s 10.0.0.0/14 -p tcp --dport 10:60
-A c4 -g c3 -p tcp --dport 51:53
-A c4 -g c3 -p tcp --dport 30:37
END

my $out2 = <<END;
:eth0_br0 -
-A FORWARD -j eth0_br0 -i eth0 -o br0
-A eth0_br0 -g c4 -d 10.4.4.0/24 -p tcp --dport 10:60
END


my $head1 = (split /\n/, $out1)[0];
my $head2 = (split /\n/, $out2)[0];

my $compiled = compile($in);
eq_or_diff(get_block($compiled, $head1), $out1, $title);
eq_or_diff(get_block($compiled, $head2), $out2, $title);

############################################################
$title = 'Un-merged port range with sub-range for iptables';
############################################################

# Ranges 10-49 and 50-60 can't be merged,
# because they have three childs 30-37,40-47,51-53
# and a merged range can have at most two childs.
$in =~ s/(service:TCP_30-37,) (service:TCP_51-53)/$1 service:TCP_40-47, $2/;

$out1 = <<END;
-A droplog -j LOG --log-level debug
-A droplog -j DROP
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
END

$out2 = <<END;
:eth0_br0 -
-A FORWARD -j eth0_br0 -i eth0 -o br0
-A eth0_br0 -g c5 -d 10.4.4.0/24 -p tcp --dport 10:60
END


$head1 = (split /\n/, $out1)[0];
$head2 = (split /\n/, $out2)[0];

$compiled = compile($in);
eq_or_diff(get_block($compiled, $head1), $out1, $title);
eq_or_diff(get_block($compiled, $head2), $out2, $title);


############################################################
done_testing;
