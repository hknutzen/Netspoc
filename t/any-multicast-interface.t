#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out1, $head1, $out2, $head2, $out3, $head3);

############################################################
$title = "Interface with DHCP server";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = IOS;
 interface:U = { ip = 10.1.1.1; hardware = e0; dhcp_server; }
}
END

$out1 = <<END;
ip access-list extended e0_in
 permit udp any any eq 67
 deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = "Interface with OSPF";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = ACE;
 interface:U = { ip = 10.1.1.1; hardware = e0; routing = OSPF; }
}
END

$out1 = <<END;
access-list e0_in extended permit 89 10.1.1.0 255.255.255.0 host 224.0.0.5
access-list e0_in extended permit 89 10.1.1.0 255.255.255.0 host 224.0.0.6
access-list e0_in extended permit 89 10.1.1.0 255.255.255.0 10.1.1.0 255.255.255.0
access-list e0_in extended deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
$title = "Interface with HSRP";
############################################################

$in = <<END;
network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = ACE;
 interface:U = { 
  ip = 10.1.1.2; 
  virtual = { ip = 10.1.1.1; type = HSRP; }
  hardware = e0; 
 }
}
END

$out1 = <<END;
access-list e0_in extended permit udp 10.1.1.0 255.255.255.0 host 224.0.0.2 eq 1985
access-list e0_in extended deny ip any any
END

$head1 = (split /\n/, $out1)[0];

eq_or_diff(get_block(compile($in), $head1), $out1, $title);

############################################################
done_testing;
