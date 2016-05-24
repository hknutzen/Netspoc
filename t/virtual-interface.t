#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $topo, $in, $out);

############################################################
$title = 'Virtual interface in non cyclic sub-graph';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; virtual = { ip = 10.1.1.1; } hardware = n1; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; virtual = { ip = 10.1.1.1; } hardware = n1; }
}
END

$out = <<'END';
Error: interface:r1.n1.virtual must be located inside cyclic sub-graph
Error: interface:r2.n1.virtual must be located inside cyclic sub-graph
END

test_err($title, $in, $out);

############################################################
$title = 'Different protocol / id at related virtual interfaces';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { 
  ip = 10.1.1.2; 
  virtual = { ip = 10.1.1.1; type = HSRP; } 
  hardware = n1; 
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.3;
  virtual = { ip = 10.1.1.1; type = VRRP; id = 123; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
END

$out = <<'END';
Error: Must use identical redundancy protocol at
 - interface:r1.n1.virtual
 - interface:r2.n1.virtual
Error: Must use identical ID at
 - interface:r1.n1.virtual
 - interface:r2.n1.virtual
END

test_err($title, $in, $out);

############################################################
$title = 'Identical id at unrelated virtual interfaces';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { 
  ip = 10.1.1.1; 
  virtual = { ip = 10.1.1.11; type = HSRP; id = 11;} 
  hardware = n1; 
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.11; type = HSRP; id = 11; }
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

router:r3 = {
 managed;
 model = ASA;
 interface:n1 = { 
  ip = 10.1.1.3; 
  virtual = { ip = 10.1.1.31; type = HSRP; id = 11; } 
  hardware = n1; 
 }
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.4;
  virtual = { ip = 10.1.1.41; type = VRRP; id = 11; } # no conflict with HSRP
  hardware = n1;
 }
 interface:n2 = { ip = 10.1.2.4; hardware = n2; }
}
END

$out = <<'END';
Error: Must use different ID at unrelated
 - interface:r1.n1.virtual
 - interface:r3.n1.virtual
END

test_err($title, $in, $out);

############################################################

done_testing;
