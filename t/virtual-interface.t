#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

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
$title = 'Routers connecting networks with virtual interfaces';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.2.2.0/24;}
network:n3 = { ip = 10.3.3.0/24;}
network:n4 = { ip = 10.4.4.0/24;}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; hardware = E1;}
 interface:n2 = {ip = 10.2.2.1; hardware = E2;}
}

router:r2 = {
 managed;
 model = ASA;
 interface:n2 = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E3;}
 interface:n3 = {ip = 10.3.3.1; virtual = {ip = 10.3.3.9;} hardware = E4;}
}

router:r3 = {
 managed;
 model = ASA;
 interface:n2 = {ip = 10.2.2.3; virtual = {ip = 10.2.2.9;} hardware = E5;}
 interface:n3 = {ip = 10.3.3.2; virtual = {ip = 10.3.3.9;} hardware = E6;}
}

router:r4 = {
 model = ASA;
 managed;
 interface:n3 = {ip = 10.3.3.3; hardware = E7;}
 interface:n4 = {ip = 10.4.4.1; hardware = E8;}
}

service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
END

$out = <<'END';
--r1
route E2 10.4.4.0 255.255.255.0 10.2.2.9
--r4
route E7 10.1.1.0 255.255.255.0 10.3.3.9
END

test_run($title, $in, $out);

############################################################
$title = 'Virtual interfaces causing several routes on backward path';
############################################################

$in =~ s/virtual = \{ip = 10.3.3.9;\}//g;

$out = <<'END';
Warning: Two static routes for network:n1
 at interface:r4.n3 via interface:r3.n3 and interface:r2.n3
END

test_warn($title, $in, $out);

############################################################

done_testing;
