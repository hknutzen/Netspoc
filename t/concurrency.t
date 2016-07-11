#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Pass 1';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = host:h1;
 permit src = user; dst = network:n2; prt = tcp 22;
}
END

# No errors expected.
$out = <<'END';
-- asa1
! n1_in
access-list n1_in extended permit tcp host 10.1.1.10 10.1.2.0 255.255.255.0 eq 22
access-list n1_in extended deny ip any any
access-group n1_in in interface n1
END

test_run($title, $in, $out, '--concurrency_pass1=2');

############################################################
$title = 'Warning from background job';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 policy_distribution_point = host:h1;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
END

# Output is indented
$out = <<'END';
 Warning: Missing rules to reach 1 devices from policy_distribution_point:
  - router:asa1
END

test_warn($title, $in, $out, '--concurrency_pass1=2');

############################################################
$title = 'Error from background job';
############################################################
# Test case copied from virtual-pathrestrict.t

$in = <<'END';
router:g = {
 managed;
 model = ASA;
 interface:a = {ip = 10.1.1.7; hardware = inside;}
}

network:a = { ip = 10.1.1.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; virtual = {ip = 10.1.1.9;} hardware = E1;}
 interface:b1 = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; virtual = {ip = 10.1.1.9;} hardware = E4;}
 interface:b1 = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
 interface:t = { ip = 10.0.0.1; hardware = t1; }
}

network:t = { ip = 10.0.0.0/30; }

router:r3 = {
 managed;
 model = IOS, FW;
 interface:t = { ip = 10.0.0.2; hardware = t1; }
 interface:a = {ip = 10.1.1.3; virtual = {ip = 10.1.1.9;} hardware = E6;}
 interface:b2 = {ip = 10.3.3.3; virtual = {ip = 10.3.3.9;} hardware = E7;}
}

router:r4 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.4; virtual = {ip = 10.1.1.9;} hardware = E8;}
 interface:b2 = {ip = 10.3.3.4; virtual = {ip = 10.3.3.9;} hardware = E9;}
}

network:b1 = { ip = 10.2.2.0/24; }
network:b2 = { ip = 10.3.3.0/24; }

service:test = {
 user = interface:g.a;
 permit src = user; dst = network:b1; prt = tcp 80;
}
END

# Output is indented
$out = <<'END';
 Error: Pathrestriction ambiguously affects generation of static routes
        at interfaces with virtual IP 10.1.1.9:
  network:b1 is reached via
  - interface:r1.a.virtual
  - interface:r2.a.virtual
  - interface:r3.a.virtual
  But 1 interface(s) of group are missing.
  Pathrestrictions must restrict paths to either
  - all interfaces or
  - no interfaces or
  - all but one interface
  of this group.
END

test_err($title, $in, $out, '--concurrency_pass1=2');

############################################################
$title = 'Abort in foreground job';
############################################################
# Don't wait for background job, but exit immediately.

$in = <<'END';
network:n1 =  {
 ip = 10.1.1.0/24; 
}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.1.2; hardware = n2;}
}

network:n2 = { ip = 10.1.1.0/24; }

END

$out = <<'END';
Error: network:n2 and network:n1 have identical IP/mask
 in nat_domain:n1
Aborted after 1 errors
END

test_err($title, $in, $out, '--max_errors=1 --concurrency_pass1=2');

############################################################
$title = 'Pass 2: 3 devices with up to 8 jobs';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.3; hardware = n1; }
}

END

# Expect normal operation with concurrency enabled.
$out = <<'END';
-- asa1
! n1_in
access-list n1_in extended deny ip any any
access-group n1_in in interface n1
-- asa2
! n1_in
access-list n1_in extended deny ip any any
access-group n1_in in interface n1
-- asa3
! n1_in
access-list n1_in extended deny ip any any
access-group n1_in in interface n1
END

test_run($title, $in, $out, '--concurrency_pass2=8');

############################################################
$title = 'Pass 2: 3 devices with 2 jobs';
############################################################

test_run($title, $in, $out, '--concurrency_pass2=2');

############################################################
done_testing;
