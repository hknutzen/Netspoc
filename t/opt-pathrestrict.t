#!/usr/bin/perl

# Enable printing of diagnostic messages.
use constant SHOW_DIAG => 1;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Optimize simple pathrestriction';
############################################################
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}

pathrestriction:p1 =
 interface:r1.n1,
 interface:r2.n1,
;
pathrestriction:p2 =
 interface:r1.n1,
 interface:r1.n2,
;

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n2;
 permit src = user; dst = interface:r2.n2; prt = tcp 22;
}
END

$out = <<"END";
DIAG: Optimized pathrestriction:p1
DIAG: Optimized pathrestriction:p2
--r1
ip access-list extended n1_in
 deny ip any any
--r2
ip access-list extended n1_in
 deny ip any host 10.1.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 eq 80
 deny ip any any
--
ip access-list extended n2_in
 permit tcp host 10.1.2.1 host 10.1.2.2 eq 22
 deny ip any any
END

test_warn($title, $in, $out);

############################################################
$title = 'Optimize and remove complex pathrestrictions';
############################################################
$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24;}
network:n4 = { ip = 10.1.4.0/24;}
network:n5 = { ip = 10.1.5.0/24;}

router:r1 = {
 managed;
 model = IOS, FW;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:r2 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

router:r3 = {
 managed;
 model = IOS, FW;
 interface:n2 = { ip = 10.1.2.3; hardware = n2; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

router:r4 = {
 managed;
 model = IOS, FW;
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }

}

pathrestriction:p1 =
 interface:r1.n3,
 interface:r4.n4,
;

pathrestriction:p2 =
 interface:r1.n3,
 interface:r4.n4,
 interface:r4.n5,
;

pathrestriction:p3 =
 interface:r1.n3,
 interface:r3.n2,
;

pathrestriction:p4 =
 interface:r1.n3,
 interface:r3.n4,
 interface:r4.n3,
;

pathrestriction:p5 =
 interface:r1.n3,
 interface:r3.n4,
 interface:r4.n4,
 interface:r4.n5,
;

pathrestriction:p6 =
 interface:r1.n2,
 interface:r2.n2,
 interface:r3.n2,
;

service:s1 = {
 user = interface:r4.n5;
 permit src = user; dst = network:n4; prt = tcp 80;
 permit src = network:n4; dst = user; prt = tcp 81;
}
END

$out = <<"END";
DIAG: Removed pathrestriction:p1; is subset of pathrestriction:p2
DIAG: Removed pathrestriction:p2; is subset of pathrestriction:p5
DIAG: Can\'t optimize pathrestriction:p3; has only 1 partition
DIAG: Optimized but preserved pathrestriction:p4; has 1 interior
DIAG: Optimized but preserved pathrestriction:p5; has 1 interior
DIAG: Optimized pathrestriction:p6
Error: No valid path
 from any:[network:n5]
 to any:[network:n4]
 for rule permit src=interface:r4.n5; dst=network:n4; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
Error: No valid path
 from interface:r4.n5
 to any:[network:n4]
 for rule permit src=interface:r4.n5; dst=network:n4; prt=tcp 80; of service:s1
 Check path restrictions and crypto interfaces.
Error: No valid path
 from any:[network:n4]
 to interface:r4.n5
 for rule permit src=network:n4; dst=interface:r4.n5; prt=tcp 81; of service:s1
 Check path restrictions and crypto interfaces.
END

test_err($title, $in, $out);

###########################################################
done_testing;
