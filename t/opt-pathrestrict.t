#!/usr/bin/perl

# Enable printing of diagnostic messages.
use constant SHOW_DIAG => 1;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

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
END

$out = <<"END";
DIAG: Optimized pathrestriction:p1
DIAG: Optimized pathrestriction:p2
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

END

$out = <<"END";
DIAG: Removed pathrestriction:p1; is subset of pathrestriction:p2
DIAG: Removed pathrestriction:p2; is subset of pathrestriction:p5
DIAG: Can\'t optimize pathrestriction:p3; has only 1 partition
DIAG: Optimized but preserved pathrestriction:p4; has 1 interior
DIAG: Optimized but preserved pathrestriction:p5; has 1 interior
DIAG: Optimized pathrestriction:p6
END

test_warn($title, $in, $out);

###########################################################
done_testing;
