#!perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out);

############################################################
$title = 'Check for owners with duplicate alias names';
############################################################

$in = <<'END';
owner:xx = {
 alias = X Quadrat;
 admins = a@b.c;
}

owner:x2 = {
 alias = X Quadrat;
 admins = a@b.c;
}
END

$out = <<'END';
Error: Name conflict between owners
 - owner:xx with alias 'X Quadrat'
 - owner:x2 with alias 'X Quadrat'
Error: Topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Check for owners with conflicting name and alias name';
############################################################

$in = <<'END';
owner:yy = {
 alias = z;
 admins = a@b.c;
}

owner:z = {
 admins = a@b.c;
}
END

$out = <<'END';
Error: Name conflict between owners
 - owner:z
 - owner:yy with alias 'z'
Error: Topology seems to be empty
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Owner at bridged network';
############################################################

$in = <<'END';
owner:xx = {
 admins = a@b.c;
}

area:all = { owner = xx; anchor = network:VLAN_40_41/40; }

network:VLAN_40_41/40 = { ip = 10.2.1.96/28; }

router:asa = {
 managed;
 model = ASA;

 interface:VLAN_40_41/40 = { hardware = outside; }
 interface:VLAN_40_41/41 = { hardware = inside; }
 interface:VLAN_40_41 = { ip = 10.2.1.99; hardware = device; }
}

network:VLAN_40_41/41 = { ip = 10.2.1.96/28; }

service:test = {
 user = network:VLAN_40_41/40;
 permit src = user; 
        dst = interface:asa.VLAN_40_41; 
        prt = ip;
}
END

$out = '';

test_err($title, $in, $out);

############################################################
$title = 'Redundant owner at bridged network';
############################################################

$in =~ s|(network:VLAN_40_41/41 = \{)|$1 owner = xx; |;

$out = <<'END';
Warning: Useless owner:xx at any:[network:VLAN_40_41/41],
 it was already inherited from area:all
END

test_err($title, $in, $out);

############################################################
$title = 'Redundant owner at nested areas';
############################################################

$in = <<'END';
owner:x = {
 admins = a@b.c;
}

# a3 < a2 < all, a1 < all
area:all = { owner = x; anchor = network:n1; }
area:a1 = { owner = x; border = interface:asa1.n1; }
area:a2 = { owner = x; border = interface:asa1.n2; }
area:a3 = { owner = x; border = interface:asa2.n3; }

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = vlan2; }
 interface:n3 = { ip = 10.1.3.2; hardware = vlan3; }
}
END

$out = <<'END';
Warning: Useless owner:x at area:a1,
 it was already inherited from area:all
Warning: Useless owner:x at area:a2,
 it was already inherited from area:all
Warning: Useless owner:x at area:a3,
 it was already inherited from area:a2
END

test_err($title, $in, $out);

############################################################
$title = 'Owner at vip interface';
############################################################

$in = <<'END';
owner:x = { admins = x@a.b; }
owner:y = { admins = y@a.b; }

network:U = { ip = 10.1.1.0/24; }
router:R = {
 managed; 
 model = ACE;
 owner = x;
 interface:U = { ip = 10.1.1.1; hardware = e0; }
 interface:V = { ip = 10.3.3.3; vip; owner = y; }
 interface:N = { ip = 10.2.2.1; hardware = e1; }
}
network:N = { ip = 10.2.2.0/24; }

service:test = {
    user = network:U;
    permit src = user; dst = interface:R.V, interface:R.U; prt = tcp 80;
}
END

$out = <<'END';
Warning: service:test has multiple owners:
 x, y
END

test_err($title, $in, $out);

############################################################
done_testing;
