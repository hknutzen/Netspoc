#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

sub test_run {
    my ($title, $input, $expected) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    my $cmd = "$^X -I lib bin/cut-netspoc --quiet $filename";
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

my ($title, $in, $out, $topo);
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}

router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
END

############################################################
$title = 'Simple service';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Named aggregate behind unmanaged';
############################################################

$in = $topo . <<'END';
any:n3 = { link = network:n3; }
service:test = {
    user = network:n1;
    permit src = user; dst = any:n3; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
any:n3 = { link = network:n3; }
service:test = {
    user = network:n1;
    permit src = user; dst = any:n3; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Unnamed aggregate behind unmanaged';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n1;
    permit src = user; dst = any:[ip=10.0.0.0/8 & network:n3]; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
service:test = {
    user = network:n1;
    permit src = user; dst = any:[ip=10.0.0.0/8 & network:n3]; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore area with owner';
############################################################

$in = $topo . <<'END';
area:n2 = { border = interface:asa1.n2;  owner = foo; }
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Area with NAT';
############################################################

$in = $topo . <<'END';
area:n2 = { border = interface:asa1.n2; nat:a2 = { ip = 10.9.9.9/32; dynamic; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
area:n2 = { border = interface:asa1.n2; nat:a2 = { ip = 10.9.9.9/32; dynamic; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Useless aggregate';
############################################################

$in = $topo . <<'END';
any:a2 = { link = network:n2; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Aggregate with NAT and owner';
############################################################

$in = $topo . <<'END';
any:a2 = { 
 link = network:n2; 
 nat:a2 = { ip = 10.9.9.9/32; dynamic; }
 owner = foo;
}
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
any:a2 = { 
 link = network:n2; 
 nat:a2 = { ip = 10.9.9.9/32; dynamic; }
 owner = foo;
}
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Used aggregate with owner';
############################################################

$in = <<'END';
any:n1 = { owner = o; link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
owner:o = { admins = a@example.com; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = any:n1; prt = tcp;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Router with reroute_permit';
############################################################

$in = <<'END';
network:n1a = { ip = 10.1.1.64/26; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = vlan1; reroute_permit = network:n1a; }
 interface:n2 = { ip = 10.1.2.1; hardware = vlan2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $in);

############################################################
done_testing;
