#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile /;

# Add "bin/" because cut-netspoc calls cut-netspoc-go in same directory.
$ENV{PATH} = "bin/:$ENV{PATH}";

sub test_run {
    my ($title, $input, $expected, @services) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';

    my $cmd = "$^X $perl_opt -I lib bin/cut-netspoc -q $filename";
    $cmd .= " @services" if @services;
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    local $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

my ($title, $in, $out, $topo);
$topo = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
END

############################################################
$title = 'Simple service, remove all hosts';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Select service on command line, ignore disabled';
############################################################

$in = $topo . <<'END';
service:s1 = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
    user = host:h10;
    permit src = user; dst = network:n2; prt = tcp 81;
}
service:s3= {
    disabled;
    user = host:h10;
    permit src = user; dst = network:n2; prt = tcp 82;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s2 = {
    user = host:h10;
    permit src = user; dst = network:n2; prt = tcp 81;
}
END

test_run($title, $in, $out, 'service:s2 service:s3');

############################################################
$title = 'Simple service, remove one host';
############################################################

$in = $topo . <<'END';
service:test = {
    user = host:h11, host:h12;
    permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = host:h11, host:h12;
    permit src = user; dst = network:n2; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Simple service, remove network and interface';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n1;
    permit src = user; dst = interface:asa1.n1; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = interface:asa1.n1; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Simple service, retain interface and attached network';
############################################################

$in = $topo . <<'END';
service:test = {
    user = network:n2;
    permit src = user; dst = interface:asa1.n1; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = interface:asa1.n1; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Retain identical protocols with different names';
############################################################

$in = $topo . <<'END';
protocol:http = tcp 80;
protocol:www  = tcp 80;

service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = protocol:http;
    permit src = user; dst = network:n3; prt = protocol:www;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
protocol:http = tcp 80;
protocol:www  = tcp 80;
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = protocol:http;
    permit src = user; dst = network:n3; prt = protocol:www;
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
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
    user = host:h10;
    permit src = user; dst = any:[ip=10.0.0.0/8 & network:n3]; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
service:test = {
    user = host:h10;
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
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
area:n2 = { border = interface:asa1.n2; nat:a2 = { ip = 10.9.0.0/16; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
area:n2 = { border = interface:asa1.n2; nat:a2 = { ip = 10.9.0.0/16; } }
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
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
 nat:a2 = { ip = 10.9.0.0/16; }
 unknown_owner = restrict;
 multi_owner = restrict;
 owner = foo;
}
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; bind_nat = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
any:a2 = {
 link = network:n2;
 nat:a2 = { ip = 10.9.0.0/16; }
 unknown_owner = restrict;
 multi_owner = restrict;
}
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Area defined by anchor, anchor ouside of path';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
area:all = { anchor = network:n4; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:test = {
    user = network:[any:[ip = 10.1.1.0/24 & area:all]];
    permit src = user; dst = network:n2; prt = tcp;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Area with border ouside of path';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
area:n1-3 = { inclusive_border = interface:asa3.n4; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:test = {
    user = network:[area:n1-3] &! network:n3 &! network:n2;
    permit src = user; dst = network:n2; prt = tcp;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Zone ouside of path';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;  }
network:n2 = { ip = 10.1.2.0/24;  }
network:n3 = { ip = 10.2.3.0/24;  }
network:n4 = { ip = 10.2.4.0/24;  }
any:n4 = { link = network:n4; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.2.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n3 = { ip = 10.2.3.2; hardware = n3; }
 interface:n4 = { ip = 10.2.4.1; hardware = n4; }
}
area:n2-4 = { inclusive_border = interface:r1.n1; }
service:s1 = {
 user = network:[any:[ip = 10.1.0.0/16 & area:n2-4]];
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

($out = $in) =~ s/^any:n4.*\n//mg;
test_run($title, $in, $out);

############################################################
$title = 'Replace empty area by empty group';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
router:r3 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:un = { unnumbered; hardware = un;
 }
}
network:un = { unnumbered; }

area:a = { inclusive_border = interface:r3.n4; }

service:s1 = {
 user = network:n2, network:[area:a];
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

$out = <<'END';
group:empty-area = ;
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n2, network:[group:empty-area];
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Mark supernet having identity NAT';
############################################################

$in = <<'END';
any:n1 = {
 nat:N = { ip = 10.9.9.0/24; dynamic; }
 link = network:n1;
}
network:n1 = { ip = 10.1.1.0/24;
 nat:N = { identity; }
}
network:n1_sub = {
 ip = 10.1.1.64/26;
 subnet_of = network:n1;
}
network:n1_subsub = {
 ip = 10.1.1.96/27;
 subnet_of = network:n1_sub;
}
router:u = {
 interface:n1;
 interface:n1_sub;
 interface:n1_subsub;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_subsub = { ip = 10.1.1.97; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; } #bind_nat = N; }
}
service:s1 = {
    user = network:n1_subsub;
    permit src = network:n2; dst = user; prt = tcp 80;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Mark networks inside aggregate';
############################################################

$in = <<'END';
network:n0 = { ip = 10.3.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
network:un = { unnumbered; }
any:n1-3 = { ip = 10.1.0.0/16; link = network:un; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n0;
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r2 = {
 interface:n3;
 interface:un;
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:un = { unnumbered; hardware = un; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = any:n1-3;
 permit src = user; dst = network:n4; prt = tcp 80;
}
END

($out = $in) =~ s/^.*:n0.*\n//mg;

test_run($title, $in, $out);

############################################################
$title = 'Matching aggregate without matching network';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24;}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.1; }
}
network:n3 = { ip = 10.1.3.0/24; }
any:10_2_0_0 = { ip = 10.2.0.0/16; link = network:n3; }
service:s1 = {
 user = any:10_2_0_0;
 permit src = network:n1; dst = user; prt = tcp 80;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Mark unmanaged at end of path';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
group:g1 = host:h3, interface:r2.n2;
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Mark 2x unmanaged at end of path';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;  }
network:n2 = { ip = 10.1.2.0/24;  }
network:n3 = { ip = 10.1.3.0/24;  }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2;
 interface:n3;
 interface:L = { ip = 10.9.9.2; loopback; }
}
router:r3 = {
 interface:n3;
 interface:L = { ip = 10.9.9.3; loopback; }
}
service:test = {
 user = interface:r2.L, interface:r3.L;
 permit src = network:n1; dst = user; prt = tcp 22;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Remove interface with multiple IP addresses';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.16/28;}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
}
network:t1 = { ip = 10.9.1.80/28; }
network:t2 = { ip = 10.9.2.80/28; }

router:r2 = {
 interface:t1 = { ip = 10.9.1.83; }
 interface:t2 = { ip = 10.9.2.83, 10.9.2.85; }
 interface:n2;
}

network:n2 = { ip = 10.1.2.0/24; }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.16/28;}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
}
network:t1 = { ip = 10.9.1.80/28; }
router:r2 = {
 interface:t1 = { ip = 10.9.1.83; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Remove interface with virtual address';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = VRRP; }
  hardware = n1;
 }
 interface:lo = {
  virtual = { ip = 10.1.4.1; type = VRRP; }
  loopback;
  hardware = lo;
 }
 interface:n2 = {
  virtual = { ip = 10.1.2.1; type = VRRP; }
  hardware = n2;
 }
 interface:n3 = {
  virtual = { ip = 10.1.3.1; type = VRRP; }
  hardware = n3;
 }
}

service:s1 = {
 user = network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = VRRP; }
  hardware = n1;
 }
 interface:n2 = {
  virtual = { ip = 10.1.2.1; type = VRRP; }
  hardware = n2;
 }
}
service:s1 = {
 user = network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Mark interface, if only virtual is used';
############################################################

$in = <<'END';
network:u = { ip = 10.9.9.0/24; }

router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = 10.9.9.1; hardware = F0;}
 interface:a = {ip = 10.1.1.9; hardware = F1;}
}
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}
network:b  = { ip = 10.2.2.0/24; }
pathrestriction:p = interface:r1.a, interface:r1.b.virtual;
service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
}
END

$out = <<'END';
network:u = { ip = 10.9.9.0/24; }
router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = 10.9.9.1; hardware = F0;}
 interface:a = {ip = 10.1.1.9; hardware = F1;}
}
network:a = { ip = 10.1.1.0/24;}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}
network:b  = { ip = 10.2.2.0/24; }
service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Remove bind_nat only once at interface with virtual';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 1.9.9.2/32; dynamic; } }

router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.1;
  virtual = { ip = 10.1.1.2; }
  hardware = n1;
  bind_nat = n2;
 }
 interface:lo = { ip = 10.9.9.2; loopback; hardware = lo; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.lo; prt = tcp 80;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.1;
  virtual = { ip = 10.1.1.2; }
  hardware = n1;
 }
 interface:lo = { ip = 10.9.9.2; loopback; hardware = lo; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.lo; prt = tcp 80;
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
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = any:n1; prt = tcp;
}
END

$out = <<'END';
any:n1 = { link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = any:n1; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Owner at network and host';
############################################################

$in = <<'END';
owner:o1 = { admins = a@example.com; watchers = b@example.com, c@example.com; }
owner:o2 = { admins = b@example.com; }
owner:o3 = { admins = c@example.com; }
owner:o4 = { admins = d@example.com; watchers = e@example.com; }
network:n1 = { ip = 10.1.1.0/24; owner = o1;
 host:h10 = { ip = 10.1.1.10; owner = o2;}
 host:h11 = { ip = 10.1.1.11;
 # owner =
 owner = o3;
 }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = host:h11;
    permit src = user; dst = network:n2; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h11 = { ip = 10.1.1.11;
 # owner =
 }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = host:h11;
    permit src = user; dst = network:n2; prt = tcp;
}
END


test_run($title, $in, $out);

############################################################
$title = 'Cleanup sub_owner';
############################################################

$in = <<'END';
owner:o1 = { admins = a@example.com; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    sub_owner = o1;
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
END


test_run($title, $in, $out);

############################################################
$title = 'Cleanup policy_distribution_point';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; host:h10 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
  policy_distribution_point = host:h10;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Cleanup pathrestriction';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
}
pathrestriction:p = interface:r1.n1, interface:r2.n3, interface:r3.n3;
service:test = {
    user = network:n1, network:n2;
    permit src = user; dst = network:n3; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
pathrestriction:p =
 interface:r1.n1,
 interface:r2.n3,
;
service:test = {
    user = network:n1, network:n2;
    permit src = user; dst = network:n3; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Cleanup reroute_permit';
############################################################

$in = <<'END';
network:n1a = { ip = 10.1.1.64/27; subnet_of = network:n1; }
network:n1b = { ip = 10.1.1.96/27; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; reroute_permit = network:n1a, network:n1b; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1b;
    permit src = user; dst = network:n2; prt = tcp;
}
END

$out = <<'END';
network:n1b = { ip = 10.1.1.96/27; subnet_of = network:n1; }
router:u = {
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; reroute_permit = network:n1b; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1b;
    permit src = user; dst = network:n2; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Remove reroute_permit';
############################################################

$in = <<'END';
network:n1a = { ip = 10.1.1.64/27; subnet_of = network:n1; }
network:n1b = { ip = 10.1.1.96/27; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; reroute_permit = network:n1a, network:n1b; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Remove router_attributes';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

area:a = {
 inclusive_border = interface:r1.n2;
 router_attributes = {
  general_permit = icmp 0, icmp 3, icmp 11;
 }
 nat:h = { ip = 10.9.9.9/32; dynamic; }
}

router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.1.2.1; hardware = inside; bind_nat = h; }
}

service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
area:a = {
 inclusive_border = interface:r1.n2;
 nat:h = { ip = 10.9.9.9/32; dynamic; }
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; }
 interface:n2 = { ip = 10.1.2.1; hardware = inside; bind_nat = h; }
}
service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Remove unused tags of bind_nat';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; nat:n3 = { ip = 10.9.3.0/24; } }
network:n4 = { ip = 10.1.4.0/24; nat:n4 = { ip = 10.9.4.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; bind_nat = n3, n4; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n1, n2; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:test = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = tcp 80;
}
END

$out = <<'END';
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; nat:n3 = { ip = 10.9.3.0/24; } }
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; bind_nat = n3; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; bind_nat = n2; }
}
service:test = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Bridged network';
############################################################

$in = <<'END';
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 managed;
 model = ASA;
 interface:n1/left = { hardware = left; }
 interface:n1/right = { hardware = right; }
 interface:n1 = { ip = 10.1.1.2; hardware = device; }
}
network:n1/right = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1/right = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1/right;
    permit src = user; dst = network:n2; prt = tcp 80;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Handle split router from pathrestriction';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24; }

router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 interface:n1;
 interface:n3;
 interface:n5;
 interface:n7;
}

router:r3 = {
 interface:n2;
 interface:n4;
 interface:n6;
 interface:n8;
}

router:r4 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n7 = { ip = 10.1.7.2; hardware = n7; }
 interface:n8 = { ip = 10.1.8.2; hardware = n8; }
}

pathrestriction:p1 =
 interface:r2.n1,
 interface:r3.n2,
;

pathrestriction:p2 =
 interface:r2.n7,
 interface:r3.n8,
;

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n8; prt = tcp 80;
}
END

$out = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n1;
 interface:n7;
}
router:r3 = {
 interface:n2;
 interface:n8;
}
router:r4 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n7 = { ip = 10.1.7.2; hardware = n7; }
 interface:n8 = { ip = 10.1.8.2; hardware = n8; }
}
pathrestriction:p1 =
 interface:r2.n1,
 interface:r3.n2,
;
pathrestriction:p2 =
 interface:r2.n7,
 interface:r3.n8,
;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n8; prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
# Shared topology for crypto tests
############################################################

$topo = <<'END';
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 identity = address;
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn1 = {
 type = ipsec:aes256SHA;
}
crypto:vpn2 = {
 type = ipsec:aes256SHA;
}
network:intern = { ip = 10.1.1.0/24;}
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn1, crypto:vpn2;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = { ip = 0.0.0.0/0; has_subnets; }
END

my $clients1 = <<'END';
router:softclients1 = {
 interface:internet = { spoke = crypto:vpn1; }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24;
 radius_attributes = {
  banner = Willkommen zurück;
 }
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
 }
 host:id:bar@domain.x = {
  ip = 10.99.1.11;
  radius_attributes = { banner = Willkommen zu Hause; }
 }
}
END

my $clients2 = <<'END';
router:softclients2 = {
 interface:internet = { spoke = crypto:vpn2; }
 interface:customers2;
}
network:customers2 = {
 ip = 10.99.2.0/24;
 radius_attributes = {
  vpn-idle-timeout = 120;
  trust-point = ASDM_TrustPoint2;
 }

 host:id:domain.x = {
  range = 10.99.2.0 - 10.99.2.63;
  radius_attributes = { split-tunnel-policy = tunnelspecified;
                        check-subject-name = ou; }
 }
 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  radius_attributes = { vpn-idle-timeout = 40; trust-point = ASDM_TrustPoint3; }
 }
}
END

my $clients3 = <<'END';
router:softclients3 = {
 interface:internet = { spoke = crypto:vpn2; }
 interface:customers3;
}
network:customers3 = {
 ip = 10.99.3.0/24;
 cert_id = cert.example.com;
 radius_attributes = {
  trust-point = ASDM_TrustPoint2;
  authentication-server-group = LDAPGROUP_3;
  authorization-server-group = LDAPGROUP_3;
  check-subject-name = cn;
 }

 host:VPN_Org1 = {
  range = 10.99.3.0 - 10.99.3.63;
  ldap_id = CN=ROL-Org1;
 }
 host:VPN_Org2 = {
  range = 10.99.3.64 - 10.99.3.95;
  ldap_id = CN=ROL-Org2;
 }
}
END

############################################################
$title = 'Crypto definitions with router fragments';
############################################################

$in = $topo . $clients1 . $clients2 . <<'END';
service:test1 = {
 user = host:id:foo@domain.x.customers1, host:id:@domain.y.customers2;
 permit src = user; dst = network:intern; prt = tcp 80;
}
service:test2 = {
 user = host:id:bar@domain.x.customers1, host:id:domain.x.customers2;
 permit src = user; dst = network:intern; prt = tcp 81;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Take one of multiple crypto networks (1)';
############################################################

my $service = <<'END';
service:test1 = {
 user = host:id:bar@domain.x.customers1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
END

$in = $topo . $clients1 . $clients2 . $service;
$out = $topo . <<'END'
router:softclients1 = {
 interface:internet = { spoke = crypto:vpn1; }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24;
 radius_attributes = {
  banner = Willkommen zurück;
 }
 host:id:bar@domain.x = {
  ip = 10.99.1.11;
  radius_attributes = { banner = Willkommen zu Hause; }
 }
}
END
. $service;
test_run($title, $in, $out);

############################################################
$title = 'Take one of multiple crypto networks (2)';
############################################################

$service = <<'END';
service:test1 = {
 user = host:id:@domain.y.customers2;
 permit src = user; dst = network:intern; prt = tcp 80;
}
END

$in = $topo . $clients1 . $clients2 . $service;
$out = $topo . <<'END'
router:softclients2 = {
 interface:internet = { spoke = crypto:vpn2; }
 interface:customers2;
}
network:customers2 = {
 ip = 10.99.2.0/24;
 radius_attributes = {
  vpn-idle-timeout = 120;
  trust-point = ASDM_TrustPoint2;
 }

 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  radius_attributes = { vpn-idle-timeout = 40; trust-point = ASDM_TrustPoint3; }
 }
}
END
. $service;
test_run($title, $in, $out);

############################################################
$title = 'Network with ID hosts';
############################################################
# Take at least one ID host

$service = <<'END';
service:test1 = {
 user = network:customers1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
END

$in = $topo . $clients1 . $clients2 . $service;
$out = $topo . <<'END'
router:softclients1 = {
 interface:internet = { spoke = crypto:vpn1; }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24;
 radius_attributes = {
  banner = Willkommen zurück;
 }
 host:id:foo@domain.x = {
  ip = 10.99.1.10;
 }
}
END
. $service;
test_run($title, $in, $out);

############################################################
$title = 'Host with ldap_id';
############################################################

$service = <<'END';
service:test1 = {
 user = host:VPN_Org1;
 permit src = user; dst = network:intern; prt = tcp 80;
}
END

$in = $topo . $clients1 . $clients3 . $service;
$out = $topo . <<'END'
router:softclients3 = {
 interface:internet = { spoke = crypto:vpn2; }
 interface:customers3;
}
network:customers3 = {
 ip = 10.99.3.0/24;
 cert_id = cert.example.com;
 radius_attributes = {
  trust-point = ASDM_TrustPoint2;
  authentication-server-group = LDAPGROUP_3;
  authorization-server-group = LDAPGROUP_3;
  check-subject-name = cn;
 }

 host:VPN_Org1 = {
  range = 10.99.3.0 - 10.99.3.63;
  ldap_id = CN=ROL-Org1;
 }
}
END
. $service;
test_run($title, $in, $out);

############################################################
$title = 'With description';
############################################################

$in = <<'END';
network:n1 = {
 description = network:n1; # looks like code
 ip = 10.1.1.0/24;
 host:h10 = {
  ip = 10.1.1.10;
 }
}
network:n2 = { ip = 10.1.2.0/24; }

router:asa1 = {
 description = description = ;
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s = {
 description = this is really important
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-90;
}
END

$out = <<'END';
network:n1 = {
 description = network:n1; # looks like code
 ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 description = description = ;
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s = {
 description = this is really important
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-90;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Unconnected parts within one topology';
############################################################
$in = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 partition = part1;
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = {
 ip = 10.1.4.0/24;
 partition = part2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.1; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n3;
 permit src = user; dst = network:n4; prt = tcp 80;
}
END

$out = $in;

test_run($title, $in, $out);

############################################################
$title = 'Unenforceable rule';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;}
network:n2 = { ip = 10.1.2.0/24;}
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = 10.1.3.2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 has_unenforceable;
 user = network:n1;
 permit src = user;
        dst = network:n2, network:n4;
        prt = tcp 22;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Negated auto interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
area:n2-3 = { border = interface:r1.n2; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = interface:[managed & area:n2-3].[auto]
        &! interface:r3.[auto];
 permit src = user; dst = network:n1; prt = udp 123;
}
END

test_run($title, $in, $in);

############################################################
$title = 'Negated interface';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = interface:r1.[all] &! interface:r1.n3 &! interface:r1.n1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
END

test_run($title, $in, $in);

############################################################
done_testing;
