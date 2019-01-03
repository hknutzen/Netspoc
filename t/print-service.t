#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile /;

sub test_run {
    my ($title, $input, $args, $expected) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';

    my $cmd = "$^X $perl_opt -I lib bin/print-service -q $filename $args";
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    local $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

my ($topo, $title, $in, $out);

############################################################
$topo = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 nat:N = { ip = 10.1.9.0/24; }
 host:h1 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:range3 = { range = 10.1.3.9-10.1.3.10; } }

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
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = N; }
}
END

############################################################
$title = 'Range, source port, deny, host, range, interface';
############################################################

$in = $topo . <<'END';
protocolgroup:ftp-all = tcp 21,
			protocol:ftp-passive-data, protocol:ftp-active-data;
protocolgroup:ftp-passive = tcp 21, protocol:ftp-passive-data;
protocol:ftp-passive-data = tcp 1024-65535, stateless;
protocol:ftp-active-data  = tcp 20:1024-65535, stateless, reversed;

service:s1 = {
    user = host:h1, network:n2;
    permit src = user; dst = network:n3; prt = protocolgroup:ftp-all;
    permit src = user; dst = host:range3; prt = udp 123;
    permit src = user; dst = interface:asa2.n3; prt = icmp 3/3;
    deny   src = user; dst = interface:asa2.n3; prt = icmp 5;
    permit src = user; dst = interface:asa2.n3; prt = icmp;
}
END

$out = <<'END';
s1:deny 10.1.9.10 10.1.3.2 icmp 5
s1:deny 10.1.2.0/24 10.1.3.2 icmp 5
s1:permit 10.1.9.10 10.1.3.0/24 tcp 21
s1:permit 10.1.2.0/24 10.1.3.0/24 tcp 21
s1:permit 10.1.9.10 10.1.3.0/24 tcp 1024-65535
s1:permit 10.1.2.0/24 10.1.3.0/24 tcp 1024-65535
s1:permit 10.1.3.0/24 10.1.9.10 tcp 20:1024-65535
s1:permit 10.1.3.0/24 10.1.2.0/24 tcp 20:1024-65535
s1:permit 10.1.9.10 10.1.3.9 udp 123
s1:permit 10.1.9.10 10.1.3.10 udp 123
s1:permit 10.1.2.0/24 10.1.3.9 udp 123
s1:permit 10.1.2.0/24 10.1.3.10 udp 123
s1:permit 10.1.9.10 10.1.3.2 icmp 3/3
s1:permit 10.1.2.0/24 10.1.3.2 icmp 3/3
s1:permit 10.1.9.10 10.1.3.2 icmp
s1:permit 10.1.2.0/24 10.1.3.2 icmp
END

test_run($title, $in, '-nat n3 service:s1', $out);

############################################################
$title = 'All services';
############################################################

$in = $topo . <<'END';
service:s1 = {
    user = network:n1;
    permit src = user; dst = network:n3; prt = ip;
}
service:s2 = {
    user = network:n2;
    permit src = user; dst = network:n3; prt = tcp;
}
END

$out = <<'END';
s1:permit 10.1.1.0/24 10.1.3.0/24 ip
s2:permit 10.1.2.0/24 10.1.3.0/24 tcp
END

test_run($title, $in, '', $out);

############################################################
$title = 'Missing "service:" keyword';
############################################################

test_run($title, $in, 's1 service:s2', $out);

############################################################
$title = 'Multiple services, show names of objects';
############################################################

$out = <<'END';
s1:permit network:n1 network:n3 ip
s2:permit network:n2 network:n3 tcp
END

test_run($title, $in, '-name service:s1 service:s2', $out);

############################################################
done_testing;
