#!perl

use strict;
use warnings;
use IPC::Run3;
use File::Temp qw/ tempdir /;
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
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out, '--concurrency_pass1=2');

############################################################
$title = 'Warning from background job';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
END

# Output is indented
$out = <<'END';
Warning: Redundant rules in service:s1 compared to service:s2:
  permit src=network:n1; dst=network:n2; prt=tcp 80; of service:s1
< permit src=network:n1; dst=network:n2; prt=ip; of service:s2
END

test_warn($title, $in, $out, '--concurrency_pass1=2');

############################################################
$title = 'Error from background job';
############################################################

$out =~ s/^Warning:/Error:/;
test_err($title, $in, $out, '--concurrency_pass1=2 --check_redundant_rules=err');

############################################################
$title = 'Abort from background job';
############################################################

$out =~ s/^Warning:/Error:/;
$out .= <<'END';
Aborted after 1 errors
END

test_err($title, $in, $out,
         '--max_errors=1 --check_redundant_rules=err --concurrency_pass1=2');

############################################################
$title = 'Abort in foreground job';
############################################################
# Don't wait for background job, but exit immediately.

$in = <<'END';
network:n1  = { ip = 10.1.1.0/24; }
network:sub = { ip = 10.1.1.8/29; }
router:r1 = {
 interface:n1;
 interface:sub;
}
END

$out = <<'END';
Error: network:sub is subnet of network:n1
 in nat_domain:[network:n1].
 If desired, declare attribute 'subnet_of'
Aborted after 1 errors
END

test_err($title, $in, $out,
         '--max_errors=1 --check_subnets=err --concurrency_pass1=2');

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
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- asa2
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
-- asa3
! n1_in
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_run($title, $in, $out, '--concurrency_pass2=8');

############################################################
$title = 'Pass 2: 3 devices with 2 jobs';
############################################################

test_run($title, $in, $out, '--concurrency_pass2=2');

############################################################
$title = 'Netspoc script with pipe from pass1 to pass2';
############################################################

$out = <<END;
END

my $in_dir = prepare_in_dir($in);
my $out_dir = tempdir( CLEANUP => 1 );
my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';
my $path = 'bin/netspoc';
open(my $fh, '<', $path) or die("Can't open $path: $!\n");
my $script;
{
    local $/ = undef;
    $script = <$fh>;
}
close($fh);

# Adapt content of netspoc script
# - insert arguments and
# - add Perl options for testing.
$script =~ s/"\$\@"/$in_dir $out_dir/g;
$script =~ s/(spoc1)/bin\/$1 -q/g;
$script =~ s/(spoc2)/bin\/$1 -q/g;
my $cmd = "bash -c '$script'";

my $stderr;
run3($cmd, \undef, \undef, \$stderr);
my $status = $?;
if ($status != 0) {
    diag("Failed:\n$stderr");
    fail($title);
}
elsif ($stderr) {
    diag("Unexpected output on STDERR:\n$stderr");
    fail($title);
}
else {

    # Only check for existence of generated files.
    # Content has already been checked above.
    for my $device (qw(asa1 asa2 asa3)) {
        my $path = "$out_dir/$device";
        ok(-f $path, "$title: $device");
    }
}

############################################################
done_testing;
