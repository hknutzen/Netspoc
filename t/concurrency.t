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
