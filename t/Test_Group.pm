package Test_Group;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempfile /;

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_group);

my $default_options = '-quiet';

sub test_group {
    my ($title, $input, $group, $expected, $options) = @_;
    $options ||= '';
    $options = "$default_options $options";

    # Prepare input file.
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    # Prepare command line.
    # Propagate options to perl process.
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';
    my $cmd = "$^X $perl_opt -I lib bin/print-group $options $filename '$group'";

    my ($stdout, $stderr);
    run3($cmd, \undef, \$stdout, \$stderr);
    if ($stderr) {
        diag("Unexpected output on STDERR:\n$stderr");
        fail($title);
        return;
    }
    eq_or_diff($stdout, $expected, $title);
    return;
}

1;
