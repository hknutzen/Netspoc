package Test_Group;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempfile /;
use Test_Netspoc qw(prepare_in_dir);

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_group);

my $default_options = '-quiet';

sub test_group {
    my ($title, $input, $group, $expected, $options) = @_;
    $options ||= '';
    $options = "$default_options $options";
    my $in_dir = prepare_in_dir($input);

    # Prepare command line.
    # Propagate options to perl process.
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';
    my $cmd = "$^X $perl_opt -I lib bin/print-group $options $in_dir '$group'";

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
