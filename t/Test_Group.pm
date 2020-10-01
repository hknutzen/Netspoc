package Test_Group;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempfile /;
use Test_Netspoc qw(prepare_in_dir);

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_group test_group_err);

my $default_options = '-q';

sub test_group {
    my ($title, $input, $group, $expected, $options) = @_;
    $options ||= '';
    $options = "$default_options $options";
    my $in_dir = prepare_in_dir($input);

    # Prepare command line.
    my $cmd = "bin/print-group $options $in_dir '$group'";

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

sub test_group_err {
    my ($title, $input, $group, $expected, $options) = @_;
    $options ||= '';
    $options = "$default_options $options";
    my $in_dir = prepare_in_dir($input);

    # Prepare command line.
    my $cmd = "bin/print-group $options $in_dir '$group'";

    my ($stdout, $stderr, $success);
    run3($cmd, $success, \$stdout, \$stderr);
    if ($success) {
        diag("Unexpected success");
        diag($stderr) if $stderr;
        fail($title);
        return;
    }
    eq_or_diff($stderr, $expected, $title);
    return;
}

1;
