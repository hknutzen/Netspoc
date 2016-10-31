package Test_Group;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

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
    my $cmd = "$^X $perl_opt -I lib bin/print-group $options $filename";

    # Put group into file if it contains multiple lines.
    if ($group =~ /\n/) {
        my ($group_fh, $filename) = tempfile(UNLINK => 1);
        print $group_fh $group;
        close $group_fh;
        $cmd .= " -f $filename";
    }

    # Add single group on command line.
    else {
        $cmd .= " '$group'";
    }
    
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    local $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

1;
