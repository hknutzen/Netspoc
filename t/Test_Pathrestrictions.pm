package Test_Pathrestrictions;

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_pathrestrictions);

sub test_pathrestrictions {
    my ($title, $input, $expected) = @_;
    my $default_option = '-quiet';

    # Print input to temp file.
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    # Call test-pathrestrictions on input file, pipe to filehandle.
    my $cmd = 
          "perl -I lib bin/check-pathrestrictions $default_option $filename";
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    local $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";

    # Compare real output with expected output.
    eq_or_diff($output, $expected, $title);
    return;

}
