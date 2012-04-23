# $Id$
package Test_Netspoc;

use strict;
use warnings;

our @ISA    = qw(Exporter);
our @EXPORT = qw(compile get_block);

use Test::More;
use File::Temp qw/ tempfile tempdir /;

my $options = '-quiet -check_redundant_rules=0 -check_service_unknown_owner=0';
sub compile {
    my($config) = @_;

    my ($fh, $filename) = tempfile(UNLINK => 1);
    print $fh $config;
    close $fh;

    my $cmd = "perl -I lib bin/netspoc $options $filename";
    open(COMPILE, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    $/ = undef;
    my $output = <COMPILE>;
    if (not close(COMPILE)) {
	$! and  die "Syserr closing pipe from $cmd: $!\n";
	my $exit_value = $? >> 8;

	# 0: Success, 1: compare found diffs
 	$exit_value == 0 || $exit_value == 1 or 
	    die "Status from $cmd: $exit_value\n";
    }
    return($output);
}

# Find lines in $data which equal elements in @find.
# Output found line and subsequent lines up to empty line or comment line.
sub get_block {
    my ($data, @find) = @_;
    map { chomp } @find;
    my @data = split /\n/, $data;
    my $out = '';
    my $match;
    for my $line (@data) {
	if (grep { $line eq $_ } @find) {
	    $out .= "$line\n";
	    $match = 1;
	}
	elsif ($match) {
	    if($line =~ m'^\s*([#!].*)?$') {
		$match = 0;
	    }
	    else {
		$out .= "$line\n";
	    }
	}
    }
    $out;
}

1;
