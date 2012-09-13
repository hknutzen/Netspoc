# $Id$
package Test_Netspoc;

use strict;
use warnings;
use IPC::Run3;

our @ISA    = qw(Exporter);
our @EXPORT = qw(compile compile_err get_block);

use Test::More;
use File::Temp qw/ tempfile tempdir /;

my $options = '-quiet -check_redundant_rules=0 -check_service_unknown_owner=0';

sub run {
    my($input) = @_;

    my ($fh, $filename) = tempfile(UNLINK => 1);
    print $fh $input;
    close $fh;

    my $cmd = "perl -I lib bin/netspoc $options $filename";
    my ($stdout, $stderr);
    run3($cmd, \undef, \$stdout, \$stderr);
    my $status = $?;
    return($status, $stdout, $stderr);
}

sub compile {
    my($input) = @_;
    my ($status, $stdout, $stderr) = run($input);

    # 0: Success, 1: compare found diffs
    $status == 0 || $status == 1 or 
	    die "Status from compile $status\n";
    $stderr and die "Unexpected output on STDERR:\n$stderr\n";
    return($stdout);
}

sub compile_err {
    my($input) = @_;
    my ($status, $stdout, $stderr) = run($input);
    if ($stderr) {
        $stderr =~ s/\nAborted with \d+ error\(s\)$//ms;
    }
    return($stderr);
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
