package Test_Netspoc;

use strict;
use warnings;

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_run test_err);

use Test::More;
use Test::Differences;
use IPC::Run3;

my $default_options = '-quiet';

sub run {
    my($input, $options) = @_;

    my $cmd = "perl -I lib bin/netspoc $default_options";
    $cmd .= " $options" if $options;
    my ($stdout, $stderr);
    run3($cmd, \$input, \$stdout, \$stderr);
    my $status = $?;
    return($status, $stdout, $stderr);
}

sub compile {
    my($input, $options) = @_;
    my ($status, $stdout, $stderr) = run($input, $options);
    if ($status != 0) {
        print STDERR "Failed:\n$stderr\n";
        return '';
    }
    if ($stderr) {
        print STDERR "Unexpected output on STDERR:\n$stderr\n";
        return '';
    }
    return($stdout);
}

sub compile_err {
    my($input, $options) = @_;
    my ($status, $stdout, $stderr) = run($input, $options);
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

sub test_run {
    my ($title, $in, $out, $options) = @_;

    # Blocks of expected output are split by single lines of dashes.
    my @out = split(/^-+\n/m, $out);

    # Get first line of each block
    my @head = map { (split /\n/, $_)[0] } @out;
    
    eq_or_diff(get_block(compile($in, $options), @head), 
               join('', @out), $title);
}

sub test_err {
    my ($title, $in, $out, $options) = @_;
    eq_or_diff(compile_err($in, $options), $out, $title);
}

1;
