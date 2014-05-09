package Test_Netspoc;

use strict;
use warnings;
use Carp;

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_run test_err);

use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempfile tempdir /;

my $default_options = '-quiet';
my $netspoc_cmd = 'perl -I lib bin/netspoc';

sub compile {
    my($input, $options) = @_;
    $options ||= '';
    my $dir = tempdir( CLEANUP => 1 );
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    my $cmd = "$netspoc_cmd $default_options $options $filename $dir";
    my ($stdout, $stderr);
    run3($cmd, \undef, \$stdout, \$stderr);
    my $status = $?;

    if ($status != 0) {
        print STDERR "Failed:\n$stderr\n";
        return '';
    }
    if ($stderr) {
        print STDERR "Unexpected output on STDERR:\n$stderr\n";
        return '';
    }
    return($dir);
}

sub compile_err {
    my($input, $options) = @_;
    $options ||= '';
    my $cmd = "$netspoc_cmd $default_options $options";
    my ($stdout, $stderr);
    run3($cmd, \$input, \$stdout, \$stderr);
    my $status = $?;
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
    my ($title, $in, $expected, $options) = @_;
    my $dir = compile($in, $options);

    # Undef input record separator to read all output at once.
    $/ = undef;

    # Blocks of expected output are split by single lines of dashes,
    # followed by an optional device name.
    my $delim  = qr/^-+[ ]*(\S*)[ ]*\n/m;
    my @expected = split($delim, $expected);
    my $first = shift @expected;
    if ($first) {
        BAIL_OUT("Missing device name in first line of code specification");
        return;
    }

    my $device = '(missing)';
    my %device2blocks;
    while (@expected) {
        if (my $next_device = shift @expected) {
            $device = $next_device;
        }
        my $text = shift @expected;
        push @{ $device2blocks{$device} }, $text;
    }

    my $multi = keys %device2blocks > 1;
    for my $device (sort keys %device2blocks) {
        open(my $out_fh, '<', "$dir/$device") or croak("Can't open '$device'");
        my $output = <$out_fh>;
        close($out_fh);

        my $blocks = $device2blocks{$device};

        # Get first line of each block
        my @head = map { (split /\n/, $_)[0] } @$blocks;
    
        my $t = $multi ? "$title: $device" : $title;
        eq_or_diff(get_block($output, @head), join('', @$blocks), $t);
    }
}

sub test_err {
    my ($title, $in, $expected, $options) = @_;
    eq_or_diff(compile_err($in, $options), $expected, $title);
}

1;
