package Test_Netspoc;

use strict;
use warnings;
use Carp;

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_run test_warn test_err test_reuse_prev
                 prepare_in_dir prepare_out_dir);

use Test::More;
use Test::Differences;
use IPC::Run3;
use Capture::Tiny 'capture_stderr';
use File::Temp qw/ tempdir /;
use File::Spec::Functions qw/ file_name_is_absolute splitpath catdir catfile /;
use File::Path 'make_path';
use lib 'lib';
use Netspoc::Compiler::Pass1;

# Add "bin/" because Pass1.pm calls other programs in same directory.
$ENV{PATH} = "bin/:$ENV{PATH}";

my $default_options = '--quiet';

sub prepare_in_dir {
    my($input) = @_;

    # Prepare input directory and file(s).
    # Input is optionally preceeded by single lines of dashes
    # followed by a filename.
    # If no filenames are given, a single file named STDIN is used.
    my $delim  = qr/^-+[ ]*(\S+)[ ]*\n/m;
    my @input = split($delim, $input);
    my $first = shift @input;

    # Input does't start with filename.
    # No further delimiters are allowed.
    if ($first) {
        if (@input) {
            BAIL_OUT("Only a single input block expected");
            return;
        }
        @input = ('STDIN', $first);
    }
    my $in_dir = tempdir( CLEANUP => 1 );
    while (@input) {
        my $path = shift @input;
        my $data = shift @input;
        if (file_name_is_absolute $path) {
            BAIL_OUT("Unexpected absolute path '$path'");
            return;
        }
        my (undef, $dir, $file) = splitpath($path);
        my $full_dir = catdir($in_dir, $dir);
        make_path($full_dir);
        my $full_path = catfile($full_dir, $file);
        open(my $in_fh, '>', $full_path) or die "Can't open $path: $!\n";
        print $in_fh $data;
        close $in_fh;
    }
    return $in_dir;
}

sub run {
    my($input, $options, $out_dir) = @_;
    $options ||= '';
    my $in_dir = prepare_in_dir($input);

    # Prepare arguments for pass 1.
    my $args = [ split(' ', $default_options),
                 split(' ', $options),
                 $in_dir ];
    push @$args, $out_dir if $out_dir;

    # Compile, capture STDERR, catch errors.
    my ($stderr, $success) =
        capture_stderr {
            my $result;
            if (system('spoc1', @$args) == 0) {
                if ($out_dir) {
                    if (system('spoc2', @$args) == 0) {
                        $result = 1;
                    }
                } else {
                    $result = 1;
                }
            };
            $result;
    };

    return($stderr, $success, $in_dir);
}

# Find lines in $data which equal elements in @find.
# Output found line and subsequent lines up to empty line or comment line.
sub get_block {
    my ($data, @find) = @_;
    chomp for @find;
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

sub compare_warnings_and_devices {
    my ($title, $in, $expected, $options, $check_stderr, $dir) = @_;

    # Blocks of expected output are split by single lines of dashes,
    # followed by an optional device name.
    my $delim = qr/^-+[ ]*(\S*)[ ]*\n/m;

    # warnings_or_empty, name1, expected1, name2_or_empty, expected2, ...
    my ($warnings, @expected) = split($delim, $expected);

    # Only generate code if some expected output has been specified.
    # Otherwise we would unintentionally increase test coverage.
    $dir = undef if not @expected;

    my ($stderr, $success, $in_dir) = run($in, $options, $dir);
    if (!$success) {
        diag("Unexpected failure:\n$stderr");
        fail($title);
        return;
    }
    if ($check_stderr) {
        $warnings ||= '';

        # Normalize input path: remove temp. directory.
        $stderr =~ s/\Q$in_dir\E\///g;

        # Normalize version number and output directory.
        if ($options and $options =~ /verbose/) {
            $stderr =~ s/(?<=^Netspoc, version ).*/TESTING/;
            $stderr =~ s/\Q$dir\E//g;
        }

        # Normalize order of DIAG messages: "Reuse .prev/".
        if ($warnings =~ /DIAG: Reused/) {
            $stderr = join '', sort split /^/, $stderr;
        }

        eq_or_diff($stderr, $warnings, $title);
    }
    else {
        if ($stderr) {
            diag("Unexpected output on STDERR:\n$stderr");
            fail($title);
            return;
        }
        if ($warnings) {
            diag("Missing device name in first line of output specification");
            fail($title);
            return;
        }
        if (not @expected) {
            diag('Missing output specifications');
            fail($title);
            return;
        }
    }

    @expected or return;

    my $device = $expected[0];
    if (not $device) {
        diag("Missing device name in first dashed line");
        fail($title);
        return;
    }

    my %device2blocks;
    while (@expected) {
        if (my $next_device = shift @expected) {
            $device = $next_device;
        }
        my $text = shift @expected;
        push @{ $device2blocks{$device} }, $text;
    }

    # Undef input record separator to read all output at once.
    local $/ = undef;
    my $multi = keys %device2blocks > 1 || $check_stderr;
    for my $device (sort keys %device2blocks) {
        open(my $out_fh, '<', "$dir/$device") or do {
            diag("Can't open '$device'");
            fail($title);
            return;
        };
        my $output = <$out_fh>;
        close($out_fh);

        my $blocks = $device2blocks{$device};

        # Get first line of each block
        my @head = map { (split /\n/, $_)[0] } @$blocks;

        my $t = $multi ? "$title: $device" : $title;
        eq_or_diff(get_block($output, @head), join('', @$blocks), $t);
    }
}

# Prepare output directory.
sub prepare_out_dir {
    return tempdir( CLEANUP => 1 );
}

# Compile input and check for expected result.
# $expected has multiple fields,
# the expected output of each tested device.
sub test_run {
    my ($title, $in, $expected, $options) = @_;
    my $dir = prepare_out_dir();
    compare_warnings_and_devices($title, $in, $expected, $options, 0, $dir);
}

# First, unnamed field of $expected is warning message,
# next (optional) fields are expected output of tested devices.
sub test_warn {
    my ($title, $in, $expected, $options) = @_;
    my $dir = prepare_out_dir();
    compare_warnings_and_devices($title, $in, $expected, $options, 1, $dir);
}

# Compile two times with possibly different input
# while reusing output directory.
# Second run will try to reuse generated files from first run.
# Expects diagnostic message on STDERR.
sub test_reuse_prev {
    my ($title, $in1, $in2, $expected, $options) = @_;
    my $dir = prepare_out_dir();
    my ($stderr, $success, $in_dir) = run($in1, $options, $dir);
    compare_warnings_and_devices($title, $in2, $expected, $options, 1, $dir);
}

# $expected has one field,
# the expected error message
sub test_err {
    my ($title, $in, $expected, $options, $out_dir) = @_;
    my ($stderr, $success, $in_dir) = run($in, $options, $out_dir);
    if ($success) {
        diag("Unexpected success");
        diag($stderr) if $stderr;
        fail($title);
        return;
    }

    # Cleanup error message.
    $stderr =~ s/\nAborted with \d+ error\(s\)$//ms;

    # Remove 'Usage' message after error message.
    $stderr =~ s/\nUsage: .*/\n/ms;

    # Normalize input path: remove temp. dir.
    $stderr =~ s/\Q$in_dir\E\///g;

    eq_or_diff($stderr, $expected, $title);
}

1;
