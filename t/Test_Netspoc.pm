package Test_Netspoc;

use strict;
use warnings;
use Carp;

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_run test_err);

use Test::More;
use Test::Differences;
use IPC::Run3;
use Capture::Tiny 'capture_stderr';
use File::Temp qw/ tempfile tempdir /;
use File::Spec::Functions qw/ file_name_is_absolute splitpath catdir catfile /;
use File::Path 'make_path';
use lib 'lib';
use Netspoc::Compiler::Pass1;
use Netspoc::Compiler::Pass2;

my $default_options = '-quiet';

sub run {
    my($input, $options, $out_dir) = @_;
    $options ||= '';

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

    # Propagate options to perl process.
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';
    $perl_opt .= ' -I lib';

    # Prepare arguments for pass 1.
    my $args = [ split(' ', $default_options),
                 split(' ', $options),
                 $in_dir ];
    push @$args, $out_dir if $out_dir;

    # Compile, capture STDERR, catch errors.
    my ($stderr, $success) = 
        capture_stderr {
            my $result;
            eval {

                # Copy unchanged arguments.
                my $args2 = [ @$args ];
                Netspoc::Compiler::Pass1::compile($args);
                Netspoc::Compiler::Pass2::compile($args2);
                $result = 1;
            };
            if($@) {
                warn $@; 
            };
            $result;
    };

    return($stderr, $success, $in_dir);
}

sub compile {
    my($input, $options) = @_;

    # Prepare output directory.
    my $out_dir = tempdir( CLEANUP => 1 );

    my ($stderr, $success, $in_dir) = run($input, $options, $out_dir);
    if (!$success) {
        print STDERR "Failed:\n$stderr\n";
        return '';
    }
    if ($stderr) {
        print STDERR "Unexpected output on STDERR:\n$stderr\n";
        return '';
    }
    return($out_dir);
}

sub compile_err {
    my($input, $options) = @_;
    my ($stderr, $success, $in_dir) = run($input, $options);

    # Cleanup error message.
    $stderr =~ s/\nAborted with \d+ error\(s\)$//ms;

    # Normalize input path: remove temp. dir.
    $stderr =~ s/\Q$in_dir\E\///g;
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
    local $/ = undef;

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
