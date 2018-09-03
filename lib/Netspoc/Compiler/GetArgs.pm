package Netspoc::Compiler::GetArgs;

=head1 NAME

Get arguments and options from command line and config file.

=head1 COPYRIGHT AND DISCLAIMER

(C) 2017 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

=cut

use strict;
use warnings;
use Netspoc::Compiler::Common;
use Netspoc::Compiler::File qw(read_file_lines);
use Getopt::Long qw(GetOptionsFromArray);
use Pod::Usage;
use open qw(:std :utf8);

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT_OK = qw(get_args read_config combine_config);

####################################################################
# User configurable options.
####################################################################

# Valid values for config options in %config.
# - Default: 0|1
# - Option with name "check_*": 0,1,'warn'
#   * 0: no check
#   * 1: throw an error if check fails
#   * warn: print warning if check fails
# - ...
#
# Key is prefix or string "_default".
# Value is pattern for checking valid values.
our %config_type = (
    check_   => '0|1|warn',
    max_     => '\d+',
    start_   => '\d+',
    concurr  => '\d+',
    ignore_  => '\S+',
    _default => '0|1',
);

our %config = (

# Use IPv4 version as default
    ipv6 => 0,

# Check for unused groups and protocolgroups.
    check_unused_groups => 'warn',

# Check for unused owners.
    check_unused_owners => 'warn',

# Check for unused protocol definitions.
    check_unused_protocols => 0,

# Allow subnets only
# - if the enclosing network is marked as 'has_subnets' or
# - if the subnet is marked as 'subnet_of'
    check_subnets => 'warn',

# Check for unenforceable rules, i.e. no managed device between src and dst.
    check_unenforceable => 'warn',

# Check for duplicate rules.
    check_duplicate_rules => 'warn',

# Check for redundant rules.
    check_redundant_rules => 'warn',
    check_fully_redundant_rules => 0,

# Check for services where owner can't be derived.
    check_service_unknown_owner => 0,

# Check for services where multiple owners have been derived.
    check_service_multi_owner => 'warn',

# Check for missing supernet rules.
    check_supernet_rules => 'warn',

# Check for transient supernet rules.
    check_transient_supernet_rules => 'warn',

# Check, that all managed routers have attribute 'policy_distribution_point',
# either directly or from inheritance.
    check_policy_distribution_point => 0,

# Optimize the number of routing entries per router:
# For each router find the hop, where the largest
# number of routing entries points to
# and replace them with a single default route.
# This is only applicable for internal networks
# which have no default route to the internet.
    auto_default_route => 1,

# Ignore these names when reading directories:
# - CVS and RCS directories
# - CVS working files
# - Editor backup files: emacs: *~
    ignore_files => '^(CVS|RCS|\.#.*|.*~)$',

# Set value to >= 2 to start concurrent processing.
    concurrency_pass1 => 1,
    concurrency_pass2 => 1,

# Abort after this many errors.
    max_errors => 10,

# Print progress messages.
    verbose => 1,

# Print progress messages with time stamps.
# Print "finished" with time stamp when finished.
    time_stamps => 0,

# Use this value when printing passed time span.
    start_time => 0,

# Pass 1 writes processed device names to STDOUT,
# pass 2 reads to be processed device names from STDIN.
    pipe => 0,

    export => 0,
);

sub get_config_keys {
    return keys %config;
}

sub valid_config_key {
    my ($key) = @_;
    return exists $config{$key};
}

# Return the config pattern for the passed key. The config pattern
# defines which values are expected for this key. If no pattern is
# found for the passed key a default pattern is returned.
sub get_config_pattern {
    my ($key) = @_;
    my $pattern;
    for my $prefix (keys %config_type) {
        if ($key =~ /^$prefix/) {
            $pattern = $config_type{$prefix};
            last;
        }
    }
    return $pattern || $config_type{_default};
}

# Check for valid config key/value pair.
# Return false on success, the expected pattern on failure.
sub check_config_pair {
    my ($key, $value) = @_;
    my $pattern = get_config_pattern($key);
    return ($value =~ /^($pattern)$/ ? undef : $pattern);
}

# Combine config hashes with default config.
# Rightmost hash overrides previous values with same key.
sub combine_config {
    my (@hrefs) = @_;
    my %result = map { $_ ? %$_ : () } \%config, @hrefs;
    return \%result;
}

####################################################################
# Argument processing
# Get option names from %config.
# Write option values back to %config.
####################################################################

# Parses named command line switches into a key/value representation,
# e.g. '-quiet' to { verbose => 0 }.
sub parse_options {
    my ($args) = @_;
    my %result;
    my $setopt = sub {
        my ($key, $val) = @_;
        if (my $expected = check_config_pair($key, $val)) {
            fatal_err("Invalid value for option $key, expected '$expected'");
        }
        $result{$key} = $val;
    };

    my %options;
    for my $key (get_config_keys()) {
        my $opt = get_config_pattern($key) eq '0|1' ? '!' : '=s';
        $options{"$key$opt"} = $setopt;
    }
    $options{quiet} = sub { $result{verbose} = 0 };
    $options{'help|?'} = sub { pod2usage(1) };
    $options{man} = sub { pod2usage(-exitstatus => 0, -verbose => 2) };

    if (!GetOptionsFromArray($args, %options)) {

        # Don't use 'exit' but 'die', so we can catch this error in tests.
        my $out;
        open(my $fh, '>', \$out) or die $!;
        pod2usage(-exitstatus => 'NOEXIT', -verbose => 0, -output => $fh);
        close $fh;
        $out ||= '';
        die("$out\n");
    }

    return \%result;
}

# Read names of input file/directory and output directory from
# passed command line arguments.
sub parse_args {
    my ($args) = @_;
    my $main_file = shift @$args or pod2usage(2);

    # $out_dir is used to store compilation results.
    # For each managed router with name X a corresponding file X
    # is created in $out_dir.
    # If $out_dir is missing, no code is generated.
    my $out_dir = shift @$args;

    # Strip trailing slash for nicer messages.
    $main_file =~ s</$><>;
    defined $out_dir and $out_dir =~ s</$><>;

    # No further arguments allowed.
    @$args and pod2usage(2);
    return ($main_file, $out_dir);
}

# Read key value pairs from file '$path/config' if file exists.
sub read_config {
    my ($dir) = @_;
    $dir or return {};
    my $file = "$dir/config";
    -f $file or return {};

    my %result;
    my $lines = read_file_lines($file);
    for my $line (@$lines) {
        chomp $line;
        $line =~ /^\s*#/ and next;
        $line =~ /^\s*$/ and next;
        if (my ($key, $val) =
            ($line =~ /\s* (\w+) \s* = \s* (\S+) ;/x)) {
            valid_config_key($key) or
                fatal_err("Invalid keyword in $file: $key");
            if (my $expected = check_config_pair($key, $val)) {
                fatal_err("Invalid value for $key in $file,",
                          " expected '$expected'");
            }
            $result{$key} = $val;
        }
        else {
            fatal_err("Unexpected line in $file: $line");
        }
    }
    return \%result;
}

sub get_args {
    my ($args) = @_;
    my ($cmd_config)        = parse_options($args);
    my ($in_path, $out_dir) = parse_args($args);
    my $file_config         = read_config($in_path);

    # Use default values from %config hash.
    # Command line options override options from 'config' file.
    # Rightmost overrides.
    my $config = combine_config($file_config, $cmd_config);

    return $config, $in_path, $out_dir;
}

1;
