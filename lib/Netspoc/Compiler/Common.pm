package Netspoc::Compiler::Common;

=head1 NAME

Common code of Pass1 and Pass2

=head1 COPYRIGHT AND DISCLAIMER

(C) 2015 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
 *config *SHOW_DIAG
 fatal_err debug info diag_msg
 $start_time progress
 numerically *a *b
 ip2int int2ip 
 $zero_ip $max_ip
 complement_32bit increment_ip
 mask2prefix prefix2mask match_ip
 add_ip_bitstrings
);

# Enable printing of diagnostic messages by 
# - either declaring main::SHOW_DIAG
# - or setting environment variable SHOW_DIAG.
use constant SHOW_DIAG => exists &main::SHOW_DIAG || $ENV{SHOW_DIAG};

our $config;

# Print error message and aborts.
sub fatal_err {
    my (@args) = @_;
    print STDERR "Error: ", @args, "\n";
    die "Aborted\n";
}

# Print arguments to STDERR if in verbose mode.
sub debug {
    my (@args) = @_;
    return if not $config->{verbose};
    print STDERR @args, "\n";
}

# Print arguments to STDERR if in verbose mode.
sub info {
    my (@args) = @_;
    return if not $config->{verbose};
    print STDERR @args, "\n";
}

# Print diagnostic message, regardless of quiet/verbose setting.
# Should be used guarded by constant SHOW_DIAG. 
# If SHOW_DIAG isn't enabled, the whole line will be removed at
# compile time and won't have any performane impact.
# Use like this:
# diag_msg("Some message") if SHOW_DIAG;
sub diag_msg {
    my (@args) = @_;
    print STDERR "DIAG: ", @args, "\n";
}

our $start_time;

# Print arguments to STDERR if in verbose mode.
# Add time stamps to output if configured.
sub progress {
    my (@args) = @_;
    return if not $config->{verbose};
    if ($config->{time_stamps}) {
        my $diff = time() - $start_time;
        unshift @args, sprintf "%3ds ", $diff;
    }
    info(@args);
}

sub numerically { return $a cmp $b }

sub ip2int {
    my ($ip) = @_;
    my ($i1,$i2,$i3,$i4) = split '\.', $ip;

    # Create bit string with 32 bits.
    return pack 'C4', $i1, $i2, $i3, $i4;
}

## no critic (RequireArgUnpacking)
sub int2ip {
    #return sprintf "%vd", pack 'N', $_[0];
    return sprintf "%vd", $_[0];
}

## use critic

our $zero_ip = pack('N', 0);
our $max_ip = pack('N', 0xffffffff);

sub complement_32bit {
    my ($ip) = @_;
    return ~$ip & 0xffffffff;
}

sub increment_ip  {
    my ($ip) = @_;
    pack('N', 1 + unpack('N', $ip));
}

# Conversion from netmask to prefix and vice versa.
{

    # Initialize private variables of this block.
    my %mask2prefix;
    my %prefix2mask;
    my $mask = pack('N', 0x00000000);
    my $bit = 0x80000000;
    my $prefix = 0;
    while(1) {
        $mask2prefix{$mask}   = $prefix;
        $prefix2mask{$prefix} = $mask;
        last if $prefix == 32;
        $prefix++;
        $mask |= pack('N', $bit);
        $bit /= 2;
    }

    # Convert a network mask to a prefix ranging from 0 to 32.
    sub mask2prefix {
        my $mask = shift;
        return $mask2prefix{$mask};
    }

    sub prefix2mask {
        my $prefix = shift;
        return $prefix2mask{$prefix};
    }
}

# Check if $ip1 is located inside network $ip/$mask.
sub match_ip {
    my ($ip1, $ip, $mask) = @_;
    return ($ip eq ($ip1 & $mask));
}

1;
