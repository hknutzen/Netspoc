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
 *config fatal_err debug info
 $start_time progress
 numerically *a *b
 ip2int int2ip complement_32bit mask2prefix prefix2mask match_ip
);

our $config;

sub fatal_err {
    my (@args) = @_;
    print STDERR "Error: ", @args, "\n";
    die "Aborted\n";
}

sub debug {
    my (@args) = @_;
    return if not $config->{verbose};
    print STDERR @args, "\n";
    return;
}

sub info {
    my (@args) = @_;
    return if not $config->{verbose};
    print STDERR @args, "\n";
    return;
}

our $start_time;

sub progress {
    my (@args) = @_;
    return if not $config->{verbose};
    if ($config->{time_stamps}) {
        my $diff = time() - $start_time;
        printf STDERR "%3ds ", $diff;
    }
    info(@args);
    return;
}

sub numerically { return $a <=> $b }

sub ip2int {
    my ($ip) = @_;
    my ($i1,$i2,$i3,$i4) = split '\.', $ip;
    return ((((($i1<<8)+$i2)<<8)+$i3)<<8)+$i4;
}

sub int2ip {
    my ($int) = @_;
    return sprintf "%vd", pack 'N', $int;
}

sub complement_32bit {
    my ($ip) = @_;
    return ~$ip & 0xffffffff;
}

# Conversion from netmask to prefix and vice versa.
{

    # Initialize private variables of this block.
    my %mask2prefix;
    my %prefix2mask;
    for my $prefix (0 .. 32) {
        my $mask = 2**32 - 2**(32 - $prefix);
        $mask2prefix{$mask}   = $prefix;
        $prefix2mask{$prefix} = $mask;
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
    return ($ip == ($ip1 & $mask));
}

1;
