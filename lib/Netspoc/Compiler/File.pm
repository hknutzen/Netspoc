package Netspoc::Compiler::File;

=head1 NAME

File operations

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
our @EXPORT = qw(read_file read_file_lines);

sub read_file {
    my ($path) = @_;
    open(my $fh, '<', $path) or die("Can't open $path: $!\n");
    my $data;
    {
        local $/ = undef;
        $data = <$fh>;
    }
    close($fh);
    return $data;
}

sub read_file_lines {
    my ($path) = @_;
    open(my $fh, '<', $path) or die("Can't open $path: $!\n");
    my @lines = <$fh>;
    close($fh);
    return \@lines;
}

1;
