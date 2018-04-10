package Netspoc::Compiler::File;

=head1 NAME

File operations

=head1 COPYRIGHT AND DISCLAIMER

(C) 2018 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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

use feature 'current_sub';
use strict;
use warnings;
use open qw(:std :utf8);
use Netspoc::Compiler::Common;

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT_OK = qw(
 read_file read_file_lines process_file_or_dir
 *current_file *input *read_ipv6 *private $filename_encode
);

our $filename_encode = 'UTF-8';

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

# Name of current input file.
our $current_file;

# Content of current file.
our $input;

# Current file has IPv6 content.
our $read_ipv6;

# Rules and objects read from directories and files with
# special name 'xxx.private' are marked with attribute {private} = 'xxx'.
# This variable is used to propagate the value from directories to its
# files and sub-directories.
our $private;

# Read input from file and process it by function which is given as argument.
sub process_file {
    (local $current_file, my $parser) = @_;

    # Read file as one large line.
    local $/;

    open(my $fh, '<', $current_file)
        or fatal_err("Can't open $current_file: $!");

    # Fill buffer with content of whole file.
    # Content is implicitly freed when subroutine is left.
    local $input = <$fh>;
    close $fh;

    $parser->();
}

sub process_file_or_dir {
    my ($path, $parser) = @_;
    my $ipv_dir = $config->{ipv6} ? 'ipv4' : 'ipv6';
    local $read_ipv6 = $config->{ipv6};

    # Handle toplevel file.
    if (not -d $path) {
        process_file($path, $parser);
        return;
    }

    # Recursively read files and directories.
    my $read_nested_files = sub {
        my ($path) = @_;
        my ($name) = ($path =~ m'([^/]*)$');

        # Handle ipv6 / ipv4 subdirectory or file.
        local $read_ipv6 = $name eq $ipv_dir ? $name eq 'ipv6' : $read_ipv6;

        # Handle private directories and files.
        my $next_private = $private;
        if ($name =~ /[.]private$/) {
            if ($private) {
                fatal_err("Nested private context is not supported:\n $path");
            }
            $next_private = $name;
        }
        local $private = $next_private;

        if (-d $path) {
            opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
            for my $file (sort map { Encode::decode($filename_encode, $_) }
                          readdir $dh)
            {
                next if $file =~ /^\./;
                next if $file =~ m/$config->{ignore_files}/o;
                my $path = "$path/$file";
                __SUB__->($path);
            }
            closedir $dh;
        }
        else {
            process_file($path, $parser);
        }
    };

    # Handle toplevel directory.
    # Special handling for "config" and "raw".
    opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
    for my $file (sort map { Encode::decode($filename_encode, $_) } readdir $dh)
    {

        next if $file =~ /^\./;
        next if $file =~ m/$config->{ignore_files}/o;

        # Ignore special files/directories.
        next if $file =~ /^(config|raw)$/;

        my $path = "$path/$file";
        $read_nested_files->($path, $parser);
    }
    closedir $dh;
}

1;
