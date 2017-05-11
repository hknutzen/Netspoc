#!/usr/bin/perl

package Test_IPv6;

use strict;
use warnings;

our @ISA    = qw(Exporter);
our @EXPORT = qw(adjust_testfile add_96);

use NetAddr::IP::Util qw(maskanyto6 inet_aton ipv6_ntoa add128 ipv6_aton
                         inet_any2n);

# Transform IPv4 prefix to IPv6 prefix.
sub add_96 {
    my ($prefix) = @_;
    if ($prefix == "0") {
        return "/0";
    }
    else {
        $prefix += 96;
        return "/$prefix";
    }
}

sub adjust_testfile {
    my ($filename, $dir) = @_;

    open (my $infilehandle, "<", $filename) or
        die "Can not open file $filename";

    my @path = split (/\//, $filename);
    my $file = pop @path;
    $file =~ /(.+)\.t/;
    my $name = $1;

    open (my $outfilehandle, ">>", $dir . "/" . $name . "_ipv6.t") or
        die "Can not open file $filename";

    # Convert IPv4 input file line by line.
    while (my $line = <$infilehandle>) {

        # Ad hoc input topology generation in huge.t requires special handling.
        if ($filename =~ "huge.t") {

            # Add function requirements to transform input to IPv6.
            $line =~ s/use\s+Test_Group;/
                       use Test_Group;
                       use lib 't\/ipv6';
                       use NetAddr::IP::Util qw(maskanyto6 inet_aton ipv6_ntoa
                                                inet_any2n);
                       use Test_IPv6 qw(add_96);\n/x;

            # Alter generated inputstring to IPv6 before test call.
            my $a = '$in =~ s/(\d+\.\d+\.\d+\.\d+)/' .
                    'ipv6_ntoa(inet_any2n($1))/eg;';
            my $b = '$in =~ s/\/(\d+)/add_96($1)/eg;';
            my $c = "test_run(\$title, \$in, \$out);";
            $line =~ s/test_run\(\$title, \$in, \$out\);/$a\n$b\n$c\n/;
        }

        # Convert prefixes.
        # Several backslashes can occur in one line, examine one at a time.
        my @matchcount = $line =~ /\/\d+/;
        if (@matchcount > 0){
            my @words = split(/(\s+)/, $line);
            for my $word (@words) {

                # Do not mistake substitution regex slash (s/ipv4/ipv4/)
                # for prefix.
                if ($word =~ /\d+\.\d+\.\d+\.\d+\/\d+\.\d+\.\d+\.\d+/) {
                    next;
                }

                # Change prefix at IPv4 address with prefix.
                if ($word =~ /\d+\.\d+\.\d+\.\d+\/\d+/) {
                    $word =~ s/\/(\d+)/add_96($1)/e;
                }

                # Change prefix in IPv4-and-prefix regex
                if ($word =~ /\d+\.\d+\.\d+\.\d+\\\/\d+/) {
                    $word =~ s/\/(\d+)/add_96($1)/e;
                }
            }
            $line = join ("", @words);
        }

        # Convert addresses.
        # Several addresses might occur in one line, alter one at a time.
        @matchcount = $line =~ /\d+\.\d+\.\d+\.\d+/g;
        if (@matchcount > 0){
            my @words = split(/(\s+)/, $line);
            for my $word (@words) {

                # Assume addresses beginning with 255 to be masks.
                $word =~ s/(255\.\d+\.\d+\.\d+)/
                           ipv6_ntoa(maskanyto6(inet_aton($1)))/eg;

                # If first IPv4 bit set, set it for IPv6 also, except
                # for multicast auto networks (beginning with 224).
                if ($word =~ /(\d+)\.\d+\.\d+\.\d+/
                    and $1 >= 128
                    and $1 != 224) {
                    $word =~ /(\d+\.\d+\.\d+\.\d+)/;
                    my $firstbits = ipv6_aton("f000::");
                    my $newaddress = $firstbits | inet_any2n($1);
                    $word =~ s/(\d+\.\d+\.\d+\.\d+)/ipv6_ntoa($newaddress)/eg;
                }

                # Alter multicast addresses
                if ($word =~ /(\d+)\.\d+\.\d+\.\d+/ and $1 == 224) {
                    $word =~ s/224.0.0.102/ff02::66/;
                    $word =~ s/224.0.0.10/ff02::a/;
                    $word =~ s/224.0.0.5/ff02::5/;
                    $word =~ s/224.0.0.6/ff02::6/;
                    $word =~ s/224.0.0.9/ff02::9/;
                }

                # Alter any other addresses.
                $word =~ s/(\d+\.\d+\.\d+\.\d+)/ipv6_ntoa(inet_any2n($1))/eg;
            }
            $line = join ("", @words);
        }

        # Convert result messages.
        $line =~ s/IP address expected/IPv6 address expected/;

        # Convert test subroutine calls
        # No IPv6 version of rename-netspoc necessary.
        if ($filename =~ /rename.t/) {

        }
        # Alter test subroutine, if it is defined within the testfile.
        elsif ($filename =~
               /export.t|cut-netspoc.t|print-service.t|add-to-netspoc.t/) {
            $line =~ s/ -q/ -q -ipv6/;
        }
        # Add -ipv6 option to the test call otherwise.
        else {
            if ($filename =~ /concurrency.t/ and $line =~ /-q/) {
                $line =~ s/-q/-q -ipv6/;
            }
            elsif ($filename =~ /options.t/ and $line =~ /undef,/) {
                $line =~ s/undef,/'-ipv6',/;
            }
            elsif ($line =~ /test_/) {
                # Add -ipv6 option with other options specified.
                if ($line =~/'\)/) {
                    $line =~ s/'\);/ -ipv6'\);/;
                }
                # Add -ipv6 option with no other options specified.
                else {
                    $line =~ s/\);/, '-ipv6'\);/;
                }
            }
        }

        print $outfilehandle $line;
    }
    close $infilehandle;
    close $outfilehandle;
}
