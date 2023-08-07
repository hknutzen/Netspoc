#!/usr/bin/perl

use strict;
use warnings;
use NetAddr::IP::Util qw(maskanyto6 inet_aton ipv6_ntoa ipv6_aton inet_any2n);
use Regexp::IPv6 qw($IPv6_re);

# mask2prefix lookup will be needed for ASA routing
my %mask2prefix;
my $prefix = 0;
my $mask = NetAddr::IP::Util::ipv6_aton('0:0:0:0:0:0:0:0');
my @big_to_little_endian = (7,5,3,1,-1,-3,-5,-7);
while (1) {
    $mask2prefix{$mask}   = $prefix;
    last if $prefix == 128;
    my $bitpos = $prefix + $big_to_little_endian[$prefix % 8];
    vec($mask, $bitpos, 1) = 1;
    $prefix++;
}

# Main program
@ARGV == 2 or die "Usage: $0 inputfile outputdir\n";
my $inputfile = $ARGV[0];
my $outdir = $ARGV[1];
adjust_testfile($inputfile, $outdir);

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

# Transform marked IPv6 "!mask" to IPv6 "/prefix".
# Invert inverted mask again.
sub to_prefix {
    my ($in) = @_;
    my $mask = substr $in, 1;
    my $v6 = ipv6_aton($mask);

    # Invert inverted mask again.
    if ($mask =~ /^:/ and $mask ne '::') {
        $v6 = ~$v6;
    }
    my $prefix = $mask2prefix{$v6};
    return "/$prefix";
}

sub adjust_testfile {
    my ($filename, $dir) = @_;

    open (my $infilehandle, "<", $filename) or
        die "Can not open file $filename";

    my @path = split (/\//, $filename);
    my $file = pop @path;
    $file =~ /(.+)\.t/;
    my $name = $1;

    open (my $outfilehandle, '>', $dir . "/" . $name . "_ipv6.t") or
        die "Can not open file $filename";

    # Convert IPv4 input file line by line.
    while (my $line = <$infilehandle>) {

        # Disable marked line
        if ($line =~ /#( *No IPv6)/i) {
            $line = "=TODO=$1\n";
        }

        # Convert icmp to icmpv6 in input lines
        # but not in JSON output of file export.t.
        if ($line =~ /[=,;']/ and $line !~ /"/) {
            $line =~ s/icmp\b/icmpv6/g;
        }

        # Convert icmp to ipv6-icmp for ip6tables.
        if ($line =~ /^-A /) {
            $line =~ s/icmp/ipv6-icmp/;
        }

        # Convert icmp to icmp6 for ASA.
        if ($line =~ /^access-list/) {
            $line =~ s/icmp/icmp6/;
        }

        # Convert ICMPv4 to ICMPv6 in JSON output for NSX.
        $line =~ s/"ICMPv4"/"ICMPv6"/;
        # Convert value of attribute 'ip_protocol' for NSX.
        $line =~ s/IPV4/IPV6/;
        # Convert name of ICMP protocol for NSX.
        $line =~ s/([\/"]Netspoc-icmp)/$1v6/;

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

        # Convert prefixes as part of address names of PAN-OS.
        $line =~ s/(\.\d+_)(\d+)(["<])/$1.($2+96).$3/e;

        # Convert addresses.
        # Several addresses might occur in one line, alter one at a time.
        @matchcount = $line =~ /\d+\.\d+\.\d+\.\d+/g;
        if (@matchcount > 0){
            my @words = split(/(\s+)/, $line);
            for my $word (@words) {

                # Ignore line
                #  check-extended-key-usage = 1.3.6.1.4.1.311.20.2.2;
                #  extended-key-usage co 1.3.6.1.4.1.311.20.2.2
                last if $word =~ /extended-key-usage/;

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

        $line =~ s/any4/any6/g;

        # Convert IP and Net object names for PAN-OS
        if ($line =~ m/(NET_|IP_)($IPv6_re)/) {
            $line =~ s/:(?=.*<ip-netmask>|.*<\/member>)/_/g;
        }

        my $ipv6 = qr/(?:$IPv6_re|::)/;

        # Convert mask to prefix in in routes.
        if ($line =~ /route(?: \w+)* $ipv6 $ipv6 (?:$ipv6|\w+)/) {
            $line =~ s/($ipv6) ($ipv6) ($ipv6|\w+)$/$1!$2 $3/;
            $line =~ s/(!$ipv6)/to_prefix($1)/e;
        }

        # Convert mask to prefix in ACLs and in network-objects.
        if ($line =~ / (?:permit|deny|network-object)/) {

            # Mark to be converted masks with "!"
            $line =~ s/($ipv6) ($ipv6) ($ipv6) ($ipv6)/$1!$2 $3!$4/ or
                $line =~ s/((?:$ipv6 )?)($ipv6) ($ipv6)/$1$2!$3/g;

            # Convert marked masks.
            $line =~ s/(!$ipv6)/to_prefix($1)/ge;
        }

        # Convert syntax and convert mask to prefix in interface ip
        if ($line =~
            s/^ ip address ($ipv6) ($ipv6)( secondary)?$/ ipv6 address $1!$2/)
        {
            $line =~ s/(!$ipv6)/to_prefix($1)/e;
        }

        # Convert syntax and convert mask to prefix in vpn-framed-ip-address
        if ($line =~
            s/^ vpn-framed-ip-address ($ipv6) ($ipv6)$/ vpn-framed-ipv6-address $1!$2/)
        {
            $line =~ s/(!$ipv6)/to_prefix($1)/e;
        }

        # Convert syntax and convert mask to prefix in 'ip local pool'
        if ($line =~
            s/^ip local pool (\S+) ($ipv6)-($ipv6) mask ($ipv6)/ipv6 local pool $1 $2!$4/)
        {
            $line =~ s/(!$ipv6)/to_prefix($1)/e;
            if (my ($len) = $line =~ m|/(\d+)$|) {
                chomp $line;
                my $count = 2 ** (128 - $len);
                $line .= " $count\n";
            }
        }

        # Convert syntax for NX-OS
        $line =~ s/^ ip (address $ipv6\/\d+)/ ipv6 $1/;

        # Convert mask to prefix in exported JSON data.
        if ($line =~ s/( : ")($ipv6)\/($ipv6)/$1$2!$3/) {
            $line =~ s/(!$ipv6)/to_prefix($1)/e;
        }

        # Convert syntax of IOS / NX-OS routing, but not iptables.
        if ($line !~ /ip route add/) {
            $line =~ s/ip route/ipv6 route/;
        }

        # Convert syntax of ASA routing.
        $line =~ s/^route /ipv6 route /;

        # Convert syntax of IOS access-list.
        $line =~ s/ip access-list extended/ipv6 access-list/;
        $line =~ s/^ (permit|deny) ip / $1 ipv6 /;
        $line =~ s/^ ip access-group/ ipv6 traffic-filter/;

        # Convert syntax of NX-OS access-list.
        $line =~ s/^ip access-list (\w+)$/ipv6 access-list $1/;

        # Change path of to be checked output files.
        # IPv6 files are generated in ipv6/ subdirectory.
        if ($line !~ m(topology|config|file|raw/| raw$|private) and
            $filename !~ /export.t/)
        {
            $line =~ s/^(-+[ ]*)([^\s>-]+)([ ]*)$/${1}ipv6\/$2$3/;
        }

        # Convert result messages.
        $line =~ s/IP address expected/IPv6 address expected/;
        $line =~ s/IPv4 topology/IPv6 topology/;
        $line =~ s/(DIAG: Reused [.]prev)/$1\/ipv6/;
        $line =~ s/Read IPv4:/Read IPv6:/;
        $line =~ s/(file ')/${1}ipv6\//;

        # Convert group names
        $line =~ s/([ >"]|Netspoc-)(g\d+[\s<"])/$1v6$2/g;

        # Convert rule names in XML: <entry name="r2">
        $line =~ s/(=")(r\d+")/$1v6$2/g;
        # Convert rule names in JSON: "id": "r7",
        $line =~ s/(: ?")(r\d+")/$1v6$2/g;

        # Add =PARAMS= with --ipv6 option before =INPUT=
        $line =~ s/^(=INPUT=.*)/=PARAMS=--ipv6\n$1/;

        print $outfilehandle $line;
    }
    close $infilehandle;
    close $outfilehandle;
}
