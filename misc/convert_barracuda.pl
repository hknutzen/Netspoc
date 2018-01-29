#!/usr/bin/perl

# Generate Netspoc services from Barracuda rules.

# Reads text file with pairs "ip name" of all defined hosts
# and networks from Netspoc.
# Reads text export of rules from barracuda firewall.
# Writes services and new host and network definitions to STDOUT.

use strict;
use warnings;
use feature 'say';

sub usage { die "$0 NETSPOC-DATA BARRACUDA-DATA\n" }

my $netspoc_file = shift or usage();
my $barracuda_file = shift or usage();
@ARGV and usage();

my %ip2name;
open (my $fh, '<', $netspoc_file) or die "Can't open $netspoc_file: $!";
while (my $line = <$fh>) {
    my ($ip, $name) = split ' ', $line;
    $ip2name{$ip} = $name;
}
close $fh;

open ($fh, '<', $barracuda_file) or die "Can't open $barracuda_file: $!";
my $title = <$fh>;
while (my $line = <$fh>) {
    my ($nr, $action, $name, $features, $srv, $src, $dst) = split /\t/, $line;
    next if $action eq 'CascadeBack ';
    if ($action =~ /^Pass/) {
        $action = 'permit';
    }
    elsif ($action =~ /^Block/) {
        $action = 'deny';
    }
    else {
        warn "Ignored line with action: $action";
        next;
    }
    $features and die "Unexpected Features: $features";
    my $prt_list = cleanup_prt($srv);
    my $src_list = normalize($src);
    my $dst_list = normalize($dst);
    write_service($name, $action, $src_list, $dst_list, $prt_list);
}
close $fh;

write_new_objects();

my %normalized_prt = (
    ECHO => 'icmp 8',
    'IPSEC-ESP' => 'proto 50',
    'IPSEC-AH' => 'proto 51',
);

sub cleanup_prt {
    my ($list) = @_;
    my %result;
    while ($list =~ m/\G.*?((?:TCP|UDP)  \d+|IP|ECHO|IPSEC-ESP|IPSEC-AH)/g) {
        my $prt = $1;
        if (my $subst = $normalized_prt{$prt}) {
            $prt = $subst;
        }
        $prt = lc $prt;
        $prt =~ s/  / /;
        $result{$prt} = 1;
    }
    return [ map { $_->[0] }
             sort { $a->[1] <=> $b->[1] || $a->[0] cmp $b->[0] }
             map { [ $_, /(?:tcp|udp) (\d+)/ ? $1 : 0 ] }
             keys %result ];
}

sub normalize {
    my ($list) = @_;
    my $has_not;
    my $has_internet;
    my %result;
    while ($list =~ m/\G.*?((?:NOT )?\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/g) {
        my $ip = $1;
        if ($ip =~ /^NOT/) {
            $has_not = 1;
            next;
        }
        if ($ip eq '0.0.0.0/0') {
            $has_internet = 1;
        }
        my $name = $ip2name{$ip} || new_name($ip);
        $result{$name} = 1;
    }
    $has_not and warn "Ignored 'NOT IP' in\n $list\n";
    return [ sort keys %result ];
}

my %new_name2ip;
sub new_name {
    my ($ip) = @_;
    my $orig_ip = $ip;
    $ip =~ s/[.]/_/g;
    my $prefix = $ip =~ /^192_168_/ ? 'DOI' : 'LNHH';
    $ip = "${prefix}_$ip";
    my $name;
    if (my ($ip1, $len) = $ip =~ /(.*)\/(.*)/) {
        $name = "network:$ip1-$len";
    }
    else {
        $name = "host:$ip";
    }
    $new_name2ip{$name} = $orig_ip;
    $ip2name{$orig_ip} = $name;
    return $name;
}

sub quad2int {
    ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) or return;
    ($1 < 256 && $2 < 256 && $3 < 256 && $4 < 256) or return;
    return $1 << 24 | $2 << 16 | $3 << 8 | $4;
}

sub write_new_objects {
    if (my @hosts =
        map { $_->[0] }
        sort { $a->[1] <=> $b->[1] }
        map { [ $_, quad2int($new_name2ip{$_}) ] }
        grep { /host:/ } keys %new_name2ip)
    {
        my $max_name = 0;
        my $max_ip = 0;
        for my $name (@hosts) {
            if (length($name) > $max_name) {
                $max_name = length($name);
            }
            my $ip = $new_name2ip{$name};
            if (length($ip) > $max_ip) {
                $max_ip = length($ip);
            }
        }
        for my $name (@hosts) {
            my $name_space = $max_name - length($name) + 1;
            my $tabs = int($name_space / 8) + 1;
            my $ip = $new_name2ip{$name};
            my $ip_space = $max_ip - length($ip) + 1;
            say $name, "\t" x $tabs, "= { ip = $ip;", " " x $ip_space ,"}";
        }
        say '';
    }
    if (my @networks = sort grep { /network:/ } keys %new_name2ip) {
        for my $name (@networks) {
            my $ip = $new_name2ip{$name};
            say "$name = { ip = $ip; }";
        }
    }
}

sub write_list {
    my ($tabs, $list) = @_;
    my $space = "\t" x $tabs;
    my $space1 = "\t";
    for my $element (@$list) {
        say "$space1$element,";
        $space1 = $space;
    }
    say "$space1;";
}

sub write_service {
    my ($name, $action, $src_list, $dst_list, $prt_list) = @_;

    # Name in Großbuchstaben und mit Unterstrichen.
    $name = uc $name;
    $name =~ s/-/_/g;
    say "service:$name = {";
    say '';
    say " description = ;";
    say '';
    print " user =";
    write_list(1, $src_list);
    say '';
    say " $action\tsrc =\tuser;";
    print "\tdst =";
    write_list(2, $dst_list);
    print "\tprt =";
    write_list(2,$prt_list);
    say "}";
    say '';
}
