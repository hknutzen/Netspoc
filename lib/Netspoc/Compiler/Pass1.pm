package Netspoc::Compiler::Pass1;

=head1 NAME

Netspoc - A Network Security Policy Compiler

=head1 COPYRIGHT AND DISCLAIMER

(c) 2018 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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

=head1 IMPLEMENTATION

=cut

use feature 'current_sub';
use strict;
use warnings;
use JSON::XS;
use Netspoc::Compiler::GetArgs qw(get_args);
use Netspoc::Compiler::File qw(
 process_file_or_dir
 *current_file *input *read_ipv6 *private $filename_encode);
use Netspoc::Compiler::Common;
use open qw(:std :utf8);
use Encode;
use IO::Pipe;
use NetAddr::IP::Util;
use Regexp::IPv6 qw($IPv6_re);

our $VERSION = '5.035'; # VERSION: inserted by DZP::OurPkgVersion
my $program = 'Netspoc';
my $version = __PACKAGE__->VERSION || 'devel';

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
  %routers
  %routers6
  %interfaces
  %networks
  %hosts
  %aggregates
  %owners
  %areas
  %pathrestrictions
  %groups
  %protocols
  %protocolgroups
  %services
  %isakmp
  %ipsec
  %crypto
  %service_rules
  %path_rules
  init_global_vars
  abort_on_error
  internal_err
  err_msg
  fatal_err
  unique
  equal
  aref_eq
  print_ip
  show_version
  split_typed_name
  skip_space_and_comment
  read_union
  is_network
  is_interface
  is_host
  get_intf
  parse_toplevel
  read_file_or_dir
  show_read_statistics
  order_protocols
  link_topology
  mark_disabled
  set_zone
  link_reroute_permit
  expand_protocols
  expand_group
  normalize_src_dst_list
  get_orig_prt
  normalize_services
  group_path_rules
  expand_crypto
  setpath
  distribute_nat_info
  combine_no_nat_sets
  find_subnets_in_zone
  find_subnets_in_nat_domain
  convert_hosts_in_rules
  propagate_owners
  path_walk
  single_path_walk
  get_nat_network
  address
);


# Use non-local function exit for efficiency.
# Perl profiler doesn't work if this is active.
my $use_nonlocal_exit = 1;

####################################################################
# Attributes of supported router models
####################################################################
my %router_info = (
    IOS => {
        routing           => 'IOS',
        filter            => 'IOS',
        stateless         => 1,
        stateless_self    => 1,
        stateless_icmp    => 1,
        inversed_acl_mask => 1,
        can_vrf           => 1,
        can_log_deny      => 1,
        log_modifiers     => { 'log-input' => ':subst' },
        has_out_acl       => 1,
        need_protect      => 1,
        crypto            => 'IOS',
        print_interface   => 1,
        comment_char      => '!',
        extension         => {
            EZVPN => { crypto    => 'EZVPN' },
            FW    => { stateless => 0 },
        },
    },
    'NX-OS' => {
        routing           => 'NX-OS',
        filter            => 'NX-OS',
        stateless         => 1,
        stateless_self    => 1,
        stateless_icmp    => 1,
        can_objectgroup   => 1,
        inversed_acl_mask => 1,
        use_prefix        => 1,
        can_vrf           => 1,
        can_log_deny      => 1,
        log_modifiers     => {},
        has_out_acl       => 1,
        need_protect      => 1,
        print_interface   => 1,
        comment_char      => '!',
    },
    ASA => {
        routing       => 'ASA',
        filter        => 'ASA',
        log_modifiers => {
            emergencies   => 0,
            alerts        => 1,
            critical      => 2,
            errors        => 3,
            warnings      => 4,
            notifications => 5,
            informational => 6,
            debugging     => 7,
            disable       => 'disable',
        },
        stateless_icmp      => 1,
        has_out_acl         => 1,
        can_acl_use_real_ip  => 1,
        can_objectgroup     => 1,
        can_dyn_crypto      => 1,
        crypto              => 'ASA',
        no_crypto_filter    => 1,
        comment_char        => '!',
        no_filter_icmp_code => 1,
        need_acl            => 1,
        extension           => {
            VPN => {
                crypto           => 'ASA_VPN',
                stateless_tunnel => 1,
                do_auth          => 1,
            },
            EZVPN => { crypto => 'ASA_EZVPN' },
        },
    },
    Linux => {
        routing          => 'iproute',
        filter           => 'iptables',
        has_io_acl       => 1,
        comment_char     => '#',
        can_managed_host => 1,
    },
);
for my $model (keys %router_info) {

    # Is changed for model with extension. Used in error messages.
    $router_info{$model}->{name} = $model;

    # Is left unchanged with extensions. Used in header of generated files.
    $router_info{$model}->{class} = $model;
}

# Use this if src or dst port isn't defined.
# Don't allocate memory again and again.
my $aref_tcp_any = [ 1, 65535 ];

# Definition of dynamic routing protocols.
my %routing_info = (
    EIGRP => {
        name   => 'EIGRP',
        prt    => { proto => 88 },
        mcast  => [ '224.0.0.10' ],
        mcast6 => [ 'ff02::a' ],
    },
    OSPF => {
        name   => 'OSPF',
        prt    => { proto => 89 },
        mcast  => [ '224.0.0.5', '224.0.0.6' ],
        mcast6 => [ 'ff02::5', 'ff02::6' ],
    },
    RIPv2 => {
        name   => 'RIP',
        prt    => { proto => 'udp', range => [ 520, 520 ] },
        mcast  => [ '224.0.0.9' ],
        mcast6 => [ 'ff02::9' ],
    },
    dynamic => { name => 'dynamic' },

    # Identical to 'dynamic', but must only be applied to router, not
    # to interface.
    manual => { name => 'manual' },
);

# Definition of redundancy protocols.
my %xxrp_info = (
    VRRP => {
        prt    => { proto => 112 },
        mcast  => [ '224.0.0.18' ],
        mcast6 => [ 'ff02::12' ],
    },
    HSRP => {
        prt    => { proto => 'udp', range => [ 1985, 1985 ] },
        mcast  => [ '224.0.0.2' ],

        # No official IPv6 multicast address for HSRP available,
        # therefore using IPv4 equivalent.
        mcast6 => [ '::e000:2' ],
    },
    HSRPv2 => {
        prt    => { proto => 'udp', range => [ 1985, 1985 ] },
        mcast  => [ '224.0.0.102' ],
        mcast6 => [ 'ff02::66' ],
    },
);

# DHCP server.
my $prt_bootps = { proto => 'udp', range => [ 67, 67 ] };

# DHCP client.
my $prt_bootpc = { proto => 'udp', range => [ 68, 68 ] };

# Comparison functions for sort.
sub by_name     { return $a->{name} cmp $b->{name} }
sub numerically { return $a <=> $b }

## no critic (RequireArgUnpacking)

# Check if all arguments are 'eq'.
sub equal {
    return 1 if not @_;
    my $first = shift;
    return not grep { $_ ne $first } @_;
}

# Return unique union of all arguments.
# Preserves original order.
sub unique {
    my %seen;
    return grep { not $seen{$_}++ } @_;
}

# Check passed arguments for duplicates.
# Return duplicate elements.
sub find_duplicates {
    my %dupl;
    $dupl{$_}++ for @_;
    return grep { $dupl{$_} > 1 } keys %dupl;
}
## use critic

# Return the intersecting elements of two array references.
sub intersect {
    my ($aref1, $aref2) = @_;
    my %seen = map { $_ => 1 } @$aref1;
    return grep { $seen{$_} } @$aref2;
}

# Delete an element from an array reference.
sub aref_delete {
    my ($aref, $elt) = @_;
    for (my $i = 0 ; $i < @$aref ; $i++) {
        if ($aref->[$i] eq $elt) {
            splice @$aref, $i, 1;

#debug("aref_delete: $elt->{name}");
            return;
        }
    }
}

# Substitute an element in an array reference.
sub aref_subst {
    my ($aref, $elt, $new) = @_;
    for (my $i = 0 ; $i < @$aref ; $i++) {
        if ($aref->[$i] eq $elt) {
            splice @$aref, $i, 1, $new;
            return;
        }
    }
}

# Compare two array references element wise.
# Return true if both arrays contain the same elements in same order.
sub aref_eq {
    my ($a1, $a2) = @_;
    @$a1 == @$a2 or return;
    for (my $i = 0 ; $i < @$a1 ; $i++) {
        return if $a1->[$i] ne $a2->[$i];
    }
    return 1;
}

# Check if two hashes contain the same keys. Values can be different.
sub keys_eq {
    my ($href1, $href2) = @_;
    keys %$href1 == keys %$href2 or return;
    for my $key (keys %$href1) {
        exists $href2->{$key} or return;
    }
    return 1;
}

# Print arguments as warning to STDERR.
sub warn_msg {
    my (@args) = @_;
    print STDERR "Warning: ", @args, "\n";
}

sub warn_or_err_msg {
    my ($type, @args) = @_;
    if ($type eq 'warn') {
        warn_msg(@args);
    }
    else {
        err_msg(@args);
    }
}

# Use content and match position of current input file.
# Return string describing current match position.
sub context {
    my $context;
    if (pos $input == length $input) {
        $context = 'at EOF';
    }
    else {
        my ($pre, $post) =
          $input =~ m/([^ \t\n,;={}]*[,;={} \t]*)\G([,;={} \t]*[^ \t\n,;={}]*)/;
        $context = qq/near "$pre<--HERE-->$post"/;
    }
    return at_line() . ", $context\n";
}

# Return current input file and line number.
sub at_line {
    my $seen_lines = substr($input, 0, pos($input));
    my $number = 1;
    $number++ while $seen_lines =~ m/\n/g;
    return " at line $number of $current_file";
}

# Print arguments together with current context to STDERR
# and abort the script.
sub syntax_err {
    my (@args) = @_;
    die "Syntax error: ", @args, context();
}

our $error_counter;

# Increment error counter.
# Abort, if the maximum number of errors is exceeded.
sub check_abort {
    $error_counter++;
    if ($error_counter >= $config->{max_errors}) {
        die "Aborted after $error_counter errors\n";
    }
}

# Abort, if $error_counter is set.
sub abort_on_error {
    if ($error_counter) {
        die "Aborted with $error_counter error(s)\n"
    }
}

# Print error message with current input file and line number.
sub error_atline {
    my (@args) = @_;
    print STDERR "Error: ", @args, at_line(), "\n";
    check_abort();
}

# Print error message.
sub err_msg {
    my (@args) = @_;
    print STDERR "Error: ", @args, "\n";
    check_abort();
}

# Print internal error message and abort.
sub internal_err {
    # uncoverable subroutine
    my (@args) = @_;				# uncoverable statement

    # Don't show inherited error.
    # Abort immediately, if other errors have already occured.
    abort_on_error();				# uncoverable statement

    $error_counter++;				# uncoverable statement
    my (undef, $file, $line) = caller;		# uncoverable statement
    my $sub = (caller 1)[3];			# uncoverable statement
    my $msg = "Internal error in $sub";		# uncoverable statement
    $msg .= ": @args" if @args;			# uncoverable statement
    $msg = "$msg\n at $file line $line\n";	# uncoverable statement
    die $msg;					# uncoverable statement
}

####################################################################
# Helper functions for reading configuration
####################################################################

# $input is used as input buffer, it holds content of current input file.
# Progressive matching is used. \G is used to match current position.

sub skip_space_and_comment {
    $input =~ m/ \G [ \t\n]* (?: [#].* $ [ \t\n]* )* /gcmx;
}

# Find next named token or separator token.
sub read_token {

    # Regex of skip_space_and_comment is inlined for performance.
    $input =~ m/ \G [ \t\n]* (?: [#].* $ [ \t\n]* )*
                 ( [^ \t\n;,={}\[\]&!]+ | \S ) /gcmx or
        syntax_err("Unexpected end of file");
    return $1;
}

# Optimize use of CORE:regcomp. Build regex only once for each token.
my %token2regex;

# Check for argument token and skip if available.
sub check {
    my $token = shift;
    skip_space_and_comment;
    my $regex = $token2regex{$token} ||= qr/\G$token/;
    return $input =~ /$regex/gc;
}

# Skip argument character without skipping whitespace.
# Usable for non token characters.
sub skip_char_direct {
    my ($expected) = @_;
    $input =~ /\G(.)/gc and $1 eq $expected or
        syntax_err("Expected '$expected'");
}

# Skip argument token.
# If it is not available an error is printed and the script terminates.
sub skip {
    my ($expected) = @_;
    my $token = read_token();
    $token eq $expected or syntax_err("Expected '$expected'");
}

# Check, if an integer is available.
sub check_int {
    skip_space_and_comment;
    if ($input =~ m/\G(\d+)/agc) {
        return $1;
    }
    else {
        return;
    }
}

# Read an integer.
sub read_int {
    my $result = check_int();
    defined $result or syntax_err("Integer expected");
    return $result;
}

# Check and convert IP address to bit string.
sub convert_ip {
    my ($token) = @_;
    if ($read_ipv6) {
        # $ipv6_re does not match "::"
        $token =~ /^$IPv6_re$|^::$/ or syntax_err("IPv6 address expected");
        return ip2bitstr($token);

    }
    $token =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/a or
        syntax_err("IP address expected");
    if ($1 > 255 or $2 > 255 or $3 > 255 or $4 > 255) {
        error_atline("Invalid IP address");
    }
    no warnings 'pack';

    # Create bit string with 32 bits.
    return pack 'C4', $1, $2, $3, $4;
}

# Read an IP address.
sub read_ip {
    return convert_ip(read_token());
}

# Read IP address and prefix length.
# x.x.x.x/n
# Return two values: IP, mask.
sub read_ip_prefix {
    my $token = read_token();
    my ($part1, $part2) = $token =~ m/^(.*)\/(.*)$/ or
        syntax_err("Expected 'IP/prefixlen'");
    my $ip = convert_ip($part1);
    my $mask = prefix2mask($part2, $read_ipv6);
    defined $mask or syntax_err('Invalid prefix');
    match_ip($ip, $ip, $mask) or error_atline("IP and mask don't match");

    # Prevent further errors.
    $ip &= $mask;
    return $ip, $mask;
}

# Read IP address and prefix length.
# Return an array containing IP, mask.
sub read_ip_prefix_pair {
    my ($ip, $mask) = read_ip_prefix();
    return [ $ip, $mask ];
}

# Read IP range. Remember: '-' may be part of token.
# ip1 - ip2
# ip1-ip2
# ip1- ip2
# ip1 -ip2
sub read_ip_range {
    skip('=');
    my ($ip1, $ip2);
    my $token = read_token();
    if (($ip1, $ip2) = $token =~ /^(.*)-(.*)$/) {
        $ip1 = convert_ip($ip1);
    }
    else {
        $ip1 = convert_ip($token);
        my $token2 = read_token();
        ($ip2) = $token2 =~ /^-(.*)$/ or syntax_err("Expected '-'");
    }
    $ip2 = read_token() if not length($ip2);
    $ip2 = convert_ip($ip2);
    skip(';');
    return $ip1, $ip2;
}

# Convert IP address from internal bit string representation to
# readable string.
## no critic (RequireArgUnpacking RequireFinalReturn)
sub print_ip {
    my ($ip) = @_;
    if (16 == length($ip)) {
        sprintf "%s", NetAddr::IP::Util::ipv6_ntoa($ip);
    }
    else {
        sprintf "%vd", $ip;
    }
}
## use critic

sub read_identifier {
    skip_space_and_comment;
    if ($input =~ m/(\G[\w-]+)/gc) {
        return $1;
    }
    else {
        syntax_err("Identifier expected");
    }
}

# Used for reading hardware name, model, admins, watchers.
sub read_name {
    skip_space_and_comment;
    if ($input =~ m/(\G[^;,\s""'']+)/gc) {
        return $1;
    }
    else {
        syntax_err("String expected");
    }
}

# Used for reading radius attributes.
sub read_string {
    skip_space_and_comment;
    if ($input =~ m/\G([^;,""''\n]+)/gc) {
        return $1;
    }
    else {
        syntax_err("String expected");
    }
}

# Object representing 'user'.
# This is only 'active' while parsing src or dst of the rule of a service.
my $user_object = { active => 0, refcount => 0, elements => undef };

# Read comma or '&' separated list of syntax elements stopped by $stop_token.
# Return list of read elements.
# Sequences of '&' separated elements are stored together in one
# array reference marked with leading '&'.
sub read_union {
    my ($stop_token) = @_;
    my @union;
    my $token = read_token();
    push @union, read_complement($token);

    while (1) {
        $token = read_token();
        if ($token eq $stop_token) {
            last;
        }
        elsif ($token eq ',') {

            # Allow trailing comma.
            $token = read_token();
            last if $token eq $stop_token;
            push @union, read_complement($token);
        }
        elsif ($token eq '&') {
            $token = read_token();
            my $value = read_complement($token);
            my $prev = $union[-1];
            if ($prev->[0] eq '&') {
                push @{ $prev->[1] }, $value;
            }
            else {
                $union[-1] = [ '&', [ $prev, $value ] ];
            }
        }
        else {
            syntax_err("Comma expected in union of values");
        }
    }
    return \@union;
}

# Check for xxx:xxx | router:xx@xx | network:xx/xx | interface:xx/xx
sub check_typed_name {
    my ($token) = @_;
    my ($type, $name, $separator) =
        $token =~ /^ (\w+) : ( [\w-]+ (?: ( [\@\/] ) [\w-]+ )? ) $/x or return;

    if ($separator) {
        if ($type eq 'router') {
            $separator eq '@' or syntax_err("Invalid token");
        }
        elsif ($type eq 'network' or $type eq 'interface') {
            $separator eq '/' or syntax_err("Invalid token");
        }
        else {
            syntax_err("Invalid token");
        }
    }
    return [ $type, $name ];
}

sub read_typed_name {
    my $token = read_token();
    return (check_typed_name($token) or syntax_err("Typed name expected"));
}

{

    # user@domain or @domain
    my $domain_regex   = qr/[\w-]+(?:\.[\w-]+)*/;
    my $user_regex     = qr/[\w-]+(?:\.[\w-]+)*/;
    my $user_id_regex  = qr/$user_regex[@]$domain_regex/;
    my $id_regex       = qr/$user_id_regex|[@]?$domain_regex/;
    my $hostname_regex = qr/(?: id:$id_regex | [\w-]+ )/x;
    my $network_regex  = qr/(?: [\w-]+ (?: \/ [\w-]+ )? )/x;

# Check for xxx:xxx or xxx:[xxx:xxx, ...]
# or interface:xxx.xxx
# or interface:xxx.xxx.xxx
# or interface:xxx.[xxx]
# or interface:r@v. ...
# or interface:....xxx/ppp...
# or interface:[xxx:xxx, ...].[xxx]
# or interface:[managed & xxx:xxx, ...].[xxx]
# or host:[managed & xxx:xxx, ...]
# or any:[ ip = n.n.n.n/len & xxx:xxx, ...]
# or network:xxx/ppp
# or host:id:user@domain.network
# or host:id:[@]domain.network
#
    sub read_extended_name {
        my ($token) = @_;

        if ($token eq 'user') {

            # Global variable for linking occurrences of 'user'.
            $user_object->{active}
              or syntax_err("Unexpected reference to 'user'");
            $user_object->{refcount}++;
            return [ 'user', $user_object ];
        }

        my ($type, $name) = $token =~ /^([\w-]+):(.*)$/ or
            syntax_err("Typed name expected");
        my $interface = $type eq 'interface';
        my $ext;

        my $read_auto_all = sub {
            skip_char_direct('[');
            my $selector = read_identifier;
            $selector =~ /^(auto|all)$/ or syntax_err("Expected [auto|all]");
            $ext = [ $selector, $ext ];
            skip ']';
        };

        if ($name) {
            if ($type eq 'host') {
                verify_hostname($name);
            }
            elsif ($type eq 'network') {
                $name =~ m/^ $network_regex $/xo or
                    syntax_err("Name or bridged name expected");
            }
            elsif ($interface) {
                my ($router_name, $net_name) =
                    $name =~ m/^ ( [\w-]+ (?: \@ [\w-]+ )? ) [.]
                                 ( $network_regex (?: [.] [\w-]+)? )? $/xo or
                    syntax_err("Interface name expected");
                $name = $router_name;
                if ($net_name) {
                    $ext = $net_name;
                }
                else {
                    $read_auto_all->();
                }

            }
            else {
                $name =~ m/^ [\w-]+ $/x or syntax_err("Name expected");
            }
        }
        else {
            skip_char_direct('[');
            if (($interface or $type eq 'host') and check('managed')) {
                $ext = 1;
                skip '&';
            }
            elsif ($type eq 'any' and check('ip')) {
                skip '=';
                $ext = read_ip_prefix_pair();
                skip '&';
            }
            $name = read_union(']');
            if ($interface) {
                skip_char_direct('.');
                $read_auto_all->();
            }
        }
        return $ext ? [ $type, $name, $ext ] : [ $type, $name ];
    }

# user@domain
    sub read_user_id {
        skip_space_and_comment;
        if ($input =~ m/\G($user_id_regex)/gco) {
            return $1;
        }
        else {
            syntax_err("Id expected (a\@b.c)");
        }
    }

# host:xxx or host:id:user@domain or host:id:[@]domain
    sub verify_hostname {
        my ($token) = @_;
        $token =~ m/^$hostname_regex$/o or syntax_err('Hostname expected');
    }
}

sub verify_name {
    my ($token) = @_;
    $token =~ m/^[\w-]+$/ or syntax_err('Valid name expected');
}

sub read_complement {
    my ($token) = @_;
    my $result;
    if ($token eq '!') {
        $token = read_token();
        $result = [ '!', read_extended_name($token) ];
    }
    else {
        $result = read_extended_name($token);
    }
    return $result;
}

# Setup standard time units with different names and plural forms.
my %timeunits = (sec => 1, min => 60, hour => 3600, day => 86400,);
$timeunits{second} = $timeunits{sec};
$timeunits{minute} = $timeunits{min};
for my $key (keys %timeunits) {
    $timeunits{"${key}s"} = $timeunits{$key};
}

# Read time value in different units, return seconds.
sub read_time_val {
    my $int    = read_int();
    my $unit   = read_identifier();
    my $factor = $timeunits{$unit} or syntax_err("Time unit expected");
    return $int * $factor;
}

sub read_time_kilobytes_pair {
    my $int    = read_int();
    my $unit   = read_identifier();
    my ($seconds, $kbytes);
    if (my $factor = $timeunits{$unit}) {
        $seconds = $int * $factor;
        $kbytes = check_int();
        if (defined $kbytes) {
            skip('kilobytes');
        }
    }
    elsif ($unit eq 'kilobytes') {
        $kbytes = $int;
    }
    else {
        syntax_err("Time unit or 'kilobytes' expected");
    }
    return [ $seconds, $kbytes ];
}

# Set description for passed object if next input is a description.
sub add_description {
    my ($obj) = @_;
    check 'description' or return;
    skip '=';

    # Read up to end of line, but ignore ';' at EOL.
    if($input =~ m/\G[ \t]*(.*?)[ \t]*;?[ \t]*$/gcm) {
        $obj->{description} = $1;
    }
}

# Split argument at first ':' and return the two parts.
sub split_typed_name {
    my ($name) = @_;

    # Split at first colon; the name may contain further colons.
    return split /[:]/, $name, 2;
}

# Read '=' and value(s).
# Argument function is used to read value(s).
# Depending on calling context, one or multiple values are returned.
sub read_assign {
    my ($fun) = @_;
    skip '=';
    if (wantarray) {
        my @val = &$fun;
        skip(';');
        return @val;
    }
    else {
        my $val = &$fun;
        skip(';');
        return $val;
    }
}

# Use the passed function to read one or more elements from global
# input until reaching a ';'.
# Return array of read elements.
sub read_assign_list {
    my ($fun) = @_;
    skip '=';
    my @result;
    while (1) {
        push @result, &$fun;
        my $token = read_token();
        last if $token eq ';';
        if ($token eq ',') {

            # Allow trailing comma.
            last if check(';');
        }
        else {
            syntax_err("Comma expected in list of values");
        }
    }
    return \@result;
}

####################################################################
# Creation of typed hashes.
# Currently we don't use OO features;
# We use 'bless' only to give each hash a distinct type.
####################################################################

# Create a new hash, blessed to given type;
# initialize it with key / value pairs.
sub new {
    my ($type, @pairs) = @_;
    my $self = { @pairs };
    return bless $self, $type;
}

# Add the passed key/value to the hash object,
# or prints an error message if key already exists.
sub add_attribute {
    my ($obj, $key, $value) = @_;
    defined $obj->{$key} and error_atline("Duplicate attribute '$key'");
    $obj->{$key} = $value;
}

our %hosts;

sub read_network_assign {
    my ($context) = @_;
    my $pair = read_assign(\&read_typed_name);
    my ($type, $name) = @$pair;
    if ($type ne 'network' or ref $name) {
        error_atline "Must only use network name in '$context'";
        $name = undef;
    }
    return $name;
}

sub read_radius_attributes {
    my $result = {};
    skip '=';
    skip '{';
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        verify_name($token);
        my $val = check('=') ? read_string : undef;
        skip ';';
        add_attribute($result, $token => $val);
    }
    return $result;
}

# Uses global variable %routing_info with definition of dynamic
# routing protocols
sub read_routing {
    my $protocol = read_assign(\&read_identifier);
    my $routing = $routing_info{$protocol}
      or error_atline('Unknown routing protocol');
    return $routing;
}

sub read_managed {
    my $managed;
    my $token = read_token();
    if ($token eq ';') {
        $managed = 'standard';
    }
    elsif ($token eq '=') {
        my $value = read_token();
        if (
            $value =~ /^(?:secondary|standard|full|primary|local
                           |routing_only)$/x
          )
        {
            $managed = $value;
        }
        else {
            error_atline(
                "Expected value:",
                " secondary|standard|full|primary|local",
                "|routing_only"
            );
        }
        skip(';');
    }
    else {
        syntax_err("Expected ';' or '='");
    }
    return $managed;
}

sub read_model {
    my $names = read_assign_list(\&read_name);
    my ($model, @attributes) = @$names;
    my $info = $router_info{$model};
    if (not $info) {
        error_atline("Unknown router model");

        # Prevent further errors.
        return { name => $model };
    }
    my $extension_info = $info->{extension} || {};

    my @ext_list = map {
        my $ext = $extension_info->{$_};
        $ext or error_atline("Unknown extension $_");
        $ext ? %$ext : ();
    } @attributes;
    if (@ext_list) {
        $info = { %$info, @ext_list };
        delete $info->{extension};
        $info->{name} = join(', ', $model, sort @attributes);
    }
    return $info;
}

# List of all managed routers.
my @managed_routers;

# List of router fragments, split from crypto routers.
my @router_fragments;

# Managed host is stored internally as an interface.
# The interface gets an artificial router.
# Both, router and interface get name "host:xx".
sub host_as_interface {
    my ($host)  = @_;
    my $name    = $host->{name};
    my $model   = delete $host->{model};
    my $hw_name = delete $host->{hardware};
    if (not $model) {
        err_msg("Missing 'model' for managed $host->{name}");

        # Prevent further errors.
        $model = $host->{model} = { name => 'unknown' };
    }
    elsif (not $model->{can_managed_host}) {
        err_msg("Must not use model $model->{name} at managed $name");
    }
    if (not $hw_name) {
        err_msg("Missing 'hardware' for $name");
    }

    # Use device_name with "host:.." prefix to prevent name clash with
    # real routers.
    my $device_name =
      $host->{server_name} ? "host:$host->{server_name}" : $name;
    my $router = new('Router', name => $name, device_name => $device_name);
    $router->{managed} = delete $host->{managed};
    $router->{model}   = $model;
    my $interface = new('Interface', %$host);
    $interface->{router} = $router;
    my $hardware = { name => $hw_name, interfaces => [$interface] };
    $interface->{hardware}        = $hardware;
    $interface->{routing}         = $routing_info{manual};
    $interface->{is_managed_host} = 1;
    $router->{interfaces}         = [$interface];
    $router->{hardware}           = [$hardware];
    if ($read_ipv6) {
        $router->{ipv6} = 1;
        $interface->{ipv6} = 1;
    }

    # Don't add to %routers
    # - Name lookup isn't needed.
    # - Linking with network isn't needed.
    push @managed_routers, $router;
    return $interface;
}

# Read definition of host.
# Is called while definition of network is read.
sub read_host {
    my ($name, $network_name) = @_;
    my $host = new('Host');
    $host->{private} = $private if $private;
    if (my ($id) = ($name =~ /^host:id:(.*)$/)) {

        # Make ID unique by appending name of enclosing network.
        $name = "$name.$network_name";
        $host->{id} = $id;
    }
    $host->{name} = $name;
    skip '=';
    skip '{';
    add_description($host);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'ip') {
            my $ip = read_assign(\&read_ip);
            add_attribute($host, ip => $ip);
        }
        elsif ($token eq 'range') {
            my ($ip1, $ip2) = read_ip_range();
            $ip1 le $ip2 or error_atline("Invalid IP range");
            add_attribute($host, range => [ $ip1, $ip2 ]);
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($host, owner => $owner);
        }

        elsif ($token eq 'managed') {
            my $managed = read_managed();

            # Currently, only simple 'managed' attribute,
            # because 'secondary' and 'local' isn't supported by Linux.
            $managed eq 'standard'
              or error_atline("Only 'managed=standard' is supported");
            add_attribute($host, managed => $managed);
        }
        elsif ($token eq 'model') {
            my $model = read_model();
            add_attribute($host, model => $model);
        }
        elsif ($token eq 'hardware') {
            my $hardware = read_assign(\&read_name);
            add_attribute($host, hardware => $hardware);
        }
        elsif ($token eq 'server_name') {
            my $server_name = read_assign(\&read_name);
            add_attribute($host, server_name => $server_name);
        }
        elsif ($token eq 'radius_attributes') {
            my $radius_attributes = read_radius_attributes();
            add_attribute($host, radius_attributes => $radius_attributes);
        }
        elsif (my ($type, $name2) = $token =~ /^ (\w+) : (.+) $/x) {
            if ($type eq 'nat') {
                verify_name($name2);
                skip '=';
                skip '{';
                skip 'ip';
                skip '=';
                my $nat_ip = read_ip;
                skip ';';
                skip '}';
                $host->{nat}->{$name2} and
                    err_msg("Duplicate NAT definition nat:$name2 at $name");
                $host->{nat}->{$name2} = $nat_ip;
            }
            else {
                syntax_err('Unexpected token');
            }
        }
        else {
            syntax_err('Unexpected token');
        }
    }
    $host->{ip} xor $host->{range}
      or err_msg("$name needs exactly one of attributes 'ip' and 'range'");

    if ($host->{managed}) {
        my %ok = (
            name        => 1,
            ip          => 1,
            nat         => 1,
            file        => 1,
            private     => 1,
            managed     => 1,
            model       => 1,
            hardware    => 1,
            server_name => 1
        );
        for my $key (sort keys %$host) {
            next if $ok{$key};
            err_msg("Managed $name must not have attribute '$key'");
        }
        $host->{ip} ||= 'short';
        return host_as_interface($host);
    }
    if ($host->{id}) {
        $host->{radius_attributes} ||= {};
    }
    else {
        $host->{radius_attributes}
          and warn_msg("Ignoring 'radius_attributes' at $name");
    }
    if ($host->{nat}) {
        if ($host->{range}) {

            # Before changing this,
            # add consistency tests in convert_hosts.
            err_msg("No NAT supported for $name with 'range'");
        }
    }
    return $host;
}

sub read_nat {
    my ($nat_tag, $obj_name, $mask_is_optional) = @_;

    # Currently this needs not to be blessed.
    my $nat = {};
    skip '=';
    skip '{';
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'ip') {
            my ($ip, $mask) = read_assign(  $mask_is_optional
                                          ? \&read_ip
                                          : \&read_ip_prefix);
            add_attribute($nat, ip   => $ip);
            add_attribute($nat, mask => $mask);
        }
        elsif ($token eq 'hidden') {
            skip(';');
            $nat->{hidden} = 1;
        }
        elsif ($token eq 'identity') {
            skip(';');
            $nat->{identity} = 1;
        }
        elsif ($token eq 'dynamic') {
            skip(';');
            $nat->{dynamic} = 1;
        }
        elsif ($token eq 'subnet_of') {
            my $net_name = read_network_assign($token);
            add_attribute($nat, subnet_of => $net_name);
        }
        else {
            syntax_err('Unexpected token');
        }
    }
    if ($nat->{hidden}) {
        for my $key (sort keys %$nat) {
            next if $key eq 'hidden';
            error_atline("Hidden NAT must not use attribute $key");
            delete $nat->{$key};
        }

        # This simplifies error checks for overlapping addresses.
        $nat->{dynamic} = 1;

        # Provide an unusable address.
        # This prevents 'Use of uninitialized value'
        # if code generation is started concurrently,
        # before all error conditions are checked.
        my $zero_ip = $nat->{ip} = get_zero_ip($read_ipv6);
        $nat->{mask} = get_host_mask($zero_ip);
    }
    elsif ($nat->{identity}) {
        for my $key (sort keys %$nat) {
            next if $key eq 'identity';
            error_atline("Identity NAT must not use attribute $key");
            delete $nat->{$key};
        }
        $nat->{dynamic} = 1;
    }
    else {
        defined($nat->{ip}) or syntax_err('Missing IP address');
    }

    # Attribute {nat_tag} is used later to look up static translation
    # of hosts inside a dynamically translated network.
    $nat->{nat_tag} = $nat_tag;

    $nat->{name} = $obj_name;
    $nat->{descr} = "nat:$nat_tag of $obj_name";
    return $nat;
}

# Mapping from network names to network objects.
our %networks;

sub read_network {
    my $name = shift;

    # Network name without prefix "network:" is needed to build
    # name of ID-hosts.
    (my $net_name = $name) =~ s/^network://;
    my $network = new('Network', name => $name);
    $network->{private} = $private if $private;
    if ($net_name =~ m,^(.*)/,) {
        $network->{bridged} = $1;
    }
    skip '=';
    skip '{';
    add_description($network);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'ip') {
            my ($ip, $mask) = read_assign(\&read_ip_prefix);
            add_attribute($network, ip   => $ip);
            add_attribute($network, mask => $mask);
        }
        elsif ($token eq 'unnumbered') {
            skip(';');
            defined $network->{ip} and error_atline("Duplicate IP address");
            $network->{ip} = 'unnumbered';
        }
        elsif ($token eq 'has_subnets') {
            skip(';');
            $network->{has_subnets} = 1;
        }
        elsif ($token eq 'crosslink') {
            skip(';');
            $network->{crosslink} = 1;
        }
        elsif ($token eq 'subnet_of') {
            my $net_name = read_network_assign($token);
            add_attribute($network, subnet_of => $net_name);
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($network, owner => $owner);
        }
        elsif ($token eq 'radius_attributes') {
            my $radius_attributes = read_radius_attributes();
            add_attribute($network, radius_attributes => $radius_attributes);
        }
        elsif (my ($type, $name2) = $token =~ /^ (\w+) : (.+) $/x) {
            if ($type eq 'host') {
                verify_hostname($name2);
                my  $host_name = $name2;
                my $host = read_host("host:$host_name", $net_name);
                $host->{network} = $network;
                $host->{ipv6} = 1 if $read_ipv6;
                if (is_host($host)) {
                    push @{ $network->{hosts} }, $host;
                    $host_name = (split_typed_name($host->{name}))[1];
                }

                # Managed host is stored as interface internally.
                else {
                    push @{ $network->{interfaces} }, $host;
                    check_interface_ip($host, $network);

                    # For use in expand_group.
                    push @{ $network->{managed_hosts} }, $host;
                }

                if (my $other = $hosts{$host_name}) {
                    my $where     = $current_file;
                    my $other_net = $other->{network};
                    if ($other_net ne $network) {
                        my $other_file = $other_net->{file};
                        if ($where ne $other_file) {
                            $where = "$other_file and $where";
                        }
                    }
                    err_msg("Duplicate definition of host:$host_name",
                            " in $where");
                }
                $hosts{$host_name} = $host;
            }
            elsif ($type eq 'nat') {
                verify_name($name2);
                my $nat_tag = $name2;
                my $nat = read_nat($nat_tag, $name);
                $nat->{name}  = $name;
                $network->{nat}->{$nat_tag} and
                    err_msg("Duplicate NAT definition nat:$nat_tag at $name");
                $network->{nat}->{$nat_tag} = $nat;
            }
            else {
                syntax_err('Unexpected token');
            }
        }
        else {
            syntax_err('Unexpected token');
        }
    }

    # Network needs at least IP and mask to be defined.
    my $ip = $network->{ip} or syntax_err("Missing network IP");

    if ($ip eq 'unnumbered') {
        my %ok = (ip => 1, name => 1, crosslink => 1, private => 1);

        # Unnumbered network must not have any other attributes.
        for my $key (sort keys %$network) {
            next if $ok{$key};
            delete $network->{$key};
            err_msg(
                "Unnumbered $name must not have ",
                ($key eq 'hosts') ? "host definition"
                : ($key eq 'nat') ? "nat definition"
                :                   "attribute '$key'"
            );
        }
    }
    elsif ($network->{bridged}) {
        if (my $hosts = $network->{hosts}) {
            for my $host (@$hosts) {
                $host->{range} or next;
                err_msg("Bridged $name must not have ",
                        "$host->{name} with range (not implemented)");
            }
        }
        if (my $hash = $network->{nat}) {
            for my $nat_tag (sort keys %$hash) {
                $hash->{$nat_tag}->{identity} and next;
                delete $hash->{$nat_tag};
                err_msg(
                    "Only identity NAT allowed for bridged $network->{name}");
                last;
            }
        }
    }
    else {
        my $mask = $network->{mask};
        for my $host (@{ $network->{hosts} }) {

            # Check compatibility of host IP and network IP/mask.
            if (my $host_ip = $host->{ip}) {
                if (not(match_ip($host_ip, $ip, $mask))) {
                    err_msg("IP of $host->{name} doesn't match",
                            " IP/mask of $name");
                }
            }

            # Check range.
            else {
                my ($ip1, $ip2) = @{ $host->{range} };
                if (
                    not(    match_ip($ip1, $ip, $mask)
                        and match_ip($ip2, $ip, $mask))
                  )
                {
                    err_msg("IP range of $host->{name} doesn't match",
                            " IP/mask of $name");
                }
            }

            # Compatibility of host and network NAT will be checked later,
            # after inherited NAT definitions have been processed.
        }
        if (@{ $network->{hosts} } and $network->{crosslink}) {
            err_msg("Crosslink $name must not have host definitions");
        }

        # Check NAT definitions.
        if (my $href = $network->{nat}) {
            for my $nat_tag (sort keys %$href) {
                my $nat = $href->{$nat_tag};
                next if $nat->{dynamic};
                $nat->{mask} eq $mask
                  or err_msg("Mask for non dynamic nat:$nat_tag",
                             " must be equal to mask of $name");
            }
        }

        # Check and mark networks with ID-hosts.
        if (my $id_hosts_count = grep { $_->{id} } @{ $network->{hosts} }) {

            # If one host has ID, all hosts must have ID.
            @{ $network->{hosts} } == $id_hosts_count
              or err_msg("All hosts must have ID in $name");

            # Mark network.
            $network->{has_id_hosts} = 1;
            $network->{radius_attributes} ||= {};
        }
        else {
            $network->{radius_attributes}
              and warn_msg("Ignoring 'radius_attributes' at $name");
        }
    }
    return $network;
}

# Mapping from interface names to interface objects.
our %interfaces;

my @virtual_interfaces;

# Tunnel networks which are already attached to tunnel interfaces
# at spoke devices. Key is crypto name, not crypto object.
my %crypto2spokes;

# Real interface at crypto hub, where tunnels are attached.
# Key is crypto name, not crypto object.
my %crypto2hub;

sub read_interface {
    my ($name) = @_;
    my $interface = new('Interface', name => $name);

    # Short form of interface definition.
    if (check(';')) {
        $interface->{ip} = 'short';
        return $interface;
    }

    my @secondary_interfaces = ();
    my $virtual;
    skip '=';
    skip '{';
    add_description($interface);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'ip') {
            my $ip_list = read_assign_list(\&read_ip);
            add_attribute($interface, ip => shift(@$ip_list));

            # Build interface objects for secondary IP addresses.
            # These objects are named interface:router.name.2, ...
            my $counter = 2;
            for my $ip (@$ip_list) {
                push @secondary_interfaces,
                  new('Interface', name => "$name.$counter", ip => $ip);
                $counter++;
            }
        }
        elsif ($token eq 'hardware') {
            my $hardware = read_assign(\&read_name);
            add_attribute($interface, hardware => $hardware);
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($interface, owner => $owner);
        }
        elsif ($token eq 'unnumbered') {
            skip(';');
            add_attribute($interface, ip => 'unnumbered');
        }
        elsif ($token eq 'negotiated') {
            skip(';');
            add_attribute($interface, ip => 'negotiated');
        }
        elsif ($token eq 'loopback') {
            skip(';');
            $interface->{loopback} = 1;
        }
        elsif ($token eq 'vip') {
            skip(';');
            $interface->{vip} = 1;
        }
        elsif ($token eq 'no_in_acl') {
            skip(';');
            $interface->{no_in_acl} = 1;
        }
        elsif ($token eq 'dhcp_server') {
            skip(';');
            $interface->{dhcp_server} = 1;
        }
        elsif ($token eq 'dhcp_client') {
            skip(';');
            $interface->{dhcp_client} = 1;
        }

        # Needed for the implicitly defined network of 'loopback'.
        elsif ($token eq 'subnet_of') {
            my $net_name = read_network_assign($token);
            add_attribute($interface, subnet_of => $net_name);
        }
        elsif ($token eq 'hub') {
            my $pairs = read_assign_list(\&read_typed_name);
            for my $pair (@$pairs) {
                my ($type, $name2) = @$pair;
                $type eq 'crypto' or error_atline("Expected type 'crypto:'");
                push @{ $interface->{hub} }, "$type:$name2";
            }
        }
        elsif ($token eq 'spoke') {
            my $pair = read_assign(\&read_typed_name);
            my ($type, $name2) = @$pair;
            $type eq 'crypto' or error_atline("Expected type 'crypto:'");
            add_attribute($interface, spoke => "$type:$name2");
        }
        elsif ($token eq 'id') {
            my $id = read_assign(\&read_user_id);
            add_attribute($interface, id => $id);
        }
        elsif (my ($type, $name2) = $token =~ /^ (\w+) : (.+) $/x) {
            if ($type eq 'nat') {
                verify_name($name2);
                my $nat_tag = $name2;
                my $nat = read_nat($nat_tag, $name, 'mask_is_optional');
                $interface->{nat}->{$nat_tag} and
                    err_msg("Duplicate NAT definition nat:$nat_tag at $name");
                $interface->{nat}->{$nat_tag} = $nat;
            }
            elsif ($type eq 'secondary') {
                verify_name($name2);

                # Build new interface for secondary IP addresses.
                my $secondary = new('Interface', name => "$name.$name2");
                skip '=';
                skip '{';
                while (1) {
                    my $token = read_token();
                    if ($token eq '}') {
                        last;
                    }
                    elsif ($token eq 'ip') {
                        my $ip = read_assign(\&read_ip);
                        add_attribute($secondary, ip => $ip);
                    }
                    else {
                        syntax_err("Expected attribute 'ip'");
                    }
                }
                if ($secondary->{ip}) {
                    push @secondary_interfaces, $secondary;
                }
                else {
                    error_atline("Missing IP address");
                }
            }
            else {
                syntax_err('Unexpected token');
            }
        }
        elsif ($token eq 'virtual') {
            $virtual and error_atline("Duplicate virtual interface");

            # Read attributes of redundancy protocol (VRRP/HSRP).
            $virtual = new(
                'Interface',
                name      => "$name.virtual",
                redundant => 1
            );
            skip '=';
            skip '{';
            while (1) {
                my $token = read_token();
                if ($token eq '}') {
                    last;
                }
                elsif ($token eq 'ip') {
                    my $ip = read_assign(\&read_ip);
                    add_attribute($virtual, ip => $ip);
                }
                elsif ($token eq 'type') {
                    my $type = read_assign(\&read_identifier);
                    $xxrp_info{$type}
                      or error_atline("Unknown redundancy protocol");
                    add_attribute($virtual, redundancy_type => $type);
                }
                elsif ($token eq 'id') {
                    my $id = read_assign(\&read_identifier);
                    $id =~ /^\d+$/a
                      or error_atline("Redundancy ID must be numeric");
                    $id < 256 or error_atline("Redundancy ID must be < 256");
                    add_attribute($virtual, redundancy_id => $id);
                }
                else {
                    syntax_err('Unexpected token');
                }
            }
            $virtual->{ip} or error_atline("Missing virtual IP");
            $virtual->{redundancy_id} and not $virtual->{redundancy_type}
              and
              syntax_err("Redundancy ID is given without redundancy protocol");
        }
        elsif ($token eq 'bind_nat') {
            my $tags = read_assign_list(\&read_identifier);
            $interface->{bind_nat} and error_atline("Duplicate NAT binding");
            $interface->{bind_nat} = [ unique sort @$tags ];
        }
        elsif ($token eq 'routing') {
            my $routing = read_routing();
            add_attribute($interface, routing => $routing);
        }
        elsif ($token eq 'reroute_permit') {
            skip '=';
            my $elements = read_union(';');
            add_attribute($interface, reroute_permit => $elements);
        }
        elsif ($token eq 'disabled') {
            skip(';');
            $interface->{disabled} = 1;
        }
        elsif ($token eq 'no_check') {
            skip(';');
            $interface->{no_check} = 1;
        }
        else {
            syntax_err('Unexpected token');
        }
    }

    # Interface at bridged network
    # - without IP is interface of bridge,
    # - with IP is interface of router.
    if ($name =~ m,/,) {
        $interface->{ip} ||= 'bridged';
    }

    # Swap virtual interface and main interface
    # or take virtual interface as main interface if no main IP available.
    # Subsequent code becomes simpler if virtual interface is main interface.
    if ($virtual) {
        if (my $ip = $interface->{ip}) {
            if ($ip =~ /^(unnumbered|negotiated|bridged)$/) {
                error_atline("No virtual IP supported for $ip interface");
            }

            # Move main IP to secondary.
            my $secondary =
              new('Interface', name => $interface->{name}, ip => $ip);
            push @secondary_interfaces, $secondary;

            # But we need the original main interface
            # when handling auto interfaces.
            $interface->{orig_main} = $secondary;
        }
        for my $attr (qw(nat hub spoke)) {
            $interface->{$attr} or next;
            err_msg("$name with virtual interface must not use",
                    " attribute '$attr'");
        }
        @{$interface}{qw(name ip redundant redundancy_type redundancy_id)} =
          @{$virtual}{qw(name ip redundant redundancy_type redundancy_id)};
        push @virtual_interfaces, $interface;
    }
    else {
        $interface->{ip} ||= 'short';
    }
    if ($interface->{nat}) {
        if ($interface->{ip} =~ /^(unnumbered|negotiated|short|bridged)$/) {
            error_atline("No NAT supported for $interface->{ip} interface");
        }
    }

    # Attribute 'vip' is an alias for 'loopback'.
    if ($interface->{vip}) {
        $interface->{loopback} = 1;
    }
    if ($interface->{loopback}) {
        my $type = $interface->{vip} ? "'vip'" : 'loopback';
        if (@secondary_interfaces) {
            error_atline("\u$type interface must not have secondary IP address");
            @secondary_interfaces = ();
            delete $interface->{orig_main};	# From virtual interface
        }

        my %copy = %$interface;

        # Only these attributes are valid.
        delete @copy{
            qw(name ip nat bind_nat hardware loopback subnet_of
              owner redundant redundancy_type redundancy_id vip)
        };
        if (keys %copy) {
            my $attr = join ", ", map { "'$_'" } sort keys %copy;
            error_atline("Invalid attributes $attr for $type interface");
        }
        if ($interface->{ip} =~ /^(unnumbered|negotiated|short|bridged)$/) {
            error_atline("\u$type interface must not be $interface->{ip}");
            $interface->{disabled} = 1;
        }
    }
    elsif ($interface->{subnet_of}) {
        error_atline("Attribute 'subnet_of' is only valid",
            " for loopback interface");
    }
    if ($interface->{ip} eq 'bridged') {
        my %ok = map({ $_ => 1 }
                     qw(ip hardware name bind_nat disabled loopback));
        if (my @extra = grep { not $ok{$_} } keys %$interface) {
            my $attr = join ", ", map { "'$_'" } sort @extra;
            error_atline("Invalid attributes $attr for bridged interface");
        }
    }
    if ($interface->{spoke}) {
        if (@secondary_interfaces) {
            error_atline("Interface with attribute 'spoke'",
                         " must not have secondary interfaces");
            @secondary_interfaces = ();
        }
        $interface->{hub}
          and error_atline(
            "Interface with attribute 'spoke'",
            " must not have attribute 'hub'"
          );
    }
    else {
        $interface->{id}
          and
          error_atline("Attribute 'id' is only valid for 'spoke' interface");
    }
    if (my $crypto_list = $interface->{hub}) {
        if ($interface->{ip} =~ /^(unnumbered|negotiated|short|bridged)$/) {
            error_atline("Crypto hub must not be $interface->{ip} interface");
        }
        for my $crypto (@$crypto_list) {
            if (my $other = $crypto2hub{$crypto}) {
                err_msg("Must use hub = $crypto exactly once, not at both\n",
                        " - $other->{name}\n",
                        " - $interface->{name}");
            }
            else {
                $crypto2hub{$crypto} = $interface;
            }
        }
    }
    if (@secondary_interfaces) {
        if ($interface->{ip} =~ /^(negotiated|short|bridged)$/) {
            error_atline("\u$interface->{ip} interface must not have",
                " secondary IP address");
            @secondary_interfaces = ();
        }
    }
    for my $secondary (@secondary_interfaces) {
        $secondary->{main_interface} = $interface;
        for my $key (qw(hardware bind_nat routing disabled)) {
            $secondary->{$key} = $interface->{$key} if $interface->{$key};
        }
    }
    return $interface, @secondary_interfaces;
}

#############################################################################
# Purpose  : Moves attribute 'no_in_acl' from interfaces to hardware because
#            ACLs operate on hardware, not on logic. Marks hardware needing
#            outgoing ACLs.
# Comments : Not more than 1 'no_in_acl' interface/router allowed.
sub check_no_in_acl {
    my ($router) = @_;
    my $no_in_acl_counter = 0;

    # At interfaces with no_in_acl move attribute to hardware.
    for my $interface (@{ $router->{interfaces} }) {
        delete $interface->{no_in_acl} or next;
        my $hardware = $interface->{hardware};

        # Prevent duplicate error message.
        next if $hardware->{no_in_acl};
        $hardware->{no_in_acl} = 1;

        # Assure max number of main interfaces at no_in_acl-hardware == 1.
        1 == grep({ not $_->{main_interface} } @{ $hardware->{interfaces} })
          or err_msg(
            "Only one logical interface allowed at hardware",
            " '$hardware->{name}' of $router->{name}\n",
            " because of attribute 'no_in_acl'"
          );
        $no_in_acl_counter++;

        # Reference no_in_acl interface in router attribute.
        $router->{no_in_acl} = $interface;
    }
    $no_in_acl_counter or return;

    # Assert maximum number of 'no_in_acl' interfaces per router
    1 == $no_in_acl_counter
      or err_msg("At most one interface of $router->{name}",
                 " may use flag 'no_in_acl'");

    # Assert router to support outgoing ACL
    $router->{model}->{has_out_acl}
      or err_msg("$router->{name} doesn't support outgoing ACL");

    # reroute_permit would generate permit any -> networks,
    # but no_in_acl would generate permit any -> any anyway.
    if ($router->{no_in_acl}->{reroute_permit}) {
        err_msg("Useless use of attribute reroute_permit together with",
                " no_in_acl at $router->{no_in_acl}->{name}");
    }

    # Must not use reroute_permit to network N together with no_in_acl.
    # In this case incoming traffic at no_in_acl interface
    # to network N wouldn't be filtered at all.
    if (my @list = grep { $_->{reroute_permit} } @{ $router->{interfaces} }) {
        if (not (1 == @list and $router->{no_in_acl} eq $list[0])) {
            err_msg("Must not use attributes no_in_acl and reroute_permit",
                    " together at $router->{name}\n",
                    " Add incoming and outgoing ACL line in raw file instead.");
        }
    }

    # Assert router not to take part in crypto tunnels.
    if (grep { $_->{hub} or $_->{spoke} } @{ $router->{interfaces} }) {
        err_msg(
            "Don't use attribute 'no_in_acl' together",
            " with crypto tunnel at $router->{name}"
        );
    }

    # Mark other hardware with attribute 'need_out_acl'.
    for my $hardware (@{ $router->{hardware} }) {
        $hardware->{no_in_acl}
          or $hardware->{need_out_acl} = 1;
    }
}

my $bind_nat0 = [];

# Mapping from router names to router objects.
our %routers;
our %routers6;

sub read_router {
    my $name = shift;
    my $has_bind_nat;

    # Extract
    # - router name without prefix "router:", needed to build interface name
    # - optional vrf name
    my ($rname, $device_name, $vrf) =
      $name =~ /^ router : ( (.*?) (?: \@ (.*) )? ) $/x;
    my $router = new('Router', name => $name, device_name => $device_name);
    if (defined $vrf) {

        # VRF value "0" would be interpreted as false by perl.
        $vrf or error_atline("Must not use '$vrf' as VRF value");
        $router->{vrf} = $vrf;
    }
    skip '=';
    skip '{';
    add_description($router);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'managed') {
            my $managed = read_managed();
            $router->{managed}
              and error_atline("Redefining 'managed' attribute");
            $router->{managed} = $managed;
        }
        elsif ($token eq 'filter_only') {
            my $filter_only = read_assign_list(\&read_ip_prefix_pair);
            add_attribute($router, filter_only => $filter_only);
        }
        elsif ($token eq 'model') {
            my $model = read_model();
            add_attribute($router, model => $model);
        }
        elsif ($token eq 'no_group_code') {
            skip(';');
            $router->{no_group_code} = 1;
        }
        elsif ($token eq 'no_protect_self') {
            skip(';');
            $router->{no_protect_self} = 1;
        }
        elsif ($token eq 'log_deny') {
            skip(';');
            $router->{log_deny} = 1;
        }
        elsif ($token eq 'acl_use_real_ip') {
            skip(';');
            $router->{acl_use_real_ip} = 1;
        }
        elsif ($token eq 'routing') {
            my $routing = read_routing();
            add_attribute($router, routing => $routing);
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($router, owner => $owner);
        }
        elsif ($token eq 'radius_attributes') {
            my $radius_attributes = read_radius_attributes();
            add_attribute($router, radius_attributes => $radius_attributes);
        }
        elsif ($token eq 'policy_distribution_point') {
            my $pair = read_assign(\&read_typed_name);
            add_attribute($router, policy_distribution_point => $pair);
        }
        elsif ($token eq 'general_permit') {
            skip('=');
            my $list = read_typed_name_or_simple_protocol_list();
            add_attribute($router, general_permit => $list);
        }
        elsif (my ($type, $name2) = $token =~ /^ (\w+) : (.+) $/x) {
            if ($type eq 'log') {
                $name2 =~ /^ [\w-]+ $/x or syntax_err("Invalid log name");
                defined($router->{log}->{$name2})
                  and error_atline("Duplicate 'log' definition");
                my $modifier = check('=') ? read_identifier() : 0;
                $router->{log}->{$name2} = $modifier;
                skip(';');
                next;
            }
            elsif ($type ne 'interface') {
                syntax_err('Unexpected token');
            }

            $name2 =~ /^ [\w-]+ (?: \/ [\w-]+ ) ? $/x or
                syntax_err("Invalid interface name");

            # Derive interface name from router name.
            my $iname = "$rname.$name2";
            for my $interface (read_interface("interface:$iname")) {
                push @{ $router->{interfaces} }, $interface;
                ($iname = $interface->{name}) =~ s/interface://;
                if ($interfaces{$iname}) {
                    error_atline("Redefining $interface->{name}");
                }

                # Assign interface to global hash of interfaces.
                $interfaces{$iname} = $interface;
                $interface->{ipv6} = 1 if $read_ipv6;

                # Link interface with router object.
                $interface->{router} = $router;

                # Link interface with network name (will be resolved later).
                $interface->{network} = $name2;

                # Set private attribute of interface.
                $interface->{private} = $private if $private;
            }
        }
        else {
            syntax_err('Unexpected token');
        }
    }

    my $model = $router->{model};

    if (my $managed = $router->{managed}) {
        if (not $model) {
            err_msg("Missing 'model' for managed $name");

            # Prevent further errors.
            $router->{model} = { name => 'unknown' };
        }

        # Router is semi_managed if only routes are generated.
        if ($managed eq 'routing_only') {
            $router->{semi_managed} = 1;
            $router->{routing_only} = 1;
            delete $router->{managed};
        }

        $router->{vrf}
          and not $model->{can_vrf}
          and err_msg("Must not use VRF at $name", " of model $model->{name}");

        # Create objects representing hardware interfaces.
        # All logical interfaces using the same hardware are linked
        # to the same hardware object.
        my %hardware;
        for my $interface (@{ $router->{interfaces} }) {

            # Managed router must not have short interface.
            if ($interface->{ip} eq 'short') {
                err_msg "Short definition of $interface->{name} not allowed";
            }

            my $hw_name = $interface->{hardware};

            # Interface of managed router needs to have a hardware
            # name.
            if (not $hw_name) {

                # Prevent duplicate error message.
                if ($interface->{ip} ne 'short') {
                    err_msg("Missing 'hardware' for $interface->{name}");
                }

                # Prevent further errors.
                $hw_name = 'unknown';
            }

            my $hardware;
            if ($hardware = $hardware{$hw_name}) {

                # All logical interfaces of one hardware interface
                # need to use the same NAT binding,
                # because NAT operates on hardware, not on logic.
                aref_eq(
                    $interface->{bind_nat} || $bind_nat0,
                    $hardware->{bind_nat}  || $bind_nat0
                  )
                  or err_msg "All logical interfaces of $hw_name\n",
                  " at $name must use identical NAT binding";
            }
            else {
                $hardware = { name => $hw_name, loopback => 1 };
                $hardware{$hw_name} = $hardware;
                push @{ $router->{hardware} }, $hardware;
                if (my $nat = $interface->{bind_nat}) {
                    $hardware->{bind_nat} = $nat;
                }
            }
            $interface->{hardware} = $hardware;

            # Hardware keeps attribute {loopback} only if all
            # interfaces have attribute {loopback}.
            if (not $interface->{loopback}) {
                delete $hardware->{loopback};
            }

            $has_bind_nat = 1 if $interface->{bind_nat};

            # Remember, which logical interfaces are bound
            # to which hardware.
            push @{ $hardware->{interfaces} }, $interface;

            # Don't allow 'routing=manual' at single interface, because
            # approve would remove manual routes otherwise.
            # Approve only leaves routes unchanged, if Netspoc generates
            # no routes at all.
            if ((my $routing = $interface->{routing})) {
                $routing->{name} eq 'manual'
                  and warn_msg(
                    "'routing=manual' must only be applied",
                    " to router, not to $interface->{name}"
                  );
            }

            # Interface inherits routing attribute from router.
            if (my $all_routing = $router->{routing}) {
                $interface->{routing} ||= $all_routing;
            }
            if ((my $routing = $interface->{routing})
                and $interface->{ip} eq 'unnumbered')
            {
                my $rname = $routing->{name};
                $rname =~ /^(?:manual|dynamic)$/
                  or err_msg("Routing $rname not supported",
                             " for unnumbered $interface->{name}");
            }

            # Interface of managed router must not have individual owner,
            # because whole device is managed from one place.
            if (delete $interface->{owner}) {
                warn_msg("Ignoring attribute 'owner' at managed ",
                         $interface->{name});
            }

            # Attribute 'vip' only supported at unmanaged router.
            if (delete $interface->{vip}) {
                err_msg("Must not use attribute 'vip' at managed $name");
            }
        }
    }
    if (my $managed = $router->{managed}) {
        if ($managed =~ /^local/) {
            if (not $router->{filter_only}) {
                $router->{filter_only} = [];
                err_msg("Missing attribute 'filter_only' for $name");
            }
            $model->{has_io_acl}
              and err_msg("Must not use 'managed = $managed' at $name",
                          " of model $model->{name}");
        }
        $router->{log_deny}
          and not $model->{can_log_deny}
          and err_msg("Must not use attribute 'log_deny' at $name",
                      " of model $model->{name}");

        if (my $hash = $router->{log}) {
            if (my $log_modifiers = $model->{log_modifiers}) {
                for my $name2 (sort keys %$hash) {

                    # 0: simple unmodified 'log' statement.
                    my $modifier = $hash->{$name2} or next;

                    $log_modifiers->{$modifier} and next;

                    my $valid = join('|', sort keys %$log_modifiers);
                    my $what = "'log:$name2 = $modifier' at $name"
                      . " of model $model->{name}";
                    if ($valid) {
                        err_msg("Invalid $what\n Expected one of: $valid");
                    }
                    else {
                        err_msg("Unexpected $what\n Use 'log:$name2;' only.");
                    }
                }

                # Store defining log tags in global %known_log.
                collect_log($hash);
            }
            else {
                my ($name2) = sort keys %$hash;
                err_msg("Must not use attribute 'log:$name2' at $name",
                        " of model $model->{name}");
            }
        }

        $router->{no_protect_self}
          and not $model->{need_protect}
          and err_msg("Must not use attribute 'no_protect_self' at $name",
            " of model $model->{name}");
        if ($model->{need_protect}) {
            $router->{need_protect} = not delete $router->{no_protect_self};
        }

        # Detailed interface processing for managed routers.
        my $has_crypto;
        for my $interface (@{ $router->{interfaces} }) {
            if ($interface->{hub} or $interface->{spoke}) {
                $has_crypto = 1;
                $model->{crypto}
                  or err_msg("Crypto not supported for $name",
                             " of model $model->{name}");
            }
            if ($interface->{no_check}
                and not($interface->{hub} and $model->{do_auth}))
            {
                delete $interface->{no_check};
                warn_msg("Ignoring attribute 'no_check' at $interface->{name}");
            }
        }

        # Collect bridged interfaces of this device and check
        # existence of corresponding layer3 device.
        my %layer3_seen;
        my $bridged;
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{ip} eq 'bridged';
            $bridged = 1;
            (my $layer3_name = $interface->{name}) =~ s/^interface:(.*)\/.*/$1/;
            my $layer3_intf;
            if (exists $layer3_seen{$layer3_name}) {
                $layer3_intf = $layer3_seen{$layer3_name};
            }
            elsif ($layer3_intf = $interfaces{$layer3_name}) {

                # Mark layer3 interface as loopback interface internally,
                # because we only have layer2 networks and no layer3 network.
                $layer3_intf->{loopback} = 1;

                # Mark layer3 interface as such to prevent warning in
                # check_subnets.
                $layer3_intf->{is_layer3} = 1;

                if ($model->{class} eq 'ASA') {
                    $layer3_intf->{hardware}->{name} eq 'device'
                      or
                      err_msg("Layer3 $interface->{name} must use 'hardware'",
                        " named 'device' for model 'ASA'");
                }
                if (my ($no_ip) =
                    $layer3_intf->{ip} =~
                    /^(unnumbered|negotiated|short|bridged)$/)
                {
                    err_msg("Layer3 $layer3_intf->{name}",
                        " must not be $no_ip");

                    # Prevent further errors.
                    $layer3_intf->{disabled} = 1;
                    $layer3_intf = undef;
                }
            }
            else {
                err_msg("Must define interface:$layer3_name for corresponding",
                    " bridge interfaces");
            }

            # Link bridged interface to corresponding layer3 interface.
            # Used in path_auto_interfaces.
            $interface->{layer3_interface} = $layer3_intf;
            $layer3_seen{$layer3_name} = $layer3_intf;
        }

        # Delete secondary interface of layer3 interface.
        # This prevents irritating error messages later.
        if (keys %layer3_seen) {
            my $changed;
            for my $interface (@{ $router->{interfaces} }) {
                my $main = $interface->{main_interface} or next;
                if ($main->{is_layer3}) {
                    err_msg(
                        "Layer3 $main->{name} must not have",
                        " secondary $interface->{name}"
                    );
                    $interface = undef;
                    $changed   = 1;
                }
            }
            $router->{interfaces} = [ grep { $_ } @{ $router->{interfaces} } ]
              if $changed;
        }

        if ($bridged and $router->{routing}) {
            err_msg("Must not apply attribute 'routing' to bridge $name");
        }

        check_no_in_acl($router);

        if ($router->{acl_use_real_ip}) {
            $has_bind_nat or
                warn_msg("Ignoring attribute 'acl_use_real_ip' at $name,\n",
                         " because it has no interface with 'bind_nat'");
            $model->{can_acl_use_real_ip} or
                warn_msg("Ignoring attribute 'acl_use_real_ip' at $name,",
                         " of model $model->{name}");
            $router->{has_crypto} and
                err_msg("Must not use attribute 'acl_use_real_ip' at $name",
                        " having crypto interfaces");
        }
        if ($managed =~ /^local/) {
            $has_bind_nat and
                err_msg("Attribute 'bind_nat' is not allowed",
                        " at interface of $name with 'managed = $managed'");
        }
        if ($model->{do_auth}) {
            grep { $_->{hub} } @{ $router->{interfaces} }
              or err_msg("Attribute 'hub' needs to be defined",
                         " at an interface of $name of model $model->{name}");

            $router->{radius_attributes} ||= {};
        }
        else {
            $router->{radius_attributes}
              and warn_msg("Ignoring 'radius_attributes' at $name");
        }
    }

    # Unmanaged device.
    else {
        my $bridged;
        if (delete $router->{owner}) {
            warn_msg("Ignoring attribute 'owner' at unmanaged $name");
        }
        for my $interface (@{ $router->{interfaces} }) {
            if (my $crypto_list = delete $interface->{hub}) {
                delete $crypto2hub{$_} for @$crypto_list;
                err_msg("Unmanaged $interface->{name} must not",
                        " use attribute 'hub'");
            }
            if (delete $interface->{reroute_permit}) {
                warn_msg(
                    "Ignoring attribute 'reroute_permit'",
                    " at unmanaged $interface->{name}"
                );
            }
            if ($interface->{ip} eq 'bridged') {
                $bridged = 1;
            }
        }

        # Unmanaged bridge would complicate generation of static routes.
        if ($bridged) {
            err_msg("Bridged interfaces must not be used at unmanged $name");
        }
    }

    my @move_locked;

    for my $interface (@{ $router->{interfaces} }) {

        # Automatically create a network for loopback interface.
        if ($interface->{loopback}) {
            my $name;
            my $net_name;

            # Special handling needed for virtual loopback interfaces.
            # The created network needs to be shared among a group of
            # interfaces.
            if ($interface->{redundant}) {

                # Shared virtual loopback network gets name
                # 'virtual:netname'. Don't use standard name to prevent
                # network from getting referenced from rules.
                $net_name = "virtual:$interface->{network}";
                $name     = "network:$net_name";
            }
            else {

                # Single loopback network needs not to get an unique name.
                # Take an invalid name 'router.loopback' to prevent name
                # clashes with real networks or other loopback networks.
                $name = $interface->{name};
                ($net_name = $name) =~ s/^interface://;
            }
            if (not $networks{$net_name}) {
                my $ip = $interface->{ip};
                my $host_mask = get_host_mask($ip);
                my $network = new(
                    'Network',
                    name => $name,
                    ip   => $ip,
                    mask => $host_mask,

                    # Mark as automatically created.
                    loopback  => 1,
                    subnet_of => delete $interface->{subnet_of},
                    is_layer3 => $interface->{is_layer3},
                );
                $network->{ipv6} = 1 if $read_ipv6;

                # Move NAT definition from interface to loopback network.
                if (my $nat = delete $interface->{nat}) {
                    for my $nat_info (values %$nat) {
                        $nat_info->{mask} = $host_mask;
                    }
                    $network->{nat} = $nat;
                }

                if (my $private = $interface->{private}) {
                    $network->{private} = $private;
                }
                $networks{$net_name} = $network;
            }
            $interface->{network} = $net_name;
        }

        # Non loopback interface must use simple NAT with single IP
        # and without any NAT attributes.
        elsif (my $nat = $interface->{nat}) {
            for my $nat_tag (sort keys %$nat) {
                my $nat_info = $nat->{$nat_tag};

                # Reject all non IP NAT attributes.
                if (my ($what) =
                    grep { $nat_info->{$_} } qw(hidden identity dynamic))
                {
                    delete $nat->{$nat_tag};
                    err_msg("Must not use '$what' in nat:$nat_tag",
                            " of $interface->{name}");
                    last;
                }

                # Convert general NAT info to single NAT IP.
                else {
                    $nat->{$nat_tag} = $nat_info->{ip};
                }
            }
        }

        # Generate tunnel interface.
        if (my $crypto = $interface->{spoke}) {
            my $net_name    = "tunnel:$rname";
            my $iname       = "$rname.$net_name";
            my $tunnel_intf = new(
                'Interface',
                name           => "interface:$iname",
                ip             => 'tunnel',
                router         => $router,
                network        => $net_name,
                real_interface => $interface
            );
            for my $key (qw(hardware routing private bind_nat id)) {
                if ($interface->{$key}) {
                    $tunnel_intf->{$key} = $interface->{$key};
                }
            }
            if ($interfaces{$iname}) {
                err_msg("Only 1 crypto spoke allowed.\n",
                        " Ignoring spoke at $iname.");
            }
            else {
                $interfaces{$iname} = $tunnel_intf;
                push @{ $router->{interfaces} }, $tunnel_intf;

                # Create tunnel network.
                my $tunnel_net = new(
                    'Network',
                    name => "network:$net_name",
                    ip   => 'tunnel'
                    );
                if (my $private = $interface->{private}) {
                    $tunnel_net->{private} = $private;
                }
                $networks{$net_name} = $tunnel_net;
                if ($read_ipv6) {
                    $tunnel_intf->{ipv6} = $tunnel_net->{ipv6} = 1;
                }

                # Tunnel network will later be attached to crypto hub.
                push @{ $crypto2spokes{$crypto} }, $tunnel_net;
            }
        }

        if (($interface->{spoke} or $interface->{hub})
            and not $interface->{no_check})
        {
            push @move_locked, $interface;
        }
    }

    move_locked_interfaces(\@move_locked) if @move_locked;

    return $router;
}

# No traffic must traverse crypto interface.
# Hence split router into separate instances, one instance for each
# crypto interface.
# Split routers are tied by identical attribute {device_name}.
sub move_locked_interfaces {
    my ($interfaces) = @_;
    for my $interface (@$interfaces) {
        my $orig_router = $interface->{router};

        # Use different and uniqe name for each split router.
        (my $name       = $interface->{name}) =~ s/^interface:/router:/;
        my $new_router  = new(
            'Router',
            %$orig_router,
            name        => $name,
            orig_router => $orig_router,
            interfaces  => [$interface]
        );
        $new_router->{ipv6} = 1 if $interface->{ipv6};
        $interface->{router} = $new_router;
        push @router_fragments, $new_router;

        # Don't check fragment for reachability.
        delete $new_router->{policy_distribution_point};

        # Remove interface from old router.
        # Retain copy of original interfaces.
        my $interfaces = $orig_router->{interfaces};
        $orig_router->{orig_interfaces} ||= [@$interfaces];
        aref_delete($interfaces, $interface);

        if ($orig_router->{managed}) {
            my $hardware = $interface->{hardware};
            $new_router->{hardware} = [$hardware];
            my $hw_list = $orig_router->{hardware};

            # Retain copy of original hardware.
            $orig_router->{orig_hardware} = [@$hw_list];
            aref_delete($hw_list, $hardware);
            1 == @{ $hardware->{interfaces} }
              or err_msg("Crypto $interface->{name} must not share hardware",
                " with other interfaces");
            if (my $hash = $orig_router->{radius_attributes}) {

                # Copy hash, because it is changed per device later.
                $new_router->{radius_attributes} = {%$hash};
            }
        }
    }
}

# Mapping from aggregate names to aggregate objects.
our %aggregates;

sub read_aggregate {
    my $name = shift;
    my $aggregate = new('Network', name => $name, is_aggregate => 1);
    $aggregate->{private} = $private if $private;
    skip '=';
    skip '{';
    add_description($aggregate);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'ip') {
            my ($ip, $mask) = read_assign(\&read_ip_prefix);
            add_attribute($aggregate, ip   => $ip);
            add_attribute($aggregate, mask => $mask);
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($aggregate, owner => $owner);
        }
        elsif ($token eq 'link') {
            my $link = read_assign(\&read_typed_name);
            add_attribute($aggregate, link => $link);
        }
        elsif ($token eq 'has_unenforceable') {
            skip(';');
            $aggregate->{has_unenforceable} = 1;
        }
        elsif ($token eq 'has_fully_redundant') {
            skip(';');
            $aggregate->{has_fully_redundant} = 1;
        }
        elsif ($token eq 'no_check_supernet_rules') {
            skip(';');
            $aggregate->{no_check_supernet_rules} = 1;
        }
        elsif (my ($type, $name2) = $token =~ /^ (\w+) : (.+) $/x) {
            if ($type eq 'nat') {
                verify_name($name2);
                my $nat_tag = $name2;
                my $nat = read_nat($nat_tag, $name);
                $aggregate->{nat}->{$nat_tag} and
                    err_msg("Duplicate NAT definition nat:$nat_tag at $name");
                $aggregate->{nat}->{$nat_tag} = $nat;
            }
            else {
                syntax_err('Unexpected token');
            }
        }
        else {
            syntax_err('Unexpected token');
        }
    }
    $aggregate->{link} or
        syntax_err("Attribute 'link' must be defined for $name");
    my $ip = $aggregate->{ip};
    if (not $ip) {
        $ip = $aggregate->{ip} = $aggregate->{mask} =
            get_zero_ip($read_ipv6);
    }
    if (not is_zero_ip($ip)) {
        for my $key (sort keys %$aggregate) {
            next
              if grep({ $key eq $_ }
                qw( name ip mask link is_aggregate private nat));
            err_msg("Must not use attribute '$key' if IP is set for $name");
        }
    }
    return $aggregate;
}

sub read_router_attributes {
    my ($parent) = @_;

    # Add name for error messages.
    my $result = { name => "router_attributes of $parent" };
    skip '=';
    skip '{';
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($result, owner => $owner);
        }
        elsif ($token eq 'policy_distribution_point') {
            my $pair = read_assign(\&read_typed_name);
            add_attribute($result, policy_distribution_point => $pair);
        }
        elsif ($token eq 'general_permit') {
            skip('=');
            my $list = read_typed_name_or_simple_protocol_list();
            add_attribute($result, general_permit => $list);
        }
        else {
            syntax_err("Unexpected attribute");
        }
    }
    return $result;
}

# Mapping from area names to area objects.
our %areas;

sub read_area {
    my $name = shift;
    my $area = new('Area', name => $name);
    skip '=';
    skip '{';
    add_description($area);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'border' or $token eq 'inclusive_border') {
            skip '=';
            my $elements = read_union(';');
            if (grep { $_->[0] ne 'interface' or ref $_->[1] } @$elements) {
                error_atline("Must only use interface names in '$token'");
                $elements = [];
            }
            add_attribute($area, $token => $elements);
        }
        elsif ($token eq 'auto_border') {
            skip(';');
            $area->{auto_border} = 1;
        }
        elsif ($token eq 'anchor') {
            my $net_name = read_network_assign($token);
            add_attribute($area, anchor => $net_name);
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($area, owner => $owner);
        }
        elsif ($token eq 'router_attributes') {
            my $router_attributes = read_router_attributes($name);
            add_attribute($area, router_attributes => $router_attributes);
        }
        elsif (my ($type, $name2) = $token =~ /^ (\w+) : (.+) $/x) {
            if ($type eq 'nat') {
                verify_name($name2);
                my $nat_tag = $name2;
                my $nat = read_nat($nat_tag, $name);
                $area->{nat}->{$nat_tag} and
                    err_msg("Duplicate NAT definition nat:$nat_tag at $name");
                $area->{nat}->{$nat_tag} = $nat;
            }
            else {
                syntax_err('Unexpected token');
            }
        }
        else {
            syntax_err('Unexpected token');
        }
    }
    ($area->{border} or $area->{inclusive_border}) and $area->{anchor}
      and err_msg(
        "Attribute 'anchor' must not be defined together with",
        " 'border' or 'inclusive_border' for $name"
      );
    $area->{anchor} or $area->{border} or $area->{inclusive_border}
      or err_msg("At least one of attributes 'border', 'inclusive_border'",
                 " or 'anchor' must be defined for $name");
    return $area;
}

# Mapping from group names to group objects.
our %groups;

sub read_group {
    my $name = shift;
    skip '=';
    my $group = new('Group', name => $name);
    $group->{private} = $private if $private;
    add_description($group);
    my $elements = check(';') ? [] : read_union(';');
    $group->{elements} = $elements;
    return $group;
}

our %protocolgroups;

sub read_protocolgroup {
    my $name = shift;
    skip '=';
    my $list = check(';') ? [] : read_typed_name_or_simple_protocol_list();
    return new('Protocolgroup', name => $name, elements => $list);
}

sub read_port_range {
    if (defined(my $port1 = check_int)) {
        error_atline("Too large port number $port1") if $port1 > 65535;
        error_atline("Invalid port number '0'") if $port1 == 0;
        if (check '-') {
            if (defined(my $port2 = check_int)) {
                error_atline("Too large port number $port2") if $port2 > 65535;
                error_atline("Invalid port number '0'") if $port2 == 0;
                error_atline("Invalid port range $port1-$port2")
                  if $port1 > $port2;
                if ($port1 == 1 and $port2 == 65535) {
                    return $aref_tcp_any;
                }
                else {
                    return [ $port1, $port2 ];
                }
            }
            else {
                syntax_err("Missing second port in port range");
            }
        }
        else {
            return [ $port1, $port1 ];
        }
    }
    else {
        return $aref_tcp_any;
    }
}

sub read_port_ranges {
    my ($prt) = @_;
    my $range = read_port_range;
    if (check ':') {
        if ($range ne $aref_tcp_any) {
            $prt->{src_range} = $range;
        }
        $prt->{dst_range} = read_port_range;
    }
    else {
        $prt->{dst_range} = $range;
    }
}

sub read_icmp_type_code {
    my ($prt) = @_;
    if (defined(my $type = check_int)) {
        error_atline("Too large ICMP type $type") if $type > 255;
        $prt->{type} = $type;
        if ($type == 0 or $type == 3 or $type == 11) {
            $prt->{stateless_icmp} = 1;
        }
        if (check '/') {
            if (defined(my $code = check_int)) {
                error_atline("Too large ICMP code $code") if $code > 255;
                $prt->{code} = $code;
            }
            else {
                syntax_err("Expected ICMP code");
            }
        }
    }
    else {

        # No type and code given.
    }
}

sub read_proto_nr {
    my ($prt) = @_;
    defined (my $nr = check_int) or syntax_err("Expected protocol number");
    error_atline("Too large protocol number $nr") if $nr > 255;
    error_atline("Invalid protocol number '0'")   if $nr == 0;
    if ($nr == 1 and not $read_ipv6) {
        error_atline("Must not use 'proto 1', use 'icmp' instead");
    }
    elsif ($nr == 4) {
        error_atline("Must not use 'proto 4', use 'tcp' instead");
    }
    elsif ($nr == 17) {
        error_atline("Must not use 'proto 17', use 'udp' instead");
    }
    elsif ($nr == 58 and $read_ipv6) {
        error_atline("Must not use 'proto 58', use 'icmpv6' instead");
    }
    $prt->{proto} = $nr;
}

# Creates a readable, unique name for passed protocol,
# e.g. "tcp 80" for { proto => 'tcp', dst_range => [80, 80] }.
sub gen_protocol_name {
    my ($protocol) = @_;
    my $proto      = $protocol->{proto};
    my $name       = $proto;

    if ($proto eq 'ip') {
    }
    elsif ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_name = sub {
            my ($v1, $v2) = @_;
            if ($v1 == $v2) {
                return ($v1);
            }
            elsif ($v1 == 1 and $v2 == 65535) {
                return ('');
            }
            else {
                return ("$v1-$v2");
            }
        };
        my $src_range = $protocol->{src_range};
        my $src_port  = $src_range && $port_name->(@$src_range);
        my $dst_port  = $port_name->(@{ $protocol->{dst_range} });
        my $port;
        $port = "$src_port:" if $src_port;
        $port .= "$dst_port" if $dst_port;
        $name .= " $port"    if $port;
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $protocol->{type})) {
            if (defined(my $code = $protocol->{code})) {
                $name = "$proto $type/$code";
            }
            else {
                $name = "$proto $type";
            }
        }
    }
    else {
        $name = "proto $proto";
    }
    return $name;
}

# Mapping from protocol names to protocol objects.
our %protocols;

sub cache_anonymous_protocol {
    my ($protocol) = @_;
    my $name = gen_protocol_name($protocol);
    if (my $cached = $protocols{$name}) {
        return $cached;
    }
    else {
        $protocol->{name}    = $name;
        $protocols{$name}    = $protocol;
        return $protocol;
    }
}

sub read_simple_protocol {
    my ($proto) = @_;
    my $protocol = { proto => $proto };
    if ($proto eq 'tcp'or $proto eq 'udp') {
        read_port_ranges($protocol);
    }
    elsif ($proto eq 'icmp'or $proto eq 'icmpv6') {

        # Internally, both 'icmp' and 'icmpv6' are stored as 'icmp'.
        $protocol->{proto} = 'icmp';

        read_icmp_type_code $protocol;
        if ($read_ipv6 xor $proto eq 'icmpv6') {
            my $v = $read_ipv6 ? 'IPv4' : 'IPv6';
            error_atline("Must use '$proto' only with $v");
        }
    }
    elsif ($proto eq 'ip') {
    }
    elsif ($proto eq 'proto') {
        read_proto_nr $protocol;
    }
    else {
        error_atline("Unknown protocol '$proto'");

        # Prevent further errors.
        $protocol->{proto} = 'ip';
    }
    return $protocol;
}

sub check_protocol_modifiers {
    my ($token, $protocol) = @_;
    while ($token eq ',') {
        my $flag = read_identifier;
        if ($flag =~ /^(?:reversed | stateless | oneway |
                          src_net | dst_net |
                          overlaps | no_check_supernet_rules )/x)
        {
            $protocol->{modifiers}->{$flag} = 1;
        }
        else {
            error_atline("Unknown modifier '$flag'");
        }
        $token = read_token();
    }
    return $token;
}

sub read_typed_name_or_simple_protocol_list {
    my @result;
    my $token = read_token();
    while (1) {
        if (my ($type, $name) = $token =~ /^(\w+):([\w-]+)$/) {
            push @result, [$type, $name];
        }
        else {
            my $protocol = read_simple_protocol($token);
            $protocol = cache_anonymous_protocol($protocol);
            push @result, $protocol;
        }
        $token = read_token();
        last if $token eq ';';
        $token eq ',' or syntax_err("Comma expected in list of protocols");
        $token = read_token();

        # Allow trailing comma.
        last if $token eq ';';
    }
    return \@result;
}

sub read_protocol {
    my ($name) = @_;
    skip '=';
    my $token = read_token();
    my $protocol = read_simple_protocol($token);
    $protocol->{name} = $name;
    $token = read_token();
    $token = check_protocol_modifiers($token, $protocol);
    $token eq ';' or syntax_err("Expected ';'");
    return $protocol;
}

# Mapping from service names to service objects.
our %services;

sub has_user {
    my ($element, $context) = @_;
    my ($type, $name) = @$element;
    if ($type eq 'user') {
        return 1;
    }
    elsif ($type eq '!') {
        return check_user_in_union([$name], $context);
    }
    elsif ($type eq  '&') {
        return check_user_in_intersection($name, $context);
    }
    elsif (ref $name) {
        return check_user_in_union($name, $context);
    }
    else {
        return 0;
    }
}

sub check_user_in_intersection {
    my ($elements, $context) = @_;
    my $count = grep { has_user($_, $context) } @$elements;
    return $count ? 1 : 0;
}

sub check_user_in_union {
    my ($elements, $context) = @_;
    my $count = grep { has_user($_, $context) } @$elements;
    $count == 0 or $count == @$elements or
        err_msg("The sub-expressions of union in $context equally must\n",
                " either reference 'user' or must not reference 'user'");
    return $count ? 1 : 0;
}

sub read_union_warn_empty {
    my ($what, $sname) = @_;
    my $result;
    if (check(';')) {
        warn_msg("$what of $sname is empty");
        $result = [];
    }
    else {
        $result = read_union(';');
    }
    return $result;
}

sub assign_union_allow_user {
    my ($name, $sname) = @_;
    skip $name;
    skip '=';
    local $user_object->{active} = 1;
    $user_object->{refcount} = 0;
    my $result = read_union_warn_empty($name, $sname);
    my $user_seen = $user_object->{refcount};
    if ($user_seen) {
        check_user_in_union($result, "$name of $sname");
    }
    return $result, $user_seen;
}

# Check if day of given date is today or has been reached already.
sub date_is_reached {
    my ($date) = @_;
    my ($y, $m, $d) = $date =~ /^(\d\d\d\d)-(\d\d)-(\d\d)$/a
        or syntax_err("Date expected as yyyy-mm-dd");
    my (undef, undef, undef, $mday, $mon, $year) = localtime(time);
    $mon += 1;
    $year += 1900;
    return ($y < $year ||
            $y == $year && ($m < $mon ||
                            $m == $mon && $d <= $mday));
}

sub read_service {
    my ($name) = @_;
    my $service = { name => $name, rules => [] };
    $service->{private} = $private if $private;
    skip '=';
    skip '{';
    add_description($service);
    while (1) {
        my $token = read_token();
        last if $token eq 'user';
        if ($token eq 'sub_owner') {
            my $sub_owner = read_assign(\&read_identifier);
            add_attribute($service, sub_owner => $sub_owner);
        }
        elsif ($token eq 'overlaps') {
            my $other = read_assign_list(\&read_typed_name);
            add_attribute($service, overlaps => $other);
        }
        elsif ($token eq 'multi_owner') {
            skip(';');
            $service->{multi_owner} = 1;
        }
        elsif ($token eq 'unknown_owner') {
            skip(';');
            $service->{unknown_owner} = 1;
        }
        elsif ($token eq 'has_unenforceable') {
            skip(';');
            $service->{has_unenforceable} = 1;
        }
        elsif ($token eq 'disabled') {
            skip(';');
            $service->{disabled} = 1;
        }
        elsif ($token eq 'disable_at') {
            my $date = $service->{disable_at} = read_assign(\&read_token);
            if (date_is_reached($date)) {
                $service->{disabled} = 1;
            }
        }

        else {
            syntax_err("Expected some valid attribute or definition of 'user'");
        }
    }

    # 'user' has already been read above.
    skip '=';
    if (check('foreach')) {
        $service->{foreach} = 1;
    }
    $service->{user} = read_union_warn_empty('user', $name);

    while (1) {
        my $token = read_token();
        last if $token eq '}';
        $token eq 'permit' or $token eq 'deny' or
            syntax_err("Expected 'permit' or 'deny'");
        my $action = $token;
        my ($src, $src_user) = assign_union_allow_user('src', $name);
        my ($dst, $dst_user) = assign_union_allow_user('dst', $name);
        skip('prt');
        skip('=');
        my $prt = read_typed_name_or_simple_protocol_list();
        $src_user or $dst_user or error_atline("Rule must use keyword 'user'");
        if ($service->{foreach} and not($src_user and $dst_user)) {
            warn_msg(
                "Rule of $name should reference 'user' in 'src' and 'dst'\n",
                " because service has keyword 'foreach'");
        }
        my $rule = {
            service  => $service,
            action   => $action,
            src      => $src,
            dst      => $dst,
            prt      => $prt,
            has_user => $src_user ? $dst_user ? 'both' : 'src' : 'dst',
        };
        if (check('log')) {
            my $list = read_assign_list(\&read_identifier);
            $rule->{log} = $list;
        }
        push @{ $service->{rules} }, $rule;
    }
    return $service;
}

our %pathrestrictions;

sub read_pathrestriction {
    my $name = shift;
    skip '=';
    my $restriction = new('Pathrestriction', name => $name);
    $restriction->{private} = $private if $private;
    add_description($restriction);
    $restriction->{elements} = read_union(';');
    return $restriction;
}

sub read_attributed_object {
    my ($name, $attr_descr) = @_;
    my $object = { name => $name };
    skip '=';
    skip '{';
    add_description($object);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        verify_name($token);
        my $attribute = $token;
        my $val_descr = $attr_descr->{$attribute}
          or syntax_err("Unknown attribute '$attribute'");
        skip '=';
        my $val;
        if (my $values = $val_descr->{values}) {
            $val = read_identifier;
            grep { $_ eq $val } @$values
              or syntax_err("Invalid value");
        }
        else {
            my $fun = $val_descr->{function};
            $val = &$fun;
        }
        skip ';';
        add_attribute($object, $attribute => $val);
    }
    for my $attribute (sort keys %$attr_descr) {
        my $description = $attr_descr->{$attribute};
        unless (defined $object->{$attribute}) {
            if (my $default = $description->{default}) {
                $object->{$attribute} = $default;
            }
            else {
                err_msg("Missing '$attribute' for $name");
            }
        }

        # Convert from syntax to internal values, e.g. 'none' => undef.
        if (my $map = $description->{map}) {
            my $value = $object->{$attribute};
            if (exists $map->{$value}) {
                $object->{$attribute} = $map->{$value};
            }
        }
    }
    return $object;
}

my %isakmp_attributes = (

    # This one is ignored and is optional.
    identity => {
        values  => [qw( address fqdn )],
        default => 'none',
        map     => { none => undef }
    },
    nat_traversal => {
        values  => [qw( on additional off )],
        default => 'off',
        map     => { off => undef }
    },
    authentication => { values   => [qw( preshare rsasig )], },
    encryption     => { values   => [qw( aes aes192 aes256 des 3des )], },
    hash           => { values   => [qw( md5 sha sha256 sha384 sha512 )], },
    ike_version    => { values   => [ 1, 2 ], default => 1, },
    lifetime       => { function => \&read_time_val, },
    group          => { values   => [ 1, 2, 5, 14, 15, 16, 19, 20, 21, 24 ], },
    trust_point => {
        function => \&read_identifier,
        default  => 'none',
        map      => { none => undef }
    },
);

our %isakmp;

sub read_isakmp {
    my ($name) = @_;
    return read_attributed_object $name, \%isakmp_attributes;
}

my %ipsec_attributes = (
    key_exchange   => {
        function => \&read_typed_name,
        default => 'none',		# Error is checked elsewhere.
        map     => { none => undef }
    },
    esp_encryption => {
        values  => [qw( none aes aes192 aes256 des 3des )],
        default => 'none',
        map     => { none => undef }
    },
    esp_authentication => {
        values  => [qw( none md5_hmac sha_hmac md5 sha sha256 sha384 sha512 )],
        default => 'none',
        map     => {
            none => undef,

            # Compatibility for old version.
            md5_hmac => 'md5',
            sha_hmac => 'sha',
        }
    },
    ah => {
        values  => [qw( none md5_hmac sha_hmac md5 sha sha256 sha384 sha512 )],
        default => 'none',
        map     => { none => undef, md5_hmac => 'md5', sha_hmac => 'sha', }
    },
    pfs_group => {
        values  => [qw( none 1 2 5 14 15 16 19 20 21 24 )],
        default => 'none',
        map     => { none => undef }
    },
    lifetime => { function => \&read_time_kilobytes_pair }
);

our %ipsec;

sub read_ipsec {
    my ($name) = @_;
    my $ipsec = read_attributed_object $name, \%ipsec_attributes;
    $ipsec->{key_exchange} or syntax_err("Missing 'key_exchange' for $name");
    return $ipsec;
}

our %crypto;

sub read_crypto {
    my ($name) = @_;
    skip '=';
    skip '{';
    my $crypto = { name => $name };
    $crypto->{private} = $private if $private;
    add_description($crypto);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'detailed_crypto_acl') {
            skip(';');
            $crypto->{detailed_crypto_acl} = 1;
        }
        elsif ($token eq 'type') {
            my $type = read_assign(\&read_typed_name);
            add_attribute($crypto, type => $type);
        }
        else {
            syntax_err('Unexpected token');
        }
    }
    $crypto->{type} or syntax_err("Missing 'type' for $name");
    return $crypto;
}

# Mapping from owner names to owner objects.
our %owners;

sub read_owner {
    my $name = shift;
    my $owner = new('Owner', name => $name);
    skip '=';
    skip '{';
    add_description($owner);
    while (1) {
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'admins') {
            my $admins = read_assign_list(\&read_name);
            add_attribute($owner, admins => $admins);
        }
        elsif ($token eq 'watchers') {
            my $watchers = read_assign_list(\&read_name);
            add_attribute($owner, watchers => $watchers);
        }
        elsif ($token eq 'show_all') {
            skip(';');
            $owner->{show_all} = 1;
            $owner->{show_hidden_owners} = 1;
        }
        elsif ($token eq 'only_watch') {
            skip(';');
            $owner->{only_watch} = 1;
        }
        elsif ($token eq 'hide_from_outer_owners') {
            skip(';');
            $owner->{hide_from_outer_owners} = 1;
        }
        elsif ($token eq 'show_hidden_owners') {
            skip(';');
            $owner->{show_hidden_owners} = 1;
        }
        else {
            syntax_err('Unexpected token');
        }
    }
    $owner->{admins} ||= [];
    return $owner;
}

# Third attribute is true, if definitions are shared between IPv4 and IPv6.
our %global_type = (
    router          => [ \&read_router,          \%routers ],
    network         => [ \&read_network,         \%networks ],
    any             => [ \&read_aggregate,       \%aggregates ],
    area            => [ \&read_area,            \%areas ],
    group           => [ \&read_group,           \%groups ],
    service         => [ \&read_service,         \%services ],
    pathrestriction => [ \&read_pathrestriction, \%pathrestrictions ],
    owner           => [ \&read_owner,           \%owners,         1 ],
    protocol        => [ \&read_protocol,        \%protocols,      1 ],
    protocolgroup   => [ \&read_protocolgroup,   \%protocolgroups, 1 ],
    isakmp          => [ \&read_isakmp,          \%isakmp,         1 ],
    ipsec           => [ \&read_ipsec,           \%ipsec,          1 ],
    crypto          => [ \&read_crypto,          \%crypto,         1 ],
);

sub parse_toplevel {

    # Check for global definitions.
    my $pair = read_typed_name();
    my ($type, $name) = @$pair;
    my $descr = $global_type{$type}
      or syntax_err("Unknown global definition");
    my ($fun, $hash, $shared) = @$descr;
    my $result = $fun->("$type:$name");
    $result->{file} = $current_file;
    if ($read_ipv6) {
        if (not $shared) {
            $result->{ipv6} = 1;
        }
        if ($type eq 'router') {
            $hash = \%routers6;
        }
    }
    if (my $other = $hash->{$name}) {
        my $file = $other->{file};
        if ($current_file ne $file) {
            $file = "$file and $current_file";
        }
        err_msg("Duplicate definition of $type:$name in $file");
    }
    $hash->{$name} = $result;

    # Result is not used in this module but can be useful
    # when this function is called from outside.
    return $result;
}

sub parse_input {
    my $length = length $input;
    while (skip_space_and_comment, pos $input != $length) {
        parse_toplevel();
    }
}

# Reads and parses netspoc input from file or from directory.
sub read_file_or_dir {
    my ($path) = @_;
    process_file_or_dir($path, \&parse_input);
}

# Prints number of read entities if in verbose mode.
sub show_read_statistics {
    my $r = keys(%routers) + keys(%routers6);
    my $n = keys %networks;
    my $h = keys %hosts;
    my $s = keys %services;
    info("Read: $r routers, $n networks, $h hosts, $s services");
}

## no critic (RequireArgUnpacking RequireFinalReturn)

# Type checking functions
sub is_network       { ref($_[0]) eq 'Network'; }
sub is_router        { ref($_[0]) eq 'Router'; }
sub is_interface     { ref($_[0]) eq 'Interface'; }
sub is_host          { ref($_[0]) eq 'Host'; }
sub is_subnet        { ref($_[0]) eq 'Subnet'; }
sub is_zone          { ref($_[0]) eq 'Zone'; }
sub is_group         { ref($_[0]) eq 'Group'; }
sub is_autointerface { ref($_[0]) eq 'Autointerface'; }

# Currently unused:
# sub is_area          { ref($_[0]) eq 'Area'; }
# sub is_protocolgroup { ref($_[0]) eq 'Protocolgroup'; }

## use critic

# Creates a string representation of a rule.
sub print_rule {
    my ($rule) = @_;

    my $extra = '';
    if (my $log = $rule->{log}) {
        my $names = join(',', @$log);
        $extra .= " log=$names;";
    }
    $extra .= " stateless"           if $rule->{stateless};
    $extra .= " stateless_icmp"      if $rule->{stateless_icmp};
    my $service = $rule->{rule} && $rule->{rule}->{service};
    $extra .= " of $service->{name}" if $service;
    my $action = $rule->{deny} ? 'deny' : 'permit';
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $prt = $rule->{prt};
    for my $what (\$src, \$dst, \$prt) {
        ref $$what eq 'ARRAY' or next;
        $$what = $$what->[0];
    }
    my $simple_rule = { %$rule, src => $src, dst => $dst, prt => $prt };
    $prt = get_orig_prt($simple_rule);
    return
        "$action src=$src->{name}; dst=$dst->{name}; prt=$prt->{name};$extra";
}

sub get_orig_prt {
    my ($rule) = @_;
    my $prt = $rule->{prt};
    my $src_range = $rule->{src_range};
    my $service = $rule->{rule}->{service};
    my $map = $src_range
            ? $service->{src_range2prt2orig_prt}->{$src_range}
            : $service->{prt2orig_prt};
    return $map->{$prt} || $prt;
}

##############################################################################
# Order protocols
##############################################################################

# Hash for converting a reference of a protocol back to this protocol.
our %ref2prt;

# Look up a protocol object by its defining attributes.
my %prt_hash;

# Add protocol to %prt_hash.
# Link duplicate protocol definitions via attribute {main}.
sub prepare_prt_ordering {
    my ($prt) = @_;
    my $proto = $prt->{proto};
    my $main_prt;
    if ($proto eq 'tcp' or $proto eq 'udp') {

        # Convert src and dst port ranges from arrays to real protocol objects.
        # This is used in function expand_rules via expand_protocols:
        # An unexpanded rule has references to TCP and UDP protocols
        # with combined src and dst port ranges. An expanded rule has
        # distinct references to src and dst protocols with a single
        # port range.
        for my $where ('src_range', 'dst_range') {

            # An array with low and high port.
            my $range = $prt->{$where} or next;
            my $key = join ':', @$range;
            my $range_prt = $prt_hash{$proto}->{$key};
            if (not $range_prt) {
                $range_prt = {
                    name  => $prt->{name},
                    proto => $proto,
                    range => $range,
                };
                $prt_hash{$proto}->{$key} = $range_prt;

                # Set up ref2prt.
                $ref2prt{$range_prt} = $range_prt;
            }
            $prt->{$where} = $range_prt;
        }
    }
    elsif ($proto eq 'icmp') {
        my $type = $prt->{type};
        my $code = $prt->{code};
        my $key  = defined $type ? (defined $code ? "$type:$code" : $type) : '';
        $main_prt = $prt_hash{$proto}->{$key}
          or $prt_hash{$proto}->{$key} = $prt;
    }
    elsif ($proto eq 'ip') {
        $main_prt = $prt_hash{$proto}
          or $prt_hash{$proto} = $prt;
    }
    else {

        # Other protocol.
        my $key = $proto;
        $main_prt = $prt_hash{proto}->{$key}
          or $prt_hash{proto}->{$key} = $prt;
    }
    if ($main_prt) {

        # Found duplicate protocol definition.  Link $prt with $main_prt.
        # We link all duplicate protocols to the first protocol found.
        # This assures that we always reach the main protocol from any duplicate
        # protocol in one step via ->{main}. This is used later to
        # substitute occurrences of $prt with $main_prt.
        $prt->{main} = $main_prt;
    }
}

# Set {up} relation between all ICMP protocols and to larger 'ip' protocol.
# Additionally fill global variable %ref2prt.
sub order_icmp {
    my ($hash, $up) = @_;

    # Handle 'icmp any'.
    if (my $prt = $hash->{''}) {
        $prt->{up} = $up;
        $up = $prt;
    }
    for my $prt (values %$hash) {

        # 'icmp any' has been handled above.
        if (not defined $prt->{type}) {
        }
        elsif (defined $prt->{code}) {
            $prt->{up} = ($hash->{ $prt->{type} } or $up);
        }
        else {
            $prt->{up} = $up;
        }

        # Set up ref2prt.
        $ref2prt{$prt} = $prt;
    }
}

# Set {up} relation for all numeric protocols to larger 'ip' protocol.
# Additionally fill global variable %ref2prt.
sub order_proto {
    my ($hash, $up) = @_;
    for my $prt (values %$hash) {
        $prt->{up} = $up;

        # Set up ref2prt.
        $ref2prt{$prt} = $prt;
    }
}

# Set {up} relation from port range to the smallest port range which
# includes it.
# If no including range is found, link it with next larger protocol.
# Set attribute {has_neighbor} to range adjacent to upper port.
# Find overlapping ranges and split one of them to eliminate the overlap.
# Set attribute {split} at original range, referencing pair of split ranges.
# Additionally fill global variable %ref2prt.
sub order_ranges {
    my ($range_href, $up) = @_;
    my @sorted =

      # Sort by low port. If low ports are equal, sort reverse by high port.
      # I.e. larger ranges coming first, if there are multiple ranges
      # with identical low port.
      sort {
             $a->{range}->[0] <=> $b->{range}->[0]
          || $b->{range}->[1] <=> $a->{range}->[1]
      } values %$range_href;

    # Check current range [a1, a2] for sub-ranges, starting at position $i.
    # Return position of range which isn't sub-range or undef
    # if end of array is reached.
    my $check_subrange;
    $check_subrange = sub {
        my ($a, $a2, $i) = @_;
        while (1) {
            return if $i == @sorted;
            my $b = $sorted[$i];
            my ($b1, $b2) = @{ $b->{range} };

            # Neighbors
            # aaaabbbb
            if ($a2 + 1 == $b1) {

                # Mark protocol as candidate for joining of port ranges during
                # optimization.
                $a->{has_neighbor} = $b->{has_neighbor} = 1;
            }

            # Not related.
            # aaaa    bbbbb
            return $i if $a2 < $b1;

            # $a includes $b.
            # aaaaaaa
            #  bbbbb
            if ($a2 >= $b2) {
                $b->{up} = $a;

# debug("$b->{name} [$b1-$b2] < $a->{name} [$a->{range}->[0]-$a2]");
                $i = $check_subrange->($b, $b2, $i + 1);

                # Stop at end of array.
                $i or return;
                next;
            }

            # $a and $b are overlapping.
            # aaaaa
            #   bbbbbb
            # Split $b in two parts $x and $y with $x included by $b:
            # aaaaa
            #   xxxyyy
            my $x1 = $b1;
            my $x2 = $a2;
            my $y1 = $a2 + 1;
            my $y2 = $b2;

# debug("$b->{name} [$b1-$b2] split into [$x1-$x2] and [$y1-$y2]");
            my $find_or_insert_range = sub {
                my ($a1, $a2, $i, $orig) = @_;
                while (1) {
                    if ($i == @sorted) {
                        last;
                    }
                    my $b = $sorted[$i];
                    my ($b1, $b2) = @{ $b->{range} };

                    # New range starts at higher position and therefore must
                    # be inserted behind current range.
                    if ($a1 > $b1) {
                        $i++;
                        next;
                    }

                    # New and current range start a same position.
                    if ($a1 == $b1) {

                        # New range is smaller and therefore must be inserted
                        # behind current range.
                        if ($a2 < $b2) {
                            $i++;
                            next;
                        }

                        # Found identical range, return this one.
                        if ($a2 == $b2) {

#                    debug("Split range is already defined: $b->{name}");
                            return $b;
                        }

                        # New range is larger than current range and therefore
                        # must be inserted in front of current one.
                        last;
                    }

                    # New range starts at lower position than current one.
                    # It must be inserted in front of current range.
                    last;
                }
                my $proto = $orig->{proto};
                my $new_range = {
                    name  => "$proto $a1-$a2",
                    proto => $proto,
                    range => [ $a1, $a2 ],

                    # Mark for range optimization.
                    has_neighbor => 1
                };

                # Insert new range at position $i.
                splice @sorted, $i, 0, $new_range;

                # Set up ref2prt.
                $ref2prt{$new_range} = $new_range;

                return $new_range;
            };
            my $left  = $find_or_insert_range->($x1, $x2, $i + 1, $b);
            my $rigth = $find_or_insert_range->($y1, $y2, $i + 1, $b);
            $b->{split} = [ $left, $rigth ];

            # Continue processing with next element.
            $i++;
        }
    };

    # Array wont be empty because $prt_tcp and $prt_udp are defined internally.
    @sorted or return;

    my $a = $sorted[0];
    $a->{up} = $up;
    my $a2 = $a->{range}->[1];
    $check_subrange->($a, $a2, 1);
}

sub expand_split_protocol {
    my ($prt) = @_;

    # Handle unset src_range.
    if (not $prt) {
        return $prt;
    }
    elsif (my $split = $prt->{split}) {
        my ($prt1, $prt2) = @$split;
        return (expand_split_protocol($prt1),
            expand_split_protocol($prt2));
    }
    else {
        return $prt;
    }
}

# Following protocols are initialized in init_protocols.
# Must not be defined as constant, because {up} relation is set
# in order_protocols dependening of other protocols from input.

# Protocol 'ip' is needed later for implementing secondary rules and
# automatically generated deny rules.
my $prt_ip;

# Protocol 'TCP any'.
my $prt_tcp;

# Protocol 'UDP any'.
my $prt_udp;

# IPSec: Internet key exchange.
# Source and destination port (range) is set to 500.
my $prt_ike;

# IPSec: NAT traversal.
my $prt_natt;

# IPSec: encryption security payload.
my $prt_esp;

# IPSec: authentication header.
my $prt_ah;

# Port range 'TCP any'; assigned in sub order_protocols below.
my $range_tcp_any;

# Port range 'tcp established' is needed later for reverse rules
# and assigned below.
my $range_tcp_established;

# Order protocols. We need this to simplify optimization.
# Additionally add internal predefined protocols.
sub order_protocols {
    progress('Arranging protocols');

    # Internal protocols need to be processed before user defined protocols,
    # because we want to avoid handling of {main} for internal protocols.
    # $prt_tcp and $prt_udp need to be processed before all other TCP and UDP
    # protocols, because otherwise the range 1..65535 would get a misleading
    # name.
    for my $prt (
        $prt_ip,
        $prt_tcp, $prt_udp,
        $prt_ike,
        $prt_natt,
        $prt_esp, $prt_ah,
        values %protocols
      )
    {
        prepare_prt_ordering $prt;
    }

    $range_tcp_any         = $prt_tcp->{dst_range};
    $range_tcp_established = {
        %$range_tcp_any,
        name        => 'reversed:TCP_ANY',
        established => 1
    };
    $range_tcp_established->{up} = $range_tcp_any;

    my $up = $prt_ip;
    order_ranges($prt_hash{tcp}, $up);
    order_ranges($prt_hash{udp}, $up);
    order_icmp($prt_hash{icmp}, $up);
    order_proto($prt_hash{proto}, $up);

    # Set up ref2prt.
    $ref2prt{$prt_ip} = $prt_ip;
}

####################################################################
# Link topology elements each with another
####################################################################

sub expand_group;

sub get_ipv4_ipv6_routers {
    return(values %routers, values %routers6);
}

# Replace the owner name by the actual owner object inside the passed
# object and aditionally returns the owner object.
# Owner attribute defaults to 'owner', but other attribute name can be used,
# e.g. 'sub_owner'.
sub link_to_owner {
    my ($obj, $key) = @_;
    $key ||= 'owner';
    if (my $value = $obj->{$key}) {
        if (my $owner = $owners{$value}) {
            return $obj->{$key} = $owner;
        }
        err_msg(
            "Can't resolve reference to '$value'",
            " in attribute '$key' of $obj->{name}"
        );
        delete $obj->{$key};
    }
    return;
}

sub link_to_real_owner {
    my ($obj, $key) = @_;
    my $owner = link_to_owner($obj, $key) or return;
    if (not @{ $owner->{admins} }) {
        $owner->{err_seen}++ or
            err_msg("Missing attribute 'admins' in $owner->{name}",
                    " of $obj->{name}");

    }
    if (delete $owner->{only_watch}) {
        err_msg("$owner->{name} with attribute 'only_watch'",
                " must only be used at area,\n not at $obj->{name}");
    }
}

sub link_owners {

    # Use sort to get deterministic error messages.
    for my $name (sort keys %owners) {
        my $owner = $owners{$name};

        # Check email addresses in admins and watchers.
        for my $attr (qw( admins watchers )) {
            my $list = $owner->{$attr} or next;
            for my $email (@$list) {

                # Check email syntax.
                # Local part definition from wikipedia,
                # without space and other quoted characters.
                # Only 7 bit ASCII.
                $email =~ m/^ [\w.!\#$%&''*+\/=?^_``{|}~-]+ \@ [\w.-]+ $/xa
                or

                # Wildcard: All addresses of email domain.
                # Only allowed as watcher.
                $attr eq 'watchers' and
                $email =~ m/^ \[all\] \@ [\w.-]+ $/xa
                or
                $email eq 'guest'
                or err_msg(
                    "Invalid email address (ASCII only)",
                    " in $attr of $owner->{name}: $email"
                  );

                # Normalize email to lower case.
                $email = lc($email);
            }
        }
    }

    # Expand watchers and check for duplicates.
    for my $name (sort keys %owners) {
        my $owner = $owners{$name};

        # Check for duplicate email addresses
        # in admins, watchers and between admins and watchers.
        my $admins   = $owner->{admins};
        my $watchers = $owner->{watchers};
        find_duplicates(@$admins, @$watchers) or next;
        for my $ref (\$admins, \$watchers) {
            my $list = $$ref;
            my @emails = find_duplicates(@$list) or next;
            $$ref = [ unique(@$list) ];
            my $type = $$ref eq $admins ? 'admins' : 'watchers';
            err_msg("Duplicates in $type of $owner->{name}: ",
                    join(', ', @emails));
        }

        # Check again, after duplicates in admins and watchers
        # have been removed.
        if (my @duplicates = find_duplicates(@$admins, @$watchers)) {
            err_msg("Duplicates in admins/watchers of $owner->{name}: ",
                    join(', ', @duplicates));
        }
    }
    for my $network (values %networks) {
        link_to_real_owner($network);
        for my $host (@{ $network->{hosts} }) {
            link_to_real_owner($host);
        }
    }
    for my $aggregate (values %aggregates) {
        link_to_real_owner($aggregate);
    }
    for my $area (values %areas) {
        link_to_owner($area);
        if (my $router_attributes = $area->{router_attributes}) {
            link_to_real_owner($router_attributes);
        }
    }
    for my $router (get_ipv4_ipv6_routers(), @router_fragments) {
        link_to_real_owner($router);
        next if $router->{managed} or $router->{routing_only};
        for my $interface (@{ $router->{interfaces} }) {
            link_to_real_owner($interface);
        }
    }
    for my $service (values %services) {
        link_to_real_owner($service, 'sub_owner');
    }
}

sub link_policy_distribution_point {
    my ($obj, $ipv6) = @_;
    my $pair = $obj->{policy_distribution_point} or return;
    my ($type, $name) = @$pair;
    if ($type ne 'host') {
        err_msg("Must only use 'host' in 'policy_distribution_point'",
                " of $obj->{name}");
    }
    elsif (my $host = expand_typed_name($type, $name, $obj->{name}, $ipv6)) {
        $obj->{policy_distribution_point} = $host;
        return;
    }
    else {
        warn_msg("Ignoring undefined $type:$name in 'policy_distribution_point'",
                " of $obj->{name}");
    }

    # Prevent further errors;
    delete $obj->{policy_distribution_point};
}

sub link_general_permit {
    my ($obj) = @_;
    my $list = $obj->{general_permit} or return;
    my $context = $obj->{name};

    # Sort protocols and src_range/dst_range/orig_prt triples by name,
    # so we can compare value lists of attribute general_permit for
    # redundancy during inheritance.
    $list = $obj->{general_permit} = [
        sort {
            (ref $a eq 'ARRAY'      ? $a->[2]->{name} : $a->{name})
              cmp(ref $b eq 'ARRAY' ? $b->[2]->{name} : $b->{name})
        } @{ split_protocols(expand_protocols($list, $context)) }
    ];

    # Don't allow port ranges. This wouldn't work, because
    # gen_reverse_rules doesn't handle generally permitted protocols.
    for my $prt (@$list) {
        my ($src_range, $range, $orig_prt);
        if (ref $prt eq 'ARRAY') {
            ($src_range, my $dst_range, $orig_prt) = @$prt;
            $range = $dst_range->{range};
        }
        else {
            $range = $prt->{range};
            $orig_prt = $prt;
        }
        my @reason;
        if ($orig_prt->{modifiers}) {
            push @reason, 'modifiers';
        }
        if ($src_range or $range and $range ne $aref_tcp_any) {
            push @reason, 'ports';
        }
        if (@reason) {
            my $reason = join ' or ', @reason;
            err_msg("Must not use '$orig_prt->{name}' with $reason",
                " in general_permit of $context");
        }
    }
}

# Link areas with referenced interfaces or network.
sub link_areas {
    for my $area (values %areas) {
        my $ipv6 = $area->{ipv6};
        if (my $net_name = $area->{anchor}) {

            # Input has already been checked by parser, so we are sure
            # to get exactly one network as result.
            my ($obj) = @{ expand_group([['network', $net_name]],
                                        $area->{name}, $ipv6) };
            $area->{anchor} = $obj;
        }
        for my $attr (qw(border inclusive_border)) {
            $area->{$attr} or next;

            # Input has already been checked by parser, so we are sure
            # to get list of interfaces as result.
            $area->{$attr} = expand_group($area->{$attr}, $area->{name}, $ipv6);
            for my $obj (@{ $area->{$attr} }) {
                my $router = $obj->{router};
                $router->{managed} or
                    err_msg("Referencing unmanaged $obj->{name} ",
                            "from $area->{name}");

                # Reverse swapped main and virtual interface.
                if (my $main_interface = $obj->{main_interface}) {
                    $obj = $main_interface;
                }
            }
        }
        if (my $router_attributes = $area->{router_attributes}) {
            link_policy_distribution_point($router_attributes, $area->{ipv6});
            link_general_permit($router_attributes);
        }
    }
}

# Link interfaces with networks in both directions.
sub link_interfaces {
    my ($router) = @_;
    my $ipv6 = $router->{ipv6};
    for my $interface (@{ $router->{interfaces} }) {
        my $net_name = $interface->{network};
        my $network  = expand_typed_name('network', $net_name,
                                         $interface->{name}, $ipv6);
        if (not $network) {
            my $msg = "Referencing undefined network:$net_name"
              . " from $interface->{name}";
            if ($interface->{disabled}) {
                warn_msg($msg);
            }
            else {
                err_msg($msg);

                # Prevent further errors.
                $interface->{disabled} = 1;
            }

            # Prevent further errors.
            # This case is handled in disable_behind.
            $interface->{network} = undef;
            next;
        }

        $interface->{network} = $network;

        # Private network must be connected to private interface
        # of same context.
        if (my $private1 = $network->{private}) {
            my $private2 = $interface->{private} || 'public';
            $private1 eq $private2
                or err_msg("$private2 $interface->{name} must not",
                           " be connected to $private1 $network->{name}");
        }

        # Public network may connect to private interface.
        # The owner of a private context can prevent a public network from
        # connecting to a private interface by simply connecting an own private
        # network to the private interface.

        push @{ $network->{interfaces} }, $interface;
        check_interface_ip($interface, $network);
    }
}

sub check_interface_ip {
    my ($interface, $network) = @_;
    my $ip         = $interface->{ip};
    my $network_ip = $network->{ip};
    if ($ip =~ /^(?:short|tunnel)$/) {

        # Nothing to check:
        # short interface may be linked to arbitrary network,
        # tunnel interfaces and networks have been generated internally.
    }
    elsif ($ip eq 'unnumbered') {
        $network_ip eq 'unnumbered'
          or err_msg("Unnumbered $interface->{name} must not be linked ",
            "to $network->{name}");
    }
    elsif ($network_ip eq 'unnumbered') {
        err_msg(
            "$interface->{name} must not be linked ",
            "to unnumbered $network->{name}"
        );
    }
    elsif ($ip eq 'negotiated') {
    }
    elsif ($ip eq 'bridged') {

        # Nothing to be checked: attribute 'bridged' is set automatically
        # for an interface without IP and linked to bridged network.
    }
    else {

        # Check compatibility of interface IP and network IP/mask.
        my $mask = $network->{mask};
        if (not(match_ip($ip, $network_ip, $mask))) {
            err_msg("$interface->{name}'s IP doesn't match ",
                "$network->{name}'s IP/mask");
        }
        if (is_host_mask($mask)) {
            if (not $network->{loopback}) {
                warn_msg(
                    "$interface->{name} has address of its network.\n",
                    " Remove definition of $network->{name} and\n",
                    " add attribute 'loopback' at",
                    " interface definition."
                );
            }
        }

        # Check network and broadcast address only for IPv4,
        # but not for /31 IPv4 (see RFC 3021).
        elsif (not (16 == length($mask) or 31 == mask2prefix($mask))) {
            if ($ip eq $network_ip) {
                err_msg("$interface->{name} has address of its network");
            }
            my $broadcast = $network_ip | ~$mask;
            if ($ip eq $broadcast) {
                err_msg("$interface->{name} has broadcast address");
            }
        }
    }
}

# Iterate over all interfaces of all routers.
# Don't use values %interfaces because we want to traverse the interfaces
# in a deterministic order.
sub link_routers {
    for my $router (sort(by_name get_ipv4_ipv6_routers()), @router_fragments) {
        link_interfaces($router);
        link_policy_distribution_point($router, $router->{ipv6});
        link_general_permit($router);
    }
}

sub link_subnet {
    my ($object, $ipv6) = @_;
    my $name = $object->{subnet_of} or return;
    my $context = $object->{descr} || $object->{name};
    my $network = expand_typed_name('network', $name, $context, $ipv6);
    if (not $network) {
        warn_msg("Ignoring undefined network:$name",
                 " from attribute 'subnet_of'\n",
                 " of $context");

        # Prevent further errors;
        delete $object->{subnet_of};
        return;
    }
    $object->{subnet_of} = $network;
    my $ip     = $network->{ip};
    my $mask   = $network->{mask};
    my $sub_ip = $object->{ip};

#    debug($network->{name}) if not defined $ip;
    if ($ip eq 'unnumbered') {
        err_msg("Unnumbered $network->{name} must not be referenced from",
                " attribute 'subnet_of'\n of $context");

        # Prevent further errors;
        delete $object->{subnet_of};
        return;
    }

    # $sub_mask needs not to be tested here,
    # because it has already been checked for $object.
    if (not(match_ip($sub_ip, $ip, $mask))) {
        err_msg("$context is subnet_of $network->{name}",
                " but its IP doesn't match that's IP/mask");
    }
    return;
}

sub link_subnets {
    for my $network (values %networks) {
        link_subnet($network, $network->{ipv6});
    }
    for my $obj (values %networks, values %aggregates, values %areas) {
        my $href = $obj->{nat} or next;
        for my $nat_tag (sort keys %$href) {
            my $nat_info = $href->{$nat_tag};
            link_subnet($nat_info, $obj->{ipv6});
        }
    }
}

our @pathrestrictions;

sub add_pathrestriction {
    my ($name, $elements) = @_;
    my $restrict = new('Pathrestriction', name => $name, elements => $elements);
    for my $interface (@$elements) {

#        debug("pathrestriction $name at $interface->{name}");
        push @{ $interface->{path_restrict} }, $restrict;
        my $router = $interface->{router};
        $router->{managed} or $router->{semi_managed} = 1;
    }
    push @pathrestrictions, $restrict;
}

sub link_pathrestrictions {
    for my $restrict (sort by_name values %pathrestrictions) {
        my $elements = expand_group($restrict->{elements},
                                    $restrict->{name}, $restrict->{ipv6});
        my $changed;
        my $private = my $no_private = $restrict->{private};
        for my $obj (@$elements) {
            if (not is_interface($obj)) {
                err_msg("$restrict->{name} must not reference $obj->{name}");
                $obj     = undef;
                $changed = 1;
                next;
            }

            # Pathrestrictions must not be applied to secondary interfaces
            $obj->{main_interface}
              and err_msg("$restrict->{name} must not reference",
                          " secondary $obj->{name}");

            # Private pathrestriction must reference at least one interface
            # of its own context.
            if ($private) {
                if (my $obj_p = $obj->{private}) {
                    $private eq $obj_p and $no_private = 0;
                }
            }

            # Public pathrestriction must not reference private interface.
            else {
                if (my $obj_p = $obj->{private}) {
                    err_msg "Public $restrict->{name} must not reference",
                      " $obj_p $obj->{name}";
                }
            }
        }
        if ($no_private) {
            err_msg "$private $restrict->{name} must reference",
              " at least one interface out of $private";
        }
        if ($changed) {
            $elements = [ grep { $_ } @$elements ];
        }
        my $count = @$elements;
        if ($count == 1) {
            warn_msg(
                "Ignoring $restrict->{name} with only",
                " $elements->[0]->{name}"
            );
            $elements = [];
        }
        elsif ($count == 0) {
            warn_msg("Ignoring $restrict->{name} without elements");
        }

        # Add pathrestriction to interface, after invalid
        # pathrestrictions have been removed.
        for my $obj (@$elements) {
            # Add pathrestriction to interface.
            # Multiple restrictions may be applied to a single
            # interface.
            push @{ $obj->{path_restrict} }, $restrict;

            # Unmanaged router with pathrestriction is handled specially.
            # It is separating zones, but gets no code.
            my $router = $obj->{router};
            $router->{managed} or $router->{semi_managed} = 1;
        }
        $restrict->{elements} = $elements;
    }
}

# If a pathrestriction is added to an unmanged router, it is marked as
# semi_managed. As a consequence, a new zone would be created at each
# interface of this router.
# If an unmanaged router has a large number of interfaces, but only
# one or a few pathrestrictions attached, we would get a large
# number of useless zones.
# To reduce the number of newly created zones, we split an unmanaged
# router with pathrestrictions, if it has more than two interfaces
# without pathrestriction:
# - original part having only interfaces without pathrestrictions,
# - one split part for each interface with pathrestrictions.
# All parts are connected by a freshly created unnumbered network.
sub split_semi_managed_router {
    for my $router (get_ipv4_ipv6_routers()) {

        # Router is marked as semi_managed, if it
        # - has pathrestriction
        # - or is managed=routing_only.
        $router->{semi_managed} or next;

        # Don't split device with 'managed=routing_only'.
        next if $router->{routing_only};

        # Count interfaces without pathrestriction.
        # Check if router has pathrestriction at all.
        my $interfaces = $router->{interfaces};
        my $has_pathrestriction;
        my $count = 0;
        for my $interface (@$interfaces) {
            next if $interface->{main_interface};
            if ($interface->{path_restrict}) {
                $has_pathrestriction = 1;
            }
            else {
                $count++;
            }
        }
        $count > 1 and $has_pathrestriction or next;

        # Retain copy of original interfaces for finding [all] interfaces.
        $router->{orig_interfaces} ||= [@$interfaces];

        # Split router into two or more parts.
        # Move each interface with pathrestriction and
        # corresponding secondary interface to new router.
#        debug "split $router->{name}";
        my @split_secondary;
        my $name = $router->{name};

        for my $interface (@$interfaces) {
            if (my $main = $interface->{main_interface}) {
                $main->{path_restrict} or next;
                push @split_secondary, $interface;
                next;
            }
            $interface->{path_restrict} or next;

            # Create new semi_manged router with identical name.
            # Add reference to original router having {orig_interfaces}.
            my $new_router = new('Router',
                                 name => "$name(split)",
                                 semi_managed => 1,
                                 orig_router => $router,
                                 interfaces => [$interface]);
            $interface->{router} = $new_router;
            push @router_fragments, $new_router;

            # Link current and newly created router by unnumbered network.
            my $intf_name = $interface->{name};
            my $network = new('Network',
                              name => "$intf_name(split Network)",
                              ip => 'unnumbered');
            my $intf1 = new('Interface',
                            name => "$intf_name(split1)",
                            ip => 'unnumbered',
                            router => $router,
                            network => $network);
            my $intf2 = new('Interface',
                            name => "$intf_name(split2)",
                            ip => 'unnumbered',
                            router => $new_router,
                            network => $network);
            $network->{interfaces} = [$intf1, $intf2];
            $new_router->{interfaces} = [$intf2, $interface];

            # Add reference to other interface at original interface
            # at newly created router. This is needed for post
            # processing in check_pathrestrictions.
            $interface->{split_other} = $intf2;

            # Replace original interface at current router.
            $interface = $intf1;
        }

        # Original router is no longer semi_manged.
        delete $router->{semi_managed};

        # Move secondary interfaces.
        for my $interface (@split_secondary) {
            aref_delete($interfaces, $interface);
            my $main_intf = $interface->{main_interface};
            my $new_router = $main_intf->{router};
            $interface->{router} = $new_router;
            push @{ $new_router->{interfaces} }, $interface;

        }
    }
}

# Collect groups of virtual interfaces
# - be connected to the same network and
# - having the same IP address.
# Link all virtual interfaces to the group of member interfaces.
# Check consistency:
# - Member interfaces must use identical protocol and identical ID.
# - The same ID must not be used by some other group
#   - connected to the same network
#   - emploing the same redundancy type
sub link_virtual_interfaces {

    # Collect array of virtual interfaces with same IP at same network.
    my %net2ip2virtual;

    # Hash table to look up first virtual interface of a group
    # inside the same network and using the same ID and type.
    my %net2id2type2virtual;
    for my $virtual1 (@virtual_interfaces) {
        next if $virtual1->{disabled};
        my $ip    = $virtual1->{ip};
        my $net   = $virtual1->{network};
        my $type1 = $virtual1->{redundancy_type} || '';
        my $id1   = $virtual1->{redundancy_id} || '';
        if (my $interfaces = $net2ip2virtual{$net}->{$ip}) {
            my $virtual2 = $interfaces->[0];
            my $type2 = $virtual2->{redundancy_type} || '';
            if ($type1 ne $type2) {
                err_msg("Must use identical redundancy protocol at\n",
                        " - $virtual2->{name}\n",
                        " - $virtual1->{name}");
            }
            my $id2 = $virtual2->{redundancy_id} || '';
            if ($id1 ne $id2) {
                err_msg("Must use identical ID at\n",
                        " - $virtual2->{name}\n",
                        " - $virtual1->{name}");
            }

            # This changes value of %net2ip2virtual and all attributes
            # {redundancy_interfaces} where this array is referenced.
            push @$interfaces, $virtual1;
            $virtual1->{redundancy_interfaces} = $interfaces;
        }
        else {
            $net2ip2virtual{$net}->{$ip} = $virtual1->{redundancy_interfaces} =
              [$virtual1];

            # Check for identical ID used at unrelated virtual interfaces
            # inside the same network.
            if ($id1) {
                if (my $other = $net2id2type2virtual{$net}->{$id1}->{$type1}) {
                    err_msg("Must use different ID at unrelated\n",
                        " - $other->{name}\n",
                        " - $virtual1->{name}");
                }
                else {
                    $net2id2type2virtual{$net}->{$id1}->{$type1} = $virtual1;
                }
            }
        }
    }

    # Automatically add pathrestriction to interfaces belonging to
    # $net2ip2virtual, if at least one interface is managed.
    # Pathrestriction would be useless if all devices are unmanaged.
    for my $href (values %net2ip2virtual) {
        for my $interfaces (values %$href) {
            next if @$interfaces < 2;
            for my $interface (@$interfaces) {
                my $router = $interface->{router};
                if ($router->{managed} or $router->{routing_only}) {
                    my $name = "auto-virtual-" . print_ip $interface->{ip};
                    add_pathrestriction($name, $interfaces);
                    last;
                }
            }
        }
    }
}

sub link_services {

    # Sort by service name to make output deterministic.
    for my $key (sort keys %services) {
        my $service = $services{$key};
        my $name    = $service->{name};

        # Substitute service name by service object.
        if (my $overlaps = $service->{overlaps}) {
            my @sobjects;
            for my $pair (@$overlaps) {
                my ($type, $oname) = @$pair;
                if ($type ne 'service') {
                    err_msg("Unexpected type '$type' in attribute 'overlaps'",
                            " of $name");
                }
                elsif (my $other = $services{$oname}) {
                    push(@sobjects, $other);
                }
                else {
                    warn_msg("Unknown $type:$oname in attribute 'overlaps'",
                             " of $name");
                }
            }
            $service->{overlaps} = \@sobjects;
        }
    }
}

##############################################################################
# Purpose    : Check, whether input Interfaces belong to same redundancy group.
# Parameters : Array keeping all interfaces of a network.
# Returns    : True, if all interfacss belong to same redundancy group,
#              false otherwise.
sub is_redundany_group {
    my ($interfaces) = @_;
    my $group = $interfaces->[0]->{redundancy_interfaces} or return;
    my $count =
      grep({ $_->{redundancy_interfaces} || '' eq $group } @$interfaces);
    return $count == @$interfaces;
}

sub check_ip_addresses {
    my ($network) = @_;
    my %ip2obj;

    # 1. Check for duplicate interface addresses.
    # 2. Short or negotiated interfaces must not be used, if a managed
    #    interface with static routing exists in the same network.
    my ($short_intf, $route_intf);
    for my $interface (@{ $network->{interfaces} }) {
        my $ip = $interface->{ip};
        if ($ip eq 'short') {

            # Ignore short interface from split crypto router.
            if (1 < @{ $interface->{router}->{interfaces} }) {
                push @$short_intf, $interface;
            }
        }
        elsif ($ip eq 'negotiated') {
            push @$short_intf, $interface;
        }
        elsif ($ip ne 'bridged') {
            my $router = $interface->{router};
            if (($router->{managed} or $router->{routing_only})
                and not $interface->{routing} and not $interface->{is_layer3})
            {
                $route_intf = $interface;
            }
            if (my $other = $ip2obj{$ip}) {
                $other->{redundant} and $interface->{redundant} or
                    err_msg("Duplicate IP address for",
                            " $other->{name} and $interface->{name}");
            }
            else {
                $ip2obj{$ip} = $interface;
            }
        }
    }
    if ($short_intf and $route_intf) {
        err_msg("Can't generate static routes for $route_intf->{name}",
                " because IP address is unknown for:\n",
                name_list($short_intf));
    }
    my $hosts = $network->{hosts} or next;
    for my $host (@$hosts) {
        my $range = $host->{range} or next;
        my ($low, $high) = @$range;
        for (my $ip = $low ; $ip le $high ; $ip = increment_ip($ip)) {
            if (my $other_device = $ip2obj{$ip}) {
                err_msg("Duplicate IP address for $other_device->{name}",
                        " and $host->{name}");
            }
        }
    }
    for my $host (@$hosts) {
        my $key = $host->{ip} || join '-', @{ $host->{range} };
        if (my $other_device = $ip2obj{$key}) {
            err_msg("Duplicate IP address for $other_device->{name}",
                    " and $host->{name}");
        }
        else {
            $ip2obj{$key} = $host;
        }
    }
}

# Check grouped bridged networks.
# Each group
# - must have the same IP address and mask,
# - must have at least two members,
# - must be adjacent
# - linked by bridged interfaces
# Each router having a bridged interface
# must connect at least two bridged networks of the same group.
sub check_bridged_networks {
    my ($prefix2net) = @_;
    for my $prefix (keys %$prefix2net) {
        if (my $network = $networks{$prefix}) {
            err_msg("Must not define $network->{name} together with",
                    " bridged networks of same name");
        }
    }
    for my $href (values %$prefix2net) {
        my @group = sort by_name values %$href;
        my $net1  = shift @group;
        @group or warn_msg("Bridged $net1->{name} must not be used solitary");
        my %seen;
        my @next = ($net1);
        my ($ip1, $mask1) = @{$net1}{qw(ip mask)};

        # Mark all networks connected directly or indirectly with $net1
        # by a bridge as 'connected' in $href.
        while (my $network = pop(@next)) {
            my ($ip, $mask) = @{$network}{qw(ip mask)};
            $ip eq $ip1 and $mask eq $mask1
              or err_msg("$net1->{name} and $network->{name} must have",
                         " identical ip/mask");
            $href->{$network} = 'connected';
            for my $in_intf (@{ $network->{interfaces} }) {
                next if $in_intf->{ip} ne 'bridged';
                my $router = $in_intf->{router};
                next if $seen{$router}++;
                my $count = 1;
                if (my $layer3_intf = $in_intf->{layer3_interface}) {
                    match_ip($layer3_intf->{ip}, $ip1, $mask1)
                      or err_msg("$layer3_intf->{name}'s IP doesn't match",
                        " IP/mask of bridged networks");
                }
                for my $out_intf (@{ $router->{interfaces} }) {
                    next if $out_intf eq $in_intf;
                    next if $out_intf->{ip} ne 'bridged';
                    my $next_net = $out_intf->{network};
                    next if not $href->{$next_net};
                    push(@next, $out_intf->{network});
                    $count++;
                }
                $count > 1
                  or err_msg("$router->{name} can't bridge a single network");
            }
        }
        for my $network (@group) {
            $href->{$network} eq 'connected'
              or err_msg(
                "$network->{name} and $net1->{name}",
                " must be connected by bridge"
              );
        }
    }
}

sub check_ip_addresses_and_bridges {
    my %prefix2net;
    for my $network (values %networks) {

        # Group bridged networks by prefix of name.
        if (my $prefix = $network->{bridged}) {
            $prefix2net{$prefix}->{$network} = $network;
            next;
        }
        my $ip = $network->{ip};
        if ($ip eq 'unnumbered') {
            my $interfaces = $network->{interfaces};
            if ($interfaces and @$interfaces > 2) {
                err_msg("Unnumbered $network->{name} is connected to",
                        " more than two interfaces:\n",
                        name_list($interfaces));
            }
            next;
        }
        next if $ip eq 'tunnel';
        next if $network->{loopback};
        check_ip_addresses($network);
    }

    # Check address conflicts for collected parts of bridged networks.
    for my $href (values %prefix2net) {
        my $dummy  = new('Network');
        my %seen;
        for my $network (sort by_name values %$href) {
            if (my $list = $network->{interfaces}) {
                push(@{ $dummy->{interfaces} },
                     @$list,

                     # Add layer 3 interfaces for address check.
                     grep { not $seen{$_}++ }
                     map { $_->{layer3_interface} || () }
                     @$list)
            }
            if (my $list = $network->{hosts}) {
                push @{ $dummy->{hosts} }, @$list;
            }
        }
        check_ip_addresses($dummy);
    }

    # Check collected parts of bridged networks.
    check_bridged_networks(\%prefix2net);

}

sub link_ipsec;
sub link_crypto;
sub link_tunnels;

sub link_topology {
    progress('Linking topology');
    link_routers;
    link_ipsec;
    link_crypto;
    link_tunnels;
    link_pathrestrictions;
    link_virtual_interfaces;
    split_semi_managed_router();
    link_areas;
    link_subnets;
    link_owners;
    link_services;
    check_ip_addresses_and_bridges();
}

####################################################################
# Mark all parts of the topology located behind disabled interfaces.
# "Behind" is defined like this:
# Look from a router to its interfaces;
# if an interface is marked as disabled,
# recursively mark the whole part of the topology located behind
# this interface as disabled.
# Be cautious with loops:
# Mark all interfaces at loop entry as disabled,
# otherwise the whole topology will get disabled.
####################################################################

sub disable_behind;

sub disable_behind {
    my ($in_interface) = @_;

#  debug("disable_behind $in_interface->{name}");
    $in_interface->{disabled} = 1;
    my $network = $in_interface->{network};
    if (not $network or $network->{disabled}) {

#      debug("Stop disabling at $network->{name}");
        return;
    }
    $network->{disabled} = 1;
    for my $host (@{ $network->{hosts} }) {
        $host->{disabled} = 1;
    }
    for my $interface (@{ $network->{interfaces} }) {
        next if $interface eq $in_interface;

        # This stops at other entry of a loop as well.
        if ($interface->{disabled}) {

#        debug("Stop disabling at $interface->{name}");
            next;
        }
        $interface->{disabled} = 1;
        my $router = $interface->{router};
        $router->{disabled} = 1;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $interface;
            disable_behind $out_interface ;
        }
    }
}

# Lists of network objects which are left over after disabling.
#my @managed_routers;	# defined above
my @routing_only_routers;
my @managed_crypto_hubs;
my @routers;
my @networks;
my @zones;
my @areas;

sub mark_disabled {
    my @disabled_interfaces = grep { $_->{disabled} } values %interfaces;

    for my $interface (@disabled_interfaces) {
        next if $interface->{router}->{disabled};
        disable_behind($interface);
        if ($interface->{router}->{disabled}) {

            # We reached an initial element of @disabled_interfaces,
            # which seems to be part of a loop.
            # This is dangerous, since the whole topology
            # may be disabled by accident.
            err_msg "$interface->{name} must not be disabled,\n",
              " since it is part of a loop";
        }
    }
    for my $interface (@disabled_interfaces) {

        # Delete disabled interfaces from routers.
        my $router = $interface->{router};
        aref_delete($router->{interfaces}, $interface);
        if ($router->{managed} or $router->{routing_only}) {
            my $hardware = $interface->{hardware};
            my $hw_interfaces = $hardware->{interfaces};
            aref_delete($hw_interfaces, $interface);
            if (not @$hw_interfaces) {
                aref_delete($router->{hardware}, $hardware);
            }
        }
    }

    # Disable area, where all interfaces or anchor are disabled.
    for my $area (sort by_name values %areas) {
        my $ok;
        if (my $anchor = $area->{anchor}) {
            $ok = !$anchor->{disabled};
        }
        else {
            for my $attr (qw(border inclusive_border)) {
                my $borders = $area->{$attr} or next;
                if (my @active_borders = grep { not $_->{disabled} } @$borders) {
                    $area->{$attr} = \@active_borders;
                    $ok = 1;
                }
            }
        }
        if ($ok) {
            push @areas, $area;
        }
        else {
            $area->{disabled} = 1;
        }
    }

    for my $router (sort(by_name get_ipv4_ipv6_routers()), @router_fragments) {
        next if $router->{disabled};
        push @routers, $router;
        if ($router->{managed}) {
            push @managed_routers, $router;
        }
        elsif ($router->{routing_only}) {
            push @routing_only_routers, $router;
        }
    }

    # Collect vrf instances belonging to one device.
    # This includes different managed hosts with identical server_name.
    # Also collect all IPv4 and IPv6 routers with same name.
    my %name_ipv2vrf;
    my %name2all;
    for my $router (@managed_routers, @routing_only_routers) {
        next if $router->{orig_router};
        my $device_name = $router->{device_name};
        my $ipv6 = $router->{ipv6} ? ',6' : '';
        push @{ $name_ipv2vrf{"$device_name$ipv6"} }, $router;
        push @{ $name2all{"$device_name"} }, $router;
    }
    for my $aref (values %name2all) {
        next if @$aref == 1;
        equal(
            map {   $_->{managed} || $_->{routing_only}
                  ? $_->{model}->{name}
                  : ()
            } @$aref
          )
          or err_msg(
            "All instances of router:$aref->[0]->{device_name}",
            " must have identical model"
          );
        for my $router (@$aref) {
            $router->{ipv_members} = $aref;
        }
    }

    for my $aref (values %name_ipv2vrf) {
        next if @$aref == 1;

        my %hardware;
        for my $router (@$aref) {
            for my $hardware (@{ $router->{hardware} }) {
                my $name = $hardware->{name};
                if (my $other = $hardware{$name}) {
                    err_msg("Duplicate hardware '$name' at",
                            " $other->{name} and $router->{name}");
                }
                else {
                    $hardware{$name} = $router;
                }
            }
        }
        my $shared_hash = {};
        for my $router (@$aref) {
            $router->{vrf_members}     = $aref;
            $router->{vrf_shared_data} = $shared_hash;
        }
    }

    # Collect networks into @networks.
    # We need a deterministic order.
    # Don't sort by name because code shouldn't change if a network is renamed.
    # Derive order from order of routers and interfaces.
    my %seen;
    for my $router (@routers) {
        my $interfaces = $router->{interfaces};
        if (not $interfaces or not @$interfaces) {
            err_msg("$router->{name} isn't connected to any network");
            next;
        }
        for my $interface (@$interfaces) {
            next if $interface->{disabled};
            my $network = $interface->{network};
            $seen{$network}++ or push @networks, $network;
        }
    }

    # Find networks not connected to any router.
    for my $network (values %networks) {
        next if $network->{disabled};
        next if $seen{$network};
        if (keys %networks > 1 or @routers) {
            err_msg("$network->{name} isn't connected to any router");
            $network->{disabled} = 1;
            for my $host (@{ $network->{hosts} }) {
                $host->{disabled} = 1;
            }
        }
        else {
            push @networks, $network;
        }
    }

    @virtual_interfaces = grep { not $_->{disabled} } @virtual_interfaces;
}

####################################################################
# Convert hosts to subnets.
# Find adjacent subnets.
# Mark subnet relation of subnets.
####################################################################

# 255.255.255.255, 127.255.255.255, ..., 0.0.0.3, 0.0.0.1, 0.0.0.0
my @inverse_masks4 = map { ~ prefix2mask($_) } (0 .. 32);
my @inverse_masks6 = map { ~ prefix2mask($_, 1) } (0 .. 128);


# Convert an IP range to a set of covering IP/mask pairs.
sub split_ip_range {
    my ($low, $high) = @_;
    my @result;
    my $inv_masks = length($low) == 4 ? \@inverse_masks4 : \@inverse_masks6;
  IP:
    while ($low le $high) {
        for my $mask (@$inv_masks) {
            is_zero_ip($low & $mask) or next;
            my $end = $low | $mask;
            $end le $high or next;
            push @result, [ $low, ~ $mask ];
            $low = increment_ip($end);
            next IP;
        }
    }
    return @result;
}

sub owner_eq {
    my ($obj1, $obj2) = @_;
    my $owner1 = $obj1->{owner};
    my $owner2 = $obj2->{owner};
    return not(($owner1 xor $owner2) or $owner1 and $owner1 ne $owner2);
}

sub check_host_compatibility {
    my ($host, $other_subnet) = @_;
    my $nat  = $host->{nat};
    my $nat2 = $other_subnet->{nat};
    if ($nat xor $nat2 or $nat and $nat ne $nat2) {
        err_msg("Inconsistent NAT definition for",
                " $other_subnet->{name} and $host->{name}");
    }
    owner_eq($host, $other_subnet) or
        warn_msg("Inconsistent owner definition for",
                " $other_subnet->{name} and $host->{name}");
}

sub convert_hosts {
    progress('Converting hosts to subnets');
    for my $network (@networks) {
        my $net_ip = $network->{ip};
        next if $net_ip =~ /^(?:unnumbered|tunnel)$/;
        my $ipv6 = $network->{ipv6};
        my $bitstr_len = $ipv6 ? 128 : 32;
        my @subnet_aref;

        # Converts hosts and ranges to subnets.
        # Eliminate duplicate subnets.
        for my $host (@{ $network->{hosts} }) {
            my ($name, $nat, $id, $owner) = @{$host}{qw(name nat id owner)};
            my @ip_mask;

            if (my $ip = $host->{ip}) {
                @ip_mask = [ $ip, get_host_mask($ip) ];
                if ($id) {
                    if (my ($user) = ($id =~ /^(.*?)\@/)) {
                        $user
                          or err_msg(
                            "ID of $name must not start",
                            " with character '\@'"
                          );
                    }
                    else {
                        err_msg("ID of $name must contain character '\@'");
                    }
                }
            }

            # Convert range.
            else {
                my ($ip1, $ip2) = @{ $host->{range} };
                @ip_mask = split_ip_range $ip1, $ip2;

                if ($id) {
                    if (@ip_mask > 1) {
                        err_msg("Range of $name with ID must expand to",
                            " exactly one subnet");
                    }
                    elsif (is_host_mask($ip_mask[0]->[1])) {
                        err_msg("$name with ID must not have single IP");
                    }
                    elsif ($id =~ /^.+\@/) {
                        err_msg("ID of $name must start with character '\@'",
                            " or have no '\@' at all");
                    }
                }
            }

            for my $ip_mask (@ip_mask) {
                my ($ip, $mask) = @$ip_mask;
                my $subnet_size = $bitstr_len - mask2prefix $mask;

                if (my $other_subnet = $subnet_aref[$subnet_size]->{$ip}) {
                    check_host_compatibility($host, $other_subnet);
                    push @{ $host->{subnets} }, $other_subnet;
                }
                else {
                    my $subnet = new(
                        'Subnet',
                        name    => $name,
                        network => $network,
                        ip      => $ip,
                        mask    => $mask,
                    );
                    $subnet->{nat}   = $nat   if $nat;
                    $subnet->{owner} = $owner if $owner;
                    if ($id) {
                        $subnet->{id} = $id;
                        $subnet->{radius_attributes} =
                          $host->{radius_attributes};
                    }
                    $subnet_aref[$subnet_size]->{$ip} = $subnet;
                    push @{ $host->{subnets} },    $subnet;
                    push @{ $network->{subnets} }, $subnet;
                }
            }
        }

        # Set {up} relation and
        # check compatibility of hosts in subnet relation.
        for (my $i = 0 ; $i < @subnet_aref ; $i++) {
            my $ip2subnet = $subnet_aref[$i] or next;

            for my $ip (keys %$ip2subnet) {
                my $subnet = $ip2subnet->{$ip};

                # Search for enclosing subnet.
                for (my $j = $i + 1 ; $j < @subnet_aref ; $j++) {
                    my $mask = prefix2mask($bitstr_len - $j, $ipv6);
                    $ip &= $mask;
                    if (my $up = $subnet_aref[$j]->{$ip}) {
                        $subnet->{up} = $up;
                        check_host_compatibility($subnet, $up);
                        last;
                    }
                }

                # Use network, if no enclosing subnet found.
                $subnet->{up} ||= $network;
            }
        }

        # Find adjacent subnets which build a larger subnet.
        my $network_size = $bitstr_len - mask2prefix($network->{mask});
        for (my $i = 0 ; $i < @subnet_aref ; $i++) {
            my $ip2subnet = $subnet_aref[$i] or next;
            my $mask = prefix2mask($bitstr_len - $i, $ipv6);

            # Identify next supernet.
            my $up_subnet_size = $i + 1;
            my $up_mask = prefix2mask($bitstr_len - $up_subnet_size, $ipv6);

            # Network mask and supernet mask differ in one bit.
            # This bit distinguishes left and right subnet of supernet:
            # mask (/30)                   255.255.255.11111100
            # xor upmask (/29)            ^255.255.255.11111000
            # equals next bit             =  0.  0.  0.00000100
            # left subnet  10.0.0.16/30 ->  10.  0.  0.00010000
            # right subnet 10.0.0.20/30 ->  10.  0.  0.00010100
            my $next = $up_mask ^ $mask;

            for my $ip (keys %$ip2subnet) {
                my $subnet = $ip2subnet->{$ip};

                # Don't combine subnets with NAT
                # ToDo: This would be possible if all NAT addresses
                # match too.
                next if $subnet->{nat};

                # Don't combine subnets having radius-ID.
                next if $subnet->{id};

                # Only take the left part of two adjacent subnets,
                # where lowest network bit is zero.
                is_zero_ip($ip & $next) or next;

                my $next_ip = $ip | $next;

                # Find corresponding right part
                my $neighbor = $ip2subnet->{$next_ip} or next;

                $subnet->{neighbor} = $neighbor;
                $neighbor->{has_neighbor} = 1;
                my $up;

                if ($up_subnet_size >= $network_size) {

                    # Larger subnet is whole network.
                    $up = $network;
                }
                elsif ( $up_subnet_size < @subnet_aref and
                        $up = $subnet_aref[$up_subnet_size]->{$ip})
                {
                }
                else {
                    (my $name = $subnet->{name}) =~ s/^.*:/auto_subnet:/;
                    $up = new(
                        'Subnet',
                        name    => $name,
                        network => $network,
                        ip      => $ip,
                        mask    => $up_mask,
                        up      => $subnet->{up},
                        );
                    $subnet_aref[$up_subnet_size]->{$ip} = $up;
                    push @{ $network->{subnets} }, $up;
                }
                $subnet->{up}   = $up;
                $neighbor->{up} = $up;
            }
        }

        # Attribute {up} has been set for all subnets now.
        # Do the same for unmanaged interfaces.
        for my $interface (@{ $network->{interfaces} }) {
            my $router = $interface->{router};
            next if $router->{managed} or $router->{routing_only};
            $interface->{up} = $network;
        }
    }
}

# Find adjacent subnets and substitute them by their enclosing subnet.
sub combine_subnets {
    my ($subnets) = @_;
    my %hash;
    @hash{@$subnets} = @$subnets;
    my @extra;
    while (1) {
        for my $subnet (@$subnets) {
            my $neighbor = $subnet->{neighbor} or next;
            $hash{$neighbor} or next;
            my $up = $subnet->{up};
            $hash{$up} = $up;
            push @extra, $up;
            delete $hash{$subnet};
            delete $hash{$neighbor};
        }
        if (@extra) {

            # Try again to combine subnets with extra subnets.
            # This version isn't optimized.
            push @$subnets, @extra;
            @extra = ();
        }
        else {
            last;
        }
    }

    return [ grep { $hash{$_} } @$subnets ];
}

####################################################################
# Expand rules
#
# Simplify rules to expanded rules where each rule has exactly one
# src, dst and prt
####################################################################

my %name2object = (
    host      => \%hosts,
    network   => \%networks,
    interface => \%interfaces,
    any       => \%aggregates,
    group     => \%groups,
    area      => \%areas,
);

sub expand_typed_name {
    my ($type, $name, $context, $ipv6) = @_;
    my $object = $name2object{$type}->{$name} or return;
    if ($ipv6 xor $object->{ipv6}) {
        my $expected = $ipv6 ? 'IPv6' : 'IPv4';
        my $found = $object->{ipv6} ? 'IPv6' : 'IPv4';
        err_msg("Must not reference $found $object->{name} in",
                " $expected context $context");
    }
    return $object;
}

sub get_intf {
    my ($router) = @_;
    if (my $orig_router = $router->{orig_router}) {
        return @{ $orig_router->{orig_interfaces} };
    }
    elsif (my $orig_interfaces = $router->{orig_interfaces}) {
        return @$orig_interfaces;
    }
    else {
        return @{ $router->{interfaces} };
    }
}

# Cache created autointerface objects:
# Parent object -> managed flag -> autointerface object
my %auto_interfaces;

# Create an autointerface from the passed router or network.
sub get_auto_intf {
    my ($object, $managed) = @_;

    # Restore effect of split router from transformation in
    # split_semi_managed_router and move_locked_interfaces.
    $object = $object->{orig_router} || $object;

    $managed ||= 0;
    my $result = $auto_interfaces{$object}->{$managed};
    if (not $result) {
        my $name;
        if (is_router $object) {
            ($name = $object->{name}) =~ s/^router://;
        }
        else {
            $name = "[$object->{name}]";
        }
        $name   = "interface:$name.[auto]";
        $result = new(
            'Autointerface',
            name    => $name,
            object  => $object,
        );
        $result->{managed} = $managed if $managed;
        $result->{disabled} = 1 if $object->{disabled};
        $auto_interfaces{$object}->{$managed} = $result;

#       debug($result->{name});
    }
    return $result;
}

# Remove and warn about duplicate values in group.
sub remove_duplicates {
    my ($aref, $context) = @_;
    my %seen;
    my @duplicates;
    for my $obj (@$aref) {
        if ($seen{$obj}++) {
            push @duplicates, $obj;
        }
    }
    if (@duplicates) {
        aref_delete($aref, $_) for @duplicates;
        warn_msg("Duplicate elements in $context:\n ",
                 join "\n ", map { $_->{name} } @duplicates);
    }
}

# Get a reference to an array of network object descriptions and
# return a reference to an array of network objects.
sub expand_group1;

sub expand_group1 {
    my ($aref, $context, $ipv6, $clean_autogrp, $with_subnets) = @_;
    my @objects;
    for my $parts (@$aref) {

        my ($type, $name, $ext) = @$parts;
        if ($type eq '&') {
            my @non_compl;
            my @compl;
            for my $element (@$name) {
                my $element1 = $element->[0] eq '!' ? $element->[1] : $element;
                my @elements =
                  map { $_->{is_used} = 1; $_; } @{
                    expand_group1(
                        [$element1], "intersection of $context",
                        $ipv6, $clean_autogrp, $with_subnets
                    )
                  };
                if ($element->[0] eq '!') {
                    push @compl, @elements;
                }
                else {
                    push @non_compl, \@elements;
                }
            }
            @non_compl >= 1
              or err_msg "Intersection needs at least one element",
              " which is not complement in $context";
            my $result;
            my $first_set = shift @non_compl;
            for my $element (@$first_set) {
                $result->{$element} = $element;
            }
            for my $set (@non_compl) {
                my $intersection;
                for my $element (@$set) {
                    if ($result->{$element}) {
                        $intersection->{$element} = $element;
                    }
                }
                $result = $intersection;
            }
            for my $element (@compl) {
                next if $element->{disabled};
                delete $result->{$element}
                  or warn_msg("Useless delete of $element->{name} in $context");
            }

            # Put result into same order as the elements of first non
            # complemented set. This set contains all elements of resulting set,
            # because we are doing intersection here.
            my $len = @objects;
            my $new_len = push @objects, grep { $result->{$_} } @$first_set;

            # Warn on empty intersection of non empty parts.
            if ($len == $new_len and @$first_set) {
                my $printable = sub {
                    my ($descr) = @_;
                    my($type, $name, $ext) = @$descr;
                    my $result = ' ';
                    if ($type eq '!') {
                        $result = '!';
                        ($type, $name, $ext) = @$name;
                    }
                    $result .= "$type:";
                    $result .= ref($name) ? "[..]" : $name;
                    $result .= ref($ext) ? ".[$ext->[0]]" : ".$ext"
                        if $ext and $type eq 'interface';
                    return $result;
                };
                warn_msg("Empty intersection in $context:",
                         "\n ",
                         join("\n&", map {$printable->($_)} @$name));
            }
        }
        elsif ($type eq '!') {
            err_msg("Complement (!) is only supported as part of intersection",
                " in $context");
        }
        elsif ($type eq 'user') {

            # Either a single object or an array of objects.
            my $elements = $name->{elements};
            push @objects, ref($elements) eq 'ARRAY' ? @$elements : $elements;
        }
        elsif ($type eq 'interface') {
            my @check;
            if (ref $name) {
                ref $ext
                  or err_msg("Must not use interface:[..].$ext in $context");
                my ($selector, $managed) = @$ext;
                my $sub_objects = expand_group1(
                    $name, "interface:[..].[$selector] of $context", $ipv6);
                for my $object (@$sub_objects) {
                    next if $object->{disabled};
                    $object->{is_used} = 1;
                    my $type = ref $object;
                    if ($type eq 'Network') {
                        if ($selector eq 'all') {
                            if ($object->{is_aggregate}) {

                                # We can't simply take
                                # aggregate -> networks -> interfaces,
                                # because subnets may be missing.
                                is_zero_ip($object->{mask})
                                  or err_msg "Must not use",
                                  " interface:[..].[all]\n",
                                  " with $object->{name} having ip/mask\n",
                                  " in $context";
                                push @check, @{ $object->{zone}->{interfaces} };
                            }

                            # Find managed interfaces of non aggregate network.
                            elsif ($managed) {
                                push @check,
                                  grep({    $_->{router}->{managed}
                                         || $_->{router}->{routing_only} }
                                       @{ $object->{interfaces} });
                            }

                            # Find all interfaces of non aggregate network.
                            else {
                                push @check, @{ $object->{interfaces} };
                            }
                        }
                        else {
                            if ($object->{is_aggregate}) {
                                err_msg "Must not use",
                                  " interface:[any:..].[auto]",
                                  " in $context";
                            }
                            else {
                                push @objects, get_auto_intf $object, $managed;
                            }
                        }
                    }
                    elsif ($type eq 'Interface') {
                        my $router = $object->{router};
                        if ($managed and
                            not ($router->{managed} or $router->{routing_only}))
                        {

                            # Do nothing.
                        }
                        elsif ($selector eq 'all') {
                            push @check, get_intf($router);
                        }
                        else {
                            push @objects, get_auto_intf $router;
                        }
                    }
                    elsif ($type eq 'Area') {
                        my @routers;

                        # Prevent duplicates and border routers.
                        my %seen;

                        # Don't add routers at border of this area.
                        for my $interface (@{ $object->{border} }) {
                            $seen{ $interface->{router} } = 1;
                        }

                        # Add routers at border of security zones inside
                        # current area.
                        for my $router (
                            map { $_->{router} }
                            map { get_intf($_) } @{ $object->{zones} }
                          )
                        {
                            if (not $seen{$router}) {
                                push @routers, $router;
                                $seen{$router} = 1;
                            }
                        }
                        if ($managed) {

                            # Remove semi managed routers.
                            @routers =
                              grep({ $_->{managed} or $_->{routing_only} }
                                @routers);
                        }
                        else {
                            push @routers, map {
                                my $r = $_->{unmanaged_routers};
                                $r ? @$r : ()
                            } @{ $object->{zones} };
                        }
                        if ($selector eq 'all') {
                            push @check, map { get_intf($_) } @routers;
                        }
                        else {
                            push @objects, map { get_auto_intf($_) } @routers;
                        }
                    }
                    elsif ($type eq 'Autointerface') {
                        my $obj = $object->{object};
                        if (is_router $obj) {
                            if ($managed and
                                not ($obj->{managed} or $obj->{routing_only}))
                            {

                                # This router has no managed interfaces.
                            }
                            elsif ($selector eq 'all') {
                                push @check, get_intf($obj);
                            }
                            else {
                                push @objects, get_auto_intf $obj;
                            }
                        }
                        else {
                            err_msg "Can't use $object->{name} inside",
                              " interface:[..].[$selector] of $context";
                        }
                    }
                    else {
                        err_msg
                          "Unexpected type '$type' in interface:[..] of $context";
                    }
                }
            }

            # interface:name.[xxx]
            elsif (ref $ext) {
                my ($selector) = @$ext;
                my $lookup = $ipv6 ? \%routers6 : \%routers;
                if (my $router = $lookup->{$name}) {
                    if ($selector eq 'all') {
                        push @check, get_intf($router);
                    }
                    else {
                        push @objects, get_auto_intf $router;
                    }
                }
                else {
                    err_msg(
                        "Can't resolve $type:$name.[$selector] in $context");
                }
            }

            # interface:name.name
            elsif (my $interface = $interfaces{"$name.$ext"}) {
                push @objects, $interface;
            }
            else {
                err_msg("Can't resolve $type:$name.$ext in $context");
            }

            # Silently remove unnumbered, bridged and tunnel interfaces
            # from automatic groups.
            push @objects,
              grep { $_->{ip} ne 'tunnel' }
              $clean_autogrp
              ? grep { $_->{ip} !~ /^(?:unnumbered|bridged)$/ } @check
              : @check;
        }
        elsif (ref $name) {
            my $sub_objects = [
                map { $_->{is_used} = 1; $_; }
                  grep { not($_->{disabled}) }
                  @{ expand_group1($name, "$type:[..] of $context", $ipv6) }
            ];
            my $get_aggregates = sub {
                my ($object, $ip, $mask) = @_;
                if (not defined $ip) {
                    $ip = $mask = get_zero_ip($object->{ipv6});
                }
                my @objects;
                my $type = ref $object;
                if ($type eq 'Area') {
                    push @objects,
                      unique(
                        map({ get_any($_, $ip, $mask) } @{ $object->{zones} }));
                }
                elsif ($type eq 'Network' and $object->{is_aggregate}) {
                    push @objects, get_any($object->{zone}, $ip, $mask);
                }
                else {
                    return;
                }
                return \@objects;
            };
            my $get_networks = sub {
                my ($object) = @_;
                my @objects;
                my $type = ref $object;
                if ($type eq 'Host' or $type eq 'Interface') {
                    return [$object->{network}];
                }
                if ($type eq 'Network') {
                    if (not $object->{is_aggregate}) {
                        push @objects, $object;
                    }

                    # Take aggregate directly. Don't use next "elsif"
                    # clause below, where it would be changed to non
                    # matching aggregate with IP 0/0.
                    else {
                        push @objects, @{ $object->{networks} };
                    }
                }
                elsif (my $aggregates = $get_aggregates->($object))
                {
                    push(
                        @objects,

                        # Check type, because $get_aggregates
                        # eventually returns non aggregate network if
                        # one matches 0/0.
                        map({ $_->{is_aggregate} ? @{ $_->{networks} } : $_ }
                            @$aggregates)
                    );
                }
                else {
                    return;
                }
                if ($with_subnets) {
                    my $get_subnets = sub {
                        my ($networks) = @_;
                        my @result;
                        for my $network (@$networks) {
                            my $subnets = $network->{networks} or next;
                            push @result, @$subnets;
                            push @result, __SUB__->($subnets);
                        }
                        return @result;
                    };
                    push @objects, $get_subnets->(\@objects);
                }
                return \@objects;
            };
            if ($type eq 'host') {
                my $managed = $ext;
                my @hosts;
                $with_subnets = undef;
                for my $object (@$sub_objects) {
                    my $type = ref $object;
                    if ($type eq 'Host') {
                        push @hosts, $object;
                    }
                    elsif ($type eq 'Interface') {
                        if ($object->{is_managed_host}) {
                            push @hosts, $object;
                        }
                        else {
                            err_msg
                              "Unexpected interface in host:[..] of $context";
                        }
                    }
                    elsif (my $networks = $get_networks->($object)) {
                        my $add_all_hosts = sub {
                            my ($network) = @_;
                            push @hosts, @{ $network->{hosts} };
                            if (my $managed_hosts = $network->{managed_hosts}) {
                                push @hosts, @$managed_hosts;
                            }
                            my $subnets = $network->{networks} or return;
                            __SUB__->($_) for @$subnets;
                        };
                        for my $network (@$networks) {
                            $add_all_hosts->($network);
                        }
                    }
                    else {
                        err_msg
                          "Unexpected type '$type' in host:[..] of $context";
                    }
                }
                if ($managed) {
                    @hosts = grep { $_->{is_managed_host} } @hosts;
                }
                push @objects, @hosts;
            }
            elsif ($type eq 'network') {
                my @list;
                for my $object (@$sub_objects) {
                    if (my $networks = $get_networks->($object)) {

                        # Silently remove from automatic groups:
                        # - crosslink network
                        # - loopback network of managed device
                        push(@list,
                               $clean_autogrp
                             ? grep {
                                 not ($_->{loopback} and
                                      $_->{interfaces}->[0]->{router}->{managed}
                                     ) }
                               grep { not($_->{crosslink}) }
                               @$networks
                             : @$networks);
                    }
                    else {
                        my $type = ref $object;
                        err_msg("Unexpected type '$type' in network:[..] of",
                            " $context");
                    }
                }

                # Ignore duplicate networks resulting from different
                # interfaces connected to the same network.
                push @objects, unique(@list);
            }
            elsif ($type eq 'any') {
                my ($ip, $mask) = $ext ? @$ext : ();
                my @list;
                for my $object (@$sub_objects) {
                    if (my $aggregates = $get_aggregates->($object, $ip, $mask))
                    {
                        push @list, @$aggregates;
                    }
                    elsif (my $networks = $get_networks->($object)) {
                        push @list,
                          map({ get_any($_->{zone}, $ip, $mask) } @$networks);
                    }
                    else {
                        my $type = ref $object;
                        err_msg
                          "Unexpected type '$type' in any:[..]",
                          " of $context";
                    }
                }

                # Ignore duplicate aggregates resulting from different
                # interfaces connected to the same aggregate.
                push @objects, unique(@list);
            }
            else {
                err_msg("Unexpected $type:[..] in $context");
            }
        }

        # An object named simply 'type:name'.
        else {
            my $object = expand_typed_name($type, $name, $context, $ipv6);
            if (not $object) {
                err_msg("Can't resolve $type:$name in $context");
                next;
            }
            $ext and
                err_msg("Unexpected '.$ext' after $type:$name in $context");

            # Split a group into its members.
            # There may be two different versions depending of $clean_autogrp.
            if (is_group $object) {

                # Two different expanded values, depending on $clean_autogrp.
                my $ext = $clean_autogrp ? 'clean' : 'noclean';
                my $attr_name = "expanded_$ext";

                my $elements = $object->{$attr_name};

                # Check for recursive definition.
                if ($object->{recursive}) {
                    err_msg("Found recursion in definition of $context");
                    $object->{$attr_name} = $elements = [];
                    delete $object->{recursive};
                }

                # Group has not been converted from names to references.
                elsif (not $elements) {

                    # Add marker for detection of recursive group definition.
                    $object->{recursive} = 1;

                    # Mark group as used.
                    $object->{is_used} = 1;

                    $elements =
                      expand_group1($object->{elements}, "$type:$name", $ipv6,
                                    $clean_autogrp);
                    delete $object->{recursive};

                    # Private group must not reference private element of other
                    # context.
                    # Public group must not reference private element.
                    my $private1 = $object->{private} || 'public';
                    for my $element (@$elements) {
                        if (my $private2 = $element->{private}) {
                            $private1 eq $private2
                              or err_msg(
                                "$private1 $object->{name} must not",
                                " reference $private2 $element->{name}"
                              );
                        }
                    }

                    # Detect and remove duplicate values in group.
                    remove_duplicates($elements, "$type:$name");

                    # Cache result for further references to the same group
                    # in same $clean_autogrp context.
                    $object->{$attr_name} = $elements;
                }
                push @objects, @$elements;
            }

            # Substitute aggregate by aggregate set of zone cluster.
            elsif ($object->{is_aggregate} and $object->{zone}->{zone_cluster}) {
                my ($ip, $mask) = @{$object}{qw(ip mask)};
                push(@objects,
                    get_cluster_aggregates($object->{zone}, $ip, $mask));
            }

            else {
                push @objects, $object;
            }
        }
    }
    return \@objects;
}

# Parameter $with_subnets is set, if called from command "print-group".
# This changes the result of network:[any|area|network:..]:
# For each resulting network, all subnets of this network in same zone
# are added.
sub expand_group {
    my ($obref, $context, $ipv6, $with_subnets) = @_;
    my $aref =
        expand_group1($obref, $context, $ipv6, 'clean_autogrp', $with_subnets);
    remove_duplicates($aref, $context);

    # Ignore disabled objects.
    my $changed;
    for my $object (@$aref) {
        if ($object->{disabled}) {
            $object  = undef;
            $changed = 1;
        }
    }
    $aref = [ grep { defined $_ } @$aref ] if $changed;
    return $aref;
}

my %subnet_warning_seen;

sub expand_group_in_rule {
    my ($obref, $context, $ipv6) = @_;
    my $aref = expand_group($obref, $context, $ipv6);

    # Ignore unusable objects.
    my $changed;
    for my $object (@$aref) {
        my $ignore;
        my $type = ref $object;
        if ($type eq 'Network') {
            if ($object->{ip} eq 'unnumbered') {
                $ignore = "unnumbered $object->{name}";
            }
            elsif ($object->{crosslink}) {
                $ignore = "crosslink $object->{name}";
            }
            elsif ($object->{is_aggregate}) {
                if ($object->{has_id_hosts}) {
                    $ignore = "$object->{name} with software clients";
                }
            }
        }
        elsif ($type eq 'Interface') {
            if ($object->{ip} =~ /^(bridged|short|unnumbered)$/) {
                $ignore = "$object->{ip} $object->{name}";
            }
        }
        elsif ($type eq 'Area') {
            $ignore = $object->{name};
        }
        if ($ignore) {
            $object  = undef;
            $changed = 1;
            warn_msg("Ignoring $ignore in $context");
        }
    }
    $aref = [ grep { defined $_ } @$aref ] if $changed;
    return $aref;
}

sub check_unused_groups {
    my $check = sub {
        my ($hash, $print_type) = @_;
        for my $name (sort keys %$hash) {
            my $value = $hash->{$name};
            next if $value->{is_used};
            warn_or_err_msg($print_type, "unused $value->{name}");
        }
    };
    if (my $conf = $config->{check_unused_groups}) {
        for my $hash (\%groups, \%protocolgroups) {
            $check->($hash, $conf);
        }
    }
    if (my $conf = $config->{check_unused_protocols}) {
        for my $hash (\%protocols) {
            $check->($hash, $conf);
        }
    }

    # Not used any longer; free memory.
    %groups = ();
}

# Result: Array of protocols.
sub expand_protocols {
    my ($aref, $context) = @_;
    my @protocols;
    for my $pair (@$aref) {

        # Handle anonymous protocol.
        if (ref($pair) eq 'HASH') {
            push @protocols, $pair;
            next;
        }

        my ($type, $name) = @$pair;
        if ($type eq 'protocol') {
            if (my $prt = $protocols{$name}) {
                push @protocols, $prt;

                # Currently needed by external program 'cut-netspoc'.
                $prt->{is_used} = 1;
            }
            else {
                err_msg("Can't resolve reference to $type:$name in $context");
                next;
            }
        }
        elsif ($type eq 'protocolgroup') {
            if (my $prtgroup = $protocolgroups{$name}) {
                my $elements = $prtgroup->{elements};
                if ($elements eq 'recursive') {
                    err_msg("Found recursion in definition of $context");
                    $prtgroup->{elements} = $elements = [];
                }

                # Check if it has already been converted
                # from names to references.
                elsif (not $prtgroup->{is_used}) {

                    # Detect recursive definitions.
                    $prtgroup->{elements} = 'recursive';
                    $prtgroup->{is_used}  = 1;
                    $elements = expand_protocols($elements, "$type:$name");

                    # Cache result for further references to the same group.
                    $prtgroup->{elements} = $elements;
                }

                # Split only once.
                push @protocols, @$elements;
            }
            else {
                err_msg("Can't resolve reference to $type:$name in $context");
                next;
            }
        }
        else {
            err_msg("Unknown type of $type:$name in $context");
        }
    }
    return \@protocols;
}

# Split protocols.
# Result:
# Reference to array with elements
# - non TCP/UDP protocol
# - dst_range of (split) TCP/UDP protocol
# - [ src_range, dst_range, orig_prt ]
#   of (split) protocol having src_range or main_prt.
sub split_protocols {
    my ($protocols) = @_;
    my @split_protocols;
    for my $prt (@$protocols) {
        my $proto = $prt->{proto};
        if (not($proto eq 'tcp' or $proto eq 'udp')) {
            push @split_protocols, $prt;
            next;
        }

        # Collect split src_range / dst_range pairs.
        my $dst_range = $prt->{dst_range};
        my $src_range = $prt->{src_range};

        # Remember original protocol as third value
        # - if src_range is given or
        # - if original protocol has modifiers or
        # - if $dst_range is shared between different protocols.
        # Cache list of triples at original protocol for re-use.
        if ($src_range or $prt->{modifiers} or
            $dst_range->{name} ne $prt->{name})
        {
            my $aref_list = $prt->{src_dst_range_list};
            if (not $aref_list) {
                for my $src_split (expand_split_protocol($src_range)) {
                    for my $dst_split (expand_split_protocol($dst_range)) {
                        push @$aref_list, [ $src_split, $dst_split, $prt ];
                    }
                }
                $prt->{src_dst_range_list} = $aref_list;
            }
            push @split_protocols, @$aref_list;
        }
        else {
            for my $dst_split (expand_split_protocol($dst_range)) {
                push @split_protocols, $dst_split;
            }
        }
    }
    return \@split_protocols;
}

########################################################################
# Handling of log attribute of rules.
########################################################################

# All log tags defined at some routers.
my %known_log;

# Store defining log tags as keys in %known_log.
sub collect_log {
    my ($log_hash) = @_;
    for my $tag (keys %$log_hash) {
        $known_log{$tag} = 1;
    }
}

# Check for referencing log tags, that corresponding defining log tags exist.
sub check_log {
    my ($log, $context) = @_;
    for my $tag (@$log) {
        $known_log{$tag} and next;
        warn_msg("Referencing unknown '$tag' in log of $context");
        aref_delete($log, $tag);
    }
}

# Normalize lists of log tags at different rules in such a way,
# that equal sets of tags are represented by 'eq' array references.
my %key2log;

sub normalize_log {
    my ($log) = @_;
    my @tags = sort @$log;
    my $key = join(',', @tags);
    return $key2log{$key} ||= \@tags;
}

########################################################################
# Normalize rules of services and
# store them unexpanded in %service_rules.
########################################################################

our %service_rules;

sub get_path;
my %obj2path; # lookup hash, keys: source/destination objects,
              #              values: corresponding path node objects

##############################################################################
# Purpose    : Expand auto interface to one or more real interfaces
#              with respect to list of destination objects.
# Note       : Different destination objects may lead to different result lists.
# Parameters : $auto_intf - an auto interface
#              $dst_list  - list of destination objects
# Result     : An array of pairs:
#              1. List of real interfaces.
#              2. Those objects from $dst_list that lead to result in 1.
sub expand_auto_intf_with_dst_list {
    my ($auto_intf, $dst_list, $context) = @_;
    my %path2result;
    my (@result_list, %result2sub_list);
    for my $dst (@$dst_list) {
        my $path = $obj2path{$dst} || get_path($dst);
        my $result = $path2result{$path};

        if (not $result) {
            $result = [];
            for my $interface (path_auto_interfaces($auto_intf, $path)) {
                if ($interface->{ip} eq 'short') {
                    err_msg("'$interface->{ip}' $interface->{name}",
                            " (from .[auto])\n",
                            " must not be used in rule of $context");
                }
                elsif ($interface->{ip} eq 'unnumbered') {

                    # Ignore unnumbered interfaces.
                }
                else {
                    push @$result, $interface;
                }
            }

            # If identical result already was found with other destination,
            # then share this result for both destinations.
            if (my ($result0) =
                grep { aref_eq($result, $_) } values %path2result)
            {
                $result = $result0;
            }

            # Don't add empty list of interfaces to $result_list.
            elsif (@$result) {
                push @result_list, $result;
            }
            $path2result{$path} = $result;
        }
        push @{$result2sub_list{$result}}, $dst;
    }
    return [ map { [ $_, $result2sub_list{$_} ] } @result_list ];
}

sub substitute_auto_intf {
    my ($src_list, $dst_list, $context) = @_;
    my @result_tuple_list;
    for (my $i = 0; $i < @$src_list; $i++) {
        my $src = $src_list->[$i];
        next if not is_autointerface($src);
        my $tuple_list =
            expand_auto_intf_with_dst_list($src, $dst_list, $context);

        # All elements of $dst_list lead to same result list of interfaces.
        if (1 == @$tuple_list) {
            my $result = $tuple_list->[0]->[0];
            splice(@$src_list, $i, 1, @$result);
            $i += @$result - 1;
            next;
        }

        # Different destination objects lead to different result sets.
        # Remove auto interface from original rule.
        splice(@$src_list, $i, 1);
        $i--;

        # Add src/dst pairs as result.
        push @result_tuple_list, @$tuple_list;
    }
    return @result_tuple_list;
}

sub classify_protocols {
    my ($prt_list, $service) = @_;
    my ($simple_prt_list, $complex_prt_list);
    for my $prt (@$prt_list) {

        # Prevent modification of original array.
        my $prt = $prt;

        # If $prt is duplicate of an identical protocol, use the
        # main protocol, but remember the original one to retrieve
        # {modifiers}.
        my $orig_prt;
        my $src_range;
        if (ref $prt eq 'ARRAY') {
            ($src_range, $prt, $orig_prt) = @$prt;
        }
        elsif (my $main_prt = $prt->{main}) {
            $orig_prt = $prt;
            $prt      = $main_prt;
        }
        my $modifiers = $orig_prt ? $orig_prt->{modifiers} : $prt->{modifiers};
        if ($orig_prt) {
            if ($src_range) {
#               debug "$context +:$prt->{name} => $orig_prt->{name}";
                $service->{src_range2prt2orig_prt}->{$src_range}->{$prt} =
                    $orig_prt;
            }
            else {
#               debug "$context $prt->{name} => $orig_prt->{name}";
                $service->{prt2orig_prt}->{$prt} = $orig_prt;
            }
        }
        if (keys %$modifiers or $src_range or $prt->{stateless_icmp}) {
            push @$complex_prt_list, [ $prt, $src_range, $modifiers ];
        }
        else {
            push @$simple_prt_list, $prt;
        }
    }
    return [$simple_prt_list, $complex_prt_list];
}

sub check_private_service {
    my ($service, $src_list, $dst_list) = @_;
    my $context = $service->{name};
    if (my $private = $service->{private}) {
        grep({ $_->{private} and $_->{private} eq $private }
             @$src_list, @$dst_list) or
                 err_msg("Rule of $private $context must reference at least",
                    " one object out of $private");
    }
    elsif (my @private = grep { $_->{private} } @$src_list, @$dst_list) {
        my $pairs =
            join("\n - ", map { "$_->{name} of $_->{private}" } @private);
        err_msg("Rule of public $context must not reference\n",
                " - $pairs");
    }
}

# Add managed hosts of networks and aggregates.
sub add_managed_hosts {
    my ($aref, $context) = @_;
    my @extra;
    for my $object (@$aref) {
        my $managed_hosts = $object->{managed_hosts} or next;
        push @extra, @$managed_hosts;
    }
    if (@extra) {
        push @$aref, @extra;
        remove_duplicates($aref, $context);
    }
    return $aref;
}

sub normalize_src_dst_list {
    my ($rule, $user, $context, $ipv6) = @_;
    $user_object->{elements} = $user;
    my $src_list =
        expand_group_in_rule($rule->{src}, "src of rule in $context", $ipv6);
    my $dst_list =
        expand_group_in_rule($rule->{dst}, "dst of rule in $context", $ipv6);

    # Expand auto interfaces in src.
    my @extra_src_dst = substitute_auto_intf($src_list, $dst_list, $context);

    # Expand auto interfaces in dst of extra_src_dst.
    if (@extra_src_dst) {
        my @extra_extra;
        for my $src_dst_list (@extra_src_dst) {
            my ($src_list, $dst_list) = @$src_dst_list;
            push(@extra_extra,
                 map { [ $_->[1], $_->[0] ] }
                 substitute_auto_intf($dst_list, $src_list, $context));
        }
        push @extra_src_dst, @extra_extra;
    }

    # Expand auto interfaces in dst.
    push(@extra_src_dst,
         map { [ $_->[1], $_->[0] ] }
         substitute_auto_intf($dst_list, $src_list, $context));
    unshift @extra_src_dst, [ $src_list, $dst_list ];
    return \@extra_src_dst;
}

sub normalize_service_rules {
    my ($service) = @_;
    my $ipv6    = $service->{ipv6};
    my $context = $service->{name};
    my $user    = $service->{user}
                = expand_group($service->{user}, "user of $context", $ipv6);
    my $rules   = $service->{rules};
    my $foreach = $service->{foreach};
    my $rule_count;

    for my $unexpanded (@$rules) {
        my $deny  = $unexpanded->{action} eq 'deny';
        my $store = $service_rules{$deny ? 'deny' : 'permit'} ||= [];
        my $log   = $unexpanded->{log};
        if ($log) {
            check_log($log, $context);
            if (@$log) {
                $log = normalize_log($log);
            }
            else {
                $log = undef;
            }
        }
        my $prt_list =
          split_protocols(expand_protocols($unexpanded->{prt}, $context));
        @$prt_list or next;
        my $prt_list_pair = classify_protocols($prt_list, $service);

        for my $element ($foreach ? @$user : ($user)) {
            my $src_dst_list_pairs =
                normalize_src_dst_list($unexpanded, $element, $context, $ipv6);
            for my $src_dst_list (@$src_dst_list_pairs) {
                my ($src_list, $dst_list) = @$src_dst_list;
                $rule_count++ if @$src_list or @$dst_list;
                @$src_list and @$dst_list or next;
                next if $service->{disabled};
                check_private_service($service, $src_list, $dst_list);
                my ($simple_prt_list, $complex_prt_list) = @$prt_list_pair;
                if ($simple_prt_list) {
                    $dst_list = add_managed_hosts($dst_list,
                                                  "dst of rule in $context");
                    my $rule = {
                        src  => $src_list,
                        dst  => $dst_list,
                        prt  => $simple_prt_list,
                        rule => $unexpanded
                    };
                    $rule->{deny} = 1    if $deny;
                    $rule->{log}  = $log if $log;
                    push @$store, $rule;
                }
                for my $tuple (@$complex_prt_list) {
                    my ($prt, $src_range, $modifiers) = @$tuple;
                    my ($src_list, $dst_list) = $modifiers->{reversed}
                                              ? ($dst_list, $src_list)
                                              : ($src_list, $dst_list);

                    $dst_list = add_managed_hosts($dst_list,
                                                  "dst of rule in $context");
                    my $rule = {
                        src  => $src_list,
                        dst  => $dst_list,
                        prt  => [$prt],
                        rule => $unexpanded
                    };
                    $rule->{deny}      = 1          if $deny;
                    $rule->{log}       = $log       if $log;
                    $rule->{src_range} = $src_range if $src_range;
                    $rule->{stateless} = 1          if $modifiers->{stateless};
                    $rule->{oneway}    = 1          if $modifiers->{oneway};
                    $rule->{no_check_supernet_rules} = 1
                        if $modifiers->{no_check_supernet_rules};
                    $rule->{src_net}   = 1          if $modifiers->{src_net};
                    $rule->{dst_net}   = 1          if $modifiers->{dst_net};
                    $rule->{stateless_icmp} = 1     if $prt->{stateless_icmp};

                    # Only used in check_service_owner.
                    $rule->{reversed}  = 1          if $modifiers->{reversed};

                    push @$store, $rule;
                }
            }
        }
    }
    if (not $rule_count and not @$user) {
        warn_msg("Must not define $context with empty users and empty rules");
    }

    # Result is stored in global %service_rules.
}

sub normalize_services {
    progress('Normalizing services');

    for my $service (sort by_name values %services) {
        normalize_service_rules($service);
    }

    # Only needed during normalize_service_rules.
    %auto_interfaces = ();
}

##############################################################################
# Distribute owner, identify service owner
##############################################################################

sub propagate_owners {
    my %zone_got_net_owners;
    my %clusters;
  ZONE:
    for my $zone (@zones) {
        if (my $cluster = $zone->{zone_cluster}) {
            $clusters{$cluster} = $cluster;
        }

        # If an explicit owner was set, it has been set for
        # the whole cluster in link_aggregates.
        next if $zone->{owner};

        # Inversed inheritance: If a zone has no direct owner and if
        # all contained real toplevel networks have the same owner,
        # then set owner of this zone to the one owner.
        my $owner;
        for my $network (@{ $zone->{networks} }) {
            my $net_owner = $network->{owner};
            next ZONE if not $net_owner;
            if ($owner) {
                next ZONE if $net_owner ne $owner;
            }
            else {
                $owner = $net_owner;
            }
        }
        if ($owner) {

#            debug("Inversed inherit: $zone->{name} $owner->{name}");
            $zone->{owner} = $owner;
            $zone_got_net_owners{$zone} = 1;
        }
    }

    # Check for consistent implicit owners of zone clusters.
    # Implicit owner from networks is only valid, if the same owner
    # is found for all zones of cluster.
    for my $cluster (values %clusters) {
        my @implicit_owner_zones = grep { $zone_got_net_owners{$_} } @$cluster
          or next;
        if (
            not (
                @implicit_owner_zones == @$cluster
                and equal(map { $_->{owner} } @implicit_owner_zones)
            )
          )
        {
            delete $_->{owner} for @implicit_owner_zones;

#            debug("Reset owner");
#            debug($_->{name}) for @implicit_owner_zones;
        }
    }

    {
        my %zone2owner2node;

        # Prepare check for redundant owner of zone in respect to some area.
        # Artificially add zone owner.
        # This simplifies check for redundant owners.
        for my $zone (@zones) {
            my $hash = $zone2owner2node{$zone} = {};
            my $owner = $zone->{owner} or next;
            $hash->{$owner} = $zone;
        }

        # Propagate owners from areas to zones.
        # - Zone inherits owner from smallest enclosing area having
        #   an owner without attribute {only_watch}.
        # - Zone inherits {watching_owners} from all enclosing areas.
        # Check for redundant owners of zones and areas.
        for my $area ( sort { @{ $a->{zones} } <=> @{ $b->{zones} } } @areas) {
            my $owner = $area->{owner} or next;
            $owner->{is_used} = 1;
            my $redundant;
            for my $zone (@{ $area->{zones} }) {
#                debug "$area->{name} $zone->{name}";
                my $hash = $zone2owner2node{$zone};
                if (my $small_area = $hash->{$owner}) {
                    $redundant->{$small_area} = $small_area;
                }
                $hash->{$owner} = $area;
                if (not ($owner->{only_watch} or
                         $zone->{owner} or

                         # Owner of loopback zone will be fixed below.
                         # Don't add it here, so owner will get added
                         # to {watching_owners}.
                         $zone->{loopback}))
                {
                    $zone->{owner} = $owner;
                }
            }
            if ($redundant) {
                for my $small_area (sort by_name values %$redundant) {
                    warn_msg("Useless $owner->{name} at $small_area->{name},\n",
                             " it was already inherited from $area->{name}");
                }
            }
        }

        # Convert intermediate hash to list {watching_owners}.
        for my $zone (@zones) {
            my $hash = $zone2owner2node{$zone};

            # Remove artificially added zone owner from hash.
            if (my $owner = $zone->{owner}) {
                delete $hash->{$owner};
            }
            keys %$hash or next;
            $zone->{watching_owners} = [ map { $_->{owner} } values %$hash ];
        }
    }

    # $upper_node: directly enclosing node of current $node.
    my $inherit = sub {
        my ($node, $upper_node) = @_;
        my $upper_owner = $upper_node->{owner};
        if (my $owner = $node->{owner}) {
            $owner->{is_used} = 1;
            if ($upper_owner and $owner eq $upper_owner) {
                if (not $zone_got_net_owners{$upper_node}) {
                    warn_msg(
                        "Useless $owner->{name} at $node->{name},\n",
                        " it was already inherited from $upper_node->{name}"
                    );
                }
            }
        }
        elsif ($upper_owner) {
            $node->{owner} = $upper_owner;
        }
    };

    # Propagate owner from network to hosts/interfaces.
    my $owner_to_hosts = sub {
        my ($network) = @_;
        for my $host (@{ $network->{hosts} }) {
            $inherit->($host, $network);
        }
        for my $interface (@{ $network->{interfaces} }) {
            my $router = $interface->{router};
            if (not ($router->{managed} or $router->{routing_only})) {
                $inherit->($interface, $network);
            }
        }
    };

    # Propagate owner recursively from network to subnetworks.
    my $owner_to_subnets = sub {
        my ($network) = @_;
        if (my $subnets = $network->{networks}) {
            for my $subnet (@$subnets) {
                $inherit->($subnet, $network);
                __SUB__->($subnet);
            }
        }
        $owner_to_hosts->($network);
    };

    # Propagate owner from zone to networks.
    for my $zone (@zones) {
        for my $network (@{ $zone->{networks} }) {
            $inherit->($network, $zone);
            $owner_to_subnets->($network);
        }
    }

    # Check owner with attribute {show_all}.
    for my $owner (sort by_name values %owners) {
        $owner->{show_all} or next;
        my @invalid;
        for my $zone (@zones) {
            next if $zone->{is_tunnel};
            if (my $zone_owner = $zone->{owner}) {
                next if $zone_owner eq $owner;
            }
            if (my $watching_owners = $zone->{watching_owners}) {
                next if grep { $_ eq $owner } @$watching_owners;
            }
            push @invalid, $zone;
        }
        if (@invalid) {
            my $missing = join("\n - ", map { $_->{name} } @invalid);
            err_msg(
                "$owner->{name} has attribute 'show_all',",
                " but doesn't own whole topology.\n",
                " Missing:\n",
                " - $missing"
            );
        }
    }

    # Handle {router_attributes}->{owner} separately.
    # Areas can be nested. Proceed from small to larger ones.
    for my $area (sort { @{ $a->{zones} } <=> @{ $b->{zones} } } @areas) {
        my $attributes = $area->{router_attributes} or next;
        my $owner      = $attributes->{owner}       or next;
        $owner->{is_used} = 1;
        for my $router (@{ $area->{managed_routers} }) {
            if (my $r_owner = $router->{owner}) {
                if ($r_owner eq $owner) {
                    warn_msg(
                        "Useless $r_owner->{name} at $router->{name},\n",
                        " it was already inherited from $attributes->{name}"
                    );
                }
            }
            else {
                $router->{owner} = $owner;
            }
        }
    }

    for my $router (@managed_routers, @routing_only_routers) {
        my $owner = $router->{owner} or next;
        $owner->{is_used} = 1;

        # Interface of managed router is not allowed to have individual owner.
        for my $interface (get_intf($router)) {
            $interface->{owner} = $owner;
        }
    }

    # Propagate owner of loopback interface to loopback network and
    # loopback zone. Even reset owners to undef, if loopback interface
    # has no owner.
    for my $router (@routers) {
        my $managed = $router->{managed} || $router->{routing_only};
        for my $interface (@{ $router->{interfaces} }) {
            $interface->{loopback} or next;
            my $owner = $interface->{owner};
            $owner and $owner->{is_used} = 1;
            my $network = $interface->{network};
            $network->{owner} = $owner;
            $network->{zone}->{owner} = $owner if $managed;
        }
    }

    # Propagate owner from enclosing network or zone to aggregate.
    for my $zone (@zones) {
        for my $aggregate (values %{ $zone->{ipmask2aggregate} }) {
            next if $aggregate->{owner};
            my $up = $aggregate;
            while ($up = $up->{up}) {
                $up->{is_aggregate} or last;
            }
            my $owner = ($up ? $up : $zone)->{owner} or next;
            $aggregate->{owner} = $owner;
        }
    }
}

sub check_service_owner {
    progress('Checking service owner');

    propagate_owners();

    my (%sname2info, %unknown2services, %unknown2unknown);

    for my $action (qw(permit deny)) {
        my $rules = $service_rules{$action} or next;
        for my $rule (@$rules) {
            my $unexpanded = $rule->{rule};
            my $service    = $unexpanded->{service};
            my $name       = $service->{name};
            my $info       = $sname2info{$name} ||= {};

            $info->{service} = $service;

            # Non 'user' objects.
            my $objects = $info->{objects} ||= {};

            # Check, if service contains a coupling rule with only
            # "user" elements.
            my $has_user = $unexpanded->{has_user};
            if ($has_user eq 'both') {
                $info->{is_coupling} = 1;
            }
            elsif (delete $rule->{reversed}) { # Attribute is no longer needed.
                $has_user = $has_user eq 'src' ? 'dst' : 'src';
            }

            # Collect objects referenced in rules of service.
            for my $what (qw(src dst)) {
                next if $what eq $has_user;
                my $group = $rule->{$what};
                @{$objects}{@$group} = @$group;
            }
        }
    }

    for my $sname (sort keys %sname2info) {
        my $info = $sname2info{$sname};
        my $service = $info->{service};

        # Collect service owners and unknown owners;
        my $service_owners;
        my $unknown_owners;

        my $objects = $info->{objects};
        for my $obj (values %$objects) {
            my $owner = $obj->{owner};
            if ($owner) {
                $service_owners->{$owner} = $owner;
            }
            else {
                $unknown_owners->{$obj} = $obj;
            }
        }

        $service->{owners} = [ values %$service_owners ];

        # Check for redundant service owner.
        # Allow dedicated service owner, if we have multiple owners
        # from @objects.
        if (my $sub_owner = $service->{sub_owner}) {
            $sub_owner->{is_used} = 1;
            keys %$service_owners == 1 and $service_owners->{$sub_owner}
              and warn_msg("Useless $sub_owner->{name} at $service->{name}");
        }

        # Check for multiple owners.
        my $multi_count = $info->{is_coupling}
                        ? 1
                        : values %$service_owners;
        if ($multi_count > 1 xor $service->{multi_owner}) {
            if ($service->{multi_owner}) {
                warn_msg("Useless use of attribute 'multi_owner' at $sname");
            }
            elsif (my $print_type = $config->{check_service_multi_owner}) {
                my @names = sort(map { ($_->{name} =~ /^owner:(.*)/)[0] }
                                 values %$service_owners);
                warn_or_err_msg($print_type,
                                "$sname has multiple owners:\n ",
                                join(', ', @names));
            }
        }

        # Check for unknown owners.
        if (($unknown_owners and keys %$unknown_owners)
            xor $service->{unknown_owner})
        {
            if ($service->{unknown_owner}) {
                warn_msg("Useless use of attribute 'unknown_owner' at $sname");
            }
            else {
                if ($config->{check_service_unknown_owner}) {
                    for my $obj (values %$unknown_owners) {
                        $unknown2unknown{$obj} = $obj;
                        push @{ $unknown2services{$obj} }, $sname;
                    }
                }
            }
        }
    }

    # Show unused owners.
    # Remove attribute {is_used}, which isn't needed any longer.
    my $unused_owners;
    for my $owner (values %owners) {
        delete $owner->{is_used} or push @$unused_owners, $owner
    }
    if ($unused_owners and (my $type = $config->{check_unused_owners})) {
        for my $name (sort map { $_->{name} } @$unused_owners) {
            warn_or_err_msg($type, "Unused $name");
        }
    }

    # Show objects with unknown owner.
    for my $names (values %unknown2services) {
        $names = join(', ', sort @$names);
    }
    for my $obj (sort by_name values %unknown2unknown) {
        warn_or_err_msg($config->{check_service_unknown_owner},
                        "Unknown owner for $obj->{name}",
                        " in $unknown2services{$obj}");
    }
}

########################################################################
# Convert hosts in normalized service_rules to subnets or to networks.
########################################################################

sub apply_src_dst_modifier {
    my ($group) = @_;
    my @modified;
    my @unmodified;
    for my $obj (@$group) {
        my $type = ref $obj;
        my $network;
        if ($type eq 'Host') {
            if ($obj->{id}) {
                push @unmodified, $obj;
                next;
            }
            $network = $obj->{network};
        }
        elsif ($type eq 'Interface') {
            if ($obj->{router}->{managed} or $obj->{loopback}) {
                push @unmodified, $obj;
                next;
            }
            $network = $obj->{network};
        }

        # Network
        else {
            push @unmodified, $obj;
            next;
        }
        push @modified, $network;
    }
    return [ @unmodified, unique(@modified) ];
}

sub convert_hosts_in_rules {
    convert_hosts();
    for my $action (qw(permit deny)) {
        my $rules = $service_rules{$action} or next;
        for my $rule (@$rules) {
            if ($rule->{src_net}) {
                $rule->{src} = apply_src_dst_modifier($rule->{src});
            }
            if ($rule->{dst_net}) {
                $rule->{dst} = apply_src_dst_modifier($rule->{dst});
            }
            for my $what (qw(src dst)) {
                my $group = $rule->{$what};
                my (@other, @subnets, %subnet2host);
                for my $obj (@$group) {

#                    debug("convert $obj->{name}");
                    if (not is_host($obj)) {
                        push @other, $obj;
                        next;
                    }
                    for my $subnet (@{ $obj->{subnets} }) {

                        # Handle special case, where network and subnet
                        # have identical address.
                        # E.g. range = 10.1.1.0-10.1.1.255.
                        # Convert subnet to network, because
                        # - different objects with identical IP
                        #   can't be checked and optimized properly.
                        if ($subnet->{mask} eq $subnet->{network}->{mask}) {
                            my $network = $subnet->{network};
                            if (    not $network->{has_id_hosts}
                                and not $subnet_warning_seen{$subnet}++)
                            {
                                warn_msg(
                                    "Use $network->{name} instead of",
                                    " $subnet->{name}\n",
                                    " because both have identical address"
                                    );
                            }
                            push @other, $network;
                        }
                        elsif (my $host = $subnet2host{$subnet}) {
                            my $sname = $rule->{rule}->{service}->{name};
                            my $context = "$what of $sname";
                            warn_msg("$obj->{name} and $host->{name}",
                                     " overlap in $context");
                        }
                        else {
                            $subnet2host{$subnet} = $obj;
                            if ($subnet->{neighbor} or $subnet->{has_neighbor})
                            {
                                push @subnets, $subnet;
                            }

                            # Subnet can't be combined.
                            else {
                                push @other, $subnet;
                            }
                        }
                    }
                }
                push @other, @{ combine_subnets(\@subnets) };
                $rule->{$what} = \@other;
            }
        }
    }
}

########################################################################
# Get zone of object
########################################################################

my %obj2zone;

sub get_zone {
    my ($obj) = @_;
    my $type = ref $obj;
    my $result;

    # Used, when called on src_path / dst_path of path_rule.
    if ($type eq 'Zone') {
        $result = $obj;
    }
    elsif ($type eq 'Router') {
        if ($obj->{managed}) {
            $result = $obj;
        }
        else {

            # Take surrounding zone from arbitrary attached network.
            $result = $obj->{interfaces}->[0]->{network}->{zone};
        }
    }
    elsif ($type eq 'Interface') {
        if ($obj->{router}->{managed}) {
            $result = $obj->{router};
        }
        else {
            $result = $obj->{network}->{zone};
        }
    }

    # When called on objects from src/dst of path_rule.
    elsif ($type eq 'Network') {
        $result = $obj->{zone};
    }
    elsif ($type eq 'Subnet') {
        $result = $obj->{network}->{zone};
    }
    return ($obj2zone{$obj} = $result);
}

########################################################################
# Collect and show unenforceable rules.
########################################################################

# This handles a rule between objects inside a single security zone or
# between interfaces of a single managed router.
# Show warning or error message if rule is between
# - different interfaces or
# - different networks or
# - subnets/hosts of different networks.
# Rules between identical objects are silently ignored.
# But a message is shown if a service only has rules between identical objects.
sub collect_unenforceable {
    my ($rule, $zone) = @_;
    my $service = $rule->{rule}->{service};

    if ($zone->{has_unenforceable}) {
        $zone->{seen_unenforceable}      = 1;
        $service->{silent_unenforceable} = 1;
        return;
    }

    my $is_coupling = $rule->{rule}->{has_user} eq 'both';
    $service->{silent_unenforceable} = 1;
    my ($src_list, $dst_list) = @{$rule}{qw(src dst)};

    for my $src (@$src_list) {
        for my $dst (@$dst_list) {

            if ($is_coupling) {
                if ($src eq $dst) {
                    next;
                }
                elsif (is_subnet $src and is_subnet($dst)) {

                    # For rules with different subnets of a single
                    # network we don't know if the subnets have been
                    # split from a single range.
                    # E.g. range 1-4 becomes four subnets 1,2-3,4
                    # For most splits the resulting subnets would be
                    # adjacent. Hence we check for adjacency.
                    if ($src->{network} eq $dst->{network}) {
                        my ($a, $b) = $src->{ip} gt $dst->{ip}
                                    ? ($dst, $src)
                                    : ($src, $dst);
                        if (increment_ip(
                                $a->{ip} | ~ ($a->{mask}))
                            eq
                            $b->{ip})
                        {
                            next;
                        }
                    }
                }

                # Different aggregates with identical IP,
                # inside a zone cluster must be considered as equal.
                elsif ($src->{is_aggregate} and $dst->{is_aggregate} and
                       $src->{ip}   eq $dst->{ip} and
                       $src->{mask} eq $dst->{mask})
                {
                    next;
                }

                # This is a common case, which results from rules like
                # user -> any:[user]
                elsif ($src->{is_aggregate} and is_zero_ip($src->{mask})) {
                    next;
                }
                elsif ($dst->{is_aggregate} and is_zero_ip($dst->{mask})) {
                    next;
                }
            }

            # Network or aggregate was only used for its managed_hosts
            # to be added automatically in expand_group.
            elsif ($dst->{managed_hosts}) {
                next;
            }
            $service->{seen_unenforceable}->{$src}->{$dst} ||= [ $src, $dst ];
        }
    }
}

sub show_unenforceable {
    for my $key (sort keys %services) {
        my $service = $services{$key};
        my $context = $service->{name};

        if ($service->{has_unenforceable}
            and (not $service->{seen_unenforceable} or
                 not$service->{seen_enforceable}))
        {
            warn_msg("Useless attribute 'has_unenforceable' at $context");
        }
        $config->{check_unenforceable} or next;
        next if $service->{disabled};

        # Warning about fully unenforceable service can't be disabled with
        # attribute has_unenforceable.
        if (not delete $service->{seen_enforceable}) {

            # Don't warn on empty service without any expanded rules.
            if ($service->{seen_unenforceable} or
                $service->{silent_unenforceable})
            {
                warn_or_err_msg($config->{check_unenforceable},
                                "$context is fully unenforceable");
            }
            next;
        }
        next if $service->{has_unenforceable};

        if (my $src_hash = delete $service->{seen_unenforceable}) {
            my @list;
            for my $dst_hash (values %$src_hash) {
                for my $aref (values %$dst_hash) {
                    my ($src, $dst) = @$aref;
                    push @list, "src=$src->{name}; dst=$dst->{name}";
                }
            }
            warn_or_err_msg($config->{check_unenforceable},
                            join "\n ",
                            "$context has unenforceable rules:",
                            sort @list);
        }
        delete $service->{silent_unenforceable};
    }
}

sub warn_useless_unenforceable {
    for my $zone (@zones) {
        $zone->{has_unenforceable} or next;
        $zone->{seen_unenforceable} and next;
        my $zero_ip = get_zero_ip($zone->{ipv6});
        my $agg00 = $zone->{ipmask2aggregate}->{"$zero_ip$zero_ip"};
        my $name = $agg00 ? $agg00->{name} : $zone->{name};
        warn_msg("Useless attribute 'has_unenforceable' at $name");
    }
}

sub remove_unenforceable_rules {
    my ($rules) = @_;
    my $changed;
    for my $rule (@$rules) {
        my ($src_path, $dst_path) = @{$rule}{qw(src_path dst_path)};
        my $src_zone = $obj2zone{$src_path} || get_zone($src_path);
        my $dst_zone = $obj2zone{$dst_path} || get_zone($dst_path);
        if (zone_eq($src_zone, $dst_zone)) {
            collect_unenforceable($rule, $src_zone);
            $rule = undef;
            $changed = 1;
        }
        else {

            # At least one rule of service is enforceable.
            # This is used to decide, if a service is fully unenforceable.
            my $service = $rule->{rule}->{service};
            $service->{seen_enforceable} = 1;
        }
    }
    if ($changed) {
        $rules = [ grep { $_ } @$rules ];
    }
    return $rules;
}

########################################################################
# Convert normalized service rules to grouped path rules.
########################################################################

sub split_rules_by_path {
    my ($rules, $where) = @_;
    my $where_path = "${where}_path";
    my @new_rules;
    for my $rule (@$rules) {
        my $group = $rule->{$where};
        my $element0 = $group->[0];
        my $path0 = $obj2path{$element0} || get_path($element0);

        # Group has elements from different zones and must be split.
        if (grep { $path0 ne ($obj2path{$_} || get_path($_)) } @$group) {
            my (%seen, @path_list, %path2group);
            for my $element (@$group) {
                my $path = $obj2path{$element};
                $seen{$path}++ or push @path_list, $path;
                push @{ $path2group{$path}}, $element;
            }
            for my $path (@path_list) {
                my $path_group = $path2group{$path};
                my $new_rule = { %$rule,
                                 $where      => $path_group,
                                 $where_path => $path };
                push @new_rules, $new_rule;
            }
        }

        # Use unchanged group, add path info.
        else {
            $rule->{$where_path} = $path0;
            push @new_rules, $rule;
        }
    }
    return \@new_rules;
}

# Hash with attributes deny, permit for storing path rules with
# different action.
our %path_rules;

sub group_path_rules {
    progress("Grouping rules");
    my $count = 0;

    for my $action (qw(permit deny)) {
        my $rules = $service_rules{$action} or next;

        # Split grouped rules such, that all elements of src and dst
        # have identical src_path/dst_path.
        $rules = split_rules_by_path($rules, 'src');
        $rules = split_rules_by_path($rules, 'dst');
        $rules = remove_unenforceable_rules($rules);
        $path_rules{$action} = $rules;
        $count += @$rules;
    }
    info("Grouped rule count: $count");

    show_unenforceable();
    warn_useless_unenforceable();
}

sub remove_simple_duplicate_rules {
    progress("Removing simple duplicate rules");
    for my $action (qw(permit deny)) {
        my $rules = $path_rules{$action} or next;
        my %src2dst2prt2rule;
        my $count = 0;
      RULE:
        for my $rule (@$rules) {
            my $src = $rule->{src};
            @$src == 1 or next;
            my $dst = $rule->{dst};
            @$dst == 1 or next;
            my $prt = $rule->{prt};
            @$prt == 1 or next;
            for my $attr (qw(src_range log oneway stateless)) {
                next RULE if $rule->{$attr};
            }
            $src = $src->[0];
            $dst = $dst->[0];
            $prt = $prt->[0];
            if ($src2dst2prt2rule{$src}->{$dst}->{$prt}) {
                diag_msg("Removed duplicate ", print_rule($rule)) if SHOW_DIAG;
                $rule = undef;
                $count++;
            }
            else {
                $src2dst2prt2rule{$src}->{$dst}->{$prt} = $rule;
            }
        }
        if ($count) {
            $path_rules{$action} = [ grep { $_ } @$rules ];
        }
    }
}


########################################################################
# Expand rules and check them for redundancy
########################################################################

# Build rule tree from expanded rules for efficient comparison of rules.
# Rule tree is a nested hash for ordering all rules.
# Put attributes with small value set first, to get a more
# memory efficient tree with few branches at root.
sub build_rule_tree {
    my ($rules) = @_;
    my $count = 0;
    my $rule_tree;

    # Simpler version of rule tree. It is used for rules without attributes
    # {deny}, {stateless} and {src_range}.
    my $simple_tree;

    for my $rule (@$rules) {
        my ($stateless, $deny, $src, $dst, $src_range, $prt) =
            @{$rule}{qw(stateless deny src dst src_range prt)};
        my $leaf_hash;

        # General path.
        if ($deny or $stateless or $src_range) {
            $leaf_hash = $rule_tree->{$stateless || ''}
                                   ->{$deny      || ''}
                                   ->{$src_range || $prt_ip}
                                   ->{$src}->{$dst} ||= {};
        }

        # Fast path.
        else {
            $leaf_hash = $simple_tree->{$src}->{$dst} ||= {};
        }

        if (my $other_rule = $leaf_hash->{$prt}) {
            ($rule->{log} || '') eq ($other_rule->{log} || '') or
                err_msg("Duplicate rules must have identical log attribute:\n",
                        " ", print_rule($other_rule), "\n",
                        " ", print_rule($rule));

            # Found identical rule.
            collect_duplicate_rules($rule, $other_rule);
            $count++;
        }
        else {
#            debug("Add:", print_rule $rule);
            $leaf_hash->{$prt} = $rule;
        }
    }

    # Insert $simple_tree into $rule_tree.
    if ($simple_tree) {
        $rule_tree->{''}->{''}->{$prt_ip} = $simple_tree;
    }
    return($rule_tree, $count);
}

# Derive reduced {local_up} relation from {up} relation between protocols.
# Reduced relation has only protocols that are referenced in list of rules.
# New relation is used in find_redundant_rules.
# We get better performance compared to original relation, because
# transient chain from some protocol to largest protocol becomes shorter.
sub set_local_prt_relation {
    my ($rules) = @_;
    my %prt_hash;
    for my $rule (@$rules) {
        my $prt_list = $rule->{prt};
        @prt_hash{@$prt_list} = @$prt_list;
    }
    for my $prt (values %prt_hash) {
        my $local_up = undef;
        my $up = $prt->{up};
        while ($up) {
            if ($prt_hash{$up}) {
                $local_up = $up;
                last;
            }
            $up = $up->{up};
        }
        $prt->{local_up} = $local_up;
    }
}

sub set_ignore_fully_redundant {
    my ($rule) = @_;
    for my $obj ($rule->{src}, $rule->{dst}) {
        my $net = $obj->{network} || $obj;
        my $zone = $net->{zone};
        if ($zone->{has_fully_redundant}) {
            $rule->{ignore_fully_redundant}++ or
                $rule->{rule}->{service}->{ignore_fully_redundant}++;
            last;
        }
    }
}

my @duplicate_rules;

sub collect_duplicate_rules {
    my ($rule, $other) = @_;
    my $service  = $rule->{rule}->{service};
    set_ignore_fully_redundant($rule);

    # Mark duplicate rules in both services.

    # But count each rule only once. For duplicate rules, this can
    # only occur for rule $other, because all identical rules are
    # compared with $other. But we need to mark $rule as well, because
    # it must only be counted once, if it is both duplicate and
    # redundandant.
    $rule->{redundant}++;
    $service->{duplicate_count}++;
    my $oservice = $other->{rule}->{service};
    if (not $other->{redundant}++) {
        $oservice->{duplicate_count}++;
        set_ignore_fully_redundant($other);
    }

    # Link both services, so we later show only one of both service as
    # redundant.
    $service->{has_same_dupl}->{$oservice} = $oservice;
    $oservice->{has_same_dupl}->{$service} = $service;

    if (my $overlaps = $service->{overlaps}) {
        for my $overlap (@$overlaps) {
            if ($oservice eq $overlap) {
                $service->{overlaps_used}->{$overlap} = $overlap;
                return;
            }
        }
    }
    if (my $overlaps = $oservice->{overlaps}) {
        for my $overlap (@$overlaps) {
            if ($service eq $overlap) {
                $oservice->{overlaps_used}->{$overlap} = $overlap;
                return;
            }
        }
    }
    my $prt1 = get_orig_prt($rule);
    my $prt2 = get_orig_prt($other);
    return if $prt1->{modifiers}->{overlaps} and $prt2->{modifiers}->{overlaps};

    push @duplicate_rules, [ $rule, $other ];
}

sub show_duplicate_rules {
    @duplicate_rules or return;
    my %sname2oname2duplicate;
  RULE:
    for my $pair (@duplicate_rules) {
        my ($rule, $other) = @$pair;

        my $sname = $rule->{rule}->{service}->{name};
        my $oname = $other->{rule}->{service}->{name};
        push(@{ $sname2oname2duplicate{$sname}->{$oname} }, $rule);
    }
    @duplicate_rules = ();

    for my $sname (sort keys %sname2oname2duplicate) {
        my $hash = $sname2oname2duplicate{$sname};
        for my $oname (sort keys %$hash) {
            my $aref = $hash->{$oname};
            my $msg  = "Duplicate rules in $sname and $oname:\n  ";
            $msg .= join("\n  ", map { print_rule $_ } @$aref);
            warn_or_err_msg($config->{check_duplicate_rules}, $msg);
        }
    }
}

my @redundant_rules;

sub collect_redundant_rules {
    my ($rule, $other, $count_ref) = @_;
    my $service  = $rule->{rule}->{service};

    # Count each redundant rule only once.
    if (not $rule->{redundant}++) {
        $$count_ref++;
        $service->{redundant_count}++;
        set_ignore_fully_redundant($rule);
    }

    my $prt1 = get_orig_prt($rule);
    my $prt2 = get_orig_prt($other);
    return if $prt1->{modifiers}->{overlaps} and $prt2->{modifiers}->{overlaps};

    my $oservice = $other->{rule}->{service};
    if (my $overlaps = $service->{overlaps}) {
        for my $overlap (@$overlaps) {
            if ($oservice eq $overlap) {
                $service->{overlaps_used}->{$overlap} = $overlap;
                return;
            }
        }
    }
    push @redundant_rules, [ $rule, $other ];
}

sub show_redundant_rules {
    @redundant_rules or return;
    my %sname2oname2redundant;
    for my $pair (@redundant_rules) {
        my ($rule, $other) = @$pair;

        my $sname = $rule->{rule}->{service}->{name};
        my $oname = $other->{rule}->{service}->{name};
        push(@{ $sname2oname2redundant{$sname}->{$oname} }, [ $rule, $other ]);
    }

    # Free memory.
    @redundant_rules = ();

    my $action = $config->{check_redundant_rules} or return;
    for my $sname (sort keys %sname2oname2redundant) {
        my $hash = $sname2oname2redundant{$sname};
        for my $oname (sort keys %$hash) {
            my $aref = $hash->{$oname};
            my $msg  = "Redundant rules in $sname compared to $oname:\n  ";
            $msg .= join(
                "\n  ",
                map {
                    my ($r, $o) = @$_;
                    print_rule($r) . "\n< " . print_rule($o);
                } @$aref
                );
            warn_or_err_msg($action, $msg);
        }
    }
}

sub show_fully_redundant_rules {
    my $action = $config->{check_fully_redundant_rules} or return;
    my %keep;
    for my $key (sort keys %services) {
        my $service = $services{$key};
        next if $keep{$service};
        my $rule_count = $service->{rule_count} or next;
        if (my $ignore_fully_redundant = $service->{ignore_fully_redundant}) {
            next if $ignore_fully_redundant == $rule_count;
        }
        my $duplicates = $service->{duplicate_count} || 0;
        my $redundants = $service->{redundant_count} || 0;
        $duplicates + $redundants == $rule_count or next;
        if (my $has_same_dupl = delete $service->{has_same_dupl}) {
            $keep{$_} = 1 for values %$has_same_dupl;
        }
        warn_or_err_msg($action, "$service->{name} is fully redundant");
    }
}

sub warn_unused_overlaps {
    for my $key (sort keys %services) {
        my $service = $services{$key};
        next if $service->{disabled};
        if (my $overlaps = $service->{overlaps}) {
            my $used = delete $service->{overlaps_used};
            for my $overlap (@$overlaps) {
                next if $overlap->{disabled};
                $used->{$overlap}
                  or warn_msg("Useless 'overlaps = $overlap->{name}'",
                    " in $service->{name}");
            }
        }
    }
}

# Expand path_rules to elementary rules.
sub expand_rules {
    my ($rules) = @_;
    my @result;
    for my $rule (@$rules) {
        my $service  = $rule->{rule}->{service};
        my ($src_list, $dst_list, $prt_list) = @{$rule}{qw(src dst prt)};
        for my $src (@$src_list) {
            for my $dst (@$dst_list) {
                for my $prt (@$prt_list) {
                    push @result, { %$rule,
                                     src => $src,
                                     dst => $dst,
                                     prt => $prt };
                    $service->{rule_count}++;
                }
            }
        }
    }
    return \@result;
}

##############################################################################
# Find redundant rules which are overlapped by some more general rule
##############################################################################

# Hash for converting a reference of an object back to this object.
my %ref2obj;

sub setup_ref2obj {
    for my $network (@networks) {
        $ref2obj{$network} = $network;
        for my $obj (@{ $network->{subnets} }, @{ $network->{interfaces} }) {
            $ref2obj{$obj} = $obj;
        }
    }
}

sub find_redundant_rules {
 my ($cmp_hash, $chg_hash) = @_;
 my $count = 0;
 for my $stateless (keys %$chg_hash) {
  my $chg_hash = $chg_hash->{$stateless};
  while (1) {
   if (my $cmp_hash = $cmp_hash->{$stateless}) {
    for my $deny (keys %$chg_hash) {
     my $chg_hash = $chg_hash->{$deny};
     while (1) {
      if (my $cmp_hash = $cmp_hash->{$deny}) {
       for my $src_range_ref (keys %$chg_hash) {
        my $chg_hash = $chg_hash->{$src_range_ref};
        my $src_range = $ref2prt{$src_range_ref};
        while (1) {
         if (my $cmp_hash = $cmp_hash->{$src_range}) {
          for my $src_ref (keys %$chg_hash) {
           my $chg_hash = $chg_hash->{$src_ref};
           my $src = $ref2obj{$src_ref};
           while (1) {
            if (my $cmp_hash = $cmp_hash->{$src}) {
             for my $dst_ref (keys %$chg_hash) {
              my $chg_hash = $chg_hash->{$dst_ref};
              my $dst = $ref2obj{$dst_ref};
              while (1) {
               if (my $cmp_hash = $cmp_hash->{$dst}) {
                for my $chg_rule (values %$chg_hash) {
                 my $prt = $chg_rule->{prt};
                 while (1) {
                  if (my $cmp_rule = $cmp_hash->{$prt}) {
                   if ($cmp_rule ne $chg_rule and
                       ($cmp_rule->{log} || '') eq ($chg_rule->{log} || ''))
                   {
                    collect_redundant_rules($chg_rule, $cmp_rule, \$count);
                   }
                  }
                  $prt = $prt->{local_up} or last;
                 }
                }
               }
               $dst = $dst->{up} or last;
              }
             }
            }
            $src = $src->{up} or last;
           }
          }
         }
         $src_range = $src_range->{up} or last;
        }
       }
      }
      last if $deny;
      $deny = 1;
     }
    }
   }
   $stateless or last;
   $stateless = '';
  }
 }
 return $count;
}

sub check_expanded_rules {
    progress('Checking for redundant rules');
    setup_ref2obj();
    my $count  = 0;
    my $dcount = 0;
    my $rcount = 0;

    # Process rules in chunks to reduce memory usage.
    # Rules with different src_path / dst_path can't be
    # redundant to each other.
    # Keep deterministic order of rules.
    my $index = 1;
    my %path2index;
    my %key2rules;
    for my $rule (@{ $path_rules{deny} }, @{ $path_rules{permit} }) {
        my $path = $rule->{src_path};
        my $key  = $path2index{$path} ||= $index++;
        push @{ $key2rules{$key} }, $rule;
    }

    for my $key (sort numerically keys %key2rules) {
        my $rules = $key2rules{$key};
        my $index = 1;
        my %path2index;
        my %key2rules;
        for my $rule (@$rules) {
            my $path = $rule->{dst_path};
            my $key  = $path2index{$path} ||= $index++;
            push @{ $key2rules{$key} }, $rule;
        }
        for my $key (sort numerically keys %key2rules) {
            my $rules = $key2rules{$key};

            my $expanded_rules = expand_rules($rules);
            $count += @$expanded_rules;
            my ($rule_tree, $deleted) = build_rule_tree($expanded_rules);
            $dcount += $deleted;
            set_local_prt_relation($rules);
            $rcount += find_redundant_rules($rule_tree, $rule_tree);
        }
    }
    show_duplicate_rules();
    show_redundant_rules();
    warn_unused_overlaps();
    show_fully_redundant_rules();
    info("Expanded rule count: $count; duplicate: $dcount; redundant: $rcount");
}

##############################################################################
# Find IP of each device, reachable from policy distribution point.
##############################################################################

# For each device, find the IP address which is used
# to manage the device from a central policy distribution point (PDP).
# This address is added as a comment line to each generated code file.
# This is to be used later when approving the generated code file.
sub set_policy_distribution_ip {
    progress('Setting policy distribution IP');

    my $need_all = $config->{check_policy_distribution_point};
    my @pdp_routers;
    my %seen;
    my @missing;
    for my $router (@managed_routers, @routing_only_routers) {
        if ($router->{policy_distribution_point}) {
            push @pdp_routers, $router;
            next;
        }
        $need_all or next;
        next if $seen{$router};
        next if $router->{orig_router};
        if (my $ipv_members = $router->{ipv_members}) {
            if (not grep { $_->{policy_distribution_point} } @$ipv_members) {
                push(@missing, {
                    name =>
                        "at least one instance of router:$router->{device_name}"
                     }
                    );
            }
            $seen{$_} = 1 for @$ipv_members;
        }
        else {
            push @missing, $router;
        }
    }
    if (my $count = @missing) {
        warn_or_err_msg($need_all,
                        "Missing attribute 'policy_distribution_point'",
                        " for $count devices:\n",
                        name_list(\@missing));
    }
    @pdp_routers or return;

    # Find all TCP ranges which include port 22 and 23.
    my @admin_tcp_keys = grep({
            my ($p1, $p2) = split(':', $_);
            $p1 <= 22 and 22 <= $p2 or $p1 <= 23 and 23 <= $p2;
        }
        keys %{ $prt_hash{tcp} });
    my @prt_list = (@{ $prt_hash{tcp} }{@admin_tcp_keys}, $prt_hash{ip});
    my %is_admin_prt = map { $_ => 1 } @prt_list;

    # Mapping from policy distribution host to subnets, networks and
    # aggregates that include this host.
    my %host2is_pdp_src;
    my $get_pdp_src = sub {
        my ($host) = @_;
        my $is_pdp_src;
        if ($is_pdp_src = $host2is_pdp_src{$host}) {
            return $is_pdp_src;
        }
        for my $pdp (map { $_ } @{ $host->{subnets} }) {
            while ($pdp) {
                $is_pdp_src->{$pdp} = 1;
                $pdp = $pdp->{up};
            }
        }
        return $host2is_pdp_src{$host} = $is_pdp_src;
    };
    my %router2found_interfaces;
    for my $rule (@{ $path_rules{permit} }) {
        my $dst_path = $rule->{dst_path};
        next if is_zone($dst_path);
        my $router = $dst_path->{router} || $dst_path;
        my $pdp = $router->{policy_distribution_point} or next;
        grep { $is_admin_prt{$_} } @{ $rule->{prt} } or next;
        my $is_pdp_src = $get_pdp_src->($pdp);
        grep { $is_pdp_src->{$_} } @{ $rule->{src} } or next;
        my $dst_list = $rule->{dst};
        @{$router2found_interfaces{$router}}{@$dst_list} = @$dst_list;
    }
    for my $router (@pdp_routers) {
        my $pdp = $router->{policy_distribution_point};
        my $found_interfaces = $router2found_interfaces{$router};
        my @result;

        # Ready, if exactly one management interface was found.
        if (keys %$found_interfaces == 1) {
            @result = values %$found_interfaces;
        }
        else {

#           debug("$router->{name}: ", scalar keys %$found_interfaces);
            my @front = path_auto_interfaces($router, $pdp);

            # If multiple management interfaces were found, take that which is
            # directed to policy_distribution_point.
            for my $front (@front) {
                if ($found_interfaces->{$front}) {
                    push @result, $front;
                }
            }

            # Take all management interfaces.
            # Preserve original order of router interfaces.
            if (not @result) {
                @result =
                  grep { $found_interfaces->{$_} } @{ $router->{interfaces} };
            }

            # Don't set {admin_ip} if no address is found.
            # Warning is printed below.
            next if not @result;
        }

        # Lookup interface address in NAT domain of PDP, because PDP
        # needs to access the device.
        # Prefer loopback interface if available.
        my $no_nat_set = $pdp->{network}->{nat_domain}->{no_nat_set};
        $router->{admin_ip} = [
            map { print_ip((address($_, $no_nat_set))->[0]) }
            sort { ($b->{loopback} || '') cmp($a->{loopback} || '') } @result
        ];
    }
    my @unreachable =
        grep { !$_->{admin_ip} && !$_->{orig_router} } @pdp_routers;
    if (my $count = @unreachable) {
        warn_msg("Missing rules to reach $count devices from",
                 " policy_distribution_point:\n",
                 name_list(\@unreachable)
        );
    }
}

##############################################################################
=head2 Distribute Network Address Translation Info

NetSPoC can deal with Network Address Translation (NAT) to translate
or hide Network addresses in parts of the topology.

NAT is defined by adding a NAT definition to the network or host
definition of the element that is to be translated or hidden. To
determine topology parts where NAT definitions are effective, NAT tags
referring to a nat definition are bound to interfaces within the
topology. This NAT binding activates NAT for every topology element
behind the interface as seen from router, so NAT is effective in
network direction of NAT binding.

The NAT binding separates the topology into a part in front of the
binding (as seen from the element with NAT defined) where the elements
original address is valid and a part behind the binding, where NAT is
effective. It is possible and sometimes neccessary to apply more than
one NAT binding: Additional NAT bindings can be used to delimit the
topology part where NAT is active, and for topologies with loops,
several NAT bindings can be required to obtain clear separation into
NAT active and inactive parts.

To keep track of which NAT tags are active in which part of the
topology, NetSpoC divides the topology into NAT domains. A NAT domain
is a maximal area of the topology (a set of connected networks) where
a common set of NAT tags (NAT set) is effective at every network.

=cut

my @natdomains;

#############################################################################
# Returns: Hash containing nat_tags declared to be non hidden at least
#          once as keys.
sub generate_lookup_hash_for_non_hidden_nat_tags {
    my %has_non_hidden;
    for my $network (@networks) {
        my $nat_hash = $network->{nat} or next;
        for my $nat_tag (keys %$nat_hash) {
            my $nat_network = $nat_hash->{$nat_tag};
            if (not $nat_network->{hidden}) {
                $has_non_hidden{$nat_tag} = 1;
             }
        }
    }
    return \%has_non_hidden;
}

# Mark invalid NAT transitions.
# A transition from nat:t1 to nat:t2 occurs at an interface I
# - if nat:t1 was active previously
# - and nat:t2 is activated at I with "bind_nat = t2".
# This transition is invalid
# - if a network:n1 exists having NAT definitions for both t1 and t2
# - and some other network:n2 exists having a NAT definition for t1,
#   but not for t2.
sub mark_invalid_nat_transitions {
    my ($nat_tag2multinat_def) = @_;
    my %result;
    for my $nat_hashes (values %$nat_tag2multinat_def) {
        next if @$nat_hashes == 1;
        my %union;
        for my $nat_hash (@$nat_hashes) {
            @union{keys %$nat_hash} = values %$nat_hash;
        }
        my $count = keys %union;
        for my $nat_hash (@$nat_hashes) {
            next if keys %$nat_hash == $count;
            my @missing = grep { not $nat_hash->{$_} } keys %union;
            for my $tag1 (keys %$nat_hash) {
                my $nat_network = $nat_hash->{$tag1};
                my $hash = $result{$tag1} ||= {};
                for my $tag2 (@missing) {
                    $hash->{$tag2} = $nat_network;
                }
            }
        }
    }
    return \%result;
}

##############################################################################
# Returns   : $nat_tag2multinat_def: Hash with NAT tags occurring in multi
#                 NAT definitions (several NAT definitions grouped at one
#                 network) as keys and arrays of NAT hashes containing the
#                 key NAT tag as values.
#             $nat_definitions: Lookup hash with all NAT tags that are
#                 defined somewhere as keys. It is used to check, if all
#                 NAT definitions are bound and if all bound NAT tags are
#                 defined somewhere.
# Comments: Also checks consistency of multi NAT tags at one network. If
#           non hidden NAT tags are grouped at one network, the same NAT
#           tags must be used as group in all other occurrences to avoid
#           ambiguities: Suppose tags A and B are both defined at network n1,
#           but only A is defined at network n2. An occurence of
#           bind_nat = A activates NAT:A. A successive bind_nat = B activates
#           NAT:B, but implicitly disables NAT:A, as for n1 only one NAT can be
#           active at a time. As NAT:A can not be active (n2) and inactive
#           (n1) in the same NAT domain, this restriction is needed.
sub generate_multinat_def_lookup {
    my ($has_non_hidden) = @_;
    my %nat_tag2multinat_def;
    my %nat_definitions;

    for my $network (@networks) {
        my $nat_hash = $network->{nat} or next;
#        debug $network->{name}, " nat=", join(',', sort keys %$nat_hash);

      NAT_TAG:
        for my $nat_tag (sort keys %$nat_hash) {
            $nat_definitions{$nat_tag} = 1;
            if (my $previous_nat_hashes = $nat_tag2multinat_def{$nat_tag}) {

                # Do not add same group twice.
                if ($has_non_hidden->{$nat_tag}) {
                    for my $nat_hash2 (@$previous_nat_hashes) {
                        next NAT_TAG if keys_eq($nat_hash, $nat_hash2);
                    }
                }

                # Check for subset relation. Keep superset only.
                else {
                    for my $nat_hash2 (@$previous_nat_hashes) {
                        my $common_keys =
                            grep { $nat_hash2->{$_} } keys %$nat_hash;
                        if ($common_keys eq keys %$nat_hash) {

                            # Ignore new nat_hash, because it is subset.
                            next NAT_TAG;
                        }
                        elsif ($common_keys eq keys %$nat_hash2) {

                            # Replace previous nat_hash by new superset.
                            $nat_hash2 = $nat_hash;
                            next NAT_TAG;
                        }
                    }

                }
            }
            push @{ $nat_tag2multinat_def{$nat_tag} }, $nat_hash;
        }
    }

    # Remove entry if nat tag never occurs in multi nat definitions (grouped).
    for my $nat_tag (keys %nat_tag2multinat_def) {
        my $nat_hashes = $nat_tag2multinat_def{$nat_tag};
        next if @$nat_hashes > 1;
        my $nat_hash = $nat_hashes->[0];
        next if keys %$nat_hash > 1;
        delete $nat_tag2multinat_def{$nat_tag};
    }

    return \%nat_tag2multinat_def, \%nat_definitions;
}

##############################################################################
# Purpose:    Perform depth first search to collect networks and limiting
#             routers of given NAT-domain.
# Parameters: $network: Network to be added to domain.
#             $domain: Domain information is collected for.
#             $in_interface: Interface $network was entered at.
# Results   : $domain contains references to its networks and limiting routers,
#             $routers that are domain limiting contain references to the
#             limited domains and store NAT tags bound to domains border
#             interfaces.
sub set_natdomain {
    my ($network, $domain, $in_interface) = @_;

    # Network was processed by a former call from find_nat_domains
    # or loop found inside a NAT domain.
    return if $network->{nat_domain};
#    debug("$domain->{name}: $network->{name}");

    $network->{nat_domain} = $domain;
    push @{ $domain->{networks} }, $network;

    # Find adjacent networks to proceed with.
    for my $interface (@{ $network->{interfaces} }) {

        # Ignore interface where we reached this network.
        next if $interface eq $in_interface;
        next if $interface->{main_interface};

#        debug("IN $interface->{name}");
        my $nat_tags = $interface->{bind_nat} || $bind_nat0;
        my $router = $interface->{router};

        my $useless_nat_binding = 1;
        my $interfaces = $router->{interfaces};
        for my $out_interface (@$interfaces) {

            # Don't process interface where we reached this router.
            next if $out_interface eq $interface;
            next if $out_interface->{main_interface};
#            debug("OUT $out_interface->{name}");

            # Current NAT domain continues behind $out_interface
            my $out_nat_tags = $out_interface->{bind_nat} || $bind_nat0;
            if (aref_eq($out_nat_tags, $nat_tags)) {

                # Prevent deep recursion inside a single NAT domain.
                next if $router->{active_path};
                local $router->{active_path} = 1;

                my $next_net = $out_interface->{network};
                set_natdomain($next_net, $domain, $out_interface);
            }

            # Another NAT domain starts at current router behind $out_interface.
            else {
                $useless_nat_binding = undef;

                # Loop found: $router is already marked to limit $domain.
                # Perform consistency check.
                if (my $other = $router->{nat_tags}->{$domain}) {
                    next if aref_eq($nat_tags, $other);
                    my $names1 = join(',', @$nat_tags) || '(none)';
                    my $names2 = join(',', @$other)    || '(none)';
                    next if $router->{nat_err_seen}->{"$names1 $names2"}++;
                    err_msg("Inconsistent NAT in loop at $router->{name}:\n",
                            " nat:$names1 vs. nat:$names2");
                }

                # Mark router as domain limiting, add router as domain border.
                else {
                    $router->{nat_tags}->{$domain} = $nat_tags;
                    push @{ $domain->{routers} },     $router;
                    push @{ $router->{nat_domains} }, $domain;
                }
            }
        }

        # Routers with same NAT tag at every interface may occur with VPN.
        if ($useless_nat_binding and @$nat_tags and
            grep { not $_->{hub} and not $_->{spoke} } @$interfaces)
        {
            my $list = join ',', map { "nat:$_" } @$nat_tags;
            warn_msg("Ignoring $list without effect, bound at",
                     " every interface of $router->{name}");
        }
    }
}

##############################################################################
# Purpose : Divide topology into NAT domains.
# Results : For every NAT domain a hash object exists. All NAT domain hashes
#           are hold within global @natdomains array. Networks and NAT domain
#           limiting routers keep references to their domains.
sub find_nat_domains {
    for my $network (@networks) {
        next if $network->{is_aggregate};
        next if $network->{nat_domain};
        (my $name = $network->{name}) =~ s/^\w+:/nat_domain:/;
        my $domain = new(
            'nat_domain',
            name     => $name,
            networks => [],
            routers  => [],
            nat_set  => {},
        );
        push @natdomains, $domain;
        set_natdomain($network, $domain, 0);
    }
}

#############################################################################
# Purpose:   For networks with multiple NAT definitions, only one NAT
#            definition can be active in a domain. Generate error otherwise.
# Parameter: $nat_tag2multinat_def: Lookup hash for elements with more
#                than one NAT tag specified.
#            $nat_set: Hash containing NAT tags already collected for domain.
#            $nat_tag: NAT tag to be added to domains NAT set.
#            $domain: Actual domain.
sub check_for_multinat_errors {
    my($nat_tag2multinat_def, $nat_set, $nat_tag, $domain) = @_;
    if (my $multinat_hashes = $nat_tag2multinat_def->{$nat_tag}) {
        for my $multinat_hash (@$multinat_hashes) {
            for my $nat_tag2 (sort keys %$multinat_hash) {
                if ($nat_set->{$nat_tag2}) {
                    err_msg(
                        "Grouped NAT tags '$nat_tag2' and '$nat_tag'",
                        " must not both be active inside $domain->{name}"
                    );
                }
            }
        }
    }
}

#############################################################################
# Purpose:   Network which has translation with tag $nat_tag must not be located
#            in domain where this tag is active.
# Parameter: $domain: Actual domain.
#            $nat_tag: NAT tag that is distributed during domain traversal.
#            $router: Router domain was entered at during domain traversal.
sub check_nat_network_location {
    my ($domain, $nat_tag, $router) = @_;
    for my $network (@{ $domain->{networks} }) {
        my $nat = $network->{nat} or next;
        $nat->{$nat_tag} or next;
        err_msg(
            "$network->{name} is translated by $nat_tag,\n",
            " but is located inside the translation domain of $nat_tag.\n",
            " Probably $nat_tag was bound to wrong interface",
            " at $router->{name}."
        );

        # Show error message only once.
        last;
    }
}

##############################################################################
# Purpose:   Generate errors if NAT tags are applied multiple times in a row.
# Parameter: $domain: Actual domain.
#            $in_router: Router domain was entered at during domain traversal.
#            $router: Router domain is left at during domain traversal.
#            $nat_tag: NAT tag that is distributed during domain traversal.
# Returns:   1, if NAT tag is applied twice on a loop path, undef otherwise.
sub check_for_proper_NAT_binding {
    my ($domain, $in_router, $router, $nat_tag) = @_;
    for my $out_domain (@{ $router->{nat_domains} }) {
        next if $out_domain eq $domain;

        # NAT tag occurs more than once in a row.
        my $out_nat_tags = $router->{nat_tags}->{$out_domain};
        if (grep { $_ eq $nat_tag } @$out_nat_tags) {

            # NAT is applied twice on loop path.
            if ($router->{active_path}) {
                return 1;
            }
            # NAT is applied twice on linear path.
            err_msg(
                "nat:$nat_tag is applied twice between",
                " $in_router->{name} and $router->{name}"
                );
        }
    }
}

##############################################################################
# Purpose:   Show errors for invalid transitions of grouped NAT tags.
# Parameter: $nat_tag: NAT tag that is distributed during domain traversal.
#            $nat_tag2: NAT tag that implicitly deactivates $nat_tag.
#            $nat_hash: NAT hash of network with both $nat_tag and $nat_tag2
#            defined.
#            $invalid_nat_transitions: Hash with pairs of NAT tags t1, t2
#                where transition from t1 to t2 is invalid.
#            $router - router where NAT transition occurs at.
sub check_for_proper_nat_transition {
    my ($nat_tag, $nat_tag2, $nat_hash, $invalid_nat_transitions, $router) = @_;
    my $nat_info  = $nat_hash->{$nat_tag};
    my $next_info = $nat_hash->{$nat_tag2};

    # Transition from hidden NAT to any other NAT is invalid.
    if ($nat_info->{hidden}) {

        # Use $next_info->{name} and not $nat_info->{name} because
        # $nat_info may show wrong network, because we combined
        # different hidden networks into $nat_tag2multinat_def.
        err_msg("Must not change hidden nat:$nat_tag",
                " using nat:$nat_tag2\n",
                " for $next_info->{name} at $router->{name}");
    }

    # Transition from dynamic to static NAT is invalid.
    elsif ($nat_info->{dynamic} and
           not $next_info->{dynamic})
    {
        err_msg("Must not change dynamic nat:$nat_tag",
                " to static using nat:$nat_tag2\n",
                " for $nat_info->{name} at $router->{name}");
    }

    # Transition from $nat_tag to $nat_tag2 is invalid,
    # if $nat_tag occurs somewhere not grouped with $nat_tag2.
    elsif (my $network = $invalid_nat_transitions->{$nat_tag}->{$nat_tag2}) {
        err_msg("Invalid transition from nat:$nat_tag to nat:$nat_tag2",
                " at $router->{name}.\n",
                " Reason:",
                " Both NAT tags are used grouped at $nat_info->{name}\n",
                " but nat:$nat_tag2 is missing at $network->{name}"
            );
    }
}

##############################################################################
# Purpose:    Performs a depth first search to distribute specified NAT tag
#             to reachable domains where NAT tag is active; checks whether
#             NAT declarations are applied correctly.
# Parameters: $domain: Domain the depth first search proceeds from.
#             $nat_tag: NAT tag that is to be distributed.
#             $nat_tag2multinat_def: Lookup hash for elements with more than
#                 one NAT tag specified.
#             $invalid_nat_transitions: Hash with pairs of NAT tags as keys,
#                 where transition from first to second tag is invalid.
#             $in_router: Router $domain was entered from.
# Results:    All domains, where NAT tag is active contain $nat_tag in their
#             {nat_set} attribute.
# Returns:    undef on success, array reference of routers, if invalid
#             path was found in loop.
sub distribute_nat1 {
    my ($domain, $nat_tag,
        $nat_tag2multinat_def, $invalid_nat_transitions,
        $in_router) = @_;
#    debug "nat:$nat_tag at $domain->{name} from $in_router->{name}";

    # Loop found or domain was processed by earlier call of distribute_nat.
    my $nat_set = $domain->{nat_set};
    return if $nat_set->{$nat_tag};

    # Perform checks before $nat_tag is added.
    check_for_multinat_errors($nat_tag2multinat_def, $nat_set,
                              $nat_tag, $domain);
    check_nat_network_location($domain, $nat_tag, $in_router);
    $nat_set->{$nat_tag} = 1;

    # Activate loop detection.
    local $in_router->{active_path} = 1;

    # Find adjacent domains with active $nat_tag to proceed traversal.
    for my $router (@{ $domain->{routers} }) {
        next if $router eq $in_router;

        # $nat_tag is deactivated at routers domain facing interface.
        my $in_nat_tags = $router->{nat_tags}->{$domain};
        next if grep { $_ eq $nat_tag } @$in_nat_tags;

        my $loop_error = check_for_proper_NAT_binding($domain, $in_router,
                                                     $router, $nat_tag);
        # Wrong NAT binding on loop path:
        # Abort traversal and start collecting error path.
        $loop_error and return [$router];

      DOMAIN:
        # Check whether $nat_tag is active in adjacent NAT domains.
        for my $out_domain (@{ $router->{nat_domains} }) {
             next if $out_domain eq $domain;

             # $nat_tag is implicitly deactivated by activation of another NAT
             # tag occuring with $nat_tag in a multinat definition
             my $out_nat_tags = $router->{nat_tags}->{$out_domain};
             if (my $multinat_hashes = $nat_tag2multinat_def->{$nat_tag}) {
                 for my $nat_tag2 (@$out_nat_tags) {
#                     debug "- $nat_tag2";
                     next if $nat_tag2 eq $nat_tag;
                     for my $nat_hash (@$multinat_hashes) {
                         if ($nat_hash->{$nat_tag2}) {
                             check_for_proper_nat_transition(
                                 $nat_tag, $nat_tag2,
                                 $nat_hash, $invalid_nat_transitions,
                                 $router);
                             next DOMAIN;
                         }
                     }
                 }
             }

             # $nat_tag is active within adjacent domain: proceed traversal
#            debug "Caller $domain->{name}";
            if (
                my $err_path = distribute_nat1(
                    $out_domain, $nat_tag,
                    $nat_tag2multinat_def, $invalid_nat_transitions,
                    $router
                )
              )
            {
                push @$err_path, $router;
                return $err_path;
            }
        }
    }
}

##############################################################################
# Purpose:    Calls distribute_nat1 to distribute specified NAT tag
#             to reachable domains where NAT tag is active. Generate
#             error message, if called function returns an error loop path.
# Parameters: $domain: Domain the depth first search starts at.
#             $nat_tag: NAT tag that is to be distributed.
#             $nat_tag2multinat_def: Lookup hash for elements with more
#                 than one NAT tag specified.
#             $invalid_nat_transitions: Hash with pairs of NAT tags as keys,
#                 where transition from first to second tag is invalid.
#             $in_router: router the depth first search starts at.
sub distribute_nat {
    my ($domain, $nat_tag,
        $nat_tag2multinat_def, $invalid_nat_transitions,
        $in_router) = @_;
    if (my $err_path =
        distribute_nat1(
            $domain, $nat_tag,
            $nat_tag2multinat_def, $invalid_nat_transitions,
            $in_router))
    {
        push @$err_path, $in_router;
        err_msg("nat:$nat_tag is applied recursively in loop at this path:\n",
            " - ", join("\n - ", map { $_->{name} } reverse @$err_path));
    }
}

##############################################################################
# Purpose: Distribute NAT tags to the domains they are active in.
#          Check every NAT tag is both bound and defined somewhere.
#          Assure unambiguous NAT for networks with multi NAT definitions.
sub distribute_nat_tags_to_nat_domains {
    my ($nat_tag2multinat_def, $nat_definitions) = @_;
    my $invalid_nat_transitions =
        mark_invalid_nat_transitions($nat_tag2multinat_def);
    for my $domain (@natdomains) {
        for my $router (@{ $domain->{routers} }) {
            my $nat_tags = $router->{nat_tags}->{$domain};
#            debug "$domain->{name} $router->{name}: ", join(',', @$nat_tags);

            # Assure every bound NAT is defined somewhere.
            for my $nat_tag (@$nat_tags) {
                if ($nat_definitions->{$nat_tag}) {
                    $nat_definitions->{$nat_tag} = 'used';
                }
                else {
                    warn_msg(
                        "Ignoring useless nat:$nat_tag",
                        " bound at $router->{name}"
                    );
                }
            }

          NAT_TAG:
            for my $nat_tag (@$nat_tags) {

                # Multiple tags are bound to interface.
                # If some network has multiple matching NAT tags,
                # the resulting NAT mapping would be ambiguous.
                if (@$nat_tags >= 2 and
                    (my $multinat_hashes = $nat_tag2multinat_def->{$nat_tag}))
                {
                    for my $multinat_hash (@$multinat_hashes) {
                        my @tags = grep { $multinat_hash->{$_} } @$nat_tags;
                        @tags >= 2 or next;
                        my $tags = join(',', @tags);
                        my $nat_net = $multinat_hash->{ $tags[0] };
                        err_msg(
                            "Must not bind multiple NAT tags '$tags'",
                            " of $nat_net->{name} at $router->{name}"
                        );

                        # Show only first error. Process only first
                        # valid NAT tag to prevent inherited errors.
                        last NAT_TAG;
                    }
                }
                distribute_nat($domain, $nat_tag,
                               $nat_tag2multinat_def,
                               $invalid_nat_transitions,
                               $router);
            }
        }
    }

    # Assure every defined NAT bound somewhere.
    for my $name (keys %$nat_definitions) {
        $nat_definitions->{$name} eq 'used'
          or warn_msg("nat:$name is defined, but not bound to any interface");
    }

}

#############################################################################
# Purpose: Check compatibility of host/interface and network NAT.
# Comment: A NAT definition for a single host/interface is only allowed,
#          if network has a dynamic NAT definition.
sub check_nat_compatibility {
    for my $network (@networks) {
        for my $obj (@{ $network->{hosts} }, @{ $network->{interfaces} }) {
            my $nat = $obj->{nat} or next;
            for my $nat_tag (sort keys %$nat) {
                my $nat_network = $network->{nat}->{$nat_tag};
                if ($nat_network and $nat_network->{dynamic}) {
                    my $obj_ip = $nat->{$nat_tag};
                    my ($ip, $mask) = @{$nat_network}{qw(ip mask)};
                    match_ip($obj_ip, $ip, $mask) or
                        err_msg("nat:$nat_tag: IP of $obj->{name} doesn't",
                                " match IP/mask of $network->{name}");
                }
                else {
                    warn_msg("Ignoring nat:$nat_tag at $obj->{name}",
                             " because $network->{name} has static",
                             " NAT definition");
                }
            }
        }
    }
}

#############################################################################
# Purpose: Find interfaces with dynamic NAT which is bound at the same
#          device. This is invalid for device with "need_protect".
# Comment: "need_protect" devices use NetSPoC generated ACLs to manage access
#          to their interfaces. To ensure safety, the devices interfaces
#          need to have a fixed address.
sub check_interfaces_with_dynamic_nat {
    for my $network (@networks) {
        my $nat = $network->{nat} or next;
        for my $nat_tag (sort keys %$nat) {
            my $nat_info = $nat->{$nat_tag};
            $nat_info->{dynamic} or next;
            next if $nat_info->{identity} or $nat_info->{hidden};
            for my $interface (@{ $network->{interfaces} }) {
                my $intf_nat = $interface->{nat};

                # Interface has static translation,
                next if $intf_nat and $intf_nat->{$nat_tag};

                my $router = $interface->{router};
                $router->{need_protect} or next;
                for my $bind_intf (@{ $router->{interfaces} }) {
                    my $bind = $bind_intf->{bind_nat} or next;
                    grep { $_ eq $nat_tag } @$bind or next;
                    err_msg(
                        "Must not apply dynamic nat:$nat_tag",
                        " to $interface->{name}",
                        " at $bind_intf->{name} of same device.\n",
                        " This isn't supported for model",
                        " $router->{model}->{name}."
                    );
                }
            }
        }
    }
}

#############################################################################
# Returns: $partitions: Lookup hash with domains as keys and partition ID
#              as values.
# Comment: NAT partitions arise, if parts of the topology are strictly
#          separated by crypto interfaces.
sub find_nat_partitions {
    my %partitions;
    my $mark_nat_partition = sub {
        my ($domain, $mark) = @_;
        return if $partitions{$domain};

#        debug "$mark $domain->{name}";
        $partitions{$domain} = $mark;
        for my $router (@{ $domain->{routers} }) {
            for my $out_domain (@{ $router->{nat_domains} }) {
                next if $out_domain eq $domain;
                __SUB__->($out_domain, $mark);
            }
        }
    };
    my $mark = 0;
    for my $domain (@natdomains) {
        $mark++;
        $mark_nat_partition->($domain, $mark);
    }
    return \%partitions;
}
#############################################################################
# Returns:   $partition2tags: Lookup hash storing for every partition ID
#                the NAT tags used within the partition.
# Parameter: $partitions: Lookup hash with domains as keys and partition ID
#                as values.
# Comment:   NAT tags only used in one partition must not be included in other
#            partitions no_nat_set.
sub map_partitions_to_NAT_tags {
    my ($partitions) = @_;
    my %partition2tags;
    for my $domain (@natdomains) {
        my $mark = $partitions->{$domain};
        for my $network (@{ $domain->{networks} }) {
            my $nat_hash = $network->{nat} or next;
            for my $nat_tag (keys %$nat_hash) {
                $partition2tags{$mark}->{$nat_tag} = 1;
            }
        }
    }
    return \%partition2tags;
}

#############################################################################
# Result  : Instead of active NAT tags, all inactive NAT tags are available
#           within every NAT domain.
# Comment : In practice, NAT tags have shown to be active more often than
#           inactive. Storing the set of inactive NAT tags significantly
#           reduces memory requirements.
sub invert_nat_sets {
    my $partitions = find_nat_partitions;
    my $partition2tags = map_partitions_to_NAT_tags($partitions);

    # Invert {nat_set} to {no_nat_set}
    for my $domain (@natdomains) {
        my $nat_set     = delete $domain->{nat_set};
        my $mark        = $partitions->{$domain};
        my $all_nat_set = $partition2tags->{$mark} ||= {};

#        debug "$mark $domain->{name} all: ", join(',', keys %$all_nat_set);
        my $no_nat_set = {%$all_nat_set};
        delete @{$no_nat_set}{ keys %$nat_set };
        $domain->{no_nat_set} = $no_nat_set;

#        debug "$mark $domain->{name} no: ", join(',', keys %$no_nat_set);
    }
}

#############################################################################
# Result : {no_nat_set} is stored at logical and hardware interfaces of
#          managed and semi managed routers.
# Comment: Neccessary at semi_managed routers to calculate {up} relation
#          between subnets.
sub distribute_no_nat_sets_to_interfaces {
    for my $domain (@natdomains) {
        my $no_nat_set = $domain->{no_nat_set};
        for my $network (@{ $domain->{networks} }) {
            for my $interface (@{ $network->{interfaces} }) {
                my $router = $interface->{router};
                $router->{managed} or $router->{semi_managed} or next;

#               debug("$domain->{name}: NAT $interface->{name}");
                $interface->{no_nat_set} = $no_nat_set;
                if (($router->{managed} or $router->{routing_only})
                    and
                    $interface->{ip} ne 'tunnel')
                {
                    $interface->{hardware}->{no_nat_set} = $no_nat_set
                }
            }
        }
    }
}

# Combine different no-nat-sets into a single no-nat-set in a way
# that NAT mapping remains identical.
# Different real NAT tags of a multi NAT set can't be combined.
# In this case either an error is shown or NAT is disabled
# for this multi NAT set.
# Hidden NAT tag is ignored if combined with a real NAT tag,
# because hidden tag doesn't affect address calculation.
#
# Parameter $context controls, if error is shown or if NAT is disabled..
sub combine_no_nat_sets {
    my ($no_nat_sets, $context, $nat_tag2multinat_def, $has_non_hidden) = @_;
    return $no_nat_sets->[0] if @$no_nat_sets == 1;
    my %combined;
    my %multi2active;
    my %multi2hidden;
    my %multi2multi;
    my $errors;
    for my $set (@$no_nat_sets) {
        for my $nat_tag (keys %$set) {
            my $multinat_hashes = $nat_tag2multinat_def->{$nat_tag};

            # Add non multi NAT tag.
            if (not $multinat_hashes) {
                $combined{$nat_tag} = 1;
                next;
            }

            for my $multinat_hash (@$multinat_hashes) {
                $multi2multi{$multinat_hash} = $multinat_hash;
                my ($active) = grep { not $set->{$_} } keys %$multinat_hash;

                # Original address is shown.
                if (not $active) {
                    $multi2active{$multinat_hash} = ':all';
                    next;
                }

                # Check if the same NAT mapping is active in all NAT domains.
                my $non_hidden = $has_non_hidden->{$active};
                my $hash = $non_hidden ? \%multi2active : \%multi2hidden;
                if (my $other = $hash->{$multinat_hash}) {
                    if ($other ne $active) {
                        if ($context and $non_hidden) {
                            if ($other eq ':all') {
                                push(@$errors,
                                     "Original address and NAT tag '$active'");
                            }
                            else {
                                push(@$errors,
                                     "Grouped NAT tags '$other' and '$active'");
                            }
                        }
                        else {
                            $hash->{$multinat_hash} = ':all';
                        }
                    }
                }
                else {
                    $hash->{$multinat_hash} = $active;
                }
            }
        }
    }

    # Add multi NAT tags.
    # Activate single tag (by leaving it out) if this tag was active in all
    # NAT domains.
    # Hidden is only set, if no non-hidden tag was found.
    # Deactivate all tags otherwise.
    for my $multinat_hash (values %multi2multi) {
        my $active_or_all =
            $multi2active{$multinat_hash} || $multi2hidden{$multinat_hash} || '';
        for my $nat_tag (keys %$multinat_hash) {
            next if $nat_tag eq $active_or_all;
            $combined{$nat_tag} = 1;
        }
    }
    if ($errors) {
        err_msg "$_\n would both be active at $context" for unique @$errors;
    }
    return \%combined;
}

# Real interface of crypto tunnel has got {no_nat_set} of that NAT domain,
# where encrypted traffic passes. But real interface gets ACL that filter
# both encrypted and unencrypted traffic. Hence a new {crypto_no_nat_set}
# is created by combining no_nat_set of real interface and some
# corresponding tunnel.
# (All tunnels are known to have identical no_nat_set.)
sub add_crypto_no_nat_set {
    my ($nat_tag2multinat_def, $has_non_hidden) = @_;
    my %seen;
    for my $crypto (values %crypto) {
        for my $tunnel (@{ $crypto->{tunnels} }) {
            next if $tunnel->{disabled};
            for my $tunnel_intf (@{ $tunnel->{interfaces} }) {
                my $real_intf = $tunnel_intf->{real_interface};
                next if $seen{$real_intf}++;
                $real_intf->{router}->{managed} or next;
                my $real_set = $real_intf->{no_nat_set};
                my $tunnel_set = $tunnel_intf->{no_nat_set};

                # Take no_nat_set of tunnel and add tags from real
                # interface.
                $real_intf->{hardware}->{crypto_no_nat_set} =
                    combine_no_nat_sets(
                        [$tunnel_set, $real_set],
                        "$real_intf->{name}\n" .
                        " for combined crypto and cleartext traffic",
                        $nat_tag2multinat_def, $has_non_hidden);
            }
        }
    }
}

#############################################################################
# Purpose : Determine NAT domains and generate inverted NAT set (no_nat_set)
#           for every NAT domain.
sub distribute_nat_info {
    progress('Distributing NAT');
    find_nat_domains();
    my $has_non_hidden = generate_lookup_hash_for_non_hidden_nat_tags();
    my ($nat_tag2multinat_def, $nat_definitions)
        = generate_multinat_def_lookup($has_non_hidden);
    distribute_nat_tags_to_nat_domains($nat_tag2multinat_def, $nat_definitions);
    check_nat_compatibility();
    check_interfaces_with_dynamic_nat();
    invert_nat_sets();
    distribute_no_nat_sets_to_interfaces();
    add_crypto_no_nat_set($nat_tag2multinat_def, $has_non_hidden);
    prepare_real_ip_nat_routers($nat_tag2multinat_def, $has_non_hidden);

    return($nat_tag2multinat_def, $has_non_hidden);
}

sub get_nat_network {
    my ($network, $no_nat_set) = @_;
    if (my $href = $network->{nat} and $no_nat_set) {
        for my $tag (keys %$href) {
            next if $no_nat_set->{$tag};
            return $href->{$tag};
        }
    }
    return $network;
}

####################################################################
# Find sub-networks
# Mark each network with the smallest network enclosing it.
####################################################################

# All interfaces and hosts of a network must be located in that part
# of the network which doesn't overlap with some subnet.
sub check_subnets {
    my ($network, $subnet) = @_;
    return if $network->{is_aggregate} or $subnet->{is_aggregate};
    my ($sub_ip, $sub_mask) = @{$subnet}{qw(ip mask)};
    my $check = sub {
        my ($ip1, $ip2, $object) = @_;
        if (match_ip($ip1, $sub_ip, $sub_mask)
            or $ip2 and (match_ip($ip2, $sub_ip, $sub_mask)
                         or $ip1 le $sub_ip and $sub_ip le $ip2)
          )
        {

            # NAT to an interface address (masquerading) is allowed.
            if (    (my $nat_tags = $object->{bind_nat})
                and (my $nat_tag2 = $subnet->{nat_tag}))
            {
                if (    grep { $_ eq $nat_tag2 } @$nat_tags
                    and $object->{ip} eq $subnet->{ip}
                    and is_host_mask($subnet->{mask}))
                {
                    return;
                }
            }
            warn_msg("IP of $object->{name} overlaps with subnet",
                     " $subnet->{name}");
        }
    };
    for my $interface (@{ $network->{interfaces} }) {
        my $ip = $interface->{ip};
        next if $ip =~ /^(?:unnumbered|negotiated|tunnel|short|bridged)$/;
        $check->($ip, undef, $interface);
    }
    for my $host (@{ $network->{hosts} }) {
        if (my $ip = $host->{ip}) {
            $check->($ip, undef, $host);
        }
        elsif (my $range = $host->{range}) {
            $check->($range->[0], $range->[1], $host);
        }
    }
}

# Dynamic NAT to loopback interface is OK,
# if NAT is applied at device of loopback interface.
sub nat_to_loopback_ok {
    my ($loopback_network, $nat_network) = @_;

    my $nat_tag1      = $nat_network->{nat_tag};
    my $device_count  = 0;
    my $all_device_ok = 0;

    # In case of virtual loopback, the loopback network
    # is attached to two or more routers.
    # Loop over these devices.
    for my $loop_intf (@{ $loopback_network->{interfaces} }) {
        $device_count++;
        my $this_device_ok = 0;

        # Check all interfaces of attached device.
        for my $all_intf (@{ $loop_intf->{router}->{interfaces} }) {
            if (my $nat_tags = $all_intf->{bind_nat}) {
                if (grep { $_ eq $nat_tag1 } @$nat_tags) {
                    $this_device_ok = 1;
                    last;
                }
            }
        }
        $all_device_ok += $this_device_ok;
    }
    return ($all_device_ok == $device_count);
}

# Find subnet relation between networks inside a zone.
# - $subnet->{up} = $bignet;
sub find_subnets_in_zone {
    progress('Finding subnets in zone');
    for my $zone (@zones) {

        # Check NAT inside zone.
        # Find networks of zone which use a NATed address inside the zone.
        # - Use this NATed address in subnet checks.
        # - If a subnet relation exists, then this NAT must be unique inside
        #   the zone.

        my $first_intf = $zone->{interfaces}->[0];
        my %seen;

        # Handle different no_nat_sets visible at border of zone.
        # For a zone without NAT, this loop is executed only once.
        for my $interface (@{ $zone->{interfaces} }) {
            my $no_nat_set = $interface->{no_nat_set};

#            debug $interface->{name};
            next if $seen{$no_nat_set}++;

            # Add networks of zone to %mask_ip_hash.
            # Use NAT IP/mask.
            my %mask_ip_hash;

            for my $network (@{ $zone->{networks} },
                values %{ $zone->{ipmask2aggregate} })
            {
                my $nat_network = $network;
                if (my $href = $network->{nat}) {
                    for my $tag (keys %$href) {
                        next if $no_nat_set->{$tag};
                        $nat_network = $href->{$tag};
                        last;
                    }
                }

                if ($nat_network->{hidden}) {
                    my $other = $network->{up} or next;
                    next if get_nat_network($other, $no_nat_set)->{hidden};
                    err_msg(
                        "Ambiguous subnet relation from NAT.\n",
                        " $network->{name} is subnet of\n",
                        " - $other->{name} at",
                        " $first_intf->{name}\n",
                        " - but it is hidden by nat:$nat_network->{nat_tag} at",
                        " $interface->{name}"
                    );
                    next;
                }
                my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };

                # Found two different networks with identical IP/mask.
                if (my $other_net = $mask_ip_hash{$mask}->{$ip}) {
                    my $name1 = $network->{name};
                    my $name2 = $other_net->{name};
                    err_msg("$name1 and $name2 have identical IP/mask",
                        " at $interface->{name}");
                }
                else {

                    # Store original network under NAT IP/mask.
                    $mask_ip_hash{$mask}->{$ip} = $network;
                }
            }

            # Compare networks of zone.
            # Go from smaller to larger networks.
            my @mask_list = reverse sort keys %mask_ip_hash;
            while (my $mask = shift @mask_list) {

                # No supernets available
                last if not @mask_list;

                my $ip_hash = $mask_ip_hash{$mask};
              SUBNET:
                for my $ip (sort keys %$ip_hash) {

                    my $subnet = $ip_hash->{$ip};

                    # Find networks which include current subnet.
                    # @mask_list holds masks of potential supernets.
                    for my $m (@mask_list) {

                        my $i = $ip & $m;
                        my $bignet = $mask_ip_hash{$m}->{$i} or next;

                        # Collect subnet relation for first no_nat_set.
                        if ($interface eq $first_intf) {
                            $subnet->{up} = $bignet;

#                           debug "$subnet->{name} -up-> $bignet->{name}";

                            push(
                                @{ $bignet->{networks} },
                                  $subnet->{is_aggregate}
                                ? @{ $subnet->{networks} || [] }
                                : ($subnet)
                            );

                            check_subnets($bignet, $subnet);
                        }

                        # Check for ambiguous subnet relation with
                        # other no_nat_sets.
                        else {
                            if (my $other = $subnet->{up}) {
                                if ($other ne $bignet) {
                                    err_msg(
                                        "Ambiguous subnet relation from NAT.\n",
                                        " $subnet->{name} is subnet of\n",
                                        " - $other->{name} at",
                                        " $first_intf->{name}\n",
                                        " - $bignet->{name} at",
                                        " $interface->{name}"
                                    );
                                }
                            }
                            else {
                                err_msg(
                                    "Ambiguous subnet relation from NAT.\n",
                                    " $subnet->{name} is subnet of\n",
                                    " - $bignet->{name} at",
                                    " $interface->{name}\n",
                                    " - but has no subnet relation at",
                                    " $first_intf->{name}"
                                );
                            }
                        }

                        # We only need to find the smallest enclosing
                        # network.
                        next SUBNET;
                    }
                    if ($interface ne $first_intf) {
                        if (my $other = $subnet->{up}) {
                            err_msg(
                                "Ambiguous subnet relation from NAT.\n",
                                " $subnet->{name} is subnet of\n",
                                " - $other->{name} at",
                                " $first_intf->{name}\n",
                                " - but has no subnet relation at",
                                " $interface->{name}"
                            );
                        }
                    }
                }
            }
        }

        # For each subnet N find the largest non-aggregate network
        # which encloses N. If one exists, store it in %max_up_net.
        # This is used to exclude subnets from $zone->{networks} below.
        # It is also used to derive attribute {max_routing_net}.
        my %max_up_net;
        my $set_max_net = sub {
            my ($network) = @_;
            return if not $network;
            if (my $max_net = $max_up_net{$network}) {
                return $max_net;
            }
            if (my $max_net = __SUB__->($network->{up})) {
                if (not $network->{is_aggregate}) {
                    $max_up_net{$network} = $max_net;

#                    debug("$network->{name} max_up $max_net->{name}");
                }
                return $max_net;
            }
            if ($network->{is_aggregate}) {
                return;
            }
            return $network;
        };
        $set_max_net->($_) for @{ $zone->{networks} };

        # For each subnet N find the largest non-aggregate network
        # inside the same zone which encloses N.
        # If one exists, store it in {max_routing_net}. This is used
        # for generating static routes.
        # We later check, that subnet relation remains stable even if
        # NAT is applied.
        for my $network (@{ $zone->{networks} }) {
            $max_up_net{$network} or next;

#            debug "Check $network->{name}";
            my $max_routing;
            my $up = $network->{up};
          UP:
            while ($up) {

                # If larger network is hidden at some place, only use
                # it for routing, if original network is hidden there
                # as well.
                # We don't need to check here that subnet relation is
                # maintained for NAT addresses.
                # That is enforced below in find_subnets_in_nat_domain.
                if (my $up_nat_hash = $up->{nat}) {
                    for my $up_nat_info (values %$up_nat_hash) {
                        $up_nat_info->{hidden} or next;
                        my $nat_hash = $network->{nat} or last UP;
                        my $nat_tag = $up_nat_info->{nat_tag};
                        my $nat_info = $nat_hash->{$nat_tag} or last UP;
                        $nat_info->{hidden} or last UP;
                    }
                }
                if (not $up->{is_aggregate}) {
                    $max_routing = $up;
                }
                $up = $up->{up};
            }
            if ($max_routing) {
                $network->{max_routing_net} = $max_routing;

#                debug "Found $max_routing->{name}";
            }
        }

        # Remove subnets of non-aggregate networks.
        $zone->{networks} =
          [ grep { not $max_up_net{$_} } @{ $zone->{networks} } ];

        # Propagate managed hosts to aggregates.
        for my $aggregate (values %{ $zone->{ipmask2aggregate} }) {
            add_managed_hosts_to_aggregate($aggregate);
        }
    }

    # It is valid to have an aggregate in a zone which has no matching
    # networks. This can be useful to add optimization rules at an
    # intermediate device.
}

# Find subnet relation between networks in different NAT domains.
# Mark networks, having subnet in other zone: $bignet->{has_other_subnet}
# 1. If set, this prevents secondary optimization.
# 2. If rule has src or dst with attribute {has_other_subnet},
#    it is later checked for missing supernets.
sub find_subnets_in_nat_domain {
    my $count = @natdomains;
    progress("Finding subnets in $count NAT domains");

    # List of all networks and NAT networks having an IP address.
    # We need this in deterministic order.
    my @nat_networks;

    # Mapping from NAT network to original network.
    my %orig_net;

    for my $network (@networks) {
        next if $network->{ip} =~ /^(?:unnumbered|tunnel)$/;
        push @nat_networks, $network;
        $orig_net{$network} = $network;
        my $nat = $network->{nat} or next;
        for my $nat_network (values %$nat) {
            next if $nat_network->{hidden};
            $orig_net{$nat_network} = $network;
            push @nat_networks, $nat_network;
        }
    }

    # 1. step:
    # Compare IP/mask of all networks and NAT networks and find relations
    # %is_in and %identical.

    # Mapping Mask -> IP -> Network|NAT Network.
    my %mask_ip_hash;

    # Mapping from network|NAT network to list of elements with
    # identical IP address.
    my %identical;
    for my $nat_network (@nat_networks) {
        my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };
        if (my $other = $mask_ip_hash{$mask}->{$ip}) {

            # Bild lists of identical networks.
            push @{ $identical{$other} ||= [$other] }, $nat_network;
        }
        else {
            $mask_ip_hash{$mask}->{$ip} = $nat_network;
        }
    }

    # Calculate %is_in relation from IP addresses;
    # This includes all addresses of all networks in all NAT domains.
    # Go from smaller to larger networks.
    # Process IPv4 and IPv6 addresses separately.
    my %is_in;
    my @mixed_mask_list = reverse sort keys %mask_ip_hash;
    for my $ip_len (4, 16) {
        my @mask_list = grep { length($_) == $ip_len } @mixed_mask_list;
        while (my $mask = shift @mask_list) {

            # No supernets available
            last if not @mask_list;

            my $ip_hash = $mask_ip_hash{$mask};
            for my $ip (sort keys %$ip_hash) {
                my $subnet = $ip_hash->{$ip};

                # @mask_list holds masks of potential supernets.
                for my $m (@mask_list) {
                    my $i      = $ip & $m;
                    my $bignet = $mask_ip_hash{$m}->{$i} or next;
                    $is_in{$subnet} = $bignet;
                    last;
                }
            }
        }
    }

    # 2. step:
    # Analyze %is_in and %identical relation for different NAT domains.

    # Mapping from subnet to bignet in same zone.
    # Bignet must be marked, if subnet is marked later with {has_other_subnet}.
    my %pending_other_subnet;
    my $mark_network_and_pending = sub {
        my ($network) = @_;
        return if $network->{has_other_subnet};
        $network->{has_other_subnet} = 1;
        my $list = delete $pending_other_subnet{$network} or return;
        __SUB__->($_) for @$list;
    };
    my %subnet_in_zone;
    my %seen;
    for my $domain (@natdomains) {

        # Ignore NAT domain consisting only of a single unnumbered network and
        # surrounded by unmanaged devices.
        # An address conflict would not be observable inside this NAT domain.
        my $domain_networks = $domain->{networks};
        if (1 == @$domain_networks) {
            my $network = $domain_networks->[0];
            if ($network->{ip} eq 'unnumbered') {
                my $interfaces = $network->{interfaces};
                if (not grep { $_->{router}->{managed} } @$interfaces) {
                    next;
                }
            }
        }

        my $no_nat_set = $domain->{no_nat_set};

        # Mark networks visible in current NAT domain.
        my %visible;
      NETWORK:
        for my $nat_network (@nat_networks) {

            # NAT network
            if (my $tag = $nat_network->{nat_tag}) {
                next NETWORK if $no_nat_set->{$tag};
            }

            # Original network having NAT definitions.
            elsif (my $href = $nat_network->{nat}) {
                for my $tag (keys %$href) {
                    next if $no_nat_set->{$tag};
                    next NETWORK;
                }
            }
            $visible{$nat_network} = 1;
        }

        # Mark and analyze networks having identical IP/mask in
        # current NAT domain.
        my %has_identical;
        for my $list (values %identical) {
            my @filtered = grep { $visible{$_} } @$list;
            @filtered > 1 or next;
            $has_identical{$_} = 1 for @filtered;

            # If $list has been fully analyzed once, don't check it again.
            next if $seen{$list};
            if (@filtered == @$list) {
                $seen{$list} = 1;
            }

            # Compare pairs of networks with identical IP/mask.
            my $nat_other = $filtered[0];
            my $other = $orig_net{$nat_other};
            for my $nat_network (@filtered[1 .. $#filtered]) {
                my $network = $orig_net{$nat_network};
                my $error;
                if ($other->{is_aggregate} or $network->{is_aggregate}) {
                    if ($other->{zone} eq $network->{zone}) {
                        $error = 1;
                    }
                    else {

                        # Check supernet rules and prevent secondary
                        # optimization, if identical IP address
                        # occurrs in different zones.
                        $other->{has_other_subnet} = 1;
                        $network->{has_other_subnet} = 1;
                    }
                }
                elsif ($nat_other->{dynamic} and $nat_network->{dynamic}) {

                    # Dynamic NAT of different networks
                    # to a single new IP/mask is OK.
                }
                elsif ($other->{loopback} and $nat_network->{dynamic}) {
                    nat_to_loopback_ok($other, $nat_network) or $error = 1;
                }
                elsif ($nat_other->{dynamic} and $network->{loopback}) {
                    nat_to_loopback_ok($network, $nat_other) or $error = 1;
                }
                elsif (($network->{bridged} || 0) eq ($other->{bridged} || 1))
                {

                    # Parts of bridged network have identical IP by design.
                }
                else {
                    $error = 1;
                }
                if ($error) {
                    my $name1 = $nat_network->{descr} || $nat_network->{name};
                    my $name2 = $nat_other->{descr} || $nat_other->{name};
                    err_msg("$name1 and $name2 have identical IP/mask\n",
                            " in $domain->{name}");
                }
            }
        }

        # Check pairs of networks, that are in subnet relation.
      SUBNET:
        for my $nat_subnet (@nat_networks) {
            my $nat_bignet = $is_in{$nat_subnet} or next;

            # If invisible, search other networks with identical IP.
            my $nat_subnet = $nat_subnet;	# Prevent aliasing.
            if (not $visible{$nat_subnet}) {
                my $identical = $identical{$nat_subnet} or next;
                if ((my $ident_net) = grep { $visible{$_} } @$identical) {
                    $nat_subnet = $ident_net;
                }
                else {
                    next;
                }
            }

            # If invisible, search other networks with identical or larger IP.
            while (not $visible{$nat_bignet}) {
                if (my $identical = $identical{$nat_bignet}) {
                    if ((my $ident_net) = grep { $visible{$_} } @$identical) {
                        $nat_bignet = $ident_net;
                        last;
                    }
                }
                $nat_bignet = $is_in{$nat_bignet} or next SUBNET;
            }
            my $subnet = $orig_net{$nat_subnet};

            # Collect subnet/supernet pairs in same zone for later check.
            {
                my $id_subnets;
                if (my $identical = $identical{$nat_subnet}) {
                    $id_subnets = [ map { $orig_net{$_} }
                                    grep { $visible{$_} } @$identical ];
                }
                else {
                    $id_subnets = [ $subnet ];
                }
                for my $subnet (@$id_subnets) {
                    my $zone = $subnet->{zone};
                    my $nat_bignet = $nat_bignet;
                    while(1) {
                        my $bignet = $orig_net{$nat_bignet};
                        if ($visible{$nat_bignet} and $bignet->{zone} eq $zone) {
                            $subnet_in_zone{$subnet}->{$bignet}->{$domain} = 1;
                            last;
                        }
                        $nat_bignet = $is_in{$nat_bignet} or last;
                    }
                }
            }

            next if $seen{$nat_bignet}->{$nat_subnet}++;
            my $bignet = $orig_net{$nat_bignet};

            # Mark network having subnet in same zone, if subnet has
            # subsubnet in other zone.
            # Remember subnet relation in same zone in %pending_other_subnet,
            # if current status of subnet is not known,
            # since status may change later.
            if ($bignet->{zone} eq $subnet->{zone}) {
                if ($subnet->{has_other_subnet} or $has_identical{$subnet}) {
                    $bignet->{has_other_subnet} = 1;
                }
                else {
                    push @{ $pending_other_subnet{$subnet} }, $bignet;
                }
            }

            # Mark network having subnet in other zone.
            else {
                $mark_network_and_pending->($bignet);

                # Mark aggregate that has other *supernet*.
                # In this situation, addresses of aggregate
                # are part of supernet and located in another
                # zone.
                if ($subnet->{is_aggregate}) {
                    $mark_network_and_pending->($subnet);
                }
            }


            if (my $print_type = $config->{check_subnets}) {

                # Take original $bignet, because currently
                # there's no method to specify a natted network
                # as value of subnet_of.
                if (
                    not(   $bignet->{is_aggregate}
                           or $subnet->{is_aggregate}
                           or $bignet->{has_subnets}
                           or $nat_subnet->{subnet_of}
                           and $nat_subnet->{subnet_of} eq $bignet
                           or $nat_subnet->{is_layer3})
                    )
                {

                    # Prevent multiple error messages in
                    # different NAT domains.
                    $nat_subnet->{subnet_of} ||= $bignet;

                    my $name1 = $nat_subnet->{descr} || $nat_subnet->{name};
                    my $name2 = $nat_bignet->{descr} || $nat_bignet->{name};
                    warn_or_err_msg(
                        $print_type,
                        "$name1 is subnet of $name2\n",
                        " in $domain->{name}.\n",
                        " If desired, either declare attribute",
                        " 'subnet_of' or attribute 'has_subnets'");
                }
            }

            check_subnets($nat_bignet, $nat_subnet);
        }
    }

    # Check networks in same zone for stable subnet relation over all
    # NAT domains. If networks are in relation at one NAT domain, they
    # must also be in relation in all other domains.
    my %net2dom2hidden;
    for my $network (@networks) {
        my $nat_hash = $network->{nat} or next;
        my @hidden_tags = grep { $nat_hash->{$_}->{hidden} } keys %$nat_hash
            or next;
        for my $domain (@natdomains) {
            my $no_nat_set = $domain->{no_nat_set};
            if (grep { not $no_nat_set->{$_} } @hidden_tags) {
                $net2dom2hidden{$network}->{$domain} = 1;
            }
        }
    }

    for my $subref (keys %subnet_in_zone) {
        my $net2dom2is_subnet = $subnet_in_zone{$subref};
        my $sub_dom2hidden = $net2dom2hidden{$subref};
        for my $bigref (keys %$net2dom2is_subnet) {
            my $dom2is_subnet = $net2dom2is_subnet->{$bigref};
            my $big_dom2hidden = $net2dom2hidden{$bigref};

            # Subnet is subnet of bignet in at least one NAT domain.
            # Check that in each NAT domain
            # - subnet relation holds or
            # - at least one of both networks is hidden.
          DOMAIN:
            for my $domain (@natdomains) {

                # Ok, is subnet in current NAT domain.
                next if $dom2is_subnet->{$domain};

                # If one or both networks are hidden, this does
                # not count as changed subnet relation.
                next if $big_dom2hidden and $big_dom2hidden->{$domain};
                next if $sub_dom2hidden and $sub_dom2hidden->{$domain};

                my $subnet = $orig_net{$subref};
                my $bignet = $orig_net{$bigref};

                # Ignore relation, if both are aggregates,
                # because IP addresses of aggregates can't be changed by NAT.
                next if $subnet->{is_aggregate} and $bignet->{is_aggregate};

                # Also check transient subnet relation.
                my $up = $subnet;
                while (my $up2 = $up->{up}) {
                    $subnet_in_zone{$up}->{$up2}->{$domain} or last;
                    next DOMAIN if $up2 eq $bigref;
                    $up = $up2;
                }

                # Identical IP from dynamic NAT is valid as subnet relation.
                my $no_nat_set = $domain->{no_nat_set};
                my $nat_subnet = get_nat_network($subnet, $no_nat_set);
                if ($nat_subnet->{dynamic}) {
                    my $nat_bignet = get_nat_network($bignet, $no_nat_set);
                    if ($nat_bignet->{dynamic} and
                        $nat_subnet->{ip} eq $nat_bignet->{ip} and
                        $nat_subnet->{mask} eq $nat_bignet->{mask})
                    {
                        next;
                    }
                }

                # Found NAT domain, where networks are not in subnet relation.
                # Remember at attribute {unstable_nat} for later check.
                push @{ $bignet->{unstable_nat}->{$no_nat_set}}, $subnet;
            }
        }
    }

    # Secondary optimization substitutes a host or interface by its
    # largest valid supernet inside the same security zone. This
    # supernet has already been calculated and stored in
    # {max_routing_net}. But {max_routing_net} can't be used if it has
    # a subnet in some other security zone. In this case we have to
    # search again for a supernet without attribute {has_other_subnet}.
    # The result is stored in {max_secondary_net}.
    for my $network (@networks) {
        my $max = $network->{max_routing_net} or next;

        # Disable {max_routing_net} if it has unstable NAT relation with
        # current subnet.
        # This test is only a rough estimation and should be refined
        # if to many valid optimizations would be disabled.
        if ($max->{unstable_nat} and $network->{nat}) {
            delete $network->{max_routing_net};
            next;
        }
        if (not $max->{has_other_subnet}) {
            $network->{max_secondary_net} = $max;
            next;
        }
        my $max_secondary;
        my $up = $network->{up};
        while ($up) {
            if ($up->{has_other_subnet}) {
                last;
            }
            else {
                if (not $up->{is_aggregate}) {
                    $max_secondary = $up;
                }
                $up = $up->{up};
            }
        }
        $network->{max_secondary_net} = $max_secondary if $max_secondary;
    }
}

# If routers are connected by crosslink network then
# no filter is needed if both have equal strength.
# If routers have different strength,
# then only the weakest devices omit the filter.
my %crosslink_strength = (
    primary         => 10,
    full            => 10,
    standard        => 9,
    secondary       => 8,
    local           => 7,
);
##############################################################################
# Purpose   : Find clusters of routers connected directly or indirectly by
#             crosslink networks and having at least one device with
#             "need_protect".
# Parameter : Hash reference storing crosslinked routers with {need_protect}
#             flag set.
sub cluster_crosslink_routers {
    my ($crosslink_routers) = @_;
    my %cluster;
    my %seen;

    # Add routers to cluster via depth first search.
    my $walk = sub {
        my ($router) = @_;
        $cluster{$router} = $router;
        $seen{$router}    = $router;
        for my $in_intf (@{ $router->{interfaces} }) {
            my $network = $in_intf->{network};
            next if not $network->{crosslink};
            next if $network->{disabled};
            for my $out_intf (@{ $network->{interfaces} }) {
                next if $out_intf eq $in_intf;
                my $router2 = $out_intf->{router};
                next if $cluster{$router2};
                __SUB__->($router2);
            }
        }
    };

    # Process all need_protect crosslinked routers.
    for my $router (values %$crosslink_routers) {
        next if $seen{$router};

        # Fill router cluster
        %cluster = ();
        $walk->($router);

        # Collect all interfaces belonging to need_protect routers of cluster...
        my @crosslink_interfaces =
          map  { @{ $_->{interfaces} } }
          grep { $crosslink_routers->{$_} }
          sort by_name values %cluster;    # Sort to make output deterministic.

        # ... add information to every cluster member as list
        # used in print_acls.
        for my $router2 (values %cluster) {
            $router2->{crosslink_interfaces} = \@crosslink_interfaces;
        }
    }
}

##############################################################################
# A crosslink network combines two or more routers to one virtual router.
# Purpose  : Assures proper usage of crosslink networks and applies the
#            crosslink attribute to the networks weakest interfaces (no
#            filtering needed at these interfaces).
# Returns  : Hash storing crosslinked routers with {need_protect} flag set.
# Comments : Function uses hardware attributes from sub check_no_in_acl.
sub check_crosslink {
    my %crosslink_routers;    # Collect crosslinked routers with {need_protect}

    # Process all crosslink networks
    for my $network (values %networks) {
        next if not $network->{crosslink};
        next if $network->{disabled};

        # Prepare tests.
        my %strength2intf;    # To identify interfaces with min router strength
        my $out_acl_count = 0;    # Assure out_ACL at all/none of the interfaces
        my @no_in_acl_intf;   # Assure all no_in_acl IFs to border the same zone

        # Process network interfaces to fill above variables.
        for my $interface (@{ $network->{interfaces} }) {
            next if $interface->{main_interface};
            my $router   = $interface->{router};
            my $hardware = $interface->{hardware};

            # Assure correct usage of crosslink network.
            if (not $router->{managed}) {
                err_msg(
                    "Crosslink $network->{name} must not be",
                    " connected to unmanged $router->{name}"
                );
                next;
            }
            1 == grep({ not $_->{main_interface} } @{ $hardware->{interfaces} })
              or err_msg("Crosslink $network->{name} must be the only network\n",
                         " connected to $hardware->{name} of $router->{name}");

            # Fill variables.
            my $managed  = $router->{managed};
            my $strength = $crosslink_strength{$managed};
            push @{ $strength2intf{$strength} }, $interface;

            if ($router->{need_protect}) {
                $crosslink_routers{$router} = $router;
            }

            if ($hardware->{need_out_acl}) {
                $out_acl_count++;
            }

            push @no_in_acl_intf,
              grep({ $_->{hardware}->{no_in_acl} } @{ $router->{interfaces} });
        }

        # Apply attribute {crosslink} to the networks weakest interfaces.
        if (my ($weakest) = sort numerically keys %strength2intf) {
            for my $interface (@{ $strength2intf{$weakest} }) {
                $interface->{hardware}->{crosslink} = 1;
            }

            # Assure 'secondary' and 'local' are not mixed in crosslink network.
            if (    $weakest == $crosslink_strength{local}
                and $strength2intf{ $crosslink_strength{secondary} })
            {
                err_msg(
                    "Must not use 'managed=local' and 'managed=secondary'",
                    " together\n at crosslink $network->{name}"
                );
            }
        }

        # Assure proper usage of crosslink network.
        not $out_acl_count
          or $out_acl_count == @{ $network->{interfaces} }
          or err_msg "All interfaces must equally use or not use outgoing ACLs",
          " at crosslink $network->{name}";
        equal(map { $_->{zone} } @no_in_acl_intf)
          or err_msg "All interfaces with attribute 'no_in_acl'",
          " at routers connected by\n crosslink $network->{name}",
          " must be border of the same security zone";
    }
    return \%crosslink_routers;
}

# Used
# - for crypto_rules,
# - rules from general_permit,
# - for default route optimization,
# - while generating chains of iptables and
# - in local optimization.
my $network_00 = new(
    'Network',
    name             => "network:0/0",
    ip               => get_zero_ip(),
    mask             => get_zero_ip(),
    is_aggregate     => 1,
    has_other_subnet => 1,
    );

my $network_00_v6 = new(
    'Network',
    name             => "network:0/0",
    ip               => get_zero_ip(1),
    mask             => get_zero_ip(1),
    is_aggregate     => 1,
    has_other_subnet => 1,
    );

sub get_network_00 {
    my ($ipv6) = @_;
    if ($ipv6) {
        return $network_00_v6;
    }
    else {
        return $network_00;
    }
}

# Find cluster of zones connected by 'local' routers.
# - Check consistency of attributes.
# - Set unique 'local_mark' for all managed routers
#   belonging to one cluster.
# Returns array of cluster infos, a hash with attributes
# - no_nat_set
# - filter_only
# - mark
sub get_managed_local_clusters {
    my $local_mark = 1;
    my @result;
    my %seen;
    for my $router0 (@managed_routers) {
        $router0->{managed} eq 'local' or next;
        next if $router0->{local_mark};
        my $filter_only = $router0->{filter_only};

        # Key from list of filter_only addresses.
        my $k0;

        # IP/mask pairs of current cluster matching {filter_only}.
        my %matched;

        my $info = { mark => $local_mark, filter_only => $filter_only };
        my $no_nat_set;

        my $walk = sub {
            my ($router) = @_;
            $router->{local_mark} = $local_mark;
            if ($filter_only ne $router->{filter_only}) {

                # All routers of a cluster must have same values in
                # {filter_only}.
                $k0 ||=
                    join(',',
                         map({ join('/', @$_) } @{ $router0->{filter_only} }));
                my $k =
                    join(',',
                         map({ join('/', @$_) } @{ $router->{filter_only} }));
                $k eq $k0
                  or err_msg(
                    "$router0->{name} and $router->{name}",
                    " must have identical values in",
                    " attribute 'filter_only'"
                  );
            }

            for my $in_intf (@{ $router->{interfaces} }) {

                # no_nat_set is known to be identical inside 'local' cluster,
                # because attribute 'bind_nat' is not valid at 'local' routers.
                $no_nat_set ||= $in_intf->{no_nat_set};
                $info->{no_nat_set} ||= $no_nat_set;
                my $zone0        = $in_intf->{zone};
                my $zone_cluster = $zone0->{zone_cluster};
                for my $zone ($zone_cluster ? @$zone_cluster : ($zone0)) {
                    next if $seen{$zone}++;

                    # All networks in local zone must match {filter_only}.
                  NETWORK:
                    for my $network (@{ $zone->{networks} }) {
                        my ($ip, $mask) = @{ address($network, $no_nat_set) };
                        for my $pair (@$filter_only) {
                            my ($i, $m) = @$pair;
                            if ($mask ge $m and match_ip($ip, $i, $m)) {
                                $matched{"$i$m"} = 1;
                                next NETWORK;
                            }
                        }
                        err_msg(
                            "$network->{name} doesn't match attribute",
                            " 'filter_only' of $router->{name}"
                        );
                    }

                    for my $out_intf (@{ $zone->{interfaces} }) {
                        next if $out_intf eq $in_intf;
                        my $router2 = $out_intf->{router};
                        my $managed = $router2->{managed} or next;
                        $managed eq 'local' or next;
                        next if $router2->{local_mark};
                        __SUB__->($router2);
                    }
                }
            }
        };

        $walk->($router0);
        push @result, $info;
        $local_mark++;

        for my $pair (@{ $router0->{filter_only} }) {
            my ($i, $m) = @$pair;
            $matched{"$i$m"} and next;
            my $ip     = print_ip($i);
            my $prefix = mask2prefix($m);
            warn_msg("Useless $ip/$prefix in attribute 'filter_only'",
                " of $router0->{name}");
        }
    }
    return \@result;
}

# Mark networks and aggregates, that are filtered at some
# managed=local devices.
# A network is marked by adding the number of the corresponding
# managed=local cluster as key to a hash in attribute {filter_at}.
sub mark_managed_local {
    my $managed_local_clusters = get_managed_local_clusters();
    for my $cluster (@$managed_local_clusters) {
        my ($no_nat_set, $filter_only, $mark) =
          @{$cluster}{qw(no_nat_set filter_only mark)};

        my $mark_networks = sub {
            my ($networks) = @_;
            for my $network (@$networks) {

                if (my $subnetworks = $network->{networks}) {
                    __SUB__->($subnetworks);
                }

                my $nat_network = get_nat_network($network, $no_nat_set);
                next if $nat_network->{hidden};
                next if $nat_network->{ip} eq 'unnumbered';
                my ($ip, $mask) = @{$nat_network}{qw(ip mask)};
                for my $pair (@$filter_only) {
                    my ($i, $m) = @$pair;
                    $mask ge $m and match_ip($ip, $i, $m) or next;

                    # Mark network and enclosing aggregates.
                    my $obj = $network;
                    while ($obj) {

                        # Has already been processed as supernet of
                        # other network.
                        last if $obj->{filter_at}->{$mark};
                        $obj->{filter_at}->{$mark} = 1;

#                        debug "Filter $obj->{name} at $mark";
                        $obj = $obj->{up};
                    }
                }
            }
        };
        for my $zone (@zones) {
            $mark_networks->($zone->{networks});
        }

        # Rules from general_permit should be applied to all devices
        # with 'managed=local'.
        $network_00->{filter_at}->{$mark} = 1;
        $network_00_v6->{filter_at}->{$mark} = 1;
    }
}

# group of reroute_permit networks must be expanded late, after areas,
# aggregates and subnets have been set up. Otherwise automatic groups
# wouldn't work.
#
# Reroute permit is not allowed between different security zones.
sub link_reroute_permit {
    for my $zone (@zones) {
        my $ipv6 = $zone->{ipv6};
        for my $interface (@{ $zone->{interfaces} }) {
            my $group = $interface->{reroute_permit} or next;
            $group = expand_group($group,
                                  "'reroute_permit' of $interface->{name}",
                                  $ipv6);
            my @checked;
            for my $obj (@$group) {
                if (is_network($obj) and not $obj->{is_aggregate}) {
                    my $net_zone = $obj->{zone};
                    if (not zone_eq($net_zone, $zone)) {
                        err_msg(
                            "Invalid reroute_permit for $obj->{name} ",
                            "at $interface->{name}:",
                            " different security zones"
                        );
                    }
                    else {
                        push @checked, $obj;
                    }
                }
                else {
                    err_msg(
                        "$obj->{name} not allowed in attribute",
                        " 'reroute_permit' of $interface->{name}"
                    );
                }
            }
            $interface->{reroute_permit} = \@checked;
        }
    }
}

##############################################################################
# Purpose  :
sub add_managed_hosts_to_aggregate {
    my ($aggregate) = @_;

    # Collect managed hosts of sub-networks.
    my $networks = $aggregate->{networks};
    if (@$networks) {
        for my $network (@$networks) {
            my $managed_hosts = $network->{managed_hosts} or next;
            push(@{ $aggregate->{managed_hosts} }, @$managed_hosts);
        }
    }

    # Collect matching managed hosts of all networks of zone.
    # Ignore sub-networks of aggregate, because they would have been
    # found in $networks above.
    else {
        my ($ip, $mask) = @{$aggregate}{qw(ip mask)};
        my $zone = $aggregate->{zone};
        for my $network (@{ $zone->{networks} }) {
            next if $network->{mask} gt $mask;
            my $managed_hosts = $network->{managed_hosts} or next;
            push(
                @{ $aggregate->{managed_hosts} },
                grep { match_ip($_->{ip}, $ip, $mask) } @$managed_hosts
            );
        }
    }
}

####################################################################
# Borders of security zones are
# a) interfaces of managed devices and
# b) interfaces of devices, which have at least one pathrestriction applied.
#
# For each security zone create a zone object.
# Link each interface at the border with the zone and vice versa.
# Additionally link each network and unmanaged router with the zone.
# Add a list of all its numbered networks to the zone.
####################################################################

##############################################################################
# Purpose  : Link aggregate and zone via references in both objects, set
#            aggregate properties according to those of the linked zone.
#            Store aggregates in @networks (providing all srcs and dsts).
sub link_aggregate_to_zone {
    my ($aggregate, $zone, $key) = @_;

    # Link aggregate with zone.
    $aggregate->{zone} = $zone;
    $zone->{ipmask2aggregate}->{$key} = $aggregate;

    # Take a new array for each aggregate, otherwise we would share
    # the same array between different aggregates.
    $aggregate->{networks} ||= [];  # Has to be initialized, even if it is empty

    # Set aggregate properties
    $zone->{has_id_hosts} and $aggregate->{has_id_hosts} = 1;

    # Store aggregate in global list of networks.
    push @networks, $aggregate;
}

##############################################################################
# Update relations {networks}, {up} and {owner} for implicitly defined
# aggregates.
# Remember:
# {up} is relation inside set of all networks and aggregates.
# {networks} is attribute of aggregates and networks,
#            but value is list of networks.
sub link_implicit_aggregate_to_zone {
    my ($aggregate, $zone, $key) = @_;

    # $key is concatenation of two bit strings, split it into original
    # bit strings. Bitstring length is 32 bit (4 bytes) for IPv4, and
    # 128 bit (16 bytes) for IPv6.
    my $size = length($key)/2;
    my ($ip, $mask) = unpack"a${size}a${size}", $key;

    my $ipmask2aggregate = $zone->{ipmask2aggregate};

    # Collect all aggregates, networks and subnets of current zone.
    # Get aggregates in deterministic order.
    my @objects = @{$ipmask2aggregate}{ sort keys %$ipmask2aggregate };
    my $add_subnets = sub {
        my ($network) = @_;
        my $subnets = $network->{networks} or return;
        push @objects, @$subnets;
        __SUB__->($_) for @$subnets;
    };
    push @objects, @{ $zone->{networks} };
    $add_subnets->($_) for @{ $zone->{networks} };

    # Collect all objects being larger and smaller than new aggregate.
    my @larger  = grep { $_->{mask} lt $mask } @objects;
    my @smaller = grep { $_->{mask} gt $mask } @objects;

    # Find subnets of new aggregate.
    for my $obj (@smaller) {
        my $i = $obj->{ip};
        match_ip($i, $ip, $mask) or next;

        # Ignore sub-subnets, i.e. supernet is smaller than new aggregate.
        if (my $up = $obj->{up}) {
            next if $up->{mask} ge $mask;
        }
        $obj->{up} = $aggregate;

#        debug "$obj->{name} -up1-> $aggregate->{name}";
        push(
            @{ $aggregate->{networks} },
            $obj->{is_aggregate} ? @{ $obj->{networks} } : $obj
        );
    }

    # Find supernet of new aggregate.
    # Iterate from smaller to larger supernets.
    # Stop after smallest supernet has been found.
    for my $obj (sort { $b->{mask} cmp $a->{mask} } @larger) {
        my ($i, $m) = @{$obj}{qw(ip mask)};
        match_ip($ip, $i, $m) or next;
        $aggregate->{up} = $obj;

#        debug "$aggregate->{name} -up2-> $obj->{name}";
        last;
    }

    link_aggregate_to_zone($aggregate, $zone, $key);
    add_managed_hosts_to_aggregate($aggregate);
}

##############################################################################
# Purpose  : Process all explicitly defined aggregates. Check proper usage of
#            aggregates. For every aggregate, link aggregate objects to all
#            zones inside the zone cluster containing the aggregates link
#            network and set aggregate and zone properties. Add aggregate
#            objects to global @networks array.
# Comments : Has to be called after zones have been set up. But before
#            find_subnets_in_zone calculates {up} and {networks} relation.
sub link_aggregates {

    my @aggregates_in_cluster;    # Collect all aggregates inside clusters
    for my $name (sort keys %aggregates) {
        my $aggregate = $aggregates{$name};
        my ($type, $name) = @{ $aggregate->{link} };

        # Assure aggregates to be linked to networks only
        if ($type ne 'network') {
            err_msg("$aggregate->{name} must not be linked to $type:$name");
            $aggregate->{disabled} = 1;
            next;
        }

        # Assure aggregate link to exist/disable aggregates without active links
        my $network = $networks{$name};
        if (not $network) {
            err_msg("Referencing undefined $type:$name",
                " from $aggregate->{name}");
            $aggregate->{disabled} = 1;
            next;
        }
        if ($network->{disabled}) {
            $aggregate->{disabled} = 1;
            next;
        }

        # Reference network link in security zone.
        my $zone = $network->{zone};
        $zone->{link} = $network;    # only used in cut-netspoc

        # Assure aggregate and network private status to be equal
        my $private1 = $aggregate->{private} || 'public';
        my $private2 = $network->{private};
        $private2 ||= 'public';
        $private1 eq $private2
          or err_msg("$private1 $aggregate->{name} must not be linked",
            " to $private2 $type:$name");

        # Assure that no other aggregate with same IP and mask exists in cluster
        my ($ip, $mask) = @{$aggregate}{qw(ip mask)};
        my $key     = "$ip$mask";
        my $cluster = $zone->{zone_cluster};
        for my $zone2 ($cluster ? @$cluster : ($zone)) {
            if (my $other = $zone2->{ipmask2aggregate}->{$key}) {
                err_msg("Duplicate $other->{name} and $aggregate->{name}",
                    " in $zone->{name}");
            }
        }

        # Collect aggregates inside clusters
        if ($cluster) {
            push(@aggregates_in_cluster, $aggregate);
        }

        # Use aggregate with ip 0/0 to set attributes of all zones in cluster.
        #
        # Even NAT is moved to zone for aggregate 0/0 although we
        # retain NAT at other aggregates.
        # This is an optimization to prevent the creation of many aggregates 0/0
        # if only inheritance of NAT from area to network is needed.
        if (is_zero_ip($mask)) {
            for my $attr (qw(has_unenforceable has_fully_redundant
                             owner nat
                             no_check_supernet_rules))
            {
                if (my $v = delete $aggregate->{$attr}) {
                    for my $zone2 ($cluster ? @$cluster : ($zone)) {
                        $zone2->{$attr} = $v;
                    }
                }
            }
        }

        # Link aggragate and zone (also setting zone{ipmask2aggregate}
        link_aggregate_to_zone($aggregate, $zone, $key);
    }

    # add aggregate to all zones in the zone cluster
    for my $aggregate (@aggregates_in_cluster) {
        duplicate_aggregate_to_cluster($aggregate);
    }
}

##############################################################################
# Parameter: $aggregate object reference, $implicit flag
# Purpose  : Create an aggregate object for every zone inside the zones cluster
#            containing the aggregates link-network.
# Comments : From users point of view, an aggregate refers to networks of a zone
#            cluster. Internally, an aggregate object represents a set of
#            networks inside a zone. Therefeore, every zone inside a cluster
#            gets its own copy of the defined aggregate to collect the zones
#            networks matching the aggregates IP address.
# TDOD     : Aggregate may be a non aggregate network,
#            e.g. a network with ip/mask 0/0. ??
sub duplicate_aggregate_to_cluster {
    my ($aggregate, $implicit) = @_;
    my $cluster = $aggregate->{zone}->{zone_cluster};
    my ($ip, $mask) = @{$aggregate}{qw(ip mask)};
    my $key = "$ip$mask";

    # Process every zone of the zone cluster
    for my $zone (@$cluster) {
        next if $zone->{ipmask2aggregate}->{$key};

#        debug("Dupl. $aggregate->{name} to $zone->{name}");

        # Create new aggregate object for every zone inside the cluster
        my $aggregate2 = new(
            'Network',
            name         => $aggregate->{name},
            is_aggregate => 1,
            ip           => $aggregate->{ip},
            mask         => $aggregate->{mask},
        );

        # Link new aggregate object and cluster
        if ($implicit) {
            link_implicit_aggregate_to_zone($aggregate2, $zone, $key);
        }
        else {
            link_aggregate_to_zone($aggregate2, $zone, $key);
        }
    }
}

###############################################################################
# Find aggregate referenced from any:[..].
# Creates new anonymous aggregate if missing.
# If zone is part of a zone_cluster,
# return aggregates for each zone of the cluster.
sub get_any {
    my ($zone, $ip, $mask) = @_;
    if (not defined $ip) {
        $ip = $mask = get_zero_ip($zone->{ipv6});
    }
    my $key     = "$ip$mask";
    my $cluster = $zone->{zone_cluster};
    if (not $zone->{ipmask2aggregate}->{$key}) {

        # Check, if there is a network with same IP as the requested
        # aggregate.  If found, don't create a new aggregate in zone,
        # but use the network instead. Otherwise {up} relation
        # wouldn't be well defined.
        if (
            my @networks = grep({ $_->{mask} eq $mask and $_->{ip} eq $ip }
                map { @{ $_->{networks} } } $cluster ? @$cluster : ($zone))
          )
        {
            for my $network (@networks) {
                my $nat = $network->{nat} or next;
                grep { not $_->{hidden} } values %$nat or next;
                my $p_ip    = print_ip($ip);
                my $prefix  = mask2prefix($mask);
                err_msg("Must not use aggregate with IP $p_ip/$prefix",
                        " in $zone->{name}\n",
                        " because $network->{name} has identical IP",
                        " but is also translated by NAT");
            }

            # Duplicate networks have already been sorted out.
            my ($network) = @networks;
            my $zone2 = $network->{zone};

            # Handle $network like an aggregate.
            $zone2->{ipmask2aggregate}->{$key} = $network;

            # Create aggregates in cluster, using the name of the network.
            duplicate_aggregate_to_cluster($network, 1) if $cluster;
        }
        else {

            # any:[network:x] => any:[ip=i.i.i.i/pp & network:x]
            my $p_ip   = print_ip($ip);
            my $prefix = mask2prefix($mask);
            my $name   = $zone->{name};
            $name =~ s/\[/[ip=$p_ip\/$prefix & / if $prefix != 0;
            my $aggregate = new(
                'Network',
                name         => $name,
                is_aggregate => 1,
                ip           => $ip,
                mask         => $mask,
            );
            $aggregate->{ipv6} = 1 if $zone->{ipv6};
            if (my $private = $zone->{private}) {
                $aggregate->{private} = $private;
            }
            link_implicit_aggregate_to_zone($aggregate, $zone, $key);
            duplicate_aggregate_to_cluster($aggregate, 1) if $cluster;
        }
    }
    if ($cluster) {
        return get_cluster_aggregates($zone, $ip, $mask);
    }
    else {
        return $zone->{ipmask2aggregate}->{$key};
    }
}

# Get set of aggregates of a zone cluster.
# Ignore zone having no aggregate from unnumbered network.
sub get_cluster_aggregates {
    my ($zone, $ip, $mask) = @_;
    my $key = "$ip$mask";
    return
      map { $_->{ipmask2aggregate}->{$key} || () } @{ $zone->{zone_cluster} };
}

###############################################################################
# Purpose  : Collects all elements (networks, unmanaged routers, interfaces) of
#            a zone object and references the zone in its elements. Sets zone
#            property flags and private status.
# Comments : Unnumbered and tunnel networks are not referenced in zone objects,
#            as they are no valid src or dst.
sub set_zone1 {
    my ($network, $zone, $in_interface) = @_;

    # Return if network was processed already (= loop was found).
    if ($network->{zone}) {
        return;
    }

    # Reference zone in network and vice versa...
    $network->{zone} = $zone;
    if (not($network->{ip} =~ /^(?:unnumbered|tunnel)$/)) {   # no valid src/dst
        push @{ $zone->{networks} }, $network;
    }

#    debug("$network->{name} in $zone->{name}");

    # Set zone property flags depending on network properties...
    $network->{ip} eq 'tunnel' and $zone->{is_tunnel}    = 1;
    $network->{has_id_hosts}   and $zone->{has_id_hosts} = 1;

    # Check network 'private' status and zone 'private' status to be equal.
    my $private1 = $network->{private} || 'public';
    if ($zone->{private}) {
        my $private2 = $zone->{private};
        if ($private1 ne $private2) {
            my $other = $zone->{networks}->[0];
            err_msg(
                "Networks of $zone->{name} all must have",
                " identical 'private' status\n",
                " - $other->{name}: $private2\n",
                " - $network->{name}: $private1"
            );
        }
    }

    # Set zone private status (attribute will be removed if value is 'public')
    $zone->{private} = $private1;

    # Proceed with adjacent elements...
    for my $interface (@{ $network->{interfaces} }) {
        next if $interface eq $in_interface;    # Ignore Interface we came from.
        my $router = $interface->{router};

        # If its a zone delimiting router, reference interface in zone and v.v.
        if ($router->{managed} or $router->{semi_managed}) {
            $interface->{zone} = $zone;
            push @{ $zone->{interfaces} }, $interface;
        }
        else {

            #If its an unmanaged router, reference router in zone and v.v.
            next if $router->{zone}; # Traverse each unmanaged router only once.
            $router->{zone} = $zone; # added only to prevent double traversal
            push @{ $zone->{unmanaged_routers} }, $router;

            # Recursively add adjacent networks.
            for my $out_interface (@{ $router->{interfaces} }) {
                next if $out_interface eq $interface;  # Ignore IF we came from.
                next if $out_interface->{disabled};
                set_zone1($out_interface->{network}, $zone, $out_interface);
            }
        }
    }
}

##############################################################################
# Purpose  : Collect zones connected by semi_managed devices into a cluster.
# Comments : Tunnel_zones are not included in zone clusters, because
#               - it is useless in rules and
#               - we would get inconsistent owner since zone of tunnel
#                 doesn't inherit from area.
sub set_zone_cluster {
    my ($zone, $in_interface, $zone_aref) = @_;

    # Reference zone in cluster object and vice versa
    push @$zone_aref, $zone if not $zone->{is_tunnel};
    $zone->{zone_cluster} = $zone_aref;

    my $private1 = $zone->{private} || 'public';

    # Find zone interfaces connected to semi-managed routers...
    for my $interface (@{ $zone->{interfaces} }) {
        next if $interface eq $in_interface;
        next if $interface->{main_interface};
        my $router = $interface->{router};
        next if $router->{managed};
        next if $router->{active_path};
        local $router->{active_path} = 1;

        # Process adjacent zones...
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $interface;
            my $next = $out_interface->{zone};
            next if $next->{zone_cluster};             #traverse zones only once
            next if $out_interface->{main_interface};

            # Check for equal private status.
            my $private2 = $next->{private} || 'public';
            $private1 eq $private2
              or err_msg(
                "Zones connected by $router->{name}",
                " must all have identical 'private' status\n",
                " - $zone->{name}: $private1\n",
                " - $next->{name}: $private2"
              );

            # Add adjacent zone recursively.
            set_zone_cluster($next, $out_interface, $zone_aref);
        }
    }
}

# Two zones are zone_eq, if
# - zones are equal or
# - both belong to the same zone cluster.
sub zone_eq {
    my ($zone1, $zone2) = @_;
    return 1 if $zone1 eq $zone2;
    my $cluster1 = $zone1->{zone_cluster} or return;
    my $cluster2 = $zone2->{zone_cluster} or return;
    return $cluster1 eq $cluster2;
}

###############################################################################
# Purpose  : Collect zones and managed routers of an area object and set a
#            reference to the area in its zones and routers.
#            For areas with defined borders: Keep track of area borders found
#            during area traversal.
#            For anchor/auto_border areas: fill {border} and {inclusive_border}
#            arrays.
# Returns  : undef (or aref of interfaces, if invalid path was found).
sub set_area1 {
    my ($obj, $area, $in_interface) = @_;

    return if $obj->{areas}->{$area};    # Found a loop.

    $obj->{areas}->{$area} = $area;  # Find duplicate/overlapping areas or loops

    my $is_zone = is_zone($obj);

    # Reference zones and managed routers in the corresponding area
    if ($is_zone) {
        if (not $obj->{is_tunnel}) {
            push @{ $area->{zones} }, $obj;
        }
    }
    elsif ($obj->{managed} or $obj->{routing_only}) {
        push @{ $area->{managed_routers} }, $obj;
    }

    my $auto_border = $area->{auto_border};
    my $lookup      = $area->{intf_lookup};

    for my $interface (@{ $obj->{interfaces} }) {

        # Ignore interface we came from.
        next if $interface eq $in_interface;

        # No further traversal at secondary interfaces
        next if $interface->{main_interface};

        # For areas with defined borders, check if border was found...
        if ($lookup->{$interface}) {
            my $is_inclusive = $interface->{is_inclusive};

            # Reached border from wrong side or border classification wrong.
            if ($is_inclusive->{$area} xor !$is_zone) {
                return [$interface];    # will be collected to show invalid path
            }

            # ...mark found border in lookup hash.
            $lookup->{$interface} = 'found';
            next;
        }

        # For auto_border areas, just collect border/inclusive_border interface
        elsif ($auto_border) {
            if ($interface->{is_border}) {
                push(
                    @{ $area->{ $is_zone ? 'border' : 'inclusive_border' } },
                    $interface
                );
                next;
            }
        }

        # Proceed traversal with next element
        my $next = $interface->{ $is_zone ? 'router' : 'zone' };
        if (my $err_path = set_area1($next, $area, $interface)) {
            push @$err_path, $interface;    # collect interfaces of invalid path
            return $err_path;
        }
    }
}

###############################################################################
# Purpose : Distribute router_attributes from the area definition to the managed
#           routers of the area.
sub inherit_router_attributes {
    my ($area) = @_;

    # Check for attributes to be inherited.
    my $attributes = $area->{router_attributes} or return;
    $attributes->{owner} and keys %$attributes == 1 and return;  # handled later

    #Process all managed routers of the area inherited from.
    for my $router (@{ $area->{managed_routers} }) {
        for my $key (keys %$attributes) {

            next if $key eq 'owner';    # Owner is handled in propagate_owners.

            # if attribute exists in router (router or smaller area definition)
            my $val = $attributes->{$key};
            if (my $r_val = $router->{$key}) {
                if (
                    $r_val eq $val      # warn, if attributes are equal
                    or ref $r_val eq 'ARRAY'
                    and ref $val eq 'ARRAY'
                    and aref_eq($r_val, $val)
                  )
                {
                    warn_msg(
                        "Useless attribute '$key' at $router->{name},\n",
                        " it was already inherited from $attributes->{name}"
                    );
                }
            }

            # Add attribute to the router object if not yet set.
            else {
                $router->{$key} = $val;
            }
        }
    }
}

###############################################################################
# Purpose : Returns true if nat hashes are equal.
sub nat_equal {
    my ($nat1, $nat2) = @_;

    # Check whether nat attributes are different...
    for my $attr (qw(ip mask dynamic hidden identity)) {
        return if defined $nat1->{$attr} xor defined $nat2->{$attr};
        defined $nat1->{$attr} or next;             # both values are undefined
        return if $nat1->{$attr} ne $nat2->{$attr}; # values of attribute differ
    }

    # ...return true if no difference found.
    return 1;
}
##############################################################################
# Purpose : 1. Generate warning if NAT values of two objects hold the same
#              attributes.
#           2. Mark NAT value of smaller object, so that warning is only
#              printed once and not again if compared with some larger object.
#              This is also used later to warn on useless identity NAT.
sub check_useless_nat {
    my ($nat1, $nat2) = @_;
    return if $nat2->{has_been_checked}++;
    if (nat_equal($nat1, $nat2)) {
        warn_msg(
            "Useless $nat2->{descr},\n",
            " it is already inherited from $nat1->{descr}"
        );
    }
}

##############################################################################
# Purpose : Distribute NAT from area to zones.
sub inherit_area_nat {

    my ($area) = @_;
    my $hash = $area->{nat} or return;

    # Process every nat definition of area.
    for my $nat_tag (sort keys %$hash) {
        my $nat = $hash->{$nat_tag};

        # Distribute nat definitions to every zone of area.
        for my $zone (@{ $area->{zones} }) {

            # Skip zone, if NAT tag exists in zone already...
            if (my $z_nat = $zone->{nat}->{$nat_tag}) {

                # ... and warn if zones NAT value holds the same attributes.
                check_useless_nat($nat, $z_nat);
                next;
            }

            # Store NAT definition in zone otherwise
            $zone->{nat}->{$nat_tag} = $nat;

#           debug "$zone->{name}: $nat_tag from $area->{name}";
        }
    }
}

###############################################################################
# Purpose : Assure that areas are processed in the right order and distribute
#           area attributes to zones and managed routers.
sub inherit_attributes_from_area {

    # Areas can be nested. Proceed from small to larger ones.
    for my $area (sort { @{ $a->{zones} } <=> @{ $b->{zones} } } @areas) {
        inherit_router_attributes($area);
        inherit_area_nat($area);
    }
}

###############################################################################
# Purpose  : Distributes NAT from aggregates and networks to other networks
#            in same zone, that are in subnet relation.
#            If a network A is subnet of multiple networks B < C,
#            then NAT of B is used.
sub inherit_nat_to_subnets_in_zone {
    my ($net_or_zone, $zone) = @_;
    my ($ip1, $mask1);
    if (is_network($net_or_zone)) {
        ($ip1, $mask1) = @{$net_or_zone}{qw(ip mask)};
    }
    else {
        my $zero_ip = get_zero_ip($net_or_zone->{ipv6});
        ($ip1, $mask1) = ($zero_ip, $zero_ip);
    }
    my $hash = $net_or_zone->{nat};
    for my $nat_tag (sort keys %$hash) {
        my $nat = $hash->{$nat_tag};

#        debug "inherit $nat_tag from $net_or_zone->{name}";

        # Distribute nat definitions to every subnet of supernet,
        # aggregate or zone.
        for my $network (@{ $zone->{networks} }) {
            my ($ip2, $mask2) = @{$network}{qw(ip mask)};

            # Only process subnets.
            $mask2 gt $mask1 or next;
            match_ip($ip2, $ip1, $mask1) or next;

            # Skip network, if NAT tag exists in network already...
            if (my $n_nat = $network->{nat}->{$nat_tag}) {

                # ... and warn if networks NAT value holds the
                # same attributes.
                check_useless_nat($nat, $n_nat);
            }

            elsif ($network->{bridged} and not $nat->{identity}) {
                err_msg(
                    "Must not inherit nat:$nat_tag at bridged",
                    " $network->{name} from $net_or_zone->{name}"
                );
            }

            # Copy NAT defintion; add description and name of original network.
            else {
                my $net_name = $network->{name};
                my $sub_nat = {
                    %$nat,
                    name  => $net_name,
                    descr => "nat:$nat_tag of $net_name",

                    # Copy attribute {subnet_of}, to suppress warning.
                    # Copy also if undefined, to overwrite value in
                    # original definition.
                    subnet_of => $network->{subnet_of},
                };

                # For static NAT
                # - merge IP from NAT network and subnet,
                # - adapt mask to size of subnet
                if (not $nat->{dynamic}) {
                    my $nat_mask = $sub_nat->{mask};

                    # Check mask of static NAT inherited from area or zone.
                    if ($nat_mask ge $mask2) {
                        err_msg("Must not inherit $nat->{descr} at",
                                " $network->{name}\n",
                                " because NAT network must be larger",
                                " than translated network");
                    }

                    # Take higher bits from NAT IP, lower bits from original IP.
                    $sub_nat->{ip} |= $ip2 & ~ $nat_mask;
                    $sub_nat->{mask} = $mask2;
                }

                $network->{nat}->{$nat_tag} = $sub_nat;
            }
        }
    }
}

sub inherit_nat_in_zone {
    for my $zone (@zones) {

        # Find all networks and aggregates of current zone,
        # that have NAT definitions.
        my @nat_supernets = grep({ $_->{nat} } @{ $zone->{networks} },
            values %{ $zone->{ipmask2aggregate} });

        # Add zone object instead of aggregate 0/0, because NAT is stored
        # at zone in this case.
        my @nat_zone = $zone->{nat} ? ($zone) : ();

        # Proceed from smaller to larger objects. (Bigger mask first.)
        for my $supernet (sort({ $b->{mask} cmp $a->{mask} } @nat_supernets),
            @nat_zone)
        {
            inherit_nat_to_subnets_in_zone($supernet, $zone);
        }
    }
}

sub check_attr_no_check_supernet_rules {
    my $check_subnets;
    $check_subnets = sub {
        my ($network_or_zone) = @_;
        my $error_list;
        my $hosts = $network_or_zone->{hosts};
        if ($hosts and @$hosts) {
            push @$error_list, $network_or_zone;
        }
        if (my $subnets = $network_or_zone->{networks}) {
            for my $subnet (@$subnets) {
                if (my $sub_error = $check_subnets->($subnet)) {
                    push @$error_list, @$sub_error;
                }
            }
        }
        return $error_list;
    };
    for my $zone (@zones) {
        $zone->{no_check_supernet_rules} or next;
        if (my $bad_networks = $check_subnets->($zone)) {
            err_msg("Must not use attribute 'no_check_supernet_rules'",
                    " at $zone->{name}\n",
                    " with networks having host definitions:\n",
                    " - ",
                    join "\n - ", map { $_->{name} } @$bad_networks);
        }
    }
}

# 1. Remove NAT entries from aggregates.
#    These are only used during NAT inheritance.
# 2. Remove identity NAT entries.
#    These are only needed during NAT inheritance.
# 3. Check for useless identity NAT.
# 4. Remove no longer used attribute {has_been_checked}.
sub cleanup_after_inheritance {
    for my $network (@networks) {
        my $href = $network->{nat} or next;
        if ($network->{is_aggregate}) {
            delete $network->{nat};
            next;
        }
        for my $nat_tag (keys %$href) {
            my $nat_network = $href->{$nat_tag};
            my $is_used = delete $nat_network->{has_been_checked};
            $nat_network->{identity} or next;
            delete $href->{$nat_tag};
            if (not keys %$href) {
                delete $network->{nat};
            }
            $is_used
              or warn_msg("Useless identity nat:$nat_tag at $network->{name}");
        }
    }
}

sub inherit_attributes {
    inherit_attributes_from_area();
    inherit_nat_in_zone();
    check_attr_no_check_supernet_rules();
    cleanup_after_inheritance();
}

##############################################################################
# Purpose  : Create a new zone object for every network without a zone
sub set_zones {

    # Process networks without a zone
    for my $network (@networks) {
        next if $network->{zone};

        # Create zone object with name of corresponding aggregate and ip 0/0.
        my $name = "any:[$network->{name}]";
        my $zone = new('Zone', name => $name, networks => []);
        $zone->{ipv6} = 1 if $network->{ipv6};
        push @zones, $zone;

        # Collect zone elements...
        set_zone1($network, $zone, 0);

        # Mark zone which consists only of a loopback network.
        $zone->{loopback} = 1
          if $network->{loopback} and @{ $zone->{networks} } == 1;

        # Attribute {is_tunnel} is set only when zone has only tunnel networks.
        if (@{ $zone->{networks} }) { # tunnel networks arent referenced in zone
            delete $zone->{is_tunnel};
        }

        # Remove zone reference from unmanaged routers (no longer needed).
        if (my $unmanaged = $zone->{unmanaged_routers}) {
            delete $_->{zone} for @$unmanaged;
        }

        # Remove private status, if 'public'
        if ($zone->{private} and $zone->{private} eq 'public') {
            delete $zone->{private};
        }
    }
}

##############################################################################
# Purpose  : Clusters zones connected by semi_managed routers. References of all
#            zones of a cluster are stored in the {zone_cluster} attribute of
#            the zones.
# Comments : The {zone_cluster} attribute is only set if the cluster has more
#            than one element.
sub cluster_zones {

    # Process all unclustered zones.
    for my $zone (@zones) {
        next if $zone->{zone_cluster};

        # Create a new cluster and collect its zones
        my $cluster = [];
        set_zone_cluster($zone, 0, $cluster);

        # delete clusters containing a single network only
        delete $zone->{zone_cluster} if 1 >= @$cluster;

#       debug('cluster: ', join(',',map($_->{name}, @{$zone->{zone_cluster}})))
#           if $zone->{zone_cluster};
    }
}

###############################################################################
# Purpose  : Mark interfaces, which are border of some area, prepare consistency
#            check for attributes {border} and {inclusive_border}.
# Comments : Area labeled interfaces are needed to locate auto_borders.
sub prepare_area_borders {
    my %has_inclusive_borders;   # collects all routers with inclusive border IF

    # Identify all interfaces which are border of some area
    for my $area (@areas) {
        for my $attribute (qw(border inclusive_border)) {
            my $border = $area->{$attribute} or next;
            for my $interface (@$border) {

                # Reference delimited area in the interfaces attributes
                $interface->{is_border} = $area;    # used for auto borders
                if ($attribute eq 'inclusive_border') {
                    $interface->{is_inclusive}->{$area} = $area;

                    # Collect routers with inclusive border interface
                    my $router = $interface->{router};
                    $has_inclusive_borders{$router} = $router;
                }
            }
        }
    }
    return \%has_inclusive_borders;
}

###############################################################################
# Purpose  : Collect zones, routers (and interfaces, if no borders defined)
#            of an area.
# Returns  : undef (or 1, if error was shown)
sub set_area {
    my ($obj, $area, $in_interface) = @_;
    if (my $err_path = set_area1($obj, $area, $in_interface)) {

        # Print error path, if errors occurred
        push @$err_path, $in_interface if $in_interface;
        my $err_intf     = $err_path->[0];
        my $is_inclusive = $err_intf->{is_inclusive};
        my $err_obj = $err_intf->{ $is_inclusive->{$area} ? 'router' : 'zone' };
        my $in_loop = $err_obj->{areas}->{$area} ? ' in loop' : '';
        err_msg(
            "Inconsistent definition of $area->{name}",
            $in_loop,
            ".\n",
            " It is reached from outside via this path:\n",
            " - ",
            join("\n - ", map { $_->{name} } reverse @$err_path)
        );
        return 1;
    }
}

###############################################################################s
# Purpose  : Set up area objects, assure proper border definitions.
sub set_areas {
    for my $area (@areas) {
        $area->{zones} = [];
        if (my $network = $area->{anchor}) {
            set_area($network->{zone}, $area, 0);
        }
        else {

            # For efficient look up if some IF is a border of current area.
            my $lookup = $area->{intf_lookup} = {};

            my $start;
            my $obj1;

            # Collect all area delimiting interfaces in border lookup array
            for my $attr (qw(border inclusive_border)) {
                my $borders = $area->{$attr} or next;
                @{$lookup}{@$borders} = @$borders;
                next if $start;

                # identify start interface and direction for area traversal
                $start = $borders->[0];
                $obj1  = $attr eq 'border'
                  ? $start->{zone}       # proceed with zone
                  : $start->{router};    # proceed with router
            }

            # Collect zones and routers of area and keep track of borders found.
            $lookup->{$start} = 'found';
            my $err = set_area($obj1, $area, $start);
            next if $err;

            # Assert that all borders were found.
            for my $attr (qw(border inclusive_border)) {
                my $borders = $area->{$attr} or next;
                my @bad_intf = grep { $lookup->{$_} ne 'found' } @$borders
                  or next;
                err_msg(
                    "Unreachable $attr of $area->{name}:\n - ",
                    join("\n - ", map { $_->{name} } @bad_intf)
                );
                $area->{$attr} =
                  [ grep { $lookup->{$_} eq 'found' } @$borders ];
            }
        }

        # Check whether area is empty (= consist of a single router)
        @{ $area->{zones} }
          or warn_msg("$area->{name} is empty");

#     debug("$area->{name}:\n ", join "\n ", map $_->{name}, @{$area->{zones}});
    }
}

###############################################################################
# Purpose : Find subset relation between areas, assure that no duplicate or
#           overlapping areas exist
sub find_area_subset_relations {
    my %seen;    # key:contained area, value: containing area

    # Process all zones contained by one or more areas
    for my $zone (@zones) {
        $zone->{areas} or next;

        # Sort areas containing zone by ascending size
        my @areas = sort(
            {    @{ $a->{zones} } <=> @{ $b->{zones} }
              || $a->{name} cmp $b->{name} }        # equal size? sort by name
            values %{ $zone->{areas} }) or next;    # Skip empty hash.

        # Take the smallest area.
        my $next = shift @areas;

        while (@areas) {
            my $small = $next;
            $next = shift @areas;
            next if $seen{$small}->{$next};  # Already identified in other zone.

            # Check that each zone of $small is part of $next.
            my $ok = 1;
            for my $zone (@{ $small->{zones} }) {
                if (not $zone->{areas}->{$next}) {
                    $ok = 0;
                    err_msg("Overlapping $small->{name} and $next->{name}");
                    last;
                }
            }

            # check for duplicates
            if ($ok) {
                if (@{ $small->{zones} } == @{ $next->{zones} }) {
                    err_msg("Duplicate $small->{name} and $next->{name}");
                }

                # reference containing area
                else {
                    $small->{subset_of} = $next;

#                    debug "$small->{name} < $next->{name}";
                }
            }

            #keep track of processed areas
            $seen{$small}->{$next} = 1;
        }
    }
}

#############################################################################
# Purpose  : Check, that area subset relations hold for routers:
#          : Case 1: If a router R is located inside areas A1 and A2 via
#            'inclusive_border', then A1 and A2 must be in subset relation.
#          : Case 2: If area A1 and A2 are in subset relation and A1 includes R,
#            then A2 also needs to include R either from 'inclusive_border' or
#            R is surrounded by zones located inside A2.
# Comments : This is needed to get consistent inheritance with
#            'router_attributes'.
sub check_routers_in_nested_areas {

    my ($has_inclusive_borders) = @_;

    # Case 1: Identify routers contained by areas via 'inclusive_border'
    for my $router (sort by_name values %$has_inclusive_borders) {

        # Sort all areas having this router as inclusive_border by size.
        my @areas =
          sort({
              @{ $a->{zones} } <=> @{ $b->{zones} } ||    # ascending order
              $a->{name} cmp $b->{name}    # equal size? sort by name
            }
            values %{ $router->{areas} });

        # Take the smallest area.
        my $next = shift @areas;

        # Pairwisely check containing areas for subset relation.
        while (@areas) {
            my $small = $next;
            $next = shift @areas;
            my $big = $small->{subset_of} || '';    # extract containing area
            next if $next eq $big;
            err_msg(
                "$small->{name} and $next->{name} must be",
                " in subset relation,\n because both have",
                " $router->{name} as 'inclusive_border'"
            );
        }
    }

    # Case 2: Identify areas in subset relation
    for my $area (@areas) {
        my $big = $area->{subset_of} or next;

        # Assure routers of the subset area to be located in containing area too
        for my $router (@{ $area->{managed_routers} }) {
            next if $router->{areas}->{$big};
            err_msg(
                "$router->{name} must be located in $big->{name},\n",
                " because it is located in $area->{name}\n",
                " and both areas are in subset relation\n",
                " (use attribute 'inclusive_border')"
            );
        }
    }
}

##############################################################################
# Purpose  : Delete unused attributes in area objects.
sub clean_areas {
    for my $area (@areas) {
        delete $area->{intf_lookup};
        for my $interface (@{ $area->{border} }) {
            delete $interface->{is_border};
            delete $interface->{is_inclusive};
        }
    }
}

###############################################################################
# Purpose  : Create zones and areas.
sub set_zone {
    progress('Preparing security zones and areas');
    set_zones();
    cluster_zones();
    my $crosslink_routers = check_crosslink();
    cluster_crosslink_routers($crosslink_routers);
    my $has_inclusive_borders = prepare_area_borders();
    set_areas();
    find_area_subset_relations();
    check_routers_in_nested_areas($has_inclusive_borders);
    clean_areas();                                  # delete unused attributes
    link_aggregates();
    inherit_attributes();
}

####################################################################
# Virtual interfaces
####################################################################
# Purpose : Assure interfaces with identical virtual IP are located inside
#           the same loop.
sub check_virtual_interfaces {
    my %seen;
    for my $interface (@virtual_interfaces) {
        my $related = $interface->{redundancy_interfaces} or next;

        # Loops inside a security zone are not known and can not be checked
        my $router = $interface->{router};
        next if not($router->{managed} or $router->{semi_managed});

        # Ignore single virtual interface.
        next if @$related <= 1;

        next if $seen{$related}++;

        # Check whether all virtual interfaces are part of a loop.
        my $err;
        for my $v (@$related) {
            if (not $v->{router}->{loop}) {
                err_msg("$v->{name} must be located inside cyclic sub-graph");
                $err = 1;
            }
        }
        if ($err) {

            # Remove invalid pathrestriction to prevent inherited errors.
            delete $_->{path_restrict} for @$related;
            next;
        }

        # Check whether all virtual interfaces are part of the same loop.
        equal(map { $_->{loop} } @$related)
          or err_msg(
            "Virtual interfaces\n ",
            join(', ', map({ $_->{name} } @$related)),
            "\n must all be part of the same cyclic sub-graph"
          );
    }
}

####################################################################
# Check pathrestrictions
####################################################################

sub get_loop {
    my ($interface) = @_;
    return    $interface->{loop}
           || $interface->{router}->{loop}
           || $interface->{zone}->{loop};
}

# Purpose : Collect proper & effective pathrestrictions in a global array.
#           Pathrestrictions have to fulfill following requirements:
#           - Located inside or at the border of cycles.
#           - At least 2 interfaces per pathrestriction.
#           - Have an effect on ACL generation.
sub check_pathrestrictions {
  RESTRICT:

    # Process every pathrestriction.
    for my $restrict (values %pathrestrictions) {
        my $elements = $restrict->{elements};    # Extract interfaces.
        @$elements or next;

        # Collect interfaces to be deleted from pathrestriction.
        my $deleted;

        my ($prev_interface, $prev_cluster);
        for my $interface (@$elements) {
            my $loop = get_loop($interface);
            my $loop_intf = $interface;

            # This router is split part of an unmanaged router.
            # It has exactly two non secondary interfaces.
            # Move pathrestriction to other interface, if that one is
            # located at border of loop.
            if (my $other = $interface->{split_other} and not $loop) {
                if ($loop = $other->{zone}->{loop}) {
                    my $rlist = delete $interface->{path_restrict};
#                   debug("Move $restrict->{name}",
#                         " from $interface->{name} to $other->{name}");
                    $other->{path_restrict} = $rlist;
                    for my $restrict (@$rlist) {
                        my $elements = $restrict->{elements};
                        aref_subst($elements, $interface, $other);
                    }
                    $loop_intf = $other;
                }
            }

            # Interfaces with pathrestriction need to be located
            # inside or at the border of cyclic graphs.
            if (not $loop) {
                warn_msg("Ignoring $restrict->{name} at $interface->{name}\n",
                         " because it isn't located inside cyclic graph");
                push @$deleted, $interface;
                next;
            }

            # Interfaces must belong to same loop cluster.
            my $cluster = $loop->{cluster_exit};
            if ($prev_cluster) {
                if (not $cluster eq $prev_cluster) {
                    warn_msg("Ignoring $restrict->{name} having elements",
                            " from different loops:\n",
                            " - $prev_interface->{name}\n",
                            " - $interface->{name}");
                    $deleted = $elements;
                    last;
                }
            }
            else {
                $prev_cluster   = $cluster;
                $prev_interface = $interface;
            }
        }

        # Delete invalid elements of pathrestriction.
        if ($deleted) {

            # Ignore pathrestriction with only one element.
            if (@$deleted + 1 == @$elements) {
                $deleted = $elements;
            }

            # Remove deleted elements from pathrestriction and
            # remove pathrestriction from deleted elements.
            # Work with copy of $elements, because we change $elements in loop.
            $deleted = [ @$elements ] if $deleted eq $elements;
            for my $element (@$deleted) {
                aref_delete($elements, $element);
                my $rlist = $element->{path_restrict};
                aref_delete($rlist, $restrict);
                if (not @$rlist) {
                    delete $element->{path_restrict};
                }
            }
            @$elements or next;
        }

        # Mark pathrestricted interface at border of loop, where loop
        # node is a zone.
        # This needs special handling during path_mark and path_walk.
        for my $interface (@$elements) {
            if (not $interface->{loop} and $interface->{zone}->{loop}) {
                $interface->{loop_zone_border} = 1;
            }
        }

        # Check for useless pathrestrictions that do not affect any ACLs...
        # Pathrestrictions at managed routers do most probably have an effect.
        grep({ $_->{router}->{managed} or $_->{router}->{routing_only} }
            @$elements)
          and next;

        # Pathrestrictions spanning different zone clusters have an effect.
        equal(map { $_->{zone_cluster} || $_ } map { $_->{zone} } @$elements)
          or next;

        # Pathrestrictions in loops with > 1 zone cluster have an effect.
        my $element      = $elements->[0];
        my $loop         = get_loop($element);
        my $zone         = $element->{zone};
        my $zone_cluster = $zone->{zone_cluster} || [$zone];

        # Process every zone in zone cluster...
        for my $zone1 (@$zone_cluster) {
            for my $interface (@{ $zone1->{interfaces} }) {
                my $router = $interface->{router};

                # ...examine its neighbour zones:
                for my $interface2 (@{ $router->{interfaces} }) {
                    my $zone2 = $interface2->{zone};
                    next if $zone2 eq $zone;
                    if (my $cluster2 = $zone2->{zone_cluster}) {
                        next if $cluster2 eq $zone_cluster;
                    }
                    if (my $loop2 = $zone2->{loop}) {
                        if ($loop eq $loop2) {

                            # Found other zone cluster in same loop.
                            next RESTRICT;
                        }
                    }
                }
            }
        }
        warn_msg(
            "Useless $restrict->{name}.\n",
            " All interfaces are unmanaged and",
            " located inside the same security zone"
        );

        # Clear interfaces of useless pathrestriction.
        $restrict->{elements} = [];
    }

    # Collect all effective pathrestrictions.
    push @pathrestrictions, sort by_name grep({ @{ $_->{elements} } }
                                              values %pathrestrictions);
}

sub delete_pathrestriction_from_interfaces {
    my ($restrict) = @_;
    my $elements = $restrict->{elements};
    for my $interface (@$elements) {
        aref_delete($interface->{path_restrict}, $restrict);

        # Delete empty array to speed up checks in cluster_path_mark.
        if (not @{ $interface->{path_restrict} }) {
            delete $interface->{path_restrict};
        }
    }
}

sub remove_redundant_pathrestrictions {

    # Calculate number of elements once for each pathrestriction.
    my %size;

    # For each element E, find pathrestrictions that contain E.
    my %element2restrictions;
    for my $restrict (@pathrestrictions) {
        my $elements = $restrict->{elements};
        $size{$restrict} = @$elements;
        for my $element (@$elements) {
            $element2restrictions{$element}->{$restrict} = $restrict;
        }
    }

    for my $restrict (@pathrestrictions) {
        my $elements = $restrict->{elements};
        my $size = @$elements;
        my $element1 = $elements->[0];
        my $href = $element2restrictions{$element1};
        my @list = grep { $size{$_} >= $size } values %$href;
        next if @list < 2;

        # Larger pathrestrictions, that reference elements of
        # $restrict.
        my $superset = \@list;

        # Check all elements of current pathrestriction.
        for my $element (@$elements) {
            next if $element eq $element1;

            # $href2 is set of all pathrestrictions that contain $element.
            my $href2 = $element2restrictions{$element};

            # Build superset for next iteration.
            my $next_superset;
            for my $restrict2 (@$superset) {
                next if $restrict2 eq $restrict;
                next if $restrict2->{deleted};
                if ($href2->{$restrict2}) {
                    push @$next_superset, $restrict2;
                }
            }

            # Pathrestriction isn't redundant if superset becomes
            # empty.
            $superset = $next_superset or last;
        }

        # $superset holds those pathrestrictions, that have
        # superset of elements of $restrict.
        $superset or next;
        $restrict->{deleted} = $superset;
        delete_pathrestriction_from_interfaces($restrict);
    }
    if (SHOW_DIAG) {
        for my $restrict (@pathrestrictions) {
            my $superset = $restrict->{deleted} or next;
            my $r_name = $restrict->{name};
            my ($o_name) = sort map { $_->{name} } @$superset;
            diag_msg("Removed $r_name; is subset of $o_name");
        }
    }
    @pathrestrictions = grep { not $_->{deleted} } @pathrestrictions;
}

####################################################################
# Optimize a class of pathrestrictions.
# Find partitions of cyclic graphs that are separated
# by pathrestrictions.
# This allows faster graph traversal.
# When entering a partition, we can already decide,
# if end of path is reachable or not.
####################################################################
#############################################################################
# Purpose  : Mark every element of a loop partition with the partitions
#            identity number.
# Parameter: $obj - current node on loop path (zone/router)
#            $in_interface - interface we come from
#            $mark - unique identity number of the loop partition
#            $lookup - hash stores interfaces of the processed pathrestriction
sub traverse_loop_part {
    my ($obj, $in_interface, $mark, $lookup) = @_;

    # Return if current node has been processed before.
    return if $obj->{reachable_part}->{$mark};
    return if $obj->{active_path};

    local $obj->{active_path} = 1;
    my $is_zone = is_zone($obj);

    # Mark current node ($obj) as member of partition.
    $obj->{reachable_part}->{$mark} = 1;

#    debug "$obj->{name} in loop part $mark";

    # Proceed pathwalk with adjacent objects.
    for my $interface (@{ $obj->{interfaces} }) {

        # Skip unessential interfaces.
        next if $interface eq $in_interface;
        next if $interface->{main_interface};

        # Stop at other interfaces of the processed pathrestriction.
        if (my $reached = $lookup->{$interface}) {
            my $current = $is_zone ? 'zone' : 'router';
            $reached->{$current} = $mark;    # store partition in lookup hash
        }

        # Continue path walk on loop path otherwise.
        else {
            $interface->{loop} or next;
            my $next = $interface->{ $is_zone ? 'router' : 'zone' };
            traverse_loop_part($next, $interface, $mark, $lookup);
        }
    }
}

#############################################################################
# Purpose    : Analyze found partitions and optimize pathrestrictions.
# Parameters : $restrict - pathrestriction to optimize (hash reference)
#              $elements - interfaces of the pathrestriction (array reference)
#              $lookup - stores adjacent partitions for every IF in elements.
sub apply_pathrestriction_optimization {
    my ($restrict, $lookup) = @_;
    my $elements = $restrict->{elements};

    # No outgoing restriction needed for a pathrestriction surrounding a
    # single zone. A rule from zone to zone would be unenforceable anyway.
    #
    # But this restriction is needed for one special case:
    # src=zone, dst=interface:r.zone
    # We must not enter router:r from outside the zone.
#        if (equal(map { $_->{zone} } @$elements)) {
#            $lookup->{$_}->{router} = 'none' for @$elements;
#        }

    # Examine interfaces in or between found partitions.
    my $has_interior;    # To count number of interfaces inside a partition.
    for my $interface (@$elements) {
        my $reached = $lookup->{$interface};

        # Count pathrestriction interfaces inside a partition.
        if ($reached->{zone} eq $reached->{router}) {
            $has_interior++;
        }

        # Store reachable partitions in the interfaces {reachable_at} hash
        else {
            for my $direction (qw(zone router)) {
                my $mark = $reached->{$direction};
                next if $mark eq 'none';
                my $obj = $interface->{$direction};
                push @{ $interface->{reachable_at}->{$obj} }, $mark;

                #debug "$interface->{name}: $direction $mark";
            }
        }
    }

    # Delete pathrestriction from {path_restrict}, if {reachable_at}
    # holds entire information.
    if (not $has_interior) { # Interfaces must not be located inside a partition.
        delete_pathrestriction_from_interfaces($restrict);
        diag_msg("Optimized $restrict->{name}") if SHOW_DIAG;
    }
    else {
        diag_msg("Optimized but preserved $restrict->{name};",
                 " has $has_interior interior")
            if SHOW_DIAG;
    }
}

#############################################################################
# Purpose : Find partitions of loops that are separated by pathrestrictions.
#           Mark every node of a partition with a unique number that is
#           attached to the partitions routers and zones, and every
#           pathrestriction with a list of partitions that can be reached.
sub optimize_pathrestrictions {
    my $mark = 1;

    # Process every pathrestriction.
    for my $restrict (@pathrestrictions) {
        my $elements = $restrict->{elements};

        # Create lookup hash with the pathrestrictions interfaces as keys to
        # store the partitions every interface adjoins in zone/router direction.
        my $lookup = {};
        for my $interface (@$elements) {
            $lookup->{$interface} = {};    # Initial values are empty hashes.
        }

        # From every interface, traverse loop in both directions.
        my $start_mark = $mark;
        for my $interface (@$elements) {
            my $reached = $lookup->{$interface};
            for my $direction (qw(zone router)) {

                # Skip direction where interface was already reached from.
                next if $reached->{$direction};    # Already a partition stored.

                # For interfaces at loop border, skip direction leaving the loop
                my $obj = $interface->{$direction};
                if (not $obj->{loop}) {
                    $reached->{$direction} = 'none';
                    next;
                }

                # Store adjoining partition of the interface.
                $reached->{$direction} = $mark;

                # Traverse loop path and mark loop partition.
                traverse_loop_part($obj, $interface, $mark, $lookup);
                $mark++;
            }
        }

        # Number of partitions found for current pathrestriction.
        my $count = $mark - $start_mark;

        # Optimize pathrestriction, if at least 2 partitions.
        if ($count > 1) {
            apply_pathrestriction_optimization($restrict, $lookup);
        }
        elsif(SHOW_DIAG) {
            diag_msg("Can't optimize $restrict->{name};",
                     " has only $count partition");
        }
    }
}

####################################################################
# Set paths for efficient topology traversal
####################################################################
# Purpose  : Find a path from every zone and router to zone1; store the
#            distance to zone1 in every object visited; identify loops and
#            add loop marker references to loop nodes.
# Parameter: $obj     : zone or managed or semi-managed router
#            $to_zone1: interface of $obj; denotes the direction to reach zone1
#            $distance: distance to zone1
# Returns  : 1. maximal value of $distance used in current subtree.
#            2. undef, if found path is not part of a loop or loop-marker
#               otherwise.
# Comments : Loop markers store following information:
#            - exit: node of the loop where zone1 is reached
#            - distance: distance of loop exit node + 1. It is needed, as the
#            nodes own distance values are later reset to the value of the
#            cluster exit object. The intermediate value is required by
#            cluster_navigation to work.
sub setpath_obj;

sub setpath_obj {
    my ($obj, $to_zone1, $distance) = @_;

    #debug("--$distance: $obj->{name} --> ". ($to_zone1 and $to_zone1->{name}));

    # Return from recursion if loop was found.
    if ($obj->{active_path}) {   # Loop found, node might be loop exit to zone1.

        # Create unique loop marker, which will be added to all loop members.
        my $new_distance = $obj->{distance} + 1;
        my $loop = $to_zone1->{loop} = {
            exit     => $obj,             # Reference exit node.
            distance => $new_distance,    # Required for cluster navigation.
        };
        return ($new_distance, $loop);
    }

    # Continue graph exploration otherwise.
    local $obj->{active_path} = 1;    # Mark current path for loop detection.
    $obj->{distance} = $distance;
    my $max_distance = $distance;

    # Process all of the objects interfaces.
    for my $interface (@{ $obj->{interfaces} }) {

        # Skip interfaces:
        next if $interface eq $to_zone1;  # Interface where we reached this obj.
        next if $interface->{loop}; # Interface is entry of already marked loop.
        next if $interface->{main_interface};

        # Get adjacent object/node.
        my $get_next = is_router($obj) ? 'zone' : 'router';
        my $next = $interface->{$get_next};

        # Proceed with next node (distance + 2 to enable intermediate values).
        (my $max, my $loop) = setpath_obj($next, $interface, $distance + 2);
        $max_distance = $max if $max > $max_distance;

        # Process recursion stack: Node is on a loop path.
        if ($loop) {
            $interface->{loop} = $loop;
            my $loop_obj = $loop->{exit};

            # Found exit of loop in direction to zone1.
            if ($obj eq $loop_obj) {

                # Mark exit node with a different loop marker linking to itself.
                # If current loop is part of a cluster,
                # this marker will be overwritten later.
                # Otherwise this is the exit of a cluster of loops.
                $obj->{loop} ||= { exit => $obj, distance => $distance, };
            }

            # Found intermediate loop node which was marked as loop before.
            elsif (my $loop2 = $obj->{loop}) {
                if ($loop ne $loop2) {    # Node is also part of another loop.

                    # Set reference to loop object with exit closer to zone1
                    if ($loop->{distance} < $loop2->{distance}) {
                        $loop2->{redirect} = $loop;    # keep info in other loop
                        $obj->{loop}       = $loop;
                    }
                    else {
                        $loop->{redirect} = $loop2;
                    }
                }
            }

            # Found intermediate loop node.
            else {
                $obj->{loop} = $loop;
            }
        }
        else {

            # Mark loop-less path.
            $interface->{to_zone1} = $obj;
        }
    }

    # Return from recursion after all interfaces have been processed.
    if ($obj->{loop} and $obj->{loop}->{exit} ne $obj) {
        return ($max_distance, $obj->{loop});

    }
    else {
        $obj->{to_zone1} = $to_zone1;
        return $max_distance;
    }
}

################################################################################
# Purpose  : Identify clusters of directly connected loops in cactus graphs.
#            Find exit node of loop cluster or single loop in direction to
#            zone1; add this exit node as marker to all loop objects of the
#            cluster.
# Parameter: $loop: Top-level loop object (after redirection).
# Returns  : A reference to the loop cluster exit node.
sub set_loop_cluster {
    my ($loop) = @_;

    # Return loop cluster exit node, if loop has been processed before.
    if (my $marker = $loop->{cluster_exit}) {
        return $marker;
    }
    else {

        # Examine the loop object referenced in the loops exit node.
        my $exit = $loop->{exit};

        # Exit node references itself: loop cluster exit found.
        if ($exit->{loop} eq $loop) {    # Exit node references itself.

#            debug("Loop $exit->{name},$loop->{distance} is in cluster $exit->{name}");
            return $loop->{cluster_exit} = $exit;
        }

        # Exit node references another loop: proceed with next loop of cluster
        else {
            my $cluster = set_loop_cluster($exit->{loop});

#           debug("Loop $exit->{name},$loop->{distance} is in cluster $cluster->{name}");
            return $loop->{cluster_exit} = $cluster;
        }
    }
}

###############################################################################
# Purpose : Set direction and distances to an arbitrary chosen start zone.
#           Identify loops inside the graph topology, tag nodes of a
#           cycle with a common loop object and distance.
#           Check for multiple unconnected parts of topology.
sub find_dists_and_loops {
    if (not @zones) {
        fatal_err("topology seems to be empty");
    }
    my $path_routers =
        [ grep { $_->{managed} or $_->{semi_managed} } @routers ];
    my $start_distance = 0;
    my @partitions;
    my (%partition2split_crypto, %router2partition);

    # Find one or more connected partitions in whole topology.
    # Only iterate zones, because unconnected routers have been
    # rejected before.
    for my $zone (@zones) {

        # Zone is connected to some previously processed partition.
        next if $zone->{to_zone1} or $zone->{loop};

        # Chose an arbitrary node to start from.
        my $zone1 = $zone;
#        debug $zone1->{name};

        # Traverse all nodes connected to zone1.
        # Second parameter stands for not existing starting interface.
        # Value must be "false" and unequal to any interface.
        my $max = setpath_obj($zone1, '', $start_distance);

        # Use other distance values in disconnected partition.
        # Otherwise pathmark would erroneously find a path between
        # disconnected objects.
        $start_distance = $max + 1;

        # Collect zone1 of each partition.
        push @partitions, $zone1;

        # Check if split crypto parts are located inside current partition.
        # Collect remaining routers for next partititions.
        my @unconnected;
        for my $router (@$path_routers) {
            if ($router->{to_zone1} or $router->{loop}) {
                $router2partition{$router} = $zone1;
                if ($router->{orig_router}) {
                    push @{ $partition2split_crypto{$zone1} }, $router;
                }
            }
            else {
                push @unconnected, $router;
            }
        }
        $path_routers = \@unconnected;
    }

    # Check for unconnected partitions.
    # Ignore partition, that is linked to some other partition
    # by split crypto router.
    my @unconnected;
  PARTITION:
    for my $zone1 (@partitions) {
        if (my $crypto_parts = $partition2split_crypto{$zone1}) {
            for my $part (@$crypto_parts) {
                my $orig_router = $part->{orig_router};
                if (my $zone2 = $router2partition{$orig_router}) {
                    next PARTITION if $zone1 ne $zone2;
                }
            }
        }
        push @unconnected, $zone1;
    }

    for my $ipv6 (1, 0) {
        my @un = grep { not $_->{ipv6} xor $ipv6 } @unconnected;
        @un > 1 or next;
        my $ipv = $ipv6 ? 'IPv6' : 'IPv4';
        err_msg("$ipv topology has unconnected parts:\n",
                " - ",
                join "\n - ", map { $_->{name} } @un);
    }
}

###############################################################################
# Purpose : Include node objects and interfaces of nested loops in the
#           containing loop; add loop cluster exits; adjust distances of
#           loop nodes.
sub process_loops {

    # Check all nodes located inside a cyclic graph.
    my @path_routers = grep { $_->{managed} or $_->{semi_managed} } @routers;
    for my $obj (@zones, @path_routers) {
        my $loop = $obj->{loop} or next;

        # Include sub-loop nodes into containing loop with exit closest to zone1
        while (my $next = $loop->{redirect}) {

            #debug("Redirect: $loop->{exit}->{name} -> $next->{exit}->{name}");
            $loop = $next;
        }
        $obj->{loop} = $loop;

        # Mark loops with cluster exit, needed for cactus graph loop clusters.
        set_loop_cluster($loop);

        # Set distance of loop node to value of cluster exit.
        $obj->{distance} = $loop->{cluster_exit}->{distance};  # keeps loop dist
    }

    # Include sub-loop IFs into containing loop with exit closest to zone1.
    for my $router (@path_routers) {
        for my $interface (@{ $router->{interfaces} }) {
            if (my $loop = $interface->{loop}) {
                while (my $next = $loop->{redirect}) {
                    $loop = $next;
                }
                $interface->{loop} = $loop;
            }
        }
    }
}

###############################################################################
# Purpose : Add navigation information to the nodes of the graph to
#           enable fast traversal; identify loops and perform further
#           consistency checks.
sub setpath {
    progress('Preparing fast path traversal');
    find_dists_and_loops();         # Add navigation info.
    process_loops();                # Refine navigation info at loop nodes.
    check_pathrestrictions();       # Consistency checks, need {loop} attribute.
    check_virtual_interfaces();     # Consistency check, needs {loop} attribute.
    remove_redundant_pathrestrictions();
    optimize_pathrestrictions();    # Add navigation info to pathrestricted IFs.
}

####################################################################
# Efficient path traversal.
####################################################################

##############################################################################
# Purpose   : Provide path node objects for objects specified as src or dst.
# Parameter : Source or destination object from an elementary rule.
# Returns   : Reference to zone or router of the given object or reference
#             to object itself, if it is a pathrestricted interface.
# Results   : Return value for given object is stored in %obj2path lookup hash.
sub get_path {
    my ($obj) = @_;
    my $type = ref $obj;
    my $result;

    # Check whether path node of object is a zone or router.
    if ($type eq 'Network') {
        $result = $obj->{zone};
    }
    elsif ($type eq 'Subnet') {
        $result = $obj->{network}->{zone};
    }
    elsif ($type eq 'Interface') {
        my $router = $obj->{router};
        if ($router->{managed} or $router->{semi_managed}) {

            # If this is a secondary interface, we can't use it to enter
            # the router, because it has an active pathrestriction attached.
            # But it doesn't matter if we use the main interface instead.
            my $main = $obj->{main_interface} || $obj;

            # Special handling needed if $src or $dst is interface
            # which has pathrestriction attached.
            if ($main->{path_restrict} or $main->{reachable_at}) {
                $result = $main;
            }
            else {
                $result = $main->{router};
            }
        }
        else { # Unmanaged routers are part of zone objects.
            $result = $obj->{network}->{zone};
        }
    }

    # This is used, if called from path_auto_interfaces.
    elsif ($type eq 'Router') {
        if ($obj->{managed} or $obj->{semi_managed}) {
            $result = $obj;
        }
        else {
            $result = $obj->{interfaces}->[0]->{network}->{zone};
        }
    }

    # This is used, if path_walk is called from find_active_routes.
    elsif ($type eq 'Zone') {
        $result = $obj;
    }

    # This is used, if expand_services is called without convert_hosts.
    elsif ($type eq 'Host') {
        $result = $obj->{network}->{zone};
    }

    # This is used, if called from group_path_rules.
    elsif ($type eq 'Autointerface') {
        my $object = $obj->{object};
        if (is_network($object)) {

            # This will be refined later, if real interface is known.
            $result = $object->{zone};
        }
        elsif ($object->{managed} or $object->{semi_managed}) {

            # This will be refined later, if real interface has pathrestriction.
            $result = $object;
        }
        else {

            # Take arbitrary interface to find zone.
            $result = $object->{interfaces}->[0]->{network}->{zone};
        }
    }

    #debug("get_path: $obj->{name} -> $result->{name}");
    return ($obj2path{$obj} = $result);
}

##############################################################################
# Purpose    : Recursively find path through a loop or loop cluster for a
#              given pair (start, end) of loop nodes, collect path information.
# Parameters : $obj - current (or start) loop node (zone or router).
#              $in_intf - interface current loop node was entered from.
#              $end - loop node that is to be reached.
#              $path_tuples - hash to collect in and out interfaces of nodes on
#                             detected path.
#              $loop_leave - array to collect last interfaces of loop path.
#              $navi - lookup hash to reduce search space, holds loops to enter.
# Returns   :  1, if path is found, 0 otherwise.
sub cluster_path_mark1 {
    my ($obj, $in_intf, $end, $path_tuples, $loop_leave, $navi) = @_;

#    debug("cluster_path_mark1: obj: $obj->{name},
#           in_intf: $in_intf->{name} to: $end->{name}");

    # Stop path exploration when activated PR (2nd occurrence) was passed.
    my $pathrestriction = $in_intf->{path_restrict};
    if ($pathrestriction) {
        for my $restrict (@$pathrestriction) {
            if ($restrict->{active_path}) {

#               debug(" effective $restrict->{name} at $in_intf->{name}");
                return 0;
            }
        }
    }

    # Node has been visited before - return to avoid walking loops.
    if ($obj->{active_path}) {

#       debug(" active: $obj->{name}");
        return 0;
    }

    # Found a path to router or zone.
    if ($obj eq $end) {

        # Store interface where we leave the loop.
        push @$loop_leave, $in_intf;

#        debug(" leave: $in_intf->{name} -> $end->{name}");
        return 1;
    }

    # Stop exploration if optimized pathrestriction inhibits reaching end node.
    # This is not grouped with other PR checks to avoid unneccessary execution.
    if (my $reachable_at = $in_intf->{reachable_at}) {
        if (my $reachable = $reachable_at->{$obj}) {
            my $has_mark = $end->{reachable_part};
            for my $mark (@$reachable) {
                if (not $has_mark->{$mark}) {
#                   debug(" unreachable3: $end_node->{name}",
#                         " from $in_intf->{name} to $obj->{name}");
                    return 0;
                }
            }
        }
    }

    # Mark current path for loop detection.
    local $obj->{active_path} = 1;

#    debug "activated $obj->{name}";

    # Activate passed pathrestrictions.
    if ($pathrestriction) {
        for my $restrict (@$pathrestriction) {

#           debug(" enabled $restrict->{name} at $in_intf->{name}");
            $restrict->{active_path} = 1;
        }
    }

    my $is_router   = ref $obj eq 'Router';
    my $get_next    = $is_router ? 'zone' : 'router';
    my $type_tuples = $path_tuples->{$is_router ? 'router' : 'zone'};
    my $success     = 0;

    # Extract navigation lookup hash.
    my $allowed = $navi->{ $obj->{loop} }
      or internal_err("Loop with empty navigation");

    # Proceed loop path exploration with every loop interface of current node.
    for my $interface (@{ $obj->{interfaces} }) {
        my $loop = $interface->{loop} or next;
        $allowed->{$loop} or next;
        next if $interface eq $in_intf;
        my $next = $interface->{$get_next};

#        debug "Try $obj->{name} -> $next->{name}";

        # If a valid path is found from next node to $end...
        if (
            cluster_path_mark1(
                $next,        $interface,  $end,
                $path_tuples, $loop_leave, $navi
            )
          )
        {

            # ...collect path information.
#	    debug(" loop: $in_intf->{name} -> $interface->{name}");
            push @$type_tuples, [ $in_intf, $interface ];
            $success = 1;
        }
    }

    # Deactivate pathrestrictions activated on path.
#    debug "deactivated $obj->{name}";
    if ($pathrestriction) {
        for my $restrict (@$pathrestriction) {

#           debug(" disabled $restrict->{name} at $in_intf->{name}");
            $restrict->{active_path} = undef;
        }
    }
    return $success;
}

##############################################################################
# Purpose    : Optimize navigation inside a cluster of loops: For a pair
#              ($from,$to) of loop nodes, identify order of loops passed
#              on the path from $from to $to. Store information as lookup
#              hash at node $from to reduce search space when finding paths
#              from $from to $to.
# Parameters : $from, $to - loop nodes pair.
# Returns    : Hash with order/navigation information: keys = loops,
#              values = loops that may be entered next from key loop.
# Results    : $from node holds navigation hash suggesting for every loop
#              of the cluster those loops, that are allowed to be entered when
#              traversing the path to $to.
sub cluster_navigation {

    my ($from, $to) = @_;
    # debug("Navi: $from->{name}, $to->{name}");

    my $navi;
    # Return filled navi hash, if pair ($from, $to) has been processed before.
    if (($navi = $from->{navi}->{$to}) and scalar keys %$navi) {
#	debug(" Cached");
        return $navi;
    }

    # Attach navi hash to $from node object.
    $navi = $from->{navi}->{$to} = {};

    # Determine loops that are passed on path from $from to $to.
    my $from_loop = $from->{loop};
    my $to_loop   = $to->{loop};
    while (1) {

        # Loops are equal, order of loops has been detected.
        if ($from_loop eq $to_loop) {
            last if $from eq $to; # Same node, no loop path to detect.

            # Add loops that may be entered from loop during path traversal.
            $navi->{$from_loop}->{$from_loop} = 1;
#	    debug("- Eq: $from_loop->{exit}->{name}$from_loop to itself");

            # Path $from -> $to traverses $from_loop and $exit_loop.
            # Inside $exit_loop, enter only $from_loop, but not from other loops
            my $exit_loop = $from_loop->{exit}->{loop};
            $navi->{$exit_loop}->{$from_loop} = 1;


#	    debug("- Add $from_loop->{exit}->{name}$from_loop to exit $exit_loop->{exit}->{name}$exit_loop");
            last;
        }

        # Different loops, take next step from loop with higher distance.
        elsif ($from_loop->{distance} >= $to_loop->{distance}) {
            $navi->{$from_loop}->{$from_loop} = 1;

#	    debug("- Fr: $from_loop->{exit}->{name}$from_loop to itself");
            $from      = $from_loop->{exit};
            $from_loop = $from->{loop};
        }

        # Take step from to_loop.
        else {
            #debug("- To: $to_loop->{exit}->{name}$to_loop to itself");
            $navi->{$to_loop}->{$to_loop} = 1;
            $to = $to_loop->{exit};
            my $entry_loop = $to->{loop};
            $navi->{$entry_loop}->{$to_loop} = 1;

#	    debug("- Add $to_loop->{exit}->{name}$to_loop to entry $entry_loop->{exit}->{name}$entry_loop");
            $to_loop = $entry_loop;
        }
    }
    return $navi;
}

##############################################################################
# Purpose    : Adapt path starting/ending at zone, such that the original
#              start/end-interface is reached.
#              First step:
#              Remove paths, that traverse router of start/end interface,
#              but don't terminate at that router. This would lead to
#              invalid paths entering the same router two times.
#              Second step:
#              Adjust start/end of paths from zone to router.
# Parameters : $start_end: start or end interface of orginal path
#              $in_out: has value 0 or 1, to access in or out interface
#                       of paths.
#              $loop_enter, $loop_leave: arrays of interfaces,
#                                        where path starts/ends.
#              $router_tuples, $zone_tuples: arrays of path tuples.
# Returns    : nothing
# Results    : Changes $loop_enter, $loop_leave, $router_tuples, $zone_tuples.
sub fixup_zone_path {
    my ($start_end, $in_out,
        $loop_enter, $loop_leave, $router_tuples, $zone_tuples) = @_;

    my $router = $start_end->{router};
    my $is_redundancy;

    # Prohibt paths traversing related redundancy interfaces.
    if (my $interfaces = $start_end->{redundancy_interfaces}) {
        @{$is_redundancy}{@$interfaces} = @$interfaces;
    }

    my @del_tuples;

    # Remove tuples traversing that router, where path should start/end.
    for my $tuple (@$router_tuples) {
        my $intf = $tuple->[$in_out];
        if ($intf->{router} eq $router) {
            if ($intf ne $start_end) {
                push @del_tuples, $tuple;
            }
        }
        elsif ($is_redundancy and $is_redundancy->{$intf}) {
            push @del_tuples, $tuple;
        }
    }
    my $tuples = $router_tuples;
    my $changed;

    # Remove dangling tuples.
    while (@del_tuples) {
        $changed = 1;
        my (%del_in, %del_out);
        for my $tuple (@del_tuples) {
            aref_delete($tuples, $tuple);
            my ($in, $out) = @$tuple;

            # Mark interfaces of just removed tuple, because adjacent tuples
            # could become dangling now.
            $del_in{$out} = $out;
            $del_out{$in} = $in;
        }

        # Remove mark, if non removed tuples are adjacent.
        for my $tuple (@$tuples) {
            my ($in, $out) = @$tuple;
            delete $del_in{$out};
            delete $del_out{$in};
        }
        keys %del_in or keys %del_out or last;
        $tuples = ($tuples eq $router_tuples) ? $zone_tuples : $router_tuples;
        @del_tuples = ();
        for my $tuple (@$tuples) {
            my ($in, $out) = @$tuple;
            if ($del_in{$in} or $del_out{$out}) {
                push @del_tuples, $tuple;
            }
        }
    }

    # Remove dangling interfaces from start and end of path.
    if ($changed) {
        my (%has_in, %has_out);


        # First/last tuple of path is known to be part of router,
        # because path starts/ends at zone.
        # But for other side of path, we don't know if it starts at
        # router or zone; so we must check $zone_tuples also.
        for my $tuple (@$router_tuples, @$zone_tuples) {
            my ($in, $out) = @$tuple;
            $has_in{$in} = $in;
            $has_out{$out} = $out;
        }
        my @del_intf = grep { not $has_in{$_} } @$loop_enter;
        aref_delete($loop_enter, $_) for @del_intf;
        @del_intf = grep { not $has_out{$_} } @$loop_leave;
        aref_delete($loop_leave, $_) for @del_intf;
    }

    # Change start/end of paths from zone to router of original interface.
    my $is_start = ($in_out == 0);
    my $out_in = $is_start ? 1 : 0;
    my $enter_leave = $is_start ? $loop_enter : $loop_leave;
    my (@add_intf, @del_intf, $seen_intf);
    for my $intf (@$enter_leave) {
        push @del_intf, $intf;
        if ($intf eq $start_end) {
            my @del_tuples = grep { $_->[$in_out] eq $intf } @$router_tuples;
            for my $tuple (@del_tuples) {
                aref_delete $router_tuples, $tuple;
                push @add_intf, $tuple->[$out_in];
            }
        }
        else {
            push(@$zone_tuples,
                 $is_start ? [ $start_end, $intf ] : [ $intf, $start_end ]);
            push @add_intf, $start_end if not $seen_intf++;
        }
    }
    aref_delete $enter_leave, $_ for @del_intf;
    push @$enter_leave, @add_intf;
}


##############################################################################
# Purpose    : Mark path starting/ending at pathrestricted interface
#              by first marking path from/to related zone and afterwards
#              fixing found path.
# Parameters : $start_store: start node or interface
#              $end_store: end node or interface
#              $start_intf: set if path starts at pathrestricted interface
#              $end_intf: set if path ends at pathrestricted interface
# Returns    : True if path was found, false otherwise.
# Results    : Sets attributes {loop_enter}, {loop_leave}, {*_path_tuples}
#              for found path and reversed path.
sub intf_cluster_path_mark {
    my ($start_store, $end_store, $start_intf, $end_intf) = @_;
    if ($start_intf) {
        $start_store = $start_intf->{zone};
    }
    if ($end_intf) {
        $end_store = $end_intf->{zone};
    }
    my (@loop_enter, @loop_leave, @router_tuples, @zone_tuples);

    # Zones are equal. Set minimal path manually.
    if ($start_store eq $end_store
        or
        $end_store->{zone} and $end_store->{zone} eq $start_store
        or
        $start_store->{zone} and $start_store->{zone} eq $end_store
        )
    {
        if ($start_intf and $end_intf) {
            @loop_enter = ($start_intf);
            @loop_leave = ($end_intf);
            @zone_tuples = ([ $start_intf, $end_intf ]);
            $start_store = $start_intf;
            $start_intf = undef;
            $end_store = $end_intf;
        }
        elsif ($start_intf) {
            @loop_enter = ($start_intf);
            @loop_leave = ($start_intf);
            $start_store = $start_intf;
            $start_intf = undef;
        }
        else {
            @loop_enter = ($end_intf);
            @loop_leave = ($end_intf);
            $end_store = $end_intf;
        }
    }

    # Mark cluster path between different zones.
    else {
        cluster_path_mark($start_store, $end_store) or return;

        @loop_enter    = @{ $start_store->{loop_enter}->{$end_store} };
        @loop_leave    = @{ $start_store->{loop_leave}->{$end_store} };
        @router_tuples = @{ $start_store->{router_path_tuples}->{$end_store} };
        @zone_tuples   = @{ $start_store->{zone_path_tuples}->{$end_store} };

        # Fixup start of path.
        if ($start_intf) {
            fixup_zone_path($start_intf, 0,
                            \@loop_enter, \@loop_leave,
                            \@router_tuples, \@zone_tuples);
            $start_store = $start_intf;
        }

        # Fixup end of path.
        if ($end_intf) {
            fixup_zone_path($end_intf, 1,
                            \@loop_enter, \@loop_leave,
                            \@router_tuples, \@zone_tuples);

            $end_store = $end_intf;
        }
    }

    # Store found path.
    $start_store->{loop_enter}->{$end_store}  = \@loop_enter;
    $start_store->{loop_leave}->{$end_store}  = \@loop_leave;
    $start_store->{router_path_tuples}->{$end_store} = \@router_tuples;
    $start_store->{zone_path_tuples}->{$end_store} = \@zone_tuples;

    # Don't store reversed path, because few path start at interface.
#    $end_store->{loop_enter}->{$start_store} = \@loop_leave;
#    $end_store->{loop_leave}->{$start_store} = \@loop_enter;
#    $end_store->{router_path_tuples}->{$start_store} =
#        [ map { [ @{$_}[1, 0] ] } @router_tuples ];
#    $end_store->{zone_path_tuples}->{$start_store} =
#        [ map { [ @{$_}[1, 0] ] } @zone_tuples ];

    return 1;
}
##############################################################################
# Purpose    : Collect path information through a loop for a pair of
#              loop nodes (zone or router).
#              Store it at the object where loop paths begins.
# Parameters : $start_store - source loop node or interface, if source
#                             is a pathrestricted interface of loop.
#              $end_store - destination loop node or interface, if destination
#                           is a pathrestricted interface of loop.
# Returns    : True if a valid path was found, false otherwise.
# Results    : Loop entering interface holds reference to where loop path
#              information is stored.
#              (Starting or ending at pathrestricted interface may lead
#               to different paths than for a simple node).
#              Referenced object holds loop path description.
sub cluster_path_mark {
    my ($start_store, $end_store) = @_;

    # Path from $start_store to $end_store has been marked already.
    if ($start_store->{loop_enter}->{$end_store}) {
        return 1;
    }

    # Entry and exit nodes inside loop.
    my ($from, $to);

    # Set variables, if path starts/ends at pathrestricted interface
    # inside of loop.
    my ($start_intf, $end_intf);

    # Set variables, if path starts or enters loop at pathrestricted
    # interface at border of loop.
    # If path starts/ends, corresponding loop node is always a router,
    # because zones case has been transformed before.
    my ($from_in, $to_out);

    if (my $router = $start_store->{router}) {
        if ($start_store->{loop}) {
            $start_intf = $start_store;
            $from       = $router;
        }
        else {
            $from_in = $start_store;
            $from =    $start_store->{loop_zone_border} && $start_store->{zone}
                    || $router;
        }
    }
    else {
        $from = $start_store;
    }
    if (my $router = $end_store->{router}) {
        if ($end_store->{loop}) {
            $end_intf = $end_store;
            $to       = $router;
        }
        else {
            $to_out = $end_store;
            $to =     $end_store->{loop_zone_border} && $end_store->{zone}
                   || $router;
        }
    }
    else {
        $to = $end_store;
    }

    if ($start_intf or $end_intf) {
        return intf_cluster_path_mark($start_store, $end_store,
                                      $start_intf, $end_intf);
    }

#    debug("cluster_path_mark: $start_store->{name} -> $end_store->{name}");
#    debug(" $from->{name} -> $to->{name}");
    my $success         = 1;
    my $from_interfaces = $from->{interfaces};

    # Activate pathrestriction at border of loop.
    for my $intf ($from_in, $to_out) {
        if (    $intf
            and (my $restrictions = $intf->{path_restrict}))
        {
            for my $restrict (@$restrictions) {

                # No path possible, if restriction has been just
                # activated at other side of loop.
                if ($restrict->{active_path}) {
                    $success = 0;
                }
                $restrict->{active_path} = 1;
            }
        }
    }

  # Check whether valid paths are possible due to optimized pathrestrictions.
  REACHABLE:
    {

        # Check, whether enter-interface has optimized pathrestriction.
        $from_in or last REACHABLE;
        my $reachable_at = $from_in->{reachable_at} or last REACHABLE;

        # Check, whether end node is reachable from enter-/start-interface.
        # For enter-interfaces, just the direction towards loop is of interest,
        # for start-interfaces, pathrestrictions in zone direction do not hold,
        # hence check router direction only.
        # Only one direction needs to be checked in both cases.
        my $reachable = $reachable_at->{$from} or last REACHABLE;
        my $has_mark  = $to->{reachable_part};
        for my $mark (@$reachable) {

            # End node is not reachable via enter-interface.
            if (not $has_mark->{$mark}) {
                $success = 0;
                last;
            }
        }
    } # end REACHABLE

    # Check whether valid paths are possible due to optimized pathrestriction
    # at outgoing interface at border of loop
  REACHABLE_TO_OUT:
    {

        # Check, whether start node is reachable from exit-interface.
        # For exit-interface, just the direction towards loop is of interest.
        $to_out or last REACHABLE_TO_OUT;
        my $reachable_at = $to_out->{reachable_at} or last REACHABLE_TO_OUT;
        my $reachable    = $reachable_at->{$to} or last REACHABLE_TO_OUT;
        my $has_mark     = $from->{reachable_part};
        for my $mark (@$reachable) {

            # Start node is not reachable via exit-interface.
            if (not $has_mark->{$mark}) {
                $success = 0;
                last;
            }
        }
    } # end REACHABLE_TO_OUT

  # Find loop paths via depth first search.
  BLOCK:
    {
        last BLOCK if not $success; # No valid path due to pathrestrictions.
        $success = 0;

        # Create variables to store the loop path.
        my $loop_enter  = []; # Interfaces of $from, where path enters cluster.
        my $loop_leave  = []; # Interfaces of $to, where cluster is left.

        # Tuples of interfaces, describing all valid paths.
        my $path_tuples = { router => [], zone => [] };

        # Create navigation look up hash to reduce search space in loop cluster.
        my $navi = cluster_navigation($from, $to) or internal_err("Empty navi");

        # Mark current path for loop detection.
        local $from->{active_path} = 1;
        my $get_next = is_router($from) ? 'zone' : 'router';
        my $allowed = $navi->{ $from->{loop} };
        # uncoverable branch true
        if (not $allowed) {
            # uncoverable statement
            internal_err("Loop $from->{loop}->{exit}->{name}$from->{loop}",
                         " with empty navi\n",
                         "Path: $start_store->{name} -> $end_store->{name}");
        }

        # To find paths, process every loop interface of $from node.
        for my $interface (@$from_interfaces) {
            my $loop = $interface->{loop} or next;

            # Skip interfaces that will not lead to a path....
            if (not $allowed->{$loop}) { #  ...nodes not included in navi.
#		debug("No: $loop->{exit}->{name}$loop");
                next;
            }
            next if ($interface->{loopback} # ...networks connecting virtual
                     and $get_next eq 'zone');# loopback interfaces.

            # Extract adjacent node (= next node on path).
            my $next = $interface->{$get_next};

            # Search path from next node to $to, store it in provided variables.
#           debug(" try: $from->{name} -> $interface->{name}");
            if (
                cluster_path_mark1(
                    $next,        $interface,  $to,
                    $path_tuples, $loop_leave, $navi
                )
              )
            {
                $success = 1;
                push @$loop_enter, $interface;

#               debug(" enter: $from->{name} -> $interface->{name}");
            }
        }

        # Don't store incomplete result.
        last BLOCK if not $success;

        # Remove duplicates from path tuples.
        # Create path tuples for
        # router interfaces, zone interfaces, and both as reversed arrays.
        my (@router_tuples, @zone_tuples,
            @rev_router_tuples, @rev_zone_tuples);
        for my $type (keys %$path_tuples) {
            my $tuples = $type eq 'router' ? \@router_tuples : \@zone_tuples;
            my $rev_tuples =
                $type eq 'router' ? \@rev_router_tuples : \@rev_zone_tuples;
            my %seen;
            for my $tuple (@{ $path_tuples->{$type} }) {
                my ($in_intf, $out_intf) = @$tuple;
                next if $seen{$in_intf}->{$out_intf}++;
                push @$tuples, $tuple;
                push @$rev_tuples, [ $out_intf, $in_intf ];
#		debug("Tuple: $in_intf->{name}, $out_intf->{name} $type");
            }
        }

        # Remove duplicates, which occur from nested loops.
        $loop_leave = [ unique(@$loop_leave) ];

        # Add loop path information to start node or interface.
        $start_store->{loop_enter}->{$end_store}  = $loop_enter;
        $start_store->{loop_leave}->{$end_store}  = $loop_leave;
        $start_store->{router_path_tuples}->{$end_store} = \@router_tuples;
        $start_store->{zone_path_tuples}->{$end_store} = \@zone_tuples;

        # Add data for reverse path.
        $end_store->{loop_enter}->{$start_store} = $loop_leave;
        $end_store->{loop_leave}->{$start_store} = $loop_enter;
        $end_store->{router_path_tuples}->{$start_store} = \@rev_router_tuples;
        $end_store->{zone_path_tuples}->{$start_store} = \@rev_zone_tuples;
    }

    # Disable pathrestriction at border of loop.
    for my $intf ($from_in, $to_out) {
        if (    $intf
            and (my $restrictions = $intf->{path_restrict}))
        {
            for my $restrict (@$restrictions) {
                $restrict->{active_path} = 0;
            }
        }
    }

    return $success;
}

sub connect_cluster_path {
    my ($from, $to, $from_in, $to_out, $from_store, $to_store) = @_;

    # Find objects to store path information inside loop.
    # Path may differ depending on whether loop entering and exiting
    # interfaces are pathrestricted or not. Storing path information
    # in different objects respects this.
    my ($start_store, $end_store);

    # Don't set $from_in if we are about to enter a loop at zone,
    # because pathrestriction at $from_in must not be activated.
    if ($from_in and $from_in eq $from_store and
        $from_store->{loop_zone_border})
    {
        $from_in = undef;
    }
    if ($to_out and $to_out eq $to_store and $to_store->{loop_zone_border}) {
        $to_out = undef;
    }

    # Path starts at pathrestricted interface inside or at border of
    # current loop.
    # Set flag, if path starts at interface of zone at border of loop.
    my $start_at_zone;
    if (not $from_in and is_interface($from_store)) {

        # Path starts at border of current loop at zone node.
        # Pathrestriction must not be activated, hence use zone as
        # $start_store.
        if ($from_store->{loop_zone_border}) {
            $start_store = $from_store->{zone};
            $start_at_zone = 1;
        }

        # Path starts inside or at border of current loop at router node.
        else {
            $start_store = $from_store;
        }
    }

    # Loop is entered at pathrestricted interface.
    elsif ($from_in and ($from_in->{path_restrict} or $from_in->{reachable_at}))
    {
        $start_store = $from_in;
    }

    # Loop starts or is entered at $from node; no pathrestriction is effective.
    else {
        $start_store = $from;
    }

    # Set $end_store with same logic that is used for $start_store.
    if (not $to_out and is_interface($to_store)) {
        if ($to_store->{loop_zone_border}) {
            $end_store = $to_store->{zone};

            # Path ends at interface of zone at border of loop.
            # Continue path to router of interface outside of loop.
            $to_out = $to_store;
        }
        else {
            $end_store = $to_store;
        }
    }
    elsif ($to_out and ($to_out->{path_restrict} or $to_out->{reachable_at})) {
        $end_store = $to_out;
    }
    else {
        $end_store = $to;
    }

    my $success = cluster_path_mark($start_store, $end_store);

    # If loop path was found, set path information for $from_in and
    # $to_out interfaces and connect them with loop path.
    if ($success) {

        my $path_attr  = $from_in || $start_at_zone ? 'path' : 'path1';
        my $path_store = $from_in || $from_store;
        $path_store->{$path_attr}->{$to_store} = $to_out;

#        debug "loop $path_attr: $path_store->{name} -> $to_store->{name}";
        # Collect path information at beginning of loop path ($start_store).
        # Loop paths beginning at loop node can differ depending on the way
        # the node is entered (interface with/without pathrestriction,
        # pathrestricted src/dst interface), requiring storing path
        # information at different objects.
        # Path information is stored at {loop_entry} attribute.
        my $entry_attr = $start_at_zone ? 'loop_entry_zone' : 'loop_entry';
        $path_store->{$entry_attr}->{$to_store} = $start_store;
        $start_store->{loop_exit}->{$to_store} = $end_store;
    }

    return $success;
}

##############################################################################
# Purpose   : Find and mark path from source to destination.
# Parameter : $from_store - Object, where path starts.
#             $to_store   - Objects, where path ends
#             Typically both are of type zone or router.
#             For details see description of sub path_walk.
# Returns   : True if valid path is found, False otherwise.
# Results   : The next interface towards $to_store is stored in attribute
#             - {path1} of $from_store and
#             - {path} of subsequent interfaces on path.
sub path_mark {
    my ($from_store, $to_store) = @_;

#   debug("path_mark $from_store->{name} --> $to_store->{name}");
    my $from = $from_store->{router} || $from_store;
    my $to   = $to_store->{router} || $to_store;
    my $from_loop = $from->{loop};
    my $to_loop   = $to->{loop};

    # No subsequent interface before first and behind last node on path.
    my $from_in = undef;
    my $to_out  = undef;

    # Follow paths from source and destination towards zone1 until they meet.
    while (1) {

        #debug("Dist: $from->{distance} $from->{name} -> ",
        #      "Dist: $to->{distance} $to->{name}");

        # Paths meet outside a loop or at the edge of a loop.
        if ($from eq $to) {

            # We need to distinguish between {path1} and {path} for
            # the case, where $from_store is a pathrestricted
            # interface I of zone at border of loop. In this case, the
            # next interface is interface I again.
            if ($from_in) {
                $from_in->{path}->{$to_store} = $to_out;
            }
            else {
                $from_store->{path1}->{$to_store} = $to_out;
            }
            return 1;
        }

        # Paths meet inside a loop.
        if (    $from_loop
            and $to_loop
            and $from_loop->{cluster_exit} eq $to_loop->{cluster_exit})
        {
            return connect_cluster_path($from, $to, $from_in, $to_out,
                                        $from_store, $to_store);
        }

        # Otherwise, take a step towards zone1 from the more distant node.
        if ($from->{distance} >= $to->{distance}) { # Take step from node $from.

            # Return, if mark has already been set for a sub-path.
            return 1 if $from_in and $from_in->{path}->{$to_store};

            # Get interface towards zone1.
            my $from_out = $from->{to_zone1};

            # If $from is a loop node, mark whole loop path within this step.
            unless ($from_out) {

                # Reached border of graph partition.
                $from_loop or return 0;

                # Get next interface behind loop from loop cluster exit.
                my $exit = $from_loop->{cluster_exit};
                $from_out = $exit->{to_zone1};

                # Reached border of graph partition.
                $from_out or return 0;

                # Mark loop path towards next interface.
                connect_cluster_path($from, $exit, $from_in, $from_out,
                                     $from_store, $to_store)
                  or return 0;
            }

            # Mark path at the interface we came from (step in path direction)
#           debug('pAth: ', $from_in ? $from_in->{name}:'', "$from_store->{name} -> $from_out->{name}");
            if ($from_in) {
                $from_in->{path}->{$to_store} = $from_out;
            }
            else {
                $from_store->{path1}->{$to_store} = $from_out;
            }
            $from      = $from_out->{to_zone1};
            $from_loop = $from->{loop};

            # Go to next node towards zone1.
            $from_in = $from_out;
        }

        # Take step towards zone1 from node $to (backwards on path).
        else {

            # Get interface towards zone1.
            my $to_in = $to->{to_zone1};

            # If $to is a loop node, mark whole loop path within this step.
            unless ($to_in) {

                # Reached border of graph partition.
                $to_loop or return 0;

                # Get next interface behind loop from loop cluster exit.
                my $entry = $to_loop->{cluster_exit};
                $to_in = $entry->{to_zone1};

                # Reached border of graph partition.
                $to_in or return 0;

                # Mark loop path towards next interface.
                connect_cluster_path($entry, $to, $to_in, $to_out,
                                     $from_store, $to_store)
                  or return 0;
            }

            # Mark path at interface we go to (step in opposite path direction).
#           debug("path: $to_in->{name} -> $to_store->{name}".($to_out ? $to_out->{name}:''));
            $to_in->{path}->{$to_store} = $to_out;
            $to = $to_in->{to_zone1};
            $to_loop = $to->{loop};

            # Go to next node towards zone1.
            $to_out  = $to_in;
        }
    }
}

##############################################################################
# Purpose :    Walk loop section of a path from a rules source to its
#              destination. Apply given function to every zone or router
#              on loop path.
# Parameters : $in - interface the loop is entered at.
#              $out - interface loop is left at.
#              $loop_entry - entry object, holding path information.
#              $loop_exit - loop exit node.
#              $call_at_zone - flag for node function is to be called at
#                              (1 - zone. 0 - router)
#              $rule - elementary rule providing source and destination.
#              $fun - Function to be applied.

sub loop_path_walk {
    my ($in, $out, $loop_entry, $loop_exit, $call_at_zone, $rule, $fun) = @_;

#    my $info = "loop_path_walk: ";
#    $info .= "$in->{name}->" if $in;
#    $info .= "$loop_entry->{name}=>$loop_exit->{name}";
#    $info .= "->$out->{name}" if $out;
#    debug($info);

    # Process entry of cyclic graph.
    my $entry_type = ref $loop_entry;
    if (
        (
            $entry_type eq 'Router'
            or

            # $loop_entry is interface with pathrestriction of original
            # loop_entry.
            $entry_type eq 'Interface'
            and

            # Take only interface which originally was a router.
            $loop_entry->{router} eq
            $loop_entry->{loop_enter}->{$loop_exit}->[0]->{router}
        ) xor $call_at_zone
      )
    {

#        debug(" loop_enter");
        for my $out_intf (@{ $loop_entry->{loop_enter}->{$loop_exit} }) {
            $fun->($rule, $in, $out_intf);
        }
    }

    # Process paths inside cyclic graph.
    my $path_tuples =
        $loop_entry
        ->{$call_at_zone ? 'zone_path_tuples' : 'router_path_tuples'}
        ->{$loop_exit};

#    debug(" loop_tuples");
    $fun->($rule, @$_) for @$path_tuples;

    # Process paths at exit of cyclic graph.
    my $exit_type = ref $loop_exit;
    my $exit_at_router =
        $exit_type eq 'Router'
        ||
        ($exit_type eq 'Interface'
        &&
         $loop_exit->{router} eq
         $loop_entry->{loop_leave}->{$loop_exit}->[0]->{router});
    if ($exit_at_router xor $call_at_zone) {

#        debug(" loop_leave");
        for my $in_intf (@{ $loop_entry->{loop_leave}->{$loop_exit} }) {
            $fun->($rule, $in_intf, $out);
        }
    }
    return $exit_at_router;
}

##############################################################################
# Purpose    : For a given rule, visit every node on path from rules source
#              to its destination. At every second node (every router or
#              every zone node) call given function.
# Parameters : $rule - rule object.
#              $fun - function to be called.
#              $where - 'Router' or 'Zone', specifies where the function gets
#              called, default is 'Router'.
sub path_walk {
    my ($rule, $fun, $where) = @_;

    # Extract path store objects (zone/router/pathrestricted interface).
    # These are typically zone or router objects:
    # - zone object for network or host,
    # - router object for interface without pathrestriction.
    # But for interface with pathrestriction, we may get different
    # paths for interfaces of the same router.
    # Hence we can't use the router but use interface object for
    # interface with pathrestriction.
    my ($from_store, $to_store) = @{$rule}{qw(src_path dst_path)};

#    debug(print_rule $rule);
#    debug(" start: $from_store->{name}, $to_store->{name}",
#          $where?", at $where":'');
#    my $fun2 = $fun;
#    $fun = sub  {
#       my($rule, $in, $out) = @_;
#       my $in_name = $in?$in->{name}:'-';
#       my $out_name = $out?$out->{name}:'-';
#       debug(" Walk: $in_name, $out_name");
#       $fun2->(@_);
#    };

    # Identify path from source to destination if not known.
    if (not exists $from_store->{path1}->{$to_store}) {
        if (not path_mark($from_store, $to_store)) {

            # Abort, if path does not exist.
            err_msg(
                "No valid path\n",
                " from $from_store->{name}\n",
                " to $to_store->{name}\n",
                " for rule ",
                print_rule($rule),
                "\n",
                " Check path restrictions and crypto interfaces."
            );
            delete $from_store->{path1}->{$to_store};
            return;
        }
    }

    # If path store is a pathrestricted interface, extract router.
    my $from = $from_store->{router} || $from_store;

    # Set flag whether to call function at first node visited (in 1.iteration)
    my $at_zone = $where && $where eq 'Zone'; # 1, if func is called at zones.
    my $call_it = (is_router($from) xor $at_zone); # Set switch accordingly.

    my $in = undef;
    my $out = $from_store->{path1}->{$to_store};
    my ($entry_hash, $loop_entry);

    # Path starts inside or at border of cyclic graph.
    #
    # Special case: Path starts at pathrestricted interface of
    # zone at border of loop and hence this pathrestriction will
    # not be activated. Use attribute loop_entry_zone, to find correct
    # path in loop.
    if (    $entry_hash = $from_store->{loop_entry_zone}
        and $loop_entry = $entry_hash->{$to_store}) {

        # Walk path starting at router outside of loop.
        $fun->($rule, undef, $from_store) if $call_it;
        $in = $from_store;
        $out = $from_store->{path}->{$to_store};
    }

    # Otherwise use attribute loop_entry, to find possibly
    # pathrestricted path in loop.
    elsif ($entry_hash = $from_store->{loop_entry}) {
        $loop_entry = $entry_hash->{$to_store};
    }

    # Walk loop path.
    if ($loop_entry)  {
        my $loop_exit = $loop_entry->{loop_exit}->{$to_store};
        my $exit_at_router =
          loop_path_walk($in, $out, $loop_entry, $loop_exit, $at_zone,
                         $rule, $fun);

        # Return, if end of path has been reached.
        $in      = $out or return;

        # Prepare to traverse path behind loop.
        $out     = $in->{path}->{$to_store};
        $call_it = not($exit_at_router xor $at_zone);
    }

    # Start walking path.
    while (1) {

        # Path continues with loop: walk whole loop path in this iteration step.
        if (    $in
            and $entry_hash = $in->{loop_entry}
            and $loop_entry = $entry_hash->{$to_store})
        {
            my $loop_exit = $loop_entry->{loop_exit}->{$to_store};
            my $exit_at_router = # last node of loop is a router ? 1 : 0
              loop_path_walk($in, $out, $loop_entry, $loop_exit,
                             $at_zone, $rule, $fun);

            # Prepare next iteration step.
            $call_it = ($exit_at_router xor $at_zone);
        }

        # Non-loop path continues - call function, if switch is set.
        elsif ($call_it) {
            $fun->($rule, $in, $out);
        }

        # Return, if end of path has been reached.
        $in      = $out or return;

        # Prepare next iteration otherwise.
        $out     = $in->{path}->{$to_store};
        $call_it = !$call_it;
    }
}

sub single_path_walk {
    my ($rule, $fun, $where) = @_;
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    $rule->{src_path} = $obj2path{$src} || get_path($src);
    $rule->{dst_path} = $obj2path{$dst} || get_path($dst);
    return path_walk($rule, $fun, $where);
}

my %border2obj2auto;

sub set_auto_intf_from_border {
    my ($border) = @_;
    my $reach_from_border = sub {
        my ($network, $in_intf, $result) = @_;
        push @{ $result->{$network} }, $in_intf;

#        debug "$network->{name}: $in_intf->{name}";
        for my $interface (@{ $network->{interfaces} }) {
            next if $interface eq $in_intf;
            next if $interface->{zone};
            next if $interface->{orig_main};
            my $router = $interface->{router};
            next if $router->{active_path};
            local $router->{active_path} = 1;
            push @{ $result->{$router} }, $interface;

#            debug "$router->{name}: $interface->{name}";

            for my $out_intf (@{ $router->{interfaces} }) {
                next if $out_intf eq $interface;
                next if $out_intf->{orig_main};
                my $out_net = $out_intf->{network};
                __SUB__->($out_net, $out_intf, $result);
            }
        }
    };
    my $result = {};
    $reach_from_border->($border->{network}, $border, $result);
    for my $aref (values %$result) {
        $aref = [ unique @$aref ];
    }
    $border2obj2auto{$border} = $result;
}

# Find auto interface inside zone.
# $border is interface at border of zone.
# $src2 is unmanaged router or network inside zone.
sub auto_intf_in_zone {
    my ($border, $src2) = @_;
    if (not $border2obj2auto{$border}) {
        set_auto_intf_from_border($border);
    }
    return @{ $border2obj2auto{$border}->{$src2} };
}

sub add_pathresticted_interfaces {
    my ($path, $obj) = @_;
    is_router($obj) or return ($path);
    my @interfaces = get_intf($obj);
    return ($path,
            grep { $_->{path_restrict} or $_->{reachable_at} } @interfaces);
}

# $src is an auto_interface or router.
# Result is the set of interfaces of $src located at direction to $dst.
sub path_auto_interfaces {
    my ($src, $dst) = @_;
    my ($src2, $managed) =
      is_autointerface($src)
      ? @{$src}{ 'object', 'managed' }
      : ($src, undef);
    my $dst2 = is_autointerface($dst) ? $dst->{object} : $dst;

    my $src_path = $obj2path{$src2} || get_path($src2);
    my $dst_path = $obj2path{$dst2} || get_path($dst2);
    return if $src_path eq $dst_path;

    # Check path separately for interfaces with pathrestriction,
    # because path from inside the router to destination may be restricted.
    my @from_list = add_pathresticted_interfaces($src_path, $src2);
    my @to_list   = add_pathresticted_interfaces($dst_path, $dst2);
    my @result;
    for my $from_store (@from_list) {
        for my $to_store (@to_list) {
            if (not $from_store->{path1}->{$to_store}) {
                if (not path_mark($from_store, $to_store)) {
                    delete $from_store->{path1}->{$to_store};
                    next;
                }
            }
            my $type = ref $from_store;
            if ($from_store->{loop_entry_zone} and
                $from_store->{loop_entry_zone}->{$to_store})
            {
                push @result, $from_store;
            }
            elsif ($from_store->{loop_entry} and
                my $entry = $from_store->{loop_entry}->{$to_store})
            {
                my $exit  = $entry->{loop_exit}->{$to_store};
                my $enter = $entry->{loop_enter}->{$exit};
                if ($type eq 'Zone') {
                    push @result, map { auto_intf_in_zone($_, $src2) } @$enter;
                }
                elsif ($type eq 'Router') {
                    push @result, @$enter;
                }

                # $type eq 'Interface'
                # Path is only ok, if it doesn't traverse
                # corrensponding router.
                # Path starts inside loop.
                # Check if some path doesn't traverse current router.
                # Then interface is ok as [auto] interface.
                elsif ($from_store->{loop}) {
                    if (grep { $_ eq $from_store } @$enter) {
                        push @result, $from_store;
                    }
                }
            }
            else {
                my $next = $from_store->{path1}->{$to_store};
                if ($type eq 'Zone') {
                    push @result, auto_intf_in_zone($next, $src2);
                }
                elsif ($type eq 'Router') {
                    push @result, $next;
                }

                # else
                # $type eq 'Interface'
                # Interface with pathrestriction at border of loop,
                # wont get additional path.
            }
        }
    }
    if (not @result) {
        err_msg(
            "No valid path\n",
            " from $src_path->{name}\n",
            " to $dst_path->{name}\n",
            " while resolving $src->{name}",
            " (destination is $dst->{name}).\n",
            " Check path restrictions and crypto interfaces."
            );
        return;
    }
    @result = grep { $_->{ip} ne 'tunnel' } unique @result;

    my $bridged_count = 0;
    for my $interface (@result) {

        # If device has virtual interface, main and virtual interface
        # are swapped.  Swap it back here because we need the
        # original main interface if an interface is used in a rule.
        if (my $orig = $interface->{orig_main}) {
            $interface = $orig;
        }

        # Change bridge interface to layer3 interface.
        # Prevent duplicate layer3 interface.
        elsif (my $layer3_intf = $interface->{layer3_interface}) {
            $interface = $layer3_intf;
            $bridged_count++;
        }
    }
    if ($bridged_count > 1) {
        @result = unique(@result);
    }

#    debug("$src2->{name}.[auto] = ", join ',', map {$_->{name}} @result);
    return ($managed ? grep { $_->{router}->{managed} } @result : @result);
}

########################################################################
# Handling of crypto tunnels.
########################################################################

sub link_ipsec {
    for my $ipsec (values %ipsec) {

        # Convert name of ISAKMP definition to object with ISAKMP definition.
        my ($type, $name) = @{ $ipsec->{key_exchange} };
        if ($type eq 'isakmp') {
            my $isakmp = $isakmp{$name}
              or err_msg "Can't resolve reference to $type:$name",
              " for $ipsec->{name}";
            $ipsec->{key_exchange} = $isakmp;
        }
        else {
            err_msg("Unknown key_exchange type '$type' for $ipsec->{name}");
        }
    }
}

sub link_crypto {
    for my $crypto (values %crypto) {
        my $name = $crypto->{name};

        # Convert name of IPSec definition to object with IPSec definition.
        my ($type, $name2) = @{ $crypto->{type} };

        if ($type eq 'ipsec') {
            my $ipsec = $ipsec{$name2}
              or err_msg "Can't resolve reference to $type:$name2",
              " for $name";
            $crypto->{type} = $ipsec;
        }
        else {
            err_msg("Unknown type '$type' for $name");
        }
    }
}

# Generate rules to permit crypto traffic between tunnel endpoints.
sub gen_tunnel_rules {
    my ($intf1, $intf2, $ipsec) = @_;
    my $use_ah = $ipsec->{ah};
    my $use_esp = $ipsec->{esp_authentication} || $ipsec->{esp_encryption};
    my $nat_traversal = $ipsec->{key_exchange}->{nat_traversal};

    my $src_path = $obj2path{$intf1} || get_path($intf1);
    my $dst_path = $obj2path{$intf2} || get_path($intf2);
    my @rules;
    my $rule = { src => [ $intf1 ], dst => [ $intf2 ],
                 src_path => $src_path, dst_path => $dst_path };
    if (not $nat_traversal or $nat_traversal ne 'on') {
        my @prt;
        $use_ah  and push @prt, $prt_ah;
        $use_esp and push @prt, $prt_esp;
        if (@prt) {
            push @rules, { %$rule, prt => \@prt };
        }
        push @rules,
          {
            %$rule,
            src_range => $prt_ike->{src_range},
            prt       => [ $prt_ike->{dst_range} ]
          };
    }
    if ($nat_traversal) {
        push @rules,
          {
            %$rule,
            src_range => $prt_natt->{src_range},
            prt       => [ $prt_natt->{dst_range} ]
          };
    }
    return \@rules;
}

# Link tunnel networks with tunnel hubs.
# ToDo: Are tunnels between different private contexts allowed?
sub link_tunnels {

    my %hub_seen;
    for my $crypto (sort by_name values %crypto) {
        my $name        = $crypto->{name};
        my $private     = $crypto->{private};
        my $real_hub    = delete $crypto2hub{$name};
        my $real_spokes = delete $crypto2spokes{$name};
        if (not $real_hub or $real_hub->{disabled}) {
            warn_msg("No hub has been defined for $name");
            next;
        }
        $real_spokes = [ grep { not $_->{disabled} } @$real_spokes ];
        @$real_spokes
          or warn_msg("No spokes have been defined for $name");

        my $isakmp  = $crypto->{type}->{key_exchange};
        my $need_id = $isakmp->{authentication} eq 'rsasig';

        # Substitute crypto name by crypto object.
        for my $crypto_name (@{ $real_hub->{hub} }) {
            $crypto_name eq $name and $crypto_name = $crypto;
        }

        # Note: Crypto router is split internally into two nodes.
        # Typically we get get a node with only a single crypto interface.
        # Take original router with cleartext interface(s).
        my $router = $real_hub->{router};
        if (my $orig_router = $router->{orig_router}) {
            $router = $orig_router;
        }
        my $model = $router->{model};

        # Router of type {do_auth} can only check certificates,
        # not pre-shared keys.
        if ($model->{do_auth} and not $need_id) {
            err_msg("$router->{name} needs authentication=rsasig",
                    " in $isakmp->{name}");
        }

        if ($model->{crypto} eq 'EZVPN') {
            err_msg("Must not use $router->{name} of model '$model->{name}'",
                    " as crypto hub");
        }

        push @managed_crypto_hubs, $router if not $hub_seen{$router}++;

        # Generate a single tunnel from each spoke to single hub.
        for my $spoke_net (@$real_spokes) {
            (my $net_name = $spoke_net->{name}) =~ s/network://;
            push @{ $crypto->{tunnels} }, $spoke_net;
            my $spoke = $spoke_net->{interfaces}->[0];
            $spoke->{crypto} = $crypto;
            my $real_spoke = $spoke->{real_interface};
            $real_spoke->{spoke} = $crypto;

            my $hardware = $real_hub->{hardware};
            (my $intf_name = $real_hub->{name}) =~ s/\..*$/.$net_name/;
            my $hub = new(
                'Interface',
                name   => $intf_name,
                ip     => 'tunnel',
                crypto => $crypto,

                # Attention: shared hardware between router and orig_router.
                hardware       => $hardware,
                is_hub         => 1,
                real_interface => $real_hub,
                router         => $router,
                network        => $spoke_net
            );
            $hub->{bind_nat} = $real_hub->{bind_nat} if $real_hub->{bind_nat};
            $hub->{routing}  = $real_hub->{routing}  if $real_hub->{routing};
            $hub->{peer}     = $spoke;
            $spoke->{peer}   = $hub;
            push @{ $router->{interfaces} },    $hub;
            push @{ $hardware->{interfaces} },  $hub;
            push @{ $spoke_net->{interfaces} }, $hub;

            # We need hub also be available in orig_interfaces.
            if (my $aref = $router->{orig_interfaces}) {
                push @$aref, $hub;
            }

            if ($real_spoke->{ip} =~ /^(?:negotiated|short|unnumbered)$/) {
                if (not($model->{do_auth} or $model->{can_dyn_crypto})) {
                    err_msg "$router->{name} can't establish crypto",
                      " tunnel to $real_spoke->{name} with unknown IP";
                }
            }

            if ($private) {
                my $s_p = $real_spoke->{private};
                my $h_p = $real_hub->{private};
                $s_p and $s_p eq $private
                  or $h_p and $h_p eq $private
                  or err_msg
                  "Tunnel $real_spoke->{name} to $real_hub->{name}",
                  " of $private $name",
                  " must reference at least one object",
                  " out of $private";
            }
            else {
                $real_spoke->{private}
                  and err_msg "Tunnel of public $name must not",
                  " reference $real_spoke->{name} of",
                  " $real_spoke->{private}";
                $real_hub->{private}
                  and err_msg "Tunnel of public $name must not",
                  " reference $real_hub->{name} of",
                  " $real_hub->{private}";
            }

            my $spoke_router = $spoke->{router};
            my @other;
            my $has_id_hosts;
            for my $interface (@{ $spoke_router->{interfaces} }) {
                my $network = $interface->{network};
                if ($network->{has_id_hosts}) {
                    $has_id_hosts = $network;
                }
                elsif ($interface->{ip} ne 'tunnel') {
                    push @other, $interface;
                }
            }
            if ($has_id_hosts and @other) {
                err_msg("Must not use $has_id_hosts->{name} with ID hosts",
                        " together with networks having no ID host:\n",
                        name_list(\@other));
            }

            if ($spoke_router->{managed} and $crypto->{detailed_crypto_acl}) {
                err_msg(
                    "Attribute 'detailed_crypto_acl' is not",
                    " allowed for managed spoke $spoke_router->{name}"
                );
            }
        }
    }

    # Check for undefined crypto references.
    for my $crypto (keys %crypto2hub) {
        my $interface = $crypto2hub{$crypto};
        err_msg("$interface->{name} references unknown $crypto");
    }
    for my $crypto (keys %crypto2spokes) {
        for my $network (@{ $crypto2spokes{$crypto} }) {
            my $interface = $network->{interfaces}->[0]->{real_interface};
            err_msg "$interface->{name} references unknown $crypto";
        }
    }
}

sub crypto_behind {
    my ($interface, $managed) = @_;
    if ($managed) {
        my $zone = $interface->{zone};
        1 == @{ $zone->{interfaces} }
          or err_msg "Exactly one security zone must be located behind",
          " managed crypto $interface->{name}";
        my $zone_networks = $zone->{networks};
        return @$zone_networks;
    }
    else {
        my $network = $interface->{network};
        1 == @{ $network->{interfaces} }
          or err_msg "Exactly one network must be located behind",
          " unmanaged crypto $interface->{name}";
        return ($network);
    }
}

# Valid group-policy attributes.
# Hash describes usage:
# - tg_general: attribute is only applicable to 'tunnel-group general-attributes'
my %asa_vpn_attributes = (

    # group-policy attributes
    banner                        => {},
    'check-subject-name'          => {},
    'dns-server'                  => {},
    'default-domain'              => {},
    'split-dns'                   => {},
    'trust-point'                 => {},
    'wins-server'                 => {},
    'vpn-access-hours'            => {},
    'vpn-idle-timeout'            => {},
    'vpn-session-timeout'         => {},
    'vpn-simultaneous-logins'     => {},
    vlan                          => {},
    'split-tunnel-policy'         => {},
    'authentication-server-group' => { tg_general => 1 },
    'authorization-server-group'  => { tg_general => 1 },
    'authorization-required'      => { tg_general => 1 },
    'username-from-certificate'   => { tg_general => 1 },
);

sub verify_asa_vpn_attributes {
    my ($obj) = @_;
    my $attributes = $obj->{radius_attributes} or return;
    for my $key (sort keys %$attributes) {
        my $spec = $asa_vpn_attributes{$key};
        $spec or err_msg("Invalid radius_attribute '$key' at $obj->{name}");
        if ($key eq 'split-tunnel-policy') {
            my $value = $attributes->{$key};
            $value =~ /^(?:tunnelall|tunnelspecified)$/
              or err_msg(
                "Unsupported value in radius_attributes",
                " of $obj->{name}\n",
                " '$key = $value'"
              );
        }
        elsif ($key eq 'trust-point') {
            if (is_host($obj)) {
                $obj->{range}
                  or err_msg("Must not use radius_attribute '$key'",
                    " at $obj->{name}");
            }
            elsif (is_network($obj)) {
                grep { $_->{ip} } @{ $obj->{hosts} }
                  and err_msg("Must not use radius_attribute '$key'",
                    " at $obj->{name}");
            }
        }
    }
}

# Host with ID that doesn't contain a '@' must use attribute
# 'verify-subject-name'.
sub verify_subject_name {
    my ($host, $peer) = @_;
    my $id = $host->{id};
    return if $id =~ /@/;
    my $has_attr = sub {
        my ($obj) = @_;
        my $attributes = $obj->{radius_attributes};
        return ($attributes && $attributes->{'check-subject-name'});
    };
    return if $has_attr->($host);
    return if $has_attr->($host->{network});
    if (not $has_attr->($peer->{router})) {
        err_msg("Missing radius_attribute 'check-subject-name'\n",
                " for $host->{name}");
    }
}

sub verify_asa_trustpoint {
    my ($router, $crypto) = @_;
    my $isakmp = $crypto->{type}->{key_exchange};
    if ($isakmp->{authentication} eq 'rsasig') {
        $isakmp->{trust_point}
          or err_msg(
            "Missing attribute 'trust_point' in",
            " $isakmp->{name} for $router->{name}"
          );
    }
}

sub expand_crypto {
    progress('Expanding crypto rules');
    my %id2intf;

    for my $crypto (sort by_name values %crypto) {
        my $isakmp  = $crypto->{type}->{key_exchange};
        my $need_id = $isakmp->{authentication} eq 'rsasig';

        # Do consistency checks and
        # add rules which allow encrypted traffic.
        for my $tunnel (@{ $crypto->{tunnels} }) {
            next if $tunnel->{disabled};
            for my $tunnel_intf (@{ $tunnel->{interfaces} }) {
                next if $tunnel_intf->{is_hub};
                my $router  = $tunnel_intf->{router};
                my $peer    = $tunnel_intf->{peer};
                my $managed = $router->{managed};
                my $hub_router     = $peer->{router};
                my $hub_model      = $hub_router->{model};
                my $hub_is_asa_vpn = $hub_model->{crypto} eq 'ASA_VPN';
                my @encrypted;
                my ($has_id_hosts, $has_other_network);

                # Analyze cleartext networks behind spoke router.
                for my $interface (@{ $router->{interfaces} }) {
                    next if $interface eq $tunnel_intf;
                    next if $interface->{spoke};
                    my $network = $interface->{network};
                    my @all_networks = crypto_behind($interface, $managed);
                    if ($network->{has_id_hosts}) {
                        $has_id_hosts = 1;
                        $managed
                          and err_msg
                          "$network->{name} having ID hosts must not",
                          " be located behind managed $router->{name}";
                        if ($hub_is_asa_vpn) {
                            verify_asa_vpn_attributes($network);
                        }

                        # Rules for single software clients are stored
                        # individually at crypto hub interface.
                        for my $host (@{ $network->{hosts} }) {
                            my $id = $host->{id};

                            # ID host has already been checked to have
                            # exactly one subnet.
                            my $subnet = $host->{subnets}->[0];
                            if ($hub_is_asa_vpn) {
                                verify_asa_vpn_attributes($host);
                                verify_subject_name($host, $peer);
                            }
                            my $no_nat_set = $peer->{no_nat_set};
                            if (my $other = $peer->{id_rules}->{$id}) {
                                my $src = $other->{src};
                                err_msg(
                                    "Duplicate ID-host $id from",
                                    " $src->{network}->{name} and",
                                    " $subnet->{network}->{name}",
                                    " at $peer->{router}->{name}"
                                );
                                next;
                            }
                            $peer->{id_rules}->{$id} = {
                                name       => "$peer->{name}.$id",
                                ip         => 'tunnel',
                                src        => $subnet,
                                no_nat_set => $no_nat_set,
                            };
                        }
                        push @encrypted, $network;
                    }
                    else {
                        $has_other_network = 1;
                        push @encrypted, @all_networks;
                    }
                }
                $has_id_hosts
                  and $has_other_network
                  and err_msg(
                    "Must not use host with ID and network",
                    " together at $tunnel_intf->{name}:\n",
                    name_list(\@encrypted)
                  );
                if (@encrypted) {
                    $has_id_hosts
                      or $has_other_network
                      or err_msg(
                        "Must use network or host with ID",
                        " at $tunnel_intf->{name}:\n",
                        name_list(\@encrypted)
                      );
                }

                my $do_auth = $hub_model->{do_auth};
                if (my $id = $tunnel_intf->{id}) {
                    $need_id
                      or err_msg(
                        "Invalid attribute 'id' at $tunnel_intf->{name}.\n",
                        " Set authentication=rsasig at $isakmp->{name}"
                      );
                    my $aref = $id2intf{$id} ||= [];
                    if (my @other =
                        grep { $_->{peer}->{router} eq $hub_router } @$aref)
                    {

                        # Id must be unique per crypto hub, because it
                        # is used to generate ACL names and other names.
                        err_msg("Must not reuse 'id = $id' at different",
                                " crypto spokes of '$hub_router->{name}':\n",
                                name_list([@other, $tunnel_intf]));
                    }
                    push(@$aref, $tunnel_intf);
                }
                elsif ($has_id_hosts) {
                    $do_auth
                      or err_msg(
                        "$hub_router->{name} can't check IDs",
                        " of $encrypted[0]->{name}"
                      );
                }
                elsif (@encrypted) {
                    if ($do_auth and not $managed) {
                        err_msg(
                            "Networks need to have ID hosts because",
                            " $hub_router->{name} has attribute 'do_auth':\n",
                            name_list(\@encrypted)
                        );
                    }
                    elsif ($need_id) {
                        err_msg(
                            "$tunnel_intf->{name}",
                            " needs attribute 'id',",
                            " because $isakmp->{name}",
                            " has authentication=rsasig"
                        );

                        # Prevent further errors.
                        $tunnel_intf->{id} = '';
                    }
                }
                $peer->{peer_networks} = \@encrypted;

                if ($managed and $router->{model}->{crypto} eq 'ASA') {
                    verify_asa_trustpoint($router, $crypto);
                }

                # Add rules to permit crypto traffic between
                # tunnel endpoints.
                # If one tunnel endpoint has no known IP address,
                # some rules have to be added manually.
                my $real_spoke = $tunnel_intf->{real_interface};
                if (    $real_spoke
                    and $real_spoke->{ip} !~ /^(?:short|unnumbered)$/)
                {
                    my $hub = $tunnel_intf->{peer};
                    my $real_hub = $hub->{real_interface};
                    for my $intf1 ($real_spoke, $real_hub)
                    {
                        # Don't generate incoming ACL from unknown
                        # address.
                        next if $intf1->{ip} eq 'negotiated';

                        my $intf2 =
                            $intf1 eq $real_hub ? $real_spoke : $real_hub;
                        my $rules =
                          gen_tunnel_rules($intf1, $intf2, $crypto->{type});
                        push @{ $path_rules{permit} }, @$rules;
                    }
                }
            }
        }
    }

    # Check for duplicate IDs of different hosts
    # coming into different hardware at current device.
    # ASA_VPN can't distinguish different hosts with same ID
    # coming into different hardware interfaces.
    for my $router (@managed_crypto_hubs) {
        my $crypto_type = $router->{model}->{crypto};
        $crypto_type eq 'ASA_VPN' or next;
        my @id_rules_interfaces =
          grep { $_->{id_rules} } @{ $router->{interfaces} };
        @id_rules_interfaces >= 2 or next;
        my %id2src;
        for my $interface (@id_rules_interfaces) {
            my $hash = $interface->{id_rules};
            for my $id (keys %$hash) {
                my $src1 = $hash->{$id}->{src};
                if (my $src2 = $id2src{$id}) {
                    err_msg(
                        "Duplicate ID-host $id from",
                        " $src1->{network}->{name} and",
                        " $src2->{network}->{name}",
                        " at $router->{name}"
                    );
                }
                else {
                    $id2src{$id} = $src1;
                }
            }
        }
    }

    for my $router (@managed_crypto_hubs) {
        my $crypto_type = $router->{model}->{crypto};
        if ($crypto_type eq 'ASA_VPN') {
            verify_asa_vpn_attributes($router);

            # Move 'trust-point' from radius_attributes to router attribute.
            my $trust_point =
              delete $router->{radius_attributes}->{'trust-point'}
              or err_msg("Missing 'trust-point' in radius_attributes",
                " of $router->{name}");
            $router->{trust_point} = $trust_point;
        }
        elsif ($crypto_type eq 'ASA') {
            for my $interface (@{ $router->{interfaces} }) {
                my $crypto = $interface->{crypto} or next;
                verify_asa_trustpoint($router, $crypto);
            }
        }
    }
}

##############################################################################
# Check if high-level and low-level semantics of rules with an supernet
# as source or destination are equivalent.
#
# I. Typically, we only use incoming ACLs.
# (A) rule "permit any:X dst"
# high-level: any:X in zone X get access to dst
# low-level: like above, but additionally, the networks matching any:X
#            in all zones on the path from zone X to dst get access to dst.
# (B) rule permit src any:X
# high-level: src gets access to any:X in zone X
# low-level: like above, but additionally, src gets access to all networks
#            matching any:X in all zones located directly behind
#            all routers on the path from src to zone X.
#
# II. Alternatively, we have a single interface Y (with attached zone Y)
#     without ACL and all other interfaces having incoming and outgoing ACLs.
# (A) rule "permit any:X dst"
#  a)  dst behind Y: filtering occurs at incoming ACL of X, good.
#  b)  dst not behind Y:
#    1. zone X == zone Y: filtering occurs at outgoing ACL, good.
#    2. zone X != zone Y: outgoing ACL would accidently
#                permit any:Y->dst, bad.
#                Additional rule required: "permit any:Y->dst"
# (B) rule "permit src any:X"
#  a)  src behind Y: filtering occurs at ougoing ACL, good
#  b)  src not behind Y:
#    1. zone X == zone Y: filtering occurs at incoming ACL at src and
#                at outgoing ACls of other non-zone X interfaces, good.
#    2. zone X != zone Y: incoming ACL at src would permit
#                src->any:Y, bad
#                Additional rule required: "permit src->any:Y".
##############################################################################

sub find_supernet {
    my ($net1, $net2) = @_;

    # Start with $net1 being the smaller network.
    ($net1, $net2) = ($net2, $net1) if $net1->{mask} lt $net2->{mask};
    while (1) {
        while ($net1->{mask} gt $net2->{mask}) {
            $net1 = $net1->{up} or return;
        }
        return $net1 if $net1 eq $net2;
        $net2 = $net2->{up} or return;
    }
}

# Find networks in zone with address
# - equal to ip/mask or
# - subnet of ip/mask
# Leave out small networks which are subnet of a matching network.
# Result:
# 0: no network found
# network:
#   a) exactly one network matches, i.e. is equal or subnet.
#   b) a supernet which encloses multiple matching networks
# String: More than one network found and no supernet exists.
#         String has the name of first two networks.
sub find_zone_network {
    my ($interface, $zone, $other) = @_;
    return 0 if $zone->{no_check_supernet_rules};
    my $no_nat_set = $interface->{no_nat_set};
    my $nat_other = get_nat_network($other, $no_nat_set);
    return 0 if $nat_other->{hidden};
    my ($ip, $mask) = @{$nat_other}{qw(ip mask)};
    my $key = "$ip$mask";
    if (my $aggregate = $zone->{ipmask2aggregate}->{$key}) {
        return $aggregate;
    }
    if (defined(my $result = $zone->{ipmask2net}->{$key})) {
        return $result;
    }

    # Real networks in zone without aggregates and without subnets.
    my $networks = $zone->{networks};
    my $result   = 0;
    for my $network (@$networks) {
        my $nat_network = get_nat_network($network, $no_nat_set);
        next if $nat_network->{hidden};
        my ($i, $m) = @{$nat_network}{qw(ip mask)};
        if (   $m ge $mask and match_ip($i, $ip, $mask)
            or $m lt $mask and match_ip($ip, $i, $m))
        {

            # Found first matching network.
            if (not $result) {
                $result = $network;
                next;
            }

            # Search a common supernet of two networks
            if (my $super = find_supernet($result, $network)) {
                $result = $super;
            }
            else {
                $result = "$result->{name}, $network->{name}";
                last;
            }
        }
    }

#    debug "zone_network:", ref($result) ? $result->{name} : $result;
    return ($zone->{ipmask2net}->{$key} = $result);
}

# Find all networks in zone, which match network from other zone.
# Result:
# undef: No network of zone matches $other.
# []   : Multiple networks match, but no supernet exists.
# [N, ..]: Array reference to networks which match $other (ascending order).
sub find_matching_supernet {
    my ($interface, $zone, $other) = @_;
    my $net_or_count = find_zone_network($interface, $zone, $other);

    # No network or aggregate matches.
    # $other wont match in current zone.
    if (not $net_or_count) {
        return;
    }

    # More than one network matches and no supernet exists.
    # Return names of that networks.
    if (not ref($net_or_count)) {
        return $net_or_count;
    }

    # Exactly one network or aggregate matches or supernet exists.
    my @result;

    # Add enclosing supernets.
    my $up = $net_or_count;
    while ($up) {
        push @result, $up;
        $up = $up->{up};
    }

#    debug "matching:", join(',', map { $_->{name} } @result);
    return \@result;
}

# Prevent multiple error messages about missing supernet rules;
my %missing_supernet;

# $rule: the rule to be checked
# $where: has value 'src' or 'dst'
# $interface: interface, where traffic reaches the device,
#             this is used to determine no_nat_set
# $zone: The zone to be checked.
#        If $where is 'src', then $zone is attached to $interface
#        If $where is 'dst', then $zone is at other side of device.
# $reversed: (optional) the check is for reversed rule at stateless device
sub check_supernet_in_zone {
    my ($rule, $where, $interface, $zone, $reversed) = @_;

    my $service = $rule->{rule}->{service};
    return if $missing_supernet{$interface}->{$service};

    my $supernet = $rule->{$where}->[0];
    my $networks = find_matching_supernet($interface, $zone, $supernet);
    return if not $networks;
    my $extra;
    if (not ref($networks)) {
        $extra = "No supernet available for $networks";
    }
    else {

        # $networks holds matching network and all its supernets.
        # Find smallest matching rule.
        my $net_hash = $rule->{zone2net_hash}->{$zone};
        for my $network (@$networks) {
            return if $net_hash->{$network}
        }
        $extra = "Tried " . join(', ', map { $_->{name} } @$networks);
    }

    $missing_supernet{$interface}->{$service} = 1;

    $rule = print_rule $rule;
    $reversed = $reversed ? 'reversed ' : '';
    warn_or_err_msg($config->{check_supernet_rules},
                    "Missing rule for ${reversed}supernet rule.\n",
                    " $rule\n",
                    " can't be effective at $interface->{name}.\n",
                    " $extra as $where.");
}

# Check if path between $supernet and $obj_list ist filtered by
# device with $mark from $router->{local_mark}.
sub is_filtered_at {
    my ($mark, $supernet, $obj_list) = @_;
    my $supernet_filter_at = $supernet->{filter_at} or return;
    $supernet_filter_at->{$mark} or return;
    my $found_filtered;
    for my $obj (@$obj_list) {
        my $obj_net       = $obj->{network} || $obj;
        my $obj_filter_at = $obj_net->{filter_at} or next;
        $obj_filter_at->{$mark} or next;
        $found_filtered = 1;
        last;
    }
    return $found_filtered;
}

# If such rule is defined
#  permit supernet1 dst
#
# and topology is like this:
#
# supernet1-R1-zone2-R2-zone3-R3-dst
#               zone4-/
#
# additional rules need to be defined as well:
#  permit supernet(zone2) dst
#  permit supernet(zone3) dst
#
# If R2 is stateless, we need one more rule to be defined:
#  permit supernet(zone4) dst
# This is so, because at R2 we would get an automatically generated
# reverse rule
#  permit dst supernet1
# which would accidentally permit traffic to supernet:[zone4] as well.
sub check_supernet_src_rule {
    my ($rule, $in_intf, $out_intf) = @_;

    # Ignore semi_managed router.
    my $router  = $in_intf->{router};
    $router->{managed} or return;

    my $src     = $rule->{src}->[0];

    # Non matching rule will be ignored at 'managed=local' router and
    # hence must no be checked.
    if (my $mark = $router->{local_mark}) {
        is_filtered_at($mark, $src, $rule->{dst}) or return;
    }

    my $dst_zone = $rule->{dst_path};
    if (is_interface($dst_zone)) {
        if (not $dst_zone->{router}->{managed}) {
            $dst_zone = $dst_zone->{zone};
        }
    }
    elsif(is_router($dst_zone)) {
        if (not $dst_zone->{managed}) {
            $dst_zone = $dst_zone->{interfaces}->[0]->{zone};
        }
    }
    my $in_zone  = $in_intf->{zone};

    # Check case II, outgoing ACL, (A)
    my $no_acl_intf;
    if ($no_acl_intf = $router->{no_in_acl}) {
        my $no_acl_zone = $no_acl_intf->{zone};

        # a) dst behind Y
        if (zone_eq($no_acl_zone, $dst_zone)) {
        }

        # b), 1. zone X == zone Y
        elsif (zone_eq($in_zone, $no_acl_zone)) {
        }

        elsif ($no_acl_intf->{main_interface}) {
        }

        # b), 2. zone X != zone Y
        else {
            check_supernet_in_zone($rule, 'src', $no_acl_intf, $no_acl_zone);
        }
    }

    my $src_zone = $src->{zone};

    # Check if reverse rule would be created and would need additional rules.
    if ($out_intf
        and $router->{model}->{stateless}
        and not $rule->{oneway}
        and grep { $_->{proto} =~ /^(?:tcp|udp|ip)$/ } @{ $rule->{prt} })

    {
        my $out_zone = $out_intf->{zone};

        # Reverse rule wouldn't allow too much traffic, if a non
        # secondary stateful device filters between current device and dst.
        # This is true if $out_zone and $dst_zone have different
        # {stateful_mark}.
        #
        # $src is supernet (not an interface) by definition and hence
        # $m1 is well defined.
        #
        # If $dst is interface or router, $m2 undefined.
        # Corresponding router is known to be managed, because
        # unmanaged $dst_zone has already been converted to zone
        # above. Managed routers are assumed to send answer packet
        # correctly back to source address.
        # Hence reverse rules need not to be checked.
        my $m1 = $out_zone->{stateful_mark};
        my $m2 = $dst_zone->{stateful_mark};
        if ($m2 and $m1 == $m2) {

            # Check case II, outgoing ACL, (B), interface Y without ACL.
            if (my $no_acl_intf = $router->{no_in_acl}) {
                my $no_acl_zone = $no_acl_intf->{zone};

                # a) dst behind Y
                if (zone_eq($no_acl_zone, $dst_zone)) {
                }

                # b) dst not behind Y
                # zone X == zone Y
                elsif (zone_eq($no_acl_zone, $src_zone)) {
                }

                elsif ($no_acl_intf->{main_interface}) {
                }

                # zone X != zone Y
                else {
                    check_supernet_in_zone($rule, 'src', $no_acl_intf,
                                           $no_acl_zone, 1);
                }
            }

            # Standard incoming ACL at all interfaces.
            else {

                # Find security zones at all interfaces except the in_intf.
                for my $intf (@{ $router->{interfaces} }) {
                    next if $intf eq $in_intf;
                    next if $intf->{loopback};

                    # Nothing to be checked for an interface directly
                    # connected to src or dst.
                    my $zone = $intf->{zone};
                    next if zone_eq($zone, $src_zone);
                    next if zone_eq($zone, $dst_zone);
                    next if $intf->{main_interface};
                    check_supernet_in_zone($rule, 'src', $intf, $zone, 1);
                }
            }
        }
    }

    # Nothing to do at first router.
    # zone2 is checked at R2, because we need the no_nat_set at R2.
    return if zone_eq($src_zone, $in_zone);

    # Check if rule "supernet2 -> dst" is defined.
    check_supernet_in_zone($rule, 'src', $in_intf, $in_zone);
}

# If such rule is defined
#  permit src supernet5
#
# and topology is like this:
#
#                      /-zone4
# src-R1-zone2-R2-zone3-R3-zone5
#      \-zone1
#
# additional rules need to be defined as well:
#  permit src supernet1
#  permit src supernet2
#  permit src supernet3
#  permit src supernet4
sub check_supernet_dst_rule {
    my ($rule, $in_intf, $out_intf) = @_;

    # Source is interface of current router.
    return unless $in_intf;

    # Ignore semi_managed router.
    my $router = $in_intf->{router};
    return if not $router->{managed};

    my $dst = $rule->{dst}->[0];

    # Non matching rule will be ignored at 'managed=local' router and
    # hence must not be checked.
    if (my $mark = $router->{local_mark}) {
        is_filtered_at($mark, $dst, $rule->{src}) or return;
    }

    my $src_zone = $rule->{src_path};
    if (is_interface($src_zone)) {
        if (not $src_zone->{router}->{managed}) {
            $src_zone = $src_zone->{zone};
        }
    }
    elsif(is_router($src_zone)) {
        if (not $src_zone->{managed}) {
            $src_zone = $src_zone->{interfaces}->[0]->{zone};
        }
    }
    my $dst_zone = $dst->{zone};

    # Check case II, outgoing ACL, (B), interface Y without ACL.
    if (my $no_acl_intf = $router->{no_in_acl}) {
        my $no_acl_zone = $no_acl_intf->{zone};

        # a) src behind Y
        if (zone_eq($no_acl_zone, $src_zone)) {
        }

        # b) src not behind Y
        # zone X == zone Y
        elsif (zone_eq($no_acl_zone, $dst_zone)) {
        }

        elsif ($no_acl_intf->{main_interface}) {
        }

        # zone X != zone Y
        else {
            check_supernet_in_zone($rule, 'dst', $in_intf, $no_acl_zone);
        }
        return;
    }

    # Check security zones at all interfaces except those connected
    # to dst or src.
    # For devices which have rules for each pair of incoming and outgoing
    # interfaces we only need to check the direct path to dst.
    my $in_zone = $in_intf->{zone};
    for my $intf (
        $router->{model}->{has_io_acl}
        ? ($out_intf)
        : @{ $router->{interfaces} }
      )
    {

        # Check each intermediate zone only once at outgoing interface.
        next if $intf eq $in_intf;
        next if $intf->{loopback};

        # Don't check interface where src or dst is attached.
        my $zone = $intf->{zone};
        next if zone_eq($zone, $src_zone);
        next if zone_eq($zone, $dst_zone);
        next if zone_eq($zone, $in_zone);
        next if $intf->{main_interface};
        check_supernet_in_zone($rule, 'dst', $in_intf, $zone);
    }
}

# Check missing supernet of each service_rule.
sub check_missing_supernet_rules {
    my ($what, $worker) = @_;
    my $other      = $what eq 'src' ? 'dst' : 'src';
    my $other_path = "${other}_path";
    my $what_path  = "${what}_path";

    my $rules = $service_rules{permit};
    for my $rule (@$rules) {
        next if $rule->{no_check_supernet_rules};
        my $list = $rule->{$what};
        my @supernets = grep { $_->{has_other_subnet} } @$list or next;

        # Build mapping from zone to hash of all src/dst networks of
        # current rule.
        my %zone2net_hash;
        for my $obj (@$list) {
            is_network($obj) or next;
            my $zone = $obj->{zone};
            $zone2net_hash{$zone}->{$obj} = $obj;
        }
        $rule->{zone2net_hash} = \%zone2net_hash;
        my $path_rules = split_rules_by_path([$rule], $other);
        for my $supernet (@supernets) {
            my $zone = $supernet->{zone};
            for my $path_rule (@$path_rules) {
                my $other_zone = get_zone($path_rule->{$other_path});
                next if zone_eq($zone, $other_zone);
                my $check_rule = { %$path_rule,
                                   $what      => [$supernet],
                                   $what_path => $zone, };
                path_walk($check_rule, $worker);
            }
        }
    }
}

sub match_prt {
    my ($prt1, $prt2) = @_;
    my $proto1 = $prt1->{proto};
    my $proto2 = $prt2->{proto};
    return 1 if $proto1 eq 'ip';
    return 1 if $proto2 eq 'ip';
    $proto1 eq $proto2 or return;
    if ($proto1 eq 'tcp' or $proto1 eq 'udp') {
        my ($l1, $h1) = @{ $prt1->{range} };
        my ($l2, $h2) = @{ $prt2->{range} };
        return $l1 <= $l2 && $h2 <= $h1 || $l2 <= $l1 && $h1 <= $h2;
    }
    elsif ($proto1 eq 'icmp') {
        my $type1 = $prt1->{type};
        return 1 if not defined $type1;
        my $type2 = $prt2->{type};
        return 1 if not defined $type2;
        $type1 == $type2 or return;
        my $code1 = $prt1->{code};
        return 1 if not defined $code1;
        my $code2 = $prt2->{code};
        return 1 if not defined $code2;
        return $code1 == $code2;
    }
    else {
        return 1;
    }
}

# Matches, if at least one pair protocols matches.
sub match_prt_list {
    my ($prt_list1, $prt_list2) = @_;
    for my $prt1 (@$prt_list1) {
        for my $prt2 (@$prt_list2) {
            match_prt($prt1, $prt2) and return 1;
        }
    }
    return 0;
}

# Find those elements of $list, with an IP address matching $obj.
# If element is aggregate that is supernet of $obj,
# than return all matching networks inside that aggregate.
sub get_ip_matching {
    my ($obj, $list, $no_nat_set) = @_;
    my $nat_obj = get_nat_network($obj, $no_nat_set);
    my ($ip, $mask) = @{$nat_obj}{ 'ip', 'mask' };

    my @matching;
    for my $src (@$list) {
        my ($i, $m) = @{address($src, $no_nat_set)};

        # Element is subnet of $obj.
        if ($m ge $mask and match_ip($i, $ip, $mask)) {
            push @matching, $src;
        }

        # Element is supernet of $obj.
        elsif ($m lt $mask and match_ip($ip, $i, $m)) {
            if ($src->{is_aggregate}) {
                my $networks = $src->{networks} or next;
                $networks = get_ip_matching($obj, $networks, $no_nat_set);
                push @matching, @$networks;
            }
            else {
                push @matching, $src;
            }
        }
    }
    return \@matching;
}

# Check that all elements of first list are contained in or equal to
# some element of second list.
sub all_contained_in {
    my ($aref1, $aref2) = @_;
    my %in_aref2;
    @in_aref2{@$aref2} = @$aref2;
  ELEMENT:
    for my $element (@$aref1) {
        next if $in_aref2{$element};
        my $up = $element;
        while ($up = $up->{up}) {
            next ELEMENT if $in_aref2{$up};
        }
        return;
    }
    return 1;
}

# Get elements that were missing
# from all_contained_in and elements_in_one_zone.
sub get_missing {
    my ($aref1, $aref2, $zone) = @_;
    my %in_aref2;
    @in_aref2{@$aref2} = @$aref2;
    my @missing;
  ELEMENT:
    for my $element (@$aref1) {
        next if $in_aref2{$element};
        my $zone2 = $obj2zone{$element} || get_zone($element);
        next if $zone2 eq $zone;
        my $up = $element;
        while ($up = $up->{up}) {
            next ELEMENT if $in_aref2{$up};
        }
        push @missing, $element;
    }
    return @missing;
}

sub elements_in_one_zone {
    my ($list1, $list2) = @_;
    my $obj0 = $list1->[0];
    my $zone0 = $obj2zone{$obj0} || get_zone($obj0);
    for my $obj (@$list1, @$list2) {
        my $zone = $obj2zone{$obj} || get_zone($obj);
        zone_eq($zone0, $zone) or return;
    }
    return 1;
}

# Mark zones, that are connected by only one router.  Ignore routers
# with only one interface occuring e.g. from split crypto routers.
sub mark_leaf_zones {
    my %leaf_zones;
    for my $zone (@zones) {
        if (1
            >=
            grep { @{ $_->{router}->{interfaces} } > 1 }
            @{ $zone->{interfaces} })
        {
            $leaf_zones{$zone} = 1;
        }
    }
    return \%leaf_zones;
}

# Check if paths from elements of $src_list to $dst_list pass $zone.
sub paths_reach_zone {
    my ($zone, $src_list, $dst_list) = @_;

    # Collect all zones and routers, where elements are located.
    my @from_list;
    my @to_list;
    my %seen;
    for my $element (@$src_list) {
        my $path = $obj2path{$element} || get_path($element);
        next if $path eq $zone;
        $seen{$path}++ or push @from_list, $path;
    }
    for my $element (@$dst_list) {
        my $path = $obj2path{$element} || get_path($element);
        next if $path eq $zone;
        $seen{$path}++ or push @to_list, $path;
    }

    my $zone_reached;
    my $check_zone = sub {
        my (undef, $in_intf, $out_intf) = @_;

        # Packets traverse $zone.
        if ($in_intf and $out_intf and $in_intf->{zone} eq $zone) {
            $zone_reached = 1;
        }
    };

    for my $from (@from_list) {
        for my $to (@to_list) {

            # Check if path from $from to $to is available.
            if (not $from->{path1}->{$to}) {
                if (not path_mark($from, $to)) {
                    delete $from->{path1}->{$to};

                    # No path found, check next pair.
                    next;
                }
            }
            my $pseudo_rule = {
                src_path => $from,
                dst_path => $to,
            };
            path_walk($pseudo_rule, $check_zone, 'Zone');
            return 1 if $zone_reached;
        }
    }
    return;
}

# Print list of names in messages.
sub name_list {
    my ($obj) = @_;
    my @names = map { $_->{name} } @$obj;
    return ' - ' . join("\n - ", @names);
}

# Print abbreviated list of names in messages.
sub short_name_list {
    my ($obj) = @_;
    my @names = map { $_->{name} } @$obj;
    my $count = @names;
    if ($count > 4) {
        splice(@names, 3, @names - 3, '...');
    }
    return ' - ' . join("\n - ", @names);
}

# Example:
# XX--R1--any:A--R2--R3--R4--YY
#
# If we have rules
#   permit XX any:A
#   permit any:B YY
# and
#   the intersection I of A and B isn't empty
# and
#   XX and YY are subnet of I
# then this traffic is implicitly permitted
#   permit XX YY
# which may be undesired.
# In order to avoid this, a warning is generated if the implied rule is not
# explicitly defined.
sub check_transient_supernet_rules {
    progress("Checking transient supernet rules");
    my $rules = $service_rules{permit};

    my $is_leaf_zone = mark_leaf_zones();

    # Build mapping from supernet to service rules having supernet as src.
    my %supernet2rules;

    # Mapping from zone to supernets found in src of rules.
    my %zone2supernets;
    for my $rule (@$rules) {
        next if $rule->{no_check_supernet_rules};
        my $src_list = $rule->{src};
        for my $obj (@$src_list) {
            $obj->{has_other_subnet} or next;

            # Ignore the internet. If the internet is used as src and dst
            # then the implicit transient rule is assumed to be ok.
            next if not $obj->{is_aggregate} and is_zero_ip($obj->{mask});

            my $zone = $obj->{zone};
            next if $zone->{no_check_supernet_rules};

            # A leaf security zone has only one exit.
            if ($is_leaf_zone->{$zone}) {

                # Check, if a managed router with only one interface
                # inside the zone is used as destination.
                my $found;
                for my $dst (@{ $rule->{dst} }) {
                    is_interface($dst) or next;
                    my $router = $dst->{router};
                    $router->{managed} or next;
                    $dst->{zone} eq $zone or next;
                    @{ $router->{interfaces} } < 2 or next;

                    # Then this zone must still be checked.
                    delete $is_leaf_zone->{$zone};
                    $found = 1;
                }

                # This leaf zone can't lead to unwanted rule chains.
                next if not $found;
            }
            $supernet2rules{$obj} or push @{ $zone2supernets{$zone} }, $obj;
            push @{ $supernet2rules{$obj} }, $rule;
        }
    }
    keys %supernet2rules or return;

    my $print_type = $config->{check_transient_supernet_rules};

    # Search rules having supernet as dst.
    for my $rule1 (@$rules) {
        next if $rule1->{no_check_supernet_rules};
        my $dst_list1 = $rule1->{dst};
        for my $obj1 (@$dst_list1) {
            $obj1->{has_other_subnet} or next;
            my $zone = $obj1->{zone};
            next if $zone->{no_check_supernet_rules};
            next if $is_leaf_zone->{$zone};

            # Find other rules with supernet as src starting in same zone.
            my $supernets = $zone2supernets{$zone} or next;
            my $no_nat_set = $zone->{no_nat_set};
            for my $obj2 (@$supernets) {

                # Find those elements of src of $rule1 with an IP
                # address matching $obj2.
                # If mask of $obj2 is 0.0.0.0, take all elements.
                # Otherwise check IP addresses in NAT domain of $obj2.
                my $src_list1 = $rule1->{src};
                if (not is_zero_ip($obj2->{mask})) {
                    $src_list1 =
                        get_ip_matching($obj2, $src_list1, $no_nat_set);
                    @$src_list1 or next;
                }
                for my $rule2 (@{ $supernet2rules{$obj2} }) {
                    match_prt_list($rule1->{prt}, $rule2->{prt}) or next;
                    match_prt($rule1->{src_range} || $prt_ip,
                              $rule2->{src_range} || $prt_ip) or next;

                    # Find elements of dst of $rule2 with an IP
                    # address matching $obj1.
                    my $dst_list2 = $rule2->{dst};
                    if (not is_zero_ip($obj1->{mask})) {
                        $dst_list2 =
                            get_ip_matching($obj1, $dst_list2, $no_nat_set);
                        @$dst_list2 or next;
                    }
                    my $src_list2 = $rule2->{src};

                    # Found transient rules $rule1 and $rule2.
                    # Check, that
                    # - either src elements of $rule1 are also src of $rule2
                    # - or dst elements of $rule2 are also dst of $rule1,
                    # - but no problem if src1 and dst2 are located
                    #   in same zone, i.e. transient traffic back to src,
                    # - also need to ignore unenforceable $rule1 and $rule2.
                    if (not (all_contained_in($src_list1, $src_list2) or
                             all_contained_in($dst_list2, $dst_list1))
                        and not elements_in_one_zone($src_list1, $dst_list2)
                        and not elements_in_one_zone($src_list1, [ $obj2 ])
                        and not elements_in_one_zone([ $obj1 ], $dst_list2)
                        and paths_reach_zone($zone, $src_list1, $dst_list2))
                    {
                        my $srv1 = $rule1->{rule}->{service}->{name};
                        my $srv2 = $rule2->{rule}->{service}->{name};
                        my $match1 = $obj1->{name};
                        my $match2 = $obj2->{name};
                        my $match =
                            $match1 eq $match2 ? $match1 : "$match1, $match2";
                        my $msg = ("Missing transient supernet rules\n".
                                   " between src of $srv1 and dst of $srv2,\n".
                                   " matching at $match.\n");
                        my @missing_src =
                            get_missing($src_list1, $src_list2, $zone);
                        my @missing_dst =
                            get_missing($dst_list2, $dst_list1, $zone);
                        $msg .= " Add";
                        if (@missing_src) {
                            $msg .= " missing src elements to $srv2:\n";
                            $msg .= short_name_list(\@missing_src);
                        }
                        $msg .= "\n or add" if @missing_src and @missing_dst;
                        if (@missing_dst) {
                            $msg .= " missing dst elements to $srv1:\n";
                            $msg .= short_name_list(\@missing_dst);
                        }
                        warn_or_err_msg($print_type, $msg);
                    }
                }
            }
        }
    }
#    progress("Transient check is ready");
}

# Handling of supernet rules created by gen_reverse_rules.
# This is not needed if a stateful and not secondary packet filter is
# located on the path between src and dst.
#
# 1. dst is supernet
#
# src--r1:stateful--dst1=supernet1--r2:stateless--dst2=supernet2
#
# gen_reverse_rule will create one additional rule
# supernet2-->src, but not a rule supernet1-->src, because r1 is stateful.
# check_supernet_src_rule would complain, that supernet1-->src is missing.
# But that doesn't matter, because r1 would permit answer packets
# from supernet2 anyway, because it's stateful.
# Hence we can skip check_supernet_src_rule for this situation.
#
# 2. src is supernet
#
# a) no stateful router on the path between stateless routers and dst.
#
#             zone2---\
# src=supernet1--r1:stateless--dst
#
# gen_reverse_rules will create one additional rule dst-->supernet1.
# check_supernet_dst_rule would complain about a missing rule
# dst-->zone2.
# To prevent this situation, check_supernet_src_rule checks for a rule
# zone2 --> dst
#
# b) at least one stateful router on the path between
#    stateless router and dst.
#
#               zone3---\
# src1=supernet1--r1:stateless--src2=supernet2--r2:stateful--dst
#
# gen_reverse_rules will create one additional rule
# dst-->supernet1, but not dst-->supernet2 because second router is stateful.
# check_supernet_dst_rule would complain about missing rules
# dst-->supernet2 and dst-->supernet3.
# But answer packets back from dst have been filtered by r2 already,
# hence it doesn't hurt if the rules at r1 are a bit too relaxed,
# i.e. r1 would permit dst to zone1 and zone3, but should only
# permit dst to zone1.
# Hence we can skip check_supernet_dst_rule for this situation.
#

# Mark zones connected by stateless or secondary packet filters or by
# semi_managed devices.
sub mark_stateful {
    my ($zone, $mark) = @_;
    $zone->{stateful_mark} = $mark;
    for my $in_interface (@{ $zone->{interfaces} }) {
        my $router = $in_interface->{router};
        my $managed = $router->{managed};
        if ($managed
            and not $router->{model}->{stateless}
            and not $managed =~ /^(?:secondary|local.*)$/)
        {
            next;
        }
        next if $router->{active_path};
        local $router->{active_path} = 1;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $in_interface;
            my $next_zone = $out_interface->{zone};
            next if $next_zone->{stateful_mark};
            mark_stateful($next_zone, $mark);
        }
    }
}

sub check_supernet_rules {
    if ($config->{check_supernet_rules}) {
        progress("Checking supernet rules");
        my $stateful_mark = 1;
        for my $zone (@zones) {
            if (not $zone->{stateful_mark}) {
                mark_stateful($zone, $stateful_mark++);
            }
        }
#        progress("Checking for missing src in supernet rules");
        check_missing_supernet_rules('src', \&check_supernet_src_rule);
#        progress("Checking for missing dst in supernet rules");
        check_missing_supernet_rules('dst', \&check_supernet_dst_rule);
        %missing_supernet = ();
    }
    if ($config->{check_transient_supernet_rules}) {
#        progress("Checking transient supernet rules");
        check_transient_supernet_rules();
    }
}

##############################################################################
# Generate reverse rules for stateless packet filters:
# For each rule with protocol tcp, udp or ip we need a reverse rule
# with swapped src, dst and src-port, dst-port.
# For rules with a tcp protocol, the reverse rule gets a tcp protocol
# without range checking but with checking for 'established` flag.
##############################################################################

sub gen_reverse_rules1 {
    my ($rule_aref) = @_;
    my @extra_rules;
    my %cache;
    for my $rule (@$rule_aref) {
        next if $rule->{oneway};
        my $deny      = $rule->{deny};
        my $prt_group = $rule->{prt};
        my @new_prt_group;
        my $tcp_seen;
        for my $prt (@$prt_group) {
            my $proto = $prt->{proto};
            if ($proto eq 'tcp') {

                # Create tcp established only once.
                next if $tcp_seen++;

                # No reverse rules will be generated for denied TCP
                # packets, because
                # - there can't be an answer if the request is already
                #   denied and
                # - the 'established' optimization for TCP below would
                #   produce wrong results.
                next if $deny;
            }
            else {
                $proto eq 'udp' or $proto eq 'ip' or next;
            }

            push @new_prt_group, $prt;
        }
        @new_prt_group or next;

        # Check path for existence of stateless router.
        my $src_path             = $rule->{src_path};
        my $dst_path             = $rule->{dst_path};
        my $has_stateless_router = $cache{$src_path}->{$dst_path};
        if (not defined $has_stateless_router) {
          PATH_WALK:
            {

                # Local function called by path_walk.
                # It uses free variable $has_stateless_router.
                my $mark_reverse_rule = sub {
                    my (undef, $in_intf, $out_intf) = @_;

                    # Destination of current rule is current router.
                    # Outgoing packets from a router itself are never filtered.
                    # Hence we don't need a reverse rule for current router.
                    return if not $out_intf;
                    my $router = $out_intf->{router};

                    # It doesn't matter if a semi_managed device is stateless
                    # because no code is generated.
                    return if not $router->{managed};
                    my $model = $router->{model};

                    if (
                        $model->{stateless}

                        # Source of current rule is current router.
                        or not $in_intf and $model->{stateless_self}
                      )
                    {
                        $has_stateless_router = 1;

                        # Jump out of path_walk.
                        no warnings "exiting";    ## no critic (ProhibitNoWarn)
                        last PATH_WALK if $use_nonlocal_exit;
                    }
                };

                path_walk($rule, $mark_reverse_rule);
            }
            $cache{$src_path}->{$dst_path} = $has_stateless_router || 0;
        }
        $has_stateless_router or next;

        # Create reverse rule.
        # Create new rule for different values of src_range.
        # Preserve original order of protocols mostly,
        # but order by src_range.
        my (@src_range_list, %src_range2prt_group);
        for my $prt (@new_prt_group) {
            my $proto = $prt->{proto};
            my $new_src_range = $prt_ip;
            my $new_prt;
            if ($proto eq 'tcp') {
                $new_prt = $range_tcp_established;
            }
            elsif ($proto eq 'udp') {

                # Swap src and dst range.
                if ($prt->{range} ne $aref_tcp_any) {
                    $new_src_range = $prt;
                }
                $new_prt = $rule->{src_range} || $prt_udp->{dst_range};
            }

            # $proto eq 'ip'
            else {
                $new_prt = $prt;
            }
            push @src_range_list, $new_src_range
                if not $src_range2prt_group{$new_src_range};
            push @{ $src_range2prt_group{$new_src_range} }, $new_prt;
        }

        for my $src_range (@src_range_list) {
            my $prt_group = $src_range2prt_group{$src_range};
            my $new_rule = {

                # This rule must only be applied to stateless routers.
                stateless => 1,
                src       => $rule->{dst},
                dst       => $rule->{src},
                src_path  => $dst_path,
                dst_path  => $src_path,
                prt       => $prt_group,
            };
            $new_rule->{src_range} = $src_range if $src_range ne $prt_ip;
            $new_rule->{deny} = 1 if $deny;

            # Don't push to @$rule_aref while we are iterating over it.
            push @extra_rules, $new_rule;
        }
    }
    push @$rule_aref, @extra_rules;
}

sub gen_reverse_rules {
    progress('Generating reverse rules for stateless routers');
    for my $type ('deny', 'permit') {
        gen_reverse_rules1($path_rules{$type});
    }
}

##############################################################################
# Mark rules for secondary filtering.
# A rule is implemented at a device
# either as a 'typical' or as a 'secondary' filter.
# A filter is called to be 'secondary' if it only checks
# for the source and destination network and not for the protocol.
# A typical filter checks for full source and destination IP and
# for the protocol of the rule.
#
# There are four types of packet filters: secondary, standard, full, primary.
# A rule is marked by two attributes which are determined by the type of
# devices located on the path from source to destination.
# - 'some_primary': at least one device is primary packet filter,
# - 'some_non_secondary': at least one device is not secondary packet filter.
# A rule is implemented as a secondary filter at a device if
# - the device is secondary and the rule has attribute 'some_non_secondary' or
# - the device is standard and the rule has attribute 'some_primary'.
# Otherwise a rules is implemented typical.
##############################################################################

# Mark security zone $zone with $mark and
# additionally mark all security zones
# which are connected with $zone by secondary packet filters.
sub mark_secondary;
sub mark_secondary {
    my ($zone, $mark) = @_;
    $zone->{secondary_mark} = $mark;

#    debug("$zone->{name} $mark");
    for my $in_interface (@{ $zone->{interfaces} }) {
        next if $in_interface->{main_interface};
        my $router = $in_interface->{router};
        if (my $managed = $router->{managed}) {
            next if $managed !~ /^(?:secondary|local.*)$/;
        }
        $zone->{has_secondary} = 1;
        next if $router->{secondary_mark};
        $router->{secondary_mark} = $mark;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $in_interface;
            next if $out_interface->{main_interface};
            my $next_zone = $out_interface->{zone};
            next if $next_zone->{secondary_mark};
            mark_secondary $next_zone, $mark;
        }
    }
}

# Mark security zone $zone with $mark and
# additionally mark all security zones
# which are connected with $zone by non-primary packet filters.
sub mark_primary;
sub mark_primary {
    my ($zone, $mark) = @_;
    $zone->{primary_mark} = $mark;
    for my $in_interface (@{ $zone->{interfaces} }) {
        next if $in_interface->{main_interface};
        my $router = $in_interface->{router};
        if (my $managed = $router->{managed}) {
            next if $managed eq 'primary';
        }
        $zone->{has_non_primary} = 1;
        next if $router->{primary_mark};
        $router->{primary_mark} = $mark;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $in_interface;
            next if $out_interface->{main_interface};
            my $next_zone = $out_interface->{zone};
            next if $next_zone->{primary_mark};
            mark_primary $next_zone, $mark;
        }
    }
}

sub get_zones {
    my ($path, $group) = @_;
    my $type = ref $path;
    if ($type eq 'Zone') {
        return [ $path ];
    }
    elsif ($type eq 'Interface') {
        return [ $path->{zone} ];
    }
    else {
        return [ unique map { $_->{zone} } @$group ];
    }
}

sub have_different_marks {
    my ($src_zones, $dst_zones, $mark) = @_;
    if (1 == @$src_zones and 1 == @$dst_zones) {
        return $src_zones->[0]->{$mark} ne $dst_zones->[0]->{$mark};
    }
    my $src_marks = [ map { $_->{$mark} } @$src_zones ];
    my $dst_marks = [ map { $_->{$mark} } @$dst_zones ];
    return not intersect($src_marks, $dst_marks);
}

# Collect conflicting rules and supernet rules for check_conflict below.
sub collect_conflict {
    my ($rule, $src_zones, $dst_zones, $src, $dst, $conflict, $is_primary) = @_;
    if (not grep({ not $_->{modifiers}->{no_check_supernet_rules} }
                 @{ $rule->{prt} }))
    {
        return;
    }
    my $established = not grep({ not $_->{established} } @{ $rule->{prt} });
    my ($zones, $other_zones) = ($src_zones, $dst_zones);
    my $list = $src;
    for my $is_src (1, 0) {
        if (not $is_src) {
            ($zones, $other_zones) = ($dst_zones, $src_zones);
            $list = $dst;
        }
        for my $zone (@$zones) {
            $zone->{$is_primary ? 'has_non_primary' : 'has_secondary'} or next;
            my $mark = $zone->{$is_primary ? 'primary_mark' : 'secondary_mark'};
            my $pushed;
            for my $other_zone (@$other_zones) {
                my $hash =
                    $conflict->{"$is_src,$is_primary,$mark,$other_zone"} ||= {};
                for my $obj (@$list) {
                    if ($obj->{has_other_subnet}) {
                        $hash->{supernets}->{$obj} = $obj if not $established;
                    }
                    elsif (not $pushed) {
                        push @{ $hash->{rules} }, $rule;
                        $pushed = 1;
                    }
                }
            }
        }
    }
}

# Disable secondary optimization for conflicting rules.
#
### Case A:
# Topology:
# src--R1--any--R2--dst,
# with R1 is "managed=secondary"
# Rules:
# 1. permit any->net:dst, telnet
# 2. permit host:src->host:dst, http
# Generated ACLs:
# R1:
# permit net:src->net:dst ip (with secondary optimization)
# R2:
# permit any net:dst telnet
# permit host:src host:dst http
# Problem:
# - src would be able to access dst with telnet, but only http was permitted,
# - the whole network of src would be able to access dst, even if
#   only a single host of src was permitted.
# - src would be able to access the whole network of dst, even if
#   only a single host of dst was permitted.
#
### Case B:
# Topology:
# src--R1--any--R2--dst,
# with R2 is "managed=secondary"
# Rules:
# 1. permit net:src->any, telnet
# 2. permit host:host:src->host:dst, http
# Generated ACLs:
# R1:
# permit net:src any telnet
# permit host:src host:dst http
# R2
# permit net:src net:dst ip
# Problem: Same as case A.
sub check_conflict {
    my ($conflict) = @_;
    my %cache;
    for my $key (keys %$conflict) {
        my ($is_src, $is_primary) = split ',', $key;
        my $hash = $conflict->{$key};
        my $supernet_hash = $hash->{supernets} or next;
        my $rules = $hash->{rules} or next;
        my $what = $is_src ? 'src' : 'dst';
      RULE:
        for my $rule1 (@$rules) {
            my $zone1 = $rule1->{"${what}_path"};
            my $list1 = $rule1->{$what};
            for my $supernet (values %$supernet_hash) {
                my $zone2 = $supernet->{zone};
                next if $zone1 eq $zone2;
                for my $obj1 (@$list1) {
                    next if $obj1->{has_other_subnet};
                    my $network = $obj1->{network} || $obj1;
                    my $is_subnet = $cache{$supernet}->{$network};
                    if (not defined $is_subnet) {
                        my ($ip, $mask) = @{$network}{ 'ip', 'mask' };
                        my $no_nat_set = $network->{nat_domain}->{no_nat_set};
                        my $obj = get_nat_network($supernet, $no_nat_set);
                        my ($i, $m) = @{$obj}{ 'ip', 'mask' };
                        $is_subnet = $m lt $mask && match_ip($ip, $i, $m);
                        $cache{$supernet}->{$network} = $is_subnet || 0;
                    }
                    $is_subnet or next;
                    delete $rule1->{$is_primary ?
                                        'some_primary' : 'some_non_secondary'};
#                   my $name1 = $rule1->{rule}->{service}->{name} || '';
#                   debug "$name1 $what";
#                   debug print_rule $rule1;
#                   debug "$obj1->{name} < $supernet->{name}";
                    next RULE;
                }
            }
        }
    }
}

sub mark_secondary_rules {
    progress('Marking rules for secondary optimization');

    my $secondary_mark = 1;
    my $primary_mark   = 1;
    for my $zone (@zones) {
        if (not $zone->{secondary_mark}) {
            mark_secondary $zone, $secondary_mark++;
        }
        if (not $zone->{primary_mark}) {
            mark_primary $zone, $primary_mark++;
        }
    }

    # Mark only permit rules for secondary optimization.
    # Don't modify a deny rule from e.g. tcp to ip.
    # Collect conflicting optimizeable rules and supernet rules.
    my $conflict = {};
    for my $rule (@{ $path_rules{permit} }) {
        my ($src, $dst, $src_path, $dst_path) =
            @{$rule}{qw(src dst src_path dst_path)};

        # Type of $src_path / $dst_path is zone, interface or router.
        # If type is router, then src/dst may contain interfaces of
        # different zones with different values of secondary_mark/primary_mark.
        # Only do optimization, if all interfaces would allow optimization.
        my $src_zones = get_zones($src_path, $src);
        my $dst_zones = get_zones($dst_path, $dst);
        if (have_different_marks($src_zones, $dst_zones, 'secondary_mark')) {
            $rule->{some_non_secondary} = 1;
            collect_conflict($rule, $src_zones, $dst_zones, $src, $dst,
                             $conflict, 0);
        }
        if (have_different_marks($src_zones, $dst_zones, 'primary_mark')) {
            $rule->{some_primary} = 1;
            collect_conflict($rule, $src_zones, $dst_zones, $src, $dst,
                             $conflict, 1);
        }
    }
    check_conflict($conflict);
}

sub check_unstable_nat_rules {
    progress('Checking rules for unstable subnet relation');
    for my $rule (@{ $path_rules{deny} }, @{ $path_rules{permit} }) {
        my ($src_list, $dst_list) = @{$rule}{qw(src dst)};
        my $unstable_src = grep { $_->{unstable_nat} } @$src_list;
        my $unstable_dst = grep { $_->{unstable_nat} } @$dst_list;
        $unstable_src or $unstable_dst or next;
        my $check = sub {
            my ($obj_list, $intf) = @_;
            my $no_nat_set = $intf->{no_nat_set};
            for my $obj (@$obj_list) {
                my $unstable_nat = $obj->{unstable_nat} or next;
                my $subnets = $unstable_nat->{$no_nat_set} or next;
                my $rule = { %$rule };
                for my $what (qw(src dst)) {
                    $rule->{$what} = [ $obj ] if $rule->{$what} eq $obj_list;
                }
                err_msg("Must not use $obj->{name} in rule\n",
                        " ", print_rule($rule), ",\n",
                        " because it is no longer supernet of\n",
                        " - ",
                        join("\n - ", map { $_->{name} } @$subnets),
                        "\n",
                        " at $intf->{name}");
            }
        };
        my $walk = sub {
            my ($rule, $in_intf, $out_intf) = @_;
            if ($in_intf) {
                $check->($src_list, $in_intf) if $unstable_src;
                $check->($dst_list, $in_intf) if $unstable_dst;
            }
            if ($out_intf and $out_intf->{router}->{model}->{stateless}) {
                my $prt_list = $rule->{prt};
                if (grep { $_->{proto} =~ /^(?:tcp|udp|ip)$/ } @$prt_list) {
                    $check->($src_list, $out_intf) if $unstable_src;
                    $check->($dst_list, $out_intf) if $unstable_dst;
                }
            }
        };
        path_walk($rule, $walk);
    }
}

sub get_zone_cluster_borders {
    my ($zone) = @_;
    my $zone_cluster = $zone->{zone_cluster} || [$zone];
    return (
        grep { $_->{router}->{managed} }
        map { @{ $_->{interfaces} } }
        @$zone_cluster);
}

# Analyze networks having host or interface with dynamic NAT.
# In this case secondary optimization must be disabled
# at border routers of zone cluster of these networks,
# because we could accidently permit traffic for the whole network
# where only a single host should be permitted.
sub mark_dynamic_host_nets {

    my %zone2dynamic;
  NETWORK:
    for my $network (@networks) {
        my $href = $network->{nat} or next;
        for my $nat_tag (keys %$href) {
            my $nat_network = $href->{$nat_tag};
            $nat_network->{dynamic} or next;
            next if $nat_network->{hidden};
            for my $obj (@{ $network->{hosts} }, @{ $network->{interfaces} }) {
                $obj->{nat} and $obj->{nat}->{$nat_tag} and next;
                $network->{has_dynamic_host} = 1;
                my $zone = $network->{zone};
                push @{ $zone2dynamic{$zone} }, $network;
                next NETWORK;
            }
        }
    }
    for my $zone (@zones) {
        my $dynamic_nets = $zone2dynamic{$zone} or next;
        for my $interface (get_zone_cluster_borders($zone)) {
            my $router = $interface->{router};
            my $managed = $router->{managed};
            next if ($managed eq 'primary' or $managed eq 'full');

            # Secondary optimization will or may be applicable
            # and must be disabled for $dynamic_nets.
            @{ $router->{no_secondary_opt} }{@$dynamic_nets} = @$dynamic_nets;
        }
    }
}



# Collect managed interfaces on path.
sub collect_path_interfaces {
    my ($rule, $in_intf, $out_intf) = @_;
    my $list = $rule->{interfaces};
    push @$list, $in_intf if $in_intf;
    push @$list, $out_intf if $out_intf;
}

# 1. Check for invalid rules accessing hidden objects.
# 2. Check host rule with dynamic NAT.
# 3. Check for partially applied hidden or dynamic NAT on path.
sub check_dynamic_nat_rules {
    progress('Checking rules with hidden or dynamic NAT');

    # Collect no_nat_sets applicable in zone
    # and combine them into {multi_no_nat_set}.
    my %zone2no_nat_set;
    for my $network (@networks) {
        my $nat_domain = $network->{nat_domain} or next;
        my $no_nat_set = $nat_domain->{no_nat_set};
        my $zone = $network->{zone};
        $zone2no_nat_set{$zone}->{$no_nat_set} = $no_nat_set;
    }
    for my $zone (@zones) {
        my @no_nat_set_list = values %{ $zone2no_nat_set{$zone} };
        my $result = pop @no_nat_set_list;
        for my $no_nat_set (@no_nat_set_list) {
            my $intersection = {};
            for my $key (%$no_nat_set) {
                $intersection->{$key} = 1 if $result->{$key};
            }
            $result = $intersection
        }
        $zone->{multi_no_nat_set} = $result;
    }

    # For each no_nat_set, collect hidden or dynamic NAT tags that are
    # active inside that no_nat_set.
    my %no_nat_set2active_tags;
    {
        my %is_dynamic_nat_tag;
        for my $network (@networks) {
            my $href = $network->{nat} or next;
            for my $nat_tag (keys %$href) {
                my $nat_network = $href->{$nat_tag};
                $nat_network->{dynamic} and $is_dynamic_nat_tag{$nat_tag} = 1;
            }
        }
        for my $natdomain (@natdomains) {
            my $no_nat_set = $natdomain->{no_nat_set};
            my @active =
                grep { not $no_nat_set->{$_} } keys %is_dynamic_nat_tag;
            @{$no_nat_set2active_tags{$no_nat_set}}{@active} = @active;
        }
    }

    # Remember, if pair of src object and dst network already has been
    # processed.
    my %seen;

    # Remember interfaces of already checked path.
    my %cache;

    my $check_dyn_nat_path = sub {
        my ($path_rule, $obj, $network, $other, $other_net, $reversed) = @_;
        my $nat_domain = $other_net->{nat_domain}; # Is undef for aggregate.

        # Find $nat_tag which is effective at $other.
        # - single: $other is host or network, $nat_domain is known.
        # - multiple: $other is aggregate.
        #             Use intersection of all no_nat_sets active in zone.
        my $no_nat_set = $nat_domain
                       ? $nat_domain->{no_nat_set}
                       : $other->{zone}->{multi_no_nat_set};

        my $show_rule = sub {
            my $rule = { %$path_rule };
            @{$rule}{qw(src dst)} =
                $reversed ? ($other, $obj) : ($obj, $other);
            return print_rule($rule);
        };

        my ($nat_seen, $hidden_seen, $static_seen);
        my $nat_hash = $network->{nat};
        for my $nat_tag (sort keys %$nat_hash) {
            next if $no_nat_set->{$nat_tag};
            $nat_seen = 1;
            my $nat_network = $nat_hash->{$nat_tag};

            # Network is hidden by NAT.
            if ($nat_network->{hidden}) {
                $hidden_seen++
                  or err_msg("$obj->{name} is hidden by nat:$nat_tag",
                             " in rule\n ", $show_rule->());
                next;
            }
            if (not $nat_network->{dynamic}) {
                $static_seen = 1;
                next;
            }

            # Detailed check for host / interface with dynamic NAT.
            # 1. Dynamic NAT address of host / interface object is
            # used in ACL at managed router at the border of zone
            # of that object. Hence the whole network would
            # accidentally be permitted.
            # 2. Check later to be added reverse rule as well.

            # Ignore network.
            next if $obj eq $network;

            # Ignore host / interface with static NAT.
            next if $obj->{nat}->{$nat_tag};

            my $check = sub {
                my ($rule, $in_intf, $out_intf) = @_;
                my $router = ($in_intf || $out_intf)->{router};

                my $check_common = sub {
                    my ($nat_intf, $reversed2) = @_;
                    my $no_nat_set = $nat_intf->{no_nat_set};
                    my $nat_network = get_nat_network($network, $no_nat_set);
                    $nat_network->{dynamic} or return;
                    my $nat_tag = $nat_network->{nat_tag};
                    return if $obj->{nat}->{$nat_tag};
                    my $intf = $reversed ? $out_intf : $in_intf;

                    # $intf would have value 'undef' if $obj is
                    # interface of current router and src/dst of rule.
                    if (not $intf or zone_eq($network->{zone}, $intf->{zone})) {
                        err_msg("$obj->{name} needs static translation",
                                " for nat:$nat_tag at $router->{name}",
                                " to be valid in",
                                $reversed2 ? ' reversed rule for' : ' rule',
                                "\n ",
                                $show_rule->());
                    }
                };
                $check_common->($in_intf);
                if ($router->{model}->{stateless}) {
                    my $prt_list = $rule->{prt};

                    # Reversed tcp rule would check for
                    # 'established' flag and hence is harmless
                    # even if it can reach whole network, because
                    # it only sends answer back for correctly
                    # established connection.
                    if (grep { $_->{proto} =~ /^(?:udp|ip)$/ } @$prt_list) {
                        $check_common->($out_intf, 1);
                    }
                }
            };
            path_walk($path_rule, $check);
        }
        $nat_seen or $static_seen = 1;

        $hidden_seen and return;

        # Check error conditition:
        # Find sub-path where dynamic / hidden NAT is inversed,
        # i.e. dynamic / hidden NAT is enabled first and disabled later.

        # Find dynamic and hidden NAT definitions of $obj.
        # Key: NAT tag,
        # value: boolean, true=hidden, false=dynamic
        my $dyn_nat_hash;
        for my $nat_tag (keys %$nat_hash) {
            my $nat_network = $nat_hash->{$nat_tag};
            $nat_network->{dynamic} or next;
            my $is_hidden = $nat_network->{hidden};
            $is_hidden or $static_seen or next;
            $dyn_nat_hash->{$nat_tag} = $nat_network->{hidden};
        }
        $dyn_nat_hash or return;

        my ($src_path, $dst_path) = @{$path_rule}{qw(src_path dst_path)};
        my $interfaces =
            $cache{$src_path}->{$dst_path} || $cache{$dst_path}->{$src_path};

        if (not $interfaces) {
            $path_rule->{interfaces} = [];
            path_walk($path_rule, \&collect_path_interfaces);
            $interfaces = $cache{$src_path}->{$dst_path} =
                delete $path_rule->{interfaces};
        }

        for my $nat_tag (sort keys %$dyn_nat_hash) {
            my @nat_interfaces =
                grep({ $no_nat_set2active_tags{$_->{no_nat_set}}->{$nat_tag} }
                     @$interfaces) or next;
            my $names =
              join("\n - ",
                   map { $_->{name} } sort by_name unique @nat_interfaces);
            my $is_hidden = $dyn_nat_hash->{$nat_tag};
            my $type = $is_hidden ? 'hidden' : 'dynamic';
            err_msg(
                "Must not apply $type NAT '$nat_tag' on path\n",
                " of",
                $reversed ? ' reversed' : '',
                " rule\n",
                " ", $show_rule->(), "\n",
                " NAT '$nat_tag' is active at\n",
                " - $names\n",
                " Add pathrestriction to exclude this path"
            );
        }
    };

    for my $what (qw(src dst)) {
        my $reversed = $what eq 'dst';
        my $other = $reversed ? 'src' : 'dst';
        for my $rule (@{ $path_rules{deny} }, @{ $path_rules{permit} }) {
            my ($from_list, $to_list) = @{$rule}{$what, $other};
            for my $from (@$from_list) {
                my $from_net = $from->{network} || $from;
                $from_net->{nat} or next;
                my $cache_obj =
                    $from_net->{has_dynamic_host} ? $from : $from_net;
                for my $to (@$to_list) {
                    my $to_net = $to->{network} || $to;
                    next if $seen{$cache_obj}->{$to_net}++;
                    $check_dyn_nat_path->($rule,
                                          $from, $from_net,
                                          $to, $to_net,
                                          $reversed);
                }
            }
        }
    }
}

########################################################################
# Routing
########################################################################

##############################################################################
# Get networks for routing.
# Add largest supernet inside the zone, if available.
# This is needed, because we use the supernet in
# secondary optimization too.
# Moreover this reduces the number of routing entries.
# It isn't sufficient to solely use the supernet because network and supernet
# can have different next hops at end of path.
# For an aggregate, take all matching networks inside the zone.
# These are supernets by design.
sub get_route_networks {
    my ($list) = @_;
    my @result;
    for my $obj (@$list) {
        my $type = ref $obj;
        if ($type eq 'Network') {
            if ($obj->{is_aggregate}) {
                push @result, @{ $obj->{networks} };
            }
            elsif (my $max = $obj->{max_routing_net}) {
                push @result, $max, $obj;
            }
            else {
                push @result, $obj;
            }
        }
        elsif ($type eq 'Subnet' or $type eq 'Interface') {
            my $net = $obj->{network};
            if (my $max = $net->{max_routing_net}) {
                push @result, $max, $net;
            }
            else {
                push @result, $net;
            }
        }
    }
    return \@result;
}

##############################################################################
# Purpose    : Provide routing information inside a security zone.
# Parameters : $zone - a zone object.
# Results    : Every zone border interface I contains a hash attribute
#              {route_in_zone}, keeping the zones networks N reachable from I as
#              keys and the next hop interface H towards N as values.
# Comments   : A cluster is a maximal set of connected networks of the security
#              zone surrounded by hop interfaces. Clusters can be empty.
#              Optimization: a default route I->{route_in_zone}->{default} = [H]
#              is stored for those border interfaces, that reach networks in
#              zone via a single hop.
sub set_routes_in_zone {
    my ($zone) = @_;

    # Collect networks at zone border and next hop interfaces in lookup hashes.
    my %border_networks;
    my %hop_interfaces;

    # Collect networks at the zones interfaces as border networks.
    for my $in_interface (@{ $zone->{interfaces} }) {
        next if $in_interface->{main_interface};
        my $network = $in_interface->{network};
        next if $border_networks{$network};
        $border_networks{$network} = $network;

        # Collect non border interfaces of the networks as next hop interfaces.
        for my $out_interface (@{ $network->{interfaces} }) {
            next if $out_interface->{zone};
            next if $out_interface->{main_interface};
            $hop_interfaces{$out_interface} = $out_interface;
        }
    }
    return if not keys %hop_interfaces;

    # Zone preprocessing: define set of networks surrounded by hop IFs (cluster)
    # via depth first search to accelerate later DFS runs starting at hop IFs.
    my %hop2cluster; # Store hop IFs as key and reached clusters as values.
    my %cluster2borders; # Store directly linked border networks for clusters.
    my $set_cluster = sub {
        my ($router, $in_intf, $cluster) = @_;
        return if $router->{active_path};
        local $router->{active_path} = 1;

        # Process every interface.
        for my $interface (@{ $router->{interfaces} }) {
            next if $interface->{main_interface};

            # Found hop interface. Add its entries on the fly and skip.
            if ($hop_interfaces{$interface}) {
                $hop2cluster{$interface} = $cluster;
                my $network = $interface->{network};
                $cluster2borders{$cluster}->{$network} = $network;
                next;
            }
            next if $interface eq $in_intf;

            # Add network behind interface to cluster.
            my $network = $interface->{network};
            next if $cluster->{$network};
            $cluster->{$network} = $network;

            # Recursively proceed with adjacent routers.
            for my $out_intf (@{ $network->{interfaces} }) {
                next if $out_intf eq $interface;
                next if $out_intf->{main_interface};
                __SUB__->($out_intf->{router}, $out_intf, $cluster);
            }
        }
    };

    # Identify network cluster for every hop interface.
    for my $interface (values %hop_interfaces) {
        next if $hop2cluster{$interface}; # Hop interface was processed before.
        my $cluster = {};
        $set_cluster->($interface->{router}, $interface, $cluster);

#	debug("Cluster: $interface->{name} ",
#             join ',', map {$_->{name}} values %$cluster);
    }

    # Perform depth first search to collect all networks behind a hop interface.
    my %hop2networks; # Hash to store the collected sets.
    my $set_networks_behind = sub {
        my ($hop, $in_border) = @_;
        return if $hop2networks{$hop}; # Hop IF network set is known already.

        # Optimization: add networks of directly attached cluster.
        my $cluster = $hop2cluster{$hop};
        my @result = values %$cluster; # Spare multiple processing of branches.
        $hop2networks{$hop} = \@result;

        # Proceed depth first search with adjacent border networks.
        for my $border (values %{ $cluster2borders{$cluster} }) {
            next if $border eq $in_border;
            push @result, $border; # Add reachable border networks to set.

            # Add cluster members of clusters reachable via border networks:
            for my $out_hop (@{ $border->{interfaces} }) {
                next if not $hop_interfaces{$out_hop};
                next if $hop2cluster{$out_hop} eq $cluster;

                # Create hop2networks entry for reachable hops and add networks
                __SUB__->($out_hop, $border);
                push @result, @{ $hop2networks{$out_hop} };
            }
        }
        # Keep every found network only once per result set.
        $hop2networks{$hop} = [ unique @result ];

#	debug("Hop: $hop->{name} ", join ',', map {$_->{name}} @result);
    };

    # In every border IF, store reachable networks and corresponding hop IF.
    # Process every border network.
    for my $border (values %border_networks) {
        my @border_intf;
        my @hop_intf;

        # Collect border and hop interfaces of the current border network.
        for my $interface (@{ $border->{interfaces} }) {
            next if $interface->{main_interface};
            if ($interface->{zone}) {
                push @border_intf, $interface;
            }
            else {
                push @hop_intf, $interface;
            }
        }

        # Optimization: All networks in zone are located behind single hop:
        if (1 == @hop_intf or is_redundany_group(\@hop_intf)) {
            for my $interface (@border_intf) {

                # Spare reachable network specification.
                # debug("Default hop $interface->{name} ",
                #        join(',', map {$_->{name}} @hop_intf));
                $interface->{route_in_zone}->{default} = \@hop_intf;
            }
            next; # Proceed with next border network.
        }

        # For every hop IF of current network, gather reachable network set.
        for my $hop (@hop_intf) {
            $set_networks_behind->($hop, $border);

            # In border IF of current network, store reachable networks and hops
            for my $interface (@border_intf) {
                for my $network (@{ $hop2networks{$hop} }) {

                    # $border will be found accidently, if clusters
                    # form a loop inside zone.
                    next if $network eq $border;
                    push @{ $interface->{route_in_zone}->{$network} }, $hop;
                }
            }
        }
    }
}

##############################################################################
# Purpose    : Gather rule specific routing information at zone border
#              interfaces: For a pair ($in_intf,$out_intf) of zone border
#              interfaces that lies on a path from src to dst, the next hop
#              interfaces H to reach $out_intf from $in_intf are determined
#              and stored.
# Parameters : $in_intf - interface zone is entered from.
#              $out_intf - interface zone is left at.
#              $dst_networks - destination networks of associated pseudo rule.
# Results    : $in_intf holds routing information that $dst_networks are
#              reachable via next hop interface H.
sub add_path_routes {
    my ($in_intf, $out_intf, $dst_networks) = @_;

    # Interface with manual or dynamic routing.
    return if $in_intf->{routing};

    my $in_net  = $in_intf->{network};
    my $out_net = $out_intf->{network};

    # Identify hop interface(s).
    # Store hop interfaces and routing information within in_intf.
    if ($in_net eq $out_net) {
        $in_intf->{hopref2obj}->{$out_intf} = $out_intf;
        @{ $in_intf->{routes}->{$out_intf} }{@$dst_networks} = @$dst_networks;
    }
    else {
        my $route_in_zone = $in_intf->{route_in_zone};
        my $hops = $route_in_zone->{default} || $route_in_zone->{$out_net};
        for my $hop (@$hops) {
            $in_intf->{hopref2obj}->{$hop} = $hop;
            @{ $in_intf->{routes}->{$hop} }{@$dst_networks} = @$dst_networks;
        }
    }
}


#############################################################################
# Purpose    : Generate routing information for a single interface at zone
#              border. Store next hop interface to every destination network
#              inside zone within the given interface object.
# Parameters : $interface - border interface of a zone.
#              $dst_networks - destination networks inside the same zone.
# Results    : $interface holds routing entries about which hops to use to
#              reach the networks specified in $dst_networks.
sub add_end_routes {
    my ($interface, $dst_networks) = @_;

    # Interface with manual or dynamic routing.
    return if $interface->{routing};

    my $intf_net      = $interface->{network};
    my $route_in_zone = $interface->{route_in_zone};

    # For every dst network, check the hops that can be used to get there.
    for my $network (@$dst_networks) {
        next if $network eq $intf_net;
        my $hops = $route_in_zone->{default} || $route_in_zone->{$network}
          or internal_err("Missing route for $network->{name}",
                          " at $interface->{name}");

        # Store the used hops and routes within the interface object.
        for my $hop (@$hops) {
            $interface->{hopref2obj}->{$hop} = $hop;
#	     debug("$interface->{name} -> $hop->{name}: $network->{name}");
            $interface->{routes}->{$hop}->{$network} = $network;
        }
    }
}

##############################################################################
# Purpose    : Transfer routing information from interfaces passed on the
#              route for a given pseudo rule into the rule object.
# Parameters : $rule - reference of a pseudo rule from routing tree.
#              $in_intf - interface the zone is entered from.
#              $out_intf -interface the zone is left at.
# Comment    : path_walk calls this function for each zone on path from src
#              to dst to create complete route documentation for the path from
#              src to dst within the rule object.
sub get_route_path {
    my ($rule, $in_intf, $out_intf) = @_;

#    debug("collect: $rule->{src}->{name} -> $rule->{dst}->{name}");
#    my $info = '';
#    $info .= $in_intf->{name} if $in_intf;
#    $info .= ' -> ';
#    $info .= $out_intf->{name} if $out_intf;
#    debug($info);

    # Packets traverse the zone.
    if ($in_intf and $out_intf) {
        push @{ $rule->{path} }, [ $in_intf, $out_intf ];
    }

    # Zone contains rule source.
    elsif (not $in_intf) {
        push @{ $rule->{path_entries} }, $out_intf;
    }

    # Zone contains rule destination.
    else {
        push @{ $rule->{path_exits} }, $in_intf;
    }
}

##############################################################################
# Purpose    : Add information from single grouped rule to routing tree.
# Parameters : $rule - to be added grouped rule.
#              $is_intf - marker: which of src and/or dst is an interface.
#              $routing_tree - the routing tree.
sub generate_routing_tree1 {
    my ($rule, $is_intf, $routing_tree) = @_;

    my ($src, $dst, $src_zone, $dst_zone) =
        @{$rule}{qw(src dst src_path dst_path)};

    # Check, whether
    # - source interface is located in security zone of destination or
    # - destination interface is located in security zone of source.
    # In this case, path_walk will do nothing.
    if ($src_zone eq $dst_zone and $is_intf) {

        # Detect next hop interfaces if src/dst are zone border interfaces.
        for my $what (split ',', $is_intf) {
            my $from = $rule->{$what}->[0];
            my $to = $what eq 'src' ? $dst : $src;
            $from = $from->{main_interface} || $from;
            my $networks = get_route_networks($to);
            add_end_routes($from, $networks);
        }
        return;
    }

    # Construct a pseudo rule with zones as src and dst and store it.
    my $pseudo_rule;

    # Check whether pseudo rule for src and dst pair is stored already.
    if ($pseudo_rule = $routing_tree->{$src_zone}->{$dst_zone}) {
    }
    elsif ($pseudo_rule = $routing_tree->{$dst_zone}->{$src_zone}) {
        ($src,      $dst)      = ($dst,      $src);
        ($src_zone, $dst_zone) = ($dst_zone, $src_zone);

        # Change only if set:
        # 'src' -> 'dst, 'dst' -> 'src', 'src,dst' unchanged.
        $is_intf &&=
            $is_intf eq 'src' ? 'dst' : $is_intf eq 'dst' ? 'src' : $is_intf;
    }

    # Generate new pseudo rule otherwise.
    else {
        $pseudo_rule = {
            src      => $src,
            dst      => $dst,
            src_path => $src_zone,
            dst_path => $dst_zone,
            prt      => $rule->{prt},
            rule     => $rule->{rule},
        };
        $routing_tree->{$src_zone}->{$dst_zone} = $pseudo_rule;
    }

    # Store src and dst networks of grouped rule within pseudo rule.
    my $src_networks = get_route_networks($src);
    @{ $pseudo_rule->{src_networks} }{@$src_networks} = @$src_networks;
    my $dst_networks = get_route_networks($dst);
    @{ $pseudo_rule->{dst_networks} }{@$dst_networks} = @$dst_networks;


    # If src/dst is interface of managed routers, add this info to
    # pseudo rule.
    if ($is_intf) {
        for my $what (split ',', $is_intf) {
            my $intf = ($what eq 'src' ? $src : $dst)->[0];

#            debug "${what}_intf: $intf->{name}";
            my $router = $intf->{router};
            $router->{managed} or $router->{routing_only} or next;
            $intf = $intf->{main_interface} || $intf;
            $pseudo_rule->{"${what}_interfaces"}->{$intf} = $intf;
            my $list = $what eq 'src' ? $dst_networks : $src_networks;
            @{ $pseudo_rule->{"${what}_intf2nets"}->{$intf} }{@$list} = @$list;
        }
    }
}

#############################################################################
# Purpose : Generate the routing tree, holding pseudo rules that represent
#           the whole grouped rule set. As the pseudo rules are
#           generated to determine routes, ports are omitted, and rules
#           refering to the same src and dst zones are summarized.
# Returns : A reference to the generated routing tree.
sub generate_routing_tree {
    my $routing_tree = {};

    # Special handling needed for rules grouped not at zone pairs but
    # grouped at routers.
    for my $rule (@{ $path_rules{permit} }) {

#        debug print_rule $rule;
        my ($src, $dst, $src_path, $dst_path) =
            @{$rule}{qw(src dst src_path dst_path)};
        if (is_zone($src_path)) {

            # Common case, process directly.
            if (is_zone($dst_path)) {
                generate_routing_tree1($rule, '', $routing_tree);
            }

            # Split group of destination interfaces, one for each zone.
            else {
                for my $interface (@$dst) {
                    my $split_rule = { %$rule,
                                       dst => [ $interface ],
                                       dst_path => $interface->{zone}, };
                    generate_routing_tree1($split_rule, 'dst',$routing_tree);
                }
            }
        }
        elsif (is_zone($dst_path)) {
            for my $interface (@$src) {
                my $split_rule = { %$rule,
                                   src => [ $interface ],
                                   src_path => $interface->{zone},};
                generate_routing_tree1($split_rule, 'src', $routing_tree);
            }
        }
        else {
            for my $src_intf (@$src) {
                for my $dst_intf (@$dst) {
                    my $split_rule = { %$rule,
                                       src => [ $src_intf ],
                                       dst => [ $dst_intf ],
                                       src_path => $src_intf->{zone},
                                       dst_path => $dst_intf->{zone}, };
                    generate_routing_tree1($split_rule, 'src,dst',
                                           $routing_tree);
                }
            }
        }
    }
    return $routing_tree;
}

##############################################################################
# Purpose    : Generate routing information for every (source,destination)
#              pair of the ruleset and store it in the affected interfaces.
# Parameters : $routing_tree - a pseudo rule set.
# Results    : Every interface object holds next hop routing information
#              for the rules of original ruleset requiring a path passing the
#              interface.
sub generate_routing_info {
    my ($routing_tree) = @_;

    # Process every pseudo rule. Within its {path} atrribute....
    for my $href (values %$routing_tree) {
        for my $pseudo_rule (values %$href) {

            # store a pair (in_interface, exit_interface) for every passed zone.
            path_walk($pseudo_rule, \&get_route_path, 'Zone');

            # Extract sources and destinations from pseudo rule.
            my @src_networks   = values %{ $pseudo_rule->{src_networks} };
            my @dst_networks   = values %{ $pseudo_rule->{dst_networks} };
            my @src_interfaces = values %{ $pseudo_rule->{src_interfaces} };
            my @dst_interfaces = values %{ $pseudo_rule->{dst_interfaces} };

            # Determine routing information for every interface pair.
            for my $tuple (@{ $pseudo_rule->{path} }) {
                my ($in_intf, $out_intf) = @$tuple;
#                debug "$in_intf->{name} => $out_intf->{name}";
                add_path_routes($in_intf, $out_intf, \@dst_networks); # IFs incl
                add_path_routes($out_intf, $in_intf, \@src_networks); # IFs incl
            }

            # Determine routing information for IF of first zone on path.
            for my $entry (@{ $pseudo_rule->{path_entries} }) {

                # For src IFs at managed routers, generate routes in both IFs.
                for my $src_intf (@src_interfaces) {

                    # Do not generate routes for src IFs at path entry routers.
                    next if $src_intf->{router} eq $entry->{router};
                    if (my $redun_intf = $src_intf->{redundancy_interfaces}) {
                        if (grep { $_->{router} eq $entry->{router} }
                            @$redun_intf)
                        {
                            next;
                        }
                    }
                    my $intf_nets = [
                        values %{ $pseudo_rule->{src_intf2nets}->{$src_intf} }
                    ];
                    add_path_routes($src_intf, $entry, $intf_nets);
                }

                # For src networks, generate routes for zone IF only.
                add_end_routes($entry, \@src_networks);
            }

            # Determine routing information for IF of last zone on path.
            for my $exit (@{ $pseudo_rule->{path_exits} }) {

                # For dst IFs at managed routers, generate routes in both IFs.
                for my $dst_intf (@dst_interfaces) {

                    # Do not generate routes for dst IFs at path exit routers.
                    next if $dst_intf->{router} eq $exit->{router};
                    if (my $redun_intf = $dst_intf->{redundancy_interfaces}) {
                        if (grep { $_->{router} eq $exit->{router} }
                            @$redun_intf)
                        {
                            next;
                        }
                    }
                    my $intf_nets = [
                        values %{ $pseudo_rule->{dst_intf2nets}->{$dst_intf} }
                    ];
                    add_path_routes($dst_intf, $exit, $intf_nets);
                }

                # For dst networks, generate routes for zone IF only.
                add_end_routes($exit, \@dst_networks);
            }
        }
    }
}

sub check_and_convert_routes;
#############################################################################
# Purpose  : Generate and store routing information for all managed interfaces.
sub find_active_routes {
    progress('Finding routes');

    # Mark interfaces of unmanaged routers such that no routes are collected.
    for my $router (get_ipv4_ipv6_routers()) {
        $router->{semi_managed} and not $router->{routing_only} or next;
        for my $interface (@{ $router->{interfaces} }) {
            $interface->{routing} = 'dynamic';
        }
    }

    # Generate navigation information for routing inside zones.
    for my $zone (@zones) {
        set_routes_in_zone $zone;
    }

    # Generate pseudo rule set with all src dst pairs to determine routes for.
    my $routing_tree = generate_routing_tree;

    # Generate routing info for every pseudo rule and store it in interfaces.
    generate_routing_info $routing_tree;

    #
    check_and_convert_routes;
}

# Parameters:
# - a bridged interface without an IP address, not usable as hop.
# - the network for which the hop was found.
# Result:
# - one or more layer 3 interfaces, usable as hop.
# Non optimized version.
# Doesn't matter as long we have only a few bridged networks
# or don't use static routing at the border of bridged networks.
sub fix_bridged_hops;

sub fix_bridged_hops {
    my ($hop, $network) = @_;
    my @result;
    my $router = $hop->{router};
    for my $interface (@{ $router->{interfaces} }) {
        next if $interface eq $hop;
      HOP:
        for my $hop2 (values %{ $interface->{hopref2obj} }) {
            for my $network2 (values %{ $interface->{routes}->{$hop2} }) {
                if ($network eq $network2) {
                    if ($hop2->{ip} eq 'bridged') {
                        push @result, fix_bridged_hops($hop2, $network);
                    }
                    else {
                        push @result, $hop2;
                    }
                    next HOP;
                }
            }
        }
    }
    return @result;
}

sub check_and_convert_routes {

    # Fix routes where bridged interface without IP address is used as
    # next hop.
    for my $router (@managed_routers, @routing_only_routers) {
        for my $interface (@{ $router->{interfaces} }) {
            next if $interface->{routing};
            next if not $interface->{network}->{bridged};
            my $add_hops;
            for my $hop (values %{ $interface->{hopref2obj} }) {
                next if $hop->{ip} ne 'bridged';
                for my $network (values %{ $interface->{routes}->{$hop} }) {
                    my @real_hops = fix_bridged_hops($hop, $network);

                    # Add real hops later, after loop over {hopref2obj}
                    # has been finished.
                    push @$add_hops, @real_hops;

                    # Add network now, because real hops are known to
                    # be different from $hop.
                    $interface->{routes}->{$_}->{$network} = $network
                        for @real_hops;
                }
                delete $interface->{hopref2obj}->{$hop};
                delete $interface->{routes}->{$hop};
            }
            $add_hops or next;
            for my $rhop (@$add_hops) {
                $interface->{hopref2obj}->{$rhop} = $rhop;
            }
        }
    }

    for my $router (@managed_routers, @routing_only_routers) {

        # Adjust routes through VPN tunnel to cleartext interface.
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{ip} eq 'tunnel';
            my $real_intf = $interface->{real_interface};
            next if $real_intf->{routing};
            my $tunnel_routes = $interface->{routes};
            $interface->{routes} = $interface->{hopref2obj} = {};
            my $real_net  = $real_intf->{network};
            my $peer      = $interface->{peer};
            my $real_peer = $peer->{real_interface};
            my $peer_net  = $real_peer->{network};

            # Find hop to peer network and add tunneled networks to this hop.
            my @hops;

            # Peer network is directly connected.
            if ($real_net eq $peer_net) {
                if ($real_peer->{ip} !~ /^(?:short|negotiated)$/) {
                    push @hops, $real_peer;
                }
                else {
                    err_msg(
                        "$real_peer->{name} used to reach",
                        " software clients\n",
                        " must not be directly connected to",
                        " $real_intf->{name}\n",
                        " Connect it to some network behind next hop"
                    );
                    next;
                }
            }

            # Peer network is located in directly connected zone.
            elsif ($real_net->{zone} eq $peer_net->{zone}) {
                my $route_in_zone = $real_intf->{route_in_zone};
                my $hops =
                  ($route_in_zone->{default} || $route_in_zone->{$peer_net})
                  or internal_err("Missing route for $peer_net->{name}",
                                  " at $real_intf->{name} ");
                push @hops, @$hops;
            }

            # Find path to peer network to determine available hops.
            else {
                my $pseudo_rule = {
                    src    => $real_intf,
                    dst    => $peer_net,
                    action => '--',
                    prt    => { name => '--' },
                };
                my @zone_hops;
                my $walk = sub {
                    my (undef,  $in_intf, $out_intf) = @_;
                    $in_intf               or internal_err("No in_intf");
                    $in_intf eq $real_intf or return;
                    $out_intf              or internal_err("No out_intf");
                    $out_intf->{network}   or internal_err "No out net";
                    push @zone_hops, $out_intf;
                };
                single_path_walk($pseudo_rule, $walk, 'Zone');
                my $route_in_zone = $real_intf->{route_in_zone};
                for my $hop (@zone_hops) {

                    my $hop_net = $hop->{network};
                    if ($hop_net eq $real_net) {
                        push @hops, $hop;
                    }
                    else {
                        my $hops =
                          (      $route_in_zone->{default}
                              || $route_in_zone->{$hop_net})
                          or
                          internal_err("Missing route for $hop_net->{name}",
                            " at $real_intf->{name}");
                        push @hops, @$hops;
                    }
                }
            }

            my $hop_routes;
            if (@hops > 1
                and equal(map({ $_->{redundancy_interfaces} || $_ } @hops))
                or @hops == 1)
            {
                my $hop = shift @hops;
                $hop_routes = $real_intf->{routes}->{$hop} ||= {};
                $real_intf->{hopref2obj}->{$hop} = $hop;

#                debug "Use $hop->{name} as hop for $real_peer->{name}";
            }
            else {

                # This can only happen for vpn software clients.
                # For hardware clients  the route is known
                # for the encrypted traffic which is allowed
                # by gen_tunnel_rules (even for negotiated interface).
                my $count = @hops;
                my $names = join('', map({ "\n - $_->{name}" } @hops));
                err_msg(
                    "Can't determine next hop to reach $peer_net->{name}",
                    " while moving routes\n",
                    " of $interface->{name} to $real_intf->{name}.\n",
                    " Exactly one route is needed,",
                    " but $count candidates were found:",
                    $names
                );
            }

            # Use found hop to reach tunneled networks in $tunnel_routes.
            for my $tunnel_net_hash (values %$tunnel_routes) {
                for my $tunnel_net (values %$tunnel_net_hash) {
                    $hop_routes->{$tunnel_net} = $tunnel_net;
                }
            }

            # Add route to reach peer interface.
            if ($peer_net ne $real_net) {
                $hop_routes->{$peer_net} = $peer_net;
            }
        }

        # Remember, via which local interface a network is reached.
        my %net2intf;

        for my $interface (@{ $router->{interfaces} }) {

            # Collect error messages for sorted / deterministic output.
            my $errors;

            # Routing info not needed, because dynamic routing is in use.
            if ($interface->{routing} or $interface->{ip} eq 'bridged') {
                delete $interface->{hopref2obj};
                delete $interface->{routes};
                next;
            }

            # Remember, via which remote interface a network is reached.
            my %net2hop;

            # Remember, via which extra remote redundancy interfaces network2
            # are reached. We use this to check, that all members of a group
            # of redundancy interfaces are used to reach a network.
            # Otherwise it would be wrong to route to virtual interface.
            my (@net_behind_virt_hop, %net2extra_hops);

            # Abort, if more than one static route exists per network.
            for my $hop (sort by_name values %{ $interface->{hopref2obj} }) {
                for my $network (values %{ $interface->{routes}->{$hop} }) {

                    # Check if network is reached via two different
                    # local interfaces.
                    if (my $interface2 = $net2intf{$network}) {
                        if ($interface2 ne $interface) {
                            push(@$errors,
                                 "Two static routes for $network->{name}\n" .
                                 " via $interface->{name} and" .
                                 " $interface2->{name}");
                        }
                    }
                    else {
                        $net2intf{$network} = $interface;
                    }

                    # Check whether network is reached via different hops.
                    # Abort, if these do not belong to same  redundancy group.
                    my $group = $hop->{redundancy_interfaces};
                    if (my $hop2 = $net2hop{$network}) {

                        # If next hop belongs to same redundancy group,
                        # collect hops for detailed check below.
                        my $group2 = $hop2->{redundancy_interfaces};
                        if ($group and $group2 and $group eq $group2) {
                            delete $interface->{routes}->{$hop}->{$network};
                            push @{ $net2extra_hops{$network} }, $hop;

                        }
                        else {
                            push(@$errors,
                                 "Two static routes for $network->{name}\n" .
                                 " at $interface->{name}" .
                                 " via $hop->{name} and $hop2->{name}");
                        }
                    }
                    else {
                        $net2hop{$network} = $hop;
                        push @net_behind_virt_hop, $network if $group;
                    }
                }
            }

            # Ensure correct routing at virtual interfaces.
            # Check whether dst network is reached via all
            # redundancy interfaces.
            for my $network (@net_behind_virt_hop) {
                my $hop1 = $net2hop{$network};
                my $extra_hops = $net2extra_hops{$network} || [];
                my $missing =
                    @{ $hop1->{redundancy_interfaces} } - @$extra_hops - 1;
                next if not $missing;

                # If dst network is reached via exactly one interface,
                # move hop from virtual to physical interface.
                # Destination is probably a loopback interface of same
                # device.
                if (not @$extra_hops and (my $phys_hop = $hop1->{orig_main})) {
                    delete $interface->{routes}->{$hop1}->{$network};
                    $interface->{routes}->{$phys_hop}->{$network} = $network;
                    $interface->{hopref2obj}->{$phys_hop} = $phys_hop;
                    next;
                }

                # Show error message if dst network is reached by
                # more than one but not by all redundancy interfaces.
                my $names =
                    join "\n - ", sort map { $_->{name} } $hop1, @$extra_hops;
                push(@$errors,
                     "Pathrestriction ambiguously affects generation" .
                     " of static routes\n       to interfaces" .
                     " with virtual IP " .
                     print_ip($hop1->{ip}) . ":\n" .
                     " $network->{name} is reached via\n" .
                     " - $names\n" .
                     " But $missing interface(s) of group" .
                     " are missing.\n" .
                     " Remaining paths must traverse\n" .
                     " - all interfaces or\n" .
                     " - exactly one interface\n" .
                     " of this group.");
            }

            # Show error messages of both tests above.
            if ($errors) {
                err_msg($_) for sort @$errors;
            }

            # Convert to array, because hash isn't needed any longer.
            # Array is sorted to get deterministic output.
            $interface->{hopref2obj} =
              [ sort by_name values %{ $interface->{hopref2obj} } ];
        }
    }
}

sub ios_route_code;
sub prefix_code;
sub full_prefix_code;
sub address;

sub print_header {
    my ($router, $what) = @_;
    my $comment_char = $router->{model}->{comment_char};
    my $where = $router->{vrf_members} ? " for $router->{name}" : '';
    print "$comment_char [ $what$where ]\n";
}

sub print_routes {
    my ($router)              = @_;
    my $ipv6                  = $router->{ipv6};
    my $model                 = $router->{model};
    my $type                  = $model->{routing};
    my $vrf                   = $router->{vrf};
    my $do_auto_default_route = $config->{auto_default_route};
    my $zero_ip               = get_zero_ip($ipv6);
    my $crypto_type = $model->{crypto} || '';
    my $asa_crypto = $crypto_type eq 'ASA';
    my (%mask2ip2net, %net2hop_info);

    for my $interface (@{ $router->{interfaces} }) {

        # Must not combine static routes to default route if any
        # interface has dynamic routing enabled.
        if ($interface->{routing}) {
            $do_auto_default_route = 0;
            next;
        }

        # ASA with site-to-site VPN needs individual routes for each peer.
        if ($asa_crypto and $interface->{hub}) {
            $do_auto_default_route = 0;
        }
        my $hardware = $interface->{hardware};
        my $no_nat_set =
            $hardware->{crypto_no_nat_set} || $hardware->{no_nat_set};

        my $routes = $interface->{routes};
        for my $hop (@{ $interface->{hopref2obj} }) {
            my $hop_info = [ $interface, $hop ];

            # A hash having all networks reachable via current hop
            # both as key and as value.
            my $net_hash = $routes->{$hop};
            for my $network (values %$net_hash) {
                my $nat_network = get_nat_network($network, $no_nat_set);
                next if $nat_network->{hidden};
                my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };
                if ($ip eq $zero_ip and $mask eq $zero_ip) {
                    $do_auto_default_route = 0;
                }

                # Implicitly overwrite duplicate networks.
                $mask2ip2net{$mask}->{$ip} = $nat_network;

                # This is unambiguous, because only a single static
                # route is allowed for each network.
                $net2hop_info{$nat_network} = $hop_info;
            }
        }
    }
    return if not keys %net2hop_info;

    # Combine adjacent networks, if both use same hop and
    # if combined network doesn't already exist.
    # Prepare @inv_prefix_aref.
    my @inv_prefix_aref;
    my $bitstr_len = $ipv6 ? 128 : 32;
    for my $mask (keys %mask2ip2net) {
        my $inv_prefix  = $bitstr_len - mask2prefix($mask);
        my $ip2net = $mask2ip2net{$mask};
        for my $ip (keys %$ip2net) {
            my $network = $ip2net->{$ip};

            # Don't combine peers of ASA with site-to-site VPN.
            if ($asa_crypto) {
                my $hop_info = $net2hop_info{$network};
                my $interface = $hop_info->[0];
                next if $interface->{hub};
            }
            $inv_prefix_aref[$inv_prefix]->{$ip} = $network;
        }
    }

    # Go from small to large networks. So we combine newly added
    # networks as well.
    for (my $inv_prefix = 0 ; $inv_prefix < @inv_prefix_aref ; $inv_prefix++) {
        next if $inv_prefix >= $bitstr_len;
        my $ip2net = $inv_prefix_aref[$inv_prefix] or next;
        my $part_mask = prefix2mask($bitstr_len - $inv_prefix, $ipv6);
        my $combined_inv_prefix = $inv_prefix + 1;
        my $combined_inv_mask =
            ~ prefix2mask($bitstr_len - $combined_inv_prefix, $ipv6);

        # A single bit, masking the lowest network bit.
        my $next = $combined_inv_mask & $part_mask;

        for my $ip (keys %$ip2net) {

            # Only analyze left part of two adjacent networks.
            ($ip & $next) eq $zero_ip or next;
            my $left = $ip2net->{$ip};

            # Find corresponding right part.
            my $next_ip = $ip | $next;
            my $right   = $ip2net->{$next_ip} or next;

            # Both parts must use equal next hop.
            my $hop_left  = $net2hop_info{$left};
            my $hop_right = $net2hop_info{$right};
            $hop_left eq $hop_right or next;

            # Combined network already exists.
            next if $inv_prefix_aref[$combined_inv_prefix]->{$ip};

            # Add combined route.
            my $mask = ~ $combined_inv_mask;
            my $combined = { ip => $ip, mask => $mask };
            $inv_prefix_aref[$combined_inv_prefix]->{$ip} = $combined;
            $mask2ip2net{$mask}->{$ip} = $combined;
            $net2hop_info{$combined} = $hop_left;

            # Left and right part are no longer used.
            delete $mask2ip2net{$part_mask}->{$ip};
            delete $mask2ip2net{$part_mask}->{$next_ip};
        }
    }

    # Find and remove duplicate networks.
    # Go from smaller to larger networks.
    my @masks = reverse sort keys %mask2ip2net;
    my (%intf2hop2nets, %net2no_opt);
    while (defined(my $mask = shift @masks)) {
      NETWORK:
        for my $ip (sort keys %{ $mask2ip2net{$mask} }) {
            my $small    = $mask2ip2net{$mask}->{$ip};
            my $hop_info = $net2hop_info{$small};
            my ($interface, $hop) = @$hop_info;

            # ASA with site-to-site VPN needs individual routes for each peer.
            if (not ($asa_crypto and $interface->{hub})) {

                # Compare current $mask with masks of larger networks.
                for my $m (@masks) {
                    my $i = $ip & $m;
                    my $ip2net = $mask2ip2net{$m} or next;
                    my $big    = $ip2net->{$i}    or next;

                    # $small is subnet of $big.
                    # If both use the same hop, then $small is redundant.
                    if ($net2hop_info{$big} eq $hop_info) {

#                        debug "Removed: $small->{name} -> $hop->{name}";
                        next NETWORK;
                    }

                    # Otherwise $small isn't redundant, even if a bigger network
                    # with same hop exists.
                    # It must not be removed by default route later.
                    $net2no_opt{$small} = 1;

#                    debug "No opt: $small->{name} -> $hop->{name}";
                    last;
                }
            }
            push(
                @{ $intf2hop2nets{$interface}->{$hop} },
                [ $ip, $mask, $small ]
            );
        }
    }

    if ($do_auto_default_route) {

        # Find interface and hop with largest number of routing entries.
        my $max_intf;
        my $max_hop;

        # Substitute routes to one hop with a default route,
        # if there are at least two entries.
        my $max = 1;
        for my $interface (@{ $router->{interfaces} }) {
            my $hop2nets = $intf2hop2nets{$interface};
            for my $hop (@{ $interface->{hopref2obj} }) {
                my $count = grep({ not $net2no_opt{ $_->[2] } }
                                 @{ $hop2nets->{$hop} || [] });
                if ($count > $max) {
                    $max_intf = $interface;
                    $max_hop  = $hop;
                    $max      = $count;
                }
            }
        }
        if ($max_intf and $max_hop) {

            # Use default route for this direction.
            # But still generate routes for small networks
            # with supernet behind other hop.
            $intf2hop2nets{$max_intf}->{$max_hop} = [
                [ $zero_ip, $zero_ip ],
                grep({ $net2no_opt{ $_->[2] } }
                    @{ $intf2hop2nets{$max_intf}->{$max_hop} })
            ];
        }
    }
    print_header($router, 'Routing');

    my $ios_vrf;
    $ios_vrf = $vrf ? "vrf $vrf " : '' if $type eq 'IOS';
    my $nxos_prefix = '';

    for my $interface (@{ $router->{interfaces} }) {
        my $hop2nets = $intf2hop2nets{$interface};
        for my $hop (@{ $interface->{hopref2obj} }) {

            # For unnumbered and negotiated interfaces use interface name
            # as next hop.
            my $hop_addr =
                $interface->{ip} =~ /^(?:unnumbered|negotiated|tunnel)$/
              ? $interface->{hardware}->{name}
              : print_ip $hop->{ip};

            for my $netinfo (@{ $hop2nets->{$hop} }) {
                if ($type eq 'IOS') {
                    my $adr = $ipv6 ?
                        full_prefix_code($netinfo) : ios_route_code($netinfo);
                    my $ip = $ipv6 ? 'ipv6' : 'ip';
                    print "$ip route $ios_vrf$adr $hop_addr\n";
                }
                elsif ($type eq 'NX-OS') {
                    if ($vrf and not $nxos_prefix) {

                        # Print "vrf context" only once
                        # and indent "ip route" commands.
                        print "vrf context $vrf\n";
                        $nxos_prefix = ' ';
                    }
                    my $adr = full_prefix_code($netinfo);
                    my $ip = $ipv6 ? 'ipv6' : 'ip';
                    print "$nxos_prefix$ip route $adr $hop_addr\n";
                }
                elsif ($type eq 'ASA') {
                    my $adr = $ipv6 ?
                        full_prefix_code($netinfo) : ios_route_code($netinfo);
                    print "ipv6 " if $ipv6;
                    print "route $interface->{hardware}->{name} $adr $hop_addr\n";
                }
                elsif ($type eq 'iproute') {
                    my $adr = prefix_code($netinfo);
                    print "ip route add $adr via $hop_addr\n";
                }
                elsif ($type eq 'none') {

                    # Do nothing.
                }
            }
        }
    }
}

##############################################################################
# Distributing rules to managed devices
##############################################################################

sub distribute_rule {
    my ($rule, $in_intf, $out_intf) = @_;

    # Traffic from src reaches this router via in_intf
    # and leaves it via out_intf.
    # in_intf is undefined if src is an interface of current router.
    # out_intf is undefined if dst is an interface of current router.
    # Outgoing packets from a router itself are never filtered.
    return unless $in_intf;
    my $router  = $in_intf->{router};
    $router->{managed} or return;
    my $model   = $router->{model};

    # Rules of type stateless must only be processed at
    # - stateless routers or
    # - routers which are stateless for packets destined for
    #   their own interfaces or
    # - stateless tunnel interfaces of ASA-VPN.
    if ($rule->{stateless}) {
        if (
            not($model->{stateless}
                or not $out_intf and $model->{stateless_self})
          )
        {
            return;
        }
    }

    # Rules of type stateless_icmp must only be processed at routers
    # which don't handle stateless_icmp automatically;
    return if $rule->{stateless_icmp} and not $model->{stateless_icmp};

    # Don't generate code for src any:[interface:r.loopback] at router:r.
    return if $in_intf->{loopback};

    # Apply only matching rules to 'managed=local' router.
    # Filter out non matching elements from src_list and dst_list.
    if (my $mark = $router->{local_mark}) {
        my $match = sub {
            my ($obj) = @_;
            my $net       = $obj->{network} || $obj;
            my $filter_at = $net->{filter_at} or return;
            return $filter_at->{$mark};
        };

        # Filter src_list and dst_list. Ignore rule if no matching element.
        my $src_list = $rule->{src};
        my @matching_src = grep { $match->($_) } @$src_list or return;
        my $dst_list = $rule->{dst};
        my @matching_dst = grep { $match->($_) } @$dst_list or return;

        # Create copy of rule. Try to reuse original src_list / dst_list.
        $rule = { %$rule };

        # Overwrite only if list has changed.
        if (@$src_list != @matching_src) {
            $rule->{src} = \@matching_src;
        }
        if (@$dst_list != @matching_dst) {
            $rule->{dst} = \@matching_dst;
        }
    }

    my $key;

    # Packets for the router itself.
    if (not $out_intf) {

        # No ACL generated for traffic to device itself.
        return if $model->{filter} eq 'ASA';

        $key = 'intf_rules';
    }
    else {
        if ($out_intf->{hardware}->{need_out_acl}) {
            push @{ $out_intf->{hardware}->{out_rules} }, $rule;
            return if $in_intf->{hardware}->{no_in_acl};
        }

        # Outgoing rules are needed at tunnel for generating
        # detailed_crypto_acl.
        if ($out_intf->{ip} eq 'tunnel' and
            $out_intf->{crypto}->{detailed_crypto_acl} and
            not $out_intf->{id_rules})
        {
            push @{ $out_intf->{out_rules} }, $rule;
        }
        $key = 'rules';
    }

    if ($in_intf->{ip} eq 'tunnel') {

        # Rules for single software clients are stored individually.
        # Consistency checks have already been done at expand_crypto.
        # Rules are needed at tunnel for generating split tunnel ACL
        # regardless of $model->{no_crypto_filter} value.
        if (my $id2rules = $in_intf->{id_rules}) {
            my $src_list = $rule->{src};

            # Check individual ID hosts of network at authenticating router.
            if (grep { $_->{has_id_hosts} } @$src_list) {
                my @host_list;
                for my $src (@$src_list) {
                    if ($src->{has_id_hosts}) {
                        push @host_list, @{ $src->{subnets} };
                    }
                    else {
                        push @host_list, $src;
                    }
                }
                $src_list = \@host_list;
                $rule = { %$rule, src => $src_list };
            }

            my %id2src_list;
            for my $src (@$src_list) {
                my $id = $src->{id};
                push @{ $id2src_list{$id} }, $src;
            }
            for my $id (keys %id2src_list) {
                my $id_src_list = $id2src_list{$id};

                # Try to reuse original rule for memory efficiency.
                my $new_rule = $rule;
                if (@$src_list != @$id_src_list) {
                    $new_rule = { %$rule, src => $id_src_list };
                }
                push @{ $id2rules->{$id}->{$key} }, $new_rule;
            }
        }

        # Rules are needed at tunnel for generating
        # detailed_crypto_acl or crypto_filter ACL.
        elsif (not $model->{no_crypto_filter} or
               $in_intf->{crypto}->{detailed_crypto_acl})
        {
            push @{ $in_intf->{$key} }, $rule;
        }

        if ($model->{no_crypto_filter}) {
            push @{ $in_intf->{real_interface}->{hardware}->{$key} }, $rule;
        }
    }

    # Remember outgoing interface.
    elsif ($key eq 'rules' and $model->{has_io_acl}) {
        push
          @{ $in_intf->{hardware}->{io_rules}->{ $out_intf->{hardware}->{name} }
          }, $rule;
    }
    else {
        push @{ $in_intf->{hardware}->{$key} }, $rule;
    }
}

my $deny_any_rule;
my $deny_any6_rule;
my $permit_any_rule;
my $permit_any6_rule;

sub get_multicast_objects {
    my ($info, $ipv6) = @_;
    my $ip_list;
    if ($ipv6) {
        $ip_list = $info->{mcast6};
    }
    else {
        $ip_list = $info->{mcast};
    }
    return [
        map { my $ip = ip2bitstr($_);
              new('Network', ip => $ip, mask => get_host_mask($ip)) } @$ip_list
        ];
}

sub add_router_acls {
    for my $router (@managed_routers) {
        my $ipv6 = $router->{ipv6};
        my $has_io_acl = $router->{model}->{has_io_acl};
        my $hardware_list = $router->{hardware};
        for my $hardware (@$hardware_list) {

            # Some managed devices are connected by a crosslink network.
            # Permit any traffic at the internal crosslink interface.
            if ($hardware->{crosslink}) {
                my $permit_any = $ipv6 ? $permit_any6_rule : $permit_any_rule;

                # We can savely change rules at hardware interface
                # because it has been checked that no other logical
                # networks are attached to the same hardware.
                #
                # Substitute or set rules for each outgoing interface.
                if ($has_io_acl) {
                    for my $out_hardware (@$hardware_list) {
                        next if $hardware eq $out_hardware;
                        $hardware->{io_rules}->{ $out_hardware->{name} } =
                            [$permit_any];
                    }
                }
                else {
                    $hardware->{rules} = [$permit_any];
                    if ($hardware->{need_out_acl}) {
                        $hardware->{out_rules} = [$permit_any];
                    }
                }
                $hardware->{intf_rules} = [$permit_any];
                next;
            }

            for my $interface (@{ $hardware->{interfaces} }) {

                # Current router is used as default router even for
                # some internal networks.
                if ($interface->{reroute_permit}) {
                    my $net_list = $interface->{reroute_permit};
                    my $rule = {
                        src => [ get_network_00($ipv6) ],
                        dst => $net_list,
                        prt => [ $prt_ip ]
                    };

                    # Prepend to all other rules.
                    if ($has_io_acl) {

                        # Incoming and outgoing interface are equal.
                        my $hw_name = $hardware->{name};
                        unshift@{ $hardware->{io_rules}->{$hw_name} }, $rule;
                    }
                    else {
                        unshift @{ $hardware->{rules} }, $rule;
                    }
                }

                # Is dynamic routing used?
                if (my $routing = $interface->{routing}) {
                    if ($routing->{name} !~ /^(?:manual|dynamic)$/) {
                        my $prt = $routing->{prt};
                        $prt = [ $prt ];
                        my $network = [ $interface->{network} ];

                        # Permit multicast packets from current network.
                        my $mcast = get_multicast_objects($routing, $ipv6);
                        push @{ $hardware->{intf_rules} },
                          {
                            src => $network,
                            dst => $mcast,
                            prt => $prt
                          };

                        # Additionally permit unicast packets.
                        # We use the network address as destination
                        # instead of the interface address,
                        # because we get fewer rules if the interface has
                        # multiple addresses.
                        push @{ $hardware->{intf_rules} },
                          {
                            src => $network,
                            dst => $network,
                            prt => $prt
                          };
                    }
                }

                # Handle multicast packets of redundancy protocols.
                if (my $type = $interface->{redundancy_type}) {
                    my $network = $interface->{network};
                    my $xrrp    = $xxrp_info{$type};
                    my $mcast   = get_multicast_objects($xrrp, $ipv6);
                    my $prt     = $xrrp->{prt};
                    push @{ $hardware->{intf_rules} },
                      {
                        src => [ $network ],
                        dst => $mcast,
                        prt => [ $prt ]
                      };
                }

                # Handle DHCP requests.
                if ($interface->{dhcp_server}) {
                    push @{ $hardware->{intf_rules} },
                      {
                        src => [ get_network_00($ipv6) ],
                        dst => [ get_network_00($ipv6) ],
                        prt => [ $prt_bootps ]
                      };
                }

                # Handle DHCP answer.
                if ($interface->{dhcp_client}) {
                    push @{ $hardware->{intf_rules} },
                      {
                        src => [ get_network_00($ipv6) ],
                        dst => [ get_network_00($ipv6) ],
                        prt => [ $prt_bootpc ]
                      };
                }
            }
        }
    }
}

sub create_general_permit_rules {
    my ($protocols, $ipv6) = @_;
    my @prt = map {   ref($_) eq 'ARRAY'
                    ? $_->[1]	# take dst range; src range was error before.
                    : $_->{main_prt}
                    ? $_->{main_prt}
                    : $_ } @$protocols;
    my $rule = {
        src => [ get_network_00($ipv6) ],
        dst => [ get_network_00($ipv6) ],
        prt => \@prt,
    };
    return $rule;
}

sub distribute_general_permit {
    for my $router (@managed_routers) {
        my $ipv6 = $router->{ipv6};
        my $general_permit = $router->{general_permit} or next;
        my $rule = create_general_permit_rules($general_permit, $ipv6);
        my $need_protect = $router->{need_protect};
        for my $in_intf (@{ $router->{interfaces} }) {
            next if $in_intf->{main_interface};

            # At VPN hub, don't permit any -> any, but only traffic
            # from each encrypted network.
            if ($in_intf->{is_hub}) {
                my $id_rules = $in_intf->{id_rules};
                for my $src (
                    $id_rules
                    ? sort by_name map({ $_->{src} } values %$id_rules)
                    : @{ $in_intf->{peer_networks} }
                  )
                {
                    my $rule = {%$rule};
                    $rule->{src} = [ $src ];
                    for my $out_intf (@{ $router->{interfaces} }) {
                        next if $out_intf eq $in_intf;
                        next if $out_intf->{ip} eq 'tunnel';

                        # Traffic traverses the device. Traffic for
                        # the device itself isn't needed at VPN hub.
                        distribute_rule($rule, $in_intf, $out_intf);
                    }
                }
            }
            else {
                for my $out_intf (@{ $router->{interfaces} }) {
                    next if $out_intf eq $in_intf;

                    # For IOS and NX-OS print this rule only
                    # once at interface filter rules below
                    # (for incoming ACL).
                    if ($need_protect) {
                        my $out_hw = $out_intf->{hardware};

                        # For interface with outgoing ACLs
                        # we need to add the rule.
                        # distribute_rule would add rule to incoming,
                        # hence we add rule directly to outgoing rules.
                        if ($out_hw->{need_out_acl}) {
                            push @{ $out_hw->{out_rules} }, $rule;
                        }
                        next;
                    }
                    next if $out_intf->{main_interface};

                    # Traffic traverses the device.
                    distribute_rule($rule, $in_intf, $out_intf);
                }

                # Traffic for the device itself.
                next if $in_intf->{ip} eq 'bridged';
                distribute_rule($rule, $in_intf, undef);
            }
        }
    }
}

sub rules_distribution {
    progress('Distributing rules');

    # Deny rules
    for my $rule (@{ $path_rules{deny} }) {
        path_walk($rule, \&distribute_rule);
    }

    # Handle global permit after deny rules.
    distribute_general_permit();

    # Permit rules
    for my $rule (@{ $path_rules{permit} }) {
        path_walk($rule, \&distribute_rule, 'Router');
    }

    add_router_acls();

    # No longer needed, free some memory.
    %obj2path       = ();
}

##############################################################################
# ACL Generation
##############################################################################

# Returns [ ip, mask ] pair
sub address {
    my ($obj, $no_nat_set) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        $obj = get_nat_network($obj, $no_nat_set);
        my $ip = $obj->{ip};
        return [ $ip, $obj->{mask} ];
    }
    elsif ($type eq 'Subnet') {
        my $network = get_nat_network($obj->{network}, $no_nat_set);
        if ($network->{dynamic}) {
            my $nat_tag = $network->{nat_tag};
            if (my $ip = $obj->{nat}->{$nat_tag}) {

                # Single static NAT IP for this host.
                return [ $ip, get_host_mask($ip) ];
            }
            else {
                return [ $network->{ip}, $network->{mask} ];
            }
        }
        else {

            # Take higher bits from network NAT, lower bits from original IP.
            # This works with and without NAT.
            my $ip =
              $network->{ip} | $obj->{ip} & ~ $network->{mask};
            return [ $ip, $obj->{mask} ];
        }
    }
    elsif ($type eq 'Interface') {
        my $ip = $obj->{ip};

        my $network = get_nat_network($obj->{network}, $no_nat_set);

        if ($ip eq 'negotiated') {
            my ($network_ip, $network_mask) = @{$network}{qw(ip mask)};
            return [ $network_ip, $network_mask ];
        }
        elsif ($network->{dynamic}) {
            my $nat_tag = $network->{nat_tag};
            if (my $ip = $obj->{nat}->{$nat_tag}) {

                # Single static NAT IP for this interface.
                return [ $ip, get_host_mask($ip) ];
            }
            else {
                return [ $network->{ip}, $network->{mask} ];
            }
        }
        else {

            # Take higher bits from network NAT, lower bits from original IP.
            # This works with and without NAT.
            $ip = $network->{ip} | $ip & ~ $network->{mask};
            return [ $ip, get_host_mask($ip) ];
        }
    }
}

sub ios_route_code {
    my ($pair) = @_;
    my ($ip, $mask) = @$pair;
    my $ip_code   = print_ip($ip);
    my $mask_code = print_ip($mask);
    return "$ip_code $mask_code";
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32.
sub prefix_code {
    my ($pair) = @_;
    my ($ip, $mask) = @$pair;
    my $ip_code     = print_ip($ip);
    return is_host_mask($mask) ? $ip_code : "$ip_code/" . mask2prefix($mask);
}

sub full_prefix_code {
    my ($pair) = @_;
    my ($ip, $mask) = @$pair;
    my $ip_code     = print_ip($ip);
    my $prefix_code = mask2prefix($mask);
    return "$ip_code/$prefix_code";
}

sub print_acl_placeholder {
    my ($router, $acl_name) = @_;

    # Add comment at start of ACL to easier find first ACL line in tests.
    my $model = $router->{model};
    my $filter = $model->{filter};
    if ($filter eq 'ASA') {
        my $comment_char = $model->{comment_char};
        print "$comment_char $acl_name\n";
    }

    print "#insert $acl_name\n";
}

# Parameter: Interface
# Analyzes dst/src_list of all rules collected at this interface.
# Result:
# List of all networks which are reachable when entering this interface.
sub get_split_tunnel_nets {
    my ($interface) = @_;

    my %split_tunnel_nets;
    for my $what (qw(rules intf_rules out_rules)) {
        my $rules = $interface->{$what} or next;
        my $where = $what eq 'out_rules' ? 'src' : 'dst';
        for my $rule (@$rules) {
            next if $rule->{deny};
            my $obj_list = $rule->{$where};
            for my $obj (@$obj_list) {
                my $network = $obj->{network} || $obj;

                # Don't add 'any' (resulting from global:permit)
                # to split_tunnel networks.
                next if is_zero_ip($network->{mask});

                $split_tunnel_nets{$network} = $network;
            }
        }
    }
    return [ sort { $a->{ip} cmp $b->{ip} || $a->{mask} cmp $b->{mask} }
          values %split_tunnel_nets ];
}

my %asa_vpn_attr_need_value =
  map { $_ => 1 }
  qw(banner dns-server default-domain split-dns wins-server address-pools
  split-tunnel-network-list vpn-filter);

sub print_asavpn {
    my ($router) = @_;
    my $ipv6 = $router->{ipv6};

    my $global_group_name = 'global';
    print <<"EOF";
group-policy $global_group_name internal
group-policy $global_group_name attributes
 pfs enable

EOF

    # Define tunnel group used for single VPN users.
    my $default_tunnel_group = 'VPN-single';
    my $trust_point          = $router->{trust_point};

    print <<"EOF";
tunnel-group $default_tunnel_group type remote-access
tunnel-group $default_tunnel_group general-attributes
 authorization-server-group LOCAL
 default-group-policy $global_group_name
 authorization-required
 username-from-certificate EA
tunnel-group $default_tunnel_group ipsec-attributes
 chain
EOF

    print <<"EOF";
 ikev1 trust-point $trust_point
 ikev1 user-authentication none
tunnel-group $default_tunnel_group webvpn-attributes
 authentication certificate
EOF

    print <<"EOF";
tunnel-group-map default-group $default_tunnel_group

EOF

    my $print_group_policy = sub {
        my ($name, $attributes) = @_;
        print "group-policy $name internal\n";
        print "group-policy $name attributes\n";
        for my $key (sort keys %$attributes) {
            my $value = $attributes->{$key};
            my $out   = $key;
            if (defined($value)) {
                $out .= ' value' if $asa_vpn_attr_need_value{$key};
                $out .= " $value";
            }
            print " $out\n";
        }
    };

    # Use id with normal length as name for group-policy, etc.
    # Total length is limited to 64 characters.
    # Max prefix is 11 characters "VPN-tunnel-"
    # Max postfix is 7 "-drc-nn".
    # Hence, usable length is limited to 46 characters.
    # Use running integer, if id is too long.
    my $id_counter = 1;
    my $gen_id_name = sub {
        my ($id) = @_;
        return length($id) <= 46 ? $id : $id_counter++;
    };
    my %cert_group_map;
    my %single_cert_map;
    my $acl_counter = 1;
    my $deny_any = $ipv6 ? $deny_any6_rule : $deny_any_rule;
    for my $interface (@{ $router->{interfaces} }) {
        next if not $interface->{ip} eq 'tunnel';
        my $no_nat_set = $interface->{no_nat_set};
        my %split_t_cache;

        if (my $hash = $interface->{id_rules}) {
            for my $id (sort keys %$hash) {
                my $id_intf = $hash->{$id};
                my $id_name = $gen_id_name->($id);
                my $src     = $id_intf->{src};
                my $pool_name;
                my $attributes = {
                    %{ $router->{radius_attributes} },
                    %{ $src->{network}->{radius_attributes} },
                    %{ $src->{radius_attributes} },
                };

                # Define split tunnel ACL.
                # Use default value if not defined.
                my $split_tunnel_policy = $attributes->{'split-tunnel-policy'};
                if (not defined $split_tunnel_policy) {

                    # Do nothing.
                }
                elsif ($split_tunnel_policy eq 'tunnelall') {

                    # This is the default value.
                    # Prevent new group-policy to be created.
                    delete $attributes->{'split-tunnel-policy'};
                }
                elsif ($split_tunnel_policy eq 'tunnelspecified') {
                    my $split_tunnel_nets = get_split_tunnel_nets($id_intf);
                    my $acl_name;
                    if (my $href = $split_t_cache{@$split_tunnel_nets}) {
                      CACHED_NETS:
                        for my $cached_name (keys %$href) {
                            my $cached_nets = $href->{$cached_name};
                            for (my $i = 0 ; $i < @$cached_nets ; $i++) {
                                if ($split_tunnel_nets->[$i] ne
                                    $cached_nets->[$i])
                                {
                                    next CACHED_NETS;
                                }
                            }
                            $acl_name = $cached_name;
                            last;
                        }
                    }
                    if (not $acl_name) {
                        $acl_name = "split-tunnel-$acl_counter";
                        $acl_counter++;
                        my $rules;
                        if (@$split_tunnel_nets) {
                            $rules = [ {
                                src => $split_tunnel_nets,
                                dst => [ get_network_00($ipv6) ],
                                prt => [ $prt_ip ],
                            } ];
                        }
                        else {
                            $rules = [ $deny_any ];
                        }
                        $split_t_cache{@$split_tunnel_nets}->{$acl_name} =
                          $split_tunnel_nets;
                        my $acl_info = {
                            name          => $acl_name,
                            rules         => $rules,
                            no_nat_set    => $no_nat_set,
                            is_std_acl    => 1,
                            is_crypto_acl => 1,
                        };
                        push @{ $router->{acl_list} }, $acl_info;
                        print_acl_placeholder($router, $acl_name);
                    }
                    $attributes->{'split-tunnel-network-list'} = $acl_name;
                }

                # Access list will be bound to cleartext interface.
                # Only check for valid source address at vpn-filter.
                $id_intf->{rules}      = [
                    {
                        src => [ $src ],
                        dst => [ get_network_00($ipv6) ],
                        prt => [ $prt_ip ],
                    }
                ];
                my $filter_name = "vpn-filter-$id_name";
                my $acl_info = {
                    name => $filter_name,
                    rules => delete $id_intf->{rules},
                    add_deny => 1,
                    no_nat_set => $no_nat_set,
                };
                push @{ $router->{acl_list} }, $acl_info;
                print_acl_placeholder($router, $filter_name);

                my $ip      = print_ip $src->{ip};
                my $network = $src->{network};
                if (is_host_mask($src->{mask})) {

                    # For anyconnect clients.
                    my (undef, $domain) = ($id =~ /^(.*?)(\@.*)$/);
                    $single_cert_map{$domain} = 1;

                    my $mask = print_ip $network->{mask};
                    my $group_policy_name;
                    if (%$attributes) {
                        $group_policy_name = "VPN-group-$id_name";
                        $print_group_policy->($group_policy_name, $attributes);
                    }
                    print "username $id nopassword\n";
                    print "username $id attributes\n";
                    print " vpn-framed-ip-address $ip $mask\n";
                    print " service-type remote-access\n";
                    print " vpn-filter value $filter_name\n";
                    print " vpn-group-policy $group_policy_name\n"
                      if $group_policy_name;
                    print "\n";
                }
                else {
                    $pool_name = "pool-$id_name";
                    my $mask = print_ip $src->{mask};
                    my $max =
                      print_ip($src->{ip} | ~ $src->{mask});
                    my $subject_name =
                      delete $attributes->{'check-subject-name'};
                    if ($id =~ /^@/) {
                        $subject_name = 'ea';
                    }
                    my $map_name = "ca-map-$id_name";
                    print "crypto ca certificate map $map_name 10\n";
                    print " subject-name attr $subject_name co $id\n";
                    print "ip local pool $pool_name $ip-$max mask $mask\n";
                    $attributes->{'vpn-filter'}    = $filter_name;
                    $attributes->{'address-pools'} = $pool_name;
                    my $group_policy_name = "VPN-group-$id_name";
                    my @tunnel_gen_att =
                      ("default-group-policy $group_policy_name");

                    # Select attributes for tunnel-group general-attributes.
                    for my $key (sort keys %$attributes) {
                        my $spec = $asa_vpn_attributes{$key};
                        if ($spec and $spec->{tg_general}) {
                            my $value = delete $attributes->{$key};
                            my $out = defined($value) ? "$key $value" : $key;
                            push(@tunnel_gen_att, $out);
                        }
                    }

                    my $trustpoint2 =
                        delete $attributes->{'trust-point'} || $trust_point;
                    my @tunnel_ipsec_att =
                      (
                        "ikev1 trust-point $trustpoint2",
                        'ikev1 user-authentication none'
                      );

                    $print_group_policy->($group_policy_name, $attributes);

                    my $tunnel_group_name = "VPN-tunnel-$id_name";
                    print <<"EOF";
tunnel-group $tunnel_group_name type remote-access
tunnel-group $tunnel_group_name general-attributes
EOF

                    for my $line (@tunnel_gen_att) {
                        print " $line\n";
                    }
                    print <<"EOF";
tunnel-group $tunnel_group_name ipsec-attributes
EOF

                    for my $line (@tunnel_ipsec_att) {
                        print " $line\n";
                    }

                    # For anyconnect clients.
                    print <<"EOF";
tunnel-group $tunnel_group_name webvpn-attributes
 authentication certificate
EOF
                    $cert_group_map{$map_name} = $tunnel_group_name;

                    print <<"EOF";
tunnel-group-map $map_name 10 $tunnel_group_name

EOF
                }
            }
        }

        # A VPN network.
        elsif (my $id = $interface->{peer}->{id}) {

            # Access list will be bound to cleartext interface.
            # Only check for correct source address at vpn-filter.
            delete $interface->{intf_rules};
            delete $interface->{rules};
            my $rules = [ { src => $interface->{peer_networks},
                            dst => [ get_network_00($ipv6) ],

                            prt => [ $prt_ip ] } ];
            my $id_name = $gen_id_name->($id);
            my $filter_name = "vpn-filter-$id_name";
            my $acl_info = {
                name => $filter_name,
                rules => $rules,
                add_deny => 1,
                no_nat_set => $no_nat_set,
            };
            push @{ $router->{acl_list} }, $acl_info;
            print_acl_placeholder($router, $filter_name);

            my $attributes = $router->{radius_attributes};

            my $group_policy_name;
            if (keys %$attributes) {
                $group_policy_name = "VPN-router-$id_name";
                $print_group_policy->($group_policy_name, $attributes);
            }
            print "username $id nopassword\n";
            print "username $id attributes\n";
            print " service-type remote-access\n";
            print " vpn-filter value $filter_name\n";
            print " vpn-group-policy $group_policy_name\n"
              if $group_policy_name;
            print "\n";
        }
    }

    # Do nothing for unmanaged VPN router without any networks.

    # Generate certificate-group-map for anyconnect/ikev2 clients.
    if (keys %cert_group_map or keys %single_cert_map) {
        for my $id (sort keys %single_cert_map) {
            my $id_name = $gen_id_name->($id);
            my $map_name = "ca-map-$id_name";
            print "crypto ca certificate map $map_name 10\n";
            print " subject-name attr ea co $id\n";
            $cert_group_map{$map_name} = $default_tunnel_group;
        }
        print "webvpn\n";
        for my $map_name (sort keys %cert_group_map) {
            my $tunnel_group_map = $cert_group_map{$map_name};
            print " certificate-group-map $map_name 10 $tunnel_group_map\n";
        }
    }
}

# Pre-processing for all interfaces.
sub print_acl_prefix {
    my ($router) = @_;
    my $model = $router->{model};
    return if $model->{filter} ne 'iptables';
    my $comment_char = $model->{comment_char};
    print "$comment_char [ PREFIX ]\n";
    print "#!/sbin/iptables-restore <<EOF\n";

    # Excempt loopback packets from connection tracking.
    print "*raw\n";
    print ":PREROUTING ACCEPT\n";
    print ":OUTPUT ACCEPT\n";
    print "-A PREROUTING -i lo -j NOTRACK\n";
    print "-A OUTPUT -o lo -j NOTRACK\n";
    print "COMMIT\n";

    # Start filter table
    print "*filter\n";
    print ":INPUT DROP\n";
    print ":FORWARD DROP\n";
    print ":OUTPUT ACCEPT\n";
    print "-A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
    print "-A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
    print "-A INPUT -j ACCEPT -i lo\n";

    # Add user defined chain 'droplog'.
    print ":droplog -\n";
    print "-A droplog -j LOG --log-level debug\n";
    print "-A droplog -j DROP\n";
    print "\n";
}

sub print_acl_suffix {
    my ($router) = @_;
    my $model = $router->{model};
    return if $model->{filter} ne 'iptables';
    my $comment_char = $model->{comment_char};
    print "$comment_char [ SUFFIX ]\n";
    print "-A INPUT -j droplog\n";
    print "-A FORWARD -j droplog\n";
    print "COMMIT\n";
    print "EOF\n";
}

sub print_iptables_acls {
    my ($router) = @_;
    for my $hardware (@{ $router->{hardware} }) {

        # Ignore if all logical interfaces are loopback interfaces.
        next if $hardware->{loopback};

        my $in_hw      = $hardware->{name};
        my $no_nat_set = $hardware->{no_nat_set};

        # Collect interface rules.
        # Add call to chain in INPUT chain.
        my $intf_acl_name = "${in_hw}_self";
        my $intf_acl_info = {
            name => $intf_acl_name,
            rules => delete $hardware->{intf_rules},
            add_deny => 1,
            no_nat_set => $no_nat_set,
        };
        push @{ $router->{acl_list} }, $intf_acl_info;
        print_acl_placeholder($router, $intf_acl_name);
        print "-A INPUT -j $intf_acl_name -i $in_hw\n";

        # Collect forward rules.
        # One chain for each pair of in_intf / out_intf.
        # Add call to chain in FORRWARD chain.
        my $rules_hash = $hardware->{io_rules};
        for my $out_hw (sort keys %$rules_hash) {
            my $acl_name = "${in_hw}_$out_hw";
            my $acl_info = {
                name => $acl_name,
                rules => delete $rules_hash->{$out_hw},
                add_deny => 1,
                no_nat_set => $no_nat_set,
            };
            push @{ $router->{acl_list} }, $acl_info;
            print_acl_placeholder($router, $acl_name);
            print "-A FORWARD -j $acl_name -i $in_hw -o $out_hw\n";
        }

        # Empty line after each chain.
        print "\n";
    }
}

sub prepare_real_ip_nat {
    my ($router, $nat_tag2multinat_def, $has_non_hidden) = @_;
    my $hw_list = $router->{hardware};

    my %effective2hw_list;
    my @two_effective;
  HARDWARE:
    for my $hardware (@$hw_list) {
        my $bind_nat = $hardware->{bind_nat} || [];

        # Build effective list of bound NAT tags.
        # Remove hidden NAT. This doesn't matter because errors with
        # hidden addresses will be detected before this is used.
        my $effective = {};
        for my $nat_tag (@$bind_nat) {
            $has_non_hidden->{$nat_tag} or next;
            $effective->{$nat_tag} = 1;
        }

        # Find identical effective bound NAT tags.
      EQ:
        for my $seen (@two_effective) {
            keys %$effective == keys %$seen or next;
            for my $nat_tag (keys %$effective) {
                my $nat = $seen->{$nat_tag} or next EQ;
                $nat eq $effective->{$nat_tag} or next EQ;
            }
            push @{ $effective2hw_list{$seen} }, $hardware;
            next HARDWARE;
        }
        if (@two_effective >= 2) {
            err_msg(
                "Must not use attribute 'acl_use_real_ip' at $router->{name}\n",
                " having different effective NAT at more than two interfaces");
            return;
        }
        push @two_effective, $effective;
        push @{ $effective2hw_list{$effective} }, $hardware;
    }
    if (@two_effective < 2) {
        warn_msg("Useless attribute 'acl_use_real_ip' at $router->{name}");
        return;
    }
    # Found two sets of hardware having identical effective bound NAT.
    # Combine no_nat_sets of each set.
    my $combine_nat = sub {
        my ($list) = @_;
        my $no_nat_sets = [ map { $_->{no_nat_set} } @$list ];
        return combine_no_nat_sets($no_nat_sets, undef,
                                   $nat_tag2multinat_def, $has_non_hidden);
    };
    my ($list1, $list2) = values %effective2hw_list;
    my $combined1 = $combine_nat->($list1);
    my $combined2 = $combine_nat->($list2);
    $_->{dst_no_nat_set} = $combined2 for @$list1;
    $_->{dst_no_nat_set} = $combined1 for @$list2;
}

sub prepare_real_ip_nat_routers {
    my ($nat_tag2multinat_def, $has_non_hidden) = @_;
    for my $router (@managed_routers, @routing_only_routers) {
        $router->{acl_use_real_ip} or next;
        prepare_real_ip_nat($router, $nat_tag2multinat_def, $has_non_hidden);
    }
}

sub print_cisco_acls {
    my ($router)      = @_;
    my $model         = $router->{model};
    my $filter        = $model->{filter};
    my $managed_local = $router->{managed} =~ /^local/;
    my $hw_list       = $router->{hardware};
    my $ipv6          = $router->{ipv6};
    my $permit_any    = $ipv6 ? $permit_any6_rule : $permit_any_rule;

    for my $hardware (@$hw_list) {

        # Ignore if all logical interfaces are loopback interfaces.
        next if $hardware->{loopback};

        # Ignore layer3 interface of ASA.
        next if $hardware->{name} eq 'device' and $model->{class} eq 'ASA';

        # Force valid array reference to prevent error
        # when checking for non empty array.
        $hardware->{rules} ||= [];

        my $no_nat_set =
            $hardware->{crypto_no_nat_set} || $hardware->{no_nat_set};
        my $dst_no_nat_set = $hardware->{dst_no_nat_set};

        # Generate code for incoming and possibly for outgoing ACL.
        for my $suffix ('in', 'out') {
            next if $suffix eq 'out' and not $hardware->{need_out_acl};

            # Don't generate single 'permit ip any any'.
            if (not $model->{need_acl}) {
                if (
                    not grep {
                        my $rules = $hardware->{$_} || [];
                        @$rules != 1 or $rules->[0] ne $permit_any
                    } (qw(rules intf_rules))
                  )
                {
                    next;
                }
            }

            my $acl_name = "$hardware->{name}_$suffix";
            my $acl_info = {
                name => $acl_name,
                no_nat_set => $no_nat_set,
            };
            $acl_info->{dst_no_nat_set} = $dst_no_nat_set if $dst_no_nat_set;

            # - Collect incoming ACLs,
            # - protect own interfaces,
            # - set {filter_any_src}.
            if ($suffix eq 'in') {
                $acl_info->{rules} = delete $hardware->{rules};

                # Marker: Generate protect_self rules, if available.
                $acl_info->{protect_self} = 1;

                if ($router->{need_protect}) {
                    $acl_info->{intf_rules} = $hardware->{intf_rules};
                }
                if ($hardware->{no_in_acl}) {
                    $acl_info->{add_permit} = 1;
                }
                else {
                    $acl_info->{add_deny} = 1;
                }

                if ($managed_local) {

                    # If attached zone has only one connection to this
                    # firewall than we don't need to check the source
                    # address. It has already been checked, that all
                    # networks of this zone match {filter_only}.
                    my $intf_ok = 0;
                    for my $interface (@{ $hardware->{interfaces} }) {
                        my $zone = $interface->{zone};
                        $zone->{zone_cluster} and last;

                        # Ignore real interface of virtual interface.
                        my @interfaces = grep({ not $_->{main_interface} }
                                              @{ $zone->{interfaces} });

                        if (@interfaces > 1) {

                            # Multilpe interfaces belonging to one redundancy
                            # group can't be used to cross the zone.
                            my @redundant =
                               grep { $_ }
                               map  { $_->{redundancy_interfaces} } @interfaces;
                            @redundant == @interfaces and equal(@redundant)
                                or last;
                        }
                        $intf_ok++;
                    }
                    if ($intf_ok == @{ $hardware->{interfaces} }) {
                        $acl_info->{filter_any_src} = 1;
                    }
                }
            }

            # Outgoing ACL
            else {
                $acl_info->{rules} = delete $hardware->{out_rules};
                $acl_info->{add_deny} = 1;

            }

            push @{ $router->{acl_list} }, $acl_info;
            print_acl_placeholder($router, $acl_name);

            # Post-processing for hardware interface
            if ($filter eq 'IOS' or $filter eq 'NX-OS') {
                push(
                    @{ $hardware->{subcmd} },
                    ($ipv6 ? "ipv6 traffic-filter" : "ip access-group")
                    . " $acl_name $suffix"
                );
            }
            elsif ($filter eq 'ASA') {
                print "access-group $acl_name $suffix interface",
                  " $hardware->{name}\n";
            }

            # Empty line after each ACL.
            print "\n";
        }
    }
}

sub generate_acls {
    my ($router) = @_;
    my $model    = $router->{model};
    my $filter   = $model->{filter};
    print_header($router, 'ACL');

    if ($filter eq 'iptables') {
        print_iptables_acls($router);
    }
    else {
        print_cisco_acls($router);
    }
}

sub gen_crypto_rules {
    my ($local, $remote) = @_;
    return [ { src => $local, dst => $remote, prt => [$prt_ip] } ];
}

sub print_ezvpn {
    my ($router) = @_;
    my @interfaces     = @{ $router->{interfaces} };
    my ($tunnel_intf)  = grep { $_->{ip} eq 'tunnel' } @interfaces;
    my $tun_no_nat_set = $tunnel_intf->{no_nat_set};
    my $wan_intf       = $tunnel_intf->{real_interface};
    my $wan_hw         = $wan_intf->{hardware};
    my $wan_no_nat_set = $wan_hw->{no_nat_set};
    my @lan_intf = grep { $_ ne $wan_intf and $_ ne $tunnel_intf } @interfaces;

    # Ezvpn configuration.
    my $ezvpn_name               = 'vpn';
    my $crypto_acl_name          = 'ACL-Split-Tunnel';
    my $crypto_filter_name       = 'ACL-crypto-filter';
    my $virtual_interface_number = 1;
    print "crypto ipsec client ezvpn $ezvpn_name\n";
    print " connect auto\n";
    print " mode network-extension\n";

    # Unnumbered, negotiated and short interfaces have been
    # rejected already.
    my $peer = $tunnel_intf->{peer};
    my $peer_ip =
        prefix_code(address($peer->{real_interface}, $wan_no_nat_set));
    print " peer $peer_ip\n";

    # Bind split tunnel ACL.
    print " acl $crypto_acl_name\n";

    # Use virtual template defined above.
    print " virtual-interface $virtual_interface_number\n";

    # xauth is unused, but syntactically needed.
    print " username test pass test\n";
    print " xauth userid mode local\n";

    # Apply ezvpn to WAN and LAN interface.
    for my $lan_intf (@lan_intf) {
        my $lan_hw = $lan_intf->{hardware};
        push(
            @{ $lan_hw->{subcmd} },
            "crypto ipsec client ezvpn $ezvpn_name inside"
        );
    }
    push(@{ $wan_hw->{subcmd} }, "crypto ipsec client ezvpn $ezvpn_name");

    # Crypto ACL controls which traffic needs to be encrypted.
    my $crypto_rules =
      gen_crypto_rules($tunnel_intf->{peer}->{peer_networks},
        [get_network_00($router->{ipv6})]);
    my $acl_info = {
        name => $crypto_acl_name,
        rules => $crypto_rules,
        no_nat_set => $tun_no_nat_set,
        is_crypto_acl => 1,
    };
    push @{ $router->{acl_list} }, $acl_info;
    print_acl_placeholder($router, $crypto_acl_name);

    # Crypto filter ACL.
    $acl_info = {
        name         => $crypto_filter_name,
        rules        => delete $tunnel_intf->{rules},
        intf_rules   => delete $tunnel_intf->{intf_rules},
        add_deny     => 1,
        protect_self => 1,
        no_nat_set   => $tun_no_nat_set,
    };
    push @{ $router->{acl_list} }, $acl_info;
    print_acl_placeholder($router, $crypto_filter_name);

    # Bind crypto filter ACL to virtual template.
    print "interface Virtual-Template$virtual_interface_number type tunnel\n";
    print($router->{ipv6} ? " ipv6 traffic-filter" : " ip access-group",
          " $crypto_filter_name in\n");
}

# Print crypto ACL.
# It controls which traffic needs to be encrypted.
sub print_crypto_acl {
    my ($interface, $suffix, $crypto) = @_;
    my $crypto_acl_name = "crypto-$suffix";

    # Generate crypto ACL entries.
    # - either generic from remote network to any or
    # - detailed to all networks which are used in rules.
    my $is_hub   = $interface->{is_hub};
    my $hub      = $is_hub ? $interface : $interface->{peer};
    my $detailed = $crypto->{detailed_crypto_acl};
    my $local    = $detailed
                 ? get_split_tunnel_nets($hub)
                 : [get_network_00($interface->{router}->{ipv6})];
    my $remote   = $hub->{peer_networks};
    $is_hub or ($local, $remote) = ($remote, $local);
    my $crypto_rules = gen_crypto_rules($local, $remote);
    my $router       = $interface->{router};
    my $no_nat_set   = $interface->{no_nat_set};
    my $acl_info = {
        name => $crypto_acl_name,
        rules => $crypto_rules,
        no_nat_set => $no_nat_set,
        is_crypto_acl => 1,

    };
    push @{ $router->{acl_list} }, $acl_info;
    print_acl_placeholder($router, $crypto_acl_name);
    return $crypto_acl_name;
}

# Print filter ACL. It controls which traffic is allowed to leave from
# crypto tunnel. This may be needed, if we don't fully trust our peer.
sub print_crypto_filter_acl {
    my ($interface, $suffix) = @_;
    my $router = $interface->{router};

    return if $router->{model}->{no_crypto_filter};

    my $crypto_filter_name = "crypto-filter-$suffix";
    my $no_nat_set = $interface->{no_nat_set};
    my $acl_info = {
        name         => $crypto_filter_name,
        rules        => delete $interface->{rules},
        intf_rules   => delete $interface->{intf_rules},
        add_deny     => 1,
        protect_self => 1,
        no_nat_set   => $no_nat_set,
    };
    push @{ $router->{acl_list} }, $acl_info;
    print_acl_placeholder($router, $crypto_filter_name);
    return $crypto_filter_name;
}

# Called for static and dynamic crypto maps.
sub print_crypto_map_attributes {
    my ($prefix, $crypto_type, $crypto_acl_name, $crypto_filter_name,
        $isakmp, $ipsec, $ipsec2trans_name)
      = @_;

    # Bind crypto ACL to crypto map.
    print "$prefix match address $crypto_acl_name\n";

    # Bind crypto filter ACL to crypto map.
    if ($crypto_filter_name) {
        print "$prefix set ip access-group $crypto_filter_name in\n";
    }

    my $transform_name = $ipsec2trans_name->{$ipsec};
    if ($crypto_type eq 'ASA') {
        if ($isakmp->{ike_version} == 2) {
            print "$prefix set ikev2 ipsec-proposal $transform_name\n";
        }
        else {
            print "$prefix set ikev1 transform-set $transform_name\n";
        }
    }
    else {
        print "$prefix set transform-set $transform_name\n";
    }

    if (my $pfs_group = $ipsec->{pfs_group}) {
        print "$prefix set pfs group$pfs_group\n";
    }

    if (my $pair = $ipsec->{lifetime}) {
        my ($sec, $kb) = @$pair;
        my $args = '';

        # Don't print default values for backend IOS.
        if (defined $sec and not ($sec == 3600 and $crypto_type eq 'IOS')) {
            $args .= " seconds $sec";
        }
        if (defined $kb and not ($kb == 4608000 and $crypto_type eq 'IOS')) {
            $args .= " kilobytes $kb";
        }
        if ($args) {
            print "$prefix set security-association lifetime$args\n";
        }
    }
}

sub print_tunnel_group {
    my ($name, $isakmp) = @_;
    my $authentication = $isakmp->{authentication};
    print "tunnel-group $name type ipsec-l2l\n";
    print "tunnel-group $name ipsec-attributes\n";
    if ($authentication eq 'rsasig') {
        my $trust_point = $isakmp->{trust_point};
        if ($isakmp->{ike_version} == 2) {
            print(" ikev2 local-authentication certificate", " $trust_point\n");
            print(" ikev2 remote-authentication certificate\n");
        }
        else {
            print " ikev1 trust-point $trust_point\n";
            print " ikev1 user-authentication none\n";
        }
    }

    # Preshared key is configured manually.
    else {
        print " peer-id-validate nocheck\n";
    }
}

sub print_ca_and_tunnel_group_map {
    my ($id, $tg_name) = @_;

    # Activate tunnel-group with tunnel-group-map.
    # Use $id as ca-map name.
    print "crypto ca certificate map $id 10\n";
    print " subject-name attr ea eq $id\n";
    print "tunnel-group-map $id 10 $tg_name\n";
}

sub print_static_crypto_map {
    my ($router, $hardware, $map_name, $interfaces, $ipsec2trans_name) = @_;
    my $model       = $router->{model};
    my $crypto_type = $model->{crypto};

    # Sequence number for parts of crypto map with different peers.
    my $seq_num = 0;

    # Peer IP must obey NAT.
    my $no_nat_set = $hardware->{no_nat_set};

    # Sort crypto maps by peer IP to get deterministic output.
    my @sorted = sort(
        { $a->{peer}->{real_interface}->{ip}
              cmp $b->{peer}->{real_interface}->{ip} } @$interfaces);

    # Build crypto map for each tunnel interface.
    for my $interface (@sorted) {
        $seq_num++;
        my $peer = $interface->{peer};
        my $peer_ip =
            prefix_code(address($peer->{real_interface}, $no_nat_set));
        my $suffix = $peer_ip;

        my $crypto = $interface->{crypto};
        my $ipsec  = $crypto->{type};
        my $isakmp = $ipsec->{key_exchange};

        my $crypto_acl_name =
          print_crypto_acl($interface, $suffix, $crypto);
        my $crypto_filter_name =
          print_crypto_filter_acl($interface, $suffix);

        # Define crypto map.
        my $prefix;
        if ($crypto_type eq 'IOS') {
            $prefix = '';
            print "crypto map $map_name $seq_num ipsec-isakmp\n";
        }
        elsif ($crypto_type eq 'ASA') {
            $prefix = "crypto map $map_name $seq_num";
        }

        # Set crypto peer.
        print "$prefix set peer $peer_ip\n";

        print_crypto_map_attributes($prefix, $crypto_type,
            $crypto_acl_name, $crypto_filter_name, $isakmp, $ipsec,
            $ipsec2trans_name);

        if ($crypto_type eq 'ASA') {
            print_tunnel_group($peer_ip, $isakmp);

            # Tunnel group needs to be activated, if certificate is in use.
            if (my $id = $peer->{id}) {
                print_ca_and_tunnel_group_map($id, $peer_ip);
            }
        }
    }
}

sub print_dynamic_crypto_map {
    my ($router, $map_name, $interfaces, $ipsec2trans_name) = @_;
    my $model       = $router->{model};
    my $crypto_type = $model->{crypto};

    # Sequence number for parts of crypto map with different certificates.
    my $seq_num = 65536;

    # Sort crypto maps by certificate to get deterministic output.
    my @sorted = sort({ $a->{peer}->{id} cmp $b->{peer}->{id} } @$interfaces);

    # Build crypto map for each tunnel interface.
    for my $interface (@sorted) {
        $seq_num--;
        my $id     = $interface->{peer}->{id};
        my $suffix = $id;

        my $crypto = $interface->{crypto};
        my $ipsec  = $crypto->{type};
        my $isakmp = $ipsec->{key_exchange};

        my $crypto_acl_name =
          print_crypto_acl($interface, $suffix, $crypto);
        my $crypto_filter_name =
          print_crypto_filter_acl($interface, $suffix);

        # Define dynamic crypto map.
        # Use certificate as name.
        my $prefix = "crypto dynamic-map $id 10";

        print_crypto_map_attributes($prefix, $crypto_type,
            $crypto_acl_name, $crypto_filter_name, $isakmp, $ipsec,
            $ipsec2trans_name);

        # Bind dynamic crypto map to crypto map.
        $prefix = "crypto map $map_name $seq_num";
        print "$prefix ipsec-isakmp dynamic $id\n";

        # Use $id as tunnel-group name
        print_tunnel_group($id, $isakmp);

        # Activate tunnel-group with tunnel-group-map.
        print_ca_and_tunnel_group_map($id, $id);
    }
}

sub print_crypto {
    my ($router) = @_;
    my $model = $router->{model};
    my $crypto_type = $model->{crypto} || '';

    # List of ipsec definitions used at current router.
    # Sort entries by name to get deterministic output.
    my @ipsec = sort by_name unique(
        map  { $_->{crypto}->{type} }
        grep { $_->{ip} eq 'tunnel' } @{ $router->{interfaces} }
    );

    # Return if no crypto is used at current router.
    return unless @ipsec;

    # List of isakmp definitions used at current router.
    # Sort entries by name to get deterministic output.
    my @isakmp = sort by_name unique(map { $_->{key_exchange} } @ipsec);

    print_header($router, 'Crypto');

    if ($crypto_type eq 'EZVPN') {
        print_ezvpn $router;
        return;
    }

    # Use interface access lists to filter incoming crypto traffic.
    # Group policy and per-user authorization access list can't be used
    # because they are stateless.
    if ($crypto_type =~ /^ASA/) {
        print "! VPN traffic is filtered at interface ACL\n";
        print "no sysopt connection permit-vpn\n";
    }

    if ($crypto_type eq 'ASA_VPN') {
        print_asavpn $router;
        return;
    }

    # Crypto config for ASA as EZVPN client is configured manually once.
    # No config is generated by netspoc.
    if ($crypto_type eq 'ASA_EZVPN') {
        return;
    }

    my $isakmp_count = 0;
    for my $isakmp (@isakmp) {

        # Only print isakmp for IOS. Approve for ASA will ignore it anyway.
        $crypto_type eq 'IOS' or next;

        $isakmp_count++;
        print "crypto isakmp policy $isakmp_count\n";

        my $authentication = $isakmp->{authentication};
        $authentication =~ s/preshare/pre-share/;
        $authentication =~ s/rsasig/rsa-sig/;

        # Don't print default value for backend IOS.
        if (not($authentication eq 'rsa-sig')) {
            print " authentication $authentication\n";
        }

        my $encryption = $isakmp->{encryption};
        if ($encryption =~ /^aes(\d+)$/a) {
            my $len = $crypto_type eq 'ASA' ? "-$1" : " $1";
            $encryption = "aes$len";
        }
        print " encryption $encryption\n";
        my $hash = $isakmp->{hash};
        print " hash $hash\n";
        my $group = $isakmp->{group};
        print " group $group\n";

        my $lifetime = $isakmp->{lifetime};

        # Don't print default value for backend IOS.
        if (not($lifetime == 86400)) {
            print " lifetime $lifetime\n";
        }
    }

    # Handle IPSEC definition.
    my $transform_count = 0;
    my %ipsec2trans_name;
    for my $ipsec (@ipsec) {
        $transform_count++;
        my $transform_name = "Trans$transform_count";
        $ipsec2trans_name{$ipsec} = $transform_name;
        my $isakmp = $ipsec->{key_exchange};

        # IKEv2 syntax for ASA.
        if ($crypto_type eq 'ASA' and $isakmp->{ike_version} == 2) {
            print "crypto ipsec ikev2 ipsec-proposal $transform_name\n";
            if (my $ah = $ipsec->{ah}) {
                print " protocol ah $ah\n";
            }
            my $esp_encr;
            if (not(my $esp = $ipsec->{esp_encryption})) {
                $esp_encr = 'null';
            }
            elsif ($esp =~ /^(aes|des|3des)$/) {
                $esp_encr = $1;
            }
            elsif ($esp =~ /^aes(192|256)$/) {
                $esp_encr = "aes-$1";
            }
            print " protocol esp encryption $esp_encr\n";
            if (my $esp_ah = $ipsec->{esp_authentication}) {
                $esp_ah =~ s/^(.+?)(\d+)/$1-$2/;
                $esp_ah =~ s/^sha$/sha-1/;
                print " protocol esp integrity $esp_ah\n";
            }
        }

        # IKEv1 syntax of ASA is identical to IOS.
        else {
            my $transform = '';
            if (my $ah = $ipsec->{ah}) {
                $transform .= "ah-$ah-hmac ";
            }
            if (not(my $esp = $ipsec->{esp_encryption})) {
                $transform .= 'esp-null ';
            }
            elsif ($esp =~ /^(aes|des|3des)$/) {
                $transform .= "esp-$1 ";
            }
            elsif ($esp =~ /^aes(192|256)$/) {
                my $len = $crypto_type eq 'ASA' ? "-$1" : " $1";
                $transform .= "esp-aes$len ";
            }
            if (my $esp_ah = $ipsec->{esp_authentication}) {
                $transform .= "esp-$esp_ah-hmac";
            }
            $transform =~ s/ $//;
            my $prefix = ($crypto_type eq 'ASA')
                       ? 'crypto ipsec ikev1'
                       : 'crypto ipsec';
            print "$prefix transform-set $transform_name $transform\n";
        }
    }

    # Collect tunnel interfaces attached to each hardware interface.
    # Differentiate on peers having static or dynamic IP address.
    my %hardware2crypto;
    my %hardware2dyn_crypto;
    for my $interface (@{ $router->{interfaces} }) {
        $interface->{ip} eq 'tunnel' or next;
        my $ip = $interface->{peer}->{real_interface}->{ip};
        if ($ip =~ /^(?:negotiated|short|unnumbered)$/) {
            push @{ $hardware2dyn_crypto{ $interface->{hardware} } },
              $interface;
        }
        else {
            push @{ $hardware2crypto{ $interface->{hardware} } }, $interface;
        }
    }

    for my $hardware (@{ $router->{hardware} }) {
        my $hw_name = $hardware->{name};

        # Name of crypto map.
        my $map_name = "crypto-$hw_name";

        my $have_crypto_map;
        if (my $interfaces = $hardware2crypto{$hardware}) {
            print_static_crypto_map($router, $hardware, $map_name, $interfaces,
                \%ipsec2trans_name);
            $have_crypto_map = 1;
        }
        if (my $interfaces = $hardware2dyn_crypto{$hardware}) {
            print_dynamic_crypto_map(
                $router, $map_name, $interfaces, \%ipsec2trans_name);
            $have_crypto_map = 1;
        }

        # Bind crypto map to interface.
        $have_crypto_map or next;
        if ($crypto_type eq 'IOS') {
            push(@{ $hardware->{subcmd} }, "crypto map $map_name");
        }
        elsif ($crypto_type eq 'ASA') {
            print "crypto map $map_name interface $hw_name\n";
        }
    }
}

sub print_interface {
    my ($router) = @_;
    my $model = $router->{model};
    $model->{print_interface} or return;
    my $class    = $model->{class};
    my $stateful = not $model->{stateless};
    my $ipv6     = $router->{ipv6};
    for my $hardware (@{ $router->{hardware} }) {
        my $name = $hardware->{name};
        my @subcmd;
        my $secondary;
        for my $intf (@{ $hardware->{interfaces} }) {
            my $addr_cmd;
            my $ip = $intf->{ip};
            if ($ip eq 'tunnel') {
                next;
            }
            elsif ($ip eq 'unnumbered') {
                $addr_cmd = 'ip unnumbered X';
            }
            elsif ($ip eq 'negotiated') {
                $addr_cmd = 'ip address negotiated';
            }
            elsif ($model->{use_prefix} or $ipv6) {
                my $addr = print_ip($ip);
                my $mask = mask2prefix($intf->{network}->{mask});
                my $ip = $ipv6 ? 'ipv6' : 'ip';
                $addr_cmd = "$ip address $addr/$mask";
                $addr_cmd .= ' secondary' if $secondary;
            }
            else {
                my $addr = print_ip($ip);
                my $mask = print_ip($intf->{network}->{mask});
                $addr_cmd = "ip address $addr $mask";
                $addr_cmd .= ' secondary' if $secondary;
            }
            push @subcmd, $addr_cmd;
            $secondary = 1 if not $ipv6;
        }
        if (my $vrf = $router->{vrf}) {
            if ($class eq 'NX-OS') {
                push @subcmd, "vrf member $vrf";
            }
            else {
                push @subcmd, "ip vrf forwarding $vrf";
            }
        }

        # Add "ip inspect" as marker, that stateful filtering is expected.
        # The command is known to be incomplete, "X" is only used as
        # placeholder.
        if ($class eq 'IOS' and $stateful and not $hardware->{loopback}) {
            push @subcmd, "ip inspect X in";
        }

        if (my $other = $hardware->{subcmd}) {
            push @subcmd, @$other;
        }
        print "interface $name\n";
        for my $cmd (@subcmd) {
            print " $cmd\n";
        }
    }
    print "\n";
}

sub print_prt {
    my ($prt) = @_;
    my $proto = $prt->{proto};
    my @result = ($proto);

    if ($proto eq 'tcp' or $proto eq 'udp') {
        push @result,  @{ $prt->{range} };
        push @result, 'established' if $prt->{established};
    }
    elsif ($proto eq 'icmp' or $proto eq 'icmpv6') {
        if (defined(my $type = $prt->{type})) {
            push @result, $type;
        }
        if (defined(my $code = $prt->{code})) {
            push @result, $code;
        }
    }
    return(join(' ', @result));
}

my %nat2obj2address;

sub print_acls {
    my ($vrf_members, $fh) = @_;
    my @acl_list;

    for my $router (@$vrf_members) {

        my $managed          = $router->{managed} || '';
        my $secondary_filter = $managed =~ /secondary$/;
        my $standard_filter  = $managed eq 'standard';
        my $model            = $router->{model};
        my $do_auth          = $model->{do_auth};
        my $active_log       = $router->{log};
        my $need_protect;

        # Collect interfaces that need protection by additional deny rules.
        # Add list to each ACL separately, because IP may be changed by NAT.
        if (
            $router->{need_protect}
            or

            # ASA protects IOS router behind crosslink interface.
            $router->{crosslink_interfaces}
          )
        {

            # Routers connected by crosslink networks are handled like
            # one large router. Protect the collected interfaces of
            # the whole cluster at each entry.
            $need_protect = $router->{crosslink_interfaces};
            if (not $need_protect) {
                $need_protect = $router->{interfaces};
                $need_protect = [
                    grep({ $_->{ip} !~
                               /^(?:unnumbered|negotiated|tunnel|bridged)$/ }
                         @$need_protect) ];
            }
        }

        my $aref = delete $router->{acl_list} or next;
        for my $acl (@$aref) {

            # Don't modify loop variable.
            my $acl = $acl;

            # Collect networks used in secondary optimization.
            my %opt_addr;

            # Collect networks forbidden in secondary optimization.
            my %no_opt_addrs;

            my $no_nat_set = delete $acl->{no_nat_set};
            my $addr_cache = $nat2obj2address{$no_nat_set} ||= {};
            my $dst_no_nat_set = delete $acl->{dst_no_nat_set} || $no_nat_set;
            my $dst_addr_cache = $nat2obj2address{$dst_no_nat_set} ||= {};
            my $protect_self = delete $acl->{protect_self};
            if ($need_protect and $protect_self) {
                $acl->{need_protect} = [

                    # Remove duplicate addresses from redundancy interfaces.
                    unique
                    map({ $addr_cache->{$_} ||=
                              full_prefix_code(address($_, $no_nat_set)) }
                        @$need_protect) ];
            }

            for my $what (qw(intf_rules rules)) {
                my $rules = $acl->{$what} or next;
                for my $rule (@$rules) {
                    my $new_rule = {};
                    $new_rule->{deny} = 1 if $rule->{deny};

                    # Add code for logging.
                    # This code is machine specific.
                    if ($active_log and (my $log = $rule->{log})) {
                        my $log_code;
                        for my $tag (@$log) {
                            if (exists $active_log->{$tag}) {
                                if (my $modifier = $active_log->{$tag}) {
                                    my $normalized =
                                        $model->{log_modifiers}->{$modifier};
                                    if ($normalized eq ':subst') {
                                        $log_code = $modifier;
                                    }
                                    else {
                                        $log_code = "log $normalized";
                                    }
                                }
                                else {
                                    $log_code = 'log';
                                }

                                # Take first of possibly several matching tags.
                                last;
                            }
                        }
                        if ($log_code) {
                            $new_rule->{log} = $log_code;
                        }
                    }

                    if (   $secondary_filter and $rule->{some_non_secondary}
                        or $standard_filter and $rule->{some_primary})
                    {
                        for my $where (qw(src dst)) {
                            my $obj_list = $rule->{$where};
                            for my $obj (@$obj_list) {

                                # Prepare secondary optimization.

                                # Restrict secondary optimization at
                                # authenticating router to prevent
                                # unauthorized access with spoofed IP
                                # address.
                                # It would be sufficient to disable
                                # optimization only for incoming
                                # traffic. But for a VPN router with
                                # only a single interface, incoming
                                # and outgoing traffic is mixed at
                                # this interface.
                                # At this stage, network with
                                # {has_id_hosts} has already been
                                # converted to single ID hosts.
                                next if $do_auth and $obj->{id};

                                my $type = ref($obj);
                                my $subst;
                                if ($type eq 'Subnet' or $type eq 'Interface') {
                                    my $net = $obj->{network};
                                    next if $net->{has_other_subnet};
                                    if (my $no_opt =
                                        $router->{no_secondary_opt})
                                    {
                                        if ($no_opt->{$net}) {
                                            $no_opt_addrs{$obj} = $obj;
                                            next;
                                        }
                                    }
                                    $subst = $net;
                                    if (my $max = $subst->{max_secondary_net}) {
                                        $subst = $max;
                                    }

                                    # Ignore loopback network.
                                    next if is_host_mask($subst->{mask});
                                }

                                # Network or aggregate.
                                else {

                                    # Don't modify protocol of rule
                                    # with {has_other_subnet}, because
                                    # this could introduce new missing
                                    # supernet rules.
                                    if ($obj->{has_other_subnet}) {
                                        $no_opt_addrs{$obj} = $obj;
                                        next;

                                    }
                                    my $max = $obj->{max_secondary_net} or next;
                                    $subst = $max;
                                }
                                $opt_addr{$subst} = $subst;
                            }
                        }
                        $new_rule->{opt_secondary} = 1;
                    }
                    $new_rule->{src} =
                        [ map { $addr_cache->{$_} ||=
                                    full_prefix_code(address($_, $no_nat_set))
                          }
                          @{ $rule->{src} } ];
                    $new_rule->{dst} =
                        [ map { $dst_addr_cache->{$_} ||=
                                    full_prefix_code(address($_,
                                                             $dst_no_nat_set))
                          }
                          @{ $rule->{dst} } ];
                    $new_rule->{prt} = [ map { $_->{printed} ||= print_prt($_) }
                                         @{ $rule->{prt} } ];
                    if (my $src_range = $rule->{src_range}) {
                        $new_rule->{src_range} =
                            $src_range->{printed} ||= print_prt($src_range);
                    }
                    $rule = $new_rule;
                }
            }

            # Secondary optimization is done in pass 2.
            # It converts protocol to IP and
            # src/dst address to network address.
            # It is controlled by this three attributes:
            # - {opt_secondary} enables secondary optimization
            # - if enabled, then networks in {opt_networks} are used
            #   for optimization.
            # - if src/dst matches {no_opt_networks}, then
            #   optimization is disabled for this single rule.
            #   This is needed because {opt_secondary} is set for
            #   grouped rules and we need to control optimization
            #   for sinlge rules.
            if (values %opt_addr) {
                $acl->{opt_networks} = [
                    sort
                    map { $addr_cache->{$_} ||=
                              full_prefix_code(address($_, $no_nat_set)) }
                    values %opt_addr ];
            }
            if (values %no_opt_addrs) {
                $acl->{no_opt_addrs} = [
                    sort
                    map { $addr_cache->{$_} ||=
                              full_prefix_code(address($_, $no_nat_set)) }
                    values %no_opt_addrs ];
            }
            push @acl_list, $acl;
        }
    }

    my $router = $vrf_members->[0];
    my $model  = $router->{model};
    my $result = { model => $model->{class}, acls  => \@acl_list };

    if (my $filter_only = $router->{filter_only}) {
        my @list = map { prefix_code($_) } @$filter_only;
        $result->{filter_only} = \@list;
    }

    if ($model->{can_objectgroup}) {
        if (not $router->{no_group_code}) {
            $result->{do_objectgroup} = 1;
        }
    }

    if ($router->{log_deny}) {
        $result->{log_deny} = 'log';
    }

    print $fh JSON::XS->new->pretty(1)->canonical(1)->encode($result);
}

# Make output directory available.
# Move old content into subdirectory ".prev/" for reuse during pass 2.
sub check_output_dir {
    my ($dir) = @_;
    if (not -e $dir) {
        mkdir $dir
          or fatal_err("Can't create output directory $dir: $!");
    }
    else {
        -d $dir or fatal_err("$dir isn't a directory");
        unlink "$dir/.devlist";

        my $prev = "$dir/.prev";
        if (not -d $prev) {
            my @old_files = glob("$dir/*");
            if (my $count = @old_files) {
                if (-d "$dir/ipv6") {
                    my @v6files = glob("$dir/ipv6/*");
                    $count += @v6files - 1;
                }
                info("Saving $count old files of '$dir' to",
                         " subdirectory '.prev'");

                # Try to remove file or symlink with same name.
                unlink $prev;
                mkdir $prev or
                    fatal_err("Can't create directory $prev: $!");
                system('mv', @old_files, $prev) == 0 or
                    fatal_err("Can't mv old files to $prev: $!");
            }
        }
    }
}

# Print generated code for each managed router.
sub print_code {
    my ($dir) = @_;
    progress('Printing intermediate code');

    ## no critic (RequireBriefOpen)
    my $to_pass2;
    if ($config->{pipe}) {
        open($to_pass2, '>&', STDOUT) or
            fatal_err("Can't open STDOUT for writing: $!");
        $to_pass2->autoflush(1);
    }
    else {
        my $devlist = "$dir/.devlist";
        open($to_pass2, '>>', $devlist) or
            fatal_err("Can't open $devlist for writing: $!");
    }
    ## use critic

    my $checked_v6dir;
    my %seen;
    for my $router (@managed_routers, @routing_only_routers) {
        next if $seen{$router};

        # Ignore split part of crypto router.
        next if $router->{orig_router};

        my $device_name = $router->{device_name};
        my $path        = $device_name;
        if ($router->{ipv6}) {
            $path = "ipv6/$path";
            my $v6dir = "$dir/ipv6";
            $checked_v6dir++ or -d $v6dir or mkdir $v6dir
                or fatal_err("Can't create output directory $v6dir: $!");
        }

        # File for router config without ACLs.
        my $config_file = "$dir/$path.config";

        ## no critic (RequireBriefOpen)
        open(my $code_fd, '>', $config_file)
          or fatal_err("Can't open $config_file for writing: $!");
        select $code_fd;
        ## use critic

        my $model        = $router->{model};
        my $comment_char = $model->{comment_char};

        # Restore interfaces of split router.
        if (my $orig_interfaces = $router->{orig_interfaces}) {
            $router->{interfaces} = $orig_interfaces;
            $router->{hardware}   = $router->{orig_hardware};
        }

        # Collect VRF members.
        my $vrf_members = $router->{vrf_members} || [$router];

        # Print version header.
        print "$comment_char Generated by $program, version $version\n\n";

        print "$comment_char [ BEGIN $device_name ]\n";
        print "$comment_char [ Model = $model->{class} ]\n";
        if (my @ips = map { @{ $_->{admin_ip} || [] } } @$vrf_members) {
            printf("$comment_char [ IP = %s ]\n", join(',', @ips));
        }
        for my $vrouter (@$vrf_members) {
            $seen{$vrouter} = 1;
            print_routes($vrouter);
            $vrouter->{managed} or next;
            print_crypto($vrouter);
            print_acl_prefix($vrouter);
            generate_acls($vrouter);
            print_acl_suffix($vrouter);
            print_interface($vrouter);
        }

        print "$comment_char [ END $device_name ]\n\n";
        select STDOUT;
        close $code_fd or fatal_err("Can't close $config_file: $!");

        # Print ACLs in machine independent format into separate file.
        # Collect ACLs from VRF parts.
        my $acl_file = "$dir/$path.rules";
        open(my $acl_fd, '>', $acl_file)
          or fatal_err("Can't open $acl_file for writing: $!");
        print_acls($vrf_members, $acl_fd);
        close $acl_fd or fatal_err("Can't close $acl_file: $!");

        # Send device name to pass 2, showing that processing for this
        # device can be started.
        print $to_pass2 "$path\n";
    }
}

# Copy raw configuration files of devices into out_dir for devices
# known from topology.
sub copy_raw1 {
    my ($raw_dir, $out_dir, $ignore_dir) = @_;
    my $ipv6 = $out_dir =~ m'/ipv6$';
    my %device_names =
      map({ $_->{device_name} => 1 }
          grep { $_->{ipv6} ? $ipv6 : !$ipv6 }
          @managed_routers, @routing_only_routers);

    # $out_dir has already been checked / created in print_code.
    opendir(my $dh, $raw_dir) or fatal_err("Can't opendir $raw_dir: $!");
    for my $file (sort map { Encode::decode($filename_encode, $_) } readdir $dh)
    {
        next if $file =~ /^\./;
        next if $file =~ m/$config->{ignore_files}/o;
        next if $ignore_dir and $file eq $ignore_dir;

        my $raw_path = "$raw_dir/$file";
        if (not -f $raw_path) {
            warn_msg("Ignoring path $raw_path");
            next;
        }
        if (not $device_names{$file}) {
            warn_msg("Found unused file $raw_path");
            next;
        }
        my $copy = "$out_dir/$file.raw";
        system("cp -f $raw_path $copy") == 0
          or fatal_err("Can't copy file $raw_path to $copy: $!");
    }
}

sub copy_raw {
    my ($in_path, $out_dir) = @_;
    my $raw_dir = "$in_path/raw";
    -d $raw_dir or return;
    if ($config->{ipv6}) {
        copy_raw1($raw_dir, "$out_dir/ipv6", 'ipv4');
        if (-d (my $subdir = "$raw_dir/ipv4")) {
            copy_raw1($subdir, $out_dir);
        }
    }
    else {
        copy_raw1($raw_dir, $out_dir, 'ipv6');
        if (-d (my $subdir = "$raw_dir/ipv6")) {
            copy_raw1($subdir, "$out_dir/ipv6");
        }
    }
}

sub show_version {
    info("$program, version $version");
}

# Start concurrent jobs.
sub concurrent {
    my ($code1, $code2) = @_;

    # Process sequentially.
    if (1 >= $config->{concurrency_pass1}) {
        $code1->();
        $code2->();
        return;
    }


    # Set up pipe between child and parent process.
    my $pipe = IO::Pipe->new();

    # Parent.
    # Fork process and read output of child process.
    if (my $child_pid = fork()) {

        $code1->();

        # Show child ouput.
        progress('Output of background job:');
        $pipe->reader();
        while (my $line = <$pipe>) {

            # Indent output of child.
            print STDERR " $line";
        }

        # Check exit status of child.
        my $pid = wait();
        $pid != -1 or internal_err("Can't find status of child");
        my $status = $?;
        if ($status != 0) {
            my $err_count = $status >> 8;
            # uncoverable branch true
            if (not $err_count) {
                # uncoverable statement
                internal_err("Background process died with status $status");
            }
            $error_counter += $err_count;
        }
    }

    # Child
    elsif (defined $child_pid) {
        $pipe->writer();

        # Redirect STDERR to pipe, so parent can read errors of child.
        open (STDERR, '>&', $pipe) or
            internal_err("Can't dup STDERR to pipe: $!");

        my $start_error_counter = $error_counter;

        # Catch errors,
        eval {

            $code2->();
            progress('Finished background job') if $config->{time_stamps};
        };
        if ($@) {

            # Show internal errors, but not "Aborted" message.
            # uncoverable branch true
            if ($@ !~ /^Aborted /) {	# uncoverable statement
                print STDERR $@;	# uncoverable statement
            }
        }

        # Tell parent process number of additional errors from child.
        exit $error_counter - $start_error_counter;
    }
    else {
        internal_err("Can't start child: $!");	# uncoverable statement
    }
}

# These must be initialized on each run, because protocols are changed
# by prepare_prt_ordering.
sub init_protocols {
    $prt_ip = { name => 'auto_prt:ip', proto => 'ip' };
    $prt_tcp = {
        name      => 'auto_prt:tcp',
        proto     => 'tcp',
        dst_range => $aref_tcp_any
    };
    $prt_udp = {
        name      => 'auto_prt:udp',
        proto     => 'udp',
        dst_range => $aref_tcp_any
    };
    $prt_ike = {
        name      => 'auto_prt:IPSec_IKE',
        proto     => 'udp',
        src_range => [ 500, 500 ],
        dst_range => [ 500, 500 ]
    };
    $prt_natt = {
        name      => 'auto_prt:IPSec_NATT',
        proto     => 'udp',
        src_range => [ 4500, 4500 ],
        dst_range => [ 4500, 4500 ]
    };
    $prt_esp = { name => 'auto_prt:IPSec_ESP', proto => 50, };
    $prt_ah  = { name => 'auto_prt:IPSec_AH',  proto => 51, };
    $permit_any_rule = {
        src => [ $network_00 ],
        dst => [ $network_00 ],
        prt => [ $prt_ip ]
    };
    $permit_any6_rule = {
        src => [ $network_00_v6 ],
        dst => [ $network_00_v6 ],
        prt => [ $prt_ip ]
    };
    $deny_any_rule = { %$permit_any_rule, deny => 1, };
    $deny_any6_rule = { %$permit_any6_rule, deny => 1, };
}

sub init_global_vars {
    $start_time            = $config->{start_time} || time();
    $error_counter         = 0;
    for my $pair (values %global_type) {
        %{ $pair->[1] } = ();
    }
    %routers6           = ();
    %interfaces         = %hosts                = ();
    @managed_routers    = @routing_only_routers = @router_fragments = ();
    @virtual_interfaces = @pathrestrictions     = ();
    @managed_crypto_hubs = @routers = @networks = @zones = @areas = ();
    @natdomains         = ();
    %auto_interfaces    = ();
    %crypto2spokes      = %crypto2hub = ();
    %service_rules      = %path_rules = ();
    %prt_hash           = %token2regex = ();
    %ref2obj            = %ref2prt = ();
    %obj2zone           = ();
    %obj2path           = ();
    %border2obj2auto    = ();
    @duplicate_rules    = @redundant_rules = ();
    %missing_supernet   = ();
    %known_log          = %key2log = ();
    %nat2obj2address    = ();
    init_protocols();
}

sub compile {
    my ($args) = @_;

    init_global_vars();
    my ($in_path, $out_dir);
    ($config, $in_path, $out_dir) = get_args($args);
    show_version();
    read_file_or_dir($in_path);

    &show_read_statistics();
    &order_protocols();
    &link_topology();
    &mark_disabled();
    &set_zone();
    &setpath();
    &distribute_nat_info();
    find_subnets_in_zone();

    # Call after find_subnets_in_zone, where $zone->{networks} has
    # been set up.
    link_reroute_permit();

    # Sets attributes used in check_dynamic_nat_rules and
    # for ACL generation.
    mark_dynamic_host_nets();

    normalize_services();
    # Abort now, if there had been syntax errors and simple semantic errors.
    abort_on_error();

    check_service_owner();
    convert_hosts_in_rules();
    group_path_rules();

    concurrent(
        sub {
            find_subnets_in_nat_domain();
            check_unstable_nat_rules();

            # Call after {up} relation for anonymous aggregates has
            # been set up.
            mark_managed_local();
        },
        sub {
            check_dynamic_nat_rules();
        });

    concurrent(
        sub {
            check_unused_groups();
            check_supernet_rules();
            check_expanded_rules();
        },
        sub {
            %service_rules = ();
            remove_simple_duplicate_rules();
            set_policy_distribution_ip();
            expand_crypto();
            find_active_routes();
            gen_reverse_rules();
            mark_secondary_rules();
            if ($out_dir) {
                rules_distribution();
                check_output_dir($out_dir);
                print_code($out_dir);
                copy_raw($in_path, $out_dir);
            }
        });

    abort_on_error();
}

1;
