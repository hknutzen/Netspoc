package Netspoc;

=head1 NAME

Netspoc - A Network Security Policy Compiler

=head1 COPYRIGHT AND DISCLAIMER

(c) 2013 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

=cut

use strict;
use warnings;
use Module::Load::Conditional qw(can_load);
my $can_json = can_load( modules => {JSON => 0.0} ) and JSON->import();
use open qw(:std :utf8);
use Encode;
my $filename_encode = 'UTF-8';

# VERSION: inserted by DZP::OurPkgVersion
my $program = 'Network Security Policy Compiler';
my $version = __PACKAGE__->VERSION || 'devel';

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
  %routers
  %interfaces
  %networks
  %hosts
  %zones
  %owners
  %areas
  %pathrestrictions
  %global_nat
  %groups
  %protocols
  %protocolgroups
  %services
  %isakmp
  %ipsec
  %crypto
  %expanded_rules
  $error_counter
  store_description
  get_config_keys
  get_config_pattern
  check_config_pair
  read_config
  set_config
  info
  progress
  abort_on_error
  set_abort_immediately
  err_msg
  fatal_err
  read_ip
  print_ip
  show_version
  split_typed_name
  is_network
  is_router
  is_interface
  is_host
  is_subnet
  is_every
  is_group
  is_protocolgroup
  is_objectgroup
  is_chain
  is_autointerface
  read_netspoc
  read_file
  read_file_or_dir
  show_read_statistics
  order_protocols
  link_topology
  mark_disabled
  set_zone
  set_service_owner
  find_subnets
  expand_services
  expand_crypto
  check_unused_groups
  setpath
  path_walk
  find_active_routes_and_statics
  check_supernet_rules
  optimize_and_warn_deleted
  optimize
  distribute_nat_info
  gen_reverse_rules
  mark_secondary_rules
  rules_distribution
  local_optimization
  check_output_dir
  print_code );

####################################################################
# User configurable options.
####################################################################

# Valid values:
# - Default: 0|1
# - Option with name "check_*": 0,1,'warn'
#  - 0: no check
#  - 1: throw an error if check fails
#  - warn: print warning if check fails
# - Option with name "max_*": integer
# Other: string
our %config = (

# Check for unused groups and protocolgroups.
    check_unused_groups => 'warn',

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

# Check for services where owner can't be derived.
    check_service_unknown_owner => 0,

# Check for services where multiple owners have been derived.
    check_service_multi_owner => 'warn',

# Check for inconsistent use of attributes 'extend' and 'extend_only' in owner.
    check_owner_extend => 0,

# Check for missing supernet rules.
    check_supernet_rules => 'warn',

# Check for transient supernet rules.
    check_transient_supernet_rules => 0,

# Check for unused raw files.
    check_raw => 'warn',

# Optimize the number of routing entries per router:
# For each router find the hop, where the largest
# number of routing entries points to
# and replace them with a single default route.
# This is only applicable for internal networks
# which have no default route to the internet.
    auto_default_route => 1,

# Add comments to generated code.
    comment_acls   => 0,
    comment_routes => 0,

# Ignore these names when reading directories:
# - CVS and RCS directories
# - CVS working files
# - Editor backup files: emacs: *~
    ignore_files => '^(CVS|RCS|\.#.*|.*~)$',

# Abort after this many errors.
    max_errors => 10,

# Print progress messages.
    verbose => 1,

# Print progress messages with time stamps.
# Print "finished" with time stamp when finished.
    time_stamps => 0,
);

# Valid values for config options in %config.
# Key is prefix or string "default".
# Value is pattern for checking valid values.
our %config_type = (
    check_   => '0|1|warn',
    max_     => '\d+',
    ignore_  => '\S+',
    _default => '0|1',
);

sub get_config_keys {
    return keys %config;
}

sub valid_config_key {
    my ($key) = @_;
    return exists $config{$key};
}

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

# Checks for valid config key/value pair.
# Returns false on success, the expected pattern on failure.
sub check_config_pair {
    my ($key, $value) = @_;
    my $pattern = get_config_pattern($key);
    return ($value =~ /^($pattern)$/ ? undef : $pattern);
}

# Set %config with pairs from one or more hashrefs.
# Rightmost hash overrides previous values with same key.
sub set_config {
    my (@hrefs) = @_;
    for my $href (@hrefs) {
        while (my ($key, $val) = each %$href) {
            $config{$key} = $val;
        }
    }
    return;
}

# Modified only by sub store_description.
my $new_store_description = 0;

sub store_description {
    my ($set) = @_;
    if (defined $set) {
        return($new_store_description = $set);
    }
    else {
        return $new_store_description;
    }
}

# Use non-local function exit for efficiency.
# Perl profiler doesn't work if this is active.
my $use_nonlocal_exit => 1;

####################################################################
# Attributes of supported router models
####################################################################
my %router_info = (
    IOS => {
        routing             => 'IOS',
        filter              => 'IOS',
        stateless           => 1,
        stateless_self      => 1,
        stateless_icmp      => 1,
        inversed_acl_mask   => 1,
        can_vrf             => 1,
        can_log_deny        => 1,
        has_out_acl         => 1,
        need_protect        => 1,
        crypto              => 'IOS',
        print_interface     => 1,
        comment_char        => '!',
        extension           => {
            EZVPN => { crypto    => 'EZVPN' },
            FW    => { stateless => 0 },
        },
    },
    'NX-OS' => {
        routing             => 'NX-OS',
        filter              => 'NX-OS',
        stateless           => 1,
        stateless_self      => 1,
        stateless_icmp      => 1,
        can_objectgroup     => 1,
        inversed_acl_mask   => 1,
        use_prefix          => 1,
        can_vrf             => 1,
        can_log_deny        => 1,
        has_out_acl         => 1,
        need_protect        => 1,
        print_interface     => 1,
        comment_char        => '!',
    },
    PIX => {
        routing             => 'PIX',
        filter              => 'PIX',
        stateless_icmp      => 1,
        can_objectgroup     => 1,
        comment_char        => '!',
        has_interface_level => 1,
        need_identity_nat   => 1,
        no_filter_icmp_code => 1,
    },

    # Like PIX, but without identity NAT.
    ASA => {
        routing             => 'PIX',
        filter              => 'PIX',
        stateless_icmp      => 1,
        has_out_acl         => 1,
        can_objectgroup     => 1,
        crypto              => 'ASA',
        no_crypto_filter    => 1,
        comment_char        => '!',
        has_interface_level => 1,
        no_filter_icmp_code => 1,
        extension           => {
            VPN => {
                crypto           => 'ASA_VPN',
                stateless_tunnel => 1,
                do_auth          => 1,
            },
            EZVPN => { crypto    => 'ASA_EZVPN' },
            '8.4' => { v8_4 => 1, },
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

# Definition of dynamic routing protocols.
# Protocols below need not to be ordered using order_protocols
# since they are only used at code generation time.
my %routing_info = (
    EIGRP => {
        name  => 'EIGRP',
        prt   => { name => 'auto_prt:EIGRP', proto => 88 },
        mcast => [
            new(
                'Network',
                name => "auto_network:EIGRP_multicast",
                ip   => gen_ip(224, 0, 0, 10),
                mask => gen_ip(255, 255, 255, 255)
            )
        ]
    },
    OSPF => {
        name  => 'OSPF',
        prt   => { name => 'auto_prt:OSPF', proto => 89 },
        mcast => [
            new(
                'Network',
                name => "auto_network:OSPF_multicast5",
                ip   => gen_ip(224, 0, 0, 5),
                mask => gen_ip(255, 255, 255, 255),
            ),
            new(
                'Network',
                name => "auto_network:OSPF_multicast6",
                ip   => gen_ip(224, 0, 0, 6),
                mask => gen_ip(255, 255, 255, 255)
            )
        ]
    },
    manual => { name => 'manual' },
);

# Definition of redundancy protocols.
my %xxrp_info = (
    VRRP => {
        prt   => { name => 'auto_prt:VRRP', proto => 112 },
        mcast => new(
            'Network',
            name => "auto_network:VRRP_multicast",
            ip   => gen_ip(224, 0, 0, 18),
            mask => gen_ip(255, 255, 255, 255)
        )
    },
    HSRP => {
        prt => {
            name      => 'auto_prt:HSRP',
            proto     => 'udp',
            src_range => {
                name  => 'auto_prt:HSRP',
                proto => 'udp',
                range => [ 1, 65535 ]
            },
            dst_range => {
                name  => 'auto_prt:HSRP',
                proto => 'udp',
                range => [ 1985, 1985 ]
            }
        },
        mcast => new(
            'Network',
            name => "auto_network:HSRP_multicast",
            ip   => gen_ip(224, 0, 0, 2),
            mask => gen_ip(255, 255, 255, 255)
        )
    }
);

## no critic (RequireArgUnpacking)

# All arguments are true.
sub all { $_ || return 0 for @_; return 1 }

# All arguments are 'eq'.
sub equal {
    return 1 if not @_;
    my $first = $_[0];
    return not grep { $_ ne $first } @_[ 1 .. $#_ ];
}

# Unique union of all elements.
# Preserves originnal order.
sub unique {
    my %seen;
    return grep { !$seen{$_}++ } @_;
}

sub find_duplicates {
    my %dupl;
    $dupl{$_}++ for @_;
    return grep { $dupl{$_} > 1 } keys %dupl;
}

sub max {
    my $max = shift(@_);
    for my $el (@_) {
        $max = $el if $max < $el;
    }
    return $max;
}

my $start_time = time();

sub info {
    return if not $config{verbose};
    print STDERR @_, "\n";
    return;
}

sub progress {
    if ($config{time_stamps}) {
        my $diff = time() - $start_time;
        printf STDERR "%3ds ", $diff;
    }
    info(@_);
    return;
}

sub warn_msg {
    print STDERR "Warning: ", @_, "\n";
    return;
}

sub debug {
    return if not $config{verbose};
    print STDERR @_, "\n";
    return;
}
## use critic

# Name of current input file.
our $current_file;

# Rules and objects read from directories and files with
# special name 'xxx.private' are marked with attribute {private} = 'xxx'.
# This variable is used to propagate the value from directories to its
# files and sub-directories.
our $private;

# Content of current file.
our $input;

# Current line number of input file.
our $line;

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
    return qq/ at line $line of $current_file, $context\n/;
}

sub at_line {
    return qq/ at line $line of $current_file\n/;
}

our $error_counter = 0;

sub check_abort {
    $error_counter++;
    if ($error_counter == $config{max_errors}) {
        die "Aborted after $error_counter errors\n";
    }
    elsif ($error_counter > $config{max_errors}) {
        die "Aborted\n";
    }
}

sub abort_on_error {
    die "Aborted with $error_counter error(s)\n" if $error_counter;
    return;
}

sub set_abort_immediately {
    $error_counter = $config{max_errors};
    return;
}

sub error_atline {
    my (@args) = @_;
    print STDERR "Error: ", @args, at_line();
    check_abort();
    return;
}

sub err_msg {
    my (@args) = @_;
    print STDERR "Error: ", @args, "\n";
    check_abort();
    return;
}

sub fatal_err {
    my (@args) = @_;
    print STDERR "Error: ", @args, "\n";
    die "Aborted\n";
}

sub syntax_err {
    my (@args) = @_;
    die "Syntax error: ", @args, context();
}

sub internal_err {
    my (@args) = @_;
    my ($package, $file, $line, $sub) = caller 1;
    die "Internal error in $sub: ", @args, "\n";
}

####################################################################
# Helper functions for reading configuration
####################################################################

# $input is used as input buffer, it holds content of current input file.
# Progressive matching is used. \G is used to match current position.
sub skip_space_and_comment {

    # Ignore trailing white space and comments.
    while ($input =~ m'\G[ \t]*(?:[#].*)?(?:\n|$)'gc) {
        $line++;
    }

    # Ignore leading white space.
    $input =~ m/\G[ \t]*/gc;
    return;
}

# Check for a string and skip if available.
sub check {
    my $token = shift;
    skip_space_and_comment;
    return $input =~ m/\G$token/gc;
}

# Skip a string.
sub skip {
    my $token = shift;
    return(check $token or syntax_err("Expected '$token'"));
}

# Check, if an integer is available.
sub check_int {
    skip_space_and_comment;
    if ($input =~ m/\G(\d+)/gc) {
        return $1;
    }
    else {
        return;
    }
}

sub read_int {
    my $result = check_int();
    defined $result or syntax_err("Integer expected");
    return $result;
}

# Read IP address. Internally it is stored as an integer.
sub check_ip {
    skip_space_and_comment;
    if ($input =~ m/\G(\d+)\.(\d+)\.(\d+)\.(\d+)/gc) {
        if ($1 > 255 or $2 > 255 or $3 > 255 or $4 > 255) {
            error_atline("Invalid IP address");
        }
        return unpack 'N', pack 'C4', $1, $2, $3, $4;
    }
    else {
        return;
    }
}

sub read_ip {
    my $result = check_ip();
    defined $result or syntax_err("IP address expected");
    return $result;
}

sub read_mask {
    my $mask = read_ip();
    defined mask2prefix($mask) or syntax_err("IP mask isn't a valid prefix");
    return $mask;
}

# Read IP address with optional prefix length or mask:
# x.x.x.x or x.x.x.x/n or x.x.x.x/m.m.m.m
sub read_ip_opt_mask {
    my $ip = read_ip;
    check('/') or return $ip;
    my $mask = check_ip();
    if (defined $mask) {
        defined mask2prefix($mask)
          or syntax_err("IP mask isn't a valid prefix");
    }
    else {
        $mask = prefix2mask(read_int());
        defined $mask or syntax_err("Invalid prefix");
    }
    return $ip, $mask;
}

sub read_ip_prefix_pair {
    my ($ip, $mask) = read_ip_opt_mask();
    defined $mask or syntax_err("Missing prefix len");
    match_ip($ip, $ip, $mask) or error_atline("IP and mask don't match");

    # Prevent further errors.
    $ip &= $mask;
    return [ $ip, $mask ];
}

sub gen_ip {
    my ($byte1, $byte2, $byte3, $byte4) = @_;
    return unpack 'N', pack('C4', $byte1, $byte2, $byte3, $byte4);
}

# Convert IP address from internal integer representation to
# readable string.
sub print_ip {
    my $ip = shift;
    return sprintf "%vd", pack 'N', $ip;
}

# Generate a list of IP strings from an ref of an array of integers.
sub print_ip_aref {
    my $aref = shift;
    return map { print_ip $_; } @$aref;
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

sub complement_32bit {
    my ($ip) = @_;
    return ~$ip & 0xffffffff;
}

# Check if $ip1 is located inside network $ip/$mask.
sub match_ip {
    my ($ip1, $ip, $mask) = @_;
    return ($ip == ($ip1 & $mask));
}

sub read_identifier {
    skip_space_and_comment;
    if ($input =~ m/(\G[\w-]+)/gc) {
        return $1;
    }
    else {
        syntax_err("Identifier expected");
    }
}

# Pattrern for attribute "visible": "*" or "name*".
sub read_owner_pattern {
    skip_space_and_comment;
    if ($input =~ m/ ( \G [\w-]* [*] ) /gcx) {
        return $1;
    }
    else {
        syntax_err("Pattern '*' or 'name*' expected");
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

# Used for reading alias name or radius attributes.
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

sub read_union {
    my ($delimiter) = @_;
    my @vals;
    my $count = $user_object->{refcount};
    push @vals, read_intersection();
    my $has_user_ref   = $user_object->{refcount} > $count;
    my $user_ref_error = 0;
    while (1) {
        last if check $delimiter;
        my $comma_seen = check ',';

        # Allow trailing comma.
        last if check $delimiter;

        $comma_seen or syntax_err("Comma expected in union of values");
        $count = $user_object->{refcount};
        push @vals, read_intersection();
        $user_ref_error ||=
          $has_user_ref != ($user_object->{refcount} > $count);
    }
    $user_ref_error
      and error_atline("The sub-expressions of union equally must\n",
                       " either reference 'user' or must not reference 'user'");
    return @vals;
}

# Check for xxx:xxx | router:xx@xx | network:xx/xx | interface:xx/xx
sub check_typed_name {
    skip_space_and_comment;
    $input =~ m/ \G (\w+) : /gcx or return;
    my $type = $1;
    my ($name, $separator);
    if ($input =~ m' \G ( [\w-]+ (?: ( [@/] ) [\w-]+ )? ) 'gcx) {
        $name = $1;
        $separator = $2;
    }
    else {
        syntax_err("Invalid token");
    }

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
    return check_typed_name || syntax_err("Typed name expected");
}

{

    # user@domain or @domain
    my $domain_regex   = qr/@(?:[\w-]+\.)+[\w-]+/;
    my $user_regex     = qr/[\w-]+(?:\.[\w-]+)*/;
    my $user_id_regex  = qr/$user_regex$domain_regex/;
    my $id_regex       = qr/$user_id_regex|$domain_regex/;
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
# or any:[ ip = n.n.n.n/len & xxx:xxx, ...]
# or network:xxx/ppp
# or host:id:user@domain.network
#
    sub read_extended_name {

        if (check 'user') {

            # Global variable for linking occurrences of 'user'.
            $user_object->{active}
              or syntax_err("Unexpected reference to 'user'");
            $user_object->{refcount}++;
            return [ 'user', $user_object ];
        }
        $input =~ m/\G([\w-]+):/gc or syntax_err("Type expected");
        my $type = $1;
        my $interface = $type eq 'interface';
        my $managed;
        my $name;
        my $ext;
        if ($input =~ m/ \G \[ /gcox) {
            if ($interface && check('managed')) {
                $managed = 1;
                skip '&';
            }
            elsif ($type eq 'any' && check('ip')) {
                skip '=';
                $ext = read_ip_prefix_pair();
                skip '&';
            }
            $name = [ read_union(']') ];
        }
        elsif ($type eq 'host') {
            $input =~ m/ \G ( $hostname_regex ) /gcox
              or syntax_err("Name or ID-name expected");
            $name = $1;
        }
        elsif ($type eq 'network') {
            $input =~ m/ \G ( $network_regex ) /gcox
              or syntax_err("Name or bridged name expected");
            $name = $1;
        }
        elsif ($interface && $input =~ m/ \G ( [\w-]+ (?: \@ [\w-]+ ) ) /gcx
            || $input =~ m/ \G ( [\w-]+ ) /gcx)
        {
            $name = $1;
        }
        else {
            syntax_err("Identifier or '[' expected");
        }
        if ($interface) {
            $input =~ m/ \G \. /gcox or syntax_err("Expected '.'");
            if ($input =~ m/ \G \[ /gcox) {
                my $selector = read_identifier;
                $selector =~ /^(auto|all)$/ or syntax_err("Expected [auto|all]");
                $ext = [ $selector, $managed ];
                skip '\]';
            }
            else {
                $input =~ m/ \G ( $network_regex ) /gcox
                  or syntax_err("Name or bridged name expected");
                $ext = $1;
                if ($input =~ m/ \G \. /gcox) {
                    $ext .= '.' . read_identifier;
                }
                $managed
                  and syntax_err("Keyword 'managed' not allowed");
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
            syntax_err("Id expected ('user\@domain' or 'user')");
        }
    }

# host:xxx or host:id:user@domain or host:id:@domain
    sub check_hostname {
        skip_space_and_comment;
        if ($input =~ m/\G host:/gcx) {
            if ($input =~ m/\G($hostname_regex)/gco) {
                return $1;
            }
            else {
                syntax_err('Hostname expected');
            }
        }
        else {
            return;
        }
    }
}

sub read_complement {
    if (check '!') {
        return [ '!', read_extended_name() ];
    }
    else {
        return read_extended_name();
    }
}

sub read_intersection {
    my @result = read_complement();
    while (check '&') {
        push @result, read_complement();
    }
    if (@result == 1) {
        return $result[0];
    }
    else {
        return [ '&', \@result ];
    }
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
    my $factor = $timeunits{$unit} or syntax_err("Invalid time unit");
    return $int * $factor;
}

sub add_description {
    my ($obj) = @_;
    skip_space_and_comment();
    check 'description' or return;
    skip '=';

    # Read up to end of line, but ignore ';' at EOL.
    # We must use '$' here to match EOL,
    # otherwise $line would be out of sync.
    $input =~ m/\G[ \t]*(.*?)[ \t]*;?[ \t]*$/gcm;
    if (store_description()) {
        $obj->{description} = $1;
    }
    return;
}

# Check if one of the keywords 'permit' or 'deny' is available.
sub check_permit_deny {
    skip_space_and_comment();
    if ($input =~ m/\G(permit|deny)/gc) {
        return $1;
    }
    else {
        return;
    }
}

sub check_nat_name {
    skip_space_and_comment;
    if ($input =~ m/\G nat:([\w-]+)/gcx) {
        return $1;
    }
    else {
        return;
    }
}
sub split_typed_name {
    my ($name) = @_;

    # Split at first colon; the name may contain further colons.
    return split /[:]/, $name, 2;
}

sub check_flag {
    my $token = shift;
    if (check $token) {
        skip(';');
        return 1;
    }
    else {
        return;
    }
}

sub read_assign {
    my ($token, $fun) = @_;
    skip $token;
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

sub check_assign {
    my ($token, $fun) = @_;
    if (check($token)) {
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
    return;
}

sub read_list {
    my ($fun) = @_;
    my @vals;
    while (1) {
        push @vals, &$fun;
        last if check(';');
        my $comma_seen = check ',';

        # Allow trailing comma.
        last if check(';');

        $comma_seen or syntax_err("Comma expected in list of values");
    }
    return @vals;
}

sub read_list_or_null {
    my ($fun) = @_;
    return () if check(';');
    return read_list($fun);
}

sub read_assign_list {
    my ($token, $fun) = @_;
    skip $token;
    skip '=';
    return read_list($fun);
}

sub check_assign_list {
    my ($token, $fun) = @_;
    if (check $token) {
        skip '=';
        return &read_list($fun);
    }
    return ();
}

sub check_assign_pair {
    my ($token, $delimiter, $fun) = @_;
    if (check $token) {
        skip '=';
        my $v1 = &$fun;
        skip $delimiter;
        my $v2 = &$fun;
        skip(';');
        return $v1, $v2;
    }
    return ();
}

# Delete an element from an array reference.
# Return 1 if found, 0 otherwise.
sub aref_delete {
    my ($aref, $elt) = @_;
    for (my $i = 0 ; $i < @$aref ; $i++) {
        if ($aref->[$i] eq $elt) {
            splice @$aref, $i, 1;

#debug("aref_delete: $elt->{name}");
            return 1;
        }
    }
    return 0;
}

# Compare two array references element wise.
sub aref_eq  {
    my ($a1, $a2) = @_;
    return 0 if @$a1 ne @$a2;
    for (my $i = 0 ; $i < @$a1 ; $i++) {
        return 0 if $a1->[$i] ne $a2->[$i];
    }
    return 1;
}

####################################################################
# Creation of typed structures
# Currently we don't use OO features;
# We use 'bless' only to give each structure a distinct type.
####################################################################

# A hash, describing, which parts are read fom JSON.
# Possible keys:
# - watchers
my $from_json;

# Create a new structure of given type;
# initialize it with key / value pairs.
sub new {
    my ($type, @pairs) = @_;
    my $self = {@pairs};
    return bless $self, $type;
}

our %hosts;

# A single host which gets the attribute {policy_distribution_point}
# is stored here.
# This is typically the netspoc server or some other server
# which is used to distribute the generated configuration files
# to managed devices.
my $policy_distribution_point;

sub check_radius_attributes {
    my $result = {};
    check 'radius_attributes' or return;
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        my $key = read_identifier();
        my $val = check('=') ? read_string : undef;
        skip ';';
        $result->{$key} and error_atline("Duplicate attribute '$key'");
        $result->{$key} = $val;
    }
    return $result;
}

sub check_routing {
    my $protocol = check_assign('routing', \&read_identifier) or return;
    my $routing = $routing_info{$protocol}
      or error_atline('Unknown routing protocol');
    return $routing;
}

sub check_managed {
    check('managed') or return;
    my $managed;
    if (check ';') {
        $managed = 'standard';
    }
    elsif (check '=') {
        my $value = read_identifier;
        if ($value =~ /^(?:secondary|standard|full|primary|local)$/) {
            $managed = $value;
        }
        else {
            error_atline("Expected value:",
                         " secondary|standard|full|primary|local");
        }
        check ';';
    }
    else {
        syntax_err("Expected ';' or '='");
    }
    return $managed;
}

sub check_model {
    my ($model, @attributes) = check_assign_list('model', \&read_name)
        or return;
    my @attr2;
    ($model, @attr2) = split /_/, $model;
    push @attributes, @attr2;
    my $info = $router_info{$model};
    if (not $info) {
        error_atline("Unknown router model");
        next;
    }
    my $extension_info = $info->{extension};
    if (@attributes and not $extension_info) {
        error_atline("No extension expected for this model");
        next;
    }

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

my @managed_routers;

# Managed host is stored internally as an interface.
# The interface gets an artificial router.
# Both, router and interface get name "host:xx".
sub host_as_interface {
    my ($host) = @_;
    my $name = $host->{name};
    my $model = delete $host->{model};
    my $hw_name = delete $host->{hardware};
    if (!$model) {
        err_msg("Missing 'model' for managed $host->{name}");
        
        # Prevent further errors.
        $host->{model} = { name => 'unknown' };
    }
    if (! $hw_name) {
        err_msg("Missing 'hardware' for $name");
    }
    $model->{can_managed_host} 
      or err_msg("Must not use model $model->{name} at managed $name");

    # Use device_name with "host:.." prefix to prevent name clash with 
    # real routers.
    my $router = new('Router', name => $name, device_name => $name);
    $router->{managed} = delete $host->{managed};
    $router->{model} = $model;
    my $interface = new('Interface', %$host);
    $interface->{router} = $router;
    my $hardware = { name => $hw_name, interfaces => [ $interface ] };
    $interface->{hardware} = $hardware;
    $interface->{routing} = $routing_info{manual};
    $router->{interfaces} = [ $interface ];
    $router->{hardware}   = [ $hardware ];

    # Don't add to %routers
    # - Name lookup isn't needed.
    # - Linking with network isn't needed.
    push @managed_routers, $router;
    return $interface;
}

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
        last if check '}';
        if (my $ip = check_assign 'ip', \&read_ip) {
            $host->{ip} and error_atline("Duplicate attribute 'ip'");
            $host->{ip} = $ip;
        }
        elsif (my ($ip1, $ip2) = check_assign_pair('range', '-', \&read_ip)) {
            $ip1 <= $ip2 or error_atline("Invalid IP range");
            $host->{range} and error_atline("Duplicate attribute 'range'");
            $host->{range} = [ $ip1, $ip2 ];
        }

        # Currently, only simple 'managed' attribute,
        # because 'secondary' and 'local' isn't supported by Linux.
        elsif (my $managed = check_managed()) {
            $host->{managed} and error_atline("Duplicate attribute 'managed'");
            $managed eq 'standard' 
              or error_atline("Only 'managed=standard' is supported");
            $host->{managed} = 'standard';
        }
        elsif (my $model = check_model()) {
            $host->{model} and error_atline("Duplicate attribute 'model'");
            $host->{model} = $model;
        }
        elsif (my $hardware = check_assign('hardware', \&read_name)) {
            $host->{hardware}
              and error_atline("Duplicate definition of hardware");
            $host->{hardware} = $hardware;
        }
        elsif (my $owner = check_assign 'owner', \&read_identifier) {
            $host->{owner} and error_atline("Duplicate attribute 'owner'");
            $host->{owner} = $owner;
        }
        elsif (my $radius_attributes = check_radius_attributes) {
            $host->{radius_attributes}
              and error_atline("Duplicate attribute 'radius_attributes'");
            $host->{radius_attributes} = $radius_attributes;
        }
        elsif (check_flag 'policy_distribution_point') {
            $policy_distribution_point = $host;
        }
        elsif (my $pair = check_typed_name) {
            my ($type, $name) = @$pair;
            if ($type eq 'nat') {
                skip '=';
                skip '{';
                skip 'ip';
                skip '=';
                my $nat_ip = read_ip;
                skip ';';
                skip '}';
                $host->{nat}->{$name}
                  and error_atline("Duplicate NAT definition");
                $host->{nat}->{$name} = $nat_ip;
            }
            else {
                syntax_err("Expected NAT definition");
            }
        }
        else {
            syntax_err("Unexpected attribute");
        }
    }
    $host->{ip} xor $host->{range}
      or error_atline("Exactly one of attributes 'ip' and 'range' is needed");

    if ($host->{id}) {
        $host->{radius_attributes} ||= {};
    }
    else {
        $host->{radius_attributes}
          and error_atline("Attribute 'radius_attributes' is not allowed",
                           " for $name");
    }
    if ($host->{nat}) {
        for my $what (qw(range subnet)) {
            if ($host->{$what}) {

                # Look at print_pix_static before changing this.
                error_atline("No NAT supported for host with '$what'");
            }
        }
    }
    if ($host->{managed}) {
        my %ok = ( name => 1, ip => 1, nat => 1, 
                   managed => 1, model => 1, hardware => 1);
        for my $key (keys %$host) {
            next if $ok{$key};
            error_atline("Managed $host->{name} must not have ",
                           ($key eq 'nat') ? "nat definition"
                         :                   "attribute '$key'");
        }
        return host_as_interface($host);
    }
    return $host;
}

sub read_nat {
    my $name = shift;

    # Currently this needs not to be blessed.
    my $nat = { name => $name };
    (my $nat_tag = $name) =~ s/^nat://;
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        if (my ($ip, $mask) = check_assign 'ip', \&read_ip_opt_mask) {
            if (defined $mask) {
                $nat->{mask} and error_atline("Duplicate IP mask");
                $nat->{mask} = $mask;
            }
            $nat->{ip} and error_atline("Duplicate IP address");
            $nat->{ip} = $ip;
        }
        elsif ($mask = check_assign 'mask', \&read_mask) {
            $nat->{mask} and error_atline("Duplicate IP mask");
            $nat->{mask} = $mask;
        }
        elsif (check_flag 'hidden') {
            $nat->{hidden} = 1;
        }
        elsif (check_flag 'identity') {
            $nat->{identity} = 1;
        }
        elsif (check_flag 'dynamic') {

            # $nat_tag is used later to look up static translation
            # of hosts inside a dynamically translated network.
            $nat->{dynamic} = $nat_tag;
        }
        elsif (my $pair = check_assign 'subnet_of', \&read_typed_name) {
            $nat->{subnet_of}
              and error_atline("Duplicate attribute 'subnet_of'");
            $nat->{subnet_of} = $pair;
        }
        else {
            syntax_err("Expected some valid NAT attribute");
        }
    }
    if ($nat->{hidden}) {
        for my $key (keys %$nat) {
            next if grep { $key eq $_ } qw( name hidden );
            error_atline("Hidden NAT must not use attribute $key");
        }

        # This simplifies error checks for overlapping addresses.
        $nat->{dynamic} = $nat_tag;
    }
    elsif ($nat->{identity}) {
        for my $key (keys %$nat) {
            next if grep { $key eq $_ } qw( name identity );
            error_atline("Identity NAT must not use attribute $key");
        }
    }
    else {
        defined($nat->{ip}) or error_atline("Missing IP address");
        if (defined $nat->{mask}) {
            if (not(match_ip($nat->{ip}, $nat->{ip}, $nat->{mask}))) {
                error_atline("$nat->{name}'s IP doesn't match its mask");
            }
        }
    }
    return $nat;
}

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
        last if check '}';
        if (my ($ip, $mask) = check_assign 'ip', \&read_ip_opt_mask) {
            if (defined $mask) {
                defined $network->{mask} and error_atline("Duplicate IP mask");
                $network->{mask} = $mask;
            }
            $network->{ip} and error_atline("Duplicate IP address");
            $network->{ip} = $ip;
        }
        elsif (defined($mask = check_assign 'mask', \&read_mask)) {
            defined $network->{mask} and error_atline("Duplicate IP mask");
            $network->{mask} = $mask;
        }
        elsif (check_flag 'unnumbered') {
            defined $network->{ip} and error_atline("Duplicate IP address");
            $network->{ip} = 'unnumbered';
        }
        elsif (check_flag 'has_subnets') {

            # Duplicate use of this flag doesn't matter.
            $network->{has_subnets} = 1;
        }
        elsif (check_flag 'crosslink') {

            # Duplicate use of this flag doesn't matter.
            $network->{crosslink} = 1;
        }
        elsif (check_flag 'isolated_ports') {

            # Duplicate use of this flag doesn't matter.
            $network->{isolated_ports} = 1;
        }
        elsif (my $pair = check_assign 'subnet_of', \&read_typed_name) {
            $network->{subnet_of}
              and error_atline("Duplicate attribute 'subnet_of'");
            $network->{subnet_of} = $pair;
        }
        elsif (my $owner = check_assign 'owner', \&read_identifier) {
            $network->{owner}
              and error_atline("Duplicate attribute 'owner'");
            $network->{owner} = $owner;
        }
        elsif (my $radius_attributes = check_radius_attributes) {
            $network->{radius_attributes}
              and error_atline("Duplicate attribute 'radius_attributes'");
            $network->{radius_attributes} = $radius_attributes;
        }
        elsif (my $host_name = check_hostname()) {
            my $host = read_host("host:$host_name", $net_name);
            if (is_host($host)) {
                push @{ $network->{hosts} }, $host;
                $host_name = (split_typed_name($host->{name}))[1];
            }

            # Managed host is stored as interface internally.
            elsif (is_interface($host)) {
                $host->{network} = $network;
                push @{ $network->{interfaces} }, $host;
                check_interface_ip($host, $network);
            }
            else {
                internal_err;
            }
            $hosts{$host_name} and error_atline("Duplicate host:$host_name");
            $hosts{$host_name} = $host;
        }
        elsif (my $nat_tag = check_nat_name()) {
            my $nat = read_nat("nat:$nat_tag");
            ($network->{nat} && $network->{nat}->{$nat_tag} ||
             $network->{identity_nat} && $network->{identity_nat}->{$nat_tag})
              and error_atline("Duplicate NAT definition");
            if ($nat->{identity}) {
                $network->{identity_nat}->{$nat_tag} = $nat;
            } 
            else {
                $nat->{name} .= "($name)";
                $network->{nat}->{$nat_tag} = $nat;
            } 
        }
        else {
            syntax_err("Expected some valid attribute");
        }
    }

    # Network needs at least IP and mask to be defined.
    my $ip = $network->{ip};

    # Use 'defined' here because IP may have value '0'.
    defined $ip or syntax_err("Missing network IP");

    if ($ip eq 'unnumbered') {
        my %ok = (ip => 1, name => 1);

        # Unnumbered network must not have any other attributes.
        for my $key (keys %$network) {
            next if $ok{$key};
            error_atline("Unnumbered $network->{name} must not have ",
                           ($key eq 'hosts') ? "host definition"
                         : ($key eq 'nat')   ? "nat definition"
                         :                     "attribute '$key'");
        }
    }
    elsif ($network->{bridged}) {
        my %ok = (ip => 1, mask => 1, bridged => 1, name => 1, 
                  identity_nat => 1, owner => 1);

        # Bridged network must not have any other attributes.
        for my $key (keys %$network) {
            next if $ok{$key};
            error_atline(
              "Bridged $network->{name} must not have ",
                ($key eq 'hosts') ? "host definition (not implemented)"
              : ($key eq 'nat')   ? "nat definition"
              :                     "attribute '$key'");
        }
    }
    else {
        my $mask = $network->{mask};

        # Use 'defined' here because mask may have value '0'.
        defined $mask or syntax_err("Missing network mask");

        # Check if network IP matches mask.
        if (not(match_ip($ip, $ip, $mask))) {
            error_atline("IP and mask don't match");

            # Prevent further errors.
            $network->{ip} &= $mask;
        }
        for my $host (@{ $network->{hosts} }) {

            # Link host with network.
            $host->{network} = $network;

            # Check compatibility of host IP and network IP/mask.
            if (my $host_ip = $host->{ip}) {
                if (not(match_ip($host_ip, $ip, $mask))) {
                    error_atline("$host->{name}'s IP doesn't match".
                                 " network IP/mask");
                }
            }
            elsif ($host->{range}) {
                my ($ip1, $ip2) = @{ $host->{range} };
                if (
                    not(    match_ip($ip1, $ip, $mask)
                        and match_ip($ip2, $ip, $mask))
                  )
                {
                    error_atline("$host->{name}'s IP range doesn't match",
                                 " network IP/mask");
                }
            }
            else {
                internal_err();
            }

            # Compatibility of host and network NAT will be checked later,
            # after global NAT definitions have been processed.
        }
        if (@{ $network->{hosts} } and $network->{crosslink}) {
            error_atline("Crosslink network must not have host definitions");
        }
        if ($network->{nat}) {
            $network->{isolated_ports}
              and error_atline("Attribute 'isolated_ports' isn't supported",
                " together with NAT");

            # Check NAT definitions.
            for my $nat (values %{ $network->{nat} }) {
                next if $nat->{hidden};
                if (defined $nat->{mask}) {
                    unless ($nat->{dynamic}) {
                        $nat->{mask} == $mask
                          or error_atline("Mask for non dynamic $nat->{name}",
                                          " must be equal to network mask");
                    }
                }
                else {

                    # Inherit mask from network.
                    $nat->{mask} = $mask;
                }

                # Check if IP matches mask.
                if (not(match_ip($nat->{ip}, $nat->{ip}, $nat->{mask}))) {
                    error_atline("IP for $nat->{name} doesn't",
                                 " match its mask");

                    # Prevent further errors.
                    $nat->{ip} &= $nat->{mask};
                }
            }
        }

        # Check and mark networks with ID-hosts.
        if (my $id_hosts_count = grep { $_->{id} } @{ $network->{hosts} }) {

            # If one host has ID, all hosts must have ID.
            @{ $network->{hosts} } == $id_hosts_count
              or error_atline("All hosts must have ID in $name");

            # Mark network.
            $network->{has_id_hosts} = 1;
            $network->{radius_attributes} ||= {};
        }
        else {
            $network->{radius_attributes}
              and error_atline("Attribute 'radius_attributes' is",
                               " not allowed for $name");
        }
    }
    return $network;
}

our %interfaces;
my @virtual_interfaces;
my $global_active_pathrestriction = new(
    'Pathrestriction',
    name        => 'global_pathrestriction',
    active_path => 1
);

sub check_global_active_pathrestriction {
    my ($interface) = @_;
    my $restrict = $interface->{path_restrict} or return;
    return(grep { $_ eq $global_active_pathrestriction } @$restrict);
}

# Tunnel networks which are already attached to tunnel interfaces
# at spoke devices. Key is crypto name, not crypto object.
my %crypto2spokes;

# Real interfaces at crypto hub, where tunnels are attached.
# Key is crypto name, not crypto object.
my %crypto2hubs;

sub read_interface {
    my ($name) = @_;
    my $interface = new('Interface', name => $name);

    # Short form of interface definition.
    if (not check '=') {
        skip ';';
        $interface->{ip} = 'short';
        return $interface;
    }

    my @secondary_interfaces = ();
    my $virtual;
    skip '{';
    add_description($interface);
    while (1) {
        last if check '}';
        if (my @ip = check_assign_list 'ip', \&read_ip) {
            $interface->{ip} and error_atline("Duplicate attribute 'ip'");
            $interface->{ip} = shift @ip;

            # Build interface objects for secondary IP addresses.
            # These objects are named interface:router.name.2, ...
            my $counter = 2;
            for my $ip (@ip) {
                push @secondary_interfaces,
                  new('Interface', name => "$name.$counter", ip => $ip);
                $counter++;
            }
        }
        elsif (check_flag 'unnumbered') {
            $interface->{ip} and error_atline("Duplicate attribute 'ip'");
            $interface->{ip} = 'unnumbered';
        }
        elsif (check_flag 'negotiated') {
            $interface->{ip} and error_atline("Duplicate attribute 'ip'");
            $interface->{ip} = 'negotiated';
        }
        elsif (check_flag 'loopback') {
            $interface->{loopback} = 1;
        }
        elsif (check_flag 'no_in_acl') {
            $interface->{no_in_acl} = 1;
        }

        # Needed for the implicitly defined network of 'loopback'.
        elsif (my $pair = check_assign 'subnet_of', \&read_typed_name) {
            $interface->{subnet_of}
              and error_atline("Duplicate attribute 'subnet_of'");
            $interface->{subnet_of} = $pair;
        }
        elsif (my @pairs = check_assign_list 'hub', \&read_typed_name) {
            for my $pair (@pairs) {
                my ($type, $name2) = @$pair;
                $type eq 'crypto' or error_atline("Expected type 'crypto'");
                push @{ $interface->{hub} }, "$type:$name2";
            }
        }
        elsif ($pair = check_assign 'spoke', \&read_typed_name) {
            my ($type, $name2) = @$pair;
            $type eq 'crypto' or error_atline("Expected type crypto");
            $interface->{spoke} and error_atline("Duplicate attribute 'spoke'");
            $interface->{spoke} = "$type:$name2";
        }
        elsif (my $id = check_assign 'id', \&read_user_id) {
            $interface->{id}
              and error_atline("Duplicate attribute 'id'");
            $interface->{id} = $id;
        }
        elsif (defined(my $level = check_assign 'security_level', \&read_int)) {
            $level > 100
              and error_atline("Maximum value for attribute security_level",
                               " is 100");
            defined $interface->{security_level}
              and error_atline("Duplicate attribute 'security_level'");
            $interface->{security_level} = $level;
        }
        elsif ($pair = check_typed_name) {
            my ($type, $name2) = @$pair;
            if ($type eq 'nat') {
                skip '=';
                skip '{';
                skip 'ip';
                skip '=';
                my $nat_ip = read_ip;
                skip ';';
                skip '}';
                $interface->{nat}->{$name2}
                  and error_atline("Duplicate NAT definition");
                $interface->{nat}->{$name2} = $nat_ip;
            }
            elsif ($type eq 'secondary') {

                # Build new interface for secondary IP addresses.
                my $secondary = new('Interface', name => "$name.$name2");
                skip '=';
                skip '{';
                while (1) {
                    last if check '}';
                    if (my $ip = check_assign 'ip', \&read_ip) {
                        $secondary->{ip}
                          and error_atline("Duplicate IP address");
                        $secondary->{ip} = $ip;
                    }
                    else {
                        syntax_err("Expected attribute IP");
                    }
                }
                $secondary->{ip} or error_atline("Missing IP address");
                push @secondary_interfaces, $secondary;
            }
            else {
                syntax_err("Expected nat or secondary interface definition");
            }
        }
        elsif (check 'virtual') {
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
                last if check '}';
                if (my $ip = check_assign 'ip', \&read_ip) {
                    $virtual->{ip}
                      and error_atline("Duplicate virtual IP address");
                    $virtual->{ip} = $ip;
                }
                elsif (my $type = check_assign 'type', \&read_identifier) {
                    $xxrp_info{$type}
                      or error_atline("Unknown redundancy protocol");
                    $virtual->{redundancy_type}
                      and error_atline("Duplicate redundancy protocol");
                    $virtual->{redundancy_type} = $type;
                }
                elsif (my $id = check_assign 'id', \&read_identifier) {
                    $id =~ /^\d+$/
                      or error_atline("Redundancy ID must be numeric");
                    $id < 256 or error_atline("Redundancy ID must be < 256");
                    $virtual->{redundancy_id}
                      and error_atline("Duplicate redundancy ID");
                    $virtual->{redundancy_id} = $id;
                }
                else {
                    syntax_err("Expected valid attribute for virtual IP");
                }
            }
            $virtual->{ip} or error_atline("Missing virtual IP");
            ($virtual->{redundancy_id} && !$virtual->{redundancy_type}) and
                syntax_err("Redundancy ID is given without redundancy protocol");
        }
        elsif (my @tags = check_assign_list 'bind_nat', \&read_identifier) {
            $interface->{bind_nat} and error_atline("Duplicate NAT binding");
            $interface->{bind_nat} = [ unique sort @tags ];
        }
        elsif (my $hardware = check_assign 'hardware', \&read_name) {
            $interface->{hardware}
              and error_atline("Duplicate definition of hardware");
            $interface->{hardware} = $hardware;
        }
        elsif (my $routing = check_routing()) {
            $interface->{routing} 
              and error_atline("Duplicate attribute 'routing'");
            $interface->{routing} = $routing;
        }
        elsif (@pairs = check_assign_list 'reroute_permit', \&read_typed_name) {
            $interface->{reroute_permit}
              and error_atline('Duplicate definition of reroute_permit');
            $interface->{reroute_permit} = \@pairs;
        }
        elsif (check_flag 'disabled') {
            $interface->{disabled} = 1;
        }
        elsif (check_flag 'no_check') {
            $interface->{no_check} = 1;
        }
        elsif (check_flag 'promiscuous_port') {
            $interface->{promiscuous_port} = 1;
        }
        else {
            syntax_err('Expected some valid attribute');
        }
    }

    if ($name =~ m,/,) {
        $interface->{ip} ||= 'bridged';
    }

    # Swap virtual interface and main interface
    # or take virtual interface as main interface if no main IP available.
    # Subsequent code becomes simpler if virtual interface is main interface.
    if ($virtual) {
        if (my $ip = $interface->{ip}) {
            if ($ip =~ /^(unnumbered|negotiated|short|bridged)$/) {
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
    if ($interface->{loopback}) {
        my %copy = %$interface;

        # Only these attributes are valid.
        delete @copy{
            qw(name ip nat bind_nat hardware loopback subnet_of
              redundant redundancy_type redundancy_id)
          };
        if (keys %copy) {
            my $attr = join ", ", map { "'$_'" } keys %copy;
            error_atline("Invalid attributes $attr for loopback interface");
        }
        if ($interface->{ip} =~ /^(unnumbered|negotiated|short|bridged)$/) {
            error_atline("Loopback interface must not be $interface->{ip}");
        }
    }
    elsif ($interface->{subnet_of}) {
        error_atline("Attribute 'subnet_of' is only valid",
                     " for loopback interface");
    }
    if ($interface->{ip} eq 'bridged') {
        my %ok = (ip => 1, hardware => 1, name => 1, bind_nat => 1);
        if (my @extra = grep { !$ok{$_} } keys %$interface) {
            my $attr = join ", ", map { "'$_'" } @extra;
            error_atline("Invalid attributes $attr for bridged interface");
        }
    }
    if (my $crypto = $interface->{spoke}) {
        @secondary_interfaces
          and error_atline("Interface with attribute 'spoke'",
                           " must not have secondary interfaces");
        $interface->{hub}
          and error_atline("Interface with attribute 'spoke'",
                           " must not have attribute 'hub'");
    }
    else {
        $interface->{id}
          and error_atline("Attribute 'id' is only valid for 'spoke' interface");
    }
    if (my $crypto_list = $interface->{hub}) {
        if ($interface->{ip} =~ /^(unnumbered|negotiated|short|bridged)$/) {
            error_atline("Crypto hub must not be $interface->{ip} interface");
        }
        for my $crypto (@$crypto_list) {
            push @{ $crypto2hubs{$crypto} }, $interface;
        }
    }
    for my $secondary (@secondary_interfaces) {
        $secondary->{main_interface} = $interface;
        for my $key (qw(hardware bind_nat routing disabled)) {
            $secondary->{$key} = $interface->{$key} if $interface->{$key};
        }

        # No traffic must pass secondary interface.
        # If secondary interface is start- or endpoint of a path,
        # the corresponding router is entered by main interface.
        push @{ $secondary->{path_restrict} }, $global_active_pathrestriction;
    }
    return $interface, @secondary_interfaces;
}

# PIX firewalls have a security level associated with each interface.
# Use attribute 'security_level' or
# try to derive the level from the interface name.
sub set_pix_interface_level {
    my ($router) = @_;
    for my $hardware (@{ $router->{hardware} }) {
        my $hwname = $hardware->{name};
        my $level;
        if (
            my @levels = grep { defined($_) }
                map { $_->{security_level} } @{ $hardware->{interfaces} }
          )
        {
            if (@levels > 2 && !equal(@levels)) {
                err_msg "Must not use different values",
                  " for attribute 'security_level\n",
                  " at $router->{name}, hardware $hwname: ", join(',', @levels);
            }
            else {
                $level = $levels[0];
            }
        }
        elsif ($hwname =~ 'inside') {
            $level = 100;
        }
        elsif ($hwname =~ 'outside') {
            $level = 0;
        }

        # It is not necessary the find the exact level; what we need to know
        # is the relation of the security levels to each other.
        elsif (($level) = ($hwname =~ /(\d+)$/) and $level <= 100) {
        }
        else {
            $level = 50;
        }
        $hardware->{level} = $level;
    }
    return;
}

my $bind_nat0 = [];

our %routers;

sub read_router {
    my $name = shift;

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
        last if check '}';
        if (my $managed = check_managed()) {
            $router->{managed} 
              and error_atline("Redefining 'managed' attribute");
            $router->{managed} = $managed;
        }
        elsif (my @filter_only = check_assign_list('filter_only', 
                                                   \&read_ip_prefix_pair)) 
        {
            $router->{filter_only}
              and error_atline("Duplicate attribute 'filter_only'");
            $router->{filter_only} = \@filter_only;
        }
        elsif (my $model = check_model()) {
            $router->{model} and error_atline("Duplicate attribute 'model'");
            $router->{model} = $model;
        }
        elsif (check_flag 'no_group_code') {
            $router->{no_group_code} = 1;
        }
        elsif (check_flag 'no_crypto_filter') {
            $router->{no_crypto_filter} = 1;
        }
        elsif (check_flag 'std_in_acl') {
            $router->{std_in_acl} = 1;
        }
        elsif (check_flag 'log_deny') {
            $router->{log_deny} = 1;
        }
        elsif (my $routing = check_routing()) {
            $router->{routing} 
              and error_atline("Duplicate attribute 'routing'");
            $router->{routing} = $routing;
        }
        elsif (my $owner = check_assign 'owner', \&read_identifier) {
            $router->{owner} and error_atline("Duplicate attribute 'owner'");
            $router->{owner} = $owner;
        }
        elsif (my $radius_attributes = check_radius_attributes) {
            $router->{radius_attributes}
              and error_atline("Duplicate attribute 'radius_attributes'");
            $router->{radius_attributes} = $radius_attributes;
        }
        else {
            my $pair = read_typed_name;
            my ($type, $network) = @$pair;
            $type eq 'interface'
              or syntax_err("Expected interface definition");

            # Derive interface name from router name.
            my $iname = "$rname.$network";
            for my $interface (read_interface "interface:$iname") {
                push @{ $router->{interfaces} }, $interface;
                ($iname = $interface->{name}) =~ s/interface://;
                if ($interfaces{$iname}) {
                    error_atline("Redefining $interface->{name}");
                }

                # Assign interface to global hash of interfaces.
                $interfaces{$iname} = $interface;

                # Link interface with router object.
                $interface->{router} = $router;

                # Link interface with network name (will be resolved later).
                $interface->{network} = $network;

                # Set private attribute of interface.
                # If a loopback network is created below it doesn't need to get
                # this attribute because the network can't be referenced.
                $interface->{private} = $private if $private;
            }
        }
    }

    # Detailed interface processing for managed routers.
    if (my $managed = $router->{managed}) {
        my $model = $router->{model};
        my $all_routing = $router->{routing};

        unless ($model) {
            err_msg("Missing 'model' for managed $name");

            # Prevent further errors.
            $router->{model} = { name => 'unknown' };
        }

        if ($managed eq 'local') {
            $router->{filter_only} or
                err_msg("Missing attribut 'filter_only' for $name");
            $model->{has_io_acl} and
                err_msg("Must not use 'managed = local' at $name",
                        " of model $model->{name}");
        }
        $router->{vrf}
          and not $model->{can_vrf}
          and err_msg("Must not use VRF at $name",
            " of model $model->{name}");

        $router->{log_deny}
          and not $model->{can_log_deny}
          and err_msg("Must not use attribute 'log_deny' at $name",
            " of model $model->{name}");

        # Create objects representing hardware interfaces.
        # All logical interfaces using the same hardware are linked
        # to the same hardware object.
        my %hardware;
        for my $interface (@{ $router->{interfaces} }) {
            if (my $hw_name = $interface->{hardware}) {
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
                if (!$interface->{loopback}) {
                    delete $hardware->{loopback};
                }

                # Remember, which logical interfaces are bound
                # to which hardware.
                push @{ $hardware->{interfaces} }, $interface;
            }
            else {

                # Managed router must not have short interface.
                if ($interface->{ip} eq 'short') {
                    err_msg
                      "Short definition of $interface->{name} not allowed";
                }
                else {

                    # Interface of managed router needs to
                    # have a hardware name.
                    err_msg("Missing 'hardware' for $interface->{name}");
                }
            }

            # Interface inherits routing attribute from router.
            if ($all_routing) {
                $interface->{routing} ||= $all_routing;
            }
            if ((my $routing = $interface->{routing}) && 
                $interface->{ip} eq 'unnumbered')
            {
                my $rname = $routing->{name};
                $rname eq 'manual' or
                    error_atline("Routing $rname not supported",
                                 " for unnumbered interface");
            }
            if (defined $interface->{security_level}
                && !$model->{has_interface_level})
            {
                warn_msg("Ignoring attribute 'security_level'",
                    " at $interface->{name}");
            }
            if ($interface->{hub} or $interface->{spoke}) {
                $model->{crypto}
                  or err_msg "Crypto not supported for $name",
                  " of model $model->{name}";
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
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{ip} eq 'bridged';
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

                if ($layer3_intf->{ip} =~
                    /^(unnumbered|negotiated|short|bridged)$/)
                {
                    err_msg(
                        "Layer3 $layer3_intf->{name}",
                        " must not be $interface->{ip}"
                    );
                }
                if ($model->{class} eq 'ASA') {
                    $layer3_intf->{hardware}->{name} eq 'device'
                      or
                      err_msg("Layer3 $interface->{name} must use 'hardware'",
                        " named 'device' for model 'ASA'");
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
        if ($model->{has_interface_level}) {
            set_pix_interface_level($router);
        }
        if ($managed eq 'local') {
            grep { $_->{bind_nat} } @{ $router->{interfaces} }
              and err_msg "Attribute 'bind_nat' is not allowed",
              " at interface of $name with 'managed = local'";
        }
        if ($model->{do_auth}) {

            grep { $_->{hub} } @{ $router->{interfaces} }
              or err_msg "Attribute 'hub' needs to be defined",
              "  at an interface of $name of model $model->{name}";

            # Don't support NAT for VPN, otherwise code generation for VPN
            # devices will become more difficult.
            grep { $_->{bind_nat} } @{ $router->{interfaces} }
              and err_msg "Attribute 'bind_nat' is not allowed",
              " at interface of $name of model $model->{name}";

            $router->{radius_attributes} ||= {};
        }
        else {
            $router->{radius_attributes}
              and err_msg "Attribute 'radius_attributes' is not allowed",
              " for $name";
        }
        if ($model->{no_crypto_filter}) {
            $router->{no_crypto_filter} = 1;
        }
    }

    # Unmanaged device.
    else {
        my $bridged;
        $router->{owner}
          and error_atline("Attribute 'owner' must only be used at",
                           " managed device");

        for my $interface (@{ $router->{interfaces} }) {
            if ($interface->{hub}) {
                error_atline("Interface with attribute 'hub' must only be",
                             " used at managed device");
            }
            if ($interface->{spoke}) {
                $router->{semi_managed} = 1;
            }
            if ($interface->{promiscuous_port}) {
                error_atline("Interface with attribute 'promiscuous_port'",
                             " must only be used at managed device");
            }
            if (delete $interface->{reroute_permit}) {
                warn_msg("Ignoring attribute 'reroute_permit'",
                         " at unmanaged $interface->{name}");
            }
            if ($interface->{ip} eq 'bridged') {
                $bridged = 1;
            }
        }

        # Unmanaged bridge would complicate generation of static routes.
        if ($bridged) {
            error_atline("Bridged interfaces must only be used",
                         " at managed device");
        }
    }

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
                $networks{$net_name} = new(
                    'Network',
                    name => $name,
                    ip   => $interface->{ip},
                    mask => 0xffffffff,

                    # Mark as automatically created.
                    loopback  => 1,
                    subnet_of => delete $interface->{subnet_of},
                    is_layer3 => $interface->{is_layer3},
                );
            }
            $interface->{network} = $net_name;
        }

        # Generate tunnel interface.
        elsif (my $crypto = $interface->{spoke}) {
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
                error_atline("Redefining $tunnel_intf->{name}");
            }
            $interfaces{$iname} = $tunnel_intf;
            push @{ $router->{interfaces} }, $tunnel_intf;

            # Create tunnel network.
            my $tunnel_net = new(
                'Network',
                name => "network:$net_name",
                ip   => 'tunnel'
            );
            $networks{$net_name} = $tunnel_net;

            # Tunnel network will later be attached to crypto hub.
            push @{ $crypto2spokes{$crypto} }, $tunnel_net;
        }
    }

    return $router;
}

our %aggregates;

sub read_aggregate {
    my $name = shift;
    my $aggregate = new('Network', name => $name, is_aggregate => 1);
    $aggregate->{private} = $private if $private;
    skip '=';
    skip '{';
    add_description($aggregate);
    while (1) {
        last if check '}';
        if (my ($ip, $mask) = check_assign 'ip', \&read_ip_opt_mask) {
            if (defined $mask) {
                defined $aggregate->{mask} 
                  and error_atline("Duplicate IP mask");
                $aggregate->{mask} = $mask;
            }
            $aggregate->{ip} and error_atline("Duplicate IP address");
            $aggregate->{ip} = $ip;
        }
        elsif (defined($mask = check_assign 'mask', \&read_mask)) {
            defined $aggregate->{mask} and error_atline("Duplicate IP mask");
            $aggregate->{mask} = $mask;
        }
        elsif (my $owner = check_assign 'owner', \&read_identifier) {
            $aggregate->{owner}
              and error_atline('Duplicate definition of owner');
            $aggregate->{owner} = $owner;
        }
        elsif (my $link = check_assign 'link', \&read_typed_name) {
            $aggregate->{link}
              and error_atline('Duplicate definition of link');
            $aggregate->{link} = $link;
        }
        elsif (check_flag 'has_unenforceable') {
            $aggregate->{has_unenforceable} = 1;
        }
        elsif (check_flag 'no_in_acl') {
            $aggregate->{no_in_acl} = 1;
        }
        else {
            syntax_err("Expected some valid attribute");
        }
    }
    $aggregate->{link} or err_msg("Attribute 'link' must be defined for $name");
    my $ip   = $aggregate->{ip};
    my $mask = $aggregate->{mask};
    if (defined $ip xor defined $mask) {
        defined $ip and syntax_err('Missing mask');
        defind $mask and syntax_err('Missing IP');
    }
    elsif (! defined $ip) {
        $aggregate->{ip} = $aggregate->{mask} = 0;
    }
    else {

        # Check if aggregate IP matches mask.
        if (not(match_ip($ip, $ip, $mask))) {
            error_atline("IP and mask don't match");
        }
    }
    if ($mask) {
        for my $key (keys %$aggregate) {
            next if grep { $key eq $_ } qw( name ip mask link is_aggregate);
            error_atline("Must not use attribute $key if mask is set");
        }
    }
    return $aggregate;
}

sub check_router_attributes {
    my $result = {};
    check 'router_attributes' or return;
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        if (my $owner = check_assign 'owner', \&read_identifier) {
            $result->{owner} and error_atline("Duplicate attribute 'owner'");
            $result->{owner} = $owner;
        }
        else {
            syntax_err("Unexpected attribute");
        }
    }
    return $result;
}

our %areas;

sub read_area {
    my $name = shift;
    my $area = new('Area', name => $name);
    skip '=';
    skip '{';
    add_description($area);
    while (1) {
        last if check '}';
        if (my @elements = check_assign_list 'border', \&read_intersection) {
            $area->{border}
              and error_atline('Duplicate definition of border');
            $area->{border} = \@elements;
        }
        elsif (check_flag 'auto_border') {
            $area->{auto_border} = 1;
        }
        elsif (my $pair = check_assign 'anchor', \&read_typed_name) {
            $area->{anchor} and error_atline("Duplicate attribute 'anchor'");
            $area->{anchor} = $pair;
        }
        elsif (my $owner = check_assign 'owner', \&read_identifier) {
            $area->{owner} and error_atline("Duplicate attribute 'owner'");
            $area->{owner} = $owner;
        }
        elsif (my $router_attributes = check_router_attributes()) {
            $area->{router_attributes}
              and error_atline("Duplicate attribute 'router_attributes'");
            $area->{router_attributes} = $router_attributes;
        }
        elsif (my $nat_name = check_nat_name()) {
            my $nat = read_nat("nat:$nat_name");
            defined $nat->{mask} or $nat->{hidden}
              or error_atline("Missing mask for $nat->{name}");
            $nat->{dynamic} or error_atline("$nat->{name} must be dynamic");
            $area->{nat}->{$nat_name}
              and error_atline("Duplicate NAT definition");
            $area->{nat}->{$nat_name} = $nat;
        }
        else {
            syntax_err("Expected some valid attribute");
        }
    }
    $area->{border}
      and $area->{anchor}
      and err_msg "Only one of attributes 'border' and 'anchor'",
      " may be defined for $name";
    $area->{anchor}
      or $area->{border}
      or err_msg "At least one of attributes 'border' and 'anchor'",
      " must be defined for $name";
    return $area;
}

our %groups;

sub read_group {
    my $name = shift;
    skip '=';
    my $group = new('Group', name => $name);
    $group->{private} = $private if $private;
    add_description($group);
    my @elements = read_list_or_null \&read_intersection;
    $group->{elements} = \@elements;
    return $group;
}

our %protocolgroups;

sub read_protocolgroup {
    my $name = shift;
    skip '=';
    my @pairs = read_list_or_null \&read_typed_name_or_simple_protocol;
    return new('Protocolgroup', name => $name, elements => \@pairs);
}

# Use this if src or dst port isn't defined.
# Don't allocate memory again and again.
my $aref_tcp_any = [ 1, 65535 ];

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
                return [ $port1, $port2 ];
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
        $prt->{src_range} = $range;
        $prt->{dst_range} = read_port_range;
    }
    else {
        $prt->{src_range} = $aref_tcp_any;
        $prt->{dst_range} = $range;
    }
    return;
}

sub read_icmp_type_code {
    my ($prt) = @_;
    if (defined(my $type = check_int)) {
        error_atline("Too large ICMP type $type") if $type > 255;
        if (check '/') {
            if (defined(my $code = check_int)) {
                error_atline("Too large ICMP code $code") if $code > 255;
                $prt->{type} = $type;
                $prt->{code} = $code;
            }
            else {
                syntax_err("Expected ICMP code");
            }
        }
        else {
            $prt->{type} = $type;
            if ($type == 0 || $type == 3 || $type == 11) {
                $prt->{flags}->{stateless_icmp} = 1;
            }
        }
    }
    else {

        # No type and code given.
    }
    return;
}

sub read_proto_nr {
    my ($prt) = @_;
    if (defined(my $nr = check_int)) {
        error_atline("Too large protocol number $nr") if $nr > 255;
        error_atline("Invalid protocol number '0'")   if $nr == 0;
        if ($nr == 1) {
            $prt->{proto} = 'icmp';

            # No ICMP type and code given.
        }
        elsif ($nr == 4) {
            $prt->{proto} = 'tcp';
            $prt->{src_range} = $prt->{dst_range} = $aref_tcp_any;
        }
        elsif ($nr == 17) {
            $prt->{proto} = 'udp';
            $prt->{src_range} = $prt->{dst_range} = $aref_tcp_any;
        }
        else {
            $prt->{proto} = $nr;
        }
    }
    else {
        syntax_err("Expected protocol number");
    }
    return;
}

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
        my $src_port = $port_name->(@{ $protocol->{src_range} });
        my $dst_port = $port_name->(@{ $protocol->{dst_range} });
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

our %protocols;

sub cache_anonymous_protocol {
    my ($protocol) = @_;
    my $name = gen_protocol_name($protocol);
    if (my $cached = $protocols{$name}) {
        return $cached;
    }
    else {
        $protocol->{name}    = $name;
        $protocol->{is_used} = 1;
        $protocols{$name}    = $protocol;
        return $protocol;
    }
}

sub read_simple_protocol {
    my $name     = shift;
    my $protocol = {};
    if (check 'ip') {
        $protocol->{proto} = 'ip';
    }
    elsif (check 'tcp') {
        $protocol->{proto} = 'tcp';
        read_port_ranges($protocol);
    }
    elsif (check 'udp') {
        $protocol->{proto} = 'udp';
        read_port_ranges $protocol;
    }
    elsif (check 'icmp') {
        $protocol->{proto} = 'icmp';
        read_icmp_type_code $protocol;
    }
    elsif (check 'proto') {
        read_proto_nr $protocol;
    }
    else {
        my $string = read_name;
        error_atline("Unknown protocol '$string'");
    }
    if ($name) {
        $protocol->{name} = $name;
    }
    else {
        $protocol = cache_anonymous_protocol($protocol);
    }
    return $protocol;
}

sub check_protocol_flags {
    my ($protocol) = @_;
    while (check ',') {
        my $flag = read_identifier;
        if ($flag =~ /^(src|dst)_(net|any)$/) {
            $protocol->{flags}->{$1}->{$2} = 1;
        }
        elsif ($flag =~
            /^(?:stateless|reversed|oneway|overlaps|no_check_supernet_rules)/)
        {
            $protocol->{flags}->{$flag} = 1;
        }
        else {
            syntax_err("Unknown flag '$flag'");
        }
    }
    return;
}

sub read_typed_name_or_simple_protocol {
    return (check_typed_name() || read_simple_protocol());
}

sub read_protocol {
    my $name = shift;
    skip '=';
    my $protocol = read_simple_protocol($name);
    check_protocol_flags($protocol);
    skip ';';
    return $protocol;
}

our %services;

sub assign_union_allow_user {
    my ($name) = @_;
    skip $name;
    skip '=';
    $user_object->{active}   = 1;
    $user_object->{refcount} = 0;
    my @result = read_union ';';
    $user_object->{active} = 0;
    return \@result, $user_object->{refcount};
}

sub read_service {
    my ($name) = @_;
    my $service = { name => $name, rules => [] };
    $service->{private} = $private if $private;
    skip '=';
    skip '{';
    add_description($service);
    while (1) {
        last if check 'user';
        if (my $sub_owner = check_assign 'sub_owner', \&read_identifier) {
            $service->{sub_owner}
              and error_atline("Duplicate attribute 'sub_owner'");
            $service->{sub_owner} = $sub_owner;
        }
        elsif (my @other = check_assign_list 'overlaps', \&read_typed_name) {
            $service->{overlaps}
              and error_atline("Duplicate attribute 'overlaps'");
            $service->{overlaps} = \@other;
        }
        elsif (my $visible = check_assign('visible', \&read_owner_pattern)) {
            $service->{visible}
              and error_atline("Duplicate attribute 'visible'");
            $service->{visible} = $visible;
        }
        elsif (check_flag('multi_owner')) {
            $service->{multi_owner} = 1;
        }
        elsif (check_flag('unknown_owner')) {
            $service->{unknown_owner} = 1;
        }
        elsif (check_flag('has_unenforceable')) {
            $service->{has_unenforceable} = 1;
        }
        elsif (check_flag('disabled')) {
            $service->{disabled} = 1;
        }
        else {
            syntax_err("Expected some valid attribute or definition of 'user'");
        }
    }

    # 'user' has already been read above.
    skip '=';
    if (check 'foreach') {
        $service->{foreach} = 1;
    }
    my @elements = read_list \&read_intersection;
    $service->{user} = \@elements;

    while (1) {
        last if check '}';
        if (my $action = check_permit_deny) {
            my ($src, $src_user) = assign_union_allow_user 'src';
            my ($dst, $dst_user) = assign_union_allow_user 'dst';
            my $prt = [
                    read_assign_list(
                        'prt', \&read_typed_name_or_simple_protocol
                    )
               ];
            $src_user
              or $dst_user
              or error_atline("Rule must use keyword 'user'");
            if ($service->{foreach} and not($src_user and $dst_user)) {
                warn_msg("Rule of $name should reference 'user'",
                         " in 'src' and 'dst'\n",
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
            push @{ $service->{rules} }, $rule;
        }
        else {
            syntax_err("Expected 'permit' or 'deny'");
        }
    }
    return $service;
}

our %global;

sub read_global {
    my ($name) = @_;
    skip '=';
    (my $action = $name) =~ s/^global://;
    $action eq 'permit' or error_atline("Unexpected name, use 'global:permit'");
    my $prt = [ read_list \&read_typed_name_or_simple_protocol ];
    return {
        name   => $name,
        action => $action,
        prt    => $prt
    };
}

our %pathrestrictions;

sub read_pathrestriction {
    my $name = shift;
    skip '=';
    my $restriction = new('Pathrestriction', name => $name);
    $restriction->{private} = $private if $private;
    add_description($restriction);
    my @elements = read_list \&read_intersection;
    $restriction->{elements} = \@elements;
    return $restriction;
}

sub read_attributed_object {
    my ($name, $attr_descr) = @_;
    my $object = { name => $name };
    skip '=';
    skip '{';
    add_description($object);
    while (1) {
        last if check '}';
        my $attribute = read_identifier;
        my $val_descr = $attr_descr->{$attribute}
          or syntax_err("Unknown attribute '$attribute'");
        skip '=';
        my $val;
        if (my $values = $val_descr->{values}) {
            $val = read_identifier;
            grep { $_ eq $val } @$values
              or syntax_err("Invalid value");
        }
        elsif (my $fun = $val_descr->{function}) {
            $val = &$fun;
        }
        else {
            internal_err();
        }
        skip ';';
        $object->{$attribute} and error_atline("Duplicate attribute");
        $object->{$attribute} = $val;
    }
    for my $attribute (keys %$attr_descr) {
        my $description = $attr_descr->{$attribute};
        unless (defined $object->{$attribute}) {
            if (my $default = $description->{default}) {
                $object->{$attribute} = $default;
            }
            else {
                error_atline("Missing '$attribute' for $object->{name}");
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
    identity      => { 
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
    hash           => { values   => [qw( md5 sha )], },
    group          => { values   => [qw( 1 2 5 )], },
    lifetime       => { function => \&read_time_val, },
    trust_point    => {
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
    key_exchange   => { function => \&read_typed_name, },
    esp_encryption => {
        values  => [qw( none aes aes192 aes256 des 3des )],
        default => 'none',
        map     => { none => undef }
    },
    esp_authentication => {
        values  => [qw( none md5_hmac sha_hmac )],
        default => 'none',
        map     => { none => undef }
    },
    ah => {
        values  => [qw( none md5_hmac sha_hmac )],
        default => 'none',
        map     => { none => undef }
    },
    pfs_group => {
        values  => [qw( none 1 2 5 )],
        default => 'none',
        map     => { none => undef }
    },
    lifetime => { function => \&read_time_val, },
);

our %ipsec;

sub read_ipsec {
    my ($name) = @_;
    return read_attributed_object $name, \%ipsec_attributes;
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
        last if check '}';
        if (check_flag 'tunnel_all') {
            $crypto->{tunnel_all} = 1;
        }
        elsif (check_flag 'detailed_crypto_acl') {
            $crypto->{detailed_crypto_acl} = 1;
        }
        elsif (my $type = check_assign 'type', \&read_typed_name) {
            $crypto->{type}
              and error_atline("Redefining 'type' attribute");
            $crypto->{type} = $type;
        }
        else {
            syntax_err("Expected valid attribute");
        }
    }
    $crypto->{type} or error_atline("Missing 'type' for $name");
    $crypto->{tunnel_all}
      or error_atline("Must define attribute 'tunnel_all' for $name");
    return $crypto;
}

our %owners;

sub read_owner {
    my $name = shift;
    my $owner = new('Owner', name => $name);
    skip '=';
    skip '{';
    add_description($owner);
    while (1) {
        last if check '}';
        if (my $alias = check_assign('alias', \&read_string)) {
            $owner->{alias}
              and error_atline("Redefining 'alias' attribute");
            $owner->{alias} = $alias;
        }
        elsif (my @admins = check_assign_list('admins', \&read_name)) {
            $owner->{admins}
              and error_atline("Redefining 'admins' attribute");
            $owner->{admins} = \@admins;
        }
        elsif (my @watchers = check_assign_list('watchers', \&read_name)) {
            if ($from_json->{watchers}) {
                error_atline("Watchers must only be defined",
                             " in JSON/ directory");
            }
            $owner->{watchers}
              and error_atline("Redefining 'watchers' attribute");
            $owner->{watchers} = \@watchers;
        }
        elsif (check_flag 'extend_only') {
            $owner->{extend_only} = 1;
        }
        elsif (check_flag 'extend') {
            $owner->{extend} = 1;
        }
        elsif (check_flag 'show_all') {
            $owner->{show_all} = 1;
        }
        else {
            syntax_err("Expected valid attribute");
        }
    }
    $owner->{admins} or error_atline("Missing attribute 'admins'");
    return $owner;
}

# For reading arbitrary names.
# Don't be greedy in regex, to prevent reading over multiple semicolons.
sub read_to_semicolon {
    skip_space_and_comment;
    if ($input =~ m/\G(.*?)(?=\s*;)/gco) {
        return $1;
    }
    else {
        syntax_err("Expected string ending with semicolon!");
    }
}

my %global_type = (
    router          => [ \&read_router,          \%routers ],
    network         => [ \&read_network,         \%networks ],
    any             => [ \&read_aggregate,       \%aggregates ],
    area            => [ \&read_area,            \%areas ],
    owner           => [ \&read_owner,           \%owners ],
    group           => [ \&read_group,           \%groups ],
    protocol        => [ \&read_protocol,        \%protocols ],
    protocolgroup   => [ \&read_protocolgroup,   \%protocolgroups ],
    service         => [ \&read_service,         \%services ],
    global          => [ \&read_global,          \%global ],
    pathrestriction => [ \&read_pathrestriction, \%pathrestrictions ],
    isakmp          => [ \&read_isakmp,          \%isakmp ],
    ipsec           => [ \&read_ipsec,           \%ipsec ],
    crypto          => [ \&read_crypto,          \%crypto ],
);

sub read_netspoc {

    # Check for global definitions.
    my $pair = check_typed_name or syntax_err('');
    my ($type, $name) = @$pair;
    my $descr = $global_type{$type}
      or syntax_err("Unknown global definition");
    my ($fun, $hash) = @$descr;
    my $result = $fun->("$type:$name");
    $result->{file} = $current_file;
    if ($hash->{$name}) {
        error_atline("Redefining $type:$name");
    }

    # Result is not used in this module but can be useful
    # when this function is called from outside.
    return $hash->{$name} = $result;
}

# Read input from file and process it by function which is given as argument.
sub read_file {
    local $current_file = shift;
    my $read_syntax = shift;

    # Read file as one large line.
    local $/;
    local $input;

    if (defined $current_file) {
        open(my $fh, '<', $current_file) 
          or fatal_err("Can't open $current_file: $!");

        # Fill buffer with content of whole file.
        # Content is implicitly freed when subroutine is left.
        $input = <$fh>;
        close $fh;
    }
    else {
        $current_file = 'STDIN';
        $input = <>;
    }
    local $line = 1;
    my $length = length $input;
    while (skip_space_and_comment, pos $input != $length) {
        &$read_syntax;
    }
    return;
}

# Try to read file 'config' in toplevel directory $path.
sub read_config {
    my ($path) = @_;
    my %result;
    my $read_config_data = sub {
        my $key = read_identifier();
        valid_config_key($key) or syntax_err("Invalid keyword");
        skip('=');
        my $val = read_identifier;
        if (my $expected = check_config_pair($key, $val)) {
            syntax_err("Expected value matching '$expected'");
        }
        skip(';');
        $result{$key} = $val;
    };

    if (defined $path && -d $path) {
        opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
        if (grep { $_ eq 'config' } readdir $dh) {
            $path = "$path/config";
            read_file $path, $read_config_data;
        }
        closedir $dh;
    }
    return \%result;
}

sub read_json_watchers {
    my ($path) = @_;
    opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
    my @files = map({ Encode::decode($filename_encode, $_) } readdir $dh);
    closedir $dh;
    for my $owner_name (@files) {
        next if $owner_name eq '.' or $owner_name eq '..';
        next if $owner_name =~ m/$config{ignore_files}/o;
        my $path = "$path/$owner_name";
        opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
        my @files = map({ Encode::decode($filename_encode, $_) } readdir $dh);
        closedir $dh;
        for my $file (@files) {
            next if $file eq '.' or $file eq '..';
            next if $file =~ m/$config{ignore_files}/o;
            my $path = "$path/$file";
            if ($file ne 'watchers') {
                err_msg("Ignoring $path");
                next;
            }
            open (my $fh, '<', $path) or fatal_err("Can't open $path");
            my $data;
            {
                local $/ = undef;
                $data = from_json( <$fh> );
            }
            close($fh);
            my $owner = $owners{$owner_name};
            if (! $owner) {
                err_msg("Referencing unknown owner:$owner_name in $path");
                next;
            }
            $owner->{watchers} and 
                err_msg("Redefinig watcher of owner:$owner_name from $path");
            $owner->{watchers} = $data;
        }
    }
    return;
}
       
sub read_json {
    my ($path) = @_;
    opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
    my @files = map({ Encode::decode($filename_encode, $_) } readdir $dh);
    closedir $dh;
    for my $file (@files) {
        next if $file eq '.' or $file eq '..';
        next if $file =~ m/$config{ignore_files}/o;
        my $path = "$path/$file";
        if ($file ne 'owner') {
            err_msg("Ignoring $path");
            next;
        }
        read_json_watchers($path);
    }
    return;
}

sub read_file_or_dir {
    my ($path, $read_syntax) = @_;
    $read_syntax ||= \&read_netspoc;

    # Handle toplevel file.
    if (!(defined $path && -d $path)) {
        read_file($path, $read_syntax);
        return;
    }

    # Recursively handle non toplevel files and directories.
    # No special handling for "config", "raw" and "*.private".
    my $read_nested_files;
    $read_nested_files = sub {
        my ($path, $read_syntax) = @_;
        if (-d $path) {
            opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
            while (my $file = Encode::decode($filename_encode, readdir $dh)) {
                next if $file eq '.' or $file eq '..';
                next if $file =~ m/$config{ignore_files}/o;
                my $path = "$path/$file";
                $read_nested_files->($path, $read_syntax);
            }
            closedir $dh;
        }
        else {
            read_file $path, $read_syntax;
        }
    };

    # Handle toplevel directory.
    # Special handling for "config", "raw", "JSON" and "*.private".
    opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
    my @files = map({ Encode::decode($filename_encode, $_) } readdir $dh);
    closedir $dh;

    if (grep { $_ eq 'JSON' } @files) {
        $can_json or 
            fatal_err("JSON module must be installed to read $path/JSON");
        $from_json = { JSON => 1 };
        if (-e "$path/JSON/owner") {
            $from_json->{watchers} = 1;
        }
    }
        
    for my $file (@files) {

        next if $file eq '.' or $file eq '..';
        next if $file =~ m/$config{ignore_files}/o;

        # Ignore special files/directories.
        next if $file =~ /^(config|raw|JSON)$/;

        my $path = "$path/$file";

        # Handle private directories and files.
        if ($file =~ m'([^/]*)\.private$') {
            local $private = $1;
            $read_nested_files->($path, $read_syntax);
        }

        # Handle standard directories and files.
        else {
            $read_nested_files->($path, $read_syntax);
        }
    }
    if (keys %$from_json) {
        read_json("$path/JSON");
    }
    return;
}

sub show_read_statistics {
    my $n  = keys %networks;
    my $h  = keys %hosts;
    my $r  = keys %routers;
    my $g  = keys %groups;
    my $s  = keys %protocols;
    my $sg = keys %protocolgroups;
    my $p  = keys %services;
    info("Read $r routers, $n networks, $h hosts");
    info("Read $p services, $g groups, $s protocols, $sg protocol groups");
    return;
}

## no critic (RequireArgUnpacking RequireFinalReturn)

# Type checking functions
sub is_network       { ref($_[0]) eq 'Network'; }
sub is_router        { ref($_[0]) eq 'Router'; }
sub is_interface     { ref($_[0]) eq 'Interface'; }
sub is_host          { ref($_[0]) eq 'Host'; }
sub is_subnet        { ref($_[0]) eq 'Subnet'; }
sub is_area          { ref($_[0]) eq 'Area'; }
sub is_zone          { ref($_[0]) eq 'Zone'; }
sub is_group         { ref($_[0]) eq 'Group'; }
sub is_protocolgroup { ref($_[0]) eq 'Protocolgroup'; }
sub is_objectgroup   { ref($_[0]) eq 'Objectgroup'; }
sub is_chain         { ref($_[0]) eq 'Chain'; }
sub is_autointerface { ref($_[0]) eq 'Autointerface'; }

## use critic

sub print_rule {
    my ($rule) = @_;
    my $extra = '';
    my $service = $rule->{rule} && $rule->{rule}->{service};
    $extra .= " $rule->{for_router}" if $rule->{for_router};
    $extra .= " stateless"           if $rule->{stateless};
    $extra .= " stateless_icmp"      if $rule->{stateless_icmp};
    $extra .= " of $service->{name}" if $service;
    my $prt = exists $rule->{orig_prt} ? 'orig_prt' : 'prt';
    my $action = $rule->{action};
    $action = $action->{name} if is_chain($action);
    return
        $action
      . " src=$rule->{src}->{name}; dst=$rule->{dst}->{name}; "
      . "prt=$rule->{$prt}->{name};$extra";
}

##############################################################################
# Order protocols
##############################################################################
my %prt_hash;

sub prepare_prt_ordering {
    my ($prt) = @_;
    my $proto = $prt->{proto};
    my $main_prt;
    if ($proto eq 'tcp' or $proto eq 'udp') {

        # Convert src and dst port ranges from arrays to real protocol objects.
        # This is used in function expand_rules: An unexpanded rule has
        # references to TCP and UDP protocols with combined src and dst port
        # ranges.  An expanded rule has distinct references to src and dst
        # protocols with a single port range.
        for my $where ('src_range', 'dst_range') {

            # An array with low and high port.
            my $range     = $prt->{$where};
            my $key       = join ':', @$range;
            my $range_prt = $prt_hash{$proto}->{$key};
            unless ($range_prt) {
                $range_prt = {
                    name  => $prt->{name},
                    proto => $proto,
                    range => $range
                };
                $prt_hash{$proto}->{$key} = $range_prt;
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
        # protocol in one step via ->{main}.  This is used later to substitute
        # occurrences of $prt with $main_prt.
        $prt->{main} = $main_prt;
    }
    return;
}

sub order_icmp {
    my ($hash, $up) = @_;

    # Handle 'icmp any'.
    if (my $prt = $hash->{''}) {
        $prt->{up} = $up;
        $up = $prt;
    }
    for my $prt (values %$hash) {

        # 'icmp any' has been handled above.
        next unless defined $prt->{type};
        if (defined $prt->{code}) {
            $prt->{up} = ($hash->{ $prt->{type} } or $up);
        }
        else {
            $prt->{up} = $up;
        }
    }
    return;
}

sub order_proto {
    my ($hash, $up) = @_;
    for my $prt (values %$hash) {
        $prt->{up} = $up;
    }
    return;
}

# Link each port range with the smallest port range which includes it.
# If no including range is found, link it with the next larger protocol.
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

    $check_subrange = sub  {
        my ($a, $a1, $a2, $i) = @_;
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

#           debug("$b->{name} [$b1-$b2] < $a->{name} [$a1-$a2]");
                $i = $check_subrange->($b, $b1, $b2, $i + 1);

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

#        debug("$b->{name} [$b1-$b2] split into [$x1-$x2] and [$y1-$y2]");
            my $find_or_insert_range = sub {
                my ($a1, $a2, $i, $orig, $prefix) = @_;
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

#                    debug("Splitted range is already defined: $b->{name}");
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
                my $new = {
                    name  => "$prefix$orig->{name}",
                    proto => $orig->{proto},
                    range => [ $a1, $a2 ],

                    # Mark for range optimization.
                    has_neighbor => 1
                };

                # Insert new range at position $i.
                splice @sorted, $i, 0, $new;
                return $new;
            };
            my $left  = $find_or_insert_range->($x1, $x2, $i + 1, $b, 'lpart_');
            my $rigth = $find_or_insert_range->($y1, $y2, $i + 1, $b, 'rpart_');
            $b->{split} = [ $left, $rigth ];

            # Continue processing with next element.
            $i++;
        }
    };

    # Array wont be empty because $prt_tcp and $prt_udp are defined internally.
    @sorted or internal_err("Unexpected empty array");

    my $a = $sorted[0];
    $a->{up} = $up;
    my ($a1, $a2) = @{ $a->{range} };

    # Ranges "TCP any" and "UDP any" 1..65535 are defined internally,
    # they include all other ranges.
    $a1 == 1 and $a2 == 65535
      or internal_err("Expected $a->{name} to have range 1..65535");

    # There can't be any port which isn't included by ranges "TCP any"
    # or "UDP any".
    $check_subrange->($a, $a1, $a2, 1) and internal_err();
    return;
}

sub expand_splitted_protocols  {
    my ($prt) = @_;
    if (my $split = $prt->{split}) {
        my ($prt1, $prt2) = @$split;
        return (expand_splitted_protocols($prt1), 
                expand_splitted_protocols($prt2));
    }
    else {
        return $prt;
    }
}

# Protocol 'ip' is needed later for implementing secondary rules and
# automatically generated deny rules.
my $prt_ip = { name => 'auto_prt:ip', proto => 'ip' };

# Protocol 'ICMP any', needed in optimization of chains for iptables.
my $prt_icmp = {
    name  => 'auto_prt:icmp',
    proto => 'icmp'
};

# Protocol 'TCP any'.
my $prt_tcp = {
    name      => 'auto_prt:tcp',
    proto     => 'tcp',
    src_range => $aref_tcp_any,
    dst_range => $aref_tcp_any
};

# Protocol 'UDP any'.
my $prt_udp = {
    name      => 'auto_prt:udp',
    proto     => 'udp',
    src_range => $aref_tcp_any,
    dst_range => $aref_tcp_any
};

# IPSec: Internet key exchange.
# Source and destination port (range) is set to 500.
my $prt_ike = {
    name      => 'auto_prt:IPSec_IKE',
    proto     => 'udp',
    src_range => [ 500, 500 ],
    dst_range => [ 500, 500 ]
};

# IPSec: NAT traversal.
my $prt_natt = {
    name      => 'auto_prt:IPSec_NATT',
    proto     => 'udp',
    src_range => [ 4500, 4500 ],
    dst_range => [ 4500, 4500 ]
};

# IPSec: encryption security payload.
my $prt_esp = { name => 'auto_prt:IPSec_ESP', proto => 50, prio => 100, };

# IPSec: authentication header.
my $prt_ah = { name => 'auto_prt:IPSec_AH', proto => 51, prio => 99, };

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
        $prt_ip,  $prt_icmp, $prt_tcp,
        $prt_udp, $prt_ike,  $prt_natt,
        $prt_esp, $prt_ah,   values %protocols
      )
    {
        prepare_prt_ordering $prt;
    }
    my $up = $prt_ip;

    # This is guaranteed to be defined, because $prt_tcp has been processed
    # already.
    $range_tcp_any         = $prt_hash{tcp}->{'1:65535'};
    $range_tcp_established = {
        %$range_tcp_any,
        name        => 'reverse:TCP_ANY',
        established => 1
    };
    $range_tcp_established->{up} = $range_tcp_any;

    order_ranges($prt_hash{tcp}, $up);
    order_ranges($prt_hash{udp}, $up);
    order_icmp($prt_hash{icmp}, $up) if $prt_hash{icmp};
    order_proto($prt_hash{proto}, $up) if $prt_hash{proto};
    return;
}

# Used in expand_protocols.
sub set_src_dst_range_list  {
    my ($prt) = @_;
    return if $prt->{src_dst_range_list};
    $prt = $prt->{main} if $prt->{main};
    my $proto = $prt->{proto};
    if ($proto eq 'tcp' or $proto eq 'udp') {
        my @src_dst_range_list;
        for my $src_range (expand_splitted_protocols $prt->{src_range}) {
            for my $dst_range (expand_splitted_protocols $prt->{dst_range}) {
                push @src_dst_range_list, [ $src_range, $dst_range ];
            }
        }
        $prt->{src_dst_range_list} = \@src_dst_range_list;
    }
    else {
        $prt->{src_dst_range_list} = [ [ $prt_ip, $prt ] ];
    }
    return;
}

####################################################################
# Link topology elements each with another
####################################################################

sub expand_group;

sub link_to_owner {
    my ($obj, $key) = @_;
    $key ||= 'owner';
    if (my $value = $obj->{$key}) {
        if (my $owner = $owners{$value}) {
            $obj->{$key} = $owner;
        }
        else {
            err_msg "Can't resolve reference to '$value'",
              " in attribute 'owner' of $obj->{name}";
            delete $obj->{$key};
        }
    }
    return;
}

sub link_owners {

    my %alias2owner;

    # Use sort to get deterministic error messages.
    for my $name (sort keys %owners) {
        my $owner = $owners{$name};

        # Check for unique alias names.
        my $alias = $owner->{alias} || $name;
        if (my $other = $alias2owner{$alias}) {
            my $descr1 = $owner->{name};
            $owner->{alias} and $descr1 .= " with alias '$owner->{alias}'";
            my $descr2 = $other->{name};
            $other->{alias} and $descr2 .= " with alias '$other->{alias}'";
            err_msg("Name conflict between owners\n - $descr1\n - $descr2");
        }
        else {
            $alias2owner{$alias} = $owner;
        }

        # Check email addresses in admins and watchers.
        for my $attr (qw( admins watchers )) {
            for my $email (@{ $owner->{$attr} }) {

                # Check email syntax.
                # Only 7 bit ASCII
                # Local part definition from wikipedia, 
                # without space and other quoted characters
                do {
                    use bytes;
                    $email =~ 
                        m/^ [\w.!\#$%&''*+\/=?^_``{|}~-]+ \@ [\w.-]+ $/x ||
                        $email eq 'guest';
                }
                or err_msg("Invalid email address (ASCII only)",
                           " in $attr of $owner->{name}: $email");

                # Normalize email to lower case.
                $email = lc($email);
            }
        }

        # Check for duplicate email addresses
        # in admins, watchers and between admins and watchers.
        if (find_duplicates(@{ $owner->{admins} }, @{ $owner->{watchers} })) {
            for my $attr (qw(admins watchers)) {
                if (my @emails = find_duplicates(@{ $owner->{$attr} })) {
                    $owner->{$attr} = [ unique(@{ $owner->{$attr} }) ];
                    err_msg("Duplicates in $attr of $owner->{name}: ", 
                              join(', ', @emails));
                }
            }
            if (my @duplicates =
                find_duplicates(@{ $owner->{admins} }, @{ $owner->{watchers} }))
            {
                err_msg("Duplicates in admins/watchers of $owner->{name}: ", 
                          join(', ', @duplicates));
            }
        }
    }
    for my $network (values %networks) {
        link_to_owner($network);
        for my $host (@{ $network->{hosts} }) {
            link_to_owner($host);
        }
    }
    for my $aggregate (values %aggregates) {
        link_to_owner($aggregate);
    }
    for my $area (values %areas) {
        link_to_owner($area);
        if (my $router_attributes = $area->{router_attributes}) {
            link_to_owner($router_attributes);
        }
    }
    for my $router (values %routers) {
        link_to_owner($router);
    }
    for my $service (values %services) {
        link_to_owner($service, 'sub_owner');
    }
    return;
}

# Link areas with referenced interfaces or network.
sub link_areas {
    for my $area (values %areas) {
        if ($area->{anchor}) {
            my @elements =
              @{ expand_group([ $area->{anchor} ], $area->{name}) };
            if (@elements == 1) {
                my $obj = $elements[0];
                if (is_network $obj) {
                    $area->{anchor} = $obj;
                }
                else {
                    err_msg
                      "Unexpected $obj->{name} in anchor of $area->{name}";

                    # Prevent further errors.
                    delete $area->{anchor};
                }
            }
            else {
                err_msg
                  "Expected exactly one element in anchor of $area->{name}";
                delete $area->{anchor};
            }

        }
        else {
            $area->{border} = expand_group $area->{border}, $area->{name};
            for my $obj (@{ $area->{border} }) {
                if (is_interface $obj) {
                    my $router = $obj->{router};
                    $router->{managed}
                      or err_msg "Referencing unmanaged $obj->{name} ",
                      "from $area->{name}";

                    # Reverse swapped main and virtual interface.
                    if (my $main_interface = $obj->{main_interface}) {
                        $obj = $main_interface;
                    }
                }
                else {
                    err_msg
                      "Unexpected $obj->{name} in border of $area->{name}";

                    # Prevent further errors.
                    delete $area->{border};
                }
            }
        }
    }
    return;
}

# Link interfaces with networks in both directions.
sub link_interfaces1 {
    my ($router) = @_;
    for my $interface (@{ $router->{interfaces} }) {
        my $net_name = $interface->{network};
        my $network  = $networks{$net_name};

        unless ($network) {
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
            if (my $private2 = $interface->{private}) {
                $private1 eq $private2
                  or err_msg("$private2.private $interface->{name} must not",
                             " be connected to $private1.private",
                             " $network->{name}");
            }
            else {
                err_msg("Public $interface->{name} must not be connected to",
                        " $private1.private $network->{name}");
            }
        }

        # Public network may connect to private interface.
        # The owner of a private context can prevent a public network from
        # connecting to a private interface by simply connecting an own private
        # network to the private interface.

        push @{ $network->{interfaces} }, $interface;
        check_interface_ip($interface, $network);
    }
    return;
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
        err_msg("$interface->{name} must not be linked ",
                "to unnumbered $network->{name}");
    }
    elsif ($ip eq 'negotiated') {
        my $network_mask = $network->{mask};

        # Negotiated interfaces are dangerous: If the attached
        # network has address 0.0.0.0/0, we would accidentally
        # permit 'any'.  We allow this only, if local networks are
        # protected by crypto.
        if ($network_mask == 0 && !$interface->{spoke}) {
            err_msg("$interface->{name} has negotiated IP",
                    " in range 0.0.0.0/0.\n",
                    " This is only allowed for interface",
                    " protected by crypto spoke");
        }
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
        if ($mask == 0xffffffff) {
            if (not $network->{loopback}) {
                warn_msg("$interface->{name} has address of its network.\n",
                         " Remove definition of $network->{name}.\n",
                         " Add attribute 'loopback' at",
                         " interface definition.");
            }
        }
        else {
            if ($ip == $network_ip) {
                err_msg("$interface->{name} has address of its network");
            }
            my $broadcast = $network_ip + complement_32bit $mask;
            if ($ip == $broadcast) {
                err_msg("$interface->{name} has broadcast address");
            }
        }
    }
    return;
}

# Iterate of all interfaces of all routers.
# Don't use values %interfaces because we want to traverse the interfaces
# in a deterministic order.
sub link_interfaces {
    for my $name (sort keys %routers) {
        link_interfaces1($routers{$name});
    }
    return;
}

sub link_subnet  {
    my ($object, $parent) = @_;

    my $context = sub {
        !$parent        ? $object->{name}
          : ref $parent ? "$object->{name} of $parent->{name}"
          :               "$parent $object->{name}";
    };
    return if not $object->{subnet_of};
    my ($type, $name) = @{ $object->{subnet_of} };
    if ($type ne 'network') {
        err_msg "Attribute 'subnet_of' of ", $context->(), "\n",
          " must not be linked to $type:$name";

        # Prevent further errors;
        delete $object->{subnet_of};
        return;
    }
    my $network = $networks{$name};
    if (not $network) {
        warn_msg("Ignoring undefined network:$name",
                 " from attribute 'subnet_of'\n of ", $context->());

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
        err_msg "Unnumbered $network->{name} must not be referenced from",
          " attribute 'subnet_of'\n of ", $context->();

        # Prevent further errors;
        delete $object->{subnet_of};
        return;
    }

    # $sub_mask needs not to be tested here,
    # because it has already been checked for $object.
    if (not(match_ip($sub_ip, $ip, $mask))) {
        err_msg $context->(), " is subnet_of $network->{name}",
          " but its IP doesn't match that's IP/mask";
    }

    # Used to check for overlaps with hosts or interfaces of $network.
    push @{ $network->{own_subnets} }, $object;
    return;
}

sub link_subnets  {
    for my $network (values %networks) {
        link_subnet $network, undef;
        for my $nat (values %{ $network->{nat} }) {
            link_subnet($nat, $network);
        }
    }
    for my $area (values %areas) {
        for my $nat (values %{ $area->{nat} }) {
            link_subnet($nat, $area);
        }
    }
    return;
}

sub link_pathrestrictions {
    for my $restrict (values %pathrestrictions) {
        $restrict->{elements} = expand_group $restrict->{elements},
          $restrict->{name};
        my $changed;
        my $private = my $no_private = $restrict->{private};
        for my $obj (@{ $restrict->{elements} }) {
            if (not is_interface($obj)) {
                err_msg("$restrict->{name} must not reference $obj->{name}");
                $obj     = undef;
                $changed = 1;
                next;
            }

            # Add pathrestriction to interface.
            # Multiple restrictions may be applied to a single
            # interface.
            push @{ $obj->{path_restrict} }, $restrict;

            # Unmanaged router with pathrestriction is handled special.
            # It is separating zones, but gets no code.
            my $router = $obj->{router};
            $router->{managed} or $router->{semi_managed} = 1;

            # Pathrestrictions must not be applied to secondary interfaces
            $obj->{main_interface}
              and err_msg "secondary $obj->{name} must not be used",
              " in pathrestriction";

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
                      " $obj_p.private $obj->{name}";
                }
            }
        }
        if ($no_private) {
            err_msg "$private.private $restrict->{name} must reference",
              " at least one interface out of $private.private";
        }
        if ($changed) {
            $restrict->{elements} = [ grep { $_ } @{ $restrict->{elements} } ];
        }
        my $count = @{ $restrict->{elements} };
        if ($count == 1) {
            warn_msg("Ignoring $restrict->{name} with only",
                     " $restrict->{elements}->[0]->{name}");
        }
        elsif ($count == 0) {
            warn_msg("Ignoring $restrict->{name} without elements");
        }

        # Add pathrestriction to tunnel interfaces,
        # which belong to real interface.
        # Don't count them as extra elements.
        for my $interface (@{ $restrict->{elements} }) {
            next if not($interface->{spoke} or $interface->{hub});

            # Don't add for no_check interface because traffic would
            # pass the pathrestriction two times.
            next if $interface->{no_check};
            my $router = $interface->{router};
            for my $intf (@{ $router->{interfaces} }) {
                my $real_intf = $intf->{real_interface};
                next if not $real_intf;
                next if not $real_intf eq $interface;

#               debug("Adding $restrict->{name} to $intf->{name}");
                push @{ $restrict->{elements} },  $intf;
                push @{ $intf->{path_restrict} }, $restrict;
            }
        }
    }
    return;
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
sub link_virtual_interfaces  {

    # Collect array of virtual interfaces with same IP at same network.
    my %net2ip2virtual;

    # Hash table to look up first virtual interface of a group
    # inside the same network and using the same ID and type.
    my %net2id2type2virtual;
    for my $virtual1 (@virtual_interfaces) {
        my $ip    = $virtual1->{ip};
        my $net   = $virtual1->{network};
        my $type1 = $virtual1->{redundancy_type} || '';
        my $id1   = $virtual1->{redundancy_id} || '';
        if (my $interfaces = $net2ip2virtual{$net}->{$ip}) {
            my $virtual2 = $interfaces->[0];
            my $type2 = $virtual2->{redundancy_type} || '';
            if ($type1 ne $type2) {
                err_msg "Virtual IP: $virtual1->{name} and $virtual2->{name}",
                  " use different redundancy protocols";
                next;
            }
            if (not $id1 eq ($virtual2->{redundancy_id} || '')) {
                err_msg "Virtual IP: $virtual1->{name} and $virtual2->{name}",
                  " use different ID";
                next;
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
                if (my $virtual2 = 
                    $net2id2type2virtual{$net}->{$id1}->{$type1}) 
                {
                    err_msg "Virtual IP:",
                      " Unrelated $virtual1->{name} and $virtual2->{name}",
                      " use identical ID";
                }
                else {
                    $net2id2type2virtual{$net}->{$id1}->{$type1} = $virtual1;
                }
            }
        }
    }
    for my $href (values %net2ip2virtual) {
        for my $interfaces (values %$href) {

            # A virtual interface is used as hop for static routing.
            # Therefore a network behind this interface must be reachable
            # via all virtual interfaces of the group.
            # This can only be guaranteed, if pathrestrictions are identical
            # on all interfaces.
            # Exception in routing code:
            # If the group has ony two interfaces, the one or other
            # physical interface can be used as hop.
            if (   @$interfaces >= 3
                && grep { $_->{path_restrict} } 
                   map { @{ $_->{router}->{interfaces} } } @$interfaces)
            {
                err_msg("Pathrestriction not supported for",
                        " group of 3 or more virtual interfaces\n ",
                        join(',', map { $_->{name} } @$interfaces));
            }

            # Automatically add pathrestriction to interfaces
            # belonging to $net2ip2virtual, if at least one interface
            # is managed.
            # Pathrestriction would be useless if all devices are unmanaged.
            elsif (grep { $_->{router}->{managed} } @$interfaces) {
                my $name = "auto-virtual-" . print_ip $interfaces->[0]->{ip};
                my $restrict = new('Pathrestriction', name => $name);
                for my $interface (@$interfaces) {

#                   debug("pathrestriction $name at $interface->{name}");
                    push @{ $interface->{path_restrict} }, $restrict;
                    my $router = $interface->{router};
                    $router->{managed} or $router->{semi_managed} = 1;
                }
            }
        }
    }
    return;
}

sub check_ip_addresses {
    for my $network (values %networks) {
        if (    $network->{ip} eq 'unnumbered'
            and $network->{interfaces}
            and @{ $network->{interfaces} } > 2)
        {
            my $msg = "Unnumbered $network->{name} is connected to"
              . " more than two interfaces:";
            for my $interface (@{ $network->{interfaces} }) {
                $msg .= "\n $interface->{name}";
            }
            err_msg($msg);
        }

        my %ip;

        # 1. Check for duplicate interface addresses.
        # 2. Short interfaces must not be used, if a managed interface
        #    with static routing exists in the same network.
        my ($short_intf, $route_intf);
        for my $interface (@{ $network->{interfaces} }) {
            my $ip = $interface->{ip};
            if ($ip eq 'short') {

                # Ignore short interface with globally active pathrestriction
                # where all traffic goes through a VPN tunnel.
                if (! check_global_active_pathrestriction($interface)) {
                    $short_intf = $interface;
                }
            }
            else {
                unless ($ip =~ /^(?:unnumbered|negotiated|tunnel)$/) {
                    if ($interface->{router}->{managed}
                        and not $interface->{routing})
                    {
                        $route_intf = $interface;
                    }
                    if (my $old_intf = $ip{$ip}) {
                        unless ($old_intf->{redundant}
                            and $interface->{redundant})
                        {
                            err_msg "Duplicate IP address for",
                              " $old_intf->{name} and $interface->{name}";
                        }
                    }
                    else {
                        $ip{$ip} = $interface;
                    }
                }
            }
            if ($short_intf and $route_intf) {
                err_msg "$short_intf->{name} must be defined in more detail,",
                  " since there is\n",
                  " a managed $route_intf->{name} with static routing enabled.";
            }
        }
        my %range;
        for my $host (@{ $network->{hosts} }) {
            if (my $ip = $host->{ip}) {
                if (my $other_device = $ip{$ip}) {
                    err_msg "Duplicate IP address for $other_device->{name}",
                      " and $host->{name}";
                }
                else {
                    $ip{$ip} = $host;
                }
            }
            elsif (my $range = $host->{range}) {
                my ($from, $to) = @$range;
                if (my $other_device = $range{$from}->{$to}) {
                    err_msg "Duplicate IP range for $other_device->{name}",
                      " and $host->{name}";
                }
                else {
                    $range{$from}->{$to} = $host;
                }
            }
        }
        for my $host (@{ $network->{hosts} }) {
            if (my $range = $host->{range}) {
                for (my $ip = $range->[0] ; $ip <= $range->[1] ; $ip++) {
                    if (my $other_device = $ip{$ip}) {
                        is_host($other_device)
                          or err_msg("Duplicate IP address for",
                                     " $other_device->{name}",
                                     " and $host->{name}");
                    }
                }
            }
        }
    }
    return;
}

sub link_ipsec;
sub link_crypto;
sub link_tunnels;

sub link_topology {
    progress('Linking topology');
    link_interfaces;
    link_ipsec;
    link_crypto;
    link_tunnels;
    link_pathrestrictions;
    link_virtual_interfaces;
    link_areas;
    link_subnets;
    link_owners;
    check_ip_addresses();
    return;
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
    return;
}

# Lists of network objects which are left over after disabling.
#my @managed_routers;	# defined above
my @managed_vpnhub;
my @routers;
my @networks;
my @zones;
my @areas;

# Transform topology for networks with isolated ports.
# If a network has attribute 'isolated_ports',
# hosts inside this network are not allowed to talk directly to each other.
# Instead the traffic must go through an interface which is marked as
# 'promiscuous_port'.
# To achieve the desired traffic flow, we transform the topology such
# that each host is moved to a separate /32 network.
# Non promiscuous interfaces are isolated as well. They are handled like hosts
# and get a separate network too.
sub transform_isolated_ports {
  NETWORK:
    for my $network (@networks) {
        if (not $network->{isolated_ports}) {
            for my $interface (@{ $network->{interfaces} }) {
                $interface->{promiscuous_port}
                  and warn_msg("Useless 'promiscuous_port' at",
                               " $interface->{name}");
            }
            next;
        }
        $network->{ip} eq 'unnumbered' and internal_err();
        my @promiscuous_ports;
        my @isolated_interfaces;
        my @secondary_isolated;
        for my $interface (@{ $network->{interfaces} }) {
            if ($interface->{promiscuous_port}) {
                push @promiscuous_ports, $interface;
            }
            elsif ($interface->{redundant}) {
                err_msg
                  "Redundant $interface->{name} must not be isolated port";
            }
            elsif ($interface->{main_interface}) {
                push @secondary_isolated, $interface
                  if not $interface->{main_interface}->{promiscuous_port};
            }
            else {
                push @isolated_interfaces, $interface;
            }
        }

        if (not @promiscuous_ports) {
            err_msg("Missing 'promiscuous_port' for $network->{name}",
                " with 'isolated_ports'");

            # Abort transformation.
            next NETWORK;
        }
        elsif (@promiscuous_ports > 1) {
            equal(map { $_->{redundancy_interfaces} || 0 } @promiscuous_ports)
              or err_msg "All 'promiscuous_port's of $network->{name}",
              " need to be redundant to each other";
        }
        $network->{hosts}
          or @isolated_interfaces
          or warn_msg("Useless attribute 'isolated_ports' at $network->{name}");

        for my $obj (@{ $network->{hosts} }, @isolated_interfaces) {
            my $ip = $obj->{ip};

            # Add separate network for each isolated host or interface.
            my $obj_name = $obj->{name};
            my $new_net  = new(
                'Network',

                # Take name of $obj for artificial network.
                name      => $obj_name,
                ip        => $ip,
                mask      => 0xffffffff,
                subnet_of => $network,
                isolated  => 1,
            );
            if (is_host($obj)) {
                $new_net->{hosts} = [$obj];
            }
            else {

                #  Don't use unnumbered, negotiated, tunnel interfaces.
                $ip =~ /^\w/ or internal_err();
                $new_net->{interfaces} = [$obj];
                $obj->{network}        = $new_net;
            }

            push @{ $network->{own_subnets} }, $new_net;
            push @networks, $new_net;

            # Copy promiscuous interface(s) and use it to link new network
            # with router.
            my @redundancy_interfaces;
            for my $interface (@promiscuous_ports) {
                my $router = $interface->{router};
                (my $router_name = $router->{name}) =~ s/^router://;
                my $hardware = $interface->{hardware};
                my $new_intf = new(
                    'Interface',
                    name     => "interface:$router_name.$obj_name",
                    ip       => $interface->{ip},
                    hardware => $hardware,
                    router   => $router,
                    network  => $new_net,
                );
                push @{ $hardware->{interfaces} }, $new_intf;
                push @{ $new_net->{interfaces} },  $new_intf;
                push @{ $router->{interfaces} },   $new_intf;
                if ($interface->{redundant}) {
                    @{$new_intf}{qw(redundant redundancy_type redundancy_id)} =
                      @{$interface}
                      {qw(redundant redundancy_type redundancy_id)};
                    push @redundancy_interfaces, $new_intf;
                }
            }

            # Automatically add pathrestriction to redundant interfaces.
            if (@redundancy_interfaces) {
                my $restrict =
                  new('Pathrestriction', name => "auto-virtual-$obj_name");
                for my $interface (@redundancy_interfaces) {
                    push @{ $interface->{path_restrict} }, $restrict;

#		    debug("pathrestriction at $interface->{name}");
                    $interface->{redundancy_interfaces} =
                      \@redundancy_interfaces;
                }
            }
        }

        # Move secondary isolated interfaces to same artificial network
        # where the corresponding main interface has been moved to.
        for my $secondary (@secondary_isolated) {
            my $new_net = $secondary->{main_interface}->{network};
            push @{ $new_net->{interfaces} }, $secondary;
            $secondary->{network} = $new_net;
        }

        # Remove hosts and isolated interfaces from original network.
        $network->{hosts} = undef;
        for my $interface (@isolated_interfaces, @secondary_isolated) {
            aref_delete $network->{interfaces}, $interface;
        }
    }
    return;
}

# Group bridged networks by prefix of name.
# Each group
# - must have the same IP address and mask,
# - must have at least two members,
# - must be adjacent
# - linked by bridged interfaces
# - IP addresses of hosts must be disjoint (ToDo).
# Each router having a bridged interface
# must connect at least two bridged networks of the same group.
sub check_bridged_networks {
    my %prefix2net;
    for my $network (@networks) {
        my $prefix = $network->{bridged} or next;
        $prefix2net{$prefix}->{$network} = $network;
    }
    for my $prefix (keys %prefix2net) {
        if (my $network = $networks{$prefix}) {
            $network->{disabled}
              or err_msg("Must not define $network->{name} together with",
                " bridged networks of same name");
        }
    }
    for my $href (values %prefix2net) {
        my @group = values %$href;
        my $net1  = pop(@group);
        @group or warn_msg("Bridged $net1->{name} must not be used solitary");
        my %seen;
        my @next = ($net1);
        my ($ip1, $mask1) = @{$net1}{qw(ip mask)};

        # Mark all networks connected directly or indirectly with $net1
        # by a bridge as 'connected' in $href.
        while (my $network = pop(@next)) {
            my ($ip, $mask) = @{$network}{qw(ip mask)};
            $ip == $ip1 and $mask == $mask1
              or err_msg("$net1->{name} and $network->{name} must have",
                " identical ip/mask");
            $href->{$network} = 'connected';
            for my $in_intf (@{ $network->{interfaces} }) {
                next if $in_intf->{ip} ne 'bridged';
                my $router = $in_intf->{router};
                next if $seen{$router};
                my $count = 1;
                $seen{$router} = $router;
                if (my $layer3_intf = $in_intf->{layer3_interface}) {
                    match_ip($layer3_intf->{ip}, $ip, $mask)
                      or err_msg("$layer3_intf->{name}'s IP doesn't match",
                        "IP/mask of bridged networks");
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
    return;
}

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
        if ($router->{managed}) {
            aref_delete($interface->{hardware}->{interfaces}, $interface);
        }
    }
    for my $area (values %areas) {
        if (my $anchor = $area->{anchor}) {
            if ($anchor->{disabled}) {
                $area->{disabled} = 1;
            }
            else {
                push @areas, $area;
            }
        }
        else {
            $area->{border} =
              [ grep { not $_->{disabled} } @{ $area->{border} } ];
            if (@{ $area->{border} }) {
                push @areas, $area;
            }
            else {
                $area->{disabled} = 1;
            }
        }
    }
    my %name2vrf;
    for my $name (sort keys %routers) {
        my $router = $routers{$name};
        next if $router->{disabled};
        push @routers, $router;
        my $device_name = $router->{device_name};
        if ($router->{managed}) {
            push @managed_routers, $router;
            push @{ $name2vrf{$device_name} }, $router;
            if ($router->{model}->{do_auth})
            {
                push @managed_vpnhub, $router;
            }
        }
    }

    # Collect vrf instances belonging to one device.
    for my $aref (values %name2vrf) {
        next if @$aref == 1;
        equal(map { $_->{managed} ? $_->{model}->{name} : () } @$aref)
          or err_msg("All VRF instances of router:$aref->[0]->{device_name}",
                     " must have identical model");

        my %hardware;
        for my $router (@$aref) {
            for my $hardware (@{ $router->{hardware} }) {
                my $name = $hardware->{name};
                if (my $other = $hardware{$name}) {
                    err_msg(
                        "Duplicate hardware '$name' at",
                        " $other->{name} and $router->{name}"
                    );
                }
                else {
                    $hardware{$name} = $router;
                }
            }
        }
        for my $router (@$aref) {
            $router->{vrf_members} = $aref;
        }
    }

    # Collect networks into @networks.
    # We need a deterministic order. 
    # Don't sort by name because code shouldn't change if a network is renamed.
    # Derive order from order of routers and interfaces.
    my %seen;
    for my $router (@routers) {
        for my $interface (@{ $router->{interfaces} }) {
            next if $interface->{disabled};
            my $network = $interface->{network};
            $seen{$network}++ or push @networks, $network;
        }
    }

    # Find networks not connected to any router.
    for my $network (values %networks) {
        next if $network->{disabled};
        if (! $seen{$network}) {
            if (keys %networks > 1) {
                err_msg("$network->{name} isn't connected to any router");
            }
            else {
                push @networks, $network;
            }
        }
    }

    @virtual_interfaces = grep { not $_->{disabled} } @virtual_interfaces;
    if ($policy_distribution_point and $policy_distribution_point->{disabled}) {
        $policy_distribution_point = undef;
    }
    check_bridged_networks();
    transform_isolated_ports();
    return;
}

####################################################################
# Convert hosts to subnets.
# Find adjacent subnets.
# Mark subnet relation of subnets.
####################################################################

# 255.255.255.255, 127.255.255.255, ..., 0.0.0.3, 0.0.0.1, 0.0.0.0
my @inverse_masks = map { complement_32bit prefix2mask $_ } (0 .. 32);

# Convert an IP range to a set of covering IP/mask pairs.
sub split_ip_range {
    my ($low, $high) = @_;
    my @result;
  IP:
    while ($low <= $high) {
        for my $mask (@inverse_masks) {
            if (($low & $mask) == 0 && ($low + $mask) <= $high) {
                push @result, [ $low, complement_32bit $mask ];
                $low = $low + $mask + 1;
                next IP;
            }
        }
    }
    return @result;
}

sub convert_hosts {
    progress('Converting hosts to subnets');
    for my $network (@networks) {
        next if $network->{ip} =~ /^(?:unnumbered|tunnel)$/;
        my @inv_prefix_aref;

        # Converts hosts and ranges to subnets.
        # Eliminate duplicate subnets.
        for my $host (@{ $network->{hosts} }) {
            my ($name, $nat, $id, $private, $owner) =
              @{$host}{qw(name nat id private owner)};
            my @ip_mask;
            if (my $ip = $host->{ip}) {
                @ip_mask = [ $ip, 0xffffffff ];
            }
            elsif ($host->{range}) {
                my ($ip1, $ip2) = @{ $host->{range} };
                @ip_mask = split_ip_range $ip1, $ip2;
            }
            else {
                internal_err("unexpected host type");
            }
            for my $ip_mask (@ip_mask) {
                my ($ip, $mask) = @$ip_mask;
                my $inv_prefix = 32 - mask2prefix $mask;
                if (my $other_subnet = $inv_prefix_aref[$inv_prefix]->{$ip}) {
                    my $nat2 = $other_subnet->{nat};
                    my $nat_error;
                    if ($nat xor $nat2) {
                        $nat_error = 1;
                    }
                    elsif ($nat and $nat2) {

                        # Number of entries is equal.
                        if (keys %$nat == keys %$nat2) {

                            # Entries are equal.
                            for my $name (keys %$nat) {
                                unless ($nat2->{$name}
                                    and $nat->{$name} eq $nat2->{$name})
                                {
                                    $nat_error = 1;
                                    last;
                                }
                            }
                        }
                        else {
                            $nat_error = 1;
                        }
                    }
                    $nat_error
                      and err_msg "Inconsistent NAT definition for",
                      " $other_subnet->{name} and $host->{name}";

                    my $owner2 = $other_subnet->{owner};
                    if (($owner xor $owner2)
                        || $owner && $owner2 && $owner ne $owner2)
                    {
                        err_msg "Inconsistent owner definition for",
                          " $other_subnet->{name} and $host->{name}";
                    }
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
                    $subnet->{nat}     = $nat     if $nat;
                    $subnet->{private} = $private if $private;
                    $subnet->{owner}   = $owner   if $owner;
                    if ($id) {
                        if ($mask == 0xffffffff) {
                            if (my ($name, $dom) = ($id =~ /^(.*?)(\@.*)$/)) {
                                $name
                                    or err_msg("ID of $name must not start", 
                                               " with character '\@'");
                            }
                            else {
                                err_msg("ID of $name must contain",
                                        " character '\@'");
                            }
                        }
                        else {
                            $id =~ /^\@/
                                or err_msg("ID of $name must start",
                                           " with character '\@'");
                        }
                        $subnet->{id} = $id;
                        $subnet->{radius_attributes} =
                          $host->{radius_attributes};
                    }
                    $inv_prefix_aref[$inv_prefix]->{$ip} = $subnet;
                    push @{ $host->{subnets} },    $subnet;
                    push @{ $network->{subnets} }, $subnet;
                }
            }
        }

        # Find adjacent subnets which build a larger subnet.
        my $network_inv_prefix = 32 - mask2prefix $network->{mask};
        for (my $i = 0 ; $i < @inv_prefix_aref ; $i++) {
            if (my $ip2subnet = $inv_prefix_aref[$i]) {
                my $next   = 2**$i;
                my $modulo = 2 * $next;
                for my $ip (keys %$ip2subnet) {
                    my $subnet = $ip2subnet->{$ip};

                    if (

                        # Don't combine subnets with NAT
                        # ToDo: This would be possible if all NAT addresses
                        #  match too.
                        # But, attention for PIX firewalls:
                        # static commands for networks / subnets block
                        # network and broadcast address.
                        not $subnet->{nat}

                        # Don't combine subnets having radius-ID.
                        and not $subnet->{id}

                        # Only take the left part of two adjacent subnets.
                        and $ip % $modulo == 0
                      )
                    {
                        my $next_ip = $ip + $next;

                        # Find the right part.
                        if (my $neighbor = $ip2subnet->{$next_ip}) {
                            $subnet->{neighbor} = $neighbor;
                            my $up_inv_prefix = $i + 1;
                            my $up;
                            if ($up_inv_prefix >= $network_inv_prefix) {

                                # Larger subnet is whole network.
                                $up = $network;
                            }
                            elsif ( $up_inv_prefix < @inv_prefix_aref
                                and $up =
                                $inv_prefix_aref[$up_inv_prefix]->{$ip})
                            {
                            }
                            else {
                                (my $name = $subnet->{name}) =~
                                  s/^.*:/auto_subnet:/;
                                my $mask = prefix2mask(32 - $up_inv_prefix);
                                $up = new(
                                    'Subnet',
                                    name    => $name,
                                    network => $network,
                                    ip      => $ip,
                                    mask    => $mask
                                );
                                if (my $private = $subnet->{private}) {
                                    $up->{private} = $private if $private;
                                }
                                $inv_prefix_aref[$up_inv_prefix]->{$ip} = $up;
                            }
                            $subnet->{up}   = $up;
                            $neighbor->{up} = $up;
                            push @{ $network->{subnets} }, $up;

                            # Don't search for enclosing subnet below.
                            next;
                        }
                    }

                    # For neighbors, {up} has been set already.
                    next if $subnet->{up};

                    # Search for enclosing subnet.
                    for (my $j = $i + 1 ; $j < @inv_prefix_aref ; $j++) {
                        my $mask = prefix2mask(32 - $j);
                        $ip = $ip & $mask;    # Perl bug #108480
                        if (my $up = $inv_prefix_aref[$j]->{$ip}) {
                            $subnet->{up} = $up;
                            last;
                        }
                    }

                    # Use network, if no enclosing subnet found.
                    $subnet->{up} ||= $network;
                }
            }
        }

        # Attribute {up} has been set for all subnets now.
        # Do the same for interfaces.
        for my $interface (@{ $network->{interfaces} }) {
            $interface->{up} = $network;
        }
    }
    return;
}

# Find adjacent subnets and substitute them by their enclosing subnet.
sub combine_subnets  {
    my ($subnets) = @_;
    my %hash = map { $_ => $_ } @$subnets;
    my @extra;
    while(1) {
        for my $subnet (@$subnets) {
            my $neighbor;
            if ($neighbor = $subnet->{neighbor} and $hash{$neighbor}) {
                my $up = $subnet->{up};
                unless ($hash{$up}) {
                    $hash{$up} = $up;
                    push @extra, $up;
                }
                delete $hash{$subnet};
                delete $hash{$neighbor};
            }
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

    # Sort networks by size of mask,
    # i.e. large subnets coming first and
    # for equal mask by IP address.
    # We need this to make the output deterministic.
    return [ sort { $a->{mask} <=> $b->{mask} || $a->{ip} <=> $b->{ip} }
          values %hash ];
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

my %auto_interfaces;

sub get_auto_intf {
    my ($object, $managed) = @_;
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
            managed => $managed
        );
        $result->{disabled} = 1 if $object->{disabled};
        $auto_interfaces{$object}->{$managed} = $result;

#       debug($result->{name});
    }
    return $result;
}

# Get a reference to an array of network object descriptions and
# return a reference to an array of network objects.
sub expand_group1;

sub expand_group1 {
    my ($aref, $context, $clean_autogrp) = @_;
    my @objects;
    for my $parts (@$aref) {

        my ($type, $name, $ext) = @$parts;
        if ($type eq '&') {
            my @non_compl;
            my @compl;
            my %router2intf;
            for my $element (@$name) {
                my $element1 = $element->[0] eq '!' ? $element->[1] : $element;
                my @elements =
                  map { $_->{is_used} = 1; $_; } @{
                    expand_group1(
                        [$element1], "intersection of $context",
                        $clean_autogrp
                    )
                  };
                for my $obj (@elements) {
                    my $type = ref $obj;
                    my $router;
                    if ($type eq 'Interface') {
                        $router = $obj->{router};
                    }
                    elsif ($type eq 'Autointerface') {
                        $router = $obj->{object};
                        is_router($router) or next;
                    }
                    else {
                        next;
                    }
                    if (my $other = $router2intf{$router}) {
                        if (ref($other) ne $type) {
                            err_msg(
                                "Must not use $obj->{name} and",
                                " $other->{name} together in $context"
                            );
                        }
                    }
                    else {
                        $router2intf{$router} = $obj;
                    }
                }
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
            for my $element (@{ $non_compl[0] }) {
                $result->{$element} = $element;
            }
            for my $set (@non_compl[ 1 .. $#non_compl ]) {
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
            push @objects, grep { $result->{$_} } @{ $non_compl[0] };
        }
        elsif ($type eq '!') {
            err_msg("Complement (!) is only supported as part of intersection");
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
                my $sub_objects = expand_group1 $name,
                  "interface:[..].[$selector] of $context";
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
                                $object->{mask} == 0
                                  or err_msg "Must not use",
                                  " interface:[..].[all]\n",
                                  " with $object->{name} having ip/mask\n",
                                  " in $context";
                                push @check, @{ $object->{zone}->{interfaces} };
                            }
                            elsif ($managed) {
                                push @check,
                                  grep { $_->{router}->{managed} }
                                  @{ $object->{interfaces} };
                            }
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
                        if ($managed and not $router->{managed}) {

                            # Do nothing.
                        }
                        elsif ($selector eq 'all') {
                            push @check, @{ $router->{interfaces} };
                        }
                        else {
                            push @objects, get_auto_intf $router;
                        }
                    }
                    elsif ($type eq 'Area') {
                        my @routers;

                        # Prevent duplicates and border routers.
                        my %seen;

                        # Don't add border routers of this area.
                        for my $interface (@{ $object->{border} }) {
                            $seen{ $interface->{router} } = 1;
                        }

                        # Add border routers of security zones inside
                        # current area.
                        for my $router (
                            map { $_->{router} }
                            map { @{ $_->{interfaces} } }
                            @{ $object->{zones} }
                          )
                        {
                            if (not $seen{$router}) {
                                push @routers, $router;
                                $seen{$router} = 1;
                            }
                        }
                        if ($managed) {
                            @routers = grep { $_->{managed} } @routers;
                        }
                        else {
                            push @routers, map {
                                my $r = $_->{unmanaged_routers};
                                $r ? @$r : ()
                            } @{ $object->{zones} };
                        }
                        if ($selector eq 'all') {
                            push @check, map { @{ $_->{interfaces} } } @routers;
                        }
                        else {
                            push @objects, map { get_auto_intf $_ } @routers;
                        }
                    }
                    elsif ($type eq 'Autointerface') {
                        my $obj = $object->{object};
                        if (is_router $obj) {
                            if ($managed and not $obj->{managed}) {

                                # This router has no managed interfaces.
                            }
                            elsif ($selector eq 'all') {
                                push @check, @{ $obj->{interfaces} };
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
                my ($selector, $managed) = @$ext;
                if (my $router = $routers{$name}) {

                    # Syntactically impossible.
                    $managed and internal_err();
                    if ($selector eq 'all') {
                        push @check, @{ $router->{interfaces} };
                    }
                    else {
                        push @objects, get_auto_intf $router;
                    }
                }
                else {
                    err_msg("Can't resolve $type:$name.[$selector] in $context");
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
                  @{ expand_group1($name, "$type:[..] of $context") }
            ];
            my $get_aggregates = sub {
                my ($object, $ip, $mask) = @_;
                my @objects;
                my $type = ref $object;
                if ($type eq 'Area') {
                    push @objects, unique(map({ get_any($_, $ip, $mask) } 
                                              @{ $object->{zones} }));
                }
                elsif ($type eq 'Network' && $object->{is_aggregate}) {
                    push @objects, $object;
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
                    push @objects, $object->{network};
                }
                elsif ($type eq 'Network' && !$object->{is_aggregate}) {
                    push @objects, $object;
                }
                elsif (my $aggregates = $get_aggregates->($object, 0, 0)) {
                    push(@objects, map { @{ $_->{networks} } } @$aggregates);
                }
                else {
                    return;
                }
                return \@objects;
            };
            if ($type eq 'host') {
                for my $object (@$sub_objects) {
                    my $type = ref $object;
                    if ($type eq 'Host') {
                        push @objects, $object;
                    }
                    elsif ($type ne 'Interface'
                        and my $networks = $get_networks->($object))
                    {
                        push @objects, map { @{ $_->{hosts} } } @$networks;
                    }
                    else {
                        err_msg
                          "Unexpected type '$type' in host:[..] of $context";
                    }
                }
            }
            elsif ($type eq 'network') {
                my @list;
                for my $object (@$sub_objects) {
                    if (my $networks = $get_networks->($object)) {

                        # Silently remove crosslink networks from
                        # automatic groups.
                        # Change loopback network to loopback interface.
                        push @list, $clean_autogrp
                          ? map {
                            if ($_->{loopback})
                            {
                                my $interfaces = $_->{interfaces};
                                if (@$interfaces > 1) {
                                    warn_msg(
                                        "Must not use $_->{name},",
                                        " use interfaces instead"
                                    );
                                }
                                $interfaces->[0];
                            }
                            else {
                                $_;
                            }
                          }
                          grep { not($_->{crosslink}) } @$networks
                          : @$networks;
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
                my ($ip, $mask) = $ext ? @$ext : (0, 0);
                my @list;
                for my $object (@$sub_objects) {
                    if (my $aggregates = 
                        $get_aggregates->($object, $ip, $mask)) 
                    {
                        push @list, @$aggregates;
                    }
                    elsif (my $networks = $get_networks->($object)) {
                        push @list, map({ get_any($_->{zone}, $ip, $mask) } 
                                        @$networks);
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
        elsif (my $object = $name2object{$type}->{$name}) {

            $ext
              and err_msg("Unexpected '.$ext' after $type:$name in $context");

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
                      expand_group1($object->{elements}, "$type:$name",
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
                    my %unique;
                    my @duplicate;
                    for my $obj (@$elements) {
                        if ($unique{$obj}++) {
                            push @duplicate, $obj;
                            $obj = undef;
                        }
                    }
                    if (@duplicate) {
                        $elements = [ grep { defined $_ } @$elements ];
                        my $msg = "Duplicate elements in $type:$name:\n "
                          . join("\n ", map { $_->{name} } @duplicate);
                        warn_msg($msg);
                    }

                    # Cache result for further references to the same group
                    # in same $clean_autogrp context.
                    $object->{$attr_name} = $elements;
                }
                push @objects, @$elements;
            }

            # Substitute aggregate by aggregate set of zone cluster.
            elsif ($object->{is_aggregate} && $object->{zone}->{zone_cluster}) {
                my ($ip, $mask) = @{$object}{qw(ip mask)};
                push(@objects,
                    get_cluster_aggregates($object->{zone}, $ip, $mask));
            }

            else {
                push @objects, $object;
            }

        }
        else {
            err_msg("Can't resolve $type:$name in $context");
        }
    }
    return \@objects;
}

sub expand_group {
    my ($obref, $context, $convert_hosts) = @_;
    my $aref = expand_group1 $obref, $context, 'clean_autogrp';
    for my $object (@$aref) {
        my $ignore;
        if ($object->{disabled}) {
            $object = undef;
        }
        elsif (is_network $object) {
            if ($object->{ip} eq 'unnumbered') {
                $ignore = "unnumbered $object->{name}";
            }
            elsif ($object->{crosslink}) {
                $ignore = "crosslink $object->{name}";
            }
        }
        elsif (is_interface $object) {
            if ($object->{ip} =~ /^(short|unnumbered)$/) {
                $ignore = "$object->{ip} $object->{name}";
            }
        }
        elsif (is_area $object) {
            $ignore = $object->{name};
        }
        if ($ignore) {
            $object = undef;
            warn_msg("Ignoring $ignore in $context");
        }
    }

    # Detect and remove duplicate values in group.
    my %unique;
    my @duplicate;
    for my $obj (@$aref) {
        next if not defined $obj;
        if ($unique{$obj}++) {
            push @duplicate, $obj;
            $obj = undef;
        }
    }
    if (@duplicate) {
        my $msg = "Duplicate elements in $context:\n "
          . join("\n ", map { $_->{name} } @duplicate);
        warn_msg($msg);
    }
    $aref = [ grep { defined $_ } @$aref ];
    if ($convert_hosts) {
        my @subnets;
        my %subnet2host;
        my @other;
        for my $obj (@$aref) {

#           debug("group:$obj->{name}");
            if (is_host $obj) {
                for my $subnet (@{ $obj->{subnets} }) {
                    if (my $host = $subnet2host{$subnet}) {
                        warn_msg("$obj->{name} and $host->{name}",
                                 " overlap in $context");
                    }
                    else {
                        $subnet2host{$subnet} = $obj;
                        push @subnets, $subnet;
                    }
                }
            }
            else {
                push @other, $obj;
            }
        }
        push @other, ($convert_hosts eq 'no_combine')
          ? @subnets
          : @{ combine_subnets \@subnets };
        return \@other;
    }
    else {
        return $aref;
    }

}

sub check_unused_groups {
    my $check = sub {
        my ($hash, $print_type) = @_;
        my $print = $print_type eq 'warn' ? \&warn_msg : \&err_msg;
        for my $name (sort keys %$hash) {
            my $value = $hash->{$name};
            next if $value->{is_used};
            $print->("unused $value->{name}");
        }
    };
    if (my $conf = $config{check_unused_groups}) {
        for my $hash (\%groups, \%protocolgroups) {
            $check->($hash, $conf);
        }
    }
    if (my $conf = $config{check_unused_protocols}) {
        for my $hash (\%protocols) {
            $check->($hash, $conf);
        }
    }

    # Not used any longer; free memory.
    %groups = ();
    return;
}

sub expand_protocols;

sub expand_protocols {
    my ($aref, $context) = @_;
    my @protocols;
    for my $pair (@$aref) {
        if (ref($pair) eq 'HASH') {
            push @protocols, $pair;
            set_src_dst_range_list($pair);
            next;
        }
        my ($type, $name) = @$pair;
        if ($type eq 'protocol') {
            if (my $prt = $protocols{$name}) {
                push @protocols, $prt;

                # Currently needed by external program 'cut-netspoc'.
                $prt->{is_used} = 1;

                # Used in expand_rules.
                set_src_dst_range_list($prt);
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
                    $elements = expand_protocols $elements, "$type:$name";

                    # Cache result for further references to the same group.
                    $prtgroup->{elements} = $elements;
                }
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

sub path_auto_interfaces;

# Hash with attributes deny, supernet, permit for storing
# expanded rules of different type.
our %expanded_rules;

# Hash for ordering all rules:
# $rule_tree{$stateless}->{$action}->{$src}->{$dst}->{$src_range}->{$prt}
#  = $rule;
my %rule_tree;

# Hash for converting a reference of a protocol back to this protocol.
my %ref2prt;

# Collect deleted rules for further inspection.
my @deleted_rules;

# Add rules to %rule_tree for efficient look up.
sub add_rules {
    my ($rules_ref) = @_;

    for my $rule (@$rules_ref) {
        my ($stateless, $action, $src, $dst, $src_range, $prt) =
          @{$rule}{ 'stateless', 'action', 'src', 'dst', 'src_range', 'prt' };
        $ref2prt{$src_range} = $src_range;
        $ref2prt{$prt}       = $prt;

        # A rule with an interface as destination may be marked as deleted
        # during global optimization. But in some cases, code for this rule
        # must be generated anyway. This happens, if
        # - it is an interface of a managed router and
        # - code is generated for exactly this router.
        # Mark such rules for easier handling.
        if (is_interface($dst) and $dst->{router}->{managed}) {
            $rule->{managed_intf} = 1;
        }
        my $old_rule =
          $rule_tree{$stateless}->{$action}->{$src}->{$dst}->{$src_range}
          ->{$prt};
        if ($old_rule) {

            # Found identical rule.
            $rule->{deleted} = $old_rule;
            push @deleted_rules, $rule;
            next;
        }

#       debug("Add:", print_rule $rule);
        $rule_tree{$stateless}->{$action}->{$src}->{$dst}->{$src_range}
          ->{$prt} = $rule;
    }
    return;
}

my %obj2zone;

sub get_zone {
    my ($obj) = @_;
    my $type = ref $obj;
    my $result;

    # A router or network with [auto] interface.
    if ($type eq 'Autointerface') {
        $obj  = $obj->{object};
        $type = ref $obj;
    }

    if ($type eq 'Network') {
        $result = $obj->{zone};
    }
    elsif ($type eq 'Subnet') {
        $result = $obj->{network}->{zone};
    }
    elsif ($type eq 'Interface') {
        if ($obj->{router}->{managed}) {
            $result = $obj->{router};
        }
        else {
            $result = $obj->{network}->{zone};
        }
    }

    # Only used when called from expand_rules.
    elsif ($type eq 'Router') {
        if ($obj->{managed}) {
            $result = $obj;
        }
        else {
            $result = $obj->{interfaces}->[0]->{network}->{zone};
        }
    }
    elsif ($type eq 'Host') {
        $result = $obj->{network}->{zone};
    }
    else {
        internal_err("unexpected $obj->{name}");
    }
    return($obj2zone{$obj} = $result);
}

sub path_walk;

sub expand_special  {
    my ($src, $dst, $flags, $context) = @_;
    my @result;
    if (is_autointerface $src) {
        for my $interface (path_auto_interfaces $src, $dst) {
            if ($interface->{ip} eq 'short') {
                err_msg "'$interface->{ip}' $interface->{name}",
                  " (from .[auto])\n", " must not be used in rule of $context";
            }
            elsif ($interface->{ip} =~ /unnumbered/) {

                # Ignore unnumbered interfaces.
            }
            else {
                push @result, $interface;
            }
        }
    }
    else {
        @result = ($src);
    }
    if ($flags->{net}) {
        my @networks;
        my @other;
        for my $obj (@result) {
            my $type = ref $obj;
            my $network;
            if ($type eq 'Network') {
                $network = $obj;
            }
            elsif ($type eq 'Subnet' or $type eq 'Host') {
                if ($obj->{id}) {
                    push @other, $obj;
                    next;
                }
                else {
                    $network = $obj->{network};
                }
            }
            elsif ($type eq 'Interface') {
                if ($obj->{router}->{managed} || $obj->{loopback}) {
                    push @other, $obj;
                    next;
                }
                else {
                    $network = $obj->{network};
                }
            }
            else {
                internal_err("unexpected $obj->{name}");
            }
            push @networks, $network if $network->{ip} ne 'unnumbered';
        }
        @result = (@other, unique(@networks));
#        debug "special: ", join(', ', map { $_->{name} } @result);
    }
    if ($flags->{any}) {
        my %zones;
        for my $obj (@result) {
            my $type = ref $obj;
            my $zone;
            if ($type eq 'Network') {
                $zone = $obj->{zone};
            }
            elsif ($type eq 'Subnet' or $type eq 'Interface' or $type eq 'Host')
            {
                $zone = $obj->{network}->{zone};
            }
            else {
                internal_err("unexpected $obj->{name}");
            }
            $zones{$zone} = $zone;
        }
        @result = map { get_any($_, 0, 0) } values %zones;
    }
    return @result;
}

# This handles a rule between objects inside a single security zone or
# between interfaces of a single managed router.
# Show warning or error message if rule is between
# - different interfaces or
# - different networks or
# - subnets/hosts of different networks.
# Rules between identical objects are silently ignored.
# But a message is shown if a service only has rules between identical objects.
sub collect_unenforceable  {
    my ($src, $dst, $zone, $service) = @_;

    if ($zone->{has_unenforceable}) {
        $zone->{seen_unenforceable} = 1;
        $service->{silent_unenforceable} = 1;
        return;
    }

    my $context = $service->{name};
    $service->{silent_unenforceable} = 1;

    # A rule between identical objects is a common case
    # which results from rules with "src=user;dst=user;".
    return if $src eq $dst;

    if (is_router $zone) {

        # Auto interface is assumed to be identical
        # to each other interface of a single router.
        return if is_autointerface($src) or is_autointerface($dst);
    }
    elsif (is_subnet $src and is_subnet($dst)) {

        # For rules with different subnets of a single network we don't
        # know if the subnets have been split from a single range.
        # E.g. range 1-4 becomes four subnets 1,2-3,4
        # For most splits the resulting subnets would be adjacent.
        # Hence we check for adjacency.
        if ($src->{network} eq $dst->{network}) {
            my ($a, $b) = $src->{ip} > $dst->{ip} ? ($dst, $src) : ($src, $dst);
            if ($a->{ip} + complement_32bit($a->{mask}) + 1 == $b->{ip}) {
                return;
            }
        }
    }
    elsif ($src->{is_aggregate} && $dst->{is_aggregate}) {

        # Both are aggregates,
        # - belonging to same zone cluster and
        # - having identical ip and mask
        return if (zone_eq($src->{zone}, $dst->{zone})
                   && $src->{ip} == $dst->{ip}
                   && $src->{mask} == $dst->{mask});
    }
    elsif ($src->{is_aggregate} && $src->{mask} == 0) {

        # This is a common case, which results from rules like
        # group:some_networks -> any:[group:some_networks]
        return if zone_eq($src->{zone}, get_zone($dst))
    }
    elsif($dst->{is_aggregate} && $dst->{mask} == 0 ) {
        return if zone_eq($dst->{zone}, get_zone($src))
    }
    $service->{seen_unenforceable}->{$src}->{$dst} ||= [ $src, $dst ];
    return;
}

sub show_unenforceable {
    my ($service) = @_;
    my $context = $service->{name};

    if ($service->{has_unenforceable} &&
        (! $service->{seen_unenforceable} || ! $service->{seen_enforceable})) 
    {
        warn_msg("Useless attribute 'has_unenforceable' at $context");
    }
    return if ! $config{check_unenforceable};
    return if $service->{disabled};

    my $print = $config{check_unenforceable} eq 'warn' ? \&warn_msg : \&err_msg;

    # Warning about fully unenforceable service can't be disabled with
    # attribute has_unenforceable.
    if (! delete $service->{seen_enforceable}) {
        
        # Don't warn on empty service without any expanded rules.
        if ($service->{seen_unenforceable} || $service->{silent_unenforceable}) 
        {
            $print->("$context is fully unenforceable");
        }
        return;
    }
    return if $service->{has_unenforceable};

    if (my $hash = delete $service->{seen_unenforceable}) {
        my $msg = "$context has unenforceable rules:";
        for my $hash (values %$hash) {
            for my $aref (values %$hash) {
                my ($src, $dst) = @$aref;
                $msg .= "\n src=$src->{name}; dst=$dst->{name}";
            }
        }
        $print->($msg);
    }
    delete $service->{silent_unenforceable};
    return;
}

sub warn_useless_unenforceable {
    for my $zone (@zones) {
        $zone->{has_unenforceable} or next;
        $zone->{seen_unenforceable} or
            warn_msg("Useless attribute 'has_unenforceable' at $zone->{name}");
    }
    return;
}

sub show_deleted_rules1 {
    return if not @deleted_rules;
    my %pname2oname2deleted;
    my %pname2file;
  RULE:
    for my $rule (@deleted_rules) {
        my $other = $rule->{deleted};

        my $prt1 = $rule->{orig_prt}  || $rule->{prt};
        my $prt2 = $other->{orig_prt} || $other->{prt};
        next if $prt1->{flags}->{overlaps} && $prt2->{flags}->{overlaps};

        my $service  = $rule->{rule}->{service};
        my $oservice = $other->{rule}->{service};
        if (my $overlaps = $service->{overlaps}) {
            for my $overlap (@$overlaps) {
                if ($oservice eq $overlap) {
                    $service->{overlaps_used}->{$overlap} = $overlap;
                    next RULE;
                }
            }
        }
        if (my $overlaps = $oservice->{overlaps}) {
            for my $overlap (@$overlaps) {
                if ($service eq $overlap) {
                    $oservice->{overlaps_used}->{$overlap} = $overlap;
                    next RULE;
                }
            }
        }
        my $pname = $service->{name};
        my $oname = $oservice->{name};
        my $pfile = $service->{file};
        my $ofile = $oservice->{file};
        $pfile =~ s/.*?([^\/]+)$/$1/;
        $ofile =~ s/.*?([^\/]+)$/$1/;
        $pname2file{$pname} = $pfile;
        $pname2file{$oname} = $ofile;
        push(@{ $pname2oname2deleted{$pname}->{$oname} }, $rule);
    }
    if (my $action = $config{check_duplicate_rules}) {
        my $print = $action eq 'warn' ? \&warn_msg : \&err_msg;
        for my $pname (sort keys %pname2oname2deleted) {
            my $hash = $pname2oname2deleted{$pname};
            for my $oname (sort keys %$hash) {
                my $aref = $hash->{$oname};
                my $msg  = "Duplicate rules in $pname and $oname:\n";
                $msg .= " Files: $pname2file{$pname} $pname2file{$oname}\n  ";
                $msg .= join("\n  ", map { print_rule $_ } @$aref);
                $print->($msg);
            }
        }
    }

    # Variable will be reused during sub optimize.
    @deleted_rules = ();
    return;
}

sub show_deleted_rules2 {
    return if not @deleted_rules;
    my %pname2oname2deleted;
    my %pname2file;
  RULE:
    for my $rule (@deleted_rules) {
        my $other = $rule->{deleted};

        # Ignore automatically generated rules from crypto.
        next if not $rule->{rule};

        my $prt1 = $rule->{orig_prt}  || $rule->{prt};
        my $prt2 = $other->{orig_prt} || $other->{prt};
        next if $prt1->{flags}->{overlaps} && $prt2->{flags}->{overlaps};

        # Rule is still needed at device of $rule->{dst}.
        if ($rule->{managed_intf} and not $rule->{deleted}->{managed_intf}) {
            next;
        }

        # Automatically generated reverse rule for stateless router
        # is still needed, even for stateful routers for static routes.
        my $src = $rule->{src};
        if (is_interface($src)) {
            my $router = $src->{router};
            if ($router->{managed}) {
                next;
            }
        }

        my $service  = $rule->{rule}->{service};
        my $oservice = $other->{rule}->{service};
        if (my $overlaps = $service->{overlaps}) {
            for my $overlap (@$overlaps) {
                if ($oservice eq $overlap) {
                    $service->{overlaps_used}->{$overlap} = $overlap;
                    next RULE;
                }
            }
        }
        my $pname = $service->{name};
        my $oname = $oservice->{name};
        my $pfile = $service->{file};
        my $ofile = $oservice->{file};
        $pfile =~ s/.*?([^\/]+)$/$1/;
        $ofile =~ s/.*?([^\/]+)$/$1/;
        $pname2file{$pname} = $pfile;
        $pname2file{$oname} = $ofile;
        push(@{ $pname2oname2deleted{$pname}->{$oname} }, [ $rule, $other ]);
    }
    if (my $action = $config{check_redundant_rules}) {
        my $print = $action eq 'warn' ? \&warn_msg : \&err_msg;
        for my $pname (sort keys %pname2oname2deleted) {
            my $hash = $pname2oname2deleted{$pname};
            for my $oname (sort keys %$hash) {
                my $aref = $hash->{$oname};
                my $msg  = "Redundant rules in $pname compared to $oname:\n";
                $msg .= " Files: $pname2file{$pname} $pname2file{$oname}\n  ";
                $msg .= join(
                    "\n  ",
                    map {
                        my ($r, $o) = @$_;
                        print_rule($r) . "\n< " . print_rule($o);
                    } @$aref
                    );
                $print->($msg);
            }
        }
    }

    # Free memory.
    @deleted_rules = ();

    return;
}

sub warn_unused_overlaps {
    for my $key (sort keys %services) {
        my $service = $services{$key};
        if (my $overlaps = $service->{overlaps}) {
            my $used = delete $service->{overlaps_used};
            for my $overlap (@$overlaps) {
                $used->{$overlap}
                  or warn_msg("Useless 'overlaps = $overlap->{name}'",
                              " in $service->{name}");
            }
        }
    }
    return;
}

# List of protocols to permit globally at any device.
my @global_permit;
my %global_permit_dst_range_list;

# Parameters:
# - Reference to array of unexpanded rules.
# - The service.
# - Reference to hash with attributes deny, supernet, permit for storing
#   resulting expanded rules of different type.
# - Reference to array of values. Occurrences of 'user' in rules
#   will be substituted by these values.
# - Flag which will be passed on to expand_group.
sub expand_rules {
    my ($service, $result, $convert_hosts) = @_;
    my $rules_ref = $service->{rules};
    my $user      = $service->{user};
    my $context   = $service->{name};
    my $disabled  = $service->{disabled};
    my $private   = $service->{private};
    my $foreach   = $service->{foreach};

    for my $unexpanded (@$rules_ref) {
        my $action = $unexpanded->{action};
        my $prt_list = expand_protocols $unexpanded->{prt}, "rule in $context";
        for my $element ($foreach ? @$user : $user) {
            $user_object->{elements} = $element;
            my $src =
              expand_group($unexpanded->{src}, "src of rule in $context",
                $convert_hosts);
            my $dst =
              expand_group($unexpanded->{dst}, "dst of rule in $context",
                $convert_hosts);
            for my $prt (@$prt_list) {
                my $flags = $prt->{flags};

                # We must not use a unspecified boolean value but values 0 or 1,
                # because this is used as a hash key in %rule_tree.
                my $stateless = $flags->{stateless} ? 1 : 0;

                my ($src, $dst) =
                  $flags->{reversed} ? ($dst, $src) : ($src, $dst);

                # If $prt is duplicate of an identical protocol,
                # use the main protocol, but remember the original
                # one for debugging / comments.
                my $orig_prt;

                # Prevent modification of original array.
                my $prt = $prt;
                if (my $main_prt = $prt->{main}) {
                    $orig_prt = $prt;
                    $prt      = $main_prt;
                }
                else {
                    my $proto = $prt->{proto};
                    if ($proto eq 'tcp' || $proto eq 'udp') {

                        # Remember unsplitted prt.
                        $orig_prt = $prt;
                    }
                }
                $prt->{src_dst_range_list} or internal_err($prt->{name});
                for my $src_dst_range (@{ $prt->{src_dst_range_list} }) {
                    my ($src_range, $prt) = @$src_dst_range;

                    if (keys %global_permit_dst_range_list && 
                        $action eq 'permit') 
                    {
                        my $up = $prt;
                        while ($up) {
                            if ($global_permit_dst_range_list{$up}) {
                                warn_msg("$prt->{name} in $context",
                                         " is redundant to global:permit");
                                last;
                            }
                            $up = $up->{up};
                        }
                    }

                    for my $src (@$src) {
                        my $src_zone = $obj2zone{$src} || get_zone $src;
                        my $src_zone_cluster = $src_zone->{zone_cluster};
                        for my $dst (@$dst) {
                            my $dst_zone = $obj2zone{$dst} || get_zone $dst;
                            my $dst_zone_cluster = $dst_zone->{zone_cluster};
                            if (   $src_zone eq $dst_zone
                                || $src_zone_cluster
                                && $dst_zone_cluster
                                && $src_zone_cluster eq $dst_zone_cluster)
                            {
                                collect_unenforceable(
                                    $src, $dst, $src_zone, $service);
                                next;
                            }

                            # At least one rule is enforceable.
                            # This is used to decide, if a service is fully
                            # unenforceable.
                            $service->{seen_enforceable} = 1;

                            my @src = expand_special $src, $dst, $flags->{src},
                              $context
                              or next;    # Prevent multiple error messages.
                            my @dst = expand_special $dst, $src, $flags->{dst},
                              $context;
                            for my $src (@src) {
                                for my $dst (@dst) {
                                    if ($private) {
                                        my $src_p = $src->{private};
                                        my $dst_p = $dst->{private};
                                        $src_p and $src_p eq $private
                                          or $dst_p and $dst_p eq $private
                                          or err_msg
                                          "Rule of $private.private $context",
                                          " must reference at least one object",
                                          " out of $private.private";
                                    }
                                    else {
                                        $src->{private}
                                          and err_msg
                                          "Rule of public $context must not",
                                          " reference $src->{name} of",
                                          " $src->{private}.private";
                                        $dst->{private}
                                          and err_msg
                                          "Rule of public $context must not",
                                          " reference $dst->{name} of",
                                          " $dst->{private}.private";
                                    }
                                    next if $disabled;

                                    my $rule = {
                                        stateless => $stateless,
                                        action    => $action,
                                        src       => $src,
                                        dst       => $dst,
                                        src_range => $src_range,
                                        prt       => $prt,
                                        rule      => $unexpanded
                                    };
                                    $rule->{orig_prt} = $orig_prt if $orig_prt;
                                    $rule->{oneway} = 1 if $flags->{oneway};
                                    $rule->{no_check_supernet_rules} = 1
                                      if $flags->{no_check_supernet_rules};
                                    $rule->{stateless_icmp} = 1
                                      if $flags->{stateless_icmp};

                                    push @$result, $rule;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    show_unenforceable($service);

    # Result is returned indirectly using parameter $result.
    return;
}

sub print_rulecount  {
    my $count = 0;
    for my $type ('deny', 'supernet', 'permit') {
        $count += grep { not $_->{deleted} } @{ $expanded_rules{$type} };
    }
    info("Expanded rule count: $count");
    return;
}

sub split_expanded_rule_types {
    my ($rules_aref) = @_;

    my (@deny, @permit, @supernet);

    for my $rule (@$rules_aref) {
        if ($rule->{action} eq 'deny') {
            push @deny, $rule;
        }
        elsif ($rule->{src}->{is_supernet} || $rule->{dst}->{is_supernet}) {
            push @supernet, $rule;
        }
        else {
            push @permit, $rule;
        }
    }

    %expanded_rules = (deny => \@deny,
                       permit => \@permit,
                       supernet => \@supernet);
    return;
}

sub expand_services {
    my ($convert_hosts) = @_;
    convert_hosts if $convert_hosts;
    progress('Expanding services');

    # Handle global:permit.
    if (my $global = $global{permit}) {
        @global_permit =
            @{ expand_protocols($global->{prt}, "$global->{name}") };
        for my $prt (@global_permit) {
            my $main_prt = $prt->{main} || $prt;
            $main_prt->{src_dst_range_list} or internal_err($main_prt->{name});
            for my $src_dst_range (@{ $main_prt->{src_dst_range_list} }) {
                my ($src_range, $dst_prt) = @$src_dst_range;
                ($src_range->{range} && $src_range->{range} ne $aref_tcp_any ||
                 $dst_prt->{range} && $dst_prt->{range} ne $aref_tcp_any) and
                 err_msg("Must not use ports in global permit: $prt->{name}");
                $global_permit_dst_range_list{$dst_prt} = $dst_prt;
            }
        }
    }

    my $expanded_rules_aref = [];

    # Sort by service name to make output deterministic.
    for my $key (sort keys %services) {
        my $service = $services{$key};
        my $name    = $service->{name};

        # Substitute service name by service object.
        if (my $overlaps = $service->{overlaps}) {
            my @pobjects;
            for my $pair (@$overlaps) {
                my ($type, $oname) = @$pair;
                if (! $type eq 'service') {
                    err_msg "Unexpected type '$type' in attribute 'overlaps'",
                      " of $name";
                }
                elsif (my $other = $services{$oname}) {
                    push(@pobjects, $other);
                }
                else {
                    warn_msg("Unknown $type:$oname in attribute 'overlaps'",
                             " of $name");
                }
            }
            $service->{overlaps} = \@pobjects;
        }

        # Attribute "visible" is known to have value "*" or "name*".
        # It must match prefix of some owner name.
        # Change value to regex to simplify tests: # name* -> /^name.*$/
        if (my $visible = $service->{visible}) {
            if (my ($prefix) = ($visible =~ /^ (\S*) [*] $/x)) {
                if ($prefix) {
                    if (not grep { /^$prefix/ } keys %owners) {
                        warn_msg("Attribute 'visible' of $name doesn't match",
                                 " any owner");
                    }
                }
                $service->{visible} = qr/^$prefix.*$/;
            }
        }

        $service->{user} = expand_group($service->{user}, "user of $name");
        expand_rules($service, $expanded_rules_aref, $convert_hosts);
    }

    warn_useless_unenforceable();
    info("Expanded rule count: ", scalar @$expanded_rules_aref);

    progress('Preparing Optimization');
    add_rules($expanded_rules_aref);
    show_deleted_rules1();

    # Set attribute {is_supernet} before calling split_expanded_rule_types.
    find_subnets_in_nat_domain();
    split_expanded_rule_types($expanded_rules_aref);
    return;
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
            next if $network->{loopback};
            next if $network->{ip} eq 'tunnel';
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
            !(
                @implicit_owner_zones == @$cluster
                && equal(map { $_->{owner} } @implicit_owner_zones)
            )
          )
        {
            $_->{owner} = undef for @implicit_owner_zones;

#            debug("Reset owner");
#            debug($_->{name}) for @implicit_owner_zones;
        }
    }

    # A zone can be part of multiple areas.
    # Find the smallest enclosing area.
    my %zone2area;
    for my $zone (@zones) {
        my @areas = values %{ $zone->{areas} } or next;
        @areas = sort { @{ $a->{zones} } <=> @{ $b->{zones} } } @areas;
        $zone2area{$zone} = $areas[0];
    }

    # Build tree from inheritance relation:
    # area -> [area|zone, ..]
    # zone  -> [network, ..]
    # network -> [network, ..]
    # network -> [host|interface, ..]
    my %tree;
    my %is_child;
    my %ref2obj;
    my $add_node = sub {
        my ($super, $sub) = @_;
        push @{ $tree{$super} }, $sub;
        $is_child{$sub}  = 1;
        $ref2obj{$sub}   = $sub;
        $ref2obj{$super} = $super;
    };

    # Find subset relation between areas.
    for my $area (values %areas) {
        if (my $super = $area->{subset_of}) {
            $add_node->($super, $area);
        }
    }

    # Find direct subset relation between areas and zones.
    for my $area (values %areas) {
        for my $zone (@{ $area->{zones} }) {
            if ($zone2area{$zone} eq $area) {
                $add_node->($area, $zone);
            }
        }
    }

    # Find subset relation between networks and hosts/interfaces.
    my $add_hosts = sub {
        my ($network) = @_;
        for my $host (@{ $network->{hosts} }) {
            $add_node->($network, $host);
        }
        for my $interface (@{ $network->{interfaces} }) {
            if (not $interface->{router}->{managed}) {
                $add_node->($network, $interface);
            }
        }
    };

    # Find subset relation between networks and networks.
    my $add_subnets;
    $add_subnets = sub {
        my ($network) = @_;
        $add_hosts->($network);
        my $subnets = $network->{networks} or return;
        for my $subnet (@$subnets) {
            $add_node->($network, $subnet);
            $add_subnets->($subnet);
        }
    };

    # Find subset relation between zones and networks.
    for my $zone (@zones) {
        for my $network (@{ $zone->{networks} }) {
            $add_node->($zone, $network);
            $add_subnets->($network);
        }
    }

    # Find root nodes.
    my @root_nodes = map { $ref2obj{$_} } grep { not $is_child{$_} } keys %tree;

    # owner is extended by e_owner at node.
    # owner->node->[e_owner, .. ]
    my %extended;

    # upper_owner: owner object without attribute extend_only or undef
    # extend: a list of owners with attribute extend
    # extend_only: a list of owners with attribute extend_only
    my $inherit;
    $inherit = sub {
        my ($node, $upper_owner, $upper_node, $extend, $extend_only) = @_;
        my $owner = $node->{owner};
        if (not $owner) {
            $node->{owner} = $upper_owner;
        }
        else {
            $owner->{is_used} = 1;
            if ($upper_owner) {
                if ($owner eq $upper_owner
                    and not $zone_got_net_owners{$upper_node})
                {
                    warn_msg("Useless $owner->{name} at $node->{name},\n",
                             " it was already inherited from",
                             " $upper_node->{name}");
                }
                if ($upper_owner->{extend}) {
                    $extend = [ @$extend, $upper_owner ];
                }
            }
            $upper_owner = $owner;
            $upper_node  = $node;
            $extended{$owner}->{$node} = [ @$extend, @$extend_only ];
        }

        my $childs = $tree{$node} or return;
        if ($upper_owner) {
            if ($upper_owner->{extend_only}) {
                $extend_only = [ @$extend_only, $upper_owner ];
                $upper_owner = undef;
                $upper_node  = undef;
            }
        }
        for my $child (@$childs) {
            $inherit->($child, $upper_owner, $upper_node, $extend,
                $extend_only);
        }
    };
    for my $node (@root_nodes) {
        $inherit->($node, undef, undef, [], []);
    }

    # Collect extended owners and check for inconsistent extensions.
    # Check owner with attribute {show_all}.
    for my $owner (values %owners) {
        my $href = $extended{$owner} or next;
        my $node1;
        my $ext1;
        my $combined;
        for my $ref (keys %$href) {
            my $node = $ref2obj{$ref};
            my $ext = { map({ ($_, $_) } @{ $href->{$ref} || [] }) };
            if ($node1) {
                my $differ;
                if (keys %$ext != keys %$ext1) {
                    $differ = 1;
                }
                else {
                    for my $ref (keys %$ext) {
                        if (not $ext1->{$ref}) {
                            $differ = 1;
                            last;
                        }
                    }
                }
                if ($differ) {
                    if ($config{check_owner_extend}) {
                        warn_msg("$owner->{name} inherits inconsistently:",
                                 "\n - at $node1->{name}: ",
                                 join(', ', map { $_->{name} } values %$ext1),
                                 "\n - at $node->{name}: ",
                                 join(', ', map { $_->{name} } values %$ext));
                    }
                    $combined = { %$ext, %$combined };
                }
            }
            else {
                ($node1, $ext1) = ($node, $ext);
                $combined = $ext1;
            }
        }
        if (keys %$ext1) {
            $owner->{extended_by} = [ values %$combined ];
        }
        if ($owner->{show_all}) {
            if (@root_nodes == 1 && (my $root = $root_nodes[0])) {
                my $root_owner = $root->{owner} || '';
                if ($root_owner eq $owner && is_area($root)) {
                    if (@{ $root->{zones} } == @zones) {
                        next;
                    }
                }
            }
            err_msg("Attribute 'show_all' is only valid for owner of area",
                " which spans the whole topology.");
        }
    }

    # Handle {router_attributes}->{owner} separately.
    # Areas can be nested. Proceed from small to larger ones.
    for my $area (
        sort { @{ $a->{zones} } <=> @{ $b->{zones} } }
        grep { not $_->{disabled} } values %areas
      )
    {
        if ($area->{router_attributes}
            and (my $owner = $area->{router_attributes}->{owner}))
        {
            $owner->{is_used} = 1;
            for my $router (area_managed_routers($area)) {
                if (my $r_owner = $router->{owner}) {
                    if ($r_owner eq $owner) {
                        warn_msg(
                          "Useless $r_owner->{name} at $router->{name},\n",
                          " it was already inherited from $area->{name}");
                    }
                }
                else {
                    $router->{owner} = $owner;
                }
            }
        }
    }

    for my $router (@managed_routers) {
        my $owner = $router->{owner} or next;
        $owner->{is_used} = 1;
        for my $interface (@{ $router->{interfaces} }) {
            $interface->{owner} = $owner;
            if ($interface->{loopback}) {
                my $network = $interface->{network};
                $network->{owner} = $owner;
                $network->{zone}->{owner} = $owner;
            }
        }
    }

    # Inherit owner from enclosing network or zone to aggregate.
    for my $zone (@zones) {
        for my $aggregate (values %{ $zone->{ipmask2aggregate} }) {
            next if $aggregate->{owner};
            my $up = $aggregate;
            while ($up = $up->{up}) {
                last if !$up->{is_aggregate};
            }
            $aggregate->{owner} = ($up ? $up : $zone)->{owner};
        }
    }
    return;
}

sub expand_auto_intf {
    my ($src_aref, $dst_aref) = @_;
    for (my $i = 0 ; $i < @$src_aref ; $i++) {
        my $src = $src_aref->[$i];
        next if not is_autointerface($src);
        my @new;
        for my $dst (@$dst_aref) {
            push @new, Netspoc::path_auto_interfaces($src, $dst);
        }

        # Substitute auto interface by real interface.
        splice(@$src_aref, $i, 1, @new);
    }
    return;
}

my %unknown2services;
my %unknown2unknown;

sub show_unknown_owners {
    for my $polices (values %unknown2services) {
        $polices = join(',', sort @$polices);
    }
    my $print =
      $config{check_service_unknown_owner} eq 'warn'
      ? \&warn_msg
      : \&err_msg;
  UNKNOWN:
    for my $obj (values %unknown2unknown) {
        my $up = $obj;
        while ($up = $up->{up}) {
            if (    $unknown2services{$up}
                and $unknown2services{$obj} eq $unknown2services{$up})
            {
                next UNKNOWN;
            }
        }
        $print->("Unknown owner for $obj->{name} in $unknown2services{$obj}");
    }
    return;
}

sub set_service_owner {
    progress('Checking service owner');

    propagate_owners();

    for my $key (sort keys %services) {
        my $service = $services{$key};
        my $pname   = $service->{name};

        my $users = expand_group($service->{user}, "user of $pname");

        # Non 'user' objects.
        my @objects;

        # Check, if service contains a coupling rule with only "user" elements.
        my $is_coupling = 0;

        for my $rule (@{ $service->{rules} }) {
            my $has_user = $rule->{has_user};
            if ($has_user eq 'both') {
                $is_coupling = 1;
                next;
            }
            for my $what (qw(src dst)) {
                next if $what eq $has_user;
                push(@objects,
                    @{ expand_group($rule->{$what}, "$what of $pname") });
            }
        }

        # Expand auto interface to set of real interfaces.
        expand_auto_intf(\@objects, $users);
        expand_auto_intf($users,    \@objects);

        # Take elements of 'user' object, if service has coupling rule.
        if ($is_coupling) {
            push @objects, @$users;
        }

        # Collect service owners and unknown owners;
        my $service_owners;
        my $unknown_owners;

        for my $obj (unique @objects) {
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
            (keys %$service_owners == 1 && $service_owners->{$sub_owner}) and
                warn_msg("Useless $sub_owner->{name} at $service->{name}");
        }

        # Check for multiple owners.
        my $multi_count =
          $is_coupling
          ? 1
          : values %$service_owners;
        if ($multi_count > 1 xor $service->{multi_owner}) {
            if ($service->{multi_owner}) {
                warn_msg("Useless use of attribute 'multi_owner' at $pname");
            }
            else {
                my $print =
                    $config{check_service_multi_owner}
                  ? $config{check_service_multi_owner} eq 'warn'
                      ? \&warn_msg
                      : \&err_msg
                  : sub { };
                my @names =
                  sort(map { ($_->{name} =~ /^owner:(.*)/)[0] }
                      values %$service_owners);
                $print->("$pname has multiple owners:\n " . join(', ', @names));
            }
        }

        # Check for unknown owners.
        if (($unknown_owners and keys %$unknown_owners)
            xor $service->{unknown_owner})
        {
            if ($service->{unknown_owner}) {
                warn_msg("Useless use of attribute 'unknown_owner' at $pname");
            }
            else {
                if ($config{check_service_unknown_owner}) {
                    for my $obj (values %$unknown_owners) {
                        $unknown2unknown{$obj} = $obj;
                        push @{ $unknown2services{$obj} }, $pname;
                    }
                }
            }
        }
    }

    # Show unused owners.
    # Remove attribute {is_used}, which isn't needed any longer.
    for my $owner (values %owners) {
        delete $owner->{is_used} or warn_msg("Unused $owner->{name}");
    }

    show_unknown_owners();
    return;
}

##############################################################################
# Distribute NAT bindings
##############################################################################

# We assume that NAT for a single network is applied at most parts of
# the topology.
# No-NAT-set: a set of NAT tags which are not applied for other networks
# at current network.
# NAT Domain: a maximal area of our topology (a set of connected networks)
# where the no-NAT-set is identical at each network.
sub set_natdomain;

sub set_natdomain {
    my ($network, $domain, $in_interface) = @_;
    $network->{nat_domain} = $domain;

#    debug("$domain->{name}: $network->{name}");
    push @{ $domain->{networks} }, $network;
    my $no_nat_set = $domain->{no_nat_set};
    for my $interface (@{ $network->{interfaces} }) {

        # Ignore interface where we reached this network.
        next if $interface eq $in_interface;

        # Ignore interface with globally active pathrestriction
        # where all traffic goes through a VPN tunnel.
        next if check_global_active_pathrestriction($interface);
        my $router = $interface->{router};
        next if $router->{active_path};
        $router->{active_path} = 1;
        my $managed  = $router->{managed}     || $router->{semi_managed};
        my $nat_tags = $interface->{bind_nat} || $bind_nat0;
        for my $out_interface (@{ $router->{interfaces} }) {
            my $out_nat_tags = $out_interface->{bind_nat} || $bind_nat0;

            # Current NAT domain continues behind $out_interface.
            if (aref_eq($out_nat_tags, $nat_tags)) {

                # no_nat_set will be collected at NAT domains, but is needed at
                # logical and hardware interfaces of managed routers.
                # Set it also for semi_managed routers to calculate
                # {up} relation between subnets.
                if ($managed) {

#                   debug("$domain->{name}: $out_interface->{name}");
                    $out_interface->{no_nat_set} = $no_nat_set;
                    $out_interface->{hardware}->{no_nat_set} = $no_nat_set
                      if $router->{managed};
                }

                # Don't process interface where we reached this router.
                next if $out_interface eq $interface;
                next if check_global_active_pathrestriction($out_interface);

                my $next_net = $out_interface->{network};

                # Found a loop inside a NAT domain.
                next if $next_net->{nat_domain};

                set_natdomain $next_net, $domain, $out_interface;
            }

            # New NAT domain starts at some interface of current router.
            # Remember NAT tag of current domain.
            else {

                # If one router is connected to the same NAT domain
                # by different interfaces, all interfaces must have
                # the same NAT binding. (This occurs only in loops).
                if (my $old_nat_tags = $router->{nat_tags}->{$domain}) {
                    if (not aref_eq($old_nat_tags, $nat_tags)) {
                        my $old_names = join(',', @$old_nat_tags) || '(none)';
                        my $new_names = join(',', @$nat_tags)     || '(none)';
                        err_msg
                          "Inconsistent NAT in loop at $router->{name}:\n",
                          " nat:$old_names vs. nat:$new_names";
                    }

                    # NAT domain and router have been linked together already.
                    next;
                }
                $router->{nat_tags}->{$domain} = $nat_tags;
                push @{ $domain->{routers} },     $router;
                push @{ $router->{nat_domains} }, $domain;
            }
        }
        $router->{active_path} = 0;
    }
    return;
}

# Distribute no_nat_sets from NAT domain to NAT domain.
# Collect bound nat_tags in $nat_bound as
#  nat_tag => router->{name} => used
sub distribute_no_nat_set;

sub distribute_no_nat_set {
    my ($domain, $no_nat_set, $in_router, $nat_bound) = @_;

    if (not $no_nat_set or not keys %$no_nat_set) {

#        debug("Emtpy tags at $domain->{name}");
        return;
    }

#    my $tags = join(',',keys %$no_nat_set);
#    debug("distribute $tags to $domain->{name}"
#	   . ($in_router ? " from $in_router->{name}" : ''));
    if ($domain->{active_path}) {

#	debug("$domain->{name} loop");
        # Found a loop
        return;
    }

    my $changed;
    for my $tag (keys %$no_nat_set) {
        next if $domain->{no_nat_set}->{$tag};
        $domain->{no_nat_set}->{$tag} = $no_nat_set->{$tag};
        $changed = 1;
    }
    return if not $changed;

    # Activate loop detection.
    $domain->{active_path} = 1;

    # Distribute no_nat_set to adjacent NAT domains.
    for my $router (@{ $domain->{routers} }) {
        next if $router eq $in_router;
        my $in_nat_tags = $router->{nat_tags}->{$domain};

        for my $tag (@$in_nat_tags) {
            if (my $href = $no_nat_set->{$tag}) {
                my $net_name = (values %$href)[0]->{name};
                err_msg "$net_name is translated by $tag,\n",
                  " but is located inside the translation domain of $tag.\n",
                  " Probably $tag was bound to wrong interface",
                  " at $router->{name}.";
            }
        }
        for my $out_dom (@{ $router->{nat_domains} }) {
            next if $out_dom eq $domain;
            my %next_no_nat_set = %$no_nat_set;
            my $nat_tags        = $router->{nat_tags}->{$out_dom};
            if (@$nat_tags >= 2) {

                # href -> [nat_tag, ..]
                my %multi;
                for my $tag (@$nat_tags) {
                    if (keys %{ $next_no_nat_set{$tag} } >= 2) {
                        push @{ $multi{ $next_no_nat_set{$tag} } }, $tag;
                    }
                }
                if (keys %multi) {
                    for my $aref (values %multi) {
                        if (@$aref >= 2) {
                            my $tags = join(',', @$aref);
                            my $net_name =
                              (values %{ $next_no_nat_set{ $aref->[0] } })[0]
                              ->{name};
                            err_msg "Must not use multiple NAT tags '$tags'",
                              " of $net_name at $router->{name}";
                        }
                    }
                }
            }

            # NAT binding removes tag from no_nat_set.
            for my $nat_tag (@$nat_tags) {
                if (my $href = delete $next_no_nat_set{$nat_tag}) {
                    $nat_bound->{$nat_tag}->{ $router->{name} } = 'used';

                    # Add other tags again if one of a group of tags
                    # was removed.
                    if (keys %$href >= 2) {

                        for my $multi (keys %$href) {
                            next if $multi eq $nat_tag;
                            if (not $next_no_nat_set{$multi}) {
                                $next_no_nat_set{$multi} = $href;

                                # Prevent transition from dynamic back to
                                # static NAT for current network.
                                if ($href->{$multi}->{hidden}) {
                                    my $net_name = $href->{$multi}->{name};
                                    err_msg "Must not change hidden NAT",
                                      " for $net_name at $router->{name}";
                                }
                                elsif (    $href->{$multi}->{dynamic}
                                    and not $href->{$nat_tag}->{dynamic}
                                    and not $href->{$nat_tag}->{hidden})
                                {
                                    my $net_name = $href->{$multi}->{name};
                                    err_msg "Must not change NAT",
                                      " from dynamic to static",
                                      " for $net_name at $router->{name}";
                                }
                            }
                        }
                    }
                }
            }
            distribute_no_nat_set($out_dom, \%next_no_nat_set, $router,
                $nat_bound);
        }
    }
    delete $domain->{active_path};
    return;
}

my @natdomains;

sub keys_equal {
    my ($href1, $href2) = @_;
    keys %$href1 == keys %$href2 or return 0;
    for my $key (keys %$href1) {
        exists $href2->{$key} or return 0;
    }
    return 1;
}

sub distribute_nat_info {
    progress('Distributing NAT');

    # Initial value for each NAT domain, distributed by distribute_no_nat_set.
    my %no_nat_set;

    # A hash with all defined NAT tags as keys and a href as value.
    # The href has those NAT tags as keys which are used together at one
    # network.
    # This is used to check,
    # - that all bound NAT tags are defined,
    # - that NAT tags are equally used grouped or solitary.
    my %nat_tags2multi;

    # NAT tags bound at some interface, tag => router_name => (1 | 'used').
    my %nat_bound;

    # Find NAT domains.
    for my $network (@networks) {
        next if $network->{is_aggregate};
        my $domain = $network->{nat_domain};
        if (not $domain) {
            (my $name = $network->{name}) =~ s/^\w+:/nat_domain:/;

#	    debug("$name");
            $domain = new(
                'nat_domain',
                name       => $name,
                networks   => [],
                routers    => [],
                no_nat_set => {},
            );
            push @natdomains, $domain;
            set_natdomain $network, $domain, 0;
        }

#	debug("$domain->{name}: $network->{name}");

        # Collect all NAT tags defined inside one NAT domain.
        # Check consistency of grouped NAT tags at one network.
        # If NAT tags are grouped at one network,
        # the same NAT tags must be used as group at all other networks.
        if (my $href = $network->{nat}) {

            # Print error message only once per network.
            my $err;
            for my $nat_tag (keys %$href) {
                if (my $href2 = $nat_tags2multi{$nat_tag}) {
                    if (not $err and not keys_equal($href, $href2)) {
                        my $tags  = join(',', keys %$href);
                        my $name  = $network->{name};
                        my $tags2 = join(',', keys %$href2);

                        # Use hash as list of pairs, take first value.
                        # Value is a NAT entry with name of the network.
                        my $name2 = (%$href2)[1]->{name};
                        err_msg
                          "If multiple NAT tags are used at one network,\n",
                          " these NAT tags must also be used together at",
                          " other networks:\n", 
                          " - $name: $tags\n",
                          " - $name2: $tags2";
                        $err = 1;
                    }
                }
                else {
                    $nat_tags2multi{$nat_tag} = $href;
                }

#		debug("$domain->{name} no_nat_set: $nat_tag");
                $no_nat_set{$domain}->{$nat_tag} = $href;
            }
        }
    }

    # Find all bound nat_tags for error checks.
    my %dom_routers;
    for my $domain (@natdomains) {
        for my $router (@{ $domain->{routers} }) {
            $dom_routers{$router} = $router;
        }
    }
    for my $router (values %dom_routers) {
        for my $domain (@{ $router->{nat_domains} }) {
            my $nat_tags = $router->{nat_tags}->{$domain};
            for my $tag (@$nat_tags) {
                $nat_bound{$tag}->{ $router->{name} } = 1;
            }
        }
    }

    # Distribute no_nat_set to neighbor NAT domains.
    for my $domain (@natdomains) {
        distribute_no_nat_set($domain, $no_nat_set{$domain}, 0, \%nat_bound);
    }

    # Check compatibility of host/interface and network NAT.
    # A NAT definition for a single host/interface is only allowed,
    # if the network has a dynamic NAT definition.
    for my $network (@networks) {
        for my $obj (@{ $network->{hosts} }, @{ $network->{interfaces} }) {
            if ($obj->{nat}) {
                for my $nat_tag (keys %{ $obj->{nat} }) {
                    my $nat_info;
                    if (    $nat_info = $network->{nat}->{$nat_tag}
                        and $nat_info->{dynamic})
                    {
                        my $obj_ip = $obj->{nat}->{$nat_tag};
                        my ($ip, $mask) = @{$nat_info}{ 'ip', 'mask' };
                        if (not(match_ip($obj_ip, $ip, $mask))) {
                            err_msg "nat:$nat_tag: $obj->{name}'s IP ",
                              "doesn't match $network->{name}'s IP/mask";
                        }
                    }
                    else {
                        err_msg "nat:$nat_tag not allowed for ",
                          "$obj->{name} because $network->{name} ",
                          "doesn't have dynamic NAT definition";
                    }
                }
            }
        }
    }
    for my $tag (keys %nat_tags2multi) {
        $nat_bound{$tag}
          or warn_msg("nat:$tag is defined, but not bound to any interface");
    }
    for my $tag (keys %nat_bound) {
        my $href = $nat_bound{$tag};
        for my $router_name (keys %$href) {
            $href->{$router_name} eq 'used'
              or warn_msg("Ignoring useless nat:$tag bound at $router_name");
        }
    }
    return;
}

####################################################################
# Find sub-networks
# Mark each network with the smallest network enclosing it.
####################################################################

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

# All interfaces and hosts of a network must be located in that part
# of the network which doesn't overlap with some subnet.
sub check_subnets {
    my ($network, $subnet)   = @_;
    return if $network->{is_aggregate} || $subnet->{is_aggregate};
    my ($sub_ip,  $sub_mask) = @{$subnet}{qw(ip mask)};
    my $check = sub {
        my ($ip1, $ip2, $object) = @_;
        if (
            match_ip($ip1, $sub_ip, $sub_mask)
            || $ip2 && (match_ip($ip2, $sub_ip, $sub_mask)
                || ($ip1 <= $sub_ip && $sub_ip <= $ip2))
          )
        {

            # NAT to an interface address (masquerading) is allowed.
            if (    (my $nat_tags = $object->{bind_nat})
                and (my ($nat_tag2) = ($subnet->{name} =~ /^nat:(.*)\(/)))
            {
                if (    grep { $_ eq $nat_tag2 } @$nat_tags
                    and $object->{ip} == $subnet->{ip}
                    and $subnet->{mask} == 0xffffffff)
                {
                    return;
                }
            }
            warn_msg("$object->{name}'s IP overlaps with subnet",
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
    return;
}

# Dynamic NAT to loopback interface is OK,
# if NAT is applied at device of loopback interface.
sub nat_to_loopback_ok {
    my ($loopback_network, $nat_network) = @_;

    my $nat_tag1      = $nat_network->{dynamic};
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

sub numerically { return $a <=> $b }
sub by_name     { return $a->{name} cmp $b->{name} }

sub link_reroute_permit;

# Compatibilty for export.pl of NetspocWeb
sub find_subnets {
    find_subnets_in_zone();
    return;
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
        my @no_nat_sets = 
            unique map { $_->{no_nat_set} } @{ $zone->{interfaces} };

        # Add networks of zone to %mask_ip_hash.
        my %mask_ip_hash;

        # A networks has different NAT addresses inside the zone.
        my %net2nat_count;

        # Found that many subnet relations.
        my %net2up_count;

        for my $network (@{ $zone->{networks} }, 
                         values %{ $zone->{ipmask2aggregate} }) 
        {
            next if $network->{ip} =~ /^(?:unnumbered|tunnel)$/;

            my @nat_networks = 
                unique map { get_nat_network($network, $_) } @no_nat_sets;
            if (@nat_networks > 1) {
                $net2nat_count{$network} = @nat_networks;
            }
            for my $nat_network (@nat_networks) {
                next if $nat_network->{hidden};
                my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };

                # Found two different networks with identical IP/mask.
                if (my $other_net = $mask_ip_hash{$mask}->{$ip}) {

                    # Different no_nat_sets map to the same network.
                    if ($other_net eq $network) {
                        $net2nat_count{$network}--;
                        if (1 == $net2nat_count{$network}) {
                            delete $net2nat_count{$network};
                        }
                        next;
                    }
                    my $name1 = $network->{name};
                    my $name2 = $other_net->{name};
                    err_msg("$name1 and $name2 have identical IP/mask",
                            " inside $zone->{name}");
                }
                else {

                    # Store network under IP/mask.
                    $mask_ip_hash{$mask}->{$ip} = $network;
                }
            }
        }

        # Compare networks of zone.
        # Go from smaller to larger networks.
        for my $mask (reverse sort keys %mask_ip_hash) {

            # Network 0.0.0.0/0.0.0.0 can't be subnet.
            last if $mask == 0;

            for my $ip (sort numerically keys %{ $mask_ip_hash{$mask} }) {

                my $subnet = $mask_ip_hash{$mask}->{$ip};

                # Find networks which include current subnet.
                my $m = $mask;
                my $i = $ip;
                while ($m) {

                    # Clear upper bit, because left shift is undefined
                    # otherwise.
                    $m &= 0x7fffffff;
                    $m <<= 1;
                    $i = $i & $m;  # Perl bug #108480 prevents use of "&=".
                    my $bignet = $mask_ip_hash{$m}->{$i};
                    next if not $bignet;

                    if ($net2nat_count{$subnet}) {
                        $net2up_count{$subnet}++;
                    }

                    # Check for ambiguous subnet relation of network
                    # with different NAT addresses.
                    if (my $other = $subnet->{up}) {
                        if ($other ne $bignet) {
                            err_msg("Ambiguous subnet relation from NAT.\n",
                                    " $subnet->{name} is subnet of",
                                    " $other->{name} and $bignet->{name}");
                        }
                        last;                        
                    }

                    $subnet->{up} = $bignet;
#                    debug "$subnet->{name} -up-> $bignet->{name}";
                    push(
                        @{ $bignet->{networks} },
                        $subnet->{is_aggregate}
                        ? @{ $subnet->{networks} || [] }
                        : ($subnet)
                        );

                    check_subnets($bignet, $subnet);

                    # We only need to find the smallest enclosing network.
                    last;
                }
            }
        }

        # Check for ambiguous subnet relation.
        for my $net_hash (keys %net2nat_count) {
            my $up_count = $net2up_count{$net_hash};
            next if ! $up_count;
            my $nat_count = $net2nat_count{$net_hash};
            next if $up_count == $nat_count;

            # Find original network from hash.
            my ($network) = grep({ $_ eq $net_hash } 
                                 @{ $zone->{networks} }, 
                                 values %{ $zone->{ipmask2aggregate} });

            my $bignet = $network->{up};
            err_msg("Ambiguous subnet relation from NAT.\n",
                    " $network->{name} is subnet of $bignet->{name},\n",
                    " but has no subnet relation in other NAT domain.");
        }

        # For each subnet N find the largest non-aggregate network
        # which encloses N. If one exists, store it in
        # {max_up_net}. This is used in secondary optimization.
        my $set_max_net;
        $set_max_net = sub {
            my ($network) = @_;
            return if not $network;
            if (my $max_net = $network->{max_up_net}) {
                return $max_net;
            }
            if (my $max_net = $set_max_net->($network->{up})) {
                if (!$network->{is_aggregate}) {
                    $network->{max_up_net} = $max_net;

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

        # Remove subnets of non-aggregate networks.
        $zone->{networks} = 
            [ grep { !$_->{max_up_net} } @{ $zone->{networks} } ];
    }

    # It is valid to have an aggregate in a zone which has no matching
    # networks. This can be useful to add optimization rules at an
    # intermediate device.

    # Call late after $zone->{networks} has been set up.
    link_reroute_permit();
    check_managed_local();
    return;
}

# Find subnet relation inside a NAT domain.
# - $subnet->{is_in}->{$no_nat_set} = $bignet;
# - $net1->{is_identical}->{$no_nat_set} = $net2
#
# Mark networks, having subnet in other zone: $bignet->{has_other_subnet}
# If set, this prevents secondary optimization.
sub find_subnets_in_nat_domain {
    progress('Finding subnets in NAT domain');
    my %seen;

    for my $domain (@natdomains) {

#     debug("$domain->{name}");
        my $no_nat_set = $domain->{no_nat_set};
        my %mask_ip_hash;
        my %identical;
        for my $network (@networks) {
            next if $network->{ip} =~ /^(?:unnumbered|tunnel)$/;
            my $nat_network = get_nat_network($network, $no_nat_set);
            next if $nat_network->{hidden};
            my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };

            # Found two different networks with identical IP/mask.
            # in current NAT domain.
            if (my $old_net = $mask_ip_hash{$mask}->{$ip}) {
                my $nat_old_net = get_nat_network($old_net, $no_nat_set);
                my $error;
                if ($old_net->{is_aggregate} || $network->{is_aggregate}) {
                    if ($old_net->{zone} eq $network->{zone}) {
                        $error = 1;
                    }
                    else {
                        if (!$old_net->{is_aggregate}) {

                            # This network has aggregate (with
                            # subnets) in other zone. Hence this
                            # network must not be used in secondary
                            # optimization.
                            $old_net->{has_other_subnet} = 1;
                        }
                        elsif (!$network->{is_aggregate}) {
                            $network->{has_other_subnet} = 1;
                        }
                    }
                }
                elsif ($nat_old_net->{dynamic} and $nat_network->{dynamic}) {

                    # Dynamic NAT of different networks
                    # to a single new IP/mask is OK.
                }
                elsif ($old_net->{loopback} and $nat_network->{dynamic}) {
                    nat_to_loopback_ok($old_net, $nat_network) or $error = 1;
                }
                elsif ($nat_old_net->{dynamic} and $network->{loopback}) {
                    nat_to_loopback_ok($network, $nat_old_net) or $error = 1;
                }
                elsif (($network->{bridged} || 0) eq ($old_net->{bridged} || 1))
                {

                    # Parts of bridged network have identical IP by design.
                }
                else {
                    $error = 1;
                }
                if ($error) {
                    my $name1 = $nat_network->{name};
                    my $name2 = $nat_old_net->{name};
                    err_msg("$name1 and $name2 have identical IP/mask");
                }
                else {

                    # Remember identical networks.
                    $identical{$old_net} ||= [$old_net];
                    push @{ $identical{$old_net} }, $network;
                }
            }
            else {

                # Store original network under NAT IP/mask.
                $mask_ip_hash{$mask}->{$ip} = $network;
            }
        }

        # Link identical networks to one representative one.
        for my $networks (values %identical) {
            $_->{is_supernet} = 1 for @$networks;
            my $one_net = shift(@$networks);
            for my $network (@$networks) {
                $network->{is_identical}->{$no_nat_set} = $one_net;
#               debug("Identical: $network->{name}: $one_net->{name}");
            }
        }


        # Go from smaller to larger networks.
        for my $mask (reverse sort keys %mask_ip_hash) {

            # Network 0.0.0.0/0.0.0.0 can't be subnet.
            last if $mask == 0;

            for my $ip (sort numerically keys %{ $mask_ip_hash{$mask} }) {

                my $subnet0 = $mask_ip_hash{$mask}->{$ip};
                for my $subnet ($subnet0, @{ $identical{$subnet0} }) {

                    # Find networks which include current subnet.
                    my $m = $mask;
                    my $i = $ip;
                    while ($m) {

                        # Clear upper bit, because left shift is undefined
                        # otherwise.
                        $m &= 0x7fffffff;
                        $m <<= 1;
                        $i = $i & $m;  # Perl bug #108480 prevents use of "&=".
                        my $bignet = $mask_ip_hash{$m}->{$i};
                        next if not $bignet;

                        my $nat_subnet = get_nat_network($subnet, $no_nat_set);
                        my $nat_bignet = get_nat_network($bignet, $no_nat_set);

                        # Mark subnet relation.
                        # This may differ for different NAT domains.
                        $subnet->{is_in}->{$no_nat_set} = $bignet;
#                        debug "$subnet->{name} -is_in-> $bignet->{name}";

                        if ($bignet->{zone} eq $subnet->{zone}) {
                            if ($subnet->{has_other_subnet}) {
#                                debug "has other1: $bignet->{name}";
                                $bignet->{has_other_subnet} = 1;
                            }
                        }
                        else {
#                            debug "has other: $bignet->{name}";
                            $bignet->{has_other_subnet} = 1;
                        }

                        # Mark network having subnets.  Rules having
                        # src or dst with subnets are collected into
                        # $expanded_rules->{supernet}
                        $bignet->{is_supernet} = 1;

                        if ($seen{$nat_bignet}->{$nat_subnet}) {
                            last;
                        }
                        $seen{$nat_bignet}->{$nat_subnet} = 1;

                        if ($config{check_subnets}) {

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

                                # Prevent multiple error messages in different
                                # NAT domains.
                                $nat_subnet->{subnet_of} = $bignet;

                                my $msg =
                                    "$nat_subnet->{name} is subnet of"
                                  . " $nat_bignet->{name}\n"
                                  . " if desired, either declare attribute"
                                  . " 'subnet_of' or attribute 'has_subnets'";

                                if ($config{check_subnets} eq 'warn') {
                                    warn_msg($msg);
                                }
                                else {
                                    err_msg($msg);
                                }
                            }
                        }

                        check_subnets($nat_bignet, $nat_subnet);
                        last;
                    }
                }
            }
        }
    }
    return;
}

sub check_no_in_acl  {

    # Propagate attribute 'no_in_acl' from zones to interfaces.
    for my $zone (@zones) {
        next if not $zone->{no_in_acl};

#	debug("$zone->{name} has attribute 'no_in_acl'");
        for my $interface (@{ $zone->{interfaces} }) {

            # Ignore secondary interface.
            next if $interface->{main_interface};

            my $router = $interface->{router};

            # Directly attached attribute 'no_in_acl' or
            # attribute 'std_in_acl' at device overrides.
            if ($router->{std_in_acl}
                or grep({ $_->{no_in_acl} and not ref $_->{no_in_acl} }
                    @{ $router->{interfaces} }))
            {
                next;
            }
            $interface->{no_in_acl} = $zone;
        }
    }

    # Move attribute 'no_in_acl' to hardware interface
    # because ACLs operate on hardware, not on logic.
    for my $router (@managed_routers) {

        # At most one interface with 'no_in_acl' allowed.
        # Move attribute to hardware interface.
        my $counter = 0;
        for my $interface (@{ $router->{interfaces} }) {
            if (delete $interface->{no_in_acl}) {
                my $hardware = $interface->{hardware};
                $hardware->{no_in_acl} = 1;

                # Ignore secondary interface.
                1 ==
                  grep(
                    { not $_->{main_interface} } @{ $hardware->{interfaces} })
                  or err_msg
                  "Only one logical interface allowed at $hardware->{name}",
                  " because it has attribute 'no_in_acl'";
                $counter++;
                $router->{no_in_acl} = $interface;
            }
        }
        next if not $counter;
        $counter == 1
          or err_msg "At most one interface of $router->{name}",
          " may use flag 'no_in_acl'";
        $router->{model}->{has_out_acl}
          or err_msg("$router->{name} doesn't support outgoing ACL");

        if (grep { $_->{hub} or $_->{spoke} } @{ $router->{interfaces} }) {
            err_msg "Don't use attribute 'no_in_acl' together",
              " with crypto tunnel at $router->{name}";
        }

        # Mark other hardware with attribute 'need_out_acl'.
        for my $hardware (@{ $router->{hardware} }) {
            $hardware->{no_in_acl}
              or $hardware->{need_out_acl} = 1;
        }
    }
    return;
}

# This uses attributes from sub check_no_in_acl.
sub check_crosslink  {

    # Collect cluster of routers connected by crosslink networks,
    # but only for Cisco routers having attribute "need_protect".
    my %crosslink_routers;

    for my $network (values %networks) {
        next if not $network->{crosslink};
        next if $network->{disabled};

        # A crosslink network combines two or more routers
        # to one virtual router.
        # No filtering occurs at the crosslink interfaces.
        my @managed_type;
        my $out_acl_count = 0;
        my @no_in_acl_intf;
        for my $interface (@{ $network->{interfaces} }) {
            my $router = $interface->{router};
            if (my $managed = $router->{managed}) {
                push @managed_type, $managed;
                if ($router->{model}->{need_protect}) {
                    $crosslink_routers{$router} = $router;
                }
            }
            else {
                err_msg "Crosslink $network->{name} must not be",
                  "connected to unmanged $router->{name}";
                next;
            }
            my $hardware = $interface->{hardware};
            @{ $hardware->{interfaces} } == 1
              or err_msg
              "Crosslink $network->{name} must be the only network\n",
              " connected to $hardware->{name} of $router->{name}";
            if ($hardware->{need_out_acl}) {
                $out_acl_count++;
            }
            push @no_in_acl_intf,
              grep({ $_->{hardware}->{no_in_acl} } @{ $router->{interfaces} });
            $hardware->{crosslink} = 1;
        }

        # Ensure clear responsibility for filtering.
        equal(@managed_type)
          or err_msg "All devices at crosslink $network->{name}",
          " must have identical managed type";

        not $out_acl_count
          or $out_acl_count == @{ $network->{interfaces} }
          or err_msg "All interfaces must equally use or not use outgoing ACLs",
          " at crosslink $network->{name}";
        equal(map { $_->{zone} } @no_in_acl_intf)
          or err_msg "All interfaces with attribute 'no_in_acl'",
          " at routers connected by\n crosslink $network->{name}",
          " must be border of the same security zone";
    }

    # Find clusters of routers connected directly or indirectly by
    # crosslink networks.
    my %cluster;
    my %seen;
    my $walk;
    $walk = sub {
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
                $walk->($router2);
            }
        }
    };

    # Collect all interfaces of cluster and add to each cluster member
    # - as list used in "protect own interfaces"
    # - as hash used in fast lookup in distribute_rule and "protect ..".
    for my $router (values %crosslink_routers) {
        next if $seen{$router};
        %cluster = ();
        $walk->($router);
        my @crosslink_interfaces =
          map { @{ $_->{interfaces} } }

          # Sort by router name to make output deterministic.
          sort by_name values %cluster;
        my %crosslink_intf_hash = map { $_ => $_ } @crosslink_interfaces;
        for my $router2 (values %cluster) {
            $router2->{crosslink_interfaces} = \@crosslink_interfaces;
            $router2->{crosslink_intf_hash}  = \%crosslink_intf_hash;
        }
    }
    return;
}

sub check_managed_local {
    my %seen;
    for my $router (@managed_routers) {
        $router->{managed} eq 'local' or next;
        next if $seen{$router};

        # Networks of current cluster matching {filter_only}.
        my %matched;

        my $walk;
        $walk = sub {
            my ($router) = @_;
            my $filter_only = $router->{filter_only};
            my $k;
            $seen{$router} = $router;
            for my $in_intf (@{ $router->{interfaces} }) {
                my $no_nat_set = $in_intf->{no_nat_set};
                my $zone0 = $in_intf->{zone};
                my $cluster = $zone0->{zone_cluster};
                for my $zone ($cluster ? @$cluster : ($zone0)) {
                    next if $zone->{disabled};
                    next if $seen{$zone};

                    # All networks in local zone must match {filter_only}.
                  NETWORK:
                    for my $network (@{ $zone->{networks} }, 
                                     values %{ $zone->{ipmask2aggregate} }) 
                    {
                        # Crosslink network won't be used in any rule.
                        next if $network->{crosslink};
                        my ($ip, $mask) = @{ address($network, $no_nat_set) };

                        # Ignore aggregate 0/0 which is available in
                        # every zone.
                        next if $mask == 0 && $network->{is_aggregate};
                        for my $pair (@$filter_only) {
                            my ($i, $m) = @$pair;
                            if ($mask >= $m && match_ip($ip, $i, $m)) {
                                $matched{"$i/$m"} = 1;
                                next NETWORK;
                            }
                        }
                        err_msg("$network->{name} doesn't match attribute",
                                " 'filter_only' of $router->{name}");
                    }
                    $seen{$zone} = $zone;
                    for my $out_intf (@{ $zone->{interfaces} }) {
                        next if $out_intf eq $in_intf;
                        my $router2 = $out_intf->{router};
                        next if not $router2->{managed};
                        next if not $router2->{managed} eq 'local';
                        next if $seen{$router2};

                        # All routers of a cluster must have same values in
                        # {filter_only}.
                        $k ||= join(',', map({ join('/', @$_) } 
                                             @$filter_only));
                        my $k2 = join(',', map({ join('/', @$_) } 
                                               @{ $router2->{filter_only} }));
                        $k2 eq $k or 
                            err_msg("$router->{name} and $router2->{name}",
                                    " must have identical values in",
                                    " attribute 'filter_only'");

                        $walk->($router2);
                    }
                }
            }
        };

        $walk->($router);

        for my $pair (@{ $router->{filter_only} }) {
            my ($i, $m) = @$pair;
            $matched{"$i/$m"} and next;
            my $ip = print_ip($i);
            my $prefix = mask2prefix($m);
            warn_msg("Useless $ip/$prefix in attribute 'filter_only'",
                     " of $router->{name}");
        }
    }
    return;
}

# group of reroute_permit networks must be expanded late, after areas,
# aggregates and subnets have been set up. Otherwise automatic groups
# wouldn't work.
#
# Reroute permit is not allowed between different security zones.
sub link_reroute_permit {
    for my $zone (@zones) {
        for my $interface (@{ $zone->{interfaces} }) {
            my $group = $interface->{reroute_permit} or next;
            $group =
              expand_group($group, "'reroute_permit' of $interface->{name}");
            my @checked;
            for my $obj (@$group) {
                if (is_network($obj)) {
                    my $net_zone = $obj->{zone};
                    if (!zone_eq($net_zone, $zone)) {
                        err_msg("Invalid reroute_permit for $obj->{name} ",
                                "at $interface->{name}:",
                                " different security zones");
                    }
                    else {
                        push @checked, $obj;
                    }
                }
                else {
                    err_msg("$obj->{name} not allowed in attribute",
                            " 'reroute_permit' of $interface->{name}");
                }
            }
            $interface->{reroute_permit} = \@checked;
        }
    }  
    return;  
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

sub link_aggregate_to_zone {
    my ($aggregate, $zone, $key) = @_;

    # Link aggregate with zone.
    $aggregate->{zone} = $zone;
    $zone->{ipmask2aggregate}->{$key} = $aggregate;

    # Must be initialized, even if aggregate contains no networks.
    # Take a new array for each aggregate, otherwise we would share
    # the same array between different aggregates.
    $aggregate->{networks} ||= [];

    if ($zone->{disabled}) {
        $aggregate->{disabled} = 1;
    }
    else {
        push @networks, $aggregate;
    }
    return;
}

# Update relations {networks} and {up} for implicitly defined aggregates.
sub link_implicit_aggregate_to_zone {
    my ($aggregate, $zone, $key) = @_;
    my ($ip, $mask) = split '/', $key;

    my $update_agg_relation = sub {

        # All aggregates without any sub networks.
        my @other_agg = grep({ my $n = $_->{networks}; !$n || !@$n; } 
                             values %{ $zone->{ipmask2aggregate} });

        # Aggregates which are subnet of new aggregate.
        my @sub_agg = grep({ $mask < $_->{mask} && 
                                 match_ip($_->{ip}, $ip, $mask) } @other_agg);
        return if !@sub_agg;

        # Sort by mask to find some largest subnet.
        my @sorted = sort { $a->{mask} <=> $b->{mask} } @sub_agg;
        my ($largest) = @sorted;

        # Find all subnets pointing to the same larger element.
        # Thus we exclude all sub-subnets.
        my $up = $largest->{up} || '';
        my @direct_sub = grep { $_->{up} || '' eq $up } @sorted;
        $aggregate->{up} = $up if $up;
        $_->{up} = $aggregate for @direct_sub;
        return;
    };
    my $update_relation;
    $update_relation = sub {
        my ($networks) = @_;
        my $found;
      NETWORK:
        for my $network (@$networks) {
            my ($i, $m) = @{$network}{qw(ip mask)};

            # Network is subnet of aggregate.
            if ($mask < $m && match_ip($i, $ip, $mask)) {
                $found = 1;
                push @{ $aggregate->{networks} }, $network;

                # Other aggregate where network is subnet.
                my $up = $network->{up};

                # Network isn't subnet of any other aggregate.
                if (! $up) {
                    $network->{up} = $aggregate;
                    next NETWORK;
                }
            
                my ($u_ip, $u_mask) = @{$up}{qw(ip mask)};

                # New aggregate is subnet of other aggregate.
                if ($u_mask < $mask && match_ip($ip, $u_ip, $u_mask)) {
                    $aggregate->{up} = $up;
                    $network->{up} = $aggregate;
                    next NETWORK;
                }

                # Other aggregate is subnet of new aggregate.
                # Find largest {up}, still contained in new aggregate.
                my $up2;
                while($up2 = $up->{up}) {

                    # Aggregate has already been inserted before, 
                    # when processing some other network of zone.
                    if ($up2 eq $aggregate) {
                        next NETWORK;
                    }
                    my ($u2_ip, $u2_mask) = @{$up2}{qw(ip mask)};
                    if ($mask < $u2_mask && match_ip($u2_ip, $ip, $mask)) {
                        $up = $up2;
                        next;
                    }
                    last;
                }
                $aggregate->{up} = $up2 if $up2;
                $up->{up} = $aggregate;
            }

            # Aggregate is subnet of network.
            # Check sub-networks of network.
            elsif ($m < $mask && match_ip($ip, $i, $m)) {
                $found = 1;
                my $sub_networks = $network->{networks};
                if ($sub_networks && @$sub_networks) {
                    $update_relation->($sub_networks);
                }
                else {
                    $update_agg_relation->();
                    $aggregate->{up} ||= $network;
                }

                # No need to check other networks, because aggregate
                # can't be subnet of multiple networks.
                last NETWORK;
            }
        }

        # Aggregate doesn't match any network.
        # Check if other aggregate matches new aggregate.
        if (! $found) {
            $update_agg_relation->();
        }
    };
    my $set_owner = sub {
        my $up = $aggregate->{up};
        my $owner;
        while ($up) {
            $owner = $up->{owner} and last;
            $up = $up->{up};
        }
        $owner ||= $zone->{owner};
        $aggregate->{owner} = $owner;
    };
    $update_relation->($zone->{networks});
    $set_owner->();
    link_aggregate_to_zone($aggregate, $zone, $key);
    return;
}

# Link aggregate to zone.  This is called late, after zones and NAT
# domains have been set up. But before find_subnets_in_zone calculates
# {up} and {networks} relation.
sub link_aggregates {
    my @aggregates_in_cluster;
    for my $key (sort keys %aggregates) {
        my $aggregate = $aggregates{$key};
        my $private1 = $aggregate->{private} || 'public';
        my $private2;
        my ($type, $name) = @{ delete($aggregate->{link}) };
        my $err;
        my $router;
        my $zone;
      BLOCK:
        {
            if ($type eq 'network') {
                my $network = $networks{$name};
                if (not $network) {
                    $err = "Referencing undefined $type:$name"
                      . " from $aggregate->{name}";
                    last BLOCK;
                }
                if ($network->{disabled}) {
                    $aggregate->{disabled} = 1;
                    next;
                }
                $private2 = $network->{private};
                $zone     = $network->{zone};

            }
            elsif ($type eq 'router') {
                $router = $routers{$name};
                if (not $router) {
                    $err = "Referencing undefined $type:$name"
                      . " from $aggregate->{name}";
                    last BLOCK;
                }
                if ($router->{disabled}) {
                    $aggregate->{disabled} = 1;
                    next;
                }
                if ($router->{managed}) {
                    $err = "$aggregate->{name} must not be linked to"
                      . " managed $router->{name}";
                    last BLOCK;
                }
                if ($router->{semi_managed}) {
                    $err = "$aggregate->{name} must not be linked to"
                      . " $router->{name} with pathrestriction";
                    last BLOCK;
                }
                if (!$router->{interfaces}) {
                    err_msg "$aggregate->{name} must not be linked to",
                      " $router->{name} without interfaces";
                    last BLOCK;
                }
                $private2 = $router->{private};
                $zone     = $router->{interfaces}->[0]->{network}->{zone};
            }
            else {
                $err = "$aggregate->{name} must not be linked to $type:$name";
                last BLOCK;
            }
            $private2 ||= 'public';
            $private1 eq $private2
              or err_msg "$private1 $aggregate->{name} must not be linked",
              " to $private2 $type:$name";

            my ($ip, $mask) = @{$aggregate}{qw(ip mask)};
            my $key = "$ip/$mask";

            my $cluster = $zone->{zone_cluster};
            for my $zone2 ($cluster ? @$cluster : ($zone)) {
                if (my $other = $zone2->{ipmask2aggregate}->{$key}) {
                    err_msg
                      "Duplicate $other->{name} and $aggregate->{name}",
                      " in $zone->{name}";
                }
            }
            if ($cluster) {
                push(@aggregates_in_cluster, $aggregate);
            }

            # Aggregate with ip 0/0 is used to set attributes of zone.
            if ($mask == 0) {
                for my $zone2 ($cluster ? @$cluster : ($zone)) {
                    for my $attr (qw(owner no_in_acl has_unenforceable)) {
                        if ($aggregate->{$attr}) {
                            $zone2->{$attr} = $aggregate->{$attr};
                        }
                    }
                }
            }
            link_aggregate_to_zone($aggregate, $zone, $key);
        }
        if ($err) {
            err_msg($err);
            $aggregate->{disabled} = 1;
        }
    }
    for my $aggregate (@aggregates_in_cluster) {
        duplicate_aggregate_to_cluster($aggregate);
    }
    return;
}

# Duplicate aggregate to all zones of a cluster.
# Aggregate may be a non aggregate network, 
# e.g. a network with ip/mask 0/0.
sub duplicate_aggregate_to_cluster {
    my ($aggregate, $implicit) = @_;

    my $cluster = $aggregate->{zone}->{zone_cluster};
    my ($ip, $mask) = @{$aggregate}{qw(ip mask)};
    my $key = "$ip/$mask";
    for my $zone (@$cluster) {
        next if $zone->{ipmask2aggregate}->{$key};
#        debug("Dupl. $aggregate->{name} to $zone->{name}");
        my $aggregate2 = new(
            'Network',
            name         => $aggregate->{name},
            is_aggregate => 1,
            ip           => $aggregate->{ip},
            mask         => $aggregate->{mask},
            );
        if ($implicit) {
            link_implicit_aggregate_to_zone($aggregate2, $zone, $key);
        }
        else {
            link_aggregate_to_zone($aggregate2, $zone, $key);
        }
    }
    return;
}

# Find aggregate referenced from any:[..].
# Creates new anonymous aggregate if missing.
# If zone is part of a zone_cluster,
# return aggregates for each zone of the cluster.
sub get_any {
    my ($zone, $ip, $mask) = @_;
    my $key = "$ip/$mask";
    my $cluster = $zone->{zone_cluster};
    if (!$zone->{ipmask2aggregate}->{$key}) {

        # Check, if there is a network with same IP as the requested
        # aggregate.  If found, don't create a new aggregate in zone,
        # but use the network instead. Otherwise {up} relation
        # wouldn't be well defined.
        if (my @networks = grep({ $_->{mask} == $mask && $_->{ip} == $ip } 
                                map { @{ $_->{networks} } }
                                $cluster ? @$cluster : ($zone)))
        {
            @networks > 1 and internal_err;
            my ($network) = @networks;
            my $zone2 = $network->{zone};

            # Handle $network like an aggregate.
            $zone2->{ipmask2aggregate}->{$key} = $network;

            # Create aggregates in cluster, using the name of the network.
            duplicate_aggregate_to_cluster($network, 1) if $cluster;
        }
        else {

            # any:[network:x] => any:[ip=i.i.i.i/pp & network:x]
            my $p_ip = print_ip($ip);
            my $prefix = mask2prefix($mask);
            my $name = $zone->{name};
            $name =~ s/\[/[ip=$p_ip\/$prefix & / if $prefix != 0;
            my $aggregate = new(
                'Network',
                name         => $name,
                is_aggregate => 1,
                ip           => $ip,
                mask         => $mask,
                );
            link_implicit_aggregate_to_zone($aggregate, $zone, $key);
            duplicate_aggregate_to_cluster($aggregate, 1) if $cluster;
        };
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
    my $key = "$ip/$mask";
    return 
        map { $_->{ipmask2aggregate}->{$key}||() } @{ $zone->{zone_cluster} };
}

sub set_zone1 {
    my ($network, $zone, $in_interface) = @_;
    if ($network->{zone}) {

        # Found a loop inside a zone.
        return;
    }
    $network->{zone} = $zone;

#    debug("$network->{name} in $zone->{name}");

    # Add network to the zone, to have all networks of a security zone
    # available.  Unnumbered or tunnel network is left out here
    # because it isn't valid src or dst.  Loopback network must be
    # preserved because it is needed for routing.
    if (not($network->{ip} =~ /^(?:unnumbered|tunnel)$/)) {
        push @{ $zone->{networks} }, $network;
    }
    for my $interface (@{ $network->{interfaces} }) {

        # Ignore interface where we reached this network.
        next if $interface eq $in_interface;
        my $router = $interface->{router};
        if ($router->{managed} or $router->{semi_managed}) {
            $interface->{zone} = $zone;
            push @{ $zone->{interfaces} }, $interface;
        }
        else {

            # Traverse each unmanaged router only once.
            next if $router->{active_path};
            $router->{active_path} = 1;
            push @{ $zone->{unmanaged_routers} }, $router;
            for my $out_interface (@{ $router->{interfaces} }) {

                # Ignore interface where we reached this router.
                next if $out_interface eq $interface;
                next if $out_interface->{disabled};
                set_zone1($out_interface->{network}, $zone, $out_interface);
            }
            delete $router->{active_path};
        }
    }
    return;
}

# Collect cluster of zones which are connected by semi_managed devices.
sub set_zone_cluster {
    my ($zone, $in_interface, $zone_aref) = @_;
    my $restrict;
    push @$zone_aref, $zone;
    $zone->{zone_cluster} = $zone_aref;

    for my $interface (@{ $zone->{interfaces} }) {
        next if $interface eq $in_interface;

        # Ignore interface with globally active pathrestriction
        # where all traffic goes through a VPN tunnel.
        next if check_global_active_pathrestriction($interface);
        my $router = $interface->{router};
        next if $router->{managed};
        next if $router->{active_path};
        $router->{active_path} = 1;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $interface;
            my $next = $out_interface->{zone};
            next if $next->{zone_cluster};
            next if check_global_active_pathrestriction($out_interface);
            set_zone_cluster($next, $out_interface, $zone_aref);
        }
        delete $router->{active_path};
    }
    return;
}

# Two zones are zone_eq, if
# - zones are equal or
# - both belong to the same zone cluster.
sub zone_eq {
    my ($zone1, $zone2) = @_;
    return(($zone1->{zone_cluster} || $zone1) eq 
           ($zone2->{zone_cluster} || $zone2));
}

# Collect all zones belonging to an area.
# Set attribute {border} for areas defined by anchor and auto_border.
sub set_area1 {
    my ($zone, $area, $in_interface) = @_;
    if ($zone->{areas}->{$area}) {

        # Found a loop.
        return;
    }

    # Add zone to the corresponding area, to have all zones of an area
    # available.
    push @{ $area->{zones} }, $zone;

    # This will be used to prevent duplicate traversal of loops and
    # later to check for duplicate and overlapping areas.
    $zone->{areas}->{$area} = $area;
    my $auto_border = $area->{auto_border};
    my $lookup      = $area->{intf_lookup};
    for my $interface (@{ $zone->{interfaces} }) {

        # Ignore interface where we reached this area.
        next if $interface eq $in_interface;

        if ($auto_border) {
            if ($interface->{is_border}) {
                push @{ $area->{border} }, $interface;
                next;
            }
        }

        # Found another border of current area.
        elsif ($lookup->{$interface}) {

            # Remember that we have found this other border.
            $lookup->{$interface} = 'found';
            next;
        }

        # Ignore secondary or virtual interface, because we check main interface.
        next if $interface->{main_interface};

        # Ignore tunnel interface. We can't test for {real_interface} here
        # because it may still be unknown.
        next if $interface->{ip} eq 'tunnel';

        my $router = $interface->{router};
        for my $out_interface (@{ $router->{interfaces} }) {

            # Ignore interface where we reached this router.
            next if $out_interface eq $interface;

            if ($auto_border) {
                if ($out_interface->{is_border}) {

                    # Take interface where we reached this router.
                    push @{ $area->{border} }, $interface;
                    next;
                }
            }

            # Found another border of current area from wrong side.
            elsif ($lookup->{$out_interface}) {
                err_msg("Inconsistent definition of $area->{name}",
                        " in loop at $out_interface->{name}");
                next;
            }
            set_area1($out_interface->{zone}, $area, $out_interface);
        }
    }
    return;
}

# Find managed routers _inside_ an area.
sub area_managed_routers {
    my ($area) = @_;

    # Fill hash with all border routers of security zones
    # including border routers of current area.
    my %routers =
      map {
        my $router = $_->{router};
        ($router => $router)
      }
      map { @{ $_->{interfaces} } } @{ $area->{zones} };

    # Remove border routers, because we only
    # need routers inside this area.
    for my $interface (@{ $area->{border} }) {
        delete $routers{ $interface->{router} };
    }

    # Remove semi_managed routers.
    return grep { $_->{managed} } values %routers;
}

# Distribute router_attributes
sub inherit_router_attributes {
    my ($area) = @_;
    my $attributes = $area->{router_attributes} or return;
    $attributes->{owner} and keys %$attributes == 1 and return;
    for my $router (area_managed_routers($area)) {
        for my $key (keys %$attributes) {

            # Owner is handled in propagate_owners.
            if (not $key eq 'owner') {
                $router->{$key} ||= $attributes->{$key};
            }
        }
    }
    return;
}

# Distribute NAT from zone to networks.
sub inherit_nat {
    my ($area) = @_;

    my $hash = $area->{nat} or return;
    for my $nat_tag (keys %$hash) {
        my $nat = $hash->{$nat_tag};
        for my $zone (@{ $area->{zones} }) {
            for my $network (@{ $zone->{networks} }) {

                # Ignore NAT definition from area
                # if network has local NAT definition or 
                # has already inherited from smaller area.
                next if $network->{nat}->{$nat_tag};

                # Ignore network with identity NAT.
                next if $network->{identity_nat}->{$nat_tag};

                next if $network->{ip} eq 'unnumbered';
                next if $network->{isolated_ports};

                if ($nat->{identify}) {
                    $network->{nat}->{$nat_tag} = $network;
                }
                else {

                    $network->{ip} eq 'bridged' and
                        err_msg("Must not inherit nat:$nat_tag",
                                " at bridged $network->{name}",
                                " from $area->{name}");

                    # Copy NAT defintion; append name of network.
                    $network->{nat}->{$nat_tag} = {
                        %$nat,
                        
                        # Needed for error messages.
                        name => "nat:$nat_tag($network->{name})",
                    };
                }
            }
        }
    }
    return;
}

sub inherit_attributes_from_area {

    # Areas can be nested. Proceed from small to larger ones.
    for my $area (
        sort { @{ $a->{zones} } <=> @{ $b->{zones} } }
        grep { not $_->{disabled} } values %areas
      )
    {
        inherit_router_attributes($area);
        inherit_nat($area);
    }
    return;
}

sub set_zone {
    progress('Preparing security zones and areas');

    # Create zone objects.
    # It gets name of corresponding aggregate with ip 0/0.
    for my $network (@networks) {
        next if $network->{zone};
        my $name = "any:[$network->{name}]";
        my $zone = new('Zone', name => $name, networks => []);
        push @zones, $zone;
        set_zone1($network, $zone, 0);

        # Mark zone which consists only of a loopback network.
        $zone->{loopback} = 1
          if $network->{loopback} && @{ $zone->{networks} } == 1;
    }

    for my $zone (@zones) {

        # Collect clusters of zones, which are connected by an unmanaged
        # (semi_managed) device into attribute {zone_cluster}.
        # This attribute is only set, if the cluster has more than one element.
        next if $zone->{zone_cluster};
        my $cluster = [];
        set_zone_cluster($zone, 0, $cluster);
        delete $zone->{zone_cluster} if 1 == @$cluster;

#       debug('cluster: ', join(',',map($_->{name}, @{$zone->{zone_cluster}})))
#           if $zone->{zone_cluster};
    }

    check_no_in_acl();
    check_crosslink();

    # Mark interfaces, which are border of some area.
    # This is needed to locate auto_borders.
    for my $area (@areas) {
        next unless $area->{border};
        for my $interface (@{ $area->{border} }) {
            $interface->{is_border} = 1;
        }
    }
    for my $area (@areas) {
        if (my $network = $area->{anchor}) {
            set_area1($network->{zone}, $area, 0);
        }
        elsif (my $interfaces = $area->{border}) {

            # For efficient look up if some interface is border of
            # current area.
            my %lookup;
            for my $interface (@$interfaces) {
                $lookup{$interface} = 1;
            }
            $area->{intf_lookup} = \%lookup;
            my $start = $interfaces->[0];
            $lookup{$start} = 'found';
            set_area1($start->{zone}, $area, $start);
            if (my @bad_intf = grep { $lookup{$_} ne 'found' } @$interfaces) {
                err_msg("Invalid border of $area->{name}\n ", join "\n ",
                        map { $_->{name} } @bad_intf);
                $area->{border} =
                  [ grep { $lookup{$_} eq 'found' } @$interfaces ];
            }
        }

#     debug("$area->{name}:\n ", join "\n ", map $_->{name}, @{$area->{zones}});
    }

    # Find subset relation between areas.
    # Complain about duplicate and overlapping areas.
    for my $zone (@zones) {
        $zone->{areas} or next;

        # Ignore empty hash.
        my @areas = values %{ $zone->{areas} } or next;

        # Take the smallest area.
        @areas = sort { @{ $a->{zones} } <=> @{ $b->{zones} } } @areas;
        my $small = shift @areas;

        while (@areas) {
            my $next = shift @areas;
            if (my $big = $small->{subset_of}) {
                $big eq $next
                  or internal_err("$small->{name} is subset of",
                                  " $big->{name} and $next->{name}");
            }
            else {

                # Each zone of $small must be part of $next.
                my $ok = 1;
                for my $zone (@{ $small->{zones} }) {
                    unless ($zone->{areas}->{$small}) {
                        $ok = 0;
                        err_msg("Overlapping $small->{name} and $next->{name}");
                        last;
                    }
                }
                if ($ok) {
                    if (@{ $small->{zones} } == @{ $next->{zones} }) {
                        err_msg("Duplicate $small->{name} and $next->{name}");
                    }
                    else {
                        $small->{subset_of} = $next;
                    }
                }
            }
            $small = $next;
        }
    }
    for my $area (@areas) {

        # Tidy up: Delete unused attribute.
        delete $area->{intf_lookup};
        for my $interface (@{ $area->{border} }) {
            delete $interface->{is_border};
        }
    }
    link_aggregates();
    inherit_attributes_from_area();
    return;
}

####################################################################
# Virtual interfaces
####################################################################

# Interfaces with identical virtual IP must be located inside the same loop.
sub check_virtual_interfaces  {
    my %seen;
    for my $interface (@virtual_interfaces) {
        my $related = $interface->{redundancy_interfaces};

        # Is not set, if other errors have been reported.
        next if not $related;

        # Loops inside a security zone are not known
        # and therefore can't be checked.
        my $router = $interface->{router};
        next if not($router->{managed} or $router->{semi_managed});

        my $err;
        for my $v (@$related) {
            next if $seen{$v};
            $seen{$v} = 1;
            if (not $v->{router}->{loop}) {
                err_msg("Virtual IP of $v->{name}\n",
                        " must be located inside cyclic sub-graph");
                $err = 1;
                next;
            }
        }
        next if $err;
        equal(map { $_->{loop} } @$related)
          or err_msg("Virtual interfaces\n ",
                     join(', ', map({ $_->{name} } @$related)),
                     "\n must all be part of the same cyclic sub-graph");
    }
    return;
}

####################################################################
# Check pathrestrictions
####################################################################

sub check_pathrestrictions {
  RESTRICT:
    for my $restrict (values %pathrestrictions) {
        my $elements = $restrict->{elements};
        next if ! @$elements;
        my $deleted;
        for my $obj (@$elements) {

            # Interfaces with pathrestriction need to be located
            # inside or at the border of cyclic graphs.
            if (
                not(   $obj->{loop}
                    || $obj->{router}->{loop}
                    || $obj->{zone}->{loop}
                    || $obj->{disabled})
              )
            {
                delete $obj->{path_restrict};
                $obj = undef;
                $deleted = 1;
                warn_msg("Ignoring $restrict->{name} at $obj->{name}\n",
                         " because it isn't located inside cyclic graph");
            }
        }
        if ($deleted) {
            $elements = $restrict->{elements} = [ grep { $_ } @$elements ];
        }
        next if ! @$elements;

        # Check for useless pathrestriction where all interfaces
        # are located inside a loop with all routers unmanaged.
        #
        # Some router is managed.
        grep { $_->{router}->{managed} } @$elements and next;

        # Different zones or zone_clusters, hence some router is managed.
        equal(map { $_->{zone_cluster} || $_ } map { $_->{zone} } @$elements)
            or next;

        # If there exists some neighbour zone or zone_cluster, located
        # inside the same loop, then some router is managed.
        # Interface is known to have attribute {loop}, 
        # because it is unmanaged and has pathrestriction.
        my $element = $elements->[0];
        my $loop = $element->{loop};
        my $zone = $element->{zone};
        my $zone_cluster = $zone->{zone_cluster} || [ $zone ];
        for my $zone1 (@$zone_cluster) {
            for my $interface (@{ $zone->{interfaces} }) {
                my $router = $interface->{router};
                for my $interface2 (@{ $router->{interfaces} }) {
                    my $zone2 = $interface2->{zone};
                    next if $zone2 eq $zone;
                    if (my $cluster2 = $zone2->{zone_cluster}) {
                        next if $cluster2 eq $zone_cluster;
                    }
                    if (my $loop2 = $zone2->{loop}) {
                        if ($loop eq $loop2) {
                        
                            # Found other zone in same loop.
                            next RESTRICT;
                        }
                    }
                }
            }
        }
        
        warn_msg("Useless $restrict->{name}.\n",
                 " All interfaces are unmanaged and",
                 " located inside the same security zone"
            );
    }
    return;
}

####################################################################
# Set paths for efficient topology traversal
####################################################################

# Parameters:
# $obj: a managed or semi-managed router or a zone
# $to_zone1: interface of $obj; go this direction to reach zone1
# $distance: distance to zone1
# Return value:
# - undef: found path is not part of a loop
# - loop-marker:
#   - found path is part of a loop
#   - a hash, which is referenced by all members of the loop
#     with this attributes:
#     - exit: that node of the loop where zone1 is reached
#     - distance: distance of the exit node + 1.
sub setpath_obj;

sub setpath_obj {
    my ($obj, $to_zone1, $distance) = @_;

#    debug("-- $distance: $obj->{name} --> $to_zone1->{name}");
    if ($obj->{active_path}) {

        # Found a loop; this is possibly exit of the loop to zone1.
        # Generate unique loop marker which references this object.
        # Distance is needed for cluster navigation.
        # We need a copy of the distance value inside the loop marker
        # because distance at object is reset later to the value of the
        # cluster exit object.
        # We must use an intermediate distance value for cluster_navigation
        # to work.
        return $to_zone1->{loop} = {
            exit     => $obj,
            distance => $obj->{distance} + 1,
        };
    }

    # Mark current path for loop detection.
    $obj->{active_path} = 1;
    $obj->{distance}    = $distance;

    my $get_next = is_router($obj) ? 'zone' : 'router';
    for my $interface (@{ $obj->{interfaces} }) {

        # Ignore interface where we reached this obj.
        next if $interface eq $to_zone1;

        # Ignore interface which is the other entry of a loop which is
        # already marked.
        next if $interface->{loop};
        my $next = $interface->{$get_next};

        # Increment by 2 because we need an intermediate value above.
        if (my $loop = setpath_obj($next, $interface, $distance + 2)) {
            my $loop_obj = $loop->{exit};

            # Found exit of loop in direction to zone1.
            if ($obj eq $loop_obj) {

                # Mark with a different marker linking to itself.
                # If current loop is part of a cluster,
                # this marker will be overwritten later.
                # Otherwise this is the exit of a cluster of loops.
                $obj->{loop} ||= { exit => $obj, distance => $distance, };
            }

            # Found intermediate loop node which was marked before.
            elsif (my $loop2 = $obj->{loop}) {
                if ($loop ne $loop2) {
                    if ($loop->{distance} < $loop2->{distance}) {
                        $loop2->{redirect} = $loop;
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
            $interface->{loop} = $loop;
        }
        else {

            # Continue marking loop-less path.
            $interface->{main} = $obj;
        }
    }
    delete $obj->{active_path};
    if ($obj->{loop} and $obj->{loop}->{exit} ne $obj) {
        return $obj->{loop};

    }
    else {
        $obj->{main} = $to_zone1;
        return 0;
    }
}

# Find cluster of directly connected loops.
# Find exit node of the cluster in direction to zone1;
# Its loop attribute has a reference to the node itself.
# Add this exit node as marker to all loops belonging to the cluster.
sub set_loop_cluster {
    my ($loop) = @_;
    if (my $marker = $loop->{cluster_exit}) {
        return $marker;
    }
    else {
        my $exit = $loop->{exit};

        # Exit node has loop marker which references the node itself.
        if ($exit->{loop} eq $loop) {

#           debug("Loop $exit->{name},$loop->{distance} is in cluster $exit->{name}");
            return $loop->{cluster_exit} = $exit;
        }
        else {
            my $cluster = set_loop_cluster($exit->{loop});

#           debug("Loop $exit->{name},$loop->{distance} is in cluster $cluster->{name}");
            return $loop->{cluster_exit} = $cluster;
        }
    }
}

sub setpath {
    progress('Preparing fast path traversal');

    # Take a random object from @zones, name it "zone1".
    @zones or fatal_err("Topology seems to be empty");
    my $zone1 = $zones[0];

    # Starting with zone1, do a traversal of the whole topology
    # to find a path from every zone and router to zone1.
    # Second  parameter is used as placeholder for a not existing
    # starting interface. Value must be "true" and unequal to any interface.
    # Third parameter is distance from $zone1 to $zone1.
    setpath_obj($zone1, {}, 0);

    # Check if all objects are connected with zone1.
    my @unconnected;
    my @path_routers = grep { $_->{managed} || $_->{semi_managed} } @routers;
    for my $object (@zones, @path_routers) {
        next if $object->{main} or $object->{loop};
        push @unconnected, $object;

        # Ignore all other objects connected to the just found object.
        setpath_obj($object, {}, 0);
    }
    if (@unconnected) {
        my $msg = "Topology has unconnected parts:";
        for my $object ($zone1, @unconnected) {
            $msg .= "\n $object->{name}";
        }
        fatal_err($msg);
    }

    for my $obj (@zones, @path_routers) {
        my $loop = $obj->{loop} or next;

        # Check all zones and routers located inside a cyclic
        # graph. Propagate loop exit into sub-loops.
        while (my $next = $loop->{redirect}) {

#           debug("Redirect: $loop->{exit}->{name} -> $next->{exit}->{name}");
            $loop = $next;
        }
        $obj->{loop} = $loop;

        # Mark connected loops with cluster exit.
        set_loop_cluster($loop);

        # Set distance of loop objects to value of cluster exit.
        $obj->{distance} = $loop->{cluster_exit}->{distance};
    }
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

    # This is called here and not at link_topology because it needs
    # attribute {loop}.
    check_pathrestrictions;
    check_virtual_interfaces;
    return;
}

####################################################################
# Efficient path traversal.
####################################################################

my %obj2path;

sub get_path {
    my ($obj) = @_;
    my $type = ref $obj;
    my $result;
    if ($type eq 'Network') {
        $result = $obj->{zone};
    }
    elsif ($type eq 'Subnet') {
        $result = $obj->{network}->{zone};
    }
    elsif ($type eq 'Interface') {
        my $router = $obj->{router};
        if ($router->{managed} || $router->{semi_managed}) {

            # If this is a secondary interface, we can't use it to enter
            # the router, because it has an active pathrestriction attached.
            # But it doesn't matter if we use the main interface instead.
            my $obj2 = $obj->{main_interface} || $obj;

            # Special handling needed if $src or $dst is interface
            # which has pathrestriction attached.
            if ($obj->{path_restrict}) {
                $result = $obj2;
            }
            else {
                $result = $obj2->{router};
            }
        }
        else {
            $result = $obj->{network}->{zone};
        }
    }

    # This is only used, if called from path_auto_interfaces.
    elsif ($type eq 'Router') {
        if ($obj->{managed} || $obj->{semi_managed}) {
            $result = $obj;
        }
        else {
            $result = $obj->{interfaces}->[0]->{network}->{zone};
        }
    }

    # This is only used, if path_walk is called from find_statics.
    elsif ($type eq 'Zone') {
        $result = $obj;
    }

    # This is only used, if Netspoc.pm is called from report.pl.
    elsif ($type eq 'Host') {
        $result = $obj->{network}->{zone};
    }
    else {
        internal_err("unexpected $obj->{name}");
    }

#    debug("get_path: $obj->{name} -> $result->{name}");
    return($obj2path{$obj} = $result);
}

# Converts hash key of reference back to reference.
my %key2obj;

sub cluster_path_mark1;

sub cluster_path_mark1 {

    my ($obj, $in_intf, $end, $path_tuples, $loop_leave, $start_intf, $end_intf,
        $navi)
      = @_;
    my @pathrestriction =
      $in_intf->{path_restrict}
      ? @{ $in_intf->{path_restrict} }
      : ();

    # Handle special case where path starts or ends at an interface with
    # pathrestriction.
    # If the router is left / entered via the same interface, ignore the PR.
    # If the router is left / entered via some other interface,
    # activate the PR of the start- / end interface before checking the current
    # interface.
    for my $intf ($start_intf, $end_intf) {
        if ($intf and $in_intf->{router} eq $intf->{router}) {
            if ($in_intf eq $intf) {
                @pathrestriction = ();
            }
            else {
                for my $restrict1 (@{ $intf->{path_restrict} }) {
                    for my $restrict2 (@pathrestriction) {
                        return 0 if $restrict1 eq $restrict2;
                    }
                }
                push @pathrestriction, @{ $intf->{path_restrict} };
            }
        }
    }

#  debug("cluster_path_mark1: obj: $obj->{name},
#        in_intf: $in_intf->{name} to: $end->{name}");
    # Check for second occurrence of path restriction.
    for my $restrict (@pathrestriction) {
        if ($restrict->{active_path}) {

#           debug(" effective $restrict->{name} at $in_intf->{name}");
            return 0;
        }
    }

    # Don't walk loops.
    if ($obj->{active_path}) {

#       debug(" active: $obj->{name}");
        return 0;
    }

    # Found a path to router or zone.
    if ($obj eq $end) {

        # Mark interface where we leave the loop.
        push @$loop_leave, $in_intf;

#     debug(" leave: $in_intf->{name} -> $end->{name}");
        return 1;
    }

    # Mark current path for loop detection.
    $obj->{active_path} = 1;

    # Mark first occurrence of path restriction.
    for my $restrict (@pathrestriction) {

#       debug(" enabled $restrict->{name} at $in_intf->{name}");
        $restrict->{active_path} = 1;
    }
    my $get_next = is_router($obj) ? 'zone' : 'router';
    my $success = 0;

    # Fill hash for restoring reference from hash key.
    $key2obj{$in_intf} = $in_intf;
    my $allowed = $navi->{ $obj->{loop} };
    for my $interface (@{ $obj->{interfaces} }) {
        next if $interface eq $in_intf;
        my $loop = $interface->{loop};
        $allowed or internal_err("Loop with empty navigation");
        next if not $loop or not $allowed->{$loop};
        my $next = $interface->{$get_next};
        if (
            cluster_path_mark1(
                $next,       $interface,  $end,      $path_tuples,
                $loop_leave, $start_intf, $end_intf, $navi
            )
          )
        {

            # Found a valid path from $next to $end.
            $key2obj{$interface} = $interface;
            $path_tuples->{$in_intf}->{$interface} = is_router($obj);

#	    debug(" loop: $in_intf->{name} -> $interface->{name}");
            $success = 1;
        }
    }
    delete $obj->{active_path};
    for my $restrict (@pathrestriction) {

#     debug(" disabled $restrict->{name} at $in_intf->{name}");
        $restrict->{active_path} = undef;
    }
    return $success;
}

# Optimize navigation inside a cluster of loops.
# Mark each loop marker
# with the allowed loops to be gone to reach $to.
# The direction is given as a loop object.
# It can be used to look up interfaces which reference
# this loop object in attribute {loop}.
# Return value:
# A hash with pairs: object -> loop-marker
sub cluster_navigation {
    my ($from, $to) = @_;
    my $from_loop = $from->{loop};
    my $to_loop   = $to->{loop};

#    debug("Navi: $from->{name}, $to->{name}");

    my $navi;
    if (($navi = $from->{navi}->{$to}) and scalar keys %$navi) {

#	debug(" Cached");
        return $navi;
    }
    $navi = $from->{navi}->{$to} = {};

    while (1) {
        if ($from_loop eq $to_loop) {
            last if $from eq $to;
            $navi->{$from_loop}->{$from_loop} = 1;

#	    debug("- Eq: $from_loop->{exit}->{name}$from_loop to itself");

            # Path $from -> $to goes through $from_loop and through $exit_loop.
            # Inside $exit_loop, enter only $from_loop, but no other loops.
            my $exit_loop = $from_loop->{exit}->{loop};
            $navi->{$exit_loop}->{$from_loop} = 1;

#	    debug("- Add $from_loop->{exit}->{name}$from_loop to exit $exit_loop->{exit}->{name}$exit_loop");
            last;
        }
        elsif ($from_loop->{distance} >= $to_loop->{distance}) {
            $navi->{$from_loop}->{$from_loop} = 1;

#	    debug("- Fr: $from_loop->{exit}->{name}$from_loop to itself");
            $from      = $from_loop->{exit};
            $from_loop = $from->{loop};
        }
        else {
            $navi->{$to_loop}->{$to_loop} = 1;

#	    debug("- To: $to_loop->{exit}->{name}$to_loop to itself");
            $to = $to_loop->{exit};
            my $entry_loop = $to->{loop};
            $navi->{$entry_loop}->{$to_loop} = 1;

#	    debug("- Add $to_loop->{exit}->{name}$to_loop to entry $entry_loop->{exit}->{name}$entry_loop");
            $to_loop = $entry_loop;
        }
    }
    return $navi;
}

# Mark paths inside a cluster of loops.
# $from and $to are entry and exit objects inside the cluster.
# The cluster is entered at interface $from_in and left at interface $to_out.
# For each pair of $from / $to, we collect attributes:
# {loop_enter}: interfaces of $from, where the cluster is entered,
# {path_tuples}: tuples of interfaces, which describe all valid paths,
# {loop_leave}: interfaces of $to, where the cluster is left.
# Return value is true if a valid path was found.
#
# $from_store is the starting object of the whole path.
# If the path starts at an interface of a loop and it has a pathrestriction attached,
# $from_store contains this interface.
sub cluster_path_mark  {
    my ($from, $to, $from_in, $to_out, $from_store, $to_store) = @_;

    # This particular path through this sub-graph is already known.
    return 1 if $from_in->{path}->{$to_store};

    # Start and end interface or undef.
    # It is set, if the path starts / ends
    # - at an interface inside the loop or
    # - at an interface at the border of the loop
    #   (an interface of a router/zone inside the loop)
    # - this interface has a pathrestriction attached.
    my ($start_intf, $end_intf);

    # Check, if loop is entered or left at interface with pathrestriction.
    # - is $from_store located inside or at border of current loop?
    # - does $from_in at border of current loop have pathrestriction ?
    # dito for $to_store and $to_out.
    my ($start_store, $end_store);
    if (is_interface($from_store)
        and ($from_store->{router} eq $from or $from_store->{zone} eq $from))
    {
        $start_intf  = $from_store;
        $start_store = $from_store;
    }
    elsif ($from_in and $from_in->{path_restrict}) {
        $start_store = $from_in;
    }
    else {
        $start_store = $from;
    }
    if (is_interface($to_store)
        and ($to_store->{router} eq $to or $to_store->{zone} eq $to))
    {
        $end_intf  = $to_store;
        $end_store = $to_store;
    }
    elsif ($to_out and $to_out->{path_restrict}) {
        $end_store = $to_out;
    }
    else {
        $end_store = $to;
    }

    my $success = 1;

#    debug("cluster_path_mark: $start_store->{name} -> $end_store->{name}");

    # Activate pathrestriction of interface at border of loop, if path starts
    # or ends outside the loop and enters the loop at such an interface.
    for my $intf ($from_in, $to_out) {
        if (    $intf
            and not $intf->{loop}
            and (my $restrictions = $intf->{path_restrict}))
        {
            for my $restrict (@$restrictions) {
                if ($restrict->{active_path}) {

                    # Pathrestriction at start and end interface
                    # prevents traffic through loop.
                    $success = 0;
                }
                $restrict->{active_path} = 1;
            }
        }
    }

    # If start / end interface is part of a group of virtual
    # interfaces (VRRP, HSRP),
    # prevent traffic through other interfaces of this group.
    for my $intf ($start_intf, $end_intf) {
        if ($intf and (my $interfaces = $intf->{redundancy_interfaces})) {
            for my $interface (@$interfaces) {
                next if $interface eq $intf;
                push @{ $interface->{path_restrict} },
                  $global_active_pathrestriction;
            }
        }
    }

  BLOCK:
    {
        last BLOCK if not $success;
        $success = 0;

        # When entering sub-graph at $from_in we will leave it at $to_out.
        $from_in->{path}->{$to_store} = $to_out;

        $from_in->{loop_entry}->{$to_store}    = $start_store;
        $start_store->{loop_exit}->{$to_store} = $end_store;

        # Path from $start_store to $end_store inside cyclic graph
        # has been marked already.
        if ($start_store->{loop_enter}->{$end_store}) {
            $success = 1;
            last BLOCK;
        }

        my $loop_enter  = [];
        my $path_tuples = {};
        my $loop_leave  = [];

        my $navi = cluster_navigation($from, $to) 
          or internal_err("Empty navi");

#	use Dumpvalue;
#	Dumpvalue->new->dumpValue($navi);

        # Mark current path for loop detection.
        $from->{active_path} = 1;
        my $get_next = is_router($from) ? 'zone' : 'router';
        my $allowed = $navi->{ $from->{loop} }
          or internal_err("Loop $from->{loop}->{exit}->{name}$from->{loop}",
            " with empty navi");
        for my $interface (@{ $from->{interfaces} }) {
            my $loop = $interface->{loop};
            next if not $loop;
            if (not $allowed->{$loop}) {

#		debug("No: $loop->{exit}->{name}$loop");
                next;
            }

            # Don't enter network which connects pair of virtual loopback
            # interfaces.
            next if $interface->{loopback} and $get_next eq 'zone';
            my $next = $interface->{$get_next};

#           debug(" try: $from->{name} -> $interface->{name}");
            if (
                cluster_path_mark1(
                    $next,       $interface,  $to,       $path_tuples,
                    $loop_leave, $start_intf, $end_intf, $navi
                )
              )
            {
                $success = 1;
                push @$loop_enter, $interface;

#               debug(" enter: $from->{name} -> $interface->{name}");
            }
        }
        delete $from->{active_path};

        # Don't store incomplete result.
        last BLOCK if not $success;

        # Convert { intf->intf->node_type } to [ intf, intf, node_type ]
        my $tuples_aref = [];
        for my $in_intf_ref (keys %$path_tuples) {
            my $in_intf = $key2obj{$in_intf_ref}
              or internal_err("Unknown in_intf at tuple");
            my $hash = $path_tuples->{$in_intf_ref};
            for my $out_intf_ref (keys %$hash) {
                my $out_intf = $key2obj{$out_intf_ref}
                  or internal_err("Unknown out_intf at tuple");
                my $at_router = $hash->{$out_intf_ref};
                push @$tuples_aref, [ $in_intf, $out_intf, $at_router ];

#		debug("Tuple: $in_intf->{name}, $out_intf->{name} $at_router");
            }
        }

        # Remove duplicates, which occur from nested loops..
        $loop_leave = [ unique(@$loop_leave) ];

        $start_store->{loop_enter}->{$end_store}  = $loop_enter;
        $start_store->{loop_leave}->{$end_store}  = $loop_leave;
        $start_store->{path_tuples}->{$end_store} = $tuples_aref;

        # Add data for reverse path.
        $end_store->{loop_enter}->{$start_store} = $loop_leave;
        $end_store->{loop_leave}->{$start_store} = $loop_enter;
        $end_store->{path_tuples}->{$start_store} =
          [ map { [ @{$_}[ 1, 0, 2 ] ] } @$tuples_aref ];
    }

    # Remove temporary added path restrictions.
    for my $intf ($start_intf, $end_intf) {
        if ($intf and (my $interfaces = $intf->{redundancy_interfaces})) {
            for my $interface (@$interfaces) {
                next if $interface eq $intf;
                pop @{ $interface->{path_restrict} };
            }
        }
    }

    # Disable pathrestriction at border of loop.
    for my $intf ($from_in, $to_out) {
        if (    $intf
            and not $intf->{loop}
            and (my $restrictions = $intf->{path_restrict}))
        {
            for my $restrict (@$restrictions) {
                $restrict->{active_path} = 0;
            }
        }
    }
    return $success;
}

# Mark path from $from to $to.
# $from and $to are either a router or a zone.
# For a path without loops, $from_store equals $from and $to_store equals $to.
# If the path starts at an interface inside a cluster of loops
# or at the border of a cluster,
# and the interface has a pathrestriction attached,
# then $from_store contains this interface.
# If the path ends at an interface inside a loop or at the border of a loop,
# $to_store contains this interface.
# At each interface on the path from $from to $to,
# we place a reference to the next interface on the path to $to_store.
# This reference is found in a hash at attribute {path}.
# Additionally we attach the path attribute to the src object.
# Return value is true if a valid path was found.
sub path_mark {
    my ($from, $to, $from_store, $to_store) = @_;

#    debug("path_mark $from_store->{name} --> $to_store->{name}");

    my $from_loop = $from->{loop};
    my $to_loop   = $to->{loop};

    # $from_store and $from differ if path starts at an interface
    # with pathrestriction.
    # Inside a loop, use $from_store, not $from,
    # because the path may differ depending on the start interface.
    # But outside a loop (pathrestriction is allowed at the border of a loop)
    # we have only a single path which enters the loop.
    # In this case we must not use the interface but the router,
    # otherwise we would get an invalid {path}:
    # $from_store->{path}->{$to_store} = $from_store;
    my $from_in = $from_store->{loop} ? $from_store : $from;
    my $to_out = undef;
    while (1) {

#        debug("Dist: $from->{distance} $from->{name} ->Dist: $to->{distance} $to->{name}");
        # Paths meet outside a loop or at the edge of a loop.
        if ($from eq $to) {

#            debug(" $from_in->{name} -> ".($to_out ? $to_out->{name}:''));
            $from_in->{path}->{$to_store} = $to_out;
            return 1;
        }

        # Paths meet inside a loop.
        if (   $from_loop
            && $to_loop
            && $from_loop->{cluster_exit} eq $to_loop->{cluster_exit})
        {
            return cluster_path_mark($from, $to, $from_in, $to_out, $from_store,
                $to_store);
        }

        if ($from->{distance} >= $to->{distance}) {

            # Mark has already been set for a sub-path.
            return 1 if $from_in->{path}->{$to_store};
            my $from_out = $from->{main};
            unless ($from_out) {

                # $from_loop references object which is loop's exit.
                my $exit = $from_loop->{cluster_exit};
                $from_out = $exit->{main};
                cluster_path_mark($from, $exit, $from_in, $from_out,
                    $from_store, $to_store)
                  or return 0;
            }

#            debug(" $from_in->{name} -> ".($from_out ? $from_out->{name}:''));
            $from_in->{path}->{$to_store} = $from_out;
            $from_in                      = $from_out;
            $from                         = $from_out->{main};
            $from_loop                    = $from->{loop};
        }
        else {
            my $to_in = $to->{main};
            unless ($to_in) {
                my $entry = $to_loop->{cluster_exit};
                $to_in = $entry->{main};
                cluster_path_mark($entry, $to, $to_in, $to_out, $from_store,
                    $to_store)
                  or return 0;
            }

#            debug(" $to_in->{name} -> ".($to_out ? $to_out->{name}:''));
            $to_in->{path}->{$to_store} = $to_out;
            $to_out                     = $to_in;
            $to                         = $to_in->{main};
            $to_loop                    = $to->{loop};
        }
    }
    return 0; # unused; only for perlcritic
}

# Walk paths inside cyclic graph
sub loop_path_walk {
    my ($in, $out, $loop_entry, $loop_exit, $call_at_zone, $rule, $fun) = @_;

#    my $info = "loop_path_walk: ";
#    $info .= "$in->{name}->" if $in;
#    $info .= "$loop_entry->{name}=>$loop_exit->{name}";
#    $info .= "->$out->{name}" if $out;
#    debug($info);

    # Process entry of cyclic graph.
    if (
        (
            is_router($loop_entry)
            or

            # $loop_entry is interface with pathrestriction of original
            # loop_entry.
            is_interface($loop_entry)
            and

            # Take only interface which originally was a router.
            $loop_entry->{router} eq
            $loop_entry->{loop_enter}->{$loop_exit}->[0]->{router}
        ) xor $call_at_zone
      )
    {

#     debug(" loop_enter");
        for my $out_intf (@{ $loop_entry->{loop_enter}->{$loop_exit} }) {
            $fun->($rule, $in, $out_intf);
        }
    }

    # Process paths inside cyclic graph.
    my $path_tuples = $loop_entry->{path_tuples}->{$loop_exit};

#    debug(" loop_tuples");
    for my $tuple (@$path_tuples) {
        my ($in_intf, $out_intf, $at_router) = @$tuple;
        $fun->($rule, $in_intf, $out_intf)
          if $at_router xor $call_at_zone;
    }

    # Process paths at exit of cyclic graph.
    if (
        (
               is_router($loop_exit)
            or is_interface($loop_exit)
            and $loop_exit->{router} eq
            $loop_entry->{loop_leave}->{$loop_exit}->[0]->{router}
        ) xor $call_at_zone
      )
    {

#     debug(" loop_leave");
        for my $in_intf (@{ $loop_entry->{loop_leave}->{$loop_exit} }) {
            $fun->($rule, $in_intf, $out);
        }
    }
    return;
}

# Apply a function to a rule at every router or zone on the path from
# src to dst of the rule.
# $where tells, where the function gets called: at 'Router' or 'Zone'.
# Default is 'Router'.
sub path_walk {
    my ($rule, $fun, $where) = @_;
    internal_err("undefined rule") unless $rule;
    my $src = $rule->{src};
    my $dst = $rule->{dst};

    my $from_store = $obj2path{$src}       || get_path $src;
    my $to_store   = $obj2path{$dst}       || get_path $dst;
    my $from       = $from_store->{router} || $from_store;
    my $to         = $to_store->{router}   || $to_store;
    my $path_store = $from_store->{loop} ? $from_store : $from;

#    debug(print_rule $rule);
#    debug(" start: $from->{name}, $to->{name}" . ($where?", at $where":''));
#    my $fun2 = $fun;
#    $fun = sub  {
#       my($rule, $in, $out) = @_;
#       my $in_name = $in?$in->{name}:'-';
#       my $out_name = $out?$out->{name}:'-';
#       debug(" Walk: $in_name, $out_name");
#       $fun2->(@_);
#    };
    $from and $to or internal_err(print_rule $rule);
    $from eq $to and internal_err("Unenforceable:\n ", print_rule $rule);

    if (!$path_store->{path}->{$to_store}) {
        if (!path_mark($from, $to, $from_store, $to_store)) {
            err_msg("No valid path\n",
                    " from $from_store->{name}\n",
                    " to $to_store->{name}\n",
                    " for rule ", print_rule($rule), "\n",
                    " Check path restrictions and crypto interfaces.");
            delete $path_store->{path}->{$to_store};
            return;
        }
    }
    my $in = undef;
    my $out;
    my $at_zone = $where && $where eq 'Zone';
    my $call_it = (is_router($from) xor $at_zone);

    # Path starts inside a cyclic graph.
    if ($from_store->{loop_exit}
        and my $loop_exit = $from_store->{loop_exit}->{$to_store})
    {
        my $loop_out = $path_store->{path}->{$to_store};
        loop_path_walk($in, $loop_out, $from_store, $loop_exit, $at_zone, $rule,
            $fun);
        if (not $loop_out) {

#           debug("exit: path_walk: dst in loop");
            return;
        }

        # Continue behind loop.
        $call_it = not(is_router($loop_exit) xor $at_zone);
        $in      = $loop_out;
        $out     = $in->{path}->{$to_store};
    }
    else {
        $out = $path_store->{path}->{$to_store};
    }
    while (1) {
        if (    $in
            and $in->{loop_entry}
            and my $loop_entry = $in->{loop_entry}->{$to_store})
        {
            my $loop_exit = $loop_entry->{loop_exit}->{$to_store};
            my $loop_out  = $in->{path}->{$to_store};
            loop_path_walk($in, $loop_out, $loop_entry, $loop_exit, $at_zone,
                $rule, $fun);
            if (not $loop_out) {

#               debug("exit: path_walk: reached dst in loop");
                return;
            }
            $call_it = not(is_router($loop_exit) xor $at_zone);
            $in      = $loop_out;
            $out     = $in->{path}->{$to_store};
        }
        else {
            if ($call_it) {
                $fun->($rule, $in, $out);
            }

            # End of path has been reached.
            if (not $out) {

#               debug("exit: path_walk: reached dst");
                return;
            }
            $call_it = !$call_it;
            $in      = $out;
            $out     = $in->{path}->{$to_store};
        }
    }
    return;
}

my %border2obj2auto;

sub set_auto_intf_from_border  {
    my ($border) = @_;
    my %active_path;
    my $reach_from_border;
    $reach_from_border = sub {
        my ($network, $in_intf, $result) = @_;
        $active_path{$network} = 1;
        $result->{$network}->{$in_intf} = $in_intf;
#        debug "$network->{name}: $in_intf->{name}";
        for my $interface (@{ $network->{interfaces} }) {
            next if $interface eq $in_intf;
            next if $interface->{zone};
            next if $interface->{orig_main};
            my $router = $interface->{router};
            next if $active_path{$router};
            $active_path{$router} = 1;
            $result->{$router}->{$interface} = $interface;
#            debug "$router->{name}: $interface->{name}";

            for my $out_intf (@{ $router->{interfaces} }) {
                next if $out_intf eq $interface;
                next if $out_intf->{orig_main};
                my $out_net = $out_intf->{network};
                $reach_from_border->($out_net, $out_intf, $result);
            }
            $active_path{$router} = 0;
        }
        $active_path{$network} = 0;
    };
    my $result = {};
    $reach_from_border->($border->{network}, $border, $result);
    for my $href (values %$result) {
        $href = [ values %$href ];
    }
    $border2obj2auto{$border} = $result;
    return;
}

# $src is an auto_interface, interface or router.
# Result is the set of interfaces of $src located at the front side
# of the direction to $dst.
sub path_auto_interfaces {
    my ($src, $dst) = @_;
    my @result;
    my ($src2, $managed) =
      is_autointerface($src)
      ? @{$src}{ 'object', 'managed' }
      : ($src, undef);
    my $dst2 = is_autointerface($dst) ? $dst->{object} : $dst;

    my $from_store = $obj2path{$src2}      || get_path $src2;
    my $to_store   = $obj2path{$dst2}      || get_path $dst2;
    my $from       = $from_store->{router} || $from_store;
    my $to         = $to_store->{router}   || $to_store;

    $from eq $to and return ();
    if (!$from_store->{path}->{$to_store}) {
        if (!path_mark($from, $to, $from_store, $to_store)) {
            err_msg("No valid path\n",
                    " from $from_store->{name}\n",
                    " to $to_store->{name}\n",
                    " while resolving $src->{name}",
                    " (destination is $dst->{name}).\n",
                    " Check path restrictions and crypto interfaces.");
            delete $from_store->{path}->{$to_store};
            return;
        }
    }
    if ($from_store->{loop_exit}
        and my $exit = $from_store->{loop_exit}->{$to_store})
    {
        @result =
          grep { $_->{ip} ne 'tunnel' } @{ $from->{loop_enter}->{$exit} };
    }
    else {
        @result = ($from_store->{path}->{$to_store});
    }

    # Find auto interface inside zone.
    # $src is located inside some zone.
    # $src2 is known to be unmanaged router or network.
    if (!is_router($from)) {
        my %result;
        for my $border (@result) {
            if (not $border2obj2auto{$border}) {
                set_auto_intf_from_border($border);
            }
            my $auto_intf = $border2obj2auto{$border}->{$src2};
            for my $interface (@$auto_intf) {
                $result{$interface} = $interface;
            }
        }
        @result = sort by_name values %result;
    }

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
    return($managed ? grep { $_->{router}->{managed} } @result : @result);
}

########################################################################
# Handling of crypto tunnels.
########################################################################

sub link_ipsec  {
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
    return;
}

sub link_crypto  {
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
    return;
}

# Generate rules to permit crypto traffic between tunnel endpoints.
sub gen_tunnel_rules  {
    my ($intf1, $intf2, $ipsec) = @_;
    my $use_ah = $ipsec->{ah};
    my $use_esp = $ipsec->{esp_authentication} || $ipsec->{esp_encryption};
    my $nat_traversal = $ipsec->{key_exchange}->{nat_traversal};
    my @rules;
    my $rule =
      { stateless => 0, action => 'permit', src => $intf1, dst => $intf2 };
    if (not $nat_traversal or $nat_traversal ne 'on') {
        $use_ah
          and push @rules, { %$rule, src_range => $prt_ip, prt => $prt_ah };
        $use_esp
          and push @rules, { %$rule, src_range => $prt_ip, prt => $prt_esp };
        push @rules,
          {
            %$rule,
            src_range => $prt_ike->{src_range},
            prt       => $prt_ike->{dst_range}
          };
    }
    if ($nat_traversal) {
        push @rules,
          {
            %$rule,
            src_range => $prt_natt->{src_range},
            prt       => $prt_natt->{dst_range}
          };
    }
    return \@rules;
}

# Link tunnel networks with tunnel hubs.
# ToDo: Are tunnels between different private contexts allowed?
sub link_tunnels  {

    # Collect clear-text interfaces of all tunnels.
    my @real_interfaces;

    for my $crypto (values %crypto) {
        my $name        = $crypto->{name};
        my $private     = $crypto->{private};
        my $real_hubs   = delete $crypto2hubs{$name};
        my $real_spokes = delete $crypto2spokes{$name};
        $real_hubs and @$real_hubs
          or warn_msg("No hubs have been defined for $name");

        $real_spokes and @$real_spokes
          or warn_msg("No spokes have been defined for $name");

        # Substitute crypto name by crypto object.
        for my $real_hub (@$real_hubs) {
            for my $crypto_name (@{ $real_hub->{hub} }) {
                $crypto_name eq $name and $crypto_name = $crypto;
            }
        }
        push @real_interfaces, @$real_hubs;

        # Generate a single tunnel from each spoke to a single hub.
        # If there are multiple hubs, they are assumed to form
        # a high availability cluster. In this case a single tunnel is created
        # with all hubs as possible endpoints. Traffic between hubs is
        # prevented by automatically added pathrestrictions.
        for my $spoke_net (@$real_spokes) {
            (my $net_name = $spoke_net->{name}) =~ s/network://;
            push @{ $crypto->{tunnels} }, $spoke_net;
            my $spoke = $spoke_net->{interfaces}->[0];
            $spoke->{crypto} = $crypto;
            my $real_spoke = $spoke->{real_interface};
            $real_spoke->{spoke} = $crypto;

            # Each spoke gets a fresh hub interface.
            my @hubs;
            for my $real_hub (@$real_hubs) {
                my $router   = $real_hub->{router};
                my $hardware = $real_hub->{hardware};
                (my $intf_name = $real_hub->{name}) =~ s/\..*$/.$net_name/;
                my $hub = new(
                    'Interface',
                    name           => $intf_name,
                    ip             => 'tunnel',
                    crypto         => $crypto,
                    hardware       => $hardware,
                    is_hub         => 1,
                    real_interface => $real_hub,
                    router         => $router,
                    network        => $spoke_net
                );
                $hub->{bind_nat} = $real_hub->{bind_nat} if $hub->{bind_nat};
                push @{ $router->{interfaces} },    $hub;
                push @{ $hardware->{interfaces} },  $hub;
                push @{ $spoke_net->{interfaces} }, $hub;
                push @{ $hub->{peers} },            $spoke;
                push @{ $spoke->{peers} },          $hub;
                push @hubs, $hub;

                # Dynamic crypto-map isn't implemented currently.
                if ($real_spoke->{ip} eq 'negotiated') {
                    if (not $router->{model}->{do_auth}) {
                        err_msg "$router->{name} can't establish crypto",
                          "tunnel to $real_spoke->{name} with negotiated IP";
                    }
                }

                if ($private) {
                    my $s_p = $real_spoke->{private};
                    my $h_p = $real_hub->{private};
                    $s_p and $s_p eq $private
                      or $h_p and $h_p eq $private
                      or err_msg
                      "Tunnel $real_spoke->{name} to $real_hub->{name}",
                      " of $private.private $name",
                      " must reference at least one object",
                      " out of $private.private";
                }
                else {
                    $real_spoke->{private}
                      and err_msg "Tunnel of public $name must not",
                      " reference $real_spoke->{name} of",
                      " $real_spoke->{private}.private";
                    $real_hub->{private}
                      and err_msg "Tunnel of public $name must not",
                      " reference $real_hub->{name} of",
                      " $real_hub->{private}.private";
                }
            }

            # Remove real interface at virtual router with only
            # software clients attached.
            # This is necessary, because we must not add pathrestriction
            # to this unmanaged device.
            my $router = $real_spoke->{router};
            my @other;
            my $has_id_hosts;
            for my $interface (@{ $router->{interfaces} }) {
                my $network = $interface->{network};
                if ($network->{has_id_hosts}) {
                    $has_id_hosts = $network;
                }
                elsif ($interface ne $real_spoke
                    && $interface->{ip} ne 'tunnel')
                {
                    push @other, $interface;
                }
            }
            if ($has_id_hosts and @other) {
                err_msg "Must not use $has_id_hosts->{name} with ID hosts",
                  " together with networks having no ID host: ",
                  join(',', map { $_->{name} } @other);
            }
            push @real_interfaces, $real_spoke;

            if ($router->{managed} && $crypto->{detailed_crypto_acl}) {
                err_msg(
                    "Attribute 'detailed_crypto_acl' is not",
                    " allowed for managed spoke $router->{name}"
                );
            }

            # Automatically add pathrestriction between interfaces
            # of redundant hubs.
            if (@hubs > 1) {
                my $name2 = "auto-restriction:$crypto->{name}";
                my $restrict = new('Pathrestriction', name => $name2);
                for my $hub (@hubs) {
                    push @{ $hub->{path_restrict} }, $restrict;
                }
            }
        }
    }

    # Check for undefined crypto references.
    for my $crypto (keys %crypto2hubs) {
        for my $interface (@{ $crypto2hubs{$crypto} }) {
            err_msg("$interface->{name} references unknown $crypto");
        }
    }
    for my $crypto (keys %crypto2spokes) {
        for my $network (@{ $crypto2spokes{$crypto} }) {
            err_msg "$network->{interfaces}->[0]->{name}",
              " references unknown $crypto";
        }
    }

    # Automatically add active pathrestriction to the real interface.
    # This allows direct traffic to the real interface from outside,
    # but no traffic from or to the real interface passing the router.
    for my $intf1 (unique(@real_interfaces)) {
        next if $intf1->{no_check};
        push @{ $intf1->{path_restrict} }, $global_active_pathrestriction;
    }
    return;
}

# Needed for crypto_rules,
# for default route optimization,
# while generating chains of iptables and
# for local optimization.
my $network_00 = new(
    'Network',
    name         => "network:0/0",
    ip           => 0,
    mask         => 0,
    is_aggregate => 1,
    is_supernet  => 1
);

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
        return($network);
    }
}

sub expand_crypto  {
    progress('Expanding crypto rules');

    my %id2interface;

    for my $crypto (values %crypto) {
        my $name = $crypto->{name};

        # Do consistency checks and
        # add rules which allow encrypted traffic.
        for my $tunnel (@{ $crypto->{tunnels} }) {
            next if $tunnel->{disabled};
            for my $tunnel_intf (@{ $tunnel->{interfaces} }) {
                next if $tunnel_intf->{is_hub};
                my $router  = $tunnel_intf->{router};
                my $managed = $router->{managed};
                my @encrypted;
                my $has_id_hosts;
                my $has_other_network;
                for my $interface (@{ $router->{interfaces} }) {
                    next if $interface eq $tunnel_intf;
                    if ($interface->{ip} eq 'tunnel') {
                        if ($managed && $router->{model}->{crypto} eq 'EZVPN') {
                            err_msg "Exactly 1 crypto tunnel expected",
                                " for $router->{name} with EZVPN";
                        }
                        next;
                    }
                    if ($interface->{spoke}) {
                        if (my $id = $interface->{id}) {
                            if (my $intf2 = $id2interface{$id}) {
                                err_msg "Same ID '$id' is used at",
                                  " $interface->{name} and $intf2->{name}";
                            }
                            $id2interface{$id} = $interface;
                        }
                        next;
                    }
                    my $network = $interface->{network};
                    my @all_networks = crypto_behind($interface, $managed);
                    if ($network->{has_id_hosts}) {
                        $has_id_hosts = 1;
                        $managed
                          and err_msg
                          "$network->{name} having ID hosts must not",
                          " be located behind managed $router->{name}";

                        # Must not have multiple networks.
                        @all_networks > 1 and internal_err();

                        # Rules for single software clients are stored
                        # individually at crypto hub interface.
                        for my $host (@{ $network->{hosts} }) {
                            my $id      = $host->{id};
                            my $subnets = $host->{subnets};
                            @$subnets > 1
                              and err_msg
                              "$host->{name} with ID must expand to",
                              "exactly one subnet";
                            my $subnet = $subnets->[0];
                            for my $peer (@{ $tunnel_intf->{peers} }) {
                                $peer->{id_rules}->{$id} = {
                                    name       => "$peer->{name}.$id",
                                    ip         => 'tunnel',
                                    src        => $subnet,
                                    no_nat_set => $peer->{no_nat_set},

                                    # Needed during local_optimization.
                                    router => $peer->{router},
                                };
                            }
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
                    " together at $tunnel_intf->{name}: ",
                    join(', ', map { $_->{name} } @encrypted)
                  );
                     $has_id_hosts
                  or $has_other_network
                  or err_msg(
                    "Must use network or host with ID",
                    " at $tunnel_intf->{name}: ",
                    join(', ', map { $_->{name} } @encrypted)
                  );

                for my $peer (@{ $tunnel_intf->{peers} }) {
                    $peer->{peer_networks} = \@encrypted;

                    # ID can only be checked at hub with attribute do_auth.
                    my $router  = $peer->{router};
                    my $do_auth = $router->{model}->{do_auth};
                    if ($tunnel_intf->{id}) {
                        $do_auth
                          or err_msg "$router->{name} can't check IDs",
                          " of $tunnel_intf->{name}";
                    }
                    elsif ($encrypted[0]->{has_id_hosts}) {
                        $do_auth
                          or err_msg "$router->{name} can't check IDs",
                          " of $tunnel_intf->{name}";
                    }
                    elsif ($do_auth) {
                        err_msg "$router->{name} can only check",
                          " interface or host having ID",
                          " at $tunnel_intf->{name}";
                    }
                }

                # Add rules to permit crypto traffic between
                # tunnel endpoints.
                # If one tunnel endpoint has no known IP address,
                # some rules have to be added manually.
                my $real_spoke = $tunnel_intf->{real_interface};
                if (    $real_spoke
                    and $real_spoke->{ip} !~ /^(?:short|unnumbered)$/)
                {
                    for my $hub (@{ $tunnel_intf->{peers} }) {
                        my $real_hub = $hub->{real_interface};
                        for my $pair (
                            [ $real_spoke, $real_hub ],
                            [ $real_hub,   $real_spoke ]
                          )
                        {
                            my ($intf1, $intf2) = @$pair;

                            # Don't generate incoming ACL from unknown
                            # address.
                            next if $intf1->{ip} eq 'negotiated';
                            my $rules_ref =
                              gen_tunnel_rules($intf1, $intf2,
                                $crypto->{type});
                            push @{ $expanded_rules{permit} }, @$rules_ref;
                            add_rules $rules_ref;
                        }
                    }
                }
            }
        }
    }

    # Check for duplicate IDs of different hosts
    # coming into current hardware interface / current device.
    for my $router (@managed_vpnhub) {
        my $is_asavpn = $router->{model}->{crypto} eq 'ASA_VPN';
        my %hardware2id2tunnel;
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{ip} eq 'tunnel';

            # ASA_VPN can't distinguish different hosts with same ID
            # coming into different hardware interfaces.
            my $hardware = $is_asavpn ? 'one4all' : $interface->{hardware};
            my $tunnel = $interface->{network};
            if (my $hash = $interface->{id_rules}) {
                for my $id (keys %$hash) {
                    if (my $tunnel2 = $hardware2id2tunnel{$hardware}->{$id}) {
                        err_msg "Using identical ID $id from different",
                          " $tunnel->{name} and $tunnel2->{name}";
                    }
                    else {
                        $hardware2id2tunnel{$hardware}->{$id} = $tunnel;
                    }
                }
            }
        }
    }

    # Hash only needed during expand_group and expand_rules.
    %auto_interfaces = ();
    return;
}

# Hash for converting a reference of an object back to this object.
my %ref2obj;

sub setup_ref2obj  {
    for my $network (@networks) {
        $ref2obj{$network} = $network;
        for my $obj (@{ $network->{subnets} }, @{ $network->{interfaces} }) {
            $ref2obj{$obj} = $obj;
        }
    }
    return;
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
    ($net1, $net2) = ($net2, $net1) if $net1->{mask} < $net2->{mask};
    while (1) {
        while ($net1->{mask} > $net2->{mask}) {
            $net1 = $net1->{up};
        }
        return $net1 if $net1 eq $net2;
        $net2 = $net2->{up} or return;
    }
    return; # unused; only for perlcritic
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
    my $no_nat_set = $interface->{no_nat_set};
    my $nat_other = get_nat_network($other, $no_nat_set);
    return 0 if $nat_other->{hidden};
    my ($ip, $mask) = @{$nat_other}{qw(ip mask)};
    my $key = "$ip/$mask";
    if (my $aggregate = $zone->{ipmask2aggregate}->{$key}) {
        return $aggregate;
    }
    if (my $result = $zone->{ipmask2net}->{$key}) {
        return $result;
    }

    # Real networks in zone without aggregates and without subnets.
    my $networks = $zone->{networks};
    my $result   = 0;
    for my $network (@$networks) {
        my $nat_network = get_nat_network($network, $no_nat_set);
        my ($i, $m) = @{$nat_network}{qw(ip mask)};
        next if $i =~ /^(?:unnumbered|tunnel)$/;

        if (   $m >= $mask && match_ip($i, $ip, $mask)
            || $m < $mask && match_ip($ip, $i, $m))
        {

            # Found first matching network.
            if (!$result) {
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
    if (!$net_or_count) {
        return;
    }

    # More than one network matches and no supernet exists.
    # Return names of that networks.
    if (!ref($net_or_count)) {
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

    my ($stateless, $action, $src, $dst, $src_range, $prt) =
      @{$rule}{qw(stateless action src dst src_range prt)};
    my $other = $where eq 'src' ? $src : $dst;

    my $networks = find_matching_supernet($interface, $zone, $other);
    return if not $networks;
    my $extra;
    if (!ref($networks)) {
        $extra = "No supernet available for $networks";
    }
    else {

        # $networks holds matching network and all its supernets.
        # Find first matching rule.
        for my $network (@$networks) {
            ($where eq 'src' ? $src : $dst) = $network;
            if ($rule_tree{$stateless}->{$action}->{$src}->{$dst}
                ->{$src_range}->{$prt})
            {
                return;
            }
        }
        $extra = "Tried " . join(', ', map { $_->{name} } @$networks);
    }

    my $service = $rule->{rule}->{service};
    return if $missing_supernet{$interface}->{$service};
    $missing_supernet{$interface}->{$service} = 1;

    $rule = print_rule $rule;
    $reversed = $reversed ? 'reversed ' : '';
    my $print =
      $config{check_supernet_rules} eq 'warn' ? \&warn_msg : \&err_msg;
    $print->(
        "Missing rule for ${reversed}supernet rule.\n",
        " $rule\n",
        " can't be effective at $interface->{name}.\n",
        " $extra as $where."
    );
    return;
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

    # Function is called from path_walk.
    my ($rule, $in_intf, $out_intf) = @_;

    # Destination is interface of current router and therefore there is
    # nothing to be checked.
    return unless $out_intf;

    # Ignore semi_managed router.
    my $router = $in_intf->{router};
    return if not $router->{managed};

    my $out_zone = $out_intf->{zone};
    my $dst      = $rule->{dst};
    my $dst_zone = get_zone($dst);
    if ($dst->{is_supernet} && $out_zone eq $dst_zone) {

        # Both src and dst are supernets and are directly connected
        # at current router. Hence there can't be any missing rules.
        # Note: Additional checks will be done for this situation at
        # check_supernet_dst_rule
        return;
    }
    my $in_zone = $in_intf->{zone};

    # Check case II, outgoing ACL, (A)
    my $no_acl_intf;
    if ($no_acl_intf = $router->{no_in_acl}) {
        my $no_acl_zone = $no_acl_intf->{zone};

        # a) dst behind Y
        if ($no_acl_zone eq $dst_zone) {
        }

        # b), 1. zone X == zone Y
        elsif ($in_zone eq $no_acl_zone) {
        }

        elsif (has_global_restrict($no_acl_intf)) {
        }

        # b), 2. zone X != zone Y
        else {
            check_supernet_in_zone($rule, 'src', $no_acl_intf, $no_acl_zone);
        }
    }
    my $src      = $rule->{src};
    my $src_zone = $src->{zone};

    # Check if reverse rule would be created and would need additional rules.
    if ($router->{model}->{stateless} && !$rule->{oneway})

    {
        my $proto = $rule->{prt}->{proto};

        # Reverse rule wouldn't allow too much traffic, if a non
        # secondary stateful device filters between current device and dst.
        # This is true if $out_zone and $dst_zone have different
        # {stateful_mark}.
        # If dst is managed interface, {stateful_mark} is undef
        # - if device is secondary managed, take mark of attached network
        # - else take value -1, different from all marks.
        # $src is supernet (not an interface) by definition
        # and hence $m1 is well defined.
        my $m1 = $out_zone->{stateful_mark};
        my $m2 = $dst_zone->{stateful_mark};
        if (!$m2) {
            my $managed = $dst->{router}->{managed};
            $m2 =
                $managed =~ /^(?:secondary|local)$/
              ? $dst->{network}->{zone}->{stateful_mark}
              : -1;
        }
        if (($proto eq 'tcp' || $proto eq 'udp' || $proto eq 'ip')
            && $m1 == $m2)
        {

            # Check case II, outgoing ACL, (B), interface Y without ACL.
            if (my $no_acl_intf = $router->{no_in_acl}) {
                my $no_acl_zone = $no_acl_intf->{zone};

                # a) dst behind Y
                if ($no_acl_zone eq $dst_zone) {
                }

                # b) dst not behind Y
                # zone X == zone Y
                elsif ($no_acl_zone eq $src_zone) {
                }

                elsif (has_global_restrict($no_acl_intf)) {
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
                    next if $zone eq $src_zone;
                    next if $zone eq $dst_zone;
                    next if has_global_restrict($intf);
                    check_supernet_in_zone($rule, 'src', $intf, $zone, 1);
                }
            }
        }
    }

    # Nothing to do at first router.
    # zone2 is checked at R2, because we need the no_nat_set at R2.
    return if $src_zone eq $in_zone;

    # Check if rule "supernet2 -> dst" is defined.
    check_supernet_in_zone($rule, 'src', $in_intf, $in_zone);
    return;
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

    # Function is called from path_walk.
    my ($rule, $in_intf, $out_intf) = @_;

    # Source is interface of current router.
    return unless $in_intf;

    # Ignore semi_managed router.
    my $router = $in_intf->{router};
    return if not $router->{managed};

    my $src      = $rule->{src};
    my $src_zone = get_zone($src);
    my $dst      = $rule->{dst};
    my $dst_zone = $dst->{zone};

    # Check case II, outgoing ACL, (B), interface Y without ACL.
    if (my $no_acl_intf = $router->{no_in_acl}) {
        my $no_acl_zone = $no_acl_intf->{zone};

        # a) src behind Y
        if ($no_acl_zone eq $src_zone) {
        }

        # b) src not behind Y
        # zone X == zone Y
        elsif ($no_acl_zone eq $dst_zone) {
        }

        elsif (has_global_restrict($no_acl_intf)) {
        }

        # zone X != zone Y
        else {
            check_supernet_in_zone($rule, 'dst', $in_intf, $no_acl_zone);
        }
        return;
    }

    # Check security zones at all interfaces except the out_intf.
    # For devices which have rules for each pair of incoming and outgoing
    # interfaces we only need to check the direct path.
    for my $intf (
        $router->{model}->{has_io_acl}
        ? ($in_intf)
        : @{ $router->{interfaces} }
      )
    {

        # Check each intermediate zone only once at outgoing interface.
        next if $intf eq $in_intf;
        next if $intf->{loopback};

        # Don't check interface where src or dst is attached.
        my $zone = $intf->{zone};
        next if $zone eq $src_zone;
        next if $zone eq $dst_zone;
        next if has_global_restrict($intf);
        check_supernet_in_zone($rule, 'dst', $in_intf, $zone);
    }
    return;
}

# Find smaller protocol of two protocols.
# Cache results.
my %smaller_prt;

sub find_smaller_prt  {
    my ($prt1, $prt2) = @_;

    if ($prt1 eq $prt2) {
        return $prt1;
    }
    if (defined(my $prt = $smaller_prt{$prt1}->{$prt2})) {
        return $prt;
    }

    my $prt = $prt1;
    while ($prt = $prt->{up}) {
        if ($prt eq $prt2) {
            $smaller_prt{$prt1}->{$prt2} = $prt1;
            $smaller_prt{$prt2}->{$prt1} = $prt1;
            return $prt1;
        }
    }
    $prt = $prt2;
    while ($prt = $prt->{up}) {
        if ($prt eq $prt1) {
            $smaller_prt{$prt1}->{$prt2} = $prt2;
            $smaller_prt{$prt2}->{$prt1} = $prt2;
            return $prt2;
        }
    }
    $smaller_prt{$prt1}->{$prt2} = 0;
    $smaller_prt{$prt2}->{$prt1} = 0;
    return 0;
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
#
# ToDo:
# Do we need to check for {zone_cluster} equality?
#
# Currently we only check aggregates/supernets with mask = 0.
# Checking of other aggregates is too complicate (NAT, intersection).

# Collect info about unwanted implied rules.
sub check_for_transient_supernet_rule {
    my %missing_rule_tree;
    my $missing_count = 0;

    for my $rule (@{ $expanded_rules{supernet} }) {
        next if $rule->{deleted};
        next if $rule->{action} ne 'permit';
        next if $rule->{no_check_supernet_rules};
        my $dst = $rule->{dst};
        next if not $dst->{is_supernet};

        # Check only 0/0 aggregates.
        next if $dst->{mask} != 0;

        # A leaf security zone has only one interface.
        # It can't lead to unwanted rule chains.
        next if @{ $dst->{zone}->{interfaces} } <= 1;

        my ($stateless1, $src1, $dst1, $src_range1, $prt1) =
          @$rule{ 'stateless', 'src', 'dst', 'src_range', 'prt' };

        # Find all rules with supernet as source, which intersects with $dst1.
        my $src2 = $dst1;
        for my $stateless2 (1, 0) {
            while (my ($dst2_str, $hash) =
                each %{ $rule_tree{$stateless2}->{permit}->{$src2} })
            {

                # Skip reverse rules.
                next if $src1 eq $dst2_str;

                my $dst2 = $ref2obj{$dst2_str};

                # Skip rules with src and dst inside a single zone.
                next
                  if (($obj2zone{$src1} || get_zone $src1) eq
                    ($obj2zone{$dst2} || get_zone $dst2));

                while (my ($src_range2_str, $hash) = each %$hash) {
                  RULE2:
                    while (my ($prt2_str, $rule2) = each %$hash) {
                        next if $rule2->{no_check_supernet_rules};

                        my $prt2       = $rule2->{prt};
                        my $src_range2 = $rule2->{src_range};

                        # Find smaller protocol of two rules found.
                        my $smaller_prt = find_smaller_prt $prt1, $prt2;
                        my $smaller_src_range = find_smaller_prt $src_range1,
                          $src_range2;

                        # If protocols are disjoint, we do not have
                        # transient-supernet-problem for $rule and $rule2.
                        next if not $smaller_prt or not $smaller_src_range;

                        # Stateless rule < stateful rule, hence use ||.
                        # Force a unique value for boolean result.
                        my $stateless = ($stateless1 || $stateless2) + 0;

                        # Check for a rule with $src1 and $dst2 and
                        # with $smaller_prt.
                        while (1) {
                            my $action = 'permit';
                            if (my $hash = $rule_tree{$stateless}) {
                                while (1) {
                                    my $src = $src1;
                                    if (my $hash = $hash->{$action}) {
                                        while (1) {
                                            my $dst = $dst2;
                                            if (my $hash = $hash->{$src}) {
                                                while (1) {
                                                    my $src_range =
                                                      $smaller_src_range;
                                                    if (my $hash =
                                                        $hash->{$dst})
                                                    {
                                                        while (1) {
                                                            my $prt =
                                                              $smaller_prt;
                                                            if (my $hash =
                                                                $hash
                                                                ->{$src_range})
                                                            {
                                                                while (1) {
                                                                    if (
                                                                        my $other_rule
                                                                        = $hash
                                                                        ->{$prt}
                                                                      )
                                                                    {

# debug(print_rule $other_rule);
                                                                        next
                                                                          RULE2;
                                                                    }
                                                                    $prt =
                                                                      $prt->{up}
                                                                      or last;
                                                                }
                                                            }
                                                            $src_range =
                                                              $src_range->{up}
                                                              or last;
                                                        }
                                                    }
                                                    $dst = $dst->{up} or last;
                                                }
                                            }
                                            $src = $src->{up} or last;
                                        }
                                    }
                                    last if $action eq 'deny';
                                    $action = 'deny';
                                }
                            }
                            last if !$stateless;

                            # Boolean value "false" is used as hash key, hence we take '0'.
                            $stateless = 0;
                        }

# debug("Src: ", print_rule $rule);
# debug("Dst: ", print_rule $rule2);
                        my $src_service = $rule->{rule}->{service}->{name};
                        my $dst_service = $rule2->{rule}->{service}->{name};
                        my $prt_name    = $smaller_prt->{name};
                        $prt_name =~ s/^.part_/[part]/;
                        if (    $smaller_src_range ne $range_tcp_any
                            and $smaller_src_range ne $prt_ip)
                        {
                            my ($p1, $p2) = @{ $smaller_src_range->{range} };
                            if ($p1 != 1 or $p2 != 65535) {
                                $prt_name = "[src:$p1-$p2]$prt_name";
                            }
                        }
                        my $new =
                          not $missing_rule_tree{$src_service}->{$dst_service}

                          # The matching supernet object.
                          ->{ $dst1->{name} }

                          # The missing rule
                          ->{ $src1->{name} }->{ $dst2->{name} }->{$prt_name}++;
                        $missing_count++ if $new;
                    }
                }
            }
        }
    }

    # No longer needed; free some memory.
    %smaller_prt = ();

    if ($missing_count) {

        my $print =
          $config{check_transient_supernet_rules} eq 'warn'
          ? \&warn_msg
          : \&err_msg;
        $print->("Missing transient rules: $missing_count");

        while (my ($src_service, $hash) = each %missing_rule_tree) {
            while (my ($dst_service, $hash) = each %$hash) {
                while (my ($supernet, $hash) = each %$hash) {
                    info
                      "Rules of $src_service and $dst_service match at $supernet";
                    info("Missing transient rules:");
                    while (my ($src, $hash) = each %$hash) {
                        while (my ($dst, $hash) = each %$hash) {
                            while (my ($prt, $hash) = each %$hash) {
                                info(" permit src=$src; dst=$dst; prt=$prt");
                            }
                        }
                    }
                }
            }
        }
    }
    return;
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
        if ($router->{managed}) {
            next
              if !$router->{model}->{stateless}
                  && $router->{managed} !~ /^(?:secondary|local)$/;
        }
        next if $router->{active_path};
        $router->{active_path} = 1;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $in_interface;
            my $next_zone = $out_interface->{zone};
            next if $next_zone->{stateful_mark};
            mark_stateful($next_zone, $mark);
        }
        delete $router->{active_path};
    }
    return;
}

sub check_supernet_rules {
    progress('Checking rules with supernet objects');
    if ($config{check_supernet_rules}) {
        my $stateful_mark = 1;
        for my $zone (@zones) {
            if (not $zone->{stateful_mark}) {
                mark_stateful($zone, $stateful_mark++);
            }
        }
        for my $rule (@{ $expanded_rules{supernet} }) {
            next if $rule->{deleted};
            next if $rule->{no_check_supernet_rules};
            if ($rule->{src}->{is_supernet}) {
                path_walk($rule, \&check_supernet_src_rule);
            }
            if ($rule->{dst}->{is_supernet}) {
                path_walk($rule, \&check_supernet_dst_rule);
            }
        }
        %missing_supernet = ();
    }
    if ($config{check_transient_supernet_rules}) {
        check_for_transient_supernet_rule();
    }

    # no longer needed; free some memory.
    %obj2zone = ();
    return;
}

##############################################################################
# Generate reverse rules for stateless packet filters:
# For each rule with protocol tcp, udp or ip we need a reverse rule
# with swapped src, dst and src-port, dst-port.
# For rules with a tcp protocol, the reverse rule gets a tcp protocol
# without range checking but with checking for 'established` flag.
##############################################################################

sub gen_reverse_rules1  {
    my ($rule_aref) = @_;
    my @extra_rules;
    for my $rule (@$rule_aref) {
        if ($rule->{deleted}) {
            my $src = $rule->{src};

            # If source is a managed interface,
            # reversed will get attribute managed_intf.
            unless (is_interface($src) and $src->{router}->{managed}) {
                next;
            }
        }
        my $prt   = $rule->{prt};
        my $proto = $prt->{proto};
        next unless $proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip';
        next if $rule->{oneway};

        # No reverse rules will be generated for denied TCP packets, because
        # - there can't be an answer if the request is already denied and
        # - the 'established' optimization for TCP below would produce
        #   wrong results.
        next if $proto eq 'tcp' and $rule->{action} eq 'deny';

        my $has_stateless_router;
      PATH_WALK:
        {

            # Local function.
            # It uses free variable $has_stateless_router.
            my $mark_reverse_rule = sub {
                my ($rule, $in_intf, $out_intf) = @_;

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
                    no warnings "exiting";	## no critic (ProhibitNoWarn)
                    last PATH_WALK if $use_nonlocal_exit;
                }
            };
            path_walk($rule, $mark_reverse_rule);
        }
        if ($has_stateless_router) {
            my $new_src_range;
            my $new_prt;
            if ($proto eq 'tcp') {
                $new_src_range = $range_tcp_any;
                $new_prt       = $range_tcp_established;
            }
            elsif ($proto eq 'udp') {

                # Swap src and dst range.
                $new_src_range = $rule->{prt};
                $new_prt       = $rule->{src_range};
            }
            elsif ($proto eq 'ip') {
                $new_prt       = $rule->{prt};
                $new_src_range = $rule->{src_range};
            }
            else {
                internal_err();
            }
            my $new_rule = {

                # This rule must only be applied to stateless routers.
                stateless => 1,
                action    => $rule->{action},
                src       => $rule->{dst},
                dst       => $rule->{src},
                src_range => $new_src_range,
                prt       => $new_prt,
            };

            # Don't push to @$rule_aref while we are iterating over it.
            push @extra_rules, $new_rule;
        }
    }
    push @$rule_aref, @extra_rules;
    add_rules \@extra_rules;
    return;
}

sub gen_reverse_rules {
    progress('Generating reverse rules for stateless routers');
    for my $type ('deny', 'supernet', 'permit') {
        gen_reverse_rules1 $expanded_rules{$type};
    }
    return;
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

sub get_zone2 {
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        return $obj->{zone};
    }
    elsif ($type eq 'Subnet') {
        return $obj->{network}->{zone};
    }
    elsif ($type eq 'Interface') {
        return $obj->{network}->{zone};
    }
}

# Mark security zone $zone with $mark and
# additionally mark all security zones
# which are connected with $zone by secondary packet filters.
sub mark_secondary;

sub mark_secondary  {
    my ($zone, $mark) = @_;
    $zone->{secondary_mark} = $mark;

#    debug("$zone->{name} $mark");
    for my $in_interface (@{ $zone->{interfaces} }) {
        my $router = $in_interface->{router};
        if (my $managed = $router->{managed}) {
            next if $managed !~ /^(?:secondary|local)$/;
        }
        next if $router->{active_path};
        $router->{active_path} = 1;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $in_interface;
            my $next_zone = $out_interface->{zone};
            next if $next_zone->{secondary_mark};
            mark_secondary $next_zone, $mark;
        }
        delete $router->{active_path};
    }
    return;
}

# Mark security zone $zone with $mark and
# additionally mark all security zones
# which are connected with $zone by non-primary packet filters.
# Test for {active_path} has been added to prevent deep recursion.
sub mark_primary;

sub mark_primary  {
    my ($zone, $mark) = @_;
    $zone->{primary_mark} = $mark;
    for my $in_interface (@{ $zone->{interfaces} }) {
        my $router = $in_interface->{router};
        if (my $managed = $router->{managed}) {
            next if $managed eq 'primary';
        }
        next if $router->{active_path};
        $router->{active_path} = 1;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $in_interface;
            my $next_zone = $out_interface->{zone};
            next if $next_zone->{primary_mark};
            mark_primary $next_zone, $mark;
        }
        delete $router->{active_path};
    }
    return;
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

    # Mark only normal rules for secondary optimization.
    # Don't modify a deny rule from e.g. tcp to ip.
    # Don't modify supernet rules, because path isn't fully known.
    for my $rule (@{ $expanded_rules{permit} }, @{ $expanded_rules{supernet} })
    {
        next
          if $rule->{deleted}
              and
              (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});

        my ($src, $dst) = @{$rule}{qw(src dst)};
        next if $src->{is_aggregate} || $dst->{is_aggregate};
        my $src_zone = get_zone2($src);
        my $dst_zone = get_zone2($dst);

        if ($src_zone->{secondary_mark} ne $dst_zone->{secondary_mark}) {
            $rule->{some_non_secondary} = 1;
        }
        if ($src_zone->{primary_mark} ne $dst_zone->{primary_mark}) {
            $rule->{some_primary} = 1;
        }
    }

    # Find rules where dynamic NAT is applied to host or interface at
    # src or dst on path to other end of rule.
    # Mark found rule with attribute {dynamic_nat} and value src|dst|src,dst.
    progress('Marking rules with dynamic NAT');
    for my $rule (
        @{ $expanded_rules{permit} },
        @{ $expanded_rules{supernet} },
        @{ $expanded_rules{deny} }
      )
    {
        next
          if $rule->{deleted}
              and
              (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});

        my $dynamic_nat;
        for my $where ('src', 'dst') {
            my $obj  = $rule->{$where};
            my $type = ref $obj;
            my $network =
              ($type eq 'Network')
              ? $obj
              : $obj->{network};
            my $nat_hash = $network->{nat} or next;
            my $other      = $where eq 'src' ? $rule->{dst} : $rule->{src};
            my $otype      = ref $other;
            my $nat_domain = ($otype eq 'Network')
              ? $other->{nat_domain}    # Is undef for aggregate.
              : $other->{network}->{nat_domain};
            my $no_nat_set = $nat_domain ? $nat_domain->{no_nat_set} : {};
            my $hidden;
            my $dynamic;

          TAG:
            for my $nat_tag (keys %$nat_hash) {

                # Find $nat_tag which is effective at $other.
                # - simple: $other is host or network, $nat_domain is known.
                # - loop: $other is aggregate.
                #         Check all NAT domains inside the zone.
                if ($nat_domain) {
                    next if $no_nat_set->{$nat_tag};
                }
                else {
                    for my $interface (@{ $other->{zone}->{interfaces} }) {
                        my $no_nat_set = $interface->{no_nat_set};
                        next TAG if $no_nat_set->{$nat_tag};
                        last;
                    }
                }

                my $nat_network = $nat_hash->{$nat_tag};

                # Network is hidden by NAT.
                if ($nat_network->{hidden} and not $hidden) {
                    $hidden = 1;
                    err_msg("$obj->{name} is hidden by NAT in rule\n ",
                            print_rule $rule);
                }

                # Network has dynamic NAT.
                # Host / interface doesn't have static NAT.
                if (    $nat_network->{dynamic}
                    and ($type eq 'Subnet' or $type eq 'Interface')
                    and not $obj->{nat}->{$nat_tag}
                    and not $dynamic)
                {
                    # Check error condition: Dynamic NAT address is
                    # used in ACL at managed router at the border of
                    # the zone of $obj. 
                    # $intf could have value 'undef' if $obj is interface of
                    # current router and destination of rule.
                    my $check = sub {
                        my ($rule, $in_intf, $out_intf) = @_;
                        my $no_nat_set = $in_intf->{no_nat_set};
                        my $nat_network = 
                            get_nat_network($network, $no_nat_set);
                        my $nat_tag = $nat_network->{dynamic};
                        return if not $nat_tag;
                        return if $obj->{nat}->{$nat_tag};
                        my $intf = $where eq 'src' ? $in_intf : $out_intf;
                        if (!$intf || 
                            zone_eq($network->{zone}, $intf->{zone}))
                        {
                            err_msg "$obj->{name} needs static translation",
                                " for nat:$nat_tag to be valid in rule\n ",
                            print_rule $rule;
                        }
                    };
                    path_walk($rule, $check);
                        
                    $dynamic_nat =
                      $dynamic_nat
                      ? "$dynamic_nat,$where"
                      : $where;

#		    debug("dynamic_nat: $where at ", print_rule $rule);
                    $dynamic = 1;
                }
            }
        }
        $rule->{dynamic_nat} = $dynamic_nat if $dynamic_nat;
    }
    return;
}

##############################################################################
# Optimize expanded rules by deleting identical rules and
# rules which are overlapped by a more general rule
##############################################################################

sub optimize_rules {
    my ($cmp_hash, $chg_hash) = @_;
    while (my ($stateless, $chg_hash) = each %$chg_hash) {
        while (1) {
            if (my $cmp_hash = $cmp_hash->{$stateless}) {
                while (my ($action, $chg_hash) = each %$chg_hash) {
                    while (1) {
                        if (my $cmp_hash = $cmp_hash->{$action}) {
                            while (my ($src_ref, $chg_hash) = each %$chg_hash) {
                                my $src = $ref2obj{$src_ref};
                                while (1) {
                                    if (my $cmp_hash = $cmp_hash->{$src}) {
                                        while (my ($dst_ref, $chg_hash) =
                                            each %$chg_hash)
                                        {
                                            my $dst = $ref2obj{$dst_ref};
                                            while (1) {
                                                if (my $cmp_hash =
                                                    $cmp_hash->{$dst})
                                                {
                                                    while (
                                                        my ($src_range_ref,
                                                            $chg_hash)
                                                        = each %$chg_hash
                                                      )
                                                    {
                                                        my $src_range =
                                                          $ref2prt{
                                                            $src_range_ref};
                                                        while (1) {
                                                            if (my $cmp_hash =
                                                                $cmp_hash
                                                                ->{$src_range})
                                                            {
                                                                for
                                                                  my $chg_rule (
                                                                    values
                                                                    %$chg_hash)
                                                                {
                                                                    next
                                                                      if
                                                                        $chg_rule
                                                                          ->{deleted};
                                                                    my $prt =
                                                                      $chg_rule
                                                                      ->{prt};
                                                                    while (1) {
                                                                        if (
                                                                            my $cmp_rule
                                                                            = $cmp_hash
                                                                            ->{
                                                                                $prt
                                                                            }
                                                                          )
                                                                        {
                                                                            unless
                                                                              (
                                                                                $cmp_rule
                                                                                eq
                                                                                $chg_rule
                                                                              )
                                                                            {

# debug("Del:", print_rule $chg_rule);
# debug("Oth:", print_rule $cmp_rule);
                                                                                $chg_rule
                                                                                  ->
                                                                                  {deleted}
                                                                                  =
                                                                                  $cmp_rule;
                                                                                push
                                                                                  @deleted_rules,
                                                                                  $chg_rule;
                                                                                last;
                                                                            }
                                                                        }
                                                                        $prt =
                                                                          $prt
                                                                          ->{up}
                                                                          or
                                                                          last;
                                                                    }
                                                                }
                                                            }
                                                            $src_range =
                                                              $src_range->{up}
                                                              or last;
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
                        last if $action eq 'deny';
                        $action = 'deny';
                    }
                }
            }
            last if !$stateless;
            $stateless = 0;
        }
    }
    return;
}

sub optimize {
    progress('Optimizing globally');
    setup_ref2obj;
    optimize_rules \%rule_tree, \%rule_tree;
    print_rulecount;
    return;
}

sub optimize_and_warn_deleted {
    optimize();
    show_deleted_rules2();
    warn_unused_overlaps();
    return;
}

# Collect networks which need NAT commands.
sub mark_networks_for_static {
    my ($rule, $in_intf, $out_intf) = @_;

    # No NAT needed for directly attached interface.
    return unless $out_intf;

    # No NAT needed for traffic originating from the device itself.
    return unless $in_intf;

    my $router = $out_intf->{router};
    return unless $router->{managed};
    my $model = $router->{model};
    return unless $model->{has_interface_level};

    # We need in_hw and out_hw for
    # - attaching attribute src_nat and
    # - getting the NAT tag.
    my $in_hw  = $in_intf->{hardware};
    my $out_hw = $out_intf->{hardware};

    my $identity_nat = $model->{need_identity_nat};
    if ($identity_nat) {

        # Static dst NAT is equivalent to reversed src NAT.
        for my $dst (@{ $rule->{dst_net} }) {
            $out_hw->{src_nat}->{$in_hw}->{$dst} = $dst;
        }
        if ($in_hw->{level} > $out_hw->{level}) {
            $in_hw->{need_nat_0} = 1;
        }
    }

    # Not identity NAT, handle real dst NAT.
    elsif (my $nat_tags = $in_hw->{bind_nat}) {
        for my $dst (@{ $rule->{dst_net} }) {
            my $nat_info = $dst->{nat} or next;
            grep({ $nat_info->{$_} } @$nat_tags) or next;

            # Store reversed dst NAT for real translation.
            $out_hw->{src_nat}->{$in_hw}->{$dst} = $dst;
        }
    }

    # Handle real src NAT.
    # Remember:
    # NAT tag for network located behind in_hw is attached to out_hw.
    my $nat_tags = $out_hw->{bind_nat} or return;
    for my $src (@{ $rule->{src_net} }) {
        my $nat_info = $src->{nat} or next;

        # We can be sure to get a single result.
        # Binding for different NAT of a single network has been
        # rejected in distribute_nat_info.
        my ($nat_net) = map({ $nat_info->{$_} || () } @$nat_tags) or next;

        # Store src NAT for real translation.
        $in_hw->{src_nat}->{$out_hw}->{$src} = $src;

        if ($identity_nat) {

            # Check if there is a dynamic NAT of src address from lower
            # to higher security level. We need this info to decide,
            # if static commands with "identity mapping" and a "nat 0" command
            # need to be generated.
            if ($nat_net->{dynamic} and $in_hw->{level} < $out_hw->{level}) {
                $in_hw->{need_identity_nat} = 1;
                $in_hw->{need_nat_0}        = 1;
            }
        }
    }
    return;
}

sub get_zone3 {
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        return $obj->{zone};
    }
    elsif ($type eq 'Subnet') {
        return $obj->{network}->{zone};
    }
    elsif ($type eq 'Interface') {
        if ($obj->{router}->{managed} or $obj->{router}->{semi_managed}) {
            return $obj;
        }
        else {
            return $obj->{network}->{zone};
        }
    }
    else {
        internal_err();
    }
}

sub get_networks {
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        if ($obj->{is_aggregate}) {
            return @{ $obj->{networks} };
        }
        else {
            return $obj;
        }
    }
    elsif ($type eq 'Subnet' or $type eq 'Interface') {
        return $obj->{network};
    }
    else {
        internal_err("unexpected $obj->{name}");
    }
}

sub find_statics  {
    progress('Finding statics');

    # We only need to traverse the topology for each pair of
    # src-(zone/router), dst-(zone/router)
    my %zone2zone2rule;
    my $pseudo_prt = { name => '--' };
    for my $rule (@{ $expanded_rules{permit} }, @{ $expanded_rules{supernet} })
    {
        my ($src, $dst) = @{$rule}{qw(src dst)};
        my $from = get_zone3 $src;
        my $to   = get_zone3 $dst;
        $zone2zone2rule{$from}->{$to} ||= {
            src     => $from,
            dst     => $to,
            action  => '--',
            prt     => $pseudo_prt,
            src_net => {},
            dst_net => {},
        };
        my $rule2 = $zone2zone2rule{$from}->{$to};
        for my $network (get_networks($src)) {
            $rule2->{src_net}->{$network} = $network;
        }
        for my $network (get_networks($dst)) {
            $rule2->{dst_net}->{$network} = $network;
        }
    }
    for my $hash (values %zone2zone2rule) {
        for my $rule (values %$hash) {
            $rule->{src_net} = [ values %{ $rule->{src_net} } ];
            $rule->{dst_net} = [ values %{ $rule->{dst_net} } ];

#           debug("$rule->{src}->{name}, $rule->{dst}->{name}");
            path_walk($rule, \&mark_networks_for_static, 'Router');
        }
    }
    return;
}

########################################################################
# Routing
########################################################################

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
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        if ($obj->{is_aggregate}) {
            return @{ $obj->{networks} };
        }
        elsif (my $max = $obj->{max_up_net}) {
            return ($max, $obj);
        }
        else {
            return $obj;
        }
    }
    elsif ($type eq 'Subnet' or $type eq 'Interface') {
        my $net = $obj->{network};
        if (my $max = $net->{max_up_net}) {
            return ($max, $net);
        }
        else {
            return $net;
        }
    }
    else {
        internal_err("unexpected $obj->{name}");
    }
}

# Set up data structure to find routing info inside a security zone.
# Some definitions:
# - Border interfaces are directly attached to the security zone.
# - Border networks are located inside the security zone and are attached
#   to border interfaces.
# - All interfaces of border networks, which are not border interfaces,
#   are called hop interfaces, because they are used as next hop from
#   border interfaces.
# - A cluster is a maximal set of connected networks of the security zone,
#   which is surrounded by hop interfaces. A cluster can be empty.
# For each border interface I and each network N inside the security zone
# we need to find the hop interface H via which N is reached from I.
# This is stored in an attribute {route_in_zone} of I.
sub set_routes_in_zone  {
    my ($zone) = @_;

    # Mark border networks and hop interfaces.
    my %border_networks;
    my %hop_interfaces;
    for my $in_interface (@{ $zone->{interfaces} }) {
        next if $in_interface->{main_interface};
        my $network = $in_interface->{network};
        next if $border_networks{$network};
        $border_networks{$network} = $network;
        for my $out_interface (@{ $network->{interfaces} }) {
            next if $out_interface->{zone};
            next if $out_interface->{main_interface};
            $hop_interfaces{$out_interface} = $out_interface;
        }
    }
    return if not keys %hop_interfaces;
    my %hop2cluster;
    my %cluster2borders;
    my $set_cluster;
    $set_cluster = sub {
        my ($router, $in_intf, $cluster) = @_;
        return if $router->{active_path};
        $router->{active_path} = 1;
        for my $interface (@{ $router->{interfaces} }) {
            next if $interface->{main_interface};
            if ($hop_interfaces{$interface}) {
                $hop2cluster{$interface} = $cluster;
                my $network = $interface->{network};
                $cluster2borders{$cluster}->{$network} = $network;
                next;
            }
            next if $interface eq $in_intf;
            my $network = $interface->{network};
            next if $cluster->{$network};
            $cluster->{$network} = $network;
            for my $out_intf (@{ $network->{interfaces} }) {
                next if $out_intf eq $interface;
                next if $out_intf->{main_interface};
                $set_cluster->($out_intf->{router}, $out_intf, $cluster);
            }
        }
        delete $router->{active_path};
    };
    for my $interface (values %hop_interfaces) {
        next if $hop2cluster{$interface};
        my $cluster = {};
        $set_cluster->($interface->{router}, $interface, $cluster);

#	debug("Cluster: $interface->{name} ",
#             join ',', map {$_->{name}} values %$cluster);
    }

    # Find all networks located behind a hop interface.
    my %hop2networks;
    my $set_networks_behind;
    $set_networks_behind = sub {
        my ($hop, $in_border) = @_;
        return if $hop2networks{$hop};
        my $cluster = $hop2cluster{$hop};

        # Add networks of directly attached cluster to result.
        my @result = values %$cluster;
        $hop2networks{$hop} = \@result;

        for my $border (values %{ $cluster2borders{$cluster} }) {
            next if $border eq $in_border;

            # Add other border networks to result.
            push @result, $border;
            for my $out_hop (@{ $border->{interfaces} }) {
                next if not $hop_interfaces{$out_hop};
                next if $hop2cluster{$out_hop} eq $cluster;
                $set_networks_behind->($out_hop, $border);

                # Add networks from clusters located behind
                # other border networks.
                push @result, @{ $hop2networks{$out_hop} };
            }
        }
#	debug("Hop: $hop->{name} ", join ',', map {$_->{name}} @result);
    };
    for my $border (values %border_networks) {
        my @border_intf;
        my @hop_intf;
        for my $interface (@{ $border->{interfaces} }) {
            next if $interface->{main_interface};
            if ($interface->{zone}) {
                push @border_intf, $interface;
            }
            else {
                push @hop_intf, $interface;
            }
        }
        for my $hop (@hop_intf) {
            $set_networks_behind->($hop, $border);
            for my $interface (@border_intf) {
                for my $network (@{ $hop2networks{$hop} }) {
                    push @{ $interface->{route_in_zone}->{$network} }, $hop;
                }
            }
        }
    }
    return;
}

# A security zone is entered at $in_intf and exited at $out_intf.
# Find the hop H to reach $out_intf from $in_intf.
# Add routing entries at $in_intf that $dst_networks are reachable via H.
sub add_path_routes  {
    my ($in_intf, $out_intf, $dst_networks) = @_;
    return if $in_intf->{routing};
    my $out_net = $out_intf->{network};
    my $hops = $in_intf->{route_in_zone}->{$out_net} || [$out_intf];
    for my $hop (@$hops) {
        $in_intf->{hop}->{$hop} = $hop;
        for my $network (@$dst_networks) {

#	    debug("$in_intf->{name} -> $hop->{name}: $network->{name}");
            $in_intf->{routes}->{$hop}->{$network} = $network;
        }
    }
    return;
}

# A security zone is entered at $interface.
# $dst_networks are located inside the security zone.
# For each element N of $dst_networks find the next hop H to reach N.
# Add routing entries at $interface that N is reachable via H.
sub add_end_routes  {
    my ($interface, $dst_networks) = @_;
    return if $interface->{routing};
    my $intf_net      = $interface->{network};
    my $route_in_zone = $interface->{route_in_zone};
    for my $network (@$dst_networks) {
        next if $network eq $intf_net;
        my $hops = $route_in_zone->{$network}
          or internal_err("Missing route for $network->{name}",
                          " at $interface->{name}");
        for my $hop (@$hops) {
            $interface->{hop}->{$hop} = $hop;

#	    debug("$interface->{name} -> $hop->{name}: $network->{name}");
            $interface->{routes}->{$hop}->{$network} = $network;
        }
    }
    return;
}

# This function is called for each zone on the path from src to dst
# of $rule.
# If $in_intf and $out_intf are both defined, packets traverse this zone.
# If $in_intf is not defined, the src is this zone.
# If $out_intf is not defined, dst is this zone;
sub get_route_path {
    my ($rule, $in_intf, $out_intf) = @_;

#    debug("collect: $rule->{src}->{name} -> $rule->{dst}->{name}");
#    my $info = '';
#    $info .= $in_intf->{name} if $in_intf;
#    $info .= ' -> ';
#    $info .= $out_intf->{name} if $out_intf;
#    debug($info);

    if ($in_intf and $out_intf) {
        push @{ $rule->{path} }, [ $in_intf, $out_intf ];
    }
    elsif (not $in_intf) {
        push @{ $rule->{path_entries} }, $out_intf;
    }
    else {
        push @{ $rule->{path_exits} }, $in_intf;
    }
    return;
}

sub check_and_convert_routes;

sub find_active_routes  {
    progress('Finding routes');
    for my $zone (@zones) {
        set_routes_in_zone $zone;
    }
    my %routing_tree;
    my $pseudo_prt = { name => '--' };
    for my $rule (@{ $expanded_rules{permit} }, @{ $expanded_rules{supernet} })
    {
        my ($src, $dst) = ($rule->{src}, $rule->{dst});

        # Ignore deleted rules.
        # Add the typical check for {managed_intf}
        # which covers the destination interface.
        # Because we handle both directions at once,
        # we would need an attribute {managed_intf}
        # for the source interface as well. But this attribute doesn't exist
        # and we add an equivalent check for source.
        if (
                $rule->{deleted}
            and (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf})
            and (
                not(is_interface $src and $src->{router}->{managed})
                or (is_interface $rule->{deleted}->{src}
                    and $rule->{deleted}->{src}->{router}->{managed})
            )
          )
        {
            next;
        }
        my $src_zone = get_zone2 $src;
        my $dst_zone = get_zone2 $dst;

        # Source interface is located in security zone of destination or
        # destination interface is located in security zone of source.
        # path_walk will do nothing.
        if ($src_zone eq $dst_zone) {
            for my $from ($src, $dst) {
                my $to = $from eq $src ? $dst : $src;
                next if not is_interface($from);
                next if not $from->{zone};
                $from = $from->{main_interface} || $from;
                my @networks = get_route_networks($to);
                add_end_routes($from, \@networks);
            }
            next;
        }
        my $pseudo_rule;
        if ($pseudo_rule = $routing_tree{$src_zone}->{$dst_zone}) {
        }
        elsif ($pseudo_rule = $routing_tree{$dst_zone}->{$src_zone}) {
            ($src,      $dst)      = ($dst,      $src);
            ($src_zone, $dst_zone) = ($dst_zone, $src_zone);
        }
        else {
            $pseudo_rule = {
                src    => $src_zone,
                dst    => $dst_zone,
                action => '--',
                prt    => $pseudo_prt,
            };
            $routing_tree{$src_zone}->{$dst_zone} = $pseudo_rule;
        }
        my @src_networks = get_route_networks($src);
        for my $network (@src_networks) {
            $pseudo_rule->{src_networks}->{$network} = $network;
        }
        my @dst_networks = get_route_networks($dst);
        for my $network (@dst_networks) {
            $pseudo_rule->{dst_networks}->{$network} = $network;
        }
        if (is_interface $src and $src->{router}->{managed}) {
            $src = $src->{main_interface} || $src;
            $pseudo_rule->{src_interfaces}->{$src} = $src;
            for my $network (@dst_networks) {
                $pseudo_rule->{src_intf2nets}->{$src}->{$network} = $network;
            }
        }
        if (is_interface $dst and $dst->{router}->{managed}) {
            $dst = $dst->{main_interface} || $dst;
            $pseudo_rule->{dst_interfaces}->{$dst} = $dst;
            for my $network (@src_networks) {
                $pseudo_rule->{dst_intf2nets}->{$dst}->{$network} = $network;
            }
        }
    }
    for my $href (values %routing_tree) {
        for my $pseudo_rule (values %$href) {
            path_walk($pseudo_rule, \&get_route_path, 'Zone');
            my $src_networks   = [ values %{ $pseudo_rule->{src_networks} } ];
            my $dst_networks   = [ values %{ $pseudo_rule->{dst_networks} } ];
            my @src_interfaces = values %{ $pseudo_rule->{src_interfaces} };
            my @dst_interfaces = values %{ $pseudo_rule->{dst_interfaces} };
            for my $tuple (@{ $pseudo_rule->{path} }) {
                my ($in_intf, $out_intf) = @$tuple;
                add_path_routes($in_intf,  $out_intf, $dst_networks);
                add_path_routes($out_intf, $in_intf,  $src_networks);
            }
            for my $entry (@{ $pseudo_rule->{path_entries} }) {
                for my $src_intf (@src_interfaces) {
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
                add_end_routes($entry, $src_networks);
            }
            for my $exit (@{ $pseudo_rule->{path_exits} }) {
                for my $dst_intf (@dst_interfaces) {
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
                add_end_routes($exit, $dst_networks);
            }
        }
    }
    check_and_convert_routes;
    return;
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
        for my $hop2 (values %{ $interface->{hop} }) {
            for my $network2 (values %{ $interface->{routes}->{$hop2} }) {
                if ($network eq $network2) {
                    if ($hop2->{ip} eq 'bridge') {
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

sub check_and_convert_routes  {
    progress('Checking for duplicate routes');

    # Fix routes to bridged interfaces without IP address.
    for my $router (@managed_routers) {
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{network}->{bridged};
            for my $hop (values %{ $interface->{hop} }) {
                next if $hop->{ip} ne 'bridged';
                for my $network (values %{ $interface->{routes}->{$hop} }) {
                    my @real_hop = fix_bridged_hops($hop, $network);
                    for my $rhop (@real_hop) {
                        $interface->{hop}->{$rhop} = $rhop;
                        $interface->{routes}->{$rhop}->{$network} = $network;
                    }
                }
                delete $interface->{hop}->{$hop};
                delete $interface->{routes}->{$hop};
            }
        }
    }

    for my $router (@managed_routers) {

        # Adjust routes through VPN tunnel to cleartext interface.
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{ip} eq 'tunnel';
            my $tunnel_routes = $interface->{routes};
            $interface->{routes} = $interface->{hop} = {};
            my $real_intf = $interface->{real_interface};
            next if $real_intf->{routing};
            for my $peer (@{ $interface->{peers} }) {
                my $real_peer = $peer->{real_interface};
                my $peer_net  = $real_peer->{network};

                # Find hop to peer network and add tunnel networks to this hop.
                my $hop_routes;

                # Special case: peer network is directly connected.
                if ($real_intf->{network} eq $peer_net) {
                    if ($real_peer->{ip} !~ /^(?:short|negotiated)$/) {
                        $hop_routes = $real_intf->{routes}->{$real_peer} ||= {};
                        $real_intf->{hop}->{$real_peer} = $real_peer;
                    }
                }

                # Search peer network behind all available hops.
                else {
                    for my $net_hash (values %{ $real_intf->{routes} }) {
                        if ($net_hash->{$peer_net}) {
                            $hop_routes = $net_hash;
                            last;
                        }
                    }
                }

                if (not $hop_routes) {

                    # Try to guess default route, if only one hop is available.
                    my @try_hops =
                      grep({ $_ ne $real_intf }
                        grep({ $_->{ip} !~ /^(?:short|negotiated)$/ }
                            @{ $real_intf->{network}->{interfaces} }));

                    if (@try_hops == 1) {
                        my $hop = $try_hops[0];
                        $hop_routes = $real_intf->{routes}->{$hop} ||= {};
                        $real_intf->{hop}->{$hop} = $hop;
                    }
                }

                # Use found hop to reach tunneled networks in $tunnel_routes.
                if ($hop_routes) {
                    for my $tunnel_net_hash (values %$tunnel_routes) {
                        for my $tunnel_net (values %$tunnel_net_hash) {
                            $hop_routes->{$tunnel_net} = $tunnel_net;
                        }
                    }
                }

                # This should never happen, because the route is known 
                # for the encrypted traffic which is allowed 
                # by gen_tunnel_rules (even for negotiated interface).
                else {
                    internal_err(
                      "Can't determine next hop while moving routes\n",
                      " of $interface->{name} to $real_intf->{name}"
                    );
                }
            }
        }

        # Remember, via which local interface a network is reached.
        my %net2intf;

        for my $interface (@{ $router->{interfaces} }) {

            # Remember, via which remote interface a network is reached.
            my %net2hop;

            # Remember, via which remote redundancy interfaces a network
            # is reached. We use this to check, if alle members of a group
            # of redundancy interfaces are used to reach the network.
            # Otherwise it would be wrong to route to the virtual interface.
            my %net2group;

            next if $interface->{loop} and $interface->{routing};
            next if $interface->{ip} eq 'bridged';
            for my $hop ( sort by_name values %{ $interface->{hop} }) {
                for my $network (values %{ $interface->{routes}->{$hop} }) {
                    if (my $interface2 = $net2intf{$network}) {
                        if ($interface2 ne $interface) {

                            # Network is reached via two different
                            # local interfaces.  Show warning if static
                            # routing is enabled for both interfaces.
                            if (    not $interface->{routing}
                                and not $interface2->{routing})
                            {
                                warn_msg (
                                  "Two static routes for $network->{name}\n",
                                  " via $interface->{name} and",
                                  " $interface2->{name}"
                                );
                            }
                        }
                    }
                    else {
                        $net2intf{$network} = $interface;
                    }
                    unless ($interface->{routing}) {
                        my $group = $hop->{redundancy_interfaces};
                        if ($group) {
                            push @{ $net2group{$network} }, $hop;
                        }
                        if (my $hop2 = $net2hop{$network}) {

                            # Network is reached via two different hops.
                            # Check if both belong to same group
                            # of redundancy interfaces.
                            my $group2 = $hop2->{redundancy_interfaces};
                            if ($group && $group2 && $group eq $group2) {

                                # Prevent multiple identical routes to
                                # different interfaces
                                # with identical virtual IP.
                                delete $interface->{routes}->{$hop}->{$network};
                            }
                            else {
                                warn_msg (
                                  "Two static routes for $network->{name}\n",
                                  " at $interface->{name}",
                                  " via $hop->{name} and $hop2->{name}"
                                );
                            }
                        }
                        else {
                            $net2hop{$network} = $hop;
                        }
                    }
                }
            }
            for my $net_ref (keys %net2group) {
                my $hops = $net2group{$net_ref};
                my $hop1 = $hops->[0];
                next if @$hops == @{ $hop1->{redundancy_interfaces} };
                my $network = $interface->{routes}->{$hop1}->{$net_ref};

                # A network is routed to a single physical interface.
                # It is probably a loopback interface of the same device.
                # Move hop from virtual to physical interface.
                if (@$hops == 1 && (my $phys_hop = $hop1->{orig_main})) {
                    delete $interface->{routes}->{$hop1}->{$net_ref};
                    $interface->{routes}->{$phys_hop}->{$network} = $network;
                    $interface->{hop}->{$phys_hop} = $phys_hop;
                }
                else {

                    # This can't occur, because we reject group of
                    # more than 3 virtual interfaces together with
                    # pathrestrictions.
                    internal_err(
                        "$network->{name} is reached via $hop1->{name}\n",
                        " but not via all related redundancy interfaces"
                    );
                }
            }

            # Convert to array, because hash isn't needed any longer.
            # Array is sorted to get deterministic output.
            $interface->{hop} =
              [ sort by_name values %{ $interface->{hop} } ];
        }
    }
    return;
}

sub find_active_routes_and_statics  {
    find_statics;
    find_active_routes;
    return;
}

sub ios_route_code;
sub prefix_code;
sub address;

sub print_routes {
    my ($router)              = @_;
    my $model                 = $router->{model};
    my $type                  = $model->{routing};
    my $vrf                   = $router->{vrf};
    my $comment_char          = $model->{comment_char};
    my $do_auto_default_route = $config{auto_default_route};
    my $crypto_type           = $model->{crypto} || '';
    my %intf2hop2nets;
    for my $interface (@{ $router->{interfaces} }) {
        next if $interface->{ip} eq 'bridged';
        if ($interface->{routing}) {
            $do_auto_default_route = 0;
            next;
        }

        my $optimize = 1;

        # ASA with site-to-site VPN needs individual routes for each peer.
        if ($interface->{hub} && $crypto_type eq 'ASA') {
            $do_auto_default_route = 0;
            $optimize = 0;
        }
        my $no_nat_set = $interface->{no_nat_set};

        for my $hop (@{ $interface->{hop} }) {
            my %mask_ip_hash;

            # A hash having all networks reachable via current hop
            # both as key and as value.
            my $net_hash = $interface->{routes}->{$hop};
            for my $network (values %$net_hash) {
                my $nat_network = get_nat_network($network, $no_nat_set);
                my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };
                if ($ip == 0 and $mask == 0) {
                    $do_auto_default_route = 0;
                }

                # Implicitly overwrite duplicate networks.
                $mask_ip_hash{$mask}->{$ip} = $nat_network;
            }

            # Find and remove duplicate networks.
            # Go from smaller to larger networks.
            my @netinfo;
            for my $mask (reverse sort keys %mask_ip_hash) {
              NETWORK:
                for my $ip (sort numerically keys %{ $mask_ip_hash{$mask} }) {

                    if ($optimize) {
                        my $m = $mask;
                        my $i = $ip;
                        while ($m) {
                            
                            # Clear upper bit, because left shift is undefined
                            # otherwise.
                            $m = $m & 0x7fffffff;
                            $m <<= 1;
                            $i = $i & $m;    # Perl bug #108480.
                            if ($mask_ip_hash{$m}->{$i}) {
                                
                                # Network {$mask}->{$ip} is redundant.
                                # It is covered by {$m}->{$i}.
                                next NETWORK;
                            }
                        }
                    }
                    push(@netinfo, [ $ip, $mask, $mask_ip_hash{$mask}->{$ip} ]);
                }
            }
            $intf2hop2nets{$interface}->{$hop} = \@netinfo;
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
            next if $interface->{ip} eq 'bridged';
            for my $hop (@{ $interface->{hop} }) {
                my $count = @{ $intf2hop2nets{$interface}->{$hop} };
                if ($count > $max) {
                    $max_intf = $interface;
                    $max_hop  = $hop;
                    $max      = $count;
                }
            }
        }
        if ($max_intf && $max_hop) {

            # Use default route for this direction.
            $intf2hop2nets{$max_intf}->{$max_hop} = [ [ 0, 0 ] ];
        }
    }
    print "$comment_char [ Routing ]\n";

    my $ios_vrf;
    $ios_vrf = $vrf ? "vrf $vrf " : '' if $type eq 'IOS';
    my $nxos_prefix = '';

    for my $interface (@{ $router->{interfaces} }) {
        next if $interface->{ip} eq 'bridged';

        # Don't generate static routing entries,
        # if a dynamic routing protocol is activated
        if ($interface->{routing}) {
            if ($config{comment_routes}) {
                print "$comment_char Routing $interface->{routing}->{name}",
                  " at $interface->{name}\n";
            }
            next;
        }

        for my $hop (@{ $interface->{hop} }) {

            # For unnumbered and negotiated interfaces use interface name
            # as next hop.
            my $hop_addr =
                $interface->{ip} =~ /^(?:unnumbered|negotiated|tunnel)$/
              ? $interface->{hardware}->{name}
              : print_ip $hop->{ip};

            for my $netinfo (@{ $intf2hop2nets{$interface}->{$hop} }) {
                if ($config{comment_routes}) {
                    print "$comment_char route $netinfo->[2] -> $hop->{name}\n";
                }
                if ($type eq 'IOS') {
                    my $adr = ios_route_code($netinfo);
                    print "ip route $ios_vrf$adr $hop_addr\n";
                }
                elsif ($type eq 'NX-OS') {
                    if ($vrf && ! $nxos_prefix) {

                        # Print "vrf context" only once
                        # and indent "ip route" commands.
                        print "vrf context $vrf\n";
                        $nxos_prefix = ' ';
                    }
                    my $adr = prefix_code($netinfo);
                    print "${nxos_prefix}ip route $adr $hop_addr\n";
                }
                elsif ($type eq 'PIX') {
                    my $adr = ios_route_code($netinfo);
                    print
                      "route $interface->{hardware}->{name} $adr $hop_addr\n";
                }
                elsif ($type eq 'iproute') {
                    my $adr = prefix_code($netinfo);
                    print "ip route add $adr via $hop_addr\n";
                }
                elsif ($type eq 'none') {

                    # Do nothing.
                }
                else {
                    internal_err("unexpected routing type '$type'");
                }
            }
        }
    }
    return;
}

##############################################################################
# NAT commands
##############################################################################

sub print_nat1 {
    my ($router, $print_dynamic, $print_static_host, $print_static) = @_;
    my $model        = $router->{model};
    my $comment_char = $model->{comment_char};
    print "$comment_char [ NAT ]\n";

    my @hardware =
      sort { $a->{level} <=> $b->{level} } @{ $router->{hardware} };

    for my $in_hw (@hardware) {
        my $src_nat = $in_hw->{src_nat} or next;
        my $in_nat = $in_hw->{no_nat_set};
        for my $out_hw (@hardware) {

            # Value is { net => net, .. }
            my $net_hash = $src_nat->{$out_hw} or next;
            my $out_nat = $out_hw->{no_nat_set};

            # Sorting is only needed for getting output deterministic.
            # For equal addresses look at the NAT address.
            my @networks =
              sort {
                     $a->{ip} <=> $b->{ip}
                  || $a->{mask} <=> $b->{mask}
                  || get_nat_network($a, $out_nat)
                  ->{ip} <=> get_nat_network($b, $out_nat)->{ip}
              } values %$net_hash;

            for my $network (@networks) {
                my ($in_ip, $in_mask, $in_dynamic) =
                  @{ get_nat_network($network, $in_nat) }{qw(ip mask dynamic)};
                my ($out_ip, $out_mask, $out_dynamic) =
                  @{ get_nat_network($network, $out_nat) }{qw(ip mask dynamic)};

                # Ignore dynamic translation, which doesn't occur at
                # current router
                if (    $out_dynamic
                    and $in_dynamic
                    and $out_dynamic eq $in_dynamic)
                {
                    $out_dynamic = $in_dynamic = undef;
                }

                # We are talking about source addresses.
                if ($out_dynamic) {

                    # Check for static NAT entries of hosts and interfaces.
                    for my $host (@{ $network->{subnets} },
                        @{ $network->{interfaces} })
                    {
                        if (my $out_host_ip = $host->{nat}->{$out_dynamic}) {
                            my $pair = address($host, $in_nat);
                            my ($in_host_ip, $in_host_mask) = @$pair;
                            $print_static_host->(
                                $in_hw, $in_host_ip, $in_host_mask, $out_hw,
                                $out_host_ip
                            );
                        }
                    }
                    $print_dynamic->(
                        $in_hw,  $in_ip,  $in_mask,
                        $out_hw, $out_ip, $out_mask
                    );
                }
                else {
                    $print_static->($in_hw, $in_ip, $in_mask, $out_hw, $out_ip);
                }
            }
        }
    }
    return;
}

sub print_pix_static {
    my ($router) = @_;

    # Index for linking "global" and "nat" commands.
    my $dyn_index = 1;

    # Hash of indexes for reusing of NAT pools.
    my %global2index;

    # Hash of indexes for creating only a single "nat" command if mapped at
    # different interfaces.
    my %nat2index;

    my $print_dynamic = sub {
        my ($in_hw, $in_ip, $in_mask, $out_hw, $out_ip, $out_mask) = @_;
        my $in_name  = $in_hw->{name};
        my $out_name = $out_hw->{name};

        # Use a single "global" command if multiple networks are
        # mapped to a single pool.
        my $global_index = $global2index{$out_name}->{$out_ip}->{$out_mask};

        # Use a single "nat" command if one network is mapped to
        # different pools at different interfaces.
        my $nat_index = $nat2index{$in_name}->{$in_ip}->{$in_mask};
        $global_index and $nat_index and internal_err();

        my $index = $global_index || $nat_index || $dyn_index++;
        if (not $global_index) {
            $global2index{$out_name}->{$out_ip}->{$out_mask} = $index;
            my $pool;

            # global (outside) 1 interface
            my $out_intf_ip = $out_hw->{interfaces}->[0]->{ip};
            if ($out_ip == $out_intf_ip && $out_mask == 0xffffffff) {
                $pool = 'interface';
            }

            # global (outside) 1 10.7.6.0-10.7.6.255 netmask 255.255.255.0
            # nat (inside) 1 14.4.36.0 255.255.252.0
            else {
                my $max  = $out_ip | complement_32bit $out_mask;
                my $mask = print_ip $out_mask;
                my $range =
                  ($out_ip == $max)
                  ? print_ip($out_ip)
                  : print_ip($out_ip) . '-' . print_ip($max);
                $pool = "$range netmask $mask";
            }
            print "global ($out_name) $index $pool\n";
        }

        if (not $nat_index) {
            $nat2index{$in_name}->{$in_ip}->{$in_mask} = $index;
            my $in   = print_ip $in_ip;
            my $mask = print_ip $in_mask;
            print "nat ($in_name) $index $in $mask";
            print " outside" if $in_hw->{level} < $out_hw->{level};
            print "\n";
        }
    };
    my $print_static_host = sub {
        my ($in_hw, $in_host_ip, $in_host_mask, $out_hw, $out_host_ip) = @_;
        my $in_name  = $in_hw->{name};
        my $out_name = $out_hw->{name};
        my $in       = print_ip $in_host_ip;
        my $mask     = print_ip $in_host_mask;
        my $out      = print_ip $out_host_ip;
        print "static ($in_name,$out_name) $out $in netmask $mask\n";
    };
    my $print_static = sub {
        my ($in_hw, $in_ip, $in_mask, $out_hw, $out_ip) = @_;
        if (   $in_hw->{level} > $out_hw->{level}
            || $in_hw->{need_identity_nat}
            || $in_ip != $out_ip)
        {
            my $in_name  = $in_hw->{name};
            my $out_name = $out_hw->{name};
            my $in       = print_ip $in_ip;
            my $out      = print_ip $out_ip;
            my $mask     = print_ip $in_mask;

            # static (inside,outside) \
            #   10.111.0.0 111.0.0.0 netmask 255.255.252.0
            print "static ($in_name,$out_name) $out $in netmask $mask\n";
        }
    };
    print_nat1($router, $print_dynamic, $print_static_host, $print_static);
    for my $in_hw (@{ $router->{hardware} }) {
        next if not $in_hw->{need_nat_0};
        print "nat ($in_hw->{name}) 0 0.0.0.0 0.0.0.0\n";
    }
    return;
}

sub print_asa_nat {
    my ($router) = @_;

    # Hash for re-using object definitions.
    my %objects;

    my $subnet_obj = sub {
        my ($ip, $mask) = @_;
        my $p_ip   = print_ip($ip);
        my $p_mask = print_ip($mask);
        my $name   = "${p_ip}_${p_mask}";
        if (not $objects{$name}) {
            print "object network $name\n";
            print " subnet $p_ip $p_mask\n";
            $objects{$name} = $name;
        }
        return $name;
    };
    my $range_obj = sub {
        my ($ip, $mask) = @_;
        my $max  = $ip | complement_32bit $mask;
        my $p_ip = print_ip($ip);
        my $name = $p_ip;
        my $sub_cmd;
        if ($ip == $max) {
            $sub_cmd = "host $p_ip";
        }
        else {
            my $p_max = print_ip($max);
            $name .= "-$p_max";
            $sub_cmd = "range $p_ip $p_max";
        }
        if (not $objects{$name}) {
            print "object network $name\n";
            print " $sub_cmd\n";
            $objects{$name} = $name;
        }
        return $name;
    };

    my $print_dynamic = sub {
        my ($in_hw, $in_ip, $in_mask, $out_hw, $out_ip, $out_mask) = @_;
        my $in_name  = $in_hw->{name};
        my $out_name = $out_hw->{name};
        my $in_obj   = $subnet_obj->($in_ip, $in_mask);
        my $out_obj;

        # NAT to interface
        my $out_intf_ip = $out_hw->{interfaces}->[0]->{ip};
        if ($out_ip == $out_intf_ip && $out_mask == 0xffffffff) {
            $out_obj = 'interface';
        }
        else {
            $out_obj = $range_obj->($out_ip, $out_mask);
        }
        print("nat ($in_name,$out_name) source dynamic $in_obj $out_obj\n");
    };
    my $print_static_host = sub {
        my ($in_hw, $in_host_ip, $in_host_mask, $out_hw, $out_host_ip) = @_;
        my $in_name      = $in_hw->{name};
        my $out_name     = $out_hw->{name};
        my $in_host_obj  = $subnet_obj->($in_host_ip, $in_host_mask);
        my $out_host_obj = $subnet_obj->($out_host_ip, $in_host_mask);
        print("nat ($in_name,$out_name) 1 source static",
            " $in_host_obj $out_host_obj\n");
    };
    my $print_static = sub {
        my ($in_hw, $in_ip, $in_mask, $out_hw, $out_ip) = @_;
        my $in_name  = $in_hw->{name};
        my $out_name = $out_hw->{name};
        my $in_obj   = $subnet_obj->($in_ip, $in_mask);
        my $out_obj  = $subnet_obj->($out_ip, $in_mask);
        print("nat ($in_name,$out_name) source static $in_obj $out_obj\n");
    };
    print_nat1($router, $print_dynamic, $print_static_host, $print_static);
    return;
}

sub optimize_nat_networks {
    my ($router) = @_;
    my @hardware = @{ $router->{hardware} };
    for my $in_hw (@hardware) {
        my $src_nat = $in_hw->{src_nat} or next;
        my $in_nat = $in_hw->{no_nat_set};
        for my $out_hw (@hardware) {

            # Value is { net => net, .. }
            my $net_hash = $src_nat->{$out_hw} or next;
            my $out_nat = $out_hw->{no_nat_set};

            # Prevent duplicate entries from different networks
            # translated to one identical address.
            my @has_indentical;
            for my $network (values %$net_hash) {
                my $identical = $network->{is_identical} or next;
                my $in        = $identical->{$in_nat};
                my $out       = $identical->{$out_nat};
                if ($in && $out && $in eq $out) {
                    push @has_indentical, $network;
                }
            }
            for my $network (@has_indentical) {
                delete $net_hash->{$network};
                my $one_net = $network->{is_identical}->{$out_nat};
                $net_hash->{$one_net} = $one_net;
            }

            # Remove redundant networks.
            # A network is redundant if some enclosing network is found
            # in both NAT domains of incoming and outgoing interface.
            for my $network (values %$net_hash) {
                my $net = $network->{is_in}->{$out_nat};
                while ($net) {
                    my $net2;
                    if (    $net_hash->{$net}
                        and $net2 = $network->{is_in}->{$in_nat}
                        and $net_hash->{$net2})
                    {
                        delete $net_hash->{$network};
                        last;
                    }
                    else {
                        $net = $net->{is_in}->{$out_nat};
                    }
                }
            }
        }
    }
    return;
}

sub print_nat {
    my ($router) = @_;
    my $model = $router->{model};

    # NAT commands not implemented for other models.
    return if not $model->{has_interface_level};

    optimize_nat_networks($router);
    if ($model->{v8_4}) {

        print_asa_nat($router);
    }
    else {
        print_pix_static($router);
    }
    return;
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
    my $router = $in_intf->{router};
    return if not $router->{managed};
    my $model = $router->{model};

    # Rules of type stateless must only be processed at
    # - stateless routers or
    # - routers which are stateless for packets destined for
    #   their own interfaces or
    # - stateless tunnel interfaces of ASA-VPN.
    if ($rule->{stateless}) {
        if (
            not(   $model->{stateless}
                or not $out_intf and $model->{stateless_self})
          )
        {
            return;
        }
    }

    # Rules of type stateless_icmp must only be processed at routers
    # which don't handle stateless_icmp automatically;
    return if $rule->{stateless_icmp} and not $model->{stateless_icmp};

    my $dst       = $rule->{dst};
    my $intf_hash = $router->{crosslink_intf_hash};

    # Rule to managed interface must be processed
    # - at the corresponding router or
    # - at the edge of a cluster of crosslinked routers
    # even if the rule is marked as deleted,
    # because code for interface is placed separately into {intf_rules}.
    if ($rule->{deleted}) {

        # We are at an intermediate router.
        return if $out_intf and (!$intf_hash || !$intf_hash->{$dst});

        # No code needed if it is deleted by another rule to the same interface.
        return if $rule->{deleted}->{managed_intf};
    }

    # Don't generate code for src any:[interface:r.loopback] at router:r.
    return if $in_intf->{loopback};

    # Validate dynamic NAT.
    if (my $dynamic_nat = $rule->{dynamic_nat}) {
        my $no_nat_set = $in_intf->{no_nat_set};
        for my $where (split(/,/, $dynamic_nat)) {
            my $obj         = $rule->{$where};
            my $network     = $obj->{network};
            my $nat_network = get_nat_network($network, $no_nat_set);
            next if $nat_network eq $network;
            my $nat_tag = $nat_network->{dynamic} or next;

            # Ignore object with static translation.
            next if $obj->{nat}->{$nat_tag};

            # Otherwise, filtering occurs at other router, therefore
            # the whole network can pass here.
            # But attention, this assumption only holds, if the other
            # router filters fully.  Hence disable optimization of
            # secondary rules.
            delete $rule->{some_non_secondary};
            delete $rule->{some_primary};

            # Permit whole network, because no static address is known.
            # Make a copy of current rule, because the original rule
            # must not be changed.
            $rule = { %$rule, $where => $network };
        }
    }

    my $key;

    # Packets for the router itself or for some interface of a
    # crosslinked cluster of routers (only IOS, NX-OS with "need_protect").
    if (!$out_intf || $intf_hash && $intf_hash->{$dst}) {

        # Packets for the router itself.  For PIX we can only reach that
        # interface, where traffic enters the PIX.
        if ($model->{filter} eq 'PIX') {
            if ($dst eq $in_intf) {
            }
            elsif ($dst eq $network_00 or $dst eq $in_intf->{network}) {

                # Ignore rule, because generated code would permit traffic
                # to cleartext interface as well.
                return if $in_intf->{ip} eq 'tunnel';

                # Change destination in $rule to interface.
                # Make a copy of current rule, because the
                # original rule must not be changed.
                $rule = {%$rule};
                $rule->{dst} = $in_intf;
            }

            # Permit management access through tunnel.
            # On ASA device use command "management-access".
            # Permit management access through bridged interface.
            elsif ($in_intf->{ip} =~ /^(?:tunnel|bridged)/) {
            }

            # Silently ignore everything else.
            else {
                return;
            }
        }
        $key = 'intf_rules';
    }
    elsif ($out_intf->{hardware}->{need_out_acl}) {
        $key = 'out_rules';
        if (not $in_intf->{hardware}->{no_in_acl}) {
            push @{ $in_intf->{hardware}->{rules} }, $rule;
        }
    }
    else {
        $key = 'rules';
    }

    if ($in_intf->{ip} eq 'tunnel') {

        # Rules for single software clients are stored individually.
        # Consistency checks have already been done at expand_crypto.
        # Rules are needed at tunnel for generating split tunnel ACL
        # regardless of $router->{no_crypto_filter} value.
        if (my $id2rules = $in_intf->{id_rules}) {
            my $src = $rule->{src};
            if (is_subnet $src) {
                my $id = $src->{id}
                  or internal_err("$src->{name} must have ID");
                my $id_intf = $id2rules->{$id}
                  or internal_err("No entry for $id at id_rules");
                push @{ $id_intf->{$key} }, $rule;
            }
            elsif (is_network $src) {
                $src->{has_id_hosts}
                  or internal_err("$src->{name} must have ID-hosts");
                for my $id (map { $_->{id} } @{ $src->{hosts} }) {
                    push @{ $id2rules->{$id}->{$key} }, $rule;
                }
            }
            else {
                internal_err(
                  "Expected host or network as src but got $src->{name}");
            }
        }

        if ($router->{no_crypto_filter}) {
            push @{ $in_intf->{real_interface}->{hardware}->{$key} }, $rule;
        }

        # Rules are needed at tunnel for generating detailed_crypto_acl.
        if (not $in_intf->{id_rules}) {
            push @{ $in_intf->{$key} }, $rule;
        }
    }
    elsif ($key eq 'out_rules') {
        push @{ $out_intf->{hardware}->{$key} }, $rule;
    }

    # Remember outgoing interface.
    elsif ($key eq 'rules' and $model->{has_io_acl}) {
        push @{ $in_intf->{hardware}->{io_rules}
              ->{ $out_intf->{hardware}->{name} } }, $rule;
    }
    else {
        push @{ $in_intf->{hardware}->{$key} }, $rule;
    }
    return;
}

# For each device, find the IP address which is used
# to manage the device from a central policy distribution point.
# This address is added as a comment line to each generated code file.
# This is to used later when approving the generated code file.
sub set_policy_distribution_ip  {
    return if not $policy_distribution_point;
    progress('Setting policy distribution IP');

    # Find all TCP ranges which include port 22 and 23.
    my @admin_tcp_keys = grep({
            my ($p1, $p2) = split(':', $_);
              $p1 <= 22 && 22 <= $p2 || $p1 <= 23 && 23 <= $p2;
        }
        keys %{ $prt_hash{tcp} });
    my @prt_list = (@{ $prt_hash{tcp} }{@admin_tcp_keys}, $prt_hash{ip});
    my %admin_prt;
    @admin_prt{@prt_list} = @prt_list;

    my %pdp_src;
    for my $pdp (map { $_ } @{ $policy_distribution_point->{subnets} }) {
        while ($pdp) {
            $pdp_src{$pdp} = $pdp;
            $pdp = $pdp->{up};
        }
    }
    my $no_nat_set =
      $policy_distribution_point->{network}->{nat_domain}->{no_nat_set};
    for my $router (@managed_routers) {
        my %interfaces;

        # Find interfaces where some rule permits management traffic.
        for my $intf (@{ $router->{hardware} },
            grep { $_->{ip} eq 'tunnel' } @{ $router->{interfaces} })
        {
            next if not $intf->{intf_rules};
            for my $rule (@{ $intf->{intf_rules} }) {
                my ($action, $src, $dst, $prt) =
                  @{$rule}{qw(action src dst prt)};
                next if $action eq 'deny';
                next if not $pdp_src{$src};
                next if not $admin_prt{$prt};
                next if not is_interface($dst);

                # Filter out traffic to other devices of crosslink cluster.
                next if not $dst->{router} eq $router;
                $interfaces{$dst} = $dst;
            }
        }
        my @result;

        # Ready, if exactly one management interface was found.
        if (keys %interfaces == 1) {
            @result = values %interfaces;
        }
        else {

#           debug("$router->{name}: ", scalar keys %interfaces);
            my @front =
              path_auto_interfaces($router, $policy_distribution_point);

            # If multiple management interfaces were found, take that which is
            # directed to policy_distribution_point.
            for my $front (@front) {
                if ($interfaces{$front}) {
                    push @result, $front;
                }
            }

            # Take all management interfaces.
            # Preserve original order of router interfaces.
            if (! @result) {
                @result = grep { $interfaces{$_} } @{ $router->{interfaces} };
            }

            # Don't set {admin_ip} if no address is found.
            # Warning is printed below.
            next if not @result;
        }

        # Prefer loopback interface if available.
        $router->{admin_ip} = [
            map { print_ip((address($_, $no_nat_set))->[0]) }
            sort { ($b->{loopback} || '') cmp($a->{loopback} || '') } @result
        ];
    }
    my %seen;
    for my $router (@managed_routers) {
        next if $seen{$router};
        my $unreachable;
        if (my $vrf_members = $router->{vrf_members}) {
            grep { $_->{admin_ip} } @$vrf_members
              or $unreachable = "at least one VRF of $router->{device_name}";

            # Print VRF instance with known admin_ip first.
            $router->{vrf_members} = [
                sort {
                    !$a->{admin_ip} <=> !$b->{admin_ip}
                    || $a->{name} cmp $b->{name}
                  } @$vrf_members
            ];
        }
        else {
            $router->{admin_ip} or $unreachable = $router->{name};
        }
        $unreachable
          and warn_msg (
            "Missing rule to reach $unreachable",
            " from policy_distribution_point"
          );
    }
    return;
}

my $permit_any_rule = {
    action    => 'permit',
    src       => $network_00,
    dst       => $network_00,
    src_range => $prt_ip,
    prt       => $prt_ip
};

sub add_router_acls  {
    for my $router (@managed_routers) {
        my $has_io_acl = $router->{model}->{has_io_acl};
        for my $hardware (@{ $router->{hardware} }) {

            # Some managed devices are connected by a crosslink network.
            # Permit any traffic at the internal crosslink interface.
            if ($hardware->{crosslink}) {

                # We can savely change rules at hardware interface
                # because it has been checked that no other logical
                # networks are attached to the same hardware.
                #
                # Substitute rules for each outgoing interface.
                if ($has_io_acl) {
                    for my $rules (values %{ $hardware->{io_rules} }) {
                        $rules = [$permit_any_rule];
                    }
                }
                else {
                    $hardware->{rules} = [$permit_any_rule];
                    if ($hardware->{need_out_acl}) {
                        $hardware->{out_rules} = [$permit_any_rule];
                    }
                }
                $hardware->{intf_rules} = [$permit_any_rule];
                next;
            }

            for my $interface (@{ $hardware->{interfaces} }) {

                # Current router is used as default router even for
                # some internal networks.
                if ($interface->{reroute_permit}) {
                    for my $net (@{ $interface->{reroute_permit} }) {

                        # Prepend to all other rules.
                        unshift(
                            @{
                                $has_io_acl

                                  # Incoming and outgoing interface are equal.
                                ? $hardware->{io_rules}->{ $hardware->{name} }
                                : $hardware->{rules}
                              },
                            {
                                action    => 'permit',
                                src       => $network_00,
                                dst       => $net,
                                src_range => $prt_ip,
                                prt       => $prt_ip
                            }
                        );
                    }
                }

                # Is dynamic routing used?
                if (my $routing = $interface->{routing}) {
                    unless ($routing->{name} eq 'manual') {
                        my $prt       = $routing->{prt};
                        my $src_range = $prt_ip;
                        if (my $dst_range = $prt->{dst_range}) {
                            $src_range = $prt->{src_range};
                            $prt       = $prt->{dst_range};
                        }
                        my $network = $interface->{network};

                        # Permit multicast packets from current network.
                        for my $mcast (@{ $routing->{mcast} }) {
                            push @{ $hardware->{intf_rules} },
                              {
                                action    => 'permit',
                                src       => $network,
                                dst       => $mcast,
                                src_range => $src_range,
                                prt       => $prt
                              };
                            $ref2obj{$mcast}     = $mcast;
                            $ref2prt{$src_range} = $src_range;
                            $ref2prt{$prt}       = $prt;
                        }

                        # Additionally permit unicast packets.
                        # We use the network address as destination
                        # instead of the interface address,
                        # because we need fewer rules if the interface has
                        # multiple addresses.
                        push @{ $hardware->{intf_rules} },
                          {
                            action    => 'permit',
                            src       => $network,
                            dst       => $network,
                            src_range => $src_range,
                            prt       => $prt
                          };
                    }
                }

                # Handle multicast packets of redundancy protocols.
                if (my $type = $interface->{redundancy_type}) {
                    my $network   = $interface->{network};
                    my $mcast     = $xxrp_info{$type}->{mcast};
                    my $prt       = $xxrp_info{$type}->{prt};
                    my $src_range = $prt_ip;

                    # Is prt TCP or UDP with destination port range?
                    # Then use source port range as well.
                    if (my $dst_range = $prt->{dst_range}) {
                        $src_range = $prt->{src_range};
                        $prt       = $dst_range;
                    }
                    push @{ $hardware->{intf_rules} },
                      {
                        action    => 'permit',
                        src       => $network,
                        dst       => $mcast,
                        src_range => $src_range,
                        prt       => $prt
                      };
                    $ref2obj{$mcast}     = $mcast;
                    $ref2prt{$src_range} = $src_range;
                    $ref2prt{$prt}       = $prt;
                }
            }
        }
    }
    return;
}

# At least for $prt_esp and $prt_ah the ACL lines need to have a fixed order.
# Otherwise,
# - if the device is accessed over an IPSec tunnel
# - and we change the ACL incrementally,
# the connection may be lost.
sub cmp_address {
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network' or $type eq 'Subnet') {
        return "$obj->{ip},$obj->{mask}";
    }
    elsif ($type eq 'Interface') {
        return("$obj->{ip}," . 0xffffffff); ## no critic (MismatchedOperators)
    }
    else {
        internal_err();
    }
}

sub has_global_restrict {
    my ($interface) = @_;
    if (my $restrictions = $interface->{path_restrict}) {
        for my $restrict (@$restrictions) {
            return 1 if $restrict->{active_path};
        }
    }
    return;
}

sub distribute_global_permit {
    for my $prt (sort by_name @global_permit) {
        my $stateless      = $prt->{flags} && $prt->{flags}->{stateless};
        my $stateless_icmp = $prt->{flags} && $prt->{flags}->{stateless_icmp};
        $prt = $prt->{main} if $prt->{main};
        $prt->{src_dst_range_list} or internal_err($prt->{name});
        for my $src_dst_range (@{ $prt->{src_dst_range_list} }) {
            my ($src_range, $prt) = @$src_dst_range;
            $ref2prt{$src_range} = $src_range;
            $ref2prt{$prt}       = $prt;
            my $rule = {
                action         => 'permit',
                src            => $network_00,
                dst            => $network_00,
                src_range      => $src_range,
                prt            => $prt,
                stateless      => $stateless,
                stateless_icmp => $stateless_icmp,
            };
            for my $router (@managed_routers) {
                my $need_protect = $router->{model}->{need_protect};
                for my $in_intf (@{ $router->{interfaces} }) {
                    next if has_global_restrict($in_intf);

                    # At VPN hub, don't permit any -> any, but only traffic
                    # from each encrypted network.
                    if ($in_intf->{is_hub}) {
                        my $id_rules = $in_intf->{id_rules};
                        for my $src (
                            $id_rules
                            ? map({ $_->{src} } values %$id_rules)
                            : @{ $in_intf->{peer_networks} }
                          )
                        {
                            my $rule = {%$rule};
                            $rule->{src} = $src;
                            for my $out_intf (@{ $router->{interfaces} }) {
                                next if $out_intf eq $in_intf;
                                next if $out_intf->{ip} eq 'tunnel';

                                # Traffic traverses the device.
                                # Traffic for the device itself isn't needed
                                # at VPN hub.
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
                            next if has_global_restrict($out_intf);

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
    }
    return;
}

sub rules_distribution {
    progress('Distributing rules');

    # Not longer used, free memory.
    %rule_tree = ();

    # Sort rules by reverse priority of protocol.
    # This should be done late to get all auxiliary rules processed.
    for my $type ('deny', 'supernet', 'permit') {
        $expanded_rules{$type} = [
            sort {
                     ($b->{prt}->{prio} || 0) <=> ($a->{prt}->{prio} || 0)
                  || ($a->{prt}->{prio} || 0)
                  && ( cmp_address($a->{src}) cmp cmp_address($b->{src})
                    || cmp_address($a->{dst}) cmp cmp_address($b->{dst}))
              } @{ $expanded_rules{$type} }
        ];
    }

    # Deny rules
    for my $rule (@{ $expanded_rules{deny} }) {
        next if $rule->{deleted};
        path_walk($rule, \&distribute_rule);
    }

    # Handle global permit after deny rules.
    distribute_global_permit();

    # Permit rules
    for my $rule (@{ $expanded_rules{supernet} }, @{ $expanded_rules{permit} })
    {
        next
          if $rule->{deleted}
              and
              (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
        path_walk($rule, \&distribute_rule, 'Router');
    }

    # Find management IP of device before ACL lines are cleared for
    # crosslink interfaces during add_router_acls.
    set_policy_distribution_ip();
    add_router_acls();

    # Prepare rules for local_optimization.
    # Aggregates with mask 0 are converted to network_00, to be able
    # to compare with internally generated rules which use network_00.
    for my $rule (@{ $expanded_rules{supernet} }) {
        next if $rule->{deleted} and not $rule->{managed_intf};
        my ($src, $dst) = @{$rule}{qw(src dst)};
        $rule->{src} = $network_00 if is_network($src) && $src->{mask} == 0;
        $rule->{dst} = $network_00 if is_network($dst) && $dst->{mask} == 0;
    }

    # No longer needed, free some memory.
    %expanded_rules = ();
    %obj2path       = ();
    %key2obj        = ();
    return;
}

##############################################################################
# ACL Generation
##############################################################################

# Parameters:
# obj: this address we want to know
# network: look inside this NAT domain
# returns a list of [ ip, mask ] pairs
sub address {
    my ($obj, $no_nat_set) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        $obj = get_nat_network($obj, $no_nat_set);

        # ToDo: Is it OK to permit a dynamic address as destination?
        if ($obj->{ip} eq 'unnumbered') {
            internal_err("Unexpected unnumbered $obj->{name}");
        }
        else {
            return [ $obj->{ip}, $obj->{mask} ];
        }
    }
    elsif ($type eq 'Subnet') {
        my $network = get_nat_network($obj->{network}, $no_nat_set);
        if (my $nat_tag = $network->{dynamic}) {
            if (my $ip = $obj->{nat}->{$nat_tag}) {

                # Single static NAT IP for this host.
                return [ $ip, 0xffffffff ];
            }
            else {

                # This has been converted to the  whole network before.
                internal_err("Unexpected $obj->{name} with dynamic NAT");
            }
        }
        else {

            # Take higher bits from network NAT, lower bits from original IP.
            # This works with and without NAT.
            my $ip =
              $network->{ip} | $obj->{ip} & complement_32bit $network->{mask};
            return [ $ip, $obj->{mask} ];
        }
    }
    elsif ($type eq 'Interface') {
        if ($obj->{ip} =~ /^(unnumbered|short)$/) {
            internal_err("Unexpected $obj->{ip} $obj->{name}");
        }

        my $network = get_nat_network($obj->{network}, $no_nat_set);

        if ($obj->{ip} eq 'negotiated') {
            my ($network_ip, $network_mask) = @{$network}{ 'ip', 'mask' };
            return [ $network_ip, $network_mask ];
        }
        if (my $nat_tag = $network->{dynamic}) {
            if (my $ip = $obj->{nat}->{$nat_tag}) {

                # Single static NAT IP for this interface.
                return [ $ip, 0xffffffff ];
            }
            else {
                internal_err("Unexpected $obj->{name} with dynamic NAT");
            }
        }
        elsif ($network->{isolated}) {

            # NAT not allowed for isolated ports. Take no bits from network,
            # because secondary isolated ports don't match network.
            return [ $obj->{ip}, 0xffffffff ];
        }
        else {

            # Take higher bits from network NAT, lower bits from original IP.
            # This works with and without NAT.
            my $ip =
              $network->{ip} | $obj->{ip} & complement_32bit $network->{mask};
            return [ $ip, 0xffffffff ];
        }
    }
    elsif ($type eq 'Objectgroup') {
        return $obj;
    }
    else {
        internal_err("Unexpected object", ref $obj);
    }
}

# Given an IP and mask, return its address in Cisco syntax.
sub cisco_acl_addr {
    my ($pair, $model) = @_;
    if (is_objectgroup $pair) {
        my $keyword = 
            $model->{filter} eq 'NX-OS' ? 'addrgroup' : 'object-group';
        return "$keyword $pair->{name}";
    }
    else {
        my ($ip, $mask) = @$pair;
        my $ip_code = print_ip($ip);
        if ($mask == 0xffffffff) {
            return "host $ip_code";
        }
        elsif ($mask == 0) {
            return "any";
        }
        elsif ($model->{use_prefix}) {
            return prefix_code($pair);
        }
        else {
            $mask = complement_32bit($mask) if $model->{inversed_acl_mask};
            my $mask_code = print_ip($mask);
            return "$ip_code $mask_code";
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
    my $prefix_code = mask2prefix($mask);
    return $prefix_code == 32 ? $ip_code : "$ip_code/$prefix_code";
}

# Returns 3 values for building a Cisco ACL:
# permit <val1> <src> <val2> <dst> <val3>
sub cisco_prt_code {
    my ($src_range, $prt, $model) = @_;
    my $proto = $prt->{proto};

    if ($proto eq 'ip') {
        return ('ip', undef, undef);
    }
    elsif ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub  {
            my ($v1, $v2) = @_;
            if ($v1 == $v2) {
                return ("eq $v1");
            }

            # PIX doesn't allow port 0; can port 0 be used anyhow?
            elsif ($v1 == 1 and $v2 == 65535) {
                return (undef);
            }
            elsif ($v2 == 65535) {
                return 'gt ' . ($v1 - 1);
            }
            elsif ($v1 == 1) {
                return 'lt ' . ($v2 + 1);
            }
            else {
                return ("range $v1 $v2");
            }
        };
        my $dst_prt = $port_code->(@{ $prt->{range} });
        if (my $established = $prt->{established}) {
            if (defined $dst_prt) {
                $dst_prt .= ' established';
            }
            else {
                $dst_prt = 'established';
            }
        }
        return ($proto, $port_code->(@{ $src_range->{range} }), $dst_prt);
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $prt->{type})) {
            if (defined(my $code = $prt->{code})) {
                if ($model->{no_filter_icmp_code}) {

                    # PIX can't handle the ICMP code field.
                    # If we try to permit e.g. "port unreachable",
                    # "unreachable any" could pass the PIX.
                    return ($proto, undef, $type);
                }
                else {
                    return ($proto, undef, "$type $code");
                }
            }
            else {
                return ($proto, undef, $type);
            }
        }
        else {
            return ($proto, undef, undef);
        }
    }
    else {
        return ($proto, undef, undef);
    }
}

# Returns iptables code for filtering a protocol.
sub iptables_prt_code {
    my ($src_range, $prt) = @_;
    my $proto = $prt->{proto};

    if ($proto eq 'ip') {
        return '';
    }
    elsif ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub  {
            my ($v1, $v2) = @_;
            if ($v1 == $v2) {
                return $v1;
            }
            elsif ($v1 == 1 and $v2 == 65535) {
                return '';
            }
            elsif ($v2 == 65535) {
                return "$v1:";
            }
            elsif ($v1 == 1) {
                return ":$v2";
            }
            else {
                return "$v1:$v2";
            }
        };
        my $sport  = $port_code->(@{ $src_range->{range} });
        my $dport  = $port_code->(@{ $prt->{range} });
        my $result = "-p $proto";
        $result .= " --sport $sport" if $sport;
        $result .= " --dport $dport" if $dport;
        $prt->{established}
          and internal_err("Unexpected protocol $prt->{name} with",
                           " 'established' flag while generating code",
                           " for iptables");
        return $result;
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $prt->{type})) {
            if (defined(my $code = $prt->{code})) {
                return "-p $proto --icmp-type $type/$code";
            }
            else {
                return "-p $proto --icmp-type $type";
            }
        }
        else {
            return "-p $proto";
        }
    }
    else {
        return "-p $proto";
    }
}

sub cisco_acl_line {
    my ($router, $rules_aref, $no_nat_set, $prefix) = @_;
    my $model       = $router->{model};
    my $filter_type = $model->{filter};
    my $numbered    = 10;
    for my $rule (@$rules_aref) {
        my ($action, $src, $dst, $src_range, $prt) =
          @{$rule}{ 'action', 'src', 'dst', 'src_range', 'prt' };
        print "$model->{comment_char} " . print_rule($rule) . "\n"
          if $config{comment_acls};
        my $spair = address($src, $no_nat_set);
        my $dpair = address($dst, $no_nat_set);
        if ($filter_type eq 'PIX') {

            # Only traffic passing through the PIX.
            my ($proto_code, $src_port_code, $dst_port_code) =
                cisco_prt_code($src_range, $prt, $model);
            my $result = "$prefix $action $proto_code";
            $result .= ' ' . cisco_acl_addr($spair, $model);
            $result .= " $src_port_code" if defined $src_port_code;
            $result .= ' ' . cisco_acl_addr($dpair, $model);
            $result .= " $dst_port_code" if defined $dst_port_code;
            print "$result\n";
        }
        elsif ($filter_type =~ /^(:?IOS|NX-OS)$/) {
            my ($proto_code, $src_port_code, $dst_port_code) =
              cisco_prt_code($src_range, $prt, $model);
            my $result = "$prefix $action $proto_code";
            $result .= ' ' . cisco_acl_addr($spair, $model);
            $result .= " $src_port_code" if defined $src_port_code;
            $result .= ' ' . cisco_acl_addr($dpair, $model);
            $result .= " $dst_port_code" if defined $dst_port_code;
            $result .= " log" if $router->{log_deny} and $action eq 'deny';
            if ($filter_type eq 'NX-OS') {
                $result = " $numbered$result";
                $numbered += 10;
            }
            print "$result\n";
        }
        else {
            internal_err("Unknown filter_type $filter_type");
        }
    }
    return;
}

my $min_object_group_size = 2;

sub find_object_groups  {
    my ($router, $hardware) = @_;
    my $model = $router->{model};
    my $is_nxos = $model->{filter} eq 'NX-OS';
    my $keyword = $is_nxos
                ? 'object-group ip address'
                : 'object-group network';

    # Find identical groups of same size.
    my $size2first2group_hash = ($router->{size2first2group_hash} ||= {});
    $router->{obj_group_counter} ||= 0;

    # Leave 'intf_rules' untouched, because they are handled
    # indivually for ASA, PIX. 
    # NX-OS needs them indivually when optimizing need_protect.
    for my $rule_type ('rules', 'out_rules') {
        next if not $hardware->{$rule_type};

        # Find object-groups in src / dst of rules.
        for my $this ('src', 'dst') {
            my $that = $this eq 'src' ? 'dst' : 'src';
            my %group_rule_tree;

            # Find groups of rules with identical
            # action, prt, src/dst and different dst/src.
            for my $rule (@{ $hardware->{$rule_type} }) {
                my $action    = $rule->{action};
                my $that      = $rule->{$that};
                my $this      = $rule->{$this};
                my $prt       = $rule->{prt};
                my $src_range = $rule->{src_range};
                $group_rule_tree{$action}->{$src_range}->{$prt}->{$that}
                  ->{$this} = $rule;
            }

            # Find groups >= $min_object_group_size,
            # mark rules belonging to one group,
            # put groups into an array / hash.
            for my $href (values %group_rule_tree) {

                # $href is {src_range => href, ...}
                for my $href (values %$href) {

                    # $href is {prt => href, ...}
                    for my $href (values %$href) {

                        # $href is {src/dst => href, ...}
                        for my $href (values %$href) {

                            # $href is {dst/src => rule, ...}
                            my $size = keys %$href;
                            if ($size >= $min_object_group_size) {
                                my $glue = {

                                    # Indicator, that no further rules need
                                    # to be processed.
                                    active => 0,

                                    # NAT map for address calculation.
                                    no_nat_set => $hardware->{no_nat_set},

                                    # object-ref => rule, ...
                                    hash => $href
                                };

                                # All this rules have identical
                                # action, prt, src/dst  and dst/src
                                # and shall be replaced by a new object group.
                                for my $rule (values %$href) {
                                    $rule->{group_glue} = $glue;
                                }
                            }
                        }
                    }
                }
            }

            my $calc_ip_mask_strings = sub {
                my ($keys, $no_nat_set) = @_;
                return(map { join('/', @$_) }
                       sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] }
                       map { address($_, $no_nat_set) }
                       map { $ref2obj{$_} || internal_err($_) }
                       @$keys);
            };

            my $build_group = sub {
                my ($ip_mask_strings) = @_;
                my $group = new(
                    'Objectgroup',
                    name       => "g$router->{obj_group_counter}",
                    elements   => $ip_mask_strings,
                    hash       => { map { $_ => 1 } @$ip_mask_strings },
                );
                $router->{obj_group_counter}++;

                # Print object-group.
                my $numbered = 10;
                print "$keyword $group->{name}\n";
                for my $ip_mask ( @$ip_mask_strings ) {
                    my $pair = [ split '/', $ip_mask ];

                    # Reject network with mask = 0 in group.
                    # This occurs if optimization didn't work correctly.
                    $pair->[1] == 0 and
                        internal_err("Unexpected object with mask 0",
                                     " in object-group of $router->{name}");
                    my $adr = cisco_acl_addr($pair, $model);
                    if ($is_nxos) {
                        print " $numbered $adr\n";
                        $numbered += 10;
                    }
                    else {
                        print " network-object $adr\n";
                    }
                }
                return $group;
            };

            # Find group with identical elements or define a new one.
            my $get_group = sub  {
                my ($glue)     = @_;
                my $hash       = $glue->{hash};
                my $no_nat_set = $glue->{no_nat_set};

                # Keys are sorted by their internal address to get
                # some "first" element. 
                # This element is useable for hashing, because addresses
                # are known to be fix during program execution.
                my @keys       = sort keys %$hash;
                my $first      = $keys[0];
                my $size       = @keys;

                # Find group with identical elements.
              HASH:
                for my $group_hash 
                    (@{ $size2first2group_hash->{$size}->{$first} }) 
                {
                    my $href = $group_hash->{hash};

                    # Check elements for equality.
                    for my $key (@keys) {
                        $href->{$key} or next HASH;
                    }

                    # Found $group_hash with matching elements.
                    # Check for existing group in current NAT domain.
                    my $nat2group = $group_hash->{nat2group};
                    if (my $group = $nat2group->{$no_nat_set}) {
                        return $group;
                    }

                    my @ip_mask_strings = 
                        $calc_ip_mask_strings->(\@keys, $no_nat_set);

                    # Check for matching group in other NAT domains.
                  GROUP:
                    for my $group (values %$nat2group) {
                        my $href = $group->{hash};

                        # Check NATed addresses for equality.
                        for my $key (@ip_mask_strings) {
                            $href->{$key} or next GROUP;
                        }

                        # Found matching group.
                        $nat2group->{$no_nat_set} = $group;
                        return $group;
                    }
                    
                    # No group found, build new group.
                    my $group = $build_group->(\@ip_mask_strings);
                    $nat2group->{$no_nat_set} = $group;
                    return $group;
                }

                # No group hash found, build new group hash with new group.
                my @ip_mask_strings = 
                    $calc_ip_mask_strings->(\@keys, $no_nat_set);
                my $group = $build_group->(\@ip_mask_strings);
                my $group_hash = {
                    hash      => $hash,
                    nat2group => { $no_nat_set => $group },
                };
                push(@{ $size2first2group_hash->{$size}->{$first} }, 
                     $group_hash);
                return $group;
            };

            # Build new list of rules using object groups.
            my @new_rules;
            for my $rule (@{ $hardware->{$rule_type} }) {

                # Remove tag, otherwise call to find_object_groups
                # for another router would become confused.
                if (my $glue = delete $rule->{group_glue}) {

#              debug(print_rule $rule);
                    if ($glue->{active}) {

#                 debug(" deleted: $glue->{group}->{name}");
                        next;
                    }
                    my $group = $get_group->($glue);

#              debug(" generated: $group->{name}");
#              # Only needed when debugging.
#              $glue->{group} = $group;

                    $glue->{active} = 1;
                    $rule = {
                        action    => $rule->{action},
                        $that     => $rule->{$that},
                        $this     => $group,
                        src_range => $rule->{src_range},
                        prt       => $rule->{prt}
                    };
                }
                push @new_rules, $rule;
            }
            $hardware->{$rule_type} = \@new_rules;
        }
    }
    return;
}

# Handle iptables.
#
sub debug_bintree {
    my ($tree, $depth) = @_;
    $depth ||= '';
    my $ip      = print_ip $tree->{ip};
    my $mask    = print_ip $tree->{mask};
    my $subtree = $tree->{subtree} ? 'subtree' : '';

#    debug($depth, " $ip/$mask $subtree");
#    debug_bintree($tree->{lo}, "${depth}l") if $tree->{lo};
#    debug_bintree($tree->{hi}, "${depth}h") if $tree->{hi};
    return;
}

# Nodes are reverse sorted before being added to bintree.
# Redundant nodes are discarded while inserting.
# A node with value of sub-tree S is discarded,
# if some parent node already has sub-tree S.
sub add_bintree;

sub add_bintree  {
    my ($tree,    $node)      = @_;
    my ($tree_ip, $tree_mask) = @{$tree}{qw(ip mask)};
    my ($node_ip, $node_mask) = @{$node}{qw(ip mask)};
    my $result;

    # The case where new node is larger than root node will never
    # occur, because nodes are sorted before being added.

    if ($tree_mask < $node_mask && match_ip($node_ip, $tree_ip, $tree_mask)) {

        # Optimization for this special case:
        # Root of tree has attribute {subtree} which is identical to
        # attribute {subtree} of current node.
        # Node is known to be less than root node.
        # Hence node together with its subtree can be discarded
        # because it is redundant compared to root node.
        # ToDo:
        # If this optimization had been done before merge_subtrees,
        # it could have merged more subtrees.
        if (   not $tree->{subtree}
            or not $node->{subtree}
            or $tree->{subtree} ne $node->{subtree})
        {
            my $mask = ($tree_mask >> 1) | 0x80000000;
            my $branch = match_ip($node_ip, $tree_ip, $mask) ? 'lo' : 'hi';
            if (my $subtree = $tree->{$branch}) {
                $tree->{$branch} = add_bintree $subtree, $node;
            }
            else {
                $tree->{$branch} = $node;
            }
        }
        $result = $tree;
    }

    # Different nodes with identical IP address.
    # This shouldn't occur, because different nodes have already 
    # been converted to an unique object:
    # 1. Different interfaces of redundancy protocols like VRRP or HSRP.
    # 2. Dynamic NAT of different networks or hosts to a single address
    #    or range.
    elsif ($tree_mask == $node_mask && $tree_ip == $node_ip) {
        my $sub1 = $tree->{subtree} || '';
        my $sub2 = $node->{subtree} || '';
        if ($sub1 ne $sub2) {
            my $ip   = print_ip $tree_ip;
            my $mask = print_ip $tree_mask;
            internal_err("Inconsistent rules for iptables for $ip/$mask");
        }
        $result = $tree;
    }

    # Create common root for tree and node.
    else {
        while (1) {
            $tree_mask = ($tree_mask & 0x7fffffff) << 1;
            last if ($node_ip & $tree_mask) == ($tree_ip & $tree_mask);
        }
        $result = new(
            'Network',
            ip   => ($node_ip & $tree_mask),
            mask => $tree_mask
        );
        @{$result}{qw(lo hi)} =
          $node_ip < $tree_ip ? ($node, $tree) : ($tree, $node);
    }

    # Merge adjacent sub-networks.
  MERGE:
    {
        $result->{subtree} and last;
        my $lo = $result->{lo} or last;
        my $hi = $result->{hi} or last;
        my $mask = ($result->{mask} >> 1) | 0x80000000;
        $lo->{mask} == $mask or last;
        $hi->{mask} == $mask or last;
        $lo->{subtree} and $hi->{subtree} or last;
        $lo->{subtree} eq $hi->{subtree} or last;

        for my $key (qw(lo hi)) {
            $lo->{$key} and last MERGE;
            $hi->{$key} and last MERGE;
        }

#       debug('Merged: ', print_ip $lo->{ip},' ',
#             print_ip $hi->{ip},'/',print_ip $hi->{mask});
        $result->{subtree} = $lo->{subtree};
        delete $result->{lo};
        delete $result->{hi};
    }
    return $result;
}

# Build a binary tree for src/dst objects.
sub gen_addr_bintree  {
    my ($elements, $tree, $no_nat_set) = @_;

    # Sort in reverse order by mask and then by IP.
    my @nodes =
      sort { $b->{mask} <=> $a->{mask} || $b->{ip} <=> $a->{ip} }
      map {
        my ($ip, $mask) = @{ address($_, $no_nat_set) };

        # The tree's node is a simplified network object with
        # missing attribute 'name' and extra 'subtree'.
        new(
            'Network',
            ip      => $ip,
            mask    => $mask,
            subtree => $tree->{$_}
          )
      } @$elements;
    my $bintree = pop @nodes;
    while (my $next = pop @nodes) {
        $bintree = add_bintree $bintree, $next;
    }

    # Add attribute {noop} to node which doesn't add any test to
    # generated rule.
    $bintree->{noop} = 1 if $bintree->{mask} == 0;

#    debug_bintree($bintree);
    return $bintree;
}

# Build a tree for src-range/prt objects. Sub-trees for tcp and udp
# will be binary trees. Nodes have attributes {proto}, {range},
# {type}, {code} like protocols (but without {name}).
# Additional attributes for building the tree:
# For tcp and udp:
# {lo}, {hi} for sub-ranges of current node.
# For other protocols:
# {seq} an array of ordered nodes for sub protocols of current node.
# Elements of {lo} and {hi} or elements of {seq} are guaranteed to be
# disjoint.
# Additional attribute {subtree} is set with corresponding subtree of
# protocol object if current node comes from a rule and wasn't inserted
# for optimization.
sub gen_prt_bintree  {
    my ($elements, $tree) = @_;

    my $ip_prt;
    my %top_prt;
    my %sub_prt;

    # Add all protocols directly below protocol 'ip' into hash %top_prt
    # grouped by protocol.  Add protocols below top protocols or below
    # other protocols of current set of protocols to hash %sub_prt.
  PRT:
    for my $prt (@$elements) {
        my $proto = $prt->{proto};
        if ($proto eq 'ip') {
            $ip_prt = $prt;
        }
        else {
            my $up = $prt->{up};

            # Check if $prt is sub protocol of any other protocol of
            # current set. But handle direct sub protocols of 'ip' as
            # top protocols.
            while ($up->{up}) {
                if (my $subtree = $tree->{$up}) {

                    # Found sub protocol of current set.
                    # Optimization:
                    # Ignore the sub protocol if both protocols 
                    # have identical subtrees.
                    # This happens for different objects having identical IP
                    # from NAT or from redundant interfaces.
                    if ($tree->{$prt} ne $subtree) {
                        push @{ $sub_prt{$up} }, $prt;
                    }
                    next PRT;
                }
                $up = $up->{up};
            }

            # Not a sub protocol (except possibly of IP).
            my $key = $proto =~ /^\d+$/ ? 'proto' : $proto;
            push @{ $top_prt{$key} }, $prt;
        }
    }

    # Collect subtrees for tcp, udp, proto and icmp.
    my @seq;

# Build subtree of tcp and udp protocols.
    #
    # We need not to handle 'tcp established' because it is only used
    # for stateless routers, but iptables is stateful.
    my $gen_lohitrees;
    my $gen_rangetree;
    $gen_lohitrees = sub {
        my ($prt_aref) = @_;
        if (not $prt_aref) {
            return (undef, undef);
        }
        elsif (@$prt_aref == 1) {
            my $prt = $prt_aref->[0];
            my ($lo, $hi) = $gen_lohitrees->($sub_prt{$prt});
            my $node = {
                proto   => $prt->{proto},
                range   => $prt->{range},
                subtree => $tree->{$prt},
                lo      => $lo,
                hi      => $hi
            };
            return ($node, undef);
        }
        else {
            my @ranges =
              sort { $a->{range}->[0] <=> $b->{range}->[0] } @$prt_aref;

            # Split array in two halves.
            my $mid   = int($#ranges / 2);
            my $left  = [ @ranges[ 0 .. $mid ] ];
            my $right = [ @ranges[ $mid + 1 .. $#ranges ] ];
            return ($gen_rangetree->($left), $gen_rangetree->($right));
        }
    };
    $gen_rangetree = sub {
        my ($prt_aref) = @_;
        my ($lo, $hi) = $gen_lohitrees->($prt_aref);
        return $lo if not $hi;
        my $proto = $lo->{proto};

        # Take low port from lower tree and high port from high tree.
        my $range = [ $lo->{range}->[0], $hi->{range}->[1] ];

        # Merge adjacent port ranges.
        if (    $lo->{range}->[1] + 1 == $hi->{range}->[0]
            and $lo->{subtree}
            and $hi->{subtree}
            and $lo->{subtree} eq $hi->{subtree})
        {
            my @hilo =
              grep { defined $_ } $lo->{lo}, $lo->{hi}, $hi->{lo}, $hi->{hi};
            if (@hilo <= 2) {

#		debug("Merged: $lo->{range}->[0]-$lo->{range}->[1]",
#		      " $hi->{range}->[0]-$hi->{range}->[1]");
                my $node = {
                    proto   => $proto,
                    range   => $range,
                    subtree => $lo->{subtree}
                };
                $node->{lo} = shift @hilo if @hilo;
                $node->{hi} = shift @hilo if @hilo;
                return $node;
            }
        }
        return (
            {
                proto => $proto,
                range => $range,
                lo    => $lo,
                hi    => $hi
            }
        );
    };
    for my $what (qw(tcp udp)) {
        next if not $top_prt{$what};
        push @seq, $gen_rangetree->($top_prt{$what});
    }

# Add single nodes for numeric protocols.
    if (my $aref = $top_prt{proto}) {
        for my $prt (sort { $a->{proto} <=> $b->{proto} } @$aref) {
            my $node = { proto => $prt->{proto}, subtree => $tree->{$prt} };
            push @seq, $node;
        }
    }

# Build subtree of icmp protocols.
    if (my $icmp_aref = $top_prt{icmp}) {
        my %type2prt;
        my $icmp_any;

        # If one protocol is 'icmp any' it is the only top protocol,
        # all other icmp protocols are sub protocols.
        if (not defined $icmp_aref->[0]->{type}) {
            $icmp_any  = $icmp_aref->[0];
            $icmp_aref = $sub_prt{$icmp_any};
        }

        # Process icmp protocols having defined type and possibly defined code.
        # Group protocols by type.
        for my $prt (@$icmp_aref) {
            my $type = $prt->{type};
            push @{ $type2prt{$type} }, $prt;
        }

        # Parameter is array of icmp protocols all having
        # the same type and different but defined code.
        # Return reference to array of nodes sorted by code.
        my $gen_icmp_type_code_sorted = sub {
            my ($aref) = @_;
            [
                map {
                    {
                        proto   => 'icmp',
                        type    => $_->{proto},
                        code    => $_->{code},
                        subtree => $tree->{$_}
                    }
                  }
                  sort { $a->{code} <=> $b->{code} } @$aref
            ];
        };

        # For collecting subtrees of icmp subtree.
        my @seq2;

        # Process grouped icmp protocols having the same type.
        for my $type (sort { $a <=> $b } keys %type2prt) {
            my $aref2 = $type2prt{$type};
            my $node2;

            # If there is more than one protocol,
            # all have same type and defined code.
            if (@$aref2 > 1) {
                my $seq3 = $gen_icmp_type_code_sorted->($aref2);

                # Add a node 'icmp type any' as root.
                $node2 = {
                    proto => 'icmp',
                    type  => $type,
                    seq   => $seq3,
                };
            }

            # One protocol 'icmp type any'.
            else {
                my $prt = $aref2->[0];
                $node2 = {
                    proto   => 'icmp',
                    type    => $type,
                    subtree => $tree->{$prt}
                };
                if (my $aref3 = $sub_prt{$prt}) {
                    $node2->{seq} = $gen_icmp_type_code_sorted->($aref3);
                }
            }
            push @seq2, $node2;
        }

        # Add root node for icmp subtree.
        my $node;
        if ($icmp_any) {
            $node = {
                proto   => 'icmp',
                seq     => \@seq2,
                subtree => $tree->{$icmp_any}
            };
        }
        elsif (@seq2 > 1) {
            $node = { proto => 'icmp', seq => \@seq2 };
        }
        else {
            $node = $seq2[0];
        }
        push @seq, $node;
    }

# Add root node for whole tree.
    my $bintree;
    if ($ip_prt) {
        $bintree = {
            proto   => 'ip',
            seq     => \@seq,
            subtree => $tree->{$ip_prt}
        };
    }
    elsif (@seq > 1) {
        $bintree = { proto => 'ip', seq => \@seq };
    }
    else {
        $bintree = $seq[0];
    }

    # Add attribute {noop} to node which doesn't need any test in
    # generated chain.
    $bintree->{noop} = 1 if $bintree->{proto} eq 'ip';
    return $bintree;
}

my %ref_type = (
    prt       => \%ref2prt,
    src_range => \%ref2prt,
    src       => \%ref2obj,
    dst       => \%ref2obj
);
$ref2prt{$prt_icmp} = $prt_icmp;

sub find_chains  {
    my ($router, $hardware) = @_;

    # For generating names of chains.
    # Initialize if called first time.
    $router->{chain_counter} ||= 1;

    my $no_nat_set = $hardware->{no_nat_set};
    my @rule_arefs = values %{ $hardware->{io_rules} };
    my $intf_rules = $hardware->{intf_rules};
    push @rule_arefs, $intf_rules if $intf_rules;

    for my $rules (@rule_arefs) {

        # Change rules to allow optimization of objects having
        # identical IP adress.
        # This is crucial for correct operation of sub add_bintree.
        # Otherwise internal_err("Inconsistent rules for iptables")
        # would be triggered.
        for my $rule (@$rules) {
            for my $what (qw(src dst)) {
                my $obj = $rule->{$what};

                # Loopback interface is converted to loopback network,
                # if other networks with same address exist.
                if ($obj->{loopback}) {
                    if (!($rules eq 'intf_rules' && $what eq 'dst')) {
                        $obj = $obj->{network};
                    }
                }

                # Identical networks from dynamic NAT and
                # from identical aggregates.
                if (my $identical = $obj->{is_identical}) {
                    if (my $other = $identical->{$no_nat_set}) {
                        $obj = $other;
                    }
                }

                # Identical redundancy interfaces.
                elsif (my $aref = $obj->{redundancy_interfaces}) {
                    if (!($rules eq 'intf_rules' && $what eq 'dst')) {
                        $obj = $aref->[0];
                    }
                }
                else {
                    next;
                }

                # Don't change rules of devices in other NAT
                # domain where we may have other relation.
                $rule = { %$rule, $what => $obj };
            }
        }

        my %cache;

        my $print_tree;
        $print_tree = sub {
            my ($tree, $order, $depth) = @_;
            my $key      = $order->[$depth];
            my $ref2x    = $ref_type{$key};
            my @elements = map { $ref2x->{$_} } keys %$tree;
            for my $elem (@elements) {

#                debug(' ' x $depth, "$elem->{name}");
                if ($depth < $#$order) {
                    $print_tree->($tree->{$elem}, $order, $depth + 1);
                }
            }
        };

        my $insert_bintree = sub {
            my ($tree, $order, $depth) = @_;
            my $key      = $order->[$depth];
            my $ref2x    = $ref_type{$key};
            my @elements = map { $ref2x->{$_} } keys %$tree;

            # Put prt/src/dst objects at the root of some subtree into a
            # (binary) tree. This is used later to convert subsequent tests
            # for ip/mask or port ranges into more efficient nested chains.
            my $bintree;
            if ($ref2x eq \%ref2obj) {
                $bintree = gen_addr_bintree(\@elements, $tree, $no_nat_set);
            }
            else {    # $ref2x eq \%ref2prt
                $bintree = gen_prt_bintree(\@elements, $tree);
            }
            return $bintree;
        };

        # Used by $merge_subtrees1 to find identical subtrees.
        # Use hash for efficient lookup.
        my %depth2size2subtrees;
        my %subtree2bintree;

        # Find and merge identical subtrees.
        my $merge_subtrees1 = sub {
            my ($tree, $order, $depth) = @_;

          SUBTREE:
            for my $subtree (values %$tree) {
                my @keys = keys %$subtree;
                my $size = @keys;

                # Find subtree with identical keys and values;
              FIND:
                for my $subtree2 (@{ $depth2size2subtrees{$depth}->{$size} }) {
                    for my $key (@keys) {
                        if (not $subtree2->{$key}
                            or $subtree2->{$key} ne $subtree->{$key})
                        {
                            next FIND;
                        }
                    }

                    # Substitute current subtree with found subtree.
                    $subtree = $subtree2bintree{$subtree2};
                    next SUBTREE;

                }

                # Found a new subtree.
                push @{ $depth2size2subtrees{$depth}->{$size} }, $subtree;
                $subtree = $subtree2bintree{$subtree} =
                  $insert_bintree->($subtree, $order, $depth + 1);
            }
        };

        my $merge_subtrees = sub {
            my ($tree, $order) = @_;

            # Process leaf nodes first.
            for my $href (values %$tree) {
                for my $href (values %$href) {
                    $merge_subtrees1->($href, $order, 2);
                }
            }

            # Process nodes next to leaf nodes.
            for my $href (values %$tree) {
                $merge_subtrees1->($href, $order, 1);
            }

            # Process nodes next to root.
            $merge_subtrees1->($tree, $order, 0);
            return $insert_bintree->($tree, $order, 0);
        };

        # Add new chain to current router.
        my $new_chain = sub {
            my ($rules) = @_;
            my $chain = new(
                'Chain',
                name  => "c$router->{chain_counter}",
                rules => $rules,
            );
            push @{ $router->{chains} }, $chain;
            $router->{chain_counter}++;
            $chain;
        };

        my $gen_chain;
        $gen_chain = sub {
            my ($tree, $order, $depth) = @_;
            my $key = $order->[$depth];
            my @rules;

            # We need the original value later.
            my $bintree = $tree;
            while (1) {
                my ($hi, $lo, $seq, $subtree) =
                  @{$bintree}{qw(hi lo seq subtree)};
                $seq = undef if $seq and not @$seq;
                if (not $seq) {
                    push @$seq, $hi if $hi;
                    push @$seq, $lo if $lo;
                }
                if ($subtree) {

#                   if($order->[$depth+1]&&
#                      $order->[$depth+1] =~ /^(src|dst)$/) {
#                       debug($order->[$depth+1]);
#                       debug_bintree($subtree);
#                   }
                    my $rules = $cache{$subtree};
                    if (not $rules) {
                        $rules =
                          $depth + 1 >= @$order
                          ? [ { action => $subtree } ]
                          : $gen_chain->($subtree, $order, $depth + 1);
                        if (@$rules > 1 and not $bintree->{noop}) {
                            my $chain = $new_chain->($rules);
                            $rules = [ { action => $chain, goto => 1 } ];
                        }
                        $cache{$subtree} = $rules;
                    }

                    my @add_keys;

                    # Don't use "goto", if some tests for sub-nodes of
                    # $subtree are following.
                    push @add_keys, (goto => 0)        if $seq;
                    push @add_keys, ($key => $bintree) if not $bintree->{noop};
                    if (@add_keys) {

                        # Create a copy of each rule because we must not change
                        # the original cached rules.
                        push @rules, map {
                            { (%$_, @add_keys) }
                        } @$rules;
                    }
                    else {
                        push @rules, @$rules;
                    }
                }
                last if not $seq;

                # Take this value in next iteration.
                $bintree = pop @$seq;

                # Process remaining elements.
                for my $node (@$seq) {
                    my $rules = $gen_chain->($node, $order, $depth);
                    push @rules, @$rules;
                }
            }
            if (@rules > 1 and not $tree->{noop}) {

                # Generate new chain. All elements of @seq are
                # known to be disjoint. If one element has matched
                # and branched to a chain, then the other elements
                # need not be tested again. This is implemented by
                # calling the chain using '-g' instead of the usual '-j'.
                my $chain = $new_chain->(\@rules);
                return [ { action => $chain, goto => 1, $key => $tree } ];
            }
            else {
                return \@rules;
            }
        };

        # Build rule trees. Generate and process separate tree for
        # adjacent rules with same action.
        my @rule_trees;
        my %tree2order;
        if ($rules and @$rules) {
            my $prev_action = $rules->[0]->{action};
            push @$rules, { action => 0 };
            my $start = my $i = 0;
            my $last = $#$rules;
            my %count;
            while (1) {
                my $rule   = $rules->[$i];
                my $action = $rule->{action};
                if ($action eq $prev_action) {

                    # Count, which key has the largest number of
                    # different values.
                    for my $what (qw(src dst src_range prt)) {
                        $count{$what}{ $rule->{$what} } = 1;
                    }
                    $i++;
                }
                else {

                    # Use key with smaller number of different values
                    # first in rule tree. This gives smaller tree and
                    # fewer tests in chains.
                    my @test_order =
                      sort { keys %{ $count{$a} } <=> keys %{ $count{$b} } }
                      qw(src_range dst prt src);
                    my $rule_tree;
                    my $end = $i - 1;
                    for (my $j = $start ; $j <= $end ; $j++) {
                        my $rule = $rules->[$j];
                        if ($rule->{prt}->{proto} eq 'icmp') {

                            # Change copy, because original rule is
                            # referenced at other devices and must be
                            # unchanged.
                            $rule = { %$rule, src_range => $prt_icmp };
                        }
                        my ($action, $t1, $t2, $t3, $t4) =
                          @{$rule}{ 'action', @test_order };
                        $rule_tree->{$t1}->{$t2}->{$t3}->{$t4} = $action;
                    }
                    push @rule_trees, $rule_tree;

#		    debug(join ', ', @test_order);
                    $tree2order{$rule_tree} = \@test_order;
                    last if not $action;
                    $start       = $i;
                    $prev_action = $action;
                }
            }
            @$rules = ();
        }

        for (my $i = 0 ; $i < @rule_trees ; $i++) {
            my $tree  = $rule_trees[$i];
            my $order = $tree2order{$tree};

#           $print_tree->($tree, $order, 0);
            $tree = $merge_subtrees->($tree, $order);
            my $result = $gen_chain->($tree, $order, 0);

            # Goto must not be used in last rule of rule tree which is
            # not the last tree.
            if ($i != $#rule_trees) {
                my $rule = $result->[-1];
                delete $rule->{goto};
            }

            # Postprocess rules: Add missing attributes src_range,
            # prt, src, dst with no-op values.
            for my $rule (@$result) {
                $rule->{src} ||= $network_00;
                $rule->{dst} ||= $network_00;
                my $prt       = $rule->{prt};
                my $src_range = $rule->{src_range};
                if (not $prt and not $src_range) {
                    $rule->{prt} = $rule->{src_range} = $prt_ip;
                }
                else {
                    $rule->{prt} ||=
                        $src_range->{proto} eq 'tcp'  ? $prt_tcp->{dst_range}
                      : $src_range->{proto} eq 'udp'  ? $prt_udp->{dst_range}
                      : $src_range->{proto} eq 'icmp' ? $prt_icmp
                      :                                 $prt_ip;
                    $rule->{src_range} ||=
                        $prt->{proto} eq 'tcp' ? $prt_tcp->{src_range}
                      : $prt->{proto} eq 'udp' ? $prt_udp->{src_range}
                      :                          $prt_ip;
                }
            }
            push @$rules, @$result;
        }
    }
    return;
}

# Print chains of iptables.
# Objects have already been normalized to ip/mask pairs.
# NAT has already been applied.
sub print_chains  {
    my ($router) = @_;

    # Declare chain names.
    for my $chain (@{ $router->{chains} }) {
        my $name = $chain->{name};
        print ":$name -\n";
    }

    # Add user defined chain 'droplog'.
    print ":droplog -\n";
    print "-A droplog -j LOG --log-level debug\n";
    print "-A droplog -j DROP\n";

    # Define chains.
    for my $chain (@{ $router->{chains} }) {
        my $name   = $chain->{name};
        my $prefix = "-A $name";

#	my $steps = my $accept = my $deny = 0;
        for my $rule (@{ $chain->{rules} }) {
            my $action = $rule->{action};
            my $action_code =
                is_chain($action) ? $action->{name}
              : $action eq 'permit' ? 'ACCEPT'
              :                       'droplog';

            # Calculate maximal number of matches if
            # - some rules matches (accept) or
            # - all rules don't match (deny).
#	    $steps += 1;
#	    if ($action eq 'permit') {
#		$accept = max($accept, $steps);
#	    }
#	    elsif ($action eq 'deny') {
#		$deny = max($deny, $steps);
#	    }
#	    elsif ($rule->{goto}) {
#		$accept = max($accept, $steps + $action->{a});
#	    }
#	    else {
#		$accept = max($accept, $steps + $action->{a});
#		$steps += $action->{d};
#	    }

            my $jump = $rule->{goto} ? '-g' : '-j';
            my $result = "$jump $action_code";
            if (my $src = $rule->{src}) {
                my $ip_mask = [ @{$src}{qw(ip mask)} ];
                if ($ip_mask->[1] != 0) {
                    $result .= ' -s ' . prefix_code($ip_mask);
                }
            }
            if (my $dst = $rule->{dst}) {
                my $ip_mask = [ @{$dst}{qw(ip mask)} ];
                if ($ip_mask->[1] != 0) {
                    $result .= ' -d ' . prefix_code($ip_mask);
                }
            }
          BLOCK:
            {
                my $src_range = $rule->{src_range};
                my $prt       = $rule->{prt};
                last BLOCK if not $src_range and not $prt;
                last BLOCK if $prt and $prt->{proto} eq 'ip';
                $src_range ||=
                    $prt->{proto} eq 'tcp' ? $prt_tcp->{src_range}
                  : $prt->{proto} eq 'udp' ? $prt_udp->{src_range}
                  :                          $prt_ip;
                if (not $prt) {
                    last BLOCK if $src_range->{proto} eq 'ip';
                    $prt =
                        $src_range->{proto} eq 'tcp'  ? $prt_tcp->{dst_range}
                      : $src_range->{proto} eq 'udp'  ? $prt_udp->{dst_range}
                      : $src_range->{proto} eq 'icmp' ? $prt_icmp
                      :                                 $prt_ip;
                }

#               debug("c ",print_rule $rule) if not $src_range or not $prt;
                $result .= ' ' . iptables_prt_code($src_range, $prt);
            }
            print "$prefix $result\n";
        }

#	$deny = max($deny, $steps);
#	$chain->{a} = $accept;
#	$chain->{d} = $deny;
#	print "# Max tests: Accept: $accept, Deny: $deny\n";
    }

    # Empty line as delimiter.
    print "\n";
    return;
}

# Find adjacent port ranges.
sub join_ranges  {
    my ($hardware) = @_;
    my $changed;
    for my $rules ('intf_rules', 'rules', 'out_rules') {
        my %hash = ();
        for my $rule (@{ $hardware->{$rules} }) {
            my ($action, $src, $dst, $src_range, $prt) =
              @{$rule}{ 'action', 'src', 'dst', 'src_range', 'prt' };

            # Only ranges which have a neighbor may be successfully optimized.
            $prt->{has_neighbor} or next;
            $hash{$action}->{$src}->{$dst}->{$src_range}->{$prt} = $rule;
        }

        # %hash is {action => href, ...}
        for my $href (values %hash) {

            # $href is {src => href, ...}
            for my $href (values %$href) {

                # $href is {dst => href, ...}
                for my $href (values %$href) {

                    # $href is {src_port => href, ...}
                    for my $src_range_ref (keys %$href) {
                        my $src_range = $ref2prt{$src_range_ref};
                        my $href      = $href->{$src_range_ref};

                        # Values of %$href are rules with identical
                        # action/src/dst/src_port and a TCP or UDP
                        # protocol.  When sorting these rules by low
                        # port number, rules with adjacent protocols
                        # will placed side by side.  There can't be
                        # overlaps, because they have been split in
                        # function 'order_ranges'.  There can't be
                        # sub-ranges, because they have been deleted
                        # as redundant above.
                        my @sorted = sort {
                            $a->{prt}->{range}->[0] <=> $b->{prt}->{range}->[0]
                        } (values %$href);
                        @sorted >= 2 or next;
                        my $i      = 0;
                        my $rule_a = $sorted[$i];
                        my ($a1, $a2) = @{ $rule_a->{prt}->{range} };
                        while (++$i < @sorted) {
                            my $rule_b = $sorted[$i];
                            my ($b1, $b2) = @{ $rule_b->{prt}->{range} };
                            if ($a2 + 1 == $b1) {

                                # Found adjacent port ranges.
                                if (my $range = delete $rule_a->{range}) {

                                    # Extend range of previous two or
                                    # more elements.
                                    $range->[1] = $b2;
                                    $rule_b->{range} = $range;
                                }
                                else {

                                    # Combine ranges of $rule_a and $rule_b.
                                    $rule_b->{range} = [ $a1, $b2 ];
                                }

                                # Mark previous rule as deleted.
                                # Don't use attribute 'deleted', this
                                # may still be set by global
                                # optimization pass.
                                $rule_a->{local_del} = 1;
                                $changed = 1;
                            }
                            $rule_a = $rule_b;
                            ($a1, $a2) = ($b1, $b2);
                        }
                    }
                }
            }
        }
        if ($changed) {
            my @rules;
            for my $rule (@{ $hardware->{$rules} }) {

                # Check and remove attribute 'local_del'.
                next if delete $rule->{local_del};

                # Process rules with joined port ranges.
                # Remove auxiliary attribute {range} from rules.
                if (my $range = delete $rule->{range}) {
                    my $prt   = $rule->{prt};
                    my $proto = $prt->{proto};
                    my $key   = join ':', @$range;

                    # Try to find existing prt with matching range.
                    # This is needed for find_object_groups to work.
                    my $new_prt = $prt_hash{$proto}->{$key};
                    unless ($new_prt) {
                        $new_prt = {
                            name  => "joined_$prt->{name}",
                            proto => $proto,
                            range => $range
                        };
                        $prt_hash{$proto}->{$key} = $new_prt;
                    }
                    my $new_rule = { %$rule, prt => $new_prt };
                    push @rules, $new_rule;
                }
                else {
                    push @rules, $rule;
                }
            }
            $hardware->{$rules} = \@rules;
        }
    }
    return;
}

# Reuse network objects at different interfaces, 
# so we get reused object-groups.
my %filter_networks;

sub get_filter_network {
    my ($ip, $mask) = @_;
    my $key = "$ip/$mask";
    my $net = $filter_networks{$key};
    if (!$net) {
        $net = new('Network', ip => $ip, mask => $mask);
        $filter_networks{$key} = $net;
        $ref2obj{$net} = $net;
    }
    return $net;
}

# Remove rules on device which filters only locally.
sub remove_non_local_rules {
    my ($router, $hardware) = @_;
    $router->{managed} eq 'local' or return;

    my $no_nat_set = $hardware->{no_nat_set};
    my $filter_only = $router->{filter_only};
    for my $rules ('rules', 'out_rules') {
        my $changed;
        for my $rule (@{ $hardware->{$rules} }) {

            # Don't remove deny rule
            next if $rule->{action} ne 'permit';
            my $both_match = 0;
            for my $what (qw(src dst)) {
                my $obj = $rule->{$what};
                my ($ip, $mask) = @{ address($obj, $no_nat_set) };
                for my $pair (@$filter_only) {
                    my ($i, $m) = @$pair;

                    # src/dst matches filter_only.
                    if ($mask > $m) {
                        match_ip($ip, $i, $m) and $both_match++;
                    }

                    # filter_only matches src/dst.
                    elsif (match_ip($i, $ip, $mask)) {
                        $both_match++;
                    }
                }
            }

            # Either src or dst or both are extern.
            # The rule will not be filtered at this device.
            if ($both_match < 2) {
                $rule = undef;
                $changed = 1;
            }
        }
        $changed and 
            $hardware->{$rules} = [ grep { $_ } @{ $hardware->{$rules} } ];
    }
    return;
}

# Add deny and permit rules at device which filters only locally.
sub add_local_deny_rules {
    my ($router, $hardware) = @_;
    $router->{managed} eq 'local' or return;
    $hardware->{crosslink} and return;

    my $filter_only = $router->{filter_only};
    my @dst_networks = map { get_filter_network(@$_) } @$filter_only;

    for my $attr (qw(rules out_rules)) {

        next if $attr eq 'rules' && $hardware->{no_in_acl};
        next if $attr eq 'out_rules' && ! $hardware->{need_out_acl};

        # If attached zone has only one connection to this firewall
        # than we don't need to check the source address.  It has
        # already been checked, that all networks of this zone match
        # {filter_only}.
        my $check = sub {
            $attr eq 'out_rules' and return;
            for my $interface (@{ $hardware->{interfaces} }) {
                my $zone = $interface->{zone};
                $zone->{zone_cluster} and return;

                # Ignore real interface of virtual interface.
                my @interfaces = grep({ ! $_->{main_interface} }
                                      @{ $zone->{interfaces} });

                if (@interfaces > 1) {


                    # Multilpe interfaces belonging to one redundancy
                    # group can't be used to cross the zone.
                    my @redundant = 
                        grep { $_ } 
                        map { $_->{redundancy_interfaces} } @interfaces;
                    @redundant == @interfaces and equal(@redundant) 
                        or return;
                }
            }
            return 1;
        };
        my @src_networks = $check->() ? ($network_00) : @dst_networks;

        my @filter_rules;
        for my $src (@src_networks) {
            for my $dst (@dst_networks) {
                push(@filter_rules, 
                     {
                         action    => 'deny',
                         src       => $src,
                         dst       => $dst,
                         src_range => $prt_ip,
                         prt       => $prt_ip
                     });
            }
        }
        my $rules = $hardware->{$attr};
        push @$rules, @filter_rules, $permit_any_rule;
    }
    return;
}

#use Time::HiRes qw ( time );
sub local_optimization {
    progress('Optimizing locally');

    # Needed in find_chains.
    $ref2obj{$network_00} = $network_00;

    my %seen;

# For debugging only
#    my %time;
#    my %r2rules;
#    my %r2id;
#    my %r2del;
#    my %r2sec;
    for my $domain (@natdomains) {
        my $no_nat_set = $domain->{no_nat_set};

        # Subnet relation may be different for each NAT domain,
        # therefore it is set up again for each NAT domain.
        for my $network (@networks) {
            next if !$network->{mask} || $network->{mask} == 0;
            my $up = $network->{is_in}->{$no_nat_set};
            if (!$up || $up->{mask} == 0) {
                $up = $network_00;
            }
            $network->{up} = $up;
        }

        for my $network (@{ $domain->{networks} }) {

            # Iterate over all interfaces attached to current network.
            # If interface is virtual tunnel for multiple software clients,
            # take separate rules for each software client.
            for my $interface (
                map { $_->{id_rules} ? values %{ $_->{id_rules} } : $_ }
                @{ $network->{interfaces} })
            {
                my $router           = $interface->{router};
                my $managed          = $router->{managed} or next;
                my $secondary_filter = $managed eq 'secondary';
                my $standard_filter  = $managed eq 'standard';
                my $do_auth          = $router->{model}->{do_auth};
                my $hardware =
                    $interface->{ip} eq 'tunnel'
                  ? $interface
                  : $interface->{hardware};

                # Do local optimization only once for each hardware interface.
                next if $seen{$hardware};
                $seen{$hardware} = 1;

                if ($router->{model}->{filter} eq 'iptables') {
                    find_chains $router, $hardware;
                    next;
                }

                remove_non_local_rules($router, $hardware);

#               my $rname = $router->{name};
#               debug("$router->{name}");
                for my $rules ('intf_rules', 'rules', 'out_rules') {

#                    my $t1 = time();

                    # For supernet / aggregate rules used in optimization.
                    my %hash;

                    # For finding duplicate rules having src or dst
                    # which exist as different objects with identical
                    # ip address.
                    my %id_hash;

                    # For finding duplicate secondary rules.
                    my %id_hash2;

                    my $changed = 0;
                    for my $rule (@{ $hardware->{$rules} }) {

                        # Change rule to allow optimization of objects
                        # having identical IP address.
                        for my $what (qw(src dst)) {
                            my $obj = $rule->{$what};
                            my $obj_changed;

                            # Change loopback interface to loopback network.
                            if ($obj->{loopback} && is_interface($obj)) {
                                if (!($rules eq 'intf_rules' && $what eq 'dst'))
                                {
                                    $obj = $obj->{network};
                                    $obj_changed = 1;
                                }
                            }

                            # Identical networks from dynamic NAT and
                            # from identical aggregates.
                            if (my $identical = $obj->{is_identical}) {
                                if (my $other = $identical->{$no_nat_set}) {
                                    $obj = $other;
                                    $obj_changed = 1;
                                }
                            }

                            # Identical redundancy interfaces.
                            elsif (my $aref = $obj->{redundancy_interfaces}) {
                                if (
                                    !($rules eq 'intf_rules' && $what eq 'dst')
                                    || (   $router->{crosslink_intf_hash}
                                        && $router->{crosslink_intf_hash}
                                        ->{ $aref->[0] })
                                  )
                                {
                                    $obj = $aref->[0];
                                    $obj_changed = 1;
                                }
                            }

                            $obj_changed or next;

                            # Don't change rules of devices in other
                            # NAT domain where we may have other
                            # relation.
                            $rule = { %$rule, $what => $obj };
                        }
                        my ($src, $dst, $action, $src_range, $prt) =
                          @{$rule}{ 'src', 'dst', 'action', 'src_range',
                            'prt' };

                        # Remove duplicate rules.
                        if ($id_hash{$action}->{$src}->{$dst}->{$src_range}
                            ->{$prt})
                        {
                            $rule    = undef;
                            $changed = 1;

#                            $r2id{$rname}++;
                            next;
                        }
                        $id_hash{$action}->{$src}->{$dst}->{$src_range}
                          ->{$prt} = $rule;

                        if (   $src->{is_supernet}
                            || $dst->{is_supernet}
                            || $rule->{stateless})
                        {
                            $hash{$action}->{$src}->{$dst}->{$src_range}
                              ->{$prt} = $rule;
                        }
                    }

#                    my $t2 = time();
#                    $time{$rname}[0] += $t2-$t1;
                  RULE:
                    for my $rule (@{ $hardware->{$rules} }) {
                        next if not $rule;

#                        my $t3 = time();
#                        $r2rules{$rname}++;

#                       debug(print_rule $rule);
#                       debug "is_supernet" if $rule->{dst}->{is_supernet};
                        my ($action, $src, $dst, $src_range, $prt) =
                          @{$rule}{ 'action', 'src', 'dst', 'src_range',
                            'prt' };

                        while (1) {
                            my $src = $src;
                            if (my $hash = $hash{$action}) {
                                while (1) {
                                    my $dst = $dst;
                                    if (my $hash = $hash->{$src}) {
                                        while (1) {
                                            my $src_range = $src_range;
                                            if (my $hash = $hash->{$dst}) {
                                                while (1) {
                                                    my $prt = $prt;
                                                    if (my $hash =
                                                        $hash->{$src_range})
                                                    {
                                                        while (1) {
                                                            if (my $other_rule =
                                                                $hash->{$prt})
                                                            {
                                                                unless ($rule eq
                                                                    $other_rule)
                                                                {

# debug("del:", print_rule $rule);
# debug("oth:", print_rule $other_rule);
                                                                    $rule =
                                                                      undef;

#                                                                    $r2del{$rname}++;
                                                                    $changed =
                                                                      1;

#                        $time{$rname}[1] += time()-$t3;
                                                                    next RULE;
                                                                }
                                                            }
                                                            $prt = $prt->{up}
                                                              or last;
                                                        }
                                                    }
                                                    $src_range =
                                                      $src_range->{up}
                                                      or last;
                                                }
                                            }
                                            $dst = $dst->{up} or last;
                                        }
                                    }
                                    $src = $src->{up} or last;
                                }
                            }
                            last if $action eq 'deny';
                            $action = 'deny';
                        }

#                        my $t4 = time();
#                        $time{$rname}[1] += $t4-$t3;

                        # Implement remaining rules as secondary rule,
                        # if possible.
                        if (   $secondary_filter && $rule->{some_non_secondary}
                            || $standard_filter && $rule->{some_primary})
                        {
                            $rule->{action} eq 'permit' or internal_err();
                            my ($src, $dst) = @{$rule}{qw(src dst)};

                            # Replace obj by largest supernet in zone,
                            # which has no subnet in other zone.
                            # We must not change to network having subnet in
                            # other zone, because then we had to do
                            # check_supernet_rules for newly created
                            # secondary rules.
                            for my $ref (\$src, \$dst) {

                                # Restrict secondary optimization at
                                # authenticating router to prevent
                                # unauthorized access with spoofed IP
                                # address.
                                if ($do_auth) {
                                    my $type = ref($$ref);

                                    # Single ID-hosts must not be
                                    # converted to network.
                                    if ($type eq 'Subnet') {
                                        next if $$ref->{id};
                                    }

                                    # Network with ID-hosts must not
                                    # be optimized at all.
                                    elsif ($type eq 'Network') {
                                        next RULE if $$ref->{has_id_hosts};
                                    }
                                }
                                if (
                                       $$ref eq $dst
                                    && is_interface($dst)
                                    && (
                                        $dst->{router} eq $router
                                        || (    $router->{crosslink_intf_hash}
                                            and $router->{crosslink_intf_hash}
                                            ->{$dst})
                                    )
                                  )
                                {
                                    next;
                                }
                                if (is_subnet($$ref) || is_interface($$ref)) {
                                    my $net = $$ref->{network};
                                    next if $net->{has_other_subnet};
                                    $$ref = $net;
                                }
                                if (my $max = $$ref->{max_up_net}) {
                                    if ($max->{has_other_subnet}) {
                                        my $net = $$ref;
                                        while (my $up = $net->{up}) {
                                            if ($up->{has_other_subnet}) {
                                                last;
                                            }
                                            else {
                                                $net = $up;
                                            }
                                        }
                                        $$ref = $net;
                                    }
                                    else {
                                        $$ref = $max;
                                    }
                                }

                                # Prevent duplicate ACLs for networks which
                                # are translated to the same ip address.
                                if (my $identical = $$ref->{is_identical}) {
                                    if (my $one_net = $identical->{$no_nat_set})
                                    {
                                        $$ref = $one_net;
                                    }
                                }
                            }

                            # Add new rule to hash. If there are multiple
                            # rules which could be converted to the same
                            # secondary rule, only the first one will be
                            # generated.
                            if (my $old = $id_hash2{$src}->{$dst}) {

                                if ($old ne $rule) {

#				    debug("sec delete: ", print_rule $rule);

                                    $rule    = undef;
                                    $changed = 1;

#                                    $r2sec{$rname}++;
                                }
                            }
                            else {

                                # Don't modify original rule, because the
                                # identical rule is referenced at different
                                # routers.
                                my $new_rule = {
                                    action    => 'permit',
                                    src       => $src,
                                    dst       => $dst,
                                    src_range => $prt_ip,
                                    prt       => $prt_ip,
                                };

#				debug("sec: ", print_rule $new_rule);
                                $id_hash2{$src}->{$dst} = $new_rule;

                                # This only works if smaller rule isn't
                                # already processed.
                                if ($src->{is_supernet} || $dst->{is_supernet})
                                {
                                    $hash{permit}->{$src}->{$dst}->{$prt_ip}
                                      ->{$prt_ip} = $new_rule;
                                }

                                # This changes @{$hardware->{$rules}} !
                                $rule = $new_rule;
                            }
                        }

#                        my $t5 = time();
#                        $time{$rname}[2] += $t5-$t4;
                    }
                    if ($changed) {
                        $hardware->{$rules} =
                          [ grep { defined $_ } @{ $hardware->{$rules} } ];
                    }
                }

                add_local_deny_rules($router, $hardware);

                # Join adjacent port ranges.  This must be called after local
                # optimization has been finished, because protocols will be
                # overlapping again after joining.
#                my $t6 = time();
                join_ranges($hardware);

#                $time{$rname}[3] += time() - $t6;
            }
        }
    }

#    my ($orules, $oid, $odel, $osec, $arules, $aid, $adel, $asec,
#        @otime, @atime);
#    my $f = '%-12s %7i %7i %7i %7i %.3f %.3f %.3f %.3f %.3f';
#    for my $aref (values %time) {
#        $aref->[4] = $aref->[0] + $aref->[1] + $aref->[2] + $aref->[3];
#        $atime[0] += $aref->[0];
#        $atime[1] += $aref->[1];
#        $atime[2] += $aref->[2];
#        $atime[3] += $aref->[3];
#        $atime[4] += $aref->[4];
#    }
#    for my $name (sort { $time{$a}[4] <=> $time{$b}[4] } keys %time) {
#        my $pre = $time{$name}[0];
#        my $while = $time{$name}[1];
#        my $secon = $time{$name}[2];
#        my $join = $time{$name}[3];
#        my $sum = $time{$name}[4];
#        my $rules = $r2rules{$name};
#        my $id = $r2id{$name} || 0;
#        my $del = $r2del{$name} || 0;
#        my $sec = $r2sec{$name} || 0;
#        $arules += $rules;
#        $aid += $id;
#        $adel += $del;
#        $asec += $sec;
#        if ($sum < 0.5) {
#            $otime[0] += $pre;
#            $otime[1] += $while;
#            $otime[2] += $secon;
#            $otime[3] += $join;
#            $otime[4] += $sum;
#            $orules += $rules;
#            $odel += $del;
#            $oid += $id;
#            $osec += $sec;
#        }
#        else {
#            $name =~ s/^router://;
#            debug(sprintf( $f, $name, $rules, $id, $del, $sec,
#                           $pre, $while, $secon, $join, $sum));
#        }
#    }
#    debug(sprintf( $f, 'other', $orules, $oid, $odel, $osec,
#                   $otime[0], $otime[1], $otime[2], $otime[3], $otime[4]));
#    debug(sprintf( $f, 'all', $arules, $aid, $adel, $asec,
#                   $atime[0], $atime[1], $atime[2], $atime[3], $atime[4]));

    return;
}

my $deny_any_rule = {
    action    => 'deny',
    src       => $network_00,
    dst       => $network_00,
    src_range => $prt_ip,
    prt       => $prt_ip
};

sub print_cisco_acl_add_deny {
    my ($router, $hardware, $no_nat_set, $model, $prefix) = @_;
    my $permit_any;

    my $rules = $hardware->{rules} ||= [];
    if (@$rules) {
        my ($action, $src, $dst, $prt) =
          @{ $rules->[-1] }{ 'action', 'src', 'dst', 'prt' };
        $permit_any =
             $action eq 'permit'
          && is_network($src)
          && $src->{mask} == 0
          && is_network($dst)
          && $dst->{mask} == 0
          && $prt eq $prt_ip;
    }

    # Add permit or deny rule at end of ACL
    # unless the previous rule is 'permit ip any any'.
    if (!$permit_any) {
        push(
            @{ $hardware->{rules} },
            $hardware->{no_in_acl} ? $permit_any_rule : $deny_any_rule
        );
        $permit_any = $hardware->{no_in_acl};
    }

    if ($router->{model}->{need_protect}) {

        # Routers connected by crosslink networks are handled like one
        # large router. Protect the collected interfaces of the whole
        # cluster at each entry.
        my $interfaces = $router->{crosslink_interfaces}
          || $router->{interfaces};
        $router->{crosslink_intf_hash} ||=
          { map { $_ => $_ } @{ $router->{interfaces} } };
        my $intf_hash = $router->{crosslink_intf_hash};

        # Add deny rules to protect own interfaces.
        # If a rule permits traffic to a directly connected network
        # behind the device, this would accidently permit traffic
        # to an interface of this device as well.

        # Deny rule is needless if there is a rule which permits any
        # traffic to the interface or
        # to one interface of a redundancy group.
        # The permit rule can be deleted if there is a permit any any rule.
        my %no_protect;
        my %seen;
        my $changed;
        for my $rule (@{ $hardware->{intf_rules} }) {
            next if $rule->{action} eq 'deny';
            my $src = $rule->{src};
            next if not is_network($src);
            next if $src->{mask} != 0;
            next if $rule->{prt} ne $prt_ip;
            my $dst = $rule->{dst};
            $no_protect{$dst} = 1 if $intf_hash->{$dst};
            $seen{ $dst->{redundancy_interfaces} }++
              if $dst->{redundancy_interfaces};

            if ($permit_any) {
                $rule    = undef;
                $changed = 1;
            }
        }
        if ($changed) {
            $hardware->{intf_rules} =
              [ grep { defined $_ } @{ $hardware->{intf_rules} } ];
        }

        # Deny rule is needless if there is no such permit rule.
        # Try to optimize this case.
        my %need_protect;
        my $protect_all;
      RULE:
        for my $rule (@{ $hardware->{rules} }) {
            next if $rule->{action} eq 'deny';
            my $dst = $rule->{dst};

            # We only need to check networks:
            # - subnet/host and interface already have been checked to
            #   have disjoint ip addresses to interfaces of current router.
            next if not is_network($dst);
            if ($dst->{mask} == 0) {
                $protect_all = 1;

#               debug("Protect all $router->{name}:$hardware->{name}");
                last RULE;
            }

            # Find interfaces of network or subnets of network,
            # which are directly attached to current router.
            for my $net ($dst,
                ($dst->{own_subnets}) ? @{ $dst->{own_subnets} } : ())
            {
                for my $intf (grep { $intf_hash->{$_} } @{ $net->{interfaces} })
                {
                    $need_protect{$intf} = $intf;

#                   debug("Need protect $intf->{name} at $hardware->{name}");
                }
            }
        }

        for my $interface (@$interfaces) {
            if (
                $no_protect{$interface}
                or not $protect_all
                and not $need_protect{$interface}

                # Interface with 'no_in_acl' gets 'permit any any' added
                # and hence needs deny rules.
                and not $hardware->{no_in_acl}
              )
            {
                next;
            }

            # Ignore 'unnumbered' interfaces.
            if ($interface->{ip} =~
                /^(?:unnumbered|negotiated|tunnel|bridged)$/)
            {
                next;
            }
            internal_err("Managed router has short $interface->{name}")
              if $interface->{ip} eq 'short';

            # IP of other interface may be unknown if dynamic NAT is used.
            if ($interface->{hardware} ne $hardware) {
                my $nat_network =
                  get_nat_network($interface->{network}, $no_nat_set);
                next if $nat_network->{dynamic};
            }
            if (    $interface->{redundancy_interfaces}
                and $seen{ $interface->{redundancy_interfaces} }++)
            {
                next;
            }

            # Protect own interfaces.
            push @{ $hardware->{intf_rules} },
              {
                action    => 'deny',
                src       => $network_00,
                dst       => $interface,
                src_range => $prt_ip,
                prt       => $prt_ip
              };
        }
        if ($hardware->{crosslink}) {
            $hardware->{intf_rules} = [];
        }
    }
    else {
      $hardware->{intf_rules} = [];
    }  

    # Concatenate Interface rules and ordinary rules.
    my $intf_rules = $hardware->{intf_rules};
    my $all_rules = $hardware->{rules};
    if (@$intf_rules) {
        $all_rules = [ @$intf_rules, @$rules ];
    }
    cisco_acl_line($router, $all_rules, $no_nat_set, $prefix);
    return;
}

# Parameter: Interface
# Analyzes dst of all rules collected at this interface.
# Result:
# Array reference to list of all networks which are allowed
# to pass this interface.
sub get_split_tunnel_nets {
    my ($interface) = @_;

    my %split_tunnel_nets;
    for my $rule (@{ $interface->{rules} }, @{ $interface->{intf_rules} }) {
        next if not $rule->{action} eq 'permit';
        my $dst = $rule->{dst};
        my $dst_network = is_network($dst) ? $dst : $dst->{network};

        # Dont add 'any' (resulting from global:permit)
        # to split_tunnel networks.
        next if $dst_network->{mask} == 0;
        $split_tunnel_nets{$dst_network} = $dst_network;
    }
    return [ sort { $a->{ip} <=> $b->{ip} || $a->{mask} <=> $b->{mask} }
          values %split_tunnel_nets ];
}

# Valid group-policy attributes.
# Hash describes usage:
# - need_value: value of attribute must have prefix 'value'
# - also_user: attribute is also applicable to 'username'
# - internal: internally generated, not allowed from config
# - tg_general: attribute is only applicable to 'tunnel-group general-attributes'
my %asa_vpn_attributes = (

    # group-policy attributes
    banner                    => { need_value => 1 },
    'dns-server'              => { need_value => 1 },
    'default-domain'          => { need_value => 1 },
    'split-dns'               => { need_value => 1 },
    'wins-server'             => { need_value => 1 },
    'vpn-access-hours'        => { also_user  => 1 },
    'vpn-idle-timeout'        => { also_user  => 1 },
    'vpn-session-timeout'     => { also_user  => 1 },
    'vpn-simultaneous-logins' => { also_user  => 1 },
    vlan                      => {},
    'address-pools'               => { need_value => 1, internal => 1 },
    'split-tunnel-network-list'   => { need_value => 1, internal => 1 },
    'split-tunnel-policy'         => { internal   => 1 },
    'vpn-filter'                  => { need_value => 1, internal => 1 },
    'authentication-server-group' => { tg_general => 1 },
    'authorization-server-group'  => { tg_general => 1 },
    'authorization-required'      => { tg_general => 1 },
    'username-from-certificate'   => { tg_general => 1 },
);

sub print_asavpn  {
    my ($router)         = @_;
    my $model            = $router->{model};
    my $no_nat_set       = $router->{hardware}->[0]->{no_nat_set};

    my $global_group_name = 'global';
    print <<"EOF";
group-policy $global_group_name internal
group-policy $global_group_name attributes
 pfs enable

EOF

    # Define tunnel group used for single VPN users.
    my $default_tunnel_group = 'VPN-single';
    my $trust_point = delete $router->{radius_attributes}->{'trust-point'}
      or err_msg
      "Missing 'trust-point' in radius_attributes of $router->{name}";

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

    if ($model->{v8_4}) {
        print <<"EOF";
 ikev1 trust-point $trust_point
 ikev1 user-authentication none
tunnel-group $default_tunnel_group webvpn-attributes
 authentication certificate
EOF
    }
    else {
        print <<"EOF";
 trust-point $trust_point
 isakmp ikev1-user-authentication none
EOF
    }
    print <<"EOF";
tunnel-group-map default-group $default_tunnel_group

EOF

    my $print_group_policy = sub {
        my ($name, $attributes) = @_;
        print "group-policy $name internal\n";
        print "group-policy $name attributes\n";
        for my $key (sort keys %$attributes) {
            my $value = $attributes->{$key};
            my $spec  = $asa_vpn_attributes{$key};
            $spec and not $spec->{tg_general}
              or err_msg("unknown radius_attribute '$key' for $router->{name}");
            my $out = $key;
            if (defined($value)) {
                $out .= ' value' if $spec->{need_value};
                $out .= " $value";
            }
            print " $out\n";
        }
    };

    my %cert_group_map;
    my %single_cert_map;
    my $user_counter = 0;
    for my $interface (@{ $router->{interfaces} }) {
        next if not $interface->{ip} eq 'tunnel';
        my %split_t_cache;

        if (my $hash = $interface->{id_rules}) {
            for my $id (sort keys %$hash) {
                my $id_intf = $hash->{$id};
                my $src     = $id_intf->{src};
                $user_counter++;
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
                        $acl_name = "split-tunnel-$user_counter";
                        if (@$split_tunnel_nets) {
                            for my $network (@$split_tunnel_nets) {
                                my $line =
                                  "access-list $acl_name standard permit ";
                                $line .=
                                  cisco_acl_addr(address($network, 
                                                         $no_nat_set), 
                                                 $model);
                                print "$line\n";
                            }
                        }
                        else {
                            print "access-list $acl_name standard deny any\n";
                        }
                        $split_t_cache{@$split_tunnel_nets}->{$acl_name} =
                          $split_tunnel_nets;
                    }
                    $attributes->{'split-tunnel-network-list'} = $acl_name;
                }
                else {
                    err_msg "Unsupported value of 'split-tunnel-policy':",
                      " $split_tunnel_policy";
                }

                # Access list will be bound to cleartext interface.
                # Only check for valid source address at vpn-filter.
                $id_intf->{intf_rules} = [];
                $id_intf->{rules}      = [
                    {
                        action    => 'permit',
                        src       => $src,
                        dst       => $network_00,
                        src_range => $prt_ip,
                        prt       => $prt_ip,
                    }
                ];
                find_object_groups($router, $id_intf);

                # Define filter ACL to be used in username or group-policy.
                my $filter_name = "vpn-filter-$user_counter";
                my $prefix      = "access-list $filter_name extended";

# Why was NAT disabled?
#                $nat_map = undef;
                print_cisco_acl_add_deny $router, $id_intf, $no_nat_set, $model,
                  $prefix;

                my $ip      = print_ip $src->{ip};
                my $network = $src->{network};
                if ($src->{mask} == 0xffffffff) {

                    # For anyconnect clients.
                    if ($model->{v8_4}) {
                        my ($name, $domain) = ($id =~ /^(.*?)(\@.*)$/);
                        $single_cert_map{$domain} = 1;
                    }

                    my $mask = print_ip $network->{mask};
                    my $group_policy_name;
                    if (%$attributes) {
                        $group_policy_name = "VPN-group-$user_counter";
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
                    $pool_name = "pool-$user_counter";
                    my $mask = print_ip $src->{mask};
                    my $max =
                      print_ip($src->{ip} | complement_32bit $src->{mask});
                    my $map_name = "ca-map-$user_counter";
                    print "crypto ca certificate map $map_name 10\n";
                    print " subject-name attr ea co $id\n";
                    print "ip local pool $pool_name $ip-$max mask $mask\n";
                    $attributes->{'vpn-filter'}    = $filter_name;
                    $attributes->{'address-pools'} = $pool_name;
                    my $group_policy_name = "VPN-group-$user_counter";
                    my @tunnel_gen_att =
                      ("default-group-policy $group_policy_name");

                    # Select attributes for tunnel-group general-attributes.
                    for my $key (sort keys %$attributes) {
                        if ($asa_vpn_attributes{$key}->{tg_general}) {
                            my $value = delete $attributes->{$key};
                            my $out = defined($value) ? "$key $value" : $key;
                            push(@tunnel_gen_att, $out);
                        }
                    }

                    my $trustpoint2 = delete $attributes->{'trust-point'}
                      || $trust_point;
                    my @tunnel_ipsec_att =
                      $model->{v8_4}
                      ? (
                        "ikev1 trust-point $trustpoint2",
                        'ikev1 user-authentication none'
                      )
                      : (
                        "trust-point $trustpoint2",
                        'isakmp ikev1-user-authentication none'
                      );

                    $print_group_policy->($group_policy_name, $attributes);

                    my $tunnel_group_name = "VPN-tunnel-$user_counter";
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
                    if ($model->{v8_4}) {
                        print <<"EOF";
tunnel-group $tunnel_group_name webvpn-attributes
 authentication certificate
EOF
                        $cert_group_map{$map_name} = $tunnel_group_name;
                    }

                    print <<"EOF";
tunnel-group-map ca-map-$user_counter 10 $tunnel_group_name

EOF
                }
            }
        }

        # A VPN network.
        else {
            $user_counter++;

            # Access list will be bound to cleartext interface.
            # Only check for correct source address at vpn-filter.
            $interface->{intf_rules} = [];
            $interface->{rules}      = [
                map {
                    {
                        action    => 'permit',
                        src       => $_,
                        dst       => $network_00,
                        src_range => $prt_ip,
                        prt       => $prt_ip,
                    }
                  } @{ $interface->{peer_networks} }
            ];
            find_object_groups($router, $interface);

            # Define filter ACL to be used in username or group-policy.
            my $filter_name = "vpn-filter-$user_counter";
            my $prefix      = "access-list $filter_name extended";

            print_cisco_acl_add_deny $router, $interface, $no_nat_set, $model,
              $prefix;

            my $id = $interface->{peers}->[0]->{id}
              or internal_err("Missing ID at $interface->{peers}->[0]->{name}");
            my $attributes = $router->{radius_attributes};

            my $group_policy_name;
            if (keys %$attributes) {
                $group_policy_name = "VPN-router-$user_counter";
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

    # Generate certificate-group-map for anyconnect/ikev2 clients.
    if (keys %cert_group_map or keys %single_cert_map) {
        for my $id (sort keys %single_cert_map) {
            $user_counter++;
            my $map_name = "ca-map-$user_counter";
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
    return;
}

sub iptables_acl_line {
    my ($rule, $no_nat_set, $prefix) = @_;
    my ($action, $src, $dst, $src_range, $prt) =
      @{$rule}{ 'action', 'src', 'dst', 'src_range', 'prt' };
    my $spair = address($src, $no_nat_set);
    my $dpair = address($dst, $no_nat_set);
    my $action_code =
        is_chain($action) ? $action->{name}
      : $action eq 'permit' ? 'ACCEPT'
      :                       'droplog';
    my $jump = $rule->{goto} ? '-g' : '-j';
    my $result = "$prefix $jump $action_code";
    if ($spair->[1] != 0) {
        $result .= ' -s ' . prefix_code($spair);
    }
    if ($dpair->[1] != 0) {
        $result .= ' -d ' . prefix_code($dpair);
    }
    if ($prt ne $prt_ip) {
        $result .= ' ' . iptables_prt_code($src_range, $prt);
    }
    print "$result\n";
    return;
}

sub print_iptables_acls {
    my ($router)     = @_;
    my $model        = $router->{model};
    my $comment_char = $model->{comment_char};

    # Pre-processing for all interfaces.
    print "#!/sbin/iptables-restore <<EOF\n";
    print "*filter\n";
    print ":INPUT DROP\n";
    print ":FORWARD DROP\n";
    print ":OUTPUT ACCEPT\n";
    print "-A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
    print "-A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
    print "-A INPUT -j ACCEPT -i lo\n";
    print_chains $router;

    for my $hardware (@{ $router->{hardware} }) {

        # Ignore if all logical interfaces are loopback interfaces.
        next if $hardware->{loopback};

        my $in_hw      = $hardware->{name};
        my $no_nat_set = $hardware->{no_nat_set};
        if ($config{comment_acls}) {

            # Name of first logical interface
            print "$comment_char $hardware->{interfaces}->[0]->{name}\n";
        }

        # Print chain and declaration for interface rules.
        # Add call to chain in INPUT chain.
        my $intf_acl_name = "${in_hw}_self";
        print ":$intf_acl_name -\n";
        print "-A INPUT -j $intf_acl_name -i $in_hw\n";
        my $intf_prefix = "-A $intf_acl_name";
        for my $rule (@{ $hardware->{intf_rules} }) {
            iptables_acl_line($rule, $no_nat_set, $intf_prefix);
        }

        # Print chain and declaration for forward rules.
        # Add call to chain in FORRWARD chain.
        # One chain for each pair of in_intf / out_intf.
        my $rules_hash = $hardware->{io_rules};
        for my $out_hw (sort keys %$rules_hash) {
            my $acl_name = "${in_hw}_$out_hw";
            print ":$acl_name -\n";
            print "-A FORWARD -j $acl_name -i $in_hw -o $out_hw\n";
            my $prefix     = "-A $acl_name";
            my $rules_aref = $rules_hash->{$out_hw};
            for my $rule (@$rules_aref) {
                iptables_acl_line($rule, $no_nat_set, $prefix, $model);
            }
        }

        # Empty line after each chain.
        print "\n";
    }
    print "-A INPUT -j droplog\n";
    print "-A FORWARD -j droplog\n";
    print "COMMIT\n";
    print "EOF\n";
    return;
}

sub print_cisco_acls {
    my ($router)     = @_;
    my $model        = $router->{model};
    my $filter       = $model->{filter};
    my $comment_char = $model->{comment_char};

    for my $hardware (@{ $router->{hardware} }) {

        # Ignore if all logical interfaces are loopback interfaces.
        next if $hardware->{loopback};

        # Ignore layer3 interface of ASA.
        next if $hardware->{name} eq 'device' && $model->{class} eq 'ASA';

        # Force valid array reference to prevent error
        # when checking for non empty array.
        $hardware->{rules} ||= [];

        if ($model->{can_objectgroup}) {
            if (not $router->{no_group_code}) {
                find_object_groups($router, $hardware);
            }
        }

        my $no_nat_set = $hardware->{no_nat_set};

        # Generate code for incoming and possibly for outgoing ACL.
        for my $suffix ('in', 'out') {
            next if $suffix eq 'out' and not $hardware->{need_out_acl};

            my $acl_name = "$hardware->{name}_$suffix";
            my $prefix;
            if ($config{comment_acls}) {

                # Name of first logical interface
                print "$comment_char $hardware->{interfaces}->[0]->{name}\n";
            }
            if ($filter eq 'IOS') {
                $prefix = '';
                print "ip access-list extended $acl_name\n";
            }
            elsif ($filter eq 'NX-OS') {
                $prefix = '';
                print "ip access-list $acl_name\n";
            }
            elsif ($filter eq 'PIX') {
                $prefix      = "access-list $acl_name";
                $prefix .= ' extended' if $model->{class} eq 'ASA';
            }

            # Incoming ACL and protect own interfaces.
            if ($suffix eq 'in') {
                print_cisco_acl_add_deny(
                    $router, $hardware, $no_nat_set, $model, $prefix
                );
            }

            # Outgoing ACL
            else {
                my $out_rules = $hardware->{out_rules} ||= [];

                # Add deny rule at end of ACL if not 'permit ip any any'
                if (!(@$out_rules && $out_rules->[-1] eq $permit_any_rule)) {
                    push(@$out_rules, $deny_any_rule);
                }
                cisco_acl_line($router, $out_rules, $no_nat_set, $prefix);
            }

            # Post-processing for hardware interface
            if ($filter eq 'IOS' || $filter eq 'NX-OS') {
                push(
                    @{ $hardware->{subcmd} },
                    "ip access-group $acl_name $suffix"
                );
            }
            elsif ($filter eq 'PIX') {
                print "access-group $acl_name $suffix interface",
                  " $hardware->{name}\n";
            }

            # Empty line after each ACL.
            print "\n";
        }
    }
    return;
}

sub print_acls {
    my ($router)     = @_;
    my $model        = $router->{model};
    my $filter       = $model->{filter};
    my $comment_char = $model->{comment_char};
    print "$comment_char [ ACL ]\n";

    if ($filter eq 'iptables') {
        print_iptables_acls($router);
    }
    else {
        print_cisco_acls($router);
    }
    return;
}

sub gen_crypto_rules {
    my ($local, $remote) = @_;
    my @crypto_rules;
    for my $src (@$local) {
        for my $dst (@$remote) {
            push(
                @crypto_rules,
                {
                    action    => 'permit',
                    src       => $src,
                    dst       => $dst,
                    src_range => $prt_ip,
                    prt       => $prt_ip
                }
            );
        }
    }
    return \@crypto_rules;
}

sub print_ezvpn {
    my ($router)     = @_;
    my $model        = $router->{model};
    my @interfaces   = @{ $router->{interfaces} };
    my @tunnel_intf = grep { $_->{ip} eq 'tunnel' } @interfaces;
    @tunnel_intf == 1 or internal_err();
    my ($tunnel_intf) = @tunnel_intf;
    my $wan_intf = $tunnel_intf->{real_interface};
    my $wan_hw = $wan_intf->{hardware};
    my $no_nat_set = $wan_hw->{no_nat_set};
    my @lan_intf = grep { $_ ne $wan_intf and $_ ne $tunnel_intf } @interfaces;

    # Ezvpn configuration.
    my $ezvpn_name               = 'vpn';
    my $crypto_acl_name          = 'ACL-Split-Tunnel';
    my $crypto_filter_name       = 'ACL-crypto-filter';
    my $virtual_interface_number = 1;
    print "crypto ipsec client ezvpn $ezvpn_name\n";
    print " connect auto\n";
    print " mode network-extension\n";

    for my $peer (@{ $tunnel_intf->{peers} }) {

        # Unnumbered, negotiated and short interfaces have been
        # rejected already.
        my $peer_ip = prefix_code(address($peer->{real_interface}, 
                                          $no_nat_set));
        print " peer $peer_ip\n";
    }

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
    $tunnel_intf->{crypto}->{detailed_crypto_acl}
      and internal_err("Unexpected attribute 'detailed_crypto_acl'",
        " at $router->{name}");
    my $crypto_rules =
      gen_crypto_rules($tunnel_intf->{peers}->[0]->{peer_networks},
        [$network_00]);
    print "ip access-list extended $crypto_acl_name\n";
    my $prefix     = '';
    cisco_acl_line($router, $crypto_rules, $no_nat_set, $prefix);

    # Crypto filter ACL.
    $prefix = '';
    $tunnel_intf->{intf_rules} ||= [];
    $tunnel_intf->{rules} ||= [];
    print "ip access-list extended $crypto_filter_name\n";
    print_cisco_acl_add_deny($router, $tunnel_intf, $no_nat_set, $model,
                             $prefix);

    # Bind crypto filter ACL to virtual template.
    print "interface Virtual-Template$virtual_interface_number type tunnel\n";
    $crypto_filter_name
      and print " ip access-group $crypto_filter_name in\n";
    return;
}

sub print_crypto {
    my ($router) = @_;
    my $model = $router->{model};
    my $crypto_type = $model->{crypto} || '';

    # List of ipsec definitions used at current router.
    # Sort entries by name to get deterministic output.
    my @ipsec = sort by_name unique(
        map { $_->{crypto}->{type} }
        grep { $_->{ip} eq 'tunnel' } @{ $router->{interfaces} }
    );

    # Return if no crypto is used at current router.
    return unless @ipsec;

    # List of isakmp definitions used at current router.
    # Sort entries by name to get deterministic output.
    my @isakmp = sort by_name unique(map { $_->{key_exchange} } @ipsec);

    my $comment_char = $model->{comment_char};
    print "$comment_char [ Crypto ]\n";

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

    $crypto_type =~ /^(:?IOS|ASA)$/
      or internal_err("Unexptected crypto type $crypto_type");

    my $isakmp_count = 0;
    for my $isakmp (@isakmp) {
        $isakmp_count++;
        print "crypto isakmp policy $isakmp_count\n";

        my $authentication = $isakmp->{authentication};
        $authentication =~ s/preshare/pre-share/;
        $authentication =~ s/rsasig/rsa-sig/;

        # Don't print default value for backend IOS.
        if (not($authentication eq 'rsa-sig' and $crypto_type eq 'IOS')) {
            print " authentication $authentication\n";
        }

        my $encryption = $isakmp->{encryption};
        if ($encryption =~ /^aes(\d+)$/) {
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
        if (not($lifetime == 86400 and $crypto_type eq 'IOS')) {
            print " lifetime $lifetime\n";
        }
    }

    # Handle IPSEC definition.
    my $transform_count = 0;
    my %ipsec2trans_name;
    for my $ipsec (@ipsec) {
        $transform_count++;
        my $transform = '';
        if (my $ah = $ipsec->{ah}) {
            if ($ah =~ /^(md5|sha)_hmac$/) {
                $transform .= "ah-$1-hmac ";
            }
            else {
                internal_err(
                    "Unsupported IPSec AH method for $crypto_type: $ah");
            }
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
        else {
            internal_err("Unsupported IPSec ESP method for $crypto_type: $esp");
        }
        if (my $esp_ah = $ipsec->{esp_authentication}) {
            if ($esp_ah =~ /^(md5|sha)_hmac$/) {
                $transform .= "esp-$1-hmac";
            }
            else {
                internal_err("Unsupported IPSec ESP auth. method for",
                             " $crypto_type: $esp_ah");
            }
        }

        # Syntax is identical for IOS and ASA.
        my $transform_name = "Trans$transform_count";
        $ipsec2trans_name{$ipsec} = $transform_name;
        print "crypto ipsec transform-set $transform_name $transform\n";
    }

    # Collect tunnel interfaces attached to one hardware interface.
    my %hardware2crypto;
    for my $interface (@{ $router->{interfaces} }) {
        if ($interface->{ip} eq 'tunnel') {
            push @{ $hardware2crypto{ $interface->{hardware} } }, $interface;
        }
    }

    for my $hardware (@{ $router->{hardware} }) {
        next if not $hardware2crypto{$hardware};
        my $name = $hardware->{name};

        # Name of crypto map.
        my $map_name = "crypto-$name";

        # Sequence number for parts of crypto map with different peers.
        my $seq_num = 0;

        # Crypto ACLs and peer IP must obey NAT.
        my $no_nat_set = $hardware->{no_nat_set};

        # Sort crypto maps by peer IP to get deterministic output.
        my @tunnels = sort {
            $a->{peers}->[0]->{real_interface}->{ip} <=> $b->{peers}->[0]
              ->{real_interface}->{ip}
        } @{ $hardware2crypto{$hardware} };

        # Build crypto map for each tunnel interface.
        for my $interface (@tunnels) {
            $seq_num++;

            my $crypto = $interface->{crypto};
            my $ipsec  = $crypto->{type};
            my $isakmp = $ipsec->{key_exchange};

            # Print crypto ACL.
            # It controls which traffic needs to be encrypted.
            my $crypto_acl_name = "crypto-$name-$seq_num";
            my $prefix;
            if ($crypto_type eq 'IOS') {
                $prefix = '';
                print "ip access-list extended $crypto_acl_name\n";
            }
            elsif ($crypto_type eq 'ASA') {
                $prefix = "access-list $crypto_acl_name extended";
            }
            else {
                internal_err();
            }

            # Print crypto ACL,
            # - either generic from remote network to any or
            # - detailed to all networks which are used in rules.
            my $is_hub   = $interface->{is_hub};
            my $hub      = $is_hub ? $interface : $interface->{peers}->[0];
            my $detailed = $crypto->{detailed_crypto_acl};
            my $local = $detailed ? get_split_tunnel_nets($hub) : [$network_00];
            my $remote = $hub->{peer_networks};
            $is_hub or ($local, $remote) = ($remote, $local);
            my $crypto_rules = gen_crypto_rules($local, $remote);
            cisco_acl_line($router, $crypto_rules, $no_nat_set, $prefix);

            # Print filter ACL. It controls which traffic is allowed to leave
            # from crypto tunnel. This may be needed, if we don't fully trust
            # our peer.
            my $crypto_filter_name;
            if (!$router->{no_crypto_filter}) {
                $crypto_filter_name = "crypto-filter-$name-$seq_num";
                if ($crypto_type eq 'IOS') {
                    $prefix = '';
                    print "ip access-list extended $crypto_filter_name\n";
                }
                else {
                    internal_err();
                }
                print_cisco_acl_add_deny($router, $interface, $no_nat_set,
                                         $model, $prefix);
            }

            # Define crypto map.
            if ($crypto_type eq 'IOS') {
                $prefix = '';
                print "crypto map $map_name $seq_num ipsec-isakmp\n";
            }
            elsif ($crypto_type eq 'ASA') {
                $prefix = "crypto map $map_name $seq_num";
            }

            # Bind crypto ACL to crypto map.
            print "$prefix match address $crypto_acl_name\n";

            # Bind crypto filter ACL to crypto map.
            if ($crypto_filter_name) {
                print "$prefix set ip access-group $crypto_filter_name in\n";
            }

            # Set crypto peers.
            # Unnumbered, negotiated and short interfaces have been
            # rejected already.
            if ($crypto_type eq 'IOS') {
                for my $peer (@{ $interface->{peers} }) {
                    my $peer_ip = prefix_code(address($peer->{real_interface}, 
                                                      $no_nat_set));
                    print "$prefix set peer $peer_ip\n";
                }
            }
            elsif ($crypto_type eq 'ASA') {
                print "$prefix set peer ",
                  join(' ',
                    map { prefix_code(address($_->{real_interface}, 
                                              $no_nat_set)) }
                      @{ $interface->{peers} }),
                  "\n";
            }

            my $transform_name = $ipsec2trans_name{$ipsec};
            my $extra_ikev1 =
              ($crypto_type eq 'ASA' && $model->{v8_4}) ? 'ikev1 ' : '';
            print "$prefix set ${extra_ikev1}transform-set $transform_name\n";

            if (my $pfs_group = $ipsec->{pfs_group}) {
                if ($pfs_group =~ /^(1|2)$/) {
                    $pfs_group = "group$1";
                }
                else {
                    err_msg
                      "Unsupported pfs group for $crypto_type: $pfs_group";
                }
                print "$prefix set pfs $pfs_group\n";
            }

            if (my $lifetime = $ipsec->{lifetime}) {

                # Don't print default value for backend IOS.
                if (not($lifetime == 3600 and $crypto_type eq 'IOS')) {
                    print "$prefix set security-association"
                      . " lifetime seconds $lifetime\n";
                }
            }

            if ($crypto_type eq 'ASA') {
                my $authentication = $isakmp->{authentication};
                for my $peer (@{ $interface->{peers} }) {
                    my $peer_ip = prefix_code(address($peer->{real_interface},
                                                      $no_nat_set));
                    print "tunnel-group $peer_ip type ipsec-l2l\n";
                    print "tunnel-group $peer_ip ipsec-attributes\n";
                    if ($authentication eq 'preshare') {
                        print " ${extra_ikev1}pre-shared-key *****\n";
                        print " peer-id-validate nocheck\n";
                    }
                    elsif ($authentication eq 'rsasig') {
                        my $trust_point = $isakmp->{trust_point}
                          or err_msg "Missing 'trust_point' in",
                          " isakmp attributes for $router->{name}";
                        print " chain\n";
                        print " ${extra_ikev1}trust-point $trust_point\n";
                        if ($model->{v8_4}) {
                            print " ikev1 user-authentication none\n";
                        }
                        else {
                            print " isakmp ikev1-user-authentication none\n";
                        }
                    }
                }
            }
        }
        if ($crypto_type eq 'IOS') {
            push(@{ $hardware->{subcmd} }, "crypto map $map_name");
        }
        elsif ($crypto_type eq 'ASA') {
            print "crypto map $map_name interface $name\n";
            print "crypto isakmp enable $name\n";
        }
    }
    return;
}

sub print_interface {
    my ($router) = @_;
    my $model = $router->{model};
    my $class = $model->{class};
    my $stateful = not $model->{stateless};
    for my $hardware (@{ $router->{hardware} }) {
        my @subcmd;
        my $secondary;
        my $addr_cmd;
        for my $intf (@{ $hardware->{interfaces} }) {
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
            elsif ($model->{use_prefix}) {
                my $addr = print_ip($ip);
                my $mask = mask2prefix($intf->{network}->{mask});
                $addr_cmd = "ip address $addr/$mask";
                $addr_cmd .= ' secondary' if $secondary;
            }
            else {
                my $addr = print_ip($ip);
                my $mask = print_ip($intf->{network}->{mask});
                $addr_cmd = "ip address $addr $mask";
                $addr_cmd .= ' secondary' if $secondary;
            }
            push @subcmd, $addr_cmd;
            $secondary = 1;
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
        if ($stateful && !$hardware->{loopback}) {
            push @subcmd, "ip inspect X in";
        }
        if (my $other = $hardware->{subcmd}) {
            push @subcmd, @$other;
        }
        my $name = $hardware->{name};

        # Split name for NX-OS: "ethernet3/4" -> "ethernet 3/4"
#        $name =~ s/(\d+)/ $1/ if ($class eq 'NX-OS');

        print "interface $name\n";
        for my $cmd (@subcmd) {
            print " $cmd\n";
        }
    }
    print "\n";
    return;
}

# Make output directory available.
sub check_output_dir {
    my ($dir) = @_;
    unless (-e $dir) {
        mkdir $dir
          or fatal_err("Can't create output directory $dir: $!");
    }
    -d $dir or fatal_err("$dir isn't a directory");
    return;
}

# Print generated code for each managed router.
sub print_code {
    my ($dir) = @_;

    # Untaint $dir. This is necessary if running setuid.
    # We can trust value of $dir because it is set by setuid wrapper.
    if ($dir) {
        ($dir) = ($dir =~ /(.*)/);
        check_output_dir($dir);
    }

    progress('Printing code');
    my %seen;
    for my $router (@managed_routers) {
        next if $seen{$router};
        my $device_name = $router->{device_name};
        if ($dir) {
            my $file = $device_name;

            # Untaint $file. It has already been checked for word characters,
            # but check again for the case of a weird locale setting.
            $file =~ /^(.*)/;
            $file = "$dir/$1";
            open(STDOUT, '>', $file)
              or fatal_err("Can't open $file for writing: $!");
        }

        my $vrf_members = $router->{vrf_members};
        for my $vrouter ($vrf_members ? @$vrf_members : ($router)) {
            $seen{$vrouter} = 1;
            my $model        = $router->{model};
            my $comment_char = $model->{comment_char};
            my $name         = $vrouter->{name};

            print "$comment_char Generated by $program, version $version\n\n";
            print "$comment_char [ BEGIN $name ]\n";
            print "$comment_char [ Model = $model->{class} ]\n";
            if ($policy_distribution_point) {
                if (my $ips = $vrouter->{admin_ip}) {
                    printf("$comment_char [ IP = %s ]\n", join(',', @$ips));
                }
            }

            print_routes $vrouter;
            print_crypto $vrouter;
            print_acls $vrouter;
            print_interface $vrouter if $model->{print_interface};
            print_nat $vrouter;
            print "$comment_char [ END $name ]\n\n";
        }
        if ($dir) {
            close STDOUT or fatal_err("Can't close $dir/$device_name: $!");
        }
    }
    return;
}

sub copy_raw {
    my ($in_path, $out_dir) = @_;
    return if ! (defined $in_path && -d $in_path);
    return if ! defined $out_dir;

    # Untaint $in_path, $out_dir. This is necessary if running setuid.
    # Trusted because set by setuid wrapper.
    ($in_path) = ($in_path =~ /(.*)/);
    ($out_dir) = ($out_dir =~ /(.*)/);
    check_output_dir($out_dir);

    my $raw_dir = "$in_path/raw";
    return if not -d $raw_dir;

    # Clean PATH if run in taint mode.
    ## no critic (RequireLocalizedPunctuationVars)
    $ENV{PATH} = '/usr/local/bin:/usr/bin:/bin';
    ## use critic

    my %routers = map { $_->{device_name} => 1 } @managed_routers;

    opendir(my $dh, $raw_dir) or fatal_err("Can't opendir $raw_dir: $!");
    while (my $file = Encode::decode($filename_encode, readdir $dh)) {
        next if $file eq '.' or $file eq '..';
        next if $file =~ m/$config{ignore_files}/o;

        # Untaint $file.
        my ($raw_file) = ($file =~ /^(.*)/);
        my $raw_path = "$raw_dir/$raw_file";
        if (not -f $raw_path) {
            warn_msg("Ignoring $raw_path");
            next;
        }
        if (not $routers{$file}) {
            if (my $conf = $config{check_raw}) {
                my $msg = "Found unused $raw_path";
                $conf eq 'warn' ? warn_msg($msg) : err_msg($msg);
            }
            next;
        }
        my $copy = "$out_dir/$raw_file.raw";
        system("cp -f $raw_path $copy") == 0
          or fatal_err("Can't copy $raw_path to $copy: $!");
    }
    return;
}

sub show_version {
    progress("$program, version $version");
    return;
}

sub show_finished {
    progress('Finished') if $config{time_stamps};
    return;
}

1;

#  LocalWords:  Netspoc Knutzen internet CVS IOS iproute iptables STDERR Perl
#  LocalWords:  netmask EOL ToDo IPSec unicast utf hk src dst ICMP IPs EIGRP
#  LocalWords:  OSPF VRRP HSRP Arnes loop's ISAKMP stateful ACLs negatable
#  LocalWords:  STDOUT
