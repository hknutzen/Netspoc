package Netspoc::Compiler::Pass1;

=head1 NAME

Netspoc - A Network Security Policy Compiler

=head1 COPYRIGHT AND DISCLAIMER

(c) 2016 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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
use JSON::XS;
use Netspoc::Compiler::GetArgs qw(get_args);
use Netspoc::Compiler::Common;
use open qw(:std :utf8);
use Encode;
my $filename_encode = 'UTF-8';

# VERSION: inserted by DZP::OurPkgVersion
my $program = 'Netspoc';
my $version = __PACKAGE__->VERSION || 'devel';

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
  %routers
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
  %global_type
  %service_rules
  %path_rules
  @pathrestrictions
  *input
  $current_file
  $error_counter
  init_global_vars
  abort_on_error
  syntax_err
  internal_err
  err_msg
  fatal_err
  unique
  equal
  aref_eq
  read_ip
  print_ip
  mask2prefix
  complement_32bit
  show_version
  split_typed_name
  skip_space_and_comment
  check
  skip
  read_typed_name
  read_union
  is_network
  is_router
  is_interface
  is_host
  is_subnet
  is_group
  is_protocolgroup
  is_autointerface
  get_intf
  read_netspoc
  read_file
  read_file_or_dir
  show_read_statistics
  order_protocols
  link_topology
  mark_disabled
  set_zone
  link_reroute_permit
  expand_protocols
  get_orig_prt
  expand_group
  expand_group_in_rule
  normalize_src_dst_list
  normalize_services
  group_path_rules
  expand_crypto
  check_unused_groups
  setpath
  find_subnets_in_zone
  find_subnets_in_nat_domain
  convert_hosts
  convert_hosts_in_rules
  propagate_owners
  find_dists_and_loops
  process_loops
  check_pathrestrictions
  optimize_pathrestrictions
  path_walk
  single_path_walk
  path_auto_interfaces
  check_supernet_rules
  optimize_and_warn_deleted
  distribute_nat_info
  get_nat_network
  gen_reverse_rules
  mark_secondary_rules
  rules_distribution
  check_output_dir
  address
  print_code
);


# Use non-local function exit for efficiency.
# Perl profiler doesn't work if this is active.
my $use_nonlocal_exit => 1;

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
    'ACE' => {
        routing           => 'IOS',
        filter            => 'ACE',
        stateless         => 0,
        stateless_self    => 0,
        stateless_icmp    => 1,
        can_objectgroup   => 1,
        inversed_acl_mask => 0,
        use_prefix        => 0,
        can_vrf           => 0,
        can_log_deny      => 0,
        log_modifiers     => {},
        has_vip           => 1,
        has_out_acl       => 1,
        need_protect      => 1,
        print_interface   => 1,
        comment_char      => '!',
    },
    PIX => {
        routing             => 'PIX',
        filter              => 'PIX',
        stateless_icmp      => 1,
        can_objectgroup     => 1,
        comment_char        => '!',
        need_identity_nat   => 1,
        no_filter_icmp_code => 1,
        need_acl            => 1,
    },

    # Like PIX, but without identity NAT.
    ASA => {
        routing       => 'PIX',
        filter        => 'PIX',
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
# Protocols get {up} relation in order_protocols.
my %routing_info;

# Definition of redundancy protocols.
# Protocols get {up} relation in order_protocols.
my %xxrp_info;

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
    return grep { !$seen{$_}++ } @_;
}

# Check passed arguments for duplicates.
# Return duplicate elements.
sub find_duplicates {
    my %dupl;
    $dupl{$_}++ for @_;
    return grep { $dupl{$_} > 1 } keys %dupl;
}

# Return the intersecting elements of two array references.
sub intersect {
    my ($aref1, $aref2) = @_;
    my %seen = map { $_ => 1 } @$aref1;
    return grep { $seen{$_} } @$aref2;
}

# Check if first list is subset of second list.
sub subset_of {
    my ($aref1, $aref2) = @_;
    my %seen = map { $_ => 1 } @$aref1;
    my $count = grep { $seen{$_} } @$aref2;
    return @$aref1 == $count;
}

# Return highest number among all arguments.
sub max {
    my $max = shift(@_);
    for my $el (@_) {
        $max = $el if $max < $el;
    }
    return $max;
}

# Delete an element from an array reference.
# Return true if element was found.
sub aref_delete {
    my ($aref, $elt) = @_;
    for (my $i = 0 ; $i < @$aref ; $i++) {
        if ($aref->[$i] eq $elt) {
            splice @$aref, $i, 1;

#debug("aref_delete: $elt->{name}");
            return 1;
        }
    }
    return;
}

# Substitute an element in an array reference.
# Return true if element was found.
sub aref_subst {
    my ($aref, $elt, $new) = @_;
    for (my $i = 0 ; $i < @$aref ; $i++) {
        if ($aref->[$i] eq $elt) {
            splice @$aref, $i, 1, $new;
            return 1;
        }
    }
    return;
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

# Print arguments as warning to STDERR..
sub warn_msg {
    print STDERR "Warning: ", @_, "\n";
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
    return;
}

# Print error message with current input file and line number.
sub error_atline {
    my (@args) = @_;
    print STDERR "Error: ", @args, at_line(), "\n";
    check_abort();
    return;
}

# Print error message.
sub err_msg {
    my (@args) = @_;
    print STDERR "Error: ", @args, "\n";
    check_abort();
    return;
}

# Print internal error message and aborts.
sub internal_err {
    my (@args) = @_;

    # Don't show inherited error.
    # Abort immediately, if other errors have already occured.
    abort_on_error();

    $error_counter++;
    my (undef, $file, $line) = caller;
    my $sub = (caller 1)[3];
    my $msg = "Internal error in $sub";
    $msg .= ": @args" if @args;
    $msg = "$msg\n at $file line $line\n";
    die $msg;
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

# Skip argument regex.
# Usable for non token characters.
# Returns matched string.
sub skip_regex {
    my ($expected) = @_;
    skip_space_and_comment;
    my $regex = $token2regex{$expected} ||= qr/\G($expected)/;
    $input =~ /$regex/gc or syntax_err("Expected '$expected'");
    return $1;
}

# Skip argument regex without skipping whitespace.
# Usable for non token characters.
# Returns matched string.
sub skip_direct {
    my ($expected) = @_;
    my $regex = $token2regex{$expected} ||= qr/\G($expected)/;
    $input =~ /$regex/gc or syntax_err("Expected '$expected'");
    return $1;
}

# Skip argument token.
# If it is not available an error is printed and the script terminates.
sub skip {
    my ($expected) = @_;
    my $token = read_token();;
    $token eq $expected or syntax_err("Expected '$expected'");
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

# Read an integer.
sub read_int {
    my $result = check_int();
    defined $result or syntax_err("Integer expected");
    return $result;
}

# Check and convert IP address to integer.
sub convert_ip {
    my ($token) = @_;
    $token =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)/ or 
        syntax_err("IP address expected");
    if ($1 > 255 or $2 > 255 or $3 > 255 or $4 > 255) {
        error_atline("Invalid IP address");
    }
    no warnings 'pack';
    return unpack 'N', pack 'C4', $1, $2, $3, $4;
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
    my $mask = prefix2mask($part2);
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

# Read IP range.
sub read_ip_range {
    skip '=';
    my $ip1 = convert_ip(skip_regex('[\d.]+'));
    skip_regex('-');
    my $ip2 = convert_ip(skip_regex('[\d.]+'));
    skip(';');
    return $ip1, $ip2;
}

# Generate an IP address as internal integer.
sub gen_ip {
    my ($byte1, $byte2, $byte3, $byte4) = @_;
    return unpack 'N', pack('C4', $byte1, $byte2, $byte3, $byte4);
}

# Convert IP address from internal integer representation to
# readable string.
## no critic (RequireArgUnpacking RequireFinalReturn)
sub print_ip {
    sprintf "%vd", pack 'N', $_[0];
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

# Read pattern for attribute "visible": "*" or "name*".
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
    return (check_typed_name($token) || syntax_err("Typed name expected"));
}

{

    # user@domain or @domain
    my $domain_regex   = qr/(?:[\w-]+\.)+[\w-]+/;
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
            syntax_err("Object type expected");
        my $interface = $type eq 'interface';
        my $ext;

        my $read_auto_all = sub {
            skip_direct('\[');
            my $selector = read_identifier;
            $selector =~ /^(auto|all)$/ or syntax_err("Expected [auto|all]");
            $ext = [ $selector, $ext ];
            skip ']';
        };

        if ($name) {
            if ($type eq 'host') {
                verify_hostname($name) or 
                    syntax_err("Name or ID-name expected");
            }
            elsif ($type eq 'network') {
                $name =~ m/^ $network_regex $/xo or
                    syntax_err("Name or bridged name expected");
            }
            elsif ($interface) {
                my ($router_name, $net_name) =
                    $name =~ m/^ ( [\w-]+ (?: \@ [\w-]+ )? ) [.] 
                                 ( $network_regex (?: [.] [\w-]+)? )? $/x or
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
            skip_direct('\[');
            if (($interface || $type eq 'host') && check('managed')) {
                $ext = 1;
                skip '&';
            }
            elsif ($type eq 'any' && check('ip')) {
                skip '=';
                $ext = read_ip_prefix_pair();
                skip '&';
            }
            $name = read_union(']');
            if ($interface) {
                skip_direct('[.]');
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
            syntax_err("Id expected ('user\@domain' or 'user')");
        }
    }

# host:xxx or host:id:user@domain or host:id:[@]domain
    sub verify_hostname {
        my ($token) = @_;
        $token =~ m/^$hostname_regex$/ or syntax_err('Hostname expected');
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
    my $factor = $timeunits{$unit} or syntax_err("Invalid time unit");
    return $int * $factor;
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
    return;
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
    return;
}

our %hosts;

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
            $value =~ /^(?:secondary|standard|full|primary|
                           local|local_secondary|routing_only)$/x
          )
        {
            $managed = $value;
        }
        else {
            error_atline(
                "Expected value:",
                " secondary|standard|full|primary",
                "|local|local_secondary|routing_only"
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
    if (!$model) {
        err_msg("Missing 'model' for managed $host->{name}");

        # Prevent further errors.
        $model = $host->{model} = { name => 'unknown' };
    }
    elsif (!$model->{can_managed_host}) {
        err_msg("Must not use model $model->{name} at managed $name");
    }
    if (!$hw_name) {
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
            $ip1 <= $ip2 or error_atline("Invalid IP range");
            add_attribute($host, range => [ $ip1, $ip2 ]);
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
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($host, owner => $owner);
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
                $host->{nat}->{$name2}
                  and error_atline("Duplicate NAT definition");
                $host->{nat}->{$name2} = $nat_ip;
            }
            else {
                syntax_err("Expected NAT definition");
            }
        }
        else {
            syntax_err("Unexpected token");
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
            # - look at print_pix_static,
            # - add consistency tests in convert_hosts.
            err_msg("No NAT supported for $name with 'range'");
        }
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
        my $token = read_token();
        if ($token eq '}') {
            last;
        }
        elsif ($token eq 'ip') {
            my ($ip, $mask) = read_assign(\&read_ip_prefix);
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

            # $nat_tag is used later to look up static translation
            # of hosts inside a dynamically translated network.
            $nat->{dynamic} = $nat_tag;
        }
        elsif ($token eq 'subnet_of') {
            my $pair = read_assign(\&read_typed_name);
            add_attribute($nat, subnet_of => $pair);
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

        # Provide an unusable address.
        # This prevents 'Use of uninitialized value' 
        # if code generation is started concurrently,
        # before all error conditions are checked.
        $nat->{ip} = 0;
        $nat->{mask} = 0xffffffff;
    }
    elsif ($nat->{identity}) {
        for my $key (keys %$nat) {
            next if grep { $key eq $_ } qw( name identity );
            error_atline("Identity NAT must not use attribute $key");
        }
        $nat->{dynamic} = $nat_tag;
    }
    else {
        defined($nat->{ip}) or error_atline('Missing IP address');
    }
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
            my $pair = read_assign(\&read_typed_name);
            add_attribute($network, subnet_of => $pair);
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
                if (is_host($host)) {
                    push @{ $network->{hosts} }, $host;
                    $host_name = (split_typed_name($host->{name}))[1];
                }

                # Managed host is stored as interface internally.
                elsif (is_interface($host)) {
                    push @{ $network->{interfaces} }, $host;
                    check_interface_ip($host, $network);

                    # For use in expand_group.
                    push @{ $network->{managed_hosts} }, $host;
                }
                else {
                    internal_err;
                }
                if (my $other = $hosts{$host_name}) {
                    my $where     = $current_file;
                    my $other_net = $other->{network};
                    if ($other_net ne $network) {
                        $where .= " $other_net->{file}";
                    }
                    err_msg("Duplicate definition of host:$host_name",
                            " in $where");
                }
                $hosts{$host_name} = $host;
            }
            elsif ($type eq 'nat') {
                verify_name($name2);
                my $nat_tag = $name2;
                my $nat = read_nat("nat:$nat_tag");
                ($network->{nat} && $network->{nat}->{$nat_tag})
                    and error_atline("Duplicate NAT definition");
                $nat->{name} .= "($name)";
                $network->{nat}->{$nat_tag} = $nat;
            }
            else {
                syntax_err("Expected host or nat definition");
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
        if (delete $network->{hosts}) {
            err_msg("Bridged $name must not have ",
                    "host definition (not implemented)");
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
            elsif ($host->{range}) {
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
            else {
                internal_err();
            }

            # Compatibility of host and network NAT will be checked later,
            # after inherited NAT definitions have been processed.
        }
        if (@{ $network->{hosts} } and $network->{crosslink}) {
            err_msg("Crosslink $name must not have host definitions");
        }
        if ($network->{nat}) {

            # Check NAT definitions.
            for my $nat (values %{ $network->{nat} }) {
                next if $nat->{dynamic};
                $nat->{mask} == $mask
                  or err_msg("Mask for non dynamic $nat->{name}",
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
my $global_active_pathrestriction = new(
    'Pathrestriction',
    name        => 'global_pathrestriction',
    active_path => 1
);

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

        # Needed for the implicitly defined network of 'loopback'.
        elsif ($token eq 'subnet_of') {
            my $pair = read_assign(\&read_typed_name);
            add_attribute($interface, subnet_of => $pair);
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
                syntax_err("Expected nat or secondary interface definition");
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
                    $id =~ /^\d+$/
                      or error_atline("Redundancy ID must be numeric");
                    $id < 256 or error_atline("Redundancy ID must be < 256");
                    add_attribute($virtual, redundancy_id => $id);
                }
                else {
                    syntax_err("Expected valid attribute for virtual IP");
                }
            }
            $virtual->{ip} or error_atline("Missing virtual IP");
            ($virtual->{redundancy_id} && !$virtual->{redundancy_type})
              and
              syntax_err("Redundancy ID is given without redundancy protocol");
        }
        elsif ($token eq 'bind_nat') {
            my $tags = read_assign_list(\&read_identifier);
            $interface->{bind_nat} and error_atline("Duplicate NAT binding");
            $interface->{bind_nat} = [ unique sort @$tags ];
        }
        elsif ($token eq 'hardware') {
            my $hardware = read_assign(\&read_name);
            add_attribute($interface, hardware => $hardware);
        }
        elsif ($token eq 'owner') {
            my $owner = read_assign(\&read_identifier);
            add_attribute($interface, owner => $owner);
        }
        elsif ($token eq 'routing') {
            my $routing = read_routing();
            add_attribute($interface, routing => $routing);
        }
        elsif ($token eq 'reroute_permit') {
            my $pairs = read_assign_list(\&read_typed_name);
            if (grep { $_->[0] ne 'network' || ref $_->[1] } @$pairs) {
                error_atline "Must only use network names in 'reroute_permit'";
                $pairs = [];
            }
            add_attribute($interface, reroute_permit => $pairs);
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
            syntax_err('Expected some valid attribute');
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
    if ($interface->{vip}) {
        $interface->{loopback} = 1;
        $interface->{hardware}
          and
          error_atline("'vip' interface must not have attribute 'hardware'");
        $interface->{hardware} = 'VIP';
    }
    if ($interface->{owner} && !$interface->{vip}) {
        error_atline("Must use attribute 'owner' only at 'vip' interface");
        delete $interface->{owner};
    }
    if ($interface->{loopback}) {
        my %copy = %$interface;

        # Only these attributes are valid.
        delete @copy{
            qw(name ip nat bind_nat hardware loopback subnet_of
              owner redundant redundancy_type redundancy_id vip)
        };
        if (keys %copy) {
            my $attr = join ", ", map { "'$_'" } keys %copy;
            my $type = $interface->{vip} ? "'vip'" : 'loopback';
            error_atline("Invalid attributes $attr for $type interface");
        }
        if ($interface->{ip} =~ /^(unnumbered|negotiated|short|bridged)$/) {
            my $type = $interface->{vip} ? "'vip'" : 'Loopback';
            error_atline("$type interface must not be $interface->{ip}");
            $interface->{disabled} = 1;
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
          and error_atline(
            "Interface with attribute 'spoke'",
            " must not have secondary interfaces"
          );
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
                err_msg("Must use $crypto exactly once, not at both\n",
                        " - $other->{name}\n",
                        " - $interface->{name}");
            }
            else {
                $crypto2hub{$crypto} = $interface;
            }
        }
    }
    if (@secondary_interfaces) {
        if ($interface->{ip} =~ /^(unnumbered|negotiated|short|bridged)$/) {
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
    return;
}

my $bind_nat0 = [];

# Mapping from router names to router objects.
our %routers;

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
        elsif ($token eq 'no_crypto_filter') {
            skip(';');
            $router->{no_crypto_filter} = 1;
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
                syntax_err("Expected interface or log definition");
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

                # Link interface with router object.
                $interface->{router} = $router;

                # Link interface with network name (will be resolved later).
                $interface->{network} = $name2;

                # Set private attribute of interface.
                $interface->{private} = $private if $private;
            }
        }
        else {
            syntax_err("Unexpected token");
        }
    }

    my $model = $router->{model};

    # Owner at vip interfaces is allowed for managed and unmanaged
    # devices and hence must be checked for both.
    {
        my $error;
        for my $interface (@{ $router->{interfaces} }) {
            if ($interface->{vip} && !($model && $model->{has_vip})) {
                $error = 1;

                # Prevent further errors.
                delete $interface->{vip};
                delete $interface->{owner};
            }
        }
        if ($error) {
            my $valid = join(
                ', ',
                grep({ $router_info{$_}->{has_vip} }
                    sort keys %router_info)
            );
            err_msg(
                "Must not use attribute 'vip' at $name\n",
                " 'vip' is only allowed for model $valid"
            );
        }
    }

    if (my $managed = $router->{managed}) {
        my $all_routing = $router->{routing};

        unless ($model) {
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
            if (!$hw_name) {

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

                # Hardware name 'VIP' is used internally at loadbalancers.
                      $hw_name eq 'VIP'
                  and $model->{has_vip}
                  and not $interface->{vip}
                  and err_msg("Must not use hardware 'VIP' at",
                    " $interface->{name}");
            }
            $interface->{hardware} = $hardware;

            # Hardware keeps attribute {loopback} only if all
            # interfaces have attribute {loopback}.
            if (!$interface->{loopback}) {
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
            if ($all_routing) {
                $interface->{routing} ||= $all_routing;
            }
            if ((my $routing = $interface->{routing})
                && $interface->{ip} eq 'unnumbered')
            {
                my $rname = $routing->{name};
                $rname =~ /^(?:manual|dynamic)$/
                  or err_msg("Routing $rname not supported",
                             " for unnumbered $interface->{name}");
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
            $router->{need_protect} = !delete $router->{no_protect_self};
        }

        # Detailed interface processing for managed routers.
        my $has_crypto;
        for my $interface (@{ $router->{interfaces} }) {
            if ($interface->{hub} or $interface->{spoke}) {
                $has_crypto = 1;
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

        check_no_in_acl($router);

        if ($router->{acl_use_real_ip}) {
            $has_bind_nat or 
                warn_msg("Ignoring attribute 'acl_use_real_ip' at $name,\n",
                         " because it has no interface with 'bind_nat'");
            $model->{can_acl_use_real_ip} or
                warn_msg("Ignoring attribute 'acl_use_real_ip' at $name,",
                         " of model $model->{name}");
            2 == @{ $router->{hardware} } or
                err_msg("Can't use attribute 'acl_use_real_ip' at $name,\n",
                        " it is only applicable at device with 2 interfaces");
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

            # Don't support NAT for VPN, otherwise code generation for VPN
            # devices will become more difficult.
            $has_bind_nat and
              err_msg("Attribute 'bind_nat' is not allowed",
                      " at interface of $name of model $model->{name}");

            $router->{radius_attributes} ||= {};
        }
        else {
            $router->{radius_attributes}
              and warn_msg("Ignoring 'radius_attributes' at $name");
        }
        if ($model->{no_crypto_filter}) {
            $router->{no_crypto_filter} = 1;
        }
    }

    # Unmanaged device.
    else {
        my $bridged;
        if (delete $router->{owner}) {
            warn_msg("Ignoring attribute 'owner' at unmanaged $name");
        }
        for my $interface (@{ $router->{interfaces} }) {
            if ($interface->{hub}) {
                err_msg("$interface->{name} with attribute 'hub'",
                          " must not be used at unmanaged $name");
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
                my $network = new(
                    'Network',
                    name => $name,
                    ip   => $interface->{ip},
                    mask => 0xffffffff,

                    # Mark as automatically created.
                    loopback  => 1,
                    subnet_of => delete $interface->{subnet_of},
                    is_layer3 => $interface->{is_layer3},
                );
                if (my $private = $interface->{private}) {
                    $network->{private} = $private;
                }
                $networks{$net_name} = $network;
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
            if (my $private = $interface->{private}) {
                $tunnel_net->{private} = $private;
            }
            $networks{$net_name} = $tunnel_net;

            # Tunnel network will later be attached to crypto hub.
            push @{ $crypto2spokes{$crypto} }, $tunnel_net;
        }

        if (($interface->{spoke} || $interface->{hub})
            && !$interface->{no_check})
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
        (my $name       = $interface->{name}) =~ s/^interface:/router/;
        my $new_router  = new(
            'Router',
            %$orig_router,
            name        => $name,
            orig_router => $orig_router,
            interfaces  => [$interface]
        );
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
    return;
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
        elsif ($token eq 'no_check_supernet_rules') {
            skip(';');
            $aggregate->{no_check_supernet_rules} = 1;
        }
        elsif (my ($type, $name2) = $token =~ /^ (\w+) : (.+) $/x) {
            if ($type eq 'nat') {
                verify_name($name2);
                my $nat_tag = $name2;
                my $nat = read_nat("nat:$nat_tag");
                $nat->{dynamic} or 
                    err_msg("$nat->{name} must be dynamic for $name");
                $aggregate->{nat}->{$nat_tag}
                and error_atline("Duplicate NAT definition");
                $aggregate->{nat}->{$nat_tag} = $nat;
            }
            else {
                syntax_err("Expected some valid attribute");
            }
        }
        else {
            syntax_err("Expected some valid attribute");
        }
    }
    $aggregate->{link} or err_msg("Attribute 'link' must be defined for $name");
    my $ip   = $aggregate->{ip};
    my $mask = $aggregate->{mask};
    if ($ip) {
        for my $key (keys %$aggregate) {
            next
              if grep({ $key eq $_ }
                qw( name ip mask link is_aggregate private nat));
            err_msg("Must not use attribute '$key' if mask is set for $name");
        }
    }
    else {
        $aggregate->{ip} = $aggregate->{mask} = 0;
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
        elsif ($token eq 'border') {
            skip '=';
            my $elements = read_union(';');
            if (grep { $_->[0] ne 'interface' || ref $_->[1] } @$elements) {
                error_atline("Must only use interface names in 'border'");
                $elements = [];
            }
            add_attribute($area, border => $elements);
        }
        elsif ($token eq 'inclusive_border') {
            skip '=';
            my $elements = read_union(';');
            if (grep { $_->[0] ne 'interface' || ref $_->[1] } @$elements) {
                error_atline("Must only use interface names in",
                             " 'inclusive_border'");
                $elements = [];
            }
            add_attribute($area, inclusive_border => $elements);
        }
        elsif ($token eq 'auto_border') {
            skip(';');
            $area->{auto_border} = 1;
        }
        elsif ($token eq  'anchor') {
            my $pair = read_assign(\&read_typed_name);
            if ($pair->[0] ne 'network' || ref $pair->[1]) {
                error_atline "Must only use network name in 'anchor'";
                $pair = undef;
            }
            add_attribute($area, anchor => $pair);
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
                my $nat = read_nat("nat:$nat_tag");
                $nat->{dynamic} or
                    err_msg("$nat->{name} must be dynamic for $name");
                $area->{nat}->{$nat_tag} and 
                    error_atline("Duplicate NAT definition");
                $area->{nat}->{$nat_tag} = $nat;
            }
            else {
                syntax_err("Expected some valid attribute");
            }
        }
        else {
            syntax_err("Expected some valid attribute");
        }
    }
    (($area->{border} || $area->{inclusive_border}) && $area->{anchor})
      and err_msg(
        "Attribute 'anchor' must not be defined together with",
        " 'border' or 'inclusive_border' for $name"
      );
    ($area->{anchor} || $area->{border} || $area->{inclusive_border})
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
                if ($port1 == 1 && $port2 == 65535) {
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
                $prt->{modifiers}->{stateless_icmp} = 1;
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
            $prt->{proto}     = 'tcp';
            $prt->{dst_range} = $aref_tcp_any;
        }
        elsif ($nr == 17) {
            $prt->{proto}     = 'udp';
            $prt->{dst_range} = $aref_tcp_any;
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
        $protocol->{is_used} = 1;
        $protocols{$name}    = $protocol;
        return $protocol;
    }
}

sub read_simple_protocol {
    my ($proto) = @_;
    my $protocol = {};
    if ($proto eq 'ip') {
        $protocol->{proto} = 'ip';
    }
    elsif ($proto eq 'tcp') {
        $protocol->{proto} = 'tcp';
        read_port_ranges($protocol);
    }
    elsif ($proto eq 'udp') {
        $protocol->{proto} = 'udp';
        read_port_ranges $protocol;
    }
    elsif ($proto eq 'icmp') {
        $protocol->{proto} = 'icmp';
        read_icmp_type_code $protocol;
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
    my ($protocol) = @_;
    while (check ',') {
        my $flag = read_identifier;
        if ($flag =~ /^(?:reversed | stateless | oneway |
                          src_net | dst_net |
                          overlaps | no_check_supernet_rules )/x)
        {
            $protocol->{modifiers}->{$flag} = 1;
        }
        else {
            syntax_err("Unknown modifier '$flag'");
        }
    }
    return;
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
    check_protocol_modifiers($protocol);
    skip ';';
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

sub assign_union_allow_user {
    my ($name, $sname) = @_;
    skip $name;
    skip '=';
    local $user_object->{active} = 1;
    $user_object->{refcount} = 0;
    my $result = read_union(';');
    my $user_seen = $user_object->{refcount};
    if ($user_seen) {
        check_user_in_union($result, "$name of $sname");
    }
    return $result, $user_seen;
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
        elsif ($token eq 'visible') {
            my $visible = read_assign(\&read_owner_pattern);
            add_attribute($service, visible => $visible);
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
        else {
            syntax_err("Expected some valid attribute or definition of 'user'");
        }
    }

    # 'user' has already been read above.
    skip '=';
    if (check('foreach')) {
        $service->{foreach} = 1;
    }
    $service->{user} = read_union(';');

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
        elsif (my $fun = $val_descr->{function}) {
            $val = &$fun;
        }
        else {
            internal_err();
        }
        skip ';';
        add_attribute($object, $attribute => $val);
    }
    for my $attribute (keys %$attr_descr) {
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
    lifetime       => { function => \&read_time_val, },
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
    key_exchange   => { function => \&read_typed_name, },
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
            syntax_err("Expected valid attribute");
        }
    }
    $crypto->{type} or err_msg("Missing 'type' for $name");
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
        elsif ($token eq 'alias') {
            my $alias = read_assign(\&read_string);
            add_attribute($owner, alias => $alias);
        }
        elsif ($token eq 'admins') {
            my $admins = read_assign_list(\&read_name);
            add_attribute($owner, admins => $admins);
        }
        elsif ($token eq 'watchers') {
            my $watchers = read_assign_list(\&read_name);
            add_attribute($owner, watchers => $watchers);
        }
        elsif ($token eq 'extend_only') {
            skip(';');
            $owner->{extend_only} = 1;
        }
        elsif ($token eq 'extend_unbounded') {
            skip(';');
            $owner->{extend_unbounded} = 1;
        }
        elsif ($token eq 'extend') {
            skip(';');
            $owner->{extend} = 1;
        }
        elsif ($token eq 'show_all') {
            skip(';');
            $owner->{show_all} = 1;
        }
        else {
            syntax_err("Expected valid attribute");
        }
    }
    $owner->{admins} ||= [];
    return $owner;
}

our %global_type = (
    router          => [ \&read_router,          \%routers ],
    network         => [ \&read_network,         \%networks ],
    any             => [ \&read_aggregate,       \%aggregates ],
    area            => [ \&read_area,            \%areas ],
    owner           => [ \&read_owner,           \%owners ],
    group           => [ \&read_group,           \%groups ],
    protocol        => [ \&read_protocol,        \%protocols ],
    protocolgroup   => [ \&read_protocolgroup,   \%protocolgroups ],
    service         => [ \&read_service,         \%services ],
    pathrestriction => [ \&read_pathrestriction, \%pathrestrictions ],
    isakmp          => [ \&read_isakmp,          \%isakmp ],
    ipsec           => [ \&read_ipsec,           \%ipsec ],
    crypto          => [ \&read_crypto,          \%crypto ],
);

sub read_netspoc {

    # Check for global definitions.
    my $pair = read_typed_name();
    my ($type, $name) = @$pair;
    my $descr = $global_type{$type}
      or syntax_err("Unknown global definition");
    my ($fun, $hash) = @$descr;
    my $result = $fun->("$type:$name");
    $result->{file} = $current_file;
    if (my $other = $hash->{$name}) {
        err_msg(
            "Duplicate definition of $type:$name in",
            " $current_file and $other->{file}"
        );
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

    open(my $fh, '<', $current_file)
        or fatal_err("Can't open $current_file: $!");

    # Fill buffer with content of whole file.
    # Content is implicitly freed when subroutine is left.
    local $input = <$fh>;
    close $fh;

    my $length = length $input;
    while (skip_space_and_comment, pos $input != $length) {
        &$read_syntax;
    }
    return;
}

sub read_file_or_dir {
    my ($path, $read_syntax) = @_;
    $read_syntax ||= \&read_netspoc;

    # Handle toplevel file.
    if (not -d $path) {
        read_file($path, $read_syntax);
        return;
    }

    # Recursively read files and directories.
    my $read_nested_files;
    my $read_nested_files0 = sub {
        my ($path, $read_syntax) = @_;
        if (-d $path) {
            opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
            while (my $file = Encode::decode($filename_encode, readdir $dh)) {
                next if $file =~ /^\./;
                next if $file =~ m/$config->{ignore_files}/o;
                my $path = "$path/$file";
                $read_nested_files->($path, $read_syntax);
            }
            closedir $dh;
        }
        else {
            read_file $path, $read_syntax;
        }
    };

    # Special handling for "*.private".
    $read_nested_files = sub {
        my ($path, $read_syntax) = @_;

        # Handle private directories and files.
        if (my ($name) = ($path =~ m'([^/]*\.private)$')) {
            if ($private) {
                err_msg("Nested private context is not supported:\n $path");
            }
            local $private = $name;
            $read_nested_files0->($path, $read_syntax);
        }
        else {
            $read_nested_files0->($path, $read_syntax);
        }
    };

    # Handle toplevel directory.
    # Special handling for "config" and "raw".
    opendir(my $dh, $path) or fatal_err("Can't opendir $path: $!");
    my @files = map({ Encode::decode($filename_encode, $_) } readdir $dh);
    closedir $dh;

    for my $file (@files) {

        next if $file =~ /^\./;
        next if $file =~ m/$config->{ignore_files}/o;

        # Ignore special files/directories.
        next if $file =~ /^(config|raw)$/;

        my $path = "$path/$file";
        $read_nested_files->($path, $read_syntax);
    }
    return;
}

# Prints number of read entities if in verbose mode.
sub show_read_statistics {
    my $n = keys %networks;
    my $h = keys %hosts;
    my $r = keys %routers;
    my $s = keys %services;
    info("Read $r routers, $n networks, $h hosts, $s services");
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
sub is_autointerface { ref($_[0]) eq 'Autointerface'; }

## use critic

# Creates a string representation of a rule.
sub print_rule {
    my ($rule) = @_;

    my $extra = '';
    my $service = $rule->{rule} && $rule->{rule}->{service};
    $extra .= " stateless"           if $rule->{stateless};
    $extra .= " stateless_icmp"      if $rule->{stateless_icmp};
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
    return;
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
        if (!defined $prt->{type}) {
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
    return;
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
    return;
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

# Protocol 'ip' is needed later for implementing secondary rules and
# automatically generated deny rules.
my $prt_ip;

# Protocol 'ICMP any', needed in optimization of chains for iptables.
my $prt_icmp;

# Protocol 'TCP any'.
my $prt_tcp;

# Protocol 'UDP any'.
my $prt_udp;

# DHCP server.
my $prt_bootps;

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
        $prt_icmp,
        $prt_tcp, $prt_udp,
        $prt_bootps,
        $prt_ike,
        $prt_natt,
        $prt_esp, $prt_ah,
        unique map({ $_->{prt} ? ($_->{prt}) : () } values %routing_info,
            values %xxrp_info),
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
    return;
}

####################################################################
# Link topology elements each with another
####################################################################

sub expand_group;

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
    if ($owner->{extend_only}) {
        
        # Prevent further errors.
        delete $owner->{extend_only};
        err_msg("$owner->{name} with attribute 'extend_only'",
                " must only be used at area,\n not at $obj->{name}");
    }
}

# Element of attribute 'watchers' of owner A is allowed to reference
# some other owner B. In this case all admins and watchers of B are
# added to watchers of A.
sub expand_watchers {
    my ($owner) = @_;
    my $names = $owner->{watchers};

    # No wathers given.
    if (!$names) {
        return $owner->{admins};
    }

    # Owners, referenced in $names have already been resolved.
    if ($owner->{watching_owners}) {
        return [ @{ $owner->{admins} }, @$names ];
    }
    if ($names eq 'recursive') {
        err_msg("Found recursive definition of watchers in $owner->{name}");
        return $owner->{watchers} = [];
    }
    $owner->{watchers} = 'recursive';
    my $watching_owners = [];
    my @expanded;
    for my $name (@$names) {
        if (my ($o_name) = ($name =~ /^owner:(.*)$/)) {
            my $owner_b = $owners{$o_name};
            if (!$owner_b) {
                err_msg("Unknown owner:$o_name referenced in watcher of",
                    " $owner->{name}");
                next;
            }
            $owner_b->{is_used} = 1;
            push @$watching_owners, $owner_b;
            push @expanded,         @{ expand_watchers($owner_b) };
        }
        else {
            push @expanded, $name;
        }
    }
    $owner->{watchers} = \@expanded;

    # Mark: no need to expand again and for cut-netspoc.
    $owner->{watching_owners} = $watching_owners;

    return [ @{ $owner->{admins} }, @expanded ];
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

        # Check and expand referenced owners in watchers.
        expand_watchers($owner);

        # Check email addresses in admins and watchers.
        for my $attr (qw( admins watchers )) {
            for my $email (@{ $owner->{$attr} }) {

                # Check email syntax.
                # Only 7 bit ASCII
                # Local part definition from wikipedia,
                # without space and other quoted characters
                do {
                    use bytes;
                    $email =~ m/^ [\w.!\#$%&''*+\/=?^_``{|}~-]+ \@ [\w.-]+ $/x
                      || $email eq 'guest';
                  }
                  or err_msg(
                    "Invalid email address (ASCII only)",
                    " in $attr of $owner->{name}: $email"
                  );

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
    for my $router (values %routers, @router_fragments) {
        link_to_real_owner($router);
        $router->{model}->{has_vip} or next;
        for my $interface (@{ $router->{interfaces} }) {
            link_to_real_owner($interface);
        }
    }
    for my $service (values %services) {
        link_to_real_owner($service, 'sub_owner');
    }
    return;
}

sub link_policy_distribution_point {
    my ($obj) = @_;
    my $pair = $obj->{policy_distribution_point} or return;
    my ($type, $name) = @$pair;
    if ($type ne 'host') {
        err_msg("Must only use 'host' in 'policy_distribution_point'",
            " of $obj->{name}");

        # Prevent further errors;
        delete $obj->{policy_distribution_point};
        return;
    }
    my $host = $hosts{$name};
    if (!$host) {
        warn_msg("Ignoring undefined host:$name",
            " in 'policy_distribution_point' of $obj->{name}");

        # Prevent further errors;
        delete $obj->{policy_distribution_point};
        return;
    }
    $obj->{policy_distribution_point} = $host;
    return;
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
        my $orig_prt;
        my $src_range;
        my $range;
        if (ref $prt eq 'ARRAY') {
            ($src_range, my $dst_range, $orig_prt) = @$prt;
            $range = $dst_range->{range};
        }
        else {
            $range = $prt->{range} or next;
            $orig_prt = $prt;
        }
        my @reason;
        if (my $modifiers = $orig_prt->{modifiers}) {
            push @reason, 'modifiers';
        }
        if ($src_range || $range && $range ne $aref_tcp_any) {
            push @reason, 'ports';
        }
        if (@reason) {
            my $reason = join ' or ', @reason;
            err_msg("Must not use '$orig_prt->{name}' with $reason",
                " in general_permit of $context");
        }
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
            for my $attr (qw(border inclusive_border)) {
                next if !$area->{$attr};
                $area->{$attr} = expand_group($area->{$attr}, $area->{name});
                for my $obj (@{ $area->{$attr} }) {
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
                          "Unexpected $obj->{name} in $attr of $area->{name}";

                        # Prevent further errors.
                        delete $area->{$attr};
                    }
                }
            }
        }
        if (my $router_attributes = $area->{router_attributes}) {
            link_policy_distribution_point($router_attributes);
            link_general_permit($router_attributes);
        }
    }
    return;
}

# Link interfaces with networks in both directions.
sub link_interfaces {
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
        if ($mask == 0xffffffff) {
            if (not $network->{loopback}) {
                warn_msg(
                    "$interface->{name} has address of its network.\n",
                    " Remove definition of $network->{name} and\n",
                    " add attribute 'loopback' at",
                    " interface definition."
                );
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

# Iterate over all interfaces of all routers.
# Don't use values %interfaces because we want to traverse the interfaces
# in a deterministic order.
sub link_routers {
    for my $router (sort(by_name values %routers), @router_fragments) {
        link_interfaces($router);
        link_policy_distribution_point($router);
        link_general_permit($router);
    }
    return;
}

sub link_subnet {
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
        warn_msg(
            "Ignoring undefined network:$name",
            " from attribute 'subnet_of'\n of ",
            $context->()
        );

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
    return;
}

sub link_subnets {
    for my $network (values %networks) {
        link_subnet($network, undef);
    }
    for my $obj (values %networks, values %aggregates, values %areas) {
        my $nat = $obj->{nat} or next;
        for my $nat (values %{ $obj->{nat} }) {
            link_subnet($nat, $obj);
        }
    }
    return;
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

            # Unmanaged router with pathrestriction is handled specially.
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
                      " $obj_p $obj->{name}";
                }
            }
        }
        if ($no_private) {
            err_msg "$private $restrict->{name} must reference",
              " at least one interface out of $private";
        }
        if ($changed) {
            $restrict->{elements} = [ grep { $_ } @{ $restrict->{elements} } ];
        }
        my $count = @{ $restrict->{elements} };
        if ($count == 1) {
            warn_msg(
                "Ignoring $restrict->{name} with only",
                " $restrict->{elements}->[0]->{name}"
            );
            $restrict->{elements} = [];
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
# All parts are connected by an freshly created unnumbered network.
sub split_semi_managed_router {
    for my $router (values %routers) {

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
                if (my $virtual2 = $net2id2type2virtual{$net}->{$id1}->{$type1})
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

    # A virtual interface is used as hop for static routing.
    # Therefore a network behind this interface must be reachable
    # via all virtual interfaces of the group.
    # This can only be guaranteed, if pathrestrictions are identical
    # at all interfaces.
    # Exception in routing code:
    # If the group has ony two interfaces, the one or other physical
    # interface can be used as hop.
    my %seen;
    for my $href (values %net2ip2virtual) {
        for my $interfaces (values %$href) {
            next if @$interfaces <= 2;
            my @virt_routers = map { $_->{router} } @$interfaces;
            my %routers_hash = map { $_ => $_ } @virt_routers;
            for my $router (@virt_routers) {
                for my $interface (@{ $router->{interfaces} }) {
                    next if $interface->{main_interface};
                    my $restricts = $interface->{path_restrict} or next;
                    for my $restrict (@$restricts) {
                        next if $seen{$restrict};
                        my @restrict_routers =
                          grep({ $routers_hash{$_} }
                            map { $_->{router} } @{ $restrict->{elements} });
                        next if @restrict_routers == @virt_routers;
                        $seen{$restrict} = 1;
                        my @info;
                        for my $router (@virt_routers) {
                            my $info = $router->{name};
                            if (grep { $_ eq $router } @restrict_routers) {
                                $info .= " has $restrict->{name}";
                            }
                            push @info, $info;
                        }
                        err_msg(
                            "Must apply pathrestriction equally to",
                            " group of routers with virtual IP:\n",
                            " - ",
                            join("\n - ", @info)
                        );
                    }
                }
            }
        }
    }

    # Automatically add pathrestriction to interfaces belonging to
    # $net2ip2virtual, if at least one interface is managed.
    # Pathrestriction would be useless if all devices are unmanaged.
    for my $href (values %net2ip2virtual) {
        for my $interfaces (values %$href) {
            for my $interface (@$interfaces) {
                my $router = $interface->{router};
                if ($router->{managed} || $router->{routing_only}) {
                    my $name = "auto-virtual-" . print_ip $interface->{ip};
                    add_pathrestriction($name, $interfaces);
                    last;
                }
            }
        }
    }
    return;
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
                if (!$type eq 'service') {
                    err_msg "Unexpected type '$type' in attribute 'overlaps'",
                      " of $name";
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

        my %ip2obj;

        # 1. Check for duplicate interface addresses.
        # 2. Short interfaces must not be used, if a managed interface
        #    with static routing exists in the same network.
        my ($short_intf, $route_intf);
        for my $interface (@{ $network->{interfaces} }) {
            my $ip = $interface->{ip};
            if ($ip eq 'short') {

                # Ignore short interface from split crypto router.
                if (1 < @{ $interface->{router}->{interfaces} }) {
                    $short_intf = $interface;
                }
            }
            else {
                unless ($ip =~ /^(?:unnumbered|negotiated|tunnel|bridged)$/) {
                    my $router = $interface->{router};
                    if (($router->{managed} || $router->{routing_only})
                        && !$interface->{routing})
                    {
                        $route_intf = $interface;
                    }
                    if (my $old_intf = $ip2obj{$ip}) {
                        unless ($old_intf->{redundant}
                            and $interface->{redundant})
                        {
                            err_msg "Duplicate IP address for",
                              " $old_intf->{name} and $interface->{name}";
                        }
                    }
                    else {
                        $ip2obj{$ip} = $interface;
                    }
                }
            }
            if ($short_intf and $route_intf) {
                err_msg "$short_intf->{name} must be defined in more detail,",
                  " since there is\n",
                  " a managed $route_intf->{name} with static routing enabled.";
            }
        }
        my %range2obj;
        for my $host (@{ $network->{hosts} }) {
            if (my $ip = $host->{ip}) {
                if (my $other_device = $ip2obj{$ip}) {
                    err_msg "Duplicate IP address for $other_device->{name}",
                      " and $host->{name}";
                }
                else {
                    $ip2obj{$ip} = $host;
                }
            }
            elsif (my $range = $host->{range}) {
                my ($from, $to) = @$range;
                if (my $other_device = $range2obj{$from}->{$to}) {
                    err_msg "Duplicate IP range for $other_device->{name}",
                      " and $host->{name}";
                }
                else {
                    $range2obj{$from}->{$to} = $host;
                }
            }
        }
        for my $host (@{ $network->{hosts} }) {
            if (my $range = $host->{range}) {
                for (my $ip = $range->[0] ; $ip <= $range->[1] ; $ip++) {
                    if (my $other_device = $ip2obj{$ip}) {
                        is_host($other_device)
                          or err_msg(
                            "Duplicate IP address for",
                            " $other_device->{name}",
                            " and $host->{name}"
                          );
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
my @routing_only_routers;
my @managed_crypto_hubs;
my @routers;
my @networks;
my @zones;
my @areas;

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
        if ($router->{managed} || $router->{routing_only}) {
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
                if (my @active_borders = grep { !$_->{disabled} } @$borders) {
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

    for my $router (sort(by_name values %routers), @router_fragments) {
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
    my %name2vrf;
    for my $router (@managed_routers, @routing_only_routers) {
        next if $router->{orig_router};
        my $device_name = $router->{device_name};
        push @{ $name2vrf{$device_name} }, $router;
    }
    for my $aref (values %name2vrf) {
        next if @$aref == 1;
        equal(
            map {
                    $_->{managed} || $_->{routing_only}
                  ? $_->{model}->{name}
                  : ()
            } @$aref
          )
          or err_msg(
            "All VRF instances of router:$aref->[0]->{device_name}",
            " must have identical model"
          );

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
        if (keys %networks > 1 or keys %routers) {
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
    check_bridged_networks();
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

sub owner_eq {
    my ($obj1, $obj2) = @_;
    my $owner1 = $obj1->{owner};
    my $owner2 = $obj2->{owner};
    return not(($owner1 xor $owner2) || $owner1 && $owner1 ne $owner2);
}

sub check_host_compatibility {
    my ($host, $other_subnet) = @_;
    my $nat  = $host->{nat};
    my $nat2 = $other_subnet->{nat};
    my $nat_error;
    if ($nat xor $nat2) {
        $nat_error = 1;
    }
    elsif ($nat and $nat2) {
        internal_err("Unexpected NAT at host range",
                     " $host->{name} or $other_subnet->{name}");
    }
    $nat_error
        and err_msg("Inconsistent NAT definition for",
                    " $other_subnet->{name} and $host->{name}");

    owner_eq($host, $other_subnet) or
        warn_msg("Inconsistent owner definition for",
                " $other_subnet->{name} and $host->{name}");
}

sub convert_hosts {
    progress('Converting hosts to subnets');
    for my $network (@networks) {
        next if $network->{ip} =~ /^(?:unnumbered|tunnel)$/;
        my @inv_prefix_aref;

        # Converts hosts and ranges to subnets.
        # Eliminate duplicate subnets.
        for my $host (@{ $network->{hosts} }) {
            my ($name, $nat, $id, $owner) = @{$host}{qw(name nat id owner)};
            my @ip_mask;
            if (my $ip = $host->{ip}) {
                @ip_mask = [ $ip, 0xffffffff ];
                if ($id) {
                    if (my ($user, $dom) = ($id =~ /^(.*?)(\@.*)$/)) {
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
            elsif ($host->{range}) {
                my ($ip1, $ip2) = @{ $host->{range} };
                @ip_mask = split_ip_range $ip1, $ip2;
                if ($id) {
                    if (@ip_mask > 1) {
                        err_msg("Range of $name with ID must expand to",
                            " exactly one subnet");
                    }
                    elsif ($ip_mask[0]->[1] == 0xffffffff) {
                        err_msg("$name with ID must not have single IP");
                    }
                    elsif ($id =~ /^.+\@/) {
                        err_msg("ID of $name must start with character '\@'",
                            " or have no '\@' at all");
                    }
                }
            }
            else {
                internal_err("unexpected host type");
            }
            for my $ip_mask (@ip_mask) {
                my ($ip, $mask) = @$ip_mask;
                my $inv_prefix = 32 - mask2prefix $mask;
                if (my $other_subnet = $inv_prefix_aref[$inv_prefix]->{$ip}) {
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
                    $subnet->{nat}     = $nat     if $nat;
                    $subnet->{owner}   = $owner   if $owner;
                    if ($id) {
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

        # Set {up} relation and 
        # check compatibility of hosts in subnet relation
        for (my $i = 0 ; $i < @inv_prefix_aref ; $i++) {
            my $ip2subnet = $inv_prefix_aref[$i] or next;
            for my $ip (keys %$ip2subnet) {
                my $subnet = $ip2subnet->{$ip};

                # Search for enclosing subnet.
                for (my $j = $i + 1 ; $j < @inv_prefix_aref ; $j++) {
                    my $mask = prefix2mask(32 - $j);
                    $ip = $ip & $mask;    # Perl bug #108480
                    if (my $up = $inv_prefix_aref[$j]->{$ip}) {
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
                                    mask    => $mask,
                                    up      => $subnet->{up},
                                );
                                $inv_prefix_aref[$up_inv_prefix]->{$ip} = $up;
                                push @{ $network->{subnets} }, $up;
                            }
                            $subnet->{up}   = $up;
                            $neighbor->{up} = $up;

                            # Don't search for enclosing subnet below.
                            next;
                        }
                    }
                }
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
    return;
}

# Find adjacent subnets and substitute them by their enclosing subnet.
sub combine_subnets {
    my ($subnets) = @_;
    my %hash = map { $_ => $_ } @$subnets;
    my @extra;
    while (1) {
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

# Check intersection of interface and auto-interface.
# Prevent expressions like "interface:r.x &! interface:r.[auto]",
# because we don't know the exact value of the auto-interface.
# The auto-interface could be "r.x" but not for sure.
# $info is hash with attributes
# - i => { $router => $interface, ... }
# - r => { $router => $autointerface, ... }
# - n => { $router => { $network => autointerface, ... }, ... }
#
# interface:router.network conflicts with interface:router.[auto]
# interface:router.network conflicts with interface:[network].[auto]
# interface:router:[auto] conflicts with interface:[network].[auto]
#  if router is connected to network.
sub check_auto_intf {
    my ($info, $elements, $context) = @_;
    my $add_info = {};

    # Check current elements with interfaces of previous elements.
    for my $obj (@$elements) {
        next if $obj->{disabled};
        my $type = ref $obj;
        my $other;
        if ($type eq 'Interface') {
            my $router  = $obj->{router};
            my $network = $obj->{network};
            $other = $info->{r}->{$router} || $info->{n}->{$router}->{$network};
            $add_info->{i}->{$router} = $obj;
        }
        elsif ($type eq 'Autointerface') {
            my $auto = $obj->{object};
            if (is_router($auto)) {
                my $router = $auto;
                $other = $info->{i}->{$router};
                if (!$other) {
                    my $href = $info->{n}->{$router};
                    $other = (values %$href)[0];
                }
                $add_info->{r}->{$router} = $obj;
            }
            else {
                my $network = $auto;
                for my $interface (@{ $network->{interfaces} }) {
                    my $router = $interface->{router};
                    $other = $info->{r}->{$router};
                    if (!$other && ($other = $info->{i}->{$router})) {
                        if (!$other->{network} eq $network) {
                            $other = undef;
                        }
                    }
                    $add_info->{n}->{$router}->{$network} = $obj;
                }
            }
        }
        if ($other) {
            err_msg("Must not use $other->{name} and $obj->{name} together\n",
                " in intersection of $context");
        }
    }

    # Extend info with values of current elements.
    for my $key (keys %$add_info) {
        my $href = $add_info->{$key};
        for my $rkey (%$href) {
            my $val = $href->{$rkey};
            if (ref $val) {
                @{ $info->{$key}->{$rkey} }{ keys %$val } = values %$val;
            }
            else {
                $info->{$key}->{$rkey} = $val;
            }
        }
    }
    return;
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
            my %autointf_info;
            for my $element (@$name) {
                my $element1 = $element->[0] eq '!' ? $element->[1] : $element;
                my @elements =
                  map { $_->{is_used} = 1; $_; } @{
                    expand_group1(
                        [$element1], "intersection of $context",
                        $clean_autogrp
                    )
                  };
                check_auto_intf(\%autointf_info, \@elements, $context);
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
            push @objects, grep { $result->{$_} } @$first_set;
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
                                  grep(
                                    {        $_->{router}->{managed}
                                          || $_->{router}->{routing_only} }
                                    @{ $object->{interfaces} });
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
                        if ($managed
                            && !($router->{managed} || $router->{routing_only}))
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
                              grep({ $_->{managed} || $_->{routing_only} }
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
                            if ($managed
                                && !($obj->{managed} || $obj->{routing_only}))
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
                my ($selector, $managed) = @$ext;
                if (my $router = $routers{$name}) {

                    # Syntactically impossible.
                    $managed and internal_err();
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
                  @{ expand_group1($name, "$type:[..] of $context") }
            ];
            my $get_aggregates = sub {
                my ($object, $ip, $mask) = @_;
                my @objects;
                my $type = ref $object;
                if ($type eq 'Area') {
                    push @objects,
                      unique(
                        map({ get_any($_, $ip, $mask) } @{ $object->{zones} }));
                }
                elsif ($type eq 'Network' && $object->{is_aggregate}) {
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
                    push @objects, $object->{network};
                }
                elsif ($type eq 'Network') {
                    if (!$object->{is_aggregate}) {
                        push @objects, $object;
                    }

                    # Take aggregate directly. Don't use next "elsif"
                    # clause below, where it would be changed to non
                    # matching aggregate with IP 0/0.
                    else {
                        push @objects, @{ $object->{networks} };
                    }
                }
                elsif (my $aggregates = $get_aggregates->($object, 0, 0)) {
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
                return \@objects;
            };
            if ($type eq 'host') {
                my $managed = $ext;
                my @hosts;
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
                        for my $network (@$networks) {
                            push @hosts, @{ $network->{hosts} };
                            if (my $managed_hosts = $network->{managed_hosts}) {
                                push @hosts, @$managed_hosts;
                            }
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
                $ext and internal_err;
                my @list;
                for my $object (@$sub_objects) {
                    if (my $networks = $get_networks->($object)) {

                        # Silently remove from automatic groups:
                        # - crosslink network
                        # - loopback network of managed device
                        # Change loopback network of unmanaged device
                        # to loopback interface.
                        push @list, $clean_autogrp
                          ? map {
                            if ($_->{loopback}) {
                                my $interfaces = $_->{interfaces};
                                my $intf       = $interfaces->[0];
                                if ($intf->{router}->{managed}) {
                                    ();
                                }
                                else {
                                    if (@$interfaces > 1) {
                                        warn_msg(
                                            "Must not use $_->{name},",
                                            " use interfaces instead"
                                        );
                                    }
                                    $intf;
                                }
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

# Remove and warn about duplicate values in group.
sub remove_duplicates {
    my ($aref, $context) = @_;
    my %seen;
    my @duplicate;
    for my $obj (@$aref) {
        if ($seen{$obj}++) {
            push @duplicate, $obj;
            $obj = undef;
        }
    }
    if (@duplicate) {
        my $msg = "Duplicate elements in $context:\n "
          . join("\n ", map { $_->{name} } @duplicate);
        warn_msg($msg);
        $aref = [ grep { defined $_ } @$aref ];
    }
    return $aref;
}

sub expand_group {
    my ($obref, $context) = @_;
    my $aref = expand_group1 $obref, $context, 'clean_autogrp';
    $aref = remove_duplicates($aref, $context);

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
    my ($obref, $context) = @_;
    my $aref = expand_group($obref, $context);

    # Ignore unusable objects.
    my $changed;
    for my $object (@$aref) {
        my $ignore;
        if (is_network $object) {
            if ($object->{ip} eq 'unnumbered') {
                $ignore = "unnumbered $object->{name}";
            }
            elsif ($object->{crosslink}) {
                $ignore = "crosslink $object->{name}";
            }
            elsif ($object->{is_aggregate}) {
                if ($object->{is_tunnel}) {
                    $ignore = "$object->{name} with tunnel";
                }
                elsif ($object->{has_id_hosts}) {
                    $ignore = "$object->{name} with software clients";
                }
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
        my $print = $print_type eq 'warn' ? \&warn_msg : \&err_msg;
        for my $name (sort keys %$hash) {
            my $value = $hash->{$name};
            next if $value->{is_used};
            $print->("unused $value->{name}");
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
    return;
}

# Result:
# Reference to array with elements
# - non TCP/UDP protocol
# - dst_range of (split) TCP/UDP protocol
# - [ src_range, dst_range, orig_prt ]
#   of (split) protocol having src_range or main_prt.
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

# Expand split protocols.
sub split_protocols {
    my ($protocols, $context) = @_;
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
                for my $src_split (expand_split_protocol $src_range) {
                    for my $dst_split (expand_split_protocol $dst_range) {
                        push @$aref_list, [ $src_split, $dst_split, $prt ];
                    }
                }
                $prt->{src_dst_range_list} = $aref_list;
            }
            push @split_protocols, @$aref_list;
        }
        else {
            for my $dst_split (expand_split_protocol $dst_range) {
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
    return;
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
# Result     : An array of tuples:
#              1. List of real interfaces.
#              2. Those objects from $dst_list that lead to result in 1.
sub expand_auto_intf_with_dst_list {
    my ($auto_intf, $dst_list, $context) = @_;
    my %path2result;
    my %result2sub_list;

    # Make result deterministic and mostly preserve original order.
    my %index2result;
    my $index = 1;
    for my $dst (@$dst_list) {

        # Destination objects with different path lead to same result.
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
            else {
                $index2result{$index++} = $result;
            }
            $path2result{$path} = $result;
        }
        push @{$result2sub_list{$result}}, $dst;
    }
    return [ map { [ $_, $result2sub_list{$_} ] }

             # Ignore empty list of real interfaces.
             map { @$_ ? $_ : () }

             map { $index2result{$_} } 
             sort numerically keys %index2result ];
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
        if (keys %$modifiers or $src_range) {
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
    my $private = $service->{private};
    my $context = $service->{name};
    for my $src (@$src_list) {
        for my $dst (@$dst_list) {

            if ($private) {
                my $src_p = $src->{private};
                my $dst_p = $dst->{private};
                $src_p and $src_p eq $private
                    or $dst_p and $dst_p eq $private
                    or err_msg(
                        "Rule of $private $context",
                        " must reference at least one object",
                        " out of $private");
            }
            else {
                $src->{private}
                and err_msg(
                    "Rule of public $context must not",
                    " reference $src->{name} of",
                    " $src->{private}");
                $dst->{private}
                and err_msg(
                    "Rule of public $context must not",
                    " reference $dst->{name} of",
                    " $dst->{private}");
            }
        }
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
        $aref = remove_duplicates($aref, $context);
    }
    return $aref;
}

sub normalize_src_dst_list {
    my ($rule, $user, $context) = @_;
    $user_object->{elements} = $user;
    my $src_list = expand_group_in_rule($rule->{src},
                                        "src of rule in $context");
    my $dst_list = expand_group_in_rule($rule->{dst},
                                        "dst of rule in $context");

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
    my $context = $service->{name};
    my $user    = $service->{user} 
                = expand_group($service->{user}, "user of $context");
    my $rules   = $service->{rules};
    my $foreach = $service->{foreach};

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
          split_protocols(
            expand_protocols($unexpanded->{prt}, "rule in $context"));
        @$prt_list or next;
        my $prt_list_pair = classify_protocols($prt_list, $service);

        for my $element ($foreach ? @$user : ($user)) {
            my $src_dst_list_pairs = 
                normalize_src_dst_list($unexpanded, $element, $context);
            next if $service->{disabled};
            for my $src_dst_list (@$src_dst_list_pairs) {
                my ($src_list, $dst_list) = @$src_dst_list;
                @$src_list and @$dst_list or next;
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
                    $rule->{stateless_icmp} = 1
                        if $modifiers->{stateless_icmp};
                    $rule->{src_net}   = 1          if $modifiers->{src_net};
                    $rule->{dst_net}   = 1          if $modifiers->{dst_net};

                    # Only used in check_service_owner.
                    $rule->{reversed}  = 1          if $modifiers->{reversed};

                    push @$store, $rule;
                }
            }
        }
    }

    # Result is stored in global %service_rules.
    return;
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
            delete $_->{owner} for @implicit_owner_zones;

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
    for my $area (@areas) {
        if (my $super = $area->{subset_of}) {
            $add_node->($super, $area);
        }
    }

    # Find direct subset relation between areas and zones.
    for my $area (@areas) {
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
            my $router = $interface->{router};
            if (!($router->{managed} || $router->{routing_only})) {
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
    my @root_nodes =
      sort by_name map { $ref2obj{$_} } grep { not $is_child{$_} } keys %tree;

    # owner is extended by e_owner at node.
    # owner->[[node, e_owner, .. ], .. ]
    my %extended;

    # upper_owner: owner object without attribute extend_only or undef
    # extend: a list of owners with attribute extend
    # extend_only: a list of owners with attribute extend_only
    my $inherit;
    $inherit = sub {
        my ($node, $upper_owner, $upper_node, $extend, $extend_only) = @_;
        my $owner = $node->{owner};
        if (not $owner) {
            $node->{owner} = $upper_owner if $upper_owner;
        }
        else {
            $owner->{is_used} = 1;
            if ($upper_owner) {
                if ($owner eq $upper_owner) {
                    if (!$zone_got_net_owners{$upper_node}) {
                        warn_msg(
                            "Useless $owner->{name} at $node->{name},\n",
                            " it was already inherited from",
                            " $upper_node->{name}"
                        );
                    }
                }
                else {
                    if ($upper_owner->{extend}) {
                        $extend = [ $upper_owner, @$extend ];
                    }
                }
            }
            my @extend_list = ($node);
            push @extend_list, @$extend      if $extend;
            push @extend_list, @$extend_only if $extend_only;
            push @{ $extended{$owner} }, \@extend_list;
        }
        if (!$owner || !$owner->{extend_only}) {
            if (my $upper_extend = $extend_only->[0]) {
                $node->{extended_owner} = $upper_extend;
            }
        }

        if ($owner && $owner->{extend_only}) {
            $extend_only = [ $owner, @$extend_only ];
            $upper_owner = undef;
            $upper_node  = undef;
        }
        elsif ($owner) {
            $upper_owner = $owner;
            $upper_node  = $node;
        }
        my $childs = $tree{$node} or return;
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
    for my $owner (sort by_name values %owners) {
        my $aref = $extended{$owner} || [];
        my $node1;
        my $ext1;
        my $combined;
        for my $node_ext (@$aref) {
            my $node = shift @$node_ext;
            next if $zone_got_net_owners{$node};
            my $ext = $node_ext;
            if ($node1) {
                for my $owner_list ($ext1, $ext) {
                    my ($other, $owner_node, $other_node) =
                      $owner_list eq $ext
                      ? ($ext1, $node, $node1)
                      : ($ext, $node1, $node);
                    for my $e_owner (@$owner_list) {
                        next if $e_owner->{extend_unbounded};
                        next if grep { $e_owner eq $_ } @$other;
                        warn_msg(
                            "$owner->{name}",
                            " is extended by $e_owner->{name}\n",
                            " - only at $owner_node->{name}\n",
                            " - but not at $other_node->{name}"
                        );
                    }
                }
                $combined = [ @$ext, @$combined ];
            }
            else {
                $combined = $ext;
                ($node1, $ext1) = ($node, $ext);
            }
        }
        if ($combined && @$combined) {
            $owner->{extended_by} = [ unique @$combined ];
        }
        if ($owner->{show_all}) {
            my @invalid;
            for my $node (@root_nodes) {
                my $node_owner = $node->{owner} || '';
                if ($node_owner ne $owner) {
                    push @invalid, $node;
                }
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

        for my $interface (get_intf($router)) {

            # Loadbalancer interface with {vip} can have dedicated owner.
            $interface->{owner} ||= $owner;
        }
    }

    # Propagate owner of loopback interface to loopback network
    # and loopback zone.
    for my $router (@routers) {
        my $managed = $router->{managed} || $router->{routing_only};
        for my $interface (@{ $router->{interfaces} }) {
            $interface->{loopback} or next;
            my $owner = $interface->{owner} or next;
            my $network = $interface->{network};
            $network->{owner} = $owner;
            $network->{zone}->{owner} = $owner if $managed;

            # Mark dedicated owner of {vip} interface, which is also a
            # loopback interface.
            $owner->{is_used} = 1;
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
            my $owner = ($up ? $up : $zone)->{owner} or next;
            $aggregate->{owner} = $owner;
        }
    }
    return;
}

sub check_service_owner {
    progress('Checking service owner');

    propagate_owners();

    my %sname2info;
    my %unknown2services;
    my %unknown2unknown;

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
            (keys %$service_owners == 1 && $service_owners->{$sub_owner})
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
            else {
                my $print =
                    $config->{check_service_multi_owner}
                  ? $config->{check_service_multi_owner} eq 'warn'
                      ? \&warn_msg
                      : \&err_msg
                  : sub { };
                my @names =
                  sort(map { ($_->{name} =~ /^owner:(.*)/)[0] }
                      values %$service_owners);
                $print->("$sname has multiple owners:\n " . join(', ', @names));
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
    for my $owner (sort by_name values %owners) {
        delete $owner->{is_used} or warn_msg("Unused $owner->{name}");
    }


    # Show objects with unknown owner.
    for my $names (values %unknown2services) {
        $names = join(', ', sort @$names);
    }
    my $print = $config->{check_service_unknown_owner} eq 'warn'
              ? \&warn_msg
              : \&err_msg;
    for my $obj (sort by_name values %unknown2unknown) {
        $print->("Unknown owner for $obj->{name} in $unknown2services{$obj}");
    }

    return;
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
        if ($type eq 'Network') {
            push @unmodified, $obj;
            next;
        }
        elsif ($type eq 'Host') {
            if ($obj->{id}) {
                push @unmodified, $obj;
                next;
            }
            $network = $obj->{network};
        }
        elsif ($type eq 'Interface') {
            if ($obj->{router}->{managed} || $obj->{loopback}) {
                push @unmodified, $obj;
                next;
            }
            $network = $obj->{network};
        }
        else {
            internal_err("unexpected $obj->{name}");
        }
        next if $network->{ip} eq 'unnumbered';
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
                my @subnets;
                my %subnet2host;
                my @other;
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
                        if ($subnet->{mask} == $subnet->{network}->{mask}) {
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
                            push @subnets, $subnet;
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

    # Used, when called on src_path / dst_path.
    elsif ($type eq 'Router') {
        if ($obj->{managed}) {
            $result = $obj;
        }
        else {
            $result = $obj->{interfaces}->[0]->{network}->{zone};
        }
    }
    elsif ($type eq 'Zone') {
        $result = $obj;
    }

    elsif ($type eq 'Host') {
        $result = $obj->{network}->{zone};
    }
    else {
        internal_err("Unexpected $obj->{name}");
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

    my $context = $service->{name};
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
                        my ($a, $b) = $src->{ip} > $dst->{ip} 
                                    ? ($dst, $src) 
                                    : ($src, $dst);
                        if ($a->{ip} + complement_32bit($a->{mask}) + 1 == 
                            $b->{ip})
                        {
                            next;
                        }
                    }
                }

                # Different aggregates with identical IP, 
                # inside a zone cluster must be considered as equal.
                elsif ($src->{is_aggregate} && $dst->{is_aggregate} &&
                       $src->{ip}   == $dst->{ip} &&
                       $src->{mask} == $dst->{mask})
                {
                    next;
                }

                # This is a common case, which results from rules like
                # user -> any:[user]
                elsif ($src->{is_aggregate} && $src->{mask} == 0) {
                    next;
                }
                elsif ($dst->{is_aggregate} && $dst->{mask} == 0) {
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
    return;
}

sub show_unenforceable {
    for my $key (sort keys %services) {
        my $service = $services{$key};
        my $context = $service->{name};

        if ($service->{has_unenforceable}
            && (!$service->{seen_unenforceable} || 
                !$service->{seen_enforceable}))
        {
            warn_msg("Useless attribute 'has_unenforceable' at $context");
        }
        next if !$config->{check_unenforceable};
        next if $service->{disabled};

        my $print = 
            $config->{check_unenforceable} eq 'warn' ? \&warn_msg : \&err_msg;

        # Warning about fully unenforceable service can't be disabled with
        # attribute has_unenforceable.
        if (!delete $service->{seen_enforceable}) {

            # Don't warn on empty service without any expanded rules.
            if ($service->{seen_unenforceable} || 
                $service->{silent_unenforceable})
            {
                $print->("$context is fully unenforceable");
            }
            next;
        }
        next if $service->{has_unenforceable};

        if (my $hash = delete $service->{seen_unenforceable}) {
            my @list;
            for my $hash (values %$hash) {
                for my $aref (values %$hash) {
                    my ($src, $dst) = @$aref;
                    push @list, "src=$src->{name}; dst=$dst->{name}";
                }
            }
            $print->(join "\n ", 
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
        my $agg00 = $zone->{ipmask2aggregate}->{'0/0'};
        my $name = $agg00 ? $agg00->{name} : $zone->{name};
        warn_msg("Useless attribute 'has_unenforceable' at $name");
    }
    return;
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
        $element0 or internal_err print_rule $rule;
        my $path0 = $obj2path{$element0} || get_path($element0);

        # Group has elements from different zones and must be split.
        if (grep { $path0 ne ($obj2path{$_} || get_path($_)) } @$group) {
            my $index = 1;
            my %path2index;
            my %key2group;
            for my $element (@$group) {
                my $path = $obj2path{$element};
                my $key  = $path2index{$path} ||= $index++;
                push @{ $key2group{$key}}, $element;
            }
            for my $key (sort numerically keys %key2group) {
                my $path_group = $key2group{$key};
                my $path = $obj2path{$path_group->[0]};
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
            for my $attr (qw(src_range log oneway stateless stateless_icmp)) {
                next RULE if $rule->{$attr};
            }
            $src = $src->[0];
            $dst = $dst->[0];
            $prt = $prt->[0];
            if ($src2dst2prt2rule{$src}->{$dst}->{$prt}) {
                $rule = undef;
                $count++;
            }
            else {
                $src2dst2prt2rule{$src}->{$dst}->{$prt} = $rule;
            }
        }
        if ($count) {
            $path_rules{$action} = [ grep { $_ } @$rules ];
#            info("Removed $count $action rules");
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

my @duplicate_rules;

sub collect_duplicate_rules {
    my ($rule, $other) = @_;

    my $prt1 = get_orig_prt($rule);
    my $prt2 = get_orig_prt($other);
    return if $prt1->{modifiers}->{overlaps} && $prt2->{modifiers}->{overlaps};

    my $service  = $rule->{rule}->{service};
    my $oservice = $other->{rule}->{service};
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
    push @duplicate_rules, [ $rule, $other ];
    return;
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

    my $action = $config->{check_duplicate_rules} or return;
    my $print  = $action eq 'warn' ? \&warn_msg : \&err_msg;
    for my $sname (sort keys %sname2oname2duplicate) {
        my $hash = $sname2oname2duplicate{$sname};
        for my $oname (sort keys %$hash) {
            my $aref = $hash->{$oname};
            my $msg  = "Duplicate rules in $sname and $oname:\n  ";
            $msg .= join("\n  ", map { print_rule $_ } @$aref);
            $print->($msg);
        }
    }
    return;
}

my @redundant_rules;

sub collect_redundant_rules {
    my ($rule, $other) = @_;

    my $prt1 = get_orig_prt($rule);
    my $prt2 = get_orig_prt($other);
    return if $prt1->{modifiers}->{overlaps} && $prt2->{modifiers}->{overlaps};

    my $service  = $rule->{rule}->{service};
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
    return;
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
    my $print = $action eq 'warn' ? \&warn_msg : \&err_msg;
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
            $print->($msg);
        }
    }
    return;
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
    return;
}

# Expand path_rules to elementary rules.
sub expand_rules {
    my ($rules) = @_;
    my @result;
    for my $rule (@$rules) {
        my ($src_list, $dst_list, $prt_list) = @{$rule}{qw(src dst prt)};
        for my $src (@$src_list) {
            for my $dst (@$dst_list) {
                for my $prt (@$prt_list) {
                    push @result, { %$rule,
                                     src => $src, 
                                     dst => $dst, 
                                     prt => $prt };
                }
            }
        }
    }
    return \@result;
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
    info("Expanded rule count: $count; duplicate: $dcount; redundant: $rcount");
    return;
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

    # Find all TCP ranges which include port 22 and 23.
    my @admin_tcp_keys = grep({
            my ($p1, $p2) = split(':', $_);
            $p1 <= 22 && 22 <= $p2 || $p1 <= 23 && 23 <= $p2;
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
        my @dst_list = grep { not $_->{vip} } @{ $rule->{dst} };
        @{$router2found_interfaces{$router}}{@dst_list} = @dst_list;
    }
    for my $router (@managed_routers, @routing_only_routers) {
        my $pdp = $router->{policy_distribution_point} or next;
        my $found_interfaces = $router2found_interfaces{$router};
        my @result;

        # Ready, if exactly one management interface was found.
        if (keys %$found_interfaces == 1) {
            @result = values %$found_interfaces;
        }
        else {

#           debug("$router->{name}: ", scalar keys %found_interfaces);
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
            if (!@result) {
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
    my %seen;
    my @unreachable;
    for my $router (@managed_routers, @routing_only_routers) {
        next if $seen{$router};
        next if !$router->{policy_distribution_point};
        next if $router->{orig_router};
        if (my $vrf_members = $router->{vrf_members}) {
            for my $member (@$vrf_members) {
                if (!$member->{admin_ip}) {
                    push(@unreachable,
                        "some VRF of router:$router->{device_name}");
                    last;
                }
            }

            # Print VRF instance with known admin_ip first.
            $router->{vrf_members} = [
                sort {
                        !$a->{admin_ip} <=> !$b->{admin_ip}
                      || $a->{name} cmp $b->{name}
                } @$vrf_members
            ];
            $seen{$_} = 1 for @$vrf_members;
        }
        else {
            $router->{admin_ip}
              or push @unreachable, $router->{name};
            $seen{$router} = 1;
        }
    }
    if (@unreachable) {
        my $count = @unreachable;
        if ($count > 4) {
            splice(@unreachable, 3, @unreachable - 3, '...');
        }
        my $list = join("\n - ", @unreachable);
        warn_msg("Missing rules to reach $count devices from",
                 " policy_distribution_point:\n",
                 " - ",
            $list
        );
    }
    return;
}

##############################################################################
# Distribute NAT bindings
##############################################################################

# NAT Set: a set of NAT tags which are effective at some location.
# NAT Domain: a maximal area of the topology (a set of connected networks)
# where the NAT set is identical at each network.
sub set_natdomain;

sub set_natdomain {
    my ($network, $domain, $in_interface) = @_;

    # Found a loop inside a NAT domain.
    return if $network->{nat_domain};

#    debug("$domain->{name}: $network->{name}");
    $network->{nat_domain} = $domain;
    push @{ $domain->{networks} }, $network;
    for my $interface (@{ $network->{interfaces} }) {

        # Ignore interface where we reached this network.
        next if $interface eq $in_interface;
        next if $interface->{main_interface};

#        debug("IN $interface->{name}");
        my $nat_tags = $interface->{bind_nat} || $bind_nat0;
        my $router = $interface->{router};

        # Found loop.
        # If one router is connected to the same NAT domain
        # by different interfaces, all interfaces must have
        # the same NAT binding.
        if (my $entry_nat_tags = $router->{active_path}) {
            next if aref_eq($nat_tags, $entry_nat_tags);
            my $names1 = join(',', @$nat_tags)       || '(none)';
            my $names2 = join(',', @$entry_nat_tags) || '(none)';
            next if $router->{nat_err_seen}->{"$names1 $names2"}++;
            err_msg("Inconsistent NAT in loop at $router->{name}:\n",
                " nat:$names1 vs. nat:$names2");

#            debug("LOOP $interface->{name}");
            next;
        }

        # 'local' declaration restores previous value on block exit.
        # Remember NAT tags at loop entry.
        local $router->{active_path} = $nat_tags;

        my $useless_nat = 1;
        my $interfaces = $router->{interfaces};
        for my $out_interface (@$interfaces) {

            # Don't process interface where we reached this router.
            next if $out_interface eq $interface;
            next if $out_interface->{main_interface};

#            debug("OUT $out_interface->{name}");
            # Current NAT domain continues behind $out_interface.
            my $out_nat_tags = $out_interface->{bind_nat} || $bind_nat0;
            if (aref_eq($out_nat_tags, $nat_tags)) {

                my $next_net = $out_interface->{network};
                set_natdomain($next_net, $domain, $out_interface);
            }

            # New NAT domain starts at some interface of current router.
            # Remember NAT tag of current domain.
            elsif (not $router->{nat_tags}->{$domain}) {
                $useless_nat = undef;
                $router->{nat_tags}->{$domain} = $nat_tags;
                push @{ $domain->{routers} },     $router;
                push @{ $router->{nat_domains} }, $domain;
            }
        }
        if ($useless_nat and @$nat_tags and
            grep { not $_->{hub} and not $_->{spoke} } @$interfaces)
        {
            my $list = join ',', map { "nat:$_" } @$nat_tags;
            warn_msg("Ignoring $list without effect, bound at",
                     " every interface of $router->{name}");
        }
    }
    return;
}

my @natdomains;

# Distribute NAT tags from NAT domain to NAT domain.
# Returns
# - undef on success
# - aref of routers, if invalid path was found in loop.
sub distribute_nat1 {
    my ($domain, $nat_tag, $nat_tags2multi, $in_router) = @_;

#    debug "nat:$nat_tag at $domain->{name} from $in_router->{name}";
    if ($domain->{active_path}) {

#	debug("$domain->{name} loop");
        # Found a loop
        return;
    }

    # Tag is already there.
    my $nat_set = $domain->{nat_set};
    return if $nat_set->{$nat_tag};

    # Must not enter one NAT domain at different routers with
    # different elements of grouped NAT tags.
    if (my $aref = $nat_tags2multi->{$nat_tag}) {
        for my $multi_href (@$aref) {
            for my $nat_tag2 (sort keys %$multi_href) {
                if ($nat_set->{$nat_tag2}) {
                    err_msg(
                        "Grouped NAT tags '$nat_tag2' and '$nat_tag'",
                        " must not both be active inside $domain->{name}"
                    );
                }
            }
        }
    }

    # Add tag.
    # Use a hash to prevent duplicate entries.
    $nat_set->{$nat_tag} = 1;

    # Network which has translation with tag $nat_tag must not be located
    # in area where this tag is effective.
    for my $network (@{ $domain->{networks} }) {
        my $nat = $network->{nat} or next;
        $nat->{$nat_tag} or next;
        err_msg(
            "$network->{name} is translated by $nat_tag,\n",
            " but is located inside the translation domain of $nat_tag.\n",
            " Probably $nat_tag was bound to wrong interface",
            " at $in_router->{name}."
        );

        # Show error message only once.
        last;
    }

    # Activate loop detection.
    local $in_router->{active_path} = 1;
    local $domain->{active_path}    = 1;

    # Distribute NAT tag to adjacent NAT domains.
    for my $router (@{ $domain->{routers} }) {
        next if $router eq $in_router;
        my $in_nat_tags = $router->{nat_tags}->{$domain};

        # Found another interface with same NAT binding.
        # This stops effect of current NAT tag.
        next if grep { $_ eq $nat_tag } @$in_nat_tags;

        # Traverse loop twice to prevent inherited errors.
        # Check for recursive and duplicate NAT.
        for my $out_domain (@{ $router->{nat_domains} }) {
            next if $out_domain eq $domain;
            my $out_nat_tags = $router->{nat_tags}->{$out_domain};

            # Must not apply one NAT tag multiple times in a row.
            if (grep { $_ eq $nat_tag } @$out_nat_tags) {

                # Check for recursive NAT in loop.
                if ($router->{active_path}) {

                    # Abort traversal and start collecting path.
                    return [$router];
                }
                err_msg(
                    "nat:$nat_tag is applied twice between",
                    " $in_router->{name} and $router->{name}"
                );
            }
        }

      DOMAIN:
        for my $out_domain (@{ $router->{nat_domains} }) {
            next if $out_domain eq $domain;
            my $out_nat_tags = $router->{nat_tags}->{$out_domain};

            # Effect of current NAT tag stops if another element of
            # grouped NAT tags becomes active.
            if (my $aref = $nat_tags2multi->{$nat_tag}) {
                for my $href (@$aref) {
                    for my $nat_tag2 (@$out_nat_tags) {
                        next if $nat_tag2 eq $nat_tag;
                        next if !$href->{$nat_tag2};

#                        debug "- $nat_tag2";
                        # Prevent transition from dynamic to
                        # static NAT.
                        my $nat_info  = $href->{$nat_tag};
                        my $next_info = $href->{$nat_tag2};

                        # Use $next_info->{name} and not $nat_info->{name}
                        # because $nat_info may show wrong network,
                        # because we combined different hidden networks into
                        # $nat_tags2multi.
                        if ($nat_info->{hidden}) {
                            err_msg(
                                "Must not change hidden nat:$nat_tag",
                                " using nat:$nat_tag2\n",
                                " for $next_info->{name}",
                                " at $router->{name}"
                            );
                        }
                        elsif ($nat_info->{dynamic}) {
                            if (!($next_info->{dynamic})) {
                                err_msg(
                                    "Must not change dynamic nat:$nat_tag",
                                    " to static using nat:$nat_tag2\n",
                                    " for $nat_info->{name}",
                                    " at $router->{name}"
                                );
                            }
                        }
                        next DOMAIN;
                    }
                }
            }

#            debug "Caller $domain->{name}";
            if (
                my $err_path = distribute_nat1(
                    $out_domain, $nat_tag, $nat_tags2multi, $router
                )
              )
            {
                push @$err_path, $router;
                return $err_path;
            }
        }
    }
    return;
}

sub distribute_nat {
    my ($domain, $nat_tag, $nat_tags2multi, $in_router) = @_;
    if (my $err_path =
        distribute_nat1($domain, $nat_tag, $nat_tags2multi, $in_router))
    {
        push @$err_path, $in_router;
        err_msg("nat:$nat_tag is applied recursively in loop at this path:\n",
            " - ", join("\n - ", map { $_->{name} } reverse @$err_path));
    }
    return;
}

sub distribute_nat_info {
    progress('Distributing NAT');

    # Mapping from nat_tag to boolean. Is false if all NAT mappings map
    # to hidden.
    my %has_non_hidden;

    for my $network (@networks) {
        my $href = $network->{nat} or next;
        for my $nat_tag (keys %$href) {
            my $nat_network = $href->{$nat_tag};
            if (!$nat_network->{hidden}) {
                $has_non_hidden{$nat_tag} = 1;
            }
        }
    }

    # A hash with all defined NAT tags.
    # It is used to check,
    # - if all NAT definitions are bound and
    # - if all bound NAT tags are defined somewhere.
    my %nat_definitions;

    # Check consistency of grouped NAT tags at one network.
    # If NAT tags are grouped at one network,
    # the same NAT tags must be used as group at all other networks.
    # Suppose tags A and B are used grouped.
    # An occurence of bind_nat = A activates NAT:A.
    # An successive bind_nat = B actives NAT:B, but implicitly disables NAT:A.
    # Hence A is disabled for all networks and therefore
    # this restriction is needed.
    # Exception:
    # NAT tags with "hidden" can be added to some valid set of grouped tags,
    # because we don't allow transition from hidden tag back to some other
    # (hidden) tag.
    #
    # A hash with all defined NAT tags as keys and aref of hrefs as value.
    # The href has those NAT tags as keys which are used together at one
    # network.
    # This is used to check,
    # that NAT tags are equally used grouped or solitary.
    my %nat_tags2multi;
    my %all_hidden;
    for my $network (@networks) {
        my $href = $network->{nat} or next;

#        debug $network->{name}, " nat=", join(',', sort keys %$href);

        # Print error message only once per network.
        my $err_shown;
        my $show_err = sub {
            my ($href1, $href2) = @_;
            return if $err_shown;
            my $tags1 = join(',', sort keys %$href1);
            my $name1 = $network->{name};
            my $tags2 = join(',', sort keys %$href2);

            # Values are NAT entries with name of network.
            # Take first value deterministically.
            my ($name2) = sort map { $_->{name} } values %$href2;
            err_msg
              "If multiple NAT tags are used at one network,\n",
              " these NAT tags must be used",
              " equally grouped at other networks:\n",
              " - $name1: $tags1\n",
              " - $name2: $tags2";
            $err_shown = 1;
            return;
        };

      NAT_TAG:
        for my $nat_tag (sort keys %$href) {
            $nat_definitions{$nat_tag} = 1;
            if (my $aref = $nat_tags2multi{$nat_tag}) {

                # If elements have a common non hidden tag,
                # then only a single href is allowed.
                if ($has_non_hidden{$nat_tag}) {
                    my $href2 = $aref->[0];
                    keys_eq($href, $href2) or $show_err->($href, $href2);
                    next NAT_TAG;
                }

                # Array of hrefs has common hidden NAT tag.
                #
                # Ignore new href if it is identical to some previous one.
                for my $href2 (@$aref) {
                    keys_eq($href, $href2) and next NAT_TAG;
                }

                # Some element is non hidden, check detailed.
                if (grep { $has_non_hidden{$_} } %$href) {

                    # Check new href for consistency with previous hrefs.
                    for my $nat_tag2 (sort keys %$href) {
                        next if $nat_tag2 eq $nat_tag;
                        for my $href2 (@$aref) {

                            # Don't check previous href with all hidden tags.
                            next if $all_hidden{$href2};

                            # Non hidden tag must not occur in other href.
                            if ($has_non_hidden{$nat_tag2}) {
                                if ($href2->{$nat_tag2}) {
                                    $show_err->($href, $href2);
                                    next NAT_TAG;
                                }
                            }

                            # Hidden tag must occur in all other hrefs.
                            else {
                                if (!$href2->{$nat_tag2}) {
                                    $show_err->($href, $href2);
                                    next NAT_TAG;
                                }
                            }
                        }
                    }
                }

                # All elements are hidden. Always ok.
                else {

                    # Mark this type of href for easier checks.
                    $all_hidden{$href} = 1;
                }

                # If current href and some previous href are in subset
                # relation, then take larger set.
                for my $href2 (@$aref) {
                    my $common_size = grep { $href2->{$_} } keys %$href;
                    if ($common_size eq keys %$href) {

                        # Ignore new href, because it is subset.
                        next NAT_TAG;
                    }
                    elsif ($common_size eq keys %$href2) {

                        # Replace previous href by new superset.
                        $href2 = $href;
                        next NAT_TAG;
                    }
                    else {

                        # Add new href below.
                    }
                }
            }
            push @{ $nat_tags2multi{$nat_tag} }, $href;
        }
    }

    # Remove single entries.
    for my $nat_tag (keys %nat_tags2multi) {
        my $aref = $nat_tags2multi{$nat_tag};
        next if @$aref > 1;
        my $href = $aref->[0];
        next if keys %$href > 1;
        delete $nat_tags2multi{$nat_tag};
    }

    # Find NAT domains.
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

    # Distribute NAT tags to NAT domains.
    for my $domain (@natdomains) {
        for my $router (@{ $domain->{routers} }) {
            my $nat_tags = $router->{nat_tags}->{$domain};

#            debug "$domain->{name} $router->{name}: ", join(',', @$nat_tags);

            # Multiple tags are bound to interface.
            # If some network has multiple matching NAT tags,
            # the resulting NAT mapping would be ambiguous.
            if (@$nat_tags >= 2) {
              NAT_TAG:
                for my $nat_tag (@$nat_tags) {
                    my $aref = $nat_tags2multi{$nat_tag} or next;
                    for my $href (@$aref) {
                        my @tags = grep { $href->{$_} && $_ } @$nat_tags;
                        @tags >= 2 or next;
                        my $tags = join(',', @tags);
                        my $nat_net = $href->{ $tags[0] };
                        err_msg(
                            "Must not bind multiple NAT tags",
                            " '$tags' of $nat_net->{name}",
                            " at $router->{name}"
                        );

                        # Show only first error. Otherwise we would
                        # show the same error multiple times.
                        last NAT_TAG;
                    }
                }
            }
            for my $nat_tag (@$nat_tags) {
                if ($nat_definitions{$nat_tag}) {
                    distribute_nat($domain, $nat_tag, \%nat_tags2multi,
                                   $router);
                    $nat_definitions{$nat_tag} = 'used';
                }
                else {
                    warn_msg(
                        "Ignoring useless nat:$nat_tag",
                        " bound at $router->{name}"
                    );
                }
            }
        }
    }

    for my $name (keys %nat_definitions) {
        $nat_definitions{$name} eq 'used'
          or warn_msg("nat:$name is defined, but not bound to any interface");
    }

    check_nat_compatibility();
    check_interfaces_with_dynamic_nat();
    invert_nat_set();
}

# Check compatibility of host/interface and network NAT.
# A NAT definition for a single host/interface is only allowed,
# if the network has a dynamic NAT definition.
sub check_nat_compatibility {
    for my $network (@networks) {
        for my $obj (@{ $network->{hosts} }, @{ $network->{interfaces} }) {
            my $nat = $obj->{nat} or next;
            for my $nat_tag (keys %$nat) {
                my $nat_network = $network->{nat}->{$nat_tag};
                if ($nat_network and $nat_network->{dynamic}) {
                    my $obj_ip = $nat->{$nat_tag};
                    my ($ip, $mask) = @{$nat_network}{qw(ip mask)};
                    match_ip($obj_ip, $ip, $mask) or
                        err_msg ("nat:$nat_tag: IP of $obj->{name} doesn't",
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

# Find interfaces with dynamic NAT which is applied at the same device.
# This is incomatible with device with "need_protect".
sub check_interfaces_with_dynamic_nat {
    for my $network (@networks) {
        my $nat = $network->{nat} or next;
        for my $nat_tag (keys %$nat) {
            my $nat_info = $nat->{$nat_tag};
            $nat_info->{dynamic} or next;
            for my $interface (@{ $network->{interfaces} }) {
                my $intf_nat = $interface->{nat};

                # Interface has static translation,
                next if $intf_nat && $intf_nat->{$nat_tag};

                my $router = $interface->{router};
                next if !$router->{need_protect};
                for my $bind_intf (@{ $router->{interfaces} }) {
                    my $bind = $bind_intf->{bind_nat} or next;
                    grep { $_ eq $nat_tag } @$bind or next;
                    err_msg(
                        "Must not apply dynamic NAT to $interface->{name}",
                        " at $bind_intf->{name} of same device.\n",
                        " This isn't supported for model",
                        " $router->{model}->{name}."
                    );
                }
            }
        }
    }
}

sub invert_nat_set {

    # Find NAT partitions.
    # NAT partitions arise, if parts of the topology are strictly
    # separated by crypto interfaces.
    my %partitions;
    my $mark_nat_partition;
    $mark_nat_partition = sub {
        my ($domain, $mark) = @_;
        return if $partitions{$domain};

#        debug "$mark $domain->{name}";
        $partitions{$domain} = $mark;
        for my $router (@{ $domain->{routers} }) {
            for my $out_domain (@{ $router->{nat_domains} }) {
                next if $out_domain eq $domain;
                $mark_nat_partition->($out_domain, $mark);
            }
        }
    };
    my $mark = 0;
    for my $domain (@natdomains) {
        $mark++;
        $mark_nat_partition->($domain, $mark);
    }

    # Collect NAT tags used in each partition.
    my %partition2tags;
    for my $domain (@natdomains) {
        my $mark = $partitions{$domain};
        for my $network (@{ $domain->{networks} }) {
            my $href = $network->{nat} or next;
            for my $nat_tag (keys %$href) {
                $partition2tags{$mark}->{$nat_tag} = 1;
            }
        }
    }

    # Invert {nat_set} to {no_nat_set}
    for my $domain (@natdomains) {
        my $nat_set     = delete $domain->{nat_set};
        my $mark        = $partitions{$domain};
        my $all_nat_set = $partition2tags{$mark} ||= {};

#        debug "$mark $domain->{name} all: ", join(',', keys %$all_nat_set);
        my $no_nat_set = {%$all_nat_set};
        delete @{$no_nat_set}{ keys %$nat_set };
        $domain->{no_nat_set} = $no_nat_set;

#        debug "$mark $domain->{name} no: ", join(',', keys %$no_nat_set);
    }

    # Distribute {no_nat_set} to interfaces.
    # no_nat_set is needed at logical and hardware interfaces of
    # managed routers. Set it also for semi_managed routers to
    # calculate {up} relation between subnets.
    for my $domain (@natdomains) {
        my $no_nat_set = $domain->{no_nat_set};
        for my $network (@{ $domain->{networks} }) {
            for my $interface (@{ $network->{interfaces} }) {
                my $router = $interface->{router};
                ($router->{managed} || $router->{semi_managed}) or next;

#               debug("$domain->{name}: NAT $interface->{name}");
                $interface->{no_nat_set} = $no_nat_set;
                $interface->{hardware}->{no_nat_set} = $no_nat_set
                  if $router->{managed} || $router->{routing_only};
            }
        }
    }
    return ();
}

# Real interface of crypto tunnel has got {no_nat_set} of that NAT domain,
# where encrypted traffic passes. But real interface gets ACL that filter
# both encrypted and unencrypted traffic. Hence no_nat_set must be extended by
# no_nat_set of some corresponding tunnel interface.
sub adjust_crypto_nat {
    my %seen;
    for my $crypto (values %crypto) {
        for my $tunnel (@{ $crypto->{tunnels} }) {
            next if $tunnel->{disabled};
            for my $tunnel_intf (@{ $tunnel->{interfaces} }) {
                my $real_intf = $tunnel_intf->{real_interface};
                next if $seen{$real_intf}++;
                $real_intf->{router}->{managed} or next;
                my $tunnel_set = $tunnel_intf->{no_nat_set};
                keys %$tunnel_set or next;

                # Copy hash, because it is shared with other interfaces.
                my $real_set = $real_intf->{no_nat_set};
                $real_set = $real_intf->{no_nat_set} = {%$real_set};
                my $hardware = $real_intf->{hardware};
                $hardware->{no_nat_set} = $real_set if ref $hardware;
                for my $nat_tag (sort keys %$tunnel_set) {

#                   debug "Adjust NAT of $real_intf->{name}: $nat_tag";
                    $real_set->{$nat_tag} = 1;
                }
            }
        }
    }
    return;
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
    return if $network->{is_aggregate} || $subnet->{is_aggregate};
    my ($sub_ip, $sub_mask) = @{$subnet}{qw(ip mask)};
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

sub by_name     { return $a->{name} cmp $b->{name} }

sub link_reroute_permit;

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

        # Collect NAT tags, that are defined and applied inside the zone.
        my %net2zone_nat_tags;

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
                next if $network->{ip} =~ /^(?:unnumbered|tunnel)$/;

                my $nat_network = $network;
                if (my $href = $network->{nat}) {
                    for my $tag (keys %$href) {
                        next if $no_nat_set->{$tag};
                        push @{ $net2zone_nat_tags{$network} }, $tag;
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
                        " - but it is hidden $nat_network->{name} at",
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
            my @mask_list = reverse sort numerically keys %mask_ip_hash;
            while (my $mask = shift @mask_list) {

                # No supernets available
                last if not @mask_list;

                my $ip_hash = $mask_ip_hash{$mask};
              SUBNET:
                for my $ip (sort numerically keys %$ip_hash) {

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
        my $set_max_net;
        $set_max_net = sub {
            my ($network) = @_;
            return if not $network;
            if (my $max_net = $max_up_net{$network}) {
                return $max_net;
            }
            if (my $max_net = $set_max_net->($network->{up})) {
                if (!$network->{is_aggregate}) {
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
        # which encloses N and which has the same NAT settings as N.
        # If one exists, store it in {max_routing_net}. This is used
        # for generating static routes.
        for my $network (@{ $zone->{networks} }) {
            my $max = $max_up_net{$network} or next;

#            debug "Check $network->{name} $max->{name}";

            my $get_zone_nat = sub {
                my ($network) = @_;
                my $nat = $network->{nat} || {};

                # Special case:
                # NAT is applied to $network inside the zone.
                # Ignore NAT tag when comparing with NAT of $up.
                if (my $aref = $net2zone_nat_tags{$network}) {
                    $nat = {%$nat};
                    for my $nat_tag (@$aref) {
                        delete $nat->{$nat_tag};
                    }
                }
                return $nat;
            };
            my $nat = $get_zone_nat->($network);
            my $max_routing;
            my $up = $network->{up};
          UP:
            while ($up) {

                # Check if NAT settings are identical.
                my $up_nat = $get_zone_nat->($up);
                keys %$nat == keys %$up_nat or last UP;
                for my $tag (keys %$nat) {
                    my $up_nat_info = $up_nat->{$tag} or last UP;
                    my $nat_info = $nat->{$tag};
                    if ($nat_info->{hidden}) {
                        $up_nat_info->{hidden} or last UP;
                    }
                    else {

                        # Check if subnet relation is maintained
                        # for NAT addresses.
                        $up_nat_info->{hidden} and last UP;
                        my ($ip, $mask) = @{$nat_info}{qw(ip mask)};
                        match_ip($up_nat_info->{ip}, $ip, $mask) or last UP;
                        $up_nat_info->{mask} >= $mask or last UP;
                    }
                }
                if (!$up->{is_aggregate}) {
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
          [ grep { !$max_up_net{$_} } @{ $zone->{networks} } ];

        # Propagate managed hosts to aggregates.
        for my $aggregate (values %{ $zone->{ipmask2aggregate} }) {
            add_managed_hosts_to_aggregate($aggregate);
        }
    }

    # It is valid to have an aggregate in a zone which has no matching
    # networks. This can be useful to add optimization rules at an
    # intermediate device.

    return;
}

# Find networks with identical IP in different NAT domains.
# Mark networks, having subnet in other zone: $bignet->{has_other_subnet}
# If set, this prevents secondary optimization.
sub find_subnets_in_nat_domain {
    my $count = @natdomains;
    progress("Finding subnets in $count NAT domains");
    my %seen;

    for my $domain (@natdomains) {

        # Ignore NAT domain consisting only of a single unnumbered network and
        # surrounded by unmanaged devices.
        # A address conflict would not be observable inside this NAT domain.
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

#        debug("$domain->{name} ", join ',', sort keys %$no_nat_set);
        my %mask_ip_hash;
        my %has_identical;
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

                        # Check supernet rules and prevent secondary
                        # optimization, if identical IP address
                        # occurrs in different zones.
                        $old_net->{has_other_subnet} = 1;
                        $network->{has_other_subnet} = 1;
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
                    err_msg("$name1 and $name2 have identical IP/mask\n",
                        " in $domain->{name}");
                }
                else {

                    # Mark duplicate aggregates / networks.
                    $has_identical{$old_net} = 1;
                    $has_identical{$network} = 1;
                }
            }
            else {

                # Store original network under NAT IP/mask.
                $mask_ip_hash{$mask}->{$ip} = $network;
            }
        }

        # Go from smaller to larger networks.
        my @mask_list = reverse sort numerically keys %mask_ip_hash;
        while (my $mask = shift @mask_list) {

            # No supernets available
            last if not @mask_list;

            my $ip_hash = $mask_ip_hash{$mask};
            for my $ip (sort numerically keys %$ip_hash) {
                my $subnet = $ip_hash->{$ip};

                # Find networks which include current subnet.
                # @mask_list holds masks of potential supernets.
                for my $m (@mask_list) {
                    my $i          = $ip & $m;
                    my $bignet     = $mask_ip_hash{$m}->{$i} or next;
                    my $nat_subnet = get_nat_network($subnet, $no_nat_set);
                    my $nat_bignet = get_nat_network($bignet, $no_nat_set);

                    # Mark network having subnet in other zone.
                    if ($bignet->{zone} ne $subnet->{zone} or
                        $subnet->{has_other_subnet} or
                        $has_identical{$subnet})
                    {

#                       debug "has other: $bignet->{name}";
                        $bignet->{has_other_subnet} = 1;
                    }

                    if ($seen{$nat_bignet}->{$nat_subnet}) {
                        last;
                    }
                    $seen{$nat_bignet}->{$nat_subnet} = 1;

                    if ($config->{check_subnets}) {

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

                            my $msg =
                                "$nat_subnet->{name} is subnet of"
                              . " $nat_bignet->{name}\n"
                              . " in $domain->{name}.\n"
                              . " If desired, either declare attribute"
                              . " 'subnet_of' or attribute 'has_subnets'";

                            if ($config->{check_subnets} eq 'warn') {
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

    # Secondary optimization substitutes a host or interface by its
    # largest valid supernet inside the same security zone. This
    # supernet has already been calculated and stored in
    # {max_routing_net}. But {max_routing_net} can't be used if it has
    # a subnet in some other security zone. In this case we have to
    # search again for a supernet without attribute {has_other_subnet}.
    # The result is stored in {max_secondary_net}.
    for my $network (@networks) {
        my $max = $network->{max_routing_net} or next;
        if (!$max->{has_other_subnet}) {
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
                if (!$up->{is_aggregate}) {
                    $max_secondary = $up;
                }
                $up = $up->{up};
            }
        }
        $network->{max_secondary_net} = $max_secondary if $max_secondary;
    }
    return;
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
    local_secondary => 6,
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
    my $walk;

    # Add routers to cluster via depth first search.
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

    # Process all need_protect crosslinked routers.
    for my $router (values %$crosslink_routers) {
        next if $seen{$router};

        # Fill router cluster
        %cluster = ();
        $walk->($router);

        # Collect all interfaces belonging to need_protect routers of cluster...
        my @crosslink_interfaces =
          grep { !$_->{vip} }
          map  { @{ $_->{interfaces} } }
          grep { $crosslink_routers->{$_} }
          sort by_name values %cluster;    # Sort to make output deterministic.

        # ... add information to every cluster member as list 
        # used in print_acls.
        for my $router2 (values %cluster) {
            $router2->{crosslink_interfaces} = \@crosslink_interfaces;
        }
    }
    return;
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
            if (!$router->{managed}) {
                err_msg(
                    "Crosslink $network->{name} must not be",
                    " connected to unmanged $router->{name}"
                );
                next;
            }
            1 == grep({ !$_->{main_interface} } @{ $hardware->{interfaces} })
              or err_msg
              "Crosslink $network->{name} must be the only network\n",
              " connected to $hardware->{name} of $router->{name}";

            # Fill variables.
            my $managed  = $router->{managed};
            my $strength = $crosslink_strength{$managed}
              or internal_err("Unexptected managed=$managed");
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
            if (   $weakest == $crosslink_strength{local}
                && $strength2intf{ $crosslink_strength{secondary} })
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
    ip               => 0,
    mask             => 0,
    is_aggregate     => 1,
    has_other_subnet => 1,
);

# Find cluster of zones connected by 'local' or 'local_secondary' routers.
# - Check consistency of attributes.
# - Set unique 'local_mark' for all zones and managed routers
#   belonging to one cluster.
# Returns array of cluster infos, a hash with attributes
# - no_nat_set
# - filter_only
# - mark
sub get_managed_local_clusters {
    my $local_mark = 1;
    my @result;
    for my $router0 (@managed_routers) {
        $router0->{managed} =~ /^local/ or next;
        next if $router0->{local_mark};
        my $filter_only = $router0->{filter_only};
        my $info = { mark => $local_mark, filter_only => $filter_only };
        my $no_nat_set;
        my $k0;

        # IP/mask pairs of current cluster matching {filter_only}.
        my %matched;

        my $walk;
        $walk = sub {
            my ($router) = @_;
            $router->{local_mark} = $local_mark;
            if ($filter_only ne $router->{filter_only}) {

                # All routers of a cluster must have same values in
                # {filter_only}.
                $k0 ||= join(',',
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
                    next if $zone->{disabled};
                    next if $zone->{local_mark};

                    # Needed for local_secondary optimization.
                    $zone->{local_mark} = $local_mark;

                    # All networks in local zone must match {filter_only}.
                  NETWORK:
                    for my $network (@{ $zone->{networks} }) {
                        my ($ip, $mask) = @{ address($network, $no_nat_set) };
                        for my $pair (@$filter_only) {
                            my ($i, $m) = @$pair;
                            if ($mask >= $m && match_ip($ip, $i, $m)) {
                                $matched{"$i/$m"} = 1;
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
                        next if $managed !~ /^local/;
                        next if $router2->{local_mark};
                        $walk->($router2);
                    }
                }
            }
        };

        $walk->($router0);
        push @result, $info;
        $local_mark++;

        for my $pair (@{ $router0->{filter_only} }) {
            my ($i, $m) = @$pair;
            $matched{"$i/$m"} and next;
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

        my $mark_networks;
        $mark_networks = sub {
            my ($networks) = @_;
            for my $network (@$networks) {

                if (my $subnetworks = $network->{networks}) {
                    $mark_networks->($subnetworks);
                }

                my $nat_network = get_nat_network($network, $no_nat_set);
                next if $nat_network->{hidden};
                next if $nat_network->{ip} eq 'unnumbered';
                my ($ip, $mask) = @{$nat_network}{qw(ip mask)};
                for my $pair (@$filter_only) {
                    my ($i, $m) = @$pair;
                    ($mask >= $m && match_ip($ip, $i, $m)) or next;

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
    return;
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
            next if $network->{mask} > $mask;
            my $managed_hosts = $network->{managed_hosts} or next;
            push(
                @{ $aggregate->{managed_hosts} },
                grep { match_ip($_->{ip}, $ip, $mask) } @$managed_hosts
            );
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
    $zone->{is_tunnel}    and $aggregate->{is_tunnel}    = 1;
    $zone->{has_id_hosts} and $aggregate->{has_id_hosts} = 1;

    if ($zone->{disabled}) {
        $aggregate->{disabled} = 1;
    }

    # Store aggregate reference in global network hash
    else {
        push @networks, $aggregate;    # @networks provides all srcs/dsts
    }
    return;
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
    my ($ip, $mask) = split '/', $key;
    my $ipmask2aggregate = $zone->{ipmask2aggregate};

    # Collect all aggregates, networks and subnets of current zone.
    # Get aggregates in deterministic order.
    my @objects = @{$ipmask2aggregate}{ sort keys %$ipmask2aggregate };
    my $add_subnets;
    $add_subnets = sub {
        my ($network) = @_;
        my $subnets = $network->{networks} or return;
        push @objects, @$subnets;
        $add_subnets->($_) for @$subnets;
    };
    push @objects, @{ $zone->{networks} };
    $add_subnets->($_) for @{ $zone->{networks} };

    # Collect all objects being larger and smaller than new aggregate.
    my @larger  = grep { $_->{mask} < $mask } @objects;
    my @smaller = grep { $_->{mask} > $mask } @objects;

    # Find subnets of new aggregate.
    for my $obj (@smaller) {
        my ($i, $m) = @{$obj}{qw(ip mask)};
        match_ip($i, $ip, $mask) or next;

        # Ignore sub-subnets, i.e. supernet is smaller than new aggregate.
        if (my $up = $obj->{up}) {
            next if $up->{mask} >= $mask;
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
    for my $obj (sort { $a->{mask} < $b->{mask} } @larger) {
        my ($i, $m) = @{$obj}{qw(ip mask)};
        match_ip($ip, $i, $m) or next;
        $aggregate->{up} = $obj;

#        debug "$aggregate->{name} -up2-> $obj->{name}";
        last;
    }

    link_aggregate_to_zone($aggregate, $zone, $key);
    add_managed_hosts_to_aggregate($aggregate);
    return;
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
        my $key     = "$ip/$mask";
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
        if ($mask == 0) {
            for my $attr (qw(has_unenforceable owner nat 
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
    return;
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
    my $key = "$ip/$mask";

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
    return;
}

###############################################################################
# Find aggregate referenced from any:[..].
# Creates new anonymous aggregate if missing.
# If zone is part of a zone_cluster,
# return aggregates for each zone of the cluster.
sub get_any {
    my ($zone, $ip, $mask) = @_;
    my $key     = "$ip/$mask";
    my $cluster = $zone->{zone_cluster};
    if (!$zone->{ipmask2aggregate}->{$key}) {

        # Check, if there is a network with same IP as the requested
        # aggregate.  If found, don't create a new aggregate in zone,
        # but use the network instead. Otherwise {up} relation
        # wouldn't be well defined.
        if (
            my @networks = grep({ $_->{mask} == $mask && $_->{ip} == $ip }
                map { @{ $_->{networks} } } $cluster ? @$cluster : ($zone))
          )
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
    my $key = "$ip/$mask";
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
    $zone->{private} =
      $private1;    # TODO: is set in every iteration. else clause?

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
    return;
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
    push @$zone_aref, $zone if !$zone->{is_tunnel};
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
    return;
}

# Two zones are zone_eq, if
# - zones are equal or
# - both belong to the same zone cluster.
sub zone_eq {
    my ($zone1, $zone2) = @_;
    return (($zone1->{zone_cluster} || $zone1) eq
          ($zone2->{zone_cluster} || $zone2));
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
        if (!$obj->{is_tunnel}) {
            push @{ $area->{zones} }, $obj;
        }
    }
    elsif ($obj->{managed} || $obj->{routing_only}) {
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
    return;
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
                    || ref $r_val eq 'ARRAY'
                    && ref $val eq 'ARRAY'
                    && aref_eq($r_val, $val)
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
    return;
}

###############################################################################
# Purpose : Returns true if nat hashes are equal.
sub nat_equal {
    my ($nat1, $nat2) = @_;

    # Check whether nat attributes are different...
    for my $attr (qw(ip mask dynamic hidden identity)) {
        return if defined $nat1->{$attr} xor defined $nat2->{$attr};
        next if !defined $nat1->{$attr};  # none of the Nats holds the attribute
        return if $nat1->{$attr} ne $nat2->{$attr}; # values of attribute differ
    }

    # ...return true if no difference found.
    return 1;
}
##############################################################################
# Purpose : 1. Generate warning if NAT value of two objects hold the same
#              attributes.
#           2. Mark occurence of identity NAT that masks inheritance.
#              This is used later to warn on useless identity NAT.
sub check_useless_nat {
    my ($nat_tag, $nat1, $nat2, $obj1, $obj2) = @_;
    if (nat_equal($nat1, $nat2)) {
        warn_msg(
            "Useless nat:$nat_tag at $obj2->{name},\n",
            " it is already inherited from $obj1->{name}"
        );
    }
    if ($nat2->{identity}) {
        $nat2->{is_used} = 1;
    }
    return;
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
                check_useless_nat($nat_tag, $nat, $z_nat, $area, $zone);
                next;
            }

            # Store NAT definition in zone otherwise
            $zone->{nat}->{$nat_tag} = $nat;

#           debug "$zone->{name}: $nat_tag from $area->{name}";
        }
    }
    return;
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
    return;
}

###############################################################################
# Purpose  : Distributes NAT from aggregates and networks to other networks
#            in same zone, that are in subnet relation.
#            If a network A is subnet of multiple networks B < C,
#            then NAT of B is used.
sub inherit_nat_to_subnets_in_zone {
    my ($net_or_zone, $zone) = @_;
    my ($ip1, $mask1) =
      is_network($net_or_zone)
      ? @{$net_or_zone}{qw(ip mask)}
      : (0, 0);
    my $hash = $net_or_zone->{nat};
    for my $nat_tag (sort keys %$hash) {
        my $nat = $hash->{$nat_tag};

#        debug "inherit $nat_tag from $net_or_zone->{name}";

        # Distribute nat definitions to every subnet of supernet, aggregate or zone.
        for my $network (@{ $zone->{networks} }) {
            my ($ip2, $mask2) = @{$network}{qw(ip mask)};

            # Only process subnets.
            $mask2 > $mask1 or next;
            match_ip($ip2, $ip1, $mask1) or next;

            # Skip network, if NAT tag exists in network already...
            if (my $n_nat = $network->{nat}->{$nat_tag}) {

                # ... and warn if networks NAT value holds the
                # same attributes.
                check_useless_nat($nat_tag, $nat, $n_nat, $net_or_zone,
                    $network);
            }

            elsif ($network->{ip} eq 'bridged' and not $nat->{identity}) {
                err_msg(
                    "Must not inherit nat:$nat_tag at bridged",
                    " $network->{name} from $net_or_zone->{name}"
                );
            }

            # Copy NAT defintion; append name of network.
            else {
                my $sub_nat = {
                    %$nat,

                    # Needed for error messages.
                    name => "nat:$nat_tag($network->{name})",
                };

                # For static NAT from net_or_zone,
                # - merge IP from supernet and subnet,
                # - adapt mask to size of subnet
                if (not $nat->{dynamic}) {

                    # Take higher bits from NAT IP, lower bits from original IP.
                    $sub_nat->{ip} |= $ip2 & complement_32bit($mask1);
                    $sub_nat->{mask} = $mask2;
                }

                $network->{nat}->{$nat_tag} = $sub_nat;
            }
        }
    }
    return;
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
        for my $supernet (sort({ $b->{mask} <=> $a->{mask} } @nat_supernets),
            @nat_zone)
        {
            inherit_nat_to_subnets_in_zone($supernet, $zone);
        }
    }
    return;
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

sub cleanup_after_inheritance {

    # 1. Remove NAT entries from aggregates.
    #    These are only used during NAT inheritance.
    # 2. Remove identity NAT entries.
    #    These are only needed during NAT inheritance.
    for my $network (@networks) {
        my $href = $network->{nat} or next;
        if ($network->{is_aggregate}) {
            delete $network->{nat};
            next;
        }
        for my $nat_tag (keys %$href) {
            my $nat_network = $href->{$nat_tag};
            $nat_network->{identity} or next;
            delete $href->{$nat_tag};
            $nat_network->{is_used}
              or warn_msg("Useless identity nat:$nat_tag at $network->{name}");
        }
    }
    return;
}

sub inherit_attributes {
    inherit_attributes_from_area();
    inherit_nat_in_zone();
    check_attr_no_check_supernet_rules();
    cleanup_after_inheritance();
    return;
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
        push @zones, $zone;

        # Collect zone elements...
        set_zone1($network, $zone, 0);

        # Mark zone which consists only of a loopback network.
        $zone->{loopback} = 1
          if $network->{loopback} && @{ $zone->{networks} } == 1;

        # Attribute {is_tunnel} is set only when zone has only tunnel networks.
        if (@{ $zone->{networks} }) { # tunnel networks arent referenced in zone
            delete $zone->{is_tunnel};
        }

        # Remove zone reference from unmanaged routers (no longer needed).
        if (my $unmanaged = $zone->{unmanaged_routers}) {
            delete $_->{zone} for @$unmanaged;
        }

        # Remove private status, if 'public'
        if ($zone->{private} && $zone->{private} eq 'public') {
            delete $zone->{private};
        }
    }
    return;
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
    return;
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
    return;
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
                    "Invalid $attr of $area->{name}:\n - ",
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
    return;
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
            { @{ $a->{zones} } <=> @{ $b->{zones} }
                  || $a->{name} cmp $b->{name} }    #equal size? sort by name
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
                if (!$zone->{areas}->{$next}) {
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
    return;
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
                  $a->{name} cmp $b->{name}
            }    # equal size? sort by name
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
    return;
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
    return;
}

###############################################################################
# Purpose  : Create zones and areas.
sub set_zone {
    progress('Preparing security zones and areas');
    set_zones();
    cluster_zones();
    my $crosslink_routers = check_crosslink();      #TODO: place somewhere else?
    cluster_crosslink_routers($crosslink_routers);  #TODO: place somewhere else?
    my $has_inclusive_borders = prepare_area_borders();
    set_areas();
    find_area_subset_relations();
    check_routers_in_nested_areas($has_inclusive_borders);
    clean_areas();                                  # delete unused attributes
    link_aggregates();
    inherit_attributes();
    return;
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
                err_msg("Virtual IP of $v->{name}\n",
                    " must be located inside cyclic sub-graph");
                $err = 1;
            }
        }
        next if $err;

        # Check whether all virtual interfaces are part of the same loop.
        equal(map { $_->{loop} } @$related)
          or err_msg(
            "Virtual interfaces\n ",
            join(', ', map({ $_->{name} } @$related)),
            "\n must all be part of the same cyclic sub-graph"
          );
    }
    return;
}

####################################################################
# Check pathrestrictions
####################################################################
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
        next if !@$elements;

        my $deleted; # Flags whether interfaces have been deleted.
        my $invalid; # Flags whether pathrestriction is invalid. 
        my $prev_interface;
        my $prev_cluster;
        for my $interface (@$elements) {
            next if $interface->{disabled};
            my $router = $interface->{router};
            my $loop =
                 $interface->{loop}
              || $router->{loop}
              || $interface->{zone}->{loop};

            # This router is split part of an unmanaged router.
            # It has exactly two non secondary interfaces.
            # Move pathrestriction to other interface, if that one is
            # located at border of loop.
            if (my $other = $interface->{split_other} and not $loop) {
                my $rlist = delete $interface->{path_restrict};
                if ($loop = $other->{zone}->{loop}) {
#                   debug("Move $restrict->{name}", 
#                         " from $interface->{name} to $other->{name}");
                    $other->{path_restrict} = $rlist;
                    for my $restrict (@$rlist) {
                        my $elements = $restrict->{elements};
                        aref_subst($elements, $interface, $other);
                    }
                }
            }

            # Interfaces with pathrestriction need to be located
            # inside or at the border of cyclic graphs.
            if (not $loop) {
                delete $interface->{path_restrict};
                warn_msg("Ignoring $restrict->{name} at $interface->{name}\n",
                         " because it isn't located inside cyclic graph");
                $interface = undef; # No longer reference this interface.
                $deleted = 1;
                next;
            }

            # Interfaces must belong to same loop cluster.
            my $cluster = $loop->{cluster_exit};
            if ($prev_cluster) {
                if (not $cluster eq $prev_cluster) {
                    warn_msg("$restrict->{name} must not have elements",
                            " from different loops:\n",
                            " - $prev_interface->{name}\n",
                            " - $interface->{name}");
                    $invalid = 1;
                    last;
                }
            }
            else {
                $prev_cluster   = $cluster;
                $prev_interface = $interface;
            }
        }

        # Check whether pathrestriction is still valid. 
        if ($deleted) {
            $elements = $restrict->{elements} = [ grep { $_ } @$elements ];
            if (1 == @$elements) { # Min. 2 interfaces/path restriction needed! 
                $invalid = 1;
            }
        }

        # Remove invalid pathrestrictions. 
        if ($invalid) {
            $elements = $restrict->{elements} = [];
            next;
        }

        # Check for useless pathrestrictions that do not affect any ACLs...
        # Pathrestrictions at managed routers do most probably have an effect.
        grep({ $_->{router}->{managed} || $_->{router}->{routing_only} }
            @$elements)
          and next;

        # Pathrestrictions spanning different zone clusters have an effect.
        equal(map { $_->{zone_cluster} || $_ } map { $_->{zone} } @$elements)
          or next;

        # Pathrestrictions in loops with > 1 zone cluster have an effect.
        my $element      = $elements->[0];
        my $loop         = $element->{loop};
        my $zone         = $element->{zone};
        my $zone_cluster = $zone->{zone_cluster} || [$zone];

        # Process every zone in zone cluster...
        for my $zone1 (@$zone_cluster) {
            for my $interface (@{ $zone->{interfaces} }) {
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

        # Empty interface array of useless pathrestrictions
        warn_msg(
            "Useless $restrict->{name}.\n",
            " All interfaces are unmanaged and",
            " located inside the same security zone"
        );
        $restrict->{elements} = [];
    }

    # Collect all effective pathrestrictions.
    push @pathrestrictions, grep({ @{ $_->{elements} } } 
                                 values %pathrestrictions);

    return;
}

sub remove_redundant_pathrestrictions {

    # For each element E, find pathrestrictions that contain E.
    my %element2restrictions;
    for my $restrict (@pathrestrictions) 
    {
        my $elements = $restrict->{elements};
        for my $element (@$elements) {
            $element2restrictions{$element}->{$restrict} = $restrict;
        }
    }

    # Check all elements that occur in two or more pathrestrictions.
    # Check each restriction only once.
    my %seen;
    for my $elt_ref (keys %element2restrictions) {
        my $href = $element2restrictions{$elt_ref};
        my @list = sort({ @{ $a->{elements} } <=> @{ $b->{elements} } } 
                        values %$href);
        while (@list >= 2) {
            my $restrict = shift @list;
            next if $seen{$restrict}++;
            my $elements = $restrict->{elements};
            for my $element (@$elements) {
                next if $element eq $elt_ref;
                my $href2 = $element2restrictions{$element};
                my $intersection;
                for my $restrict2 (values %$href) {
                    next if $restrict2 eq $restrict;
                    if ($href2->{$restrict2}) {
                        $intersection->{$restrict2} = $restrict2;
                    }
                }
                $href = $intersection or last;
            }
            if ($href) {
                $restrict->{deleted} = 1;
                my ($other) = values %$href;
#                debug "$restrict->{name} < $other->{name}";
            }
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
            next if !$interface->{loop};
            my $next = $interface->{ $is_zone ? 'router' : 'zone' };
            traverse_loop_part($next, $interface, $mark, $lookup);
        }
    }
    return;
}

#############################################################################
# Purpose    : Analyze found partitions and optimize pathrestrictions.
# Parameters : $restrict - pathrestriction to optimize (hash reference)
#              $elements - interfaces of the pathrestriction (array reference)
#              $lookup - stores adjacent partitions for every IF in elements.
sub apply_pathrestriction_optimization {
    my ($restrict, $elements, $lookup) = @_;

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
        if (   $reached->{zone} eq $reached->{router}
            && $reached->{zone} ne 'none')
        {
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

    # Delete pathrestriction objects, if {reachable_at} holds entire info.
    if (!$has_interior) {   # Interfaces must not be located inside a partition.
        for my $interface (@$elements) {

            #debug "remove $restrict->{name} from $interface->{name}";
            aref_delete($interface->{path_restrict}, $restrict)
              or internal_err("Can't remove $restrict->{name}",
                " from $interface->{name}");

            # Delete empty array to speed up checks in cluster_path_mark.
            if (!@{ $interface->{path_restrict} }) {
                delete $interface->{path_restrict};
            }
        }
    }
    else {
#            debug "Can't opt. $restrict->{name}, has $has_interior interior";
    }
    return;
}

#############################################################################
# Purpose : Find partitions of loops that are separated by pathrestrictions.
#           Mark every node of a partition with a unique number that is
#           attached to the partitions routers and zones, and every
#           pathrestriction with a list of partitions that ca be reached.
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
                if (!$obj->{loop}) {
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

        # Optimize pathrestriction.
        if ($mark > $start_mark + 0) {    # Optimization needs 2 partitions min.
            apply_pathrestriction_optimization($restrict, $elements, $lookup);
        }
    }
    return;
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
#            nodes own distance values are later reset zo the value of the
#            cluster exit object. The intermediate value is required by
#            cluster_navigation to work.
sub setpath_obj;

sub setpath_obj {
    my ($obj, $to_zone1, $distance) = @_;

    #debug("--$distance: $obj->{name} --> ". ($to_zone1 && $to_zone1->{name}));

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
    @zones or fatal_err("Topology seems to be empty");
    my $path_routers = 
        [ grep { $_->{managed} || $_->{semi_managed} } @routers ];
    my $start_distance = 0;
    my @partitions;
    my %partition2split_crypto;
    my %router2partition;

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

    if (@unconnected > 1) {
        err_msg("Topology has unconnected parts:\n",
                " - ", 
                join "\n - ", map { $_->{name} } @unconnected);
    }
            
    return;
}

###############################################################################
# Purpose : Include node objects and interfaces of nested loops in the
#           containing loop; add loop cluster exits; adjust distances of
#           loop nodes.
sub process_loops {

    # Check all nodes located inside a cyclic graph.
    my @path_routers = grep { $_->{managed} || $_->{semi_managed} } @routers;
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
    return;
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
    return;
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
        if ($router->{managed} || $router->{semi_managed}) {

            # If this is a secondary interface, we can't use it to enter
            # the router, because it has an active pathrestriction attached.
            # But it doesn't matter if we use the main interface instead.
            my $main = $obj->{main_interface} || $obj;

            # Special handling needed if $src or $dst is interface
            # which has pathrestriction attached.
            if ($main->{path_restrict} || $main->{reachable_at}) {
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
        if ($obj->{managed} || $obj->{semi_managed}) {
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
        elsif ($object->{managed} || $object->{semi_managed}) {

            # This will be refined later, if real interface has pathrestriction.
            $result = $object;
        }
        else {

            # Take arbitrary interface to find zone.
            $result = $object->{interfaces}->[0]->{network}->{zone};
        }
    }

    else {
        internal_err("unexpected $obj->{name}");
    }

    #debug("get_path: $obj->{name} -> $result->{name}");
    return ($obj2path{$obj} = $result);
}

# When used as hash keys, Perl converts references to address strings - 
# this  hash is used to convert them back to references. 
my %key2obj;

##############################################################################
# Purpose    : Recursively find path through a loop or loop cluster for a 
#              given pair (start, end) of loop nodes, collect path information. 
# Parameters : $obj - current (or start) loop node (zone or router).
#              $in_intf - interface current loop node was entered from. 
#              $end - loop node that is to be reached.
#              $end_intf - dst interface, if it is a pathrestricted interface
#                          in or at border of current loop, undef otherwise.
#              $path_tuples - hash to collect in and out interfaces of nodes on
#                             detected path.
#              $loop_leave - array to collect last interfaces of loop path.
#              $navi - lookup hash to reduce search space, holds loops to enter.
# Returns   :  1, if path is found, 0 otherwise.
sub cluster_path_mark1 {
    my ($obj, $in_intf, $end, $end_intf, $path_tuples, $loop_leave, $navi) = @_;

    # Check if IF current node was entered at ($in_interface) is pathrestricted.
    my $pathrestriction = $in_intf->{path_restrict};
    my $reachable_at    = $in_intf->{reachable_at};

#    debug("cluster_path_mark1: obj: $obj->{name},
#           in_intf: $in_intf->{name} to: $end->{name}");

    # Stop path exploration when activated PR (2nd occurrence) was passed.
    if ($pathrestriction) {
        for my $restrict (@$pathrestriction) {
            if ($restrict->{active_path}) {
#           debug(" effective $restrict->{name} at $in_intf->{name}");
                return 0;
            }
        }
    }

    # Check optimized pathrestriction: is $end_intf reachable?
    # To achieve equal routes for every IP of a network, zone of 
    # $end_intf (instead of its router) must be reached to find a valid path.
    # As the interfaces zone can be located behind its router, which is the 
    # end node of the loop path, this test must be performed before checking
    # whether end node was reached and a path was found.   
    if ($reachable_at && $end_intf && 
        $end_intf ne $in_intf) { # Valid path found otherwise.  
        if (my $reachable = $reachable_at->{$obj}) {
            my $other = $end_intf->{zone};

            # If zone is located in loop, perform usual reachable check for it.
            if ($other->{loop}) {
                my $has_mark = $other->{reachable_part};
                for my $mark (@$reachable) {
                    if (!$has_mark->{$mark}) {

#                        debug(" unreachable: $other->{name}",
#                              " from $in_intf->{name} to $obj->{name}");
                        return 0;
                    }
                }
            }

            # If $end_intf is at border of loop, its zone might be located
            # outside of loop and no {reachable_part} is set at $other.
            # If partition starting at $in_intf also starts at $end_intf,
            # path to $other includes 2 pathrestrictions and is invalid.
            else {
                if (my $reachable_at2 = $end_intf->{reachable_at}) {
                    if (my $reachable2 =
                        $reachable_at2->{ $end_intf->{router} })
                    {
                        if (intersect($reachable, $reachable2)) {
#                            debug(" unreachable2: $other->{name}",
#                                  " from $in_intf->{name} to $obj->{name}");
                            return 0;
                        }
                    }
                }
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
    if ($reachable_at) {
        if (my $reachable = $reachable_at->{$obj}) {
            my $end_node = $end_intf ? $end_intf->{zone} : $end;#for consistency
            my $has_mark = $end_node->{reachable_part};
            for my $mark (@$reachable) {
                if (!$has_mark->{$mark}) {
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

    # Activate passed path restrictions.
    if ($pathrestriction) {
        for my $restrict (@$pathrestriction) {

#           debug(" enabled $restrict->{name} at $in_intf->{name}");
            $restrict->{active_path} = 1;
        }
    }

    my $get_next = is_router($obj) ? 'zone' : 'router';
    my $success = 0;

    # Fill hash for restoring references from hash key.
    $key2obj{$in_intf} = $in_intf;

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
                $next,        $interface,  $end, $end_intf,
                $path_tuples, $loop_leave, $navi
            )
          )
        {

            # ...collect path information.
            $key2obj{$interface} = $interface;
            $path_tuples->{$in_intf}->{$interface} = is_router($obj);
#	    debug(" loop: $in_intf->{name} -> $interface->{name}");
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
            $navi->{$from_loop}->{$from_loop} = 1; # TODO: Why not include exit?
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
            $navi->{$from_loop}->{$from_loop} = 1;# TODO: Why not include exit?

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
# Purpose    : Collect path information through a loop for a pair ($from,$to)
#              of loop nodes, store it at the object where loop paths begins.
# Parameters : $from - node (zone or router) loop cluster is entered at
#              $to - node (zone or router) loop cluster is left at.
#              $from_in - interface $from is entered at 
#              $to_out - interface $to is left at. 
#              $from_store - source node or interface reference, if source is a 
#                            pathrestricted interface.  
#              $to_store - destination node or interface reference, if 
#                          destination is a pathrestricted interface.
# Returns    : True if a valid path was found, False otherwise.
# Results    : Loop entering interface holds reference to where loop path 
#              information is stored (starting at node or pathrestricted IF
#              may lead to different paths). Referenced object holds loop path 
#              description.
sub cluster_path_mark {
    my ($from, $to, $from_in, $to_out, $from_store, $to_store) = @_;

    # This particular path through this sub-graph is already known.
    return 1 if $from_in->{path}->{$to_store};

    # Allow easy checks for whether source or destination are pathrestricted 
    # interfaces in or at border of current loop by setting these, if so.
    my ($start_intf, $end_intf);

    # Define objects to store path information in by setting these. 
    # Path may differ depending on whether loop entering IF is pathrestricted
    # or not. Storing path information in different objects respects this.
    my ($start_store, $end_store);

    # Set declared variables.
    if (is_interface($from_store) # Src is pathrestricted IF of $from loop node.
        and ($from_store->{router} eq $from or $from_store->{zone} eq $from))
    {
        $start_intf  = $from_store;
        $start_store = $from_store;
    }
     elsif ($from_in # Loop is entered from  pathrestricted interface.
        and ($from_in->{path_restrict} or $from_in->{reachable_at}))
    {
        $start_store = $from_in;
    }
    else {
        $start_store = $from;
    }

    if (is_interface($to_store) # Dst is pathrestricted IF of $to loop node.
        and ($to_store->{router} eq $to or $to_store->{zone} eq $to))
    {
        $end_intf  = $to_store;
        $end_store = $to_store;
    }
    elsif ($to_out # Loop is left at pathrestricted interface.
           and ($to_out->{path_restrict} or $to_out->{reachable_at})) {
        $end_store = $to_out;
    }
    else {
        $end_store = $to;
    }

    my $success         = 1;
    my $from_interfaces = $from->{interfaces};
#    debug("cluster_path_mark: $start_store->{name} -> $end_store->{name}");

    # Activate pathrestrictions at interface the loop is entered at.
    if (    $from_in
        and not $from_in->{loop} # Loop path is entered from outside loop via
        and (my $restrictions = $from_in->{path_restrict}) # pathrestricted IF
        and not $start_intf) # that is not source of path.
    {
        for my $restrict (@$restrictions) {# set flag for passed p-restrictions
            $restrict->{active_path} = 1;
        }
    }

    # Activate pathrestrictions at interface the loop is left at.
    if (    $to_out
        and not $to_out->{loop} # Loop path is left via
        and (my $restrictions = $to_out->{path_restrict}) # pathrestricted IF
        and not $end_intf) # that is not destination of path.
    {
        for my $restrict (@$restrictions) {

            # No path possible, if restriction was activated at in_interface.
            if ($restrict->{active_path}) {
                $success = 0;
            }
            $restrict->{active_path} = 1;
        }
    }

  # Check whether valid paths are possible due to optimized pathrestrictions.
  REACHABLE:
    {
        # If dst is a pathrestricted IF, consider it to be part of its zone. 
        # This guarantees equal routes for all IP addresses of a network. 
        my $end_node = $end_intf ? $end_intf->{zone} : $to;

        # If start-interface is directly connected to an $end_node zone, use
        # this direct path and ignore all other possible paths (=interfaces).
        if ($start_intf && $start_intf->{zone} eq $end_node) {
            $from_interfaces = [$start_intf];
            last REACHABLE;
        }

        # Check, whether enter-/start-interface has optimized pathrestriction. 
        my $intf = $start_intf || $from_in;
        my $reachable_at = $intf->{reachable_at}        or last REACHABLE;

        # Check, whether end node is reachable from enter-/start-interface.
        # For enter-interfaces, just the direction towards loop is of interest,
        # for start-interfaces, pathrestrictions in zone direction do not hold,
        # hence check router direction only.
        # Only one direction needs to be checked in both cases.
        my $start_node = $start_intf ? $start_intf->{router} : $from;
        my $reachable    = $reachable_at->{$start_node} or last REACHABLE;
        my $has_mark     = $end_node->{reachable_part};
        for my $mark (@$reachable) {

            # End node is not reachable via enter-/start-interface.
            if (!$has_mark->{$mark}) {

                # For start-interfaces, path in zone direction might exist.
                if ($start_intf) {                    
                    $from_interfaces = [$start_intf];# Ignore all other IFs.
                }

                # For enter-interfaces, no valid path is possible.
                else {
                    $success = 0;
                }
                last;
            }
        }

        # For start-IF, temporarily disable optimized PRs in direction to zone.
        if ($success && $start_intf) {
            my $zone = $start_intf->{zone};
            $intf->{saved_reachable_at_zone} = delete $reachable_at->{$zone};
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
            if (!$has_mark->{$mark}) {
                $success = 0;
                last;
            }
        }
    } # end REACHABLE_TO_OUT

    # If start-/end- interface is part of a group of virtual interfaces 
    # (VRRP, HSRP), prevent traffic through other interfaces of this group
    # by temporarily adding activated pathrestrictions at redundancy interfaces.
    for my $intf ($start_intf, $end_intf) {
        next if !$intf;
        if (my $interfaces = $intf->{redundancy_interfaces}) {
            for my $interface (@$interfaces) {
                next if $interface eq $intf;
                push @{ $interface->{path_restrict} },
                  $global_active_pathrestriction;
            }
        }
    }

    # For start-/end interfaces (path starts or ends at an interface
    # with pathrestriction), pathrestrictions are required to be activated 
    # in router, not in zone direction. The basic algorithm starts path 
    # exploration at the router of such an interface though. Per default, 
    # path restriction activation is therefore contrary to the requirements.
    # To fix this, pathrestrictions are temporarily moved from the start-/end 
    # interface to the other interfaces of the router. 
    # TODO: How about activating the pathrestrictions and temporarily 
    # deleting it from the interface? Or let exploration start at the 
    # interfaces zone in this case (would lead to a gap within the marked path)?
    for my $intf ($start_intf, $end_intf) {
        next if !$intf;

        # Check whether from/to node is router of start-/and-interface
        my $router = $intf->{router};
        next if !($router eq $from || $router eq $to);

        # Delete pathrestriction from start/end interface 
        my $removed = delete $intf->{path_restrict} or next;
        $intf->{saved_path_restrict} = $removed;

        # Move pathrestriction to other interfaces of router.
        for my $interface (@{ $router->{interfaces} }) {
            next if $interface eq $intf;

            # Check whether pathrestrictions are defined for these IFs. 
            my $orig = $interface->{saved_path_restrict} =
              $interface->{path_restrict};
            if ($orig) {
 
                # If pathrestrictions exist in both IF and start-/end-interface,
                # prohibit path by adding activated global pathrestriction.
                # TODO: what about just excluding IF from from-IFs?
                if (intersect($orig, $removed)) {
                    $interface->{path_restrict} =
                      [$global_active_pathrestriction];
                }

                # Otherwise, add pathrestrictions to interface.
                else {
                    $interface->{path_restrict} = [ @$orig, @$removed ];
                }
            }
            else {
                $interface->{path_restrict} = $removed;
            }
        }
    }

  # Find loop paths via DFS.
  BLOCK:
    {
        last BLOCK if not $success; # No valid path due to pathrestrictions.
        $success = 0;

        # Collect path information at beginning of loop path ($start_store).
        # Loop paths beginning at loop node can differ depending on the way
        # the node is entered (interface with/without pathrestriction,
        # pathrestricted src/dst interface), requirings storing path 
        # information at different objects.
        # {loop_entry} attribute shows, where path information can be found.
        $from_in->{loop_entry}->{$to_store}    = $start_store;# node or IF w. PR
        $start_store->{loop_exit}->{$to_store} = $end_store;

        # Path from $start_store to $end_store has been marked already.
        if ($start_store->{loop_enter}->{$end_store}) {
            $success = 1;
            last BLOCK;
        }

        # Create variables to store the loop path. 
        my $loop_enter  = [];# Interfaces of $from, where path enters cluster.
        my $path_tuples = {};# Tuples of interfaces, describing all valid paths.
        my $loop_leave  = [];# Interfaces of $to, where cluster is left.
        
        # Create navigation look up hash to reduce search space in loop cluster.
        my $navi = cluster_navigation($from, $to)
          or internal_err("Empty navi");

        # Mark current path for loop detection.
        local $from->{active_path} = 1;
        my $get_next = is_router($from) ? 'zone' : 'router';
        my $allowed = $navi->{ $from->{loop} }
          or internal_err("Loop $from->{loop}->{exit}->{name}$from->{loop}",
            " with empty navi");

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
                    $next,        $interface,  $to, $end_intf,
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

        # Convert $path_tuples: {intf->intf->node_type} to [intf,intf,node_type]
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

        # Remove duplicates, which occur from nested loops.
        $loop_leave = [ unique(@$loop_leave) ];

        # Add loop path information to start node or interface.
        $start_store->{loop_enter}->{$end_store}  = $loop_enter;
        $start_store->{loop_leave}->{$end_store}  = $loop_leave;
        $start_store->{path_tuples}->{$end_store} = $tuples_aref;

        # Add data for reverse path.
        $end_store->{loop_enter}->{$start_store} = $loop_leave;
        $end_store->{loop_leave}->{$start_store} = $loop_enter;
        $end_store->{path_tuples}->{$start_store} =
          [ map { [ @{$_}[ 1, 0, 2 ] ] } @$tuples_aref ];
    }

    # Restore temporarily moved path restrictions.
    for my $intf ($start_intf, $end_intf) {
        next if !$intf;
        next if !$intf->{saved_path_restrict};
        my $router = $intf->{router};
        for my $interface (@{ $router->{interfaces} }) {
            if (my $orig = delete $interface->{saved_path_restrict}) {
                $interface->{path_restrict} = $orig;
            }
            else {
                delete $interface->{path_restrict};
            }
        }
    }

    # Restore temporarily deleted optimized pathrestrictions.
    if ($start_intf) {
        if (my $orig = delete $start_intf->{saved_reachable_at_zone}) {
            my $zone = $start_intf->{zone};
            $start_intf->{reachable_at}->{$zone} = $orig;
        }
    }

    # Remove temporarily added activated pathrestrictions at redundancy IFs. 
    for my $intf ($start_intf, $end_intf) {
        next if !$intf;
        if (my $interfaces = $intf->{redundancy_interfaces}) {
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

    # If loop path was found, set path information at $from_in and $to_out IFs.
    # TODO: Needed only if paths meet in loop, otherwise path_mark sets these.
    if ($success) {
        $from_in->{path}->{$to_store} = $to_out; 
    }
    return $success;
}

##############################################################################
# Purpose   : Find and mark path from an elementary rules source to its 
#             destination.   
# Parameter : $from - zone or router corresponding to elementary rules source
#             $to - zone or router corresponding to the rules destination
#             $from_store - $from or interface reference, if source is a 
#                           pathrestricted interface  
#             $to_store - $to or interface reference, if destination is a 
#                         pathrestricted interface 
# Returns   : True if valid path is found, False otherwise.
# Results   : A reference to the next interface towards destination is stored
#             in the {path} hash attribute of the source or its corresponding 
#             zone/router and every interface object on path.
sub path_mark {
    my ($from, $to, $from_store, $to_store) = @_;

#    debug("path_mark $froma_store->{name} --> $to_store->{name}");

    my $from_loop = $from->{loop};
    my $to_loop = $to->{loop};

    # Identify first and last object on path to hold path information.
    # Outside a loop, path marks are always stored in the corresponding router 
    # object. Paths beginning at pathrestricted interfaces in loops can be 
    # different though from the paths that are found for the associated router, 
    # as in such cases, the interface is considered to be part of the zone 
    # to achieve equal routing for all interfaces of a network. 
    # To distinguish the different paths, path information is stored within
    # the interface in such cases (otherwise it is stored within router).
    my $from_in = $from_store->{loop} ? $from_store : $from; # Src obj. to mark
    my $to_out = undef; # No subsequent interface for last interface on path.

    # Follow paths from source and destination towards zone1 until they meet.
    while (1) {
# debug("Dist: $from->{distance} $from->{name} ->Dist: $to->{distance} $to->{name}");

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
            return cluster_path_mark($from, $to, $from_in, $to_out,
                                     $from_store, $to_store);
        }

        # Otherwise, take a step towards zone1 from the more distant node.
        if ($from->{distance} >= $to->{distance}) { # Take step from node $from.

            # Return, if mark has already been set for a sub-path.
            return 1 if $from_in->{path}->{$to_store};
 
            # Get interface towards zone1.
            my $from_out = $from->{to_zone1};

            # If from is a loop node, mark whole loop path within this step. 
            unless ($from_out) {

                # Reached border of graph partition.
                return 0 if !$from_loop;

                # Get next interface behind loop from loop cluster exit.
                my $exit = $from_loop->{cluster_exit};
                $from_out = $exit->{to_zone1};

                # Reached border of graph partition.
                return 0 if !$from_out;
                
                # Mark loop path towards next interface.
                cluster_path_mark($from, $exit, $from_in, $from_out,
                    $from_store, $to_store)
                  or return 0;
            }

#         debug(" $from_in->{name} -> ".($from_out ? $from_out->{name}:''));
            # Mark path at the interface we came from (step in path direction)
            $from_in->{path}->{$to_store} = $from_out; #ref to next path IF

            # Go to next node towards zone1.
            $from_in                      = $from_out;
            $from                         = $from_out->{to_zone1};
            $from_loop                    = $from->{loop};
        }

        # Take step towards zone1 from node $to (backwards on path).
        else {
            # Get interface towards zone1.
            my $to_in = $to->{to_zone1};

            # If to is a loop node, mark whole loop path within this step.
            unless ($to_in) {

                # Reached border of graph partition.
                return 0 if !$to_loop;

                # Get next interface behind loop from loop cluster exit.
                my $entry = $to_loop->{cluster_exit};
                $to_in = $entry->{to_zone1};

                # Reached border of graph partition.
                return 0 if !$to_in;

                # Mark loop path towards next interface.
                cluster_path_mark($entry, $to, $to_in, $to_out, $from_store,
                    $to_store)
                  or return 0;
            }

#             debug(" $to_in->{name} -> ".($to_out ? $to_out->{name}:''));
            # Mark path at interface we go to (step in opposite path direction).
            $to_in->{path}->{$to_store} = $to_out;

            # Go to next node towards zone1.
            $to_out                     = $to_in;
            $to                         = $to_in->{to_zone1};
            $to_loop                    = $to->{loop};
        }
    }
    return 0;    # unused; only for perlcritic
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
    my $path_tuples = $loop_entry->{path_tuples}->{$loop_exit};

#    debug(" loop_tuples");
    for my $tuple (@$path_tuples) {
        my ($in_intf, $out_intf, $at_router) = @$tuple;
        $fun->($rule, $in_intf, $out_intf)
          if $at_router xor $call_at_zone;
    }

    # Process paths at exit of cyclic graph.
    my $exit_type = ref $loop_exit;
    my $exit_at_router = $exit_type eq 'Router'
      || ($exit_type eq 'Interface'
        && $loop_exit->{router} eq
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

    # Extract path node objects (zone/router/pathrestricted interface).
    my $from_store = $rule->{src_path};
    my $to_store   = $rule->{dst_path};

    # If path node is a pathrestricted interface, extract router. 
    my $from       = $from_store->{router} || $from_store;
    my $to         = $to_store->{router}   || $to_store;

    # Get access to stored paths - for pathrestricted IFs, take IF path store
    # (allowed paths may differ from those of the associated router).
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

    # Perform consistency checks.
    $from and $to or internal_err(print_rule $rule);
    $from eq $to and internal_err("Unenforceable:\n ", print_rule $rule);

    # Identify path from source to destination if not known.
    if (not exists $path_store->{path}->{$to_store}) {
        if (!path_mark($from, $to, $from_store, $to_store)) { # Find path.

            # Break, if path does not exist.
            err_msg(
                "No valid path\n",
                " from $from_store->{name}\n",
                " to $to_store->{name}\n",
                " for rule ",
                print_rule($rule),
                "\n",
                " Check path restrictions and crypto interfaces."
            );
            delete $path_store->{path}->{$to_store};
            return;
        }
    }

    # Set switch whether to call function at first node visited (in 1.iteration)
    my $at_zone = $where && $where eq 'Zone'; # 1, if func is called at zones. 
    my $call_it = (is_router($from) xor $at_zone); # Set switch accordingly. 

    my $in = undef;
    my $out;

    # If Path starts inside cyclic graph or at IF of router inside cyclic graph.
    if (    $from->{loop}
        and $from_store->{loop_exit} # Path exists for start node, leading to...
        and my $loop_exit = $from_store->{loop_exit}->{$to_store}) # ...dst.
    {
        my $loop_out = $path_store->{path}->{$to_store};

        # ... walk loop path first.
        my $exit_at_router =
          loop_path_walk($in, $loop_out, $from_store, $loop_exit, $at_zone,
            $rule, $fun);

        if (not $loop_out) {
#           debug("exit: path_walk: dst in loop");
            return;
        }

        # Then prepare to begin with path behind loop.
        $call_it = not($exit_at_router xor $at_zone);
        $in      = $loop_out;
        $out     = $in->{path}->{$to_store};
    }
    else {
        $out = $path_store->{path}->{$to_store};
    }

    # Start walking path. 
    while (1) {

        # Path continues with loop: walk whole loop path in this iteration step.
        if (    $in
            and $in->{loop_entry} # In interface is entry to a loop path...
            and my $loop_entry = $in->{loop_entry}->{$to_store}) # ...to dest.
        {
            my $loop_exit = $loop_entry->{loop_exit}->{$to_store};# exit object.
            my $loop_out  = $in->{path}->{$to_store};# exit interface

            my $exit_at_router = # last node of loop is a router ? 1 : 0 
              loop_path_walk($in, $loop_out, $loop_entry, $loop_exit,
                $at_zone, $rule, $fun); # Process whole loop path.
 
            # End of path has been reached.
            if (not $loop_out) {

#               debug("exit: path_walk: reached dst in loop");
                return;
            }

            # Prepare next iteration step.
            $call_it = not($exit_at_router xor $at_zone);
            $in      = $loop_out;
            $out     = $in->{path}->{$to_store};
        }

        # Non-loop path continues - call function, if switch is set.
        else {
            if ($call_it) {
                $fun->($rule, $in, $out);
            }

            # Return, if end of path has been reached.
            if (not $out) {
#               debug("exit: path_walk: reached dst");
                return;
            }
            
            # Prepare next iteration otherwise.
            $call_it = !$call_it;
            $in      = $out;
            $out     = $in->{path}->{$to_store};
        }
    }
    return;
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
    my $reach_from_border;
    $reach_from_border = sub {
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
                $reach_from_border->($out_net, $out_intf, $result);
            }
        }
    };
    my $result = {};
    $reach_from_border->($border->{network}, $border, $result);
    for my $aref (values %$result) {
        $aref = [ unique @$aref ];
    }
    $border2obj2auto{$border} = $result;
    return;
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
            grep { $_->{path_restrict} || $_->{reachable_at} } @interfaces);
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

            my $from = $from_store->{router} || $from_store;
            my $to   = $to_store->{router}   || $to_store;

            if (!$from_store->{path}->{$to_store}) {
                if (!path_mark($from, $to, $from_store, $to_store)) {
                    delete $from_store->{path}->{$to_store};
                    next;
                }
            }
            if ($from_store->{loop_exit}
                and my $exit = $from_store->{loop_exit}->{$to_store})
            {
                my $enter = $from_store->{loop_enter}->{$exit};
                if (is_interface($from_store)) {

                    # Path is only ok, if it doesn't traverse
                    # corrensponding router.
                    my $path_ok;

                    # Path starts inside loop.
                    # Check if some path doesn't traverse current router.
                    # Then interface is ok as [auto] interface.
                    if ($from_store->{loop}) {
                        if (grep { $_ eq $from_store } @$enter) {
                            $path_ok = 1;
                        }   
                    }

                    # Otherwise path starts at border of loop.
                    # If node inside the loop is a zone, then node
                    # outside the loop is a router and interface is ok
                    # as [auto] interface.
                    elsif(not $from->{loop}) {
                        $path_ok = 1;
                    }
                    push @result, $from_store if $path_ok;
                }
                elsif (not is_router($from)) {
                    push @result, map { auto_intf_in_zone($_, $src2) } @$enter;
                }
                else {                    
                    push @result, @$enter;
                }
            }
            else {
                my $next = $from_store->{path}->{$to_store};
                if (is_interface($from_store)) {
                    if ($next and $next->{router} ne $from) {
                        push @result, $from_store;
                    }
                }
                elsif (not is_router($from)) {
                    push @result, auto_intf_in_zone($next, $src2);
                }
                else {
                    push @result, $next;
                }
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
    return;
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
    return;
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
        $real_spokes = [ grep { !$_->{disabled} } @$real_spokes ];
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
                err_msg "Must not use $has_id_hosts->{name} with ID hosts",
                  " together with networks having no ID host: ",
                  join(',', map { $_->{name} } @other);
            }

            if ($spoke_router->{managed} && $crypto->{detailed_crypto_acl}) {
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
    return;
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
    return;
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
    return;
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
    return;
}

sub expand_crypto {
    progress('Expanding crypto rules');

    my %id2interface;

    for my $crypto (values %crypto) {
        my $name    = $crypto->{name};
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
                my @encrypted;
                my $has_id_hosts;
                my $has_other_network;
                my @verify_radius_attributes;

                # Analyze cleartext networks behind spoke router.
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
                        push @verify_radius_attributes, $network;

                        # Must not have multiple networks.
                        @all_networks > 1 and internal_err();

                        # Rules for single software clients are stored
                        # individually at crypto hub interface.
                        for my $host (@{ $network->{hosts} }) {
                            my $id = $host->{id};

                            # ID host has already been checked to have
                            # exacly one subnet.
                            my $subnet = $host->{subnets}->[0];
                            push @verify_radius_attributes, $host;
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

                my $real_spoke = $tunnel_intf->{real_interface};
                $peer->{peer_networks} = \@encrypted;
                my $hub_router = $peer->{router};
                my $do_auth = $hub_router->{model}->{do_auth};
                if ($tunnel_intf->{id}) {
                    $need_id
                      or err_msg(
                        "Invalid attribute 'id' at",
                        " $tunnel_intf->{name}.\n",
                        " Set authentication=rsasig at",
                        " $isakmp->{name}"
                      );
                }
                elsif ($encrypted[0]->{has_id_hosts}) {
                    $do_auth
                      or err_msg(
                        "$hub_router->{name} can't check IDs",
                        " of $encrypted[0]->{name}"
                      );
                }
                elsif ($do_auth) {
                    err_msg(
                        "Networks need to have ID hosts because",
                        " $hub_router->{name} has attribute 'do_auth':",
                        "\n - ",
                        join("\n - ", map { $_->{name} } @encrypted)
                    );
                }
                elsif ($need_id) {
                    err_msg(
                        "$tunnel_intf->{name}",
                        " needs attribute 'id',",
                        " because $isakmp->{name}",
                        " has authentication=rsasig"
                    );
                }

                if ($peer->{router}->{model}->{crypto} eq 'ASA_VPN') {
                    for my $obj (@verify_radius_attributes) {
                        verify_asa_vpn_attributes($obj);
                        if (is_host($obj)) {
                            verify_subject_name($obj, $peer);
                        }
                    }
                }

                if ($managed && $router->{model}->{crypto} eq 'ASA') {
                    verify_asa_trustpoint($hub_router, $crypto);
                }

                # Add rules to permit crypto traffic between
                # tunnel endpoints.
                # If one tunnel endpoint has no known IP address,
                # some rules have to be added manually.
                if (    $real_spoke
                    and $real_spoke->{ip} !~ /^(?:short|unnumbered)$/)
                {
                    my $hub = $tunnel_intf->{peer};
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
                          gen_tunnel_rules($intf1, $intf2, $crypto->{type});
                        push @{ $path_rules{permit} }, @$rules_ref;
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
    return;
}

# Hash for converting a reference of an object back to this object.
my %ref2obj;

sub setup_ref2obj {
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
        next if $nat_network->{hidden};
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

    my $service = $rule->{rule}->{service};
    return if $missing_supernet{$interface}->{$service};

    my $supernet = $rule->{$where}->[0];
    my $networks = find_matching_supernet($interface, $zone, $supernet);
    return if not $networks;
    my $extra;
    if (!ref($networks)) {
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
    my $print =
      $config->{check_supernet_rules} eq 'warn' ? \&warn_msg : \&err_msg;
    $print->(
        "Missing rule for ${reversed}supernet rule.\n",
        " $rule\n",
        " can't be effective at $interface->{name}.\n",
        " $extra as $where."
    );
    return;
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

    # Destination is interface of current router and therefore there is
    # nothing to be checked.
    return unless $out_intf;

    # Ignore semi_managed router.
    my $router  = $in_intf->{router};
    my $managed = $router->{managed} or return;

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
    my $out_zone = $out_intf->{zone};

    # Check if reverse rule would be created and would need additional rules.
    if ($router->{model}->{stateless} 
        and not $rule->{oneway}
        and grep { $_->{proto} =~ /^(?:tcp|udp|ip)$/ } @{ $rule->{prt} })

    {

        # Reverse rule wouldn't allow too much traffic, if a non
        # secondary stateful device filters between current device and dst.
        # This is true if $out_zone and $dst_zone have different
        # {stateful_mark}.
        # If dst is interface or router, {stateful_mark} is undef
        # - if device is semi_managed or secondary managed, 
        #   take mark of attached network
        # - else take value -1, different from all marks.
        # $src is supernet (not an interface) by definition
        # and hence $m1 is well defined.
        my $m1 = $out_zone->{stateful_mark};
        my $m2 = $dst_zone->{stateful_mark};
        if (!$m2) {
            if (is_router($dst_zone)) {
                my $managed = $dst_zone->{managed};
                $m2 = ($managed =~ /^(?:secondary|local.*)$/)
                    ? $dst_zone->{interfaces}->[0]->{network}->{zone}
                               ->{stateful_mark}
                    : -1;
            }
            else {
                my $managed = $dst_zone->{router}->{managed};
                $m2 = ($managed =~ /^(?:secondary|local.*)$/)
                    ? $dst_zone->{network}->{zone}->{stateful_mark}
                    : -1;
            }
        }
        if ($m1 == $m2) {

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
                    next if $intf->{loopback} && !$intf->{vip};

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
        next if $intf->{loopback} && !$intf->{vip};

        # Don't check interface where src or dst is attached.
        my $zone = $intf->{zone};
        next if zone_eq($zone, $src_zone);
        next if zone_eq($zone, $dst_zone);
        next if zone_eq($zone, $in_zone);
        next if $intf->{main_interface};
        check_supernet_in_zone($rule, 'dst', $in_intf, $zone);
    }
    return;
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
# Currently we only check aggregates/supernets with mask = 0.
# Checking of other aggregates is too complicate (NAT, intersection).

# Collect info about unwanted implied rules.
sub check_transient_supernet_rules {
    my $rules = $service_rules{permit};

    # Build mapping from supernet to service rules having supernet as src.
    my %supernet2rules;
    for my $rule (@$rules) {
        next if $rule->{no_check_supernet_rules};
        my $src_list = $rule->{src};
        for my $obj (@$src_list) {
            $obj->{has_other_subnet} or next;

            # Check only 0/0 aggregates.
            $obj->{mask} == 0 or next;

            push @{ $supernet2rules{$obj} }, $rule;
        }
    }
    keys %supernet2rules or return;

    my $print = $config->{check_transient_supernet_rules} eq 'warn'
              ? \&warn_msg
              : \&err_msg;

    # Search rules having supernet as dst.
    for my $rule1 (@$rules) {
        next if $rule1->{no_check_supernet_rules};
        my $dst_list = $rule1->{dst};
        for my $obj (@$dst_list) {
            $obj->{has_other_subnet} or next;
            $obj->{mask} == 0 or next;

            # A leaf security zone has only one interface.
            # It can't lead to unwanted rule chains.
            next if @{ $obj->{zone}->{interfaces} } <= 1;

            my $other_rules = $supernet2rules{$obj} or next;
            for my $rule2 (@$other_rules) {
                match_prt_list($rule1->{prt}, $rule2->{prt}) or next;
                match_prt($rule1->{src_range} || $prt_ip,
                          $rule2->{src_range} || $prt_ip) or next;

                # Found transient rules $rule1 and $rule2.
                # Check, that 
                # - either src elements of $rule1 are also src of $rule2
                # - or dst elements of $rule2 are also dst of $rule1,
                # - but no problem if src1 and dst2 are located in same zone,
                #   i.e. transient traffic back to src,
                # - also need to ignore unenforceable $rule1 and $rule2.
                my $src_list1 = $rule1->{src};
                my $dst_list1 = $rule1->{dst};
                my $src_list2 = $rule2->{src};
                my $dst_list2 = $rule2->{dst};
                if (not (subset_of($src_list1, $src_list2) or
                         subset_of($dst_list2, $dst_list1))
                    and not elements_in_one_zone($src_list1, $dst_list2)
                    and not elements_in_one_zone($src_list1, [ $obj ])
                    and not elements_in_one_zone([ $obj ], $dst_list2))
                {
                    my $srv1 = $rule1->{rule}->{service}->{name};
                    my $srv2 = $rule2->{rule}->{service}->{name};
                    my $match = $obj->{name};
                    $print->("Missing transient supernet rules\n",
                             " between src of $srv1 and dst of $srv2,\n",
                             " matching at $match");
                }
            }
        }
    }
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
    return;
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
    return;
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
        my $deny = $rule->{deny};

        my $prt_group = $rule->{prt};
        my @new_prt_group;
        for my $prt (@$prt_group) {
            my $proto = $prt->{proto};
            next unless $proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip';

            # No reverse rules will be generated for denied TCP packets, 
            # because
            # - there can't be an answer if the request is already denied and
            # - the 'established' optimization for TCP below would produce
            #   wrong results.
            next if $proto eq 'tcp' and $deny;
            push @new_prt_group, $prt;
        }
        @new_prt_group or next;

        # Check path for existence of stateless router.
        my $src_path             = $rule->{src_path};
        my $dst_path             = $rule->{dst_path};
        my $has_stateless_router = $cache{$src_path}->{$dst_path};
        if (!defined $has_stateless_router) {
          PATH_WALK:
            {

                # Local function called by path_walk.
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
        my %key2prt_group;
        my $index = 1;
        my %src_range2index;
        my %index2src_range;
        my $tcp_seen;
        for my $prt (@new_prt_group) {
            my $proto = $prt->{proto};
            my $new_src_range = $prt_ip;
            my $new_prt;
            if ($proto eq 'tcp') {

                # Create tcp established only once.
                next if $tcp_seen;
                $new_prt = $range_tcp_established;
                $tcp_seen = 1;
            }
            elsif ($proto eq 'udp') {

                # Swap src and dst range.
                $new_src_range = $prt;
                if ($new_src_range->{range} eq $aref_tcp_any) {
                    $new_src_range = $prt_ip;
                }
                $new_prt = $rule->{src_range};
                if (not $new_prt) {
                    $new_prt = $prt_udp->{dst_range};
                }
            }
            elsif ($proto eq 'ip') {
                $new_prt = $prt;
            }
            else {
                internal_err();
            }
            $index2src_range{$index} = $new_src_range;
            my $key = $src_range2index{$new_src_range} ||= $index++;
            push @{ $key2prt_group{$key} }, $new_prt;
        }
       
        for my $key (sort numerically keys %key2prt_group) {
            my $prt_group = $key2prt_group{$key};
            my $src_range = $index2src_range{$key};
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
    return;
}

sub gen_reverse_rules {
    progress('Generating reverse rules for stateless routers');
    for my $type ('deny', 'permit') {
        gen_reverse_rules1($path_rules{$type});
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
    return;
}

# Mark security zone $zone with $mark and
# additionally mark all security zones
# which are connected with $zone by non-primary packet filters.
# Test for {active_path} has been added to prevent deep recursion.
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
    return;
}

# Set 'local_secondary_mark' for secondary optimization inside one cluster.
# Two zones get the same mark if they are connected by local_secondary router.
sub mark_local_secondary;

sub mark_local_secondary {
    my ($zone, $mark) = @_;
    $zone->{local_secondary_mark} = $mark;

#    debug "local_secondary $zone->{name} : $mark";
    for my $in_interface (@{ $zone->{interfaces} }) {
        next if $in_interface->{main_interface};
        my $router = $in_interface->{router};
        if (my $managed = $router->{managed}) {
            next if $managed ne 'local_secondary';
        }
        next if $router->{local_secondary_mark};
        $router->{local_secondary_mark} = $mark;
        for my $out_interface (@{ $router->{interfaces} }) {
            next if $out_interface eq $in_interface;
            next if $out_interface->{main_interface};
            my $next_zone = $out_interface->{zone};
            next if $next_zone->{local_secondary_mark};
            mark_local_secondary($next_zone, $mark);
        }
    }
    return;
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

sub have_set_and_equal_marks {
    my ($src_zones, $dst_zones, $mark) = @_;
    my $src_marks = [ map { $_->{$mark} or return; } @$src_zones ];
    my $dst_marks = [ map { $_->{$mark} or return; } @$dst_zones ];
    return equal(@$src_marks, @$dst_marks);
}

sub mark_secondary_rules {
    progress('Marking rules for secondary optimization');

    my $secondary_mark        = 1;
    my $primary_mark          = 1;
    my $local_secondary_mark  = 1;
    for my $zone (@zones) {
        if (not $zone->{secondary_mark}) {
            mark_secondary $zone, $secondary_mark++;
        }
        if (not $zone->{primary_mark}) {
            mark_primary $zone, $primary_mark++;
        }
        if (not $zone->{local_secondary_mark}) {
            mark_local_secondary($zone, $local_secondary_mark++);
        }
    }

    # Mark only permit rules for secondary optimization.
    # Don't modify a deny rule from e.g. tcp to ip.
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
        }
        elsif (have_set_and_equal_marks($src_zones, $dst_zones, 'local_mark') and
               have_different_marks($src_zones, $dst_zones, 
                                    'local_secondary_mark')) 
        {
            $rule->{some_non_secondary} = 1;
        }
        if (have_different_marks($src_zones, $dst_zones, 'primary_mark')) {
            $rule->{some_primary} = 1;
        }
    }
    return;
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

# 1. Check for invalid rules accessing hidden objects.
# 2. Check host rule with dynamic NAT.
# 3. Check for partially applied hidden or dynamic NAT on path.
sub check_dynamic_nat_rules {
    progress('Checking rules with hidden or dynamic NAT');

    # Collect hidden or dynamic NAT tags.
    my %is_dynamic_nat_tag;
    for my $network (@networks) {
        my $href = $network->{nat} or next;
        for my $nat_tag (keys %$href) {
            my $nat_network = $href->{$nat_tag};
            $nat_network->{dynamic} and $is_dynamic_nat_tag{$nat_tag} = 1;
        }
    }

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

    # Check path for inversed hidden or dynamic NAT.
    my $check_dyn_nat = sub {
        my ($rule, $in_intf, $out_intf) = @_;
        my $no_nat_set1 = $in_intf  ? $in_intf->{no_nat_set}  : undef;
        my $no_nat_set2 = $out_intf ? $out_intf->{no_nat_set} : undef;
        for my $nat_tag (keys %is_dynamic_nat_tag) {
            if ($no_nat_set1) {
                $no_nat_set1->{$nat_tag}
                  or push @{ $rule->{active_nat_at}->{$nat_tag} }, $in_intf;
            }
            if ($no_nat_set2) {
                $no_nat_set2->{$nat_tag}
                  or push @{ $rule->{active_nat_at}->{$nat_tag} }, $out_intf;
            }
        }
    };

    # Remember, if pair of src object and destination no_nat_set
    # already has been processed.
    my %seen;

    # Remember, if path has already been checked for inversed dynamic NAT.
    my %cache;

    my $check_dyn_nat_path = sub {
        my ($path_rule, $obj, $other, $reversed) = @_;

        my $network    = $obj->{network} || $obj;
        my $nat_hash   = $network->{nat} or return;
        my $other_net  = $other->{network} || $other;
        my $nat_domain = $other_net->{nat_domain}; # Is undef for aggregate.

        # Find $nat_tag which is effective at $other.
        # - single: $other is host or network, $nat_domain is known.
        # - multiple: $other is aggregate.
        #             Use intersection of all no_nat_sets active in zone.
        my $no_nat_set = $nat_domain 
                       ? $nat_domain->{no_nat_set} 
                       : $other->{zone}->{multi_no_nat_set};

        my $cache_obj = $network->{has_dynamic_host} ? $obj : $network;
        return if $seen{$cache_obj}->{$no_nat_set}++;

        my $show_rule = sub {
            my $rule = { %$path_rule };
            @{$rule}{qw(src dst)} = 
                $reversed ? ($other, $obj) : ($obj, $other); 
            return print_rule($rule);
        };

        my $nat_seen;
        my $hidden_seen;
        my $static_seen;
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
                    my $nat_network =
                        get_nat_network($network, $no_nat_set);
                    my $nat_tag = $nat_network->{dynamic};
                    return if not $nat_tag;
                    return if $obj->{nat}->{$nat_tag};
                    my $intf = $reversed ? $out_intf : $in_intf;

                    # $intf would have value 'undef' if $obj is
                    # interface of current router and src/dst of rule.
                    if (!$intf || zone_eq($network->{zone}, $intf->{zone})) {
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
            $dyn_nat_hash->{$nat_tag} = $nat_network->{hidden};
        }
        $dyn_nat_hash or return;

        my ($src_path, $dst_path) = @{$path_rule}{qw(src_path dst_path)};
        my $active_nat_at = $cache{$src_path}->{$dst_path}
          || $cache{$dst_path}->{$src_path};

        if (!$active_nat_at) {
            $path_rule->{active_nat_at} = {};
            path_walk($path_rule, $check_dyn_nat);
            $cache{$src_path}->{$dst_path} =
                $active_nat_at = delete $path_rule->{active_nat_at};
        }

        for my $nat_tag (sort keys %$dyn_nat_hash) {
            my $interfaces = $active_nat_at->{$nat_tag} or next;
            my $is_hidden = $dyn_nat_hash->{$nat_tag};
            ($is_hidden || $static_seen) or next;
            my $names =
              join("\n - ", map({ $_->{name} } sort(by_name @$interfaces)));
            my $type = $is_hidden ? 'hidden' : 'dynamic';
            err_msg(
                "Must not apply $type NAT '$nat_tag' on path\n",
                " of",
                $reversed ? ' reversed' : '',
                " rule\n",
                " ",
                $show_rule->(),
                "\n",
                " NAT '$nat_tag' is active at\n",
                " - $names\n",
                " Add pathrestriction",
                " to exclude this path"
            );
        }
    };

    for my $rule (@{ $path_rules{deny} }, @{ $path_rules{permit} }) {
        my ($src_list, $dst_list) = @{$rule}{qw(src dst)};
        for my $src (@$src_list) {
            for my $dst (@$dst_list) {
                $check_dyn_nat_path->($rule, $src, $dst);
                $check_dyn_nat_path->($rule, $dst, $src, 'reversed');
            }
        }
    }
    return;
}

##############################################################################
# Find redundant rules which are overlapped by some more general rule
##############################################################################
sub find_redundant_rules {
 my ($cmp_hash, $chg_hash) = @_;
 my $count = 0;
 while (my ($stateless, $chg_hash) = each %$chg_hash) {
  while (1) {
   if (my $cmp_hash = $cmp_hash->{$stateless}) {
    while (my ($deny, $chg_hash) = each %$chg_hash) {
     while (1) {
      if (my $cmp_hash = $cmp_hash->{$deny}) {
       while (my ($src_range_ref, $chg_hash) = each %$chg_hash) {
        my $src_range = $ref2prt{$src_range_ref};
        while (1) {
         if (my $cmp_hash = $cmp_hash->{$src_range}) {
          while (my ($src_ref, $chg_hash) = each %$chg_hash) {
           my $src = $ref2obj{$src_ref};
           while (1) {
            if (my $cmp_hash = $cmp_hash->{$src}) {
             while (my ($dst_ref, $chg_hash) = each %$chg_hash) {
              my $dst = $ref2obj{$dst_ref};
              while (1) {
               if (my $cmp_hash = $cmp_hash->{$dst}) {
                for my $chg_rule (values %$chg_hash) {
                 my $prt = $chg_rule->{prt};
                 while (1) {
                  if (my $cmp_rule = $cmp_hash->{$prt}) {
                   if ($cmp_rule ne $chg_rule &&
                       ($cmp_rule->{log} || '') eq ($chg_rule->{log} || ''))
                   {
                    collect_redundant_rules($chg_rule, $cmp_rule);

                    # Count each redundant rule only once.
                    $count++ if not $chg_rule->{redundant}++;
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
   last if !$stateless;
   $stateless = '';
  }
 }
 return $count;
}

########################################################################
# Routing
########################################################################

##############################################################################
# TODO: Add standard function comment.
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
        else {
            internal_err("unexpected $obj->{name}");
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
    my $set_cluster;
    $set_cluster = sub {
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
                $set_cluster->($out_intf->{router}, $out_intf, $cluster);
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
    my $set_networks_behind;
    $set_networks_behind = sub {
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
                $set_networks_behind->($out_hop, $border);
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
    return;
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
    return if $interface->{routing}; # Interface with manual routing.
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
    return;
}

sub check_and_convert_routes;
#############################################################################
# Purpose  : Generate and store routing information for all managed interfaces.
sub find_active_routes {
    progress('Finding routes');

    # Generate navigation information for routing inside zones.
    for my $zone (@zones) {
        set_routes_in_zone $zone;
    }

    # Generate pseudo rule set with all src dst pairs to determine routes for.
    my $routing_tree = generate_routing_tree;

    # Generate routing info for every pseudo rule and store it in interfaces.
    generate_routing_info $routing_tree;

    # TODO
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
        for my $hop2 (values %{ $interface->{hopref2obj} }) {
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

sub check_and_convert_routes {

    # Fix routes to bridged interfaces without IP address.
    for my $router (@managed_routers, @routing_only_routers) {
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{network}->{bridged};
            for my $hop (values %{ $interface->{hopref2obj} }) {
                next if $hop->{ip} ne 'bridged';
                for my $network (values %{ $interface->{routes}->{$hop} }) {
                    my @real_hop = fix_bridged_hops($hop, $network);
                    for my $rhop (@real_hop) {
                        $interface->{hopref2obj}->{$rhop} = $rhop;
                        $interface->{routes}->{$rhop}->{$network} = $network;
                    }
                }
                delete $interface->{hopref2obj}->{$hop};
                delete $interface->{routes}->{$hop};
            }
        }
    }

    for my $router (@managed_routers, @routing_only_routers) {

        # Adjust routes through VPN tunnel to cleartext interface.
        for my $interface (@{ $router->{interfaces} }) {
            next if not $interface->{ip} eq 'tunnel';
            my $tunnel_routes = $interface->{routes};
            $interface->{routes} = $interface->{hopref2obj} = {};
            my $real_intf = $interface->{real_interface};
            next if $real_intf->{routing};
            my $real_net  = $real_intf->{network};
            my $peer      = $interface->{peer};
            my $real_peer = $peer->{real_interface};
            my $peer_net  = $real_peer->{network};

            # Find hop to peer network and add tunnel networks to this hop.
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
                    my ($rule, $in_intf, $out_intf) = @_;
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
                && equal(map({ $_->{redundancy_interfaces} || $_ } @hops))
                || @hops == 1)
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

            # Remember, via which remote interface a network is reached.
            my %net2hop;

            # Remember, via which remote redundancy interfaces a network
            # is reached. We use this to check, if alle members of a group
            # of redundancy interfaces are used to reach the network.
            # Otherwise it would be wrong to route to the virtual interface.
            my %net2group;

            next if $interface->{loop} and $interface->{routing};
            next if $interface->{ip} eq 'bridged';
            my $warn_msg;
            for my $hop (sort by_name values %{ $interface->{hopref2obj} }) {
                for my $network (values %{ $interface->{routes}->{$hop} }) {
                    if (my $interface2 = $net2intf{$network}) {
                        if ($interface2 ne $interface) {

                            # Network is reached via two different
                            # local interfaces.  Show warning if static
                            # routing is enabled for both interfaces.
                            if (    not $interface->{routing}
                                and not $interface2->{routing})
                            {
                                push(@$warn_msg,
                                     "Two static routes for $network->{name}" .
                                     "\n via $interface->{name} and" .
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
                                push(@$warn_msg,
                                     "Two static routes for $network->{name}" .
                                     "\n at $interface->{name}" .
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
            if ($warn_msg) {
                warn_msg($_) for sort @$warn_msg;
            }
            for my $net_ref (keys %net2group) {
                my $hops = $net2group{$net_ref};
                my $hop1 = $hops->[0];
                my $missing = @{ $hop1->{redundancy_interfaces} } - @$hops;
                next if not $missing;
                my $network = $interface->{routes}->{$hop1}->{$net_ref};

                # A network is routed to a single physical interface.
                # It is probably a loopback interface of the same device.
                # Move hop from virtual to physical interface.
                if (@$hops == 1 && (my $phys_hop = $hop1->{orig_main})) {
                    delete $interface->{routes}->{$hop1}->{$net_ref};
                    $interface->{routes}->{$phys_hop}->{$network} = $network;
                    $interface->{hopref2obj}->{$phys_hop} = $phys_hop;
                }
                else {

                    # This occurs if different redundancy groups use
                    # parts of of a group of routers.
                    # More than 3 virtual interfaces together with
                    # pathrestrictions have already been rejected.
                    my $names =
                        join("\n - ", map({ $_->{name} } sort(by_name @$hops)));
                    err_msg(
                        "$network->{name} is reached via group of",
                        " redundancy interfaces:\n",
                        " - $names\n",
                        " But $missing interfaces of group are missing."
                    );
                }
            }

            # Convert to array, because hash isn't needed any longer.
            # Array is sorted to get deterministic output.
            $interface->{hopref2obj} =
              [ sort by_name values %{ $interface->{hopref2obj} } ];
        }
    }
    return;
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
    return;
}

sub print_routes {
    my ($router)              = @_;
    my $model                 = $router->{model};
    my $type                  = $model->{routing};
    my $vrf                   = $router->{vrf};
    my $do_auto_default_route = $config->{auto_default_route};
    my $crypto_type = $model->{crypto} || '';
    my $asa_crypto = $crypto_type eq 'ASA';
    my %intf2hop2nets;
    my @interfaces;
    my %mask2ip2net;
    my %net2hop_info;
    my %net2no_opt;

    for my $interface (@{ $router->{interfaces} }) {
        next if $interface->{ip} eq 'bridged';
        if ($interface->{routing}) {
            $do_auto_default_route = 0;
            next;
        }

        push @interfaces, $interface;

        # ASA with site-to-site VPN needs individual routes for each peer.
        if ($asa_crypto && $interface->{hub}) {
            $do_auto_default_route = 0;
        }
        my $no_nat_set = $interface->{no_nat_set};

        for my $hop (@{ $interface->{hopref2obj} }) {
            my $hop_info = [ $interface, $hop ];

            # A hash having all networks reachable via current hop
            # both as key and as value.
            my $net_hash = $interface->{routes}->{$hop};
            for my $network (values %$net_hash) {
                my $nat_network = get_nat_network($network, $no_nat_set);
                next if $nat_network->{hidden};
                my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };
                if ($ip == 0 and $mask == 0) {
                    $do_auto_default_route = 0;
                }

                # Implicitly overwrite duplicate networks.
                $mask2ip2net{$mask}->{$ip} = $nat_network;
                $net2hop_info{$nat_network} = $hop_info;
            }
        }
    }
    return if not @interfaces;
 
    # Combine adjacent networks, if both use same hop and 
    # if combined network doesn't already exist.
    # Prepare @inv_prefix_aref.
    my @inv_prefix_aref;
    for my $mask (keys %mask2ip2net) {
        my $inv_prefix  = 32 - mask2prefix($mask);
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
        my $ip2net = $inv_prefix_aref[$inv_prefix] or next;
        my $next   = 2**$inv_prefix;
        my $modulo = 2 * $next;
        for my $ip (keys %$ip2net) {

            # Only analyze left part of two adjacent networks.
            $ip % $modulo == 0 or next;
            my $left = $ip2net->{$ip};

            # Find right part.
            my $next_ip = $ip + $next;
            my $right   = $ip2net->{$next_ip} or next;

            # Both parts must use equal next hop.
            my $hop_left  = $net2hop_info{$left};
            my $hop_right = $net2hop_info{$right};
            $hop_left eq $hop_right or next;

            # Combined network already exists.
            my $combined_inv_prefix = $inv_prefix + 1;
            next if $inv_prefix_aref[$combined_inv_prefix]->{$ip};

            # Add combined route.
            my $mask = 0xffffffff - $modulo + 1;
            my $combined = { ip => $ip, mask => $mask };
            $inv_prefix_aref[$combined_inv_prefix]->{$ip} = $combined;
            $mask2ip2net{$mask}->{$ip} = $combined;
            $net2hop_info{$combined} = $hop_left;

            # Left and right part are no longer used.
            my $part_mask = 0xffffffff - $next + 1;
            delete $mask2ip2net{$part_mask}->{$ip};
            delete $mask2ip2net{$part_mask}->{$next_ip};
        }
    }

    # Find and remove duplicate networks.
    # Go from smaller to larger networks.
    my @masks = reverse sort numerically keys %mask2ip2net;
    while (defined(my $mask = shift @masks)) {
      NETWORK:
        for my $ip (sort numerically keys %{ $mask2ip2net{$mask} }) {
            my $small    = $mask2ip2net{$mask}->{$ip};
            my $hop_info = $net2hop_info{$small};
            my ($interface, $hop) = @$hop_info;

            # ASA with site-to-site VPN needs individual routes for each peer.
            if (!($asa_crypto && $interface->{hub})) {

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
        for my $interface (@interfaces) {
            for my $hop (@{ $interface->{hopref2obj} }) {
                my $count = grep({ !$net2no_opt{ $_->[2] } }
                    @{ $intf2hop2nets{$interface}->{$hop} || [] });
                if ($count > $max) {
                    $max_intf = $interface;
                    $max_hop  = $hop;
                    $max      = $count;
                }
            }
        }
        if ($max_intf && $max_hop) {

            # Use default route for this direction.
            # But still generate routes for small networks
            # with supernet behind other hop.
            $intf2hop2nets{$max_intf}->{$max_hop} = [
                [ 0, 0 ],
                grep({ $net2no_opt{ $_->[2] } }
                    @{ $intf2hop2nets{$max_intf}->{$max_hop} })
            ];
        }
    }
    print_header($router, 'Routing');

    my $ios_vrf;
    $ios_vrf = $vrf ? "vrf $vrf " : '' if $type eq 'IOS';
    my $nxos_prefix = '';

    for my $interface (@interfaces) {
        for my $hop (@{ $interface->{hopref2obj} }) {

            # For unnumbered and negotiated interfaces use interface name
            # as next hop.
            my $hop_addr =
                $interface->{ip} =~ /^(?:unnumbered|negotiated|tunnel)$/
              ? $interface->{hardware}->{name}
              : print_ip $hop->{ip};

            for my $netinfo (@{ $intf2hop2nets{$interface}->{$hop} }) {
                if ($type eq 'IOS') {
                    my $adr = ios_route_code($netinfo);
                    print "ip route $ios_vrf$adr $hop_addr\n";
                }
                elsif ($type eq 'NX-OS') {
                    if ($vrf && !$nxos_prefix) {

                        # Print "vrf context" only once
                        # and indent "ip route" commands.
                        print "vrf context $vrf\n";
                        $nxos_prefix = ' ';
                    }
                    my $adr = full_prefix_code($netinfo);
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
    my $managed = $router->{managed} or return;
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
        return if $model->{filter} eq 'PIX';

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
            my $src_list = $rule->{src};
            my %id2src_list;
            for my $src (@$src_list) {
                if (is_subnet $src) {
                    my $id = $src->{id} or 
                        internal_err("$src->{name} must have ID");
                    push @{ $id2src_list{$id} }, $src;
                }
                elsif (is_network $src) {
                    $src->{has_id_hosts} or 
                        internal_err("$src->{name} must have ID-hosts");
                    for my $id (map { $_->{id} } @{ $src->{hosts} }) {
                        push @{ $id2src_list{$id} }, $src;
                    }
                }
                else {
                    internal_err(
                        "Unexpected $src->{name} without ID\n ",
                        print_rule $rule);
                }
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
        push
          @{ $in_intf->{hardware}->{io_rules}->{ $out_intf->{hardware}->{name} }
          }, $rule;
    }
    else {
        push @{ $in_intf->{hardware}->{$key} }, $rule;
    }
}

my $permit_any_rule;

sub add_router_acls {
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
                    my $net_list = $interface->{reroute_permit};
                    my $rule = {
                        src => [ $network_00 ],
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
                        if (my $dst_range = $prt->{dst_range}) {
                            $prt = $dst_range;
                        }
                        $prt = [ $prt ];
                        my $network = [ $interface->{network} ];

                        # Permit multicast packets from current network.
                        my $mcast = $routing->{mcast};
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
                    my $mcast   = $xxrp_info{$type}->{mcast};
                    my $prt     = $xxrp_info{$type}->{prt};
                    if (my $dst_range = $prt->{dst_range}) {
                        $prt = $dst_range;
                    }
                    push @{ $hardware->{intf_rules} },
                      {
                        src => [ $network ],
                        dst => [ $mcast ],
                        prt => [ $prt ]
                      };
                }

                # Handle DHCP requests.
                if ($interface->{dhcp_server}) {
                    push @{ $hardware->{intf_rules} },
                      {
                        src => [ $network_00 ],
                        dst => [ $network_00 ],
                        prt => [ $prt_bootps->{dst_range} ]
                      };
                }
            }
        }
    }
    return;
}

sub create_general_permit_rules {
    my ($protocols) = @_;
    my @prt = map {   ref($_) eq 'ARRAY' 
                    ? $_->[1]	# take dst range; src range was error before.
                    : $_->{main_prt} 
                    ? $_->{main_prt} 
                    : $_ } @$protocols;
    my $rule = {
        src => [ $network_00 ],
        dst => [ $network_00 ],
        prt => \@prt,
    };
    return $rule;
}

sub distribute_general_permit {
    for my $router (@managed_routers) {
        my $general_permit = $router->{general_permit} or next;
        my $rule = create_general_permit_rules($general_permit);
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
    return;
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
    %key2obj        = ();
    return;
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

        if ($ip eq 'unnumbered') {
            internal_err("Unexpected unnumbered $obj->{name}");
        }
        else {
            return [ $ip, $obj->{mask} ];
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
                return [ $network->{ip}, $network->{mask} ];
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
        my $ip = $obj->{ip};
        if ($ip eq 'unnumbered' or $ip eq 'short') {
            internal_err("Unexpected $ip $obj->{name}");
        }

        my $network = get_nat_network($obj->{network}, $no_nat_set);

        if ($ip eq 'negotiated') {
            my ($network_ip, $network_mask) = @{$network}{qw(ip mask)};
            return [ $network_ip, $network_mask ];
        }
        elsif (my $nat_tag = $network->{dynamic}) {
            if (my $ip = $obj->{nat}->{$nat_tag}) {

                # Single static NAT IP for this interface.
                return [ $ip, 0xffffffff ];
            }
            else {
                return [ $network->{ip}, $network->{mask} ];
            }
        }
        else {

            # Take higher bits from network NAT, lower bits from original IP.
            # This works with and without NAT.
            $ip = $network->{ip} | $ip & complement_32bit $network->{mask};
            return [ $ip, 0xffffffff ];
        }
    }
    else {
        internal_err("Unexpected object of type '$type'");
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

sub full_prefix_code {
    my ($pair) = @_;
    my ($ip, $mask) = @$pair;
    my $ip_code     = print_ip($ip);
    my $prefix_code = mask2prefix($mask);
    return "$ip_code/$prefix_code";
}

my $deny_any_rule;

sub print_acl_placeholder {
    my ($router, $acl_name) = @_;

    # Add comment at start of ACL to easier find first ACL line in tests.
    my $model = $router->{model};
    my $filter = $model->{filter};
    if ($filter =~ /^(?:PIX|ACE)$/) {
        my $comment_char = $model->{comment_char};
        print "$comment_char $acl_name\n";
    }
        
    print "#insert $acl_name\n";
}

# Parameter: Interface
# Analyzes dst_list of all rules collected at this interface.
# Result:
# Array reference to sorted list of all networks which are allowed
# to pass this interface.
sub get_split_tunnel_nets {
    my ($interface) = @_;

    my %split_tunnel_nets;
    for my $rule (@{ $interface->{rules} }, @{ $interface->{intf_rules} }) {
        next if $rule->{deny};
        my $dst_list = $rule->{dst};
        for my $dst (@$dst_list) {
            my $dst_network = $dst->{network} || $dst;

            # Don't add 'any' (resulting from global:permit)
            # to split_tunnel networks.
            next if $dst_network->{mask} == 0;
            $split_tunnel_nets{$dst_network} = $dst_network;
        }
    }
    return [ sort { $a->{ip} <=> $b->{ip} || $a->{mask} <=> $b->{mask} }
          values %split_tunnel_nets ];
}

my %asa_vpn_attr_need_value =
  map { $_ => 1 }
  qw(banner dns-server default-domain split-dns wins-server address-pools
  split-tunnel-network-list vpn-filter);

sub print_asavpn {
    my ($router)   = @_;
    my $model      = $router->{model};
    my $no_nat_set = $router->{hardware}->[0]->{no_nat_set};

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
    for my $interface (@{ $router->{interfaces} }) {
        next if not $interface->{ip} eq 'tunnel';
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
                                dst => [ $network_00 ],
                                prt => [ $prt_ip ],
                            } ];
                        }
                        else {
                            $rules = [ $deny_any_rule ];
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
                        dst => [ $network_00 ],
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
                if ($src->{mask} == 0xffffffff) {

                    # For anyconnect clients.
                    my ($name, $domain) = ($id =~ /^(.*?)(\@.*)$/);
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
                      print_ip($src->{ip} | complement_32bit $src->{mask});
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
                        if ($spec && $spec->{tg_general}) {
                            my $value = delete $attributes->{$key};
                            my $out = defined($value) ? "$key $value" : $key;
                            push(@tunnel_gen_att, $out);
                        }
                    }

                    my $trustpoint2 = delete $attributes->{'trust-point'}
                      || $trust_point;
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
        else {

            # Access list will be bound to cleartext interface.
            # Only check for correct source address at vpn-filter.
            delete $interface->{intf_rules};
            delete $interface->{rules};
            my $rules = [ { src => $interface->{peer_networks}, 
                            dst => [ $network_00 ], 

                            prt => [ $prt_ip ] } ];
            my $id = $interface->{peer}->{id}
              or internal_err("Missing ID at $interface->{peer}->{name}");
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
    return;
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
    return;
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
    return;
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
    return;
}

sub print_cisco_acls {
    my ($router)      = @_;
    my $model         = $router->{model};
    my $filter        = $model->{filter};
    my $managed_local = $router->{managed} =~ /^local/;
    my $hw_list       = $router->{hardware};
    
    for my $hardware (@$hw_list) {

        # Ignore if all logical interfaces are loopback interfaces.
        next if $hardware->{loopback};

        # Ignore layer3 interface of ASA.
        next if $hardware->{name} eq 'device' && $model->{class} eq 'ASA';

        # Force valid array reference to prevent error
        # when checking for non empty array.
        $hardware->{rules} ||= [];

        my $no_nat_set = $hardware->{no_nat_set};

        # Generate code for incoming and possibly for outgoing ACL.
        for my $suffix ('in', 'out') {
            next if $suffix eq 'out' and not $hardware->{need_out_acl};

            # Don't generate single 'permit ip any any'.
            if (!$model->{need_acl}) {
                if (
                    !grep {
                        my $rules = $hardware->{$_} || [];
                        @$rules != 1 || $rules->[0] ne $permit_any_rule
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

            if ($router->{acl_use_real_ip}) {
                my $hw0 = $hw_list->[0];
                my $dst_hw = $hardware eq $hw0 ? $hw_list->[1] : $hw0;
                $acl_info->{dst_no_nat_set} = $dst_hw->{no_nat_set};
            }

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
                        my @interfaces = grep({ !$_->{main_interface} } 
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
            if ($filter eq 'IOS' || $filter eq 'NX-OS') {
                push(
                    @{ $hardware->{subcmd} },
                    "ip access-group $acl_name $suffix"
                );
            }
            elsif ($filter eq 'ACE') {
                push(
                    @{ $hardware->{subcmd} },
                    "access-group ${suffix}put $acl_name"
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
    return;
}

sub gen_crypto_rules {
    my ($local, $remote) = @_;
    return [ { src => $local, dst => $remote, prt => [$prt_ip] } ];
}

sub print_ezvpn {
    my ($router)   = @_;
    my $model      = $router->{model};
    my @interfaces = @{ $router->{interfaces} };
    my @tunnel_intf = grep { $_->{ip} eq 'tunnel' } @interfaces;
    @tunnel_intf == 1 or internal_err();
    my ($tunnel_intf) = @tunnel_intf;
    my $wan_intf      = $tunnel_intf->{real_interface};
    my $wan_hw        = $wan_intf->{hardware};
    my $no_nat_set    = $wan_hw->{no_nat_set};
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
    my $peer_ip = prefix_code(address($peer->{real_interface}, $no_nat_set));
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
    $tunnel_intf->{crypto}->{detailed_crypto_acl}
      and internal_err("Unexpected attribute 'detailed_crypto_acl'",
        " at $router->{name}");
    my $crypto_rules =
      gen_crypto_rules($tunnel_intf->{peer}->{peer_networks},
        [$network_00]);
    my $acl_info = {
        name => $crypto_acl_name,
        rules => $crypto_rules,
        no_nat_set => $no_nat_set,
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
        no_nat_set   => $no_nat_set,
    };
    push @{ $router->{acl_list} }, $acl_info;
    print_acl_placeholder($router, $crypto_filter_name);

    # Bind crypto filter ACL to virtual template.
    print "interface Virtual-Template$virtual_interface_number type tunnel\n";
    print " ip access-group $crypto_filter_name in\n";
    return;
}

# Print crypto ACL.
# It controls which traffic needs to be encrypted.
sub print_crypto_acl {
    my ($interface, $suffix, $crypto, $crypto_type) = @_;
    my $crypto_acl_name = "crypto-$suffix";

    # Generate crypto ACL entries.
    # - either generic from remote network to any or
    # - detailed to all networks which are used in rules.
    my $is_hub   = $interface->{is_hub};
    my $hub      = $is_hub ? $interface : $interface->{peer};
    my $detailed = $crypto->{detailed_crypto_acl};
    my $local    = $detailed ? get_split_tunnel_nets($hub) : [$network_00];
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
    my ($interface, $suffix, $crypto_type) = @_;
    my $router = $interface->{router};

    return if $router->{no_crypto_filter};

    my $crypto_filter_name = "crypto-filter-$suffix";
    my $model      = $router->{model};
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
    my ($prefix, $model, $crypto_type, $crypto_acl_name, $crypto_filter_name,
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

    if (my $lifetime = $ipsec->{lifetime}) {

        # Don't print default value for backend IOS.
        if (not($lifetime == 3600 and $crypto_type eq 'IOS')) {
            print(
                "$prefix set security-association",
                " lifetime seconds $lifetime\n"
            );
        }
    }
    return;
}

sub print_tunnel_group {
    my ($name, $interface, $isakmp) = @_;
    my $model          = $interface->{router}->{model};
    my $no_nat_set     = $interface->{no_nat_set};
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
    return;
}

sub print_ca_and_tunnel_group_map {
    my ($id, $tg_name) = @_;

    # Activate tunnel-group with tunnel-group-map.
    # Use $id as ca-map name.
    print "crypto ca certificate map $id 10\n";
    print " subject-name attr ea eq $id\n";
    print "tunnel-group-map $id 10 $tg_name\n";
    return;
}

sub print_static_crypto_map {
    my ($router, $hardware, $map_name, $interfaces, $ipsec2trans_name) = @_;
    my $model       = $router->{model};
    my $crypto_type = $model->{crypto};
    my $hw_name     = $hardware->{name};

    # Sequence number for parts of crypto map with different peers.
    my $seq_num = 0;

    # Crypto ACLs and peer IP must obey NAT.
    my $no_nat_set = $hardware->{no_nat_set};

    # Sort crypto maps by peer IP to get deterministic output.
    my @sorted = sort(
        { $a->{peer}->{real_interface}->{ip}
              <=> $b->{peer}->{real_interface}->{ip} } @$interfaces);

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
          print_crypto_acl($interface, $suffix, $crypto, $crypto_type);
        my $crypto_filter_name =
          print_crypto_filter_acl($interface, $suffix, $crypto_type);

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

        print_crypto_map_attributes($prefix, $model, $crypto_type,
            $crypto_acl_name, $crypto_filter_name,
            $isakmp, $ipsec, $ipsec2trans_name);

        if ($crypto_type eq 'ASA') {
            print_tunnel_group($peer_ip, $interface, $isakmp);

            # Tunnel group needs to be activated, if certificate is in use.
            if (my $id = $peer->{id}) {
                print_ca_and_tunnel_group_map($id, $peer_ip);
            }
        }
    }
    return;
}

sub print_dynamic_crypto_map {
    my ($router, $hardware, $map_name, $interfaces, $ipsec2trans_name) = @_;
    my $model       = $router->{model};
    my $crypto_type = $model->{crypto};
    $crypto_type eq 'ASA' or internal_err();
    my $hw_name = $hardware->{name};

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
          print_crypto_acl($interface, $suffix, $crypto, $crypto_type);
        my $crypto_filter_name =
          print_crypto_filter_acl($interface, $suffix, $crypto_type);

        # Define dynamic crypto map.
        # Use certificate as name.
        my $prefix = "crypto dynamic-map $id 10";

        print_crypto_map_attributes($prefix, $model, $crypto_type,
            $crypto_acl_name, $crypto_filter_name,
            $isakmp, $ipsec, $ipsec2trans_name);

        # Bind dynamic crypto map to crypto map.
        $prefix = "crypto map $map_name $seq_num";
        print "$prefix ipsec-isakmp dynamic $id\n";

        # Use $id as tunnel-group name
        print_tunnel_group($id, $interface, $isakmp);

        # Activate tunnel-group with tunnel-group-map.
        print_ca_and_tunnel_group_map($id, $id);
    }
    return;
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

    $crypto_type =~ /^(:?IOS|ASA)$/
      or internal_err("Unexptected crypto type $crypto_type");

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
            print_dynamic_crypto_map($router, $hardware, $map_name,
                $interfaces, \%ipsec2trans_name);
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
    return;
}

sub print_interface {
    my ($router) = @_;
    my $model = $router->{model};
    return if !$model->{print_interface};
    my $class    = $model->{class};
    my $stateful = not $model->{stateless};
    for my $hardware (@{ $router->{hardware} }) {
        my $name = $hardware->{name};
        next if $name eq 'VIP' and $model->{has_vip};
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
        if ($class eq 'IOS' && $stateful && !$hardware->{loopback}) {
            push @subcmd, "ip inspect X in";
        }
        if (my $other = $hardware->{subcmd}) {
            push @subcmd, @$other;
        }

        # Split name for ACE: "vlan3029" -> "vlan 3029"
        $name =~ s/(\d+)/ $1/ if ($class eq 'ACE');

        print "interface $name\n";
        for my $cmd (@subcmd) {
            print " $cmd\n";
        }
    }
    print "\n";
    return;
}

sub print_prt {
    my ($prt) = @_;
    my $proto = $prt->{proto};
    my @result = ($proto);

    if ($proto eq 'tcp' or $proto eq 'udp') {
        push @result,  @{ $prt->{range} };
        push @result, 'established' if $prt->{established};
    }
    elsif ($proto eq 'icmp') {
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
            ||

            # ASA protects IOS router behind crosslink interface.
            $router->{crosslink_interfaces}
          )
        {

            # Routers connected by crosslink networks are handled like
            # one large router. Protect the collected interfaces of
            # the whole cluster at each entry.
            $need_protect = $router->{crosslink_interfaces};
            if (!$need_protect) {
                $need_protect = $router->{interfaces};
                $need_protect = [ 
                    grep({ $_->{ip} !~ /^(?:unnumbered|negotiated|tunnel|bridged)$/ } 
                         @$need_protect) ];
                if ($model->{has_vip}) {
                    $need_protect = [ grep { !$_->{vip} } @$need_protect ];
                }
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
                    if ($active_log && (my $log = $rule->{log})) {
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

                    if (   $secondary_filter && $rule->{some_non_secondary}
                        || $standard_filter && $rule->{some_primary})
                    {
                        for my $where (qw(src dst)) {
                            my $obj_list = $rule->{$where};
                            for my $obj (@$obj_list) {

                                # Prepare secondary optimization.
                                my $type = ref($obj);

                                # Restrict secondary optimization at
                                # authenticating router to prevent
                                # unauthorized access with spoofed IP
                                # address.
                                if ($do_auth) {

                                    # Single ID-hosts must not be
                                    # converted to network.
                                    if ($type eq 'Subnet') {
                                        next if $obj->{id};
                                    }

                                    # Network with ID-hosts must not
                                    # be optimized at all.
                                    if ($obj->{has_id_hosts}) {
                                        $no_opt_addrs{$obj} = $obj;
                                        next;
                                    }
                                }

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
                                    next if $subst->{mask} == 0xffffffff;
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

        my $prev = "$dir/.prev";
        if (not -d $prev) {
            my @old_files = glob("$dir/*");
            if (my $count = @old_files) {
                progress("Moving $count old files in '$dir' to",
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
    return;
}

# Print generated code for each managed router.
sub print_code {
    my ($dir) = @_;

    # Untaint $dir. This is necessary if running setuid.
    # We can trust value of $dir because it is set by setuid wrapper.
    ($dir) = ($dir =~ /(.*)/);
    check_output_dir($dir);

    progress('Printing intermediate code');
    my %seen;
    for my $router (@managed_routers, @routing_only_routers) {
        next if $seen{$router};

        # Ignore split part of crypto router.
        next if $router->{orig_router};

        my $device_name = $router->{device_name};
        my $file        = $device_name;

        # Untaint $file. It has already been checked for word characters,
        # but check again for the case of a weird locale setting.
        $file =~ s/^(.*)/$1/;

        # File for router config without ACLs.
        my $config_file = "$dir/$file.config";

        ## no critic (RequireBriefOpen)
        open(my $code_fd, '>', $config_file)
          or fatal_err("Can't open $config_file for writing: $!");
        select $code_fd;

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
        if ($router->{policy_distribution_point}) {
            if (my @ips = map { @{ $_->{admin_ip} || [] } } @$vrf_members) {
                printf("$comment_char [ IP = %s ]\n", join(',', @ips));
            }
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
        ## use critic

        # Print ACLs in machine independent format into separate file.
        # Collect ACLs from VRF parts.
        my $acl_file = "$dir/$file.rules";
        open(my $acl_fd, '>', $acl_file)
          or fatal_err("Can't open $acl_file for writing: $!");
        print_acls($vrf_members, $acl_fd);
        close $acl_fd or fatal_err("Can't close $acl_file: $!");

    }
}

# Copy raw configuration files of devices into out_dir for devices
# known from topology.
sub copy_raw {
    my ($in_path, $out_dir) = @_;
    return if !(defined $in_path && -d $in_path);
    return if !defined $out_dir;

    # Untaint $in_path, $out_dir. This is necessary if running setuid.
    # Trusted because set by setuid wrapper.
    ($in_path) = ($in_path =~ /(.*)/);
    ($out_dir) = ($out_dir =~ /(.*)/);

    # $out_dir has already been checked / created in print_code.

    my $raw_dir = "$in_path/raw";
    return if not -d $raw_dir;

    # Clean PATH if run in taint mode.
    ## no critic (RequireLocalizedPunctuationVars)
    $ENV{PATH} = '/usr/local/bin:/usr/bin:/bin';
    ## use critic

    my %device_names =
      map { $_->{device_name} => 1 } @managed_routers, @routing_only_routers;

    opendir(my $dh, $raw_dir) or fatal_err("Can't opendir $raw_dir: $!");
    while (my $file = Encode::decode($filename_encode, readdir $dh)) {
        next if $file =~ /^\./;
        next if $file =~ m/$config->{ignore_files}/o;

        # Untaint $file.
        my ($raw_file) = ($file =~ /^(.*)/);
        my $raw_path = "$raw_dir/$raw_file";
        if (not -f $raw_path) {
            warn_msg("Ignoring $raw_path");
            next;
        }
        if (not $device_names{$file}) {
            warn_msg("Found unused $raw_path");
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

# Start concurrent jobs.
sub concurrent {
    my ($code1, $code2) = @_;

    # Process sequentially.
    if (1 >= $config->{concurrency_pass1}) {
        $code1->();
        $code2->();
    }

    # Parent.
    # Fork process and read output of child process.
    ## no critic (RequireBriefOpen)
    elsif (my $child_pid = open(my $child_fd, '-|')) {

        $code1->();

        # Show child ouput.
        progress('Output of background job:');
        while (my $line = <$child_fd>) {

            # Indent output of child.
            print STDERR " $line";
        }

        # Check exit status of child.
        if (not close ($child_fd)) {
            my $status = $?;
            if ($status != 0) {
                my $err_count = $status >> 8;
                if (not $err_count) {
                    internal_err("Background process died with status $status");
                }
                $error_counter += $err_count;
            }
        }
    }
    ## use critic

    # Child
    elsif (defined $child_pid) {

        # Catch errors,
        eval { 

            # Redirect STDERR to STDOUT, so parent can read output of child.
            open (STDERR, ">&STDOUT") or internal_err("Can't dup STDOUT: $!");

            $code2->();
            progress('Finished background job') if $config->{time_stamps};
        };
        if ($@) {

            # Show internal errors, but not "Aborted" message.
            if ($@ !~ /^Aborted /) {
                print STDOUT $@;
            }
        }
        exit $error_counter;
    }
    else {
        internal_err("Can't start child: $!");
    }
}

# These must be initialized on each run, because protocols are changed
# by prepare_prt_ordering.
sub init_protocols {

    %routing_info = (
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
        dynamic => { name => 'dynamic' },

        # Identical to 'dynamic', but must only be applied to router.
        manual => { name => 'manual' },
    );
    %xxrp_info = (
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
                dst_range => [ 1985, 1985 ],
            },
            mcast => new(
                'Network',
                name => "auto_network:HSRP_multicast",
                ip   => gen_ip(224, 0, 0, 2),
                mask => gen_ip(255, 255, 255, 255)
            )
        },
        HSRPv2 => {
            prt => {
                name      => 'auto_prt:HSRPv2',
                proto     => 'udp',
                dst_range => [ 1985, 1985 ],
            },
            mcast => new(
                'Network',
                name => "auto_network:HSRPv2_multicast",
                ip   => gen_ip(224, 0, 0, 102),
                mask => gen_ip(255, 255, 255, 255)
            )
        },
    );

    $prt_ip = { name => 'auto_prt:ip', proto => 'ip' };
    $prt_icmp = {
        name  => 'auto_prt:icmp',
        proto => 'icmp'
    };
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
    $prt_bootps = {
        name      => 'auto_prt:bootps',
        proto     => 'udp',
        dst_range => [ 67, 67 ]
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
    $deny_any_rule = { %$permit_any_rule, deny => 1, };

    return;
}

sub init_global_vars {
    $start_time            = $config->{start_time} || time();
    $error_counter         = 0;
    for my $pair (values %global_type) {
        %{ $pair->[1] } = ();
    }
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
    %key2obj            = ();
    %border2obj2auto    = ();
    @duplicate_rules    = @redundant_rules = ();
    %missing_supernet   = ();
    %known_log          = %key2log = ();
    %nat2obj2address    = ();
    init_protocols();
    return;
}

sub compile {
    my ($args) = @_;

    my ($in_path, $out_dir);
    ($config, $in_path, $out_dir) = get_args($args);
    init_global_vars();
    &show_version();
    &read_file_or_dir($in_path);
    &show_read_statistics();
    &order_protocols();
    &link_topology();
    &mark_disabled();
    &set_zone();
    &setpath();
    &distribute_nat_info();
    find_subnets_in_zone();

    # Call after find_subnets_in_zone, because original no_nat_set was
    # needed there.
    adjust_crypto_nat();

    # Call after find_subnets_in_zone, where $zone->{networks} has
    # been set up.
    link_reroute_permit();

    # Sets attributes used in check_dynamic_nat_rules and 
    # for ACL generation.
    mark_dynamic_host_nets();

    normalize_services();
    find_subnets_in_nat_domain();

    # Call after {up} relation for anonymous aggregates has been set up.
    mark_managed_local();

    check_service_owner();
    convert_hosts_in_rules();
    group_path_rules();

    # Abort now, if there had been syntax errors and simple semantic errors.
    abort_on_error();

    concurrent(
        sub {
            check_unused_groups();
            check_dynamic_nat_rules();
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
#                DB::enable_profile();
                print_code($out_dir);
#                DB::disable_profile();
                copy_raw($in_path, $out_dir);
            }
        });

    abort_on_error();

    return;
}

1;
