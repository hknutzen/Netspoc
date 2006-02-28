#!/usr/bin/perl
# Netspoc.pm
# A Network Security Policy Compiler
# http://netspoc.berlios.de
# (c) 2005 by Heinz Knutzen <heinzknutzen@users.berlios.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

use strict;
use warnings;

package Netspoc;
require Exporter;
use Getopt::Long;

# We need this for German umlauts being part of \w.
# Uncomment next line, if your files are latin1..9 encoded.
use locale;

# Uncomment next line, if your files are utf8 encoded.
##use open ':utf8';

my $program = 'Network Security Policy Compiler';
my $version =
  (split ' ', '$Id$ ')[2];

our @ISA    = qw(Exporter);
our @EXPORT = qw(
  %routers
  %interfaces
  %networks
  %hosts
  %anys
  %everys
  %areas
  %pathrestrictions
  %global_nat
  %groups
  %services
  %servicegroups
  %policies
  %isakmp
  %ipsec
  %crypto
  %expanded_rules
  $error_counter
  $max_errors
  $store_description
  info
  err_msg
  read_ip
  print_ip
  show_version
  split_typed_name
  is_network
  is_router
  is_interface
  is_host
  is_subnet
  is_any
  is_every
  is_group
  is_servicegroup
  is_objectgroup
  is_chain
  read_args
  read_netspoc
  read_file
  read_file_or_dir
  show_read_statistics
  order_services
  link_topology
  mark_disabled
  find_subnets
  setany
  expand_policies
  expand_crypto
  check_unused_groups
  setpath
  path_walk
  find_active_routes_and_statics
  check_any_rules
  optimize
  optimize_reverse_rules
  distribute_nat_info
  gen_reverse_rules
  mark_secondary_rules
  order_any_rules
  repair_deny_influence
  rules_distribution
  local_optimization
  check_output_dir
  print_code );

####################################################################
# User configurable options.
####################################################################
my $verbose        = 1;
my $comment_acls   = 0;
my $comment_routes = 0;

# Possible values: 0,1,'warn';
my $allow_unused_groups = 'warn';

# Allow subnets only
# - if the enclosing network is marked as 'route_hint' or
# - if the subnet is marked as 'subnet_of'
# Possible values: 0,1,'warn';
my $strict_subnets = 'warn';

# Check for unenforceable rules, i.e. no managed device between src and dst.
# Possible values: 0,1,'warn';
my $check_unenforceable = 0;

# Optimize the number of routing entries per router:
# For each router find the hop, where the largest
# number of routing entries points to
# and replace them with a single default route.
# This is only applicable for internal networks
# which have no default route to the internet.
my $auto_default_route = 1;

# Ignore these names when reading directories:
# - directory raw for prolog & epilogue files
# - CVS and RCS directories
# - CVS working files
# - Editor backup files: emacs: *~
my $ignore_files = '^(raw|CVS|RCS|\.#.*|.*~)$';

# Abort after this many errors.
our $max_errors = 10;

# Store descriptions as an attribute of policies.
# This may be useful when called from a reporting tool.
our $store_description = 0;

# Print warning about ignored ICMP code fields at PIX firewalls.
my $warn_pix_icmp_code = 0;

# Use nonlocal function exit for efficiency.
# Perl profiler doesn't work if this is active.
my $use_nonlocal_exit = 1;

####################################################################
# Attributes of supported router models
####################################################################
my %router_info = (
    IOS => {
        name           => 'IOS',
        stateless      => 1,
        stateless_self => 1,
        routing        => 'IOS',
        filter         => 'IOS',
        crypto         => 'IOS',
        comment_char   => '!',
    },
    IOS_FW => {
        name           => 'IOS_FW',
        stateless_self => 1,
        routing        => 'IOS',
        filter         => 'IOS',
        crypto         => 'IOS',
        comment_char   => '!',
    },
    PIX => {
        name                => 'PIX',
        routing             => 'PIX',
        filter              => 'PIX',
        crypto              => 'PIX',
        no_crypto_filter    => 1,
        comment_char        => '!',
        has_interface_level => 1,
        no_filter_icmp_code => 1,
    },
    Linux => {
        name         => 'Linux',
        routing      => 'iproute',
        filter       => 'iptables',
        comment_char => '#',
    },

    # Cisco VPN 3000 Concentrator including RADIUS config.
    VPN3K => {
        name           => 'VPN3K',
        stateless      => 1,
        stateless_self => 1,
	routing        => 'none',
        filter         => 'VPN3K',
	crypto         => 'ignore',
        comment_char   => '!',
    },
);

####################################################################
# Error Reporting
####################################################################

sub info ( @ ) {
    print STDERR @_, "\n" if $verbose;
}

sub warn_msg ( @ ) {
    print STDERR "Warning: ", @_, "\n";
}

sub debug ( @ ) {
    print STDERR @_, "\n";
}

# Name of current input file.
our $file;

# Content of current file.
our $input;

# Current line number of input file.
our $line;

sub context() {
    my $context;
    if (pos $input == length $input) {
        $context = 'at EOF';
    }
    else {
        my ($pre, $post) =
          $input =~ m/([^ \t\n,;={}]*[,;={} \t]*)\G([,;={} \t]*[^ \t\n,;={}]*)/;
        $context = qq/near "$pre<--HERE-->$post"/;
    }
    return qq/ at line $line of $file, $context\n/;
}

sub at_line() {
    return qq/ at line $line of $file\n/;
}

our $error_counter = 0;

sub check_abort() {
    $error_counter++;
    if ($error_counter == $max_errors) {
        die "Aborted after $error_counter errors\n";
    }
    elsif ($error_counter > $max_errors) {
        die "Aborted\n";
    }
}

sub error_atline( @ ) {
    print STDERR "Error: ", @_, at_line;
    check_abort;
}

sub err_msg( @ ) {
    print STDERR "Error: ", @_, "\n";
    check_abort;
}

sub syntax_err( @ ) {
    die "Syntax error: ", @_, context;
}

sub internal_err( @ ) {
    my ($package, $file, $line, $sub) = caller 1;
    die "Internal error in $sub: ", @_, "\n";
}

####################################################################
# Helper functions for reading configuration
####################################################################

# $_ is used as input buffer, it holds content of current input file.
# Progressive matching is used. \G and pos are used to query current position.
# Return value is false if progressive matching has reached end of buffer.
sub skip_space_and_comment() {

    # Ignore trailing whitespace and comments.
    while ($input =~ m'\G[ \t]*([!#].*)?\n'gc) {
        $line++;
    }

    # Ignore leading whitespace.
    $input =~ m/\G[ \t]*/gc;

    # Check and return EOF status.
    return pos $input != length $input;
}

# Check for a string and skip if available.
sub check( $ ) {
    my $token = shift;
    skip_space_and_comment;
    return $input =~ m/\G$token/gc;
}

# Skip a string.
sub skip ( $ ) {
    my $token = shift;
    check $token or syntax_err "Expected '$token'";
}

# Check, if an integer is available.
sub check_int() {
    skip_space_and_comment;
    if ($input =~ m/\G(\d+)/gc) {
        return $1;
    }
    else {
        return undef;
    }
}

sub read_int() {
    check_int or syntax_err "Integer expected";
}

# Conversion from netmask to prefix and vice versa.
{

    # initialize private variables of this block
    my %mask2prefix;
    my %prefix2mask;
    for my $prefix (0 .. 32) {
        my $mask = 2**32 - 2**(32 - $prefix);
        $mask2prefix{$mask}   = $prefix;
        $prefix2mask{$prefix} = $mask;
    }

    # Convert a network mask to a prefix ranging from 0 to 32.
    sub mask2prefix( $ ) {
        my $mask = shift;
        if (defined(my $prefix = $mask2prefix{$mask})) {
            return $prefix;
        }
        internal_err "Network mask ", print_ip $mask, " isn't a valid prefix";
    }

    sub prefix2mask( $ ) {
        my $prefix = shift;
        if (defined(my $mask = $prefix2mask{$prefix})) {
            return $mask;
        }
        internal_err "Invalid prefix: $prefix";
    }
}

sub complement_32bit( $ ) {
    my ($ip) = @_;
    return ~$ip & 0xffffffff;
}

# Read IP address. Internally it is stored as an integer.
sub read_ip() {
    skip_space_and_comment;
    if ($input =~ m/\G(\d+)\.(\d+)\.(\d+)\.(\d+)/gc) {
        if ($1 > 255 or $2 > 255 or $3 > 255 or $4 > 255) {
            error_atline "Invalid IP address";
        }
        return unpack 'N', pack 'C4', $1, $2, $3, $4;
    }
    else {
        syntax_err "IP address expected";
    }
}

# Read IP address with optional prefix length: x.x.x.x or x.x.x.x/n.
sub read_ip_opt_prefixlen() {
    my $ip  = read_ip;
    my $len = undef;
    if ($input =~ m/\G\/(\d+)/gc) {
        if ($1 <= 32) {
            $len = $1;
        }
        else {
            error_atline "Prefix length must be greater than 32";
        }
    }
    return $ip, $len;
}

sub gen_ip( $$$$ ) {
    return unpack 'N', pack 'C4', @_;
}

# Convert IP address from internal integer representation to
# readable string.
sub print_ip( $ ) {
    my $ip = shift;
    return sprintf "%vd", pack 'N', $ip;
}

# Generate a list of IP strings from an ref of an array of integers.
sub print_ip_aref( $ ) {
    my $aref = shift;
    return map { print_ip $_; } @$aref;
}

# Check for xxx:xxx
sub check_typed_name() {
    skip_space_and_comment;
    if ($input =~ m/(\G\w+:[\w-]+)/gc) {
        return $1;
    }
    else {
        return undef;
    }
}

sub read_typed_name() {
    check_typed_name or syntax_err "Typed name expected";
}

# Read interface:xxx.xxx
sub read_interface_name() {
    skip_space_and_comment;
    if ($input =~ m/(\G\w+:[\w-]+\.[\w-]+)/gc) {
        return $1;
    }
    else {
        syntax_err "Interface name expected";
    }
}

{

    # user@domain or @domain
    my $domain_regex = qr/@(?:[\w-]+\.)+[\w-]+/;
    my $user_regex =qr/[\w-]+(?:\.[\w-]+)*/;
    my $full_id_regex = qr/$user_regex$domain_regex/;
    my $id_regex = qr/(?:$user_regex)?$domain_regex/;
    my $hostname_regex = qr/host:(?:id:$id_regex|[\w-]+)/;

# Check for xxx:xxx or xxx:[xxx] or xxx:[xxx:xxx]
# or interface:xxx.xxx or interface:xxx.[xxx] or interface:[xxx].[xxx]
# or host:id:user@domain.network
    sub check_typed_ext_name() {
	skip_space_and_comment;
	if ($input =~ m/\G(interface:[][\w-]+\.[][\w-]+ |
			   $hostname_regex |
			   \w+:[][:\w-]+)/gcx) {
	    return $1;
	}
	else {
	    return undef;
	}
    }

    sub read_typed_ext_name() {
	check_typed_ext_name or syntax_err "Typed extended name expected";
    }

# user@domain
    sub read_full_id() {
	skip_space_and_comment;
	if ($input =~ m/\G($full_id_regex)/gco) {
	    return $1;
	}
	else {
	    syntax_err "Full id expected";
	}
    }

# host:xxx or host:id:user@domain or host:id:@domain
    sub check_hostname() {
	skip_space_and_comment;
	if ($input =~
	    m/\G($hostname_regex)/gc) {
	    return $1;
	}
	else {
	    return undef;
	}
    }
}

sub read_identifier() {
    skip_space_and_comment;
    if ($input =~ m/(\G[\w-]+)/gc) {
        return $1;
    }
    else {
        syntax_err "Identifier expected";
    }
}

# Used for reading interface names and attribute 'owner'.
sub read_name() {
    skip_space_and_comment;
    if ($input =~ m/(\G[^;,\s"']+)/gc) {
        return $1;
    }
    else {
        syntax_err "String expected";
    }
}

# Used for reading RADIUS attributes.
sub read_string() {
    skip_space_and_comment;
    if ($input =~ m/\G([^;,"'\n]+)/gc) {
        return $1;
    }
    else {
        syntax_err "String expected";
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
sub read_time_val() {
    my $int    = read_int;
    my $unit   = read_identifier;
    my $factor = $timeunits{$unit} or syntax_err "Invalid time unit";
    return $int * $factor;
}

sub check_description() {
    skip_space_and_comment;
    if (check 'description') {
        skip '=';

        # Read up to end of line, but ignore ';' at EOL.
        # We must use '$' here to match EOL,
        # otherwise $line would be out of sync.
        $input =~ m/\G(.*);?$/gcm;
        return $store_description ? $1 : undef;
    }
    else {
        return undef;
    }
}

# Check if one of the keywords 'permit' or 'deny' is available.
sub check_permit_deny() {
    skip_space_and_comment;
    if ($input =~ m/\G(permit|deny)/gc) {
        return $1;
    }
    else {
        return undef;
    }
}

sub split_typed_name( $ ) {
    my ($name) = @_;

    # Split at first colon, thus the name may contain further colons.
    split /:/, $name, 2;
}

sub check_flag( $ ) {
    my $token = shift;
    if (check $token) {
        skip ';';
        return 1;
    }
    else {
        return undef;
    }
}

sub read_assign($&) {
    my ($token, $fun) = @_;
    skip $token;
    skip '=';
    if (wantarray) {
        my @val = &$fun;
        skip ';';
        return @val;
    }
    else {
        my $val = &$fun;
        skip ';';
        return $val;
    }
}

sub check_assign($&) {
    my ($token, $fun) = @_;
    if (check $token) {
        skip '=';
        if (wantarray) {
            my @val = &$fun;
            skip ';';
            return @val;
        }
        else {
            my $val = &$fun;
            skip ';';
            return $val;
        }
    }
    return;
}

sub read_list(&) {
    my ($fun) = @_;
    my @vals;
    while (1) {
        push @vals, &$fun;
        last if check ';';
        check ',';

        # Allow trailing comma.
        last if check ';';
    }
    return @vals;
}

sub read_list_or_null(&) {
    return () if check ';';
    &read_list(@_);
}

sub read_assign_list($&) {
    my ($token, $fun) = @_;
    skip $token;
    skip '=';
    &read_list($fun);
}

sub check_assign_list($&) {
    my ($token, $fun) = @_;
    if (check $token) {
        skip '=';
        return &read_list($fun);
    }
    return ();
}

sub check_assign_range($&) {
    my ($token, $fun) = @_;
    if (check $token) {
        skip '=';
        my $v1 = &$fun;
        skip '-';
        my $v2 = &$fun;
        skip ';';
        return $v1, $v2;
    }
    return ();
}

# Delete an element from an array reference.
# Return 1 if found, 0 otherwise.
sub aref_delete( $$ ) {
    my ($elt, $aref) = @_;
    for (my $i = 0 ; $i < @$aref ; $i++) {
        if ($aref->[$i] eq $elt) {
            splice @$aref, $i, 1;

#debug "aref_delete: $elt->{name}";
            return 1;
        }
    }
    return 0;
}

####################################################################
# Creation of typed structures
# Currently we don't use OO features;
# We use 'bless' only to give each structure a distinct type.
####################################################################

# Create a new structure of given type;
# initialize it with key / value pairs.
sub new( $@ ) {
    my $type = shift;
    my $self = {@_};
    return bless $self, $type;
}

# A hash with all defined NAT names.
# It is used to check,
# - if all defined NAT mappings are used and
# - if all used mappings are defined.
my %nat_definitions;

our %hosts;

sub check_radius_attributes() {
    my $result = {};
    check 'radius_attributes' or
      return undef;
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        my $key = read_identifier;
        skip '=';
	my $val = read_string;
	skip ';';
	$result->{$key} and error_atline "Duplicate attribute '$key'";
	$result->{$key} = $val;
    }
    return $result;
}

sub read_host( $$ ) {
    my($name, $network_name) = @_;
    my $host = new 'Host';
    if(my ($id) = ($name =~ /^host:id:(.*)$/)) {

	# Make ID unique by appending name of enclosing network.
	$name = "$name.$network_name";
	$host->{id} = $id;
    }
    $host->{name} = $name;
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        if (my @ip = check_assign_list 'ip', \&read_ip) {
            $host->{ips} and error_atline "Duplicate attribute 'ip'";
            $host->{ips} = \@ip;
        }
        elsif (my ($ip1, $ip2) = check_assign_range 'range', \&read_ip) {
            $ip1 <= $ip2 or error_atline "Invalid IP range";
            $host->{range} and error_atline "Duplicate attribute 'range'";
            $host->{range} = [ $ip1, $ip2 ];
        }
        elsif (my @owner = check_assign_list 'owner', \&read_name) {
            $host->{owner} and error_atline "Duplicate attribute 'owner'";
            $host->{owner} = \@owner;
        }
	elsif (my $radius_attributes = check_radius_attributes) {
	    $host->{radius_attributes} and
	      error_atline "Duplicate attribute 'radius_attributes'";
	    $host->{radius_attributes} = $radius_attributes;
	}
        elsif (my $string = check_typed_name) {
            my ($type, $name) = split_typed_name $string;
            if ($type eq 'nat') {
                skip '=';
                skip '{';
                skip 'ip';
                skip '=';
                my $nat_ip = read_ip;
                skip ';';
                skip '}';
                $host->{nat}->{$name}
                  and error_atline "Duplicate NAT definition";
                $host->{nat}->{$name} = $nat_ip;
            }
            else {
                syntax_err "Expected NAT definition";
            }
        }
        else {
            error_atline "Expected some valid attribute";
        }
    }
    $host->{ips} xor $host->{range}
      or error_atline
	"Exactly one of attributes 'ip' and 'range' is needed";

    if ($host->{id}) {
	$host->{radius_attributes} ||= {};
    } else {
	$host->{radius_attributes}
	  and error_atline
	    "Attribute 'radius_attributes' is not allowed for $name";
    }
    if ($host->{nat}) {
        if ($host->{range}) {

            # Look at print_pix_static before changing this.
            error_atline "No NAT supported for host with IP range";
        }
        elsif (@{ $host->{ips} } > 1) {

            # Look at print_pix_static before changing this.
            error_atline "No NAT supported for host with multiple IPs";
        }
    }
    return $host;
}

sub read_nat( $ ) {
    my $name = shift;

    # Currently this needs not to be blessed.
    my $nat = { name => $name };
    (my $nat_tag = $name) =~ s/^nat://;
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        if (my ($ip, $prefixlen) = check_assign 'ip', \&read_ip_opt_prefixlen) {
            if ($prefixlen) {
                my $mask = prefix2mask $prefixlen;
                $nat->{mask} and error_atline "Duplicate IP mask";
                $nat->{mask} = $mask;
            }
            $nat->{ip} and error_atline "Duplicate IP address";
            $nat->{ip} = $ip;
        }
        elsif (my $mask = check_assign 'mask', \&read_ip) {
            $nat->{mask} and error_atline "Duplicate IP mask";
            $nat->{mask} = $mask;
        }
        elsif (my $dynamic = check_flag 'dynamic') {

            # $nat_tag is used later to lookup static translation
            # of hosts inside a dynamically translated network.
            $nat->{dynamic} = $nat_tag;
        }
        elsif (my $subnet = check_assign 'subnet_of', \&read_typed_name) {
            $nat->{subnet_of}
              and error_atline "Duplicate attribute 'subnet_of'";
            $nat->{subnet_of} = $subnet;
        }
    }
    $nat->{ip} or error_atline "Missing IP address";
    $nat_definitions{$nat_tag} = 1;
    return $nat;
}

our %networks;

sub read_network( $ ) {
    my $name = shift;

    # Network name without prefix "network:" is needed to build
    # name of ID-hosts.
    (my $net_name = $name) =~ s/^network://;
    my $network = new('Network', name => $name);
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        if (my ($ip, $prefixlen) = check_assign 'ip', \&read_ip_opt_prefixlen) {
            if (defined $prefixlen) {
                my $mask = prefix2mask $prefixlen;
                defined $network->{mask} and error_atline "Duplicate IP mask";
                $network->{mask} = $mask;
            }
            $network->{ip} and error_atline "Duplicate IP address";
            $network->{ip} = $ip;
        }
        elsif (defined (my $mask = check_assign 'mask', \&read_ip)) {
            defined $network->{mask} and error_atline "Duplicate IP mask";
            $network->{mask} = $mask;
        }
        elsif (check_flag 'unnumbered') {
            defined $network->{ip} and error_atline "Duplicate IP address";
            $network->{ip} = 'unnumbered';
        }
        elsif (check_flag 'route_hint') {

            # Duplicate use of this flag doesn't matter.
            $network->{route_hint} = 1;
        }
	elsif (my $id = check_assign 'id', \&read_full_id) {
	    $network->{id}
	      and error_atline "Duplicate attribute 'id'";
	    $network->{id} = $id;
	}
        elsif (my $subnet = check_assign 'subnet_of', \&read_typed_name) {
            $network->{subnet_of}
              and error_atline "Duplicate attribute 'subnet_of'";
            $network->{subnet_of} = $subnet;
        }
        elsif (my @owner = check_assign_list 'owner', \&read_name) {
            $network->{owner}
              and error_atline "Duplicate attribute 'owner'";
            $network->{owner} = \@owner;
        }
	elsif (my $radius_attributes = check_radius_attributes) {
	    $network->{radius_attributes} and
	      error_atline "Duplicate attribute 'radius_attributes'";
	    $network->{radius_attributes} = $radius_attributes;
	}
	elsif (my $string = check_hostname) {
	    my $host = read_host $string, $net_name;
	    push @{ $network->{hosts} }, $host;
	    my($dummy, $host_name) = split_typed_name $host->{name};
	    $hosts{$host_name} and error_atline "Duplicate host:$host_name";
	    $hosts{$host_name} = $host;
	}
        else {
            my $string = read_typed_name;
            my ($type, $name) = split_typed_name $string;
            if ($type eq 'nat') {
                my $nat = read_nat $string;
                $network->{nat}->{$name}
                  and error_atline "Duplicate NAT definition";
                $network->{nat}->{$name} = $nat;
            }
            else {
                syntax_err "Expected NAT or host definition";
            }
        }
    }

    # Network needs at least IP and mask to be defined.
    my $ip = $network->{ip};

    # Use 'defined' here because IP may have value '0'.
    defined $ip or syntax_err "Missing network IP";
    if ($ip eq 'unnumbered') {

        # Unnumbered network must not have any other attributes.
        for my $key (keys %$network) {
            next if $key eq 'ip' or $key eq 'name';
            error_atline "Unnumbered $network->{name} must not have ",
              ($key eq 'hosts') ? "host definition"
              : ($key eq 'nat') ? "nat definition"
              : "attribute '$key'";
        }
    }
    else {
        my $mask = $network->{mask};

	# Use 'defined' here because mask may have value '0'.
	defined $mask or syntax_err "Missing network mask";

        # Check if network ip matches mask.
        if (($ip & $mask) != $ip) {
            error_atline "IP and mask don't match";

            # Prevent further errors.
            $network->{ip} &= $mask;
        }
        for my $host (@{ $network->{hosts} }) {

            # Link host with network.
            $host->{network} = $network;

            # Check compatibility of host ip and network ip/mask.
            if ($host->{ips}) {
                for my $host_ip (@{ $host->{ips} }) {
                    if ($ip != ($host_ip & $mask)) {
                        error_atline
                          "$host->{name}'s IP doesn't match network IP/mask";
                    }
                }
            }
            elsif ($host->{range}) {
                my ($ip1, $ip2) = @{ $host->{range} };
                if (   $ip != ($ip1 & $mask)
		       or $ip != ($ip2 & $mask)) {
                    error_atline "$host->{name}'s IP range doesn't match",
                      " network IP/mask";
                }
            }
            else {
                internal_err;
            }

            # Compatibility of host and network NAT will be checked later,
            # after global NAT definitions have been processed.
        }
        if (@{ $network->{hosts} } and $network->{route_hint}) {
            error_atline "network must not have host definitions\n",
              " because it has attribute 'route_hint'";
        }

        # Check NAT definitions.
        if ($network->{nat}) {
            for my $nat (values %{ $network->{nat} }) {
                if (defined $nat->{mask}) {
                    unless ($nat->{dynamic}) {
                        $nat->{mask} == $mask
                          or error_atline "Mask for non dynamic $nat->{name}",
			    " must be equal to network mask";
                    }
                }
                else {

                    # Inherit mask from network.
                    $nat->{mask} = $mask;
                }

                # Check if ip matches mask.
                if (($nat->{ip} & $nat->{mask}) != $nat->{ip}) {
                    error_atline "IP for $nat->{name} of doesn't",
                      " match its mask";

                    # Prevent further errors.
                    $nat->{ip} &= $nat->{mask};
                }
            }
        }

	# Check and mark networks with ID-hosts.
	if (my $id_hosts_count = grep { $_->{id} } @{ $network->{hosts} }) {

	    # If one host has ID, all hosts must have ID.
	    @{ $network->{hosts} } == $id_hosts_count
	      or error_atline "All hosts must have ID in $name";

	    # Mark network.
	    $network->{has_id_hosts} = 1;

	    $network->{id}
	      and error_atline
		"Must not use attribute 'id' at $network->{name}\n",
		  " when hosts with ID are defined inside";
	}
	if ($network->{id} or $network->{has_id_hosts}) {
	    $network->{radius_attributes} ||= {};
	} else {
	    $network->{radius_attributes}
	      and error_atline
		"Attribute 'radius_attributes' is not allowed for $name";
	}
    }
    return $network;
}

# Definition of dynamic routing protocols.
# Services below need not to be ordered using order_services
# since they are only used at code generation time.
my %routing_info = (
    EIGRP => {
        name  => 'EIGRP',
        srv   => { name => 'auto_srv:EIGRP', proto => 88 },
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
        srv   => { name => 'auto_srv:OSPF', proto => 89 },
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
        srv   => { name => 'auto_srv:VRRP', proto => 112 },
        mcast => new(
            'Network',
            name => "auto_network:VRRP_multicast",
            ip   => gen_ip(224, 0, 0, 18),
            mask => gen_ip(255, 255, 255, 255)
        )
    },
    HSRP => {
        srv => {
            name      => 'auto_srv:HSRP',
            proto     => 'udp',
            src_range => {
                name  => 'auto_srv:HSRP',
                proto => 'udp',
                range => [ 1, 65535 ]
            },
            dst_range => {
                name  => 'auto_srv:HSRP',
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

our %interfaces;
my @virtual_interfaces;
my @disabled_interfaces;
my @auto_crypto_interfaces;

sub read_interface( $ ) {
    my ($name) = @_;
    my $interface = new('Interface', name => $name);
    unless (check '=') {

        # Short form of interface definition.
        skip ';';
        $interface->{ip} = 'short';
    }
    else {
        skip '{';
        while (1) {
            last if check '}';
            if (my @ip = check_assign_list 'ip', \&read_ip) {
                $interface->{ip} and error_atline "Duplicate attribute 'ip'";
                $interface->{ip} = \@ip;
            }
            elsif (check_flag 'unnumbered') {
                $interface->{ip} and error_atline "Duplicate attribute 'ip'";
                $interface->{ip} = 'unnumbered';
            }
            elsif (check_flag 'negotiated') {
                $interface->{ip} and error_atline "Duplicate attribute 'ip'";
                $interface->{ip} = 'negotiated';
            }
            elsif (my $string = check_typed_name) {
                my ($type, $name) = split_typed_name $string;
                if ($type eq 'nat') {
                    skip '=';
                    skip '{';
                    skip 'ip';
                    skip '=';
                    my $nat_ip = read_ip;
                    skip ';';
                    skip '}';
                    $interface->{nat}->{$name}
                      and error_atline "Duplicate NAT definition";
                    $interface->{nat}->{$name} = $nat_ip;
                }
                else {
                    syntax_err "Expected named attribute";
                }
            }
            elsif (check 'virtual') {

                # Read attributes of redundancy protocol (VRRP/HSRP).
                my $virtual = {};
                skip '=';
                skip '{';
                while (1) {
                    last if check '}';
                    if (my $ip = check_assign 'ip', \&read_ip) {
                        $virtual->{ip}
                          and error_atline "Duplicate virtual IP address";
                        $virtual->{ip} = $ip;
                    }
                    elsif (my $type = check_assign 'type', \&read_name) {
                        $xxrp_info{$type}
                          or error_atline "Unknown redundancy protocol";
                        $virtual->{type}
                          and error_atline "Duplicate redundancy type";
                        $virtual->{type} = $type;
                    }
                    elsif (my $id = check_assign 'id', \&read_name) {
                        $id =~ /^\d+$/
                          or error_atline "Redundancy ID must be numeric";
                        $id < 256
                          or error_atline "Redundancy ID must be < 256";
                        $virtual->{id}
                          and error_atline "Duplicate redundancy ID";
                        $virtual->{id} = $id;
                    }
                    else {
                        syntax_err "Expected valid attribute for virtual IP";
                    }
                }
                $virtual->{ip} or error_atline "Missing virtual IP";
                $virtual->{type}
                  or error_atline "Missing type of redundancy protocol";
                $interface->{virtual} and error_atline "Duplicate virtual IP";
                $interface->{virtual} = $virtual;
                push @virtual_interfaces, $interface;
            }
            elsif (my $value = check_assign 'managed', \&read_identifier) {
                $interface->{managed}
                  and error_atline "Duplicate managed interface type";
                if ($value =~ /^full|secondary$/) {
                    $interface->{managed} = $value;
                }
                else {
                    error_atline "Unknown managed interface type";
                }
                $interface->{managed} = $value;
            }
            elsif (my $nat = check_assign 'nat', \&read_identifier) {

                # Bind NAT to an interface.
                $interface->{bind_nat}
                  and error_atline "Duplicate NAT binding";
                $interface->{bind_nat} = $nat;
            }
            elsif (my $hardware = check_assign 'hardware', \&read_name) {
                $interface->{hardware}
                  and error_atline "Duplicate definition of hardware";
                $interface->{hardware} = $hardware;
            }
            elsif (my $protocol = check_assign 'routing', \&read_name) {
                my $routing = $routing_info{$protocol}
                  or error_atline "Unknown routing protocol";
                $interface->{routing}
                  and error_atline "Duplicate routing protocol";
                $interface->{routing} = $routing;
            }
            elsif (my @names = check_assign_list 'reroute_permit',
                \&read_typed_name)
            {
                my @networks;
                for my $name (@names) {
                    my ($type, $net) = split_typed_name $name;
                    if ($type eq 'network') {
                        push @networks, $net;
                    }
                    else {
                        error_atline 'Expected networks as values';
                    }
                }
                $interface->{reroute_permit}
                  and error_atline 'Duplicate definition of reroute_permit';
                $interface->{reroute_permit} = \@networks;
            }
            elsif (check_flag 'disabled') {
                push @disabled_interfaces, $interface;
            }
            elsif (check_flag 'no_check') {
                $interface->{no_check} = 1;
            }
	    elsif (my $ipsec = check_assign 'auto_crypto', \&read_typed_name) {
		$interface->{auto_crypto}
		  and error_atline 'Duplicate definition of attribute auto_crypto';
		$interface->{auto_crypto} = $ipsec;
		push @auto_crypto_interfaces, $interface;
	    }
            else {
                syntax_err 'Expected some valid attribute';
            }
        }
        unless ($interface->{ip}) {
            error_atline "Missing IP address";
        }
        if ($interface->{nat}) {
            if ($interface->{ip} =~ /unnumbered|negotiated/) {
                error_atline "No NAT supported for $interface->{ip} interface";
            }
            elsif (@{ $interface->{ip} } > 1) {

                # Look at print_pix_static before changing this.
                error_atline "No NAT supported for interface with multiple IPs";
            }
            elsif ($interface->{virtual}) {
                error_atline "No NAT supported for interface with virtual IP";
            }
        }
	if (my $virtual = $interface->{virtual}) {
	    $interface->{ip} =~ /unnumbered|negotiated/
	      and error_atline "No virtual IP supported for $interface->{ip} interface";
	    grep { $_ == $virtual->{ip} } @{ $interface->{ip} }
	      and error_atline "Virtual IP redefines standard IP";

	    # Add virtual IP to list of real IP addresses.
	    push @{ $interface->{ip} }, $virtual->{ip};
	}
	if ($interface->{auto_crypto}) {
	    if ($interface->{ip} =~ /unnumbered|negotiated/) {
                error_atline "No auto_crypto supported for  $interface->{ip} interface";
            }
	}
    }
    return $interface;
}

# PIX firewalls have a security level associated with each interface.
# We don't want to expand our syntax to state them explicitly,
# but instead we try to derive the level from the interface name.
# It is not necessary the find the exact level; what we need to know
# is the relation of the security levels to each other.
sub set_pix_interface_level( $ ) {
    my ($router) = @_;
    for my $hardware (@{ $router->{hardware} }) {
        my $hwname = $hardware->{name};
        my $level;
        if ($hwname eq 'inside') {
            $level = 100;
        }
        elsif ($hwname eq 'outside') {
            $level = 0;
        }
        else {
            unless (($level) = ($hwname =~ /(\d+)$/)
                and 0 < $level
                and $level < 100)
            {
                err_msg "Can't derive PIX security level for ",
                  "$hardware->{interfaces}->[0]->{name}\n",
                  " Interface name should contain a number",
                  " which is used as level";
                $level = 0;
            }
        }
        $hardware->{level} = $level;
    }
}

# Routers which reference one or more RADIUS servers.
my @auth_routers;

our %routers;

sub read_router( $ ) {
    my $name = shift;

    # Router name without prefix "router:" is needed to build interface name.
    (my $rname = $name) =~ s/^router://;
    my $router = new('Router', name => $name);
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        if (check 'managed') {
            $router->{managed}
              and error_atline "Redefining 'managed' attribute";
            my $managed;
            if (check ';') {
                $managed = 'full';
            }
            elsif (check '=') {
                my $value = read_identifier;
                if ($value =~ /^full|secondary$/) {
                    $managed = $value;
                }
                else {
                    error_atline "Unknown managed device type";
                }
                check ';';
            }
            else {
                syntax_err "Expected ';' or '='";
            }
            $router->{managed} = $managed;
        }
        elsif (my $model = check_assign 'model', \&read_identifier) {
            $router->{model} and error_atline "Redefining 'model' attribute";
            unless ($router->{model} = $router_info{$model}) {
                error_atline "Unknown router model '$model'";

                # Prevent further errors.
                $router->{model} = {};
            }
        }
        elsif (check_flag 'no_group_code') {
            $router->{no_group_code} = 1;
        }
        elsif (check_flag 'no_crypto_filter') {
            $router->{no_crypto_filter} = 1;
        }
	elsif (my @radius_servers =
	       check_assign_list 'radius_servers', \&read_typed_name)
        {
	    $router->{radius_servers} and
	      error_atline "Redefining 'radius' attribute";
	    $router->{radius_servers} = \@radius_servers;
	    push @auth_routers, $router;
	}
	elsif (my $radius_attributes = check_radius_attributes) {
	    $router->{radius_attributes} and
	      error_atline "Duplicate attribute 'radius_attributes'";
	    $router->{radius_attributes} = $radius_attributes;
	}
        else {
            my $string = read_typed_name;
            my ($type, $network) = split_typed_name $string;
            $type eq 'interface'
              or syntax_err "Expected interface definition";

            # Derive interface name from router name.
            my $iname     = "$rname.$network";
            my $interface = read_interface "interface:$iname";
            push @{ $router->{interfaces} }, $interface;
            if ($interfaces{$iname}) {
                error_atline "Redefining $interface->{name}";
            }

            # Assign interface to global hash of interfaces.
            $interfaces{$iname} = $interface;

            # Link interface with router object.
            $interface->{router} = $router;

            # Link interface with network name (will be resolved later).
            $interface->{network} = $network;
        }
    }

    # Detailed interface processing for managed routers.
    if (my $managed = $router->{managed}) {

        unless ($router->{model}) {
            err_msg "Missing 'model' for managed $name";

            # Prevent further errors.
            $router->{model} = { name => 'unknown' };
        }

        # Create objects representing hardware interfaces.
        # All logical interfaces using the same hardware are linked
        # to the same hardware object.
        my %hardware;
        for my $interface (@{ $router->{interfaces} }) {
            if (my $hw_name = $interface->{hardware}) {
                my $hardware;
                if ($hardware = $hardware{$hw_name}) {
                    no warnings "uninitialized";

                    # All logical interfaces of one hardware interface
                    # need to use the same nat binding,
                    # because NAT operates on hardware, not on logic.
                    $interface->{bind_nat} eq $hardware->{bind_nat}
                      or err_msg "All logical interfaces of $hw_name\n",
                      " at $router->{name} must use identical NAT binding";
                }
                else {
                    $hardware = { name => $hw_name };
                    $hardware{$hw_name} = $hardware;
                    push @{ $router->{hardware} }, $hardware;
                    if (my $nat = $interface->{bind_nat}) {
                        $hardware->{bind_nat} = $nat;
                    }
                }
                $interface->{hardware} = $hardware;

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
                    err_msg "Missing 'hardware' for $interface->{name}";
                }
            }

            # Propagate filtering attribute 'full' or 'secondary'
            # from router to interfaces.
            $interface->{managed} ||= $managed;
        }
        if ($router->{model}->{has_interface_level}) {
            set_pix_interface_level $router;
        }
	if ($router->{model}->{name} eq 'VPN3K') {
	    $router->{radius_servers} or
	      err_msg "Attribute 'radius_servers' needs to be defined",
		" for $name";
	    $router->{radius_attributes} ||= {};
	}
	else {
	    $router->{radius_attributes}
	      and err_msg "Attribute 'radius_attributes' is not allowed",
		" for $router->{name}";
	    grep { $_->{no_check} } @{$router->{interfaces}}
	      and err_msg "Attribute 'no_check' is not allowed",
		" at interface of $router->{name}";
	}
    }
    else {

        # Interfaces of unmanaged router must not have attribute "managed";
        for my $interface (@{ $router->{interfaces} }) {
            err_msg "$interface->{name} must not have attribute 'managed'\n",
              " because $router->{name} is unmanaged"
              if $interface->{managed};
        }
    }

    return $router;
}

our %anys;

sub read_any( $ ) {
    my $name = shift;
    my $any = new 'Any', name => $name;
    skip '=';
    skip '{';
    if (my @owner = check_assign_list 'owner', \&read_name) {
        $any->{owner} = \@owner;
    }
    $any->{link} = read_assign 'link', \&read_typed_name;
    skip '}';
    return $any;
}

our %everys;

sub read_every( $ ) {
    my $name = shift;
    skip '=';
    skip '{';
    my $link = read_assign 'link', \&read_typed_name;
    skip '}';
    return new('Every', name => $name, link => $link);
}

our %areas;

sub read_area( $ ) {
    my $name = shift;
    my $area = new('Area', name => $name);
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        if (my @names = check_assign_list 'border', \&read_typed_ext_name) {
            my @interfaces;
            for my $name (@names) {
                my ($type, $interface) = split_typed_name $name;
                if ($type eq 'interface') {
                    push @interfaces, $interface;
                }
                else {
                    error_atline 'Expected interfaces as values';
                }
            }
            $area->{border}
              and error_atline 'Duplicate definition of border';
            $area->{border} = \@interfaces;
        }
        elsif (check_flag 'auto_border') {
            $area->{auto_border} = 1;
        }
        elsif (my $name = check_assign 'anchor', \&read_typed_name) {
            my ($type, $network) = split_typed_name $name;
            if ($type eq 'network') {
                $area->{anchor} = $network;
            }
            else {
                error_atline 'Expected network as value';
            }
        }
        elsif (my @owner = check_assign_list 'owner', \&read_name) {
            $area->{owner} and error_atline "Duplicate attribute 'owner'";
            $area->{owner} = \@owner;
        }
        else {
            syntax_err "Expected some valid attribute";
        }
    }
    $area->{border}
      and $area->{anchor}
      and err_msg "Only one of attributes 'border' and 'anchor'",
      " may be defined for $name";
    $area->{anchor}
      and not $area->{auto_border}
      and err_msg "Attribute 'anchor' needs attribute 'auto_border'",
      "to be defined as well";
    $area->{anchor}
      or $area->{border}
      or err_msg "At least one of attributes 'border' and 'anchor'",
      " must be defined for $name";
    return $area;
}

our %groups;

sub read_group( $ ) {
    my $name = shift;
    skip '=';
    my @objects = read_list_or_null \&read_typed_ext_name;
    return new('Group', name => $name, elements => \@objects);
}

our %servicegroups;

sub read_servicegroup( $ ) {
    my $name = shift;
    skip '=';
    my @objects = read_list_or_null \&read_typed_name;
    return new('Servicegroup', name => $name, elements => \@objects);
}

# Use this if src or dst port isn't defined.
# Don't allocate memory again and again.
my $aref_tcp_any = [ 1, 65535 ];

sub read_port_range() {
    if (defined(my $port1 = check_int)) {
        error_atline "Too large port number $port1" if $port1 > 65535;
        error_atline "Invalid port number '0'"      if $port1 == 0;
        if (check '-') {
            if (defined(my $port2 = check_int)) {
                error_atline "Too large port number $port2" if $port2 > 65535;
                error_atline "Invalid port number '0'"      if $port2 == 0;
                error_atline "Invalid port range $port1-$port2"
                  if $port1 > $port2;
                return [ $port1, $port2 ];
            }
            else {
                syntax_err "Missing second port in port range";
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

sub read_port_ranges( $ ) {
    my ($srv) = @_;
    my $range = read_port_range;
    if (check ':') {
        $srv->{src_range} = $range;
        $srv->{dst_range} = read_port_range;
    }
    else {
        $srv->{src_range} = $aref_tcp_any;
        $srv->{dst_range} = $range;
    }
}

sub read_icmp_type_code( $ ) {
    my ($srv) = @_;
    if (defined(my $type = check_int)) {
        error_atline "Too large ICMP type $type" if $type > 255;
        if (check '/') {
            if (defined(my $code = check_int)) {
                error_atline "Too large ICMP code $code" if $code > 255;
                $srv->{type} = $type;
                $srv->{code} = $code;
            }
            else {
                syntax_err "Expected ICMP code";
            }
        }
        else {
            $srv->{type} = $type;
        }
    }
    else {

        # No type and code given.
    }
}

sub read_proto_nr( $ ) {
    my ($srv) = @_;
    if (defined(my $nr = check_int)) {
        error_atline "Too large protocol number $nr" if $nr > 255;
        error_atline "Invalid protocol number '0'"   if $nr == 0;
        if ($nr == 1) {
            $srv->{proto} = 'icmp';

            # No icmp type and code given.
        }
        elsif ($nr == 4) {
            $srv->{proto} = 'tcp';
            $srv->{src_range} = $srv->{dst_range} = $aref_tcp_any;
        }
        elsif ($nr == 17) {
            $srv->{proto} = 'udp';
            $srv->{src_range} = $srv->{dst_range} = $aref_tcp_any;
        }
        else {
            $srv->{proto} = $nr;
        }
    }
    else {
        syntax_err "Expected protocol number";
    }
}

our %services;

sub read_service( $ ) {
    my $name = shift;
    my $service = { name => $name };
    skip '=';
    if (check 'ip') {
        $service->{proto} = 'ip';
    }
    elsif (check 'tcp') {
        $service->{proto} = 'tcp';
        read_port_ranges($service);
    }
    elsif (check 'udp') {
        $service->{proto} = 'udp';
        read_port_ranges $service;
    }
    elsif (check 'icmp') {
        $service->{proto} = 'icmp';
        read_icmp_type_code $service;
    }
    elsif (check 'proto') {
        read_proto_nr $service;
    }
    else {
        my $string = read_name;
        error_atline "Unknown protocol $string in definition of $name";
    }
    skip ';';
    return $service;
}

our %policies;

sub read_user_or_typed_name_list( $ ) {
    my ($name) = @_;
    skip $name;
    skip '=';
    if (check 'user') {
        skip ';';
        return 'user';
    }
    else {
        return read_list \&read_typed_ext_name;
    }
}

sub read_policy( $ ) {
    my ($name) = @_;
    skip '=';
    skip '{';
    my $policy = { name => $name, rules => [] };
    if (my $description = check_description) {
        $policy->{description} = $description;
    }
    my @user = read_assign_list 'user', \&read_typed_ext_name;
    $policy->{user} = \@user;
    while (1) {
        last if check '}';
        if (my $action = check_permit_deny) {
            my $src = [ read_user_or_typed_name_list 'src' ];
            my $dst = [ read_user_or_typed_name_list 'dst' ];
            my $srv = [ read_assign_list 'srv', \&read_typed_name ];
            if ($src->[0] eq 'user') {
                $src = 'user';
            }
            if ($dst->[0] eq 'user') {
                $dst = 'user';
            }
            if ($src ne 'user' && $dst ne 'user') {
                err_msg "All rules of $policy->{name} must use keyword 'user'";
            }
            my $rule = {
                policy => $policy,
                action => $action,
                src    => $src,
                dst    => $dst,
                srv    => $srv
            };
            push @{ $policy->{rules} }, $rule;
        }
        else {
            syntax_err "Expected 'permit' or 'deny'";
        }
    }
    return $policy;
}

our %pathrestrictions;

sub read_pathrestriction( $ ) {
    my $name = shift;
    skip '=';
    my $restriction = new('Pathrestriction', name => $name);
    if (my $description = check_description) {
        $restriction->{description} = $description;
    }
    my @names = read_list \&read_interface_name;
    @names > 1 or warn_msg "Ignoring $name with less than 2 interfaces";
    my @interfaces;
    for my $name (@names) {
        my ($type, $interface) = split_typed_name $name;
        if ($type eq 'interface') {
            push @interfaces, $interface;
        }
        else {
            error_atline "Expected interfaces as values";
        }
    }
    $restriction->{elements} = \@interfaces;
    return $restriction;
}

our %global_nat;

sub read_global_nat( $ ) {
    my $name = shift;
    my $nat  = read_nat $name;
    if (defined $nat->{mask}) {
        if (($nat->{ip} & $nat->{mask}) != $nat->{ip}) {
            error_atline "Global $nat->{name}'s IP doesn't match its mask";
            $nat->{ip} &= $nat->{mask};
        }
    }
    else {
        error_atline "Missing mask for global $nat->{name}";
    }
    $nat->{dynamic}
      or error_atline "Global $nat->{name} must be dynamic";
    return $nat;
}

sub read_attributed_object( $$ ) {
    my ($name, $attr_descr) = @_;
    my $object = { name => $name };
    skip '=';
    skip '{';
    while (1) {
        last if check '}';
        my $attribute = read_identifier;
        my $val_descr = $attr_descr->{$attribute}
          or syntax_err "Unknown attribute '$attribute'";
        skip '=';
        my $val;
        if (my $values = $val_descr->{values}) {
            $val = read_identifier;
            grep { $_ eq $val } @$values
              or syntax_err "Invalid value";
        }
        elsif (my $fun = $val_descr->{function}) {
            $val = &$fun;
        }
        else {
            internal_err;
        }
        skip ';';
        $object->{$attribute} and error_atline "Duplicate attribute";
        $object->{$attribute} = $val;
    }
    for my $attribute (keys %$attr_descr) {
        my $description = $attr_descr->{$attribute};
        unless (defined $object->{$attribute}) {
            if (my $default = $description->{default}) {
                $object->{$attribute} = $default;
            }
            else {
                error_atline "Missing '$attribute' for $object->{name}";
            }
        }

        # Convert to from syntax to internal values, e.g. 'none' => undef.
        if (my $map = $description->{map}) {
            my $value = $object->{$attribute};
            if (exists $map->{$value}) {
                $object->{$attribute} = $map->{$value};
            }
        }
    }
    return $object;
}

# Some attributes are currently commented out,
# because they aren't supported by backendcurrently
my %isakmp_attributes = (
    identity      => { values => [qw( address fqdn )], },
    nat_traversal => {
        values  => [qw( on off )],
        default => 'off',
        map     => { off => undef }
    },
    authentication => { values   => [qw( preshare rsasig )], },
    encryption     => { values   => [qw( aes aes192 des 3des )], },
    hash           => { values   => [qw( md5 sha )], },
    group          => { values   => [qw( 1 2 5 )], },
    lifetime       => { function => \&read_time_val, },
);

our %isakmp;

sub read_isakmp( $ ) {
    my ($name) = @_;
    return read_attributed_object $name, \%isakmp_attributes;
}

my %ipsec_attributes = (
    key_exchange   => { function => \&read_typed_name, },
    esp_encryption => {
        values  => [qw( none aes aes192 des 3des )],
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

sub read_ipsec( $ ) {
    my ($name) = @_;
    return read_attributed_object $name, \%ipsec_attributes;
}

our %crypto;

sub read_crypto( $ ) {
    my ($name) = @_;
    skip '=';
    skip '{';
    my $crypto = { name => $name };
    if (my $description = check_description) {
        $crypto->{description} = $description;
    }
    while (1) {
        last if check '}';
        if (my $action = check_permit_deny) {
            my $src = [ read_assign_list 'src', \&read_typed_ext_name ];
            my $dst = [ read_assign_list 'dst', \&read_typed_ext_name ];
            my $srv = [ read_assign_list 'srv', \&read_typed_name ];
            my $rule = {
                action => $action,
                src    => $src,
                dst    => $dst,
                srv    => $srv
            };
            push @{ $crypto->{rules} }, $rule;
        }
        elsif (my $type = check_assign 'type', \&read_typed_name) {
            $crypto->{type}
              and error_atline "Redefining 'type' attribute";
            $crypto->{type} = $type;
        }
        elsif (my @hubs = check_assign_list 'hub', \&read_typed_ext_name) {
            $crypto->{hub}
              and error_atline "Redefining 'hub' attribute";
            $crypto->{hub} = \@hubs;
        }
        elsif (my @spokes = check_assign_list 'spoke', \&read_typed_ext_name) {
            $crypto->{spoke}
              and error_atline "Redefining 'spoke' attribute";
            $crypto->{spoke} = \@spokes;
        }
        elsif (my @mesh = check_assign_list 'mesh', \&read_typed_ext_name) {
            push @{ $crypto->{meshes} }, \@mesh;
        }
        else {
            syntax_err "Expected valid attribute or rule";
        }
    }
    $crypto->{type} or error_atline "Missing 'type' for $name";

    # Hub and spoke must attributes must be used pairwise.
    # But we can only do a rough estimate,
    # because hub or spoke could be defined as an empty group.
    $crypto->{hub} and $crypto->{spoke}
      or error_atline "Missing 'spoke' for $name";
    $crypto->{spoke} and $crypto->{hub}
      or error_atline "Missing 'hub' for $name";

    return $crypto;
}

my %global_type = (
    router          => [ \&read_router,          \%routers ],
    network         => [ \&read_network,         \%networks ],
    any             => [ \&read_any,             \%anys ],
    every           => [ \&read_every,           \%everys ],
    area            => [ \&read_area,            \%areas ],
    group           => [ \&read_group,           \%groups ],
    service         => [ \&read_service,         \%services ],
    servicegroup    => [ \&read_servicegroup,    \%servicegroups ],
    policy          => [ \&read_policy,          \%policies ],
    pathrestriction => [ \&read_pathrestriction, \%pathrestrictions ],
    nat             => [ \&read_global_nat,      \%global_nat ],
    isakmp          => [ \&read_isakmp,          \%isakmp ],
    ipsec           => [ \&read_ipsec,           \%ipsec ],
    crypto          => [ \&read_crypto,          \%crypto ],
);

sub read_netspoc() {

    # Check for global definitions.
    my $string = check_typed_name or syntax_err '';
    my ($type, $name) = split_typed_name $string;
    my $descr = $global_type{$type}
      or syntax_err "Unknown global definition";
    my ($fun, $hash) = @$descr;
    my $result = $fun->($string);
    $result->{file} = $file;
    if ($hash->{$name}) {
        error_atline "Redefining $string";
    }

    # Result is not used in this module but can be useful
    # when this function is called from outside.
    return $hash->{$name} = $result;
}

# Read input from file and process it by function which is given as argument.
sub read_file( $$ ) {
    local $file = shift;
    my $read_syntax = shift;
    local *FILE;
    open FILE, $file or die "Can't open $file: $!\n";

    # Fill buffer with content of whole FILE.
    local $input = <FILE>;
    close FILE;
    local $line = 1;
    while (skip_space_and_comment) {
        &$read_syntax;
    }
}

sub read_file_or_dir( $;$ );

sub read_file_or_dir( $;$ ) {
    my ($path, $read_syntax) = @_;
    $read_syntax ||= \&read_netspoc;

    # Undef input record separator.
    local $/;
    if (-d $path) {
        local (*DIR);

        # Strip trailing slash for nicer file names in messages.
        $path =~ s</$><>;
        opendir DIR, $path or die "Can't opendir $path: $!\n";
        while (my $file = readdir DIR) {
            next if $file eq '.' or $file eq '..';
            next if $file =~ m/$ignore_files/;
            $file = "$path/$file";
            read_file_or_dir $file, $read_syntax;
        }
    }
    else {
        read_file $path, $read_syntax;
    }
}

sub show_read_statistics() {
    my $n  = keys %networks;
    my $h  = keys %hosts;
    my $r  = keys %routers;
    my $g  = keys %groups;
    my $s  = keys %services;
    my $sg = keys %servicegroups;
    my $p  = keys %policies;
    info "Read $r routers, $n networks, $h hosts";
    info "Read $s services, $sg service groups";
    info "Read $g groups, $p policies";
}

##############################################################################
# Helper functions
##############################################################################

# Type checking functions
sub is_network( $ )      { ref($_[0]) eq 'Network'; }
sub is_router( $ )       { ref($_[0]) eq 'Router'; }
sub is_interface( $ )    { ref($_[0]) eq 'Interface'; }
sub is_host( $ )         { ref($_[0]) eq 'Host'; }
sub is_subnet( $ )       { ref($_[0]) eq 'Subnet'; }
sub is_any( $ )          { ref($_[0]) eq 'Any'; }
sub is_every( $ )        { ref($_[0]) eq 'Every'; }
sub is_area( $ )         { ref($_[0]) eq 'Area'; }
sub is_group( $ )        { ref($_[0]) eq 'Group'; }
sub is_servicegroup( $ ) { ref($_[0]) eq 'Servicegroup'; }
sub is_objectgroup( $ )  { ref($_[0]) eq 'Objectgroup'; }
sub is_chain( $ )        { ref($_[0]) eq 'Chain'; }

sub print_rule( $ ) {
    my ($rule) = @_;
    my $extra = '';
    $extra .= " $rule->{for_router}" if $rule->{for_router};
    $extra .= " stateless"           if $rule->{stateless};
    my $srv = exists $rule->{orig_srv} ? 'orig_srv' : 'srv';
    my $action = $rule->{action};
    $action = $action->{name} if is_chain $action;
    return $action
      . " src=$rule->{src}->{name}; dst=$rule->{dst}->{name}; "
      . "srv=$rule->{$srv}->{name};$extra";
}

##############################################################################
# Order services
##############################################################################
my %srv_hash;

sub prepare_srv_ordering( $ ) {
    my ($srv) = @_;
    my $proto = $srv->{proto};
    my $main_srv;
    if ($proto eq 'tcp' or $proto eq 'udp') {

        # Convert src and dst port ranges from arrays to real service objects.
        # This is used in function expand_rules: An unexpanded rule has
        # references to TCP and UDP services with combined src and dst port
        # ranges.  An expanded rule has distinct references to src and dst
        # services with a single port range.
        for my $where ('src_range', 'dst_range') {

            # An array with low and high port.
            my $range     = $srv->{$where};
            my $key       = join ':', @$range;
            my $range_srv = $srv_hash{$proto}->{$key};
            unless ($range_srv) {
                $range_srv = {
                    name  => $srv->{name},
                    proto => $proto,
                    range => $range
                };
                $srv_hash{$proto}->{$key} = $range_srv;
            }
            $srv->{$where} = $range_srv;
        }
    }
    elsif ($proto eq 'icmp') {
        my $type = $srv->{type};
        my $code = $srv->{code};
        my $key  = defined $type ? (defined $code ? "$type:$code" : $type) : '';
        $main_srv = $srv_hash{$proto}->{$key}
          or $srv_hash{$proto}->{$key} = $srv;
    }
    elsif ($proto eq 'ip') {
        $main_srv = $srv_hash{$proto}
          or $srv_hash{$proto} = $srv;
    }
    else {

        # Other protocol.
        my $key = $proto;
        $main_srv = $srv_hash{proto}->{$key}
          or $srv_hash{proto}->{$key} = $srv;
    }
    if ($main_srv) {

        # Found duplicate service definition.  Link $srv with $main_srv.
        # We link all duplicate services to the first service found.
        # This assures that we always reach the main service from any duplicate
        # service in one step via ->{main}.  This is used later to substitute
        # occurrences of $srv with $main_srv.
        $srv->{main} = $main_srv;
    }
}

sub order_icmp( $$ ) {
    my ($hash, $up) = @_;

    # Handle 'icmp any'.
    if (my $srv = $hash->{''}) {
        $srv->{up} = $up;
        $up = $srv;
    }
    for my $srv (values %$hash) {

        # 'icmp any' has been handled above.
        next unless defined $srv->{type};
        if (defined $srv->{code}) {
            $srv->{up} = ($hash->{ $srv->{type} } or $up);
        }
        else {
            $srv->{up} = $up;
        }
    }
}

sub order_proto( $$ ) {
    my ($hash, $up) = @_;
    for my $srv (values %$hash) {
        $srv->{up} = $up;
    }
}

# Link each port range with the smallest port range which includes it.
# If no including range is found, link it with the next larger service.
sub order_ranges( $$ ) {
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
    $check_subrange = sub ( $$$$ ) {
        my ($a, $a1, $a2, $i) = @_;
        while (1) {
            return if $i == @sorted;
            my $b = $sorted[$i];
            my ($b1, $b2) = @{ $b->{range} };

            # Neighbors
            # aaaabbbb
            if ($a2 + 1 == $b1) {

                # Mark service as candidate for joining of port ranges during
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

#	    debug "$b->{name} [$b1-$b2] < $a->{name} [$a1-$a2]";
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

#	 debug "$b->{name} [$b1-$b2] split into [$x1-$x2] and [$y1-$y2]";
            my $find_or_insert_range = sub( $$$$$ ) {
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

#		     debug "Splitted range is already defined: $b->{name}";
                            return $b;
                        }

                        # New range is larger tha current range and therefore
                        # must be inserted before current one.
                        last;
                    }

                    # New range starts at lower position than current one.
                    # It must be inserted before current range.
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

    # Array wont be empty because $srv_tcp and $srv_udp are defined internally.
    @sorted or internal_err "Unexpected empty array";

    my $a = $sorted[0];
    $a->{up} = $up;
    my ($a1, $a2) = @{ $a->{range} };

    # Ranges "TCP any" and "UDP any" 1..65535 are defined internally,
    # they include all other ranges.
    $a1 == 1 and $a2 == 65535
      or internal_err "Expected $a->{name} to have range 1..65535";

    # There can't be any port which isn't included by ranges "TCP any" or "UDP
    # any".
    $check_subrange->($a, $a1, $a2, 1) and internal_err;
}

sub expand_splitted_services ( $ );

sub expand_splitted_services ( $ ) {
    my ($srv) = @_;
    if (my $split = $srv->{split}) {
        my ($srv1, $srv2) = @$split;
        return expand_splitted_services $srv1, expand_splitted_services $srv2;
    }
    else {
        return $srv;
    }
}

# Service 'ip' is needed later for secondary rules and
# automatically generated deny rules.
my $srv_ip = { name => 'auto_srv:ip', proto => 'ip' };

# Service 'TCP any'.
my $srv_tcp = {
    name      => 'auto_srv:tcp',
    proto     => 'tcp',
    src_range => $aref_tcp_any,
    dst_range => $aref_tcp_any
};

# Service 'UDP any'.
my $srv_udp = {
    name      => 'auto_srv:udp',
    proto     => 'udp',
    src_range => $aref_tcp_any,
    dst_range => $aref_tcp_any
};

# IPSec: Internet key exchange.
# Source and destination port (range) is set to 500.
my $srv_ike = {
    name      => 'auto_srv:IPSec_IKE',
    proto     => 'udp',
    src_range => [ 500, 500 ],
    dst_range => [ 500, 500 ]
};

# IPSec: NAT traversal.
my $srv_natt = {
    name      => 'auto_srv:IPSec_NATT',
    proto     => 'udp',
    src_range => [ 4500, 4500 ],
    dst_range => [ 4500, 4500 ]
};

# IPSec: encryption security payload.
my $srv_esp = { name => 'auto_srv:IPSec_ESP', proto => 50 };

# IPSec: authentication header.
my $srv_ah = { name => 'auto_srv:IPSec_AH', proto => 51 };

# Port range 'TCP any'; assigned in sub order_services below.
my $range_tcp_any;

# Port range 'tcp established' is needed later for reverse rules
# and assigned below.
my $range_tcp_established;

# Order services. We need this to simplify optimization.
# Additionally add internal predefined services.
sub order_services() {
    info 'Arranging services';

    # Internal services need to be processed before user defined services,
    # because we want to avoid handling of {main} for internal services.
    # $srv_tcp and $srv_udp need to be processed before all other TCP and UDP
    # services, because otherwise the range 1..65535 would get a misleading
    # name.
    for my $srv ($srv_ip, $srv_tcp, $srv_udp, $srv_ike, $srv_natt, $srv_esp,
        $srv_ah, values %services)
    {
        prepare_srv_ordering $srv;
    }
    my $up = $srv_ip;

    # This is guaranteed to be defined, because $srv_tcp has been processed
    # already.
    $range_tcp_any         = $srv_hash{tcp}->{'1:65535'};
    $range_tcp_established = {
        %$range_tcp_any,
        name        => 'reverse:TCP_ANY',
        established => 1
    };
    $range_tcp_established->{up} = $range_tcp_any;

    order_ranges($srv_hash{tcp}, $up);
    order_ranges($srv_hash{udp}, $up);
    order_icmp($srv_hash{icmp}, $up) if $srv_hash{icmp};
    order_proto($srv_hash{proto}, $up) if $srv_hash{proto};
}

####################################################################
# Link topology elements each with another
####################################################################

# Link 'any' and 'every' objects with referenced objects.
sub link_any_and_every() {
    for my $obj (values %anys, values %everys) {
        my ($type, $name) = split_typed_name($obj->{link});
        if ($type eq 'network') {
            $obj->{link} = $networks{$name};
        }
        elsif ($type eq 'router') {
            if (my $router = $routers{$name}) {
                $router->{managed}
                  and err_msg "$obj->{name} must not be linked to",
                  " managed $router->{name}";

                # Take some network connected to this router.
                # Since this router is unmanaged, all connected networks
                # will belong to the same security domain.
                unless ($router->{interfaces}) {
                    err_msg "$obj->{name} must not be linked to",
                      " $router->{name} without interfaces";
                    $obj->{disabled} = 1;
                    next;
                }
                $obj->{link} = $router->{interfaces}->[0]->{network};
            }

            # Force error handling below.
            else {
                $obj->{link} = undef;
            }
        }
        else {
            err_msg "$obj->{name} must not be linked to '$type:$name'";
            $obj->{disabled} = 1;
            next;
        }
        unless ($obj->{link}) {
            err_msg "Referencing undefined $type:$name from $obj->{name}";
            $obj->{disabled} = 1;
        }
    }
}

# Link areas with referenced interfaces or network.
sub link_areas() {
    for my $area (values %areas) {
        if (my $name = $area->{anchor}) {
            if (my $network = $networks{$name}) {
                $area->{anchor} = $network;
            }
            else {
                err_msg
                  "Referencing undefined network:$name from $area->{name}";

                # Prevent further errors.
                delete $area->{anchor};
                last;
            }
        }
        else {
            for my $name (@{ $area->{border} }) {
                if (my $interface = $interfaces{$name}) {
                    $interface->{router}->{managed}
                      or err_msg "Referencing unmanaged $interface->{name} ",
                      "from $area->{name}";
                    $name = $interface;
                }
                else {
                    err_msg "Referencing undefined interface:$name",
                      " from $area->{name}";

                    # Prevent further errors.
                    delete $area->{border};
                    last;
                }
            }
        }
    }
}

# Link interface with network in both directions.
sub link_interface_with_net( $ ) {
    my ($interface) = @_;
    my $net_name    = $interface->{network};
    my $network     = $networks{$net_name};
    unless ($network) {
        my $msg =
          "Referencing undefined network:$net_name from $interface->{name}";
        if (grep { $interface eq $_ } @disabled_interfaces) {

            # There is no attached network to be disabled.
            aref_delete $interface, \@disabled_interfaces;
            warn_msg $msg;
        }
        else {
            err_msg $msg;
        }

        # Prevent further errors.
        aref_delete $interface, $interface->{router}->{interfaces};
        return;
    }
    $interface->{network} = $network;
    if ($interface->{reroute_permit}) {
        for my $name (@{ $interface->{reroute_permit} }) {
            if (my $network = $networks{$name}) {
                $name = $network;
            }
            else {
                warn_msg "Ignoring undefined network:$name ",
                  "from attribute 'reroute_permit'\n of $interface->{name}";

                # Prevent further errors.
                delete $interface->{reroute_permit};
            }
        }
    }
    my $ip = $interface->{ip};
    my $network_ip = $network->{ip};
    if ($ip eq 'short') {

        # Nothing to check: short interface may be linked to arbitrary network.
    }
    elsif ($ip eq 'unnumbered') {
        $network->{ip} eq 'unnumbered'
          or err_msg "Unnumbered $interface->{name} must not be linked ",
          "to $network->{name}";
    }
    elsif ($network_ip eq 'unnumbered') {
	err_msg "$interface->{name} must not be linked ",
	  "to unnumbered $network->{name}";
    }
    elsif ($ip eq 'negotiated') {
	# Nothing to be checked: negotiated may be linked to any numbered network.
    }
    else {

        # Check compatibility of interface ip and network ip/mask.
        my $mask       = $network->{mask};
        for my $interface_ip (@$ip) {
            if ($network_ip != ($interface_ip & $mask)) {
                err_msg "$interface->{name}'s IP doesn't match ",
                  "$network->{name}'s IP/mask";
            }
            unless ($mask == 0xffffffff) {
                if ($interface_ip == $network_ip) {
                    err_msg "$interface->{name} has address of its network";
                }
                my $broadcast = $network_ip + complement_32bit $mask;
                if ($interface_ip == $broadcast) {
                    err_msg "$interface->{name} has broadcast address";
                }
            }
        }
    }
    push @{ $network->{interfaces} }, $interface;
}

sub link_pathrestrictions() {
    for my $restrict (values %pathrestrictions) {
        for my $name (@{ $restrict->{elements} }) {
            if (my $interface = $interfaces{$name}) {
                $interface->{router}->{managed}
                  or err_msg "Referencing unmanaged $interface->{name} ",
                  "from $restrict->{name}";

                # Multiple restrictions may be applied to a single
                # interface.
                push @{ $interface->{path_restrict} }, $restrict;

                # Substitute interface name by interface object.
                $name = $interface;
            }
            else {
                err_msg "Referencing undefined interface:$name ",
                  "from $restrict->{name}";

                # Prevent further errors.
                $restrict->{elements} = [];
            }
        }
    }
}


sub expand_group( $$;$ );

# Link RADIUS servers referenced in authenticating routers.
sub link_radius() {
    for my $router (@auth_routers) {
	next if $router->{disabled};

	$router->{radius_servers} =
	  expand_group $router->{radius_servers}, $router->{name};
	for my $element (@{ $router->{radius_servers} }) {
	    if (is_host $element) {
		if ($element->{range} or @{ $element->{ips} } > 1) {
		    err_msg "$element->{name} must have single IP address\n",
		      " because it is used as RADUIS server";
		}
	    } else {
		err_msg "$element->{name} can't be used as RADIUS server";
	    }
	}
    }
}

sub link_auto_crypto() {
    for my $interface (@auto_crypto_interfaces) {

	# Convert name of ipsec definition to object of ipsec definition.
        my ($type, $name) = split_typed_name $interface->{auto_crypto};
        if ($type eq 'ipsec') {
            my $ipsec = $ipsec{$name}
              or err_msg "Can't resolve reference to '$type:$name' at $interface->{name}";
            $interface->{auto_crypto} = $ipsec;
	} else {
	    err_msg "Unknown type '$type' for $name";
	}
    }
}

sub link_topology() {
    info "Linking topology";
    for my $interface (values %interfaces) {
        link_interface_with_net($interface);
    }
    link_any_and_every;
    link_areas;
    link_pathrestrictions;
    link_radius;
    link_auto_crypto;
    for my $network (values %networks) {
        if (    $network->{ip} eq 'unnumbered'
            and $network->{interfaces}
            and @{ $network->{interfaces} } > 2)
        {
            err_msg "Unnumbered $network->{name} is connected to",
              " more than two interfaces:";
            for my $interface (@{ $network->{interfaces} }) {
                print STDERR " $interface->{name}\n";
            }
        }

        # 1. Check for duplicate interface addresses.
        # 2. Short interfaces must not be used, if a managed interface
        #    with static routing exists in the same network.
        my %ip;
        my ($short_intf, $route_intf);
        for my $interface (@{ $network->{interfaces} }) {
            my $ips = $interface->{ip};
            if ($ips eq 'short') {
                $short_intf = $interface;
            }
            else {
                if ($interface->{router}->{managed}
                    and not $interface->{routing})
                {
                    $route_intf = $interface;
                }
                unless ($ips =~ /unnumbered|negotiated/) {
                    for my $ip (@$ips) {
                        if (my $old_intf = $ip{$ip}) {
                            unless ($ip eq $old_intf->{virtual}->{ip}
                                and $ip eq $interface->{virtual}->{ip})
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
            }
            if ($short_intf and $route_intf) {
                err_msg "$short_intf->{name} must be defined in more detail,",
                  " since there is\n",
                  " a managed $route_intf->{name} with static routing enabled.";
            }
        }
        for my $host (@{ $network->{hosts} }) {
            if (my $ips = $host->{ips}) {
                for my $ip (@$ips) {
                    if (my $old_intf = $ip{$ip}) {
                        err_msg "Duplicate IP address for $old_intf->{name}",
                          " and $host->{name}";
                    }
                }
            }
            elsif (my $range = $host->{range}) {
                for (my $ip = $range->[0] ; $ip <= $range->[1] ; $ip++) {
                    if (my $old_intf = $ip{$ip}) {
                        err_msg "Duplicate IP address for $old_intf->{name}",
                          " and $host->{name}";
                    }
                }
            }
        }
        if ($network->{subnet_of}) {
            my ($type, $name) = split_typed_name($network->{subnet_of});
            if ($type eq 'network') {
                if (my $subnet = $networks{$name}) {
                    $network->{subnet_of} = $subnet;
                }
                else {
                    warn_msg "Ignoring undefined network:$name",
                      " from attribute 'subnet_of'\n", " of $network->{name}";
                }
            }
            else {
                err_msg "Attribute 'subnet_of' of $network->{name}",
                  " must not be linked to $type:$name";
            }
        }
        for my $nat (values %{ $network->{nat} }) {
            if ($nat->{subnet_of}) {
                my ($type, $name) = split_typed_name($nat->{subnet_of});
                if ($type eq 'network') {
                    if (my $subnet = $networks{$name}) {
                        $nat->{subnet_of} = $subnet;
                    }
                    else {
                        warn_msg "Ignoring undefined network:$name",
                          " from attribute 'subnet_of'\n",
                          " of $nat->{name} of $network->{name}";
                    }
                }
                else {
                    err_msg "Attribute 'subnet_of' of",
                      " $nat->{name} of $network->{name}\n",
                      " must not be linked to $type:$name";
                }
            }
        }
    }
    for my $nat (values %global_nat) {
        if ($nat->{subnet_of}) {
            my ($type, $name) = split_typed_name($nat->{subnet_of});
            if ($type eq 'network') {
                if (my $subnet = $networks{$name}) {
                    $nat->{subnet_of} = $subnet;
                }
                else {
                    warn_msg "Ignoring undefined network:$name",
                      " from attribute 'subnet_of'\n",
                      " of global $nat->{name}";
                }
            }
            else {
                err_msg "Attribute 'subnet_of' of global $nat->{name}",
                  " must not be linked to $type:$name";
            }
        }
    }
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

sub disable_behind( $ );

sub disable_behind( $ ) {
    my ($in_interface) = @_;

#  debug "disable_behind $in_interface->{name}";
    $in_interface->{disabled} = 1;
    my $network = $in_interface->{network};
    if ($network->{disabled}) {

#     debug "Stop disabling at $network->{name}";
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

#	 debug "Stop disabling at $interface->{name}";
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
my @managed_routers;
my @routers;
my @networks;
my @all_anys;
my @all_areas;

sub mark_disabled() {

    # Mark all disabled interfaces for the second pass to be able
    # detecting loops.
    for my $interface (@disabled_interfaces) {
        $interface->{disabled} = 1;
    }
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
        aref_delete($interface, $router->{interfaces});
    }
    for my $obj (values %everys) {
        next if $obj->{disabled};
        $obj->{disabled} = 1 if $obj->{link}->{disabled};
    }
    for my $obj (values %anys) {
        next if $obj->{disabled};
        if ($obj->{link}->{disabled}) {
            $obj->{disabled} = 1;
        }
        else {
            push @all_anys, $obj;
        }
    }
    for my $area (values %areas) {
        if (my $anchor = $area->{anchor}) {
            push @all_areas, $area if not $anchor->{disabled};
        }
        else {
            $area->{border} =
              [ grep { not $_->{disabled} } @{ $area->{border} } ];
            push @all_areas, $area if @{ $area->{border} };
        }
    }
    for my $router (values %routers) {
        unless ($router->{disabled}) {
            push @routers, $router;
            push @managed_routers, $router if $router->{managed};
        }
    }
    for my $network (values %networks) {
        unless ($network->{disabled}) {
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
my @inverse_masks = map { complement_32bit prefix2mask $_ } (0 .. 32);

# Convert an IP range to a set of covering IP/mask pairs.
sub split_ip_range( $$ ) {
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

sub convert_hosts() {
    info "Converting hosts to subnets";
    for my $network (@networks) {
        next if $network->{ip} eq 'unnumbered';
        my @inv_prefix_aref;

        # Converts hosts and ranges to subnets.
        # Eliminate duplicate subnets.
        for my $host (@{ $network->{hosts} }) {
            my $name = $host->{name};
            my $nat  = $host->{nat};
            my $id   = $host->{id};
            my @ip_mask;
            if ($host->{ips}) {
                @ip_mask = map [ $_, 0xffffffff ], @{ $host->{ips} };
            }
            elsif ($host->{range}) {
                my ($ip1, $ip2) = @{ $host->{range} };
                @ip_mask = split_ip_range $ip1, $ip2;
            }
            else {
                internal_err "unexpected host type";
            }
            for my $ip_mask (@ip_mask) {
                my ($ip, $mask) = @$ip_mask;
                my $inv_prefix = 32 - mask2prefix $mask;
                if (my $other_subnet = $inv_prefix_aref[$inv_prefix]->{$ip}) {
                    my $nat2 = $other_subnet->{nat};
                    if ($nat xor $nat2) {
                        err_msg "Inconsistent NAT definition for",
                          "$other_subnet->{name} and $host->{name}";
                    }
                    elsif ($nat and $nat2) {

                        # Number of entries is equal.
                        if (keys %$nat == keys %$nat2) {

                            # Entries are equal.
                            for my $name (keys %$nat) {
                                unless ($nat2->{$name}
                                    and $nat->{$name} eq $nat2->{$name})
                                {
                                    err_msg "Inconsistent NAT definition for",
                                      "$other_subnet->{name} and $host->{name}";
                                    last;
                                }
                            }
                        }
                        else {
                            err_msg "Inconsistent NAT definition for",
                              "$other_subnet->{name} and $host->{name}";
                        }
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
                        nat     => $nat
                    );
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

        # Find adjacent subnets which build a larger subnet.
        my $network_inv_prefix = 32 - mask2prefix $network->{mask};
        for (my $i = 0 ; $i < @inv_prefix_aref ; $i++) {
            if (my $ip2subnet = $inv_prefix_aref[$i]) {
                my $next   = 2**$i;
                my $modulo = 2 * $next;
                for my $ip (keys %$ip2subnet) {
                    my $subnet = $ip2subnet->{$ip};

                    # Don't combine subnets with NAT
                    # ToDo: This would be possible if all NAT addresses
                    #  match too.
                    # But, attention for PIX firewalls:
                    # static commands for networks / subnets block
                    # network and broadcast address.
                    next if $subnet->{nat};

		    # Don't combine subnets having radius-ID.
		    next if $subnet->{id};

                    # Only take the left part of two adjacent subnets.
                    if ($ip % $modulo == 0) {
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
                                $inv_prefix_aref[$up_inv_prefix]->{$ip} = $up;
                            }
                            $subnet->{up}   = $up;
                            $neighbor->{up} = $up;

                            # Don't search for enclosing subnet below.
                            next;
                        }
                    }

                    # For neighbors, {up} has been set already.
                    next if $subnet->{up};

                    # Search for enclosing subnet.
                    for (my $j = $i + 1 ; $j < @inv_prefix_aref ; $j++) {
                        my $mask = prefix2mask(32 - $j);
                        $ip &= $mask;
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
        # Do the same for interfaces and the network itself.
        $network->{up} = $network->{any};
        for my $interface (@{ $network->{interfaces} }) {
            $interface->{up} = $network;
        }
    }
}

# Find adjacent subnets and substitute them by their enclosing subnet.
sub combine_subnets ( $ ) {
    my ($aref) = @_;
    my %hash;
    for my $subnet (@$aref) {
        $hash{$subnet} = $subnet;
    }
    for my $subnet (@$aref) {
        my $neighbor;
        if ($neighbor = $subnet->{neighbor} and $hash{$neighbor}) {
            my $up = $subnet->{up};
            unless ($hash{$up}) {
                $hash{$up} = $up;
                push @$aref, $up;
            }
            delete $hash{$subnet};
            delete $hash{$neighbor};
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
# src, dst and srv
####################################################################

my %name2object = (
    host      => \%hosts,
    network   => \%networks,
    interface => \%interfaces,
    any       => \%anys,
    every     => \%everys,
    group     => \%groups,
);

# Initialize 'special' objects which implicitly denote a group of objects.
#
# interface:[managed].[all], group of all interfaces of managed routers
# interface:[managed].[auto], group of [auto] interfaces of managed routers
# interface:[all].[all], all routers, all interfaces
# interface:[all].[auto], all routers, [auto] interfaces
# any:[all], group of all security domains
# any:[local], denotes the 'any' object, which is directly attached to
#              an interface.

sub set_auto_groups () {
    my @managed_interfaces;
    my @all_interfaces;
    for my $router (values %routers) {
        my @interfaces =
          grep { not $_->{ip} =~ /unnumbered|negotiated/ } @{ $router->{interfaces} };
        if ($router->{managed}) {
            push @managed_interfaces, @interfaces;
        }
        push @all_interfaces, @interfaces;
        (my $name = $router->{name}) =~ s /^router://;
        $interfaces{"$name.[all]"} = new(
            'Group',
            name     => "interface:$name.[all]",
            elements => \@interfaces,
            is_used  => 1
        );
    }
    $interfaces{'[managed].[all]'} = new(
        'Group',
        name     => "interface:[managed].[all]",
        elements => \@managed_interfaces,
        is_used  => 1
    );
    $interfaces{'[all].[all]'} = new(
        'Group',
        name     => "interface:[all].[all]",
        elements => \@all_interfaces,
        is_used  => 1
    );
    $routers{'[managed]'} = new(
        'Group',
        name     => "router:[managed]",
        elements => \@managed_routers,
        is_used  => 1
    );
    $routers{'[all]'} = new(
        'Group',
        name     => "router:[all]",
        elements => \@routers,
        is_used  => 1
    );
    $anys{'[all]'} = new(
        'Group',
        name     => "any:[all]",
        elements => \@all_anys,
        is_used  => 1
    );

    # String is expanded to a real 'any' object during expand_rules.
    $anys{'[local]'} = "any:[local]";
}

# Get a reference to an array of network object names and
# return a reference to an array of network objects
sub expand_group1( $$ );

sub expand_group1( $$ ) {
    my ($obref, $context) = @_;
    my @objects;
    for my $tname (@$obref) {
        my ($type, $name) = split_typed_name($tname);
        my $object;
        if (not $name2object{$type}) {
            err_msg "Unknown type of '$tname' in $context";
            next;
        }
        unless (    # A simple object type:name.
            $object = $name2object{$type}->{$name}
            or

            # interface:name.[auto]
            $type eq 'interface'
            and $name =~ /^(.*)\.\[auto\]$/
            and $object = $routers{$1}
            or

            # network:[area:name] or any:[area:name]
            # Variable $type will be used below when expanding area to objects
            # of type $type.
            $type     =~ /^(network|any)$/
            and $name =~ /^\[area:(.*)\]/
            and $object = $areas{$1}
          )
        {
            err_msg "Can't resolve reference to '$tname' in $context";
            next;
        }

        # Split a group into its members.
        if (is_group $object) {
            my $elements = $object->{elements};

            # Check for recursive definitions.
            if ($elements eq 'recursive') {
                err_msg "Found recursion in definition of $context";
                $object->{elements} = $elements = [];
            }

            # Detect, if group has already been converted from names to
            # references.
            unless ($object->{is_used}) {

                # Mark group for detection of recursive group definitions.
                $object->{elements} = 'recursive';
                $object->{is_used}  = 1;
                $elements = expand_group1 $elements, $tname;

                # Cache result for further references to the same group.
                $object->{elements} = $elements;
            }
            push @objects, @$elements;
        }
        elsif (is_every $object) {

            # Expand an 'every' object to all networks in its security domain.
            # Attention: this doesn't include unnumbered networks.
            unless ($object->{disabled}) {
                push @objects,
                  grep { not $_->{route_hint} }
                  @{ $object->{link}->{any}->{networks} };

                # This may later be used to check that this object is used.
                # Similar to check_unused_groups.
                $object->{is_used} = 1;
            }
        }
        elsif (is_area $object) {

            # Expand an 'area' object to containing networks or 'any' objects,
            # depending on value of $type.
            unless ($object->{disabled}) {
                if ($type eq 'network') {
                    push @objects,
                      grep { not $_->{route_hint} } map @{ $_->{networks} },
                      @{ $object->{anys} };
                }
                elsif ($type eq 'any') {
                    push @objects, @{ $object->{anys} };
                }
                else {
                    internal_err;
                }

                # This may later be used to check that this object is used.
                # Similar to check_unused_groups.
                $object->{is_used} = 1;
            }
        }
        else {
            push @objects, $object;
        }
    }
    for my $object (@objects) {

        # Ignore "any:[local]".
        next unless ref $object;
        if ($object->{disabled}) {
            $object = undef;
        }
        elsif (is_network $object) {
            if ($object->{ip} eq 'unnumbered') {
                err_msg
                  "Unnumbered $object->{name} must not be used in $context";
                $object = undef;
            }
            elsif ($object->{route_hint}) {
                err_msg "$object->{name} marked as 'route_hint'",
                  " must not be used in $context";
                $object = undef;
            }
	    elsif ($object->{has_id_hosts}) {
		err_msg "$object->{name} having ID-hosts must",
		  " not be used in $context";
	    }
        }
        elsif (is_interface $object) {
            if ($object->{ip} =~ /short|unnumbered|negotiated/) {
                err_msg "$object->{ip} $object->{name} must not be used in $context";
                $object = undef;
            }
        }
    }
    return \@objects;
}

sub expand_group( $$;$ ) {
    my ($obref, $context, $convert_hosts) = @_;
    my $aref = expand_group1 $obref, $context;
    if ($convert_hosts) {
        my @subnets;
        my @other;
        for my $obj (@$aref) {
            next unless $obj;
            if (is_host $obj) {
                push @subnets, @{ $obj->{subnets} };
            }
            else {
                push @other, $obj;
            }
        }
        push @other, @{ combine_subnets \@subnets };
        return \@other;
    }
    else {
        return [ grep { defined $_ } @$aref ];
    }

}

sub check_unused_groups() {
    return unless $allow_unused_groups;
    for my $group (values %groups, values %servicegroups) {
        unless ($group->{is_used}) {
            my $msg;
            if (my $size = @{ $group->{elements} }) {
                $msg = "unused $group->{name} with $size element(s)";
            }
            else {
                $msg = "unused empty $group->{name}";
            }
            if ($allow_unused_groups eq 'warn') {
                warn_msg $msg;
            }
            else {
                err_msg $msg;
            }
        }
    }
}

sub expand_services( $$ );

sub expand_services( $$ ) {
    my ($aref, $context) = @_;
    my @services;
    for my $tname (@$aref) {
        my ($type, $name) = split_typed_name($tname);
        if ($type eq 'service') {
            if (my $srv = $services{$name}) {
                push @services, $srv;

		# Currently needed by external program 'cut-netspoc'.
		$srv->{is_used}  = 1;
            }
            else {
                err_msg "Can't resolve reference to '$tname' in $context";
                next;
            }
        }
        elsif ($type eq 'servicegroup') {
            if (my $srvgroup = $servicegroups{$name}) {
                my $elements = $srvgroup->{elements};
                if ($elements eq 'recursive') {
                    err_msg "Found recursion in definition of $context";
                    $srvgroup->{elements} = $elements = [];
                }

                # Check if it has already been converted
                # from names to references.
                elsif (not $srvgroup->{is_used}) {

                    # Detect recursive definitions.
                    $srvgroup->{elements} = 'recursive';
                    $srvgroup->{is_used}  = 1;
                    $elements = expand_services $elements, $tname;

                    # Cache result for further references to the same group.
                    $srvgroup->{elements} = $elements;
                }
                push @services, @$elements;
            }
            else {
                err_msg "Can't resolve reference to '$tname' in $context";
                next;
            }
        }
        else {
            err_msg "Unknown type of '$type:$name' in $context";
        }
    }
    return \@services;
}

sub path_first_interfaces( $$ );

# Hash with attributes deny, any, permit for storing
# expanded rules of different type.
our %expanded_rules = (deny => [], any => [], permit => []);

# Hash for ordering all rules:
# $rule_tree{$action}->{$src}->{$dst}->{$src_range}->{$srv} = $rule;
my %rule_tree;
my %reverse_rule_tree;

# Hash for converting a reference of an object back to this object.
my %ref2obj;

# Add rules to $rule_tree for efficient lookup.
sub add_rules( $$ ) {
    my ($rules_ref, $rule_tree) = @_;
    for my $rule (@$rules_ref) {
        my ($action, $src, $dst, $src_range, $srv) =
          @{$rule}{ 'action', 'src', 'dst', 'src_range', 'srv' };
        $ref2obj{$src_range} = $src_range;
        $ref2obj{$srv}       = $srv;

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
          $rule_tree->{$action}->{$src}->{$dst}->{$src_range}->{$srv};
        if ($old_rule) {

            # Found identical rule.
            $rule->{deleted} = $old_rule;
            next;
        }
        $rule_tree->{$action}->{$src}->{$dst}->{$src_range}->{$srv} = $rule;
    }
}

sub get_any( $ ) {
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        return $obj->{any};
    }
    elsif ($type eq 'Subnet') {
        return $obj->{network}->{any};
    }
    elsif ($type eq 'Interface') {
        if ($obj->{router}->{managed}) {
            return $obj->{router};
        }
        else {
            return $obj->{network}->{any};
        }
    }
    elsif ($type eq 'Any') {
        return $obj;
    }

    # Only used when called from expand_rules.
    elsif ($type eq 'Router') {
        if ($obj->{managed}) {
            return $obj;
        }
        else {
            return $obj->{interfaces}->[0]->{network}->{any};
        }
    }
    elsif ($type eq 'Host') {
        return $obj->{network}->{any};
    }
    elsif ($obj eq 'any:[local]') {
        return $obj;    # A value, not equal to any other security domain.
    }
    else {
        internal_err "unexpected $obj->{name}";
    }
}

# Return associated 'any' object of an interface.
# Give error message if no interface is provided.
sub get_any_local ( $ ) {
    my ($obj) = @_;
    if (is_interface $obj and $obj->{router}->{managed}) {
        return $obj->{any};
    }
    else {
        my $name = $obj eq 'any:[local]' ? $obj : $obj->{name};
        err_msg "any:[local] must only be used in conjunction",
          " with a managed interface\n", " but not with $name in rule of $name";

        # Continue with a valid value to prevent further errors.
        return $obj;
    }
}

sub get_auto_interface ( $$$ ) {
    my ($src, $dst, $context) = @_;
    my @result;
    for my $interface (path_first_interfaces $src, $dst) {
        if ($interface->{ip} =~ /unnumbered|short|negotiated/) {
            err_msg "'$interface->{ip}' $interface->{name}",
              " (from .[auto])\n", " must not be used in rule of $context";
        }
        else {
            push @result, $interface;
        }
    }
    return @result;
}

# This handles a rule between objects inside a single security domain or
# between interfaces of a single managed router or between two instances of
# 'any:[local]'.
sub warn_unenforceable ( $$$$ ) {
    my ($src, $dst, $domain, $context) = @_;

    if ($src eq 'any:[local]') {
        err_msg "'any:[local]' is used as src and dst in $context";
        return;
    }
    return if not $check_unenforceable;

    # A rule between identical objects is a common case
    # which results from rules with "src=user;dst=user;".
    return if $src eq $dst;

    if (is_router $domain) {

        # Auto interface is assumed to be identical
        # to each other interface of a single router.
        return if is_router $src or is_router $dst;
    }
    else {
        if (   is_subnet $src and is_subnet $dst
            or is_host $src and is_host $dst )
        {

            # For rules with different subnets of a single network no warning
            # is shown, because at this point we don't know if the subnets
            # have been expanded from a single host.
            return if $src->{network} eq $dst->{network};
        }
    }

    # Show warning or error message if rule is between
    # - different interfaces or
    # - different networks or
    # - subnets/hosts of different networks.
    my $msg =
      "Unenforceable rule of $context:\n src=$src->{name}; dst=$dst->{name}";
    $check_unenforceable eq 'warn' ? warn_msg $msg : err_msg $msg;
}

# Parameters:
# - Reference to array of unexpanded rules.
# - Current context for error messages: name of policy or crypto object.
# - Reference to hash with attributes deny, any, permit for storing
#   resulting expanded rules of different type.
sub expand_rules ( $$$ ) {
    my ($rules_ref, $context, $result) = @_;

    # For collecting resulting expanded rules.
    my ($deny, $any, $permit) = @{$result}{ 'deny', 'any', 'permit' };

    for my $unexpanded (@$rules_ref) {

        my $action = $unexpanded->{action};
        for my $src (@{ $unexpanded->{src} }) {
            my $src_any = get_any $src;
            for my $dst (@{ $unexpanded->{dst} }) {
                my $dst_any = get_any $dst;

                # Check for unenforceable rule.
                if ($src_any eq $dst_any) {
                    warn_unenforceable $src, $dst, $src_any, $context;

                    # Ignore this rule.
                    next;
                }
                my @src =
                    is_router $src
                  ? get_auto_interface $src, $dst, $context
                  : ($src);
                my @dst =
                    is_router $dst
                  ? get_auto_interface $dst, $src, $context
                  : ($dst);
                for my $src (@src) {

                    # Prevent modification of original array.
                    my $src = $src;
                    $ref2obj{$src} = $src;
                    for my $dst (@dst) {
                        my $dst = $dst;    # Prevent ...
                        if ($src eq 'any:[local]') {
                            $src = get_any_local($dst);
                            $ref2obj{$src} = $src;
                        }
                        if ($dst eq 'any:[local]') {
                            $dst = get_any_local($src);
                        }
                        $ref2obj{$dst} = $dst;
                        for my $srv (@{ $unexpanded->{srv} }) {

                            # If $srv is duplicate of an identical service,
                            # use the main service, but remember the original
                            # one for debugging / comments.
                            my $orig_srv;

                            # Prevent modification of original array.
                            my $srv = $srv;
                            my $add_rule = sub ( $$$$$$$ ) {
                                my ($action, $src, $dst, $src_range, $srv,
                                    $unexpanded, $orig_srv)
                                  = @_;
                                my $rule = {
                                    action    => $action,
                                    src       => $src,
                                    dst       => $dst,
                                    src_range => $src_range,
                                    srv       => $srv,

                                    # Remember unexpanded rule.
                                    rule => $unexpanded
                                };
                                $rule->{orig_srv} = $orig_srv if $orig_srv;
                                if ($action eq 'deny') {
                                    push @$deny, $rule;
                                }
                                elsif (is_any($src) or is_any($dst)) {
                                    push @$any, $rule;
                                }
                                else {
                                    push @$permit, $rule;
                                }
                            };
                            if (my $main_srv = $srv->{main}) {
                                $orig_srv = $srv;
                                $srv      = $main_srv;
                            }
                            my $src_range;
                            my $proto = $srv->{proto};
                            if ($proto eq 'tcp' || $proto eq 'udp') {
                                $orig_srv  = $srv unless $orig_srv;
                                $src_range = $srv->{src_range};
                                $srv       = $srv->{dst_range};
                                for my $src_range (
                                    expand_splitted_services $src_range)
                                {
                                    for my $srv (expand_splitted_services $srv)
                                    {
                                        $add_rule->(
                                            $action, $src, $dst, $src_range,
                                            $srv, $unexpanded, $orig_srv
                                        );
                                    }
                                }
                            }
                            else {
                                $src_range = $srv_ip;
                                $add_rule->(
                                    $action, $src, $dst, $src_range, $srv,
                                    $unexpanded, $orig_srv
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    # Result is indirectly returned using parameter $result.
}

sub expand_policies( ;$) {
    my ($convert_hosts) = @_;
    convert_hosts if $convert_hosts;
    info "Expanding policies";

    # Prepare special groups.
    set_auto_groups;

    # Sort by policy name to make output deterministic.
    for my $key (sort keys %policies) {
        my $policy = $policies{$key};
        my $name   = $policy->{name};
        my $user   = $policy->{user} = expand_group $policy->{user},
          "user of $name", $convert_hosts;
        for my $rule (@{ $policy->{rules} }) {
            for my $where ('src', 'dst') {
                if ($rule->{$where} eq 'user') {
                    $rule->{$where} = $user;
                }
                else {
                    $rule->{$where} =
                      expand_group($rule->{$where}, "$where of rule in $name",
                        $convert_hosts);
                }
            }
            $rule->{srv} = expand_services $rule->{srv}, "rule in $name";
        }
        expand_rules $policy->{rules}, $name, \%expanded_rules;
    }
    for my $type ('deny', 'any', 'permit') {
        add_rules $expanded_rules{$type}, \%rule_tree;
    }
}

##############################################################################
# Distribute NAT bindings
##############################################################################

# NAT Map: a mapping Network -> NAT-Network (i.e. ip, mask, dynamic)
# NAT Domain: an maximal area of our topology (a set of connected networks)
# where the NAT mapping is identical at each network.
sub set_natdomain( $$$ );

sub set_natdomain( $$$ ) {
    my ($network, $domain, $in_interface) = @_;
    if ($network->{nat_domain}) {

        # Found a loop inside a NAT domain.
        return;
    }
    $network->{nat_domain} = $domain;
    push @{ $domain->{networks} }, $network;
    my $nat_map = $domain->{nat_map};
    for my $interface (@{ $network->{interfaces} }) {

        # Ignore interface where we reached this network.
        next if $interface eq $in_interface;
        my $router  = $interface->{router};
        my $managed = $router->{managed};
        my $nat_tag = $interface->{bind_nat} || 0;
        for my $out_interface (@{ $router->{interfaces} }) {
            my $out_nat_tag = $out_interface->{bind_nat} || 0;
            if ($out_nat_tag eq $nat_tag) {

                # $nat_map will be collected at nat domains, but is needed at
                # logical and hardware interfaces of managed routers.
                if ($managed) {

#	       debug "$domain->{name}: $out_interface->{name}";
                    $out_interface->{nat_map} =
                      $out_interface->{hardware}->{nat_map} = $nat_map;
                }

                # Don't process interface where we reached this router.
                next if $out_interface eq $interface;

                # Current nat domain continues behind this interface.
                set_natdomain $out_interface->{network}, $domain,
                  $out_interface;
            }
            else {

                # New NAT domain starts at some interface of current router.
                # Remember NAT tag of current domain.
                if (my $old_nat_tag = $router->{nat_tag}->{$domain}) {
                    if ($old_nat_tag ne $nat_tag) {
                        err_msg
                          "Inconsistent NAT in loop at $router->{name}:\n",
                          "nat:$old_nat_tag vs. nat:$nat_tag";
                    }

                    # NAT domain and router have been linked together already.
                    next;
                }
                $router->{nat_tag}->{$domain} = $nat_tag;
                push @{ $domain->{routers} },     $router;
                push @{ $router->{nat_domains} }, $domain;
            }
        }
    }
}

sub distribute_nat1( $$$$ );

sub distribute_nat1( $$$$ ) {
    my ($domain, $nat_tag, $depth, $in_router) = @_;

#  debug "nat:$nat_tag depth $depth at $domain->{name} from $in_router->{name}";
    if ($domain->{active_path}) {

#     debug "nat:$nat_tag loop";
        # Found a loop
        return;
    }

    # Tag is already there.
    return if $domain->{nat_info}->[$depth]->{$nat_tag};

    # Check for an alternate border (with different depth)
    # of current NAT domain. In this case, there is another NAT binding
    # on the path which might overlap some translations of current NAT binding.
    if (my $nat_info = $domain->{nat_info}) {
        my $max_depth = @$nat_info;
        for (my $i = 0 ; $i < $max_depth ; $i++) {
            if ($nat_info->[$i]->{$nat_tag}) {
                err_msg "Inconsistent multiple occurrences of nat:$nat_tag";
                return;
            }
        }
    }

    # Add tag at level $depth.
    # Use a hash to prevent duplicate entries.
    $domain->{nat_info}->[$depth]->{$nat_tag} = $nat_tag;

    # Network which has translation with tag $nat_tag must not be located
    # in area where this tag is effective.
    for my $network (@{ $domain->{networks} }) {
        if ($network->{nat} and $network->{nat}->{$nat_tag}) {
            err_msg "$network->{name} is translated by $nat_tag,\n",
              " but is located inside the translation domain of $nat_tag.\n",
              " Probably $nat_tag was bound to wrong interface.";
        }
    }

    # Activate loop detection.
    $domain->{active_path} = 1;

    # Distribute NAT tag to adjacent NAT domains.
    for my $router (@{ $domain->{routers} }) {
        next if $router eq $in_router;
        my $our_nat_tag = $router->{nat_tag}->{$domain};

        # Found another interface with same NAT binding.
        # This stops effect of current NAT tag.
        next if $our_nat_tag and $our_nat_tag eq $nat_tag;
        for my $out_domain (@{ $router->{nat_domains} }) {
            next if $out_domain eq $domain;
            my $depth = $depth;
            $depth++ if $router->{nat_tag}->{$out_domain};
            distribute_nat1 $out_domain, $nat_tag, $depth, $router;
        }
    }
    delete $domain->{active_path};
}

my @natdomains;

sub distribute_nat_info() {
    info "Distributing NAT";
    my %nat_tag2networks;

    # Find NAT domains.
    for my $network (@networks) {
        if (my $href = $network->{nat}) {
            for my $nat_tag (keys %$href) {
                push @{ $nat_tag2networks{$nat_tag} }, $network;
            }
        }
        next if $network->{nat_domain};
        (my $name = $network->{name}) =~ s/^network:/nat_domain:/;

#     debug "$name";
        my $domain = new(
            'nat_domain',
            name     => $name,
            networks => [],
            nat_map  => {}
        );
        push @natdomains, $domain;
        set_natdomain $network, $domain, 0;
    }

    # Distribute NAT tags to NAT domains.
    for my $domain (@natdomains) {
        for my $router (@{ $domain->{routers} }) {
            my $nat_tag = $router->{nat_tag}->{$domain} or next;
            if ($nat_definitions{$nat_tag}) {
                distribute_nat1 $domain, $nat_tag, 0, $router;
                $nat_definitions{$nat_tag} = 'used';
            }
            else {
                warn_msg "Ignoring undefined nat:$nat_tag",
                  " used at $router->{name}";
            }
        }
    }

    # Convert global NAT definitions to local ones.
    for my $nat_tag (keys %global_nat) {
        my $global = $global_nat{$nat_tag};
      DOMAIN:
        for my $domain (@natdomains) {
            for my $href (@{ $domain->{nat_info} }) {
                next DOMAIN if $href->{$nat_tag};
            }

#	 debug "$domain->{name}";
            for my $network (@{ $domain->{networks} }) {

                # If network has local NAT definition,
                # then skip global NAT definition.
                next if $network->{nat}->{$nat_tag};

#	    debug "global nat:$nat_tag to $network->{name}";
                $network->{nat}->{$nat_tag} = $global;

                # Needed for error messages.
                $network->{nat}->{$nat_tag}->{name} = $network->{name};
                push @{ $nat_tag2networks{$nat_tag} }, $network;
            }
        }
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
                        if ($ip != ($obj_ip & $mask)) {
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

    # Summarize NAT info to NAT mapping.
    for my $domain (@natdomains) {

        # Network to address mapping (only for networks with NAT).
        my $nat_map  = $domain->{nat_map};
        my $nat_info = $domain->{nat_info};

#     debug "$domain->{name}";
        next unless $nat_info;

        # Reuse memory.
        delete $domain->{nat_info};
        for my $href (@$nat_info) {
            for my $nat_tag (values %$href) {
                for my $network (@{ $nat_tag2networks{$nat_tag} }) {
                    next if $nat_map->{$network};
                    $nat_map->{$network} = $network->{nat}->{$nat_tag};

#	       debug " Map: $network->{name} -> ",
#	       print_ip $nat_map->{$network}->{ip};
                }
            }
        }
    }
    for my $name (keys %nat_definitions) {
        warn_msg "nat:$name is defined, but not used"
          unless $nat_definitions{$name} eq 'used';
    }
}

####################################################################
# Find subnetworks
# Mark each network with the smallest network enclosing it.
####################################################################
sub find_subnets() {
    info "Finding subnets";
    for my $domain (@natdomains) {

#     debug "$domain->{name}";
        my $nat_map = $domain->{nat_map};
        my %mask_ip_hash;
        for my $network (@networks) {
            next if $network->{ip} eq 'unnumbered';
            my $nat_network = $nat_map->{$network} || $network;
            my ($ip, $mask) = @{$nat_network}{ 'ip', 'mask' };
            if (my $old_net = $mask_ip_hash{$mask}->{$ip}) {
                my $nat_old_net = $nat_map->{$old_net} || $old_net;
                unless ($nat_old_net->{dynamic} and $nat_network->{dynamic}) {
                    err_msg "$network->{name} and $old_net->{name}",
                      " have identical ip/mask\n", " in $domain->{name}";
                }
            }
            else {
                $mask_ip_hash{$mask}->{$ip} = $network;
            }
        }

        # Go from smaller to larger networks.
        for my $mask (reverse sort keys %mask_ip_hash) {

            # Network 0.0.0.0/0.0.0.0 can't be subnet.
            last if $mask == 0;
            for my $ip (keys %{ $mask_ip_hash{$mask} }) {
                my $m = $mask;
                my $i = $ip;
                while ($m) {

                    # Clear upper bit, because left shift is undefined
                    # otherwise.
                    $m &= 0x7fffffff;
                    $m <<= 1;
                    $i &= $m;
                    if ($mask_ip_hash{$m}->{$i}) {
                        my $bignet = $mask_ip_hash{$m}->{$i};
                        my $subnet = $mask_ip_hash{$mask}->{$ip};

                        # Mark subnet relation.
                        # This may differ for different NAT domains.
                        $subnet->{is_in}->{$nat_map} = $bignet;
                        if ($strict_subnets) {
                            $bignet = $nat_map->{$bignet} || $bignet;
                            $subnet = $nat_map->{$subnet} || $subnet;
                            unless ($bignet->{route_hint}
                                or $subnet->{subnet_of}
                                and $subnet->{subnet_of} eq $bignet)
                            {

                                # Prevent multiple error messages in different
                                # NAT domains.
                                $subnet->{subnet_of} = $bignet;
                                my $msg =
                                  "$subnet->{name} is subnet of $bignet->{name}\n"
                                  . " in $domain->{name}\n"
                                  . " if desired, either declare attribute"
				  . " 'subnet_of' or attribute 'route_hint'";
                                if ($strict_subnets eq 'warn') {
                                    warn_msg $msg;
                                }
                                else {
                                    err_msg $msg;
                                }
                            }
                        }

                        # We only need to find the smallest enclosing network.
                        last;
                    }
                }
            }
        }

        # We must not set an arbitrary default route
        # if a network 0.0.0.0/0 exists and may be referenced in some rule.
        if ($auto_default_route && (my $network = $mask_ip_hash{0}->{0})) {
	    if (not $network->{route_hint}) {
		err_msg "auto_default_route is set and $network->{name}",
		  " has IP address 0.0.0.0/0\n",
		    " either deactivate auto_default_route\n",
		      " or set attribute 'route_hint' of $network->{name}";
		$auto_default_route = 0;
	    }
        }
    }
}

####################################################################
# For each security domain find its associated 'any' object or
# generate a new one if none was declared.
# Link each interface at the border of this security domain with
# its 'any' object and vice versa.
# Additionally link each network and unmanaged router in this security
# domain with the associated 'any' object.
# Add a list of all numbered networks of a security domain to its
# 'any' object.
####################################################################
sub setany_network( $$$ );

sub setany_network( $$$ ) {
    my ($network, $any, $in_interface) = @_;
    if ($network->{any}) {

        # Found a loop inside a security domain.
        return;
    }
    $network->{any} = $any;

    # Add network to the corresponding 'any' object,
    # to have all networks of a security domain available.
    # Unnumbered networks are left out here because
    # they aren't a valid src or dst.
    unless ($network->{ip} eq 'unnumbered') {
        push @{ $any->{networks} }, $network;
    }
    for my $interface (@{ $network->{interfaces} }) {

        # Ignore interface where we reached this network.
        next if $interface eq $in_interface;
        my $router = $interface->{router};
        if ($router->{managed}) {
            $interface->{any} = $any;
            push @{ $any->{interfaces} }, $interface;
        }
        else {
            for my $out_interface (@{ $router->{interfaces} }) {

                # Ignore interface where we reached this router.
                next if $out_interface eq $interface;
                setany_network $out_interface->{network}, $any, $out_interface;
            }
        }
    }
}

# Collect all 'any' objects belonging to an area.
sub setarea1( $$$ );

sub setarea1( $$$ ) {
    my ($any, $area, $in_interface) = @_;
    if ($any->{areas}->{$area}) {

        # Found a loop.
        return;
    }
    $any->{active_path} = 1;

    # Add any object to the corresponding area,
    # to have all any objects of an area available.
    push @{ $area->{anys} }, $any;

    # This will be used to prevent duplicate traversal of loops and
    # later to check for duplicate and overlapping areas.
    $any->{areas}->{$area} = $area;
    my $auto_border = $area->{auto_border};
    my $lookup      = $area->{intf_lookup};
    for my $interface (@{ $any->{interfaces} }) {

        # Ignore interface where we reached this network.
        next if $interface eq $in_interface;

        # Found another border of current area.
        if ($lookup->{$interface}) {

            # Remember that we have found this other border.
            $lookup->{$interface} = 'found';
            next;
        }
        next if $auto_border and $interface->{is_border};
        my $router = $interface->{router};
        for my $out_interface (@{ $router->{interfaces} }) {

            # Ignore interface where we reached this router.
            next if $out_interface eq $interface;

            # Found another border of current area from wrong side.
            if ($lookup->{$out_interface}) {
                err_msg "Inconsistent definition of $area->{name}",
		  " in loop at $out_interface->{name}";
                next;
            }
            next if $auto_border and $out_interface->{is_border};
            setarea1 $out_interface->{any}, $area, $out_interface;
        }
    }
}

sub setany() {
    for my $any (@all_anys) {
        $any->{networks} = [];
        my $network = $any->{link};
        if (my $old_any = $network->{any}) {
            err_msg
              "More than one 'any' object defined in a security domain:\n",
              " $old_any->{name} and $any->{name}";
        }
        is_network $network
          or internal_err "unexpected object $network->{name}";
        setany_network $network, $any, 0;

        # Make results deterministic.
        @{ $any->{networks} } =
          sort { $a->{ip} <=> $b->{ip} } @{ $any->{networks} };
    }

    # Automatically add an 'any' object to each security domain
    # where none has been declared.
    for my $network (@networks) {
        next if $network->{any};
        (my $name = $network->{name}) =~ s/^network:/auto_any:/;
        my $any = new('Any', name => $name, link => $network);
        $any->{networks} = [];
        push @all_anys, $any;
        setany_network $network, $any, 0;

        # Make results deterministic.
        @{ $any->{networks} } =
          sort { $a->{ip} <=> $b->{ip} } @{ $any->{networks} };
    }

    # Mark interfaces, which are border of some area.
    # This is needed to locate auto_borders.
    for my $area (@all_areas) {
        next unless $area->{border};
        for my $interface (@{ $area->{border} }) {
            $interface->{is_border} = 1;
        }
    }
    for my $area (@all_areas) {
        if (my $network = $area->{anchor}) {
            setarea1 $network->{any}, $area, 0;
        }
        elsif (my $interfaces = $area->{border}) {

            # For efficient lookup if some interface is border of current area.
            my %lookup;
            for my $interface (@$interfaces) {
                $lookup{$interface} = 1;
            }
            $area->{intf_lookup} = \%lookup;
            my $start = $interfaces->[0];
            $lookup{$start} = 'found';
            setarea1 $start->{any}, $area, $start;
            if (my @bad_intf = grep { $lookup{$_} ne 'found' } @$interfaces) {
                err_msg "Invalid border of $area->{name}\n ", join "\n ",
                  map $_->{name}, @bad_intf;
                $area->{border} =
                  [ grep { $lookup{$_} eq 'found' } @$interfaces ];
            }
        }

#     debug "$area->{name}:\n ", join "\n ", map $_->{name}, @{$area->{anys}};
    }

    # Find subset relation between areas.
    # Complain about duplicate and overlapping areas.
    for my $any (@all_anys) {
        next unless $any->{areas};

        # Ignore empty hash.
        my @areas = values %{ $any->{areas} } or next;
        @areas = sort { @{ $a->{anys} } <=> @{ $b->{anys} } } @areas;

        # Take the smallest area.
        my $small = shift @areas;
        while (@areas) {
            my $next = shift @areas;
            if (my $big = $small->{subset_of}) {
                $big eq $next
                  or internal_err "$small->{name} is subset of",
                  " $big->{name} and $next->{name}";
            }
            else {

                # Each 'any' object of $small must be part of $next.
                my $ok = 1;
                for my $any (@{ $small->{anys} }) {
                    unless ($any->{areas}->{$small}) {
                        $ok = 0;
                        err_msg "Overlapping $small->{name} and $next->{name}";
                        last;
                    }
                }
                if ($ok) {
                    if (@{ $small->{anys} } == @{ $next->{anys} }) {
                        err_msg "Duplicate $small->{name} and $next->{name}";
                    }
                    else {
                        $small->{subset_of} = $next;
                    }
                }
            }
            $small = $next;
        }
    }
    for my $area (@all_areas) {

        # Tidy up: Delete unused attribute.
        delete $area->{intf_lookup};
        for my $interface (@{ $area->{border} }) {
            delete $interface->{is_border};
        }
    }
}

####################################################################
# Set paths for efficient topology traversal
####################################################################

# Collect all networks and routers located inside a cyclic graph.
my @loop_objects;

sub setpath_obj( $$$ );

sub setpath_obj( $$$ ) {
    my ($obj, $to_net1, $distance) = @_;

#  debug("-- $distance: $obj->{name} --> $to_net1->{name}");
    # $obj: a managed router or a network
    # $to_net1: interface of $obj; go this direction to reach net1
    # $distance: distance to net1
    # return value used in different manners:
    # (1) a flag, indicating that the current path is part of a loop
    # (2) that obj, which is starting point of the loop (as seen from net1)
    if ($obj->{active_path}) {

        # Found a loop.
        return $obj;
    }

    # Mark current path for loop detection.
    $obj->{active_path} = 1;
    $obj->{distance}    = $distance;

    my $loop_start;
    my $loop_distance;
    my $get_next = is_router $obj ? 'network' : 'router';
    for my $interface (@{ $obj->{interfaces} }) {

        # Ignore interface where we reached this obj.
        next if $interface eq $to_net1;

        # Ignore interface which is the other entry of a loop
        # which is already marked.
        next if $interface->{in_loop};
        my $next = $interface->{$get_next};
        if (my $loop = setpath_obj $next, $interface, $distance + 1) {

            # Path is part of a loop.
            if (!$loop_start or $loop->{distance} < $loop_distance) {
                $loop_start    = $loop;
                $loop_distance = $loop->{distance};
            }
            $interface->{in_loop} = 1;
        }
        else {

            # Continue marking loop-less path.
            $interface->{main} = $obj;
        }
    }
    delete $obj->{active_path};
    if ($loop_start) {

        # Mark every node of a cyclic graph with the graph's starting point
        # or the starting point of a subgraph
        $obj->{loop} = $loop_start;
        push @loop_objects, $obj;

#     debug "Loop($obj->{distance}): $obj->{name} -> $loop_start->{name}";
        unless ($obj eq $loop_start) {

            # We are still inside a loop.
            return $loop_start;
        }
    }
    $obj->{main} = $to_net1;
    return 0;
}

sub setpath() {
    info "Preparing fast path traversal";

    # Take a random network from @networks, name it "net1".
    @networks or die "Error: Topology seems to be empty\n";
    my $net1 = $networks[0];

    # Starting with net1, do a traversal of the whole topology
    # to find a path from every network and router to net1.
    # Second  parameter $net1 is used as placeholder for a not existing
    # starting interface.
    setpath_obj $net1, $net1, 2;

    # Check if all objects are connected with net1.
    for my $object (@networks, @routers) {
        next if $object->{main} or $object->{loop};
        err_msg "Found unconnected $object->{name}";

        # Prevent further errors when calling
        # path_first_interfaces from expand_rules.
        $object->{disabled} = 1;
    }

    # Propagate loop starting point into all sub-loops.
    for my $obj (@loop_objects) {
        my $loop = $obj->{loop};
        my $next = $loop->{loop};
        if ($next ne $loop) {
            $loop = $next;
            while (1) {
                $next = $loop->{loop};
                if ($loop eq $next) { last; }
                else { $loop = $next; }
            }

#	 debug "adjusting $obj->{name} loop to $loop->{name}";
            $obj->{loop} = $loop;

            # Only starting point of a loop has attribute {main}.
            # This property is used in path_mark.
            delete $obj->{main};
        }

#     debug "adjusting $obj->{name} distance to $loop->{distance}";
        $obj->{distance} = $loop->{distance};
    }

    # Data isn't needed any more.
    @loop_objects = undef;

    # Check consistency of virtual interfaces:
    # Interfaces with identical virtual IP must
    # - be connected to the same network,
    # - be located inside the same loop,
    # - use the same redundancy protocol,
    # - use the same id (currently optional).
    my %same_ip;

    # Unrelated virtual interfaces with identical IP must be located
    # in different networks.
    my %same_id;
    for my $interface (@virtual_interfaces) {
        unless ($interface->{router}->{loop}) {
            warn_msg "Ignoring virtual IP of $interface->{name}\n",
              " because it isn't located inside cyclic graph";
            next;
        }
        my $ip = $interface->{virtual}->{ip};
        push @{ $same_ip{$ip} }, $interface;
    }
    for my $aref (values %same_ip) {
        my ($i1, @rest) = @$aref;
        my $id1 = $i1->{virtual}->{id} || '';
        my $other;
        if ($id1) {
            if (    $other = $same_id{$id1}
                and $i1->{network} eq $other->{network})
            {
                err_msg "Virtual IP: Unrelated $i1->{name} and $other->{name}",
                  " have identical ID";
            }
            else {
                $same_id{$id1} = $i1;
            }
        }
        if (@rest) {
            my $network1 = $i1->{network};
            my $loop1    = $i1->{router}->{loop};
            my $type1    = $i1->{virtual}->{type};
            for my $i2 (@rest) {
                my $network2 = $i2->{network};
                my $loop2    = $i2->{router}->{loop};
                my $type2    = $i2->{virtual}->{type};
                my $id2      = $i2->{virtual}->{id} || '';
                $network1 eq $network2
                  or err_msg "Virtual IP: $i1->{name} and $i2->{name}",
                  " are connected to different networks";
                $type1 eq $type2
                  or err_msg "Virtual IP: $i1->{name} and $i2->{name}",
                  " use different redundancy protocols";
                $id1 eq $id2
                  or err_msg "Virtual IP: $i1->{name} and $i2->{name}",
                  " use different ID";
                $loop1 and $loop2 and $loop1 eq $loop2
                  or err_msg "Virtual IP: $i1->{name} and $i2->{name}",
                  " are part of different cyclic subgraphs";
            }
        }
        else {
            warn_msg "Virtual IP: Missing second interface for $i1->{name}";
        }
    }

    # Check that interfaces with pathrestriction are located inside
    # of cyclic graphs
    for my $restrict (values %pathrestrictions) {
        for my $interface (@{ $restrict->{elements} }) {
            next if $interface->{disabled};
            $interface->{in_loop}
              or warn_msg "Ignoring $restrict->{name} at $interface->{name}\n",
              " because it isn't located inside cyclic graph";
        }
    }
}

####################################################################
# Efficient path traversal.
####################################################################

sub get_networks ( $ ) {
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        return $obj;
    }
    elsif ($type eq 'Subnet' or $type eq 'Interface') {
        return $obj->{network};
    }
    elsif ($type eq 'Any') {
        return @{ $obj->{networks} };
    }
    else {
        internal_err "unexpected $obj->{name}";
    }
}

sub get_path( $ ) {
    my ($obj) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        return $obj;
    }
    elsif ($type eq 'Subnet') {
        return $obj->{network};
    }
    elsif ($type eq 'Interface') {
        my $router = $obj->{router};

        # Special handling needed if $src or $dst are interface inside a loop.
        if ($obj->{in_loop}) {

            # path_walk needs this attributes to be set
            $obj->{loop}     = $router->{loop};
            $obj->{distance} = $router->{distance};
            return $obj;
        }
        else {
            return $router;
        }
    }
    elsif ($type eq 'Any') {

        # We may take any network of this security domain,
        # but attribute {link} is guaranteed to contain a valid network.
        return $obj->{link};
    }
    elsif ($type eq 'Router') {

        # This is only used, when called from path_first_interfaces or
        # from find_active_routes_and_statics.
        return $obj;
    }
    elsif ($type eq 'Host') {

        # This is only used, if Netspoc.pm is called from Arnes report.pl.
        return $obj->{network};
    }
    else {
        internal_err "unexpected $obj->{name}";
    }
}

# Converts hash key of reference back to reference.
my %key2obj;

sub loop_path_mark1( $$$$$ );

sub loop_path_mark1( $$$$$ ) {
    my ($obj, $in_intf, $from, $to, $collect) = @_;

#  debug "loop_path_mark1: obj: $obj->{name},
#        in_intf: $in_intf->{name} from: $from->{name}, to: $to->{name}";
    # Check for second occurrence of path restriction.
    for my $restrict (@{ $in_intf->{path_restrict} }) {
        if ($restrict->{active_path}) {

#	 debug " effective $restrict->{name} at $in_intf->{name}";
            return 0;
        }
    }

    # Don't walk loops.
    if ($obj->{active_path}) {

#     debug " active: $obj->{name}";
        return 0;
    }

    # Found a path to router or network.
    if ($obj eq $to) {

        # Mark interface where we leave the loop.
        $to->{loop_leave}->{$from}->{$in_intf} = $in_intf;

#     debug " leave: $in_intf->{name} -> $to->{name}";
        return 1;
    }

    # Found a path to interface as destination.
    if (is_interface $to and $obj eq $to->{router}) {
        if ($in_intf eq $to or not $to->{network}->{active_path}) {

            # Found a valid path.
            $to->{loop_leave}->{$from}->{$in_intf} = $in_intf;

#	 debug " leave: $in_intf->{name} -> $to->{name}";
            return 1;
        }
        else {

#	 debug " invalid path: $in_intf->{name} -> $to->{name}";
            return 0;
        }
    }

    # Mark current path for loop detection.
    $obj->{active_path} = 1;

    # Mark first occurrence of path restriction.
    for my $restrict (@{ $in_intf->{path_restrict} }) {

#     debug " enabled $restrict->{name} at $in_intf->{name}";
        $restrict->{active_path} = 1;
    }
    my $get_next = is_router $obj ? 'network' : 'router';
    my $success  = 0;

    # Fill hash for restoring reference from hash key.
    $key2obj{$in_intf} = $in_intf;
    for my $interface (@{ $obj->{interfaces} }) {
        next unless $interface->{in_loop};
        next if $interface eq $in_intf;
        my $next = $interface->{$get_next};
        if (loop_path_mark1 $next, $interface, $from, $to, $collect) {

            # Found a valid path from $next to $to
            $key2obj{$interface} = $interface;
            $collect->{$in_intf}->{$interface} = is_router $obj;

#	 debug " loop: $in_intf->{name} -> $interface->{name}";
            $success = 1;
        }
    }
    delete $obj->{active_path};
    for my $restrict (@{ $in_intf->{path_restrict} }) {

#     debug " disabled $restrict->{name} at $in_intf->{name}";
        delete $restrict->{active_path};
    }
    return $success;
}

# Mark paths inside a cyclic subgraph.
# $from and $to are entry and exit objects of the subgraph.
# The subgraph is entered at interface $from_in and left at interface $to_out.
# For each pair of $from / $to, we collect attributes:
# {loop_enter}: interfaces of $from, where the subgraph is entered,
# {path_tuples}: tuples of interfaces, which describe all valid paths,
# {loop_leave}: interfaces of $to, where the subgraph is left.
sub loop_path_mark ( $$$$$ ) {
    my ($from, $to, $from_in, $to_out, $dst) = @_;

#  debug "loop_path_mark: $from->{name} -> $to->{name}";
    # Loop has been entered at this interface before, or path starts at this
    # object.
    return if $from_in->{path}->{$dst};
    $from_in->{path}->{$dst} = $to_out;
    return if is_interface $from and $from->{router} eq $to;
    return if is_interface $to   and $from           eq $to->{router};
    $from_in->{loop_entry}->{$dst} = $from;
    $from->{loop_exit}->{$dst}     = $to;

    # Path from $from to $to inside cyclic graph has been marked already.
    return if $from->{path_tuples}->{$to};

    # Use this anonymous hash for collecting paths as tuples of interfaces.
    my $collect = {};
    $from->{path_tuples}->{$to} = $collect;
    my $success = 0;
    if (is_interface $from) {
        my $router  = $from->{router};
        my $network = $from->{network};

        # Mark current path for loop detection.
        $router->{active_path} = 1;
        if (loop_path_mark1 $network, $from, $from, $to, $collect) {
            $success = 1;
            push @{ $from->{loop_enter}->{$to} }, $from;

#	 debug " enter: $from->{name} -> $from->{name}";
        }

        # Additionally mark network of interface $from for loop detection.
        $network->{active_path} = 1;
        for my $interface (@{ $router->{interfaces} }) {
            next unless $interface->{in_loop};
            next if $interface eq $from;
            my $next = $interface->{network};
            if (loop_path_mark1 $next, $interface, $from, $to, $collect) {
                $success = 1;
                push @{ $from->{loop_enter}->{$to} }, $interface;

#	    debug " enter: $from->{name} -> $interface->{name}";
            }
        }
        delete $network->{active_path};
        delete $router->{active_path};
    }
    else {

        # Mark current path for loop detection.
        $from->{active_path} = 1;
        my $get_next = is_router $from ? 'network' : 'router';
        for my $interface (@{ $from->{interfaces} }) {
            next unless $interface->{in_loop};
            my $next = $interface->{$get_next};
            if (loop_path_mark1 $next, $interface, $from, $to, $collect) {
                $success = 1;
                push @{ $from->{loop_enter}->{$to} }, $interface;

#	    debug " enter: $from->{name} -> $interface->{name}";
            }
        }
        delete $from->{active_path};
    }

    # Convert hash of interfaces to array of interfaces.
    $to->{loop_leave}->{$from} = [ values %{ $to->{loop_leave}->{$from} } ];
    $success
      or err_msg "No valid path from $from->{name} to $to->{name}\n",
      " (destination is $dst->{name})\n", " Too many path restrictions?";
}

# Mark path from src to dst.
# src and dst are either a router or a network.
# At each interface on the path from src to dst,
# we place a reference to the next interface on the path to dst.
# This reference is found at a key which is the reference to dst.
# Additionally we attach this information to the src object.
sub path_mark( $$ ) {
    my ($src, $dst) = @_;
    my $from      = $src;
    my $to        = $dst;
    my $from_in   = $from;
    my $to_out    = undef;
    my $from_loop = $from->{loop};
    my $to_loop   = $to->{loop};

#  debug "path_mark $from->{name} --> $to->{name}";
    while (1) {

        # Paths meet outside a loop or at the edge of a loop.
        if ($from eq $to) {

#	 debug " $from_in->{name} -> ".($to_out?$to_out->{name}:'');
            $from_in->{path}->{$dst} = $to_out;
            return;
        }

        # Paths meet inside a loop.
        if ($from_loop and $to_loop and $from_loop eq $to_loop) {
            loop_path_mark($from, $to, $from_in, $to_out, $dst);
            return;
        }
        if ($from->{distance} >= $to->{distance}) {

            # Mark has already been set for a sub-path.
            return if $from_in->{path}->{$dst};
            my $from_out = $from->{main};
            unless ($from_out) {

                # $from_loop contains object which is loop's exit
                $from_out = $from_loop->{main};
                loop_path_mark($from, $from_loop, $from_in, $from_out, $dst)
                  unless $from_in->{path}->{$dst};
            }

#	 debug " $from_in->{name} -> ".($from_out?$from_out->{name}:'');
            $from_in->{path}->{$dst} = $from_out;
            $from_in                 = $from_out;
            $from                    = $from_out->{main};
            $from_loop               = $from->{loop};
        }
        else {
            my $to_in = $to->{main};
            unless ($to_in) {
                $to_in = $to_loop->{main};
                loop_path_mark($to_loop, $to, $to_in, $to_out, $dst)
                  unless $from_in->{path}->{$dst};
            }

#	 debug " $to_in->{name} -> ".($to_out?$to_out->{name}:'');
            $to_in->{path}->{$dst} = $to_out;
            $to_out                = $to_in;
            $to                    = $to_in->{main};
            $to_loop               = $to->{loop};
        }
    }
}

# Walk paths inside cyclic graph
sub loop_path_walk( $$$$$$$ ) {
    my ($in, $out, $loop_entry, $loop_exit, $call_at_router, $rule, $fun) = @_;

#    my $info = "loop_path_walk: ";
#    $info .= "$in->{name}->" if $in;
#    $info .= "$loop_entry->{name}->$loop_exit->{name}";
#    $info .= "->$out->{name}" if $out;
#    debug $info;
    # Process entry of cyclic graph.
    if ((is_router $loop_entry or is_interface $loop_entry) eq $call_at_router)
    {

#     debug " loop_enter";
        for my $out_intf (@{ $loop_entry->{loop_enter}->{$loop_exit} }) {
            $fun->($rule, $in, $out_intf);
        }
    }

    # Process paths inside cyclic graph.
    my $tuples = $loop_entry->{path_tuples}->{$loop_exit};

#  debug " loop_tuples";
    for my $in_intf_ref (keys %$tuples) {
        my $in_intf = $key2obj{$in_intf_ref};
        my $hash    = $tuples->{$in_intf_ref};
        for my $out_intf_ref (keys %$hash) {
            my $out_intf  = $key2obj{$out_intf_ref};
            my $at_router = $hash->{$out_intf_ref};
            $fun->($rule, $in_intf, $out_intf) if $at_router eq $call_at_router;
        }
    }

    # Process paths at exit of cyclic graph.
    if ((is_router $loop_exit or is_interface $loop_exit) eq $call_at_router) {

#     debug " loop_leave";
        for my $in_intf (@{ $loop_exit->{loop_leave}->{$loop_entry} }) {
            $fun->($rule, $in_intf, $out);
        }
    }
}

# Find all rules in $rule_tree which are related to $rule and return
# appertaining crypto maps.
# Two rules r1 and r2 are related, if
# - r1.src op r2.src and r1.dst op r2.dst and r1.srv op r2.srv
# with op: <= or >=
sub find_related_rules ( $$ ) {
    my ($rule, $rule_tree) = @_;
    my $result;
    my $overlap;
    my $src = $rule->{src};
    my $check_dst = sub ( $$ ) {
        my ($rule_tree, $above) = @_;
        my $dst = $rule->{dst};
        my $check_srv = sub ( $$ ) {
            my ($rule_tree, $above) = @_;
            my $srv = $rule->{srv};
            my $check_src_range = sub ( $$ ) {
                my ($rule_tree, $above) = @_;
                my $src_range = $rule->{src_range};
                if (my $aref = $rule_tree->{above}->{$src_range}) {
                    for my $map (@$aref) {
                        push @$result, $map;
                        $overlap = 1;
                    }
                }
                else {
                    while (1) {
                        if (my $map = $rule_tree->{$src_range}) {
                            push @$result, $map;
                            $overlap ||= $above;
                            last;
                        }
                        $src_range = $src_range->{up} or last;
                    }
                }
            };
            if (my $aref = $rule_tree->{above}->{$srv}) {
                for my $rule_tree (@$aref) {
                    $check_src_range->($rule_tree, 1);
                }
            }
            else {
                while (1) {
                    if (my $rule_tree = $rule_tree->{$srv}) {
                        $check_src_range->($rule_tree, $above);
                    }
                    $srv = $srv->{up} or last;
                }
            }
        };
        if (my $aref = $rule_tree->{above}->{$dst}) {
            for my $rule_tree (@$aref) {
                $check_srv->($rule_tree, 1);
            }
        }
        else {
            while (1) {
                if (my $rule_tree = $rule_tree->{$dst}) {
                    $check_srv->($rule_tree, $above);
                }
                $dst = $dst->{up} or last;
            }
        }
    };
    if (my $aref = $rule_tree->{above}->{$src}) {
        for my $rule_tree (@$aref) {
            $check_dst->($rule_tree, 1);
        }
    }
    else {
        while (1) {
            if (my $rule_tree = $rule_tree->{$src}) {
                $check_dst->($rule_tree, 0);
            }
            $src = $src->{up} or last;
        }
    }
    return $result ? ($result, $overlap) : ();
}

# Check if
# - $rule matches rules in $rule_tree ($rule <= some element of $rule_tree) or
# - $rule overlaps rules in $rule_tree
#   ($rule has intersection with some element(s) of $rule_tree)
sub crypto_match( $$ ) {
    my ($rule, $rule_tree) = @_;
    my $some_deny = 0;

    # ToDo: What about deny- $rule.
    if (my $deny_tree = $rule_tree->{deny}) {
        if (my ($map_aref, $overlap) = find_related_rules $rule, $deny_tree) {
            if (not $overlap) {

                # Packets described by $rule never pass tunnel.
                return ();
            }
            else {

                # Some packets don't pass tunnel, but continue checking.
                $some_deny = 1;
            }
        }
    }
    if (my ($map_aref, $overlap) = find_related_rules $rule,
        $rule_tree->{permit})
    {
        return $map_aref, $overlap | $some_deny;
    }
    else {
        return ();
    }
}

# Apply a function to a rule at every router or network
# on the path from src to dst of the rule.
# $where tells, where the function gets called: at 'Router' or 'Network'.
sub path_walk( $$;$ ) {
    my ($rule, $fun, $where) = @_;
    internal_err "undefined rule" unless $rule;
    my $src  = $rule->{src};
    my $dst  = $rule->{dst};
    my $from = get_path $src;
    my $to   = get_path $dst;

#    debug print_rule $rule;
#    debug(" start: $from->{name}, $to->{name}" . ($where?", at $where":''));
#    my $fun2 = $fun;
#    $fun = sub ( $$$;$ ) {
#	my($rule, $in, $out, $crypto_map) = @_;
#	my $in_name = $in?$in->{name}:'-';
#	my $out_name = $out?$out->{name}:'-';
#	my $crypto = $crypto_map?'crypto':'';
#	debug " Walk: $in_name, $out_name $crypto";
#	$fun2->(@_);
#    };
    unless ($from and $to) {
        internal_err print_rule $rule;
    }
    if ($from eq $to) {

        # Don't process rule again later.
        $rule->{deleted} = $rule;
        return;
    }
    path_mark($from, $to) unless $from->{path}->{$to};
    my $in = undef;
    my $out;
    my $at_router = not($where && $where eq 'Network');
    my $call_it   = (is_network($from) xor $at_router);

    # Path starts inside a cyclic graph.
    # Crypto tunnel must not start inside acyclic graph,
    # hence no crypto check needed.
    if ($from->{loop_exit} and my $loop_exit = $from->{loop_exit}->{$to}) {
        my $loop_out = $from->{path}->{$to};
        loop_path_walk $in, $loop_out, $from, $loop_exit, $at_router, $rule,
          $fun;
        unless ($loop_out) {

#	 debug "exit: path_walk: dst in loop";
            return;
        }

        # Continue behind loop.
        $in      = $loop_out;
        $call_it = not(is_network($loop_exit) xor $at_router);
        $out     = $in->{path}->{$to};
    }
    else {
        $out = $from->{path}->{$to};
    }
    while (1) {
        if ($call_it) {

            # Call, even if crypto tunnel at $out is used.
            $fun->($rule, $in, $out);

            # Check if a crypto tunnel is applicable.
            # Crypto tunnel is only used in mode $at_router.
            if ($at_router and (my $tree = $out->{crypto_rule_tree})) {
                my ($map_aref, $overlap) = crypto_match $rule, $tree;
                if ($map_aref) {
                    for my $map (@$map_aref) {
                        my $peer     = $map->{peer};
                        my $next     = $peer->{path}->{$to};
                        my $peer_map = $peer->{tunnel}->{$out};

                        # Call at router at other end of tunnel.
                        # Pass additional parameter $peer_map, to indicate
                        # that $peer is tunnel interface.
                        $fun->($rule, $peer, $next, $peer_map);
                        if ($overlap) {

                            # Walk clear text path as well.
                        }
                        else {

                            # Continue behind tunnel.
                            # This happens only if @$map_aref == 1.
                            $in  = $peer;
                            $out = $next;
                        }
                    }
                }
            }
        }

        # End of path has been reached.
        if (not defined $out) {

#	 debug "exit: path_walk: reached dst";
            return;
        }
        $call_it = !$call_it;
        $in      = $out;
        if ($in->{loop_entry} and my $loop_entry = $in->{loop_entry}->{$to}) {
            my $loop_exit = $loop_entry->{loop_exit}->{$to};
            my $loop_out = $in->{path}->{$to};
	    loop_path_walk $in, $loop_out, $loop_entry, $loop_exit,
	      $at_router, $rule, $fun;
	    if ($loop_out) {
                $in      = $loop_out;
                $call_it = not(is_network($loop_exit) xor $at_router);
            }
            else {
#	    debug "exit: path_walk: dst in loop";
                return;
            }
        }
        $out = $in->{path}->{$to};
    }
}

sub path_first_interfaces( $$ ) {
    my ($src, $dst) = @_;
    my $from = get_path($src);
    my $to   = get_path($dst);
    $from eq $to and return ();
    path_mark($from, $to) unless $from->{path}->{$to};
    if (my $exit = $from->{loop_exit}->{$to}) {

#     debug "$from->{name}.[auto] = ",
#     join ',', map {$_->{name}} @{$from->{loop_enter}->{$exit}};
        return @{ $from->{loop_enter}->{$exit} };
    }
    else {

#     debug "$from->{name}.[auto] = $from->{path}->{$to}->{name}";
        return ($from->{path}->{$to});
    }
}

########################################################################
# Handling of crypto tunnels and crypto rules.
########################################################################

# ToDo: Currently exactly one single tunnel must be found.
# Later we should be able to find the longest tunnel out of multiple tunnels.
# But overlapping tunnels must not be accepted, to avoid inconsistent paths.
sub distribute_crypto_rule ( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $crypto = $rule->{crypto};

    # Check for a matching tunnel end.
    if ($in_intf and $in_intf->{tunnel}) {
        for my $start_inf (@{ $rule->{tunnel_start} }) {
            if (my $map = $in_intf->{tunnel}->{$start_inf}) {
                $map->{crypto} eq $rule->{crypto}
                  or err_msg "Tunnel between $start_inf->{name} and",
                  " $in_intf->{name}\n",
                  " belongs to $map->{crypto}->{name} but matching rule\n ",
                  print_rule $rule, "\n", " belongs to $rule->{crypto}->{name}";
                if (my $tunnel = $rule->{tunnel}) {
                    err_msg "Multiple tunnels are matching rule\n ",
                      print_rule $rule,
                      "\n Tunnel: $tunnel->[0]->{name} -- $tunnel->[1]->{name}",
                      "\n Tunnel: $start_inf->{name} -- $in_intf->{name}";
                }
                $rule->{tunnel} = [ $start_inf, $in_intf ];
            }
        }
    }

    # Remember a tunnel start.
    if ($out_intf and $out_intf->{tunnel}) {
        push @{ $rule->{tunnel_start} }, $out_intf;
    }
}

# Reverse a crypto rule and check if srv is valid for IPSec.
sub reverse_rule ( $ ) {
    my ($rule) = @_;
    my ($action, $src, $dst, $src_range, $srv) =
      @{$rule}{ 'action', 'src', 'dst', 'src_range', 'srv' };
    my $proto = $srv->{proto};
    my $new_srv;
    my $new_src_range = $srv_ip;
    if ($proto eq 'tcp' || $proto eq 'udp') {
        for my $range ($srv->{range}, $src_range->{range}) {
            (        $range->[0] == $range->[1]
                  || $range->[0] == 1 && $range->[1] == 65535)
              or err_msg
              "Crypto rule must not use $srv->{name} with port ranges";
        }

        # Swap src and dst range.
        $new_src_range = $srv;
        $new_srv       = $src_range;
    }
    elsif ($proto eq 'icmp') {
        $srv->{type}
          and err_msg "Crypto rule must not use $srv->{name} with type";
        $new_srv = $srv;
    }
    else {
        $new_srv = $srv;
    }
    my $new_rule = {
        action    => $action,
        src       => $dst,
        dst       => $src,
        src_range => $new_src_range,
        srv       => $new_srv
    };
}

# Generate rules to permit crypto traffic between tunnel endpoints.
sub gen_tunnel_rules ( $$$ ) {
    my ($intf1, $intf2, $ipsec) = @_;
    my $use_ah = $ipsec->{ah};
    my $use_esp = $ipsec->{esp_authentication} || $ipsec->{esp_encryption};
    my $use_nat_traversal = $ipsec->{key_exchange}->{nat_traversal};
    my @rules;
    my $rule = { action => 'permit', src => $intf1, dst => $intf2 };
    if ($use_nat_traversal) {
	$rule->{src_range} = $srv_natt->{src_range};
	$rule->{srv}       = $srv_natt->{dst_range};
	push @rules, $rule;
    }
    else {
	$rule->{src_range} = $srv_ip;
	$use_ah  and push @rules, { %$rule, srv => $srv_ah };
	$use_esp and push @rules, { %$rule, srv => $srv_esp };
	$rule->{src_range} = $srv_ike->{src_range};
	$rule->{srv}       = $srv_ike->{dst_range};
	push @rules, $rule;
    }
    return \@rules;
}

sub expand_crypto () {
    info "Preparing crypto tunnels and expanding crypto rules";
    for my $ipsec (values %ipsec) {

        # Convert name of ISAKMP definition to object with ISAKMP definition.
        my ($type, $name) = split_typed_name $ipsec->{key_exchange};
        if ($type eq 'isakmp') {
            my $isakmp = $isakmp{$name}
              or err_msg "Can't resolve reference to '$type:$name'",
              " for $ipsec->{name}";
            $ipsec->{key_exchange} = $isakmp;
        }
        else {
            err_msg "Unknown type '$type' for $ipsec->{name}";
        }
    }
    for my $crypto (values %crypto) {
        my $name = $crypto->{name};

        # Convert name of ipsec definition to object with ipsec definition.
        my ($type, $name2) = split_typed_name $crypto->{type};

        # Used later when generating rules for AH, ESP and IKE.
        my ($use_ah, $use_esp, $use_nat_traversal);
        if ($type eq 'ipsec') {
            my $ipsec = $ipsec{$name2}
              or err_msg "Can't resolve reference to '$type:$name2'",
              " for $name";
            $crypto->{type} = $ipsec;
        }
        else {
            err_msg "Unknown type '$type' for $name";
        }

        # Resolve tunnel endpoints to lists of interfaces.
        for my $what ('hub', 'spoke') {
            $crypto->{$what} = expand_group($crypto->{$what}, "$what of $name");
            for my $element (@{ $crypto->{$what} }) {
                next if is_interface $element;

                # [auto] interface is represented by router object.
                next if is_router $element;
                err_msg "Illegal element in $what of $name: $element->{name}";
            }
        }
        for my $mesh (@{ $crypto->{meshes} }) {
            $mesh = [ expand_group $mesh, "mesh of $name" ];
            for my $element (@$mesh) {
                next if is_interface $element;
                next if is_router $element;
                err_msg "Illegal element in mesh of $name: $element->{name}";
            }
        }
        my @pairs;
        for my $hub (@{ $crypto->{hub} }) {
            for my $spoke (@{ $crypto->{spoke} }) {
                push @pairs, [ $hub, $spoke ];
            }
        }
        for my $mesh (@{ $crypto->{meshes} }) {
            for my $intf1 (@$mesh) {
                for my $intf2 (@$mesh) {
                    next if $intf1 eq $intf2;
                    push @pairs, [ $intf1, $intf2 ];
                }
            }
        }
        my $check = sub ( @ ) {
            my ($intf1, $intf2) = @_;
            my @intf1 = path_first_interfaces $intf1, $intf2 or

              # Both interfaces have same router.
              return undef;
            my @intf2 = path_first_interfaces $intf2, $intf1;
            if (@intf1 > 1) {
                err_msg "Tunnel of $name starting at $intf2->{name}",
                  " has multiple endpoints at $intf1->{name}";
            }
            if (is_router $intf1) {
                ($intf1) = @intf1;
            }
            else {
                my ($tmp) = @intf1;
                unless ($tmp eq $intf1) {
                    err_msg "Tunnel of $name starting at $intf2->{name}\n",
                      " uses wrong endpoint at $intf1->{name}.\n",
                      " Use $tmp->{name} instead.";
                }
                $intf1 = $tmp;
            }
            if ($intf1->{ip} =~ /unnumbered|short|negotiated/) {
                err_msg "'$intf1->{ip}' $intf1->{name}\n",
                  " must not be used in tunnel of $name";
            }
            return $intf1;
        };
        for my $pair (@pairs) {
            my $intf1 = $check->(@{$pair}[ 0, 1 ]) or

              # Silently ignore pairs where both interfaces have same router.
              next;
            my $intf2 = $check->(@{$pair}[ 1, 0 ]);

            # Test for $intf2->{tunnel}->{$intf1} isn't necessary, because
            # tunnels are always defined symmetrically.
            if (my $old_map = $intf1->{tunnel}->{$intf2}) {
                err_msg "Duplicate tunnel",
                  " between $intf1->{name} and $intf2->{name}\n",
                  " defined in $old_map->{crypto}->{name} and $name";
            }
            if ($intf1->{in_loop}) {
                err_msg "$intf1->{name} must not be used in tunnel of $name\n",
                  " because it is located inside a cyclic subgraph";
            }

            # Do a stronger check for loop here,
            # to get a simpler implementation in path_walk.
            if ($intf2->{router}->{loop}) {
                err_msg "$intf2->{name} must not be used in tunnel of $name\n",
                  " because its router is located inside a cyclic subgraph";
            }

            # Subsequent code is needed for both directions.
            for my $pair ([ $intf1, $intf2 ], [ $intf2, $intf1 ]) {
                my ($intf1, $intf2) = @$pair;

                # Add a data structure for each tunnel, which is used to
                # collect
                # - crypto ACL
                # - crypto access-group for devices which allow separate
                #   filtering for encrypted traffic
                #   (no attribute no_crypto_filter).
                # Data will be used later to generate "crypto map" commands.
                my $crypto_map = { crypto => $crypto, peer => $intf2 };
                $intf1->{tunnel}->{$intf2} = $crypto_map;
                push @{ $intf1->{hardware}->{crypto_maps} }, $crypto_map
                  if $intf1->{router}->{managed};

                # Add rules to permit crypto traffic between tunnel endpoints.
                my $rules_ref = gen_tunnel_rules $intf1, $intf2, $crypto->{type};
                push @{ $expanded_rules{permit} }, @$rules_ref;
                add_rules $rules_ref, \%rule_tree;
                $ref2obj{$intf1} = $intf1;
            }
        }

# Convert typed names in crypto rule to internal objects.
        for my $rule (@{ $crypto->{rules} }) {
            for my $where ('src', 'dst') {
                $rule->{$where} = expand_group(
                    $rule->{$where},
                    "$where of rule in $name",

                    # Convert hosts to subnets.
                    1
                );
            }
            $rule->{srv} = expand_services $rule->{srv}, "rule of $name";
        }
        my (@deny, @any, @permit);
        my $result = $crypto->{expanded_rules} = {
            deny   => \@deny,
            any    => \@any,
            permit => \@permit
        };

        # This adds expanded rules to $result.
        expand_rules $crypto->{rules}, $name, $result;

# Distribute rules to tunnels.
        my $add_rule = sub ( $$$ ) {
            my ($rule, $start, $end) = @_;
            my $crypto_map = $start->{tunnel}->{$end};
            my ($action, $src, $dst, $src_range, $srv) =
              @{$rule}{ 'action', 'src', 'dst', 'src_range', 'srv' };
            if (my $old_map =
                $start->{crypto_rule_tree}->{$action}->{$src}->{$dst}
                ->{$src_range}->{$srv})
            {
                err_msg "Duplicate crypto rule at $start->{name}\n ",
                  print_rule $rule;
            }

            # crypto_rule_tree is used to efficiently decide,
            # if a policy rule fully uses a tunnel or not.
            # $ref2obj has already been filled by expand_rules
            $start->{crypto_rule_tree}->{$action}->{$src}->{$dst}->{$src_range}
              ->{$srv} = $crypto_map;

            # Additionally add entries to crypto_rule_tree, which allow
            # for efficient test, if a rule has intersection with some
            # rule(s) in crypto_rule_tree.
            my $subtree  = $start->{crypto_rule_tree}->{$action};
            my $subtree2 = $subtree->{$src};
            while ($src = $src->{up}) {
                push @{ $subtree->{above}->{$src} }, $subtree2;
            }
            $subtree  = $subtree2;
            $subtree2 = $subtree->{$dst};
            while ($dst = $dst->{up}) {
                push @{ $subtree->{above}->{$dst} }, $subtree2;
            }
            $subtree  = $subtree2;
            $subtree2 = $subtree->{$src_range};
            while ($src_range = $src_range->{up}) {
                push @{ $subtree->{above}->{$src_range} }, $subtree2;
            }
            $subtree  = $subtree2;
            $subtree2 = $subtree->{$srv};
            while ($srv = $srv->{up}) {
                push @{ $subtree->{above}->{$srv} }, $subtree2;
            }

            # Rules are stored additionally in crypto_map for code generation.
            push @{ $crypto_map->{crypto_rules} }, $rule;
        };
	# ToDo:
	# Is special handling of deny rules necessary?
	# Check for matching high-level and low-level semantic of any rules.
        for my $rule (@deny, @any , @permit) {
            $rule->{crypto} = $crypto;

            # Find tunnel where $rule is applicable.
            path_walk($rule, \&distribute_crypto_rule);

            # Clean up helper attribute of &distribute_crypto_rule
            delete $rule->{tunnel_start};
            if (my $tunnel = delete $rule->{tunnel}) {
                my ($start, $end) = @$tunnel;
                $add_rule->($rule, $start, $end);
                $add_rule->(reverse_rule $rule, $end, $start);
            }
            else {
                err_msg "No matching tunnel found for rule of $name\n ",
                  print_rule $rule;
            }
        }
    }
}

##############################################################################
# Check if high-level and low-level semantics of rules with an 'any' object
# as source or destination are equivalent.
# (A) rule "permit any:X dst"
# high-level: all networks of security domain X get access to dst
# low-level: like above, but additionally, the networks of
#            all security domains on the path from any:x to dst
#            get access to dst.
# (B) rule permit src any:X
# high-level: src gets access to all networks of security domain X
# low-level: like above, but additionally, src gets access to the networks of
#            all security domains located directly behind all routers on the
#            path from src to any:X
##############################################################################

{

    # Prevent multiple error messages about missing 'any' rules;
    my %missing_any;

    sub err_missing_any ( $$$$ ) {
        my ($rule, $any, $where, $router) = @_;
        return if $missing_any{$any};
        $missing_any{$any} = $any;
        my $policy = $rule->{rule}->{policy}->{name};
        $rule   = print_rule $rule;
        $router = $router->{name};
        err_msg "Missing 'any' rule.\n", " $rule\n", " of $policy\n",
          " can't be effective at $router.\n",
          " There needs to be defined a similar rule with\n",
          " $where=$any->{name}";
    }
}

# If such rule is defined
#  permit any1 dst
#
# and topology is like this:
#
# any1-R1-any2-R2-any3-R3-dst
#         any4-/
#
# additional rules need to be defined as well:
#  permit any2 dst
#  permit any3 dst
#
# If R2 is stateless, we need one more rule to be defined:
#  permit any4 dst
# This is, because at R2 we would get an automatically generated
# reverse rule
#  permit dst any1
# which would accidently permit traffic to any4 as well.
sub check_any_src_rule( $$$ ) {

    # Function is called from path_walk.
    my ($rule, $in_intf, $out_intf) = @_;

    # out_intf may be undefined if dst is an interface and
    # we just process the corresponding router,
    # thus we better use in_intf.
    my $router = $in_intf->{router};
    return unless $router->{managed};

    # Check only for the first router, because next test will be done
    # for rule "permit any2 dst" anyway.
    return unless $in_intf->{any} eq $rule->{src};

    # Destination is interface of current router and therefore there is
    # nothing to be checked.
    return unless $out_intf;

    my $out_any = $out_intf->{any};
    my $dst     = $rule->{dst};
    if ($out_any eq $dst) {

        # Both src and dst are 'any' objects and are directly connected
        # at current router. Hence there can't be any missing rules.
        # But we need to know about this situation later during code
        # generation.
        # Note: Additional checks will be done for this situation at
        # check_any_dst_rule
        $rule->{any_are_neighbors} = 1;
        return;
    }

    # Check if reverse rule would need additional rules.
    if ($router->{model}->{stateless}) {
        my $proto = $rule->{srv}->{proto};
        if ($proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip') {

            # Find security domains at all interfaces except the in_intf.
            for my $intf (@{ $router->{interfaces} }) {
                next if $intf eq $in_intf;

                # Nothing to be checked for the interface which is connected
                # directly to the destination 'any' object.
                next if $intf eq $out_intf;
                my $any = $intf->{any};
                unless ($rule_tree{ $rule->{action} }->{$any}->{$dst}
                    ->{ $rule->{src_range} }->{ $rule->{srv} })
                {
                    err_missing_any $rule, $any, 'src', $router;
                }
            }
        }
    }
    my $dst_any = get_any $dst;

    # Security domain of dst is directly connected with current router.
    # Hence there can't be any missing rules.
    return if $out_any eq $dst_any;
    unless ($rule_tree{ $rule->{action} }->{$out_any}->{$dst}
        ->{ $rule->{src_range} }->{ $rule->{srv} })
    {
        err_missing_any $rule, $out_any, 'src', $router;
    }
}

# If such rule is defined
#  permit src any5
#
# and topology is like this:
#
#                      /-any4
# src-R1-any2-R2-any3-R3-any5
#      \-any1
#
# additional rules need to be defined as well:
#  permit src any1
#  permit src any2
#  permit src any3
#  permit src any4
sub check_any_dst_rule( $$$ ) {

    # Function is called from path_walk.
    my ($rule, $in_intf, $out_intf) = @_;

    # in_intf may be undefined if src is an interface and
    # we just process the corresponding router,
    # thus we better use out_intf
    my $router = $out_intf->{router};
    return unless $router->{managed};

    my $out_any = $out_intf->{any};

    # We only need to check last router on path.
    return unless $rule->{dst} eq $out_any;

    # Source is interface of current router.
    return unless $in_intf;

    my $in_any    = $in_intf->{any};
    my $src       = $rule->{src};
    my $src_range = $rule->{src_range};
    my $srv       = $rule->{srv};
    my $src_any   = get_any $src;

    # Find security domains at all interfaces except the in_intf.
    for my $intf (@{ $router->{interfaces} }) {

        # Nothing to be checked for the interface which is connected
        # directly to the destination 'any' object.
        next if $intf eq $out_intf;
        my $any = $intf->{any};

        # Nothing to be checked if src is directly attached to current router.
        next if $any eq $src_any;
        unless (
            $rule_tree{ $rule->{action} }->{$src}->{$any}->{$src_range}->{$srv})
        {
            err_missing_any $rule, $any, 'dst', $router;
        }
    }
}

# Handling of any rules created by gen_reverse_rules.
#
# 1. dst is any
#
# src--r1:stateful--dst1=any1--r2:stateless--dst2=any2
#
# gen_reverse_rule will create one additional rule
# any2-->src, but not a rule any1-->src, because r1 is stateful.
# check_any_src_rule would complain, that any1-->src is missing.
# But that doesn't matter, because r1 would permit answer packets
# from any2 anyway, because it's stateful.
# Hence we can skip check_any_src_rule for this situation.
#
# 2. src is any
#
# a) no stateful router on the path between stateless routers and dst.
#
#        any2---\
# src=any1--r1:stateless--dst
#
# gen_reverse_rules will create one additional rule dst-->any1.
# check_any_dst_rule would complain about a missing rule
# dst-->any2.
# To prevent this situation, check_any_src_rule checks for a rule
# any2 --> dst
#
# b) at least one stateful router on the path between
#    stateless router and dst.
#
#        any3---\
# src1=any1--r1:stateless--src2=any2--r2:stateful--dst
#
# gen_reverse_rules will create one additional rule
# dst-->any1, but not dst-->any2 because second router is stateful.
# check_any_dst_rule would complain about missing rules
# dst-->any2 and dst-->any3.
# But answer packets back from dst have been filtered by r2 already,
# hence it doesn't hurt if the rules at r1 are a bit too relaxed,
# i.e. r1 would permit dst to any, but should only permit dst to any1.
# Hence we can skip check_any_dst_rule for this situation.
# (Case b isn't implemented currently.)
#

sub check_any_rules() {
    info "Checking rules with 'any' objects";
    for my $rule (@{ $expanded_rules{any} }) {
        next if $rule->{deleted};
        next if $rule->{stateless};
        if (is_any($rule->{src})) {
            path_walk($rule, \&check_any_src_rule);
        }
        if (is_any($rule->{dst})) {
            path_walk($rule, \&check_any_dst_rule);
        }
    }
}

##############################################################################
# Generate reverse rules for stateless packet filters:
# For each rule with protocol tcp, udp or ip we need a reverse rule
# with swapped src, dst and src-port, dst-port.
# For rules with a tcp service, the reverse rule gets a tcp service
# without range checking but with checking for 'established` flag.
##############################################################################

sub gen_reverse_rules1 ( $ ) {
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
        my $srv   = $rule->{srv};
        my $proto = $srv->{proto};
        next unless $proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip';

        # No reverse rules will be generated for denied TCP packets, because
        # - there can't be an answer if the request is already denied and
        # - the 'established' optimization for TCP below would produce
        #   wrong results.
        next if $proto eq 'tcp' and $rule->{action} eq 'deny';

        my $has_stateless_router;
      PATH_WALK:
        {

            # Local function.
            # It uses variable $has_stateless_router.
            my $mark_reverse_rule = sub( $$$ ) {
                my ($rule, $in_intf, $out_intf) = @_;

                # Destination of current rule is current router.
                # Outgoing packets from a router itself are never filtered.
                # Hence we don't need a reverse rule for current router.
                return if not $out_intf;
                my $router = $out_intf->{router};
                return unless $router->{managed};
                my $model = $router->{model};

                # Source of current rule is current router.
                if (not $in_intf) {
                    if ($model->{stateless_self}) {
                        $has_stateless_router = 1;

                        # Jump out of path_walk.
                        no warnings "exiting";
                        last PATH_WALK if $use_nonlocal_exit;
                    }
                }
                elsif ($model->{stateless}) {
                    $has_stateless_router = 1;

                    # Jump out of path_walk.
                    no warnings "exiting";
                    last PATH_WALK if $use_nonlocal_exit;
                }
            };
            path_walk($rule, $mark_reverse_rule);
        }
        if ($has_stateless_router) {
            my $new_src_range;
            my $new_srv;
            if ($proto eq 'tcp') {
                $new_src_range = $range_tcp_any;
                $new_srv       = $range_tcp_established;
            }
            elsif ($proto eq 'udp') {

                # Swap src and dst range.
                $new_src_range = $rule->{srv};
                $new_srv       = $rule->{src_range};
            }
            elsif ($proto eq 'ip') {
                $new_srv       = $rule->{srv};
                $new_src_range = $rule->{src_range};
            }
            else {
                internal_err;
            }
            my $new_rule = {
                action    => $rule->{action},
                src       => $rule->{dst},
                dst       => $rule->{src},
                src_range => $new_src_range,
                srv       => $new_srv,

                # This rule must only be applied to stateless routers.
                stateless => 1
            };
            $new_rule->{any_are_neighbors} = 1 if $rule->{any_are_neighbors};

            # Don't push to @$rule_aref while we are iterating over it.
            push @extra_rules, $new_rule;
        }
    }
    push @$rule_aref, @extra_rules;
    add_rules \@extra_rules, \%reverse_rule_tree;
}

sub gen_reverse_rules() {
    info "Generating reverse rules for stateless routers";
    for my $type ('deny', 'any', 'permit') {
        gen_reverse_rules1 $expanded_rules{$type};
    }
}

##############################################################################
# Mark rules for secondary filters.
# At secondary packet filter interfaces, packets are only checked for its
# src and dst networks, if there is a full packet filter interface on the path
# from src to dst, were the original rule is checked.
##############################################################################

sub mark_secondary_rules() {
    info "Marking rules for secondary optimization";

    # Mark only normal rules for optimization.
    # We can't change a deny rule from e.g. tcp to ip.
    # We can't change 'any' rules, because path is unknown.
  RULE:
    for my $rule (@{ $expanded_rules{permit} }) {
        next
          if $rule->{deleted}
          and (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
        my $mark_secondary_rule = sub( $$$ ) {
            my ($rule, $in_intf, $out_intf) = @_;
            if (not $in_intf) {

                # Source of rule must be some interface of current router,
                # because $in_intf is undefined.
                my $src = $rule->{src};

                # If source is outgoing interface then its network
                # isn't filtered at this router.
                return if $src eq $out_intf;

                # Remaining case:
                # Interface is located behind router when looking
                # into direction of destination.
                # Router isn't managed.
                return unless $src->{managed};

                # Interface isn't full filter.
                return unless $src->{managed} eq 'full';
            }
            else {

                # Router isn't managed.
                return unless $in_intf->{managed};

                # Interface isn't full filter.
                return unless $in_intf->{managed} eq 'full';

                # Destination of rule is an interface of current router.
                # But network of interface wouldn't be filtered, if it's
                # located before router.
                # Hence, this router doesn't count as a full packet filter.
                return if not $out_intf and $rule->{dst} eq $in_intf;

                # A full filter inside a loop doesn't count, because there
                # might be another path without a full packet filter.
                # But a full packet filter at loop entry or exit is sufficient.
                # ToDo: This could be analyzed in more detail.
                return if $in_intf->{in_loop} and $out_intf->{in_loop};
            }

            # Optimization should only take place for IP addresses
            # which are really filtered by a full packet filter.
            # ToDo: Think about virtual interfaces sitting
            # all on the same hardware.
            $rule->{has_full_filter} = 1;

            # Jump out of path_walk.
            no warnings "exiting";
            next RULE if $use_nonlocal_exit;
        };
        path_walk($rule, $mark_secondary_rule);
    }
}

##############################################################################
# Optimize expanded rules by deleting identical rules and
# rules which are overlapped by a more general rule
##############################################################################

sub optimize_rules( $$ ) {
    my ($cmp_hash, $chg_hash) = @_;
    for my $action (keys %$chg_hash) {
        my $chg_hash = $chg_hash->{$action};
        while (1) {
            if (my $cmp_hash = $cmp_hash->{$action}) {
                for my $src_ref (keys %$chg_hash) {
                    my $chg_hash = $chg_hash->{$src_ref};
                    my $src      = $ref2obj{$src_ref};
                    while (1) {
                        if (my $cmp_hash = $cmp_hash->{$src}) {
                            for my $dst_ref (keys %$chg_hash) {
                                my $chg_hash = $chg_hash->{$dst_ref};
                                my $dst      = $ref2obj{$dst_ref};
                                while (1) {
                                    if (my $cmp_hash = $cmp_hash->{$dst}) {
                                        for my $src_range_ref (keys %$chg_hash)
                                        {
                                            my $chg_hash =
                                              $chg_hash->{$src_range_ref};
                                            my $src_range =
                                              $ref2obj{$src_range_ref};
                                            while (1) {
                                                if (my $cmp_hash =
                                                    $cmp_hash->{$src_range})
                                                {
                                                    for my $chg_rule (
                                                        values %$chg_hash)
                                                    {
                                                        next
                                                          if
                                                          $chg_rule->{deleted};
                                                        my $srv =
                                                          $chg_rule->{srv};
                                                        while (1) {
                                                            if (my $cmp_rule =
                                                                $cmp_hash
                                                                ->{$srv})
                                                            {
                                                                unless (
                                                                    $cmp_rule eq
                                                                    $chg_rule)
                                                                {
                                                                    $chg_rule
                                                                      ->{deleted}
                                                                      = $cmp_rule;
                                                                    last;
                                                                }
                                                            }
                                                            $srv = $srv->{up}
                                                              or last;
                                                        }
                                                    }
                                                }
                                                $src_range = $src_range->{up}
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

sub optimize() {
    info "Optimizing globally";
    optimize_rules \%rule_tree, \%rule_tree;
}

# Normal rules > reverse rules.
sub optimize_reverse_rules() {
    info "Optimizing reverse rules";
    optimize_rules \%reverse_rule_tree, \%reverse_rule_tree;
    optimize_rules \%rule_tree,         \%reverse_rule_tree;
}

########################################################################
# Routing
# Add a component 'route' to each interface, which holds an array of
# networks reachable using this interface as next hop.
########################################################################

# This function is called for each network on the path from src to dst
# of $rule.
# If $in_intf and $out_intf are both defined, packets traverse this network.
# If $in_intf is not defined, there is no interface where we could add
# routing entries.
# If $out_intf is not defined, dst is this network;
# hence dst is directly connected to $in_intf
sub collect_route( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;

#    debug "collect: $rule->{src}->{name} -> $rule->{dst}->{name}";
#    my $info = '';
#    $info .= $in_intf->{name} if $in_intf;
#    $info .= ' -> ';
#    $info .= $out_intf->{name} if $out_intf;
#    debug $info;;
    if ($in_intf and $out_intf) {
        return unless $in_intf->{router}->{managed};

        # Remember network which is reachable via $out_intf.
        my $network = $rule->{dst};

        # This router and all routers from here to dst have been processed
        # already.
        # But we can't be sure about this, if we are walking inside a loop.
        if (    $use_nonlocal_exit
            and $in_intf->{routes}->{$out_intf}->{$network}
            and not $in_intf->{in_loop})
        {

            # Jump out of path_walk in sub find_active_routes_and_statics
            no warnings "exiting";
            next RULE;
        }

#	debug "Route at $in_intf->{name}: $network->{name} via $out_intf->{name}";
        $in_intf->{routes}->{$out_intf}->{$network} = $network;

        # Store $out_intf itself, since we need to go back
        # from hash key to original object later.
        $in_intf->{hop}->{$out_intf} = $out_intf;
    }
}

sub check_and_convert_routes () {
    info "Checking for duplicate routes";
    for my $router (@managed_routers) {

        # Remember, via which local interface a network is reached.
        my %net2intf;
        for my $interface (@{ $router->{interfaces} }) {

            # Remember, via which remote interface a network is reached.
            my %net2hop;

            # Convert to array, because hash isn't needed any longer.
            # Array is sorted to get deterministic output.
            $interface->{hop} =
              [ sort { $a->{name} cmp $b->{name} }
                  values %{ $interface->{hop} } ];
            for my $hop (@{ $interface->{hop} }) {
                for my $network (values %{ $interface->{routes}->{$hop} }) {
                    if (my $interface2 = $net2intf{$network}) {
                        if ($interface2 ne $interface) {

                            # Network is reached via two different
                            # local interfaces.
                            # Check if both have dynamic routing enabled.
                            unless ($interface->{routing}
                                and $interface2->{routing})
                            {
                                warn_msg
                                  "Two static routes for $network->{name}\n",
                                  " via $interface->{name} and ",
                                  "$interface2->{name}";
                            }
                        }
                    }
                    else {
                        $net2intf{$network} = $interface;
                    }
                    unless ($interface->{routing}) {
                        if (my $hop2 = $net2hop{$network}) {

                            # Network is reached via two different hops.
                            # Check if both are reached via the same virtual IP.
                            if (    $hop->{virtual}
                                and $hop2->{virtual}
                                and $hop->{virtual}->{ip} eq
                                $hop2->{virtual}->{ip})
                            {

                                # Prevent multiple identical routes to different
                                # interfaces with identical virtual IP.
                                delete $interface->{routes}->{$hop}->{$network};
                            }
                            else {
                                warn_msg
                                  "Two static routes for $network->{name}\n",
                                  " at $interface->{name}";
                            }
                        }
                        else {
                            $net2hop{$network} = $hop;
                        }
                    }
                }
            }
        }
    }
}

# Collect networks for generation of static commands.
sub mark_networks_for_static( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;

    # No static needed for directly attached interface.
    return unless $out_intf;
    my $router = $out_intf->{router};
    return unless $router->{managed};
    return unless $router->{model}->{has_interface_level};

    # No static needed for traffic coming from the PIX itself.
    return unless $in_intf;

    # We need in_hw and out_hw for
    # - their names and for
    # - getting the NAT domain
    my $in_hw  = $in_intf->{hardware};
    my $out_hw = $out_intf->{hardware};
    my $dst    = $rule->{dst};

    # dst has been added before; skip NAT calculation.
    return if $out_hw->{static}->{$in_hw}->{$dst};
    err_msg "Traffic to $rule->{dst}->{name} can't pass\n",
      " from  $in_intf->{name} to $out_intf->{name},\n",
      " because they have equal security levels.\n"
      if $in_hw->{level} == $out_hw->{level};

    # This router and all routers from here to dst have been processed already.
    # But we can't be sure about this, if we are walking inside a loop.
    if (    $use_nonlocal_exit
        and $out_hw->{static}->{$in_hw}->{$dst}
        and not $in_intf->{in_loop})
    {

        # Jump out of path_walk in sub find_active_routes_and_statics
        no warnings "exiting";
        next RULE;
    }

    # Put networks into a hash to prevent duplicates.
    $out_hw->{static}->{$in_hw}->{$dst} = $dst;

    # Do we need to generate "nat 0" for an interface?
    if ($in_hw->{level} < $out_hw->{level}) {
        $out_hw->{need_nat_0} = 1;
    }
    else {

        # Check, if there is a dynamic NAT of a dst address from higher
        # to lower security level. We need this info to decide,
        # if static commands with "identity mapping" and
        # a "nat 0" command needs to be generated.
        $out_hw->{need_always_static} and return;

        # Remember: NAT tag for networks behind out_hw is attached to in_hw.
        my $nat_tag = $in_hw->{bind_nat} or return;
        if (   $dst->{nat}
            && $dst->{nat}->{$nat_tag}
            && $dst->{nat}->{$nat_tag}->{dynamic})
        {
            $out_hw->{need_always_static} = 1;
            $out_hw->{need_nat_0}         = 1;
        }
    }
}

sub find_active_routes_and_statics () {
    info "Finding routes and statics";
    my %routing_tree;
    my $pseudo_srv = { name => '--' };
    my $fun = sub ( $$ ) {
        my ($src, $dst) = @_;

        # Don't apply get_network to $src, but use get_path instead:
        # - It doesn't matter which network of an 'any' object is used.
        # - We must preserve managed interfaces, since they may get routing
        #   entries added.
        my $from = get_path $src;

#     debug "$from->{name} -> $to->{name}";
        # 'any' objects are expanded to all its contained networks
        # hosts and interfaces expand to its containing network.
        # Don't try to use an interface as destination of $pseudo_rule;
        # this would give wrong routes and statics, if a path restriction
        # is applied to this interface.
        for my $network (get_networks($dst)) {
            next if $network->{ip} eq 'unnumbered';
            unless ($routing_tree{$from}->{$network}) {
                my $pseudo_rule = {
                    src    => $from,
                    dst    => $network,
                    action => '--',
                    srv    => $pseudo_srv,
                };
                $routing_tree{$from}->{$network} = $pseudo_rule;
            }
        }
    };
    for my $rule (@{ $expanded_rules{permit} }, @{ $expanded_rules{any} }) {
        $fun->($rule->{src}, $rule->{dst});
    }
    for my $hash (values %routing_tree) {
      RULE:
        for my $pseudo_rule (values %$hash) {
            path_walk($pseudo_rule, \&mark_networks_for_static, 'Router');
        }
    }

    # Additionally process reverse direction for routing.
    for my $rule (@{ $expanded_rules{permit} }, @{ $expanded_rules{any} }) {
        $fun->($rule->{dst}, $rule->{src});
    }
    for my $hash (values %routing_tree) {
      RULE:
        for my $pseudo_rule (values %$hash) {
            path_walk($pseudo_rule, \&collect_route, 'Network');
        }
    }
    check_and_convert_routes;
}

sub ios_route_code( $ );
sub prefix_code( $ );
sub address( $$ );

# Needed for default route optimization and
# while generating chains of iptables and
# for local optimization.
my $network_00 = new('Network', name => "network:0/0", ip => 0, mask => 0);

sub print_routes( $ ) {
    my ($router)     = @_;
    my $type         = $router->{model}->{routing};
    my $comment_char = $router->{model}->{comment_char};
    if ($auto_default_route) {

        # Find interface and hop with largest number of routing entries.
        my $max_intf;
        my $max_hop;

        # Substitute routes to one hop with a default route,
        # if there are at least two entries.
        my $max = 1;
        for my $interface (@{ $router->{interfaces} }) {
            if ($interface->{routing}) {

                # If dynamic routing is activated for any interface
                # of the current router, don't do this optimization at all.
                $max_intf = undef;
                last;
            }
            for my $hop (@{ $interface->{hop} }) {
                my $count = keys %{ $interface->{routes}->{$hop} };
                if ($count > $max) {
                    $max_intf = $interface;
                    $max_hop  = $hop;
                    $max      = $count;
                }
            }
        }
        if ($max_intf && $max_hop) {

            # Use default route for this direction.
            $max_intf->{routes}->{$max_hop} = { $network_00 => $network_00 };
        }
    }
    print "$comment_char [ Routing ]\n";
    for my $interface (@{ $router->{interfaces} }) {

        # Don't generate static routing entries,
        # if a dynamic routing protocol is activated
        if ($interface->{routing}) {
            if ($comment_routes) {
                print "$comment_char Routing $interface->{routing}->{name}",
                  " at $interface->{name}\n";
            }
            next;
        }
        my $nat_map = $interface->{nat_map};
        for my $hop (@{ $interface->{hop} }) {

            # For unnumbered networks use interface name as next hop.
            my $hop_addr =
                $hop->{ip} eq 'unnumbered'
              ? $interface->{hardware}->{name}
              : $hop->{virtual}
              ?

              # Take virtual IP if available.
              print_ip $hop->{virtual}->{ip}
              :

              # Take first IP from list of IP addresses.
              print_ip $hop->{ip}->[0];

            # A hash having all networks reachable via current hop
            # both as key and as value.
            my $net_hash = $interface->{routes}->{$hop};
            for my $network

              # Sort networks by mask in reverse order,
              # i.e. small networks coming first and
              # for equal mask by IP address.
              # We need this to make the output deterministic
              (sort { $b->{mask} <=> $a->{mask} || $a->{ip} <=> $b->{ip} }
                values %$net_hash)
            {

                # Network is redundant, if directly enclosing network
                # is located behind same hop.
                if (my $bignet = $network->{is_in}->{$nat_map}) {
                    next if $net_hash->{$bignet};
                }
                if ($comment_routes) {
                    print "! route $network->{name} -> $hop->{name}\n";
                }
                if ($type eq 'IOS') {
                    my $adr = ios_route_code(address($network, $nat_map));
                    print "ip route $adr\t$hop_addr\n";
                }
                elsif ($type eq 'PIX') {
                    my $adr = ios_route_code(address($network, $nat_map));
                    print
                      "route $interface->{hardware}->{name} $adr\t$hop_addr\n";
                }
                elsif ($type eq 'iproute') {
                    my $adr = prefix_code(address($network, $nat_map));
                    print "ip route add $adr via $hop_addr\n";
                }
		elsif ($type eq 'none') {

		    # Do nothing.
		}
                else {
                    internal_err "unexpected routing type '$type'";
                }
            }
        }
    }
}

##############################################################################
# 'static' commands for pix firewalls
##############################################################################

sub print_pix_static( $ ) {
    my ($router) = @_;
    my %ref2hw;
    my $comment_char = $router->{model}->{comment_char};
    print "$comment_char [ Static ]\n";

    # Print security level relation for each interface.
    print "! Security levels: ";
    my $prev_level;
    for my $hardware (sort { $a->{level} <=> $b->{level} }
        @{ $router->{hardware} })
    {

        # For getting reference back from key.
        $ref2hw{$hardware} = $hardware;
        my $level = $hardware->{level};
        if (defined $prev_level) {
            print(($prev_level == $level) ? " = " : " < ");
        }
        print $hardware->{name};
        $prev_level = $level;
    }
    print "\n";

    my $nat_index = 1;
    for
      my $out_hw (sort { $a->{level} <=> $b->{level} } @{ $router->{hardware} })
    {
        next unless $out_hw->{static};
        my $out_name = $out_hw->{name};
        my $out_nat  = $out_hw->{nat_map};
        for my $in_hw (
            sort { $a->{level} <=> $b->{level} }
            map  { $ref2hw{$_} }

            # Key is reference to hardware interface.
            keys %{ $out_hw->{static} }
          )
        {

            # Value is { net => net, .. }
            my ($net_hash) = $out_hw->{static}->{$in_hw};
            my $in_name    = $in_hw->{name};
            my $in_nat     = $in_hw->{nat_map};

            # Sorting is only needed for getting output deterministic.
            my @networks =
              sort { $a->{ip} <=> $b->{ip} || $a->{mask} <=> $b->{mask} }
              values %$net_hash;

            # Mark redundant network as deleted.
            # A network is redundant if some enclosing network is found
            # in both NAT domains of incoming and outgoing interface.
            for my $network (@networks) {
                my $net = $network->{is_in}->{$in_nat};
                while ($net) {
                    my $net2;
                    if (    $net_hash->{$net}
                        and $net2 = $network->{is_in}->{$out_nat}
                        and $net_hash->{$net2})
                    {
                        $network = undef;
                        last;
                    }
                    else {
                        $net = $net->{is_in}->{$in_nat};
                    }
                }
            }
            for my $network (@networks) {
                next unless defined $network;
                my ($in_ip, $in_mask, $in_dynamic) =
                  @{ $in_nat->{$network} || $network }{ 'ip', 'mask',
                    'dynamic' };
                my ($out_ip, $out_mask, $out_dynamic) =
                  @{ $out_nat->{$network} || $network }{ 'ip', 'mask',
                    'dynamic' };
                if ($in_mask == 0 || $out_mask == 0) {
                    err_msg "Pix doesn't support static command for ",
                      "mask 0.0.0.0 of $network->{name}\n";
                }

                # We are talking about destination addresses.
                if ($out_dynamic) {
                    unless ($in_dynamic
                        && $in_dynamic eq $out_dynamic
                        && $in_ip      eq $out_ip
                        and $in_mask   eq $out_mask)
                    {
                        warn_msg "Ignoring NAT for dynamically translated ",
                          "$network->{name}\n",
                          "at hardware $out_hw->{name} of $router->{name}";
                    }
                }
                elsif ($in_dynamic) {

                    # global (outside) 1 \
                    #   10.70.167.0-10.70.167.255 netmask 255.255.255.0
                    # nat (inside) 1 141.4.136.0 255.255.252.0
                    my $in_ip_max = $in_ip | complement_32bit $in_mask;
                    $in_ip     = print_ip $in_ip;
                    $in_ip_max = print_ip $in_ip_max;
                    $out_ip    = print_ip $out_ip;
                    $in_mask   = print_ip $in_mask;
                    $out_mask  = print_ip $out_mask;
                    print "global ($in_name) $nat_index ",
                      "$in_ip-$in_ip_max netmask $in_mask\n";
                    print "nat ($out_name) $nat_index $out_ip $out_mask";
                    print " outside" if $in_hw->{level} > $out_hw->{level};
                    print "\n";
                    $nat_index++;

                    # Check for static NAT entries of hosts and interfaces.
                    for my $host (@{ $network->{subnets} },
                        @{ $network->{interfaces} })
                    {
                        if (my $in_ip = $host->{nat}->{$in_dynamic}) {
                            my @addresses = address($host, $out_nat);
                            err_msg "$host->{name}: NAT only for hosts / ",
                              "interfaces with a single IP"
                              if @addresses != 1;
                            my ($out_ip, $out_mask) = @{ $addresses[0] };
                            $in_ip    = print_ip $in_ip;
                            $out_ip   = print_ip $out_ip;
                            $out_mask = print_ip $out_mask;
                            print "static ($out_name,$in_name) ",
                              "$in_ip $out_ip netmask $out_mask\n";
                        }
                    }
                }
                else {    # both static
                    if (   $in_hw->{level} < $out_hw->{level}
                        || $out_hw->{need_always_static}
                        || $in_ip ne $out_ip)
                    {
                        $in_ip   = print_ip $in_ip;
                        $out_ip  = print_ip $out_ip;
                        $in_mask = print_ip $in_mask;

                        # static (inside,outside) \
                        #   10.111.0.0 111.0.0.0 netmask 255.255.252.0
                        print "static ($out_name,$in_name) ",
                          "$in_ip $out_ip netmask $in_mask\n";
                    }
                }
            }
        }
        print "nat ($out_name) 0 0.0.0.0 0.0.0.0\n" if $out_hw->{need_nat_0};
    }
}

##############################################################################
# Distributing rules to managed devices
##############################################################################

sub distribute_rule( $$$;$ ) {
    my ($rule, $in_intf, $out_intf, $in_crypto_map) = @_;

    # Traffic from src reaches this router via in_intf
    # and leaves it via out_intf.
    # in_intf is undefined if src is an interface of current router.
    # out_intf is undefined if dst is an interface of current router.
    # Outgoing packets from a router itself are never filtered.
    return unless $in_intf;
    my $router = $in_intf->{router};
    return unless $router->{managed};

    # Rules of type stateless must only be processed at stateless routers
    # or at routers which are stateless for packets destined for
    # their own interfaces.
    my $model = $router->{model};
    if ($rule->{stateless}) {
        unless ($model->{stateless}
            or not $out_intf and $model->{stateless_self})
        {
            return;
        }
    }

    # Rules to managed interfaces must be processed
    # at the corresponding router even if they are marked as deleted,
    # because code for interfaces is placed before the 'normal' code.
    if ($rule->{deleted}) {

        # We are on an intermediate router if $out_intf is defined.
        return if $out_intf;

        # No code needed if it is deleted by another rule to the same interface.
        return if $rule->{deleted}->{managed_intf};
    }

    # Validate dynamic NAT.
    if (my $nat_map = $in_intf->{nat_map}) {
        for my $where ('src', 'dst') {
            my $obj = $rule->{$where};
            if (is_subnet $obj || is_interface $obj) {
                my $network = $obj->{network};
                if (my $nat_network = $nat_map->{$network}) {
                    if (my $nat_tag = $nat_network->{dynamic}) {

                        # Doesn't have a static translation.
                        unless ($obj->{nat}->{$nat_tag}) {
                            my $intf = $where eq 'src' ? $in_intf : $out_intf;

                            # Object is located in the same security domain,
                            # hence there is no other managed router
                            # in between.
			    # $intf could have value 'undef' if $obj is
			    # interface of current router and destination of rule.
                            if (! $intf || $network->{any} eq $intf->{any}) {
                                err_msg "$obj->{name} needs static translation",
                                  " for nat:$nat_tag\n",
                                  " to be valid in rule\n ", print_rule $rule;
                            }

                            # Otherwise, filtering occurs at other router,
                            # therefore the whole network can pass here.
                            # But attention, this assumption only holds,
                            # if the other router filters fully.
                            # Hence disable 'secondary' optimization.
                            undef $rule->{has_full_filter};

                            # Make a copy of current rule, because the
                            # original rule must not be changed.
                            $rule = {%$rule};

                            # Permit whole network, because no static address
                            # is known.
                            $rule->{$where} = $network;
                        }
                    }
                }
            }
        }
    }

    # VPN3K: At interfaces without tag 'no_check',
    # src  of rule must only be host or network with ID.
    if ($router->{model}->{name} eq 'VPN3K' and not $in_intf->{no_check}) {
	my $src = $rule->{src};
	if ($src->{id}) {
	    if (is_network $src and $in_intf->{auto_crypto}) {

		# Automatically generate IPSec-Tunnel to corresponding router.
		my $peer = $src->{interfaces}->[0]->{router};
		$peer->{auto_crypto_peer}->{$in_intf} = $in_intf;
	    }
	} else {
	    err_msg
	      "Source of rule must have ID when entering $in_intf->{name} in rule\n ",
	      print_rule $rule;
	}
    }
    my $aref;
    my $store =
      ($in_crypto_map && !$model->{no_crypto_filter})
      ? $in_crypto_map
      : $in_intf->{hardware};

#  debug "$router->{name} store: $store->{name}";
    if (not $out_intf) {

        # Packets for the router itself.  For PIX we can only reach that
        # interface, where traffic enters the PIX.
        return if $model->{filter} eq 'PIX' and $rule->{dst} ne $in_intf;

#     debug "$router->{name} intf_rule: ",print_rule $rule,"\n";
        push @{ $store->{intf_rules} }, $rule;
    }
    else {

#     debug "$router->{name} rule: ",print_rule $rule,"\n";
        # Prevent duplicate rules, when path is splitting behind current
        # router. This might occur at the start or inside a cyclic graph.
        # Therefore check if last rule and current rule are identical.
        # This test can't easily be done at local_optimization,
        # because it wouldn't find IDENTICAL rules.
        # Force auto-vivification.
        my $aref = \@{ $store->{rules} };
        push @$aref, $rule
          unless $router->{loop}
          and @$aref
          and $aref->[$#$aref] eq $rule;
    }
}

# For rules with src=any:*, call distribute_rule only for
# the first router on the path from src to dst.
sub distribute_rule_at_src( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $router = $in_intf->{router};
    return unless $router->{managed};
    my $src = $rule->{src};
    is_any $src or internal_err "$src must be of type 'any'";

    # Rule is only processed at the first router on the path.
    if ($in_intf->{any} eq $src) {
        &distribute_rule(@_);
    }
}

# For rules with dst=any:*, call distribute_rule only for
# the last router on the path from src to dst.
sub distribute_rule_at_dst( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $router = $out_intf->{router};
    return unless $router->{managed};
    my $dst = $rule->{dst};
    is_any $dst or internal_err "$dst must be of type 'any'";

    # Rule is only processed at the last router on the path.
    if ($out_intf->{any} eq $dst) {
        &distribute_rule(@_);
    }
}

sub rules_distribution() {
    info "Distributing rules";

    # Deny rules
    for my $rule (@{ $expanded_rules{deny} }) {
        next if $rule->{deleted};
        path_walk($rule, \&distribute_rule);
    }

    # Rules with 'any' object as src or dst.
    for my $rule (@{ $expanded_rules{any} }) {
        next
          if $rule->{deleted}
          and (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
        if (is_any $rule->{src}) {
            if (is_any $rule->{dst}) {

                # Both, src and dst are 'any' objects.
                # We only need to generate code if they are directly connected
                # by a managed router.
                # See check_any_both_rule above for details.
                if ($rule->{any_are_neighbors}) {
                    path_walk($rule, \&distribute_rule_at_dst);
                }
            }
            else {
                path_walk($rule, \&distribute_rule_at_src);
            }
        }
        elsif (is_any $rule->{dst}) {
            path_walk($rule, \&distribute_rule_at_dst);
        }
        else {
            internal_err "unexpected rule ", print_rule $rule, "\n";
        }
    }

    # Other permit rules
    for my $rule (@{ $expanded_rules{permit} }) {
        next
          if $rule->{deleted}
          and (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
        path_walk($rule, \&distribute_rule, 'Router');
    }
}

##############################################################################
# ACL Generation
##############################################################################

# Parameters:
# obj: this address we want to know
# network: look inside this nat domain
# returns a list of [ ip, mask ] pairs
sub address( $$ ) {
    my ($obj, $nat_map) = @_;
    my $type = ref $obj;
    if ($type eq 'Network') {
        $obj = $nat_map->{$obj} || $obj;

        # ToDo: Is it OK to permit a dynamic address as destination?
        if ($obj->{ip} eq 'unnumbered') {
            internal_err "Unexpected unnumbered $obj->{name}\n";
        }
        else {
            return [ $obj->{ip}, $obj->{mask} ];
        }
    }
    elsif ($type eq 'Subnet') {
        my $network = $obj->{network};
        $network = $nat_map->{$network} || $network;
        if (my $nat_tag = $network->{dynamic}) {
            if (my $ip = $obj->{nat}->{$nat_tag}) {

                # Single static NAT IP for this host.
                return [ $ip, 0xffffffff ];
            }
            else {

                # This has been converted to the  whole network before.
                internal_err "Unexpected $obj->{name} with dynamic NAT";
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
    if ($type eq 'Interface') {
        if ($obj->{ip} =~ /unnumbered|short/) {
            internal_err "Unexpected $obj->{ip} $obj->{name}\n";
        }

        my $network = $obj->{network};
        $network = $nat_map->{$network} || $network;
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
                internal_err "Unexpected $obj->{name} with dynamic NAT";
            }
        }
        else {
            my @ip = @{ $obj->{ip} };

            # Take higher bits from network NAT, lower bits from original IP.
            # This works with and without NAT.
            my ($network_ip, $network_mask) = @{$network}{ 'ip', 'mask' };
            return map {
                [
                    $network_ip | $_ & complement_32bit $network_mask,
                    0xffffffff
                ]
            } @ip;
        }
    }
    elsif ($type eq 'Any') {
        return [ 0, 0 ];
    }
    elsif ($type eq 'Objectgroup') {
        $obj;
    }
    else {
        internal_err "Unexpected object $obj->{name}";
    }
}

# Given an IP and mask, return its address in IOS syntax.
# If optional third parameter is true, use inverted netmask for IOS ACLs.
sub ios_code( $;$ ) {
    my ($pair, $inv_mask) = @_;
    if (is_objectgroup $pair) {
        return "object-group $pair->{name}";
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
        else {
            my $mask_code =
              print_ip($inv_mask ? complement_32bit $mask : $mask);
            return "$ip_code $mask_code";
        }
    }
}

sub ios_route_code( $ ) {
    my ($pair) = @_;
    my ($ip, $mask) = @$pair;
    my $ip_code   = print_ip($ip);
    my $mask_code = print_ip($mask);
    return "$ip_code $mask_code";
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32.
sub prefix_code( $ ) {
    my ($pair) = @_;
    my ($ip, $mask) = @$pair;
    my $ip_code     = print_ip($ip);
    my $prefix_code = mask2prefix($mask);
    return $prefix_code == 32 ? $ip_code : "$ip_code/$prefix_code";
}

my %pix_srv_hole;

# Print warnings about the PIX service hole.
sub warn_pix_icmp() {
    if (%pix_srv_hole) {
        warn_msg "Ignored the code field of the following ICMP services\n",
          " while generating code for pix firewalls:";
        while (my ($name, $count) = each %pix_srv_hole) {
            print STDERR " $name: $count times\n";
        }
    }
}

# Returns 3 values for building an IOS or PIX ACL:
# permit <val1> <src> <val2> <dst> <val3>
sub cisco_srv_code( $$$ ) {
    my ($src_range, $srv, $model) = @_;
    my $proto = $srv->{proto};

    if ($proto eq 'ip') {
        return ('ip', '', '');
    }
    elsif ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub ( $$ ) {
            my ($v1, $v2) = @_;
            if ($v1 == $v2) {
                return ("eq $v1");
            }

            # PIX doesn't allow port 0; can port 0 be used anyhow?
            elsif ($v1 == 1 and $v2 == 65535) {
                return ('');
            }
            elsif ($v2 == 65535) {
                $v1--;
                return "gt $v1";
            }
            elsif ($v1 == 1) {
                $v2++;
                return "lt $v2";
            }
            else {
                return ("range $v1 $v2");
            }
        };
        my $established = $srv->{established} ? ' established' : '';
        return (
            $proto,
            $port_code->(@{ $src_range->{range} }),
            $port_code->(@{ $srv->{range} }) . $established
        );
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $srv->{type})) {
            if (defined(my $code = $srv->{code})) {
                if ($model->{no_filter_icmp_code}) {

                    # PIX can't handle the ICMP code field.
                    # If we try to permit e.g. "port unreachable",
                    # "unreachable any" could pass the PIX.
                    $pix_srv_hole{ $srv->{name} }++;
                    return ($proto, '', $type);
                }
                else {
                    return ($proto, '', "$type $code");
                }
            }
            else {
                return ($proto, '', $type);
            }
        }
        else {
            return ($proto, '', '');
        }
    }
    else {
        return ($proto, '', '');
    }
}

# Code filtering traffic with PIX as destination.
sub pix_self_code ( $$$$$$ ) {
    my ($action, $spair, $dst, $src_range, $srv, $model) = @_;
    my $src_code = ios_route_code $spair;
    my $dst_intf = $dst->{hardware}->{name};
    my $proto    = $srv->{proto};
    if ($proto eq 'icmp') {
        my ($proto_code, $src_port_code, $dst_port_code) =
          cisco_srv_code($src_range, $srv, $model);
        return "icmp $action $src_code $dst_port_code $dst_intf";
    }
    elsif ($proto eq 'tcp' and $action eq 'permit') {
        my @code;
        my ($v1, $v2) = @{ $srv->{range} };
        if ($v1 <= 23 && 23 <= $v2) {
            push @code, "telnet $src_code $dst_intf";
        }
        if ($v1 <= 22 && 22 <= $v2) {
            push @code, "ssh $src_code $dst_intf";
        }
        if ($v1 <= 80 && 80 <= $v2) {
            push @code, "http $src_code $dst_intf";
        }
        return join "\n", @code;
    }
    else {
        return undef;
    }
}

# Returns iptables code for filtering a service.
sub iptables_srv_code( $$ ) {
    my ($src_range, $srv) = @_;
    my $proto = $srv->{proto};

    if ($proto eq 'ip') {
        return '';
    }
    elsif ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub ( $$ ) {
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
        my $dport  = $port_code->(@{ $srv->{range} });
        my $result = "-p $proto";
        $result .= " -sport $sport" if $sport;
        $result .= " -dport $dport" if $dport;
        $srv->{established}
          and internal_err "Unexpected service $srv->{name} with",
          " 'established' flag while generating code for iptables";
        return $result;
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $srv->{type})) {
            if (defined(my $code = $srv->{code})) {
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

sub acl_line( $$$$ ) {
    my ($rules_aref, $nat_map, $prefix, $model) = @_;
    my $filter_type = $model->{filter};
    for my $rule (@$rules_aref) {
        my ($action, $src, $dst, $src_range, $srv) =
          @{$rule}{ 'action', 'src', 'dst', 'src_range', 'srv' };
        print "$model->{comment_char} " . print_rule($rule) . "\n"
          if $comment_acls;
        for my $spair (address($src, $nat_map)) {
            for my $dpair (address($dst, $nat_map)) {
                if ($filter_type eq 'PIX') {
                    if ($prefix) {

                        # Traffic passing through the PIX.
                        my ($proto_code, $src_port_code, $dst_port_code) =
                          cisco_srv_code($src_range, $srv, $model);
                        my $src_code = ios_code($spair);
                        my $dst_code = ios_code($dpair);
                        print "$prefix $action $proto_code ",
                          "$src_code $src_port_code $dst_code $dst_port_code\n";
                    }
                    else {

                        # Traffic for the PIX itself.
                        if (my $code = pix_self_code $action, $spair, $dst,
                            $src_range, $srv, $model)
                        {

                            # Attention: $code might have multiple lines.
                            print "$code\n";
                        }
                        else {

                            # Other rules are ignored silently.
                        }
                    }
                }
                elsif ($filter_type eq 'IOS') {
                    my $inv_mask = $filter_type eq 'IOS';
                    my ($proto_code, $src_port_code, $dst_port_code) =
                      cisco_srv_code($src_range, $srv, $model);
                    my $src_code = ios_code($spair, $inv_mask);
                    my $dst_code = ios_code($dpair, $inv_mask);
                    print "$prefix $action $proto_code ",
                      "$src_code $src_port_code $dst_code $dst_port_code\n";
                }
                elsif ($filter_type eq 'iptables') {
                    my $srv_code    = iptables_srv_code($src_range, $srv);
                    my $src_code    = prefix_code($spair);
                    my $dst_code    = prefix_code($dpair);
                    my $action_code =
                        is_chain $action ? $action->{name}
                      : $action eq 'permit' ? 'ACCEPT'
                      : 'DROP';
                    print "$prefix -j $action_code ",
                      "-s $src_code -d $dst_code $srv_code\n";
                }
                else {
                    internal_err "Unknown filter_type $filter_type";
                }
            }
        }
    }
}

my $min_object_group_size = 2;

sub find_object_groups ( $ ) {
    my ($router) = @_;

    # For collecting found object-groups.
    my @groups;

    # Find identical groups in identical NAT domain and of same size.
    my %nat2size2group;

    # For generating names of object-groups.
    my $counter = 1;

    # Find object-groups in src / dst of rules.
    for my $this ('src', 'dst') {
        my $that = $this eq 'src' ? 'dst' : 'src';
        my $tag = "${this}_group";
        for my $hardware (@{ $router->{hardware} }) {
            my %group_rule_tree;

            # Find groups of rules with identical
            # action, srv, src/dst and different dst/src.
            for my $rule (@{ $hardware->{rules} }) {
                my $action    = $rule->{action};
                my $that      = $rule->{$that};
                my $this      = $rule->{$this};
                my $srv       = $rule->{srv};
                my $src_range = $rule->{src_range};
                $group_rule_tree{$action}->{$src_range}->{$srv}->{$that}
                  ->{$this} = $rule;
            }

            # Find groups >= $min_object_group_size,
            # mark rules belonging to one group,
            # put groups into an array / hash.
            for my $href (values %group_rule_tree) {

                # $href is {src_range => href, ...}
                for my $href (values %$href) {

                    # $href is {srv => href, ...}
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
                                    nat_map => $hardware->{nat_map},

                                    # For check, if interfaces belong to
                                    # identical NAT domain.
                                    bind_nat => $hardware->{bind_nat} || 0,

                                    # object-ref => rule, ...
                                    hash => $href
                                };

                                # All this rules have identical
                                # action, srv, src/dst  and dst/src
                                # and shall be replaced by a new object group.
                                for my $rule (values %$href) {
                                    $rule->{$tag} = $glue;
                                }
                            }
                        }
                    }
                }
            }
        }

        # Find a group with identical elements or define a new one.
        my $get_group = sub ( $ ) {
            my ($glue)   = @_;
            my $hash     = $glue->{hash};
            my $bind_nat = $glue->{bind_nat};
            my @keys     = keys %$hash;
            my $size     = @keys;

            # Find group with identical elements.
            for my $group (@{ $nat2size2group{$bind_nat}->{$size} }) {
                my $href = $group->{hash};
                my $eq   = 1;
                for my $key (@keys) {
                    unless ($href->{$key}) {
                        $eq = 0;
                        last;
                    }
                }
                if ($eq) {
                    $glue->{group} = $group;
                    return;
                }
            }

            # Not found, build new group.
            my $group = new(
                'Objectgroup',
                name     => "g$counter",
                elements => [ map { $ref2obj{$_} } @keys ],
                hash     => $hash,
                nat_map  => $glue->{nat_map}
            );
            for my $element (@{ $group->{elements} }) {
                is_any $element
                  and internal_err
                  "Unexpected $element->{name} in object-group";
            }
            push @{ $nat2size2group{$bind_nat}->{$size} }, $group;
            push @groups, $group;
            $counter++;
            $glue->{group} = $group;
        };

        # Build new list of rules using object groups.
        for my $hardware (@{ $router->{hardware} }) {
            my @new_rules;
            for my $rule (@{ $hardware->{rules} }) {
                if (my $glue = $rule->{$tag}) {

#	       debug print_rule $rule;
                    # Remove tag, otherwise call to find_object_groups
                    # for another router would become confused.
                    delete $rule->{$tag};
                    if ($glue->{active}) {

#		  debug " deleted: $glue->{group}->{name}";
                        next;
                    }
                    $get_group->($glue);

#	       debug " generated: $glue->{group}->{name}";
                    $glue->{active} = 1;
                    $rule = {
                        action    => $rule->{action},
                        $that     => $rule->{$that},
                        $this     => $glue->{group},
                        src_range => $rule->{src_range},
                        srv       => $rule->{srv}
                    };
                }
                push @new_rules, $rule;
            }
            $hardware->{rules} = \@new_rules;
        }
    }

    # Print PIX object-groups.
    for my $group (@groups) {
        my $nat_map = $group->{nat_map};
        print "object-group network $group->{name}\n";
        for my $pair (
            sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] }
            map { address($_, $nat_map) } @{ $group->{elements} }
          )
        {
            my $adr = ios_code($pair);
            print " network-object $adr\n";
        }
    }

    # Empty line as delimiter.
    print "\n";
}

sub find_chains ( $ ) {
    my ($router) = @_;

    # For collecting found chains.
    my @chains;

    # For generating names of chains.
    my $counter = 1;

    # Find groups in src / dst of rules.
    for my $this ('dst', 'src') {
        my $that = $this eq 'src' ? 'dst' : 'src';
        my $tag  = "${this}_group";

        # Find identical chains in identical NAT domain,
        # with same action and size.
        my %nat2action2size2group;
        for my $hardware (@{ $router->{hardware} }) {
            my %group_rule_tree;

            # Find groups of rules with identical
            # action, srv, src/dst and different dst/src.
            for my $rule (@{ $hardware->{rules} }) {

                # Action may be reference to chain from first round.
                my $action    = $rule->{action};
                my $that      = $rule->{$that};
                my $this      = $rule->{$this};
                my $src_range = $rule->{src_range};
                my $srv       = $rule->{srv};
                $group_rule_tree{$action}->{$src_range}->{$srv}->{$that}
                  ->{$this} = $rule;
            }

            # Find groups >= $min_object_group_size,
            # mark rules belonging to one group,
            # put groups into an array / hash.
            for my $href (values %group_rule_tree) {

                # $href is {src_range => href, ...}
                for my $href (values %$href) {

                    # $href is {srv => href, ...}
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
                                    nat_map => $hardware->{nat_map},

                                    # For check, if interfaces belong to
                                    # identical NAT domain.
                                    bind_nat => $hardware->{bind_nat} || 0,

                                    # object-ref => rule, ...
                                    hash => $href
                                };

                                # All this rules have identical
                                # action, srv, src/dst  and dst/src
                                # and shall be replaced by a new chain.
                                for my $rule (values %$href) {
                                    $rule->{$tag} = $glue;
                                }
                            }
                        }
                    }
                }
            }
        }

        # Find a chain of same type and with identical elements or
        # define a new one.
        my $get_chain = sub ( $$ ) {
            my ($glue, $action) = @_;
            my $hash     = $glue->{hash};
            my $bind_nat = $glue->{bind_nat};
            my @keys     = keys %$hash;
            my $size     = @keys;

            # Find chain with identical elements.
            for my $chain (
                @{ $nat2action2size2group{$bind_nat}->{$action}->{$size} })
            {
                my $href = $chain->{hash};
                my $eq   = 1;
                for my $key (@keys) {
                    unless ($href->{$key}) {
                        $eq = 0;
                        last;
                    }
                }
                if ($eq) {
                    $glue->{chain} = $chain;
                    return;
                }
            }

            # Not found, build new chain.
            my $chain = new(
                'Chain',
                name     => "c$counter",
                action   => $action,
                where    => $this,
                elements => [ map { $ref2obj{$_} } @keys ],
                hash     => $hash,
                nat_map  => $glue->{nat_map}
            );
            for my $element (@{ $chain->{elements} }) {
                is_any $element
                  and internal_err "Unexpected $element->{name} in chain";
            }
            push @{ $nat2action2size2group{$bind_nat}->{$action}->{$size} },
              $chain;
            push @chains, $chain;
            $counter++;
            $glue->{chain} = $chain;
        };

        # Build new list of rules using chains.
        for my $hardware (@{ $router->{hardware} }) {
            my @new_rules;
            for my $rule (@{ $hardware->{rules} }) {
                if (my $glue = $rule->{$tag}) {

#	       debug print_rule $rule;
                    # Remove tag, otherwise a subsequent call to
                    # find_object_groups or find_chains would become confused.
                    delete $rule->{$tag};
                    if ($glue->{active}) {

#		  debug " deleted: $glue->{chain}->{name}";
                        next;
                    }

                    # Action may be a previously found chain.
                    $get_chain->($glue, $rule->{action});

#	       debug " generated: $glue->{chain}->{name}";
                    $glue->{active} = 1;
                    $rule = {
                        action    => $glue->{chain},
                        $this     => $network_00,
                        $that     => $rule->{$that},
                        src_range => $rule->{src_range},
                        srv       => $rule->{srv}
                    };
                }
                push @new_rules, $rule;
            }
            $hardware->{rules} = \@new_rules;
        }
    }

    # Print chains of iptables.
    for my $chain (@chains) {
        my $name        = $chain->{name};
        my $action      = $chain->{action};
        my $action_code =
            is_chain $action ? $action->{name}
          : $action eq 'permit' ? 'ACCEPT'
          : 'DROP';
        my $nat_map = $chain->{nat_map};
        print "iptables -N $name\n";
        for my $pair (
            sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] }
            map { address($_, $nat_map) } @{ $chain->{elements} }
          )
        {
            my $obj_code = prefix_code($pair);
            my $type = $chain->{where} eq 'src' ? '-s' : '-d';
            print "iptables -A $name -j $action_code $type $obj_code\n";
        }
    }

    # Empty line as delimiter.
    print "\n";
}

# Find adjacent port ranges.
sub join_ranges ( $) {
    my ($hardware) = @_;
    my $changed;
    for my $rules ('intf_rules', 'rules') {
        my %hash = ();
        for my $rule (@{ $hardware->{$rules} }) {
            my ($action, $src, $dst, $src_range, $srv) =
              @{$rule}{ 'action', 'src', 'dst', 'src_range', 'srv' };

            # Only ranges which have a neighbor may be successfully optimized.
            $srv->{has_neighbor} or next;
            $hash{$action}->{$src}->{$dst}->{$src_range}->{$srv} = $rule;
        }

        # %hash is {action => href, ...}
        for my $href (values %hash) {

            # $href is {src => href, ...}
            for my $href (values %$href) {

                # $href is {dst => href, ...}
                for my $href (values %$href) {

                    # $href is {src_port => href, ...}
                    for my $src_range_ref (keys %$href) {
                        my $src_range = $ref2obj{$src_range_ref};
                        my $href      = $href->{$src_range_ref};

                        # Values of %$href are rules with identical
                        # action/src/dst/src_port and a TCP or UDP service.  When
                        # sorting these rules by low port number, rules with
                        # adjacent services will placed side by side.  There can't
                        # be overlaps, because they have been split in function
                        # 'order_ranges'.  There can't be sub-ranges, because they
                        # have been deleted as redundant above.
                        my @sorted =
                          sort {
                            $a->{srv}->{range}->[0] <=> $b->{srv}->{range}->[0]
                          } (values %$href);
                        @sorted >= 2 or next;
                        my $i      = 0;
                        my $rule_a = $sorted[$i];
                        my ($a1, $a2) = @{ $rule_a->{srv}->{range} };
                        while (++$i < @sorted) {
                            my $rule_b = $sorted[$i];
                            my ($b1, $b2) = @{ $rule_b->{srv}->{range} };
                            if ($a2 + 1 == $b1) {

                                # Found adjacent port ranges.
                                if (my $range = delete $rule_a->{range}) {

                                    # Extend range of previous two or more elements.
                                    $range->[1] = $b2;
                                    $rule_b->{range} = $range;
                                }
                                else {

                                    # Combine ranges of $rule_a and $rule_b.
                                    $rule_b->{range} = [ $a1, $b2 ];
                                }

                                # Mark previous rule as deleted.
                                # Don't use attribute 'deleted', this may still be
                                # set by global optimization pass.
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
                    my $srv   = $rule->{srv};
                    my $proto = $srv->{proto};
                    my $key   = join ':', @$range;

                    # Try to find existing srv with matching range.
                    # This is needed for find_object_groups to work.
                    my $new_srv = $srv_hash{$proto}->{$key};
                    unless ($new_srv) {
                        $new_srv = {
                            name  => "joined_$srv->{name}",
                            proto => $proto,
                            range => $range
                        };
                        $srv_hash{$proto}->{$key} = $new_srv;
                    }
                    my $new_rule = { %$rule, srv => $new_srv };
                    push @rules, $new_rule;
                }
                else {
                    push @rules, $rule;
                }
            }
            $hardware->{$rules} = \@rules;
        }
    }
}

sub local_optimization() {
    info "Optimizing locally";
    for my $rule (@{ $expanded_rules{any} }, @{ $expanded_rules{permit} }) {
        next if $rule->{deleted} and not $rule->{managed_intf};
        $rule->{src} = $network_00 if is_any $rule->{src};
        $rule->{dst} = $network_00 if is_any $rule->{dst};
    }
    for my $domain (@natdomains) {
        my $nat_map = $domain->{nat_map};

        # Subnet relation may be different for each NAT domain,
        # therefore it is set up again for each NAT domain.
        for my $network (@networks) {
            $network->{up} = $network->{is_in}->{$nat_map} || $network_00;
        }
        for my $network (@{ $domain->{networks} }) {
            for my $interface (@{ $network->{interfaces} }) {
                my $router = $interface->{router};
                next unless $router->{managed};
                my $secondary_router = $interface->{managed} eq 'secondary';
		my $is_vpn3k         = $router->{model}->{filter} eq 'VPN3K';
                my $hardware         = $interface->{hardware};

                # Do local optimization only once for each hardware interface.
                next if $hardware->{seen};
                $hardware->{seen} = 1;
                for my $rules ('intf_rules', 'rules') {
                    my %hash;
                    my $changed = 0;
                    for my $rule (@{ $hardware->{$rules} }) {
                        my ($action, $src, $dst, $src_range, $srv) =
                          @{$rule}{ 'action', 'src', 'dst', 'src_range',
                            'srv' };
                        $hash{$action}->{$src}->{$dst}->{$src_range}->{$srv} =
                          $rule;
                    }
                  RULE:
                    for my $rule (@{ $hardware->{$rules} }) {
                        my ($action, $src, $dst, $src_range, $srv) =
                          @{$rule}{ 'action', 'src', 'dst', 'src_range',
                            'srv' };
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
                                                    my $srv = $srv;
                                                    if (my $hash =
                                                        $hash->{$src_range})
                                                    {
                                                        while (1) {
                                                            if (my $other_rule =
                                                                $hash->{$srv})
                                                            {
                                                                unless ($rule eq
                                                                    $other_rule)
                                                                {
                                                                    $rule =
                                                                      undef;
                                                                    $changed =
                                                                      1;
                                                                    next RULE;
                                                                }
                                                            }
                                                            $srv = $srv->{up}
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

                        # Convert remaining rules to secondary rules,
                        # if possible.
                        if ($secondary_router && $rule->{has_full_filter}) {
                            $action = $rule->{action};

			    $src = $rule->{src};

			    # Single ID-hosts must not be converted to
			    # network at authenticating router.
			    if (not(is_subnet $src and
				    $src->{id} and
				    $is_vpn3k))
			    {
				# get_networks has a single result if
				# not called with an 'any' object as argument.
				$src = get_networks $src;
			    }
                            $dst = $rule->{dst};
                            if (not(is_interface $dst and
				    $dst->{router} eq $router) and
				not(is_subnet $dst and
				    $dst->{id} and
				    $is_vpn3k))
                            {
                                $dst = get_networks $dst;
                            }

                            # Don't modify original rule, because the
                            # identical rule is referenced at different
                            # routers.
                            my $new_rule = {
                                action    => $action,
                                src       => $src,
                                dst       => $dst,
                                src_range => $srv_ip,
                                srv       => $srv_ip,
                            };

                            # Add new rule to hash. If there are multiple
                            # rules which could be converted to the same
                            # secondary rule, only the first one will be
                            # generated.
                            $hash{$action}->{$src}->{$dst}->{$srv_ip}
                              ->{$srv_ip} = $new_rule;

                            # This changes @{$hardware->{$rules}} !
                            $rule = $new_rule;
                        }
                    }
                    if ($changed) {
                        $hardware->{$rules} =
                          [ grep { defined $_ } @{ $hardware->{$rules} } ];
                    }
                }

                # Join adjacent port ranges.  This must be called after local
                # optimization has been finished because services will be
                # overlapping again after joining.
                join_ranges $hardware;
            }
        }
    }
}

sub print_xml( $ );
sub print_xml( $ ) {
    my($arg) = @_;
    my $ref = ref $arg;
    if (not $ref) {
	print "$arg";
    } elsif ($ref eq 'HASH') {
	for my $tag (keys %$arg) {
	    print "<$tag>";
	    print_xml $arg->{$tag};
	    print "</$tag>\n"
	}
    } else {
	for my $element (@$arg) {
	    print_xml $element;
	}
    }
}

sub print_vpn3k( $ ) {
    my ($router) = @_;
    my $model = $router->{model};
    my %vpn_config = ();
    ($vpn_config{'vpn-device'} = $router->{name})  =~ s/^router://;
    $vpn_config{'aaa-server'} =
      [ map { { radius => print_ip $_->{ips}->[0] } }
	    @{ $router->{radius_servers} } ];
    my @entries = ();
    for my $hardware (@{ $router->{hardware} }) {
        my $hw_name = $hardware->{name};
        my $nat_map = $hardware->{nat_map};

	# Rules of $hardware->{intf_rules} are ignored.
	# Protection for device must currently be configured manually.

	# Collect rules belonging to a single authenticated user or network.
	my %id_rules;
	for my $rule (@{ $hardware->{rules} }) {
	    my $src = $rule->{src};
	    if ($src->{id}) {
		push @{ $id_rules{$src} }, $rule;
	    } elsif ((is_subnet $src || is_interface $src)
		     && $src->{network}->{id}) {
		internal_err "Unexpected src $src->{name} in rule",
		  " at $router->{name}";
	    }
	    else {

		# Traffic from not authenticated sources must only enter
		# at 'no_check' interface.
		# This has been verified during rules distribution.
		# They are silently ignored and should be filtered manually.
	    }
	}
	for my $rules (values %id_rules) {
	    my $src = $rules->[0]->{src};
	    my %entry;
	    $entry{'Called-Station-Id'} = $hw_name;
	    if (is_subnet $src) {
		my $id = $src->{id};
		my $ip = print_ip $src->{ip};
		if ($src->{mask} == 0xffffffff) {
		    $entry{id} = $id;
		    $entry{'Framed-IP-Address'} = $ip;
		}
		else {
		    $entry{suffix} = $id;
		    my $mask = print_ip complement_32bit $src->{mask};
		    $entry{network} = { base => $ip, mask => $mask };
		}
		$entry{inherited} =
		  { %{ $router->{radius_attributes} },
		    %{ $src->{network}->{radius_attributes}},
		    %{ $src->{radius_attributes}},
		  };
	    } elsif (is_network $src) {
		my $id = $src->{id};
		$entry{id} = $id;
		$entry{inherited} = { %{ $router->{radius_attributes} },
				      %{ $src->{radius_attributes}},
				    };
	    } else {
		internal_err "Unexpected src $src->{name}";
	    }
	    my @in_acl;
	    for my $rule (@$rules) {
		my ($action, $src, $dst, $src_range, $srv) =
		  @{$rule}{ 'action', 'src', 'dst', 'src_range', 'srv' };
		my ($proto_code, $src_port_code, $dst_port_code) =
		  cisco_srv_code($src_range, $srv, $model);
		my $spair = address $src, $nat_map;
		for my $dpair (address($dst, $nat_map)) {

		    # 2nd argument: inverted mask.
		    my $src_code = ios_code($spair, 1);
		    my $dst_code = ios_code($dpair, 1);
		    my $code =
		      "$action $proto_code $src_code $src_port_code" .
			" $dst_code $dst_port_code";
		    push @in_acl, { ace => $code };
		}
	    }
	    $entry{in_acl} = \@in_acl;
	    push @entries, { user_entry => \%entry };
	}
    }
    $vpn_config{entries} = \@entries;
    my $result = { 'vpn-config' => \%vpn_config };
    print_xml $result;
}

sub print_acls( $ ) {
    my ($router)     = @_;
    my $model        = $router->{model};
    my $filter       = $model->{filter};
    my $comment_char = $model->{comment_char};

    print "$comment_char [ ACL ]\n";
    if ($filter eq 'PIX') {
        find_object_groups($router) unless $router->{no_group_code};
    }
    elsif ($filter eq 'iptables') {
        find_chains($router) unless $router->{no_group_code};
    }

    # Collect IP addresses of all interfaces.
    my @ip;
    for my $hardware (@{ $router->{hardware} }) {
        for my $interface (@{ $hardware->{interfaces} }) {

            # Current router is used as default router even for some internal
            # networks.
            if ($interface->{reroute_permit}) {
                for my $net (@{ $interface->{reroute_permit} }) {

                    # This is not allowed between different security domains.
                    if ($net->{any} ne $interface->{any}) {
                        err_msg "Invalid reroute_permit for $net->{name} ",
                          "at $interface->{name}: different security domains";
                        next;
                    }

                    # Prepend to all other rules.
                    unshift(
                        @{ $hardware->{rules} },
                        {
                            action    => 'permit',
                            src       => $network_00,
                            dst       => $net,
                            src_range => $srv_ip,
                            srv       => $srv_ip
                        }
                    );
                }
            }

            # Is dynamic routing used?
            if (my $routing = $interface->{routing}) {
                unless ($routing->{name} eq 'manual') {
                    my $srv       = $routing->{srv};
                    my $src_range = $srv_ip;
                    if (my $dst_range = $srv->{dst_range}) {
                        $src_range = $srv->{src_range};
                        $srv       = $srv->{dst_range};
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
                            srv       => $srv
                          };
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
                        srv       => $srv
                      };
                }
            }

            # Handle multicast packets of redundancy protocols.
            if (my $virtual = $interface->{virtual}) {
                my $type      = $virtual->{type};
                my $src       = $interface->{network};
                my $dst       = $xxrp_info{$type}->{mcast};
                my $srv       = $xxrp_info{$type}->{srv};
                my $src_range = $srv_ip;
                if (my $dst_range = $srv->{dst_range}) {
                    $src_range = $srv->{src_range};
                    $srv       = $srv->{dst_range};
                }
                push @{ $hardware->{intf_rules} },
                  {
                    action    => 'permit',
                    src       => $src,
                    dst       => $dst,
                    src_range => $src_range,
                    srv       => $srv
                  };
            }
        }
    }

    # Add deny rules.
    for my $hardware (@{ $router->{hardware} }) {

        # Force valid array reference to prevent error in next but one line.
        $hardware->{rules} ||= [];
        if ($filter eq 'IOS' and @{ $hardware->{rules} }) {
            my $nat_map = $hardware->{nat_map};
            for my $interface (@{ $router->{interfaces} }) {

                # Ignore 'unnumbered' interfaces.
                next if $interface->{ip} =~ /unnumbered|negotiated/;
                internal_err "Managed router has short $interface->{name}"
                  if $interface->{ip} eq 'short';

                # IP of other interface may be unknown if dynamic NAT is used.
                if ($interface->{hardware} ne $hardware
                    and (my $nat_network = $nat_map->{ $interface->{network} }))
                {
                    next if $nat_network->{dynamic};
                }

                # Protect own interfaces.
                push @{ $hardware->{intf_rules} },
                  {
                    action    => 'deny',
                    src       => $network_00,
                    dst       => $interface,
                    src_range => $srv_ip,
                    srv       => $srv_ip
                  };
            }
        }
        if ($filter eq 'iptables') {
            push @{ $hardware->{intf_rules} },
              {
                action    => 'deny',
                src       => $network_00,
                dst       => $network_00,
                src_range => $srv_ip,
                srv       => $srv_ip
              };
        }
        push @{ $hardware->{rules} },
          {
            action    => 'deny',
            src       => $network_00,
            dst       => $network_00,
            src_range => $srv_ip,
            srv       => $srv_ip
          };
    }

    # Generate code.
    for my $hardware (@{ $router->{hardware} }) {
        my $name = "$hardware->{name}_in";
        my $intf_name;
        my $prefix;
        my $intf_prefix;
        if ($comment_acls) {

            # Name of first logical interface
            print "$comment_char $hardware->{interfaces}->[0]->{name}\n";
        }
        if ($filter eq 'IOS') {
            $intf_prefix = $prefix = '';
            print "ip access-list extended $name\n";
        }
        elsif ($filter eq 'PIX') {
            $intf_prefix = '';
            $prefix      = "access-list $name";
        }
        elsif ($filter eq 'iptables') {
            $intf_name   = "$hardware->{name}_self";
            $intf_prefix = "iptables -A $intf_name";
            $prefix      = "iptables -A $name";
            print "iptables -N $name\n";
            print "iptables -N $intf_name\n";
        }
        my $nat_map = $hardware->{nat_map};

        # Interface rules
        acl_line $hardware->{intf_rules}, $nat_map, $intf_prefix, $model;

        # Ordinary rules
        acl_line $hardware->{rules}, $nat_map, $prefix, $model;

        # Post-processing for hardware interface
        if ($filter eq 'IOS') {
            print "interface $hardware->{name}\n";
            print " ip access-group $name in\n";
        }
        elsif ($filter eq 'PIX') {
            print "access-group $name in interface $hardware->{name}\n";
        }

        # Empty line after each interface.
        print "\n";
    }

    # Post-processing for all interfaces.
    if ($filter eq 'iptables') {
        print "iptables -P INPUT DROP\n";
        print "iptables -F INPUT\n";
        print
          "iptables -A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
        for my $hardware (@{ $router->{hardware} }) {
            my $if_name = "$hardware->{name}_self";
            print "iptables -A INPUT -j $if_name -i $hardware->{name} \n";
        }
        print "iptables -A INPUT -j DROP -s 0.0.0.0/0 -d 0.0.0.0/0\n";

        #
        print "iptables -P FORWARD DROP\n";
        print "iptables -F FORWARD\n";
        print
          "iptables -A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
        for my $hardware (@{ $router->{hardware} }) {
            my $name = "$hardware->{name}_in";
            print "iptables -A FORWARD -j $name -i $hardware->{name}\n";
        }
        print "iptables -A FORWARD -j DROP -s 0.0.0.0/0 -d 0.0.0.0/0\n";
    }
}

sub prepare_auto_crypto( $ ) {
    my ($router) = @_;

    # Interfaces of vpn3k devices.
    my @peers = values %{$router->{auto_crypto_peer}};

    # All peers need to use the same ipsec definition.
    my %ipsec;
    for my $peer (@peers) {
	my $ipsec = $peer->{auto_crypto};
	$ipsec{$ipsec} = $ipsec;
    }
    values %ipsec == 1
      or err_msg "ipsec-definitions for auto_crypto must be identical at:",
	map { "\n $_->{router}->{name}" } @peers;
    my($ipsec) = values %ipsec;

    # There needs to be exactly one local network.
    # That is a network with only this router attached.
    # This network must have ID which is to be authenticated at vpn3k device.
    my $local_net;
    for my $interface (@{$router->{interfaces}}) {
	my $network = $interface->{network};
	if (@{$network->{interfaces}} == 1) {
	    if ($local_net) {
		err_msg "$router->{name} must have exacly one local network",
		  " because it has auto_crypto to $peers[0].",
		    " But there are at least two networks attached:\n",
		    "$local_net->{name} and $network->{name}";
	    } elsif (@{$interface->{hardware}->{interfaces}} > 1) {
		err_msg "$network->{name} must be the only network attached to",
		  " $interface->{hardware}->{name}"
	      } elsif (not $network->{id}) {
		  err_msg "$network->{name} must have ID, because it is attached",
		    " to $router->{name} with auto_crypto";
	      } else {
		$local_net = $network;
	    }
	}
    }
    $local_net or
      err_msg "At least one local network with ID needs to be attached to $router->{name}";

    for my $hardware (@{ $router->{hardware} }) {
	my $interfaces = $hardware->{interfaces};
	@$interfaces > 1 and 
	  err_msg "Interface $hardware->{name} of $router->{name} must have extly one",
	    "logical interface";
	my $interface = $interfaces->[0];
	next if $interface->{network} eq $local_net;
	my $crypto_map = { crypto => { type => $ipsec },
			   peers => \@peers,

			   # Any traffic from local_net needs to be encrypted.
			   crypto_rules => [ { action    => 'permit',
					       src       => $local_net,
					       dst       => $network_00,
					       src_range => $srv_ip,
					       srv       => $srv_ip
					     } ],
			   intf_rules => [],
			   rules => $hardware->{rules},
			 };
	$hardware->{rules} = [];
	$hardware->{crypto_maps} = [ $crypto_map ];
	my @intf_rules = @{$hardware->{intf_rules}};
	my @crypto_rules;
	my @real_rules;
	for my $rule (@{$hardware->{intf_rules}}) {
	    if (grep { $rule->{src} eq $_ } @{$hardware->{interfaces}} ) {
		push @real_rules, $rule;
	    } else {
		push @crypto_rules, $rule;
	    }
	}
	for my $peer (@peers) {
	    my $rules_ref = gen_tunnel_rules $peer, $interface, $ipsec;
	    push @real_rules, @$rules_ref;
	}
	$hardware->{intf_rules} = \@real_rules;
	$crypto_map->{intf_rules} = \@crypto_rules;
    }
}

sub print_crypto( $ ) {
    my ($router) = @_;

    if ($router->{auto_crypto_peer}) {
	prepare_auto_crypto $router;
    }

    # List of ipsec definitions used at current router.
    my @ipsec;

    # How often each ipsec definition is used.
    my %ipsec;

    # Find, which ipsec definitions are used at current router.
    for my $hardware (@{ $router->{hardware} }) {
        for my $crypto_map (@{ $hardware->{crypto_maps} }) {
            my $ipsec = $crypto_map->{crypto}->{type};
            unless ($ipsec{$ipsec}++) {
                push @ipsec, $ipsec;
            }
        }
    }

    # Return if no crypto is used at current router.
    return unless @ipsec;

    # List of isakmp definitions used at current router.
    my @isakmp;

    # How often each isakmp definition is used.
    my %isakmp;

    # Find, which isakmp definitions are used at current router.
    for my $ipsec (@ipsec) {
        my $isakmp = $ipsec->{key_exchange};
        unless ($isakmp{$isakmp}++) {
            push @isakmp, $isakmp;
        }
    }
    my $model       = $router->{model};
    my $crypto_type = $model->{crypto};
    unless ($crypto_type) {
        err_msg
          "Crypto not supported for $router->{name} of type $model->{name}";
        return;
    }
    return if $crypto_type eq 'ignore';
    my $comment_char = $model->{comment_char};
    print "$comment_char [ Crypto ]\n";
    $crypto_type =~ /^IOS|PIX$/ or internal_err;
    if (@ipsec > 1) {
        err_msg "Only one ipsec definition supported at $router->{name}\n ",
          "but these are used: ", join ', ', map $_->{name}, @ipsec;
        return;
    }
    my $ipsec = $ipsec[0];

    # Handle ISAKMP definition.
    my $isakmp   = $ipsec->{key_exchange};
    my $prefix   = $crypto_type eq 'IOS' ? 'crypto isakmp' : 'isakmp';

    my $identity = $isakmp->{identity};
    $identity = 'hostname' if $identity eq 'fqdn';
    if ($identity ne 'address' and $crypto_type eq 'IOS') {

	# Don't print default value for backend IOS.
	print "$prefix identity $identity\n";
    }
    if ($isakmp->{nat_traversal}) {
        print "$prefix nat-traversal\n";
    }
    if ($crypto_type eq 'IOS') {
        print "crypto isakmp policy 1\n";
        $prefix = '';
    }
    else {
        $prefix = "isakmp policy 1";
    }

    my $authentication = $isakmp->{authentication};
    $authentication =~ s/preshare/pre-share/;
    $authentication =~ s/rsasig/rsa-sig/;
    if ($authentication ne 'rsa-sig' and $crypto_type eq 'IOS') {

	# Don't print default value for backend IOS.
	print "$prefix authentication $authentication\n";
    }

    my $encryption = $isakmp->{encryption};
    print "$prefix encryption $encryption\n";
    my $hash = $isakmp->{hash};
    print "$prefix hash $hash\n";
    my $group = $isakmp->{group};
    print "$prefix group $group\n";

    my $lifetime = $isakmp->{lifetime};
    if ($lifetime != 86400 and $crypto_type eq 'IOS') {

	# Don't print default value for backend IOS.
	print "$prefix lifetime $lifetime\n";
    }

    # Handle IPSEC definition.
    my $transform = '';
    if (my $ah = $ipsec->{ah}) {
        if ($ah =~ /^(md5|sha)_hmac$/) {
            $transform .= "ah-$1-hmac ";
        }
        else {
            err_msg "Unsupported IPSec AH method for $crypto_type: $ah";
        }
    }
    if (not(my $esp = $ipsec->{esp_encryption})) {
        $transform .= 'esp-null ';
    }
    elsif ($esp =~ /^(aes|des|3des)$/) {
        $transform .= "esp-$1 ";
    }
    elsif ($esp =~ /^aes(192|256)$/) {
        $transform .= "esp-aes-$1 ";
    }
    else {
        err_msg "Unsupported IPSec ESP method for $crypto_type: $esp";
    }
    if (my $esp_ah = $ipsec->{esp_authentication}) {
        if ($esp_ah =~ /^(md5|sha)_hmac$/) {
            $transform .= "esp-$1-hmac";
        }
        else {
            err_msg
              "Unsupported IPSec ESP auth. method for $crypto_type: $esp_ah";
        }
    }

    # Syntax is identical for IOS and PIX.
    my $transform_name = 'Trans';
    print "crypto ipsec transform-set $transform_name $transform\n";

    my $ipsec_lifetime = $ipsec->{lifetime};
    if ($ipsec_lifetime != 3600 and $crypto_type eq 'IOS') {

	# Don't print default value for backend IOS.
	print "crypto ipsec security-association lifetime seconds $ipsec_lifetime",
    }

    my $pfs_group = $ipsec->{pfs_group};
    if ($pfs_group =~ /^(1|2)$/) {
        $pfs_group = "group$1";
    }
    else {
        err_msg "Unsupported pfs group for $crypto_type: $pfs_group";
    }

    for my $hardware (@{ $router->{hardware} }) {
	next if not @{$hardware->{crypto_maps}};
        my $name = $hardware->{name};

        # Name of crypto map.
        my $map_name = "crypto-$name";

        # Sequence number for parts of crypto map with different peers.
        my $seq_num = 0;

        # Crypto ACLs must obey NAT.
        my $nat_map = $hardware->{nat_map};
        for my $map (@{ $hardware->{crypto_maps} }) {
            $seq_num++;

            # Print crypto ACL. It controls which traffic needs to be encrypted.
            my $crypto_acl_name = "crypto-$name-$seq_num";
            my $prefix;
            if ($crypto_type eq 'IOS') {
                $prefix = '';
                print "ip access-list extended $crypto_acl_name\n";
            }
            elsif ($crypto_type eq 'PIX') {
                $prefix = "access-list $crypto_acl_name";
            }
            else {
                internal_err;
            }
            acl_line $map->{crypto_rules}, $nat_map, $prefix, $model;

            # Print filter ACL. It controls which traffic is allowed to leave
            # from crypto tunnel. This may be needed, if we don't fully trust
            # our peer.
            my $crypto_filter_name;
            if ($map->{intf_rules} || $map->{rules}) {
                $crypto_filter_name = "crypto-filter-$name-$seq_num";
                if ($crypto_type eq 'IOS') {
                    $prefix = '';
                    print "ip access-list extended $crypto_filter_name\n";
                }
                elsif ($crypto_type eq 'PIX') {
                    $prefix = "access-list $crypto_filter_name";
                }
                acl_line $map->{intf_rules}, $nat_map, $prefix, $model;
                acl_line $map->{rules},      $nat_map, $prefix, $model;
            }
            if ($crypto_type eq 'IOS') {
                $prefix = '';
                print "crypto map $map_name $seq_num ipsec-isakmp\n";
            }
            elsif ($crypto_type eq 'PIX') {
                $prefix = "crypto map $map_name $seq_num";
                print "$prefix ipsec-isakmp\n";
            }
            print "$prefix match address $crypto_acl_name\n";
            $crypto_filter_name
              and print "$prefix set ip access-group $crypto_filter_name in\n";

	    # Auto_crypto case allows multiple peers.
	    my @peers = $map->{peers} ? @{$map->{peers}} : ($map->{peer});
	    
	    for my $peer (@peers) {

		# Take first IP.
		# Unnumbered, negotiated and short interfaces have been rejected already.
		my $peer_ip = print_ip $peer->{ip}->[0];
		print "$prefix set peer $peer_ip\n";
	    }
            print "$prefix set transform-set $transform_name\n";
            $pfs_group and print "$prefix set pfs $pfs_group\n";
        }
        if ($crypto_type eq 'IOS') {
            print "interface $name\n";
            print " crypto map $map_name\n";
        }
        elsif ($crypto_type eq 'PIX') {
            print "crypto map $map_name interface $name\n";
            print "isakmp enable $name\n";
        }
    }
}

# Make output directory available.
sub check_output_dir( $ ) {
    my ($dir) = @_;
    unless (-e $dir) {
        mkdir $dir or die "Abort: can't create output directory $dir: $!\n";
    }
    -d $dir or die "Abort: $dir isn't a directory\n";
}

# Print generated code for each managed router.
sub print_code( $ ) {
    my ($dir) = @_;
    $dir and check_output_dir $dir;
    info "Printing code";
    for my $router (@managed_routers) {
        my $model        = $router->{model};
        my $comment_char = $model->{comment_char};
        my $name         = $router->{name};
        if ($dir) {
            my $file = $name;
            $file =~ s/^router://;
            $file = "$dir/$file";
            open STDOUT, ">$file" or die "Can't open $file: $!\n";
        }

	# Handle VPN3K separately;
	if ($model->{filter} eq 'VPN3K') {
	    print_vpn3k $router;
	    next;
	}

        print "$comment_char Generated by $program, version $version\n\n";
        print "$comment_char [ BEGIN $name ]\n";
        print "$comment_char [ Model = $model->{name} ]\n";
        print_routes $router;

	# ACLs are changed for auto_crypto peers, hence print_crypto first.
        print_crypto $router;
        print_acls $router;
        print_pix_static $router if $model->{has_interface_level};
        print "$comment_char [ END $name ]\n\n";

        if ($dir) {
            close STDOUT or die "Can't close $file: $!\n";
        }
    }
    $warn_pix_icmp_code && warn_pix_icmp;
}

####################################################################
# Argument processing
####################################################################
sub usage() {
    die <<'MSG'
Usage: $0 [options] {in-directory | in-file | -} [out-directory]
Compile all files from 'in-directory' or from a single 'in-file' or from STDIN.
Output is generated in 'out-directory' or sent to STDOUT.
Options:
-[no]comment_acls	Add comments to generated ACLs
-[no]comment_routes	Add comments to generated routes
-[no]auto_default_route	Use default route to minimize number of routing entries
-verbose		Show statistics and compilation steps
-quiet			Disable -verbose
-max_errors=<n>		Abort after that number of errors
-ignore_files=<regexp>	Ignore some files inside in-directory
			Default is '^(raw|CVS|RCS|\.#.*|.*~)$'
-strict_subnets=yes|no|warn	Subnets must be declared with 'subnet_of'
-allow_unused_groups=yes|no|warn
-check_unenforceable=yes|no|warn
MSG
      ;
}

sub check_tri( $ ) {
    my ($val) = @_;
    if ($val =~ /^(1|yes|true)$/i) {
        return 1;
    }
    elsif ($val =~ /^(0|no|false)$/i) {
        return 0;
    }
    elsif ($val =~ /^w(arn(ing)?)?$/i) {
        return 'warn';
    }
    else {
        die "Invalid value '$val', must be yes, no or warn\n";
    }
}

sub read_args() {
    GetOptions

      # Simple option, variable is set to 1.
      'verbose' => \$verbose,
      'quiet'   => sub { $verbose = 0 },

      # Negatable options; use as -xxx or -noxxx
      'comment_acls!'       => \$comment_acls,
      'comment_routes!'     => \$comment_routes,
      'auto_default_route!' => \$auto_default_route,

      # Option with integer value. Use as 'max_errors=4' or 'max_errors 4'.
      'max_errors=i' => \$max_errors,

      # Option with string value.
      'ignore_files=s' => \$ignore_files,

      # Function checks validity of string value.
      'strict_subnets=s' =>
      sub { my $value = $_[1]; $strict_subnets = check_tri $value },
      'allow_unused_groups=s' =>
      sub { my $value = $_[1]; $allow_unused_groups = check_tri $value },
      'check_unenforceable_rules=s' =>
      sub { my $value = $_[1]; $check_unenforceable = check_tri $value },
      or usage;
    my $main_file = shift @ARGV or usage;

    # $out_dir is used to store compilation results:
    # For each managed router with name X a corresponding file X
    # is created in $out_dir.
    # If $out_dir is missing, all code is printed to STDOUT.
    my $out_dir = shift @ARGV;

    # Strip trailing slash for nicer messages.
    $out_dir and $out_dir =~ s</$><>;

    # No further arguments allowed.
    not @ARGV or usage;
    return $main_file, $out_dir;
}

sub show_version() {
    info "$program, version $version";
}

1

#  LocalWords:  Netspoc Knutzen internet CVS IOS iproute iptables STDERR Perl
#  LocalWords:  netmask EOL ToDo IPSec unicast utf hk src dst ICMP IPs EIGRP
#  LocalWords:  OSPF VRRP HSRP Arnes loop's ISAKMP stateful ACLs negatable
#  LocalWords:  STDOUT
