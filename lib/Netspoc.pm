#!/usr/bin/perl
# Netspoc.pm
# A Network Security Policy Compiler
# http://netspoc.berlios.de
# (c) 2004 by Heinz Knutzen <heinzknutzen@users.berlios.de>
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

my $program = 'Network Security Policy Compiler';
my $version = (split ' ','$Id$ ')[2];

our @ISA = qw(Exporter);
our @EXPORT = qw(%routers %interfaces %networks %hosts %anys %everys
		 %groups %services %servicegroups 
		 %policies
		 @expanded_deny_rules
		 @expanded_any_rules
		 @expanded_rules
		 $error_counter $max_errors
		 $store_description
		 info
		 err_msg
		 read_ip
		 print_ip
		 show_version
		 read_args
		 read_file
		 read_file_or_dir
		 show_read_statistics 
		 order_services 
		 link_topology 
		 mark_disabled 
		 find_subnets 
		 setany 
		 expand_rules 
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
my $verbose = 1;
my $comment_acls = 0;
my $comment_routes = 0;
my $warn_unused_groups = 1;
# allow subnets only 
# if the enclosing network is marked as 'route_hint' or
# if the subnet is marked as 'subnet_of'
my $strict_subnets = 'warn';
# Optimize the number of routing entries per router:
# For each router find the hop, where the largest 
# number of routing entries points to 
# and replace them with a single default route.
# This is only applicable for internal networks 
# which have no default route to the internet.
my $auto_default_route = 1;
# ignore these names when reading directories:
# - CVS and RCS directories
# - CVS working files
# - directory raw for prolog & epilog files
# - Editor backup files: emacs: *~
my $ignore_files = qr/^CVS$|^RCS$|^\.#|^raw$|~$/;
# abort after this many errors
our $max_errors = 10;
# Store descriptions as an attribute of policies.
# This may be useful when called from a reporting tool.
our $store_description = 0;
# Print warning about ignored icmp code fields at PIX firewalls
my $warn_pix_icmp_code = 0;

####################################################################
# Attributes of supported router models
####################################################################
my %router_info =
(
 IOS => {
     name => 'IOS',
     stateless => 1,
     stateless_self => 1,
     routing => 'IOS',
     filter => 'IOS',
     comment_char => '!'
     },
 IOS_FW => {
     name => 'IOS_FW',
     stateless_self => 1,
     routing => 'IOS',
     filter => 'IOS',
     comment_char => '!'
     },
 PIX => {
     name => 'PIX',
     routing => 'PIX',
     filter => 'PIX',
     comment_char => '!',
     has_interface_level => 1,
     no_filter_icmp_code => 1
     },
 Linux => {
     name => 'Linux',
     routing => 'iproute',
     filter => 'iptables',
     comment_char => '#'
     }
 );

####################################################################
# Error Reporting
####################################################################

sub info ( @ ) {
    print STDERR @_, "\n" if $verbose;
}

sub warning ( @ ) {
    print STDERR "Warning: ", @_, "\n";
}

sub debug ( @ ) {
    print STDERR @_, "\n";
}

# Filename of current input file.
our $file;
# Eof status of current file.
our $eof;
sub context() {
    my $context;
    if($eof) {
	$context = 'at EOF';
    } else {
	my($pre, $post) =
	    m/([^\s,;={}]*[,;={}\s]*)\G([,;={}\s]*[^\s,;={}]*)/;
	$context = qq/near "$pre<--HERE-->$post"/;
    }
    return qq/ at line $. of $file, $context\n/;
}

sub at_line() {
    return qq/ at line $. of $file\n/;
}

our $error_counter = 0;

sub check_abort() {
    $error_counter++;
    if($error_counter == $max_errors) {
	die "Aborted after $error_counter errors\n";
    }elsif($error_counter > $max_errors) {
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
    my($package, $file, $line, $sub) = caller 1;
    die "Internal error in $sub: ", @_, "\n";
}

####################################################################
# Reading topology, Services, Groups, Rules
####################################################################

# $_ is used as input buffer, it holds the rest of the current input line
sub skip_space_and_comment() {
    # ignore trailing whitespace and comments
    while ( m'\G\s*([!#].*)?$ 'gcx and not $eof) {
	$_ = <FILE>;
	# <> becomes undefined at eof
	unless(defined $_) {
	    $_ = '';
	    $eof = 1;
	    return;
	}
	# Cut off trailing linefeed.
	chomp;
    }
    # Ignore leading whitespace.
    m/\G\s*/gc;
}

# Our input buffer $_ gets undefined, if we reached eof.
sub check_eof() {
    skip_space_and_comment;
    return $eof;
}

# Check for a string and skip if available.
sub check( $ ) {
    my $token = shift;
    skip_space_and_comment;
    return m/\G$token/gc;
}

# Skip a string.
sub skip ( $ ) {
    my $token = shift;
    check $token or syntax_err "Expected '$token'";
}

# Check, if an integer is available.
sub check_int() {
    skip_space_and_comment;
    if(m/\G(\d+)/gc) {
	return $1;
    } else {
	return undef;
    }
}

# Read IP address,
# internally it is stored as an integer
sub read_ip() {
    skip_space_and_comment;
    if(m/\G(\d+)\.(\d+)\.(\d+)\.(\d+)/gc) {
	if($1 > 255 or $2 > 255 or $3 > 255 or $4 > 255) {
	    error_atline "Invalid IP address";
	}
	return unpack 'N', pack 'C4',$1,$2,$3,$4;
    } else {
	syntax_err "Expected IP address";
    }
}

sub gen_ip( $$$$ ) {
    return unpack 'N', pack 'C4',@_;
}

# Convert IP address from internal integer representation to
# readable string.
sub print_ip( $ ) {
    my $ip = shift;
    return sprintf "%vd", pack 'N', $ip;
}

# Conversion from netmask to prefix and vice versa.
{
    # initialize private variables of this block
    my %mask2prefix;
    my %prefix2mask;
    for my $prefix (0 .. 32) {
	my $mask = 2**32 - 2**(32-$prefix);
	$mask2prefix{$mask} = $prefix;
	$prefix2mask{$prefix} = $mask;
    }

    # Convert a network mask to a prefix ranging from 0 to 32.
    sub mask2prefix( $ ) {
	my $mask = shift;
	if(defined(my $prefix = $mask2prefix{$mask})) {
	    return $prefix;
	}
	internal_err "Network mask ", print_ip $mask, " isn't a valid prefix";
    }
    sub prefix2mask( $ ) {
	my $prefix = shift;
	if(defined(my $mask = $prefix2mask{$prefix})) {
	    return $mask;
	}
	internal_err "Invalid prefix: $prefix";
    }
}
   
# Generate a list of IP strings from an ref of an array of integers.
sub print_ip_aref( $ ) {
    my $aref = shift;
    return map { print_ip $_; } @$aref;
}
		
# Check for xxx:xxx
sub check_typed_name() {
    use locale;		# now German umlauts are part of \w
    skip_space_and_comment;
    if(m/(\G\w+:[\w-]+)/gc) {
	return $1;
    } else {
	return undef;
    }
}

sub read_typed_name() {
    check_typed_name or
	syntax_err "Typed name expected";
}

# Read interface:xxx.xxx
sub read_interface_name() {
    use locale;		# now German umlauts are part of \w
    skip_space_and_comment;
    if(m/(\G\w+:[\w-]+\.[\w-]+)/gc) {
	return $1;
    } else {
	syntax_err "Interface name expected";
    }
}

# Check for xxx:xxx or xxx:[xxx] or interface:xxx.xxx
# or interface:xxx.[xxx] or interface:[xxx].[xxx]
sub check_typed_ext_name() {
    use locale;		# now German umlauts are part of \w
    skip_space_and_comment;
    if(m/\G(interface:[][\w-]+\.[][\w-]+|\w+:[][\w-]+)/gc) {
	return $1;
    } else {
	return undef;
    }
}

sub read_typed_ext_name() {
    check_typed_ext_name or
	syntax_err "Typed extended name expected";
}

sub read_identifier() {
    use locale;		# now German umlauts are part of \w
    skip_space_and_comment;
    if(m/(\G[\w-]+)/gc) {
	return $1;
    } else {
	syntax_err "Identifier expected";
    }
}

# Used for reading interface names.
sub read_string() {
    skip_space_and_comment;
    if(m/(\G[^;,=]+)/gc) {
	return $1;
    } else {
	syntax_err "String expected";
    }
}

sub read_description() {
    skip_space_and_comment;
    if(check 'description') {
	skip '=';
	# read up to end of line, but ignore ';' at eol
	m/\G(.*);?$/gc; 
	return $1; 
    }
}

# Check if one of the keywords 'permit' or 'deny' is available.
sub check_permit_deny() {
    skip_space_and_comment;
    if(m/\G(permit|deny)/gc) {
	return $1;
    } else {
	return undef;
    }
}

sub split_typed_name( $ ) {
    my($name) = @_;
    # Split at first colon, thus the name may contain further colons.
    split /:/, $name, 2;
}

sub check_flag( $ ) {
    my $token = shift;
    if(check $token) {
	skip ';';
	return 1;
    } else {
	return undef;
    }
}

sub read_assign($&) {
    my($token, $fun) = @_;
    skip $token;
    skip '=';
    my $val = &$fun;
    skip ';';
    return $val;
}

sub check_assign($&) {
    my($token, $fun) = @_;
    my $val;
    if(check $token) {
	skip '=';
	$val = &$fun;
	skip ';';
    }
    return $val;
}

sub read_list(&) {
    my($fun) = @_;
    my @vals;
    while(1) {
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
    my($token, $fun) = @_;
    skip $token;
    skip '=';
    &read_list($fun);
}

sub check_assign_list($&) {
    my($token, $fun) = @_;
    if(check $token) {
	skip '=';
	return &read_list($fun);
    }
    return ();
}

# Delete an element from an array reference.
# Return 1 if found, 0 otherwise.
sub aref_delete( $$ ) {
    my($elt, $aref) = @_;
    for(my $i = 0; $i < @$aref; $i++) {
	if($aref->[$i] eq $elt) {
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
    my $self = { @_ };
    return bless $self, $type;
}

# A hash with all defined nat names.
# Is used, to check, 
# - if all defined nat mappings are used and
# - if all used mappings are defined.
my %nat_definitions;

our %hosts;
sub read_host( $ ) {
    my $name = shift;
    my $host;
    skip '=';
    skip '{';
    my $token = read_identifier;
    if($token eq 'ip') {
	skip '=';
	my @ip = read_list \&read_ip;
	$host = new 'Host', name => "host:$name", ips => [ @ip ];
    } elsif($token eq 'range') {
	skip '=';
	my $ip1 = read_ip;
	skip '-';
	my $ip2 = read_ip;
	skip ';';
	$ip1 <= $ip2 or error_atline "Invalid IP range";
	$host = new('Host',
		    name => "host:$name",
		    range => [ $ip1, $ip2 ]);
    } else {
	syntax_err "Expected 'ip' or 'range'";
    }
    while(1) {
	last if check '}';
	my($type, $name) = split_typed_name read_typed_name;
	if($type eq 'nat') {
	    skip '=';
	    skip '{';
	    skip 'ip';
	    skip '=';
	    my $nat_ip = read_ip;
	    skip ';';
	    skip '}';
	    $host->{nat}->{$name} and
		error_atline "Duplicate NAT definition";
	    $host->{nat}->{$name} = $nat_ip;
	} else {
	    syntax_err "Expected NAT definition";
	}
    }
    if($host->{nat}) {
	if($host->{range}) {
	    # Look at print_pix_static before changing this.
	    error_atline "No NAT supported for host with IP range";
	} elsif(@{$host->{ips}} > 1) {
	    # Look at print_pix_static before changing this.
	    error_atline "No NAT supported for host with multiple IPs";
	}
    }
    if(my $old_host = $hosts{$name}) {
	error_atline "Redefining host:$name";
    }
    $hosts{$name} = $host;
    return $host;
}

our %networks;
sub read_network( $ ) {
    my $name = shift;
    my $network = new('Network',
		      name => "network:$name",
		      file => $file);
    skip '=';
    skip '{';
    $network->{route_hint} = check_flag 'route_hint';
    $network->{subnet_of} =
	check_assign 'subnet_of', \&read_typed_name;
    my $ip;
    my $mask;
    my $token = read_identifier;
    if($token eq 'ip') {
	skip '=';
	$ip = read_ip;
	skip ';';
	$mask = read_assign 'mask', \&read_ip;
	# Check if network ip matches mask.
	if(($ip & $mask) != $ip) {
	    error_atline "$network->{name}'s IP doesn't match its mask";
	    $ip &= $mask;
	}
	$network->{ip} = $ip;
	$network->{mask} = $mask;
    } elsif($token eq 'unnumbered') {
	$ip = $network->{ip} = 'unnumbered';
	skip ';';
    } else {
	syntax_err "Expected 'ip' or 'unnumbered'";
    }
    while(1) {
	last if check '}';
	my($type, $name) = split_typed_name read_typed_name;
	if($type eq 'host') {
	    my $host = read_host $name;
	    push @{$network->{hosts}}, $host;
	} elsif($type eq 'nat') {
	    skip '=';
	    skip '{';
	    skip 'ip';
	    skip '=';
	    my $nat_ip = read_ip;
	    skip ';';
	    my $nat_mask;
	    if(check 'mask') {
		skip '=';
		$nat_mask = read_ip;
		skip ';';
	    } else {
		# Inherit mask from network.
		$nat_mask = $mask;
	    }
	    my $dynamic;
	    if(check 'dynamic') {
		skip ';';
 		$dynamic = 1;
	    } else {
		$nat_mask == $mask or
		    error_atline "Non dynamic NAT mask must be ",
		    "equal to network mask";
	    }
	    skip '}';
	    # Check if ip matches mask.
	    if(($nat_ip & $nat_mask) != $nat_ip) {
		error_atline "$network->{name}'s NAT IP doesn't ",
		"match its mask";
		$nat_ip &= $nat_mask;
	    }
	    $network->{nat}->{$name} and
		error_atline "Duplicate NAT definition";
	    # NAT definition is of type network itself, for simpler code
	    # when processing NAT.
	    my $nat = new('Network',
			  name => $network->{name},
			  ip => $nat_ip, mask => $nat_mask );
	    # $name is the nat_tag which is used later to lookup 
	    # static translation of hosts inside a dynamically 
	    # translated network.
	    $nat->{dynamic} = $name if $dynamic;
	    $network->{nat}->{$name} = $nat;
	    $nat_definitions{$name} = 1;
	} else {
	    syntax_err "Expected NAT or host definition";
	}
    }
    # Check compatibility of host ip and network ip/mask.
    for my $host (@{$network->{hosts}}) {
	if($host->{ips}) {
	    for my $host_ip (@{$host->{ips}}) {
		if($ip != ($host_ip & $mask)) {
		    error_atline "Host IP doesn't match ",
		    "network IP/mask";
		}
	    }
	} elsif($host->{range}) {
	    my ($ip1, $ip2) = @{$host->{range}};
	    if($ip != ($ip1 & $mask) or
	       $ip != ($ip2 & $mask)) {
		error_atline "Host IP range doesn't match ",
		"network IP/mask";
	    }
	} else {
	    internal_err "$host->{name} hasn't ip or range";
	}
	# Check compatibility of host and network NAT.
	# A NAT definition for a single host is only allowed,
	# if the network has a dynamic NAT definition.
	if($host->{nat}) {
	    for my $nat_tag (keys %{$host->{nat}}) {
		my $nat_info;
		if($nat_info = $network->{nat}->{$nat_tag}
		   and $nat_info->{dynamic}) {
		    my $host_ip = $host->{nat}->{$nat_tag};
		    my($ip, $mask) = @{$nat_info}{'ip', 'mask'}; 
		    if($ip != ($host_ip & $mask)) {
			err_msg "nat:$nat_tag: $host->{name}'s IP ",
			"doesn't match $network->{name}'s IP/mask";
		    }
		} else {
		    err_msg "nat:$nat_tag not allowed for ",
		    "$host->{name} because $network->{name} ",
		    "doesn't have dynamic NAT definition";
		}
	    }
	}
 	# Link host with network.
 	$host->{network} = $network;
    }
    if($network->{nat} and $ip eq 'unnumbered') {
	err_msg "Unnumbered $network->{name} must not have ",
	"nat definition";
    }
    if(@{$network->{hosts}} and $ip eq 'unnumbered') {
	err_msg "Unnumbered $network->{name} must not have ",
	"host definitions";
    }
    if(@{$network->{hosts}} and $network->{route_hint}) {
	err_msg "$network->{name} must not have host definitions",
	"\n because it has attribute 'route_hint'";
    }
    if($networks{$name}) {
	error_atline "Redefining $network->{name}";
    }
    $networks{$name} = $network;
}


# Services below need not to be ordered using order_services
# since they are only used at code generation time.
my %routing_info =
(EIGRP => {srv => { name => 'auto_srv:EIGRP', proto => 88 },
	   mcast => [ new('Network',
			  name => "network:EIGRP_224.0.0.10",
			  ip => gen_ip(224,0,0,10),
			  mask => gen_ip(255,255,255,255)) ]},
 OSPF => {srv => { name => 'auto_srv:OSPF', proto => 89 },
	  mcast => [ new('Network',
			  name => "network:OSPF_224.0.0.5",
			  ip => gen_ip(224,0,0,5),
			  mask => gen_ip(255,255,255,255),
			  ),
		     new('Network',
			  name => "network:OSPF_224.0.0.6",
			  ip => gen_ip(224,0,0,6),
			  mask => gen_ip(255,255,255,255)) ]});
our %interfaces;
my @virtual_interfaces;
my @disabled_interfaces;
sub read_interface( $$ ) {
    my($router, $net) = @_;
    my $name = "$router.$net";
    my $interface = new('Interface', 
			name => "interface:$name",
			network => $net);
    unless(check '=') {
	# short form of interface definition
	skip ';';
	$interface->{ip} = 'short';
    } else {
	skip '{';
	my $token = read_identifier;
	if($token eq 'ip') {
	    skip '=';
	    my @ip = read_list \&read_ip;
	    $interface->{ip} = \@ip;
	} elsif($token eq 'unnumbered') {
	    $interface->{ip} = 'unnumbered';
	    skip ';';
	} else {
	    syntax_err "Expected 'ip' or 'unnumbered'";
	}
	while(1) {
	    last if check '}';
	    if(my $string = check_typed_name) {
		my($type, $name) = split_typed_name $string;
		if($type eq 'nat') {
		    skip '=';
		    skip '{';
		    skip 'ip';
		    skip '=';
		    my $nat_ip = read_ip;
		    skip ';';
		    skip '}';
		    $interface->{nat}->{$name} and
			error_atline "Duplicate NAT definition";
		    $interface->{nat}->{$name} = $nat_ip;
		} else {
		    syntax_err "Expected named attribute";
		}
	    } elsif(my $virtual =
		    check_assign 'virtual', \&read_ip) {
		# read virtual IP for VRRP / HSRP
		$interface->{ip} eq 'unnumbered' and
		    error_atline "No virtual IP supported for ",
		    "unnumbered interface";
		grep { $_ == $virtual } @{$interface->{ip}} and
		    error_atline
			"Virtual IP redefines standard IP";
		$interface->{virtual} and
		    error_atline "Duplicate virtual IP";
		$interface->{virtual} = $virtual;
		push @virtual_interfaces, $interface;
	    } elsif(my $nat =
		    check_assign 'nat', \&read_identifier) {
		# bind NAT to an interface
		$interface->{bind_nat} and
		    error_atline "Duplicate NAT binding";
		$interface->{bind_nat} = $nat;
	    } elsif(my $hardware =
		    check_assign 'hardware', \&read_string) {
		$interface->{hardware} and
		    error_atline
		    "Duplicate definition of hardware for interface";
		$interface->{hardware} = $hardware;
	    } elsif(my $protocol =
		    check_assign 'routing', \&read_string) {
		unless($routing_info{$protocol}) {
		    error_atline "Unknown routing protocol";
		}
		$interface->{routing} and
		    error_atline "Duplicate routing protocol";
		$interface->{routing} = $protocol;
	    } elsif(my @names =
		    check_assign_list('reroute_permit',
				       \&read_typed_name)) {
		my @networks;
		for my $name (@names) {
		    my($type, $net) = split_typed_name $name;
		    if($type eq 'network') {
			push @networks, $net;
		    } else {
			error_atline "Expected networks as values";
		    }
		}		
		$interface->{reroute_permit} = \@networks;
	    }
	    elsif(check_flag 'disabled') {
		push @disabled_interfaces, $interface;
	    } else {
		syntax_err "Expected some valid attribute";
	    }
	}
	if($interface->{nat}) {
	    if($interface->{ip} eq 'unnumbered') {
		error_atline "No NAT supported for unnumbered ",
		"interface";
	    } elsif(@{$interface->{ip}} > 1) {
		# look at print_pix_static before changing this
		error_atline "No NAT supported for interface ",
		"with multiple IPs";
	    }
	}
    }
    if($interfaces{$name}) {
	error_atline "Redefining $interface->{name}";
    }
    # assign interface to global hash of interfaces
    $interfaces{$name} = $interface;
    return $interface;
}

# PIX firewalls have a security level associated with each interface.
# We don't want to expand our syntax to state them explicitly,
# but instead we try to derive the level from the interface name.
# It is not necessary the find the exact level; what we need to know
# is the relation of the security levels to each other.
sub set_pix_interface_level( $ ) {
    my($router) = @_;
    for my $hardware (@{$router->{hardware}}) {
	my $hwname = $hardware->{name};
	my $level;
	if($hwname eq 'inside') {
	    $level = 100;
	} elsif($hwname eq 'outside') {
	    $level = 0;
	} else {
	    unless(($level) = ($hwname =~ /(\d+)$/) and
		   0 < $level and $level < 100) {
		err_msg "Can't derive PIX security level for ",
		"$hardware->{interfaces}->[0]->{name}";
	    }
	}
	$hardware->{level} = $level;
    }
}

our %routers;
sub read_router( $ ) {
    my $name = shift;
    my $router = new('Router',
		     name => "router:$name",
		     file => $file);
    skip '=';
    skip '{';
    while(1) {
	last if check '}';
	if(check 'managed') {
	    $router->{managed} and
		error_atline "Redefining 'managed' attribute";
	    my $managed;
	    if(check ';') {
		$managed = 'full';
	    } elsif(check '=') {
		my $value = read_identifier;
		if($value =~ /^full|secondary$/) {
		    $managed = $value;
		}
		else {
		    error_atline "Unknown managed device type";
		}
		check ';';
	    } else {
		syntax_err "Expected ';' or '='";
	    }
	    $router->{managed} = $managed;
	}
	elsif(my $model =
	      check_assign 'model', \&read_identifier) {
	    $router->{model} and
		error_atline "Redefining 'model' attribute";
	    my $info = $router_info{$model};
	    $info or error_atline "Unknown router model '$model'";
	    $router->{model} = $info;
	} elsif(check_flag('no_object_groups')) {
	    $router->{no_object_groups} = 1;
	} else {
	    my($type,$iname) = split_typed_name(read_typed_name);
	    $type eq 'interface' or
		syntax_err "Expected interface definition";
	    my $interface = read_interface $name, $iname;
	    push @{$router->{interfaces}}, $interface;
	    # Link router with interface.
	    $interface->{router} = $router;
	}
    }
    # Detailed interface processing for managed routers.
    if($router->{managed}) {
	unless($router->{model}) {
	    # Prevent further errors.
	    $router->{model} = {};
	    err_msg "Missing 'model' for managed router:$name";
	}
	# Create objects representing hardware interfaces.
	# All logical interfaces using the same hardware are linked
	# to the same hardware object.
	my %hardware;
	for my $interface (@{$router->{interfaces}}) {
	    if(my $hw_name = $interface->{hardware}) {
		my $hardware;
		if($hardware = $hardware{$hw_name}) {
		    no warnings "uninitialized";
		    # All logical interfaces of one hardware interface
		    # need to use the same nat binding,
		    # because NAT operates on hardware, not on logic.
		    $interface->{bind_nat} eq $hardware->{bind_nat} or
			err_msg "All interfaces of $router->{name} ",
			"must use identical NAT binding";
		} else {
		    $hardware = { name => $hw_name };
		    $hardware{$hw_name} = $hardware;
		    push @{$router->{hardware}}, $hardware;
		    if(my $nat = $interface->{bind_nat}) {
			$hardware->{bind_nat} = $nat;
		    }
		}
		$interface->{hardware} = $hardware;
		# Remember, which logical interfaces are bound
		# to which hardware.
		push @{$hardware->{interfaces}}, $interface;
	    } else {
		# Managed router must not have short interface.
		if($interface->{ip} eq 'short') {
		    err_msg "Short definition of $interface->{name} ",
		    "not allowed";
		} else {
		    # Interface of managed router needs to
		    # have a hardware name.
		    err_msg "Missing 'hardware' for $interface->{name}";
		}
	    }
	}
	if($router->{model}->{has_interface_level}) {
	    set_pix_interface_level $router;
	}
    }
    if($routers{$name}) {
	error_atline "Redefining $router->{name}";
    }
    $routers{$name} = $router;
}

our %anys;
sub read_any( $ ) {
    my $name = shift;
    skip '=';
    skip '{';
    my $link = read_assign 'link', \&read_typed_name;
    skip '}';
    my $any = new('Any', name => "any:$name", link => $link,
		  file => $file);
    if($anys{$name}) {
	error_atline "Redefining $any->{name}";
    }
    $anys{$name} = $any;
}

our %everys;
sub read_every( $ ) {
    my $name = shift;
    skip '=';
    skip '{';
    my $link = read_assign 'link', \&read_typed_name;
    skip '}';
    my $every = new('Every', name => "every:$name", link => $link,
		    file => $file);
    if(my $old_every = $everys{$name}) {
	error_atline "Redefining $every->{name}";
    }
    $everys{$name} = $every;
}

our %groups;
sub read_group( $ ) {
    my $name = shift;
    skip '=';
    my @objects = read_list_or_null \&read_typed_ext_name;
    my $group = new('Group',
		    name => "group:$name",
		    elements => \@objects,
		    file => $file);
    if(my $old_group = $groups{$name}) {
	error_atline "Redefining $group->{name}";
    }
    $groups{$name} = $group;
}

our %servicegroups;
sub read_servicegroup( $ ) {
   my $name = shift;
   skip '=';
   my @objects = read_list_or_null \&read_typed_name;
   my $srvgroup = new('Servicegroup',
		      name => "servicegroup:$name",
		      elements => \@objects,
		      file => $file);
   if(my $old_group = $servicegroups{$name}) {
       error_atline "Redefining servicegroup:$name";
   }
   $servicegroups{$name} = $srvgroup;
}

sub read_port_range() {
    if(defined (my $port1 = check_int)) {
	error_atline "Too large port number $port1" if $port1 > 65535;
	error_atline "Invalid port number '0'" if $port1 == 0;
	if(check '-') {
	    if(defined (my $port2 = check_int)) {
		error_atline "Too large port number $port2" if $port2 > 65535;
		error_atline "Invalid port number '0'" if $port2 == 0;
		error_atline "Invalid port range $port1-$port2" if $port1 > $port2;
		return $port1, $port2;
	    } else {
		syntax_err "Missing second port in port range";
	    }
	} else {
	    return $port1, $port1;
	}
    } else {
	return 1, 65535;
    }
}

sub read_port_ranges( $ ) {
    my($srv) = @_;
    my($from, $to) = read_port_range;
    if(check '->') {
	my($from2, $to2) = read_port_range;
	$srv->{ports} = [ $from, $to, $from2, $to2 ];
    } else {
	$srv->{ports} = [ 1, 65535, $from, $to ];
    }
}

sub read_icmp_type_code( $ ) {
    my($srv) = @_;
    if(defined (my $type = check_int)) {
	error_atline "Too large icmp type $type" if $type > 255;
	if(check '/') {
	    if(defined (my $code = check_int)) {
		error_atline "Too large icmp code $code" if $code > 255;
		$srv->{type} = $type;
		$srv->{code} = $code;
	    } else {
		syntax_err "Expected icmp code";
	    }
	} else {
	    $srv->{type} = $type;
	}
    } else {
	# No type and code given.
    }
}

sub read_proto_nr( $ ) {
    my($srv) = @_;
    if(defined (my $nr = check_int)) {
	error_atline "Too large protocol number $nr" if $nr > 255;
	error_atline "Invalid protocol number '0'" if $nr == 0;
	if($nr == 1) {
	    $srv->{proto} = 'icmp';
	    # No icmp type and code given.
	} elsif($nr == 4) {
	    $srv->{proto} = 'tcp';
	    $srv->{ports} = [ 1, 65535, 1, 65535 ];
	} elsif($nr == 17) {
	    $srv->{proto} = 'udp';
	    $srv->{ports} = [ 1, 65535, 1, 65535 ];
	} else {
	    $srv->{proto} = $nr;
	}
    } else {
	syntax_err "Expected protocol number";
    }
}

our %services;
sub read_service( $ ) {
    my $name = shift;
    my $srv = { name => "service:$name",
		file => $file };
    skip '=';
    if(check 'ip') {
	$srv->{proto} = 'ip';
    } elsif(check 'tcp') {
	$srv->{proto} = 'tcp';
	read_port_ranges($srv);
    } elsif(check 'udp') {
	$srv->{proto} = 'udp';
	read_port_ranges $srv;
    } elsif(check 'icmp') {
	$srv->{proto} = 'icmp';
	read_icmp_type_code $srv;
    } elsif(check 'proto') {
	read_proto_nr $srv;
    } else {
	my $name = read_string;
	error_atline "Unknown protocol $name in definition of service:$name";
    }
    skip ';';
    if(my $old_srv = $services{$name}) {
	error_atline "Redefining service:$name";
    }
    $services{$name} = $srv; 
}

our %policies;

sub read_user_or_typed_name_list( $ ) {
    my ($name) = @_;
    skip $name;
    skip '=';
    if(check 'user') {
	skip ';';
	return 'user';
    } else {
	return read_list \&read_typed_ext_name;
    }
}

sub read_policy( $ ) {
    my($name) = @_;
    skip '=';
    skip '{';
    my $policy = { name => "policy:$name",
		   rules => [],
		   file => $file
	       };
    my $description = read_description;
    $store_description and $policy->{description} = $description;
    my @user = read_assign_list 'user', \&read_typed_ext_name;
    $policy->{user} = \@user;
    while(1) {
	last if check '}';
	if(my $action = check_permit_deny) {
	    my $src = [ read_user_or_typed_name_list 'src' ];
	    my $dst = [ read_user_or_typed_name_list 'dst' ];
	    my $srv = [ read_assign_list 'srv', \&read_typed_name ];
	    if($src->[0] eq 'user') {
		$src = 'user';
	    }
	    if($dst->[0] eq 'user') {
		$dst = 'user';
	    }
	    if($src ne 'user' && $dst ne 'user') {
		err_msg "All rules of $policy->{name} must use keyword 'user'";
	    }
	    my $rule = { action => $action,
			 src => $src, dst => $dst, srv => $srv};
	    push @{$policy->{rules}}, $rule;
	} else {
	    syntax_err "Expected 'permit' or 'deny'";
	}
    }
    if($policies{$name}) {
	error_atline "Redefining policy:$name";
    }
    $policies{$name} = $policy; 
}

our %pathrestrictions;
sub read_pathrestriction( $ ) {
   my $name = shift;
   skip '=';
   my $description = read_description;
   my @names = read_list_or_null \&read_interface_name;
   my @interfaces;
   for my $name (@names) {
       my($type, $intf) = split_typed_name $name;
       if($type eq 'interface') {
	   push @interfaces, $intf;
       } else {
	   error_atline "Expected interfaces as values";
       }
   }		
   @names > 1 or
       error_atline "pathrestriction:$name must use more than one interface";
   my $restriction = new('Pathrestriction',
			 name => "pathrestriction:$name",
			 elements => \@interfaces,
			 file => $file);
   $store_description and $restriction->{description} = $description;
   if(my $old_restriction = $pathrestrictions{$name}) {
       error_atline "Redefining pathrestriction:$name";
   }
   $pathrestrictions{$name} = $restriction;
}

sub read_netspoc() {
    # Check for different definitions.
    if(my $string = check_typed_name) {
	my($type,$name) = split_typed_name $string;
	if($type eq 'router') {
	    read_router $name;
	} elsif ($type eq 'network') {
	    read_network $name;
	} elsif ($type eq 'any') {
	    read_any $name;
	} elsif ($type eq 'every') {
	    read_every $name;
	} elsif ($type eq 'group') {
	    read_group $name;
	} elsif ($type eq 'service') {
	    read_service $name;
	} elsif ($type eq 'servicegroup') {
	    read_servicegroup $name;
	} elsif ($type eq 'policy') {
	    read_policy $name;
	} elsif ($type eq 'pathrestriction') {
	    read_pathrestriction $name;
	} else {
	    syntax_err "Unknown global definition";
	}
    } elsif (check 'include') {
	my $file = read_string;
	read_data $file, \&read_netspoc;
    } else {
	syntax_err '';
    }
}

# reads input from file
sub read_file( $$ ) {	
    local $file = shift;
    my $read_syntax = shift;
    local $eof = 0;
    local *FILE;
    open FILE, $file or die "can't open $file: $!";
    # set input buffer to defined state
    # when called from 'include:' ignore rest of line
    $_ = '';
    while(not check_eof) {
	&$read_syntax;
    }
}

sub read_file_or_dir( $ );
sub read_file_or_dir( $ ) {
    my($path) = @_;
    if(-f $path) {
	read_file $path, \&read_netspoc;
    } elsif(-d $path) {
	local(*DIR);
	# Strip trailing slash for nicer file names in messages.
	$path =~ s</$><>;
	opendir DIR, $path or die "Can't opendir $path: $!";
	while(my $file = readdir DIR) {
	    next if $file eq '.' or $file eq '..';
	    next if $file =~ m/$ignore_files/;
	    $file = "$path/$file";
	    read_file_or_dir $file;
	}
    } else {
	die "Can't read path '$path'\n";
    }
}	
	
sub show_read_statistics() {
    my $n = keys %networks;
    my $h = keys %hosts;
    my $r = keys %routers;
    my $g = keys %groups;
    my $s = keys %services;
    my $sg = keys %servicegroups;
    my $p = keys %policies;
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
sub is_group( $ )        { ref($_[0]) eq 'Group'; }
sub is_servicegroup( $ ) { ref($_[0]) eq 'Servicegroup'; }
sub is_objectgroup( $ )  { ref($_[0]) eq 'Objectgroup'; }
sub is_chain( $ )        { ref($_[0]) eq 'Chain'; }

sub print_rule( $ ) {
    my($rule) = @_;
    my $extra = '';;
    $extra .= " $rule->{for_router}" if $rule->{for_router};
    $extra .= " stateless" if $rule->{stateless};
    if($rule->{orig_any}) { $rule = $rule->{orig_any}; }
    my $srv = exists $rule->{orig_srv} ? 'orig_srv' : 'srv';
    my $action = $rule->{action};
    $action = $action->{name} if is_chain $action;
    return $action .
	" src=$rule->{src}->{name}; dst=$rule->{dst}->{name}; " .
	"srv=$rule->{$srv}->{name};$extra";
}

##############################################################################
# Order services
##############################################################################
my %srv_hash;
sub prepare_srv_ordering( $ ) {
    my($srv) = @_;
    my $proto = $srv->{proto};
    my $main_srv;
    if($proto eq 'tcp' or $proto eq 'udp') {
	my $key = join ':', @{$srv->{ports}};
	$main_srv = $srv_hash{$proto}->{$key} or
	    $srv_hash{$proto}->{$key} = $srv;
    } elsif($proto eq 'icmp') {
	my $key = !defined $srv->{type} ? '' : (!defined $srv->{code} ? $srv->{type} :
					"$srv->{type}:$srv->{code}");
	$main_srv = $srv_hash{$proto}->{$key} or
	    $srv_hash{$proto}->{$key} = $srv;
    } elsif($proto eq 'ip') {
	$main_srv = $srv_hash{$proto} or
	    $srv_hash{$proto} = $srv;
    } else { # other protocol
	my $key = $proto;
	$main_srv = $srv_hash{proto}->{$key} or
		$srv_hash{proto}->{$key} = $srv;
    }
    if($main_srv) {
	# Found duplicate service definition.
	# Link $srv with $main_srv.
	# We link all duplicate services to the first service found.
	# This assures that we always reach the main service
	# from any duplicate service in one step via ->{main}
	# This is used later to substitute occurrences of
	# $srv with $main_srv
	$srv->{main} = $main_srv;
    }
}

sub order_icmp( $$ ) {
    my($hash, $up) = @_;
    # icmp any
    if(my $srv = $hash->{''}) {
	$srv->{up} = $up;
	$up = $srv;
    }
    for my $srv (values %$hash) {
	# 'icmp any' has been handled above
	next unless defined $srv->{type};
	if(defined $srv->{code}) {
	    $srv->{up} = ($hash->{$srv->{type}} or $up);
	} else {
	    $srv->{up} = $up;
	}
    }
}

sub order_proto( $$ ) {
    my($hash, $up) = @_;
    for my $srv (values %$hash) {
	$srv->{up} = $up;
    }
}

# Link each port range with the smallest port range which includes it.
# If no including range is found, link it with the next larger service.
sub order_ranges( $$ ) {
    my($range_href, $up) = @_;
    for my $srv1 (values %$range_href) {
	next if $srv1->{main};
	my @p1 = @{$srv1->{ports}};
	my $min_size_src = 65536;
	my $min_size_dst = 65536;
	$srv1->{up} = $up;
	for my $srv2 (values %$range_href) {
	    next if $srv1 eq $srv2;
	    next if $srv2->{main};
	    my @p2 = @{$srv2->{ports}};
	    if($p1[0] == $p2[0] and $p1[1] == $p2[1] and
	       $p1[2] == $p2[2] and $p1[3] == $p2[3]) {
		# Found duplicate service definition
		# Link $srv2 with $srv1
		# Since $srv1 is not linked via ->{main},
		# we never get chains of ->{main}
		$srv2->{main} = $srv1;
	    } elsif($p2[0] <= $p1[0] and $p1[1] <= $p2[1] and 
		    $p2[2] <= $p1[2] and $p1[3] <= $p2[3]) {
		# Found service definition with both ranges being larger
		my $size_src = $p2[1]-$p2[0];
		my $size_dst = $p2[3]-$p2[2];
		if($size_src <= $min_size_src and $size_dst < $min_size_dst or
		   $size_src < $min_size_src and $size_dst <= $min_size_dst) {
		    $min_size_src = $size_src;
		    $min_size_dst = $size_dst;
		    $srv1->{up} = $srv2;
		} elsif($size_src >= $min_size_src and
			$size_dst >= $min_size_dst) {
		    # both ranges are larger than a previously found range, 
		    # ignore this one
		} else {
		    # src range is larger and dst range is smaller or
		    # src range is smaller and dst range is larger
		    # ToDo: Implement this.
		    err_msg "Can't arrange $srv2->{name}\n",
		    " Please contact author";
		}
	    } elsif($p1[0] < $p2[0] and $p2[0] <= $p1[1] and $p1[1] < $p2[1] or
		    $p1[2] < $p2[2] and $p2[2] <= $p1[3] and $p1[3] < $p2[3] or
		    # 1111111
		    #    2222222
		    $p2[0] < $p1[0] and $p1[0] <= $p2[1] and $p2[1] < $p1[1] or
		    $p2[2] < $p1[2] and $p1[2] <= $p2[3] and $p2[3] < $p1[3]) {
		#    1111111
		# 2222222
		# ToDo: Implement this
		err_msg "Overlapping port ranges are not supported currently.\n",
		" Workaround: Split one of $srv1->{name}, $srv2->{name} manually";
	    }    
	}
    }
}

sub add_reverse_srv( $ ) {
    my($hash) = @_;
    for my $srv (values %$hash) {
	# swap src and dst ports
	my @ports =  @{$srv->{ports}}[2,3,0,1];
	my $key = join ':', @ports;
	unless($hash->{$key}) {
	    (my $name = $srv->{name}) =~ s/^service:/reverse:/;
	    $hash->{$key} =  { name => $name,
			       proto => $srv->{proto},
			       ports => [ @ports ] };
	}
    }
}

# We need service "ip" later for secondary rules.
my $srv_ip;
# We need service "tcp established" later for reverse rules.
my $srv_tcp_established = 
{ name => 'reverse:TCP_ANY',
  proto => 'tcp',
  ports => [ 1,65535, 1,65535 ],
  established => 1
  };

# Order services. We need this to simplify optimization.
# Additionally add
# - one TCP "established" service and 
# - reversed UDP services 
# for generating reverse rules later.
sub order_services() {
    info "Arranging services";
    for my $srv (values %services) {
	prepare_srv_ordering($srv);
    }
    unless($srv_hash{ip}) {
	my $name = 'auto_srv:ip';
	$srv_hash{ip} = { proto => 'ip', name => $name };
	$services{$name} = $srv_hash{ip};
    }
    my $up = $srv_ip = $srv_hash{ip};
    if(my $tcp = $srv_hash{tcp}->{'1:65535:1:65535'}) {
	$srv_tcp_established->{up} = $tcp;
    } else {
	$srv_tcp_established->{up} = $up;
    }
    add_reverse_srv($srv_hash{udp});
    order_ranges($srv_hash{tcp}, $up);
    order_ranges($srv_hash{udp}, $up);
    order_icmp($srv_hash{icmp}, $up) if $srv_hash{icmp};
    order_proto($srv_hash{proto}, $up) if $srv_hash{proto};

    # it doesn't hurt to set {depth} for services with {main} defined
    for my $srv ($srv_ip, $srv_tcp_established,
		 values %{$srv_hash{tcp}}, values %{$srv_hash{udp}},
		 values %{$srv_hash{icmp}}, values %{$srv_hash{proto}}) {
	my $depth = 0;
	my $up = $srv;
	while($up = $up->{up}) {
	    $depth++;
	}
	$srv->{depth} = $depth;
#	debug "$srv->{name} < $srv->{up}->{name}" if $srv->{up};
    }
}

####################################################################
# Link topology elements each with another
####################################################################

# link 'any' and 'every' objects with referenced objects
sub link_any_and_every() {
    for my $obj (values %anys, values %everys) {
	my($type, $name) = split_typed_name($obj->{link});
	if($type eq 'network') {
	    $obj->{link} = $networks{$name};
	} elsif($type eq 'router') {
	    if(my $router = $routers{$name}) {
		$router->{managed} and
		    err_msg "$obj->{name} must not be linked to",
		    "managed $router->{name}";
		# Take some network connected to this router.
		# Since this router is unmanged, all connected networks
		# will belong to the same security domain.
		$router->{interfaces} or
		    err_msg "$obj->{name} must not be linked to",
		    "$router->{name} without interfaces";
		$obj->{link} = $router->{interfaces}->[0]->{network};
	    }
	} else {
	    err_msg "$obj->{name} must not be linked to '$type:$name'";
	    $obj->{disabled} = 1;
	    next;
	}
	unless($obj->{link}) {
	    err_msg "Referencing undefined $type:$name from $obj->{name}";
	    $obj->{disabled} = 1;
	}
    }
}

# link interface with network in both directions
sub link_interface_with_net( $ ) {
    my($interface) = @_;
    my $net_name = $interface->{network};
    my $network = $networks{$net_name};
    unless($network) {
	err_msg "Referencing undefined network:$net_name ",
	    "from $interface->{name}";
	# prevent further errors
	push @disabled_interfaces, $interface;
	return;
    }
    $interface->{network} = $network;
    if($interface->{reroute_permit}) {
	for my $name (@{$interface->{reroute_permit}}) {
	    my $network = $networks{$name};
	    unless($network) {
		err_msg "Referencing undefined network:$name ",
		"from attribute 'reroute_permit' of $interface->{name}";
		# prevent further errors
		delete $interface->{reroute_permit};
		next;
	    }
	    $name = $network;
	}
    }
    my $ip = $interface->{ip};
    if($ip eq 'short') {
	# nothing to check: short interface may be linked to arbitrary network
    } elsif($ip eq 'unnumbered') {
	$network->{ip} eq 'unnumbered' or
	    err_msg "Unnumbered $interface->{name} must not be linked ",
	    "to $network->{name}";
    } else {
	# check compatibility of interface ip and network ip/mask
	my $network_ip = $network->{ip};
	my $mask = $network->{mask};
	for my $interface_ip (@$ip,
			      $interface->{virtual} ?
			      $interface->{virtual} : ()) {
	    if($network_ip eq 'unnumbered') {
		err_msg "$interface->{name} must not be linked ",
		"to unnumbered $network->{name}";
		next;
	    }
	    if($network_ip != ($interface_ip & $mask)) {
		err_msg "$interface->{name}'s IP doesn't match ",
		"$network->{name}'s IP/mask";
	    }
	    if($interface_ip == $network_ip) {
		err_msg "$interface->{name} has address of its network";
	    }
	    my $broadcast = $network_ip + ~$mask;
	    if($interface_ip == $broadcast) {
		err_msg "$interface->{name} has broadcast address";
	    }
	}
	# Check compatibility of interface and network NAT.
	# A NAT definition for a single interface is only allowed,
	# if the network has a dynamic NAT definition.
	if($interface->{nat}) {
	    for my $nat_tag (keys %{$interface->{nat}}) {
		my $nat_info;
		if($nat_info = $network->{nat}->{$nat_tag} and
		   $nat_info->{dynamic}) {
		    my $interface_ip = $interface->{nat}->{$nat_tag};
		    my($ip, $mask) = @{$nat_info}{'ip', 'mask'}; 
		    if($ip != ($interface_ip & $mask)) {
			err_msg "nat:$nat_tag: $interface->{name}'s IP ",
			"doesn't match $network->{name}'s IP/mask";
		    }
		} else {
		    err_msg "nat:$nat_tag not allowed for ",
		    "$interface->{name} because $network->{name} ",
		    "doesn't have a dynamic NAT definition";
		}
	    }
	}
    }
    push(@{$network->{interfaces}}, $interface);
}

sub link_pathrestrictions() {
    for my $restrict (values %pathrestrictions) {
	for my $name (@{$restrict->{elements}}) {
	    if(my $interface = $interfaces{$name}) {
		$interface->{router}->{managed} or
		    err_msg "Referencing unmanaged $interface->{name} ",
		    "from $restrict->{name}";
		# Multiple restrictions may be applied to a single 
		# interface.
		push @{$interface->{path_restrict}}, $restrict;
		# Substitute interface name by interface object.
		$name = $interface;
	    } else {
		err_msg "Referencing undefined interface:$name ", 
		"from $restrict->{name}";
	    }
	}
    }
}

sub link_topology() {
    for my $interface (values %interfaces) {
	link_interface_with_net($interface);
    }
    link_any_and_every;
    link_pathrestrictions;
    for my $network (values %networks) {
	if($network->{ip} eq 'unnumbered' and $network->{interfaces} and
	   @{$network->{interfaces}} > 2) {
	    err_msg "Unnumbered $network->{name} is connected to",
	    " more than two interfaces:";
	    for my $interface (@{$network->{interfaces}}) {
		print STDERR " $interface->{name}\n";
	    }
	}
	# 1. Check for duplicate interface addresses.
	# 2. Short interfaces must not be used, if a managed interface 
	#    with static routing exists in the same network.
	my %ip;
	my ($short_intf, $route_intf);
	for my $interface (@{$network->{interfaces}}) {
	    my $ips = $interface->{ip};
	    if($ips eq 'short') {
		$short_intf = $interface;
	    } else {
		if($interface->{router}->{managed} and
		   not $interface->{routing}) {
		    $route_intf = $interface;
		}
		unless($ips eq 'unnumbered') {
		    for my $ip (@$ips) {
			if(my $old_intf = $ip{$ip}) {
			    warning "Duplicate IP address for",
			    " $old_intf->{name} and $interface->{name}";
			}
			$ip{$ip} = $interface;
		    }
		}
	    }
	    if($short_intf and $route_intf) {
		err_msg "$short_intf->{name} must be defined in more detail,",
		" since there is\n",
		" a managed $route_intf->{name} with static routing enabled.";
	    }
	}
	for my $host (@{$network->{hosts}}) {
	    if(my $ips = $host->{ips}) {
		for my $ip (@$ips) {
		    if(my $old_intf = $ip{$ip}) {
			err_msg "Duplicate IP address for $old_intf->{name}",
			" and $host->{name}";
		    }
		}
	    } elsif(my $range = $host->{range}) {
		for(my $ip = $range->[0]; $ip <= $range->[1]; $ip++) {
		    if(my $old_intf = $ip{$ip}) {
			err_msg "Duplicate IP address for $old_intf->{name}",
			" and $host->{name}";
		    }
		}
	    }
	}
	if($network->{subnet_of}) {
	    my($type, $name) = split_typed_name($network->{subnet_of});
	    if($type eq 'network') {
		my $subnet = $networks{$name} or
		    err_msg "Referencing undefined network:$name ",
		    "from attribute 'subnet_of' of $network->{name}";
		$network->{subnet_of} = $subnet;
	    } else {
		err_msg "Attribute 'subnet_of' of $network->{name} ",
		"must not be linked to $type:$name";
	    }
	}
    }
}

####################################################################
# Mark all parts of the topology lying behind disabled interfaces.
# "Behind" is defined like this:
# Look from a router to its interfaces; 
# if an interface is marked as disabled, 
# recursively mark the whole part of the topology lying behind 
# this interface as disabled.
# Be cautious with loops:
# If an interface inside a loop is marked as disabled,
# this will mark the whole topology as disabled.
####################################################################

sub disable_behind( $ );
sub disable_behind( $ ) {
    my($in_interface) = @_;
    return if $in_interface->{disabled};
    $in_interface->{disabled} = 1;
    my $network = $in_interface->{network};
    $network->{disabled} = 1;
    for my $host (@{$network->{hosts}}) {
	$host->{disabled} = 1;
    }
    for my $interface (@{$network->{interfaces}}) {
	next if $interface eq $in_interface;
	next if $interface->{disabled};
	$interface->{disabled} = 1;
	my $router = $interface->{router};
	$router->{disabled} = 1;
	# a disabled router must not be managed
	if($router->{managed}) {
	    warning "Disabling managed $router->{name}";
	}
	for my $out_interface (@{$router->{interfaces}}) {
	    next if $out_interface eq $interface;
	    next if $out_interface->{disabled};
	    disable_behind $out_interface ;
	}
    }
}	

# Lists of network objects which are left over after disabling.
my @managed_routers;
my @routers;
my @networks;
my @all_anys;

sub mark_disabled() {
    for my $interface (@disabled_interfaces) {
	next if $interface->{router}->{disabled};
	disable_behind($interface);
	if($interface->{router}->{disabled}) {
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
	$obj->{disabled} = 1 if $obj->{link}->{disabled};
    }
    for my $obj (values %anys) {
	if($obj->{link}->{disabled}) {
	    $obj->{disabled} = 1;
	} else {
	    push @all_anys, $obj;
	}
    }
    for my $router (values %routers) {
	unless($router->{disabled}) {
	    push @routers, $router;
	    push @managed_routers, $router if $router->{managed};
	}
    }
    for my $network (values %networks) {
	unless($network->{disabled}) {
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

# Convert an IP range to a set of covering IP/mask pairs
sub split_ip_range( $$ ) {
    my($a, $b) = @_;
    # b is inclusive upper bound
    # change it to exclusive upper bound
    $b++;
    my $i = $a;
    my @result;
    while($i < $b) {
	my $j = $i;
	my $add = 1;
	# j even
	while(($j & 1) == 0) {
	    $j >>= 1; $add <<= 1;
	    if($i+$add > $b) {
		$add >>= 1;
		last;
	    }
	}
	my $mask = ~($add-1);
	push @result, [ $i, $mask ];
	$i += $add;
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
	for my $host (@{$network->{hosts}}) {
	    my $name = $host->{name};
	    my $nat = $host->{nat};
	    my @ip_mask;
	    if($host->{ips}) {
		@ip_mask = map [ $_, 0xffffffff ], @{$host->{ips}};
	    } elsif($host->{range}) {
		my($ip1, $ip2) = @{$host->{range}};
		@ip_mask = split_ip_range $ip1, $ip2;
	    } else {
		internal_err "unexpected host type";
	    }
	    for my $ip_mask (@ip_mask) {
		my($ip, $mask) = @$ip_mask;
		my $inv_prefix = 32 - mask2prefix $mask;
		if(my $other_subnet = $inv_prefix_aref[$inv_prefix]->{$ip}) {
		    my $nat2 = $other_subnet->{nat};
		    if($nat xor $nat2) {
			err_msg "Inconsistent NAT definition for",
			"$other_subnet->{name} and $host->{name}";
		    } elsif($nat and $nat2) {
			# Number of entries is equal.
			if(keys %$nat eq keys %$nat2) {
			    # Entries are equal.
			    for my $name (keys %$nat) {
				unless($nat2->{$name} and
				       $nat->{$name} eq $nat2->{$name}) {
				    err_msg "Inconsistent NAT definition for",
				    "$other_subnet->{name} and $host->{name}";
				    last;
				}
			    }
			} else {
			    err_msg "Inconsistent NAT definition for",
			    "$other_subnet->{name} and $host->{name}";
			}
		    }
		    push @{$host->{subnets}}, $other_subnet;
		} else {
		    my $subnet = new('Subnet',
				     name => $name,
				     network => $network,
				     ip => $ip, mask => $mask,
				     nat => $nat);
		    $inv_prefix_aref[$inv_prefix]->{$ip} = $subnet;
		    push @{$host->{subnets}}, $subnet;
		    push @{$network->{subnets}}, $subnet;
		}
	    }
	}
	# Find adjacent subnets which build a larger subnet.
	my $network_inv_prefix = 32 - mask2prefix $network->{mask};
	for(my $i = 0; $i < @inv_prefix_aref; $i++) {
	    if(my $ip2subnet = $inv_prefix_aref[$i]) {
		my $next = 2 ** $i;
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
		    # Only take the left part of two adjacent subnets.
		    if($ip % $modulo == 0) {
			my $next_ip = $ip + $next;
			# Find the right part.
			if(my $neighbor = $ip2subnet->{$next_ip}) {
			    $subnet->{neighbor} = $neighbor;
			    my $up_inv_prefix = $i + 1;
			    my $up;
			    if($up_inv_prefix >= $network_inv_prefix) {
				# Larger subnet is whole network.
				$up = $network;
			    } elsif($up_inv_prefix < @inv_prefix_aref and
				    $up = $inv_prefix_aref[$up_inv_prefix]->{$ip}) {
			    } else {
				(my $name = $subnet->{name}) =~
				    s/^.*:/auto_subnet:/;
				my $mask = prefix2mask(32 - $up_inv_prefix);
				$up = new('Subnet',
					  name => $name,
					  network => $network,
					  ip => $ip, mask => $mask);
				$inv_prefix_aref[$up_inv_prefix]->{$ip} = $up;
			    }
			    $subnet->{up} = $up;
			    $neighbor->{up} = $up;
			    # Don't search for enclosing subnet below.
			    next;
			}
		    }
		    # For neighbors, {up} has been set already.
		    next if $subnet->{up};
		    # Search for enclosing subnet.
		    for(my $j = $i + 1; $j < @inv_prefix_aref; $j++) {
			my $mask = prefix2mask(32 - $j);
			$ip &= $mask;
			if(my $up = $inv_prefix_aref[$j]->{$ip}) {
			    $subnet->{up} = $up;
			    last;
			}
		    }
		    # Use network, if no enclosing subnet found.
		    $subnet->{up} ||= $network;
		}
	    }
	}
    }
}

# Find adjacent subnets and substitute them by their enclosing subnet.
sub combine_subnets ( $ ) {
    my($aref) = @_;
    my %hash;
    for my $subnet (@$aref) {
	$hash{$subnet} = $subnet;
    }
    for my $subnet (@$aref) {
	my $neighbor;
	if($neighbor = $subnet->{neighbor} and $hash{$neighbor}) {
	    my $up = $subnet->{up};
	    unless($hash{$up}) {
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

my %name2object =
(
 host => \%hosts,
 network => \%networks,
 interface => \%interfaces,
 any => \%anys,
 every => \%everys,
 group => \%groups
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
	my @interfaces = grep({ not $_->{ip} eq 'unnumbered' }
			      @{$router->{interfaces}});
	if($router->{managed}) {
	    push @managed_interfaces, @interfaces;
	}
	push @all_interfaces, @interfaces;
	(my $name = $router->{name}) =~ s /^router://;
	$interfaces{"$name.[all]"} =
	    new('Group', name => "interface:$name.[all]",
		elements => \@interfaces, is_used => 1);	    
    }
    $interfaces{'[managed].[all]'} =
	new('Group', name => "interface:[managed].[all]",
	    elements => \@managed_interfaces, is_used => 1);
    $interfaces{'[all].[all]'} =
	new('Group', name => "interface:[all].[all]",
	    elements => \@all_interfaces, is_used => 1);
    $routers{'[managed]'} =
	new('Group', name => "router:[managed]",
	    elements => \@managed_routers, is_used => 1);
    $routers{'[all]'} =
	new('Group', name => "router:[all]",
	    elements => \@routers, is_used => 1);
    $anys{'[all]'} = 
	new('Group', name => "any:[all]",
	    elements => \@all_anys, is_used => 1);
    # String is expanded to a real 'any' object during expand_rules.
    $anys{'[local]'} = 	"any:[local]";
}

# Get a reference to an array of network object names and 
# return a reference to an array of network objects
sub expand_group1( $$ );
sub expand_group1( $$ ) {
    my($obref, $context) = @_;
    my @objects;
    for my $tname (@$obref) {
	my($type, $name) = split_typed_name($tname);
	my $object;
	unless($name2object{$type}) {
	    err_msg "Unknown type of '$tname' in $context";
	    next;
	}
	unless($object = $name2object{$type}->{$name} or
	       $type eq 'interface' and
	       $name =~ /^(.*)\.\[auto\]$/ and
	       $object = $routers{$1}) {
	    err_msg "Can't resolve reference to '$tname' in $context";
	    next;
	}
	# Split a group into its members.
	if(is_group $object) {
	    my $elements = $object->{elements};
	    # Check for recursive definitions.
	    if($elements eq 'recursive') {
		err_msg "Found recursion in definition of $context";
		$object->{elements} = $elements = [];
	    }
	    # detect, if group has already been converted
	    # from names to references
	    unless($object->{is_used}) {
		# mark group for detection of recursive group definitions
		$object->{elements} = 'recursive';
		$object->{is_used} = 1;
		$elements = expand_group1 $elements, $tname;
		# cache result for further references to the same group
		$object->{elements} = $elements;
	    }
	    push @objects, @$elements;
	} elsif(is_every $object) {
	    # expand an 'every' object to all networks in its security domain
	    # Attention: this doesn't include unnumbered networks
	    push @objects,  @{$object->{link}->{any}->{networks}}
	    unless $object->{disabled};
	} else {
	    push @objects, $object;
	}
    }
    for my $object (@objects) {
	# ignore "any:[local]"
	next unless ref $object;
	if($object->{disabled}) {
	    $object = undef;
	} elsif(is_network $object) {
	    if($object->{ip} eq 'unnumbered') {
		err_msg "Unnumbered $object->{name} must not be used in $context";
		$object = undef;
	    } elsif($object->{route_hint}) {
		err_msg "$object->{name} marked as 'route_hint' must not be used in $context";
		$object = undef;
	    }
	} elsif(is_interface $object) {
	    if($object->{ip} eq 'unnumbered') {
		err_msg "Unnumbered $object->{name} must not be used in $context";
		$object = undef;
	    } elsif($object->{ip} eq 'short') {
		err_msg "Short $object->{name} must not be used in $context";
		$object = undef;;
	    }
	}
    }
    return \@objects;
}

sub expand_group( $$$ ) {
    my($obref, $context, $convert_hosts) = @_;
    my $aref = expand_group1 $obref, $context;
    if($convert_hosts) {
	my @subnets;
	my @other;
	for my $obj (@$aref) {
	    next unless $obj;
	    if(is_host $obj) {
		push  @subnets, @{$obj->{subnets}};
	    } else {
		push @other, $obj;
	    }
	}
	push @other, @{combine_subnets \@subnets};
	return \@other;
    } else {
	return [ grep $_, @$aref ];
    }

}    

sub check_unused_groups() {
    return unless $warn_unused_groups;
    for my $group (values %groups, values %servicegroups) {
	unless($group->{is_used}) {
	    if(my $size = @{$group->{elements}}) {
		warning "unused $group->{name} with $size element(s)";
	    } else {
		warning "unused empty $group->{name}";
	    }
	}
    }
}

sub expand_services( $$ );
sub expand_services( $$ ) {
    my($aref, $context) = @_;
    my @services;
    for my $tname (@$aref) {
	my($type, $name) = split_typed_name($tname);
	if($type eq 'service') {
	    if(my $srv = $services{$name}) {
		push @services, $srv;
	    } else {
		err_msg "Can't resolve reference to '$tname' in $context";
		next;
	    }
	} elsif ($type eq 'servicegroup') {
            if(my $srvgroup = $servicegroups{$name}) {
		my $elements = $srvgroup->{elements};
		if($elements eq 'recursive') {
		    err_msg "Found recursion in definition of $context";
		    $srvgroup->{elements} = $elements = [];
		}
		# Check if it has already been converted
		# from names to references.
		elsif(not $srvgroup->{is_used}) {
		    # detect recursive definitions
		    $srvgroup->{elements} = 'recursive';
		    $srvgroup->{is_used} = 1;
		    $elements = expand_services $elements, $tname;
		    # Cache result for further references to the same group.
		    $srvgroup->{elements} = $elements;
		}
		push @services, @$elements;
	    } else {
	        err_msg "Can't resolve reference to '$tname' in $context";
		next;
	    }
	} else {
	    err_msg "Unknown type of '$type:$name' in $context";
	}
    }
    return \@services;
}

sub path_first_interfaces( $$ );

# array of expanded deny rules
our @expanded_deny_rules;
# array of expanded permit rules
our @expanded_rules;
# array of expanded any rules
our @expanded_any_rules;
# Hash for ordering all rules:
# $rule_tree{$action}->{$src}->{$dst}->{$srv} = $rule;
my %rule_tree;
my %reverse_rule_tree;
# Hash for converting a reference of an object back to this object.
my %ref2obj;

# Add rule to %rule_tree or %reverse_rule_tree for later optimization.
sub add_rule( $ ) {
    my ($rule) = @_;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    # A rule with an interface as destination may be marked as deleted
    # during global optimization. But in some case, code for this rule 
    # must be generated anyway. This happens, if
    # - it is an interface of a managed router and
    # - code is generated for exacty this router.
    # Mark such rules for easier handling.
    if(is_interface($dst) and $dst->{router}->{managed}) {
	$rule->{managed_intf} = 1;
    }
    my $rule_tree = $rule->{stateless} ? \%reverse_rule_tree : \%rule_tree;
    my $old_rule = $rule_tree->{$action}->{$src}->{$dst}->{$srv};
    if($old_rule) {
	# Found identical rule.
	$rule->{deleted} = $old_rule;
	return;
    } 
    $rule_tree->{$action}->{$src}->{$dst}->{$srv} = $rule;
}

sub expand_rules( ;$) {
    my($convert_hosts) = @_;
    convert_hosts if $convert_hosts;
    info "Expanding rules";
    # Prepare special groups.
    set_auto_groups;
    # Sort keys to make output deterministic.
    for my $name (sort keys %policies) {
	my $policy = $policies{$name};
	my $user = $policy->{user} = expand_group($policy->{user},
						  "user of $policy->{name}",
						  $convert_hosts);
	for my $p_rule (@{$policy->{rules}}) {
	    my $rule = {};
	    my $action = $rule->{action} = $p_rule->{action};
	    for my $where ('src', 'dst') {
		if($p_rule->{$where} eq 'user') {
		    $rule->{$where} = $user;
		} else {
		    $rule->{$where} = $p_rule->{$where} =
			expand_group($p_rule->{$where},
				     "$where of rule in $policy->{name}",
				     $convert_hosts);
		}
	    }
	    $rule->{srv} = expand_services($p_rule->{srv},
					   "rule in $policy->{name}");
	    # remember original policy
	    $rule->{policy} = $policy;
	    # ... and remember original rule
	    $rule->{p_rule} = $p_rule;

	    my $get_any_local = sub ( $ ) {
		my ($obj) = @_;
		if(is_interface $obj and $obj->{router}->{managed}) {
		    return $obj->{any};
		} else {
		    my $name = $obj eq 'any:[local]' ? $obj : $obj->{name};
		    err_msg "any:[local] must only be used in conjunction",
		    " with a managed interface\n",
		    " but not $name in $rule->{policy}->{name}";
		    $rule->{deleted} = 1;
		    # Continue with a valid value to prevent further errors.
		    return $obj;
		}
	    };
	    my $get_auto_interface = sub ( $$ ) {
		my($src, $dst) = @_;
		my @result;
		for my $interface (path_first_interfaces $src, $dst) {
		    if($interface->{ip} =~ /^unnumbered|short$/) {
			err_msg "'$interface->{ip}' $interface->{name}",
			" (from .[auto])\n",
			" must not be used in rule";
		    } else {
			push @result, $interface;
		    }
		}
		return @result;
	    };
	    for my $src (@{$rule->{src}}) {
		for my $dst (@{$rule->{dst}}) {

		    my @src = is_router $src ?
			$get_auto_interface->($src, $dst) : ($src);
		    my @dst = is_router $dst ?
			$get_auto_interface->($dst, $src) : ($dst);
		    for my $src (@src) {
			# Prevent modification of original array.
			my $src = $src;	
			$ref2obj{$src} = $src;
			for my $dst (@dst) {
			    my $dst = $dst; # prevent ...
			    if($src eq 'any:[local]') {
				$src = $get_any_local->($dst);
				$ref2obj{$src} = $src;
			    }
			    if($dst eq 'any:[local]') {
				$dst = $get_any_local->($src);
			    }
			    $ref2obj{$dst} = $dst;
			    for my $srv (@{$rule->{srv}}) {
				my $expanded_rule = { action => $action,
						      src => $src,
						      dst => $dst,
						      srv => $srv,
						      # Remember original rule.
						      rule => $rule
						      };
				# If $srv is duplicate of an identical service,
				# use the main service, but remember
				# the original one for debugging / comments.
				if(my $main_srv = $srv->{main}) {
				    $expanded_rule->{srv} = $main_srv;
				    $expanded_rule->{orig_srv} = $srv;
				}
				if($action eq 'deny') {
				    push(@expanded_deny_rules, $expanded_rule);
				} elsif(is_any($src) or is_any($dst)) {
				    push(@expanded_any_rules, $expanded_rule);
				} else {
				    push(@expanded_rules, $expanded_rule);
				}
				add_rule $expanded_rule;
			    }
			}
		    }
		}
	    }
	}
    }
    if($verbose) {
	my $nd = 0+@expanded_deny_rules;
	my $n  = 0+@expanded_rules;
	my $na = 0+@expanded_any_rules;
	info " deny $nd, permit: $n, permit any: $na";
    }
}

##############################################################################
# Distribute NAT bindings from interfaces to affected networks
##############################################################################

# Mapping: Network -> address
# NAT Domain: an area of our topology (a set of networks)
# where the NAT mapping is identical at each network.

# Find and mark NAT domains.
# A nat domain is an area of connected networks
# which has a set of interfaces as border.
sub set_natdomain( $$$ );
sub set_natdomain( $$$ ) {
    my($network, $domain, $in_interface) = @_;
    if($network->{nat_domain}) {
	# Found a loop inside a NAT domain.
	return;
    }
    $network->{nat_domain} = $domain;
    push(@{$domain->{networks}}, $network);
    my $nat_map = $domain->{nat_map};
    for my $interface (@{$network->{interfaces}}) {
	# Ignore interface where we reached this network.
	next if $interface eq $in_interface;
	my $router = $interface->{router};
	my $managed = $router->{managed};
	my $nat_tag = $interface->{bind_nat};
	for my $out_interface (@{$router->{interfaces}}) {
	    no warnings "uninitialized";
	    if($out_interface->{bind_nat} eq $nat_tag) {
		# $nat_map will be collected at nat domains, but is needed at
		# logical and hardware interfaces of managed routers.
		if($managed) {
#		    debug "$domain->{name}: $out_interface->{name}";
		    $out_interface->{nat_map} =
			$out_interface->{hardware}->{nat_map} = $nat_map;
		}
		$out_interface->{nat_domain} = $domain;
		# Don't process interface where we reached this router.
		next if $out_interface eq $interface;
		# Current nat domain continues behind this interface.
		set_natdomain $out_interface->{network}, $domain,
		$out_interface;
	    } else {
		# New nat domain behind this interface.
		# Remember outgoing nat_tag; needed in distribute_nat1 below.
		push @{$domain->{connect}->{$nat_tag}}, $out_interface;
	    }
		
	}

    }
}

sub distribute_nat1( $$$ );
sub distribute_nat1( $$$ ) {
    my($domain, $nat, $depth) = @_;
#    debug "nat:$nat depth $depth at $domain->{name}";
    if($domain->{active_path}) {
#	debug "nat:$nat loop";
	# Found a loop
	return;
    }
    return if $domain->{nat_info}->[$depth]->{$nat};
    if(my $nat_info = $domain->{nat_info}) {
	my $max_depth = @$nat_info;
	for(my $i = 0; $i < $max_depth; $i++) {
	    if($nat_info->[$i]->{$nat}) {
		# Found an alternate border of current NAT domain
		# There is another NAT binding on the path which
		# might overlap some translations of current NAT
		err_msg "Inconsistent multiple occurrences of nat:$nat";
		return;
	    }
	}
    }
    # Use a hash to prevent duplicate entries.
    $domain->{nat_info}->[$depth]->{$nat} = $nat;
    # Loop detection
    $domain->{active_path} = 1;
    my $connect = $domain->{connect};
    for my $nat_tag (keys %$connect) {
	# Found another border of current nat domain.
	next if $nat_tag and $nat_tag eq $nat;
	for my $interface (@{$connect->{$nat_tag}}) {
	    my $depth = $depth;
	    if($interface->{bind_nat}) { 
		$depth++;
		if($interface->{bind_nat} eq $nat) {
		    err_msg "Found NAT loop for nat:$nat at $interface->{name}";
		    next;
		}
	    }
#	    debug "$interface->{name}";
	    distribute_nat1 $interface->{nat_domain}, $nat, $depth;
	}
    }
    delete $domain->{active_path};
}
 
my @all_natdomains;

sub distribute_nat_info() {
    info "Distributing NAT";
    my %nat_tag2networks;
    # Find nat domains.
    # Build mapping from nat tags to networks. 
    for my $network (@networks) {
	if(my $href = $network->{nat}) {
	    for my $nat_tag (keys %$href) {
		push @{$nat_tag2networks{$nat_tag}}, $network;
	    }
	}
	next if $network->{nat_domain};
	(my $name = $network->{name}) =~ s/^network:/nat_domain:/;
#	debug "$name";
	my $domain = new('nat_domain',
			 name => $name,
			 networks => [],
			 nat_map => {});
	push @all_natdomains, $domain;
	set_natdomain $network, $domain, 0;
    }
    # Distribute nat info to nat domains.
    for my $router (@routers) {
	for my $interface (@{$router->{interfaces}}) {
	    my $nat_tag = $interface->{bind_nat} or next;
	    if($nat_definitions{$nat_tag}) {
		distribute_nat1 $interface->{nat_domain}, $nat_tag, 0;
		$nat_definitions{$nat_tag} = 'used';
	    } else {
		warning "Ignoring undefined nat:$nat_tag",
		"bound to $interface->{name}";
	    }
	}
    }
    # Summarize nat info to nat mapping.
    for my $domain (@all_natdomains) {
	# Network to address mapping (only for networks with NAT).
	my $nat_map = $domain->{nat_map};
	my $nat_info = $domain->{nat_info};
#	debug "$domain->{name}";
	next unless $nat_info;
	# Reuse memory.
	delete $domain->{nat_info};
	for my $href (@$nat_info) {
	    for my $nat_tag (values %$href) {
		for my $network (@{$nat_tag2networks{$nat_tag}}) {
		    next if $nat_map->{$network};
		    $nat_map->{$network} = $network->{nat}->{$nat_tag};
#		    debug " Map: $network->{name} -> ",
#		    print_ip $nat_map->{$network}->{ip};
		}
	    }
	}
	# Reuse memory.
	delete $domain->{managed_interfaces};
	for my $network (@{$domain->{networks}}) {
	    if(my $href = $nat_map->{$network}) {
		my $name = "nat:$href->{tag}";
		err_msg "$network->{name} is translated by $name,\n",
		" but it lies inside the translation domain of $name.\n",
		" Probably $name was bound to wrong interface.";
	    }
	}
	# Reuse memory.
	delete $domain->{networks};
    }
    for my $name (keys %nat_definitions) {
	warning "nat:$name is defined, but not used" 
	    unless $nat_definitions{$name} eq 'used';
    }
}

####################################################################
# Find subnetworks
# Mark each network with the smallest network enclosing it.
# Mark each network which encloses some other network.
####################################################################
sub find_subnets() {
    info "Finding subnets";
    for my $domain (@all_natdomains) {
#	debug "$domain->{name}";
	my $nat_map = $domain->{nat_map};
	my %mask_ip_hash;
	for my $network (@networks) {
	    next if $network->{ip} eq 'unnumbered';
	    my $nat_network = $nat_map->{$network} || $network;
	    my ($ip, $mask) = @{$nat_network}{'ip', 'mask'};
	    if(my $old_net = $mask_ip_hash{$mask}->{$ip}) {
		err_msg 
		    "$network->{name} and $old_net->{name}",
		    "have identical ip/mask";
	    } else {
		$mask_ip_hash{$mask}->{$ip} = $network;
	    }
	}
	# go from smaller to larger networks
	for my $mask (reverse sort keys %mask_ip_hash) {
	    # Network 0.0.0.0/0.0.0.0 can't be subnet.
	    last if $mask == 0;
	    for my $ip (keys %{$mask_ip_hash{$mask}}) {
		my $m = $mask;
		my $i = $ip;
		while($m) {
		    $m <<= 1;
		    $i &= $m;
		    if($mask_ip_hash{$m}->{$i}) {
			my $bignet = $mask_ip_hash{$m}->{$i};
			my $subnet = $mask_ip_hash{$mask}->{$ip};
			# Mark subnet relation. 
			# This may differ for different NAT domains.
			$subnet->{is_in}->{$nat_map} = $bignet;
			if($strict_subnets and
			   not($bignet->{route_hint} or
			       $subnet->{subnet_of} and
			       $subnet->{subnet_of} eq $bignet)) {
			    my $msg =
				"$subnet->{name} is subnet of $bignet->{name}\n" .
				" if desired, either declare attribute 'subnet_of'" .
				" or attribute 'route_hint'";
			    if($strict_subnets eq 'warn') {
				warning $msg;
			    } else {
				err_msg $msg;
			    }
			}
			# We only need to find the smallest enclosing network.
			last;
		    }
		}
	    }
	}
	# We must not set an arbitrary default route 
	# if a network 0.0.0.0/0 exists.
	if($auto_default_route && $mask_ip_hash{0}->{0}) {
	    err_msg "\$auto_default_route must not be activated,",
	    " because $mask_ip_hash{0}->{0}->{name} has IP address 0.0.0.0";
	    $auto_default_route = 0;
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
# 'any' object
####################################################################

# Forward declaration.
sub setany_network( $$$ );

sub setany_network( $$$ ) {
    my($network, $any, $in_interface) = @_;
    if($network->{any}) {
	# Found a loop inside a security domain.
	return;
    }
    $network->{any} = $any;
    # Add network to the corresponding 'any' object,
    # to have all networks of a security domain available.
    # Unnumbered networks are left out here because
    # they aren't a valid src or dst.
    # But we need them later in get_path for security domains
    # consisting solely of unnumbered networks.
    if($network->{ip} eq 'unnumbered') {
	push(@{$any->{unnumbered}}, $network);
    } else {
	push(@{$any->{networks}}, $network);
    }
    for my $interface (@{$network->{interfaces}}) {
	# Ignore interface where we reached this network.
	next if $interface eq $in_interface;
	my $router = $interface->{router};
	if($router->{managed}) {
	    $interface->{any} = $any;
	    push @{$any->{interfaces}}, $interface;
	} else {
	    for my $out_interface (@{$router->{interfaces}}) {
		# Ignore interface where we reached this router.
		next if $out_interface eq $interface;
		setany_network $out_interface->{network}, $any, $out_interface;
	    }
	}
    }
}

sub setany() {
    for my $any (@all_anys) {
	$any->{networks} = [];
	my $network = $any->{link};
	if(my $old_any = $network->{any}) {
	    err_msg
		"More than one 'any' object defined in a security domain:\n",
		" $old_any->{name} and $any->{name}";
	}
	is_network $network or
	    internal_err "unexpected object $network->{name}";
	setany_network $network, $any, 0;
	# Make results deterministic.
	@{$any->{networks}} =
	    sort { $a->{ip} <=> $b->{ip} } @{$any->{networks}};
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
	@{$any->{networks}} =
	    sort { $a->{ip} <=> $b->{ip} } @{$any->{networks}};
    }
}
	
####################################################################
# Set paths for efficient topology traversal
####################################################################

# collect all networks and routers lying inside a cyclic graph
my @loop_objects;

sub setpath_obj( $$$ );
sub setpath_obj( $$$ ) {
    my($obj, $to_net1, $distance) = @_;
#    debug("-- $distance: $obj->{name} --> $to_net1->{name}");
    # $obj: a managed router or a network
    # $to_net1: interface of $obj; go this direction to reach net1
    # $distance: distance to net1
    # return value used in different manners:
    # (1) a flag, indicating that the current path is part of a loop
    # (2) that obj, which is starting point of the loop (as seen from net1)
    if($obj->{active_path}) {
	# Found a loop
	return $obj;
    }
    # mark current path for loop detection
    $obj->{active_path} = 1;
    $obj->{distance} = $distance;

    my $loop_start;
    my $loop_distance;
    my $get_next = is_router $obj ? 'network' : 'router';
    for my $interface (@{$obj->{interfaces}}) {
	# ignore interface where we reached this obj
	next if $interface eq $to_net1;
	# ignore interface which is the other entry of a loop 
	# which is already marked
	next if $interface->{in_loop};
	my $next = $interface->{$get_next};
	if(my $loop = setpath_obj $next, $interface, $distance+1) {
	    # path is part of a loop
	    if(!$loop_start or $loop->{distance} < $loop_distance) {
		$loop_start = $loop;
		$loop_distance = $loop->{distance};
	    }
	    $interface->{in_loop} = 1;
	} else {
	    # continue marking loop-less path
	    $interface->{main} = $obj;
	}
    }
    delete $obj->{active_path};
    if($loop_start) {
	# Mark every node of a cyclic graph with the graph's starting point
	# or the starting point of a subgraph
	$obj->{loop} = $loop_start;
	push @loop_objects, $obj;
#	debug "Loop($obj->{distance}): $obj->{name} -> $loop_start->{name}";
	unless($obj eq $loop_start) {
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
    @networks or die "Topology seems to be empty";
    my $net1 = $networks[0];

    # Starting with net1, do a traversal of the whole topology
    # to find a path from every network and router to net1.
    # Second  parameter $net1 is used as placeholder for a not existing
    # starting interface.
    setpath_obj $net1, $net1, 2;

    # Check if all networks are connected with net1.
    for my $network (@networks) {
	next if $network eq $net1;
	$network->{main} or $network->{loop} or
	    err_msg "Found unconnected $network->{name}";
    }
    
    # Propagate loop starting point into all sub-loops.
    for my $obj (@loop_objects) {
	my $loop = $obj->{loop};
	my $next = $loop->{loop};
	if($next ne  $loop) {
	    $loop = $next;
	    while(1) {
		$next = $loop->{loop};
		if($loop eq $next) { last; }
		else { $loop = $next; }
	    }
#	    debug "adjusting $obj->{name} loop to $loop->{name}";
	    $obj->{loop} = $loop;
	}
#	debug "adjusting $obj->{name} distance to $loop->{distance}";
	$obj->{distance} = $loop->{distance};
    }
    # Data isn't needed any more.
    @loop_objects = undef;

    # Check consistency of virtual interfaces:
    # Interfaces with identical virtual IP must 
    # be connected to the same network and 
    # must lie inside the same loop.
    my %same_ip;
    for my $interface (@virtual_interfaces) {
	my $ip = $interface->{virtual};
	push @{$same_ip{$ip}}, $interface;
    }
    for my $aref (values %same_ip) {
        my($i1, @rest) = @$aref;
        if(@rest) {
            my $network1 = $i1->{network};
            my $loop1 = $i1->{router}->{loop};
            for my $i2 (@rest) {
                $network1 eq $i2->{network} or
                    err_msg "Virtual IP: $i1->{name} and $i2->{name} ",
                    "are connected to different networks";
                $loop1 and $i2->{router}->{loop} and
                    $loop1 eq $i2->{router}->{loop} or
                    err_msg "Virtual IP: $i1->{name} and $i2->{name} ",
                    "are part of different cyclic subgraphs";
            } 
        } else {
            warning "Virtual IP: Missing second interface for $i1->{name}";
        } 
    }
    
    # Check that interfaces with pathrestriction are located inside 
    # of cyclic graphs
    for my $restrict (values %pathrestrictions) {
	for my $interface (@{$restrict->{elements}}) {
	    next if $interface->{disabled};
	    $interface->{in_loop} or
		err_msg "$interface->{name} of $restrict->{name}\n",
		" isn't located inside cyclic graph";
	}
    }
}

####################################################################
# Efficient path traversal.
####################################################################

sub get_networks ( $ ) {
    my($obj) = @_;
    my $type = ref $obj;
    if($type eq 'Network') {
	return $obj;
    } elsif($type eq 'Subnet' or $type eq 'Interface') {
	return $obj->{network};
    } elsif($type eq 'Any') {
	return @{$obj->{networks}};
    } else {
	internal_err "unexpected $obj->{name}";
    }
}

sub get_path( $ ) {
    my($obj) = @_;
    my $type = ref $obj;
    if($type eq 'Network') {
	return $obj;
    } elsif($type eq 'Subnet') {
	return $obj->{network};
    } elsif($type eq 'Interface') {
	return $obj->{router};
    } elsif($type eq 'Any') {
	# Take one random network of this security domain.
	return
	    $obj->{networks} ? $obj->{networks}->[0] : $obj->{unnumbered}->[0];
    } elsif($type eq 'Router') {
	# This is only used, when called from path_first_interfaces or
	# from find_active_routes_and_statics.
	return $obj;
    } elsif($type eq 'Host') {
	# This is only used, if Netspoc.pm is called from Arnes report.pl.
	return $obj->{network};
    } else {
	internal_err "unexpected $obj->{name}";
    }
}

# Converts hash key of reference back to reference.
my %key2obj;

sub loop_path_mark1( $$$$$ );
sub loop_path_mark1( $$$$$ ) {
    my($obj, $in_intf, $from, $to, $collect) = @_;
    # Check for second occurrence of path restriction.
    for my $restrict (@{$in_intf->{path_restrict}}) {
	if($restrict->{active_path}) {
#	    debug " effective $restrict->{name} at $in_intf->{name}";
	    return 0;
	}
    }
    # Found a path to $to.
    if($obj eq $to) {
	# Mark interface where we leave the loop.
	push @{$to->{loop_leave}->{$from}}, $in_intf;
#	debug " leave: $in_intf->{name} -> $to->{name}";
	return 1;
    }
    # Don't walk loops.
    return 0 if $obj->{active_path};
    # Mark current path for loop detection.
    $obj->{active_path} = 1;
    # Mark first occurrence of path restriction.
    for my $restrict (@{$in_intf->{path_restrict}}) {
#	debug " enabled $restrict->{name} at $in_intf->{name}";
	$restrict->{active_path} = 1;
    }
    my $get_next = is_router $obj ? 'network' : 'router';
    my $success = 0;
    # Fill hash for restoring reference from hash key.
    $key2obj{$in_intf} = $in_intf;
    for my $interface (@{$obj->{interfaces}}) {
        next unless $interface->{in_loop};
        next if $interface eq $in_intf;
        my $next = $interface->{$get_next};
	if(loop_path_mark1 $next, $interface, $from, $to, $collect) {
	    # Found a valid path from $next to $to
	    $key2obj{$interface} = $interface;
	    $collect->{$in_intf}->{$interface} = is_router $obj;
#	    debug " loop: $in_intf->{name} -> $interface->{name}";
            $success = 1;
        }
    }
    delete $obj->{active_path};
    for my $restrict (@{$in_intf->{path_restrict}}) {
#	debug " disabled $restrict->{name} at $in_intf->{name}";
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
    my($from, $to, $from_in, $to_out, $dst) = @_;
#   debug "loop_path_mark: $from->{name} -> $to->{name}";
    # loop has been entered at this interface before, or path starts at this object
    return if $from_in->{path}->{$dst};
    $from_in->{path}->{$dst} = $to_out;
    # Loop is only passed by.
    # This test is required although there is a similar test in path_mark.
    return if $from eq $to;	
    $from_in->{loop_entry}->{$dst} = $from;
    $from->{loop_exit}->{$dst} = $to;
    # Path from $from to $to inside cyclic graph has been marked already.
    return if $from->{path_tuples}->{$to};
    # Use this anonymous hash for collecting paths as tuples of interfaces.
    my $collect = {};
    $from->{path_tuples}->{$to} = $collect;
    # Mark current path for loop detection.
    $from->{active_path} = 1;
    my $get_next = is_router $from ? 'network' : 'router';
    my $success = 0;
    for my $interface (@{$from->{interfaces}}) {
        next unless $interface->{in_loop};
        my $next = $interface->{$get_next};
        if(loop_path_mark1 $next, $interface, $from, $to, $collect) {
	    $success = 1;
	    push @{$from->{loop_enter}->{$to}}, $interface;
#	    debug " enter: $from->{name} -> $interface->{name}";
        }
    }
    delete $from->{active_path};
    $success or err_msg "No valid path from $from->{name} to $to->{name}\n",
    " Too many path restrictions?";
}

# Mark path from src to dst.
# src and dst are either a router or a network.
# At each interface on the path from src to dst,
# we place a reference to the next interface on the path to dst.
# This reference is found at a key which is the reference to dst.
# Additionally we attach this information to the src object.
sub path_mark( $$ ) {
    my ($src, $dst) = @_;
    my $from = $src;
    my $to = $dst;
    my $from_in = $from;
    my $to_out = undef;
    my $from_loop = $from->{loop};
    my $to_loop = $to->{loop};
#    debug "path_mark $from->{name} --> $to->{name}";
    while(1) {
	$from and $to or internal_err;
	# paths meet outside a loop or at the edge of a loop
	if($from eq $to) {
#	    debug " $from_in->{name} -> ".($to_out?$to_out->{name}:'');
	    $from_in->{path}->{$dst} = $to_out;
	    return;
	}
	# paths meet inside a loop	
	if($from_loop and $to_loop and $from_loop eq $to_loop) {
	    loop_path_mark($from, $to, $from_in, $to_out, $dst);
	    return;
	}
	$from->{distance} and $to->{distance} or internal_err;
	if($from->{distance} >= $to->{distance}) {
	    # mark has already been set for a sub-path
	    return if $from_in->{path}->{$dst};
	    my $from_out;
	    if($from_loop) {
		# $from_loop contains object which is loop's exit
		$from_out = $from_loop->{main};
		loop_path_mark($from, $from_loop, $from_in, $from_out, $dst);
	    } else {
		$from_out = $from->{main};
	    }
#	    debug " $from_in->{name} -> ".($from_out?$from_out->{name}:'');
	    $from_in->{path}->{$dst} = $from_out;
	    $from_in = $from_out;
	    $from = $from_out->{main};
	    $from_loop = $from->{loop};
	} else {
	    my $to_in;
	    if($to_loop) {
		$to_in = $to_loop->{main};
		loop_path_mark($to_loop, $to, $to_in, $to_out, $dst);
	    } else {
		$to_in = $to->{main};
	    }
#	    debug " $to_in->{name} -> ".($to_out?$to_out->{name}:'');
	    $to_in->{path}->{$dst} = $to_out;
	    $to_out = $to_in;
	    $to = $to_in->{main};
	    $to_loop = $to->{loop};
	}
    }
}

# Walk paths inside cyclic graph
sub loop_path_walk( $$$$$$$$ ) {
    my($in, $out, $loop_entry, $loop_exit, $dst_intf,
       $call_at_router, $rule, $fun) = @_;
#    my $info = "loop_path_walk: ";
#    $info .= "$in->{name}->" if $in;
#    $info .= "$loop_entry->{name}->$loop_exit->{name}";
#    $info .= "->$out->{name}" if $out;
#    debug $info;
    # Handle special case: If
    # - $dst is interface,
    # - $loop_entry is a network and
    # - $dst is located inside this network,
    # then don't walk all paths of current loop,
    # but walk directly to $dst.
    if($dst_intf and $loop_entry eq $dst_intf->{network}) {
	if($call_at_router) {
	    &$fun($rule, $dst_intf, undef);
	} else {
	    &$fun($rule, $in, $dst_intf);
	}
	return;
    }	
    # Process entry of cyclic graph
    if(is_router($loop_entry) eq $call_at_router) {
#	debug " loop_enter";
	for my $out_intf (@{$loop_entry->{loop_enter}->{$loop_exit}}) {
	    &$fun($rule, $in, $out_intf);
	}
    }
    # Process paths inside cyclic graph
    my $tuples = $loop_entry->{path_tuples}->{$loop_exit};
#    debug " loop_tuples";
    for my $in_intf_ref (keys %$tuples) {
	my $in_intf = $key2obj{$in_intf_ref};
	my $hash = $tuples->{$in_intf_ref};
	for my $out_intf_ref (keys %$hash) {
	    my $out_intf = $key2obj{$out_intf_ref};
	    my $at_router = $hash->{$out_intf_ref};
	    &$fun($rule, $in_intf, $out_intf) if $at_router eq $call_at_router;
	}
    }
    # Process paths at exit of cyclic graph
    if(is_router($loop_exit) eq $call_at_router) {
#	debug " loop_leave";
	for my $in_intf (@{$loop_exit->{loop_leave}->{$loop_entry}}) {
	    &$fun($rule, $in_intf, $out);
	}
    }
}    

sub path_info ( $$ ) {
    my ($in_intf, $out_intf) = @_;
    my $in_name = $in_intf?$in_intf->{name}:'-';
    my $out_name = $out_intf?$out_intf->{name}:'-';
    debug " Walk: $in_name, $out_name";
}
    
# Apply a function to a rule at every router or network
# on the path from src to dst of the rule.
# $where tells, where the function gets called: at 'Router' or 'Network'.
sub path_walk( $$;$ ) {
    my ($rule, $fun, $where) = @_;
    internal_err "undefined rule" unless $rule;
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $from = get_path $src;
    my $to =  get_path $dst;
#    debug print_rule $rule;
#    debug(" start: $from->{name}, $to->{name}" . ($where?", at $where":''));
#    my $fun2 = $fun;
#    $fun = sub ( $$$ ) { 
#	my($rule, $in, $out) = @_;
#	path_info $in, $out;
#	&$fun2($rule, $in, $out);
#    };
    unless($from and $to) {
	internal_err print_rule $rule;
    }
    if($from eq $to) {
	# Don't process rule again later
	$rule->{deleted} = $rule;
	return;
    }
    path_mark($from, $to) unless $from->{path}->{$to};
    # Special handling needed if $dst is an interface inside a loop.
    my $dst_intf; $dst_intf = $dst if is_interface $dst and $to->{loop};
    my $in = undef;
    my $out;
    my $at_router = not($where && $where eq 'Network');
    my $call_it = (is_network($from) xor $at_router);
    # Path starts inside a cyclic graph.
    if($from->{loop_exit} and my $loop_exit = $from->{loop_exit}->{$to}) {
	my $loop_out = $from->{path}->{$to};
	loop_path_walk $in, $loop_out, $from, $loop_exit, $dst_intf,
	$at_router, $rule, $fun;
	unless($loop_out) {
#	    debug "exit: path_walk: dst in loop";
	    return;
	}
	# Continue behind loop.
	$in = $loop_out;
	$call_it = not(is_network($loop_exit) xor $at_router);
	$out = $in->{path}->{$to};
    } else {
	$out = $from->{path}->{$to};
    }
    while(1) {
	&$fun($rule, $in, $out) if $call_it;
	# End of path has been reached.
	if(not defined $out) {
#	    debug "exit: path_walk: reached dst";
	    return;
	}
	$call_it = ! $call_it;
	$in = $out;
	if($in->{loop_entry} and my $loop_entry = $in->{loop_entry}->{$to}) {
	    my $loop_exit = $loop_entry->{loop_exit}->{$to};
	    my $loop_out = $in->{path}->{$to};
	    loop_path_walk $in, $loop_out, $loop_entry, $loop_exit, $dst_intf,
	    $at_router, $rule, $fun;
	    # Path terminates inside cyclic graph.
	    unless($loop_out) {
#	    debug "exit: path_walk: dst in loop";
		return;
	    }
	    $in = $loop_out;
	    $call_it = not (is_network($loop_exit) xor $at_router);
	}
	$out = $in->{path}->{$to};
    }
}

sub path_first_interfaces( $$ ) {
    my ($src, $dst) = @_;
    my $from = get_path($src);
    my $to = get_path($dst);
    if($from eq $to) {
	return $dst;
    }
    path_mark($from, $to) unless $from->{path}->{$to};
    if(is_interface $dst and $dst->{network} eq $from) {
#	debug "$from->{name}.[auto] = $dst->{name}";
	return $dst;
    } 
    elsif(my $exit = $from->{loop_exit}->{$to}) {
#	debug "$from->{name}.[auto] = ".join ',', map {$_->{name}} @{$from->{loop_enter}->{$exit}};
	return @{$from->{loop_enter}->{$exit}};
    } else {
#	debug "$from->{name}.[auto] = $from->{path}->{$to}->{name}";
	return ($from->{path}->{$to});
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
#            all security domains lying directly behind all routers on the
#            path from src to any:X
##############################################################################

sub get_any( $ ) {
    my($obj) = @_;
    my $type = ref $obj;
    if($type eq 'Network') {
	return $obj->{any};
    } elsif($type eq 'Subnet') {
	return $obj->{network}->{any};
    } elsif($type eq 'Interface') {
	if($obj->{router}->{managed}) {
	    return $obj->{router};
	} else {
	    return $obj->{network}->{any};
	}
    } elsif($type eq 'Any') {
	return $obj;
    } else {
	internal_err "unexpected $obj->{name}";
    }
}

{
    # Prevent multiple error messages about missing 'any' rules;
    my %missing_any;

    sub err_missing_any ( $$$$ ) {
	my($rule, $any, $where, $router) = @_;
	return if $missing_any{$any};
	$missing_any{$any} = $any;
	my $policy = $rule->{rule}->{policy}->{name};
	$rule = print_rule $rule;
	$router = $router->{name};
	err_msg  "Missing 'any' rule.\n", 
	" $rule\n",
	" of $policy\n",
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
    my $dst = $rule->{dst};
    if($out_any eq $dst) {
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
    if($router->{model}->{stateless}) {
	my $proto = $rule->{srv}->{proto};
	if($proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip') {
	    # Find security domains at all interfaces except the in_intf.
	    for my $intf (@{$router->{interfaces}}) {
		next if $intf eq $in_intf;
		# Nothing to be checked for the interface which is connected
		# directly to the destination 'any' object.
		next if $intf eq $out_intf;
		my $any = $intf->{any};
		unless($rule_tree{$rule->{action}}->
		       {$any}->{$dst}->{$rule->{srv}}) {
		    err_missing_any $rule, $any, 'src', $router;
		}
	    }
	}
    }	    
    my $dst_any = get_any $dst;
    # Security domain of dst is directly connected with current router.
    # Hence there can't be any missing rules.
    return if $out_any eq $dst_any;
    unless($rule_tree{$rule->{action}}->
	   {$out_any}->{$dst}->{$rule->{srv}}) {
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

    my $in_any = $in_intf->{any};
    my $src = $rule->{src};
    my $srv = $rule->{srv};
    my $src_any = get_any $src;

    # Find security domains at all interfaces except the in_intf.
    for my $intf (@{$router->{interfaces}}) {
	# Nothing to be checked for the interface which is connected
	# directly to the destination 'any' object.
	next if $intf eq $out_intf;
	my $any = $intf->{any};
	# Nothing to be checked if src is directly attached to current router.
	next if $any eq $src_any;
	unless($rule_tree{$rule->{action}}->
	       {$src}->{$any}->{$srv}) {
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
# hence it doesn`t hurt if the rules at r1 are a bit too relaxed,
# i.e. r1 would permit dst to any, but should only permit dst to any1.
# Hence we can skip check_any_dst_rule for this situation.
# (Case b isn't implemented currently.)
# 

sub check_any_rules() {
    info "Checking rules with 'any' objects";
    for my $rule (@expanded_any_rules) {
	next if $rule->{deleted};
	next if $rule->{stateless};
	if(is_any($rule->{src})) {
	    path_walk($rule, \&check_any_src_rule);
	}
	if(is_any($rule->{dst})) {
	    path_walk($rule, \&check_any_dst_rule);
	}
    }
}

##############################################################################
# Generate reverse rules for stateless packet filters:
# For each rule with protocol tcp, udp or ip we need a reverse rule
# with swapped src, dst and src-port, dst-port.
# For rules with a tcp service, the reverse rule gets a tcp service
# without ports checking but with checking for 'established` flag.
##############################################################################

sub gen_reverse_rules1 ( $ ) {
    my($rule_aref) = @_;
    my @extra_rules;
    for my $rule (@$rule_aref) {
	if($rule->{deleted}) {
	    my $src = $rule->{src};
	    # If source is a managed interface,
	    # reversed will get attribute managed_intf.
	    unless(is_interface($src) and $src->{router}->{managed}) {
		next;
	    }
	}
	my $srv = $rule->{srv};
	my $proto = $srv->{proto};
	next unless $proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip';
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
		if(not $in_intf) {
		    if($model->{stateless_self}) {
			$has_stateless_router = 1;
			# Jump out of path_walk.
			no warnings "exiting";
			last PATH_WALK;
		    }
		}
		elsif($model->{stateless}) {
		    $has_stateless_router = 1;
		    # Jump out of path_walk.
		    no warnings "exiting";
		    last PATH_WALK;
		}
	    };
	    path_walk($rule, $mark_reverse_rule);
	}
	if($has_stateless_router) {
	    my $new_srv;
	    if($proto eq 'tcp') {
		$new_srv = $srv_tcp_established;
	    } elsif($proto eq 'udp') {
		# Swap src and dst ports.
		my @ports =  @{$srv->{ports}}[2,3,0,1];
		my $key1 = $proto;
		my $key2 = join ':', @ports;
		$new_srv = $srv_hash{$key1}->{$key2} or
			internal_err "no reverse $srv->{name} found";
	    } elsif($proto eq 'ip') {
		$new_srv = $srv;
	    } else {
		internal_err;
	    }
	    my $new_rule = { 
		action => $rule->{action},
		src => $rule->{dst},
		dst => $rule->{src},
		srv => $new_srv,
		# This rule must only be applied to stateless routers.
		stateless => 1,
		orig_rule => $rule};
	    $new_rule->{any_are_neighbors} = 1 if $rule->{any_are_neighbors};
	    add_rule $new_rule;
	    # Don't push to @$rule_aref while we are iterating over it.
	    push @extra_rules, $new_rule;
	}
    }
    push @$rule_aref, @extra_rules;
}

sub gen_reverse_rules() {
    info "Generating reverse rules for stateless routers";
    gen_reverse_rules1 \@expanded_deny_rules;
    gen_reverse_rules1 \@expanded_rules;
    gen_reverse_rules1 \@expanded_any_rules;
}

##############################################################################
# Mark rules for secondary filters.
# At secondary packet filters, packets are only checked for its 
# src and dst networks, if there is a full packet filter on the path from
# src to dst, were the original rule is checked.
##############################################################################

sub mark_secondary_rules() {
    info "Marking rules for secondary optimization";

    # Mark only normal rules for optimization.
    # We can't change a deny rule from e.g. tcp to ip.
    # We can't change 'any' rules, because path is unknown.
  RULE:
    for my $rule (@expanded_rules) {
	next if $rule->{deleted} and
	    (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
	my $mark_secondary_rule = sub( $$$ ) {
	    my ($rule, $in_intf, $out_intf) = @_;
	    my $router = ($in_intf || $out_intf)->{router};
	    return unless $router->{managed};
	    if($router->{managed} eq 'full') {
		# Optimization should only take place for IP addresses
		# which are really filtered by a full packet filter. 
		# ToDo: Think about virtual interfaces sitting
		# all on the same hardware.
		# Source or destination of rule is an interface of current router.
		# Hence, this router doesn't count as a full packet filter.
		return if not $in_intf and $rule->{src} eq $out_intf;
		return if not $out_intf and $rule->{dst} eq $in_intf;
		# A full filter inside a loop doesn't count, because there might
		# be another path without a full packet filter.
		# But a full packet filter at loop entry or exit is sufficient.
		# ToDo: this could be analyzed in more detail
		return if $in_intf->{in_loop} and $out_intf->{in_loop};
		$rule->{has_full_filter} = 1;
		# Jump out of path_walk.
		no warnings "exiting";
		next RULE;
	    }
	};
	path_walk($rule, $mark_secondary_rule);
    }
}

##############################################################################
# Optimize expanded rules by deleting identical rules and 
# rules which are overlapped by a more general rule
##############################################################################

sub optimize_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;
    for my $action (keys %$chg_hash) {
	my $chg_hash = $chg_hash->{$action};
	while(1) {
	    if(my $cmp_hash = $cmp_hash->{$action}) {
		my($cmp_hash, $chg_hash) = ($cmp_hash, $chg_hash);
		for my $src_ref (keys %$chg_hash) {
		    my $chg_hash = $chg_hash->{$src_ref};
		    my $src = $ref2obj{$src_ref};
		    while(1) {
			if(my $cmp_hash = $cmp_hash->{$src}) {
			    for my $dst_ref (keys %$chg_hash) {
				my $chg_hash = $chg_hash->{$dst_ref};
				my $dst = $ref2obj{$dst_ref};
				while(1) {
				    if(my $cmp_hash = $cmp_hash->{$dst}) {
					for my $chg_rule (values %$chg_hash) {
					    next if $chg_rule->{deleted};
					    my $srv = $chg_rule->{srv};
					    while(1) {
						if(my $cmp_rule = $cmp_hash->{$srv}) {
						    unless($cmp_rule eq $chg_rule) {
							$chg_rule->{deleted} = $cmp_rule;
							last;
						    }
						}
						$srv = $srv->{up} or last;
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
	    if($action eq 'permit') {
		$action = 'deny';
	    } else {	# deny
		last;
	    }
	}
    }
}

sub optimize() {
    info "Global optimization";
    # Prepare data structures
    for my $network (@networks) {
	next if $network->{up};
	$network->{up} = $network->{any};
	for my $interface (@{$network->{interfaces}}) {
	    $interface->{up} = $network;
	}
    }
    optimize_rules \%rule_tree, \%rule_tree;
    if($verbose) {
	my($n, $nd, $na) = (0,0,0);
	for my $rule (@expanded_deny_rules) { $nd++ if $rule->{deleted}	}
	for my $rule (@expanded_rules) { $n++ if $rule->{deleted} }
	for my $rule (@expanded_any_rules) {
	    $na++ if $rule->{deleted};
	}
	info "Deleted redundant rules: $nd deny, $n permit, $na permit any";
    }
}

# normal rules > reverse rules
sub optimize_reverse_rules() {
    info "Optimization of reverse rules";
    optimize_rules \%reverse_rule_tree, \%reverse_rule_tree;
    optimize_rules \%rule_tree, \%reverse_rule_tree;
}

####################################################################
# Routing
# Add a component 'route' to each interface.
# It holds an array of networks reachable
# using this interface as next hop
####################################################################

# This function is called for each network on the path from src to dst
# of $rule.
# If $in_intf and $out_intf are both defined, packets traverse this network.
# If $in_intf is not defined, there is no interface where we could add
# routing entries.
# If $out_intf is not defined, dst is this network;
# hence dst is directly connected to $in_intf
sub collect_route( $$$ ) {
    my($rule, $in_intf, $out_intf) = @_;
#    debug "collect: $rule->{src}->{name} -> $rule->{dst}->{name}";
#    my $info = '';
#    $info .= $in_intf->{name} if $in_intf;
#    $info .= ' -> ';
#    $info .= $out_intf->{name} if $out_intf;
#    debug $info;;
    if($in_intf and $out_intf) {
	return unless $in_intf->{router}->{managed};
	# Remember network which is reachable via $out_intf.
	my $network = $rule->{dst};
	# This router and all routers from here to dst have been processed already.
	if($in_intf->{routes}->{$out_intf}->{$network}) {
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
	for my $interface (@{$router->{interfaces}}) {
	    # Remember, via which remote interface a network is reached.
	    my %net2hop;
	    # Convert to sorted array, because hash isn't neede any longer.
	    $interface->{hop} = [ sort { $a->{name} cmp $b->{name} }
				  values %{$interface->{hop}} ];
	    for my $hop (@{$interface->{hop}}) {
		for my $network (values %{$interface->{routes}->{$hop}}) {
		    if(my $interface2 = $net2intf{$network}) {
			if($interface2 ne $interface) {
			    # Network is reached via two different
			    # local interfaces.
			    # Check if both have dynamic routing enabled.
			    unless($interface->{routing} and
				   $interface2->{routing}) {
				warning
				    "Two static routes for $network->{name}\n",
				    " via $interface->{name} and ",
				    "$interface2->{name}";
			    }
			}
		    } else {
			$net2intf{$network} = $interface;
		    }
		    unless($interface->{routing}) {
			if(my $hop2 = $net2hop{$network}) {
			    # Network is reached via two different hops.
			    # Check if both are reached via the same virtual IP.
			    if($hop->{virtual} and $hop2->{virtual} and
				   $hop->{virtual} eq $hop2->{virtual}) {
				# Prevent multiple identical routes to different
				# interfaces with identical virtual IP.
				delete $interface->{routes}->{$hop}->{$network};
			    } else {
				warning
				    "Two static routes for $network->{name}\n",
				    " at $interface->{name}";
			    }
			} else {
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
    my($rule, $in_intf, $out_intf) = @_;
    # no static needed for directly attached interface
    return unless $out_intf;
    my $router = $out_intf->{router};
    return unless $router->{managed};
    return unless $router->{model}->{has_interface_level};
    # no static needed for traffic coming from the PIX itself
    return unless $in_intf;
    # We need in_hw and out_hw for
    # - their names and for
    # - getting the NAT domain
    my $in_hw = $in_intf->{hardware};
    my $out_hw = $out_intf->{hardware};
    my $dst = $rule->{dst};
    # dst has been added before; skip NAT calculation.
    return if $out_hw->{static}->{$in_hw}->{$dst};
    err_msg "Traffic to $rule->{dst}->{name} can't pass\n",
    " from  $in_intf->{name} to $out_intf->{name},\n",
    " because they have equal security levels.\n"
	if $in_hw->{level} == $out_hw->{level};
    # This router and all routers from here to dst have been processed already.
    if($out_hw->{static}->{$in_hw}->{$dst}) {
	# Jump out of path_walk in sub find_active_routes_and_statics
	no warnings "exiting";
	next RULE;
    }
    # Put networks into a hash to prevent duplicates.
    $out_hw->{static}->{$in_hw}->{$dst} = $dst;
    # Do we need to generate "nat 0" for an interface?
    if($in_hw->{level} < $out_hw->{level}) {
	$out_hw->{need_nat_0} = 1;
    } else {
	# Check, if there is a dynamic NAT of a dst address from higher
	# to lower security level. We need this info to decide,
	# if static commands with "identity mapping" and 
	# a "nat 0" command needs to be generated.
	$out_hw->{need_always_static} and return;
	# Remember: NAT tag for networks behind out_hw is attached to in_hw.
	my $nat_tag = $in_hw->{bind_nat} or return;
	if($dst->{nat} &&
	   $dst->{nat}->{$nat_tag} &&
	   $dst->{nat}->{$nat_tag}->{dynamic}) {
	    $out_hw->{need_always_static} = 1;
	    $out_hw->{need_nat_0} = 1;
	}
    }
}

sub find_active_routes_and_statics () {
    info "Finding routes and statics";
    my %routing_tree;
    my $pseudo_srv = { name => '--'};
    my $fun = sub ( $$ ) {
	my($src,$dst) = @_;
	# Don't apply get_network to $src, but use get_path instead:
	# - It doesn't matter which network of an 'any' object is used.
	# - We must preserve managed interfaces, since they may get routing
	#   entries added.
	my $from = get_path $src;
#	debug "$from->{name} -> $to->{name}";
	# 'any' objects are expanded to all its contained networks
	# hosts and interfaces expand to its containing network.
	# Don't try to use an interface as destination of $pseudo_rule;
	# this would give wrong routes and statics, if a path restriction
	# is applied to this interface.
	for my $network (get_networks($dst)) {
	    next if $network->{ip} eq 'unnumbered';
	    unless($routing_tree{$from}->{$network}) {
		my $pseudo_rule = { src => $from,
				    dst => $network,
				    action => '--',
				    srv => $pseudo_srv,
				    };
		$routing_tree{$from}->{$network} = $pseudo_rule;
	    }
	}
    };
    for my $rule (@expanded_rules, @expanded_any_rules) {
	$fun->($rule->{src}, $rule->{dst});
    }
    for my $hash (values %routing_tree) {
      RULE:
	for my $pseudo_rule (values %$hash) {
	    path_walk($pseudo_rule, \&mark_networks_for_static, 'Router');
	}
    }
    # Additionally process reverse direction for routing
    for my $rule (@expanded_rules, @expanded_any_rules) {
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

# Needed for default route optimization and
# while generating chains of iptables and 
# for local optimization.
my $network_00 = new('Network', name => "network:0/0", ip => 0, mask => 0);

sub print_routes( $ ) {
    my($router) = @_;
    my $type = $router->{model}->{routing};
    if($auto_default_route) {
	# Find interface and hop with largest number of routing entries.
	my $max_intf;
	my $max_hop;
	# Substitute routes to one hop with a default route,
	# if there are at least two entries.
	my $max = 1;
	for my $interface (@{$router->{interfaces}}) {
	    if($interface->{routing}) {
		# If dynamic routing is activated for any interface 
		# of the current router, don't do this optimization at all.
		$max_intf = undef;
		last;
	    }
	    # Sort interfaces by name to make output deterministic
	    for my $hop (@{$interface->{hop}}) {
		my $count = keys %{$interface->{routes}->{$hop}};
		if($count > $max) {
		    $max_intf = $interface;
		    $max_hop = $hop;
		    $max = $count;
		}
	    }
	}
	if($max_intf && $max_hop) {
	    # use default route for this direction
	    $max_intf->{routes}->{$max_hop} = { $network_00 => $network_00 };
	}
    }
    print "[ Routing ]\n";
    for my $interface (@{$router->{interfaces}}) {
	# Don't generate static routing entries, 
	# if a dynamic routing protocol is activated
	if($interface->{routing}) {
	    if($comment_routes) {
		print "! Dynamic routing $interface->{routing}",
		" at $interface->{name}\n";
	    } 
	    next;
	}
	my $nat_map = $interface->{nat_map};
	# Sort interfaces by name to make output deterministic
	for my $hop (@{$interface->{hop}}) {
	    # for unnumbered networks use interface name as next hop
	    my $hop_addr =
		$hop->{ip} eq 'unnumbered' ?
		$interface->{hardware}->{name} :
		$hop->{virtual} ?
		print_ip $hop->{virtual} :
		print_ip $hop->{ip}->[0];
	    # A hash having all networks reachable via current hop
	    # as key as well as value.
	    my $net_hash = $interface->{routes}->{$hop};
	    for my $network
		# Sort networks by mask in reverse order,
		# i.e. small networks coming first and 
		# for equal mask by IP address.
		# We need this to make the output deterministic
		( sort { $b->{mask} <=> $a->{mask} || $a->{ip} <=> $b->{ip} }
		  values %$net_hash)
	    {
		# Network is redundant, if directly enclosing network
		# lies behind the same hop.
		next if $network->{is_in}->{$nat_map} and
		    $net_hash->{$network->{is_in}->{$nat_map}};
		if($comment_routes) {
		    print "! route $network->{name} -> $hop->{name}\n";
		}
		if($type eq 'IOS') {
		    my $adr =
			&ios_route_code(&address($network, $nat_map, 'src'));
		    print "ip route $adr\t$hop_addr\n";
		} elsif($type eq 'PIX') {
		    my $adr =
			&ios_route_code(&address($network, $nat_map, 'src'));
		    print "route $interface->{hardware}->{name} $adr\t$hop_addr\n";
		} elsif($type eq 'iproute') {
		    my $adr =
			&prefix_code(&address($network, $nat_map, 'src'));
		    print "ip route add $adr via $hop_addr\n";
		} else {
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
    my($router) = @_;
    my %ref2hw;
    print "[ Static ]\n";
    # Print security level relation for each interface.
    print "! Security levels: ";
    my $prev_level;
    for my $hardware (sort { $a->{level} <=> $b->{level} }
		      @{$router->{hardware}} ) {
	# For getting reference back from key.
	$ref2hw{$hardware} = $hardware;
	my $level = $hardware->{level};
	if(defined $prev_level) {
	    print(($prev_level == $level) ? " = ": " < ");
	}
	print $hardware->{name};
	$prev_level = $level;
    }
    print "\n";

    my $nat_index = 1;
    for my $out_hw (sort { $a->{level} <=> $b->{level} }
		      @{$router->{hardware}}) {
	next unless $out_hw->{static};
	my $out_name = $out_hw->{name};
	my $out_nat = $out_hw->{nat_map};
	for my $in_hw (sort { $a->{level} <=> $b->{level} }
		       map { $ref2hw{$_} }
		       # Key is reference to hardware interface.
		       keys %{$out_hw->{static}}) {
	    # Value is { net => net, .. }
	    my($net_hash) = $out_hw->{static}->{$in_hw};
	    my $in_name = $in_hw->{name};
	    my $in_nat = $in_hw->{nat_map};
	    # Sorting is only needed for getting output deterministic.
	    my @networks =
		sort { $a->{ip} <=> $b->{ip} || $a->{mask} <=> $b->{mask} }
	    values %$net_hash;
	    # Mark redundant network as deleted.
	    # A network is redundant if some enclosing network is found 
	    # in both NAT domains of incoming and outgoing interface.
	    for my $network (@networks) {
		my $net = $network->{is_in}->{$in_nat};
		while($net) {
		    my $net2;
		    if($net_hash->{$net} and
		       $net2 = $network->{is_in}->{$out_nat} and
		       $net_hash->{$net2}) {
			$network = undef;
			last;
		    } else {
			$net = $net->{is_in}->{$in_nat};
		    }
		}
	    }
	    for my $network (@networks) {
		next unless defined $network;
		my($in_ip, $in_mask, $in_dynamic) =
		    @{$in_nat->{$network} || $network}{'ip', 'mask', 'dynamic'};
		my($out_ip, $out_mask, $out_dynamic) = 
		    @{$out_nat->{$network} || $network}{'ip', 'mask', 'dynamic'};
		if($in_mask == 0 || $out_mask == 0) {
		    err_msg "Pix doesn't support static command for ",
		    "mask 0.0.0.0 of $network->{name}\n";
		}
		# We are talking about destination addresses.
		if($out_dynamic) {
		    unless($in_dynamic && $in_dynamic eq $out_dynamic &&
			   $in_ip eq $out_ip and $in_mask eq $out_mask) {
			warning "Ignoring NAT for dynamically translated ",
			"$network->{name}\n",
			"at hardware $out_hw->{name} of $router->{name}";
		    }
		} elsif($in_dynamic) {
		    # global (outside) 1 \
		    #   10.70.167.0-10.70.167.255 netmask 255.255.255.0
		    # nat (inside) 1 141.4.136.0 255.255.252.0
		    my $in_ip_max = $in_ip + ~$in_mask;
		    $in_ip = print_ip $in_ip;
		    $in_ip_max = print_ip $in_ip_max;
		    $out_ip = print_ip $out_ip;
		    $in_mask = print_ip $in_mask;
		    $out_mask = print_ip $out_mask;
		    print "global ($in_name) $nat_index ",
		    "$in_ip-$in_ip_max netmask $in_mask\n";
		    print "nat ($out_name) $nat_index $out_ip $out_mask";
		    print " outside" if $in_hw->{level} > $out_hw->{level};
		    print "\n";
		    $nat_index++;
		    # Check for static NAT entries of hosts and interfaces.
		    for my $host (@{$network->{subnets}},
				  @{$network->{interfaces}}) {
			if(my $in_ip = $host->{nat}->{$in_dynamic}) {
			    my @addresses = &address($host, $out_nat, 'dst');
			    err_msg "$host->{name}: NAT only for hosts / ",
			    "interfaces with a single IP"
				if @addresses != 1;
			    my($out_ip, $out_mask) = @{$addresses[0]};
			    $in_ip = print_ip $in_ip;
			    $out_ip = print_ip $out_ip;
			    $out_mask = print_ip $out_mask;
			    print "static ($out_name,$in_name) ",
			    "$in_ip $out_ip netmask $out_mask\n";
			}
		    }
		} else {	# both static
		    if($in_hw->{level} < $out_hw->{level} ||
		       $out_hw->{need_always_static} ||
		       $in_ip ne $out_ip) {
			$in_ip = print_ip $in_ip;
			$out_ip = print_ip $out_ip;
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

sub distribute_rule( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    # Traffic from src reaches this router via in_intf
    # and leaves it via out_intf.
    # in_intf is undefined if src is an interface of the current router
    # out_intf is undefined if dst is an interface of the current router
    # Outgoing packets from a router itself are never filtered.
    return unless $in_intf;
    my $router = $in_intf->{router};
    return unless $router->{managed};
    # Rules of type stateless must only be processed at stateless routers
    # or at routers which are stateless for packets destined for
    # their own interfaces.
    my $model = $router->{model};
    if($rule->{stateless}) {
	unless($model->{stateless} or
	       not $out_intf and $model->{stateless_self}) {
	    return;
	}
    }

    # Rules to managed interfaces must be processed
    # at the corresponding router even if they are marked as deleted,
    # because code for interfaces is placed before the 'normal' code.
    if($rule->{deleted}) {
	# We are on an intermediate router if $out_intf is defined.
	return if $out_intf;
	# No code needed if it is deleted by another rule to the same interface.
	return if $rule->{deleted}->{managed_intf};
    }
    # Validate dynamic NAT.
    if(my $nat_map = $in_intf->{nat_map}) {
	for my $where ('src', 'dst') {
	    my $obj = $rule->{$where};
	    if(is_subnet $obj || is_interface $obj) {
		my $network = $obj->{network};
		if(my $nat_network = $nat_map->{$network}) {
		    if(my $nat_tag = $nat_network->{dynamic}) {
			# Doesn't have a static translation.
			unless($obj->{nat}->{$nat_tag}) {
			    my $intf = $where eq 'src' ? $in_intf : $out_intf;
			    # Object lies in the same security domain,
			    # hence there is no other managed router 
			    # in between.
			    if($network->{any} eq $intf->{any}) {
				err_msg 
				    "$obj->{name} needs static translation",
				    " for nat:$nat_tag\n",
				    " to be valid in rule\n ",
				    print_rule $rule;
			    }
			    # Otherwise, filtering occurs at other router,
			    # therefore the whole network can pass here.
			    # But attention, this assumption only holds,
			    # if the other router filters fully. 
			    # Hence disable secondary optimization.
			    undef $rule->{has_full_filter};
			    $rule = { %$rule };
			    $rule->{$where} = $network;
			}
		    }
		}
	    }
	}
    }

    my $aref;
    # Packets for the router itself
    if(not $out_intf) {
	# For PIX firewalls it is unnecessary to process rules for packets
	# to the PIX itself, because it accepts them anyway (telnet, IPSec).
	# ToDo: Check if this assumption holds for deny ACLs as well
	return if $model->{filter} eq 'PIX' and $rule->{action} eq 'permit';
#	debug "$router->{name} intf_rule: ",print_rule $rule,"\n";
	$aref = \@{$in_intf->{hardware}->{intf_rules}};
    } else {
#	debug "$router->{name} rule: ",print_rule $rule,"\n";
	$aref = \@{$in_intf->{hardware}->{rules}};
    }
    # Add rule, but prevent duplicates, which might occur 
    # at the start of a loop.
    # Therefore check if last rule and current rule are identical.
    push @$aref, $rule
	unless @$aref and $aref->[$#$aref] eq $rule;

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
    if($in_intf->{any} eq $src) {
	&distribute_rule(@_);
    }
}

# For rules with dst=any:*, call distribute_rule only for
# the last router on the path from src to dst.
sub distribute_rule_at_dst( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $router = $out_intf->{router};
    return unless $router->{managed};
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    is_any $dst or internal_err "$dst must be of type 'any'";
    # Rule is only processed at the last router on the path.
    if($out_intf->{any} eq $dst) {
	&distribute_rule(@_);
    }
}

sub rules_distribution() {
    info "Rules distribution";
    # Deny rules
    for my $rule (@expanded_deny_rules) {
	next if $rule->{deleted};
	path_walk($rule, \&distribute_rule);
    }
    # Rules with 'any' object as src or dst
    for my $rule (@expanded_any_rules) {
	next if $rule->{deleted} and
	    (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
	if(is_any $rule->{src}) {
	    if(is_any $rule->{dst}) {
		# Both, src and dst are 'any' objects.
		# We only need to generate code if they are directly connected
		# by a managed router.
		# See check_any_both_rule above for details.
		if($rule->{any_are_neighbors}) {
		    path_walk($rule, \&distribute_rule_at_dst);
		}
	    } else {
		path_walk($rule, \&distribute_rule_at_src);
	    }
	} elsif(is_any $rule->{dst}) {
	    path_walk($rule, \&distribute_rule_at_dst);
	} else {
	    internal_err "unexpected rule ", print_rule $rule, "\n";
	}
    }
    # Other permit rules
    for my $rule (@expanded_rules) {
	next if $rule->{deleted} and
	    (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
	path_walk($rule, \&distribute_rule, 'Router');
    }
}

##############################################################################
# ACL Generation
##############################################################################

# Parameters:
# obj: this address we want to know
# network: look inside this nat domain
# direction: is obj used as source or destination 
# returns a list of [ ip, mask ] pairs
sub address( $$$ ) {
    my ($obj, $nat_map, $direction) = @_;
    my $type = ref $obj;
    if($type eq 'Network') {
	$obj = $nat_map->{$obj} || $obj;
	# ToDo: Is is ok to permit a dynamic address as destination?
	if($obj->{ip} eq 'unnumbered') {
	    internal_err "unexpected unnumbered $obj->{name}\n";
	} else {
	    return [$obj->{ip}, $obj->{mask}];
	}
    } elsif($type eq 'Subnet') {
	my $network = $obj->{network};
	$network = $nat_map->{$network} || $network;
	if(my $nat_tag = $network->{dynamic}) {
	    if(my $ip = $obj->{nat}->{$nat_tag}) {
		# single static NAT IP for this host
		return [$ip, 0xffffffff];
	    } else {
		internal_err "Unexpected $obj->{name} with dynamic NAT";
	    }
	} else {
	    # Take higher bits from network NAT, lower bits from original IP.
	    # This works with and without NAT.
	    my $ip = $network->{ip} | $obj->{ip} & ~$network->{mask};
	    return [$ip, $obj->{mask}];
	}
    }
    if($type eq 'Interface') {
	if($obj->{ip} eq 'unnumbered' or $obj->{ip} eq 'short') {
	    internal_err "unexpected $obj->{ip} $obj->{name}\n";
	}
	my $network = $obj->{network};
	$network = $nat_map->{$network} || $network;
	if(my $nat_tag = $network->{dynamic}) {
	    if(my $ip = $obj->{nat}->{$nat_tag}) {
		# single static NAT IP for this interface
		return [$ip, 0xffffffff];
	    } else {
		internal_err "Unexpected $obj->{name} with dynamic NAT";
	    }
	} else {
	    my @ip = @{$obj->{ip}};
	    # Virtual IP must be added for deny rules,
	    # it doesn't hurt for permit rules.
	    push @ip, $obj->{virtual} if $obj->{virtual};
	    # Take higher bits from network NAT, lower bits from original IP.
	    # This works with and without NAT.
	    my ($network_ip, $network_mask) = @{$network}{'ip', 'mask'};
	    return map { [$network_ip | $_ & ~$network_mask, 0xffffffff] } @ip;
	}
    } elsif($type eq 'Any') {
	return [0, 0];
    } elsif($type eq 'Objectgroup') {
	$obj;
    } else {
	internal_err "unexpected object $obj->{name}";
    }
}

# Given an IP and mask, return its address in IOS syntax.
# If optional third parameter is true, use inverted netmask for IOS ACLs.
sub ios_code( $;$ ) {
    my($pair, $inv_mask) = @_;
    if(is_objectgroup $pair) {
	return "object-group $pair->{name}";
    } else {
	my($ip, $mask) = @$pair;
	my $ip_code = print_ip($ip);
	if($mask == 0xffffffff) {
	    return "host $ip_code";
	} elsif($mask == 0) {
	    return "any";
	} else {
	    my $mask_code = print_ip($inv_mask?~$mask:$mask);
	    return "$ip_code $mask_code";
	}
    }
}

sub ios_route_code( $ ) {
    my($pair) = @_;
    my($ip, $mask) = @$pair;
    my $ip_code = print_ip($ip);
    my $mask_code = print_ip($mask);
    return "$ip_code $mask_code";
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32.
sub prefix_code( $ ) {
    my($pair) = @_;
    my($ip, $mask) = @$pair;
    my $ip_code = print_ip($ip);
    my $prefix_code = mask2prefix($mask);
    return $prefix_code == 32 ? $ip_code : "$ip_code/$prefix_code";
}

my %pix_srv_hole;

# Print warnings about the PIX service hole.
sub warn_pix_icmp() {
    if(%pix_srv_hole) {
	warning "Ignored the code field of the following ICMP services\n",
	" while generating code for pix firewalls:";
	while(my ($name, $count) = each %pix_srv_hole) {
	    print STDERR " $name: $count times\n";
	}
    }
}

# Returns 3 values for building an IOS or PIX ACL:
# permit <val1> <src> <val2> <dst> <val3>
sub cisco_srv_code( $$ ) {
    my ($srv, $model) = @_;
    my $proto = $srv->{proto};

    if($proto eq 'ip') {
	return('ip', '', '');
    } elsif($proto eq 'tcp' or $proto eq 'udp') {
	my @p = @{$srv->{ports}};
	my $port_code = sub ( $$ ) {
	    my($v1, $v2) = @_;
	    if($v1 == $v2) {
		return("eq $v1");
	    } 
	    # PIX doesn't allow port 0; can port 0 be used anyhow?
	    elsif($v1 == 1 and $v2 == 65535) {
		return('');
	    } elsif($v2 == 65535) {
		$v1--;
		return "gt $v1";
	    } elsif($v1 == 1) {
		$v2++;
		return "lt $v2";
	    } else {
		return("range $v1 $v2");
	    }
	};
	my $established = $srv->{established} ? ' established' : '';
	return($proto, &$port_code(@p[0,1]),
	       &$port_code(@p[2,3]) . $established);
    } elsif($proto eq 'icmp') {
	if(defined (my $type = $srv->{type})) {
	    if(defined (my $code = $srv->{code})) {
		if($model->{no_filter_icmp_code}) {
		    # PIX can't handle the ICMP code field.
		    # If we try to permit e.g. "port unreachable", 
		    # "unreachable any" could pass the PIX. 
		    $pix_srv_hole{$srv->{name}}++;
		    return($proto, '', $type);
		} else {
		    return($proto, '', "$type $code");
		}
	    } else {
		return($proto, '', $type);
	    }
	} else  {
	    return($proto, '', '');
	}
    } else {
	return($proto, '', '');
    }
}

# Returns iptables code for filtering a service.
sub iptables_srv_code( $ ) {
    my ($srv) = @_;
    my $proto = $srv->{proto};

    if($proto eq 'ip') {
	return '';
    } elsif($proto eq 'tcp' or $proto eq 'udp') {
	my @p = @{$srv->{ports}};
	my $port_code = sub ( $$ ) {
	    my($v1, $v2) = @_;
	    if($v1 == $v2) {
		return $v1;
	    } elsif($v1 == 1 and $v2 == 65535) {
		return '';
	    } elsif($v2 == 65535) {
		return "$v1:";
	    } elsif($v1 == 1) {
		return ":$v2";
	    } else {
		return "$v1:$v2";
	    }
	};
	my $sport = &$port_code(@p[0,1]);
	my $dport = &$port_code(@p[2,3]);
	my $result = "-p $proto";
	$result .= " -sport $sport" if $sport;
	$result .= " -dport $dport" if $dport;
	$srv->{established} and
	    internal_err "Unexpected service $srv->{name} with",
	    " 'established' flag while generating code for iptables";
	return $result;
    } elsif($proto eq 'icmp') {
	if(defined (my $type = $srv->{type})) {
	    if(defined (my $code = $srv->{code})) {
		return "-p $proto --icmp-type $type/$code";
	    } else {
		return "-p $proto --icmp-type $type";
	    }
	} else {
	    return "-p $proto";
	}
    } else {
	return "-p $proto"
    }
}

sub acl_line( $$$$ ) {
    my($rules_aref, $nat_map, $prefix, $model) = @_;
    my $filter_type = $model->{filter};
    for my $rule (@$rules_aref) {
	my $action = $rule->{action};
	my $src = $rule->{src};
	my $dst = $rule->{dst};
	my $srv = $rule->{srv};
	print "$model->{comment_char} ". print_rule($rule)."\n"
	    if $comment_acls;
	for my $spair (address($src, $nat_map, 'src')) {
	    for my $dpair (address($dst, $nat_map, 'dst')) {
		if($filter_type eq 'IOS' or $filter_type eq 'PIX') {
		    my $inv_mask = $filter_type eq 'IOS';
		    my ($proto_code, $src_port_code, $dst_port_code) =
			cisco_srv_code($srv, $model);
		    my $src_code = ios_code($spair, $inv_mask);
		    my $dst_code = ios_code($dpair, $inv_mask);
		    print "$prefix $action $proto_code ",
		    "$src_code $src_port_code $dst_code $dst_port_code\n";
		} elsif($filter_type eq 'iptables') {
		    my $srv_code = iptables_srv_code($srv);
		    my $src_code = prefix_code($spair);
		    my $dst_code = prefix_code($dpair);
		    my $action_code =
			is_chain $action ? $action->{name} :
			$action eq 'permit' ? 'ACCEPT' : 'DROP';
		    print "$prefix -j $action_code ",
		    "-s $src_code -d $dst_code $srv_code\n";
		} else {
		    internal_err "Unknown filter_type $filter_type";
		}
	    }
	}
    }
}

my $min_object_group_size = 2;

sub find_object_groups ( $ ) {
    my($router) = @_;
    # For collecting found object-groups 
    my @groups;
    # Find identical groups in identical NAT domain and of same size
    my %nat2size2group;
    # For generating names of object-groups
    my $counter = 1;
    # Find object-groups in src / dst of rules
    for my $this ('src', 'dst') {
	my $that = $this eq 'src' ? 'dst' : 'src';
	my $tag = "${this}_group";
	for my $hardware (@{$router->{hardware}}) {
	    my %group_rule_tree;
	    # find groups of rules with identical 
	    # action, srv, src/dst and different dst/src
	    for my $rule (@{$hardware->{rules}}) {
		my $action = $rule->{action};
		my $that = $rule->{$that};
		my $this = $rule->{$this};
		my $srv = $rule->{srv};
		$group_rule_tree{$action}->{$srv}->{$that}->{$this} = $rule;
	    }
	    # Find groups >= $min_object_group_size,
	    # mark rules belonging to one group,
	    # put groups into an array / hash
	    for my $href (values %group_rule_tree) {
		# $href is {srv => href, ...}
		for my $href (values %$href) {
		    # $href is {src/dst => href, ...}
		    for my $href (values %$href) {
			# $href is {dst/src => rule, ...}
			my $size = keys %$href;
			if($size >= $min_object_group_size) {
			    my $glue = {
				# Indicator, that no further rules need
				# to be processed.
				active => 0,
				# NAT domain for address calculation
				nat_map => $hardware->{nat_map},
				# for check, if interfaces belong to
				# identical NAT domain
				bind_nat => $hardware->{bind_nat} || 'none',
				# object-ref => rule, ...
				hash => $href};
			    # all this rules have identical
			    # action, srv, src/dst  and dst/stc 
			    # and shall be replaced by a new object group
			    for my $rule (values %$href) {
				$rule->{$tag} = $glue;
			    }
			}
		    }
		}
	    }
	}
	# Find a group with identical elements or define a new one
	my $get_group = sub ( $ ) {
	    my ($glue) = @_;
	    my $hash = $glue->{hash};
	    my $bind_nat = $glue->{bind_nat};
	    my @keys = keys %$hash;
	    my $size = @keys;
	    # Find group with identical elements.
	    for my $group (@{$nat2size2group{$bind_nat}->{$size}}) {
		my $href = $group->{hash};
		my $eq = 1;
		for my $key (@keys) {
		    unless($href->{$key}) {
			$eq = 0;
			last;
		    }
		}
		if($eq) {
		    $glue->{group} = $group;
		    return;
		}		
	    }
	    # Not found, build new group.
	    my $group = new('Objectgroup',
			    name => "g$counter",
			    elements => [ map { $ref2obj{$_} } @keys ],
			    hash => $hash,
			    nat_map => $glue->{nat_map});
	    for my $element (@{$group->{elements}}) {
		is_any $element and
		    internal_err "Unexpected $element->{name} in object-group";
	    }
	    push @{$nat2size2group{$bind_nat}->{$size}}, $group;
	    push @groups, $group;
	    $counter++;
	    $glue->{group} = $group;
	};
	# Build new list of rules using object groups.
	for my $hardware (@{$router->{hardware}}) {
	    my @new_rules;
	    for my $rule (@{$hardware->{rules}}) {
		if(my $glue = $rule->{$tag}) {
#		    debug print_rule $rule;
		    # Remove tag, otherwise call to find_object_groups 
		    # for another router would become confused.
		    delete $rule->{$tag};
		    if($glue->{active}) {
#			debug " deleted: $glue->{group}->{name}";
			next;
		    }
		    $get_group->($glue);
#		    debug " generated: $glue->{group}->{name}";
		    $glue->{active} = 1;
		    $rule = {action => $rule->{action},
			     $that => $rule->{$that},
			     $this => $glue->{group},
			     srv => $rule->{srv}};
		}
		push @new_rules, $rule;
	    }
	    $hardware->{rules} = \@new_rules;
	}
    }
    # print PIX object-groups
    for my $group (@groups) {
	my $nat_map =  $group->{nat_map};
        print "object-group network $group->{name}\n";
        for my $pair (sort { $a->[0] <=> $b->[0] ||  $a->[1] <=> $b->[1] }
			 map { address($_, $nat_map, 'src') }
			 @{$group->{elements}}) {
	    my $adr = ios_code($pair);
	    print " network-object $adr\n";
	}
    }
    # Empty line as delimiter.
    print "\n";
}

sub find_chains ( $ ) {
    my($router) = @_;
    # For collecting found chains. 
    my @chains;
    # For generating names of chains
    my $counter = 1;
    # Find groups in src / dst of rules
    for my $this ('dst', 'src') {
	my $that = $this eq 'src' ? 'dst' : 'src';
	my $tag = "${this}_group";
	# Find identical chains in identical NAT domain, 
	# with same action and size
	my %nat2action2size2group;
	for my $hardware (@{$router->{hardware}}) {
	    my %group_rule_tree;
	    # find groups of rules with identical 
	    # action, srv, src/dst and different dst/src
	    for my $rule (@{$hardware->{rules}}) {
		# Action may be reference to chain from first round.
		my $action = $rule->{action};
		my $that = $rule->{$that};
		my $this = $rule->{$this};
		my $srv = $rule->{srv};
		$group_rule_tree{$action}->{$srv}->{$that}->{$this} = $rule;
	    }
	    # Find groups >= $min_object_group_size,
	    # mark rules belonging to one group,
	    # put groups into an array / hash
	    for my $href (values %group_rule_tree) {
		# $href is {srv => href, ...}
		for my $href (values %$href) {
		    # $href is {src/dst => href, ...}
		    for my $href (values %$href) {
			# $href is {dst/src => rule, ...}
			my $size = keys %$href;
			if($size >= $min_object_group_size) {
			    my $glue = {
				# Indicator, that no further rules need
				# to be processed.
				active => 0,
				# NAT domain for address calculation
				nat_map => $hardware->{nat_map},
				# for check, if interfaces belong to
				# identical NAT domain
				bind_nat => $hardware->{bind_nat} || 'none',
				# object-ref => rule, ...
				hash => $href};
			    # all this rules have identical
			    # action, srv, src/dst  and dst/src 
			    # and shall be replaced by a new chain
			    for my $rule (values %$href) {
				$rule->{$tag} = $glue;
			    }
			}
		    }
		}
	    }
	}
	# Find a chain of same type and with identical elements or
	# define a new one
	my $get_chain = sub ( $$ ) {
	    my ($glue, $action) = @_;
	    my $hash = $glue->{hash};
	    my $bind_nat = $glue->{bind_nat};
	    my @keys = keys %$hash;
	    my $size = @keys;
	    # Find chain with identical elements.
	    for my $chain (@{$nat2action2size2group
			     {$bind_nat}->{$action}->{$size}}) {
		my $href = $chain->{hash};
		my $eq = 1;
		for my $key (@keys) {
		    unless($href->{$key}) {
			$eq = 0;
			last;
		    }
		}
		if($eq) {
		    $glue->{chain} = $chain;
		    return;
		}		
	    }
	    # Not found, build new chain.
	    my $chain = new('Chain',
			    name => "c$counter",
			    action => $action,
			    where => $this,
			    elements => [ map { $ref2obj{$_} } @keys ],
			    hash => $hash,
			    nat_map => $glue->{nat_map});
	    for my $element (@{$chain->{elements}}) {
		is_any $element and
		    internal_err "Unexpected $element->{name} in chain";
	    }
	    push @{$nat2action2size2group{$bind_nat}->{$action}->{$size}},
	    $chain;
	    push @chains, $chain;
	    $counter++;
	    $glue->{chain} = $chain;
	};
	# Build new list of rules using chains.
	for my $hardware (@{$router->{hardware}}) {
	    my @new_rules;
	    for my $rule (@{$hardware->{rules}}) {
		if(my $glue = $rule->{$tag}) {
#		    debug print_rule $rule;
		    # Remove tag, otherwise a subsequent call to
		    # find_object_groups or find_chains would become confused.
		    delete $rule->{$tag};
		    if($glue->{active}) {
#			debug " deleted: $glue->{chain}->{name}";
			next;
		    }
		    # Action may be a previously found chain.
		    $get_chain->($glue, $rule->{action});
#		    debug " generated: $glue->{chain}->{name}";
		    $glue->{active} = 1;
		    $rule = {action => $glue->{chain},
			     $this => $network_00,
			     $that => $rule->{$that},
			     srv => $rule->{srv}};
		}
		push @new_rules, $rule;
	    }
	    $hardware->{rules} = \@new_rules;
	}
    }
    # print chains
    for my $chain (@chains) {
	my $name = $chain->{name};
	my $action = $chain->{action};
	my $action_code =
	    is_chain $action ? $action->{name} :
	    $action eq 'permit' ? 'ACCEPT' : 'DROP';
	my $nat_map =  $chain->{nat_map};
	print "iptables -N $name\n";
        for my $pair (sort { $a->[0] <=> $b->[0] ||  $a->[1] <=> $b->[1] }
		      map { address($_, $nat_map, 'src') }
		      @{$chain->{elements}}) {
	    my $obj_code = prefix_code($pair);
	    my $type = $chain->{where} eq 'src' ? '-s' : '-d';
	    print "iptables -A $name -j $action_code $type $obj_code\n";
	}
    }
    # Empty line as delimiter.
    print "\n";
}

sub local_optimization() {
    info "Local optimization";
    # Prepare data structures
    for my $network (@networks) {
	$network->{up} = $network->{subnet_of} || $network_00;
	for my $interface (@{$network->{interfaces}}) {
	    $interface->{up} = $network;
	}
    }
    for my $rule (@expanded_any_rules, @expanded_rules) {
	next if $rule->{deleted} and not $rule->{managed_intf};
	$rule->{src} = $network_00 if is_any $rule->{src};
	$rule->{dst} = $network_00 if is_any $rule->{dst};
    }
    for my $router (@managed_routers) {
 	my $secondary_router = $router->{managed} eq 'secondary';
	for my $hardware (@{$router->{hardware}}) {
	    for my $rules ('intf_rules', 'rules') {
		my %hash;
		for my $rule (@{$hardware->{$rules}}) {
		    my $src = $rule->{src};
		    my $dst = $rule->{dst};
		    my $srv = $rule->{srv};
		    $hash{$src}->{$dst}->{$srv} = $rule;
		}
		my $changed = 0;
	      RULE:
		for my $rule (@{$hardware->{$rules}}) {
		    my $src = $rule->{src};
		    my $dst = $rule->{dst};
		    my $srv = $rule->{srv};
		    while($src) {
			my $dst = $dst;
			my $hash = $hash{$src};
			while($dst) {
			    my $srv = $srv;
			    my $hash = $hash->{$dst};
			    while($srv) {
				if(my $old_rule = $hash->{$srv}) {
				    unless($rule eq $old_rule) {
					$rule = undef;
					$changed = 1;
					next RULE;
				    }
				}
				$srv = $srv->{up};
			    }
			    $dst = $dst->{up};
			}
			$src = $src->{up};
		    }
		    # Convert remaining rules to secondary rules, if possible.
		    if($secondary_router && $rule->{has_full_filter}) {
			# get_networks has a single result if not called 
			# with an 'any' object as argument
			$src = get_networks $rule->{src};
			$dst = $rule->{dst};
			unless(is_interface $dst && $dst->{router} eq $router) {
			    $dst = get_networks $dst;
			}
			my $new_rule = {
			    action => $rule->{action},
			    src => $src,
			    dst => $dst,
			    srv => $srv_ip };
			$hash{$src}->{$dst}->{$srv_ip} = $new_rule;
			# This changes @{$hardware->{$rules}} !
			$rule = $new_rule;
		    }
			
		}
		if($changed) {
		    $hardware->{$rules} =
			[ grep $_, @{$hardware->{$rules}} ];
		}
	    }
	}
    }
}	    
	
sub print_acls( $ ) {
    my($router) = @_;
    my $model = $router->{model};
    print "[ ACL ]\n";
    if($model->{filter} eq 'PIX' and not $router->{no_object_groups}) {
	find_object_groups($router);
    } elsif($model->{filter} eq 'iptables') { 
	find_chains($router);
    }
    my $comment_char = $model->{comment_char};
    # Collect IP addresses of all interfaces
    my @ip;
    for my $hardware (@{$router->{hardware}}) {
	# We need to know, if packets for a dynamic routing protocol 
	# are allowed for a hardware interface.
	my %routing;
	for my $interface (@{$hardware->{interfaces}}) {
	    # Current router is used as default router even for some internal
	    # networks.
	    if($interface->{reroute_permit}) {
		for my $net (@{$interface->{reroute_permit}}) {
		    # This is not allowed between different security domains.
		    if($net->{any} ne $interface->{any}) {
			err_msg "Invalid reroute_permit for $net->{name} ",
			"at $interface->{name}: different security domains";
			next;
		    }
		    # prepend to all other rules
		    unshift(@{$hardware->{rules}}, { action => 'permit', 
						     src => $network_00,
						     dst => $net,
						     srv => $srv_ip });
		}
	    }
	    # Is dynamic routing used?
	    if(my $type = $interface->{routing}) {
		unless($routing{$type}) {
		    # Prevent duplicate rules from multiple logical interfaces.
		    $routing{$type} = 1;
		    # Permit multicast packets as destination.
		    # permit ip any host 224.0.0.xx
		    for my $mcast (@{$routing_info{$type}->{mcast}}) {
			push(@{$hardware->{intf_rules}},
			     { action => 'permit',
			       src => $network_00,
			       dst => $mcast,
			       srv => $srv_ip });
		    }
		    # Permit dynamic routing protocol packets from
		    # attached networks to this router.
		    # We use the network instead of the interface,
		    # because we need fewer rules if the interface has 
		    # multiple addresses.
		    my $network = $interface->{network};
		    push(@{$hardware->{intf_rules}},
			 { action => 'permit', 
			   src => $network,
			   dst => $network,
			   srv => $routing_info{$type}->{srv} });
		}
	    }
	}
    }
    # Add deny rules. 
    for my $hardware (@{$router->{hardware}}) {
	if($model->{filter} eq 'IOS' and @{$hardware->{rules}}) {
	    for my $interface (@{$router->{interfaces}}) {
		# ignore 'unnumbered' and 'short' interfaces
		next if $interface->{ip} eq 'unnumbered' or
		    $interface->{ip} eq 'short';
		# Protect own interfaces.
		push(@{$hardware->{intf_rules}}, { action => 'deny',
						   src => $network_00,
						   dst => $interface,
						   srv => $srv_ip });
	    }
	}
	if($model->{filter} eq 'iptables') {
	    push(@{$hardware->{intf_rules}}, { action => 'deny',
					       src => $network_00,
					       dst => $network_00,
					       srv => $srv_ip });
	}
	push(@{$hardware->{rules}}, { action => 'deny',
				      src => $network_00,
				      dst => $network_00,
				      srv => $srv_ip });
    }
    # Generate code.
    for my $hardware (@{$router->{hardware}}) {
	my $name = "$hardware->{name}_in";
	my $intf_name;
	my $prefix;
	my $intf_prefix;
	if($comment_acls) {
	    # Name of first logical interface
	    print "$comment_char $hardware->{interfaces}->[0]->{name}\n";
	}
	if($model->{filter} eq 'IOS') {
	    $intf_prefix = $prefix = '';
	    print "ip access-list extended $name\n";
	} elsif($model->{filter} eq 'PIX') {
	    $intf_prefix = $prefix = "access-list $name";
	} elsif($model->{filter} eq 'iptables') {
	    $intf_name = "$hardware->{name}_self";
	    $intf_prefix = "iptables -A $intf_name";
	    $prefix = "iptables -A $name";
	    print "iptables -N $name\n";
	    print "iptables -N $intf_name\n";
	}
	my $nat_map = $hardware->{nat_map};
	# Interface rules
	acl_line $hardware->{intf_rules}, $nat_map, $intf_prefix, $model;
	# Ordinary rules
	acl_line $hardware->{rules}, $nat_map, $prefix, $model;
	# Postprocessing for hardware interface
	if($model->{filter} eq 'IOS') {
	    print "interface $hardware->{name}\n";
	    print " access group $name\n";
	} elsif($model->{filter} eq 'PIX') {
	    print "access-group $name in interface $hardware->{name}\n";
	}
	# Empty line after each interface.
	print "\n";
    }
    # Post-processing for all interfaces.
    if($model->{filter} eq 'iptables') {
	print "iptables -P INPUT DROP\n";
	print "iptables -F INPUT\n";
	print "iptables -A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
	for my $hardware (@{$router->{hardware}}) {
	    my $if_name = "$hardware->{name}_self";
	    print "iptables -A INPUT -j $if_name -i $hardware->{name} \n";
	}
	print "iptables -A INPUT -j DROP -s 0.0.0.0/0 -d 0.0.0.0/0\n";
	#
	print "iptables -P FORWARD DROP\n";
	print "iptables -F FORWARD\n";
	print "iptables -A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED\n";
	for my $hardware (@{$router->{hardware}}) {
	    my $name = "$hardware->{name}_in";
	    print "iptables -A FORWARD -j $name -i $hardware->{name}\n";
	}
	print "iptables -A FORWARD -j DROP -s 0.0.0.0/0 -d 0.0.0.0/0\n";
    }
}

# Make output directory available.
sub check_output_dir( $ ) {
    my($dir) = @_;
    unless(-e $dir) {
	mkdir $dir or die "Abort: can't create output directory $dir: $!\n";
    }
    -d $dir or die "Abort: $dir isn't a directory\n";
}

# Print generated code for each managed router.
sub print_code( $ ) {
    my($dir) = @_;
    check_output_dir($dir);
    info "Printing code";
    for my $router (@managed_routers) {
	my $model = $router->{model};
	my $name = $router->{name};
	my $file = $name;
	$file =~ s/^router://;
	$file = "$dir/$file";
	open STDOUT, ">$file" or die "Can't open $file: $!\n";
	print "!! Generated by $program, version $version\n\n";
	print "[ BEGIN $name ]\n";
	print "[ Model = $model->{name} ]\n";
	print_routes($router);
	print_acls($router);
	print_pix_static($router) if $model->{has_interface_level};
	print "[ END $name ]\n\n";
	close STDOUT or die "Can't close $file\n";
    }
    $warn_pix_icmp_code && warn_pix_icmp;
}

####################################################################
# Argument processing
####################################################################
sub usage() {
    die "Usage: $0 {in-file | in-directory} out-directory\n";
}

sub read_args() {
    my $main_file = shift @ARGV or usage;
    my $out_dir = shift @ARGV or usage;
    # Strip trailing slash for nicer messages.
    $out_dir =~ s</$><>;
    not @ARGV or usage;
    return $main_file, $out_dir;
}

sub show_version() {
    info "$program, version $version";
}

1
