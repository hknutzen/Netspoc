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

our @ISA = qw(Exporter);
our @EXPORT = qw(%routers %interfaces %networks %hosts %anys %everys
		 %groups %services %servicegroups 
		 %policies @rules
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
		 convert_any_rules 
		 optimize
		 optimize_reverse_rules
		 distribute_nat_info
		 gen_reverse_rules
		 gen_secondary_rules 
		 order_any_rules
		 repair_deny_influence 
		 rules_distribution
		 check_output_dir
		 print_code );

my $program = 'Network Security Policy Compiler';
my $version = (split ' ','$Id$ ')[2];

####################################################################
# User configurable options
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
# allow rules at top-level or only as part of policies
# Possible values: 0 | warn | 1
my $allow_toplevel_rules = 0;
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

# filename of current input file
our $file;
# eof status of current file
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

sub line() {
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
    print STDERR "Error: ", @_, &line();
    check_abort();
}

sub err_msg( @ ) {
    print STDERR "Error: ", @_, "\n";
    check_abort();
}

sub syntax_err( @ ) {
    die "Syntax error: ", @_, &context();
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
	# cut off trailing linefeed
	chop;
    }
    # ignore leading whitespace
    m/\G\s*/gc;
}

# our input buffer $_ gets undefined, if we reached eof
sub check_eof() {
    &skip_space_and_comment();
    return $eof;
}

# check for a string and skip if available
sub check( $ ) {
    my $token = shift;
    &skip_space_and_comment();
    # ToDo: escape special RE characters in $token
    return(m/\G$token/gc);
}

# skip a string
sub skip ( $ ) {
    my $token = shift;
    &check($token) or syntax_err "Expected '$token'";
}

# check, if an integer is available
sub check_int() {
    &skip_space_and_comment();
    if(m/\G(\d+)/gc) {
	return $1;
    } else {
	return undef;
    }
}

# read IP address
# internally it is stored as an integer
sub read_ip() {
    &skip_space_and_comment();
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

# convert IP address from internal integer representation to
# readable string
sub print_ip( $ ) {
    my $ip = shift;
    return sprintf "%vd", pack 'N', $ip;
}

# Conversion from netmask to prefix and vice versa
{
    # initialize private variables of this block
    my %mask2prefix;
    my %prefix2mask;
    for my $prefix (0 .. 32) {
	my $mask = 2**32 - 2**(32-$prefix);
	$mask2prefix{$mask} = $prefix;
	$prefix2mask{$prefix} = $mask;
    }

    # convert a network mask to a prefix ranging from 0 to 32
    sub print_prefix( $ ) {
	my $mask = shift;
	if(defined(my $prefix = $mask2prefix{$mask})) {
	    return $prefix;
	}
	internal_err "Network mask ", print_ip $mask, " isn't a valid prefix";
    }
}
   
# generate a list of IP strings from an ref of an array of integers
sub print_ip_aref( $ ) {
    my $aref = shift;
    return map { print_ip($_); } @$aref;
}
		
# check for xxx:xxx or xxx:xxx.xxx
sub check_typed_name() {
    use locale;		# now German umlauts are part of \w
    &skip_space_and_comment();
    if(m/(\G\w+:\w+(\.\w+)?)/gc) {
	return $1;
    } else {
	return undef;
    }
}

sub read_typed_name() {
    check_typed_name() or
	syntax_err "Typed name expected";
}

# check for xxx:xxx or xxx:[xxx] or xxx:[xxx].[xxx] or xxx:xxx.[xxx]
sub check_typed_ext_name() {
    use locale;		# now German umlauts are part of \w
    &skip_space_and_comment();
    if(m/(\G\w+:[][\w]+(\.[][\w]+)?)/gc) {
	return $1;
    } else {
	return undef;
    }
}

sub read_typed_ext_name() {
    check_typed_ext_name() or
	syntax_err "Typed extended name expected";
}

sub read_identifier() {
    use locale;		# now German umlauts are part of \w
    &skip_space_and_comment();
    if(m/(\G\w+)/gc) {
	return $1;
    } else {
	syntax_err "Identifier expected";
    }
}

# used for reading interface names
sub read_string() {
    &skip_space_and_comment();
    if(m/(\G[^;,=]+)/gc) {
	return $1;
    } else {
	syntax_err "String expected";
    }
}

sub read_description() {
    &skip_space_and_comment();
    if(&check('description')) {
	&skip('=');
	# read up to end of line, but ignore ';' at eol
	m/\G(.*);?$/gc; 
	return $1; 
    }
}

# check if one of the keywords 'permit' or 'deny' is available
sub check_permit_deny() {
    &skip_space_and_comment();
    if(m/\G(permit|deny)/gc) {
	return $1;
    } else {
	return undef;
    }
}

sub split_typed_name( $ ) {
    my($name) = @_;
    # split at first colon, thus the name may contain further colons
    split /:/, $name, 2;
}

sub check_flag( $ ) {
    my $token = shift;
    if(&check($token)) {
	&skip(';');
	return 1;
    } else {
	return undef;
    }
}

sub read_assign($&) {
    my($token, $fun) = @_;
    &skip($token);
    &skip('=');
    my $val = &$fun();
    &skip(';');
    return $val;
}

sub check_assign($&) {
    my($token, $fun) = @_;
    my $val;
    if(&check($token)) {
	&skip('=');
	$val = &$fun();
	&skip(';');
    }
    return $val;
}

sub read_list(&) {
    my($fun) = @_;
    my @vals;
    while(1) {
        push(@vals, &$fun);
	last if check ';';
	check ',';
	# allow trailing comma
	last if check ';';
    }
    return @vals;
}

sub read_list_or_null(&) {
    return () if check(';');
    &read_list(@_);
}

sub read_assign_list($&) {
    my($token, $fun) = @_;
    &skip($token);
    &skip('=');
    &read_list($fun);
}

sub check_assign_list($&) {
    my($token, $fun) = @_;
    if(&check($token)) {
	&skip('=');
	return &read_list($fun);
    }
    return ();
}

####################################################################
# Creation of typed structures
# Currently we don't use OO features;
# We use 'bless' only to give each structure a distinct type
####################################################################

# Create a new structure of given type;
# initialize it with key / value pairs
sub new( $@ ) {
    my $type = shift;
    my $self = { @_ };
    return bless($self, $type);
}

# A hash with all defined nat names.
# Is used, to check, 
# - if all defined nat mappings are used and
# - if all used mappings are defined
my %nat_definitions;

our %hosts;
sub read_host( $ ) {
    my $name = shift;
    my $host;
    my @hosts;
    &skip('=');
    &skip('{');
    my $token = read_identifier();
    if($token eq 'ip') {
	&skip('=');
	my @ip = &read_list(\&read_ip);
	if(@ip == 1) {
	    $host = new('Host', name => "host:$name", ip => $ip[0]);
	    @hosts = ($host);
	} else {
	    # a host with multiple IP addresses is represented 
	    # internally as a group of simple hosts
	    @hosts =
		map { new('Host',
			  name => "auto_host:$name",
			  ip => $_) } @ip;
	    $host = new('Group', name => "host:$name",
			elements => \@hosts, is_used => 1);
	}
    } elsif($token eq 'range') {
	&skip('=');
	my $ip1 = &read_ip;
	skip('-');
	my $ip2 = &read_ip;
	&skip(';');
	$ip1 <= $ip2 or error_atline "Invalid IP range";
	$host = new('Host',
		    name => "host:$name",
		    range => [ $ip1, $ip2 ]);
	@hosts = ($host);
    } else {
	syntax_err "Expected 'ip' or 'range'";
    }
    while(1) {
	last if &check('}');
	my($type, $name) = split_typed_name(read_typed_name());
	if($type eq 'nat') {
	    &skip('=');
	    &skip('{');
	    &skip('ip');
	    &skip('=');
	    my $nat_ip = &read_ip();
	    &skip(';');
	    &skip('}');
	    # It is sufficient to use $host and not @hosts, because
	    # NAT is currently only allowed for hosts with one IP.
	    $host->{nat}->{$name} = $nat_ip;
	} else {
	    syntax_err "Expected NAT definition";
	}
    }
    if($host->{nat}) {
	if($host->{range}) {
	    # look at print_pix_static before changing this
	    error_atline "No NAT supported for host with IP range";
	} elsif(@hosts > 1) {
	    # look at print_pix_static before changing this
	    error_atline "No NAT supported for host with multiple IPs";
	}
    }
    if(my $old_host = $hosts{$name}) {
	error_atline "Redefining host:$name";
    }
    $hosts{$name} = $host;
    return @hosts;
}

our %networks;
sub read_network( $ ) {
    my $name = shift;
    my $network = new('Network',
		      name => "network:$name",
		      file => $file);
    skip('=');
    skip('{');
    $network->{route_hint} = &check_flag('route_hint');
    $network->{subnet_of} =
	&check_assign('subnet_of', \&read_typed_name);
    my $ip;
    my $mask;
    my $token = read_identifier();
    if($token eq 'ip') {
	&skip('=');
	$ip = &read_ip;
	skip(';');
	$mask = &read_assign('mask', \&read_ip);
	# check if network ip matches mask
	if(($ip & $mask) != $ip) {
	    error_atline "$network->{name}'s IP doesn't match its mask";
	    $ip &= $mask;
	}
	$network->{ip} = $ip;
	$network->{mask} = $mask;
    } elsif($token eq 'unnumbered') {
	$ip = $network->{ip} = 'unnumbered';
	skip(';');
    } else {
	syntax_err "Expected 'ip' or 'unnumbered'";
    }
    while(1) {
	last if &check('}');
	my($type, $name) = split_typed_name(read_typed_name());
	if($type eq 'host') {
	    my @hosts = &read_host($name);
	    push(@{$network->{hosts}}, @hosts);
	} elsif($type eq 'nat') {
	    &skip('=');
	    &skip('{');
	    &skip('ip');
	    &skip('=');
	    my $nat_ip = &read_ip();
	    &skip(';');
	    my $nat_mask;
	    if(&check('mask')) {
		&skip('=');
		$nat_mask = &read_ip();
		&skip(';');
	    } else {
		# inherit mask from network
		$nat_mask = $mask;
	    }
	    my $dynamic;
	    if(&check('dynamic')) {
		&skip(';');
 		$dynamic = 1;
	    } else {
		$nat_mask == $mask or
		    error_atline "Non dynamic NAT mask must be ",
		    "equal to network mask";
	    }
	    &skip('}');
	    # check if ip matches mask
	    if(($nat_ip & $nat_mask) != $nat_ip) {
		error_atline "$network->{name}'s NAT IP doesn't ",
		"match its mask";
		$nat_ip &= $nat_mask;
	    }
	    $network->{nat}->{$name} = { ip => $nat_ip,
					 mask => $nat_mask,
					 dynamic => $dynamic };
	    $nat_definitions{$name} = 1;
	} else {
	    syntax_err "Expected NAT or host definition";
	}
    }
    # Check compatibility of host ip and network ip/mask.
    for my $host (@{$network->{hosts}}) {
	if(exists $host->{ip}) {
	    if($ip != ($host->{ip} & $mask)) {
		error_atline "Host IP doesn't match ",
		"network IP/mask";
	    }
	} elsif(exists $host->{range}) {
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
	# Link host with network
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
    &mark_ip_ranges($network);
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
    unless(&check('=')) {
	# short form of interface definition
	skip(';');
	$interface->{ip} = 'short';
    } else {
	&skip('{');
	my $token = read_identifier();
	if($token eq 'ip') {
	    &skip('=');
	    my @ip = &read_list(\&read_ip);
	    $interface->{ip} = \@ip;
	} elsif($token eq 'unnumbered') {
	    $interface->{ip} = 'unnumbered';
	    &skip(';');
	} else {
	    syntax_err "Expected 'ip' or 'unnumbered'";
	}
	while(1) {
	    last if &check('}');
	    if(my $string = &check_typed_name()) {
		my($type, $name) = split_typed_name($string);
		if($type eq 'nat') {
		    &skip('=');
		    &skip('{');
		    &skip('ip');
		    &skip('=');
		    my $nat_ip = &read_ip();
		    &skip(';');
		    &skip('}');
		    $interface->{nat}->{$name} = $nat_ip;
		} else {
		    syntax_err "Expected named attribute";
		}
	    } elsif(my $virtual =
		    &check_assign('virtual', \&read_ip)) {
		# read virtual IP for VRRP / HSRP
		$interface->{ip} eq 'unnumbered' and
		    error_atline "No virtual IP supported for ",
		    "unnumbered interface";
		grep { $_ == $virtual } @{$interface->{ip}} and
		    error_atline
			"Virtual IP redefines standard IP";
		$interface->{virtual} and
		    error_atline "Redefining virtual IP";
		$interface->{virtual} = $virtual;
		push @virtual_interfaces, $interface;
	    } elsif(my $nat =
		    &check_assign('nat', \&read_identifier)) {
		# bind NAT to an interface
		$interface->{bind_nat} and
		    error_atline "Redefining NAT binding";
		$interface->{bind_nat} = $nat;
	    } elsif(my $hardware =
		    &check_assign('hardware', \&read_string)) {
		$interface->{hardware} and
		    error_atline "Redefining hardware of interface";
		$interface->{hardware} = $hardware;
	    } elsif(my $protocol =
		    &check_assign('routing', \&read_string)) {
		unless($routing_info{$protocol}) {
		    error_atline "Unknown routing protocol";
		}
		$interface->{routing} and
		    error_atline "Redefining routing protocol";
		$interface->{routing} = $protocol;
	    } elsif(my @names =
		    &check_assign_list('reroute_permit',
				       \&read_typed_name)) {
		my @networks;
		for my $name (@names) {
		    my($type, $net) = split_typed_name($name);
		    if($type eq 'network') {
			push @networks, $net;
		    } else {
			error_atline "Expected networks as values";
		    }
		}		
		$interface->{reroute_permit} = \@networks;
	    }
	    elsif(&check_flag('disabled')) {
		$interface->{disabled} or 
		    push @disabled_interfaces, $interface;
		$interface->{disabled} = 1;
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
    skip('=');
    skip('{');
    while(1) {
	last if &check('}');
	if(&check('managed')) {
	    $router->{managed} and
		error_atline "Redefining 'managed' attribute";
	    my $managed;
	    if(&check(';')) {
		$managed = 'full';
	    } elsif(&check('=')) {
		my $value = &read_identifier();
		if($value =~ /^full|secondary$/) {
		    $managed = $value;
		}
		else {
		    error_atline "Unknown managed device type";
		}
		&check(';');
	    } else {
		&syntax_err("Expected ';' or '='");
	    }
	    $router->{managed} = $managed;
	}
	elsif(my $model =
	      &check_assign('model', \&read_identifier)) {
	    $router->{model} and
		error_atline "Redefining 'model' attribute";
	    my $info = $router_info{$model};
	    $info or error_atline "Unknown router model '$model'";
	    $router->{model} = $info;
	} elsif(&check_flag('use_object_groups')) {
	    $router->{use_object_groups} = 1;
	} else {
	    my($type,$iname) = split_typed_name(read_typed_name());
	    $type eq 'interface' or
		syntax_err "Expected interface definition";
	    my $interface = &read_interface($name, $iname);
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
	    set_pix_interface_level($router);
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
    skip('=');
    skip('{');
    my $link = &read_assign('link', \&read_typed_name);
    &skip('}');
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
    skip('=');
    skip('{');
    my $link = &read_assign('link', \&read_typed_name);
    &skip('}');
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
    skip('=');
    my @objects = &read_list_or_null(\&read_typed_ext_name);
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
   skip('=');
   my @objects = &read_list_or_null(\&read_typed_name);
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
    if(defined (my $port1 = &check_int())) {
	error_atline "Too large port number $port1" if $port1 > 65535;
	error_atline "Invalid port number '0'" if $port1 == 0;
	if(&check('-')) {
	    if(defined (my $port2 = &check_int())) {
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
    my($from, $to) = &read_port_range();
    if(&check('->')) {
	my($from2, $to2) = &read_port_range();
	$srv->{ports} = [ $from, $to, $from2, $to2 ];
    } else {
	$srv->{ports} = [ 1, 65535, $from, $to ];
    }
}

sub read_icmp_type_code() {
    my($srv) = @_;
    if(defined (my $type = &check_int())) {
	error_atline "Too large icmp type $type" if $type > 255;
	if(&check('/')) {
	    if(defined (my $code = &check_int())) {
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
	# no type, no code
    }
}

sub read_proto_nr() {
    my($srv) = @_;
    if(defined (my $nr = &check_int())) {
	error_atline "Too large protocol number $nr" if $nr > 255;
	error_atline "Invalid protocol number '0'" if $nr == 0;
	if($nr == 1) {
	    $srv->{proto} = 'icmp';
	    # no icmp type, no code
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
    &skip('=');
    if(&check('ip')) {
	$srv->{proto} = 'ip';
    } elsif(&check('tcp')) {
	$srv->{proto} = 'tcp';
	&read_port_ranges($srv);
    } elsif(&check('udp')) {
	$srv->{proto} = 'udp';
	&read_port_ranges($srv);
    } elsif(&check('icmp')) {
	$srv->{proto} = 'icmp';
	&read_icmp_type_code($srv);
    } elsif(&check('proto')) {
	&read_proto_nr($srv);
    } else {
	my $name = read_string();
	error_atline "Unknown protocol $name in definition of service:$name";
    }
    &skip(';');
    if(my $old_srv = $services{$name}) {
	error_atline "Redefining service:$name";
    }
    $services{$name} = $srv; 
}

our %policies;
our @rules;

sub read_user_or_typed_name_list( $ ) {
    my ($name) = @_;
    &skip($name);
    &skip('=');
    if(&check('user')) {
	skip(';');
	return 'user';
    } else {
	return &read_list(\&read_typed_ext_name);
    }
}

sub read_policy( $ ) {
    my($name) = @_;
    skip('=');
    skip('{');
    my $policy = { name => "policy:$name",
		   rules => [],
		   file => $file
	       };
    my $description = &read_description();
    $store_description and $policy->{description} = $description;
    my @user = &read_assign_list('user', \&read_typed_ext_name);
    $policy->{user} = \@user;
    while(1) {
	last if &check('}');
	if(my $action = check_permit_deny()) {
	    my $src = [ &read_user_or_typed_name_list('src') ];
	    my $dst = [ &read_user_or_typed_name_list('dst') ];
	    my $srv = [ &read_assign_list('srv', \&read_typed_name) ];
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
	    push(@{$policy->{rules}}, $rule);
	} else {
	    syntax_err "Expected 'permit' or 'deny'";
	}
    }
    if($policies{$name}) {
	error_atline "Redefining policy:$name";
    }
    $policies{$name} = $policy; 
}

sub read_rule( $ ) {
    my($action) = @_;
    my @src = &read_assign_list('src', \&read_typed_ext_name);
    my @dst = &read_assign_list('dst', \&read_typed_ext_name);
    my @srv = &read_assign_list('srv', \&read_typed_name);
    my $rule = { action => $action,
		 src => \@src, dst => \@dst, srv => \@srv,
		 file => $file};
    push(@rules, $rule);
    if($allow_toplevel_rules =~ /^0|warn$/) {
	my $msg = "Rule must be declared as part of policy";
	if($allow_toplevel_rules eq 'warn') {
	    warning $msg;
	} else {
	    error_atline $msg;
	}
    }
}

our %pathrestrictions;
sub read_pathrestriction( $ ) {
   my $name = shift;
   skip('=');
   my $description = &read_description();
   my @objects = &read_list_or_null(\&read_typed_name);
   @objects > 1 or
       error_atline "pathrestriction:$name must use more than one interface";
   my $restriction = new('Pathrestriction',
			 name => "pathrestriction:$name",
			 elements => \@objects,
			 file => $file);
   $store_description and $restriction->{description} = $description;
   if(my $old_restriction = $pathrestrictions{$name}) {
       error_atline "Redefining pathrestriction:$name";
   }
   $pathrestrictions{$name} = $restriction;
}

sub read_netspoc() {
    # check for definitions
    if(my $string = check_typed_name()) {
	my($type,$name) = split_typed_name($string);
	if($type eq 'router') {
	    &read_router($name);
	} elsif ($type eq 'network') {
	    &read_network($name);
	} elsif ($type eq 'any') {
	    &read_any($name);
	} elsif ($type eq 'every') {
	    &read_every($name);
	} elsif ($type eq 'group') {
	    &read_group($name);
	} elsif ($type eq 'service') {
	    &read_service($name);
	} elsif ($type eq 'servicegroup') {
	    &read_servicegroup($name);
	} elsif ($type eq 'policy') {
	    &read_policy($name);
	} elsif ($type eq 'pathrestriction') {
	    &read_pathrestriction($name);
	} else {
	    syntax_err "Unknown global definition";
	}
    } elsif(my $action = check_permit_deny()) {
	&read_rule($action);
    } elsif (check('include')) {
	my $file = read_string();
	&read_data($file, \&read_netspoc);
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
    open(FILE, $file) or die "can't open $file: $!";
    # set input buffer to defined state
    # when called from 'include:' ignore rest of line
    $_ = '';
    while(not &check_eof()) {
	&$read_syntax();
    }
}

sub read_file_or_dir( $ ) {
    my($path) = @_;
    if(-f $path) {
	read_file $path, \&read_netspoc;
    } elsif(-d $path) {
	local(*DIR);
	# strip trailing slash for nicer file names in messages
	$path =~ s./$..;
	opendir DIR, $path or die "Can't opendir $path: $!";
	while(my $file = readdir DIR) {
	    next if $file eq '.' or $file eq '..';
	    next if $file =~ m/$ignore_files/;
	    $file = "$path/$file";
	    &read_file_or_dir($file);
	}
    } else {
	die "Can't read path '$path'\n";
    }
}	
	
sub show_read_statistics() {
    my $n = keys %routers;
    info "Read $n routers";
    $n = keys %networks;
    info "Read $n networks";
    $n = keys %groups;
    info "Read $n groups";
    $n = keys %services;
    info "Read $n services";
    $n = keys %servicegroups;
    info "Read $n service groups";
    $n = keys %policies;
    info "Read $n policies";
    $n = @rules;
    info "Read $n rules" if $n;
}

##############################################################################
# Helper functions
##############################################################################

# Type checking functions
sub is_network( $ )          { ref($_[0]) eq 'Network'; }
sub is_router( $ )       { ref($_[0]) eq 'Router'; }
sub is_interface( $ )    { ref($_[0]) eq 'Interface'; }
sub is_host( $ )         { ref($_[0]) eq 'Host'; }
sub is_any( $ )          { ref($_[0]) eq 'Any'; }
sub is_every( $ )        { ref($_[0]) eq 'Every'; }
sub is_group( $ )        { ref($_[0]) eq 'Group'; }
sub is_servicegroup( $ ) { ref($_[0]) eq 'Servicegroup'; }
sub is_objectgroup( $ )  { ref($_[0]) eq 'Objectgroup'; }

sub print_rule( $ ) {
    my($rule) = @_;
    my $extra = '';;
    $extra .= " $rule->{for_router}" if $rule->{for_router};
    $extra .= " stateless" if $rule->{stateless};
    if($rule->{orig_any}) { $rule = $rule->{orig_any}; }
    my $srv = exists($rule->{orig_srv}) ? 'orig_srv' : 'srv';
    return $rule->{action} .
	" src=$rule->{src}->{name}; dst=$rule->{dst}->{name}; " .
	"srv=$rule->{$srv}->{name};$extra";
}

####################################################################
# Try to convert hosts with successive IP addresses to an IP range
####################################################################

# Find IP ranges in a list of sorted hosts
# Call a function on each range
sub process_ip_ranges( $$ ) {
    my($sorted, $fun) = @_;
    # Add a dummy host which doesn't match any range, to simplify the code: 
    # we don't have to process any range after the loop has finished
    push @$sorted, {ip => 0 };
    my $start_range = 0;
    my $prev_ip = $sorted->[0]->{ip};
    for(my $i = 1; $i < @$sorted; $i++) {
	my $host = $sorted->[$i];
	my $ip = $host->{ip};
	# continue current range
	if($ip == $prev_ip + 1 or $ip == $prev_ip) {
	    $prev_ip = $ip;
	} else {
	    my $end_range = $i - 1;
	    # found a range with at least 2 elements
	    if($start_range < $end_range) {
		# This may be a range with all identical IP addresses.
		# This is useful if we have different hosts with 
		# identical IP addresses
		&$fun($sorted, $start_range, $end_range);
	    }
	    # start a new range
	    $start_range = $i;
	    $prev_ip = $ip;
	}
    }
    # remove the dummy 
    pop @$sorted;
}

# Called from read_network.
# Works on the hosts of a network.
# Selects hosts, not ranges,
# detects successive IP addresses and links them to an 
# anonymous hash which is used to collect IP ranges later.
# ToDo: augment existing ranges by hosts or other ranges
# ToDo: support chains of network > range > range .. > host
# Hosts with an explicit NAT definition are left out from this optimization
sub mark_ip_ranges( $ ) {
    my($network) = @_;
    my @hosts = grep { $_->{ip} and not $_->{nat} } @{$network->{hosts}};
    my @ranges = grep { $_->{range} } @{$network->{hosts}};
    return unless @hosts;
    @hosts = sort { $a->{ip} <=> $b->{ip} } @hosts;
    my $fun = sub {
	my($aref, $start_range, $end_range) = @_;
	my $range_mark = {};
	# mark hosts of range
	for(my $j = $start_range; $j <= $end_range; $j++) {
	    $aref->[$j]->{range_mark} = $range_mark;
	}
	# fill range_mark with predefined ranges for later substitution
	my $begin = $aref->[$start_range]->{ip};
	my $end = $aref->[$end_range]->{ip};
	for my $range (@ranges) {
	    my($ip1, $ip2) = @{$range->{range}};
	    if($begin <= $ip1 and $ip2 <= $end) {
		$range_mark->{$ip1}->{$ip2} = $range;
	    }
	}
    };
    process_ip_ranges \@hosts, $fun;
}

# Called from expand_group
# Checks, if a group of network objects contains hosts which may be converted
# to an IP range
sub gen_ip_ranges( $ ) {
    my($obref) = @_;
    my @hosts_in_range = grep { is_host $_ and $_->{range_mark} } @$obref;
    if(@hosts_in_range) {
	my @objects = grep { not is_host $_ } @$obref;
	# we want to have hosts and ranges together in generated code
	my @hosts = grep { is_host $_ and not $_->{range_mark} } @$obref;
	my %in_range;
	# collect host belonging to one range
	for my $host (@hosts_in_range) {
	    my $range_mark = $host->{range_mark};
	    push @{$in_range{$range_mark}}, $host;
	}
	for my $aref (values %in_range) {
	    my $fun = sub {
		my($aref, $start_range, $end_range) = @_;
		my $begin = $aref->[$start_range]->{ip};
		my $end = $aref->[$end_range]->{ip};
		my $range_mark = $aref->[$start_range]->{range_mark};
		my $range;
		unless($range = $range_mark->{$begin}->{$end}) {
		    (my $name = $aref->[$start_range]->{name}) =~
			s/^.*:/auto_range:/;
		    $range = 
			new('Host',
			    name => $name,
			    range => [ $begin, $end ],
			    network => $aref->[$start_range]->{network},
			    # remember original hosts for later reference
			    orig_hosts => [ @$aref[$start_range .. $end_range] ],
			    );
		    $range_mark->{$begin}->{$end} = $range;
		}
		# substitute first host with range
		$aref->[$start_range] = $range;
		# mark other hosts of range as deleted
		for(my $j = $start_range+1; $j <= $end_range; $j++) {
		    $aref->[$j] = undef;
		}
	    };
	    my @sorted = sort { $a->{ip} <=> $b->{ip} } @$aref;
	    process_ip_ranges \@sorted, $fun;
	    push @hosts, grep { defined $_ } @sorted;
	}
	# make the result deterministic
	push @objects, sort { ($a->{ip} || $a->{range}->[0]) <=>
				  ($b->{ip} || $b->{range}->[0]) } @hosts;
	return \@objects;
    } else {
	return $obref;
    }
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

# we need service "ip" later for secondary rules
my $srv_ip;
# We need service "tcp established" later for reverse rules
my $srv_tcp_established = 
{ name => 'reverse:TCP_ANY',
  proto => 'tcp',
  ports => [ 1,65535, 1,65535 ],
  established => 1
  };

# Order services. We need this to order any rules for not 
# influencing themselves.
# Additionally add
# - one TCP "established" service and 
# - reversed UDP services 
# for generating reverse rules later.
sub order_services() {
    for my $srv (values %services) {
	&prepare_srv_ordering($srv);
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
#	info "$srv->{name} < $srv->{up}->{name}" if $srv->{up};
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
	    my $router = $routers{$name};
	    $router and $router->{managed} and
		err_msg "$obj->{name} must not be linked to managed $router->{name}";
	    $obj->{link} = $router;
	} else {
	    err_msg "$obj->{name} must not be linked to '$type:$name'";
	}
	$obj->{link} or
	    err_msg "Referencing undefined $type:$name from $obj->{name}";
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
	$interface->{disabled} = 1;
	return;
    }
    $interface->{network} = $network;
    if($interface->{reroute_permit}) {
	for my $net (@{$interface->{reroute_permit}}) {
	    my $network = $networks{$net};
	    unless($network) {
		err_msg "Referencing undefined network:$net ",
		"from attribute 'reroute_permit' of $interface->{name}";
		# prevent further errors
		$interface->{disabled} = 1;
	    }
	    $net = $network;
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
	for my $string (@{$restrict->{elements}}) {
	    my($type, $name) = split_typed_name($string);
	    if($type eq 'interface') {
		if(my $interface = $interfaces{$name}) {
		    # Multiple restrictions may be applied to a single 
		    # interface.
		    push @{$interface->{path_restrict}}, $restrict;
		    # Substitute interface name by interface object.
		    $string = $interface;
		} else {
		    err_msg "Referencing undefined $type:$name ", 
		    "from $restrict->{name}";
		}
	    } else {
		err_msg "$restrict->{name} must not reference '$type:$name'";
	    }
	}
    }
}

sub link_topology() {
    &link_any_and_every();
    for my $interface (values %interfaces) {
	&link_interface_with_net($interface);
    }
    &link_pathrestrictions();
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
	    next if $ips eq 'unnumbered';
	    if($ips eq 'short') {
		$short_intf = $interface;
		$route_intf and
		    err_msg "$short_intf->{name} must be given an IP address, since there is\n",
		    " a managed $route_intf->{name} with static routing enabled.";
		next;
	    }
	    if($interface->{router}->{managed} and not $interface->{routing}) {
		$route_intf = $interface;
		$short_intf and
		    err_msg "$short_intf->{name} must be given an IP address, since there is\n",
		    " a managed $route_intf->{name} with static routing enabled.";
	    }
	    for my $ip (@$ips) {
		if(my $old_intf = $ip{$ip}) {
		    warning "Duplicate IP address for $old_intf->{name}",
		    " and $interface->{name}";
		}
		$ip{$ip} = $interface;
	    }
	}
#	for my $host (@{$network->{hosts}}) {
#	    if(my $ip = $host->{ip}) {
#		if(my $old_intf = $ip{$ip}) {
#		    err_msg "Duplicate IP address for $old_intf->{name}",
#		    " and $host->{name}";
#		}
#	    } elsif(my $range = $host->{range}) {
#		for(my $ip = $range->[0]; $ip <= $range->[1]; $ip++) {
#		    if(my $old_intf = $ip{$ip}) {
#			err_msg "Duplicate IP address for $old_intf->{name}",
#			" and $host->{name}";
#		    }
#		}
#	    }
#	}
	next unless $network->{subnet_of};
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
 router => \%routers,
 any => \%anys,
 every => \%everys,
 group => \%groups
 );

my @all_anys;
my @managed_routers;

# Initialize 'special' objects which implicitly denote a group of objects.
#
# interface:[managed].[all], group of all interfaces of managed routers
# interface:[managed].[auto], group of [auto] interfaces of managed routers
# interface:[all].[all], all routers, all interfaces
# interface:[all].[auto], all routers, [auto] interfaces
# any:[all], group of all security domains
sub set_auto_groups () {
    my @all_routers;
    my @managed_interfaces;
    my @all_interfaces;
    for my $router (values %routers) {
	my @interfaces = grep { not $_->{ip} eq 'unnumbered' } @{$router->{interfaces}};
	if($router->{managed}) {
	    push @managed_routers, $router;
	    push @managed_interfaces, @interfaces;
	}
	push @all_routers, $router;
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
	    elements => \@all_routers, is_used => 1);
    @all_anys or internal_err "\@all_anys is empty";
    $anys{'[all]'} = 
	new('Group', name => "any:[all]",
	    elements => \@all_anys, is_used => 1);
    # Artificial 'any' object, denotes the 'any' object,
    # which is directly attached to an interface.
    # String is expanded to a real 'any' object in expand_rules.
    $anys{'[local]'} = 	"any:[local]";
}

# Get a reference to an array of network object names and 
# return a reference to an array of network objects
sub expand_group( $$ ) {
    my($obref, $context) = @_;
    my @objects;
    for my $tname (@$obref) {
	# rename router:xx to interface:xx.[all]
	# to preserve compatibility with older versions
	$tname =~ s/^router:(.*)$/interface:$1.[all]/;
	my($type, $name) = split_typed_name($tname);
	my $object;
	unless($object = $name2object{$type}->{$name} or
	       $type eq 'interface' and
	       $name =~ /^(.*)\.\[auto\]$/ and
	       $object = $routers{$1}) {
	    err_msg "Can't resolve reference to '$tname' in $context";
	    next;
	}
	# split a group into its members
	if(is_group $object) {
	    my $elements = $object->{elements};
	    # check for recursive definitions
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
		$elements = &expand_group($elements, $tname);
		# cache result for further references to the same group
		$object->{elements} = $elements;
	    }
	    push @objects, @$elements;
	} elsif(is_every $object) {
	    # expand an 'every' object to all networks in its security domain
	    # Attention: this doesn't include unnumbered networks
	    push @objects,  @{$object->{link}->{any}->{networks}};
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
    @objects = grep { defined $_ } @objects;
    return gen_ip_ranges(\@objects);
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
		# check if it has already been converted
		# from names to references
		elsif(not $srvgroup->{is_used}) {
		    # detect recursive definitions
		    $srvgroup->{elements} = 'recursive';
		    $srvgroup->{is_used} = 1;
		    $elements = &expand_services($elements, $tname);
		    # cache result for further references to the same group
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
# hash for ordering all rules:
# $rule_tree{$action}->{$src}->[0]->{$dst}->[0]->{$srv} = $rule;
# see &add_rule for details
my %rule_tree;

sub expand_rules() {
    info "Expanding rules";
    # Prepare special groups
    set_auto_groups();
    for my $name (sort keys %policies) {
	my $policy = $policies{$name};
	my $user = $policy->{user};
	for my $p_rule (@{$policy->{rules}}) {
	    # New hash with identical keys and values
	    my $rule = { %$p_rule };
	    if($rule->{src} eq 'user') {
		$rule->{src} = $user;
	    } else {
		$p_rule->{src} = expand_group $p_rule->{src}, "src of rule in $policy->{name}";
	    }
	    if($rule->{dst} eq 'user') {
		$rule->{dst} = $user;
	    } else {
		$p_rule->{dst} = expand_group $p_rule->{dst}, "dst of rule in $policy->{name}";
	    }
	    # remember original policy
	    $rule->{policy} = $policy;
	    # ... and remember original rule
	    $rule->{p_rule} = $p_rule;
	    push @rules, $rule;
	}
	$policy->{user} = expand_group $policy->{user}, "user of $policy->{name}";
    }
    for my $rule (@rules) {
	my $action = $rule->{action};
	my $policy = $rule->{policy};
	$rule->{src} = expand_group $rule->{src}, 'src of rule';
	$rule->{dst} = expand_group $rule->{dst}, 'dst of rule';
	$rule->{srv} = expand_services $rule->{srv}, 'rule';

	my $get_any_local = sub ( $ ) {
	    my ($obj) = @_;
	    if(is_interface $obj and $obj->{router}->{managed}) {
		return $obj->{any};
	    } else {
		err_msg "any:[local] must only be used in conjunction with an\n",
		" managed interface in $rule->{policy}->{name}";
		# Continue with an valid value to prevent further errors.
		if($obj eq 'any:[local]') {
		    $rule->{deleted} = 1;
		    return $obj;
		}elsif(is_any $obj) {
		    return $obj;
		}elsif(is_network $obj) {
		    return $obj->{any};
		}elsif(is_host $obj || is_interface $obj) {
		    return $obj->{network}->{any};
		} else {
		    internal_err;
		}
	    }
	};
	for my $src (@{$rule->{src}}) {
	    for my $dst (@{$rule->{dst}}) {
		
		my @src = is_router $src ?
		    path_first_interfaces $src, $dst :
			$src eq 'any:[local]' ? $get_any_local->($dst) : ($src);
		my @dst = is_router $dst ?
		    path_first_interfaces $dst, $src :
			$dst eq 'any:[local]' ? $get_any_local->($src) : ($dst);
		for my $src (@src) {
		    for my $dst (@dst) {
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
				$expanded_rule->{deny_networks} = [];
				push(@expanded_any_rules, $expanded_rule);
			    } else {
				push(@expanded_rules, $expanded_rule);
			    }
			    &add_rule($expanded_rule);
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

####################################################################
# Order 'any' rules
#
# Rules with an 'any' object as src or dst will be augmented with
# deny_networks later. deny_networks expand to deny rules
# during code generation. Such an automatically generated deny rule
# should only influence the 'any' rule it is attached to.
# To minimize the risk that deny_networks influence
# an unrelated 'any' rule, we order 'any' rules such that 'large'
# rules are placed below 'small' rules.
####################################################################

# We put 'any' rules into a hash which eases building an ordered
# list of 'any' rules with 'smaller' rules coming first:
# - First, rules are ordered by their srv part, 
#   smaller services coming first.
# - Next, rules are ordered by src and dst:
#  - any host
#  - host any
#  - any network
#  - network any
#  - any any
# Note:
# TCP and UDP port ranges may be not orderable if they are overlapping.
# If necessary, we split ranges and their corresponding rules
# into smaller pieces to make them orderable.

sub typeof( $ ) {
    my($ob) = @_;
    if(is_host($ob) or is_interface($ob)) {
	return 'host';
    } elsif(is_network($ob)) {
	return 'network';
    } elsif(is_any($ob)) {
	return 'any';
    } else {
	internal_err "expected host|network|any but got '$ob->{name}'";
    }
}

sub order_any_rules2 ( @ ) {
    my %ordered_any_rules;
    for my $rule (@_) {
	my $depth = $rule->{srv}->{depth};
	defined $depth or internal_err "no depth for $rule->{srv}->{name}";
	my $srcid = typeof($rule->{src});
	my $dstid = typeof($rule->{dst});
	push @{$ordered_any_rules{$depth}->{$srcid}->{$dstid}}, $rule;
    }

    # counter for sorted permit any rules
    my $anyrule_index = 0;
    my @result;
    # add all rules with matching srcid and dstid to result
    my $get_rules_from_hash = sub ( $$$ ) {
	my($hash, $srcid, $dstid) = @_;
	my $rules_aref = $hash->{$srcid}->{$dstid};
	if(defined $rules_aref) {
	    for my $rule (@$rules_aref) {
		# add an incremented index to each any rule
		# for simplifying a later check if one rule
		# influences another one
		$rule->{i} = $anyrule_index++;
		push(@result, $rule);
	    }
	}
    };

    for my $depth (reverse sort keys %ordered_any_rules) {
	my $hash = $ordered_any_rules{$depth};
	next unless defined $hash;
	&$get_rules_from_hash($hash, 'any','host');
	&$get_rules_from_hash($hash, 'host','any');
	&$get_rules_from_hash($hash, 'any','network');
	&$get_rules_from_hash($hash, 'network','any');
	&$get_rules_from_hash($hash, 'any','any');
    }
    return @result;
}

sub order_any_rules () {
    @expanded_any_rules = order_any_rules2 @expanded_any_rules;
}

####################################################################
# Repair deny influence
#
# After ordering permit 'any' rules and inserting of deny_networks 
# we have to check for one pathological case, were a deny_network
# influences an unrelated 'any' rule, i.e. some packets are denied
# although they should be permitted.
# Example:
# 1. deny	net1  host2
# 2. permit	any   host2
# 3. permit	host1 any	 with host1 < net1
# Problem: Traffic from host1 to host2 is denied by rule 1 and
# permitted by rule 3.
# But rule 1 is only related to rule 2 and must not deny traffic
# which is allowed by rule 3
# Solution: 
# add additional rule 0
# 0. permit	host1 host2
# 1. deny	net1  host2
# 2. permit	any   host2
# 3. permit	host1 any
####################################################################

# we don't need to handle secondary services, they have been substituted
# via ->{main} in expand_rules
sub ge_srv( $$ ) {
    my($s1, $s2) = @_;
    $s1 eq $s2 and return 1;
    $s1->{depth} >= $s2->{depth} and return 0;
    while(my $up = $s2->{up}) {
	return 1 if $up eq $s1;
	$s2 = $up;
    }
    return 0;
}

#
# any3--net1/host1--any2/net2/host2--
#
# search for
# deny 	    net1  host2 <-- $net
# permit    any3  host2 <-- $arule
# permit    host1 any2  <-- $rule
# with host1 < net1, any2 > host2
# ToDo: May the deny rule influence any other rules where
# dst is some 'any' object not in relation to host2 ?
# I think not.
sub repair_deny_influence1( $$ ) {
    my($any_rules_ref, $normal_rules_ref) = @_;
    for my $erule (@$any_rules_ref) {
	next unless exists $erule->{any_rules};
	my $dst = $erule->{dst};
	next unless
	    is_host $dst or
	    is_interface $dst and
	    # we don't need to repair anything for rules with an managed
	    # interface as dst, since permission to access an 'any' object
	    # doesn't imply permission to access an managed interface
	    # lying at the border of the security domain.
	    not $dst->{router}->{managed};
	# Check those 'any' rules which are generated for all 'any' objects
	# on the path from src 'any' object to dst.
	# Note: $erule->{dst} eq $arule->{dst}
	for my $arule (@{$erule->{any_rules}}) {
	    # ToDo: think twice if we have an unexpected relation with
	    # code generation of deleted interface rules
	    next if $arule->{deleted};
	    next unless $arule->{deny_networks};
	    my $dst_any = $dst->{network}->{any} or
		internal_err "No 'any' object in security domain of $dst";
	    for my $net (@{$arule->{deny_networks}}) {
		for my $host (@{$net->{hosts}}, @{$net->{interfaces}}) {
		    # Don't repair, even if managed interface is src
		    next if is_interface $host and $host->{router}->{managed};
		    # search for rules with action = permit, src = host and
		    # dst = dst_any in %rule_tree
		    my $src_hash = $rule_tree{permit};
		    next unless $src_hash;
		    # do we have any rule with src = host ?
		    next unless $src_hash->{$host};
		    # do we have any rule with dst = dst_any ?
		    next unless $src_hash->{$host}->[0]->{$dst_any};
		    my $srv_hash = $src_hash->{$host}->[0]->{$dst_any}->[0];
		    # get all rules, srv doesn't matter
		    for my $rule (values %$srv_hash) {
			# ToDo: see above
			next if $rule->{deleted};
#		    print STDERR "Got here:\n $net->{name}\n ",
#		    print_rule $arule,"\n ",
#		    print_rule $rule,"\n";
			# we are only interested in rules behind the 'any' rule
			next unless $rule->{i} > $erule->{i};
			next unless ge_srv($rule->{srv}, $arule->{srv});
			my $src = $rule->{src};
			next if is_interface $src and is_interface $dst and
			    $src->{router} eq $dst->{router};
			my $hrule = { action => 'permit',
				      src => $src,
				      dst => $dst,
				      srv => $arule->{srv},
				      stateless => $arule->{stateless}
				  };
			push @$normal_rules_ref, $hrule;
		    }
		}
	    }
	}
    }
}

sub repair_deny_influence() {
    info "Repairing deny influence";
    repair_deny_influence1 \@expanded_any_rules, \@expanded_rules;
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
sub disable_behind( $ ) {
    my($incoming) = @_;
    $incoming->{disabled} = 1;
    my $network = $incoming->{network};
    # stop, if we found a loop
    return if $network->{disabled};
    $network->{disabled} = 1;
    for my $host (@{$network->{hosts}}) {
	$host->{disabled} = 1;
    }
    for my $interface (@{$network->{interfaces}}) {
	next if $interface eq $incoming;
	$interface->{disabled} = 1;
	my $router = $interface->{router};
	# stop, if we found a loop
	return if $router->{disabled};
	$router->{disabled} = 1;
	# a disabled router must not be managed
	if($router->{managed}) {
	    $router->{managed} = 0;
	    warning "Disabling managed $router->{name}";
	}
	for my $outgoing (@{$router->{interfaces}}) {
	    next if $outgoing eq $interface;
	    if($outgoing->{disabled}) {
		# We found an already disabled interface,
		# but its router was not disabled.
		# Hence, we reached an initial element 
		# of @disabled_interfaces, which seems to 
		# be part of a loop. 
		# This is dangerous, since the whole topology 
		# may be disabled by accident.
		err_msg "$outgoing->{name} must not be disabled,\n",
		"since it is part of a loop";
		next;
	    }
	    &disable_behind($outgoing);
	}
    }
}	

sub mark_disabled() {
    for my $interface (@disabled_interfaces) {
	disable_behind($interface);
    }
    for my $interface (@disabled_interfaces) {
	# if we expand a router later to its set of interfaces,
	# don't add disabled interfaces.
	my $router = $interface->{router};
	&aref_delete($interface, $router->{interfaces});
    }
    for my $any (values %anys, values %everys) {
	$any->{disabled} = 1 if $any->{link}->{disabled};
    }
}

####################################################################
# Find subnetworks
# Mark each network with the smallest network enclosing it
# Mark each network which encloses some other network
####################################################################
sub find_subnets() {
    info "Finding subnets";
    my %mask_ip_hash;
    for my $network (values %networks) {
	next if $network->{ip} eq 'unnumbered';
	next if $network->{disabled};
	# Ignore a network, if NAT is defined for it
	# ToDo: do a separate calculation for each NAT domain
	next if $network->{nat} and %{$network->{nat}};
	if(my $old_net = $mask_ip_hash{$network->{mask}}->{$network->{ip}}) {
	    err_msg "$network->{name} and $old_net->{name} have identical ip/mask";
	}
	$mask_ip_hash{$network->{mask}}->{$network->{ip}} = $network;
    }
    # go from smaller to larger networks
    for my $mask (reverse sort keys %mask_ip_hash) {
	# network 0.0.0.0/0.0.0.0 can't be subnet
	last if $mask == 0;
	for my $ip (keys %{$mask_ip_hash{$mask}}) {
	    my $m = $mask;
	    my $i = $ip;
	    while($m) {
		$m <<= 1;
		$i &= $m;
		if($mask_ip_hash{$m}->{$i}) {
		    my $bignet = $mask_ip_hash{$m}->{$i};
		    $bignet->{enclosing} = 1;
		    my $subnet = $mask_ip_hash{$mask}->{$ip};
		    $subnet->{is_in} = $bignet;
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
		    # we only need to find the smallest enclosing network
		    last;
		}
	    }
	}
    }
    # we must not set an arbitrary default route if a network 0.0.0.0/0 exists
    if($auto_default_route && $mask_ip_hash{0}->{0}) {
	err_msg "\$auto_default_route must not be activated,",
	" because $mask_ip_hash{0}->{0}->{name} has IP address 0.0.0.0";
	$auto_default_route = 0;
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

sub setany_network( $$$ ) {
    my($network, $any, $in_interface) = @_;
    if($network->{any}) {
	# Found a loop inside a security domain
	return;
    }
    $network->{any} = $any;
    # Add network to the corresponding 'any' object,
    # to have all networks of a security domain available.
    # Unnumbered networks are left out here because
    # they aren't a valid src or dst
    push(@{$any->{networks}}, $network)
	unless $network->{ip} eq 'unnumbered';
    for my $interface (@{$network->{interfaces}}) {
	# ignore interface where we reached this network
	next if $interface eq $in_interface;
	&setany_router($interface->{router}, $any, $interface);
    }
}
 
sub setany_router( $$$ ) {
    my($router, $any, $in_interface) = @_;
    if($router->{managed}) {
	$in_interface->{any} = $any;
	push @{$any->{interfaces}}, $in_interface;
	return;
    }
    if($router->{any}) {
	# Found a loop inside a security domain
	return;
    }
    for my $interface (@{$router->{interfaces}}) {
	# ignore interface where we reached this router
	next if $interface eq $in_interface;
	next if $interface->{disabled};
	&setany_network($interface->{network}, $any, $interface);
    }
}

sub setany() {
    @all_anys = grep { not $_->{disabled} } values %anys;
    for my $any (@all_anys) {
	$any->{networks} = [];
	my $obj = $any->{link};
	if(my $old_any = $obj->{any}) {
	    err_msg
		"More than one 'any' object defined in a security domain:\n",
		" $old_any->{name} and $any->{name}";
	}
	if(is_network $obj) {
	    setany_network $obj, $any, 0;
	} elsif(is_router $obj) {
	    setany_router $obj, $any, 0;
	} else {
	    internal_err "unexpected object $obj->{name}";
	}
	# make results deterministic
	@{$any->{networks}} =
	    sort { $a->{ip} <=> $b->{ip} } @{$any->{networks}};
    }

    # automatically add an 'any' object to each security domain
    # where none has been declared
    for my $network (values %networks) {
	next if $network->{any};
	next if $network->{disabled};
	(my $name = $network->{name}) =~ s/^network:/auto_any:/;
	my $any = new('Any', name => $name, link => $network);
	$any->{networks} = [];
	push @all_anys, $any;
	setany_network $network, $any, 0;
	# make results deterministic
	@{$any->{networks}} =
	    sort { $a->{ip} <=> $b->{ip} } @{$any->{networks}};
    }
}
	
####################################################################
# Set paths for efficient topology traversal
####################################################################

# collect all networks and routers lying inside a cyclic graph
my @loop_objects;

sub setpath_obj( $$$ ) {
    my($obj, $to_net1, $distance) = @_;
#    info("-- $distance: $obj->{name} --> $to_net1->{name}");
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
	if(my $loop = &setpath_obj($next, $interface, $distance+1)) {
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
#	info "Loop($obj->{distance}): $obj->{name} -> $loop_start->{name}";
	unless($obj eq $loop_start) {
	    # We are still inside a loop
	    return $loop_start;
	}
    }
    $obj->{main} = $to_net1;
    return 0;
}

sub setpath() {
    info "Preparing fast path traversal";
    # take a random network from %networks, name it "net1"
    my $net1 = (values %networks)[0] or die "Topology seems to be empty\n";

    # Starting with net1, do a traversal of the whole topology
    # to find a path from every network and router to net1.
    # "xxx" is used as placeholder for a starting interface.
    setpath_obj($net1, "xxx", 2);

    # check, if all networks are connected with net1 
    for my $network (values %networks) {
	next if $network eq $net1;
	next if $network->{disabled};
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
#	    info "adjusting $obj->{name} loop to $loop->{name}";
	    $obj->{loop} = $loop;
	}
#	info "adjusting $obj->{name} distance to $loop->{distance}";
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
            err_msg "Virtual IP: Missing second interface for $i1->{name}";
        } 
    }
    
    # Check that interfaces with pathrestriction are located inside 
    # of cyclic graphs
    for my $restrict (values %pathrestrictions) {
	for my $interface (@{$restrict->{elements}}) {
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
    if(is_host $obj or is_interface $obj) {
	return $obj->{network};
    } elsif(is_network $obj) {
	return $obj;
    } elsif(is_any $obj) {
	return @{$obj->{networks}};
    } else {
	internal_err "unexpected $obj->{name}";
    }
}
 
sub get_path( $ ) {
    my($obj) = @_;
    if(is_host($obj)) {
	return $obj->{network};
    } elsif(is_interface($obj)) {
	return $obj->{router};
    } elsif(is_network($obj)) {
	return $obj;
    } elsif(is_any($obj)) {
	# take one random network of this security domain
	return $obj->{networks}->[0];
    } elsif(is_router($obj)) {
	# this is only used, when called from 
	# find_active_routes_and_statics or from get_auto_interfaces
	return $obj;
    } else {
	internal_err "unexpected $obj->{name}";
    }
}

# converts hash key of reference back to reference
my %key2obj;

sub loop_path_mark1( $$$$$ ) {
    my($obj, $in_intf, $from, $to, $collect) = @_;
    # Check for second occurrence of path restriction.
    for my $restrict (@{$in_intf->{path_restrict}}) {
	if($restrict->{active_path}) {
#	    info " effective $restrict->{name} at $in_intf->{name}";
	    return 0;
	}
    }
    # Found a path to $to.
    if($obj eq $to) {
	# Mark interface where we leave the loop.
	push @{$to->{loop_leave}->{$from}}, $in_intf;
#	info " leave: $in_intf->{name} -> $to->{name}";
	return 1;
    }
    # Don't walk loops.
    return 0 if $obj->{active_path};
    # Mark current path for loop detection.
    $obj->{active_path} = 1;
    # Mark first occurrence of path restriction.
    for my $restrict (@{$in_intf->{path_restrict}}) {
#	info " enabled $restrict->{name} at $in_intf->{name}";
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
	if(&loop_path_mark1($next, $interface, $from, $to, $collect)) {
	    # Found a valid path from $next to $to
	    $key2obj{$interface} = $interface;
	    $collect->{$in_intf}->{$interface} = is_router $obj;
#	    info " loop: $in_intf->{name} -> $interface->{name}";
            $success = 1;
        }
    }
    delete $obj->{active_path};
    for my $restrict (@{$in_intf->{path_restrict}}) {
#	info " disabled $restrict->{name} at $in_intf->{name}";
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
#   info "loop_path_mark: $from->{name} -> $to->{name}";
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
#	    info " enter: $from->{name} -> $interface->{name}";
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
#    info "path_mark $from->{name} --> $to->{name}";
    while(1) {
	$from and $to or internal_err "";
	# paths meet outside a loop or at the edge of a loop
	if($from eq $to) {
#	    info " $from_in->{name} -> ".($to_out?$to_out->{name}:'');
	    $from_in->{path}->{$dst} = $to_out;
	    return;
	}
	# paths meet inside a loop	
	if($from_loop and $to_loop and $from_loop eq $to_loop) {
	    loop_path_mark($from, $to, $from_in, $to_out, $dst);
	    return;
	}
	$from->{distance} and $to->{distance} or internal_err "";
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
#	    info " $from_in->{name} -> ".($from_out?$from_out->{name}:'');
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
#	    info " $to_in->{name} -> ".($to_out?$to_out->{name}:'');
	    $to_in->{path}->{$dst} = $to_out;
	    $to_out = $to_in;
	    $to = $to_in->{main};
	    $to_loop = $to->{loop};
	}
    }
}

# Walk paths inside cyclic graph
sub loop_path_walk( $$$$$$$ ) {
    my($in, $out, $loop_entry, $loop_exit, $call_at_router, $rule, $fun) = @_;
#    my $info = "loop_path_walk: ";
#    $info .= "$in->{name}->" if $in;
#    $info .= "$loop_entry->{name}->$loop_exit->{name}";
#    $info .= "->$out->{name}" if $out;
#    info $info;
    # Process entry of cyclic graph
    if(is_router($loop_entry) eq $call_at_router) {
#	info " loop_enter";
	for my $out_intf (@{$loop_entry->{loop_enter}->{$loop_exit}}) {
	    &$fun($rule, $in, $out_intf);
	}
    }
    # Process paths inside cyclic graph
    my $tuples = $loop_entry->{path_tuples}->{$loop_exit};
#    info " loop_tuples";
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
#	info " loop_leave";
	for my $in_intf (@{$loop_exit->{loop_leave}->{$loop_entry}}) {
	    &$fun($rule, $in_intf, $out);
	}
    }
}    

sub path_info ( $$ ) {
    my ($in_intf, $out_intf) = @_;
    my $in_name = $in_intf?$in_intf->{name}:'-';
    my $out_name = $out_intf?$out_intf->{name}:'-';
    info " Walk: $in_name, $out_name";
}
    
# Apply a function to a rule at every router or network
# on the path from src to dst of the rule.
# $where says, where the function gets called: at 'Router' or 'Network'.
sub path_walk( $&$ ) {
    my ($rule, $fun, $where) = @_;
    internal_err "undefined rule" unless $rule;
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $from = get_path $src;
    my $to =  get_path $dst;
#    info print_rule $rule;
#    info(" start: $from->{name}, $to->{name}" . ($where?", at $where":''));
#    my $fun2 = $fun;
#    $fun = sub ( $$$ ) { 
#	my($rule, $in, $out) = @_;
#	path_info $in, $out;
#	&$fun2($rule, $in, $out);
#    };
    if($from eq $to) {
	# don't process rule again later
	$rule->{deleted} = $rule;
	return;
    }
    path_mark($from, $to) unless $from->{path}->{$to};
    my $in = undef;
    my $out;
    my $at_router = not($where && $where eq 'Network');
    my $call_it = (is_network($from) xor $at_router);
    if(my $loop_exit = $from->{loop_exit}->{$to}) {
	my $loop_out = $from->{path}->{$to};
	loop_path_walk $in, $loop_out, $from, $loop_exit,
	$at_router, $rule, $fun;
	unless($loop_out) {
#	    info "exit: path_walk: dst in loop";
	    return;
	}
	# continue behind loop
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
#	    info "exit: path_walk: reached dst";
	    return;
	}
	$call_it = ! $call_it;
	$in = $out;
	if(my $loop_entry = $in->{loop_entry}->{$to}) {
	    my $loop_exit = $loop_entry->{loop_exit}->{$to};
	    my $loop_out = $in->{path}->{$to};
	    loop_path_walk $in, $loop_out, $loop_entry, $loop_exit,
	    $at_router, $rule, $fun;
	    # path terminates inside cyclic graph
	    unless($loop_out) {
#	    info "exit: path_walk: dst in loop";
		return;
	    }
	    $in = $loop_out;
	    $call_it = not (is_network($loop_exit) xor $at_router);
	}
	$out = $in->{path}->{$to};
    }
}

sub path_first_interfaces( $$ ) {
    my ($from, $to) = @_;
    $from = &get_path($from);
    $to = &get_path($to);
    &path_mark($from, $to) unless $from->{path}->{$to};
    if(my $exit = $from->{loop_exit}->{$to}) {
#	info "$from->{name}.[auto] = ".join ',', map {$_->{name}} @{$from->{loop_enter}->{$exit}};
	return @{$from->{loop_enter}->{$exit}};
    } else {
#	info "$from->{name}.[auto] = $from->{path}->{$to}->{name}";
	return ($from->{path}->{$to});
    }
}

##############################################################################
# Convert semantics of rules with an 'any' object as source or destination
# from high-level to low-level:
# (A) rule "permit any:X dst"
# high-level: all networks of security domain X get access to dst
# low-level: like above, but additionally, the networks of
#            all security domains on the path from any:x to dst
#            get access to dst.
# (B) rule permit src any:X
# high-level: src gets access to all networks of security domain X
# low-level: like above, but additionally, src gets access to the networks of
#            all security domains lying directly behind all routers on the path
#            from src to any:X
# To preserve the overall meaning while converting from 
# high-level to low-level semantics, deny rules have to be
# inserted automatically.
##############################################################################

# permit any1 dst
#
#      N2-\/-N3
# any1-R1-any2-R2-any3-R3-dst
#   N1-/    N4-/    \-N5
# -->
# deny N5 dst
# permit any3 dst
# deny N2 dst
# deny N3 dst
# permit any2 dst
# permit any1 dst
sub convert_any_src_rule( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    # out_intf may be undefined if dst is an interface and
    # we just process the corresponding router; but that doesn't matter here.
    my $router = $in_intf->{router};
    return unless $router->{managed};

    my $any = $in_intf->{any};
    unless($any) {
	internal_err "$in_intf->{name} has no associated any";
    }
    # nothing to do for the first router
    return if $any eq $rule->{src};

    my $any_rule = {src => $any,
		    dst => $rule->{dst},
		    srv => $rule->{srv},
		    action => 'permit',
		    stateless => $rule->{stateless},
		    i => $rule->{i},
		    orig_any => $rule,
		    deny_networks => [ @{$any->{networks}} ]
		    };
    push @{$rule->{any_rules}}, $any_rule;
    &add_rule($any_rule);
}

# permit src any5
#
#      N2-\  N6-N3-\   /-N4-any4
# src-R1-any2-R2-any3-R3-any5
#      \-N1-any1
# -->
# deny src N1
# permit src any1
# deny src N2
# permit src any2
# deny src N6 
# deny src N3 
# permit src any3
# deny src N4
# permit src any4
# permit src any5
sub convert_any_dst_rule( $$$ ) {
    # in_intf points to src, out_intf to dst
    my ($rule, $in_intf, $out_intf) = @_;
    # in_intf may be undefined if src is an interface and
    # we just process the corresponding router,
    # thus we better use out_intf
    my $router = $out_intf->{router};
    return unless $router->{managed};

    my $src = $rule->{src};
    my $srv = $rule->{srv};

    # Let us assume two rules: 
    # 1. permit src any:X 
    # 2. permit src any:Y    /-any:X
    # and this topology: src-R1-any:Y
    # with any:X and any:Y directly attached to different interfaces of R1.
    # Since we are generating only ACLs for inbound filtering,
    # we would get two identical ACL entries at interface:R1.src:
    # 1. permit src any
    # 2. permit src any
    # To identify these related rules at each router, we link them together
    # at each router were they are applicable.
    # Later, when generating code for the first rule at a router,
    # the value of {active} is changed from 0 to 1. This indicates
    # that no code needs to be generated for subsequent related rules
    # at the same router.
    $router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv}->{active} = 0;
    my $link = $router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv};
    # Find networks at all interfaces except the in_intf.
    # For the case that src is interface of current router,
    # take only the out_intf
    for my $intf ($in_intf?@{$router->{interfaces}}:($out_intf)) {
	# nothing to do for in_intf:
	# case 1: it is the first router near src
	# case 2: the in_intf is on the same security domain
	# as an out_intf of some other router on the path
	next if $in_intf and $intf eq $in_intf;
	my $any = $intf->{any};
	# Nothing to be inserted for the interface which is connected
	# directly to the destination 'any' object.
	# But link it together with other 'any' rules at the last router
	# (R3 in the picture above)
	if($any eq $rule->{dst}) {
	    $rule->{any_dst_group} = $link;
	    next;
	}
	# any_dst_group-optimization may lead to false results when applied
	# inside a loop
	my $link = $intf->{router}->{loop} ? undef : $link;

	my $any_rule = {src => $src,
			dst => $any,
			srv => $srv,
			action => 'permit',
			stateless => $rule->{stateless},
			i => $rule->{i},
			orig_any => $rule,
			deny_networks => [ @{$any->{networks}} ],
			any_dst_group => $link
			};
	push @{$rule->{any_rules}}, $any_rule;
	&add_rule($any_rule);
    }
}

# Both src and dst of processed rule are an 'any' object.
sub check_any_both_rule ( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    # Neither in_intf nor out_intf may be undefined, because src and dst
    # can't be an interface of current router.
    my $router = $in_intf->{router};
    return unless $router->{managed};
    my $src = $rule->{src};
    my $srv = $rule->{srv};
    # See above for comment.
    $router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv}->{active} = 0;
    my $link = $router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv};
    my $current_in_any = $in_intf->{any};
    push @{$rule->{src_any_on_path}}, $current_in_any;
    for my $in_any (@{$rule->{src_any_on_path}}) {
	# Find 'any' objects at all outgoing interfaces.
	for my $intf (@{$router->{interfaces}}) {
	    # Nothing to do for in_intf:
	    # Case 1: it is the first router near src.
	    # Case 2: the in_intf is connected to the same security domain
	    # as an out_intf of the previous router on the path.
	    next if $intf eq $in_intf;
	    my $out_any = $intf->{any};
	    # Nothing to be checked for the original rule.
	    if($out_any eq $rule->{dst} and $in_any eq $src) {
		# Both 'any' objects are directly connected by a managed router.
		if($in_any eq $current_in_any) {
		    $rule->{any_dst_group} = $link;
		    $rule->{any_are_neighbors} = 1;
		}
		next;
	    }
	    unless($rule_tree{$rule->{action}}->
		   {$in_any}->[0]->{$out_any}->[0]->{$srv}) {
		err_msg "For ", print_rule $rule, " to be effective\n",
		" there needs to be defined a similar rule with\n",
		" src=$in_any->{name} and dst=$out_any->{name}";
	    }
	}
    }
}

sub convert_any_rules() {
    info "Converting rules for 'any' objects";
    for my $rule (@expanded_any_rules) {
	next if $rule->{deleted};
	$rule->{any_rules} = [];
	if(is_any($rule->{src})) {
	    if(is_any($rule->{dst})) {
		&path_walk($rule, \&check_any_both_rule);
	    } else {
		&path_walk($rule, \&convert_any_src_rule);
	    }
	}elsif(is_any($rule->{dst})) {
	    &path_walk($rule, \&convert_any_dst_rule);
	} else {
	    internal_err;
	}
    }
}

##############################################################################
# Generate reverse rules for stateless packet filters:
# For each rule with protocol tcp, udp or ip we need a reverse rule
# with swapped src, dst and src-port, dst-port.
# For rules with an tcp service, the reverse rule gets a tcp service
# with additional 'established` flag.
##############################################################################

my @reverse_rules;
my %reverse_rule_tree;

sub gen_reverse_rules1 ( $ ) {
    my($rule_aref) = @_;
    my @extra_rules;
    for my $rule (@$rule_aref) {
	if($rule->{deleted}) {
	    my $src = $rule->{src};
	    # if source is a managed interface,
	    # reversed will get attribute managed_intf
	    unless(is_interface($src) and $src->{router}->{managed}) {
		next;
	    }
	}
	my $srv = $rule->{srv};
	my $proto = $srv->{proto};
	next unless $proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip';
	my $has_stateless_router;
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
		}
	    }
	    elsif($model->{stateless}) {
		$has_stateless_router = 1;
	    }
	};
	&path_walk($rule, $mark_reverse_rule);
	if($has_stateless_router) {
	    my $new_srv;
	    if($proto eq 'tcp') {
		$new_srv = $srv_tcp_established;
	    } elsif($proto eq 'udp') {
		# swap src and dst ports
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
		# this rule must only be applied to stateless routers
		stateless => 1,
		orig_rule => $rule};
	    $new_rule->{deny_networks} = [] if $rule->{deny_networks};
	    &add_rule($new_rule);
	    # don' push to @$rule_aref while we are iterating over it
	    push @extra_rules, $new_rule;
	}
    }
    push @$rule_aref, @extra_rules;
}

sub gen_reverse_rules() {
    info "Generating reverse rules for stateless routers";
    gen_reverse_rules1 \@expanded_deny_rules;
    gen_reverse_rules1 \@expanded_rules;
    # ToDo: How does this interact with convert_any_rules?
    gen_reverse_rules1 \@expanded_any_rules;
}

##############################################################################
# Generate and optimize rules for secondary filters.
# At secondary packet filters, packets are only checked for its 
# src and dst networks, if there is a full packet filter on the path from
# src to dst, were the original rule is checked.
##############################################################################

my @secondary_rules;

sub gen_secondary_rules() {
    info "Generating and optimizing rules for secondary routers";

    my %secondary_rule_tree;
    # Mark only normal rules for optimization.
    # We can't change a deny rule from e.g. tcp to ip.
    # ToDo: Think about applying this to 'any' rules
    for my $rule (@expanded_rules) {
	next if $rule->{deleted} and
	    (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
	my $has_full_filter;
	my $has_secondary_filter;
	my $dst_is_secondary;
	# Local function.
	# It uses variables $has_secondary_filter and $has_full_filter.
	my $mark_secondary_rule = sub( $$$ ) {
	    my ($rule, $in_intf, $out_intf) = @_;
	    my $router = ($in_intf || $out_intf)->{router};
	    return unless $router->{managed};
	    if($router->{managed} eq 'full') {
		# there might be another path, without a full packet filter
		# ToDo: this could be analyzed in more detail
		return if $router->{loop};
		# Optimization should only take place for IP addresses
		# which are really filtered by a full packet filter. 
		# ToDo: Think about virtual interfaces sitting
		# all on the same hardware.
		# Source or destination of rule is an interface of current router.
		# Hence, this router doesn't count as a full packet filter.
		return if not $in_intf and $rule->{src} eq $out_intf;
		return if not $out_intf and $rule->{dst} eq $in_intf;
		$has_full_filter = 1;
	    } elsif($router->{managed} eq 'secondary') {
		$has_secondary_filter = 1;
		# Interface of current router is destination of rule.
		if(not $out_intf) {
		    $dst_is_secondary = 1;
		}
	    }
	};

	&path_walk($rule, $mark_secondary_rule);
	if($has_secondary_filter && $has_full_filter) {
	    $rule->{for_router} = 'full';
	    # get_networks has a single result if not called 
	    # with an 'any' object as argument
	    my $src = get_networks $rule->{src};
	    my $dst = $rule->{dst};
	    # ToDo: build two rules if there are two secondary routers
	    $dst = get_networks $dst unless $dst_is_secondary;
	    # nothing to do, if there is  an identical secondary rule
	    unless($secondary_rule_tree{$src}->{$dst}) {
		my $rule = {
		    orig_rule => $rule,
		    action => $rule->{action},
		    src => $src,
		    dst => $dst,
		    srv => $srv_ip,
		    for_router => 'secondary' };
		$secondary_rule_tree{$src}->{$dst} = $rule;
		push @secondary_rules, $rule;
	    }
	}
    }
}

##############################################################################
# Distribute NAT bindings from interfaces to affected networks
##############################################################################

sub setnat_network( $$$$ ) {
    my($network, $in_interface, $nat, $depth) = @_;
##  info "nat:$nat depth $depth at $network->{name}";
    if($network->{active_path}) {
##	info "nat:$nat loop";
	# Found a loop
	return;
    }
    if($network->{nat_info}) {
	my $max_depth = @{$network->{nat_info}};
	for(my $i = 0; $i < $max_depth; $i++) {
	    if($network->{nat_info}->[$i]->{$nat}) {
##		info "nat:$nat: other binding";
		# Found an alternate border of current NAT domain
		if($i != $depth) {
		    # There is another NAT binding on the path which
		    # might overlap some translations of current NAT
		    err_msg "Inconsistent multiple occurrences of nat:$nat";
		}
		return;
	    }
	}
    }
    # Use a hash to prevent duplicate entries
    $network->{nat_info}->[$depth]->{$nat} = $nat;
    # Loop detection
    $network->{active_path} = 1;
    if($network->{nat}->{$nat}) {
	err_msg "$network->{name} is translated by nat:$nat,\n",
	" but it lies inside the translation sphere of nat:$nat.\n",
	" Probably nat:$nat was bound to wrong interface.";
    }
    for my $interface (@{$network->{interfaces}}) {
	# ignore interface where we reached this network
	next if $interface eq $in_interface;
	# found another border of current nat domain
	next if $interface->{bind_nat} and $interface->{bind_nat} eq $nat;
	&setnat_router($interface->{router}, $interface, $nat, $depth);
    }
    delete $network->{active_path};
}
 
sub setnat_router( $$$$ ) {
    my($router, $in_interface, $nat, $depth) = @_;
    for my $interface (@{$router->{interfaces}}) {
	# ignore interface where we reached this router
	next if $interface eq $in_interface;
	next if $interface->{disabled};
	my $depth = $depth;
	if($interface->{bind_nat}) { 
	    $depth++;
	    if($interface->{bind_nat} eq $nat) {
		err_msg "Found NAT loop for nat:$nat at $interface->{name}";
		next;
	    }
	}
	&setnat_network($interface->{network}, $interface, $nat, $depth);
    }
}

sub distribute_nat_info() {
    info "Distributing NAT";
    for my $router (values %routers) {
	for my $interface (@{$router->{interfaces}}) {
	    my $nat = $interface->{bind_nat} or next;
	    if($nat_definitions{$nat}) {
		&setnat_network($interface->{network}, $interface, $nat, 0);
		$nat_definitions{$nat} = 'used';
	    } else {
		warning "Ignoring undefined nat:$nat bound to $interface->{name}";
	    }
	}
    }
    # {nat_info} was collected at networks, but is needed at
    # logical and hardware interfaces of managed routers
    for my $router (values %routers) {
	next unless $router->{managed};
	for my $interface (@{$router->{interfaces}}) {
	    $interface->{nat_info} = $interface->{hardware}->{nat_info} =
		$interface->{network}->{nat_info};
	}
    }
    for my $name (keys %nat_definitions) {
	warning "nat:$name is defined, but not used" 
	    unless $nat_definitions{$name} eq 'used';
    }
}

##############################################################################
# Optimize expanded rules by deleting identical rules and 
# rules which are overlapped by a more general rule
##############################################################################

# Add rule to %rule_tree or %reverse_rule_tree
sub add_rule( $ ) {
    my ($rule) = @_;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    # Mark rules with managed interface as dst 
    # because they get special handling during code generation
    if(is_interface($dst) and $dst->{router}->{managed}) {
	$rule->{managed_intf} = 1;
    }
    my $rule_tree = $rule->{stateless} ? \%reverse_rule_tree : \%rule_tree;
    my $old_rule = $rule_tree->{$action}->{$src}->[0]->{$dst}->[0]->{$srv};
    if($old_rule) {
	# Found identical rule
	# For 'any' rules we must preserve the rule without deny_networks
	# i.e. any_with_deny < any
	if($action eq 'permit' and
	   (is_any $src or is_any $dst) and
	   @{$rule->{deny_networks}} == 0) {
	    $old_rule->{deleted} = $rule;
	    # continue adding new rule below
	} else {
	    $rule->{deleted} = $old_rule;
	    return;
	}
    } 
    $rule_tree->{$action}->{$src}->[0]->{$dst}->[0]->{$srv} = $rule;
    $rule_tree->{$action}->{$src}->[1] = $src;
    $rule_tree->{$action}->{$src}->[0]->{$dst}->[1] = $dst;
}

# delete an element from an array reference
# return 1 if found, 0 otherwise
sub aref_delete( $$ ) {
    my($elt, $aref) = @_;
    for(my $i = 0; $i < @$aref; $i++) {
	if($aref->[$i] eq $elt) {
	    splice @$aref, $i, 1;
#info "aref_delete: $elt->{name}";
	    return 1;
	}
    }
    return 0;
}

# Optimization of automatically generated any rules 
# with attached deny networks
#
# 1.
# cmp: permit any(deny_net: net2,net3) dst srv
# chg: permit host1 dst' srv'
# --> if host1 not in net2 or net3, dst >= dst', srv >= srv'
# delete chg rule
# 2.
# cmp: permit any(deny_net: net2,net3) dst srv
# chg: permit net1 dst' srv'
# --> if net1 not eq net2 or net3, dst >= dst', srv >= srv'
# delete chg rule
# 3.
# cmp permit any(deny_net: net1,net2) dst srv
# chg permit net1 dst srv
# -->
# delete chg rule
# remove net1 from cmp rule
# 4. (currently not implemented because relation is in 'wrong' order)
# cmp permit any(deny_net: net1,net2) dst srv
# chg permit net1 dst' srv'
# --> if dst <= dst', srv <= srv'
# remove net1 from cmp rule
# 5.
# cmp permit any(deny_net: net1,net2) dst srv
# chg permit any(deny_net: net1,net2,net3,...) dst' srv'
# --> if dst >= dst', srv >= srv'
# delete chg rule
#
# It doesn't hurt if deny_networks of a cmp rule are 
# removed later even if it was used before to delete a chg rule.
#
# ToDo: Why aren't these optimizations applicable to deny rules?
#
sub optimize_any_rule( $$$ ) {
    my($here, $cmp_rule, $chg_rule) = @_;
    my $obj = $chg_rule->{$here};
    # Case 1
    if(is_host $obj or is_interface $obj) {
	unless(grep { $obj->{network} eq $_ } @{$cmp_rule->{deny_networks}}) {
	    $chg_rule->{deleted} = $cmp_rule;
	}
    }
    elsif(is_network $obj) {
	my $there = $here eq 'src' ? 'dst' : 'src';
	# Case 2
	unless(grep { $obj eq $_ } @{$cmp_rule->{deny_networks}}) {
	    $chg_rule->{deleted} = $cmp_rule;
	}
	# Case 3
	elsif($cmp_rule->{$there} eq $chg_rule->{$there} and
	      $cmp_rule->{srv} eq $chg_rule->{srv} and
	      aref_delete($obj, $cmp_rule->{deny_networks})) {
	    $chg_rule->{deleted} = $cmp_rule;
	}
    }
    elsif(is_any $obj) {
	# Case 5
	# Check if deny_networks of cmp rule are subset of
	# deny_networks of chg rule.
	my $subset = 1;
	for my $net (@{$cmp_rule->{deny_networks}}) {
	    unless(grep { $net eq $_ }
		   @{$chg_rule->{deny_networks}}) {
		$subset = 0;
		last;
	    }
	}
	if($subset) {
	    $chg_rule->{deleted} = $cmp_rule;
	}
    } else {
	internal_err "unexpected type of $obj->{name}";
    }
}

# A rule may be deleted if we find a similar rule with greater or equal srv.
# Property of parameters:
# Rules in $cmp_hash >= rules in $chg_hash
sub optimize_srv_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;
 
    # optimize full rules
    for my $chg_rule (values %$chg_hash) {
	# don't change this attribute again.
	# This is vital for managed_intf optimization to work
	next if $chg_rule->{deleted};
# info "chg: ", print_rule $chg_rule;
# map {info "chg deny-net: ",$_->{name} } @{$chg_rule->{deny_networks}};
	my $srv = $chg_rule->{srv};
	while($srv) {
	    if(my $cmp_rule = $cmp_hash->{$srv}) {
		unless($cmp_rule eq $chg_rule) {
# info "cmp: ", print_rule $cmp_rule;
# map {info "cmp deny-net: ",$_->{name} } @{$cmp_rule->{deny_networks}};
		    if($cmp_rule->{action} eq 'permit' and
		       $chg_rule->{action} eq 'permit') {
			if(is_any $cmp_rule->{src}) {
			    &optimize_any_rule('src', $cmp_rule, $chg_rule);
			} elsif (is_any $cmp_rule->{dst}) {
			    &optimize_any_rule('dst', $cmp_rule, $chg_rule);
			} else {
			    $chg_rule->{deleted} = $cmp_rule;
			}
		    } else {
			$chg_rule->{deleted} = $cmp_rule;
		    }
# info "deleted" if $chg_rule->{deleted};
		    last;
		}
	    }
	    $srv = $srv->{up};
	}
    }
}

#           any,any
#          /       \
#      net,any   any,net
#       /     \ /     \
#  host,any net,net any,host
#       \     / \     /
#     host,net   net,host
#          \       /
#          host,host
#
# any > net > host
sub optimize_dst_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;
    return unless $cmp_hash and $chg_hash;
    for my $aref (values %$chg_hash) {
	my($next_hash, $dst) = @$aref;
	my $cmp_dst;
	my $any;
	if(is_host($dst) or is_interface($dst)) {
	    # First compare with dst of other rules.
	    # This is vital for managed_intf optimization to work.
	    $cmp_dst = $cmp_hash->{$dst} and
		&optimize_srv_rules($cmp_dst->[0], $next_hash);
	    $cmp_dst = $cmp_hash->{$dst->{network}} and
		&optimize_srv_rules($cmp_dst->[0], $next_hash);
	    $any = $dst->{network}->{any} and
		$cmp_dst = $cmp_hash->{$any} and
		    &optimize_srv_rules($cmp_dst->[0], $next_hash);
	} elsif(is_network($dst)) {
	    $cmp_dst = $cmp_hash->{$dst} and
		&optimize_srv_rules($cmp_dst->[0], $next_hash);
	    $any = $dst->{any} and
		$cmp_dst = $cmp_hash->{$any} and
		&optimize_srv_rules($cmp_dst->[0], $next_hash);
	} elsif(is_any($dst)) {
	    $cmp_dst = $cmp_hash->{$dst} and
		&optimize_srv_rules($cmp_dst->[0], $next_hash);
	} else {
	    internal_err "a rule was applied to unsupported dst '$dst->{name}'";
	}
    }
}
    
sub optimize_src_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;
    return unless $cmp_hash and $chg_hash;
    for my $aref (values %$chg_hash) {
	my($next_hash, $src) = @$aref;
	my $cmp_src;
	my $any;
	if(is_host($src) or is_interface($src)) {
	    $cmp_src = $cmp_hash->{$src} and
		&optimize_dst_rules($cmp_src->[0], $next_hash);
	    $cmp_src = $cmp_hash->{$src->{network}} and
		&optimize_dst_rules($cmp_src->[0], $next_hash);
	    $any = $src->{network}->{any} and
		$cmp_src = $cmp_hash->{$any} and
		    &optimize_dst_rules($cmp_src->[0], $next_hash);
	} elsif(is_network($src)) {
	    $cmp_src = $cmp_hash->{$src} and
		&optimize_dst_rules($cmp_src->[0], $next_hash);
	    $any = $src->{any} and
		$cmp_src = $cmp_hash->{$any} and
		&optimize_dst_rules($cmp_src->[0], $next_hash);
	} elsif(is_any($src)) {
	    $cmp_src = $cmp_hash->{$src} and
		&optimize_dst_rules($cmp_src->[0], $next_hash);
	} else {
	    internal_err "a rule was applied to unsupported src '$src->{name}'";
	}
    }
}

# deny > permit 
sub optimize_action_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;
    my $cmp_deny = $cmp_hash->{deny};
    my $chg_deny = $chg_hash->{deny};
    my $cmp_permit = $cmp_hash->{permit};
    my $chg_permit = $chg_hash->{permit};
    if($chg_deny && $cmp_deny) {
	&optimize_src_rules($cmp_deny, $chg_deny);
    }
    if($chg_permit && $cmp_permit) {
	&optimize_src_rules($cmp_permit, $chg_permit);
    }
    if($chg_deny && $cmp_permit) {
	&optimize_src_rules($cmp_permit, $chg_deny);
    }
}

sub optimize() {
    info "Optimization";
    optimize_action_rules \%rule_tree, \%rule_tree;
    if($verbose) {
	my($n, $nd, $na, $naa) = (0,0,0,0);
	for my $rule (@expanded_deny_rules) { $nd++ if $rule->{deleted}	}
	for my $rule (@expanded_rules) { $n++ if $rule->{deleted} }
	for my $rule (@expanded_any_rules) {
	    $na++ if $rule->{deleted};
	    for my $any_rule (@{$rule->{any_rules}}) {
		$naa++ if $any_rule->{deleted};
	    }
	}
	info "Deleted redundant rules:";
	info " $nd deny, $n permit, $na permit any, $naa permit any from any";
    }
}

# normal rules > reverse rules
sub optimize_reverse_rules() {
    info "Optimization of reverse rules";
    optimize_action_rules \%reverse_rule_tree, \%reverse_rule_tree;
    optimize_action_rules \%rule_tree, \%reverse_rule_tree;
}

####################################################################
# Routing
# Add a component 'route' to each interface.
# It holds an array of networks reachable
# using this interface as next hop
####################################################################

# This function is called for each network on the path from src to dst
# of $rule.
# If $in_intf and $out_intf are both defined, 
# packets traverse this network.
# If $in_intf is not defined, there is no interface where we could add
# routing entries.
# If $out_intf is not defined, dst is this network;
# hence dst is directly connected to $in_intf
sub collect_route( $$$ ) {
    my($rule, $in_intf, $out_intf) = @_;
#    info "collect: $rule->{src}->{name} -> $rule->{dst}->{name}";
#    my $info = '';
#    $info .= $in_intf->{name} if $in_intf;
#    $info .= ' -> ';
#    $info .= $out_intf->{name} if $out_intf;
#    info $info;;
    if($in_intf and $out_intf) {
	return unless $in_intf->{router}->{managed};
	# Remember network which is reachable via $out_intf
	my $network = $rule->{dst_network};
	# ignore network, which was generated via get_networks from an interface
	return if $out_intf->{network} eq $network;
#	info "Route at $in_intf->{name}: $network->{name} via $out_intf->{name}";
	$in_intf->{routes}->{$out_intf}->{$network} = $network;
	# Store $out_intf itself, since we need to go back 
	# from hash key to original object later.
	$in_intf->{hop}->{$out_intf} = $out_intf;
    }
}

sub check_duplicate_routes () {
    for my $router (values %routers) {
	next unless $router->{managed};
	# Remember, via which local interface a network is reached.
	my %net2intf;
	for my $interface (@{$router->{interfaces}}) {
	    # Remember, via which remote interface a network is reached.
	    my %net2hop;
	    for my $hop (values %{$interface->{hop}}) {
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
			    unless($hop->{virtual} and $hop2->{virtual} and
				   $hop->{virtual} eq $hop2->{virtual}) {
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

sub mark_networks_for_static( $$$ ) {
    my($rule, $in_intf, $out_intf) = @_;
    # no static needed for directly attached interface
    return unless $out_intf;
    my $router = $out_intf->{router};
    return unless $router->{managed};
    return unless $router->{model}->{has_interface_level};
    # no static needed for traffic coming from the PIX itself
    return unless $in_intf;
    my $in_hw = $in_intf->{hardware};
    my $out_hw = $out_intf->{hardware};
    err_msg "Traffic to $rule->{dst}->{name} can't pass\n",
    " from  $in_intf->{name} to $out_intf->{name},\n",
    " because they have equal security levels.\n"
	if $in_hw->{level} == $out_hw->{level};
    # Collect networks for generation of static commands.
    # Put networks into a hash to prevent duplicates.
    # We need in_hw and out_hw for
    # - their names and for
    # - getting the NAT domain
    my $dst = $rule->{dst_network};
    return if $dst->{ip} eq 'unnumbered';
    $out_hw->{static}->{$in_hw}->{$dst} = $dst;
    # Do we need to generate "nat 0" for an interface?
    if($in_hw->{level} < $out_hw->{level}) {
	$out_hw->{need_nat_0} = 1;
    } else {
	# Check, if there is a dynamic NAT of a dst address from higher
	# to lower security level. We need this info to decide,
	# if static commands with "identity mapping" and "nat 0"
	# need to be generated.
	my $nat_tag = $out_hw->{bind_nat} or return;
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
#	info "$from->{name} -> $to->{name}";
	# 'any' objects are expanded to all its contained networks
	# hosts and interfaces expand to its containing network
	for my $network (get_networks($dst)) {
	    my $to = is_interface $dst ? $dst : $network;
	    unless($routing_tree{$from}->{$to}) {
		my $pseudo_rule = { src => $from,
				    dst => $to,
				    action => '--',
				    srv => $pseudo_srv,
				    dst_network => $network
				    };
		$routing_tree{$from}->{$to} = $pseudo_rule;
	    }
	}
    };
    for my $rule (@expanded_rules, @expanded_any_rules) {
	$fun->($rule->{src}, $rule->{dst});
    }
    for my $hash (values %routing_tree) {
	for my $pseudo_rule (values %$hash) {
	    &path_walk($pseudo_rule, \&mark_networks_for_static, 'Router');
	}
    }
    # Additionally process reverse direction for routing
    for my $rule (@expanded_rules, @expanded_any_rules) {
	$fun->($rule->{dst}, $rule->{src});
    }
    for my $hash (values %routing_tree) {
	for my $pseudo_rule (values %$hash) {
	    &path_walk($pseudo_rule, \&collect_route, 'Network');
	}
    }
    check_duplicate_routes();
}

# needed for default route optimization
my $network_00 = new('Network', name => "network:0/0", ip => 0, mask => 0);

sub print_routes( $ ) {
    my($router) = @_;
    my $type = $router->{model}->{routing};
    if($auto_default_route) {
	# find interface and hop with largest number of routing entries
	my $max_intf;
	my $max_hop;
	# substitute routes to one hop with a default route,
	# if there are at least two entries.
	my $max = 1;
	for my $interface (@{$router->{interfaces}}) {
	    if($interface->{routing}) {
		# if dynamic routing is activated for any interface 
		# of the current router, don't do this optimization at all
		$max_intf = undef;
		last;
	    }
	    # Sort interfaces by name to make output deterministic
	    for my $hop (sort { $a->{name} cmp $b->{name} }
			 values %{$interface->{hop}}) {
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
	my $nat_info = $interface->{nat_info};
	# Sort interfaces by name to make output deterministic
	for my $hop (sort { $a->{name} cmp $b->{name} }
			 values %{$interface->{hop}}) {
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
		next if $network->{is_in} and $net_hash->{$network->{is_in}};
		if($comment_routes) {
		    print "! route $network->{name} -> $hop->{name}\n";
		}
		if($type eq 'IOS') {
		    my $adr =
			&ios_route_code(&address($network, $nat_info, 'src'));
		    print "ip route $adr\t$hop_addr\n";
		} elsif($type eq 'PIX') {
		    my $adr =
			&ios_route_code(&address($network, $nat_info, 'src'));
		    print "route $interface->{hardware}->{name} $adr\t$hop_addr\n";
		} elsif($type eq 'iproute') {
		    my $adr =
			&prefix_code(&address($network, $nat_info, 'src'));
		    print "ip route add $adr via $hop_addr\n";
		} else {
		    internal_err
			"unexpected routing type '$type'";
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
	my $out_nat = $out_hw->{nat_info};
	for my $in_hw (sort { $a->{level} <=> $b->{level} }
		       map { $ref2hw{$_} }
		       # Key is reference to hardware interface.
		       keys %{$out_hw->{static}}) {
	    # Value is { net => net, .. }
	    my($net_hash) = $out_hw->{static}->{$in_hw};
	    my $in_name = $in_hw->{name};
	    my $in_nat = $in_hw->{nat_info};
	    # Sorting is only needed for getting output deterministic.
	    my @networks =
		sort { $a->{ip} <=> $b->{ip} || $a->{mask} <=> $b->{mask} }
	    values %$net_hash;
	    # Mark enclosing networks, which are used in statics at this router
	    my %enclosing;
	    for my $network (@networks) {
		$network->{enclosing} and $enclosing{$network} = 1;
	    }
	    # Mark redundant networks as deleted,
	    # if any enclosing network is found.
	    for my $network (@networks) {
		my $net = $network->{is_in};
		while($net) {
		    if($enclosing{$net}) {
			$network = undef;
			last;
		    } else {
			$net = $net->{is_in};
		    }
		}
	    }
	    for my $network (@networks) {
		next unless defined $network;
		$network->{mask} == 0 and
		    err_msg "Pix doesn't support static command for ",
		    "mask 0.0.0.0 of $network->{name}\n";
		my $sub = sub () {
		    my($network, $nat_info) = @_;
		    my($nat_tag, $network_ip, $mask, $dynamic) =
			&nat_lookup($network, $nat_info);
		    if($nat_tag) {
			return $network_ip, $mask, $dynamic?$nat_tag:undef;
		    } else {
			return $network->{ip}, $network->{mask};
		    }
		};
		my($in_ip, $in_mask, $in_dynamic) = $sub->($network, $in_nat);
		my($out_ip,
		   $out_mask, $out_dynamic) = $sub->($network, $out_nat);
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
		    for my $host (@{$network->{hosts}},
				  @{$network->{interfaces}}) {
			if(my $in_ip = $host->{nat}->{$in_dynamic}) {
			    my @addresses = &address($host, $out_nat);
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
		       $out_hw->{need_always_static}) {
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
    my ($rule, $in_intf, $out_intf, $any_rule) = @_;
    # Traffic from src reaches this router via in_intf
    # and leaves it via out_intf.
    # in_intf is undefined if src is an interface of the current router
    # out_intf is undefined if dst is an interface of the current router
    # Outgoing packets from a router itself are never filtered.
    return unless $in_intf;
    my $router = $in_intf->{router};
    return unless $router->{managed};
    # Rules of type secondary are only applied to secondary routers.
    # Rules of type full are only applied to full filtering routers.
    # All other rules are applied to all routers.
    if(my $type = $rule->{for_router}) {
	return unless $type eq $router->{managed};
    }
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
	# No code needed if it is deleted by another rule to the same interface
	return if $rule->{deleted}->{managed_intf};
    }
    # Packets for the router itself
    if(not $out_intf) {
	# For PIX firewalls it is unnecessary to process rules for packets
	# to the PIX itself, because it accepts them anyway (telnet, IPSec).
	# ToDo: Check if this assumption holds for deny ACLs as well
	return if $model->{filter} eq 'PIX' and $rule->{action} eq 'permit';
#	info "$router->{name} intf_rule: ",print_rule $rule,"\n";
	push @{$in_intf->{hardware}->{intf_rules}}, $rule;
    } 
    # 'any' rules must be placed in a separate array, because they must no
    # be subject of object-group optimization
    elsif($any_rule) {
#	info "$router->{name} any_rule: ",print_rule $rule,"\n";
	push @{$in_intf->{hardware}->{any_rules}}, $rule;
    } else {
#	info "$router->{name} rule: ",print_rule $rule,"\n";
	push @{$in_intf->{hardware}->{rules}}, $rule;
    }
}

sub check_deleted ( $$ ) {
    my($rule, $out_intf) = @_;
    if($rule->{deleted}) {
	if($rule->{managed_intf}) {
	    if($out_intf) {
		# We are on an intermediate router if $out_intf is defined,
		# hence normal 'delete' is valid.
		return 1;
	    }
	    if($rule->{deleted}->{managed_intf}) {
		# No code needed if it is deleted by another 
		# rule to the same interface.
		return 1;
	    }
	} else {
	    # Not a managed interface, normal 'delete' is valid.
	    return 1;
	}
    }
    return 0;
}

# For deny and permit rules with src=any:*, call distribute_rule only for
# the first router on the path from src to dst.
sub distribute_rule_at_src( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $router = $in_intf->{router};
    return unless $router->{managed};
    my $src = $rule->{src};
    is_any $src or internal_err "$src must be of type 'any'";
    # The main rule is only processed at the first router on the path.
    if($in_intf->{any} eq $src) {
	# optional 4th parameter 'any_rule' must be set!
	&distribute_rule(@_, 1) unless check_deleted $rule, $out_intf;
    }
    # Auxiliary rules are never needed at the first router.
    elsif(exists $rule->{any_rules}) {
	# check for auxiliary 'any' rules
	for my $any_rule (@{$rule->{any_rules}}) {
	    next unless $in_intf->{any} eq $any_rule->{src};
	    # We need to know exactly if code is generated,
	    # otherwise we would generate deny rules accidently.
	    next if check_deleted $any_rule, $out_intf;
	    # Put deny rules directly in front of
	    # the corresponding permit 'any' rule.
	    for my $deny_network (@{$any_rule->{deny_networks}}) {
		my $deny_rule = { action => 'deny',
				  src => $deny_network,
				  dst => $any_rule->{dst},
				  srv => $any_rule->{srv},
				  stateless => $any_rule->{stateless} };
		&distribute_rule($deny_rule, $in_intf, $out_intf, 1);
	    }
	    &distribute_rule($any_rule, $in_intf, $out_intf, 1);
	}
    }
}

# For permit dst=any:*, call distribute_rule only for
# the last router on the path from src to dst.
sub distribute_rule_at_dst( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $router = $out_intf->{router};
    return unless $router->{managed};
    my $dst = $rule->{dst};
    is_any $dst or internal_err "$dst must be of type 'any'";
    # This is called for the main rule and its auxiliary rules.
    # First build a list of all adjacent 'any' objects.
    my @neighbor_anys;
    for my $intf (@{$out_intf->{router}->{interfaces}}) {
	next if $in_intf and $intf eq $in_intf;
	push @neighbor_anys, $intf->{any};
    }
    # Generate deny rules in a first pass, since all related
    # 'any' rules must be placed behind them.
    for my $any_rule (@{$rule->{any_rules}}) {
	next unless grep { $_ eq $any_rule->{dst} } @neighbor_anys;
	next if $any_rule->{deleted};
	for my $deny_network (@{$any_rule->{deny_networks}}) {
	    my $deny_rule = {action => 'deny',
			     src => $any_rule->{src},
			     dst => $deny_network,
			     srv => $any_rule->{srv},
			     stateless => $any_rule->{stateless}
			 };
	    &distribute_rule($deny_rule, $in_intf, $out_intf, 1);
	}
    }
    for my $any_rule ($rule, @{$rule->{any_rules}}) {
	next unless grep { $_ eq $any_rule->{dst} } @neighbor_anys;
	next if $any_rule->{deleted};
	if($any_rule->{any_dst_group}) {
	    unless($any_rule->{any_dst_group}->{active}) {
		&distribute_rule($any_rule, $in_intf, $out_intf, 1);
		$any_rule->{any_dst_group}->{active} = 1;
	    }
	} else {
	    &distribute_rule($any_rule, $in_intf, $out_intf, 1);
	}
    }
}

sub rules_distribution() {
    info "Rules distribution";
    # Deny rules
    for my $rule (@expanded_deny_rules) {
	next if $rule->{deleted};
	&path_walk($rule, \&distribute_rule);
    }
    # Permit rules
    for my $rule (@expanded_rules, @secondary_rules) {
	next if $rule->{deleted} and
	    (not $rule->{managed_intf} or $rule->{deleted}->{managed_intf});
	&path_walk($rule, \&distribute_rule, 'Router');
    }
    # Rules with 'any' object as src or dst
    for my $rule (@expanded_any_rules) {
	if(is_any $rule->{src}) {
	    if(is_any $rule->{dst}) {
		# Both, src and dst are 'any' objects.
		# We only need to generate code if they are directly connected
		# by a managed router.
		# See check_any_both_rule() above for details.
		if($rule->{any_are_neighbors}) {
		    &path_walk($rule, \&distribute_rule_at_dst);
		}
	    } else {
		&path_walk($rule, \&distribute_rule_at_src);
	    }
	} elsif(is_any $rule->{dst}) {
	    &path_walk($rule, \&distribute_rule_at_dst);
	} else {
	    internal_err "unexpected rule ", print_rule $rule, "\n";
	}
    }
}

##############################################################################
# ACL Generation
##############################################################################

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

# Parameters:
# obj: this address we want to know
# network: look inside this nat domain
# direction: is obj used as source or destination 
# returns a list of [ ip, mask ] pairs
sub address( $$$ ) {
    my ($obj, $nat_info, $direction) = @_;
    if(is_host($obj)) {
	my($nat_tag, $network_ip, $mask, $dynamic) =
	   &nat_lookup($obj->{network}, $nat_info);
	if($nat_tag) {
	    if($dynamic) {
		if(my $ip = $obj->{nat}->{$nat_tag}) {
		    # single static NAT IP for this host
		    return [$ip, 0xffffffff];
		} else {
		    # Use the address of the whole pool.
		    # This is not an security leak, because we are filtering
		    # for the host address at the NAT device
		    return [$network_ip, $mask];
		}
	    } else {
		# Take higher bits from network NAT,
		# lower bits from original IP
		if($obj->{range}) {
		    my($ip1, $ip2) = 
			map { $network_ip | $_ & ~$mask } 
		    @{$obj->{range}};
		    return &split_ip_range($ip1, $ip2);
		} else {
		    my $ip = $network_ip | $obj->{ip} & ~$mask;
		    return [$ip, 0xffffffff];
		}
	    }
	} else {
	    if($obj->{range}) {
		return &split_ip_range(@{$obj->{range}});
	    } else {
		return [$obj->{ip}, 0xffffffff];
	    }
	}
    }
    if(is_interface($obj)) {
	if($obj->{ip} eq 'unnumbered' or $obj->{ip} eq 'short') {
	    internal_err "unexpected $obj->{ip} $obj->{name}\n";
	}
	my($nat_tag, $network_ip, $mask, $dynamic) =
	   &nat_lookup($obj->{network}, $nat_info);
	if($nat_tag) {
	    if($dynamic) {
		if(my $ip = $obj->{nat}->{$nat_tag}) {
		    # single static NAT IP for this interface
		    return [$ip, 0xffffffff];
		} else {
		    # Use the address of the whole pool.
		    # This is not an security leak, because we are filtering
		    # for the interface address at the NAT device
		    return [$network_ip, $mask];
		}
	    } else {
		# Take higher bits from network NAT,
		# lower bits from original IP
		return map { [$network_ip | $_ & ~$mask, 0xffffffff] }
		@{$obj->{ip}};
	    }
	} else {
	    my @ip = @{$obj->{ip}};
	    # Virtual IP must be added for deny rules, it doesn't hurt for permit rules.
	    push @ip, $obj->{virtual} if $obj->{virtual};
	    return map { [$_, 0xffffffff] } @ip;
	}
    } elsif(is_network($obj)) {
	my($nat_tag, $network_ip, $mask, $dynamic) =
	   &nat_lookup($obj, $nat_info);
	if($nat_tag) {
	    # It is useless do use a dynamic address as destination,
	    # but we permit it anyway.
	    #if($dynamic and $direction eq 'dst') {
	    #  err_msg "Dynamic nat:$nat_tag of $obj->{name} ",
	    #  "can't be used as destination";
	    #}
	    return [$network_ip, $mask];
	} else {

	    if($obj->{ip} eq 'unnumbered') {
		internal_err "unexpected unnumbered $obj->{name}\n";
	    } else {
		return [$obj->{ip}, $obj->{mask}];
	    }
	}
    } elsif(is_any($obj)) {
	return [0, 0];
    } elsif(is_objectgroup $obj) {
	$obj;
    } else {
	internal_err "unexpected object $obj->{name}";
    }
}

# Lookup NAT tag of a network while generating code in a domain
# represented by a network.
# Data structure:
# $nat_info->[$depth]->{$nat_tag} = $nat_tag;
sub nat_lookup( $$ ) {
    my($net, $nat_info) = @_;
    $nat_info or return undef;
    # Iterate from most specific to less specific NAT tags
    for my $href (@$nat_info) {
	for my $nat_tag (values %$href) {
	    if($net->{nat}->{$nat_tag}) {
		return($nat_tag,
		       @{$net->{nat}->{$nat_tag}}{'ip', 'mask', 'dynamic'});
	    }
	}
    }
    return undef;
}

# Given an IP and mask, return its address in IOS syntax
# If third parameter is true, use inverted netmask for IOS ACLs
sub ios_code( $$$ ) {
    my($pair, $inv_mask) = @_;
    if(is_objectgroup $pair) {
	return "object-group $pair->{name}";
    } else {
	my($ip, $mask) = @$pair;
	my $ip_code = &print_ip($ip);
	if($mask == 0xffffffff) {
	    return "host $ip_code";
	} elsif($mask == 0) {
	    return "any";
	} else {
	    my $mask_code = &print_ip($inv_mask?~$mask:$mask);
	    return "$ip_code $mask_code";
	}
    }
}

sub ios_route_code( $$ ) {
    my($pair) = @_;
    my($ip, $mask) = @$pair;
    my $ip_code = &print_ip($ip);
    my $mask_code = &print_ip($mask);
    return "$ip_code $mask_code";
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32.
sub prefix_code( $$ ) {
    my($pair) = @_;
    my($ip, $mask) = @$pair;
    my $ip_code = &print_ip($ip);
    my $prefix_code = &print_prefix($mask);
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
    my($rules_aref, $nat_info, $prefix, $model) = @_;
    my $filter_type = $model->{filter};
    for my $rule (@$rules_aref) {
	my $action = $rule->{action};
	my $src = $rule->{src};
	my $dst = $rule->{dst};
	my $srv = $rule->{srv};
	print "$model->{comment_char} ". print_rule($rule)."\n"
	    if $comment_acls;
	for my $spair (&address($src, $nat_info, 'src')) {
	    for my $dpair (&address($dst, $nat_info, 'dst')) {
		if($filter_type eq 'IOS' or $filter_type eq 'PIX') {
		    my $inv_mask = $filter_type eq 'IOS';
		    my ($proto_code, $src_port_code, $dst_port_code) =
			cisco_srv_code($srv, $model);
		    my $src_code = &ios_code($spair, $inv_mask);
		    my $dst_code = &ios_code($dpair, $inv_mask);
		    print "$prefix $action $proto_code ",
		    "$src_code $src_port_code $dst_code $dst_port_code\n";
		} elsif($filter_type eq 'iptables') {
		    my $srv_code = iptables_srv_code($srv);
		    my $src_code = &prefix_code($spair);
		    my $dst_code = &prefix_code($dpair);
		    my $action_code = $action eq 'permit' ? 'ACCEPT' : 'DROP';
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
	my %ref2obj;
	for my $hardware (@{$router->{hardware}}) {
	    my %group_rule_tree;
	    # find groups of rules with identical 
	    # action, srv, src/dst and different dst/src
	    for my $rule (@{$hardware->{rules}}) {
		my $action = $rule->{action};
		my $that = $rule->{$that};
		my $this = $rule->{$this};
		my $srv = $rule->{srv};
		$ref2obj{$this} = $this;
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
				nat_info => $hardware->{interface}->{nat_info},
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
	    # find group with identical elements
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
	    # Not found, build new group
	    my $group = new('Objectgroup',
			    name => "g$counter",
			    elements => [ map { $ref2obj{$_} } @keys ],
			    hash => $hash,
			    nat_info => $glue->{nat_info});
	    push @{$nat2size2group{$bind_nat}->{$size}}, $group;
	    push @groups, $group;
	    $counter++;
	    return $glue->{group} = $group;
	};
	# build new list of rules using object groups
	for my $hardware (@{$router->{hardware}}) {
	    my @new_rules;
	    for my $rule (@{$hardware->{rules}}) {
		if(my $glue = $rule->{$tag}) {
#		    info print_rule $rule;
		    # remove tag, otherwise call to find_object_groups 
		    # for another router would become confused
		    delete $rule->{$tag};
		    if($glue->{active}) {
#			info " deleted: $glue->{group}->{name}";
			next;
		    }
		    $get_group->($glue);
#		    info " generated: $glue->{group}->{name}";
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
        print "object-group network $group->{name}\n";
	my $nat_info =  $group->{nat_info};
        for my $pair (sort { $a->[0] <=> $b->[0] ||  $a->[1] <=> $b->[1] }
			 map { &address($_, $nat_info, 'src') }
			 @{$group->{elements}}) {
	    my $adr = &ios_code($pair);
	    print " network-object $adr\n";
	}
    }
    # Empty line as delimiter
    print "\n";
}

sub print_acls( $ ) {
    my($router) = @_;
    my $model = $router->{model};
    print "[ ACL ]\n";
    if($model->{filter} eq 'PIX' and $router->{use_object_groups}) {
	&find_object_groups($router);
    }
    my $comment_char = $model->{comment_char};
    # Collect IP addresses of all interfaces
    my @ip;
    for my $hardware (@{$router->{hardware}}) {
	# We need to know, if packets for a dynamic routing protocol 
	# are allowed for a hardware interface
	my %routing;
	for my $interface (@{$hardware->{interfaces}}) {
	    # Current router is used as default router even for some internal
	    # networks
	    if($interface->{reroute_permit}) {
		for my $net (@{$interface->{reroute_permit}}) {
		    # this is not allowed between different security domains
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
		    # prevent duplicate rules from multiple logical interfaces
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
    # Add deny rules 
    for my $hardware (@{$router->{hardware}}) {
	if($model->{filter} eq 'IOS' and
	   ($hardware->{rules} or $hardware->{any_rules})) {
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
	push(@{$hardware->{any_rules}}, { action => 'deny',
				      src => $network_00,
				      dst => $network_00,
				      srv => $srv_ip });
    }
    # Generate code
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
	# Take network of first logical interface for determining the NAT domain.
	# During NAT processing above, we have assured, that all logical interfaces
	# of one hardware interface have the same NAT bindings.
	my $nat_info = $hardware->{interfaces}->[0]->{nat_info};
	# Interface rules
	acl_line $hardware->{intf_rules}, $nat_info, $intf_prefix, $model;
	# Ordinary rules
	acl_line $hardware->{rules}, $nat_info, $prefix, $model;
	# 'any' rules
	acl_line $hardware->{any_rules}, $nat_info, $prefix, $model;
	# Postprocessing for hardware interface
	if($model->{filter} eq 'IOS') {
	    print "interface $hardware->{name}\n";
	    print " access group $name\n";
	} elsif($model->{filter} eq 'PIX') {
	    print "access-group $name in interface $hardware->{name}\n";
	}
	# Empty line after each interface
	print "\n";
    }
    # Post-processing for all interfaces
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

# make output directory available
sub check_output_dir( $ ) {
    my($dir) = @_;
    unless(-e $dir) {
	mkdir $dir or die "Abort: can't create output directory $dir: $!\n";
    }
    -d $dir or die "Abort: $dir isn't a directory\n";
}

# Print generated code for each managed router
sub print_code( $ ) {
    my($dir) = @_;
    &check_output_dir($dir);
    info "Printing code";
    for my $router (values %routers) {
	next unless $router->{managed};
	my $model = $router->{model};
	my $name = $router->{name};
	my $file = $name;
	$file =~ s/^router://;
	$file = "$dir/$file";
	open STDOUT, ">$file" or die "Can't open $file: $!\n";
	print "!! Generated by $program, version $version\n\n";
	print "[ BEGIN $name ]\n";
	print "[ Model = $model->{name} ]\n";
	&print_routes($router);
	&print_acls($router);
	&print_pix_static($router);
	print "[ END $name ]\n\n";
	close STDOUT or die "Can't close $file\n";
    }
    $warn_pix_icmp_code && &warn_pix_icmp();
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
    # strip trailing slash for nicer messages
    $out_dir =~ s./$..;
    not @ARGV or usage;
    return $main_file, $out_dir;
}

sub show_version() {
    info "$program, version $version";
}

1
