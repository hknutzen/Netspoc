#!/usr/bin/perl
# Netspoc.pm
# A Network Security Policy Compiler
# http://netspoc.berlios.de
# (c) 2003 by Heinz Knutzen <heinzknutzen@users.berlios.de>
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
		 set_route_in_any 
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
		 acl_generation 
		 check_output_dir
		 print_code
		 warn_pix_icmp);

my $program = 'Network Security Policy Compiler';
my $version = (split ' ','$Id$ ')[2];

####################################################################
# User configurable options
####################################################################
my $verbose = 1;
my $comment_acls = 1;
my $comment_routes = 1;
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
# allow rules at toplevel or only as part of policies
# Possible values: 0 | warn | 1
my $allow_toplevel_rules = 0;
# Store descriptions as an attribute of policies.
# This may be useful when called from a reporting tool.
our $store_description = 0;

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
sub add_context( $ ) {
    my($msg) = @_;
    my $context;
    if($eof) {
	$context = 'at EOF';
    } else {
	my($pre, $post) =
	    m/([^\s,;={}]*[,;={}\s]*)\G([,;={}\s]*[^\s,;={}]*)/;
	$context = qq/near "$pre<--HERE-->$post"/;
    }
    qq/$msg at line $. of $file, $context\n/;
}

sub add_line( $ ) {
    my($msg) = @_;
    qq/$msg at line $. of $file\n/;
}

our $error_counter = 0;

sub check_abort() {
    if(++$error_counter >= $max_errors) {
	die "Aborted after $error_counter errors\n";
    }
}
    
sub error_atline( $ ) {
    my($msg) = @_; 
    print STDERR "Error: ", add_line($msg);
    check_abort();
}

sub err_msg( @ ) {
    print STDERR "Error: ", @_, "\n";
    check_abort();
}

sub syntax_err( $ ) {
    my($msg) = @_;    
    die "Syntax error: ", add_context $msg;
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

sub read_list_or_null(&) {
    my($fun) = @_;
    my @vals;
    return @vals if check(';');
    push(@vals, &$fun);
    while(&check(',')) {
        push(@vals, &$fun);
    }
    &skip(';');
    return @vals;
}

sub read_list(&) {
    my($fun) = @_;
    my @vals;
    push(@vals, &$fun);
    while(&check(',')) {
	push(@vals, &$fun);
    }
    &skip(';');
    return @vals;
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

# Create a new structure of given type; initialize it with key / value pairs
sub new( $@ ) {
    my $type = shift;
    my $self = { @_ };
    return bless($self, $type);
}

# A hash with all defined nat names.
# Is used, to check, 
# - if all defined nat mappings are used and
# - if all used mappings are defined
my %nat_definitons;

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
	    # a host with multiple IP addresses is represented internally as
	    # a group of simple hosts
	    @hosts =
		map { new('Host', name => "auto_host:$name", ip => $_) } @ip;
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
	$host = new('Host', name => "host:$name", range => [ $ip1, $ip2 ]);
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
	    $host->{nat}->{$name} = $nat_ip;
	    $nat_definitons{$name} = 1;
	} else {
	    syntax_err "Expected NAT definition";
	}
    }
    if($host->{nat}) {
	if($host->{range}) {
	    error_atline "No NAT supported for host with IP range";
	} elsif(@hosts > 1) {
	    error_atline "No NAT supported for host with multiple IP's";
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
		      hosts => [],
		      file => $file
		      );
    skip('=');
    skip('{');
    $network->{route_hint} = &check_flag('route_hint');
    $network->{subnet_of} = &check_assign('subnet_of', \&read_typed_name);
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
	    # check compatibility of host ip and network ip/mask
	    for my $host (@hosts) {
		if(exists $host->{ip}) {
		    if($ip != ($host->{ip} & $mask)) {
			error_atline "$host->{name}'s IP doesn't match $network->{name}'s IP/mask";
		    }
		} elsif(exists $host->{range}) {
		    my ($ip1, $ip2) = @{$host->{range}};
		    if($ip != ($ip1 & $mask) or $ip != ($ip2 & $mask)) {
			error_atline "$host->{name}'s IP range doesn't match $network->{name}'s IP/mask";
		    }
		} else {
		    internal_err "$host->{name} hasn't ip or range";
		}
		# Check compatibility of host and network NAT.
		# A NAT defintion for a single host is only allowed,
		# if the network has a dynamic NAT defintion.
		if($host->{nat}) {
		    for my $nat_tag (keys %{$host->{nat}}) {
			my $nat_info;
			if($nat_info = $network->{nat}->{$nat_tag} and
			   $nat_info->{dynamic}) {
			    my $host_ip = $host->{nat}->{$nat_tag};
			    my($ip, $mask) = @{$nat_info}{'ip', 'mask'}; 
			    if($ip != ($host_ip & $mask)) {
				err_msg "nat:$nat_tag: $host->{name}'s IP ",
				"doesn't match $network->{name}'s IP/mask";
			    }
			} else {
			    err_msg
				"nat:$nat_tag not allowed for $host->{name} ",
				"because $network->{name} doesn't have ",
				"dynamic NAT definition";
			}
		    }
		}
		$host->{network} = $network;
	    }
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
		    error_atline
		    "Non dynamic NAT mask must be equal to network mask";
	    }
	    &skip('}');
	    # check if ip matches mask
	    if(($nat_ip & $nat_mask) != $nat_ip) {
		error_atline
		    "$network->{name}'s NAT IP doesn't match its mask";
		$nat_ip &= $nat_mask;
	    }
	    $network->{nat}->{$name} = { ip => $nat_ip,
					 mask => $nat_mask,
					 dynamic => $dynamic };
	    $nat_definitons{$name} = 1;
	} else {
	    syntax_err "Expected NAT or host definition";
	}
    }
    if($network->{nat} and $ip eq 'unnumbered') {
	err_msg "Unnumbered $network->{name} must not have nat definition";
    }
    if(@{$network->{hosts}} and $ip eq 'unnumbered') {
	err_msg "Unnumbered $network->{name} must not have host definitions";
    }
    if(@{$network->{hosts}} and $network->{route_hint}) {
	err_msg "$network->{name} must not have host definitions,\n",
	    " since it has attribute 'route_hint'";
    }
    &mark_ip_ranges($network);
    if($networks{$name}) {
	error_atline "Redefining $network->{name}";
    }
    $networks{$name} = $network;
}

my %valid_routing = (OSPF => 1);
our %interfaces;
my @disabled_interfaces;
sub read_interface( $$ ) {
    my($router, $net) = @_;
    my $name = "$router.$net";
    my $interface = new('Interface', 
			name => "interface:$name",
			network => $net
			);
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
		    $nat_definitons{$name} = 1;
		} else {
		    syntax_err "Expected NAT definition";
		}
	    } elsif(my $nat = &check_assign('nat', \&read_identifier)) {
		# bind NAT to an interface
		$interface->{bind_nat} and
		    error_atline "Redefining NAT binding";
		$interface->{bind_nat} = $nat;
	    } elsif(my $hardware = &check_assign('hardware', \&read_string)) {
		$interface->{hardware} and
		    error_atline "Redefining hardware of interface";
		$interface->{hardware} = $hardware;
	    } elsif(my $protocol = &check_assign('routing', \&read_string)) {
		unless($valid_routing{$protocol}) {
		    error_atline "Unknown routing protocol '$protocol'";
		}
		$interface->{routing} and
		    error_atline "Redefining routing protocal if interface";
		$interface->{routing} = $protocol;
	    } elsif(my @names = &check_assign_list('reroute_permit',
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
		error_atline "No NAT supported for unnumbered interface";
	    } elsif(@{$interface->{ip}} > 1) {
		error_atline
		    "No NAT supported for interface with multiple IP's";
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
    my($interface) = @_;
    my $hwname = $interface->{hardware};
    my $level;
    if($hwname eq 'inside') {
	$level = 100;
    } elsif($hwname eq 'outside') {
	$level = 0;
    } else {
	unless(($level) = ($hwname =~ /(\d+)$/) and
	       0 < $level and $level < 100) {
	    err_msg "Can't derive PIX security level from $interface->{name}";
	}
    }
    $interface->{level} = $level;
}

our %routers;
sub read_router( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $managed;
    if(&check('managed')) {
	if(&check(';')) {
	    $managed = 'full';
	} elsif(&check('=')) {
	    my $value = &read_identifier();
	    if($value =~ /^full|secondary$/) { $managed = $value; }
	    else { error_atline "Unknown managed device type '$value'"; }
	    &check(';');
	} else {
	    &syntax_err("Expected ';' or '='");
	}
    }
    my $model;
    if($model = &check_assign('model', \&read_identifier)) {
       my $info = $router_info{$model};
       $info or error_atline "Unknown router model '$model'";
       $model = $info;
    }
    if($managed and not $model) {
	err_msg "Missing 'model' for managed router:$name";
    }
    my $static_manual = &check_flag('static_manual');
    my $router = new('Router',
		     name => "router:$name",
		     managed => $managed,
		     file => $file
		     );
    $router->{model} = $model if $managed;
    $router->{static_manual} = 1 if $static_manual and $managed;
    while(1) {
	last if &check('}');
	my($type,$iname) = split_typed_name(read_typed_name());
	syntax_err "Expected interface definition" unless $type eq 'interface';
	my $interface = &read_interface($name, $iname);
	push @{$router->{interfaces}}, $interface;
	# assign router to interface
	$interface->{router} = $router;
	# managed router must not have short interface
	if($managed and $interface->{ip} eq 'short') {
	    err_msg "Short definition of $interface->{name} not allowed";
	}
	# interface of managed router needs to have a hardware name
	if($managed and not defined $interface->{hardware}) {
	    err_msg "Missing 'hardware' for $interface->{name}";
	}
	# NAT is only supported at managed routers
	if($interface->{bind_nat} and not $managed) {
	    err_msg "Can't bind NAT to unmanaged $interface->{name}";
	}
	if($managed and $model->{has_interface_level}) {
	    set_pix_interface_level($interface);
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
    my @objects = &read_list_or_null(\&read_typed_name);
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
	return &read_list(\&read_typed_name);
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
    my @user = &read_assign_list('user', \&read_typed_name);
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
    my @src = &read_assign_list('src', \&read_typed_name);
    my @dst = &read_assign_list('dst', \&read_typed_name);
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
    # check if the network is already linked with another interface
    if(defined $network->{interfaces}) {
	my $old_intf = $network->{interfaces}->[0];
	# if network is already linked to a short interface
	# it must not be linked to any other interface
	if($old_intf->{ip} eq 'short') {
	    err_msg "$network->{name} must not be linked with $interface->{name},\n",
	    " since it is already linked with short $old_intf->{name}";
	}
	# if network is already linked to any interface
	# it must not be linked to a short interface
	if($ip eq 'short') {
	    err_msg "$network->{name} must not be linked with $old_intf->{name},\n",
	    " since it is already linked with short $interface->{name}";
	}
    } 

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
	for my $interface_ip (@$ip) {
	    if($network_ip eq 'unnumbered') {
		err_msg "$interface->{name} must not be linked ",
		"to unnumbered $network->{name}";
	    }
	    if($network_ip != ($interface_ip & $mask)) {
		err_msg "$interface->{name}'s IP doesn't match ",
		"$network->{name}'s IP/mask";
	    }
	}
	# Check compatibility of interface and network NAT.
	# A NAT defintion for a single interface is only allowed,
	# if the network has a dynamic NAT defintion.
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
		    err_msg "nat:$nat_tag not allowed for $interface->{name} ",
		    "because $network->{name} doesn't have a",
		    "dynamic NAT definition";
		}
	    }
	}
    }
    push(@{$network->{interfaces}}, $interface);
}

sub link_topology() {
    &link_any_and_every();
    for my $interface (values %interfaces) {
	&link_interface_with_net($interface);
    }
    for my $network (values %networks) {
	if($network->{ip} eq 'unnumbered' and @{$network->{interfaces}} > 2) {
	    err_msg "Unnumbered $network->{name} is connected to",
	    " more than two interfaces:";
	    for my $interface (@{$network->{interfaces}}) {
		print STDERR " $interface->{name}\n";
	    }
	}
	my %ip;
	for my $interface (@{$network->{interfaces}}) {
	    my $ips = $interface->{ip};
	    next if $ips eq 'unnumbered' or $ips eq 'short';
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
    router => \%routers,
    interface => \%interfaces,
    any => \%anys,
    every => \%everys,
    group => \%groups
 );

# Get a reference to an array of network object names and 
# return a reference to an array of network objects
sub expand_group( $$ ) {
    my($obref, $context) = @_;
    my @objects;
    for my $tname (@$obref) {

	my($type, $name) = split_typed_name($tname);
	my $object;
	unless($object = $name2object{$type}->{$name}) { 
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
	} elsif(is_router $object) {
	    # split a router into it's numbered interfaces
	    for my $interface (@{$object->{interfaces}}) {
		unless($interface->{ip} eq 'unnumbered') {
		    push @objects, $interface;
		}
	    }
	} elsif(is_every $object) {
	    # expand an 'every' object to all networks in its security domain
	    # Attention: this doesn't include unnumbered networks
	    push @objects,  @{$object->{link}->{any}->{networks}};
	} else {
	    push @objects, $object;
	}
    }
    for my $object (@objects) {
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
    for my $name (sort keys %policies) {
	my $policy = $policies{$name};
	my $user = $policy->{user};
	for my $p_rule (@{$policy->{rules}}) {
	    # new hash with identical keys and values
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
	
	for my $src (@{$rule->{src}}) {
	    for my $dst (@{$rule->{dst}}) {
		for my $srv (@{$rule->{srv}}) {
		    my $expanded_rule = { action => $action,
					  src => $src,
					  dst => $dst,
					  srv => $srv,
					  # remember original rule
					  rule => $rule
					  };
		    # if $srv is duplicate of an identical service
		    # use the main service, but remember the original one
		    # for debugging / comments
		    if(my $main_srv = $srv->{main}) {
			$expanded_rule->{srv} = $main_srv;
			$expanded_rule->{orig_srv} = $srv;
		    }
		    if($action eq 'deny') {
			push(@expanded_deny_rules, $expanded_rule);
		    } elsif(is_any($src) and is_any($dst)) {
			err_msg "Rule '", print_rule $expanded_rule, "'\n",
			" has 'any' objects both as src and dst.\n",
			" This is not supported currently. ",
			"Use one 'every' object instead";
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
# recursivly mark the whole part of the topology lying behind 
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

my @all_anys;

sub setany() {
    @all_anys = grep { not $_->{disabled} } values %anys;
    for my $any (@all_anys) {
	my $obj = $any->{link};
	if(my $old_any = $obj->{any}) {
	    err_msg
		"More than one 'any' object definied in a security domain:\n",
		" $old_any->{name} and $any->{name}";
	}
	if(is_network $obj) {
	    setany_network $obj, $any, 0;
	} elsif(is_router $obj) {
	    setany_router $obj, $any, 0;
	} else {
	    internal_err "unexpected object $obj->{name}";
	}
    }

    # automatically add an 'any' object to each security domain
    # where none has been declared
    for my $network (values %networks) {
	next if $network->{any};
	next if $network->{disabled};
	(my $name = $network->{name}) =~ s/^network:/auto_any:/;
	my $any = new('Any', name => $name, link => $network);
	push @all_anys, $any;
	setany_network $network, $any, 0;
    }
}
	
####################################################################
# Set paths for efficient topology traversal
####################################################################
sub setpath_obj( $$$ ) {
    my($obj, $to_any1, $distance) = @_;
#info("-- $distance: $obj->{name} --> $to_any1->{name}");
    # $obj: a managed router or an 'any' object
    # $to_any1: interface of $obj; go this direction to reach any1
    # $distance: distance to any1
    # return value:
    # (1) a flag, indicating that the current path is part of a loop
    # (2) that obj, which is starting point of the loop (as seen from any1)
    if($obj->{active_path}) {
	# Found a loop
	# detect if multiple loops end at current object
	$obj->{right} and err_msg "Found nested loop at $obj->{name}";
	$obj->{right} = $to_any1;
	$to_any1->{left} = $obj;
	return $obj;
    }
    # mark current path for loop detection
    $obj->{active_path} = 1;
    $obj->{distance} = $distance;

    my $in_loop = 0;
    for my $interface (@{$obj->{interfaces}}) {
	# ignore interface where we reached this obj
	next if $interface eq $to_any1;
	# ignore interface which is the other entry of a loop 
	# which is already marked
	next if $interface->{right};
	my $next = is_any $obj ? $interface->{router} : $interface->{any};
	if(my $loop = &setpath_obj($next, $interface, $distance+1)) {
	    # path is part of a loop
	    # detected if multiple loops start at current object
	    $in_loop and err_msg "Found nested loop at $obj->{name}";
	    $in_loop = $loop;
	    $interface->{right} = $obj;
	    $obj->{left} = $interface
	} else {
	    # continue marking loopless path
	    $interface->{main} = $obj;
	}
    }
    delete $obj->{active_path};
    if($in_loop) {
	# mark every node of a loop with the loops starting point
	$obj->{loop} = $in_loop;
	unless($obj->{right}) {
	    # inside a loop not at the starting point
	    $obj->{right} = $to_any1;
	    $to_any1->{left} = $obj;
	    # every node of a loop gets the distance of its starting point
	    $obj->{distance} = $in_loop->{distance};
#info "Loop($obj->{distance}): $obj->{name}";
	    return $in_loop;
	}
    }
    $obj->{main} = $to_any1;
    return 0;
}

sub setpath() {
    # take a random managed element from @all_anys, name it "any1"
    my $any1 = $all_anys[0] or die "Topology seems to be empty\n";

    # Artificially add an interface to any1 with lowest distance.
    my $interface = new('Interface',
			name => "interface:ARTIFICIAL\@$any1->{name}",
			dist2router => 1);
    push @{$any1->{interfaces}}, $interface;

    # Starting with any1, do a traversal of the whole network 
    # to find a path from every security domain and router to any1
    setpath_obj($any1, $interface, 2);

    # check, if all security domains are connected with any1 
    for my $any (@all_anys) {
	next if $any eq $any1;
	$any->{main} or $any->{right} or
	    err_msg "Found unconnected security domain $any->{name}";
    }
}

####################################################################
# Efficient path traversal.
# Used for conversion of 'any' rules and for generation of ACLs
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
	return $obj->{network}->{any};
    } elsif(is_interface($obj)) {
	if($obj->{router}->{managed}) {
	    return $obj->{router};
	} else {
	    return $obj->{network}->{any};
	}
    } elsif(is_network($obj)) {
	return $obj->{any};
    } elsif(is_any($obj)) {
	return $obj;
    } elsif(is_router($obj)) {
	# this is only allowed, when called from 
	# find_active_routes_and_statics
	return $obj;
    } else {
	internal_err "unexpected object $obj->{name}";
    }
}

# Mark path $from -> $to inside of loops.
# In general we use the reference to $dst as a key.
# At the forking we build a second key by appending
# the string "2." to the reference: "2.$dst"
sub loop_part_mark ( $$$$$$ ) {
    my($direction, $from, $to, $from_in, $to_out, $dst) = @_;
    my $mark = $direction eq 'left' ? $dst : "2.$dst";
    while(1) {
	# mark may be set already, if this function was called for
	# a sub-path before
	if($from eq $to) {
#	    info "$from_in->{name} -> ".($to_out?$to_out->{name}:'');
	    $from_in->{$mark} = $to_out;
	    return;
	}
	my $from_out = $from->{$direction};
#	info "$from_in->{name} -> ".($from_out?$from_out->{name}:'');
	$from_in->{$mark} = $from_out;
	$from_in = $from_out;
	$from = $from_out->{$direction};
	$mark = $dst;
    }
}

sub loop_path_mark ( $$$$$ ) {
    my($from, $to, $from_in, $to_out, $dst) = @_;
    loop_part_mark('left', $from, $to, $from_in, $to_out, $dst);
    loop_part_mark('right', $from, $to, $from_in, $to_out, $dst);
}

# Mark path from src to dst.
# src and dst are either a managed router or an 'any' object.
# At each interface on the path from src to dst,
# we place a reference to the next interface on the path to dst.
# This reference is found under a key which is the reference to dst.
# Additionally we attach this information to the src network object.
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
	# paths meet outside a loop or at the edge of a loop
	if($from eq $to) {
#	    info "$from_in->{name} -> ".($to_out?$to_out->{name}:'');
	    $from_in->{$dst} = $to_out;
	    return;
	}
	# paths meet inside a loop	
	if($from_loop and $to_loop and $from_loop eq $to_loop) {
	    loop_path_mark($from, $to, $from_in, $to_out, $dst);
	    return;
	}
	if($from->{distance} >= $to->{distance}) {
	    if($from_loop) {
		my $loop_out = $from_loop->{main};
		loop_path_mark($from, $from_loop, $from_in, $loop_out, $dst);
		$from_in = $loop_out;
		$from = $loop_out->{main};
	    } else {
		my $from_out = $from->{main};
#		info "$from_in->{name} -> ".($from_out?$from_out->{name}:'');
		$from_in->{$dst} = $from_out;
		$from_in = $from_out;
		$from = $from_out->{main};
	    }
	    $from_loop = $from->{loop};
	} else {
	    if($to_loop) {
		my $loop_in = $to_loop->{main};
		loop_path_mark($to_loop, $to, $loop_in, $to_out, $dst);
		$to_out = $loop_in;
		$to = $loop_in->{main};
	    } else {
		my $to_in = $to->{main};
#		info "$to_in->{name} -> ".($to_out?$to_out->{name}:'');
		$to_in->{$dst} = $to_out;
		$to_out = $to_in;
		$to = $to_in->{main};
	    }
	    $to_loop = $to->{loop};
	}
    }
}

sub path_info ( $$ ) {
    my ($in_intf, $out_intf) = @_;
    my $in_name = $in_intf?$in_intf->{name}:'-';
    my $out_name = $out_intf?$out_intf->{name}:'-';
    info "$in_name, $out_name";
}

# Used as a marker to detect loops when traversing topology graph
my $walk_mark = 1;

# Apply a function to a rule at every managed router
# on the path from src to dst of the rule
# src-R5-R4-\
#           |-R2-R1
#    dst-R3-/
sub path_walk( $&$ ) {
    my ($rule, $fun, $where) = @_;
    internal_err "undefined rule" unless $rule;
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $from = get_path $src;
    my $to =  get_path $dst;
#    info print_rule $rule;
#    info "start: $from->{name}, $to->{name}";
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
    &path_mark($from, $to) unless $from->{$to};
    $walk_mark++;
    my $in = undef;
    my $out = $from->{$to};
    my $type = is_router $from ? 'Router' : 'Any';
    &part_walk($in, $out, $to, $type, $rule, $fun, $where);
    if(my $out2 = $from->{"2.$to"}) {
	&part_walk($in, $out2, $to, $type, $rule, $fun, $where);
    }
}

sub part_walk( $$$$ ) {
    my($in, $out, $to, $type, $rule, $fun, $where) = @_;
#    info "part_walk: in = ".($in?$in->{name}:'').", out = $out->{name}";
    while(1) {
	if(not defined $out) {
	    &$fun($rule, $in, $out) if $type eq $where;
#	    info "exit: part_walk: reached dst";
	    return;
	} elsif(defined $out->{walk_mark} and
		$out->{walk_mark} eq $walk_mark) {
	    &$fun($rule, $in, $out) if $type eq $where;
#           info "exit: part_walk: was there";
	    return;
	}
	&$fun($rule, $in, $out) if $type eq $where;
	$out->{walk_mark} = $walk_mark;
	$in = $out;
	$out = $in->{$to};
	$type = $type eq 'Router' ? 'Any' : 'Router';
	if(my $out2 = $in->{"2.$to"}) {
	    &part_walk($in, $out2, $to, $type, $rule, $fun, $where);
	}
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
    my $src = $rule->{src};
    my $srv = $rule->{srv};
    # in_intf may be undefined if src is an interface and
    # we just process the corresponding router,
    # thus we better use out_intf
    my $router = $out_intf->{router};

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
    # This optimization is only applicable for stateful routers.
    my $link;
    unless($router->{model}->{stateless}) {
	$router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv}->{active} = 0;
	$link = $router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv};
    }
    # Find networks at all interfaces except the in_intf.
    # For the case that src is interface of current router,
    # take only the out_intf
    for my $intf ($in_intf?@{$router->{interfaces}}:($out_intf)) {
	# nothing to do for in_intf:
	# case 1: it is the first router near src
	# case 2: the in_intf is on the same security domain
	# as an out_intf of some other router on the path
	next if defined $in_intf and $intf eq $in_intf;
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
	my $link = $intf->{any}->{loop} ? undef : $link;

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

sub convert_any_rules() {
    for my $rule (@expanded_any_rules) {
	next if $rule->{deleted};
	$rule->{any_rules} = [];
	if(is_any($rule->{src})) {
	    &path_walk($rule, \&convert_any_src_rule, 'Router');
	}
	if(is_any($rule->{dst})) {
	    &path_walk($rule, \&convert_any_dst_rule, 'Router');
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
	next if $rule->{deleted};
	my $srv = $rule->{srv};
	my $proto = $srv->{proto};
	next unless $proto eq 'tcp' or $proto eq 'udp' or $proto eq 'ip';
	my $has_stateless_router;
	# Local function.
	# It uses variable $has_stateless_router.
	my $mark_reverse_rule = sub( $$$ ) {
	    my ($rule, $src_intf, $dst_intf) = @_;
	    # Destination of current rule is current router.
	    # Outgoing packets from a router itself are never filtered.
	    # Hence we don't need a reverse rule for current router.
	    return if not $dst_intf;
	    my $model = $dst_intf->{router}->{model};
	    # Source of current rule is current router.
	    if(not $src_intf) {
		if($model->{stateless_self}) {
		    $has_stateless_router = 1;
		}
	    }
	    elsif($model->{stateless}) {
		$has_stateless_router = 1;
	    }
	};
	&path_walk($rule, $mark_reverse_rule, 'Router');
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
	    my $new_rule = { %$rule };
	    $new_rule->{src} = $rule->{dst};
	    $new_rule->{dst} = $rule->{src};
	    $new_rule->{srv} = $new_srv;
	    # this rule must only be applied to stateless routers
	    $new_rule->{stateless} = 1;
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
    info "Generating and optimizing rules for secondary filters";

    my %secondary_rule_tree;
    # Mark only normal rules for optimization.
    # We can't change a deny rule from e.g. tcp to ip.
    # ToDo: Think about applying this to 'any' rules
    for my $rule (@expanded_rules) {
	next if $rule->{deleted};
	my $has_full_filter;
	my $has_secondary_filter;
	my $dst_is_secondary;
	# Local function.
	# It uses variables $has_secondary_filter and $has_full_filter.
	my $mark_secondary_rule = sub( $$$ ) {
	    my ($rule, $src_intf, $dst_intf) = @_;
	    my $router = ($src_intf || $dst_intf)->{router};
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
		return if not $src_intf and $rule->{src} eq $dst_intf;
		return if not $dst_intf and $rule->{dst} eq $src_intf;
		$has_full_filter = 1;
	    } elsif($router->{managed} eq 'secondary') {
		$has_secondary_filter = 1;
		# Interface of current router is destination of rule.
		if(not $dst_intf) {
		    $dst_is_secondary = 1;
		}
	    }
	};

	&path_walk($rule, $mark_secondary_rule, 'Router');
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
		# copy original rule;
		my $rule = { %$rule };
		$rule->{src} = $src;
		$rule->{dst} = $dst;
		$rule->{srv} = $srv_ip;
		$rule->{for_router} = 'secondary';
		$secondary_rule_tree{$src}->{$dst} = $rule;
		push @secondary_rules, $rule;
	    }
	}
    }
}

##############################################################################
# Distribute NAT bindings from interfaces to affected networks
##############################################################################

sub setnat_any( $$$$ ) {
    my($any, $in_interface, $nat, $depth) = @_;
    info "nat:$nat depth $depth at $any->{name}";
    if($any->{active_path}) {
	info "nat:$nat loop";
	# Found a loop
	return;
    }
    if($any->{bind_nat}) {
	my $max_depth = @{$any->{bind_nat}};
	for(my $i = 0; $i < $max_depth; $i++) {
	    if($any->{bind_nat}->[$i]->{$nat}) {
		info "nat:$nat: other binding";
		# Found an alternate border of current NAT domain
		if($i != $depth) {
		    # There is another NAT binding on the path which
		    # might overlap some translations of current NAT
		    err_msg "Inconsistent multiple occurences of nat:$nat";
		}
		return;
	    }
	}
    }
    # Use a hash to prevet duplicate entries
    $any->{bind_nat}->[$depth]->{$nat} = $nat;
    # Loop detection
    $any->{active_path} = 1;
    for my $network (@{$any->{networks}}) {
	if($network->{nat}->{$nat}) {
	    err_msg "$network->{name} is translated by nat:$nat,\n",
	    " but it lies inside the translation sphere of nat:$nat.\n",
	    " Propably nat:$nat was bound to wrong interface.";
	}
    }
    for my $interface (@{$any->{interfaces}}) {
	# ignore interface where we reached this network
	next if $interface eq $in_interface;
	# found another border of current nat domain
	next if $interface->{bind_nat} and $interface->{bind_nat} eq $nat;
	&setnat_router($interface->{router}, $interface, $nat, $depth);
    }
    delete $any->{active_path};
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
	&setnat_any($interface->{any}, $interface, $nat, $depth);
    }
}

sub distribute_nat_info() {
    info "Distributing NAT";
    for my $router (values %routers) {
	for my $interface (@{$router->{interfaces}}) {
	    my $nat = $interface->{bind_nat} or next;
	    if($nat_definitons{$nat}) {
		&setnat_any($interface->{any}, $interface, $nat, 0);
		$nat_definitons{$nat} = 'used';
	    } else {
		warning "Ignoring undefined nat:$nat bound to $interface->{name}";
	    }
	}
    }
    for my $name (keys %nat_definitons) {
	warning "nat:$name is defined, but not used" 
	    unless $nat_definitons{$name} eq 'used';
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
	$rule->{managed_if} = 1;
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
# 4. (currently not implemented)
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
sub optimize_any_rule( $$ ) {
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

# A security domain with multiple networks has some unmanaged routers.
# For each interface at the border of a security domain,
# fill a hash referenced by $route, showing by wich internal interface
# each network may be reached from outside.
# If a network may be reached by multiple paths, use the interface
# with the shortest path.
sub set_networks_behind ( $$$$ ) {
    my($hop, $depth, $route, $result) = @_;
    for my $interface (@{$hop->{router}->{interfaces}}) {
	next if $interface eq $hop;
 	next if $interface->{disabled};
	# add directly connected network
	my $network = $interface->{network};
	if($network->{depth} && $depth >= $network->{depth}) {
	    # found a loop, current path is longer, don't go further
	    next;
	}
	unless($interface->{ip} eq 'unnumbered') {
	    # remember length of path
	    $network->{depth} = $depth;
	    # ToDo: If this is inside a loop,
	    # we must delete the previously found longer paths
	    # to prevent duplicate routing entries
	    $result->{$network} = $route;
	}
	for my $next_hop (@{$network->{interfaces}}) {
	    next if $next_hop eq $interface;
	    # we reached an other side of the current security domain
	    next if $next_hop->{any};
	    # add networks reachable via interfaces behind
	    # the directly connected networks
	    &set_networks_behind($next_hop, $depth+1, $route, $result);
	}
    }
}

sub set_route_in_any () {
    info "Finding routes to unmanaged devices";
    for my $any (@all_anys) {
	for my $border (@{$any->{interfaces}}) {
	    my $network = $border->{network};
	    # has already been calculated
	    next if $network->{route_in_any};
	    $network->{route_in_any} = {};
	    for my $interface (@{$network->{interfaces}}) {
		# ignore current or other border interfaces
		next if $interface->{any};
		# all networks behind $interface are reachable via $interface
		set_networks_behind($interface, 1, $interface,
				    $network->{route_in_any});
	    }
	    # we need to calculate separate values of depth
	    # for each border interface.
	    # Attention: $any->{networks} doesn't include unnumbered networks
	    for my $network (@{$any->{networks}}) {
		delete $network->{depth};
	    }
	}
    }
}

# This function is called for each 'any' object on the path from src to dst
# of $rule.
# If $in_intf and $out_intf are both defined, 
# packets traverse this 'any'object.
# If $in_intf is not defined, src lies inside this 'any' object,
# no routing entries are needed.
# If $out_intf is not defined, dst lies inside this 'any' object;
# we need to add routing entries to $in_intf for each network of dst,
# which isn't directly connected to $in_intf.
sub collect_route( $$$ ) {
    my($rule, $in_intf, $out_intf) = @_;
    if($in_intf and $out_intf) {
	my $hop;
	my $back_hop;
	if($in_intf->{network} eq $out_intf->{network}) {
	    # No intermediate router lies between in_intf and out_intf,
	    # hence we reach dst simply via $out_intf
	    $hop = $out_intf;
	    $back_hop = $in_intf;
	} else {
	    # Need to find appropriate interface of intermediate router.
	    # This info was collected before by &set_route_in_any and stored
	    # under {route_in_any} in a hash,
	    # where we find the next hop inside the current 'any' object.
	    $hop = $in_intf->{network}->{route_in_any}->{$out_intf->{network}};
	    $back_hop = $out_intf->{network}->{route_in_any}->{$in_intf->{network}};
	}
	# Remember which networks are reachable via $hop
	for my $network (values %{$rule->{dst_networks}}) {
	    # ignore directly connected network
	    next if $network eq $in_intf->{network};
	    $in_intf->{routes}->{$hop}->{$network} = $network;
	    # Store $hop itself, since we need to go back 
	    # from hash key to original object later.
	    $in_intf->{hop}->{$hop} = $hop;
	}
	# Remember which networks are reachable via $back_hop
	for my $network (values %{$rule->{src_networks}}) {
	    # ignore directly connected network
	    next if $network eq $out_intf->{network};
	    $out_intf->{routes}->{$back_hop}->{$network} = $network;
	    # Store $back_hop itself, since we need to go back 
	    # from hash key to original object later.
	    $out_intf->{hop}->{$back_hop} = $back_hop;
	}
    } elsif($in_intf) { # and not $out_intf
	# path ends here
	for my $network (values %{$rule->{dst_networks}}) {
	    # ignore directly connected network
	    next if $network eq $in_intf->{network};
	    my $hop = $in_intf->{network}->{route_in_any}->{$network};
	    $in_intf->{routes}->{$hop}->{$network} = $network;
	    $in_intf->{hop}->{$hop} = $hop;
	}
    } elsif($out_intf) { # and not $in_intf
	# path ends here
	for my $network (values %{$rule->{src_networks}}) {
	    # ignore directly connected network
	    next if $network eq $out_intf->{network};
	    my $back_hop = $out_intf->{network}->{route_in_any}->{$network};
	    $out_intf->{routes}->{$back_hop}->{$network} = $network;
	    $out_intf->{hop}->{$back_hop} = $back_hop;
	}
    }
}

sub find_active_routes_and_statics () {
    info "Finding routes and statics";
    my %routing_tree;
    for my $rule (@expanded_rules, @expanded_any_rules) {
	my $src = $rule->{src};
	my $dst = $rule->{dst};
	my $from = get_path $src;
	my $to = get_path $dst;
	my $pseudo_rule;
	unless($pseudo_rule = $routing_tree{$from}->{$to}) {
	    $pseudo_rule->{src} = $from;
	    $pseudo_rule->{dst} = $to;
	    $pseudo_rule->{src_networks} = {};
	    $pseudo_rule->{dst_networks} = {};
	    $pseudo_rule->{action} = '--';
	    $pseudo_rule->{srv} = {name => '--'};
	    $routing_tree{$from}->{$to} = $pseudo_rule;
	}
	for my $network (get_networks($src)) {
	    $pseudo_rule->{src_networks}->{$network} = $network;
	}
	for my $network (get_networks($dst)) {
	    $pseudo_rule->{dst_networks}->{$network} = $network;
	}
    }
    for my $hash (values %routing_tree) {
	for my $pseudo_rule (values %$hash) {
	    &path_walk($pseudo_rule, \&collect_route, 'Any');
	    &path_walk($pseudo_rule, \&mark_networks_for_static, 'Router');
	}
    }
}

# needed for default route optimization
my $network_default = new('Network',
			  name => "network:0.0.0.0/0.0.0.0",
			  ip => 0,
			  mask => 0
			  );
sub print_routes( $ ) {
    my($router) = @_;
    print "[ Routing ]\n";
    if($auto_default_route) {
	# find interface and hop with largest number of routing entries
	my $max_intf;
	my $max_hop;
	# substitue routes to one hop with a default route,
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
	    $max_intf->{routes}->{$max_hop} = { $network_default =>
						     $network_default };
	}
    }
    for my $interface (@{$router->{interfaces}}) {
	# don't generate static routing entries, 
	# if a dynamic routing protocol is activated
	if($interface->{routing}) {
	    if($comment_routes) {
		print "! Dynamic routing $interface->{routing}",
		" at $interface->{name}\n";
		next;
	    } 
	}
	my $any = $interface->{any};
	# Sort interfaces by name to make output deterministic
	for my $hop (sort { $a->{name} cmp $b->{name} }
		     values %{$interface->{hop}}) {
	    # for unnumbered networks use interface name as next hop
	    my $hop_addr = $hop->{ip} eq 'unnumbered' ?
		$interface->{hardware} : print_ip $hop->{ip}->[0];
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
		next unless defined $network;
		if($comment_routes) {
		    print "! route $network->{name} -> $hop->{name}\n";
		}
		if($router->{model}->{routing} eq 'IOS') {
		    my $adr = &ios_route_code(@{&address($network, $any, 'src')});
		    print "ip route $adr\t$hop_addr\n";
		} elsif($router->{model}->{routing} eq 'PIX') {
		    my $adr = &ios_route_code(@{&address($network, $any, 'src')});
		    print "route $interface->{hardware} $adr\t$hop_addr\n";
		} elsif($router->{model}->{routing} eq 'iproute') {
		    my $adr = &prefix_code(@{&address($network, $any, 'src')});
		    print "ip route $adr via $hop_addr\n";
		} else {
		    internal_err
			"unexpected routing type $router->{model}->{routing}";
		}
	    }
	}
    }
}

##############################################################################
# 'static' commands for pix firewalls
##############################################################################
sub mark_networks_for_static( $$$ ) {
    my($rule, $in_intf, $out_intf) = @_;
    # no static needed for directly attached interface
    return unless $out_intf;
    return unless $out_intf->{router}->{model}->{has_interface_level};
    # no static needed for traffic coming from the PIX itself
    return unless $in_intf;
    # no static needed for traffic from higher to lower security level
    return if $in_intf->{level} > $out_intf->{level};
    die "Traffic to $rule->{dst}->{name} can't pass\n",
    " from  $in_intf->{name} to $out_intf->{name},\n",
    " since they have equal security levels.\n"
	if $in_intf->{level} == $out_intf->{level};
    
    my $in_any = $in_intf->{any};
    my $out_any = $out_intf->{any};
    for my $net (values %{$rule->{dst_networks}}) {
	next if $net->{ip} eq 'unnumbered';
	# collect networks reachable from lower security level
	# for generation of static commands
	$net->{mask} == 0 and
	    die "Pix doesn't support static command for mask 0.0.0.0 of $net->{name}\n";
	my($nat_tag, $ip, $mask, $dynamic) = &nat_lookup($net, $in_any);
	# put networks into a hash to prevent duplicates
	$out_intf->{static}->{$in_intf->{hardware}}->{$net} = $net;
    }
}

sub print_pix_static( $ ) {
    my($router) = @_;
    print "[ Static ]\n";
    # print security level relation for each interface
    print "! Security levels: ";
    my $prev_level;
    for my $interface (sort { $a->{level} <=> $b->{level} }
		       @{$router->{interfaces}} ) {
	my $level = $interface->{level};
	if(defined $prev_level) {
	    print(($prev_level == $level)? " = ": " < ");
	}
	print $interface->{hardware};
	$prev_level = $level;
    }
    print "\n";
		       
    for my $interface (sort { $a->{hardware} cmp $b->{hardware} }
		       @{$router->{interfaces}}) {
	my $static = $interface->{static};
	next unless $static;
	my $high = $interface->{hardware};
	# make output deterministic
	for my $low (sort keys %$static) {
	    my @networks =
		sort { $a->{ip} <=> $b->{ip} } values %{$static->{$low}};
	    # find enclosing networks
	    my %enclosing;
	    for my $network (@networks) {
		$network->{enclosing} and $enclosing{$network} = 1;
	    }
	    # mark redundant networks as deleted
	    # if any enclosing network is found
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
		my $ip = print_ip $network->{ip};
		my $mask = print_ip $network->{mask};
		print "static ($high,$low) $ip $ip netmask $mask\n";
	    }
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

# Paramters:
# obj: this address w e want to know
# any: look inside this nat domain
# direction: do we want to a source or destination address
# returns a list of [ ip, mask ] pairs
sub address( $$$ ) {
    my ($obj, $any, $direction) = @_;
    if(is_host($obj)) {
	my($nat_tag, $network_ip, $mask, $dynamic) =
	   &nat_lookup($obj->{network}, $any);
	if($nat_tag) {
	    if($dynamic) {
		if(my $ip = $obj->{nat}->{$nat_tag}) {
		    # single static NAT IP for this host
		    return [$ip, 0xffffffff];
		} else {
		    err_msg "$obj->{name} has no known address in context ",
		    "of dynamic nat.$nat_tag";
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
	   &nat_lookup($obj->{network}, $any);
	if($nat_tag) {
	    if($dynamic) {
		if(my $ip = $obj->{nat}->{$nat_tag}) {
		    # single static NAT IP for this interface
		    return [$ip, 0xffffffff];
		} else {
		    err_msg "$obj->{name} has no known address in context ",
		    "of dynamic nat.$nat_tag";
		}
	    } else {
		# Take higher bits from network NAT,
		# lower bits from original IP
		return map { [$network_ip | $_ & ~$mask, 0xffffffff] }
		@{$obj->{ip}};
	    }
	} else {
	    return map { [$_, 0xffffffff]  } @{$obj->{ip}};
	}
    } elsif(is_network($obj)) {
	my($nat_tag, $network_ip, $mask, $dynamic) =
	   &nat_lookup($obj, $any);
	if($nat_tag) {
	    if($dynamic and $direction eq 'dst') {
		err_msg "Dynamic nat:$nat_tag of $obj->{name} ",
		"can't be used as destination";
	    }
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
    } else {
	internal_err "unexpected object $obj->{name}";
    }
}

# Lookup NAT tag of a network while generating code in a domain
# represented by an 'any' object.
# Data structure:
# $any->{bind_nat}->[$depth]->{$nat_tag} = $nat_tag;
sub nat_lookup( $$ ) {
    my($net, $any) = @_;
    # Iterate from most specific to less specific NAT tags
    for my $href (@{$any->{bind_nat}}) {
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
     my($ip, $mask, $inv_mask) = @_;
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

sub ios_route_code( $$ ) {
    my($ip, $mask) = @_;
    my $ip_code = &print_ip($ip);
    my $mask_code = &print_ip($mask);
    return "$ip_code $mask_code";
}

# Given an IP and mask, return its address as "x.x.x.x/x"
sub prefix_code( $$ ) {
    my($ip, $mask) = @_;
    my $ip_code = &print_ip($ip);
    my $prefix_code = &print_prefix($mask);
    return "$ip_code/$prefix_code";
}

my %pix_srv_hole;

# Print warnings about the PIX service hole
sub warn_pix_icmp() {
    if(%pix_srv_hole) {
	warning "Ignored the code field of the following ICMP services\n",
	" while generating code for pix firewalls:";
	while(my ($name, $count) = each %pix_srv_hole) {
	    print STDERR " $name: $count times\n";
	}
    }
}

# returns 3 values for building an IOS or PIX ACL:
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

sub acl_line( $$$$$$$ ) {
    my ($action, $src_ip, $src_mask, $dst_ip, $dst_mask, $srv, $model) = @_;
    my $filter_type = $model->{filter};
    if($filter_type eq 'IOS' or $filter_type eq 'PIX') {
	my $inv_mask = $filter_type eq 'IOS';
	my ($proto_code, $src_port_code, $dst_port_code) =
	    cisco_srv_code($srv, $model);
	my $src_code = ios_code($src_ip, $src_mask, $inv_mask);
	my $dst_code = ios_code($dst_ip, $dst_mask, $inv_mask);
	"$action $proto_code $src_code $src_port_code $dst_code $dst_port_code\n";
    } elsif($filter_type eq 'iptables') {
	my $srv_code = iptables_srv_code($srv);
	my $src_code = prefix_code($src_ip, $src_mask);
	my $dst_code = prefix_code($dst_ip, $dst_mask);
	my $action_code = $action eq 'permit' ? 'ACCEPT' : 'DROP';
	"-j $action_code -s $src_code -d $dst_code $srv_code\n";
    } else {
	internal_err "Unknown filter_type $filter_type";
    }
}

sub collect_acls( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    # Traffic from src reaches this router via in_intf
    # and leaves it via out_intf.
    # in_intf is undefined if src is an interface of the current router
    # out_intf is undefined if dst  is an interface of the current router
    # Outgoing packets from a router itself are never filtered.
    return unless $in_intf;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    my $router = $in_intf->{router};
    my $model = $router->{model};
    # Rules of type secondary are only applied to secondary routers.
    # Rules of type full are only applied to full filtering routers.
    # All other rules are applied to all routers.
    if(my $type = $rule->{for_router}) {
	return unless $type eq $router->{managed};
    }
    # Rules of type stateless must only be processed at 
    # stateless routers
    # or at routers which are stateless for packets destined for
    # their own interfaces
    if($rule->{stateless}) {
	unless($model->{stateless} or
	       not $out_intf and $model->{stateless_self}) {
	    return;
	}
    }

    # Rules to managed interfaces must be processed
    # at the corresponding router even if they are marked as deleted,
    # because code for interfaces is placed before the 'normal' code.
    # ToDo: But we might get duplicate ACLs for an interface.
    if($rule->{deleted}) {
	# we are on an intermediate router if $out_intf is defined
	return if $out_intf;
    }
    my $comment_char = $model->{comment_char};
    my @src_addr = &address($src, $in_intf->{any}, 'src');
    my @dst_addr = &address($dst, ($out_intf?$out_intf:$dst)->{any}, 'dst');
    my $code_aref;
    # Packets for the router itself
    if(not defined $out_intf) {
	# For PIX firewalls it is unnecessary to generate permit ACLs
	# for packets to the PIX itself
	# because it accepts them anyway (telnet, IPSec)
	# ToDo: Check if this assumption holds for deny ACLs as well
	return if $model->{filter} eq 'PIX' and $action eq 'permit';
	$code_aref = \@{$router->{if_code}->{$in_intf->{hardware}}};
    } else {
	# collect generated code at hardware interface,
	# not at logical interface
	$code_aref = \@{$router->{code}->{$in_intf->{hardware}}};
    }
    if($comment_acls) {
	push(@$code_aref, "$comment_char ". print_rule($rule)."\n");
    }
    for my $spair (@src_addr) {
	my($src_ip, $src_mask) = @$spair;
	for my $dpair (@dst_addr) {
	    my ($dst_ip, $dst_mask) = @$dpair;
	    push(@$code_aref,
		 acl_line($action,
			  $src_ip, $src_mask, $dst_ip, $dst_mask, $srv,
			  $model));
	}
    }
}

# For deny and permit rules with src=any:*, call collect_acls only for
# the first router on the path from src to dst
sub collect_acls_at_src( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $src = $rule->{src};
    is_any $src or internal_err "$src must be of type 'any'";
    # the main rule is only processed at the first router on the path
    if($in_intf->{any} eq $src) {
	&collect_acls(@_)
	    unless $rule->{deleted} and not $rule->{managed_if};
    }
    # auxiliary rules are never needed at the first router
    elsif(exists $rule->{any_rules}) {
	# check for auxiliary 'any' rules
	for my $any_rule (@{$rule->{any_rules}}) {
	    next unless $in_intf->{any} eq $any_rule->{src};
	    next if $any_rule->{deleted} and not $any_rule->{managed_if};
	    # Generate code for deny rules directly in front of
	    # the corresponding permit 'any' rule
	    for my $deny_network (@{$any_rule->{deny_networks}}) {
		my $deny_rule = {action => 'deny',
				 src => $deny_network,
				 dst => $any_rule->{dst},
				 srv => $any_rule->{srv},
				 stateless => $any_rule->{stateless}
			     };
		&collect_acls($deny_rule, $in_intf, $out_intf);
	    }
	    &collect_acls($any_rule, $in_intf, $out_intf);
	}
    }
}

# For permit dst=any:*, call collect_acls only for
# the last router on the path from src to dst
sub collect_acls_at_dst( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $dst = $rule->{dst};
    is_any $dst or internal_err "$dst must be of type 'any'";
    # this is called for the main rule and its auxiliary rules
    #
    # first build a list of all adjacent 'any' objects
    my @neighbour_anys;
    for my $intf (@{$out_intf->{router}->{interfaces}}) {
	next if $in_intf and $intf eq $in_intf;
	push @neighbour_anys, $intf->{any};
    }
    # generate deny rules in a first pass, since all related
    # 'any' rules must be placed behind them
    for my $any_rule (@{$rule->{any_rules}}) {
	next unless grep { $_ eq $any_rule->{dst} } @neighbour_anys;
	next if $any_rule->{deleted} and not $any_rule->{managed_if};
	for my $deny_network (@{$any_rule->{deny_networks}}) {
	    my $deny_rule = {action => 'deny',
			     src => $any_rule->{src},
			     dst => $deny_network,
			     srv => $any_rule->{srv},
			     stateless => $any_rule->{stateless}
			 };
	    &collect_acls($deny_rule, $in_intf, $out_intf);
	}
    }
    for my $any_rule ($rule, @{$rule->{any_rules}}) {
	next unless grep { $_ eq $any_rule->{dst} } @neighbour_anys;
	next if $any_rule->{deleted} and not $any_rule->{managed_if};
	if($any_rule->{any_dst_group}) {
	    unless($any_rule->{any_dst_group}->{active}) {
		&collect_acls($any_rule, $in_intf, $out_intf);
		$any_rule->{any_dst_group}->{active} = 1;
	    }
	} else {
	    &collect_acls($any_rule, $in_intf, $out_intf);
	}
    }
}

sub acl_generation() {
    info "Code generation";
    # Code for deny rules
    for my $rule (@expanded_deny_rules) {
	next if $rule->{deleted};
	&path_walk($rule, \&collect_acls, 'Router');
    }
    # Code for permit rules
    for my $rule (@expanded_rules, @secondary_rules) {
	next if $rule->{deleted} and not $rule->{managed_if};
	&path_walk($rule, \&collect_acls, 'Router');
    }
    # Code for rules with 'any' object as src or dst
    for my $rule (@expanded_any_rules) {
	if(is_any $rule->{src}) {
	    &path_walk($rule, \&collect_acls_at_src, 'Router');
	} elsif(is_any $rule->{dst}) {
	    &path_walk($rule, \&collect_acls_at_dst, 'Router');
	} else {
	    internal_err "unexpected rule ", print_rule $rule, "\n";
	}
	# ToDo: Handle is_any src && is_any dst
    }
}

# This service needs not to be ordered using order_services
# since we only use it at code generation time.
my $srv_ospf = { name => 'auto_srv:ospf', proto => 89 };

sub print_acls( $ ) {
    my($router) = @_;
    my $model = $router->{model};
    my $comment_char = $model->{comment_char};
    print "[ ACL ]\n";
    # We need to know all hardware interface names.
    # It isn't sufficient to iterate over the keys from $router->{code},
    # since some interfaces may have no ACL at all.
    my %hardware;
    # Collect IP addresses of all interfaces
    my @ip;
    # We need to know, if packets for dynamic routing protocol OSPF
    # are allowed for a hardware interface
    my %ospf;
    for my $interface (@{$router->{interfaces}}) {
	# ignore 'unnumbered' and 'short' interfaces
	next if $interface->{ip} eq 'unnumbered' or $interface->{ip} eq 'short';
	my $hardware = $interface->{hardware};
	# Remember interface name for comments
	$hardware{$hardware} = $interface->{name};
	push @ip, @{$interface->{ip}};
	# is OSPF used? What are the destination networks?
	if($interface->{routing} and $interface->{routing} eq 'OSPF') {
	    push @{$ospf{$hardware}}, $interface->{network};
	}
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
		my $code_aref = \@{$router->{code}->{$hardware}};
		my ($ip, $mask) = @{&address($net, $net->{any}, 'src')};
		# prepend to all other ACLs
		unshift(@$code_aref,
			acl_line('permit', 0,0, $ip, $mask, $srv_ip, $model));
	    }
	}
    }
    for my $hardware (sort keys %hardware) {
	if($ospf{$hardware}) {
	    my $code_aref = \@{$router->{if_code}->{$hardware}};
	    if($comment_acls) {
		push @$code_aref, "$comment_char OSPF\n";
	    }
	    push(@$code_aref,
		 #  permit ip any host 224.0.0.5
		 acl_line('permit',
			  0,0,gen_ip(224,0,0,5),gen_ip(255,255,255,255),
			  $srv_ip, $model));
	    push(@$code_aref,
		 #  permit ip any host 224.0.0.6
		 acl_line('permit',
			  0,0,gen_ip(224,0,0,6),gen_ip(255,255,255,255),
			  $srv_ip, $model));
	    # Permit OSPF packets from attached networks to this router.
	    # We use the network address instead of the interface
	    # addresses, because it is shorter if the interface has 
	    # multiple addresses.
	    for my $net (@{$ospf{$hardware}}) {
		my ($ip, $mask) = @{&address($net, $net->{any}, 'src')};
		push(@$code_aref,
		     #  permit ospf $net $net
		     acl_line('permit',
			      $ip, $mask, $ip, $mask, $srv_ospf, $model));
	    }
	}
    }
    for my $hardware (sort keys %hardware) {
	my $name = "${hardware}_in";
	my $code = $router->{code}->{$hardware};
	my $if_code = $router->{if_code}->{$hardware};
	# force auto-vivification
	push @$code, ();
	push @$if_code, ();
	if($comment_acls) {
	    print "$comment_char $hardware{$hardware}\n";
	}
	if($model->{filter} eq 'IOS') {
	    print "ip access-list extended $name\n";
	    # First, handle ACLs where destination is one of 
	    # this routers interfaces
	    for my $line (@$if_code) {
		print " $line";
	    }
	    if(@$code) {
		if($comment_acls and @ip) {
		    print " $comment_char Protect own interfaces\n";
		}
		for my $ip (@ip) {
		    print " deny ip any host ". print_ip($ip) ."\n";
		}
		for my $line (@$code) {
		    print " $line";
		}
	    }
	    print " deny ip any any\n";
	    print "interface $hardware\n";
	    print " access group $name\n\n";
	} elsif($model->{filter} eq 'PIX') {
	    for my $line (@$if_code, @$code) {
		if($line =~ /^$comment_char/) {
		    print $line;
		} else {
		    print "access-list $name $line";
		}
	    }
	    print "access-list $name deny ip any any\n";
	    print "access-group $name in $hardware\n\n";
	} elsif($model->{filter} eq 'iptables') {
	    my $if_name = "${hardware}_self";
	    for my $line (@$if_code) {
		if($line =~ /^$comment_char/) {
		    print $line;
		} else {
		    print "iptables -A $if_name $line";
		}
	    }
	    print "iptables -A $if_name -j DROP -s 0.0.0.0/0 -d 0.0.0.0/0\n";
	    for my $line (@$code) {
		if($line =~ /^$comment_char/) {
		    print $line;
		} else {
		    print "iptables -A $name $line";
		}
	    }
	    print "iptables -A $name -j DROP -s 0.0.0.0/0 -d 0.0.0.0/0\n";
	} else {
	    internal_err "unsupported router filter type '$model->{filter}'";
	}
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
	&print_pix_static($router)
	    if $model->{has_interface_level} and not $router->{static_manual};
	print "[ END $name ]\n\n";
	close STDOUT or die "Can't close $file\n";
    }
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
