#!/usr/bin/perl
# netspoc
# A Network Security Policy Compiler
# http://netspoc.berlios.de
# (c) 2002 by Heinz Knutzen <heinzknutzen@users.berlios.de>
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
# Optimize number of routing entries per router
# by replacing all routes going to the same hop 
# with the default route
my $auto_default_route = 1;
# ignore these names when reading directories:
# - CVS and RCS directories
# - CVS working files
# - directory raw for prolog & epilog files
# - Editor backup files: emacs: *~
my $ignore_files = qr/^CVS$|^RCS$|^\.#|^raw$|~$/;
# abort after this many errors
my $max_errors = 10;

####################################################################
# Error Reporting
####################################################################

sub info ( @ ) {
    print STDERR @_, "\n" if $verbose;
}

sub warning ( @ ) {
    print STDERR "Warning: ", @_, "\n";
}

# input filename from command line
my $main_file;
# filename of current input file
our $file;
# eof status of current file
our $eof;
sub add_context( $ ) {
    my($msg) = @_;
    my $at_file = ($file eq $main_file)?'':" of $file";
    my $context;
    if($eof) {
	$context = 'at EOF';
    } else {
	my($pre, $post) =
	    m/([^\s,;={}]*[,;={}\s]*)\G([,;={}\s]*[^\s,;={}]*)/;
	$context = qq/near "$pre<--HERE-->$post"/;
    }
    qq/$msg at line $.$at_file, $context\n/;
}

sub add_line( $ ) {
    my($msg) = @_;
    my $at_file = ($file eq $main_file)?'':" of $file";
    qq/$msg at line $.$at_file\n/;
}

my $error_counter = 0;

sub check_abort() {
    if(++$error_counter >= $max_errors) {
	die "Aborted after $error_counter errors\n";
    }
}
    
sub error_atline( $ ) {
    my($msg) = @_; 
    print STDERR add_line($msg);
    check_abort();
}

sub err_msg( @ ) {
    print STDERR @_, "\n";
    check_abort();
}

sub syntax_err( $ ) {
    my($msg) = @_;    
    die add_context $msg;
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

# convert IP address from internal integer representation to
# readable string
sub print_ip( $ ) {
    my $ip = shift;
    return sprintf "%vd", pack 'N', $ip;
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

my %hosts;
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
    &skip('}');
    if(my $old_host = $hosts{$name}) {
	error_atline "Redefining host:$name";
    }
    $hosts{$name} = $host;
    return @hosts;
}

my %networks;
sub read_network( $ ) {
    my $name = shift;
    my $network = new('Network',
		      name => "network:$name",
		      hosts => [],
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
	my($type, $hname) = split_typed_name(read_typed_name());
	syntax_err "Expected host definition" unless($type eq 'host');
	my @hosts = &read_host($hname);
	if($ip eq 'unnumbered') {
	    error_atline "Unnumbered network must not contain hosts";
	    # ignore host
	    next;
	}
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
	    $host->{network} = $network;
	}
	push(@{$network->{hosts}}, @hosts);
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

my %interfaces;
my @disabled_interfaces;
sub read_interface( $$ ) {
    my($router, $net) = @_;
    my $name = "$router.$net";
    my $interface = new('Interface', 
			name => "interface:$name",
			network => $net,
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
	    skip(';');
	} else {
	    syntax_err "Expected 'ip' or 'unnumbered'";
	}
	my $hardware = &check_assign('hardware', \&read_string);
	$hardware and $interface->{hardware} = $hardware;
	if(&check_flag('ospf')) {
	    $interface->{ospf} = 1;
	}
	if(&check_flag('disabled')) {
	    $interface->{disabled} = 1;
	    push @disabled_interfaces, $interface;
	}
	&skip('}');
    }
    if($interfaces{$name}) {
	error_atline "Redefining $interface->{name}";
	next;
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

my %valid_model = (IOS => 1, IOS_FW => 1, PIX => 1);
my %routers;
sub read_router( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $managed = &check_flag('managed');
    $managed = 'full' if $managed;
    my $filter = &check_assign('filter', \&read_identifier);
    if(defined $filter) {
	if($filter eq 'full') { $managed = 'full'; }
	elsif($filter eq 'secondary') { $managed = 'secondary'; }
	elsif($filter eq 'none') { $managed = 0; }
    }
    my $model = &check_assign('model', \&read_identifier);
    if($model and not $valid_model{$model}) {
	error_atline "Unknown router model '$model'";
    }
    if($managed and not $model) {
	err_msg "Missing 'model' for managed router:$name";
    }
    my $static_manual = &check_flag('static_manual');
    my $routing_manual = &check_flag('routing_manual');
    my $router = new('Router',
		     name => "router:$name",
		     managed => $managed,
		     );
    $router->{model} = $model if $managed;
    $router->{static_manual} = 1 if $static_manual and $managed;
    $router->{routing_manual} = 1 if $routing_manual and $managed;
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
	if($managed and $model eq 'PIX') {
	    set_pix_interface_level($interface);
	}
    }
    if($routers{$name}) {
	error_atline "Redefining $router->{name}";
    }
    $routers{$name} = $router;
}

my %anys;
sub read_any( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $link = &read_assign('link', \&read_typed_name);
    &skip('}');
    my $any = new('Any', name => "any:$name", link => $link);
    if($anys{$name}) {
	error_atline "Redefining $any->{name}";
    }
    $anys{$name} = $any;
}

my %everys;
sub read_every( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $link = &read_assign('link', \&read_typed_name);
    &skip('}');
    my $every = new('Every', name => "every:$name", link => $link);
    if(my $old_every = $everys{$name}) {
	error_atline "Redefining $every->{name}";
    }
    $everys{$name} = $every;
}

my %groups;
sub read_group( $ ) {
    my $name = shift;
    skip('=');
    my @objects = &read_list_or_null(\&read_typed_name);
    my $group = new('Group',
		    name => "group:$name",
		    elements => \@objects);
    if(my $old_group = $groups{$name}) {
	error_atline "Redefining $group->{name}";
    }
    $groups{$name} = $group;
}

my %servicegroups;
sub read_servicegroup( $ ) {
   my $name = shift;
   skip('=');
   my @objects = &read_list_or_null(\&read_typed_name);
   my $srvgroup = new('Servicegroup',
		      name => "servicegroup:$name",
		      elements => \@objects);
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
		$srv->{v1} = $type;
		$srv->{v2} = $code;
	    } else {
		syntax_err "Expected icmp code";
	    }
	} else {
	    $srv->{v1} = $type;
	    $srv->{v2} = 'any';
	}
    } else {
	$srv->{v1} = 'any';
    }
}

sub read_proto_nr() {
    my($srv) = @_;
    if(defined (my $nr = &check_int())) {
	error_atline "Too large protocol number $nr" if $nr > 255;
	error_atline "Invalid protocol number '0'" if $nr == 0;
	if($nr == 1) {
	    $srv->{type} = 'icmp';
	    $srv->{v1} = 'any';
	} elsif($nr == 4) {
	    $srv->{type} = 'tcp';
	    $srv->{ports} = [ 1, 65535, 1, 65535 ];
	} elsif($nr == 17) {
	    $srv->{type} = 'udp';
	    $srv->{ports} = [ 1, 65535, 1, 65535 ];
	} else {
	    $srv->{type} = 'proto';
	    $srv->{v1} = $nr;
	}
    } else {
	syntax_err "Expected protocol number";
    }
}

my %services;
sub read_service( $ ) {
    my $name = shift;
    my $srv = { name => $name };
    &skip('=');
    if(&check('ip')) {
	$srv->{type} = 'ip';
    } elsif(&check('tcp')) {
	$srv->{type} = 'tcp';
	&read_port_ranges($srv);
    } elsif(&check('udp')) {
	$srv->{type} = 'udp';
	&read_port_ranges($srv);
    } elsif(&check('icmp')) {
	$srv->{type} = 'icmp';
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
    &prepare_srv_ordering($srv);
}

my @rules;
sub read_rule( $ ) {
    my($action) = @_;
    my @src = &read_assign_list('src', \&read_typed_name);
    my @dst = &read_assign_list('dst', \&read_typed_name);
    my @srv = &read_assign_list('srv', \&read_typed_name);
    my $rule =
    { action => $action, src => \@src, dst => \@dst, srv => \@srv };
    push(@rules, $rule);
}

# reads input from file
sub read_data( $ ) {	
    local($file) = @_;
    local $eof = 0;
    local *FILE;
    open(FILE, $file) or die "can't open $file: $!";
    # set input buffer to defined state
    # when called from 'include:' ignore rest of line
    $_ = '';
    while(1) {
	last if &check_eof();
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
	    } else {
		syntax_err "Unknown global definition";
	    }
	} elsif(my $action = check_permit_deny()) {
	    &read_rule($action);
	} elsif (check('include')) {
	    my $file = read_string();
	    &read_data($file);
	} else {
	    syntax_err "Syntax error";
	}
    }
}

sub read_file_or_dir( $ ) {
    my($path) = @_;
    if(-f $path) {
	read_data $path;
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
    $n = @rules;
    info "Read $n rules";
}

##############################################################################
# Helper functions
##############################################################################

# Type checking functions
sub is_net( $ )          { ref($_[0]) eq 'Network'; }
sub is_router( $ )       { ref($_[0]) eq 'Router'; }
sub is_interface( $ )    { ref($_[0]) eq 'Interface'; }
sub is_host( $ )         { ref($_[0]) eq 'Host'; }
sub is_any( $ )          { ref($_[0]) eq 'Any'; }
sub is_every( $ )        { ref($_[0]) eq 'Every'; }
sub is_group( $ )        { ref($_[0]) eq 'Group'; }
sub is_servicegroup( $ ) { ref($_[0]) eq 'Servicegroup'; }

sub print_rule( $ ) {
    my($rule) = @_;
    if($rule->{orig_any}) { $rule = $rule->{orig_any}; }
    my $srv = exists($rule->{orig_srv}) ? 'orig_srv' : 'srv';
    return $rule->{action} .
	" src=$rule->{src}->{name}; dst=$rule->{dst}->{name}; " .
	"srv=$rule->{$srv}->{name};";
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
# ToDo:
# - augment existing ranges by hosts or other ranges
# ==> support chains of network > range > range .. > host
sub mark_ip_ranges( $ ) {
    my($network) = @_;
    my @hosts = grep { $_->{ip} } @{$network->{hosts}};
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
			    network => $aref->[$start_range]->{network});
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
    my $type = $srv->{type};
    if($type eq 'tcp' or $type eq 'udp') {
	push @{$srv_hash{$type}}, $srv;
    } else { # ip, proto, icmp
	my $v1 = $srv->{v1};
	my $v2 = $srv->{v2};
	my $main_srv;
	if(defined $v2) {
	    $main_srv = $srv_hash{$type}->{$v1}->{$v2} or
		$srv_hash{$type}->{$v1}->{$v2} = $srv;
	} elsif(defined $v1) {
	    $main_srv = $srv_hash{$type}->{$v1} or
		$srv_hash{$type}->{$v1} = $srv;
	} else {
	    $main_srv = $srv_hash{$type} or
		$srv_hash{$type} = $srv;
	}
	if($main_srv) {
	    # found duplicate service definition
	    # link $srv with $main_srv
	    # We link all duplicate services to the first service found.
	    # This assures that we always reach the main service
	    # from any duplicate service in one step via ->{main}
	    # This is used later to substitute occurrences of
	    # $srv with $main_srv
	    $srv->{main} = $main_srv;
	}
    }
}

sub order_icmp( $$ ) {
    my($hash, $up) = @_;
    if($hash->{any}) {
	$hash->{any}->{up} = $up;
	$up = $hash->{any};
    }
    while(my($type, $hash2) = each(%$hash)) {
	my $up = $up;
	next if $type eq 'any';
	if($hash2->{any}) {
	    $hash2->{any}->{up} = $up;
	    $up = $hash2->{any};
	}
	while(my($code, $srv) = each(%$hash2)) {
	    next if $code eq 'any';
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
    my($range_aref, $up) = @_;
    for my $srv1 (@$range_aref) {
	next if $srv1->{main};
	my @p1 = @{$srv1->{ports}};
	my $min_size_src = 65536;
	my $min_size_dst = 65536;
	$srv1->{up} = $up;
	for my $srv2 (@$range_aref) {
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

sub order_services() {
    my $up = undef;
    if($srv_hash{ip}) {
	$up = $srv_hash{ip};
    }
    order_ranges($srv_hash{tcp}, $up) if $srv_hash{tcp};
    order_ranges($srv_hash{udp}, $up) if $srv_hash{udp};
    order_icmp($srv_hash{icmp}, $up) if $srv_hash{icmp};
    order_proto($srv_hash{proto}, $up) if $srv_hash{proto};

    # it doesn't hurt to set {up} for services with {main} defined
    for my $srv (values %services) {
	my $depth = 0;
	my $up = $srv;
	while($up = $up->{up}) {
	    $depth++;
	}
	$srv->{depth} = $depth;
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
    my $net = $networks{$net_name};
    unless($net) {
	err_msg "Referencing undefined network:$net_name ",
	    "from $interface->{name}";
	# prevent further errors
	$interface->{disabled} = 1;
	return;
    }
    $interface->{network} = $net;
    my $ip = $interface->{ip};
    # check if the network is already linked with another interface
    if(defined $net->{interfaces}) {
	my $old_intf = $net->{interfaces}->[0];
	# if network is already linked to a short interface
	# it must not be linked to any other interface
	if($old_intf->{ip} eq 'short') {
	    err_msg "$net->{name} must not be linked with $interface->{name},\n",
	    " since it is already linked with short $old_intf->{name}";
	}
	# if network is already linked to any interface
	# it must not be linked to a short interface
	if($ip eq 'short') {
	    err_msg "$net->{name} must not be linked with $old_intf->{name},\n",
	    " since it is already linked with short $interface->{name}";
	}
    } 

    if($ip eq 'short') {
	# nothing to check: short interface may be linked to arbitrary network
    } elsif($ip eq 'unnumbered') {
	$net->{ip} eq 'unnumbered' or
	    err_msg "unnumbered $interface->{name} must not be linked ",
	    "to $net->{name}";
    } else {
	# check compatibility of interface ip and network ip/mask
	for my $interface_ip (@$ip) {
	    my $net_ip = $net->{ip};
	    if($net_ip eq 'unnumbered') {
		err_msg "$interface->{name} must not be linked ",
		"to unnumbered $net->{name}";
	    }
	    my $mask = $net->{mask};
	    if($net_ip != ($interface_ip & $mask)) {
		err_msg "$interface->{name}'s IP doesn't match ",
		"$net->{name}'s IP/mask";
	    }
	}
    }
    push(@{$net->{interfaces}}, $interface);
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
    } elsif(is_net($ob)) {
	return 'network';
    } elsif(is_any($ob)) {
	return 'any';
    } else {
	internal_err "expected host|network|any but got '$ob->{name}'";
    }
}

# new block with private global variables
{
    # hash for ordering permit any rules; 
    # when sorted, they are added later to @expanded_any_rules
    my %ordered_any_rules;

    sub order_any_rule ( $ ) {
	my($rule) = @_;
	my $depth = $rule->{srv}->{depth};
	my $srcid = typeof($rule->{src});
	my $dstid = typeof($rule->{dst});
	push @{$ordered_any_rules{$depth}->{$srcid}->{$dstid}}, $rule;
    }

    # counter for expanded permit any rules
    my $anyrule_index = 0;

    # add all rules with matching srcid and dstid to expanded_any_rules
    sub add_rule_2hash( $$$$ ) {
	my($result_aref, $hash, $srcid, $dstid) = @_;
	my $rules_aref = $hash->{$srcid}->{$dstid};
	if(defined $rules_aref) {
	    for my $rule (@$rules_aref) {
		# add an incremented index to each any rule
		# for simplifying a later check if one rule
		# influences another one
		$rule->{i} = $anyrule_index++;
		push(@$result_aref, $rule);
	    }
	}
    }

    sub add_ordered_any_rules( $ ) {
	my($aref) = @_;
	for my $depth (reverse sort keys %ordered_any_rules) {
	    my $hash = $ordered_any_rules{$depth};
	    next unless defined $hash;
	    add_rule_2hash($aref, $hash, 'any','host');
	    add_rule_2hash($aref, $hash, 'host','any');
	    add_rule_2hash($aref, $hash, 'any','network');
	    add_rule_2hash($aref, $hash, 'network','any');
	    add_rule_2hash($aref, $hash, 'any','any');
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
	    # split a router into its interfaces
	    push @objects, @{$object->{interfaces}};
	} elsif(is_every $object) {
	    # expand an 'every' object to all networks in its security domain
	    push @objects,  @{$object->{link}->{any}->{networks}};
	} else {
	    push @objects, $object;
	}
    }
    for my $object (@objects) {
	if($object->{disabled}) {
	    $object = undef;
	} elsif(is_net $object) {
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
my @expanded_deny_rules;
# array of expanded permit rules
my @expanded_rules;
# array of expanded any rules
my @expanded_any_rules;
# hash for ordering all rules:
# $rule_tree{$action}->{$src}->[0]->{$dst}->[0]->{$srv} = $rule;
# see &add_rule for details
my %rule_tree;

sub expand_rules() {
    for my $rule (@rules) {
	my $action = $rule->{action};
	$rule->{src} = expand_group $rule->{src}, 'src of rule';
	$rule->{dst} = expand_group $rule->{dst}, 'dst of rule';
	
	for my $src (@{$rule->{src}}) {
	    for my $dst (@{$rule->{dst}}) {
		for my $srv (@{expand_services $rule->{srv}, 'rule'}) {
		    my $expanded_rule = { action => $action,
					  src => $src,
					  dst => $dst,
					  srv => $srv
					  };
		    # if $srv is duplicate of an identical service
		    # use the main service, but remember the original one
		    # for debugging / comments
		    if(my $main_srv = $srv->{main}) {
			$expanded_rule->{srv} = $main_srv;
			$expanded_rule->{orig_srv} = $srv;
		    }
		    # Mark rules with managed interface as src or dst 
		    # because they get special handling during code generation
		    if(is_interface($src) and $src->{router}->{managed} or
		       is_interface($dst) and $dst->{router}->{managed}) {
			$expanded_rule->{managed_if} = 1;
		    }
		    if($action eq 'deny') {
			push(@expanded_deny_rules, $expanded_rule);
			&add_rule($expanded_rule);
		    } elsif(is_any($src) and is_any($dst)) {
			err_msg "Rule '", print_rule $expanded_rule, "'\n",
			" has 'any' objects both as src and dst.\n",
			" This is not supported currently. ",
			"Use one 'every' object instead";
		    } elsif(is_any($src)) {
			$expanded_rule->{deny_src_networks} = [];
			order_any_rule($expanded_rule);
		    } elsif(is_any($dst)) {
			$expanded_rule->{deny_dst_networks} = [];
			order_any_rule($expanded_rule);
		    } else {
			push(@expanded_rules, $expanded_rule);
			&add_rule($expanded_rule);
		    }
		}
	    }
	}
    }
    # add ordered 'any' rules which have been ordered by order_any_rule
    add_ordered_any_rules(\@expanded_any_rules);
    for my $expanded_rule (@expanded_any_rules) {
	&add_rule($expanded_rule);
    }
    if($verbose) {
	my $nd = 0+@expanded_deny_rules;
	my $n  = 0+@expanded_rules;
	my $na = 0+@expanded_any_rules;
	info "Expanded rules:\n",
	" deny $nd, permit: $n, permit any: $na";
    }
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
# ToDo:
# May the deny rule influence any other rules where
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
	    next unless $arule->{deny_src_networks};
	    my $dst_any = $dst->{network}->{any} or
		internal_err "No 'any' object in security domain of $dst";
	    for my $net (@{$arule->{deny_src_networks}}) {
		for my $host (@{$net->{hosts}}, @{$net->{interfaces}}) {
		    # Don't repair, even if managed interface is src
		    next if is_interface $host and $host->{router}->{managed};
		    # search for rules with action = permit, src = host and
		    # dst = dst_any in $rule_tree
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
				      srv => $arule->{srv}
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
	if(is_net $obj) {
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
sub setpath_obj( $$$$ ) {
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
	$obj->{right} and err_msg "found nested loop at $obj->{name}";
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
	    $in_loop and err_msg "found nested loop at $obj->{name}";
	    $in_loop = $loop;
	    $interface->{right} = $obj;
	    $obj->{left} = $interface
	} else {
	    # continue marking loopless path
	    $interface->{main} = $obj;
	}
    }
    $obj->{active_path} = 0;
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
    &setpath_obj($any1, $interface, 2, 0);

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
    } elsif(is_net $obj) {
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
    } elsif(is_net($obj)) {
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
   
# Mark path from src to dst
sub path_mark( $$ ) {
    my ($src, $dst) = @_;
    my $from = $src;
    my $to = $dst;
    my $from_in;
    my $to_out;
    my $from_loop = $from->{loop};
    my $to_loop = $to->{loop};
    while(1) {
	# paths meet outside a loop or at the edge of a loop
	return if $from eq $to;
	# paths meet inside a loop	
	if($from_loop and $to_loop and $from_loop eq $to_loop) {
	    $from->{$dst} = $to;
	    return;
	}
	if($from->{distance} >= $to->{distance}) {
	    if($from_loop) {
		$from->{$dst} = $from_loop;
		$from = $from_loop;
	    }
	    my $from_out = $from->{main};
	    $from->{$dst} = $from_out;
	    $from = $from_out->{main};
	    $from_out->{$dst} = $from;
	    $from_in = $from_out;
	    $from_loop = $from->{loop};
	} else {
	    if($to_loop) {
		$to_loop->{$dst} = $to;
		$to = $to_loop;
	    }
	    my $to_in = $to->{main};
	    $to_in->{$dst} = $to;
	    $to = $to_in->{main};
	    $to->{$dst} = $to_in;
	    $to_out = $to_in;
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

sub go_path( $$$$$$$$ ) {
    my($rule, $fun, $where, $from_in, $from, $to, $to_out, $path) = @_;
    while($from ne $to) {
	my $from_out = $from->{$path};
	&$fun($rule, $from_in, $from_out) if ref($from) eq $where;
	$from = $from_out->{$path};
	$from_in = $from_out;
    }
    &$fun($rule, $from_in, $to_out) if ref($from) eq $where;
}

sub go_loop( $$$$$$$ ) {
    my($rule, $fun, $where, $from_in, $from, $to, $to_out, $path) = @_;
    if($where eq 'Any') {
	# processing routes: take only the shortest path throug loop
	# ToDo: rethink, is this always the right thing to do?
	my $node = $from;
	my $left_len = 0;
	while($node ne $to) {
	    $node = $node->{left}->{left};
	    $left_len++;
	}
	$node = $from;
	my $right_len = 0;
	while($node ne $to) {
	    $node = $node->{right}->{right};
	    $right_len++;
	}
	if($left_len == $right_len) {
	    # Generate duplicate routing entry for the current destination.
	    # This may be ok, if only one interface is active,
	    # or generation of routing entries may be disabled at all
	    # for the current router using 'routing_manual'
	    &go_path(@_, 'left');
	    &go_path(@_, 'right');
	}
	if($left_len < $right_len) {
	    &go_path(@_, 'left');
	} else {
	    &go_path(@_, 'right');
	}
    } else {
	&go_path(@_, 'left');
	&go_path(@_, 'right');
    }
}    

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
#	my($rule, $from_in, $from_out) = @_;
#	path_info $from_in, $from_out;
#	&$fun2($rule, $from_in, $from_out);
#    };
    if($from eq $to) {
	unless($src eq $dst) {
	    warning "Unenforceable rule\n ", print_rule($rule);
	}
	# don't process rule again later
	$rule->{deleted} = $rule;
	return;
    }
    &path_mark($from, $to) unless $from->{$to};
    my $from_in;
    my $from_loop = $from->{loop};
    my $to_loop = $to->{loop};
    while($from ne $to) {
	if($from_loop and $to_loop and $from_loop eq $to_loop) {
	    # path terminates at a loop
	    # $from ne $to ==> go through loop in both directions
	    &go_loop($rule, $fun, $where, $from_in, $from, $to, undef);
	    return;
	}
	# does it go through a loop or does it only touch the loop at an edge
	# ToDo: Find a better test / data structure
	if($from_loop && $from->{$to}->{loop}) {
	    # go through loop to exit of loop
	    my $to_loop = $from->{$to};
	    my $loop_out = $to_loop->{$to};
	    &go_loop($rule, $fun, $where, $from_in, $from, $to_loop, $loop_out);
	    $from = $loop_out->{$to};
	    $from_in = $loop_out;
	} else {
	    my $from_out = $from->{$to};
	    &$fun($rule, $from_in, $from_out) if ref($from) eq $where;
	    $from = $from_out->{$to};
	    $from_in = $from_out;
	}
	$from_loop = $from->{loop};
    }
#    path_info $from_in, undef if is_router $to;
    &$fun($rule, $from_in, undef) if ref($to) eq $where;
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
		    i => $rule->{i},
		    orig_any => $rule,
		    deny_src_networks => [ @{$any->{networks}} ]
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
    if($router->{model} eq 'PIX' or $router->{model} eq 'IOS_FW') {
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
			i => $rule->{i},
			orig_any => $rule,
			deny_dst_networks => [ @{$any->{networks}} ],
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
# Mark and optimize rules at secondary filters
# At secondary packet filters, we check only for src and dst network
##############################################################################

sub mark_secondary_rule( $$$ ) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $router = ($src_intf || $dst_intf)->{router};
    if($router->{managed} eq 'full' and not $router->{loop}) {
	$rule->{has_full_filter} = 1;
    } elsif($router->{managed} eq 'secondary') {
	$rule->{has_secondary_filter} = 1;
    }
}

sub mark_secondary_rules() {
    info "Marking and optimizing rules of secondary filters";
    # mark only normal rules for optimization, not 'deny', not 'any'
    my %secondary_rule_tree;
    for my $rule (@expanded_rules) {
	next if $rule->{deleted};
	&path_walk($rule, \&mark_secondary_rule, 'Router');
	if($rule->{has_secondary_filter} = 
	   $rule->{has_secondary_filter} && $rule->{has_full_filter}) {
	    # get_networks has a single result if not called 
	    # with an 'any' object as argument
	    my $src = get_networks $rule->{src};
	    my $dst = get_networks $rule->{dst};
	    my $old_rule = $secondary_rule_tree{$src}->{$dst};
	    if($old_rule) {
		# found redundant rule
		$old_rule->{secondary_deleted} = $rule;
	    }
	    $secondary_rule_tree{$src}->{$dst} = $rule;
	}
    }
}

##############################################################################
# Optimize expanded rules by deleting identical rules and 
# rules which are overlapped by a more general rule
##############################################################################

# Add rule to $rule_tree 
sub add_rule( $ ) {
    my ($rule) = @_;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    my $old_rule =$rule_tree{$action}->{$src}->[0]->{$dst}->[0]->{$srv};
    if($old_rule) {
	# Found identical rule
	# For 'any' rules we must preserve the rule without deny_networks
	# i.e. auto_any < any
	if($action eq 'permit' and
	   (is_any $src and @{$rule->{deny_src_networks}} == 0
	    or
	    is_any $dst and @{$rule->{deny_dst_networks}} == 0)) {
	    $old_rule->{deleted} = $rule;
	    # continue adding new rule below
	} else {
	    $rule->{deleted} = $old_rule;
	    return;
	}
    } 
    $rule_tree{$action}->{$src}->[0]->{$dst}->[0]->{$srv} = $rule;
    $rule_tree{$action}->{$src}->[1] = $src;
    $rule_tree{$action}->{$src}->[0]->{$dst}->[1] = $dst;
}

# delete an element from an array reference
# return 1 if found, 0 otherwise
sub aref_delete( $$ ) {
    my($elt, $aref) = @_;
    for(my $i = 0; $i < @$aref; $i++) {
	if($aref->[$i] eq $elt) {
	    splice @$aref, $i, 1;
	    return 1;
	}
    }
    return 0;
}

#
# cmp permit auto_any(deny_net: net1,net2) dst srv
# chg permit net1 dst srv
# -->
# cmp permit auto_any(deny_net: net2) dst srv
#
# cmp permit auto_any(deny_net: net1,net2) dst' srv'
# chg permit net1 dst srv
# --> if dst >= dst', srv >= srv'
# cmp permit auto_any(deny_net: net2) dst srv'
# chg permit net1 dst srv
#
# cmp permit auto_any(deny_net: -) dst srv
# chg permit auto_any(deny_net: net2,net3) dst srv'
# --> if srv >= srv'
# cmp permit auto_any(deny_net: -) dst srv
#
# cpm permit auto_any(deny_net: net1,net2) dst srv
# chg permit auto_any(deny_net: net1,net2) dst srv'
# --> if srv >= srv'
# cmp permit auto_any(deny_net: net1,net2) dst srv
#
# cmp permit auto_any(deny_net: net1,net2) dst srv
# chg permit auto_any(deny_net: net2,net3) dst srv'
# --> if srv >= srv'
# cmp permit auto_any(deny_net: net1,net2) dst srv
# chg permit auto_any(deny_net: net3) dst srv'
#
# ToDo: Why aren't these optimizations applicable to deny rules?
#
sub optimize_auto_any_rules( $$ ) {
    my($cmp_rule, $chg_rule) = @_;
    if($cmp_rule->{action} eq 'permit' and
       $chg_rule->{action} eq 'permit'){
	if(is_any $cmp_rule->{src}) {
	    if(is_net $chg_rule->{src} and
	       aref_delete($chg_rule->{src}, $cmp_rule->{deny_src_networks})) {
		if($cmp_rule->{dst} eq $chg_rule->{dst} and
		   $cmp_rule->{srv} eq $chg_rule->{srv}) {
		    $chg_rule->{deleted} = $cmp_rule;
		}
		return 1;
	    }
	    elsif(is_any $chg_rule->{src}) {
		if(@{$cmp_rule->{deny_src_networks}} == 0) {
		    $chg_rule->{deleted} = $cmp_rule;
		} else {
		    my $equal_deny_net = 1;
		    for my $net (@{$cmp_rule->{deny_src_networks}}) {
			$equal_deny_net &=
			    aref_delete $net, $chg_rule->{deny_src_networks};
		    }
		    if($equal_deny_net) {
			$chg_rule->{deleted} = $cmp_rule;
		    }
		}
		return 1;
	    }
	}
# equivalent for auto_any at dst
	if(is_any $cmp_rule->{dst}) {
	    if(is_net $chg_rule->{dst} and
	       aref_delete($chg_rule->{dst}, $cmp_rule->{deny_dst_networks})) {
		if($cmp_rule->{src} eq $chg_rule->{src} and
		   $cmp_rule->{srv} eq $chg_rule->{srv}) {
		    $chg_rule->{deleted} = $cmp_rule;
		}
		return 1;
	    }
	    elsif(is_any $chg_rule->{dst}) {
		if(@{$cmp_rule->{deny_dst_networks}} == 0) {
		    $chg_rule->{deleted} = $cmp_rule;
		} else {
		    my $equal_deny_net = 1;
		    for my $net (@{$cmp_rule->{deny_dst_networks}}) {
			$equal_deny_net &=
			    aref_delete $net, $chg_rule->{deny_dst_networks};
		    }
		    if($equal_deny_net) {
			$chg_rule->{deleted} = $cmp_rule;
		    }
		}
		return 1;
	    }
	}
    }
    return 0;
}

# A rule may be deleted if we find a similar rule with greater or equal srv.
# Property of parameters:
# Rules in $cmp_hash >= rules in $chg_hash
sub optimize_srv_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;
 
    # optimize full rules
    for my $chg_rule (values %$chg_hash) {
	my $srv = $chg_rule->{srv};
	while($srv) {
	    if(my $cmp_rule = $cmp_hash->{$srv}) {
		unless($cmp_rule eq $chg_rule) {
		    unless(&optimize_auto_any_rules($cmp_rule, $chg_rule)) { 
			$chg_rule->{deleted} = $cmp_rule;
		    }
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
	} elsif(is_net($dst)) {
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
	} elsif(is_net($src)) {
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
sub optimize_rules() {
    my $deny_hash;
    if($deny_hash = $rule_tree{deny}) {
	&optimize_src_rules($deny_hash, $deny_hash);
    }
    if(my $permit_hash = $rule_tree{permit}) {
	&optimize_src_rules($permit_hash, $permit_hash);
	$deny_hash and
	    &optimize_src_rules($deny_hash, $permit_hash);
    }
}

sub optimize() {
    info "Optimization";
    &optimize_rules();
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

####################################################################
# Routing
# Add a component 'route' to each interface.
# It holds an array of networks reachable
# using this interface as next hop
####################################################################

# A security domain with multiple networks has some unmanaged routers.
# For each interface at the border of a security domian,
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
	    $in_intf->{routing}->{$hop}->{$network} = $network;
	    # Store $hop itself, since we need to go back 
	    # from hash key to original object later.
	    $in_intf->{hop}->{$hop} = $hop;
	}
	# Remember which networks are reachable via $back_hop
	for my $network (values %{$rule->{src_networks}}) {
	    # ignore directly connected network
	    next if $network eq $out_intf->{network};
	    $out_intf->{routing}->{$back_hop}->{$network} = $network;
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
	    $in_intf->{routing}->{$hop}->{$network} = $network;
	    $in_intf->{hop}->{$hop} = $hop;
	}
    } elsif($out_intf) { # and not $in_intf
	# path ends here
	for my $network (values %{$rule->{src_networks}}) {
	    # ignore directly connected network
	    next if $network eq $out_intf->{network};
	    my $back_hop = $out_intf->{network}->{route_in_any}->{$network};
	    $out_intf->{routing}->{$back_hop}->{$network} = $network;
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
	    # Sort interfaces by name to make output deterministic
	    for my $hop (sort { $a->{name} cmp $b->{name} }
			 values %{$interface->{hop}}) {
		my $count = keys %{$interface->{routing}->{$hop}};
		if($count > $max) {
		    $max_intf = $interface;
		    $max_hop = $hop;
		    $max = $count;
		}
	    }
	}
	if($max_intf && $max_hop) {
	    # use default route for this direction
	    $max_intf->{routing}->{$max_hop} = { $network_default =>
						     $network_default };
	}
    }
    for my $interface (@{$router->{interfaces}}) {
	# Sort interfaces by name to make output deterministic
	for my $hop (sort { $a->{name} cmp $b->{name} }
		     values %{$interface->{hop}}) {
	    # for unnumbered networks use interface name as next hop
	    my $hop_addr = $hop->{ip} eq 'unnumbered' ?
		$interface->{hardware} : print_ip $hop->{ip}->[0];
	    # A hash having all networks reachable via current hop
	    # as key as well as value.
	    my $net_hash = $interface->{routing}->{$hop};
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
		my $adr = &adr_code($network, 0);
		if($router->{model} =~ /^IOS/) {
		    print "ip route $adr\t$hop_addr\n";
		} elsif($router->{model} eq 'PIX') {
		    print "route $interface->{hardware} $adr\t$hop_addr\n";
		} else {
		    internal_err "unexpected router model $router->{model}";
		}
	    }
	}
    }
}

##############################################################################
# 'static' commands for pix firewalls
##############################################################################
sub mark_networks_for_static( $$$ ) {
    my($rule, $src_intf, $dst_intf) = @_;
    # no static needed for directly attached interface
    return unless $dst_intf;
    return unless $dst_intf->{router}->{model} eq 'PIX';
    # no static needed for traffic coming from the pix itself
    return unless $src_intf;
    # no static needed for traffic from higher to lower security level
    return if $src_intf->{level} > $dst_intf->{level};
    die "Traffic to $rule->{dst}->{name} can't pass\n",
    " from  $src_intf->{name} to $dst_intf->{name},\n",
    " since they have equal security levels.\n"
	if $src_intf->{level} == $dst_intf->{level};

    for my $net (values %{$rule->{dst_networks}}) {
	next if $net->{ip} eq 'unnumbered';
	# collect networks reachable from lower security level
	# for generation of static commands
	$net->{mask} == 0 and
	    die "Pix doesn't support static command for mask 0.0.0.0 of $net->{name}\n";
	# put networks into a hash to prevent duplicates
	$dst_intf->{static}->{$src_intf->{hardware}}->{$net} = $net;
    }
}

sub print_pix_static( $ ) {
    my($router) = @_;
    print "[ Static ]\n";
    print "! Security levels: ";
    my $last_level;
    for my $interface (sort { $a->{level} <=> $b->{level} }
		       @{$router->{interfaces}} ) {
	my $level = $interface->{level};
	if(defined $last_level) {
	    print(($last_level == $level)? " = ": " < ");
	}
	print $interface->{hardware};
	$last_level = $level;
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

sub split_ip_range( $$$ ) {
    my($a, $b, $inv_mask) = @_;
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
	if($mask == 0xffffffff) {
	    push @result, 'host '. &print_ip($i);
	} else {
	    my $ip_code = &print_ip($i);
	    my $mask_code = &print_ip($inv_mask?~$mask:$mask);
	    push @result, "$ip_code $mask_code";
	}
	$i += $add;
    }
    return @result;
}

sub adr_code( $$ ) {
    my ($obj, $inv_mask) = @_;
    if(is_host($obj)) {
	if($obj->{range}) {
	    return &split_ip_range(@{$obj->{range}}, $inv_mask);
	} else {
	    return 'host '. &print_ip($obj->{ip});
	}
    }
    if(is_interface($obj)) {
	if($obj->{ip} eq 'unnumbered' or $obj->{ip} eq 'short') {
	    internal_err "unexpected $obj->{ip} $obj->{name}\n";
	} else {
	    return map { 'host '. &print_ip($_) } @{$obj->{ip}};
	}
    } elsif(is_net($obj)) {
	if($obj->{ip} eq 'unnumbered') {
	    internal_err "unexpected unnumbered $obj->{name}\n";
	} else {
	    my $ip_code = &print_ip($obj->{ip});
	    my $mask_code = &print_ip($inv_mask?~$obj->{mask}:$obj->{mask});
	    return "$ip_code $mask_code";
	}
    } elsif(is_any($obj)) {
	return 'any';
    } else {
	internal_err "unexpected object $obj->{name}";
    }
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

sub range_code( $$ ) {
    my($v1, $v2) = @_;
    if($v1 == $v2) {
	return("eq $v1");
    } elsif($v1 == 1 and $v2 == 65535) {
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
}

# returns 3 values for building an ACL:
# permit <val1> <src> <val2> <dst> <val3>
sub srv_code( $$ ) {
    my ($srv, $model) = @_;
    my $proto = $srv->{type};

    if($proto eq 'ip') {
	return('ip', '', '');
    } elsif($proto eq 'tcp' or $proto eq 'udp') {
	my @p = @{$srv->{ports}};
	return($proto, &range_code(@p[0,1]), &range_code(@p[2,3]));
    } elsif($proto eq 'icmp') {
	my $type = $srv->{v1};
	if($type eq 'any') {
	    return($proto, '', '');
	} else {
	    my $code = $srv->{v2};
	    if($code eq 'any') {
		return($proto, '', $type);
	    } else {
		if($model eq 'PIX') {
		    # PIX can't handle the ICMP code field.
		    # If we try to permit e.g. "port unreachable", 
		    # "unreachable any" could pass the PIX. 
		    $pix_srv_hole{$srv->{name}}++;
		    return($proto, '', $type);
		} else {
		    return($proto, '', "$type $code");
		}
	    }
	}
    } elsif($proto eq 'proto') {
	my $nr = $srv->{v1};
	return($nr, '', '');
    } else {
	internal_err "a rule has unknown protocol '$proto'";
    }
}

sub collect_acls( $$$ ) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    # Traffic from src reaches this router via src_intf
    # and leaves it via dst_intf 
    # src_intf is undefined if src is an interface of the current router
    # analogous for dst_intf 
    my $router = ($src_intf || $dst_intf)->{router};
    # this is a secondary packet filter:
    # we need to filter only IP-Addresses
    my $secondary =
	$router->{managed} eq 'secondary' && $rule->{has_full_filter};
    if($secondary) {
	$src = get_networks $src;
	$dst = get_networks $dst;
    }
    # Rules from / to managed interfaces must be processed
    # at the corresponding router even if they are marked as deleted.
    # ToDo: Rethink about different 'deleted' attributes
    if($rule->{deleted} || $secondary && $rule->{secondary_deleted}) {
	# we are on an intermediate router
	# if both $src_intf and $dst_intf are defined
	return if defined $src_intf and defined $dst_intf;
# ToDo: Check if this optimization is valid
#	if(not defined $src_intf) {
#	    # src is an interface of the current router
#	    # and it was deleted because we have a similar rule
#	    # for an interface of the current router
#	    if($src eq $rule->{deleted}->{src}) {
#		# The rule in {deleted} may be ineffective
#		# if it is an interface -> any rule with attached auto-deny rule(s)
#		# ToDo: Check if one of deny_dst_networks matches $src
#		return unless is_any $rule->{deleted}->{dst} and
#		    $rule->{deleted}->{deny_dst_networks};
#	    }
#	}
#	if(not defined $dst_intf) {
#	    if($dst eq $rule->{deleted}->{dst}) {
#		# ToDo: see above
#		return unless is_any $rule->{deleted}->{src} and
#		    $rule->{deleted}->{deny_src_networks};
#	    }
#	}
    }
    my $model = $router->{model};
    my $inv_mask = $model =~ /^IOS/;
    my @src_code = &adr_code($src, $inv_mask);
    my @dst_code = &adr_code($dst, $inv_mask);
    my ($proto_code, $src_port_code, $dst_port_code) = &srv_code($srv, $model);
    if(defined $src_intf) {
	my $code_aref;
	# Packets for the router itself
	if(not defined $dst_intf) {
	    # For PIX firewalls it is unnecessary to generate permit ACLs
	    # for packets to the pix itself
	    # because it accepts them anyway (telnet, IPSec)
	    # ToDo: Check if this assumption holds for deny ACLs as well
	    return if $model eq 'PIX' and $action eq 'permit';
	    $code_aref = \@{$router->{if_code}->{$src_intf->{hardware}}};
	} else {
	    # collect generated code at hardware interface,
	    # not at logical interface
	    $code_aref = \@{$router->{code}->{$src_intf->{hardware}}};
	}
	if($comment_acls) {
	    push(@$code_aref, "! ". print_rule($rule)."\n");
	}
	for my $src_code (@src_code) {
	    for my $dst_code (@dst_code) {
		push(@$code_aref,
		     $secondary ?
		     "$action ip $src_code $dst_code\n" :
		     "$action $proto_code $src_code $src_port_code $dst_code $dst_port_code\n");
	    }
	}
	# Code for stateless IOS: automatically permit return packets
	# for TCP and UDP
	if($model eq 'IOS' and defined $dst_intf and
	   ($srv->{type} eq 'tcp' or $srv->{type} eq 'udp')) {
	    $code_aref = \@{$router->{code}->{$dst_intf->{hardware}}};
	    if($comment_acls) {
		push(@$code_aref, "! REVERSE: ". print_rule($rule)."\n");
	    }
	    my $established = $srv->{type} eq 'tcp' ? 'established' : '';
	    for my $src_code (@src_code) {
		for my $dst_code (@dst_code) {
		    push(@$code_aref,
			 $secondary ?
			 "$action ip $dst_code $src_code\n" :
			 "$action $proto_code $dst_code $dst_port_code $src_code $src_port_code $established\n");
		}
	    }
	}
    } elsif(defined $dst_intf) {
	# src_intf is undefined: src is an interface of this router
	# No filtering necessary for packets to PIX itself
	return if $model eq 'PIX' and $action eq 'permit';
	# For IOS only packets from dst back to this router are filtered
	if($srv->{type} eq 'tcp' or $srv->{type} eq 'udp') {
	    my $code_aref = \@{$router->{if_code}->{$dst_intf->{hardware}}};
	    if($comment_acls) {
		push(@$code_aref, "! REVERSE: ". print_rule($rule)."\n");
	    }
	    my $established = $srv->{type} eq 'tcp' ? 'established' : '';
	    for my $src_code (@src_code) {
		for my $dst_code (@dst_code) {
		    push(@$code_aref,
			 $secondary ?
			 "$action ip $dst_code $src_code\n" :
			 "$action $proto_code $dst_code $dst_port_code $src_code $src_port_code $established\n");
		}
	    }
	}
    } else {
	internal_err "no interfaces for ", print_rule($rule);
    }
}

# For deny and permit rules with src=any:*, call collect_acls only for
# the first router on the path from src to dst
sub collect_acls_at_src( $$$ ) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $src = $rule->{src};
    is_any $src or internal_err "$src must be of type 'any'";
    # the main rule is only processed at the first router on the path
    if($src_intf->{any} eq $src) {
	&collect_acls(@_)
	    unless $rule->{deleted} and not $rule->{managed_if};
    }
    # auxiliary rules are never needed at the first router
    elsif(exists $rule->{any_rules}) {
	# check for auxiliary 'any' rules
	for my $any_rule (@{$rule->{any_rules}}) {
	    next unless $src_intf->{any} eq $any_rule->{src};
	    next if $any_rule->{deleted} and not $any_rule->{managed_if};
	    # Generate code for deny rules directly in front of
	    # the corresponding permit 'any' rule
	    for my $deny_network (@{$any_rule->{deny_src_networks}}) {
		my $deny_rule = {action => 'deny',
				 src => $deny_network,
				 dst => $any_rule->{dst},
				 srv => $any_rule->{srv}
			     };
		&collect_acls($deny_rule, $src_intf, $dst_intf);
	    }
	    &collect_acls($any_rule, $src_intf, $dst_intf);
	}
    }
}

# For permit dst=any:*, call collect_acls only for
# the last router on the path from src to dst
sub collect_acls_at_dst( $$$ ) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $dst = $rule->{dst};
    is_any $dst or internal_err "$dst must be of type 'any'";
    # this is called for the main rule and its auxiliary rules
    #
    # first build a list of all adjacent 'any' objects
    my @neighbour_anys;
    for my $intf (@{$dst_intf->{router}->{interfaces}}) {
	next if $src_intf and $intf eq $src_intf;
	push @neighbour_anys, $intf->{any};
    }
    # generate deny rules in a first pass, since all related
    # 'any' rules must be placed behind them
    for my $any_rule (@{$rule->{any_rules}}) {
	next unless grep { $_ eq $any_rule->{dst} } @neighbour_anys;
	next if $any_rule->{deleted} and not $any_rule->{managed_if};
	for my $deny_network (@{$any_rule->{deny_dst_networks}}) {
	    my $deny_rule = {action => 'deny',
			     src => $any_rule->{src},
			     dst => $deny_network,
			     srv => $any_rule->{srv}
			 };
	    &collect_acls($deny_rule, $src_intf, $dst_intf);
	}
    }
    for my $any_rule ($rule, @{$rule->{any_rules}}) {
	next unless grep { $_ eq $any_rule->{dst} } @neighbour_anys;
	next if $any_rule->{deleted} and not $any_rule->{managed_if};
	if($any_rule->{any_dst_group}) {
	    unless($any_rule->{any_dst_group}->{active}) {
		&collect_acls($any_rule, $src_intf, $dst_intf);
		$any_rule->{any_dst_group}->{active} = 1;
	    }
	} else {
	    &collect_acls($any_rule, $src_intf, $dst_intf);
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
    for my $rule (@expanded_rules) {
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

sub print_acls( $ ) {
    my($router) = @_;
    my $model = $router->{model};
    print "[ ACL ]\n";
    # We need to know all hardware interface names.
    # It isn't sufficient to iterate over the keys from $router->{code},
    # since some interfaces may have no ACL at all.
    my %hardware;
    # Collect IP addresses of all interfaces
    my @ip;
    # We need to know, if OSPF messages are allowed for a
    # hardware interface
    my %ospf;
    for my $interface (@{$router->{interfaces}}) {
	# ignore 'unnumbered' and 'short' interfaces
	next if $interface->{ip} eq 'unnumbered' or $interface->{ip} eq 'short';
	# Remember interface name for comments
	$hardware{$interface->{hardware}} = $interface->{name};
	push @ip, @{$interface->{ip}};
	# is OSPF used?
	if($interface->{ospf}) {
	    $ospf{$interface->{hardware}} = 1;
	}
    }
    for my $hardware (sort keys %hardware) {
	my $name = "${hardware}_in";
	my $code = $router->{code}->{$hardware};
	my $if_code = $router->{if_code}->{$hardware};
	# force auto-vivification
	push @$code, ();
	push @$if_code, ();
	if($model =~ /^IOS/) {
	    if($comment_acls) {
		print "! $hardware{$hardware}\n";
	    }
	    print "ip access-list extended $name\n";
	    for my $line (@$if_code) {
		print " $line";
	    }
	    if($ospf{$hardware}) {
		if($comment_acls) {
		    print " ! OSPF\n";
		}
		print " permit ip any host 224.0.0.5\n";
		print " permit ip any host 224.0.0.6\n";
	    }
	    if(@$code) {
		if($comment_acls and @ip) {
		    print " ! Protect own interfaces\n";
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
	} elsif($model eq 'PIX') {
	    if($comment_acls) {
		print "! $hardware{$hardware}\n";
	    }
	    for my $line (@$if_code, @$code) {
		if($line =~ /^\s*!/) {
		    print $line;
		} else {
		    print "access-list $name $line";
		}
	    }
	    print "access-list $name deny ip any any\n";
	    print "access-group $name in $hardware\n\n";
	} else {
	    internal_err "unsupported router model $model";
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
	print "[ Model = $model ]\n";
	&print_routes($router) unless $router->{routing_manual};
	&print_acls($router);
	&print_pix_static($router)
	    if $model eq 'PIX' and not $router->{static_manual};
	print "[ END $name ]\n\n";
	close STDOUT or die "Can't close $file\n";
    }
}

####################################################################
# Argument processing
####################################################################
sub usage() {
    die "Usage: $0 [-c config] {in-file | in-directory} out-directory\n";
}

my $conf_file;
my $out_dir;
sub read_args() {
    use Getopt::Std;
    my %opts;
    getopts('c:', \%opts);
    $conf_file = $opts{c};
    $main_file = shift @ARGV or usage;
    $out_dir = shift @ARGV or usage;
    # strip trailing slash for nicer messages
    $out_dir =~ s./$..;
    not @ARGV or usage;
}

sub read_config() {
    open FILE, $conf_file or die "can't open $conf_file: $!";
    while(<FILE>) {
	# ignore comments
	s/#.*$//;
	# ignore empty lines
	next if /^\s*$/;
	my($key, $val) = m/(\S+)\s*=\s*(\S+)/;
    }
    close FILE;
}
	    
####################################################################
# Main program
####################################################################

&read_args();
&read_config() if $conf_file;
info "$program, version $version";
&read_file_or_dir($main_file);
&show_read_statistics();
&order_services();
&link_topology();
&mark_disabled();
&find_subnets();
&setany();
&expand_rules();
&check_unused_groups();
&setpath();
die "Aborted with $error_counter error(s)\n" if $error_counter;
$error_counter = $max_errors; # following errors should always abort
# Find routes before conversion of any rules, 
# because that will introduce additinal 'any' objects,
# which would result in superfluous routes
&set_route_in_any();
&find_active_routes_and_statics();
&convert_any_rules();
&optimize();
&mark_secondary_rules();
&repair_deny_influence();
&acl_generation();
&check_output_dir($out_dir);
&print_code($out_dir);
&warn_pix_icmp();
