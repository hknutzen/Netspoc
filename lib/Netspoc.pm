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
my $strict_subnets = 1;
# ignore these names when reading directories:
# - CVS and RCS directories
# - CVS working files
# - directory raw for prolog & epilog files
# - Editor backup files: emacs: *~
my $ignore_files = qr/^CVS$|^RCS$|^.#|^raw$|~$/;
# abort after this many errors
my $max_errors = 10;

####################################################################
# Error Reporting
####################################################################

sub info ( @ ) {
    print STDERR @_ if $verbose;
}

sub warning ( @ ) {
    print STDERR "Warning: ", @_;
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
	my $disabled = &check_flag('disabled');
	if($disabled) {
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

my %valid_model = (IOS => 1, PIX => 1);
my %routers;
sub read_router( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $managed = &check_flag('managed');
    my $model = &check_assign('model', \&read_identifier);
    if($model and not $valid_model{$model}) {
	error_atline "Unknown router model '$model'";
    }
    if($managed and not $model) {
	err_msg "Missing 'model' for managed router:$name";
    }
    my $static_manual = &check_flag('static_manual');
    my $router = new('Router',
		     name => "router:$name",
		     managed => $managed,
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

sub read_port_range( $ ) {
    my($srv) = @_;
    if(defined (my $port1 = &check_int())) {
	error_atline "Too large port number $port1" if $port1 > 65535;
	error_atline "Invalid port number '0'" if $port1 == 0;
	if(&check('-')) {
	    if(defined (my $port2 = &check_int())) {
		error_atline "Too large port number $port2" if $port2 > 65535;
		error_atline "Invalid port number '0'" if $port2 == 0;
		error_atline "Invalid port range $port1-$port2" if $port1 > $port2;
		$srv->{v1} = $port1;
		$srv->{v2} = $port2;
	    } else {
		syntax_err "Missing second port in port range";
	    }
	} else {
	    $srv->{v1} = $port1;
	    $srv->{v2} = $port1;
	}
    } else {
	$srv->{v1} = 1;
	$srv->{v2} = 65535;
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
	    $srv->{v1} = 1;
	    $srv->{v2} = 65535;
	} elsif($nr == 17) {
	    $srv->{type} = 'udp';
	    $srv->{v1} = 1;
	    $srv->{v2} = 65535;
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
	&read_port_range($srv);
    } elsif(&check('udp')) {
	$srv->{type} = 'udp';
	&read_port_range($srv);
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
    info "Read $n routers\n";
    $n = keys %networks;
    info "Read $n networks\n";
    $n = keys %groups;
    info "Read $n groups\n";
    $n = keys %services;
    info "Read $n services\n";
    $n = keys %servicegroups;
    info "Read $n service groups\n";
    $n = @rules;
    info "Read $n rules\n";
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
    # add a dummy host which doesn't match any range, to simplify the code: 
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
	my $x1 = $srv1->{v1};
	my $y1 = $srv1->{v2};
	my $min_size = 65536;
	$srv1->{up} = $up;
	for my $srv2 (@$range_aref) {
	    next if $srv1 eq $srv2;
	    next if $srv2->{main};
	    my $x2 = $srv2->{v1};
	    my $y2 = $srv2->{v2};
	    if($x2 == $x1 and $y1 == $y2) {
		# Found duplicate service definition
		# Link $srv2 with $srv1
		# Since $srv1 is not linked via ->{main},
		# we never get chains of ->{main}
		$srv2->{main} = $srv1;
	    } elsif($x2 <= $x1 and $y1 <= $y2) {
		my $size = $y2-$x2;
		if($size < $min_size) {
		    $min_size = $size;
		    $srv1->{up} = $srv2;
		}
	    } elsif($x1 < $x2 and $x2 <= $y1 and $y1 < $y2 or
		# 1111111
		#    2222222
	       $x2 < $x1 and $x1 <= $y2 and $y2 < $y1) {
		#    1111111
		# 2222222
		# ToDo: Implement this function
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
	    $router->{managed} and
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

sub order_any_rule ( $$ ) {
    my($rule, $href) = @_;
    my $depth = $rule->{srv}->{depth};
    my $srcid = typeof($rule->{src});
    my $dstid = typeof($rule->{dst});
    push @{$href->{$depth}->{$srcid}->{$dstid}}, $rule;
}

# counter for expanded permit any rules
my $anyrule_index = 0;

# add all rules with matching srcid and dstid to expanded_any_rules
sub add_rule_2hash( $$$$ ) {
    my($result_aref, $hash,$srcid,$dstid) = @_;
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

sub add_ordered_any_rules( $$ ) {
    my($aref, $href) = @_;
    for my $depth (reverse sort keys %$href) {
	my $hash = $href->{$depth};
	next unless defined $hash;
	add_rule_2hash($aref, $hash, 'any','host');
	add_rule_2hash($aref, $hash, 'host','any');
	add_rule_2hash($aref, $hash, 'any','network');
	add_rule_2hash($aref, $hash, 'network','any');
	add_rule_2hash($aref, $hash, 'any','any');
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
	    push @objects,  @{$object->{link}->{border}->{networks}};
	} else {
	    push @objects, $object;
	}
    }
    for my $object (@objects) {
	$object = undef if $object->{disabled};
	if(is_net $object) {
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
		warning "unused $group->{name} with $size element(s)\n";
	    } else {
		warning "unused empty $group->{name}\n";
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
# hash for ordering permit any rules; 
# when sorted, they are added later to @expanded_any_rules
my %ordered_any_rules;
# hash for ordering all rules:
# $rule_tree{$action}->{$src}->[0]->{$dst}->[0]->{$srv} = $rule;
# see &add_rule for details
my %rule_tree;

sub expand_rules() {
    for my $rule (@rules) {
	my $src_any_group = {};
	my $dst_any_group = {};
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
		    } elsif(is_any($src) and is_any($dst)) {
			err_msg "Rule '", print_rule $expanded_rule, "'\n",
			" has 'any' objects both as src and dst.\n",
			" This is not supported currently. ",
			"Use one 'every' object instead";
		    } elsif(is_any($src)) {
			$src_any_group->{$src} = 1;
			$expanded_rule->{src_any_group} = $src_any_group;
			order_any_rule($expanded_rule, \%ordered_any_rules);
		    } elsif(is_any($dst)) {
			$dst_any_group->{$dst} = 1;
			$expanded_rule->{dst_any_group} = $dst_any_group;
			order_any_rule($expanded_rule, \%ordered_any_rules);
		    } else {
			push(@expanded_rules, $expanded_rule);
		    }
		}
	    }
	}
    }
    # add ordered 'any' rules which have been ordered by order_any_rule
    add_ordered_any_rules(\@expanded_any_rules, \%ordered_any_rules);
    if($verbose) {
	my $nd = 0+@expanded_deny_rules;
	my $n  = 0+@expanded_rules;
	my $na = 0+@expanded_any_rules;
	info "Expanded rules:\n",
	" deny $nd, permit: $n, permit any: $na\n";
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
	    my $dst_any = $dst->{network}->{border}->{any} or
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
    info "Repairing deny influence\n";
    repair_deny_influence1 \@expanded_any_rules, \@expanded_rules;
}

####################################################################
# mark all parts of the topology lying behind disabled interfaces
####################################################################
sub disable_behind( $ ) {
    my($incoming) = @_;
    $incoming->{disabled} = 1;
    my $network = $incoming->{network};
    $network->{disabled} = 1;
    for my $host (@{$network->{hosts}}) {
	$host->{disabled} = 1;
    }
    for my $interface (@{$network->{interfaces}}) {
	next if $interface eq $incoming;
	$interface->{disabled} = 1;
	my $router = $interface->{router};
	$router->{disabled} = 1;
	# a disabled router can't be managed
	if($router->{managed}) {
	    $router->{managed} = 0;
	    warning "Disabling managed $router->{name}\n";
	}
	for my $outgoing (@{$router->{interfaces}}) {
	    next if $outgoing eq $interface;
	    # Loop detection occurs later in setpath
	    next if $outgoing->{disabled};
	    &disable_behind($outgoing);
	}
    }
}	

sub mark_disabled() {
    for my $interface (@disabled_interfaces) {
	disable_behind($interface);
    }
    for my $interface (@disabled_interfaces) {
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
    info "Finding subnets\n";
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
			err_msg "$subnet->{name} is subnet of $bignet->{name}\n",
			" if desired, either declare attribute 'subnet_of'",
			" or attribute 'route_hint'";
		    }
		    # we only need to find the smallest enclosing network
		    last;
		}
	    }
	}
    }
}

####################################################################
# Set paths for efficient topology traversal
####################################################################

sub setpath_router( $$$$ ) {
    my($router, $to_border, $border, $distance) = @_;
    # ToDo: operate with loops
    if($router->{border}) {
	err_msg "Found a loop at $router->{name}.\n",
	" Loops are not supported in this version";
	return;
    }
    $router->{border} = $border;
    $router->{to_border} = $to_border;
    $router->{distance} = $distance;
    for my $interface (@{$router->{interfaces}}) {
	# ignore interface where we reached this router
	next if $interface eq $to_border;
	if($router->{managed}) {
	    &setpath_network($interface->{network},
			     $interface, $interface, $distance+1);
	} else {
	    &setpath_network($interface->{network},
			     $interface, $border, $distance);
	}
    }
}

sub setpath_network( $$$$ ) {
    my ($network, $to_border, $border, $distance) = @_;
    # ToDo: operate with loops
    if($network->{border}) {
	err_msg "Found a loop at $network->{name}.\n",
	" Loops are not supported in this version";
	return;
    }
    $network->{border} = $border;
    # Add network to the corresponding border,
    # to have all networks of a security domain available.
    # Unnumbered networks are left out here because
    # they aren't a valid src or dst
    push(@{$border->{networks}}, $network)
	unless $network->{ip} eq 'unnumbered';
    for my $interface (@{$network->{interfaces}}) {
	# ignore interface where we reached this network
	next if $interface eq $to_border;
	&setpath_router($interface->{router},
			$interface, $border, $distance);
    }
}

sub setpath() {
    # take a random managed element from %routers, name it "router1"
    my $router1;
    for my $router (values %routers) {
	if($router->{managed}) {
	    $router1 = $router;
	    last;
	}
    }
    $router1 or die "Topology needs at least one managed router\n"; 

    # Starting with router1, do a traversal of the whole network 
    # to find a path from every network and router to router1
    &setpath_router($router1, 'not undef', undef, 0);

    # check if all networks and routers are connected with router1
    for my $obj (values %networks, values %routers) {
	next if $obj eq $router1;
	next if $obj->{disabled};
	$obj->{border} or
	    err_msg "Found unconnected node: $obj->{name}";
    }
    # link each 'any' object with its corresponding 
    # border interface and vice versa
    for my $any (values %anys) {
	my $border = $any->{link}->{border};
	$any->{border} = $border;
	if(my $old_any = $border->{any}) {
	    err_msg
		"More than one 'any' object definied in a security domain:\n",
		" $old_any->{name} and $any->{name}";
	}
	$border->{any} = $any;
    }
    # each security domain needs an 'any' object, 
    # later for 'any' conversion
    for my $router (values %routers) {
	next unless $router->{managed};
	for my $interface (@{$router->{interfaces}}) {
	    # not a border interface
	    next if $interface eq $router->{to_border};
	    # already has an 'any' object
	    next if $interface->{any};
	    my $network = $interface->{network};
	    (my $name = $network->{name}) =~ s/^network:/auto_any:/;
	    my $any = new('Any',
			  name => $name,
			  link => $network,
			  border => $interface);
	    $interface->{any} = $any;
	}
    }
}

####################################################################
# Functions for path traversal
# Used for conversion of 'any' rules and for generation of ACLs
####################################################################

sub get_border( $ ) {
    my($obj) = @_;
    if(is_host($obj)) {
	return $obj->{network}->{border};
    } elsif(is_interface($obj)) {
	if($obj->{router}->{managed}) {
	    return undef;
	} else {
	    return $obj->{network}->{border};
	}
    } elsif(is_net($obj) or is_any($obj)) {
	return $obj->{border};
    } else {
	internal_err "unexpected object $obj->{name}";
    }
}

# Apply a function to a rule at every managed router
# on the path from src to dst of the rule
# src-R5-R4-\
#           |-R2-R1
#    dst-R3-/
sub path_walk($&) {
    my ($rule, $fun) = @_;
    internal_err "undefined rule" unless $rule;
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $src_intf = &get_border($src);
    my $dst_intf = &get_border($dst);
    my $src_router = $src_intf?$src_intf->{router}:$src->{router};
    my $dst_router = $dst_intf?$dst_intf->{router}:$dst->{router};
    my $src_dist = $src_router->{distance};
    my $dst_dist = $dst_router->{distance};

    if(# src and dst are interfaces on the same router
       not defined $src_intf and not defined $dst_intf
       and $src_router eq $dst_router or
       # no border between src and dst
       defined $src_intf and defined $dst_intf and $src_intf eq $dst_intf) {
	# no message if src eq dst; this happens for group to group rules
	unless($src eq $dst) {
	    warning "Unenforceable rule\n ", print_rule($rule), "\n";
	}
	# don't process rule again later
	$rule->{deleted} = $rule;
	return;
    }

    # go from src to dst until equal distance is reached
    while($src_dist > $dst_dist) {
	my $out_intf = $src_router->{to_border};
	&$fun($rule, $src_intf, $out_intf);
	$src_intf = $src_router->{border};
	$src_router = $src_intf->{router};
	$src_dist = $src_router->{distance};
    }

    # go from dst to src until equal distance is reached
    while($src_dist < $dst_dist) {
	my $in_intf = $dst_router->{to_border};
	&$fun($rule, $in_intf, $dst_intf);
	$dst_intf = $dst_router->{border};
	$dst_router = $dst_intf->{router};
	$dst_dist = $dst_router->{distance};
    }

    # now alternating go one step from src and one from dst
    # until the router in the middle is reached
    while($src_router ne $dst_router) {
	my $out_intf = $src_router->{to_border};
	&$fun($rule, $src_intf, $out_intf);
	$src_intf = $src_router->{border};
	$src_router = $src_intf->{router};

	my $in_intf = $dst_router->{to_border};
	&$fun($rule, $in_intf, $dst_intf);
	$dst_intf = $dst_router->{border};
	$dst_router = $dst_intf->{router};
    }

    # $src_router eq $dst-router
    # if we reached the router via different interfaces, 
    # the router lies on the path
    if(not defined $src_intf or
       not defined $dst_intf or
       $src_intf ne $dst_intf) {
	&$fun($rule, $src_intf, $dst_intf);
    } else {
	# the router doesn't lie on the path, nothing to do
    }
}

##############################################################################
# Convert semantics of rules with an 'any' object as source or destination
# from high-level to low-level:
# high-level: any:X denotes all networks of security domain X
# low-level:  automatically insert 'any' rules with attached deny rules 
#             at intermediate paths.
##############################################################################

# permit any1 dst
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

    # we don't need the interface itself, but only information about all
    # networks and the 'any' object at that interface. We get this information
    # at the border interface, not the to_border interface
    if($in_intf eq $router->{to_border}) {
	$in_intf = $router->{border};
    }
    my $any = $in_intf->{any};
    # nothing to do for the first router
    return if $any eq $rule->{src};

    # Optimization: nothing to do if there is a similar rule
    # with another 'any' object as src
    return if $rule->{src_any_group}->{$any};

    my $any_rule = {src => $any,
		    dst => $rule->{dst},
		    srv => $rule->{srv},
		    action => 'permit',
		    i => $rule->{i},
		    deny_src_networks => [ @{$in_intf->{networks}} ]
		    };
    push @{$rule->{any_rules}}, $any_rule;
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
    # we just process the corresponding router;
    my $router = $out_intf->{router};
    # link together 'any' rules at one router:
    # code needs to be generated only for the first processed rule 
    $router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv}->{active} = 0;
    my $link = $router->{dst_any_link}->{$rule->{action}}->{$src}->{$srv};

    # Find networks at all interfaces except the in_intf.
    # For the case that src is interface of current router,
    # take only the out_intf
    for my $orig_intf ($in_intf?@{$router->{interfaces}}:($out_intf)) {
	# copy $intf to prevent changing of the iterated array
	my $intf = $orig_intf;

	# nothing to do for in_intf:
	# case 1: it is the first router near src
	# case 2: the in_intf is on the same security domain
	# as an out_intf of some other router on the path
	next if defined $in_intf and $intf eq $in_intf;

	# see comment in &gen_any_src_deny
	if($intf eq $router->{to_border}) {
	    $intf = $router->{border};
	}
	my $any = $intf->{any};
	# Nothing to be inserted for the interface which is connected
	# directly to the destination 'any' object.
	# But link it together with other 'any' rules at the last router
	# (R3 in the picture above)
	if($any eq $rule->{dst}) {
	    $rule->{any_dst_group} = $link;
	    next;
	}

	# Optimization: nothing to do if there is a similar rule
	# with another 'any' object as dst
	next if $rule->{dst_any_group}->{$any};

	my $any_rule = {src => $src,
			dst => $any,
			srv => $srv,
			action => 'permit',
			i => $rule->{i},
			deny_dst_networks => [ @{$intf->{networks}} ],
			any_dst_group => $link
			};
	push @{$rule->{any_rules}}, $any_rule;
    }
}

sub convert_any_rules() {
    for my $rule (@expanded_any_rules) {
	next if $rule->{deleted};
	$rule->{any_rules} = [];
	if(is_any($rule->{src})) {
	    $rule->{deny_src_networks} = [];
	    &path_walk($rule, \&convert_any_src_rule);
	}
	if(is_any($rule->{dst})) {
	    $rule->{deny_dst_networks} = [];
	    &path_walk($rule, \&convert_any_dst_rule);
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

# a rule may be deleted if we find a similar rule with greater or equal srv
sub optimize_srv_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;

    for my $rule (values %$chg_hash) {
	my $srv = $rule->{srv};
	while($srv) {
	    if(my $cmp_rule = $cmp_hash->{$srv}) {
		unless($cmp_rule eq $rule) {

# optimize auto_any rules:
#
# cmp permit net1 dst srv
# chg permit auto_any(deny_net: net1,net2) dst srv
# -->
# chg permit auto_any(deny_net: net2) dst srv
#
# cmp permit net1 dst srv
# chg permit auto_any(deny_net: net1,net2) dst' srv'
# --> if dst >= dst', srv >= srv'
# cmp permit net1 dst srv
# chg permit auto_any(deny_net: net2) dst srv'
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
		    if($cmp_rule->{action} eq 'permit' and
		       $rule->{action} eq 'permit'){
			if(is_any $rule->{src}) {
			    my $cmp_src = $cmp_rule->{src};
			    if(is_net $cmp_src and
			       aref_delete($cmp_src, $rule->{deny_src_networks})) {
				if($cmp_rule->{dst} eq $rule->{dst} and
				   $cmp_rule->{srv} eq $rule->{srv}) {
				    $cmp_rule->{deleted} = $rule;
				}
				last;
			    }
			    if(is_any $cmp_src) {
				if(@{$cmp_rule->{deny_src_networks}} == 0) {
				    $rule->{deleted} = $cmp_rule;
				} else {
				    my $equal_deny_net = 1;
				    for my $net (@{$cmp_rule->
						   {deny_src_networks}}) {
					$equal_deny_net &= aref_delete $net, $rule->
					{deny_src_networks};
				    }
				    if($equal_deny_net) {
					$rule->{deleted} = $cmp_rule;
				    }
				}
				last;
			    }
			}
# equivalent for auto_any at dst
			if(is_any $rule->{dst}) {
			    my $cmp_dst = $cmp_rule->{dst};
			    if(is_net $cmp_dst and
			       aref_delete($cmp_dst, $rule->{deny_dst_networks})) {
				if($cmp_rule->{dst} eq $rule->{dst} and
				   $cmp_rule->{srv} eq $rule->{srv}) {
				    $cmp_rule->{deleted} = $rule;
				}
				last;
			    }
			    if(is_any $cmp_dst) {
				if(@{$cmp_rule->{deny_dst_networks}} == 0) {
				    $rule->{deleted} = $cmp_rule;
				} else {
				    my $equal_deny_net = 1;
				    for my $net (@{$cmp_rule->
						   {deny_dst_networks}}) {
					$equal_deny_net &= aref_delete $net, $rule->
					{deny_dst_networks};
				    }
				    if($equal_deny_net) {
					$rule->{deleted} = $cmp_rule;
				    }
				}
				last;
			    }
			}
		    } 			    
		    $rule->{deleted} = $cmp_rule;
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
	    $any = $dst->{network}->{border}->{any} and
		$cmp_dst = $cmp_hash->{$any} and
		    &optimize_srv_rules($cmp_dst->[0], $next_hash);
	} elsif(is_net($dst)) {
	    $cmp_dst = $cmp_hash->{$dst} and
		&optimize_srv_rules($cmp_dst->[0], $next_hash);
	    $any = $dst->{border}->{any} and
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
	    $any = $src->{network}->{border}->{any} and
		$cmp_src = $cmp_hash->{$any} and
		    &optimize_dst_rules($cmp_src->[0], $next_hash);
	} elsif(is_net($src)) {
	    $cmp_src = $cmp_hash->{$src} and
		&optimize_dst_rules($cmp_src->[0], $next_hash);
	    $any = $src->{border}->{any} and
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
    info "Preparing optimization\n";
    # add rules to $rule_tree for efficient rule compare operations
    for my $rule (@expanded_deny_rules, @expanded_rules) {
	&add_rule($rule);
    }
    for my $rule (@expanded_any_rules) {
	&add_rule($rule);
	for my $any_rule (@{$rule->{any_rules}}) {
	    &add_rule($any_rule);
	}
    }
    info "Starting optimization\n";
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
	info "Deleted redundant rules:\n";
	info " $nd deny, $n permit, $na permit any, $naa permit any from any\n";
    }
}

####################################################################
# Set routes
# Add a component 'route' to each interface.
# It holds an array of networks reachable
# when using this interface as next hop
####################################################################
    
sub get_networks_behind ( $ ) {
    my($hop) = @_;
    # return if the values have already been calculated
    return @{$hop->{route}} if exists $hop->{route};
    my @networks;
    for my $interface (@{$hop->{router}->{interfaces}}) {
	next if $interface eq $hop;
 	next if $interface->{disabled};
	# add directly connected network
	unless($interface->{ip} eq 'unnumbered') {
	    push @networks, $interface->{network};
	}
	for my $next_hop (@{$interface->{network}->{interfaces}}) {
	    next if $next_hop eq $interface;
	    # add networks reachable via interfaces behind
	    # the directly connected networks
	    push @networks, &get_networks_behind($next_hop);
	}
    }
    $hop->{route} = \@networks;
    return @networks;
}
	

# Set routes
sub setroute() {
    info "Setting routes\n";
    for my $interface (values %interfaces) {
	# info isn't needed for interface at leaf network
	next if @{$interface->{network}->{interfaces}} == 1;
	get_networks_behind $interface;
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
	" while generating code for pix firewalls:\n";
	while(my ($name, $count) = each %pix_srv_hole) {
	    print STDERR " $name: $count times\n";
	}
    }
}

sub srv_code( $$ ) {
    my ($srv, $model) = @_;
    my $proto = $srv->{type};
    my $v1 = $srv->{v1};
    my $v2 = $srv->{v2};

    if($proto eq 'ip') {
	return('ip', '');
    } elsif($proto eq 'tcp' or $proto eq 'udp') {
	my $port = $v1;
	if($v1 == $v2) {
	    return($proto, "eq $v1");
	} elsif($v1 == 1 and $v2 == 65535) {
	    return($proto, '');
	} else {
	    return($proto, "range $v1 $v2");
	}
    } elsif($proto eq 'icmp') {
	my $type = $v1;
	if($type eq 'any') {
	    return($proto, '');
	} else {
	    my $code = $v2;
	    if($code eq 'any') {
		return($proto, $type);
	    } else {
		if($model eq 'PIX') {
		    # PIX can't handle the ICMP code.
		    # If we try to permit e.g. "port unreachable", 
		    # "unreachable any" could pass the PIX. 
		    $pix_srv_hole{$srv->{name}}++;
		    return($proto, $type);
		} else {
		    return($proto, "$type $code");
		}
	    }
	}
    } elsif($proto eq 'proto') {
	my $nr = $v1;
	return($nr, '');
    } else {
	internal_err "a rule has unknown protocol '$proto'";
    }
}

sub collect_networks_for_routes_and_static( $$$ ) {
    my($rule, $src_intf, $dst_intf) = @_;
    return unless $rule->{action} eq 'permit';
    return unless $dst_intf;
    my $dst = $rule->{dst};
    my @networks;
    if(is_host $dst or is_interface $dst) {
	@networks = ($dst->{network});
    } elsif(is_net $dst) {
	@networks = ($dst);
    } elsif(is_any $dst) {
	# We approximate an 'any' object with 
	# every network of that security domain
	# but ignore deny_dst_networks from 'any' rule
	@networks = grep { my $elt = $_;
			   not grep { $_ eq $elt }
			   @{$rule->{deny_dst_networks}}
		       }
	@{$dst->{border}->{networks}};
    } else {
	internal_err "unexpected dst $dst->{name}";
    }
    for my $net (@networks) {
	next if $net->{ip} eq 'unnumbered';
	# mark reachable networks for generation of route commands
	$dst_intf->{used_route}->{$net} = 1;
	# collect networks reachable from lower security level
	# for generation of static commands
	if($dst_intf->{router}->{model} eq 'PIX' and $src_intf) {
	    if($src_intf->{level} < $dst_intf->{level}) {	
		$net->{mask} == 0 and
		    die "Pix doesn't support static command for mask 0.0.0.0 of $net->{name}\n";
		# put networks into a hash to prevent duplicates
		$dst_intf->{static}->{$src_intf->{hardware}}->{$net} = $net;
	    } elsif($src_intf->{level} == $dst_intf->{level}) {	
		die "Traffic to $dst->{name} can't pass\n",
		" from  $src_intf->{name} to $dst_intf->{name},\n",
		" since they have equal security levels.\n";
	    }
	}
    }
}

sub print_pix_static( $ ) {
    my($router) = @_;
    print "[ Static ]\n";
    print "! Security levels: ";
    my $last_level;
    for my $interface (sort { $a->{level} <=> $b->{level} } @{$router->{interfaces}} ) {
	my $level = $interface->{level};
	if(defined $last_level) {
	    print(($last_level == $level)? " = ": " < ");
	}
	print $interface->{hardware};
	$last_level = $level;
    }
    print "\n";
		       
    for my $interface (@{$router->{interfaces}}) {
	my $static = $interface->{static};
	next unless $static;
	my $high = $interface->{hardware};
	for my $low (keys %$static) {
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
    # Rules from / to managed interfaces should be processed
    # at the corresponding router even if they are marked as deleted.
    if($rule->{deleted}) {
	# we are on an intermediate router
	# if both $src_intf and $dst_intf are defined
	return if defined $src_intf and defined $dst_intf;
	if(not defined $src_intf) {
	    # src is an interface of the current router
	    # and it was deleted because we have a similar rule
	    # for an interface of the current router
	    if($src eq $rule->{deleted}->{src}) {
		# The rule in {deleted} may be ineffective
		# if it is an interface -> any rule with attached auto-deny rule(s)
		# ToDo: Check if one of deny_dst_networks matches $src
		return unless is_any $rule->{deleted}->{dst} and $rule->{deleted}->{deny_dst_networks};
	    }
	}
	if(not defined $dst_intf) {
	    if($dst eq $rule->{deleted}->{dst}) {
		# ToDo: see above
		return unless is_any $rule->{deleted}->{src} and $rule->{deleted}->{deny_src_networks};
	    }
	}
    }
    my $model = $router->{model};
    &collect_networks_for_routes_and_static($rule, $src_intf, $dst_intf);
    my $inv_mask = $model eq 'IOS';
    my @src_code = &adr_code($src, $inv_mask);
    my @dst_code = &adr_code($dst, $inv_mask);
    my ($proto_code, $port_code) = &srv_code($srv, $model);
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
		     "$action $proto_code $src_code $dst_code $port_code\n");
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
			 "$action $proto_code $dst_code $port_code $src_code $established\n");
		}
	    }
	}
    } else {
	internal_err "no interfaces for ", print_rule($rule);
    }
}

# For deny rules and permit src=any:*, call collect_acls only for
# the first border on the path from src to dst
sub collect_acls_at_src( $$$ ) {
    push @_, 'src';
    &collect_acls_at_end(@_);
}

# For permit dst=any:*, call collect_acls only for
# the last border on the path from src to dst
sub collect_acls_at_dst( $$$ ) {
    push @_, 'dst';
    &collect_acls_at_end(@_);
}
# Case 1:
# r1-src-r2-r3-dst: get_border(src) = r1: r1 is not on path, but r2.border = r1
# Case 1a/2a: src is interface of managed router
# get_border(src) is undef, r.src_intf is undef, src.router = dst_intf.router
# Case 2:
# r3-src-r2-r1-dst: get_border(src) = r2: r2 is 1st border on path
sub collect_acls_at_end( $$$$ ) {
    my ($rule, $src_intf, $dst_intf, $where) = @_;
    my $end = $rule->{$where};
    my $end_intf = ($where eq 'src')? $src_intf:$dst_intf;
    my $end_border = &get_border($end);
    # Case 1a/2a:
    if(not defined $end_border) {
	if(not defined $end_intf) {
	    &collect_acls($rule, $src_intf, $dst_intf);
	} else {
	    &collect_networks_for_routes_and_static($rule, $src_intf, $dst_intf);
	}
    } else {
	my $router = $end_intf->{router};
        # Case 1:
	if($router->{to_border} eq $end_intf and
	   $router->{border} eq $end_border) {
	    &collect_acls($rule, $src_intf, $dst_intf);
	}
	# Case 2:
	elsif($end_border eq $end_intf) {
	    &collect_acls($rule, $src_intf, $dst_intf);
	} else {
	    &collect_networks_for_routes_and_static($rule, $src_intf, $dst_intf);
	}
    }
}

sub acl_generation() {
    info "Starting code generation\n";
    # First generate code for deny rules
    for my $rule (@expanded_deny_rules) {
	next if $rule->{deleted};
	&path_walk($rule, \&collect_acls);
    }
    # Code for permit rules
    for my $rule (@expanded_rules) {
	next if $rule->{deleted} and not $rule->{managed_if};
	&path_walk($rule, \&collect_acls);
    }
    # Code for rules with 'any' object as src or dst
    for my $rule (@expanded_any_rules) {
	if(is_any $rule->{src}) {
	    if(exists $rule->{any_rules}) {
		for my $any_rule (@{$rule->{any_rules}}) {
		    next if $any_rule->{deleted} and
			not $any_rule->{managed_if};
		    # Generate code for deny rules directly in front of
		    # the corresponding permit 'any' rule
		    for my $deny_network (@{$any_rule->{deny_src_networks}}) {
			my $deny_rule = {action => 'deny',
					 src => $deny_network,
					 dst => $any_rule->{dst},
					 srv => $any_rule->{srv}
				     };
			&path_walk($deny_rule, \&collect_acls_at_src);
		    }
		    &path_walk($any_rule, \&collect_acls_at_src);
		}
	    }
	    next if $rule->{deleted} and not $rule->{managed_if};
	    &path_walk($rule, \&collect_acls_at_src);
	} elsif(is_any $rule->{dst}) {
	    # two passes:
	    # first generate deny rules,
	    for my $any_rule (@{$rule->{any_rules}}) {
		next if $any_rule->{deleted} and
		    not $any_rule->{managed_if};
		for my $deny_network (@{$any_rule->{deny_dst_networks}}) {
		    my $deny_rule = {action => 'deny',
				     src => $any_rule->{src},
				     dst => $deny_network,
				     srv => $any_rule->{srv}
				 };
		    &path_walk($deny_rule, \&collect_acls_at_dst);
		}
	    }
	    # second generate 'any' + auto 'any' rules
	    for my $any_rule ($rule, @{$rule->{any_rules}}) {
		next if $any_rule->{deleted} and
			not $any_rule->{managed_if};
		unless($any_rule->{any_dst_group}->{active}) {
		    &path_walk($any_rule, \&collect_acls_at_dst);
		    $any_rule->{any_dst_group}->{active} = 1;
		} else {
		    &path_walk($any_rule, \&collect_networks_for_routes_and_static);
		}
	    }
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
    for my $interface (@{$router->{interfaces}}) {
	$hardware{$interface->{hardware}} = 1;
	# ignore 'unnumbered' and 'short' interfaces
	next if ref $interface->{ip} eq 'SCALAR';
	push @ip, @{$interface->{ip}};
    }
    for my $hardware (sort keys %hardware) {
	my $name = "${hardware}_in";
	my $code = $router->{code}->{$hardware};
	my $if_code = $router->{if_code}->{$hardware};
	# force auto-vivification
	push @$code;
	push @$if_code;
	if($model eq 'IOS') {
	    print "ip access-list extended $name\n";
	    for my $line (@$if_code) {
		print " $line";
	    }
	    if(@$code) {
		if($comment_acls and @ip) {
		    print " ! Protect interfaces\n";
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

sub print_routes( $ ) {
    my($router) = @_;
    print "[ Routing ]\n";
    for my $interface (@{$router->{interfaces}}) {
	my $used_route = $interface->{used_route};
	for my $hop (@{$interface->{network}->{interfaces}}) {
	    next if $hop eq $interface;
	    my $hop_ip = print_ip $hop->{ip}->[0];
	    # sort networks by mask in reverse order, i.e. large masks coming
	    # first and for equal mask by IP address
	    # we need this
	    # 1. for routing on demand to work
	    # 2. to make the output deterministic
	    my @networks =
		sort { $b->{mask} <=> $a->{mask} || $a->{ip} <=> $b->{ip} }
	    @{$hop->{route}};
	    # find enclosing networks
	    my %enclosing;
	    for my $network (@networks) {
		$network->{enclosing} and $enclosing{$network} = 1;
	    }
	    for my $network (@networks) {
		if(not $used_route->{$network}) {
		    # no route needed if all traffic to this network is denied
		    $network = undef;
		} elsif($network->{is_in} and $enclosing{$network->{is_in}}) {
		    # Mark redundant network as deleted, if directly
		    # enclosing network lies behind the same hop.
		    # But add the enclosing network to used_route.
		    $used_route->{$network->{is_in}} = 1;
		    $network = undef;
		}
	    }
	    for my $network (@networks) {
		next unless defined $network;
		if($comment_routes) {
		    print "! route $network->{name} -> $hop->{name}\n";
		}
		my $adr = adr_code $network, 0;
		if($router->{model} eq 'IOS') {
		    print "ip route $adr\t$hop_ip\n";
		} elsif($router->{model} eq 'PIX') {
		    print "route $interface->{hardware} $adr\t$hop_ip\n";
		} else {
		    internal_err "unsupported router model $router->{model}";
		}
	    }
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
    info "Printing code\n";
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
	&print_routes($router);
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
info "$program, version $version\n";
&read_file_or_dir($main_file);
&show_read_statistics();
&order_services();
&link_topology();
&mark_disabled();
&find_subnets();
&setpath();
&expand_rules();
&check_unused_groups();
die "Aborted with $error_counter error(s)\n" if $error_counter;
$error_counter = $max_errors; # following errors should always abort
&convert_any_rules();
&optimize();
&repair_deny_influence();
&setroute();
&acl_generation();
&check_output_dir($out_dir);
&print_code($out_dir);
&warn_pix_icmp();
