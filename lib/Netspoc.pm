#!/usr/bin/perl
# File: netspoc.pl
# Author: Heinz Knutzen
# Address: heinz.knutzen@web.de, heinz.knutzen@dzsh.de
# Description:
# An attempt for a simple and fast replacement of Cisco's
# Cisco Secure Policy Manager (CSPM)

use strict;
use warnings;

my $program = 'NETwork Security POlicy Compiler';
my($version)= '$Revision$ ' =~ m/([0-9.]+)/;

####################################################################
# User configurable options
####################################################################
my $verbose = 1;
my $comment_acls = 1;
my $comment_routes = 1;
# if set to 1, may give better performance for very large rule sets
my $pre_optimization = 0;
# ignore these names when reading directories
my @ignore_files = qw(CVS RCS raw);
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

# input filename from commandline
my $main_file;
# filename of curent input file
our $file;
# eof status of current file
our $eof;
sub add_context( $ ) {
    my($msg) = @_;
    my $at_file = ($file eq $main_file)?'':" of $file";
    my($context) = m/([^\s,;={}]*([,;={}]|\s*)\G([,;={}]|\s*)[^\s,;={}]*)/;
    if($eof) { $context = 'at EOF'; } else { $context = qq/near "$context"/; }
    qq/$msg at line $.$at_file, $context\n/;
}

sub add_line( $ ) {
    my($msg) = @_;
    my $at_file = ($file eq $main_file)?'':" of $file";
    qq/$msg at line $.$at_file\n/;
}

my $error_counter = 0;

sub error_atline( $ ) {
    my($msg) = @_; 
    if($error_counter++ > $max_errors) {
	die add_line($msg);
    } else {
	print STDERR add_line($msg);
    }
}

sub err_msg( $ ) {
    my($msg) = @_; 
    if($error_counter++ > $max_errors) {
	die $msg;
    } else {
	print STDERR "$msg\n";
    }
}

sub syntax_err( $ ) {
    my($msg) = @_;    
    die add_context $msg;
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
	# cut off trailing lf
	chop;
    }
    # ignore leading witespace
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
    # todo: escape special RE characters in $token
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
    use locale;		# now german umlauts are part of \w
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
    use locale;		# now german umlauts are part of \w
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
# We use 'bless' only to give each structure a distinc type
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
    my $host = new('Host', name => "host:$name");
    &skip('=');
    &skip('{');
    my $token = read_identifier();
    if($token eq 'ip') {
	&skip('=');
	my @ip = &read_list(\&read_ip);
	$host->{ip} = \@ip;
    } elsif($token eq 'range') {
	&skip('=');
	my $ip1 = &read_ip;
	skip('-');
	my $ip2 = &read_ip;
	$ip1 <= $ip2 or error_atline "Invalid IP range";
	$host->{ip} = [ $ip1, $ip2 ];
	$host->{is_range} = 1;
	&skip(';');
    } else {
	syntax_err "Expected 'ip' or 'range'";
    }
    &skip('}');
    if(my $old_host = $hosts{$name}) {
	error_atline "Redefining host:$name";
    }
    $hosts{$name} = $host;
    return $host;
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
    my $ip;
    my $mask;
    my $token = read_identifier();
    if($token eq 'ip') {
	&skip('=');
	$ip = &read_ip;
	skip(';');
	$mask = &read_assign('mask', \&read_ip);
	# check if network ip matches mask
	if($ip & ~$mask != 0) {
	    my $ip_string = &print_ip($ip);
	    my $mask_string = &print_ip($mask);
	    error_atline "$network->{name}'s ip $ip_string " .
		"doesn't match its mask $mask_string";
	}
	$network->{ip} = $ip;
	$network->{mask} = $mask;
    } elsif($token eq 'unnumbered') {
	$network->{ip} = 'unnumbered';
	skip(';');
    } else {
	syntax_err "Expected 'ip' or 'unnumbered'";
    }
    while(1) {
	last if &check('}');
	my($type, $hname) = split_typed_name(read_typed_name());
	syntax_err "Expected host definition" unless($type eq 'host');
	if($ip eq 'unnumbered') {
	    error_atline "Unnumbered network must not contain hosts";
	}
	my $host = &read_host($hname);
	# check compatibility of host ip and network ip/mask
	for my $host_ip  (@{$host->{ip}}) {
	    if($ip != ($host_ip & $mask)) {
		my $ip_string = &print_ip($ip);
		my $mask_string = &print_ip($mask);
		my $host_ip_string = &print_ip($host_ip);
		error_atline "$host->{name}'s ip $host_ip_string doesn't match $network->{name}'s ip/mask $ip_string/$mask_string";
	    }
	}
	$host->{network} = $network;
	push(@{$network->{hosts}}, $host);
    }
    &find_ip_ranges($network->{hosts}, $network);
    if(my $old_net = $networks{$name}) {
	my $ip_string = &print_ip($network->{ip});
	my $old_ip_string = &print_ip($old_net->{ip});
	error_atline "Redefining network:$name from " . 
	    "$old_ip_string to $ip_string";
    }
    $networks{$name} = $network;
}

my @disabled_interfaces;

sub read_interface( $ ) {
    my $net = shift;
    my $interface = new('Interface', 
			# name will be set by caller
			network => $net,
			);
    unless(&check('=')) {
	skip(';');
	# short form of interface definition: only link to cloud network
	$interface->{ip} = 'cloud';
	return $interface;
    }
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
    return $interface;
}

# PIX firewalls have a security level associated wih each interface.
# We don't want to expand our syntax to state them explicitly,
# but instead we try to derive the level from the interface name.
# It is not neccessary the find the exact level; what we need to know
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
	unless($level = ($hwname =~ /(\d+)$/) and
	       0 < $level and $level < 100) {
	    err_msg "Can't derive PIX security level from $interface->{name}";
	}
    }
    $interface->{level} = $level;
}

my %valid_model = (IOS => 1, PIX => 1);
my %routers;
my %interfaces;
my $default_route;
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
    my $router = new('Router',
		     name => "router:$name",
		     managed => $managed,
		     );
    $router->{model} = $model if $managed;
    if(&check_flag('default_route')) {
	$default_route and
	    error_atline "Redefining default_route from $default_route->{name}";
	$default_route = $router;
    }
    while(1) {
	last if &check('}');
	my($type,$iname) = split_typed_name(read_typed_name());
	syntax_err "Expected interface definition" unless $type eq 'interface';
	my $interface = &read_interface($iname);
	$iname = "$name.$iname";
	$interface->{name} = "interface:$iname";
	if(my $old_interface = $interfaces{$iname}) {
	    error_atline "Redefining $interface->{name}";
	}
	# assign interface to global hash of interfaces
	$interfaces{$iname} = $interface;
	push @{$router->{interfaces}}, $interface;
	# assign router to interface
	$interface->{router} = $router;
	# interface of managed router must not be a cloud interface
	if($managed and $interface->{ip} eq 'cloud') {
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
    if(my $old_router = $routers{$name}) {
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
    if(my $old_any = $anys{$name}) {
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
    if(my $old_group = $groups{$name}) {
	error_atline "Redefining group:$name";
    }
    $groups{$name} = \@objects;
}

my %servicegroups;
sub read_servicegroup( $ ) {
   my $name = shift;
    skip('=');
    my @objects = &read_list_or_null(\&read_typed_name);
    if(my $old_group = $servicegroups{$name}) {
        error_atline "Redefining servicegroup:$name";
    }
    $servicegroups{$name} = \@objects;
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
      FILE:
	while(my $file = readdir DIR) {
	    next if $file eq '.' or $file eq '..';
	    for my $name (@ignore_files) {
		next FILE if $file eq $name;
	    }
	    $file = "$path/$file";
	    &read_file_or_dir($file);
	}
    } else {
	&usage();
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
sub is_net( $ ) {
    my($obj) = @_;
    return ref($obj) eq 'Network';
}
sub is_router( $ ) {
    my($obj) = @_;
    return ref($obj) eq 'Router';
}
sub is_interface( $ ) {
    my($obj) = @_;
    return ref($obj) eq 'Interface';
}
sub is_host( $ ) {
    my($obj) = @_;
    return ref($obj) eq 'Host';
}
sub is_any( $ ) {
    my($obj) = @_;
    return ref($obj) eq 'Any';
}
sub is_every( $ ) {
    my($obj) = @_;
    return ref($obj) eq 'Every';
}

sub print_rule( $ ) {
    my($rule) = @_;
    my $srv = exists($rule->{orig_srv}) ? 'orig_srv' : 'srv';
    return $rule->{action} .
	" src=$rule->{src}->{name}; dst=$rule->{dst}->{name}; " .
		     "srv=$rule->{$srv}->{name};";
}

##############################################################################
# Build linked data structures
##############################################################################

# Called from read_network
# Takes a references to the array of hosts from one network.
# Selects hosts with a single ip addresses,
# detects adjacent ip addresses and link them to an 
# automatically generated ip range
# ToDo:
# - handle hosts with multiple ip addresses
# - check if any of the existing ranges may be used
# - augment existing ranges by hosts or other ranges
# ==> support chains of network > range > range .. > host
sub find_ip_ranges( $$ ) {
    my($host_aref, $network) = @_;
    my @hosts =  grep { not $_->{is_range} and @{$_->{ip}} == 1 } @$host_aref;
    my @sorted = sort { $a->{ip}->[0] <=> $b->{ip}->[0] } @hosts;
    # add a dummy host to simplify the code
    push @sorted, {ip => [-1] };
    my $start_range;
    my $last_ip = 0;
    for(my $i = 0; $i < @sorted; $i++) {
	my $host = $sorted[$i];
	my $ip = $host->{ip}->[0];
	if(defined $start_range) {
	    if($ip == $last_ip + 1 or $ip == $last_ip) {
		# continue current range
		$last_ip = $ip;
	    } else {
		if($start_range < $i - 1) {
		    my $end_range = $i - 1;
		    # found a range with at least 2 elements
		    my $begin = $sorted[$start_range]->{ip}->[0];
		    my $end = $sorted[$end_range]->{ip}->[0];
		    # ignore last element if it is even
		    # last element may be duplicate
		    while(not ($end & 1)) {
			$end_range--;
			$end = $sorted[$end_range]->{ip}->[0];
		    }
		    if($begin != $end) {
			my $range = new('Host', name => 'auto range',
					ip => [ $begin, $end ],
					is_range => 1,
					network => $network);
			# mark hosts of range
			for(my $j = $start_range; $j <= $end_range; $j++) {
			    $sorted[$j]->{in_range} = $range;
			}
		    }
		}
		# start a new range
		# it is useless to start a range at an odd ip address
		# because it can't be matched by a subnet
		if(($ip & 1) == 0) {
		    $start_range = $i;
		    $last_ip = $ip;
		} else {
		    undef $start_range;
		}
	    }
	} elsif(($ip & 1) == 0) {
	    $start_range = $i;
	    $last_ip = $ip;
	}
    }
}

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
	    # We link all duplicate services to the first service we found.
	    # This assures that we always reach the main service
	    # from any duplicate service in one step via ->{main}
	    # This is used later to substitute occurences of
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

# Link each port range with the smalles port range which includes it.
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
		err_msg "Overlapping port ranges are not supported currently.
Workaround: Split one of $srv1->{name}, $srv2->{name} manually";
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
		err_msg "$obj->{name} must not be linked " .
		    "to managed $router->{name}";
	    $obj->{link} = $router;
	} else {
	    err_msg "$obj->{name} must not be linked to '$type:$name'";
	}
	$obj->{link} or
	    err_msg "Referencing unknown $type:$name from $obj->{name}";
    }
}

# link interface with network in both directions
sub link_interface_with_net( $ ) {
    my($interface) = @_;
    my $net_name = $interface->{network};
    my $net = $networks{$net_name} or
	err_msg "Referencing unknown network:$net_name " .
	    "from $interface->{name}";
    $interface->{network} = $net;
    my $ip = $interface->{ip};
    # check if the network is already linked with another interface
    if(defined $net->{interfaces}) {
	my $old_intf = $net->{interfaces}->[0];
	# if network is already linked to a cloud interface
	# it must not be linked to any other interface
	if($old_intf->{ip} eq 'cloud') {
	    my $rname = $interface->{router}->{name};
	    err_msg "Cloud $net->{name} must not be linked to $rname";
	}
	# if network is already linked to any interface
	# it must not be linked to a cloud interface
	if($ip eq 'cloud') {
	    my $rname = $old_intf->{router}->{name};
	    err_msg "Cloud $net->{name} must not be linked to $rname";
	}
    } 

    if($ip eq 'cloud') {
	# nothing to check: cloud interface may be linked to any network
    } elsif($ip eq 'unnumbered') {
	$net->{ip} eq 'unnumbered' or
	    die "unnumbered $interface->{name} must not be linked " .
		"to $net->{name}";
    } else {
	# check compatibility of interface ip and network ip/mask
	for my $interface_ip (@$ip) {
	    my $net_ip = $net->{ip};
	    if($net_ip eq 'unnumbered') {
		err_msg "$interface->{name} must not be linked " .
		    "to unnumbered $net->{name}";
	    }
	    my $mask = $net->{mask};
	    if($net_ip != ($interface_ip & $mask)) {
		err_msg "$interface->{name}'s ip doesn't match " .
		    "$net->{name}'s ip/mask";
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
}

##############################################################################
# Expand rules
#
# Simplify rules to expanded rules where each rule has exactly one 
# src, dst and srv
##############################################################################

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
    if($obref eq 'recursive') {
	err_msg "Found recursion in definition of $context";
	return [];
    }
    if(@$obref == 0 or ref $obref->[0]) {
	# group has already been converted from names to references
	return $obref;
    }
    my @objects;
    for my $tname (@$obref) {
	my($type, $name) = split_typed_name($tname);
	my $object;
	unless($object = $name2object{$type}->{$name}) {
	    err_msg "Can't resolve reference to '$tname' in $context";
	    next;
	}
	if(is_host $object or is_any $object) {
	    push @objects, $object unless $object->{disabled};
	} elsif(is_net $object or is_interface $object) {
	    if($object->{ip} eq 'unnumbered') {
		err_msg "Unnumbered $object->{name} must not be used in $context";
		next;
	    }
	    push @objects, $object unless $object->{disabled};
	} elsif(is_router $object) {
	    # split a router into its interfaces
	    push @objects, grep { not $_->{disabled} }
	    @{$object->{interfaces}};
	} elsif(is_every $object) {
	    # if the 'every' object itself is disabled, ignore all networks
	    next if $object->{disabled};
	    # expand an 'every' object to all networks in its security domain
	    # check each network if it is disabled
	    push @objects, grep { not $_->{disabled} }
	    @{$object->{link}->{border}->{networks}};
	} elsif(ref $object eq 'ARRAY') {
	    # substitute a group by its members
	    # detect recursive group definitions
	    $groups{$name} = 'recursive';
	    $obref = &expand_group($object, $tname);
	    $groups{$name} = $obref;
	    push @objects, @$obref;
	} else {
	    die "internal in expand_group: unexpected type '$object->{name}'";
	}
    }
    my @hosts_in_range = grep { is_host $_ and $_->{in_range} } @objects;
    if(@hosts_in_range) {
	@objects = grep { not(is_host $_ and $_->{in_range}) } @objects;
	my %in_range;
	# collect host belonging to one range
	for my $host (@hosts_in_range) {
	    my $range = $host->{in_range};
	    push @{$in_range{$range}}, $host;
	}
	for my $aref (values %in_range) {
	    my @sorted = sort { $a->{ip}->[0] <=> $b->{ip}->[0] } @$aref;
	    my $range = $sorted[0]->{in_range};
	    my $begin = $range->{ip}->[0];
	    my $end = $range->{ip}->[1];
	    my $first = $sorted[0]->{ip}->[0];
	    my $last =  $sorted[@sorted - 1]->{ip}->[0];
	    my $last_ip = $first;
	    # check if hosts are successive
	    for my $host (@sorted) {
		my $ip = $host->{ip}->[0];
		$ip == $last_ip + 1 or $ip == $last_ip or last;
		$last_ip = $ip;
	    }
	    # check if this set of hosts may be substituted by the range
	    if($first == $begin and $last == $end and $last == $last_ip) {
		push @objects, $range;
	    } else {
		# ToDo: generate subranges if $first != $last
		push @objects, @sorted;
	    }
	}
    }
    return \@objects;
}

sub expand_services( $$ ) {
    my($aref, $context) = @_;
    if($aref eq 'recursive') {
	err_msg "Found recursion in definition of $context";
	return [];
    }
    if(@$aref == 0 or ref $aref->[0]) {
	# has already been converted from names to references
	return $aref;
    }
    my @services;
    for my $tname (@$aref) {
	my($type, $name) = split_typed_name($tname);
	my $srv;
	if($type eq 'service') {
	    $srv = $services{$name} or
		err_msg "Can't resolve reference to '$tname' in $context";
	    push @services, $srv;
	} elsif ($type eq 'servicegroup') {
            my $aref = $servicegroups{$name} or
	        err_msg "Can't resolve reference to '$tname' in $context";
	    # detect recursive definitions
	    $servicegroups{$name} = 'recursive';
	    $aref = &expand_services($aref, $tname);
	    $servicegroups{$name} = $aref;
	    push @services, @$aref;
	} else {
	    err_msg "Unknown type of '$type:$name' in $context";
	}
    }
    return \@services;
}

# array of expanded permit rules
my @expanded_rules;
# array of expanded deny rules
my @expanded_deny_rules;
# array of expanded any rules
my @expanded_any_rules;
# counter for expanded permit any rules
my $anyrule_index = 0;
# hash for ordering permit any rules; 
# when sorted, they are added later to @expanded_any_rules
my %ordered_any_rules;
# hash for ordering all rules:
# $rule_tree{$src}->[0]->{$dst}->[0]->{$action}->{$srv} = $rule;
# see &add_rule for details
my %rule_tree;

sub expand_rules() {
    for my $rule (@rules) {
	my $src_any_group = {};
	my $dst_any_group = {};
	my $action = $rule->{action};
	for my $src (@{expand_group $rule->{src}, 'src of rule'}) {
	    for my $dst (@{expand_group $rule->{dst}, 'dst of rule'}) {
		for my $srv (@{expand_services $rule->{srv}, 'rule'}) {
		    my $expanded_rule = { action => $action,
					  src => $src,
					  dst => $dst,
					  srv => $srv
					  };
		    # if $srv is duplicate of an identical service
		    # use the main service, but rember the original one
		    # for debugging / comments
		    if(my $main_srv = $srv->{main}) {
			$expanded_rule->{srv} = $main_srv;
			$expanded_rule->{orig_srv} = $srv;
		    }
		    if($action eq 'deny') {
			push(@expanded_deny_rules, $expanded_rule);
		    } elsif(is_any($src)) {
			$src_any_group->{$src} = 1;
			$expanded_rule->{src_any_group} = $src_any_group;
			&order_any_rule($expanded_rule);
		    } elsif(is_any($dst)) {
			$dst_any_group->{$dst} = 1;
			$expanded_rule->{dst_any_group} = $dst_any_group;
			&order_any_rule($expanded_rule);
		    } else {
			push(@expanded_rules, $expanded_rule);
		    }
		}
	    }
	}
    }
    # add ordered 'any' rules which have been ordered by order_any_rule
    for my $depth (reverse sort keys %ordered_any_rules) {
	&add_ordered_any_rules($ordered_any_rules{$depth});
    }
    if($verbose) {
	my $nd = 0+@expanded_deny_rules;
	my $n  = 0+@expanded_rules;
	my $na = 0+@expanded_any_rules;
	info "Expanded rules: deny $nd, permit: $n, permit any: $na,\n";
    }
}

####################################################################
# Order 'any' rules
#
# Rules with an 'any' object as src or dst will be augmented with
# so called weak_deny rules later. A weak_deny rule should only 
# influence the 'any' rule it is attached to.
# To minimize the risk that a weak_deny rule influences 
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
# If neccessary, we split ranges and their corresponding rules
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
	die "internal in typeof: expected host|network|any but got '$ob->{name}'";
    }
}

sub order_any_rule ( $ ) {
    my($rule) = @_;
    my $depth = $rule->{srv}->{depth};
    my $srcid = typeof($rule->{src});
    my $dstid = typeof($rule->{dst});
    push @{$ordered_any_rules{$depth}->{$srcid}->{$dstid}}, $rule;
}

# add all rules with matching srcid and dstid to expanded_any_rules
sub add_rule_2hash( $$$ ) {
    my($hash,$srcid,$dstid) = @_;
    my $aref = $hash->{$srcid}->{$dstid};
    if(defined $aref) {
	for my $rule (@$aref) {
	    # add an incremented index to each any rule
	    # for simplifying a later check if one rule
	    # influences another one
	    $rule->{i} = $anyrule_index++;
	    push(@expanded_any_rules, $rule);
	}
    }
}

sub add_ordered_any_rules( $ ) {
    my($hash) = @_;
    return unless defined $hash;
    add_rule_2hash($hash, 'any','host');
    add_rule_2hash($hash, 'host','any');
    add_rule_2hash($hash, 'any','network');
    add_rule_2hash($hash, 'network','any');
    add_rule_2hash($hash, 'any','any');
}

####################################################################
# Check for deny influence
#
# After ordering of deny rules and inserting of weak_deny rules 
# we have to check for one pathological case, were a weak_deny rule
# influences an unrelated any rule, i.e. some packets are denied
# although they should be.allowed.
# Example:
# 1. weak_deny   net1  host2
# 2. permit      any   host2
# 3. permit      host1 any	 with host1 < net1
# Problem: Traffic from host1 to host2 is denied by rule 1 and
# permitted by rule 3.
# But rule 1 is only related to rule 2 and must not deny traffic
# which is allowed by rule 3
# Possible solution (currently not implemented):
# 0. permit      host1 host2
# 1. weak_deny   net1  host2
# 2. permit      any   host2
# 3. permit      host1 any
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

# search for
# weak_deny net1  host2 <-- drule
# permit    any3  host2 <-- arule
# permit    host1 any2  <-- rule
# with host1 < net1, any2 > host2
# ToDo:
# May the weak_deny rule influence any other rules where
# dst is some 'any' object not in relation to host2 ?
# I think not.
sub check_deny_influence() {
    info "Checking for deny influence\n";
    for my $arule (@expanded_any_rules) {
	next if $arule->{deleted};
	next unless exists $arule->{deny_rules};
	next unless is_host $arule->{dst} or is_interface $arule->{dst};
	for my $drule (@{$arule->{deny_rules}}) {
	    next if $drule->{deleted};
	    my $net = $drule->{src};
	    my $dst = $drule->{dst};
	    next unless (is_host $dst or is_interface $dst) and is_net $net;
	    my $dst_any = $dst->{network}->{border}->{any};
	    next unless $dst_any;
	    for my $host (@{$net->{hosts}}, @{$net->{interfaces}}) {
		# search for rules with action = permit, src = host and
		# dst = dst_any in $rule_tree
		my $src_hash = $rule_tree{'permit'};
		next unless $src_hash;
		# do we have any rule with src = host ?
		next unless $src_hash->{$host};
		# do we have any rule with dst = dst_any ?
		next unless $src_hash->{$host}->[0]->{$dst_any};
		my $srv_hash = $src_hash->{$host}->[0]->{$dst_any}->[0];
		# get all rules, srv doesn't matter
		for my $rule (values %$srv_hash) {
		    next if $rule->{deleted};
		    # we are only interested in rules behind the weak_deny rule
		    next unless $rule->{i} > $arule->{i};
#		    print STDERR "Got here:\n ",print_rule $drule,"\n ",
#		    print_rule $arule,"\n ",
#		    print_rule $rule,"\n";
		    if(ge_srv($rule->{srv}, $drule->{srv})) {
			warning "currently not implemented correctly:\n ",
			print_rule($drule), "\n influences\n ",
			print_rule($rule), "\n";
		    }
		}
	    }
	}
    }
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
    for my $any (values %anys, values %everys) {
	$any->{disabled} = 1 if $any->{link}->{disabled};
    }
    $default_route->{disabled} and 
	err_msg "Disabling default route $default_route->{name}";
}

####################################################################
# Set paths for efficient topology traversal
####################################################################

sub setpath_router( $$$$ ) {
    my($router, $to_border, $border, $distance) = @_;
    # ToDo: operate with loops
    if($router->{border}) {
	err_msg "Found a loop at $router->{name}. " .
		"Loops are not supported in this version";
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
	err_msg "Found a loop at $network->{name}. " .
	    "Loops are not supported in this version";
    }
    $network->{border} = $border;
    # add network to the corresponding border;
    # this info is used later for optimization,
    # generation of weak_deny rules for 'any' rules and
    # expansion of 'every' objects.
    # Unnumbered networks can be left out here because
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

    # Beginning with router1, do a traversal of the whole network 
    # to find a path from every network and router to router1
    &setpath_router($router1, 'not undef', undef, 0);

    # check if all networks and routers are connected with router1
    for my $obj (values %networks, values %routers) {
	next if $obj eq $router1;
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
		"More than one 'any' object definied in a security domain:\n"
		    . "$old_any->{name} and $any->{name}";
	}
	$border->{any} = $any;
    }
}

##############################################################################
# Functions for path traversal
# Used for generation of weak deny rules from 'any' rules and
# for generation of ACLs
##############################################################################

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
	die "internal in get_border: unexpected object $obj->{name}";
    }
}

# Apply a function to a rule at every managed router
# on the path from src to dst of the rule
# src-R5-R4-\
#           |-R2-R1
#    dst-R3-/
sub path_walk($&) {
    my ($rule, $fun) = @_;
    die "internal in path_walk: undefined rule" unless $rule;
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
	$rule->{deleted} = 1;
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
# Process all rules with an 'any' object as source or destination.
# Automatically insert deny rules at intermediate paths.
##############################################################################

my $weak_deny_counter = 0;

#     N4-\
# any-R1-N1-R2-dst
#  N2-/  N3-/
# -->
# deny N1 dst (on R2)
# deny N4 dst (on R2)
# permit any dst (on R1 and R2)
sub gen_any_src_deny( $$$ ) {
    my ($rule, $in_intf, $out_intf) = @_;
    # out_intf may be undefined if dst is an interface and
    # we just process the corresponding router; but that doesn't matter here.
    my $router = $in_intf->{router};

    # we don't need the interface itself, but only information about all
    # networks and the any  object at that interface. We get this information
    # at the border interface, not the to_border interface
    if($in_intf eq $router->{to_border}) {
	$in_intf = $router->{border};
    }
    # nothing to do for the first router
    return if $in_intf->{any} and $in_intf->{any} eq $rule->{src};

    # Optimization: nothing to do if there is a similar rule
    # with another 'any' object as src
    return if $in_intf->{any} and $rule->{src_any_group}->{$in_intf->{any}};

    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    my $action = 'weak_deny';
    for my $src (@{$in_intf->{networks}}) {
	my $deny_rule = {src => $src,
			 dst => $dst,
			 srv => $srv,
			 action => $action
		     };
	# add generated rule to the current any-rule
	push(@{$rule->{deny_rules}}, $deny_rule);
	# add rule to rule tree
	&add_rule($deny_rule);
	# counter for verbosity
	$weak_deny_counter++;
    }
}

#     N4-\
# src-R1-N1-R2-any

#  N2-/  N3-/
# -->
# deny src N2 (on R1)
# deny src N1 (on R1)
# deny src N4 (on R1)
# deny src N3 (on R2 and/or R1)
# permit src any (on R1 and R2)
sub gen_any_dst_deny( $$$ ) {
    # in_intf points to src, out_intf to dst
    my ($rule, $in_intf, $out_intf) = @_;
    my $src = $rule->{src};
    my $srv = $rule->{srv};
    my $action = 'weak_deny';
    # in_intf may be undefined if src is an interface and
    # we just process the corresponding router;
    my $router = $out_intf->{router};

    # find networks at all interfaces except the in_intf
    # for the case that src is interface of current router,
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
	# nothing to do for the interface which is connected
	# directly to the destination 'any' object
	next if $intf->{any} and $intf->{any} eq $rule->{dst};

	# Optimization: nothing to do if there is a similar rule
	# with another 'any' object as dst
	return if $intf->{any} and $rule->{dst_any_group}->{$intf->{any}};

	for my $dst (@{$intf->{networks}}) {
	    my $deny_rule = {src => $src,
			     dst => $dst,
			     srv => $srv,
			     action => $action
			 };
	    # add generated rule to the current any-rule
	    push(@{$rule->{deny_rules}}, $deny_rule);
	    # add rule to rule tree
	    &add_rule($deny_rule);
	    # counter for verbosity
	    $weak_deny_counter++;
	}
    }
}

# generate deny rules for any rules
sub gen_deny_rules() {
    for my $rule (@expanded_any_rules) {
	next if $rule->{deleted};
	if(is_any($rule->{src})) {
	    &path_walk($rule, \&gen_any_src_deny);
	}
	if(is_any($rule->{dst})) {
	    &path_walk($rule, \&gen_any_dst_deny);
	}
    }
    info "Generated $weak_deny_counter deny rules from 'any' rules\n";
}

##############################################################################
# Optimize expanded rules by deleting identical rules and 
# rules which are overlapped by a more general rule
##############################################################################

# Add rule to $rule_tree 
# If a fully identical rule is already present, it is marked
# as deleted and substituted by the new one.
sub add_rule( $ ) {
    my ($rule) = @_;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    if($rule_tree{$action}->{$src}->[0]->{$dst}->[0]->{$srv}) {
	# found identical rule: delete current one
	$rule->{deleted} = 1;
	return;
    } else {
	$rule_tree{$action}->{$src}->[0]->{$dst}->[0]->{$srv} = $rule;
	$rule_tree{$action}->{$src}->[1] = $src;
	$rule_tree{$action}->{$src}->[0]->{$dst}->[1] = $dst;
    }
}

# a rule may be deleted if we find a similar rule with greater or equal srv
sub optimize_srv_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;

    for my $rule (values %$chg_hash) {
	my $srv = $rule->{srv};
	while($srv) {
	    if(my $rule2 = $cmp_hash->{$srv}) {
		unless($rule2 eq $rule) {
		    # Rule with managed interface as dst must not be deleted
		    # if it is superseded by a network or 'any' object.
		    # ToDo: Refine this rule
		    unless(is_interface $rule->{dst} and
			   $rule->{dst}->{router}->{managed} and
			   not is_interface $rule2->{dst}) {
			$rule->{deleted} = 1;
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
	    die "internal in optimize_dst_rules: ",
	    "a rule was applied to unsupported dst '$dst->{name}'";
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
	    die "internal in optimize_src_rules: ",
	    "a rule was applied to unsupported src '$src->{name}'";
	}
    }
}

# deny > permit > weak_deny
sub optimize_rules() {
    my($deny_hash, $permit_hash, $weak_hash);
    if($deny_hash = $rule_tree{deny}) {
	&optimize_src_rules($deny_hash, $deny_hash);
    }
    if($permit_hash = $rule_tree{permit}) {
	&optimize_src_rules($permit_hash, $permit_hash);
	$deny_hash and
	    &optimize_src_rules($deny_hash, $permit_hash);
    }
    if($weak_hash = $rule_tree{weak_deny}) {
	&optimize_src_rules($weak_hash, $weak_hash);
	$permit_hash and
	    &optimize_src_rules($permit_hash, $weak_hash);
	$deny_hash and
	    &optimize_src_rules($deny_hash, $weak_hash);
    }
}

# Prepare optimization of rules
# add rules to $rule_tree for efficent rule compare operations
sub prepare_optimization() {
    info "Preparing optimization\n";
    # weak deny rules are generated & added later
    for my $rule (@expanded_deny_rules, @expanded_rules, @expanded_any_rules)
    {
	&add_rule($rule);
    }
}

# Global variables for statistic data of pre optimization
# They are used to prevent duplicate reports about deleted rules
my($nd1,$n1,$na1) = (0,0,0);

sub extra_optimization() {
    info "Starting pre-optimization\n";
    &optimize_rules();
    if($verbose) {
	for my $rule (@expanded_deny_rules) { $nd1++ if $rule->{deleted} }
	for my $rule (@expanded_rules) { $n1++ if $rule->{deleted} }
	for my $rule (@expanded_any_rules) { $na1++ if $rule->{deleted}	}
	info "Deleted redundant rules:\n";
	info "$nd1 deny, $n1 permit, $na1 permit any\n";
    }
}

sub optimization() {
    info "Starting optimization\n";
    &optimize_rules();
    if($verbose) {
	my($n, $nd, $na, $nw) = (0,0,0,0);
	for my $rule (@expanded_deny_rules) { $nd++ if $rule->{deleted}	}
	for my $rule (@expanded_rules) { $n++ if $rule->{deleted} }
	for my $rule (@expanded_any_rules) {
	    $na++ if $rule->{deleted};
	    if(exists $rule->{deny_rules}) {
		for my $deny_rule (@{$rule->{deny_rules}}) {
		    $nw++ if $deny_rule->{deleted};
		}
	    }
	}
	$nd -= $nd1;
	$n -= $n1;
	$na -= $na1;
	info "Deleted redundant rules:\n";
	info " $nd deny, $n permit, $na permit any, $nw deny from any\n";
    }
}

####################################################################
# Set routes
# Add a component 'route' to each router.
# It holds an array of arrays:[ [ $interface, network, network, .. ], ...
####################################################################

# This is used as destination network for default routes
my $net0000 = new('Network', name => 'default', ip => 0, mask => 0);

sub setroute_router( $$ ) {
    my($router, $to_default, $default) = @_;
    # first, add the interface where we reach the networks behind this router
    my @routing = ($to_default);
    for my $interface (@{$router->{interfaces}}) {
	# ignore interface where we reached this router
	next if $interface eq $to_default;
	next if $interface->{disabled};
	my $net = $interface->{network};
	if($net->{ip} ne 'unnumbered') {
	    # add directly connected networks
	    # but not for unnumbered interfaces
	    push @routing, $net;
	}
	&setroute_network($net, $interface);
    }
    for my $interface (@{$router->{interfaces}}) {
	for my $routing (@{$interface->{route}}) {
	    my $interface = $routing->[0];
	    my $len = @$routing;
	    for(my $i = 1; $i < $len; $i++) {
		# add networks which lie behind other routers
		push @routing, $routing->[$i];
	    }
	}
    }
    # add default route
    push @{$to_default->{route}}, [ $default, $net0000 ] if $to_default;
    return \@routing;
}

sub setroute_network( $$ ) {
    my ($network, $to_default) = @_;
    my @routing;
    # first, collect all networks which lie behind other routers
    for my $interface (@{$network->{interfaces}}) {
	# ignore interface where we reached this network
	next if $interface eq $to_default;
	# route: 1st element is interface,
	# rest are networks reachable via this interface
	my $route = &setroute_router($interface->{router},
				     $interface, $to_default);
	push @routing, $route;
    }
    # add collected routes to the interface, where we reached this network
    push @{$to_default->{route}}, @routing;
    # add collected routes to other interfaces at this network,
    # but prevent duplicates
    for my $interface (@{$network->{interfaces}}) {
	next if $interface eq $to_default;
	for my $route (@routing) {
	    next if $route->[0] eq $interface;
	    push @{$interface->{route}}, $route;
	}
    }
}

# Set routes
sub setroute() {
    $default_route or die "Topology needs one default route\n";
    info "Setting routes\n";
    &setroute_router($default_route, 0);
}

##############################################################################
# Code Generation
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
	push @result, print_ip($i) .' '. print_ip($inv_mask?~$mask:$mask);
	$i += $add;
    }
    return @result;
}

sub adr_code( $$ ) {
    my ($obj, $inv_mask) = @_;
    if(is_host($obj)) {
	if($obj->{is_range}) {
	    return &split_ip_range(@{$obj->{ip}}, $inv_mask);
	} else {
	    return map { 'host '. &print_ip($_) } @{$obj->{ip}};
	}
    }
    if(is_interface($obj)) {
	if($obj->{ip} eq 'unnumbered') {
	    die "internal in adr_code: unexpected unnumbered $obj->{name}\n";
	} else {
	    return map { 'host '. &print_ip($_) } @{$obj->{ip}};
	}
    } elsif(is_net($obj)) {
	if($obj->{ip} eq 'unnumbered') {
	    die "internal in adr_code: unexpected unnumbered $obj->{name}\n";
	} else {
	    my $ip_code = &print_ip($obj->{ip});
	    my $mask_code = &print_ip($inv_mask?~$obj->{mask}:$obj->{mask});
	    return "$ip_code $mask_code";
	}
    } elsif(is_any($obj)) {
	return 'any';
    } else {
	die "internal in adr_code: unsupported object $obj->{name}";
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
	die "internal in srv_code: a rule has unknown protocol '$proto'";
    }
}

# find largest mask which encloses a given ip adress
# Examples: 1->1/1, 2->2/2, 3->2/2, 4->4/4, 5->4/4, 6->4/4, 
# 13->8/8, 96->64/64, 129->128/128, 234->128/128
sub find_max_mask( $ ) {
    my($ip) = @_;
    return 0 if $ip == 0;
    # set $m to 11110
    my $m = ~1;
    # search the highest 1 bit in $ip
    while($ip & $m) {
	# fill with 0 from right
	# 11100, 11000, ...
	$m <<= 1;
    }
    # 111000 -> 000111
    $m = ~$m; 
    # 000111 -> 000011
    $m >>= 1;
    # 000011 -> 000100
    $m += 1;
    return $m;
}

sub collect_pix_static( $$$ ) {
    my($src_intf, $dst_intf, $rule) = @_;
    my $dst = $rule->{dst};
    my @networks;
    if(is_host $dst or is_interface $dst) {
	@networks = ($dst->{network});
    } elsif(is_net $dst) {
	@networks = ($dst);
    } elsif(is_any $dst) {
	# We approximate an 'any' object with 
	# every network of that security domain
	@networks = @{$dst->{border}->{networks}};
    } else {
	die "internal in collect_pix_static: unexpected dst $dst->{name}";
    }
    for my $net (@networks) {
	my $ip = $net->{ip} or
	    die "Pix doesn't support static command for IP 0.0.0.0\n";
	my $m = find_max_mask $ip;
	$dst_intf->{static}->{$src_intf->{hardware}}->{$m} = 1;
    }
}

sub gen_pix_static( $ ) {
    my($router) = @_;
    print "[ Static ]\n";
    for my $interface (@{$router->{interfaces}}) {
	my $static = $interface->{static};
	next unless $static;
	my $high = $interface->{hardware};
	for my $low (keys %$static) {
	    for my $m (sort keys %{$static->{$low}}) {
		my $ip = print_ip $m;
		print "static ($high,$low) $ip $ip netmask $ip\n";
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
    my $router;
    $src_intf and $router = $src_intf->{router};
    $dst_intf and $router = $dst_intf->{router};
    my $model = $router->{model};
    if($model eq 'PIX' and $src_intf and $dst_intf and
       $src_intf->{level} < $dst_intf->{level}) {
	&collect_pix_static($src_intf, $dst_intf, $rule);
    }
    my $inv_mask = $model eq 'IOS';
    my @src_code = &adr_code($src, $inv_mask);
    my @dst_code = &adr_code($dst, $inv_mask);
    my ($proto_code, $port_code) = &srv_code($srv, $model);
    $action = 'deny' if $action eq 'weak_deny';
    # ToDo: For PIX firewalls it is unnecessary to allow ipsec packets,
    # because these are allowed implicitly
    if(defined $src_intf) {
	# collect generated code at hardware interface,
	# not at logical interface
	my $code_aref = \@{$router->{code}->{$src_intf->{hardware}}};
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
	# For IOS and PIX, only packets from dst back to
	# this router are filtered
	my $code_aref = \@{$router->{code}->{$dst_intf->{hardware}}};
	if($comment_acls) {
	    push(@$code_aref, "! ". print_rule($rule)."\n");
	}
	for my $src_code (@src_code) {
	    for my $dst_code (@dst_code) {
		my $established;
		if($srv->{type} eq 'tcp') {
		    $established = 'established';
		} elsif($srv->{type} eq 'udp') {
		    $established = '';
		} else {
		    # for other protocols, no return packets are
		    # permitted implicitly
		    next;
		}
		push(@$code_aref,
		     "$action $proto_code $dst_code $port_code $src_code $established\n");
	    }
	}
    } else {
	die "internal in collect_acls: no interfaces for ".
	    print_rule($rule);
    }
}

# Curently unused
# ToDo: Check, if it is ok, to use this function for deny rules
#
# For deny rules call collect_acls only for the first border
# on the path from src to dst
# Case 1:
# r1-src-r2-r3-dst: get_border(src) = r1: r1 is not on path, but r2.border = r1
# Case 1a/2a: src is interface of managed router
# get_border(src) is undef, r.src_intf is undef, src.router = dst_intf.router
# Case 2:
# r3-src-r2-r1-dst: get_border(src) = r2: r2 is 1st border on path
sub collect_acls_at_src( $$$ ) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $src = $rule->{src};
    my $src_border = &get_border($src);
    # Case 1a/2a:
    if(not defined $src_border) {
	if(not defined $src_intf) {
	    &collect_acls($rule, $src_intf, $dst_intf);
	}
    } else {
	my $router = $src_intf->{router};
        # Case 1:
	if($router->{to_border} eq $src_intf and $router->{border} eq $src_border) {
	    &collect_acls($rule, $src_intf, $dst_intf);
	}
	# Case 2:
	if($src_border eq $src_intf) {
	    &collect_acls($rule, $src_intf, $dst_intf);
	}
    }
}

sub gen_acls( $ ) {
    my($router) = @_;
    my $model = $router->{model};
    print "[ ACL ]\n";
    while(my($hardware, $code) = each %{$router->{code}}) {
	my $name = "${hardware}_in";
	if($model eq 'IOS') {
	    print "ip access-list extended $name\n";
	    for my $line (@$code) {
		print " $line";
	    }
	    print " deny ip any any\n";
	    print "interface $hardware\n";
	    print " access group $name\n\n";
	} elsif($model eq 'PIX') {
	    for my $line (@$code) {
		if($line =~ /^\s*!/) {
		    print $line;
		} else {
		    print "access-list $name $line";
		}
	    }
	    print "access-list $name deny ip any any\n";
	    print "access-group $name in $hardware\n\n";
	} else {
	    die "internal in gen_acls: unsupported model $model";
	}
    }
}

sub acl_generation() {
    info "Starting code generation\n";
    # First Generate code for deny rules, then for permit rules
    for my $rule (@expanded_deny_rules, @expanded_rules) {
	next if $rule->{deleted};
	&path_walk($rule, \&collect_acls);
    }
    # Generate code for weak deny rules directly in front of
    # the corresponding 'permit any' rule
    for my $rule (@expanded_any_rules) {
	next if $rule->{deleted};
	if(exists $rule->{deny_rules}) {
	    for my $deny_rule (@{$rule->{deny_rules}}) {
		next if $deny_rule->{deleted};
		&path_walk($deny_rule, \&collect_acls); #_at_src);
	    }
	}
	&path_walk($rule, \&collect_acls);
    }
}

sub gen_routes( $ ) {
    my($router) = @_;
    print "[ Routing ]\n";
    for my $interface (@{$router->{interfaces}}) {
	for my $routing (@{$interface->{route}}) {
	    my $next_hop = $routing->[0];
	    my $hop_ip = print_ip $next_hop->{ip}->[0];
	    for(my $i = 1; $i < @$routing; $i++) {
		if($comment_routes) {
		    print "! route $routing->[$i]->{name} -> $next_hop->{name}\n";
		}
		my $adr = adr_code $routing->[$i], 0;
		if($router->{model} eq 'IOS') {
		    print "ip route $adr\t$hop_ip\n";
		} elsif($router->{model} eq 'PIX') {
		    print "route $interface->{hardware} $adr\t$hop_ip\n";
		} else {
		    die "internal in gen_routes: unexpected router model $router->{model}";
		}
	    }
	}
    }
}

# Print generated code for each managed router
sub print_code() {
    info "Printing code\n";
    print "!! Generated by $program, version $version\n\n";
    for my $router (values %routers) {
	next unless $router->{managed};
	my $model = $router->{model};
	print "[ BEGIN $router->{name} ]\n";
	print "[ Model = $model ]\n";
	&gen_routes($router);
	&gen_acls($router);
	$model eq 'PIX' and &gen_pix_static($router);
	print "[ END $router->{name} ]\n\n";
    }
}

####################################################################
# Argument processing
####################################################################
sub usage() {
    die "Usage: $0 [-c config] file | directory\n";
}

my $conf_file;
sub read_args() {
    use Getopt::Std;
    my %opts;
    getopts('c:', \%opts);
    $conf_file = $opts{c};
    $main_file = shift @ARGV or usage;
    not @ARGV or usage;
}

sub read_config() {
    open FILE, $conf_file or die "can't open $conf_file: $!";
    while(<FILE>) {
	# ignore comments
	s'#.*$'';
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
&read_file_or_dir($main_file);
&show_read_statistics();
&order_services();
&link_topology();
&mark_disabled();
&setpath();
&expand_rules();
die "Aborted with $error_counter error(s)\n" if $error_counter;
$error_counter = $max_errors; # following errors should always abort
&prepare_optimization();
&extra_optimization() if $pre_optimization;
&gen_deny_rules();
&optimization();
&check_deny_influence();
&setroute();
&acl_generation();
&print_code();
&warn_pix_icmp();
