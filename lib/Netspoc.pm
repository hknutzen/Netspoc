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
    my $first = shift;
    $first = "Warning: $first";
    print STDERR $first, @_;
}

my $main_file;
our $file;
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
# Phase 1
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
    &skip('=');
    &skip('{');
    my $token = read_identifier();
    my $host = new('Host', name => "host:$name");
    if($token eq 'ip') {
	&skip('=');
	my @ip = &read_list(\&read_ip);
	$host->{ip} = \@ip;
    } elsif($token eq 'range') {
	&skip('=');
	my $ip1 = &read_ip;
	skip('-');
	my $ip2 = &read_ip;
	$host->{ip} = [ $ip1, $ip2 ];
	$host->{is_range} = 1;
	&skip(';');
    } else {
	syntax_err "Illegal token";
    }
    &skip('}');
    if(my $old_host = $hosts{$name}) {
	my $ip_string = &print_ip($host->{ip}->[0]);
	my $old_ip_string = &print_ip($old_host->{ip}->[0]);
	error_atline "Redefining host:$name from IP $old_ip_string to $ip_string";
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
	syntax_err "Illegal token";
    }
    while(1) {
	last if &check('}');
	my($type, $hname) = split_typed_name(read_typed_name());
	syntax_err "Illegal token" unless($type eq 'host');
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
	$host->{net} = $network;
	push(@{$network->{hosts}}, $host);
    }
    if(my $old_net = $networks{$name}) {
	my $ip_string = &print_ip($network->{ip});
	my $old_ip_string = &print_ip($old_net->{ip});
	error_atline "Redefining network:$name from " . 
	    "$old_ip_string to $ip_string";
    }
    $networks{$name} = $network;
}

sub read_interface( $ ) {
    my $net = shift;
    my $interface = new('Interface', 
			# name will be set by caller
			net => $net,
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
	syntax_err "Illegal token";
    }
    my $hardware = &check_assign('hardware', \&read_string);
    $hardware and $interface->{hardware} = $hardware;
    &skip('}');
    return $interface;
}

# PIX firewalls have a security level associated wih each interface.
# We don't want to expand our syntax to state them explicitly,
# but instead we try to derive the level from the interface name.
# It is not neccessary the find the exact level; what we need to know
# is the relation of the security levels to each other
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
	    err_msg "can't derive security level from $interface->{name}";
	}
    }
    $interface->{level} = $level;
}

my %valid_model = (IOS => 1, PIX => 1);
my %routers;
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
		     interfaces => {},
		     );
    $router->{model} = $model if $managed;
    &check_flag('default_route') and $default_route = $router;
    while(1) {
	last if &check('}');
	my($type,$iname) = split_typed_name(read_typed_name());
	syntax_err "Illegal token" unless $type eq 'interface';
	my $interface = &read_interface($iname);
	$interface->{name} = "interface:$name.$iname";
	if(my $old_interface = $router->{interfaces}->{$iname}) {
	    my $ip_string = &print_ip($interface->{ip});
	    my $old_ip_string = &print_ip($old_interface->{ip});
	    error_atline "Redefining $interface->{name} from IP $old_ip_string to $ip_string";
	}
	# assign interface to routers hash of interfaces
	$router->{interfaces}->{$iname} = $interface;
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
	error_atline "Redefining router:$name";
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
	opendir DIR, $path or die "Can't opendir $path: $!";
	# for nicer file names in messages
	$path =~ s./$..;
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
# Phase 2
# Build linked data structures
##############################################################################

# eliminate TCP/UDP overlapping port ranges
# 12345 6
#  2345
#    45|6|7|8
#           89
#
# 123|45
#  23|456
#   3|4567
#     456789
#
# 1234-5
#  234-5-6
#   34-5-6-7
#    4|5|6|789
sub eliminate_overlapping_ranges( \@ ) {
    my($aref) = @_;
    for my $srv1 (@$aref) {
	my $x1 = $srv1->{v1};
	my $y1 = $srv1->{v2};
	for my $srv2 (@$aref) {
	    my $x2 = $srv2->{v1};
	    my $y2 = $srv2->{v2};
	    # overlap check
	    if($x1 < $x2 and $x2 <= $y1 and $y1 < $y2 or
		# 1111111
		#    2222222
	       $x2 < $x1 and $x1 <= $y2 and $y2 < $y1) {
		#    1111111
		# 2222222
		#
		# ToDo: Implement this function
		err_msg "Overlapping port ranges are not supported currently.
Workaround: Split one of $srv1->{name}, $srv2->{name} manually";
	    }    
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
	my $old_srv;
	if(defined $v2) {
	    $old_srv = $srv_hash{$type}->{$v1}->{$v2};
	    $srv_hash{$type}->{$v1}->{$v2} = $srv;
	} elsif(defined $v1) {
	    $old_srv = $srv_hash{$type}->{$v1};
	    $srv_hash{$type}->{$v1} = $srv;
	} else {
	    $old_srv = $srv_hash{$type};
	    $srv_hash{$type} = $srv;
	}
	if($old_srv) {
	    # found duplicate service definition
	    # link $old_srv with $srv
	    # Later substitute occurences of $old_srv with $srv
	    $old_srv->{main} = $srv;
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
	my $min_size = 2^16;
	$srv1->{up} = $up;
	for my $srv2 (@$range_aref) {
	    next if $srv1 eq $srv2;
	    my $x2 = $srv2->{v1};
	    my $y2 = $srv2->{v2};
	    if($x2 == $x1 and $y1 == $y2) {
		# found duplicate service definition
		# link $srv2 with $srv1
		# Later substitute occurences of $srv2 with $srv1
		$srv2->{main} = $srv1;
	    }
	    if($x2 <= $x1 and $y1 <= $y2) {
		my $size = $y2-$x2;
		if($size < $min_size) {
		    $min_size = $size;
		    $srv1->{up} = $srv2;
		}
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

    for my $srv (values %services) {
	my $depth = 0;
	my $up = $srv;
	while($up = $up->{up}) {
	    $depth++;
	}
	$srv->{depth} = $depth;
    }
}

# Get a reference to an array of network object names and substitute
# the names with the referenced network objects
sub subst_netob_names( $$ ) {
    my($obref, $context) = @_;
    my @unknown;
    for my $object (@$obref) {
	my($type, $name) = split_typed_name($object);
	if($type eq 'host') {
	    $object = $hosts{$name};
	} elsif($type eq 'network') {
	    $object = $networks{$name};
	} elsif($type eq 'router') {
	    $object = $routers{$name};
	} elsif($type eq 'interface') {
	    my($router, $interface)  = split /\./, $name, 2;
	    $object = $routers{$router}->{interfaces}->{$interface};
	} elsif($type eq 'any') {
	    $object = $anys{$name};
	} elsif($type eq 'every') {
	    $object = $everys{$name};
	} elsif($type eq 'group') {
	    $object = $groups{$name};
	} else {
	    err_msg "Illegally typed '$type:$name' in $context";
	}
	unless(defined $object) {
	    err_msg "Unknown object '$type:$name' in $context";
	}
    }
}

sub subst_srv_names( $$ ) {
    my($aref, $context) = @_;
    for my $srv (@$aref) {
	my($type, $name) = split_typed_name($srv);
	if($type eq 'service') {
	    $srv = $services{$name} or
		err_msg "Undefined '$type:$name' in $context";
	} elsif ($type eq 'servicegroup') {
            $srv = $servicegroups{$name} or
	        err_msg "Undefined '$type:$name' in $context";
	} else {
	    err_msg "Illegally typed '$type:$name' in $context";
	}
    }
}

sub subst_name_with_ref_for_any_and_every() {
    for my $obj (values %anys, values %everys) {
	my($type, $name) = split_typed_name($obj->{link});
	if($type eq 'network') {
	    $obj->{link} = $networks{$name};
	} elsif($type eq 'router') {
	    my $router = $routers{$name};
	    not $router->{managed} or
		err_msg "$obj->{name} must not be linked to managed $router->{name}";
	    $obj->{link} = $router;
	} else {
	    err_msg "$obj->{name} must not be linked to '$type:$name'";
	}
    }
}

sub link_interface_with_net( $ ) {
    my($interface) = @_;

    my $net_name = $interface->{net};
    my $net = $networks{$net_name};
    unless($net) {
	err_msg "Referencing unknown network:$net_name from $interface->{name}";
    }
    $interface->{net} = $net;

    my $ip = $interface->{ip};
    # check if the network is already linked with another interface
    if(defined $net->{interfaces}) {
	my $old_intf = $net->{interfaces}->[0];
	# if it is linked already to a cloud 
	# it must not be linked to any other interface
	if($old_intf->{ip} eq 'cloud') {
	    my $rname = $interface->{router}->{name};
	    err_msg "Cloud $net->{name} must not be linked to $rname";
	}
	# if it is linked already to a router 
	# it must not be linked to a cloud
	if($ip eq 'cloud') {
	    my $rname = $old_intf->{router}->{name};
	    err_msg "Cloud $net->{name} must not be linked to $rname";
	}
    } 

    if($ip eq 'cloud') {
	# nothing to check: cloud interface may be linked to any interface
    } elsif($ip eq 'unnumbered') {
	$net->{ip} eq 'unnumbered' or
	    die "unnumbered $interface->{name} must not be linked to $net->{name}";
    } else {
	# check compatibility of interface ip and network ip/mask
	for my $interface_ip (@$ip) {
	    my $ip = $net->{ip};
	    if($ip eq 'unnumbered') {
		err_msg "$interface->{name} must not be linked to unnumbered $net->{name}";
	    }
	    my $mask = $net->{mask};
	    if($ip != ($interface_ip & $mask)) {
		err_msg "$interface->{name}'s ip doesn't match $net->{name}'s ip/mask";
	    }
	}
    }
    push(@{$net->{interfaces}}, $interface);
}

##############################################################################
# Phase 3
# Expand rules
#
# Simplify rules to expanded rules where each rule has exactly one 
# src, dst and srv
##############################################################################

sub expand_object( $ ) {
    my($ob) = @_;
    if(ref($ob) eq 'ARRAY') {
	# a group is represented by an array of its members
	# some members may again be groups
	return map { &expand_object($_) } @$ob;
    } elsif(is_router($ob)) {
	# split up a router into its interfaces
	return @{$ob->{interfaces}};
    } elsif(is_every($ob)) {
	# expand an 'every' object to all networks in its security domain
	return @{$ob->{link}->{border}->{networks}};
    } elsif((is_interface($ob) or is_net($ob)) and $ob->{ip} eq 'unnumbered') {
	err_msg "Unnumbered $ob->{name} must not be used in rule";
	return ();
    } else {
	# an atomic object
	return $ob;
    }
}

sub expand_srv( $ ) {
    my($srv) = @_;
    if(ref($srv) eq 'ARRAY') {
	# Service groups are arrays of srv
	# some members may again be service groups
	return map { &expand_srv($_) } @$srv;
    } else {
	return $srv;
    }
}
    
# array of expanded permit rules
my @expanded_rules;
# array of expanded deny rules
my @expanded_deny_rules;
# array of expanded any rules
my @expanded_any_rules;
# counter for expanded permit any rules
my $anyrule_index = 0;

sub gen_expanded_rules() {
    for my $rule (@rules) {
	my $src_any_group = {};
	my $dst_any_group = {};
	for my $src (&expand_object($rule->{src})) {
	    for my $dst (&expand_object($rule->{dst})) {
		for my $srv (&expand_srv($rule->{srv})) {
		    my $action = $rule->{action};
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
			&order_rules($expanded_rule);
		    } elsif(is_any($dst)) {
			$dst_any_group->{$dst} = 1;
			$expanded_rule->{dst_any_group} = $dst_any_group;
			&order_rules($expanded_rule);
		    } else {
			push(@expanded_rules, $expanded_rule);
		    }
		}
	    }
	}
    }
}

# put an expanded rule into a data structure which eases building an ordered
# list of expanded rules with the following properties:
# - rules with an any object as src or estination are put at the end
#   (we call dem any-rules)
# - any-rules are ordered themselve:
#  - host any
#  - any host
#  - net any
#  - any net
#  - any any
# - all any-rules are ordered in their srv component, 
#  i.e. for every i,j with i < j either rule(i).srv < rule(j).srv
#  or rule(i).srv and rule(j).srv are not comparable
# Note:
# TCP and UDP port ranges may be not orderable if they are overlapping.
# If neccessary, we split ranges and their corresponding rules
# into smaller pieces to make them orderable.

sub typeof( $ ) {
    my($ob) = @_;
    if(is_host($ob) or is_interface($ob)) {
	return 'host';
    } elsif(is_net($ob)) {
	return 'net';
    } elsif(is_any($ob)) {
	return 'any';
    } else {
	die "internal in typeof: expected host|net|any but got $ob->{name}";
    }
}

sub order_rule_dst ( $$ ) {
    my($rule, $hash) = @_;
    my $id = typeof($rule->{dst});
    push(@{$hash->{$id}}, $rule);
}

sub order_rule_src ( $$ ) {
    my($rule, $hash) = @_;
    my $id = typeof($rule->{src});
    # \% : force autovivification
    order_rule_dst($rule, \%{$hash->{$id}});
}    

# hash for ordering permit any rules; 
# when sorted, they are added later to @expanded_any_rules
my %ordered_any_rules;

sub order_rules ( $ ) {
    my($rule) = @_;
    my $srv = $rule->{srv};
    my $depth = $srv->{depth};
    order_rule_src($rule, \%{$ordered_any_rules{$depth}});
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

sub addrule_ordered_src_dst( $ ) {
    my($hash) = @_;
    return unless defined $hash;
    add_rule_2hash($hash, 'host','any');
    add_rule_2hash($hash, 'any','host');
    add_rule_2hash($hash, 'net','any');
    add_rule_2hash($hash, 'any','net');
    add_rule_2hash($hash, 'any','any');
}

sub add_ordered_any_rules() {
    for my $depth (reverse sort keys %ordered_any_rules) {
	addrule_ordered_src_dst($ordered_any_rules{$depth});
    }
}

sub ge_srv( $$ ) {
    my($s1, $s2) = @_;
    while(my $up = $s2->{up}) {
	return 1 if $up eq $s1;
	$s2 = $up;
    }
    return 0;
}

# Check if two services are equal or if one is subset of the other.
# Real intersections of port ranges shouldn't happen, since
# they were split into smaller pieces before
sub match_srv( $$ ) {
    my($s1, $s2) = @_;
    return ge_srv($s1, $s2) or ge_srv($s2,$s1);
}

# ToDo: add 'is_interface' case
sub check_deny_influence() {
    for my $arule (@expanded_any_rules) {
	next if $arule->{deleted};
	next unless exists $arule->{deny_rules};
	next unless is_host($arule->{src});
	for my $drule (@{$arule->{deny_rules}}) {
	    next if $drule->{deleted};
	    my $src = $drule->{src};
	    my $net = $drule->{dst};
	    next unless is_host($src) and is_net($net);
	    my $border = get_border($src);
	    # ToDo: Check ALL 'any' objects
	    my $any = $border->{any};
	    next unless $any;
	    for my $rule (@{$any->{rules}}) {
		my $host = $rule->{dst};
		next unless is_host($host);
		next unless $host->{net} eq $net;
		next unless $rule->{i} > $arule->{i};
		if(match_srv($drule->{srv}, $rule->{srv})) {
		    my $rd = print_rule($drule);
		    my $r = print_rule($rule);
		    die "currently not implemeted correctly: $rd influences $r";
		}
	    }
	}
    }
}

####################################################################
# Phase 4
# Find paths
####################################################################

# find paths from every network and router to the starting object 'router 1'
sub setpath_router( $$$$ ) {
    my($router, $to_border, $border, $distance) = @_;
    # ToDo: operate with loops
    if($router->{border}) {
	err_msg "There is a loop at $router->{name}. " .
		"Loops are not supported in this version";
    }
    $router->{border} = $border;
    $router->{to_border} = $to_border;
    $router->{distance} = $distance;
    for my $interface (@{$router->{interfaces}}) {
	# ignore interface where we reached this router
	next if $interface eq $to_border;
	if($router->{managed}) {
	    &setpath_network($interface->{net},
			     $interface, $interface, $distance+1);
	} else {
	    &setpath_network($interface->{net},
			     $interface, $border, $distance);
	}
    }
}

sub setpath_network( $$$$ ) {
    my ($network, $to_border, $border, $distance) = @_;
    # ToDo: operate with loops
    if($network->{border}) {
	err_msg "There is a loop at $network->{name}. " .
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

# link each 'any object' with its corresponding border and vice versa
sub setpath_anys() {
    for my $any (values %anys) {
	my $border = $any->{link}->{border} or
	    err_msg "Found unconnected node: $any->{link}->{name}";
	$any->{border} = $border;
	if(my $old_any = $border->{any}) {
	    err_msg "More than one any object definied in a security domain: "
		. "$old_any->{name} and $any->{name}";
	}
	$border->{any} = $any;
    }
}

##############################################################################
# Helper functions: path traversal
##############################################################################

sub get_border( $ ) {
    my($obj) = @_;
    my $border;

    if(is_host($obj)) {
	$border = $obj->{net}->{border};
    } elsif(is_interface($obj)) {
	if($obj->{router}->{managed}) {
	    return undef;
	} else {
	    $border = $obj->{net}->{border};
	}
    } elsif(is_net($obj) or is_any($obj)) {
	$border = $obj->{border};
    } else {
	die "internal in get_border: unexpected object $obj->{name}";
    }
    $border or die "Found unconnected node: $obj->{name}\n";
    return $border;
}

# Applying a function on a rule at every managed router
# from src to dst of the rule
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
# Phase 5
# Process all rules with an any object as source or destination.
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
    # with another any object as src
    return if $in_intf->{any} and $rule->{src_any_group}->{$in_intf->{any}};

    for my $net (@{$in_intf->{networks}}) {
	my $deny_rule = {src => $net,
			 dst => $rule->{dst},
			 srv => $rule->{srv},
			 action => 'weak_deny'
		     };
	# add generated rule to the current any-rule
	push(@{$rule->{deny_rules}}, $deny_rule);
	# add generated rule to src for later optimzation phase
	push(@{$net->{rules}}, $deny_rule);
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
	# directly to the destination any object
	next if $intf->{any} and $intf->{any} eq $rule->{dst};

	# Optimization: nothing to do if there is a similar rule
	# with another any object as dst
	return if $intf->{any} and $rule->{dst_any_group}->{$intf->{any}};

	for my $net (@{$intf->{networks}}) {
	    my $deny_rule = {src => $rule->{src},
			     dst => $net,
			     srv => $rule->{srv},
			     action => 'weak_deny'
			 };
	    # add generated rule to the current any-rule
	    push(@{$rule->{deny_rules}}, $deny_rule);
	    # add generated rule to src for later optimzation phase
	    push(@{$deny_rule->{src}->{rules}}, $deny_rule);
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
}

##############################################################################
# Phase 6
# Optimize expanded rules by deleting identical rules and 
# rules which are overlapped by a more general rule
##############################################################################

# traverse rules and network objects top down, 
# starting with a security domain its any-object
sub addrule_border_any( $ ) {
    my ($border) = @_;
    my $any = $border->{any};
    if($any) {
	# add rule to dst object but remember that src was any
	for my $rule (@{$any->{rules}}) {
	    # \% : force autovivification
	    &add_rule($rule,\%{$rule->{dst}->{src_any}});
	}
	# now, rules with identical src and dst
	# are collected at the dst
	# 1. optimize overlapping services
	# 2. compare with other rules where src' = src and dst' > dst
	for my $rule (@{$any->{rules}}) {
	    unless($rule->{dst}->{src_any}->{isoptimized}) {
		&optimize_rules($rule->{dst}, 'src_any');
		# set 'isoptimized' to prevent a repeated optimization
		# of rules having the same src and dst
		$rule->{dst}->{src_any}->{isoptimized} = 1;
	    }
	}
    }
    # optimize rules having a network < any as src
    for my $network (@{$border->{networks}}) {
	&addrule_net($network);
    }
    if($any) {
	# clear rules at dst object before optimization of next any object
	for my $rule (@{$any->{rules}}) {
	    delete($rule->{dst}->{src_any});
	}
    }
}

sub addrule_net( $ ) {
    my ($net) = @_;
    for my $rule (@{$net->{rules}}) {
	# \% : force autovivification
	&add_rule($rule,\%{$rule->{dst}->{src_net}});
    }
    for my $rule (@{$net->{rules}}) {
	unless($rule->{dst}->{src_net}->{isoptimized}) {
	    &optimize_rules($rule->{dst}, 'src_net');
	    $rule->{dst}->{src_net}->{isoptimized} = 1;
	}
    }
    for my $host (@{$net->{hosts}}, @{$net->{interfaces}}) {
	&addrule_host($host);
    }
    for my $rule (@{$net->{rules}}) {
	delete($rule->{dst}->{src_net});
    }
}

# this subroutine is applied to hosts as well as interfaces
sub addrule_host( $ ) {
    my ($host) = @_;

    # first, add rules to dst host
    for my $rule (@{$host->{rules}}) {
	# \% : force autovivification
	&add_rule($rule,\%{$rule->{dst}->{src_host}});
    }
    # second, optimize rules for each host, where rules were added
    for my $rule (@{$host->{rules}}) {
	unless($rule->{dst}->{src_host}->{isoptimized}) {
	    &optimize_rules($rule->{dst}, 'src_host');
	    $rule->{dst}->{src_host}->{isoptimized} = 1;
	}
    }
    # clear rules before optimization of next host
    for my $rule (@{$host->{rules}}) {
	delete($rule->{dst}->{src_host});
    }
}    

# Add rule to a group of rules with identical src and dst
# and identical or different action and srv. 
# If a fully identical rule is already present, it is marked
# as deleted and substituted by the new one.
sub add_rule( $$ ) {
    my ($rule, $srv_hash) = @_;
    my $srv = $rule->{srv};
    my $action = $rule->{action};
    # We use the address of the srv object as a hash key here
    my $old_rule = $srv_hash->{$action}->{$srv};
    # found identical rule: delete first one
    $old_rule->{deleted} = 1 if $old_rule;
    $srv_hash->{$action}->{$srv} = $rule;
    return($srv_hash);
}

# a rule may be deleted if we find a similar rule with greater or equal srv
sub optimize_srv_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;

    for my $rule (values %$chg_hash) {
	my $srv = $rule->{srv};
	while($srv) {
	    if(my $rule2 = $cmp_hash->{$srv}) {
		unless($rule2 eq $rule) {
		    $rule->{deleted} = 1;
		    last;
		}
	    }
	    $srv = $srv->{up};
	}
    }
}

# deny > permit > weak_deny
sub optimize_action_rules( $$ ) {
    my($cmp_hash, $chg_hash) = @_;
    my($cmp_sub_hash, $chg_sub_hash);

    if($chg_sub_hash = $chg_hash->{deny}) {
	$cmp_sub_hash = $cmp_hash->{deny} and
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
    }
    if($chg_sub_hash = $chg_hash->{permit}) {
	$cmp_sub_hash = $cmp_hash->{permit} and
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
	$cmp_sub_hash = $cmp_hash->{deny} and
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
    }
    if($chg_sub_hash = $chg_hash->{weak_deny}) {
	$cmp_sub_hash = $cmp_hash->{weak_deny} and
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
	$cmp_sub_hash = $cmp_hash->{permit} and
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
	$cmp_sub_hash = $cmp_hash->{deny} and
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
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
sub optimize_rules( $$ ) {
    my($dst, $src_tag) = @_;
    my @src_tags;

    if($src_tag eq 'src_host') {
	@src_tags = ('src_host', 'src_net', 'src_any');
    } elsif ($src_tag eq 'src_net') {
	@src_tags = ('src_net', 'src_any');
    } elsif ($src_tag eq 'src_any') {
	@src_tags = ('src_any');
    }
    if(is_host($dst) or is_interface($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{net}->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{net}->{border}->{any}->{$i}, 
				$dst->{$src_tag});
	}
    } elsif(is_net($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{border}->{any}->{$i}, 
				$dst->{$src_tag});
	}
    } elsif(is_any($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	}
    } else {
	die "internal in optimize_rules: a rule was applied to unsupported dst '$dst->{name}'";
    }
}

####################################################################
# Phase 7
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
	my $net = $interface->{net};
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

##############################################################################
# Phase 8
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
	@networks = ($dst->{net});
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
	my $hardware = $src_intf->{hardware};
	if($comment_acls) {
	    push(@{$router->{code}->{$hardware}}, "! ". print_rule($rule)."\n");
	}
	for my $src_code (@src_code) {
	    for my $dst_code (@dst_code) {
		push(@{$router->{code}->{$hardware}},
		     "$action $proto_code $src_code $dst_code $port_code\n");
	    }
	}
    } elsif(defined $dst_intf) {
	# src_intf is undefined: src is an interface of this router
	# For IOS and PIX, only packets from dst back to
	# this router are filtered
	my $hardware = $dst_intf->{hardware};
	if($comment_acls) {
	    push(@{$router->{code}->{$hardware}}, "! ". print_rule($rule)."\n");
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
		push(@{$router->{code}->{$hardware}},
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

# substitute group member names with links to network objects
while(my($name, $aref) = (each %groups)) {
    subst_netob_names($aref, "group:$name");
}

# substitute names in service groups with corresponding services
while(my($name, $aref) = (each %servicegroups)) {
    subst_srv_names($aref, "servicegroup:$name");
}

# substitute rule targets with links to network objects
# and service names with service definitions
for my $rule (@rules) {
    subst_netob_names($rule->{src}, 'src of rule');
    subst_netob_names($rule->{dst}, 'dst of rule');
    subst_srv_names($rule->{srv}, 'rule');
}

# link 'any' and 'every' objects with referenced objects
subst_name_with_ref_for_any_and_every();

# link interface with network in both directions
for my $router (values %routers) {
    # substitute hash with array, since names are not needed any more
    $router->{interfaces} = [ values(%{$router->{interfaces}}) ];
    for my $interface (@{$router->{interfaces}}) {
	&link_interface_with_net($interface);
    }
}

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
setpath_anys();

# expand rules
&gen_expanded_rules();

# add sorted any rules to @expanded_any_rules
&add_ordered_any_rules();
if($verbose) {
    my $nd = 0+@expanded_deny_rules;
    my $n  = 0+@expanded_rules;
    my $na = 0+@expanded_any_rules;
    info "Expanded rules: deny $nd, permit: $n, permit any: $na,\n";
}

die "Aborted with $error_counter error(s)\n" if $error_counter;
# following errors should always abort
$error_counter = $max_errors;

info "Preparing optimization\n";
# Prepare optimization of rules
# link rules with the source network object of the rule
for my $rule (@expanded_deny_rules, @expanded_rules, @expanded_any_rules) {
    # weak deny rules are generated & added later
    push(@{$rule->{src}->{rules}}, $rule);
}

my($nd1,$n1,$na1) = (0,0,0);
if($pre_optimization) {
    info "Starting pre-optimization\n";
    # Optimize rules for each security domain
    for my $router (values %routers) {
	next unless $router->{managed};
	for my $interface (@{$router->{interfaces}}) {
	    next if $interface eq $router->{to_border};
	    &addrule_border_any($interface);
	}
    } 
    if($verbose) {
	for my $rule (@expanded_deny_rules) {
	    $nd1++ if $rule->{deleted};
	}
	for my $rule (@expanded_rules) {
	    $n1++ if $rule->{deleted};
	}
	for my $rule (@expanded_any_rules) {
	    $na1++ if $rule->{deleted};
	}
	info "Deleted redundant rules: $nd1 deny, $n1 permit, $na1 permit any\n";
    }
}

# generate deny rules for any rules
&gen_deny_rules();
info "Generated $weak_deny_counter deny rules from 'any rules'\n";

info "Starting optimization\n";
# Optimze rules for each security domain
for my $router (values %routers) {
    next unless $router->{managed};
    for my $interface (@{$router->{interfaces}}) {
	next if $interface eq $router->{to_border};
	&addrule_border_any($interface);
    }
} 
if($verbose) {
    my($n, $nd, $na, $nw) = (0,0,0,0);
    for my $rule (@expanded_deny_rules) {
	$nd++ if $rule->{deleted};
    }
    for my $rule (@expanded_rules) {
	$n++ if $rule->{deleted};
    }
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

info "Checking for deny influence\n";
check_deny_influence();

# Set routes
$default_route or die "Topology needs one default route\n";
info "Setting routes\n";
&setroute_router($default_route, 0);

info "Starting code generation\n";
# First Generate code for deny rules .
for my $rule (@expanded_deny_rules) {
    next if $rule->{deleted};
    &path_walk($rule, \&collect_acls); #_at_src);
}

# Distribute permit rules to managed routers
# src-R1-R2-\
#           |-Rx
#    dst-R3-/
for my $rule (@expanded_rules) {
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

# Print generated code for each managed router
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

# Print warnings about the PIX service hole
if(%pix_srv_hole) {
    warning "Ignored the code field of the following ICMP services\n",
    " while generating code for pix firewalls:\n";
    while(my ($name, $count) = each %pix_srv_hole) {
	print STDERR " $name: $count times\n";
    }
}
