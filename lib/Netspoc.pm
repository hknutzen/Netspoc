#!/usr/bin/perl
# File: netspoc.pl
# Author: Heinz Knutzen
# Address: heinz.knutzen@web.de, heinz.knutzen@dzsh.de
# Description:
# An attempt for a simple and fast replacement of Cisco's
# Cisco Secure Policy Manager (CSPM)

use strict;
use warnings;

our $program = 'NETwork Security POlicy Compiler';
our($version)= '$Revision$ ' =~ m/([0-9.]+)/;

####################################################################
# Options
####################################################################
our $verbose = 1;
our $comment_acls = 1;

##############################################################################
# Phase 1
# Reading topology, Services, Groups, Rules
##############################################################################

our $eof;
# $_ is used as input buffer, it holds the rest of the current input line
sub skip_space_and_comment() {
    # ignore trailing whitespace and comments
    while ( m'\G\s*([!#].*)?$ 'gcx and not $eof) {
	$_ = <>;
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

sub add_context( $ ) {
    my($msg) = @_;
    my($context) = m/([^\s,;={}]*([,;={}]|\s*)\G([,;={}]|\s*)[^\s,;={}]*)/;
    if($eof) { $context = 'at EOF'; } else { $context = qq/near "$context"/; }
    qq/$msg at line $., $context\n/;
}

sub add_line( $ ) {
    my($msg) = @_;
    qq/$msg at line $.\n/;
}

our $error_counter = 0;

sub error_atline( $ ) {
    my($msg) = @_; 
    if($error_counter++ > 10) {
	die add_line($msg);
    } else {
	print STDERR add_line($msg);
    }
}

sub err_msg( $ ) {
    my($msg) = @_; 
    if($error_counter++ > 10) {
	die $msg;
    } else {
	print STDERR "$msg\n";
    }
}

sub syntax_err( $ ) {
    my($msg) = @_;    
    die add_context $msg;
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

# check if one of the keywords 'permit' or 'deny' is available
sub check_permit_deny() {
    &skip_space_and_comment();
    if(m/\G(permit|deny)/gc) {
	return $1;
    } else {
	return undef;
    }
}

# read a boolean value
sub read_bool() {
    if(&check('0') or &check('false')) {
	return 0;
    } elsif(&check('1') or &check('true')) {
	return 1;
    } else {
	syntax_err "Expected boolean value";
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
	return(($1*256+$2)*256+$3)*256+$4;
    } else {
	syntax_err "Expected IP address";
    }
}

# convert IP address from internal integer representation to
# readable string
sub print_ip( $ ) {
    my $ip = shift;
    my $v1 = $ip % 256;
    $ip >>= 8;
    my $v2 = $ip % 256;
    $ip >>= 8;
    my $v3 = $ip % 256;
    $ip >>= 8;
    my $v4 = $ip % 256;
    $ip >>= 8;
    return "$v4.$v3.$v2.$v1";
}

# generate a list of IP strings from an ref of an array of integers
sub print_ip_aref( $ ) {
    my $aref = shift;
    return map { print_ip($_); } @$aref;
}
	
# read string up to some delimiting character or end of line
# Note: blank space is allowed inside of names 
# but ignored at the beginning and end
sub read_name() {
    use locale;		# now german umlauts are part of \w

    &skip_space_and_comment();

    # Allow dot in names to ease using ip addresses in names.
    # When dot is used as separator in interface:router.network,
    # we take the first dot. 
    # ToDo: This is ambiguous.
    # Allow colon in names; if colon is used as separator in type:name,
    # we take the first colon
    if(m#(\G[\w !:./*()+-]+)#gc) {
	my $name = $1;
	# delete trailing space
	$name =~ s/\s*$//;
	return $name;
    } else {
	syntax_err "Expected name";
    }
}

sub split_typed_name( $ ) {
    my($name) = @_;
    # split at first colon, thus the name may contain further colons
    split /:/, $name, 2;
}

sub read_assign($&) {
    my($token, $fun) = @_;
    &skip($token);
    &skip('=');
    my $val = &$fun();
    &skip(';');
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

sub read_network_name() {
    my($type, $name) = split_typed_name(&read_name());
    if($type ne 'network') {
	syntax_err "expected network:<name>";
    }
    return $name
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

our %hosts;
sub read_host( $ ) {
    my $name = shift;
    &skip('=');
    &skip('{');
    my $token = read_name();
    my $host = new('Host', name => $name);
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

our %networks;
sub read_network( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $ip = &read_assign('ip', \&read_ip);
    my $mask = &read_assign('mask', \&read_ip);
    # check if network ip matches mask
    if($ip & ~$mask != 0) {
	my $ip_string = &print_ip($ip);
	my $mask_string = &print_ip($mask);
	error_atline "network:$name's ip $ip_string doesn't match its mask $mask_string";
    }
    my $network = new('Network',
		      name => $name,
		      ip => $ip,
		      mask => $mask,
		      hosts => [],
		      );
    while(1) {
	last if &check('}');
	my($type, $hname) = split_typed_name(read_name());
	syntax_err "Illegal token" unless($type eq 'host');
	my $host = &read_host($hname);
	# check compatibility of host ip and network ip/mask
	for my $host_ip  (@{$host->{ip}}) {
	    if($ip != ($host_ip & $mask)) {
		my $ip_string = &print_ip($ip);
		my $mask_string = &print_ip($mask);
		my $host_ip_string = &print_ip($host_ip);
		error_atline "host:$host->{name}'s ip $host_ip_string doesn't match net:$name's ip/mask $ip_string/$mask_string";
	    }
	}
	$host->{net} = $network;
	push(@{$network->{hosts}}, $host);
    }
    if(my $old_net = $networks{$name}) {
	my $ip_string = &print_ip($network);
	my $old_ip_string = &print_ip($old_net);
	error_atline "Redefining network:$name from $old_ip_string to $ip_string";
    }
    $networks{$name} = $network;
}

sub read_interface( $ ) {
    my $net = shift;
    &skip('=');
    &skip('{');
    my $token = read_name();
    my $interface = new('Interface', 
			name => $net,
			link => $net,
			);
    my $ip;
    if($token eq 'ip') {
	&skip('=');
	my @ip = &read_list(\&read_ip);
	$interface->{ip} = \@ip;
    } elsif($token eq 'unnumbered') {
	$interface->{ip} = [];
	skip(';');
    } else {
	syntax_err "Illegal token";
    }
    $interface->{physical} = &read_assign('physical', \&read_name);
    &skip('}');
    return $interface;
}

our %routers;
sub read_router( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $managed = &read_assign('managed', \&read_bool);
    my $type;
    if($managed) {
	$type = &read_assign('type', \&read_name);
    } elsif(check('type')) {
	# for unmananged routers type is optional
	skip('=');
	&read_name();
	skip(';');
    }
    my $router = new('Router',
		     name => $name,
		     managed => $managed,
		     interfaces => {},
		     );
    $router->{type} = $type if $type;
    while(1) {
	last if &check('}');
	my($type,$iname) = split_typed_name(read_name());
	syntax_err "Illegal token" unless $type eq 'interface';
	my $interface = &read_interface($iname);
	if(my $old_interface = $router->{interfaces}->{$iname}) {
	    my $ip_string = &print_ip($interface->{ip});
	    my $old_ip_string = &print_ip($old_interface->{ip});
	    error_atline "Redefining interface:$name.$interface->{name} from IP $old_ip_string to $ip_string";
	}
	# assign interface to routers hash of interfaces
	$router->{interfaces}->{$iname} = $interface;
	# assign router to interface
	$interface->{router} = $router;
    }
    if(my $old_router = $routers{$name}) {
	error_atline "Redefining router:$name";
    }
    $routers{$name} = $router;
}

# very similar to router, but has no 'managed' setting and has additional 
# definition part 'links' 
our %clouds;
sub read_cloud( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $cloud = new('Router', name => $name);
    while(1) {
	last if &check('}');
	my($type, $iname) = split_typed_name(read_name());
	if ($type eq 'interface') {
	    my $interface = &read_interface($iname);
	    if(my $old_interface = $cloud->{interfaces}->{$iname}) {
		my $ip_string = &print_ip($interface->{ip});
		my $old_ip_string = &print_ip($old_interface->{ip});
		error_atline "Redefining interface:$name.$iname from $old_ip_string to $ip_string";
	    }
	    # assign interface to clouds hash of interfaces
	    $cloud->{interfaces}->{$iname} = $interface;
	    # assign cloud to interface
	    # treat cloud as a router
	    $interface->{router} = $cloud;
	}
	elsif($type eq 'links' and ! defined $iname) {
	    &skip('=');
	    my @links = &read_list(\&read_network_name);
	    my $cloud_intf_counter = 1;
	    for my $link (@links) {
		# implement link to cloud network as a special interface 
		# without ip address 
		my $interface = new('Interface',
				    name => $link,
				    ip => 'cloud',
				    link => $link,
				    router => $cloud
				    );
		$cloud_intf_counter += 1;
		# assign interface to clouds hash of interfaces
		$cloud->{interfaces}->{$link} = $interface;
	    }
	}
	else {
	    syntax_err "Illegal token";
	}
    }
    if(my $old_cloud = $clouds{$name}) {
	error_atline "Redefining cloud:$name";
    }
    $clouds{$name} = $cloud;
}

our %anys;
sub read_any( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $link = &read_assign('link', \&read_name);
    &skip('}');
    my $any = new('Any', name => $name, link => $link);
    if(my $old_any = $anys{$name}) {
	error_atline "Redefining any:$name";
    }
    $anys{$name} = $any;
}

our %everys;
sub read_every( $ ) {
    my $name = shift;
    skip('=');
    skip('{');
    my $link = &read_assign('link', \&read_name);
    &skip('}');
    my $every = new('Every', name => $name, link => $link);
    if(my $old_every = $everys{$name}) {
	error_atline "Redefining every:$name";
    }
    $everys{$name} = $every;
}

our %groups;
sub read_group( $ ) {
    my $name = shift;
    skip('=');
    my @objects = &read_list_or_null(\&read_name);
    if(my $old_group = $groups{$name}) {
	error_atline "Redefining group:$name";
    }
    $groups{$name} = \@objects;
}

our %servicegroups;
sub read_servicegroup( $ ) {
   my $name = shift;
    skip('=');
    my @objects = &read_list_or_null(\&read_name);
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

our %services;
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
	my $name = read_name();
	error_atline "Unknown protocol $name in definition of service:$name";
    }
    &skip(';');
    if(my $old_srv = $services{$name}) {
	error_atline "Redefining service:$name";
    }
    $services{$name} = $srv; 
    &prepare_srv_ordering($srv);
}

our @rules;
sub read_rules() {
    # read rules as long as another permit or deny keyword follows
    while(my $action = &check_permit_deny()) {
	my @src = &read_assign_list('src', \&read_name);
	my @dst = &read_assign_list('dst', \&read_name);
	my @srv = &read_assign_list('srv', \&read_name);
	my $rule = { action => $action,
		     src => \@src,
		     dst => \@dst,
		     srv => \@srv
		     };
	push(@rules, $rule);
    }
}

# reads input from <>, e.g. all files if given on the command line or STDIN
sub read_data() {	
    # set input buffer to defined state
    $_ = '';
    while(1) {
	last if &check_eof();
	my($type,$name) = split_typed_name(read_name());
	if($type eq 'router') {
	    &read_router($name);
	} elsif ($type eq 'network') {
	    &read_network($name);
	} elsif ($type eq 'cloud') {
	    &read_cloud($name);
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
	}elsif ($type eq 'rules') {
	    # name of rules:name should be empty or will be ignored
	    &read_rules();
	} else {
	    syntax_err "Expected global definition";
	}
    }
    if($verbose) {
	my $n = keys %routers;
	print STDERR "Read $n routers\n";
	$n = keys %networks;
	print STDERR "Read $n networks\n";
	$n = keys %clouds;
	print STDERR "Read $n clouds\n";
	$n = keys %groups;
	print STDERR "Read $n groups\n";
	$n = keys %services;
	print STDERR "Read $n services\n";
	$n = keys %servicegroups;
	print STDERR "Read $n service groups\n";
	$n = @rules;
	print STDERR "Read $n rules\n";
    }
}

##############################################################################
# Helper functions
##############################################################################

# Type checking functions
# ToDo: find a more elgant solution
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

# give a readable name of a network object
sub printable( $ ) {
    my($obj) = @_;
    my $out;
    if(&is_net($obj)) {$out = 'network';}
    elsif(&is_router($obj)) {$out = 'router';}
    elsif(&is_interface($obj)) {
	return "interface:$obj->{router}->{name}.$obj->{name}";}
    elsif(&is_host($obj)) {$out = 'host';}
    elsif(&is_any($obj)) {$out = 'any';}
    elsif(&is_every($obj)) {$out = 'every';}
    else { die "internal in printable: unknown object '$obj->{name}'";}
    return "$out:$obj->{name}";
}

sub print_srv( $ ) {
    my($srv) = @_;
    return "service:$srv->{name}";
}

sub print_rule( $ ) {
    my($obj) = @_;
    return $obj->{action} .
	" src=".&printable($obj->{src}).
	    "; dst=".&printable($obj->{dst}).
		"; srv=". print_srv($obj->{srv}).";";
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
		my $name1 = print_srv $srv1;
		my $name2 = print_srv $srv2;
		err_msg "Overlapping port ranges are not supported currently.
Workaround: Split one of $name1, $name2 manually";
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
	    my $name1 = print_srv $srv;
	    my $name2 = print_srv $old_srv;
	    error_atline "Services are duplicate: $name1, $name2";
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

# Link each port range with the smalles port range which includes it or
# if no including range is found, link it with the next larger service.
sub order_ranges( $$) {
    my($range_aref, $up) = @_;
    for my $srv1 (@$range_aref) {
	my $x1 = $srv1->{v1};
	my $y1 = $srv1->{v2};
	my $min_size = 2^16;
	$srv1->{up} = $up;
	for my $srv2 (@$range_aref) {
	    next if $srv1 eq $srv2;
	    my $x2 = $srv2->{v1};
	    my $y2 = $srv2->{v2};
	    if($x2 == $x1 and $y1 == $y2) {
		my $name1 = print_srv $srv1;
		my $name2 = print_srv $srv2;
		err_msg "Services are duplicate: $name1, $name2";
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
	# the name may contain colons
	my($type, $name) = split_typed_name($object);
	if($type eq 'host') {
	    $object = $hosts{$name};
	} elsif($type eq 'network') {
	    $object = $networks{$name};
	} elsif($type eq 'router') {
	    $object = $routers{$name};
	} elsif($type eq 'interface') {
	    # ToDo: Both router and network names may contain dots.
	    # We have to resolve this ambiguity somehow.
	    # Currently we split at the first dot,
	    # since in network names dots are more propable.
	    my($router, $interface)  = split /\./, $name, 2;
	    $object = $routers{$router}->{interfaces}->{$interface} or
 		$object = $clouds{$router}->{interfaces}->{$interface};
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
	} elsif($type eq 'cloud') {
	    $obj->{link} = $clouds{$name};
	} else {
	    err_msg "Illegally typed '$type:$name' in " . printable($obj);
	}
    }
}

sub link_interface_with_net( $ ) {
    my($interface) = @_;

    my $net_name = $interface->{link};
    my $net = $networks{$net_name};
    unless($net) {
	err_msg "Referencing unknown network:$net_name from " .
	    printable($interface);
    }
    $interface->{link} = $net;

    my $is_cloud_intf = $interface->{ip} eq 'cloud';
    # check, if the network is already linked with 
    # an interface of the other type
    if(defined $net->{is_cloud_network} and
       $net->{is_cloud_network} != $is_cloud_intf) {
	err_msg "network:$net_name must not be linked to an interface" .
	    "since it is linked to a cloud";
    } 
    $net->{is_cloud_network} = $is_cloud_intf;

    if(! $is_cloud_intf) {
	# check compatibility of interface ip and network ip/mask
	for my $interface_ip (@{$interface->{ip}}) {
	    my $ip = $net->{ip};
	    my $mask = $net->{mask};
	    if($ip != ($interface_ip & $mask)) {
		my $iname = printable($interface);
		err_msg "${iname}'s ip doesn't match net:${net_name}'s ip/mask";
	    }
	}
    }
    push(@{$net->{interfaces}}, $interface);
}

##############################################################################
# Phase 3
# Expand rules
##############################################################################

# simplify rules to expanded rules where each rule has exactly one 
# src, dst and srv

sub expand_object( $ ) {
    my($ob) = @_;
    if(ref($ob) eq 'ARRAY') {
	# a group is represented by an array of its members
	return $ob;
    } elsif(is_router($ob)) {
	# split up a router into its interfaces
	return $ob->{interfaces};
    } elsif(is_every($ob)) {
	# expand an 'every' object to all networks in the perimeter
	return $ob->{link}->{border}->{networks};
    } else {
	# an atomic object
	return $ob;
    }
}
    
# array of expanded permit rules
our @expanded_rules;
# array of expanded deny rules
our @expanded_deny_rules;
# array of expanded any rules
our @expanded_any_rules;
# hash for ordering permit any rules; 
# when sorted, they are added to @expanded_any_rules
our %ordered_any_rules;
# counter for expanded permit any rules
our $anyrule_index = 0;

sub gen_expanded_rules( $$$$ ) {
    my($action, $src_aref, $dst_aref, $srv_aref) = @_;
    for my $src (@$src_aref) {
	my $aref = expand_object($src);
	if(ref($aref) eq 'ARRAY') {
	    &gen_expanded_rules($action, $aref, $dst_aref, $srv_aref);
	} else {
	    &expand_rule_dst($action, $src, $dst_aref, $srv_aref);
	}
    }
}

sub expand_rule_dst( $$$$ ) {
    my($action, $src, $dst_aref, $srv_aref) = @_;
    for my $dst (@$dst_aref) {
	my $aref = expand_object($dst);
	if(ref($aref) eq 'ARRAY') {
	    &expand_rule_dst($action, $src, $aref, $srv_aref);
	} else {
	    &expand_rule_srv($action, $src, $dst, $srv_aref);
	}
    }
}

sub expand_rule_srv( $$$$ ) {
    my($action, $src, $dst, $srv_aref) = @_;
    for my $srv (@$srv_aref) {
	# Service groups are arrays of srv
	if(ref($srv) eq 'ARRAY') {
	    &expand_rule_srv($action, $src, $dst, $srv);
	} else {
	    my $expanded_rule = { action => $action,
				  src => $src,
				  dst => $dst,
				  srv => $srv
				  };
	    if($action eq 'deny') {
		push(@expanded_deny_rules, $expanded_rule);
	    } elsif(is_any($src) or is_any($dst)) {
		&order_rules($expanded_rule,
			     \%ordered_any_rules);
	    } else {
		push(@expanded_rules, $expanded_rule);
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
	die "internal in typeof: expected host|net|any but got ".
	    printable($ob);
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

sub order_rules ( $$ ) {
    my($rule, $hash) = @_;
    my $srv = $rule->{srv};
    my $depth = $srv->{depth};
    order_rule_src($rule, \%{$hash->{$depth}});
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

sub addrule_ordered_srv( $ ) {
    my($hash) = @_;
    for my $depth (reverse sort keys %$hash) {
	addrule_ordered_src_dst($hash->{$depth});
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

# check, if two services are equal or have a non empty intersection.
# Real intersection of port ranges shouldn't happen, since
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
    
##############################################################################
# Phase 4
# Find paths
##############################################################################

# find paths from every network and router to the starting object 'router 1'
sub setpath_router( $$$$ ) {
    my($router, $to_border, $border, $distance) = @_;
    # ToDo: operate correctly with loops
    if($router->{border}) {
	err_msg "There is a loop at " .
	    printable($router) .
		". Loops are not supported in this version";
    }
    $router->{border} = $border;
    $router->{to_border} = $to_border;
    $router->{distance} = $distance;
    for my $interface (@{$router->{interfaces}}) {
	# ignore interface where we reached this router
	next if $interface eq $to_border;
	if($router->{managed}) {
	    &setpath_network($interface->{link},
			     $interface, $interface, $distance+1);
	} else {
	    &setpath_network($interface->{link},
			     $interface, $border, $distance);
	}
    }
}

sub setpath_network( $$$$ ) {
    my ($network, $to_border, $border, $distance) = @_;
    # ToDo: operate correctly with loops
    if($network->{border}) {
	err_msg "There is a loop at " .
	    printable($network) .
	      ". Loops are not supported in this version";
    }
    $network->{border} = $border;
    # add network to the corresponding border;
    # this info is used later for optimization,
    # generation of weak_deny rules for 'any' rules and
    # expansion of 'every' objects
    push(@{$border->{networks}}, $network);
    for my $interface (@{$network->{interfaces}}) {
	# ignore interface where we reached this network
	next if $interface eq $to_border;
	&setpath_router($interface->{router},
			$interface, $border, $distance);
    }
}

# link each 'any object' with its correspnding border and vice versa
sub setpath_anys() {
    for my $any (values %anys) {
	my $border = $any->{link}->{border} or
	    err_msg "Found unconnected node: ". printable($any->{link});
	$any->{border} = $border;
	if(my $old_any = $border->{any}) {
	    err_msg "More than one any object definied in a perimeter: any:$old_any->{name} and any:$any->{name}";
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

    if(&is_host($obj)) {
	$border = $obj->{net}->{border};
    } elsif(&is_interface($obj)) {
	if($obj->{router}->{managed}) {
	    return undef;
	} else {
	    $border = $obj->{link}->{border};
	}
    } elsif(&is_net($obj) or &is_any($obj)) {
	$border = $obj->{border};
    } else {
	die "internal in get_border: unexpected object " . &printable($obj);
    }
    $border or die "Found unconnected node: ". printable($obj);
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
	    print STDERR "Unenforceable rule\n ", print_rule($rule), "\n";
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

our $weak_deny_counter = 0;

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
    return if $rule->{deleted};
    my $router = $in_intf->{router};

    # we don't need the interface itself, but only information about all
    # networks and the any  object at that interface. We get this information
    # at the border interface, not the to_border interface
    if($in_intf eq $router->{to_border}) {
	$in_intf = $router->{border};
    }
    # nothing to do for the first router
    return if $in_intf->{any} and $in_intf->{any} eq $rule->{src};

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
    return if $rule->{deleted};
    my $router = $out_intf->{router};

    # find networks at all interfaces except the in_intf
    # for the case that src is interface of current router,
    # take only the out_intf
    for my $orig_intf ($in_intf?@{$router->{interfaces}}:($out_intf)) {
	# copy $intf to prevent changing of the iterated array
	my $intf = $orig_intf;

	# nothing to do for in_intf:
	# case 1: it is the first router near src
	# case 2: the in_intf is on the same perimeter
	# as an out_intf of some other router on the path
	next if defined $in_intf and $intf eq $in_intf;

	# see comment in &gen_any_src_deny
	if($intf eq $router->{to_border}) {
	    $intf = $router->{border};
	}
	# nothing to do for the interface which is connected
	# directly to the destination any object
	next if $intf->{any} and $intf->{any} eq $rule->{dst};

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

##############################################################################
# Phase 6
# Optimize expanded rules by deleting identical rules and 
# rules which are overlapped by a more general rule
##############################################################################

# traverse rules and network objects top down, 
# beginning with a perimeter
sub addrule_border_any( $ ) {
    my ($border) = @_;
    my $any = $border->{any};
    if($any) {
	# add rule to dst object but remember that src was any
	for my $rule (@{$any->{rules}}) {
	    $rule->{dst}->{src_any} =
		&add_rule($rule,$rule->{dst}->{src_any});
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
	$rule->{dst}->{src_net} =
	    &add_rule($rule,$rule->{dst}->{src_net});
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
	$rule->{dst}->{src_host} =
	    &add_rule($rule,$rule->{dst}->{src_host});
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
    $old_rule->{deleted} = 1 if $old_rule;
    $srv_hash->{$action}->{$srv} = $rule;
    return($srv_hash);
}

# a rule may be deleted if we find a similar rule with greater srv
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
    if(&is_host($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{net}->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{net}->{border}->{any}->{$i}, 
				$dst->{$src_tag});
	}
    } elsif(&is_interface($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{link}->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{link}->{border}->{any}->{$i}, 
				$dst->{$src_tag});
	}
    } elsif(&is_net($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{border}->{any}->{$i}, 
				$dst->{$src_tag});
	}
    } elsif(&is_any($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	}
    } else {
	die "internal in optimize_rules: a rule was applied to unsupported dst '$dst->{name}'";
    }
}

##############################################################################
# Phase 7
# Code Generation
##############################################################################

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
	push @result, print_ip($i) .' '. print_ip($mask);
	$i += $add;
    }
    return @result;
}

sub adr_code( $ ) {
    my ($obj) = @_;
    if(&is_host($obj) and $obj->{is_range}) {
	return &split_ip_range(@{$obj->{ip}});
    }
    if(&is_host($obj) or &is_interface($obj)) {
	return map { 'host '. &print_ip($_) } @{$obj->{ip}};
    } elsif(&is_net($obj)) {
	my $ip_code = &print_ip($obj->{ip});
	my $mask_code = &print_ip($obj->{mask});
	return "$ip_code $mask_code";
    } elsif(&is_any($obj)) {
	return 'any';
    } else {
	my $name = printable($obj);
	die "internal in adr_code: unsupported object '$name'";
    }
}

sub srv_code( $ ) {
    my ($srv) = @_;
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
		return($proto, "$type $code");
	    }
	}
    } elsif($proto eq 'proto') {
	my $nr = $v1;
	return($nr, '');
    } else {
	die "internal in srv_code: a rule has unknown protocol '$proto'";
    }
}

sub gen_code( $$$ ) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    my @src_code = &adr_code($src);
    my @dst_code = &adr_code($dst);
    my ($proto_code, $port_code) = &srv_code($srv);
    $action = 'deny' if $action eq 'weak_deny';
    if(defined $src_intf) {
	if($comment_acls) {
	    push(@{$src_intf->{code}}, "! ". print_rule($rule)."\n");
	}
	for my $src_code (@src_code) {
	    for my $dst_code (@dst_code) {
		push(@{$src_intf->{code}},
		     "$action $proto_code $src_code $dst_code $port_code\n");
	    }
	}
    } else {	# defined $dst_intf
	if($comment_acls) {
	    push(@{$dst_intf->{code}}, "! ". print_rule($rule)."\n");
	}
	for my $src_code (@src_code) {
	    for my $dst_code (@dst_code) {
		push(@{$dst_intf->{code}},
		     # ToDo: add 'established' for TCP
		     "$action $proto_code $dst_code $port_code $src_code\n");
	    }
	}
    }
}

# for deny rules call gen_code only for the first border
# on the path from src to dst
# Case 1:
# r1-src-r2-r3-dst: get_border(src) = r1: r1 is not on path, but r2.border = r1
# Case 1a/2a: src is interface of managed router
# get_border(src) is undef, r.src_intf is undef, src.router = dst_intf.router
# Case 2:
# r3-src-r2-r1-dst: get_border(src) = r2: r2 is 1st border on path
# ToDo: this code works only for 2nd case
# ToDo: If src is an managed interface, inverse deny rules have to be generated
sub gen_code_at_src( $$$ ) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $src = $rule->{src};
    my $src_border = &get_border($src);
    # Case 1a/2a:
    if(not defined $src_border) {
	if(not defined $src_intf) {
	    &gen_code($rule, $src_intf, $dst_intf);
	}
    } else {
	my $router = $src_intf->{router};
        # Case 1:
	if($router->{to_border} eq $src_intf and $router->{border} eq $src_border) {
	    &gen_code($rule, $src_intf, $dst_intf);
	}
	# Case 2:
	if($src_border eq $src_intf) {
	    &gen_code($rule, $src_intf, $dst_intf);
	}
    }
}


##############################################################################
# Main program
##############################################################################

&read_data();

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
for my $router (values %routers, values %clouds) {
    # substitute hash with array, since names are not needed any more
    $router->{interfaces} = [ values(%{$router->{interfaces}}) ];
    for my $interface (@{$router->{interfaces}}) {
	&link_interface_with_net($interface);
    }
}

# take a random managed element from %routers, name it "router1"
our $router1;
for my $router (values %routers) {
    if($router->{managed}) {
	$router1 = $router;
	last;
    }
}
$router1 or err_msg "Topology has no managed router"; 
if($verbose) {
    my $name = printable($router1);
    print STDERR "Selected $name as 'router 1'\n";
}

# Beginning with router1, do a traversal of the whole network 
# to find a path from every network and router to router1
&setpath_router($router1, 'not undef', undef, 0);
setpath_anys();

# expand rules
for my $rule (@rules) {
    &gen_expanded_rules($rule->{action},
			$rule->{src}, $rule->{dst}, $rule->{srv});
}
# add sorted any rules to @expanded_rules
&addrule_ordered_srv(\%ordered_any_rules);
if($verbose) {
    my $nd = 0+@expanded_deny_rules;
    my $n  = 0+@expanded_rules;
    my $na = 0+@expanded_any_rules;
    print STDERR "Expanded rules: deny $nd, permit: $n, permit any: $na,\n";
}

die "Aborted with errors\n" if $error_counter;
$error_counter = 10;

print STDERR "Preparing optimization\n" if $verbose;
# Prepare optimization of rules
# link rules with the source network object of the rule
for my $rule (@expanded_deny_rules, @expanded_rules, @expanded_any_rules) {
    # weak deny rules are generated & added later
    push(@{$rule->{src}->{rules}}, $rule);
}

print STDERR "Starting first optimization\n" if $verbose;
# Optimze rules for each particular perimeter
for my $router (values %routers) {
    next unless $router->{managed};
    for my $interface (@{$router->{interfaces}}) {
	next if $interface eq $router->{to_border};
	&addrule_border_any($interface);
    }
} 
if($verbose) {
    our($nd1,$n1,$na1) = (0,0,0);
    for my $rule (@expanded_deny_rules) {
	$nd1++ if $rule->{deleted};
    }
    for my $rule (@expanded_rules) {
	$n1++ if $rule->{deleted};
    }
    for my $rule (@expanded_any_rules) {
	$na1++ if $rule->{deleted};
    }
    print STDERR
	"Deleted redundant rules: $nd1 deny, $n1 permit, $na1 permit any\n";
}

# generate deny rules for any rules
for my $rule (@expanded_any_rules) {
    if(&is_any($rule->{src})) {
 	&path_walk($rule, \&gen_any_src_deny);
    }
    if(&is_any($rule->{dst})) {
	&path_walk($rule, \&gen_any_dst_deny);
    }
}
if($verbose) {
    print STDERR "Generated $weak_deny_counter deny rules from 'any rules'\n";
}

print STDERR "Starting second optimization\n" if $verbose;
# Optimze rules for each particular perimeter
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
    our($nd1,$n1,$na1);
    $nd -= $nd1;
    $n -= $n1;
    $na -= $na1;
    print STDERR "Deleted redundant rules:\n";
    print STDERR " $nd deny, $n permit, $na permit any, $nw deny from any\n";
}

print STDERR "Checking for deny influence\n" if $verbose;
check_deny_influence();

print STDERR "Starting code generation\n" if $verbose;
# First Generate code for deny rules .
for my $rule (@expanded_deny_rules) {
    next if $rule->{deleted};
    &path_walk($rule, \&gen_code_at_src);
}

# Distribute permit rules to managed routers
# src-R1-R2-\
#           |-Rx
#    dst-R3-/
for my $rule (@expanded_rules) {
    next if $rule->{deleted};
    &path_walk($rule, \&gen_code);
}

# Generate code for weak deny rules directly before the corresponding 
# permit any rule
for my $rule (@expanded_any_rules) {
    next if $rule->{deleted};
    if(exists $rule->{deny_rules}) {
	for my $deny_rule (@{$rule->{deny_rules}}) {
	    next if $deny_rule->{deleted};
	    &path_walk($deny_rule, \&gen_code_at_src);
	}
    }
    &path_walk($rule, \&gen_code);
}

print "!! Generated by $program version $version\n\n";

# Print generated code for each managed router
for my $router (values %routers) {
    next unless $router->{managed};
    print "!! Access Lists for $router->{name}\n";
    for my $interface (@{$router->{interfaces}}) {
	# ToDo: currently we operate with logical interfaces per network
	# but access lists work with physical interfaces
	print "ip access-list extended $interface->{physical}_in\n";
	for my $line (@{$interface->{code}}) {
	    print " $line";
	}
	print " deny any any\n";
	print "interface $interface->{physical}\n";
	print " access group $interface->{physical}_in\n";
	print "\n";
    }
}
