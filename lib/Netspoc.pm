#!/usr/bin/perl

# File: open-spm.pl
# Author: Heinz Knutzen
# Description:
# An attempt for a simple and fast replacement of Cisco's
# Cisco Secure Policy Manager

$longname = 'Open Secure Policy Manager';
$shortname = 'open-spm';
$version = 0.21;

##############################################################################
# Phase 1
# Reading topology, Services, Groups, Rules
##############################################################################

# $_ is used as input buffer, it holds the rest of the current input line
sub skip_space_and_comment() {
    # ignore trailing whitespace and comments
    while ( m'^\s*([!#].*)?$ 'x ) {
	$_ = <>;
	unless(defined $_) {
	    $_ = '<EOF>';
	    $eof = 1;
	    return;
	}
	# cut off trailing lf
	chop;
    }
    # ignore leading witespace
    s/^\s*//;
}

# our input buffer $_ gets undefined, if we reached eof
sub check_eof() {
    &skip_space_and_comment();
    return $eof;
}

# check for a string and skip if available
sub check($) {
    my $token = shift;
    &skip_space_and_comment();
    # todo: escape special RE characters in $token
    return(s/^$token//);
}

# skip a string
sub skip ($) {
    my $token = shift;
    &check($token) || die "expected '$token', but found '$_'";
}

# check, if an integer is available
sub check_int() {
    &skip_space_and_comment();
    if(s/^(\d+)//) {
	return $1;
    } else {
	return undef;
    }
}

# check if one of the keywords 'permit' or 'deny' is available
sub check_permit_deny() {
    &skip_space_and_comment();
    if(s/^(permit|deny)//) {
	return $1;
    } else {
	return undef;
    }
}

# read a boolean value
sub read_bool() {
    if(&check('0') || &check('false')) {
	return 0;
    } elsif(&check('1') || &check('true')) {
	return 1;
    } else {
	die "expected boolean value, but found '$_'";
    }
}

# read IP address
# internally it is stored as an integer
sub read_ip() {
    &skip_space_and_comment();
    if(s/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})//) {
	if($1 > 255 || $2 > 255 || $3 > 255 || $4 > 255) {
	    die "invalid IP address $1.$2.$3.$4";
	}
	return(($1*256+$2)*256+$3)*256+$4;
    } else {
	die "expected IP address, but got $_";
    }
}

# convert IP address from internal integer representation to
# readable string
sub print_ip() {
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

# read string up to some delimiting character or end of line
# Note: blank space is allowed inside of names 
# but ignored at the beginning or end
sub read_name() {
    use locale;

    &skip_space_and_comment();

    # allow dot in names to ease using ip addresses in names
    # if dot is used as separator in router.interface,
    # we take the last dot
    if(s/(^[\w .-]+)//) {
	my $name = $1;
	# delete trailing space
	$name =~ s/\s*$//;
	return $name;
    } else {
	die "can't find name in '$_'";
    }
}

sub read_type_prefix() {
    my $type = &read_name();
    &skip(':');
    return $type;
}

sub read_typed_name() {
    my $type = &read_type_prefix();
    my $name = &read_name();
    return("${type}:${name}");
}

sub read_assign($&) {
    my($token, $fun) = @_;
    &skip($token);
    &skip('=');
    my $val = &$fun();
    &skip(';');
    return $val;
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
    my($type, $name) = split(':', &read_typed_name());
    if($type ne 'network') {
	die "expected network, but got $type:$name";
    }
    return $name
}

sub read_host() {
    my $name = &read_name();
    &skip('=');
    &skip('{');
    my $ip = &read_assign('ip', \&read_ip);
    &skip('}');
    my $host = { name => $name,
		 ip => $ip,
	     };
    if(my $old_host = $hosts{$name}) {
	my $ip_string = &print_ip($ip);
	my $old_ip_string = &print_ip($old_host->{ip});
	die "redefining host:$name from IP $old_ip_string to $ip_string";
    }
    $hosts{$name} = $host;
    return $host;
}

sub read_network() {
    my $name = &read_name();
    skip('=');
    skip('{');
    my $ip = &read_assign('ip', \&read_ip);
    my $mask = &read_assign('mask', \&read_ip);
    # check if network ip matches mask
    if($ip & ~$mask != 0) {
	my $ip_string = &print_ip($ip);
	my $mask_string = &print_ip($mask);
	die "network:$name's ip $ip_string doesn't match its mask $mask_string";
    }
    my $network = { name => $name,
		    ip => $ip,
		    mask => $mask,
		    hosts => [],
		};
    while(1) {
	last if &check('}');
	my $type = &read_type_prefix();
	die "unknown definition $type: in network $name"
	    unless($type eq 'host');
	my $host = &read_host();
	# check compatibility of host ip and network ip/mask
	my $host_ip = $host->{ip};
	if($ip != ($host_ip & $mask)) {
	    my $ip_string = &print_ip($ip);
	    my $mask_string = &print_ip($mask);
	    my $host_ip_string = &print_ip($host_ip);
	    die "host:$host->{name}'s ip $host_ip_string doesn't match net:$name's ip/mask $ip_string/$mask_string";
	}
	$host->{net} = $network;
	push(@{$network->{hosts}}, $host);
    }
    if(my $old_net = $networks{$name}) {
	my $ip_string = &print_ip($ip);
	my $mask_string = &print_ip($mask);
	my $old_ip_string = &print_ip($old_net->{ip});
	my $old_mask_string = &print_ip($old_net->{mask});
	die "redefining network:$name from $old_ip_string/$old_mask_string to $ip_string/$mask_string";
    }
    $networks{$name} = $network;
}

sub read_interface() {
    my $name = &read_name();
    &skip('=');
    &skip('{');
    my $ip = &read_assign('ip', \&read_ip);
    my $net = &read_assign('link', \&read_network_name);
    &skip('}');
    my $interface = { name => $name,
		      ip => $ip,
		      link => $net,
		  };
    return $interface;
}

sub read_router() {
    my $name = &read_name();
    skip('=');
    skip('{');
    my $managed = &read_assign('managed', \&read_bool);
    my $type;
    $type = &read_assign('type', \&read_name) if $managed;
    my $router = { name => $name,
		   managed => $managed,
		   type => $type,
		   interfaces => {},
	       };
    while(1) {
	last if &check('}');
	my $type = &read_type_prefix();
	die "unknown definition $type: in router $name" 
	    unless $type eq 'interface';
	my $interface = &read_interface();
	if(my $old_interface = $router->{interfaces}->{$interface->{name}}) {
	    my $ip_string = &print_ip($interface->{ip});
	    my $old_ip_string = &print_ip($old_interface->{ip});
	    die "redefining interface:$name.$interface->{name} from IP $old_ip_string to $ip_string";
	}
	# assign interface to routers hash of interfaces
	$router->{interfaces}->{$interface->{name}} = $interface;
	# assign router to interface
	$interface->{router} = $router;
    }
    if(my $old_router = $routers{$name}) {
	die "redefinig router:$name";
    }
    $routers{$name} = $router;
}

# very similar to router, but has no 'managed' setting and has additional 
# definition parts 'links' and 'any'
sub read_cloud() {
    my $name = &read_name();
    skip('=');
    skip('{');
    my $cloud = { name => $name };
    if(&check('links')) {
	&skip('=');
	my @links = &read_list(\&read_network_name);
	my $cloud_intf_counter = 1;
	for my $link (@links) {
	    # implement link to cloud network as a special interface 
	    # without ip address 
	    my $interface = { name => "_link_$cloud_intf_counter",
			      ip => 'cloud',
			      link => $link
			      };
	    $cloud_intf_counter += 1;
	    # assign interface to clouds hash of interfaces
	    $cloud->{interfaces}->{$interface->{name}} = $interface;
	}
    }
    while(1) {
	last if &check('}');
	my $type = &read_type_prefix();
	if ($type eq 'interface') {
	    my $interface = &read_interface();
	    if(my $old_interface = $cloud->{interfaces}->{$interface->{name}}) {
		my $ip_string = &print_ip($interface->{ip});
		my $old_ip_string = &print_ip($old_interface->{ip});
		die "redefining interface:$name.$interface->{name} from IP $old_ip_string to $ip_string";
	    }
	    # assign interface to clouds hash of interfaces
	    $cloud->{interfaces}->{$interface->{name}} = $interface;
	    # assign cloud to interface
	    # treat cloud as a router
	    $interface->{router} = $cloud;
	}
	elsif ($type eq 'any') {
	    my $name2 = &read_name();
	    skip(';');
	    if($cloud->{any}) {
		die "found two any objects in cloud:$name";
	    }
	    if(my $old_any = $anys{$name2}) {
		die "redefining any:$name2 in cloud:$name";
	    }
	    my $any = { name => $name2,
			 link => $cloud
			 };
	    # we need the link from cloud to the any object later when finding
	    # paths
	    $cloud->{any} = $any;
	    $anys{$name2} = $any;
	} else {
	    die "unknown definition $type:$name2 in cloud:$name";
	}
    }
    if(my $old_cloud = $clouds{$name}) {
	die "redefinig cloud:$name";
    }
    $clouds{$name} = $cloud;
}
	    
sub read_group() {
    my $name = &read_name();
    skip('=');
    my @objects = &read_list(\&read_typed_name);
    if(my $old_group = $groups{$name}) {
	die "redefinig group:$name";
    }
    $groups{$name} = \@objects;
}

sub read_port_range() {
    if(defined (my $port1 = &check_int())) {
	die "too large port number $port1" if $port1 > 65535;
	die "invalid port number '0'" if $port1 == 0;
	if(&check('-')) {
	    if(defined (my $port2 = &check_int())) {
		die "too large port number $port2" if $port2 > 65535;
		die "invalid port number '0'" if $port2 == 0;
		return "$port1-$port2";
	    } else {
		die "expected second port in port range '$port1-' but got $_";
	    }
	} else {
	    return $port1;
	}
    } else {
	return 'any';
    }
}

sub read_icmp_type_code() {
    if(defined (my $type = &check_int())) {
	die "too large icmp type $type" if $type > 255;
	if(&check('/')) {
	    if(defined (my $code = &check_int())) {
		die "too large icmp code $code" if $code > 255;
		return($type, $code);
	    } else {
		die "expected icmp code after '$type/' but got $_";
	    }
	} else {
	    return($type, 'any');
	}
    } else {
	return 'any';
    }
}

sub read_proto_nr() {
    if(defined (my $nr = &check_int())) {
	die "too large protocol number $nr" if $nr > 255;
	die "invalid protocol number '0'" if $nr == 0;
	if($nr == 1) {
	    return('icmp', 'any');
	} elsif($nr == 4) {
	    return('tcp', 'any');
	} elsif($nr == 17) {
	    return('udp', 'any');
	} else {
	    return('proto', $nr);
	}
    } else {
	die "expected protocol number after 'proto' but got $_";
    }
}

sub read_service() {
    my $name = &read_name();
    my @srv;
    &skip('=');
    if(&check('ip')) {
	push(@srv, 'ip');
    } elsif(&check('tcp')) {
	push(@srv, 'tcp');
	push(@srv, &read_port_range());
    } elsif(&check('udp')) {
	push(@srv, 'udp');
	push(@srv, &read_port_range());
    } elsif(&check('icmp')) {
	push(@srv, 'icmp');
	push(@srv, &read_icmp_type_code());
    } elsif(&check('proto')) {
	push(@srv, 'proto');
	push(@srv, &read_proto_nr());
    } else {
	die "unknown protocol in definition of service $name: $_";
    }
    &skip(';');
    if(my $old_srv = $services{$name}) {
	die "redefinig service:$name";
    }
    $services{$name} = \@srv; 
}

sub read_rules() {
    # read rules as long as another permit or deny keyword follows
    while(my $action = &check_permit_deny()) {
	my @src = &read_assign_list('src', \&read_typed_name);
	my @dst = &read_assign_list('dst', \&read_typed_name);
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
	$type = &read_type_prefix();
	if($type eq 'router') {
	    &read_router();
	} elsif ($type eq 'network') {
	    &read_network();
	} elsif ($type eq 'cloud') {
	    &read_cloud();
	} elsif ($type eq 'group') {
	    &read_group();
	} elsif ($type eq 'service') {
	    &read_service();
	} elsif ($type eq 'servicegroup') {
	    &read_servicegroup();
	}elsif ($type eq 'rules') {
	    &read_rules();
	} else {
	    die "unknown global definition $type:";
	}
    }
}

##############################################################################
# Helper functions
##############################################################################

# Type checking functions
# ToDo: find a more elgant solution
sub is_net($) {
    my($obj) = @_;
    return exists $obj->{hosts};
}
sub is_router($) {
    my($obj) = @_;
    return exists $obj->{managed};
}
sub is_interface($) {
    my($obj) = @_;
    return exists $obj->{router};
}
sub is_host($) {
    my($obj) = @_;
    return exists($obj->{net});
}
sub is_any($) {
    my($obj) = @_;
    return exists($obj->{link}) && not exists($obj->{ip});
}

# give a readable name of a network object
sub printable($) {
    my($obj) = @_;
    my $out;
    if(&is_net($obj)) {$out = 'network';}
    elsif(&is_router($obj)) {$out = 'router';}
    elsif(&is_interface($obj)) {$out = 'interface';}
    elsif(&is_host($obj)) {$out = 'host';}
    elsif(&is_any($obj)) {$out = 'any';}
    else { die "internal in printable: unknown object '$obj->{name}'";}
    return "$out:$obj->{name}";
}

##############################################################################
# Phase 2
# Build linked data structures
##############################################################################

# get a reference to an array of network object names and substitute
# the names by the referenced network objects
sub subst_names_with_refs($) {
    my($obref) = @_;
    for my $object (@$obref) {
	my($type, $name) = split(':', $object);
	if($type eq 'host') {
	    $object = $hosts{$name};
	} elsif($type eq 'network') {
	    $object = $networks{$name};
	} elsif($type eq 'router') {
	    $object = $routers{$name};
	} elsif($type eq 'interface') {
	    # split at last dot, since router name may contain dots
	    # first .* is greedy, thus we find last dot
	    my($router, $interface)  = ($name =~ /^(.*)\.(.*)$/);
	    $object = $routers{$router}->{interfaces}->{$interface};
	} elsif($type eq 'any') {
	    $object = $anys{$name};
	} elsif($type eq 'group') {
	    $object = $groups{$name};
	} else {
	    die "unknown object type '$type'";
	}
	die "undefined reference $type:$name" unless defined $object;
    }
}
	
sub link_interface_with_net($) {
    my($interface) = @_;

    my $net_name = $interface->{link};
    my $net = $networks{$net_name};
    unless($net) {
	my $rname = $interface->{router}->{name};
	my $iname = $interface->{name};
	die "undefined reference from interface:$rname.$iname to network:$net_name";
    }
    $interface->{link} = $net;

    my $is_cloud_intf = $interface->{ip} eq 'cloud';
    # check, if the network is already linked with 
    # an interface of the other type
    if(defined $net->{is_cloud_network} &&
       $net->{is_cloud_network} != $is_cloud_intf) {
	die "net:$net_name must not be linked to an interface since it is linked to a cloud";
    } 
    $net->{is_cloud_network} = $is_cloud_intf;

    if(! $is_cloud_intf) {
	# check compatibility of interface ip and network ip/mask
	my $interface_ip = $interface->{ip};
	my $ip = $net->{ip};
	my $mask = $net->{mask};
	if($ip != ($interface_ip & $mask)) {
	    my $rname = $interface->{router}->{name};
	    my $iname = $interface->{name};
	    die "interface:$rname.${iname}'s ip doesn't match net:${net_name}'s ip/mask";
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
sub gen_expanded_rules($$$$) {
    my($action, $src_aref, $dst_aref, $srv_aref) = @_;
    for my $src (@$src_aref) {
	# a group is represented as an array of its members
	if(ref($src) eq 'ARRAY') {
	    &gen_expanded_rules($action, $src, $dst_aref, $srv_aref);
	} else {
	    for my $dst (@$dst_aref) {
		if(ref($dst) eq 'ARRAY') {
		    &gen_expanded_rules($action, [ $src ], $dst, $srv_aref);
		} else {
		    for my $srv (@$srv_aref) {
			my $expanded_rule = { action => $action,
					      src => $src,
					      dst => $dst,
					      srv => $srv
					      };
			if($action eq 'deny') {
			    push(@expanded_deny_rules, $expanded_rule);
			} else {
			    push(@expanded_rules, $expanded_rule);
			}
		    }
		}
	    }
	}
    }
}

##############################################################################
# Phase 4
# Find paths
##############################################################################

# select a starting router ($router1) and
# find paths from every network and router to the starting object
sub setpath_router($$$$) {
    my($router, $to_pep, $pep, $distance) = @_;
    # ToDo: operate correctly with loops
    if($router->{pep}) {
	die "There is a loop at router:$router->{name}. Loops are not supported in this version";
    }
    $router->{pep} = $pep;
    $router->{to_pep} = $to_pep;
    $router->{distance} = $distance;
    for my $interface (@{$router->{interfaces}}) {
	# ignore interface where we reached this router
	next if $interface eq $to_pep;
	if($router->{managed}) {
	    &setpath_network($interface->{link},
			     $interface, $interface, $distance+1);
	} else {
	    &setpath_network($interface->{link},
			     $interface, $pep, $distance);
	}
    }
    if(my $any = $router->{any}) {
	$any->{pep} = $pep;
	if(my $old_any = $pep->{any}) {
	    die "More than one any object definied in a perimeter: any:$old_any->{name} and any:$any->{name}";
	}
	$pep->{any} = $any;
    }
}

sub setpath_network($$$$) {
    my ($network, $to_pep, $pep, $distance) = @_;
    # ToDo: operate correctly with loops
    if($network->{pep}) {
	die "There is a loop at net:$network->{name}. Loops are not supported in this version";
    }
    $network->{pep} = $pep;
    # add network to the corresponding pep; this info is used later
    # for optimization and generation of weak_deny rules for 'any' rules
    push(@{$pep->{networks}}, $network);
    for my $interface (@{$network->{interfaces}}) {
	# ignore interface where we reached this network
	next if $interface eq $to_pep;
	&setpath_router($interface->{router},
			$interface, $pep, $distance);
    }
}

##############################################################################
# Helper functions: 
# Applying a function on every managed router from src to dst of a rule
##############################################################################

sub get_pep($) {
    my($obj) = @_;

    if(&is_host($obj)) {
	return $obj->{net}->{pep};
    } elsif(&is_interface($obj)) {
	return $obj->{link}->{pep};
    } elsif(&is_net($obj) || &is_any($obj)) {
	return $obj->{pep};
    } else {
	$name = &printable($obj);
	die "internal in get_pep: unsupported object '$name'";
    }
}

# It applies a function on any managed router which lies on the path
# between src and dst of a supplied rule
sub path_walk($&) {
    my ($rule, $fun) = @_;
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $src_intf = &get_pep($src);
    my $dst_intf = &get_pep($dst);

    if($src_intf eq $dst_intf) {
	my $src_name = &printable($src);
	my $dst_name = &printable($dst);

	warn "unenforceble rule from '$src_name' to '$dst_name'";
	# don't process rule again later
	$rule->{deleted} = 1;
	return;
    }
    my $src_router = $src_intf->{router};
    my $dst_router = $dst_intf->{router};

    my $src_dist = $src_router->{distance};
    my $dst_dist = $dst_router->{distance};

    # go from src to dst until equal distance is reached
    while($src_dist > $dst_dist) {
	my $out_intf = $src_router->{to_pep};
	&$fun($rule, $src_intf, $out_intf);
	$src_intf = $src_router->{pep};
	$src_router = $src_intf->{router};
	$src_dist = $src_router->{distance};
    }

    # go from dst to src until equal distance is reached
    while($src_dist < $dst_dist) {
	my $in_intf = $dst_router->{to_pep};
	&$fun($rule, $in_intf, $dst_intf);
	$dst_intf = $dst_router->{pep};
	$dst_router = $dst_intf->{router};
	$dst_dist = $dst_router->{distance};
    }

    # now alternating go one step from src and one from dst
    # until the router in the middle is reached
    while($src_router != $dst_router) {
	my $out_intf = $src_router->{to_pep};
	&$fun($rule, $src_intf, $out_intf);
	$src_intf = $src_router->{pep};
	$src_router = $src_intf->{router};

	my $in_intf = $dst_router->{to_pep};
	&$fun($rule, $in_intf, $dst_intf);
	$dst_intf = $dst_router->{pep};
	$dst_router = $dst_intf->{router};
    }

    # if we reached the router via different interfaces, 
    # the router lies on the path
    if($src_intf != $dst_intf) {
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

#     N4-\
# any-R1-N1-R2-dst
#  N2-/  N3-/
# -->
# deny N1 dst (on R2)
# deny N4 dst (on R2)
# permit any dst (on R1 and R2)
sub gen_any_src_deny($$$) {
    my ($rule, $in_intf, $out_intf) = @_;
    my $router = $in_intf->{router};

    # we don't need the interface itself, but only information about all
    # networks and the any  object at that interface. We get this information
    # at the pep interface, not the to_pep interface
    if($in_intf eq $router->{to_pep}) {
	$in_intf = $router->{pep};
    }
    # nothing to do for the first router
    return if $in_intf->{any} eq $rule->{src};

    for $net (@{$in_intf->{networks}}) {
	my $deny_rule = {src => $net,
			 dst => $rule->{dst},
			 srv => $rule->{srv},
			 action => 'weak_deny'
		     };
	push(@{$rule->{deny_rules}}, $deny_rule);
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
sub gen_any_dst_deny($$$) {
    # in_intf points to src, out_intf to dst
    my ($rule, $in_intf, $out_intf) = @_;
    my $router = $in_intf->{router};

    # find networks at all interfaces except the in_intf
    for my $orig_intf (@{$router->{interfaces}}) {
	# copy $intf to prevent changing of the iterated array
	my $intf = $orig_intf;

	# nothing to do for in_intf:
	# case 1: it is the first router near src
	# case 2: the in_intf is on the same perimeter
	# as an out_intf of some other router on the path
	next if $intf == $in_intf;

	# see comment in &gen_any_src_deny
	if($intf eq $router->{to_pep}) {
	    $intf = $router->{pep};
	}
	# nothing to do for the interface which is connected
	# directly to the destination any object
	next if $intf->{any} eq $rule->{dst};

	for $net (@{$intf->{networks}}) {
	    my $deny_rule = {src => $rule->{src},
			     dst => $net,
			     srv => $rule->{srv},
			     action => 'weak_deny'
			 };
	    push(@{$rule->{deny_rules}}, $deny_rule);
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
sub addrule_pep_any($) {
    my ($pep) = @_;
    my $any = $pep->{any};
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
    for my $network (@{$pep->{networks}}) {
	&addrule_net($network);
    }
    if($any) {
	# clear rules at dst object before optimization of next any object
	for my $rule (@{$any->{rules}}) {
	    delete($rule->{dst}->{src_any});
	}
    }
}

sub addrule_net($) {
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

# this subroutine is applied to hosts and interfaces as well
sub addrule_host($) {
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

# Representation of srv in rules and srv_hash
# ip
# tcp any
# tcp port
# tcp port-port
# udp ...
# icmp any
# icmp type any
# icmp type code
# proto nr
#
# add rule to a group of rules with identical src and dst
# and identical or different srv. 
# If a fully identical rule is already present, it is marked
# as deleted and substituted by the new one.
sub add_rule($$) {
    my ($rule, $srv_hash) = @_;
    my ($type, $v1, $v2) = @{$rule->{srv}};
    my $action = $rule->{action};
    my $old_rule;

    if(defined $v2) {
	$old_rule = $srv_hash->{$action}->{$type}->{$v1}->{$v2};
	$srv_hash->{$action}->{$type}->{$v1}->{$v2} = $rule;
    } elsif (defined $v1) {
	$old_rule = $srv_hash->{$action}->{$type}->{$v1};
	$srv_hash->{$action}->{$type}->{$v1} = $rule;
    } else {
	$old_rule = $srv_hash->{$action}->{$type};
	$srv_hash->{$action}->{$type} = $rule;
    }
    $old_rule->{deleted} = 1 if $old_rule;
    return($srv_hash);
}

# tcp any
# tcp port
# tcp port-port
# udp ...
sub optimize_tcp_udp_rules($$) {
    my ($cmp_hash, $chg_hash) = @_;

    # 'tcp/udp any' supersedes every port or port range
    if(exists $cmp_hash->{any} &&
       (my $rule = $cmp_hash->{any})) {
	while(my($key, $rule2) = (each %$chg_hash)) {
	    next if $rule2 eq $rule;
	    $rule2->{deleted} = 1;
	}
    } else {
	# find port ranges
	while(my($key, $rule) = (each %$cmp_hash)) {
	    if(my($from, $to) = ($key =~ /^(.*)-(.*)$/)) {
		# compare this range with all other ports and ranges
		while(my($key2, $rule2) = (each %$chg_hash)) {
		    # this occurs if $cmp_hash and $chg_hash are identical
		    next if $rule2 eq $rule;
		    if(my($from2, $to2) = ($key2 =~ /^(.*)-(.*)$/)) {
			if($from >= $from2 && $to2 <= $to) {
			    $rule2->{deleted} = 1;
			}
		    } else {
			if($from >= $key2 && $key2 <= $to) {
			    $rule2->{deleted} = 1;
			}
		    }
		}
	    } else {
		# don't try to find identical ports on equal hashes
		unless($cmp_hash eq $chg_hash) {
		    # a single port supersedes only an identical port
		    if(exist $chg_hash->{$key} &&
		       (my $rule2 = $chg_hash->{$key})) {
			$rule2->{deleted} = 1;
		    }
		}
	    }
	}
    }
}

# icmp any
# icmp type any
# icmp type code
sub optimize_icmp_rules($$) {
    my ($cmp_hash, $chg_hash) = @_;

    # 'icmp any' supersedes every type or type,code
    if(exists $cmp_hash->{any} &&
       (my $rule = $cmp_hash->{any})) {
	while(my($type, $hash2) = (each %$chg_hash)) {
	    next if $hash2 eq $rule;
	    while(my($code, $rule2) = (each %$hash2)) {
		$rule2->{deleted} = 1;
	    }
	}
    } else {
	while(my($type, $hash2) = (each %$cmp_hash)) {    
	    # 'type,any' supersedes every `type,code` entry
	    if(exists $hash2->{any} &&
	       (my $rule = $hash2->{any})) {
		while(my($code, $rule2) = (each %{$chg_hash->{$type}})) {
		    next if $rule2 eq $rule;
		    $rule2->{deleted} = 1;
		}
	    } else {
		&optimize_identical_rules($hash2, $chg_hash->{$type});
	    }
	}
    }
}

sub optimize_identical_rules($$) {
    my ($cmp_hash, $chg_hash) = @_;

    # don't try to find identical keys on equal hashes
    return if($cmp_hash == $chg_hash);

    while(my($key, $rule) = (each %$cmp_hash)) {
	if(exists $chg_hash->{$key} &&
	   (my $rule2 = $chg_hash->{$key})) {
	    $rule2->{deleted} = 1;
	}
    }
}

sub delete_srv_rules($) {
    my ($hash) = @_;

    while(my($key, $rule) = (each %$hash)) {
	$rule->{deleted} = 1;
    }
}

sub delete_icmp_rules($) {
    my ($hash) = @_;

    while(my($type, $hash2) = (each %$hash)) {   
	while(my($code, $rule) = (each %$hash2)) {
	    $rule->{deleted} = 1;
	}
    }
}

sub optimize_srv_rules($$) {
    my($cmp_hash, $chg_hash) = @_;

    if(exists $cmp_hash->{ip} && $cmp_hash->{ip}) {
	for my $i ('tcp','udp','proto') {
	    if(exists $chg_hash->{$i} &&
	       (my $hash = $chg_hash->{$i})) {
		&delete_srv_rules($hash);
	    }
	}
	if(my $hash = $chg_hash->{icmp}) {
	    &delete_icmp_rules($hash);
	}
    } else {
	my($cmp_sub_hash, $chg_sub_hash);
	exists $cmp_hash->{tcp} && exists $chg_hash->{tcp} &&
	    ($cmp_sub_hash = $cmp_hash->{tcp}) &&
		($chg_sub_hash = $chg_hash->{tcp}) && 
		    &optimize_tcp_udp_rules($cmp_sub_hash, $chg_sub_hash);
	exists $cmp_hash->{udp} && exists $chg_hash->{udp} &&
	    ($cmp_sub_hash = $cmp_hash->{udp}) &&
		($chg_sub_hash = $chg_hash->{udp}) &&
		    &optimize_tcp_udp_rules($cmp_sub_hash, $chg_sub_hash);
	exists $cmp_hash->{icmp} && exists $chg_hash->{icmp} &&
	    ($cmp_sub_hash = $cmp_hash->{icmp}) &&
		($chg_sub_hash = $chg_hash->{icmp}) &&
		    &optimize_icmp_rules($cmp_sub_hash, $chg_sub_hash);
	exists $cmp_hash->{proto} && exists $chg_hash->{proto} &&
	    ($cmp_sub_hash = $cmp_hash->{proto}) &&
		($chg_sub_hash = $chg_hash->{proto}) &&
		    &optimize_identical_rules($cmp_sub_hash, $chg_sub_hash);
    } 
}

# deny > permit > weak_deny
sub optimize_action_rules($$) {
    my($cmp_hash, $chg_hash) = @_;
    my($cmp_sub_hash, $chg_sub_hash);

    if(exists $chg_hash->{deny} && ($chg_sub_hash = $chg_hash->{deny})) {
	exists $cmp_hash->{deny} && ($cmp_sub_hash = $cmp_hash->{deny}) &&
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
    }
    if(exists $chg_hash->{permit} && ($chg_sub_hash = $chg_hash->{permit})) {
	exists $cmp_hash->{permit} && ($cmp_sub_hash = $cmp_hash->{permit}) &&
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
	exists $cmp_hash->{deny} && ($cmp_sub_hash = $cmp_hash->{deny}) &&
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
    }
    if(exists $chg_hash->{weak_deny} &&
       ($chg_sub_hash = $chg_hash->{weak_deny})) {
	exists $cmp_hash->{weak_deny} &&
	    ($cmp_sub_hash = $cmp_hash->{weak_deny}) &&
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
	exists $cmp_hash->{permit} && ($cmp_sub_hash = $cmp_hash->{permit}) &&
	    &optimize_srv_rules($cmp_sub_hash, $chg_sub_hash);
	exists $cmp_hash->{deny} && ($cmp_sub_hash = $cmp_hash->{deny}) &&
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
sub optimize_rules($$) {
    my($dst, $src_tag) = @_;
    my @src_tags;

    if($src_tag eq 'src_host') {
	@src_tags = ('src_host', 'src_net', 'src_any');
    } elsif ($src_tag eq 'src_net') {
	@src_tags = ('src_net', 'src_any');
    } elsif ($src_tag eq 'src_any') {
	@src_tags = ('src_any');
    }
    if(&is_host($dst) || &is_interface($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{net}->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{net}->{pep}->{any}->{$i}, 
				$dst->{$src_tag});
	}
    } elsif(&is_net($dst)) {
	for my $i (@src_tags) {
	    &optimize_action_rules($dst->{$i}, $dst->{$src_tag});
	    &optimize_action_rules($dst->{pep}->{any}->{$i}, 
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

sub adr_code($) {
    my ($obj) = @_;
    if(&is_host($obj)) {
	my $ip_code = &print_ip($obj->{ip});
	return "host $ip_code";
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

sub srv_code($) {
    my ($srv) = @_;
    my $proto = $srv->[0];

    if($proto eq 'ip') {
	return('ip', '');
    } elsif($proto eq 'tcp' || $proto eq 'udp') {
	my $port = $srv->[1];
	if($port eq 'any') {
	    return($proto, '');
	} elsif(my($from, $to) = ($port =~ /^(.*)-(.*)$/)) {
	    return($proto, "range $from $to");
	} else {
	    return($proto, "eq $port");
	}
    } elsif($proto eq 'icmp') {
	my $type = $srv->[1];
	if($type eq 'any') {
	    return($proto, '');
	} else {
	    my $code = $srv->[2];
	    if($code eq 'any') {
		return($proto, $type);
	    } else {
		return($proto, "$type $code");
	    }
	}
    } elsif($proto eq 'proto') {
	my $nr = $srv->[1];
	return($nr, '');
    } else {
	die "internal in srv_code: a rule has unknown protocol '$proto'";
    }
}

sub gen_code($$$) {
    my ($rule, $src_intf, $dst_intf) = @_;
    my $action = $rule->{action};
    my $src = $rule->{src};
    my $dst = $rule->{dst};
    my $srv = $rule->{srv};
    my $router = $src_intf->{router};
    my $src_code = &adr_code($src);
    my $dst_code = &adr_code($dst);
    my ($proto_code, $port_code) = &srv_code($srv);

    $action = 'deny' if $action eq 'weak_deny';
    push(@{$src_intf->{code}},
	 "$action $proto_code $src_code $dst_code $port_code\n");
}    

# call gen_code only for the first pep on the path from src to dst
# r1-src-r2-r3-dst: get_pep(src) = r1, r1 is not on path
# r3-src-r2-r1-dst: get_pep(src) = r2, r2 is 1st pep on path
# ToDo: this code works only for 2nd case
sub gen_code_at_src($$$) {
    my ($rule, $src_intf, $dst_intf) = @_;
#    my $src = $rule->{src};
#    my $src_pep = &get_pep($src);
#    if($src_pep eq $src_intf) {
	&gen_code($rule, $src_intf, $dst_intf);
#    }
}


##############################################################################
# Main program
##############################################################################

&read_data();
    
# substitute group member names with links to network objects
for my $array_ref (values %groups) {
    &subst_names_with_refs($array_ref);
}

# substitute rule targets with links to network objects
# and service names with service definitions
for my $rule (@rules) {
    &subst_names_with_refs($rule->{src});
    &subst_names_with_refs($rule->{dst});
    for my $srv (@{$rule->{srv}}) {
	my $srv_def = $services{$srv} || die "undefined service '$srv'";
	$srv = $srv_def;
    }
}
	
# link interface with network in both directions
for my $router (values %routers, values %clouds) {
    # substitute hash with array, since names are not needed any more
    $router->{interfaces} = [ values(%{$router->{interfaces}}) ];
    for my $interface (@{$router->{interfaces}}) {
	&link_interface_with_net($interface);
    }
}

# expand rules
for my $rule (@rules) {
    &gen_expanded_rules($rule->{action},
			$rule->{src}, $rule->{dst}, $rule->{srv});
}

# take a random managed element from %routers, name it "router1"
for my $router (values %routers) {
    if($router->{managed}) {
	$router1 = $router;
	last;
    }
} 
 
# Beginning with router1, do a traversal of the whole network 
# to find a path from every network and router to router1
&setpath_router($router1, 'not undef', undef, 0);

# generate deny rules for any rules
for my $rule (@expanded_rules) {
    if(&is_any($rule->{src})) {
	&path_walk($rule, \&gen_any_src_deny);
    }
    if(&is_any($rule->{dst})) {
	&path_walk($rule, \&gen_any_dst_deny);
    }
}

# Prepare optimization of rules
# link rules with the source network object of the rule
for my $rule (@expanded_deny_rules, @expanded_rules) {
    if(exists $rule->{deny_rules}) {
	for my $deny_rule (@{$rule->{deny_rules}}) {
	    push(@{$deny_rule->{src}->{rules}}, $deny_rule);
	}
    }
    push(@{$rule->{src}->{rules}}, $rule);
}

# Optimze rules for each particular perimeter
for my $router (values %routers) {
    next unless $router->{managed};
    for my $interface (@{$router->{interfaces}}) {
	next if $interface eq $router->{to_pep};
	&addrule_pep_any($interface);
    }
} 

# Generate code for deny rules first.
# It suffices to distribute to the first pep on the path from src to dst
for my $rule (@expanded_deny_rules) {
    &path_walk($rule, \&gen_code_at_src);
}

# Distribute permit rules to peps
# src-R1-R2-\
#           |-Rx
#    dst-R3-/
# Generate code for weak deny rules directly before the corresponding 
# permit any rule
for my $rule (@expanded_deny_rules, @expanded_rules) {
    next if $rule->{deleted};
    if(exists $rule->{deny_rules}) {
	for my $deny_rule (@{$rule->{deny_rules}}) {
	    next if $deny_rule->{deleted};
	    &path_walk($deny_rule, \&gen_code_at_src);
	}
    }
    &path_walk($rule, \&gen_code);
}

# Print generated code for each managed router
for my $router (values %routers) {
    next unless $router->{managed};
    print "!! Access Lists for Router '$router->{name}':\n";
    for my $interface (@{$router->{interfaces}}) {
	print "ip access-list extended $interface->{name}_in\n";
	for my $line (@{$interface->{code}}) {
	    print $line;
	}
	print "deny any any\n";
	print "interface $interface->{name}\n";
	print "access group $interface->{name}_in $interface->{name}\n";
	print "\n";
    }
}
