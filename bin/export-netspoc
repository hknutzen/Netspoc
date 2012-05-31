#!/usr/local/bin/perl

use strict;
use warnings;
use JSON;
use Netspoc;
use open qw(:std :utf8);

my $VERSION = 
    ( split ' ', '$Id$' )[2];

sub usage {
    die "Usage: $0 netspoc-data out-directory\n";
}

# Argument processing.
my $netspoc_data = shift @ARGV or usage();
my $out_dir = shift @ARGV or usage();

# Remove trailing slash.
$out_dir =~ s,/$,,;

# Copy version information from this file and
# take modification date for all newly created files.
my $policy_file = "$netspoc_data/POLICY";

sub abort {
    my ($msg) = @_;
    die "$msg\n";
}

sub internal_err {
    my ($msg) = @_;
    abort "internal: $msg";
}

sub create_dirs {
    my ($path) = @_;
    $path = "$out_dir/$path";
    my @parts = split('/', $path);
    my $name = shift @parts;
    check_output_dir($name);
    for my $part (@parts) {
	$name .= "/$part";
	check_output_dir($name);
    }
}

sub export {
    my ($path, $data) = @_;
    $path = "$out_dir/$path";
    open (my $fh, '>', $path) or die "Can't open $path\n";
    print $fh to_json($data, {pretty => 1, canonical => 1});
    close $fh or die "Can't close $path\n";
}

# Unique union of all elements.
sub unique(@) {
	return values %{ {map { $_ => $_ } @_}}; 
}

sub by_name { $a->{name} cmp $b->{name} }

# Take higher bits from network NAT, lower bits from original IP.
# This works with and without NAT.
sub nat {
    my ($ip, $network) = @_;
    $network->{ip} | $ip & Netspoc::complement_32bit ($network->{mask});
}

sub ip_nat_for_object {
    my ($obj) = @_;
    my $ip;
    my $nat;

# This code is a modified copy of Netspoc::address.
# - It needs to handle objects of type 'Host' instead of 'Subnet'.
# - Handles dynamic NAT for hosts.
# - It returns strings of textual ip/mask, not pairs of numbers.
    my $type = ref $obj;
    if ($type eq 'Network') {
	my $get_ip = sub {
	    my ($obj) = @_;
	    if ($obj->{hidden}) {
		'hidden';
	    }
	    elsif ($obj->{ip} eq 'unnumbered') {
		$obj->{ip}
	    }

	    # Don't print mask for loopback network. It needs to have
	    # exactly the same address as the corresponding loopback interface.
	    elsif ($obj->{loopback}) {
		print_ip($obj->{ip});
	    }

            # Print no mask for aggregate with mask 0, for compatibility
            # with old version.
            elsif ($obj->{is_aggregate} && $obj->{mask} == 0) {
		print_ip($obj->{ip});
	    }
	    else {
		join('/', print_ip($obj->{ip}), print_ip($obj->{mask}));
	    }
	};
	$ip = $get_ip->($obj);
	if (my $hash = $obj->{nat}) {
	    for my $tag (keys %$hash) {
		my $nat_obj = $hash->{$tag};
		$nat->{$tag} = $get_ip->($nat_obj);
	    }
	}
    }
    elsif ($type eq 'Host') {
	my $get_ip = sub {
	    my ($obj, $network) = @_;
	    if (my $nat_tag = $network->{dynamic}) {
		if ($obj->{nat} and (my $ip = $obj->{nat}->{$nat_tag})) {

		    # Single static NAT IP for this host.
		    print_ip($ip);
		}
		elsif ($network->{hidden}) {
		    'hidden';
		}
		else {

		    # Dynamic NAT, take whole network.
		    join('/', 
			 print_ip($network->{ip}), print_ip($network->{mask}));
		}
	    }
	    else {
		if ( my $range = $obj->{range} ) {
		    join('-', map { print_ip(nat($_, $network)) } @$range);
		}
		else {
		    print_ip(nat($obj->{ip}, $network));
		}
	    }
	};
        my $network = $obj->{network};
	$ip = $get_ip->($obj, $network);
	if (my $hash = $network->{nat}) {
	    for my $tag (keys %$hash) {
		my $nat_obj = $hash->{$tag};
		$nat->{$tag} = $get_ip->($obj, $nat_obj);
	    }
	}
    }
    elsif ($type eq 'Interface') {
	my $get_ip = sub {
	    my ($obj, $network) = @_;
	    if ($obj->{ip} =~ /unnumbered|short/) {
		$obj->{ip};
	    }
	    elsif ($obj->{ip} eq 'negotiated') {

		# Take whole network.
		join('/', 
		     print_ip($network->{ip}), print_ip($network->{mask}));
	    }
	    elsif (my $nat_tag = $network->{dynamic}) {
		if (my $ip = $obj->{nat}->{$nat_tag}) {

		    # Single static NAT IP for this interface.
		    print_ip($ip);
		}
		elsif ($network->{hidden}) {
		    'hidden';
		}
		else {
		    
		    # Dynamic NAT, take whole network.
		    join('/', 
			 print_ip($network->{ip}), print_ip($network->{mask}));
		}
	    }
	    elsif ($network->{isolated}) {

		# NAT not allowed for isolated ports. 
		# Take no bits from network, because secondary isolated ports 
		# don't match network.
		print_ip($obj->{ip});
	    }
	    else {
		print_ip(nat($obj->{ip}, $network));
	    }
	};
        my $network = $obj->{network};
	$ip = $get_ip->($obj, $network);
	if (my $hash = $network->{nat}) {
	    for my $tag (keys %$hash) {
		my $nat_obj = $hash->{$tag};
		$nat->{$tag} = $get_ip->($obj, $nat_obj);
	    }
	}
    }
    else {
        internal_err "Unexpected object $obj->{name}";
    }
    return $nat ? ( ip => $ip, nat => $nat ) : ( ip => $ip );
}

# Check if all arguments are 'eq'.
sub equal {
    return 1 if not @_;
    my $first = $_[0];
    return not grep { $_ ne $first } @_[ 1 .. $#_ ];
}

sub owner_for_object {	
    my ($object) = @_;
    if (my $owner_obj = $object->{owner}) {
	(my $name = $owner_obj->{name}) =~ s/^owner://;
	return $name;
    }
    return ();
}

sub sub_owners_for_object {	
    my ($object) = @_;
    if (my $aref = $object->{sub_owners}) {
	return map { (my $name = $_->{name}) =~ s/^owner://; $name } @$aref;
    }
    return ();
}

sub owners_for_objects {	
    my ($objects) = @_;
    my %owners;
    for my $object (@$objects) {
	if (my $name = owner_for_object($object)) {
	    $owners{$name} = $name;
	}
    }
    return [ sort values %owners ];
}

sub sub_owners_for_objects {	
    my ($objects) = @_;
    my %owners;
    for my $object (@$objects) {
	for my $name (sub_owners_for_object($object)) {
	    $owners{$name} = $name;
	}
    }
    return [ sort values %owners ];
}

sub expand_auto_intf {
    my ($src_aref, $dst_aref) = @_;
    for (my $i = 0; $i < @$src_aref; $i++) {
	my $src = $src_aref->[$i];
	next if not is_autointerface($src);
	my @new;
	my %seen;
	for my $dst (@$dst_aref) {
	    for my $interface (Netspoc::path_auto_interfaces($src, $dst)) {
		if (not $seen{$interface}++) {
		    push @new, $interface;
		}
	    }
	}

	# Substitute auto interface by real interfaces.
	splice(@$src_aref, $i, 1, @new)
    }
}

sub proto_descr {
    my ($protocols) = @_;
    my @result;
    for my $proto0 (@$protocols) {
	my $protocol = $proto0;
	my $desc = my $ptype = $protocol->{proto};
	if ($ptype eq 'tcp' or $ptype eq 'udp') {
	    my $port_code = sub ( $$ ) {
		my ($v1, $v2) = @_;
		if ($v1 == $v2) {
		    return $v1;
		}
		elsif ($v1 == 1 and $v2 == 65535) {
		    return '';
		}
		else {
		    return "$v1-$v2";
		}
	    };
	    my $sport  = $port_code->(@{ $protocol->{src_range}->{range} });
	    my $dport  = $port_code->(@{ $protocol->{dst_range}->{range} });
	    if ($sport) {
		$desc .= " $sport:$dport";
	    }
	    elsif ($dport) {
		$desc .= " $dport";
	    }
	}
	elsif ($ptype eq 'icmp') {
	    if (defined(my $type = $protocol->{type})) {
		if (defined(my $code = $protocol->{code})) {
		    $desc .= " $type/$code";
		}
		else {
		    $desc .= " $type";
		}
	    }
	}
	if (my $flags = $protocol->{flags}) {
	    for my $key (sort keys %$flags) {
		next if $key eq 'stateless_icmp';
		next if $key eq 'overlaps';
		next if $key eq 'no_check_supernet_rules';
		if ($key eq 'src' or $key eq 'dst') {
		    for my $part (sort keys %{$flags->{$key}}) {
			$desc .= ", ${key}_$part";
		    }
		}
		else {
		    $desc .= ", $key";
		}
	    }
	}
	push @result, $desc;
    }
    @result = sort @result;
    \@result;
}

sub find_visibility {
    my ($owners, $uowners) = @_;
    my $visibility;
    my %hash = map { $_ => 1} @$owners;
    my @extra_uowners = grep { not $hash{$_} } @$uowners;
    my @DA_extra = grep({ $_ =~ /^DA_/ } @extra_uowners);
    my @other_extra = grep({ $_ !~ /^DA_/ } @extra_uowners);
			   
    # No known owner or owner of users.
    if (not @$owners and not @$uowners) {
	# Default: private
    }
    # Set of uowners is subset of owners.
    elsif (not @extra_uowners) {
	# Default: private
    }
    # Restricted visibility
    elsif (@other_extra <= 2) {
	if (@DA_extra >= 3) {
	    $visibility = 'DA_*';
	}
    }
    else {
	$visibility = '*';
    }
    $visibility;
}

# All objects referenced in rules and in networks and hosts of owners.
my %all_objects;

sub setup_service_info {
    progress("Setup service info");
    for my $service (values %services) {
        next if $service->{disabled};
	my $pname = $service->{name};

	my $users = $service->{expanded_user} =
	    Netspoc::expand_group($service->{user}, "user of $pname");

	# Non 'user' objects.
	my @objects;

	# Check, if service contains a coupling rule with only "user" elements.
	my $is_coupling = 0;

	for my $rule (@{ $service->{rules} }) {
	    my $has_user = $rule->{has_user};
	    $rule->{expanded_prt} =
		proto_descr(Netspoc::expand_protocols($rule->{prt}, 
						     "rule in $pname"));
	    if ($has_user eq 'both') {
		$is_coupling = 1;
		next;
	    }
	    for my $what (qw(src dst)) {

		next if $what eq $has_user;
		my $all = 

		    # Store expanded src and dst for later use 
		    # in export_protocols.
		    $rule->{"expanded_$what"} = 
		    [ sort by_name
		    @{ Netspoc::expand_group($rule->{$what}, 
					     "$what of $pname") } ];

		# Expand auto interface to set of real interfaces.
		# This changes {expanded_src} and {expanded_dst} as well.
		expand_auto_intf($all, $users);
		push(@objects, @$all);
	    }
	}

	@objects = unique(@objects);

	# Expand auto interface to set of real interfaces.
	# This changes {expanded_user} as well.
	expand_auto_intf($users, \@objects);

	# Store referenced objects for later use during export.
	@all_objects{@objects, @$users} = (@objects, @$users);

	# Take elements of 'user' object, if service has coupling rule.
	if ($is_coupling) {
	    @objects = unique(@objects, @$users);
	}

	# Input: owner objects, output: owner names
	my $owners = owners_for_objects(\@objects);

	# Add artificial owner :unknown if owner is unknown.
	push @$owners, ':unknown' if not @$owners;
	$service->{owners} = $owners;
	$service->{sub_owners} = sub_owners_for_objects(\@objects);
	my $uowners = $service->{uowners} = $is_coupling ? [] : owners_for_objects($users);
	$service->{sub_uowners} = $is_coupling ? [] : sub_owners_for_objects($users);

	# Für Übergangszeit aus aktueller Benutzung bestimmen.
	$service->{visible} ||= find_visibility($owners, $uowners);
	$service->{visible} and $service->{visible} =~ s/\*$/.*/;
    }
}

######################################################################
# Fill attribute sub_owners at objects which contain objects
# belonging to other owners.
######################################################################

# We can't use %aggregates from Netspoc.pm because it only holds named
# aggregates.  But we need unnamed aggregates like any:[network:XX]
# as well.
my @all_zones;

sub setup_sub_owners {
    progress("Setup sub owners");
    my %all_zones;
    for my $host (values %hosts) {
	$host->{disabled} and next;
	my $host_owner = $host->{owner} or next;
	my $network = $host->{network};
	my $net_owner = $network->{owner};
	if ( not ($net_owner and $host_owner eq $net_owner)) {
	    $network->{sub_owners}->{$host_owner} = $host_owner;
#	    Netspoc::debug "$network->{name} : $host_owner->{name}";
	}
    }
    for my $network (values %networks) {
	$network->{disabled} and next;
	my @owners;
	if (my $hash = $network->{sub_owners}) {
	    @owners = values %$hash;

	    # Substitute hash by array. 
	    # Use a copy because @owners is changed below.
	    $network->{sub_owners} = [ @owners ];
	}
	if (my $net_owner = $network->{owner}) {
	    push @owners, $net_owner;
	}
	my $zone = $network->{zone};
	$all_zones{$zone} = $zone;
	my $zone_owner = $zone->{owner};
	for my $owner (@owners) {
	    if ( not ($zone_owner and $owner eq $zone_owner)) {
		$zone->{sub_owners}->{$owner} = $owner;
#		Netspoc::debug "$zone->{name} : $owner->{name}";
	    }
	}
    }

    # Substitute hash by array.
    @all_zones = values %all_zones;
    for my $zone (@all_zones) {
	if (my $hash = $zone->{sub_owners}) {
	    $zone->{sub_owners} = [ values %$hash ];
	}
    }
}

my $master_owner;

sub find_master_owner {
    for my $owner (values %owners) {
        if ($owner->{show_all}) {
            (my $name = $owner->{name}) =~ s/^owner://;
            $master_owner = $name;
            progress("Found master owner: $name");
            last;
        }
    }
}

######################################################################
# Export no-NAT-set
# - relate each network to its owner and sub_owners
# - build a no_nat_set for each owner, where own networks are'nt translated
######################################################################

sub export_no_nat_set {
    progress("Export no-NAT-sets");
    my %owner2net;
    for my $network (values %networks) {
	$network->{disabled} and next;
	for my $owner_name 
	    (owner_for_object($network), sub_owners_for_object($network))
	{
	    $owner2net{$owner_name}->{$network} = $network;
	}
    }
    my %owner2no_nat_set;
    my %all_nat_tags;
    $owner2net{$_} ||= {} for keys %owners;
    for my $owner_name (sort keys %owner2net) {
	my %nat_domains;
	for my $network (values %{ $owner2net{$owner_name} }) {
	    my $nat_domain = $network->{nat_domain};
	    $nat_domains{$nat_domain} = $nat_domain;
	}
	my @nat_domains = values %nat_domains;
	if (not @nat_domains) {

	    # Special value 'undef' marks owner without any networks.
	    # This will be changed to all_nat_tags below.
	    $owner2no_nat_set{$owner_name} = undef;
	    next;
	}
#	if ((my $count = @nat_domains) > 1) {
#	    print "$owner_name has $count nat_domains\n";
#	    for my $network (values %{ $owner2net{$owner_name} }) {
#		my $d = $network->{nat_domain};
#		print " - $d->{name}: $network->{name}\n";
#	    }
#	}

	# Build union of no_nat_sets
	my $no_nat_set = [ sort(unique(map(keys(%{ $_->{no_nat_set} }), 
					   @nat_domains))) ];
#	Netspoc::debug "$owner_name: ", join(',', sort @$no_nat_set);
	$owner2no_nat_set{$owner_name} = $no_nat_set;
	@all_nat_tags{@$no_nat_set} = @$no_nat_set;
    }
    my @all_nat_tags = sort values %all_nat_tags;
    for my $owner_name (keys %owner2no_nat_set) {
	my $no_nat_set = $owner2no_nat_set{$owner_name} || \@all_nat_tags;
	create_dirs("owner/$owner_name");
	export("owner/$owner_name/no_nat_set", $no_nat_set);
    }
}

####################################################################
# Export hosts, networks and zones (represented by aggregate 0/0) for
# each owner and sub_owner.
####################################################################

# {networks} only contains toplevel networks.
# Add subnets recursively.
sub add_subnetworks {
    my ($networks) = @_;
    my @sub_networks;
    for my $network (@$networks) {
        if (my $sub = $network->{networks}) {
            push @sub_networks, @{ add_subnetworks($sub) };
        }
    }
    return @sub_networks ? [ @$networks, @sub_networks ] : $networks;
}

sub export_assets {
    progress("Export assets");
    my %result;

    my $export_networks = sub {
	my ($networks, $owner, $own_zone) = @_;
	my %sub_result;
	for my $net (@$networks) {
	    next if $net->{disabled};
	    next if $net->{loopback};
	    next if $net->{ip} eq 'tunnel';
	    $all_objects{$net} = $net;
	    my $net_name = $net->{name};
	    my $net_owner = owner_for_object($net) || '';

	    # Export hosts and interfaces.
	    my @childs = (@{ $net->{hosts} }, @{ $net->{interfaces} });

	    # Show only own childs in foreign network.
	    my $own_network = $net_owner eq $owner;
	    if (not $own_network and not $own_zone) {
		@childs = 
		    grep { my $o = owner_for_object($_); $o and $o eq $owner } 
		         @childs;
	    }

	    @all_objects{@childs} = @childs;
	    @childs = sort map $_->{name}, @childs;
	    $sub_result{$net_name} = \@childs;
	}
	return \%sub_result;
    };

    for my $zone (@all_zones) {
	next if $zone->{disabled};
	next if $zone->{loopback};

        # Ignore empty zone with only tunnel or unnumbered networks.
        next if not @{ $zone->{networks} };

        # All aggregates can be used in rules.
        for my $aggregate (values %{ $zone->{ipmask2aggregate} }) {
            $all_objects{$aggregate} = $aggregate;
        }

        # Zone with network 0/0 doesn't have an aggregate 0/0.
        my $any = $zone->{ipmask2aggregate}->{'0/0'};
	my $zone_name = $any ? $any->{name} : $zone->{name};
	my $zone_owner = owner_for_object($zone) || '';
        my $networks = add_subnetworks($zone->{networks});
	for my $owner (owner_for_object($zone), sub_owners_for_object($zone)) {

	    # Show only own or sub_own networks in foreign zone.
	    my $own_zone = $zone_owner eq $owner;
            my $own_networks;
	    if (not $own_zone) {
		$own_networks = 
		    [ grep 
		      grep({ $owner eq $_ } 
			   owner_for_object($_), sub_owners_for_object($_)), 
		      @$networks ];
	    }
            else {
                $own_networks = $networks;
            }

            $result{$owner}->{anys}->{$zone_name}->{networks} = 
		$export_networks->($own_networks, $owner, $own_zone);
	}
        if ($master_owner) {
             $result{$master_owner}->{anys}->{$zone_name}->{networks} = 
	         $export_networks->($networks, $master_owner, 1);
        }
    }

    $result{$_} ||= {} for keys %owners;
    for my $owner (keys %result) {
	my $hash = $result{$owner};
	create_dirs("owner/$owner");
	export("owner/$owner/assets", $hash);
    }
}

####################################################################
# Services, rules, users
####################################################################

sub export_services {
    progress("Export services");
    my %phash;
    my %owner2type2phash;
    for my $service (sort by_name values %services) {
        next if $service->{disabled};
        if ($master_owner) {
            $owner2type2phash{$master_owner}->{owner}->{$service} = $service;
	}
        for my $owner (@{ $service->{owners} }, @{ $service->{sub_owners} }) {
            $owner2type2phash{$owner}->{owner}->{$service} = $service;
        }          
        for my $owner (@{ $service->{uowners} }, @{ $service->{sub_uowners} }) {
            if (not $owner2type2phash{$owner}->{owner}->{$service}) {
                $owner2type2phash{$owner}->{user}->{$service} = $service;
            }
        }
        for my $owner (keys %owners) {
            if (not ($owner2type2phash{$owner}->{owner}->{$service} or 
                     $owner2type2phash{$owner}->{user}->{$service})) 
            {
                if ($service->{visible} and $owner =~ /^$service->{visible}/) {
                    $owner2type2phash{$owner}->{visible}->{$service} = $service;
                }
            }
        }
	my $details = {
	    description => $service->{description},
	    owner => $service->{owners},
	};
	if (@{ $service->{sub_owners} }) {
	    $details->{sub_owners} = $service->{sub_owners};
	}
	my @rules = map {
	    { 
		action => $_->{action},
		has_user => $_->{has_user},
		src => [ map $_->{name}, @{ $_->{expanded_src} } ],
		dst => [ map $_->{name}, @{ $_->{expanded_dst} } ],
		srv => $_->{expanded_prt},
	    }
	} @{ $service->{rules} };
	(my $pname = $service->{name}) =~ s/^\w+://;
	$phash{$pname} = { details => $details, rules => \@rules };
    }
    export("services", \%phash);

    progress("Export users and service_lists");
    $owner2type2phash{$_} ||= {} for keys %owners;
    for my $owner (sort keys %owner2type2phash) {
	my $type2phash = $owner2type2phash{$owner} || {};
	my %type2pnames;
	my %service2users;
	for my $type (qw(owner user visible)) {
	    my $services = [ sort by_name values %{ $type2phash->{$type} } ];
	    my $pnames = $type2pnames{$type} = [];
	    for my $service (@$services) { 
		(my $pname = $service->{name}) =~ s/^\w+://;
		push @$pnames, $pname;
		next if $type eq 'visible';
		my @users;
		if ($type eq 'owner') {
		    @users = @{ $service->{expanded_user} };
		}
		elsif ($type eq 'user') {
		    @users = 
			grep { 
			    my $uowner = owner_for_object($_);
			    if ($uowner && $uowner eq $owner) {
				1;
			    }
			    elsif (my $sub_owners = $_->{sub_owners}) {
				grep { $_->{name} eq "owner:$owner" } 
				@$sub_owners;
			    }
			    else {
				0;
			    }
			}
		    @{ $service->{expanded_user} };
		}
		@users = sort map $_->{name}, @users;
		$service2users{$pname} = \@users;
	    }
	}
	create_dirs("owner/$owner");
	export("owner/$owner/service_lists", \%type2pnames);
	export("owner/$owner/users", \%service2users);
    }
}

####################################################################
# Export all objects referenced by rules, users and assets.
####################################################################

sub export_objects {
    progress("Export objects");
    my %objects = map { 
	$_->{name} => { 


	    # Add key 'ip' and optionally key 'nat'.
	    ip_nat_for_object($_),
	    owner => scalar owner_for_object($_),
	} 
    } values %all_objects;
    export("objects", \%objects);
}

####################################################################
# find Email -> Admin -> Owner
####################################################################

sub export_owners {
    progress("Export owners");
    my %email2owners;
    for my $name ( keys %owners ) {
	my $owner = $owners{$name};
	my @emails;
	my @watchers;
	my @e_owners;
	create_dirs("owner/$name");
	for my $admin ( @{ $owner->{admins} } ) {
	    my $email = $admin->{email};
	    $email2owners{$email}->{$name} = $name;
	    push @emails, $email;
	}
	if (my $watchers = $owner->{watchers}) {
	    for my $admin ( @$watchers ) {
		my $email = $admin->{email};

		# Watchers are allowed to login, but aren't shown as owner.
		$email2owners{$email}->{$name} = $name;
		push @watchers, $email;
	    }
	}
	if (my $aref = $owner->{extended_by}) {
	    for my $e_owner (@$aref) {
		for my $admin ( @{ $e_owner->{admins} } ) {
		    my $email = $admin->{email};
		    $email2owners{$email}->{$name} = $name;
		}
		(my $e_name = $e_owner->{name}) =~ s/^owner://;
		push @e_owners, $e_name;
	    }
	}
	export("owner/$name/emails", 
	       [ map { { email => $_ } } sort @emails ]);
	export("owner/$name/watchers", 
	       [ map { { email => $_ } } sort @watchers ]);
	export("owner/$name/extended_by", 
	       [ map { { name => $_ } } sort @e_owners ]);
    }
    
    # Substitute hash by array.
    $_ = [ sort values(%$_) ] for values %email2owners;

    export("email", \%email2owners);
}

sub copy_policy_file {
    if ( -f $policy_file) {
        system("find $out_dir -type f -exec touch -r $policy_file {} \\;");
	system("cp -pf $policy_file $out_dir") == 0 or
	    abort "Can't copy $policy_file";
    }
}

####################################################################
# Initialize Netspoc data
####################################################################
set_config({time_stamps => 1, max_errors => 9999});

# Set global config variable of Netspoc to store attribute 'description'.
store_description(1);
read_file_or_dir($netspoc_data);
order_protocols();
link_topology();
mark_disabled();
distribute_nat_info();
set_zone();
setpath();
find_subnets();
setup_sub_owners();
set_service_owner();
setup_service_info();
find_master_owner();

####################################################################
# Export data
####################################################################
create_dirs('');
export_owners();
export_assets();
export_services();
export_objects();
export_no_nat_set();
copy_policy_file();
progress("Ready");
