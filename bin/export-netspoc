#!/usr/local/bin/perl

use strict;
use warnings;
use JSON;
use Netspoc;

sub usage {
    die "Usage: $0 netspoc-data out-directory\n";
}

# Configuration data.
my $netspoc_data = shift @ARGV or usage();
my $out_dir = shift @ARGV or usage();

# Remove trailing slash.
$out_dir =~ s,/$,,;

my $VERSION = ( split ' ', '$Id$' )[2];

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
    print $fh to_json($data, {utf8 => 1, pretty => 1, canonical => 1});
    close $fh or die "Can't close $path\n";
}
    
sub is_numeric { 
    my ($value) = @_;
    $value =~ /^\d+$/; 
}

# Store no_nat_set for each owner.
# This is the union of all no_nat_sets of that nat_domains
# where networks of an owner are located.
my %owner2no_nat_set;

# Take higher bits from network NAT, lower bits from original IP.
# This works with and without NAT.
sub nat {
    my ($ip, $network) = @_;
    $network->{ip} | $ip & Netspoc::complement_32bit ($network->{mask});
}

sub ip_for_object {
    my ($obj, $no_nat_set) = @_;

# This code is a modified copy of Netspoc::address.
# - It needs to handle objects of type 'Host' instead of 'Subnet'.
# - Handles dynamic NAT for hosts.
# - It returns strings of textual ip/mask, not pairs of numbers.
    my $type = ref $obj;
    if ($type eq 'Network') {
        $obj = Netspoc::get_nat_network($obj, $no_nat_set);
        if ($obj->{hidden}) {
            internal_err "Unexpected hidden $obj->{name}\n";
        }
        elsif ($obj->{ip} eq 'unnumbered') {
            internal_err "Unexpected unnumbered $obj->{name}\n";
        }
        else {
	    join('/', print_ip($obj->{ip}), print_ip($obj->{mask}));
        }
    }
    elsif ($type eq 'Host') {
        my $network = $obj->{network};
        $network = Netspoc::get_nat_network($network, $no_nat_set);
        if (my $nat_tag = $network->{dynamic}) {
            if (my $ip = $obj->{nat}->{$nat_tag}) {

                # Single static NAT IP for this host.
		print_ip($ip);
            }
            else {

                # Dynamic NAT, take whole network.
		join(' ', 
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
    }
    elsif ($type eq 'Interface') {
        if ($obj->{ip} =~ /unnumbered|short/) {
            internal_err "Unexpected $obj->{ip} $obj->{name}\n";
        }

        my $network = $obj->{network};
        $network = Netspoc::get_nat_network($network, $no_nat_set);

        if ($obj->{ip} eq 'negotiated') {

	    # Take whole network.
	    join(' ', print_ip($network->{ip}), print_ip($network->{mask}));
        }
	elsif ($network->{isolated}) {

	    # NAT not allowed for isolated ports. Take no bits from network, 
	    # because secondary isolated ports don't match network.
	    print_ip($obj->{ip});
	}
        else {
	    print_ip(nat($obj->{ip}, $network));
	}
    }
    elsif ( Netspoc::is_any( $obj ) ) {
	print_ip( 0 );
    }
    else {
        internal_err "Unexpected object $obj->{name}";
    }
}

sub ip_for_objects {
    my ($objects, $no_nat_set) = @_;
    [ map { ip_for_object($_, $no_nat_set) } @$objects ];
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
    return [ values %owners ];
}

sub sub_owners_for_objects {	
    my ($objects) = @_;
    my %owners;
    for my $object (@$objects) {
	for my $name (sub_owners_for_object($object)) {
	    $owners{$name} = $name;
	}
    }
    return [ values %owners ];
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
	$protocol = $protocol->{main} if $protocol->{main};
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

my $policy_info;

sub setup_policy_info {
    progress("Setup policy info");
    for my $policy (values %policies) {
	my $pname = $policy->{name};

	my $users = $policy->{expanded_user} =
	    Netspoc::expand_group($policy->{user}, "user of $pname");

	# Non 'user' objects.
	my @objects;

	# Check, if policy contains a coupling rule with only "user" elements.
	my $is_coupling = 0;

	for my $rule (@{ $policy->{rules} }) {
	    my $has_user = $rule->{has_user};
	    if ($has_user eq 'both') {
		$is_coupling = 1;
		next;
	    }
	    for my $what (qw(src dst)) {

		next if $what eq $has_user;
		my $all = 

		    # Store expanded src and dst for later use in get_rules
		    $rule->{"expanded_$what"} =
		    Netspoc::expand_group($rule->{$what}, "$what of $pname");
		push(@objects, @$all);

		# Expand auto interface to set of real interfaces.
		# This changes {expanded_src} and {expanded_dst} as well.
		expand_auto_intf($all, $users);
	    }
	    $rule->{expanded_srv} =
		proto_descr(Netspoc::expand_services($rule->{srv}, 
						     "rule in $pname"));
	}

	# Expand auto interface to set of real interfaces.
	# This changes {expanded_user} as well.
	expand_auto_intf($users, \@objects);

	# Take elements of 'user' object, if policy has coupling rule.
	if ($is_coupling) {
	    push @objects, @$users;
	}

	# Remove duplicate objects;
	my %objects = map { $_ => $_ } @objects;
	@objects = values %objects;


	# Input: owner objects, output: owner names
	my $owners = $policy->{owners} = owners_for_objects(\@objects);
	$policy->{sub_owners} = sub_owners_for_objects(\@objects);
	my $uowners = $policy->{uowners} = $is_coupling ? [] : owners_for_objects($users);
	$policy->{sub_uowners} = $is_coupling ? [] : sub_owners_for_objects($users);

	# Für Übergangszeit aus aktueller Benutzung bestimmen.
	$policy->{visible} ||= find_visibility($owners, $uowners);
	$policy->{visible} and $policy->{visible} =~ s/\*$/.*/;
    }
}

######################################################################
# Fill attribute sub_owners at objects which contain objects
# belonging to other owners.
######################################################################

sub setup_sub_owners {
    progress("Setup sub owners");
    for my $host (values %hosts) {
	$host->{disabled} and next;
	my $host_owner = $host->{owner} or next;
	my $network = $host->{network};
	my $net_owner = $network->{owner};
	if ( not ($net_owner and $host_owner eq $net_owner)) {
	    $network->{sub_owners}->{$host_owner} = $host_owner;
	}
    }
    for my $network (values %networks) {
	$network->{disabled} and next;
	my @owners;
	if (my $hash = $network->{sub_owners}) {
	    @owners = values %$hash;

	    # Substitute hash by array. Use a copy because @owner is changed below.
	    $network->{sub_owners} = [ @owners ];
	}
	if (my $net_owner = $network->{owner}) {
	    push @owners, $net_owner;
	}
	my $any = $network->{any};
	my $any_owner = $any->{owner};
	for my $owner (@owners) {
	    if ( not ($any_owner and $owner eq $any_owner)) {
		$any->{sub_owners}->{$owner} = $owner;
	    }
	}
    }

    # Substitute hash by array.
    for my $any (values %anys) {
	if (my $hash = $any->{sub_owner}) {
	    $any->{sub_owners} = [ values %$hash ];
	}
    }
}

######################################################################
# Setup NAT
# - relate each network to its owner and sub_owners
# - build a no_nat_set for each owner, where own networks are'nt translated
######################################################################

sub setup_owner2nat {
    progress("Setup NAT for owner");
    my %owner2net;
    for my $network (values %networks) {
	$network->{disabled} and next;
	for my $owner_name 
	    (owner_for_object($network), sub_owners_for_object($network))
	{
	    $owner2net{$owner_name}->{$network} = $network;
	}
    }
    for my $owner_name (sort keys %owner2net) {
	my %nat_domains;
	for my $network (values %{ $owner2net{$owner_name} }) {
	    my $nat_domain = $network->{nat_domain};
	    $nat_domains{$nat_domain} = $nat_domain;
	}
	my @nat_domains = values %nat_domains;	
#	if ((my $count = @nat_domains) > 1) {
#	    print "$owner_name has $count nat_domains\n";
#	    for my $network (values %{ $owner2net{$owner_name} }) {
#		my $d = $network->{nat_domain};
#		print " - $d->{name}: $network->{name}\n";
#	    }
#	}

	# Build union of no_nat_sets
	$owner2no_nat_set{$owner_name} = 
	{ map(%{ $_->{no_nat_set} }, @nat_domains) };
#	Netspoc::debug 
#	    "$owner_name: ", 
#	    join(',', sort keys %{$owner2no_nat_set{$owner_name}});
    }
}

####################################################################
# Export hosts, networks and 'any' objects for each owner and
# sub_owner.
####################################################################

sub by_name { $a->{name} cmp $b->{name} }

sub export_anys {
    my %owner2obj;
    for my $obj (values %anys) {
	next if $obj->{disabled};
	for my $owner (owner_for_object($obj), sub_owners_for_object($obj)) {
	    push @{ $owner2obj{$owner} }, $obj;
	}
    }
    for my $owner (keys %owner2obj) {
	my $aref = $owner2obj{$owner};
	my @data = 
	    sort by_name 
	    map { { name => $_->{name},
		    owner => owner_for_object($_), } } 
	@$aref;
	export("owner/$owner/anys", \@data);
    }
}

sub export_networks {
    my %owner2obj;
    for my $obj (values %networks) {
	next if $obj->{disabled};
	for my $owner (owner_for_object($obj), sub_owners_for_object($obj)) {
	    push @{ $owner2obj{$owner} }, $obj;
	}
    }
    for my $owner (keys %owner2obj) {
	my $no_nat_set = $owner2no_nat_set{$owner};
	my $aref = $owner2obj{$owner};

	# Export networks.
	my @data = 
	    sort by_name 
	    map { { name => $_->{name},
		    ip => ip_for_object($_, $no_nat_set),
		    owner => scalar owner_for_object($_), } }
	grep { not $_->{loopback} }
	@$aref;
	export("owner/$owner/networks", \@data);

	# Export hosts.
	create_dirs("owner/$owner/hosts");
	for my $network (@$aref) {
	    (my $net_name = $network->{name}) =~ s/^network://;
	    my $net_owner = owner_for_object($network);
	    my $hosts;

	    # Show all hosts in own network.
	    if ($net_owner and $net_owner eq $owner) {
		$hosts = $network->{hosts};
	    }

	    # Show only own hosts in other network.
	    else {
		$hosts = [ grep { my $host_owner = owner_for_object($_);
				   $host_owner and $host_owner eq $owner } 
			    @{ $network->{hosts} } ];
	    }

	    # Only write data, if any host is available.
	    if (@$hosts) {
		my @data = sort by_name
		    map { { name => $_->{name},
			    ip =>  ip_for_object($_, $no_nat_set),
			    owner => owner_for_object($_), } } 
		@$hosts;
		export("owner/$owner/hosts/$net_name", \@data);
	    }
	}
    }
}

####################################################################
# Services, rules, users
####################################################################

sub export_services {
    my (%owner, %user, %visible);
    for my $policy (values %policies) {
	for my $owner (@{ $policy->{owners} }, @{ $policy->{sub_owners} }) {
	    $owner{$owner}->{$policy} = $policy;
	}
	for my $owner (@{ $policy->{uowners} }, @{ $policy->{sub_uowners} }) {
	    $owner{$owner}->{$policy} or 
		$user{$owner}->{$policy} = $policy;
	}
	for my $owner (keys %owners) {
	    $owner{$owner}->{$policy} or $user{$owner}->{$policy} or
		$policy->{visible} and $owner =~ /^$policy->{visible}/ and 
		$visible{$owner}->{$policy} = $policy;
	}
    }
    my %service_info = ( owner => \%owner,
			 user  => \%user,
			 visible => \%visible 
			 );
    for my $type (sort keys %service_info) {
	progress("- $type");
	my $href = $service_info{$type};
	for my $owner (sort keys %$href) {
#	    progress("$owner");
	    create_dirs("owner/$owner/services");
	    create_dirs("owner/$owner/service_list");
	    my @details;
	    for my $policy ( sort by_name values %{ $href->{$owner} }) { 
		(my $pname = $policy->{name}) =~ s/policy://;
		push @details, {
		    name => $pname,
		    description => $policy->{description},
		    owner => join(',', @{ $policy->{owners} }),
		}; 
		my $no_nat_set = $owner2no_nat_set{$owner};
		my @rules = 
		    map {
			{ 
			    action => $_->{action},
			    has_user => $_->{has_user},
			    src => ip_for_objects($_->{expanded_src}, 
						  $no_nat_set),
			    dst => ip_for_objects($_->{expanded_dst}, 
						  $no_nat_set),
			    srv => $_->{expanded_srv},
			}
		    } @{ $policy->{rules} };
		my @users;
		if ($type eq 'owner') {
		    @users = @{ $policy->{expanded_user} };
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
		    @{ $policy->{expanded_user} };
		}
		else {
		    @users = ();
		}
		@users = sort by_name
		    map { { name  => $_->{name},
			    ip    => ip_for_object($_, $no_nat_set),
			    owner => scalar owner_for_object($_),
			} } @users;
		my $path = "owner/$owner/services/$pname";
		create_dirs($path);
		export("$path/rules", \@rules);
		export("$path/users", \@users);
	    }
	    export("owner/$owner/service_list/$type", \@details);
	}
    }
}

####################################################################
# find Email -> Admin -> Owner
####################################################################

sub export_owners {
    my %email2owners;
    for my $name ( keys %owners ) {
	my $owner = $owners{$name};
	my @emails;
	my @e_owners;
	create_dirs("owner/$name");
	for my $admin ( @{ $owner->{admins} } ) {

	    # Normalize email to lower case.
	    my $email = lc $admin->{email};
	    $email2owners{$email}->{$name} = $name;
	    push @emails, $email;
	}
	if (my $aref = $owner->{extended_by}) {
	    for my $e_owner (@$aref) {
		for my $admin ( @{ $e_owner->{admins} } ) {

		    # Normalize email to lower case.
		    my $email = lc $admin->{email};
		    $email2owners{$email}->{$name} = $name;
		}
		(my $e_name = $e_owner->{name}) =~ s/^owner://;
		push @e_owners, $e_name;
	    }
	}
	export("owner/$name/emails", 
	       [ map { { email => $_ } } sort @emails ]);
	export("owner/$name/extended_by", 
	       [ map { { name => $_ } } sort @e_owners ]);
    }
    for my $email (keys %email2owners) {
	my $href = $email2owners{$email};
	create_dirs("email/$email");
	export("email/$email/owners", 
	       [ map { { name => $_ } } sort values %$href ]);
    }
}

####################################################################
# Initialize Netspoc data
####################################################################
sub init_data {

    # Set global config variable of Netspoc to store attribute 'description'.
    store_description(1);
    read_file_or_dir($netspoc_data);
    order_services();
    link_topology();
    mark_disabled();
    setup_sub_owners();
    distribute_nat_info();
    find_subnets();
    setany();
    setpath();
    set_policy_owner();
    setup_owner2nat();
    setup_policy_info();
}


####################################################################
# Export data
####################################################################

set_config({time_stamps => 1});
init_data();
progress("Owners");
export_owners();
progress("Anys");
export_anys();
progress("Networks");
export_networks();
progress("Services");
export_services();
progress("Ready");
