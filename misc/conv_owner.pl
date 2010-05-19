
use strict;
use warnings;

my $in  = $ARGV[0];
$in   ||= './topology';
my $out = $ARGV[1];
$out  ||= $in . '.new';
#die "File $out exists!" if -e $out;
my $oc  = 0; # owner-counter
my %owners;
my %admins;
my %admin2name;

open( IN,  "<$in" ) or die "Open failed: $!";
open( OUT, ">$out" ) or die "Open failed: $!";

while ( <IN> ) {

    # Transfer comments to new file untouched.
    if ( /^\s*\#/ ) {
	print OUT;
	next;
    }

    # Match owner declarations.
    if ( my ( $pre, $declare, $owner, $post ) =
	 /(.*)(owner\s*=\s*)([^;]+)\s*;(.*)$/ ) {
	my @old_owners = split /\s*,\s*/, $owner;

	# Replace special chars @.-: with an underscore.
	# Associate original admin-email with replaced
	# string in hash admin2name.
	my @new_owners = map {
	    my $replace = $_;
	    ( $replace = $replace ) =~ s/[\@\.\-\:]+/_/g; # subst special chars
	    ( $replace = $replace ) =~ s/\s*//g; # remove whitespace
	    $admin2name{"admin:$replace"} = $_;
	    $replace;
	} sort @old_owners;

	my $new_owner = 'owner:' . $new_owners[0];
	my $owner_admins = join ',', map { "admin:$_" } @new_owners;
	if ( my $admins = $owners{$new_owner} ) {
	    if ( $owner_admins ne $admins ) {

		# Create new unique name for owner.

		#print "FOUND $new_owner with same name but " .
		#    "different admins:\n";
		#print "\tOLD: $admins \n\tNEW: $owner_admins\n";

		my $nr = 0;
		while ( $owners{$new_owner . '_' . ++$nr} ) {};
		$new_owner = $new_owner . '_' . $nr;
		#print "Set owner to $new_owner = $owner_admins\n";
		$owners{$new_owner} = $owner_admins;
	    }
	}
	else {
	    $owners{$new_owner} = $owner_admins;
	}
	
	print OUT "$pre"  if $pre;
	print OUT "$declare$new_owner;\n";
	print OUT "$post\n" if $post =~ /\S+/;
    }
    else {
	print OUT;
    }
}

print OUT "##### automatically generated owners ###################\n\n";

for my $new_owner ( keys %owners ) {
    print OUT "$new_owner = {\n";
    print OUT " admins = " . $owners{$new_owner} . ";\n";
    print OUT "}\n\n";
}

print OUT "##### automatically generated admins ###################\n\n";

for my $owner ( keys %owners ) {

    my @admins = split /\s*,\s*/, $owners{$owner};

    for my $admin_name ( @admins ) {

	# only create admin once
	next if $admins{$admin_name}; 
	$admins{$admin_name} = 1;

	print OUT "$admin_name = {\n";

	# Construct name from email-prefix.
	my $name  = '';
	my $match = '';
	my $admin = $admin2name{$admin_name}; # original admin-email
	if ( $admin =~ /^([\w\-\.]+)\@/ ) {
	    if ( ( $match = $1 ) =~ /^([\w\-]+)\.([\w\-]+)/ ) {
		my $first_name = uppercase_name( $1 );
		my $last_name  = uppercase_name( $2 );
		$name = $first_name . ' ' . $last_name;
	    }
	    else {
		$name = ucfirst( $match );
	    }
	}
	else {
	    die "Invalid admin:\"$admin\"\n";
	}

	print OUT " name  = $name;\n";
	print OUT " email = $admin;\n";
	print OUT "}\n\n";
    }
}
 
close( IN  ) or die "Close failed: $!";
close( OUT ) or die "Close failed: $!";


# Uppercase first letter of normal names like "holger" and double
# names with a dash like "hans-ulrich".
# Returns "Holger" for the first and "Hans-Ulrich" for the latter.
sub uppercase_name {
    my $input = shift;
    if ( $input =~ /^([^-]*)-([^-]*)$/ ) {
	return ucfirst($1) . '-' . ucfirst($2);
    }
    else {
	return ucfirst( $input );
    }
}
