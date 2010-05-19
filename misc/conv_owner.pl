#!/usr/bin/perl
# Read from stdin or from files given as arguments.
# Print to stdout.

use strict;
use warnings;

my %owners;
my %admins;
my %admin2name;

# Read whole input at once.
undef $/;
my $data = <>;

# Finde Toplevel area, network, any Deklarationen ggf. mit Kommentar davor.
# Bestimme Position vor dem Kommentar als Einfügepunkt 
# für die neue Owner-Deklaration.
# Oder finde owner.

# Gefundenen Owner durch Verweis auf Deklaration ersetzen.
# Ganz neuer Owner:
# Deklaration vor letzter Topelevel-Deklaration einfügen.

# Einfügepunkt vor Toplevel-Deklaration
my $top_insert;

while ($data =~ 
       m/\G
       (?:.*\n)+? # alles davor, mindestens ein Zeilenende
	
       (?: # Klammer um Alternative: deklaration oder owner
	# Toplevel-Deklaration ggf. mit Kommentar-Zeilen davor
	(
	 (?:\#.*\n)* # Kommentar-Zeilen
	 \s*(?:area|any|network):\S+ # Toplevel-Deklaration
	 )
	
	|
	
	# Owner-Zeile
	(?:
	 [^\n#]* # In der gleichen Zeile vor owner, Kommentare ignorieren
	 owner\s*=\s*
	 ([^;]+) # der alte owner Inhalt
	 )
	)
       /mxgc) { 

    # Found toplevel declaration, remember insert position.
    if ($1) {
	$top_insert = pos($data) - length($1);
#	print STDERR "Found decl: '$1', top_insert = $top_insert\n";
    }

    # Convert owner. Insert owner declaration if needed.
    elsif ($2) {

	# Remember current \G position before changing $data.
	my $pos = pos($data);

#	print STDERR "Found owner: '$2'\n";
	my $owner = lc $2;
	my @old_owners = split /\s*,\s*/, $owner;
	@old_owners or die "Missing owners\n";

	# Replace special chars with an underscore.
	# Associate original admin-email with replaced
	# string in hash admin2name.
	my @new_owners = map {

	    # Leerzeichen am Anfang und Ende streichen.
	    s/^\s*//;
	    s/\s*$//;
	    (my $replace = $_) =~ s/[^\w-]+/_/g;
	    $admin2name{$replace} = $_;
	    $replace;
	} sort @old_owners;

	# Take name from first admin.
	# Add suffix "_g<n>" if group of admin with <n> members.
	my $count = @new_owners;
	my $new_owner = $new_owners[0];
	$new_owner .= "_g$count" if $count > 1;
	my $owner_admins = join ', ', @new_owners;
	my $add_decl;
	if ( my $admins = $owners{$new_owner} ) {
	    if ( $owner_admins ne $admins ) {

		# Create new unique name for owner.
		my $nr = 0;
		while ( $owners{$new_owner . '_' . ++$nr} ) {};
		$new_owner = $new_owner . '_' . $nr;
		$owners{$new_owner} = $owner_admins;
		$add_decl = 1;
	    }
	}
	else {
	    $owners{$new_owner} = $owner_admins;
	    $add_decl = 1;
	}
	
	# Change Owner
	my $insert = $pos - length($owner);
	substr($data, $insert, length($owner)) = $new_owner;
	$pos = $pos - length($owner) + length($new_owner);
#	print STDERR "New owner: $new_owner\n";

	if ($add_decl) {

	    $top_insert
		or die "Didn't found insert position for owner declaration\n";

	    # Insert declarations:
	    # - owner
	    my $decl = "\n"
		. "owner:$new_owner = {\n" 
		. " admins = $owners{$new_owner};\n"
		. "}\n\n";

	    # - admins.
	    my @admins = split /, /, $owners{$new_owner};
	    for my $admin_name ( @admins ) {

		# Only create admin once.
		next if $admins{$admin_name}; 
		$admins{$admin_name} = 1;


		# Construct name from email prefix.
		# Uppercase first letter of words.
		my $admin = $admin2name{$admin_name}; # original admin-email
		$admin =~ /^(.+)\@/ or die "Error: Invalid admin: '$admin'\n";
		my $name = $1;
		$name = 
		    join(' ',
			 map { join('-', map { ucfirst($_) } split(/-/, $_)) }
			 split(/\./, $name));
		
		$decl .= "admin:$admin_name = {\n"
		    . " name  = $name;\n"
		    . " email = $admin;\n"
		    . "}\n";
	    }
	    substr($data, $top_insert, 0) = $decl;
	    $top_insert += length($decl);
	    $pos += length($decl);
	}

	# Update \G position.
	pos($data) = $pos;
    }
    else {
	die "No match\n";
    }
}

print $data;
