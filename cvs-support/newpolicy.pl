#!/usr/bin/perl
# File: update
# Author: Heinz Knutzen
# Address: heinz.knutzen@web.de, heinz.knutzen@dzsh.de
# Description:
# Integrates netspoc with version control / build management
# Should be called from a user in a CVS controled directory with
# netspoc configuration files.
# - identifies the current policy 
# - checks if all changes are commited, aborts if not
# - calculates the next policy tag
# - tags users current configuration with new policy tag
# - extracts the tagged configuration into the policy database
# - compiles the new policy
# - marks the new directory as current policy

use strict;
use warnings;
use Fcntl qw/:flock/; # import LOCK_* constants
use constant CURRENT => 'current';
use constant NETSPOC => 'netspoc';

my $id = '$Id$ ';
my $project = '/home/madnes';
my $compiler = 'netspoc.pl';

# policy database
my $policydb = "$project/" . NETSPOC;
# link to current policy
my $link = "$policydb/" . CURRENT;
my $lock = "$policydb/LOCK";
my $home = $ENV{HOME};
# users working directory
my $working = "$home/" . NETSPOC;

$ENV{CVSROOT} or die "Abort:  No CVSROOT specified!\n";

my $pdir = readlink "$link" or
    die "Can't read link " . CURRENT . "in $policydb. Check and repair manually.\n";
# strip trailing slash
$pdir =~ s'/$'';
# link may be relative or absolute
$pdir = "$policydb/$pdir" unless $pdir =~ m'^/';
-d $pdir or die "$pdir isn't a directory\n";
my($policy) = ($pdir =~ m'([^/]+$)') or die "Error: can't extract basename from $pdir\n";
my($count) = ($policy =~ /^p(\d+)$/) or die "Error: invalid policy name: $policy";

# user must have checked in current policy
chdir $working or die "Error: can't change to $working: $!\n";
system("cvs -nQ tag -c test") == 0 or die "Aborted\n";

# Lock policy database
open LOCK, "$lock" or die "Error: couldn't open $lock: $!";
flock(LOCK, LOCK_EX | LOCK_NB) or die "Abort: Another $0 is running\n";

# increment policy counter
$count++;
$policy = "p$count";
$pdir = "$policydb/$policy";
if(-d $pdir) {
    warn "Skipping unfinished policy $policy\n";
    $count++;
    $policy = "p$count";
    $pdir = "$policydb/$policy";
}
print STDERR "Saving policy $count\n";

# tagging policy
system("cvs -Q tag -c $policy") == 0 or die "Aborted\n";

# check out new policy into policy database
chdir $policydb or die "Error: can't cd to $policydb: $!\n";
mkdir $pdir or die "Error: can't create $pdir: $!\n";
chdir $policy or die "Error: can't cd to $pdir: $!\n";
system("cvs -Q checkout -d src -r $policy " . NETSPOC) == 0 or
    die "Error: can't checkout $policy to $pdir/src\n";

# compile new policy
chdir $pdir or die "Error: can't cd to $pdir: $!\n";
print STDERR "Compiling policy $count\n";
system("$compiler src code ") == 0 or warn "$compiler failed: $?\n";
# make new policy read only
system("chmod -R a-w *") == 0 or warn "Can't make $pdir/* read only\n";
system("chmod a+w .") == 0 or warn "Can't make $pdir world writable\n";

chdir $policydb or die "Error: can't cd to $policydb: $!\n";
unlink $link or die "Error: can't remove $link: $!\n";
symlink $policy, CURRENT or
    die "Error: failed to create symlink '" . CURRENT . "' to $policy in $policydb\n";

print STDERR "Updating policy $count complete\n";

# Unlock policy database: implicitly by exit
