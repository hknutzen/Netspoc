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
use constant CURRENT => 'current';
use constant NETSPOC => 'netspoc';

my $project = '/home/madnes';
my $compiler = 'netspoc.pl';
my $code = 'code.acl';

# policy database
my $policydb = "$project/" . NETSPOC;
# link to current policy
my $link = "$policydb/" . CURRENT;
my $home = $ENV{HOME};
# users working directory
my $working = "$home/" . NETSPOC;

my $pdir = readlink "$link" or die "Can't read $link\nAnother $0 running?\n";
# strip trailing slash
$pdir =~ s'/$'';
# link may be relative or absolute
$pdir = "$policydb/$pdir" unless $pdir =~ m'^/';
-d $pdir or die "$pdir isn't a directory\n";
my($policy) = ($pdir =~ m'([^/]+$)') or die "Error: can't extract basename from $pdir\n";
my($count) = ($policy =~ /^p(\d+)$/) or die "Error: invalid policy name: $policy";

# user must have checked in current policy
chdir $working or die "Error: can't change do $working: $!\n";
system("cvs -nQ tag -c test") == 0 or die "Aborted\n";

# Semaphore, lock policy database
unlink $link or die "Error: can't remove $link\nAnother $0 running?\n";

# increment policy counter
$count++;
$policy = "p$count";
print STDERR "Saving policy $count\n";

# tagging policy
system("cvs -Q tag -c $policy") == 0 or die "Aborted\n";

# check out new policy into policy database
chdir $policydb or die "Error: can't cd to $policydb: $!\n";
$pdir = "$policydb/$policy";
mkdir $policy or die "Error: can't create $pdir: $!\n";
chdir $policy or die "Error: can't cd to $pdir: $!\n";
system("cvs -Q checkout -d src -r $policy " . NETSPOC) == 0 or
    die "Error: can't checkout $policy to $pdir/src\n";

# compile new policy
chdir $pdir or die "Error: can't cd to $pdir: $!\n";
print STDERR "Compiling policy $count\n";
system("$compiler src > $code") == 0 or warn "$compiler failed: $?\n";
# make new policy read only
system("chmod -R a-w .") == 0 or warn "Can't make $pdir read only\n";

# Semaphore, unlock policy database
chdir $policydb or die "Error: can't cd to $policydb: $!\n";
symlink $policy, CURRENT or
    die "Error: failed to create symlink '" . CURRENT . "' to $policy in $policydb\n";

print STDERR "Updating policy $count complete\n";
