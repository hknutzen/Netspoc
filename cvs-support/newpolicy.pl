#!/usr/bin/perl
# newpolicy -- integrates NetSPoC with CVS
# http://netspoc.berlios.de
# (c) 2007 by Heinz Knutzen <heinzknutzen@users.berlios.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Description:
# Integrates NetSPoC with version control / build management.
# The current user must have a working directory 'netspoc'
# in his home directory with NetSPoC files checked out
# from the CVS repository.
# - identifies the current policy from policy db
# - calculates the next policy tag
# - extracts newest configuration from repository into policy database
# - checks if working directory of current user
#   - is identical to extracted configuration,
#   - then we know, it is updated and all changes are commited, 
#   - aborts if not
# - compiles the new policy
# - tags extracted configuration with new policy tag
# - marks new policy in policy db as current
#
# $Id$

use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);

# Get real UID of calling user (not the effective UID from setuid wrapper).
my $real_uid = $<;

# Get users pw entry.
my @pwentry = getpwuid($real_uid) or 
    die "Can't get pwentry of UID $real_uid: $!";

# Get users home directory.
my $home = $pwentry[7] or die "Can't get home directory for UID $real_uid";

# Users netspoc directory.
my $working = "$home/netspoc";

# Path of policy database.
my $policydb = '/home/diamonds/netspoc';

# Name of netspoc compiler, PATH from sanitized environment (see below).
my $compiler = 'netspoc';

# Name of cvs module in repository.
my $module = 'netspoc';

# Link to current policy.
my $link = "$policydb/current";

# The lock file for preventing concurrent updates.
my $lock = "$policydb/LOCK";

# Set secure path.
$ENV{PATH} = "/usr/local/bin:/usr/bin:/bin";

# Lock policy database.
sysopen LOCK, "$lock", O_RDONLY | O_CREAT or
    die "Error: can't open $lock: $!";
if (not flock(LOCK, LOCK_EX | LOCK_NB)) {

    # Read user and time from lockfile.
    open(my $fh, '<', $lock) or die "Can't open $lock for reading: $!";
    my $status = <$fh>;
    close $fh;
    die "Abort: Another $0 is running. $status\n";
}

# Write user and time to lockfile for better error message.
my $user =  $pwentry[0] or die "Can't get user name for UID $real_uid";
open(my $fh, '>', $lock) or die "Can't open $lock for writing: $!";
my $status = "Started by $user at " . localtime() . "\n";
print $fh $status;
close $fh;
    
# Read current policy name from POLICY file from repository.
my $fcount;
if(open POLICY, "cvs -Q checkout -p $module/POLICY|") {
    my $line = <POLICY>;
    close POLICY;
    # $pfile contains one line: "# p22 comment .."
    ($fcount) = ($line =~ m'^#? *p(\d+) ') or
	die "Error: found no valid policy name in $module/POLICY\n";
}
else {
    $fcount = 0;
}
  
# Read current policy name from symbolic link.
my $lcount;
if(my $name = readlink $link) {

    # Link must have name "p<number>".
    ($lcount) = ($name =~ /^p(\d+)$/) or
	die "Error: found invalid policy name '$name' in $link";
}
else {
    $lcount = 0;
}

# Compare $fcount and $lcount.
# Typically both values are identical.
# Take maximum if values are different. 
my $count = $fcount > $lcount ? $fcount : $lcount;
    
# Increment counter.
$count++;

# Get next policy name.
my $policy = "p$count";

# Directory and file names of new policy in policy database.
my $pdir  = "$policydb/$policy";
my $psrc  = "$pdir/src";
my $pcode = "$pdir/code";
my $plog  = "$pdir/compile.log";

# Cleanup leftovers from previous unsuccessful build of this policy.
system('rm', '-rf', $pdir);

# Create directory for new policy.
print STDERR "Saving policy $count\n";
mkdir $pdir or die "Error: can't create $pdir: $!\n";

# In server mode, cvs commands need relative pathnames.
# Hence change into parent directory.
chdir($pdir) or die "Error: during 'cd $pdir': $!\n";

# Check out newest files from repository
# into subdirectory "src" of policy directory.
system('cvs', '-Q', 'checkout', '-d', 'src', $module) == 0 or
    die "Error: can't checkout $policy to $psrc\n";

# Sanity check that working copy of calling user 
# is identical to just checked out copy.
system('diff', '-qr', '-x', 'CVS', '-x', '*~', $working, $psrc) == 0 or
    die "Error: $working isn't up to date\n";

# Compile new policy.
print STDERR "Compiling policy $count; log files in $plog \n";
open COMPILE, "$compiler $psrc $pcode 2>&1 |" or
    die "Can't execute $compiler: $!\n";
open LOG, '>', "$plog" or die "Can't open $plog: $!\n";
while(<COMPILE>) {
    print LOG; 
    print STDERR;
}
close LOG;
close COMPILE;

# Compiled successfully.
if ($? == 0) {

    # Update POLICY file of current version.
    # Use relative pathname.
    my $pfile = "src/POLICY";
    system('cvs', 'edit', $pfile) == 0 or die "Aborted\n";
    open  PFILE, ">", $pfile or die "Can't open $pfile: $!\n";
    print PFILE "# $policy # Current policy, don't edit manually!\n";
    close PFILE;
    system('cvs', 'commit', '-m', $policy , $pfile) == 0 or die "Aborted\n";

    # Add tags to files of current version.
    system('cvs', '-Q', 'tag', $policy, 'src') == 0 or die "Aborted\n";

    # Mark new policy as current.
    chdir $policydb or die "Error: can't cd to $policydb: $!\n";
    unlink $link;
    symlink $policy, $link or
	die "Error: failed to create symlink $link to $policy\n";
    print STDERR "Updated current policy to '$policy'\n";

    # Success.
    exit 0;
}

# Failed to compile.
else {
    print STDERR "New policy failed to compile\n";
    my $current = readlink $link;
    $current and print STDERR "Left current policy as '$current'\n";

    # Failure.
    exit 1;
}

# Unlock policy database: implicitly by exit.
