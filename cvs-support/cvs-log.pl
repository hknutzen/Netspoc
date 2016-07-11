#!/usr/bin/perl
# File: cvs-log.pl
# Author: Heinz Knutzen
# Address: heinz.knutzen@dataport.de
# Description:
# This script is called from $CVSROOT/CVSROOT/loginfo
# Usage:
# cvs-log.pl <user> <cvsroot> <module>
# Log message is read from STDIN
# Parsed output is written to STDOUT
#
# $Id$

use strict;
use warnings;
use Fcntl qw/:flock/; # import LOCK_* constants

my $user = shift;
my $cvsroot = shift;
my $module = shift;
$cvsroot =~ s,/$,,;
my $prefix = "$cvsroot/$module";

# Read loginfo from STDIN.
# Example:
#
# Update of /usr/local/cvsroot/netspoc/rule
# In directory netspoc:/home/arne/netspoc/rule
#
# Modified Files:
#        Management_10
# Added Files:
# Removed Files:
# Log Message:
# blah

my $dir;
my %files;
my @log;
my $stat = 0;
while(<>) {
    /^Update of (.*)$/ and ($dir = $1, next);
    /^Modified Files:$/ and ($stat = 'mod', next);
    /^Added Files:$/ and ($stat = 'add',next);
    /^Removed Files:$/ and ($stat = 'del', next);
    /^Log Message:$/ and ($stat = 'log', next);
    $stat eq 'log' and (push(@log, $_), next); 
    /^\t(.*?)\s*$/ and (push(@{$files{$stat}}, $1), next);
}

$dir =~ s,^$prefix/?,,;
$dir .= '/' if $dir;
my (undef,$min,$hour,$mday,$mon,$year,undef,undef) = localtime;
$year += 1900;
$mon += 1;

my $out = sprintf "%d-%02d-%02d %02d:%02d  %s\n", $year,$mon,$mday,$hour,$min,$user;

for my $file (@{$files{add}}) { $out .= "\t* $dir$file: added\n"; }
for my $file (@{$files{del}}) { $out .= "\t* $dir$file: deleted\n"; }
for my $file (@{$files{mod}}) { $out .= "\t* $dir$file:\n"; }
for my $log (@log) { $out .= "\t$log"; }
$out .= "\n" unless $out =~ /\n$/;

print $out;


