#!/usr/bin/perl

use strict;
use warnings;

use lib '.';
use Test_IPv6;


@ARGV == 2 or die "Usage: $0 inputfile outputdir\n";
my $inputfile = $ARGV[0];
my $outdir = $ARGV[1];
adjust_testfile($inputfile, $outdir);
