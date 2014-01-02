#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempfile tempdir /;

sub test_run {
    my ($title, $input, $expected) = @_;
    my $dir = tempdir( CLEANUP => 1 );
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    my $cmd = "perl bin/export-netspoc -quiet $filename $dir";
    my ($stdout, $stderr);
    run3($cmd, \undef, \$stdout, \$stderr);
    my $status = $?;
    if ($status != 0) {
        print STDERR "Failed:\n$stderr\n";
        return '';
    }
    if ($stderr) {
        print STDERR "Unexpected output on STDERR:\n$stderr\n";
        return '';
    }

    # Blocks of expected output are split by single lines of dashes.
    my @out = split(/^-+\n/m, $expected);
    
    # Undef input record separator to read all output at once.
    $/ = undef;

    for my $out (@out) {
        
        # Strip filename from first line of each block .
        my ($fname, $out) = split(/\n/, $out, 2);

        open(my $out_fh, '<', "$dir/$fname") or die "Can't open $fname";
        my $output = <$out_fh>;
        close($out_fh);
        eq_or_diff($output, $out, "$title: $fname");
    }
    return;
}

my ($in, $out, $title);

my $topo = <<'END';
owner:x = { admins = x@b.c; }
owner:y = { admins = y@b.c; }
owner:z = { admins = z@b.c; }

area:all = { owner = x; anchor = network:Big; }
any:Big  = { owner = y; link = network:Big; }
any:Sub1 = { ip = 10.1.0.0/23; link = network:Big; }
any:Sub2 = { ip = 10.1.1.0/25; link = network:Big; }

network:Sub = { ip = 10.1.1.0/24; owner = z; subnet_of = network:Big; }
router:u = { 
 interface:Sub;
 interface:Big; 
}
network:Big = { 
 ip = 10.1.0.0/16;
 host:B10 = { ip = 10.1.0.10; owner = z; }
}

router:asa = {
 managed;
 model = ASA;
 routing = manual;
 interface:Big = { ip = 10.1.0.1; hardware = outside; }
 interface:Kunde = { ip = 10.2.2.1; hardware = inside; }
}

network:Kunde = { ip = 10.2.2.0/24; }
END

############################################################
$title = 'Owner of area, subnet';
############################################################

$in = <<END;
$topo
service:test = {
 user = network:Sub;
 permit src = user; dst = network:Kunde; prt = tcp 80; 
}
END

$out = <<END;
owner/x/assets
{
   "anys" : {
      "any:[network:Kunde]" : {
         "networks" : {
            "network:Kunde" : [
               "interface:asa.Kunde"
            ]
         }
      }
   }
}
--
owner/y/assets
{
   "anys" : {
      "any:Big" : {
         "networks" : {
            "network:Big" : [
               "host:B10",
               "interface:asa.Big",
               "interface:u.Big"
            ],
            "network:Sub" : [
               "interface:u.Sub"
            ]
         }
      }
   }
}
--
owner/z/assets
{
   "anys" : {
      "any:Big" : {
         "networks" : {
            "network:Big" : [
               "host:B10"
            ],
            "network:Sub" : [
               "interface:u.Sub"
            ]
         }
      }
   }
}
--
owner/x/service_lists
{
   "owner" : [
      "test"
   ],
   "user" : [],
   "visible" : []
}
--
owner/y/service_lists
{
   "owner" : [],
   "user" : [],
   "visible" : []
}
--
owner/z/service_lists
{
   "owner" : [],
   "user" : [
      "test"
   ],
   "visible" : []
}
END

test_run($title, $in, $out);

############################################################
$title = 'Owner of larger matching aggregate';
############################################################

$in = <<END;
$topo
service:test = {
 user = any:Sub1;
 permit src = user; dst = network:Kunde; prt = tcp 80; 
}
END

$out = <<END;
owner/y/service_lists
{
   "owner" : [],
   "user" : [
      "test"
   ],
   "visible" : []
}
END

test_run($title, $in, $out);

############################################################
$title = 'Owner of smaller matching aggregate';
############################################################

$in = <<END;
$topo
service:test = {
 user = any:Sub2;
 permit src = user; dst = network:Kunde; prt = tcp 80; 
}
END

$out = <<END;
owner/z/service_lists
{
   "owner" : [],
   "user" : [
      "test"
   ],
   "visible" : []
}
END

test_run($title, $in, $out);

############################################################
$title = 'Network and host having different owner';
############################################################

$in = <<END;
$topo
service:test = {
 user = host:B10;
 permit src = user; dst = network:Kunde; prt = tcp 80; 
}
service:test2 = {
 user = network:Big;
 permit src = user; dst = network:Kunde; prt = tcp 88; 
}
END

$out = <<END;
owner/y/service_lists
{
   "owner" : [],
   "user" : [
      "test2"
   ],
   "visible" : []
}
--
owner/z/service_lists
{
   "owner" : [],
   "user" : [
      "test",
      "test2"
   ],
   "visible" : []
}
END

test_run($title, $in, $out);

############################################################
done_testing;
