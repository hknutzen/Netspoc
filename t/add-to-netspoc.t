#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

sub test_run {
    my ($title, $input, $args, $expected) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    my $cmd = "perl -I lib bin/add-to-netspoc -q - $args < $filename";
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

my ($title, $in, $out);

############################################################
$title = 'Add to network';
############################################################

$in = <<'END';
network:Test =  { ip = 10.9.1.0/24; }
group:G = interface:r.Test, # comment
    host:id:h@dom.top.Test,
    network:Test,
host:x, network:Test, host:y,
    ;
END

$out = <<'END';
network:Test =  { ip = 10.9.1.0/24; }
group:G = interface:r.Test, # comment
    host:id:h@dom.top.Test,
    network:Test,
    host:Toast,
host:x, network:Test, host:Toast, host:y,
    ;
END

test_run($title, $in, 'network:Test host:Toast', $out);

############################################################
$title = 'Add in service, but not in area and pathrestriction';
############################################################

$in = <<'END';
service:x = {
 user = interface:r.x, host:b;
 permit src = any:x; dst = user; prt = tcp;
 permit src = user; dst = any:x; 
        prt = tcp;
}
pathrestriction:p =
 interface:r.x,
 interface:r.y
;
area:a = {
 border = interface:r.x;
}
END

$out = <<'END';
service:x = {
 user = interface:r.x, host:y, host:b;
 permit src = any:x, group:y; dst = user; prt = tcp;
 permit src = user; dst = any:x, group:y; 
        prt = tcp;
}
pathrestriction:p =
 interface:r.x,
 interface:r.y
;
area:a = {
 border = interface:r.x;
}
END

test_run($title, $in, 'interface:r.x host:y any:x group:y', $out);

############################################################
$title = 'Indentation';
############################################################

$in = <<'END';
group:x = 
 host:a,
  host:b, host:c,
  host:d
  ,
  host:e ###
  , host:f,
  host:g;
END

$out = <<'END';
group:x = 
 host:a,
 host:a1,
  host:b, host:b1, host:c,
  host:d,
  host:d1
  ,
  host:e,
  host:e1 ###
  , host:f, host:f1,
  host:g,
  host:g1;
END

test_run($title, $in, 
         'host:a host:a1 host:b host:b1 host:d host:d1'.
         ' host:e host:e1 host:f host:f1 host:g host:g1', 
         $out);

############################################################
$title = 'Find and add umlauts';
############################################################

$in = <<'END';
group:x = host:Müß, host:Mass;
END

$out = <<'END';
group:x = host:Müß, host:Muess, host:Mass, host:Maß;
END

test_run($title, $in, 'host:Müß host:Muess host:Mass host:Maß', $out);

############################################################
$title = 'Read pairs from file';
############################################################

my $add_to = <<'END';
host:abc network:abx
network:xyz host:id:xyz@dom
any:aaa group:bbb
interface:r.n.sec interface:r.n
END
my ($in_fh, $filename) = tempfile(UNLINK => 1);
print $in_fh $add_to;
close $in_fh;

$in = <<'END';;
group:g = 
interface:r.n, interface:r.n.sec,
any:aaa, network:xyz,
host:abc;
END

$out = <<'END';;
group:g = 
interface:r.n, interface:r.n.sec, interface:r.n,
any:aaa, group:bbb, network:xyz, host:id:xyz@dom,
host:abc,
network:abx;
END

test_run($title, $in, "-f $filename", $out);

############################################################
done_testing;
