#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

sub test_run {
    my ($what, $title, $input, $args, $expected) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';

    my $cmd = "$^X $perl_opt -I lib $what -q - $args < $filename";
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    local $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

sub test_add {
    my ($title, $input, $args, $expected) = @_;
    $title = "Add: $title";
    test_run('bin/add-to-netspoc', $title, $input, $args, $expected);
    return;
}

sub test_rmv {
    my ($title, $input, $args, $expected) = @_;
    $title = "Remove: $title";
    test_run('bin/remove-from-netspoc',  $title, $input, $args, $expected);
    return;
}

my ($title, $in, $out);

############################################################
$title = 'host at network';
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

test_add($title, $in, 'network:Test host:Toast', $out);
test_rmv($title, $out, 'host:Toast', $in);

############################################################
$title = 'host after automatic group';
############################################################

$in = <<'END';
group:abc =
 any:[ ip = 10.1.0.0/16 & network:def ],
 host:xyz,
;
END

$out = <<'END';
group:abc =
 any:[ ip = 10.1.0.0/16 & network:def ],
 host:xyz,
 host:h,
;
END

test_add($title, $in, 'host:xyz host:h', $out);
test_rmv($title, $out, 'host:h', $in);

############################################################
$title = 'network after intersection';
############################################################

$in = <<'END';
group:abc =
 group:g &! host:xyz,
 network:def,
;
END

$out = <<'END';
group:abc =
 group:g &! host:xyz,
 network:def,
 network:n,
;
END

test_add($title, $in, 'network:def network:n', $out);
test_rmv($title, $out, 'network:n', $in);

############################################################
$title = 'network in automatic group';
############################################################

$in = <<'END';
group:abc =
 any:[ ip = 10.1.0.0/16 & network:n1, network:n2,
       network:n3, ],
;
END

$out = <<'END';
group:abc =
 any:[ ip = 10.1.0.0/16 & network:n1, network:n1a, network:n2,
       network:n3, network:n4, ],
;
END

test_add($title, $in, 'network:n1 network:n1a network:n3 network:n4', $out);
test_rmv($title, $out, 'network:n1a network:n4', $in);

############################################################
$title = 'in service, but not in area and pathrestriction';
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

test_add($title, $in, 'interface:r.x host:y any:x group:y', $out);
test_rmv($title, $out, 'host:y group:y', $in);

############################################################
$title = 'with indentation';
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

test_add($title, $in, 
         'host:a host:a1 host:b host:b1 host:d host:d1'.
         ' host:e host:e1 host:f host:f1 host:g host:g1', 
         $out);

$in = <<'END';
group:x = 
 host:a,
  host:b, host:c,
  host:d,

  host:e,
host:f,
  host:g,
  ;
END

test_rmv($title, $out, 'host:a1 host:b1 host:d1 host:e1 host:f1 host:g1', $in);
############################################################
$title = 'Find and change umlauts';
############################################################

$in = <<'END';
group:x = host:Müß, host:Mass;
END

$out = <<'END';
group:x = host:Müß, host:Muess, host:Mass, host:Maß;
END

test_add($title, $in, 'host:Müß host:Muess host:Mass host:Maß', $out);
test_rmv($title, $out, 'host:Muess host:Maß', $in);
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

test_add($title, $in, "-f $filename", $out);

my $remove_from = <<'END';
network:abx
host:id:xyz@dom
group:bbb
interface:r.n
END
($in_fh, $filename) = tempfile(UNLINK => 1);
print $in_fh $remove_from;
close $in_fh;

$in = <<'END';;
group:g = 
interface:r.n.sec,
any:aaa, network:xyz,
host:abc,
;
END

test_rmv($title, $out, "-f $filename", $in);

############################################################
done_testing;
