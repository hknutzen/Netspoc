#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw(tempfile);

sub test_run {
    my ($what, $title, $input, $args, $expected) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    my $cmd = "$what -q $filename $args";
    my $stderr;
    run3($cmd, \undef, \undef, \$stderr);
    my $status = $? >> 8;
    $stderr ||= '';
    if ($status != 0) {
        diag("Unexpected failure:\n$stderr");
        fail($title);
    }

    open(my $fh, '<', $filename) or die("Can't open $filename: $!\n");
    local $/ = undef;
    my $output = <$fh>;
    close($fh);
    eq_or_diff("$stderr$output", $expected, $title);
}

sub test_add {
    my ($title, $input, $args, $expected) = @_;
    $title = "Add: $title";
    test_run('bin/add-to-netspoc', $title, $input, $args, $expected);
}

sub test_rmv {
    my ($title, $input, $args, $expected) = @_;
    $title = "Remove: $title";
    test_run('bin/remove-from-netspoc',  $title, $input, $args, $expected);
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
$title = 'host after automatic interface';
############################################################

$in = <<'END';
group:abc =
 interface:r1@vrf.[auto],
 network:xyz,
;
END

$out = <<'END';
group:abc =
 interface:r1@vrf.[auto],
 host:h,
 network:xyz,
;
END

test_add($title, $in, 'interface:r1@vrf.\[auto\] host:h', $out);
test_rmv($title, $out, 'host:h', $in);

############################################################
$title = 'automatic interface after host';
############################################################

$in = <<'END';
group:abc =
 host:h,
 network:xyz,
;
END

$out = <<'END';
group:abc =
 host:h,
 interface:r1@vrf.[auto],
 network:xyz,
;
END

test_add($title, $in, 'host:h interface:r1@vrf.\[auto\]', $out);
test_rmv($title, $out, 'interface:r1@vrf.\[auto\]', $in);

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
$title = 'Warn group with intersection';
############################################################

$in = <<'END';
group:g2 = group:g1 &! network:n2;
END

$out = <<'END';
Warning: Substituted in intersection
group:g2 = group:g1, group:g3 &! network:n2;
END

test_add($title, $in, 'group:g1 group:g3', $out);

############################################################
$title = 'No warn group with intersection';
############################################################

$in = <<'END';
group:g3 = group:g1, group:g2 &! network:n2;
END

$out = <<'END';
group:g3 = group:g1, group:g3, group:g2 &! network:n2;
END

test_add($title, $in, 'group:g1 group:g3', $out);

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
$title = 'area in automatic group';
############################################################

$in = <<'END';
group:abc =
 any:[ ip = 10.1.0.0/16 & area:a1, ],
;
END

$out = <<'END';
group:abc =
 any:[ ip = 10.1.0.0/16 & area:a1, area:a2, ],
;
END

test_add($title, $in, 'area:a1 area:a2', $out);
test_rmv($title, $out, 'area:a2', $in);

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
  host:e, ###
  host:e1
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

  host:e, ###
 host:f,
  host:g;
END

test_rmv($title, $out, 'host:a1 host:b1 host:d1 host:e1 host:f1 host:g1', $in);

############################################################
$title = 'Add on new line for single object after definition';
############################################################

$in = <<'END';
group:g-1 = host:a,
          ;
END

$out = <<'END';
group:g-1 = host:a,
            host:a1,
          ;
END

test_add($title, $in, 'host:a host:a1', $out);

############################################################
$title = 'Add on new line for single object after definition (2)';
############################################################

$in = <<'END';
# first line
group:g-1 = host:a,
          ;
END

$out = <<'END';
# first line
group:g-1 = host:a,
            host:a1,
          ;
END

test_add($title, $in, 'host:a host:a1', $out);

############################################################
$title = 'List terminates at EOF';
############################################################

$in = "group:g = host:a;";

$out = <<'END';
group:g = host:a,
          host:b;
END

test_add($title, $in, 'host:a host:b', $out);

############################################################
$title = 'Unchanged list  at EOF';
############################################################

$in = "group:g = host:a;";

test_add($title, $in, 'host:x host:b', $in);

############################################################
$title = 'Find group after commented group';
############################################################

$in = <<'END';
# group:g1 =
# host:c,
# ;

group:g2 =
 host:a,
 host:b,
;
END

$out = <<'END';
# group:g1 =
# host:c,
# ;

group:g2 =
 host:b,
;
END

test_rmv($title, $in, 'host:a', $out);

############################################################
$title = 'Remove trailing comma in separate line';
############################################################

$in = <<'END';
group:g1 =
 host:a,
 host:b #b
 #c
,
;
group:g2 =
 host:b
 #c
  ,;
END

$out = <<'END';
group:g1 =
 host:a,
 #c

;
group:g2 =
 #c
;
END

test_rmv($title, $in, 'host:b', $out);

############################################################
$title = 'No trailing comma after comment';
############################################################

$in = <<'END';
group:g1 =
 host:a,
 host:b #b
 #c
 # invalid comma behind ';' for test
;,
END

$out = <<'END';
group:g1 =
 host:a,
 #c
 # invalid comma behind ';' for test
;,
END

test_rmv($title, $in, 'host:b', $out);

############################################################
$title = 'When all elements in one list are removed, do not change next list';
############################################################

$in = <<'END';
service:s1 = {
 user = host:a,
        host:b;
 permit src = host:c,
              host:d;
        dst = user;
        prt = tcp 80 90;
}
END

$out = <<'END';
service:s1 = {
 user = ;
 permit src = host:c,
              host:d;
        dst = user;
        prt = tcp 80 90;
}
END

test_rmv($title, $in, 'host:a host:b', $out);

############################################################
$title = 'Find and change umlauts';
############################################################

$in = <<'END';
group:BÖSE = host:Müß, host:Mass;
END

$out = <<'END';
group:BÖSE = host:Müß, host:Muess, host:Mass, host:Maß;
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
host:abc;
END

test_rmv($title, $out, "-f $filename", $in);

############################################################
$title = 'Element to remove does not exist';
############################################################

$in = <<'END';
group:g1 =
 host:a,
 host:b,
;
END

$out = <<'END';
group:g1 =
 host:a,
 host:b,
;
END

test_rmv($title, $in, 'host:c', $out);

############################################################
$title = 'Group with description';
############################################################

$in = <<'END';
group:g1 =
 description = host:a, host:b, ;
 host:a,
 host:b,
;
END

$out = <<'END';
group:g1 =
 description = host:a, host:b, ;
 host:a,
;
END

test_rmv($title, $in, 'host:b', $out);
############################################################
done_testing;
