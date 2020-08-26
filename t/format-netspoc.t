#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw(tempfile);

sub run {
    my ($input) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;
    my $cmd = "bin/format-netspoc $filename";
    my $stderr;
    run3($cmd, \undef, \undef, \$stderr);
    my $status = $? >> 8;
    $stderr ||= '';
    $stderr =~ s/\Q$filename\E/INPUT/g;
    open(my $fh, '<', $filename) or die("Can't open $filename: $!\n");
    local $/ = undef;
    my $output = <$fh>;
    close($fh);
    return($status, $output, $stderr);
}

sub test_run {
    my ($title, $input, $expected) = @_;
    my ($status, $output, $stderr) = run($input);
    if ($status != 0) {
        diag("Unexpected failure:\n$stderr");
        fail($title);
        return
    }
    $stderr =~ s/Changed INPUT\n$//;
    eq_or_diff("$stderr$output", $expected, $title);
}

sub test_err {
    my ($title, $input, $expected) = @_;
    my ($status, $output, $stderr) = run($input);
    if ($status == 0) {
        diag("Unexpected success\n");
        fail($title);
        return
    }
    $stderr =~ s/Aborted\n$//;
    eq_or_diff($stderr, $expected, $title);
}

my ($title, $in, $out);

############################################################
$title = 'Unknown type';
############################################################

$in = <<'END';
foo:x =
END

$out = <<'END';
Syntax error: Unknown global definition at line 1 of INPUT, near "foo:x<--HERE--> ="
END

test_err($title, $in, $out);

############################################################
$title = 'Empty input';
############################################################

$in = '';

$out = <<'END';
END

test_run($title, $in, $out);

############################################################
$title = 'Only comments in file';
############################################################

$in = <<'END';

# c1
  #c1b


#c2


END

$out = <<'END';
# c1
#c1b

#c2

END

test_run($title, $in, $out);

############################################################
$title = 'Empty group';
############################################################

$in = <<'END';
group:g1 = ; # IGNORED
END

$out = <<'END';
group:g1 =
;
END

test_run($title, $in, $out);

############################################################
$title = 'Group with union, intersection, complement';
############################################################

$in = <<'END';
group:g1 =
 host:h1,
 group:g2 & group:g3 &! host:h2 &! host:h3,
 network:n1,;
END

$out = <<'END';
group:g1 =
 group:g2
 & group:g3
 &! host:h2
 &! host:h3
 ,
 network:n1,
 host:h1,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Short automatic groups';
############################################################

$in = <<'END';
group:g1 =
 interface:r1.[auto],
 interface:[
  network:n1
 ].[all],
 interface:r1.[
  auto
 ],
 any:[area:a1]
 ,
 network:[   area:a2, ],  ;
END

$out = <<'END';
group:g1 =
 any:[area:a1],
 network:[area:a2],
 interface:[network:n1].[all],
 interface:r1.[auto],
 interface:r1.[auto],
;
END

test_run($title, $in, $out);

############################################################
$title = 'Nested automatic groups';
############################################################

$in = <<'END';
group:g1 =
 interface:[network:n2, network:n1].[all],
 network:[any:[area:a1]],
 network:[
  interface:[area:a3, area:a2].[all] &! interface:r1.n3, interface:r1.n3.virtual
 ]  ;
END

$out = <<'END';
group:g1 =
 network:[
  any:[area:a1],
 ],
 network:[
  interface:[
   area:a2,
   area:a3,
  ].[all]
  &! interface:r1.n3
  ,
  interface:r1.n3.virtual,
 ],
 interface:[
  network:n1,
  network:n2,
 ].[all],
;
END

test_run($title, $in, $out);

############################################################
$title = 'Missing [any|all]';
############################################################

$in = <<'END';
group:g1 = interface:r1.[ ;
END

$out = <<'END';
Syntax error: Expected [auto|all] at line 1 of INPUT, near "interface:r1.[ ;<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid group name';
############################################################

$in = <<'END';
group:g1@2 = ;
END

$out = <<'END';
Syntax error: Invalid token at line 1 of INPUT, near "group:g1@2<--HERE--> = ;"
END

test_err($title, $in, $out);

############################################################
$title = 'Empty interface name';
############################################################

$in = <<'END';
group:g1 = interface:;
END

$out = <<'END';
Syntax error: Interface name expected at line 1 of INPUT, near "interface:<--HERE-->;"
END

test_err($title, $in, $out);

############################################################
$title = 'Missing network in interface name';
############################################################

$in = <<'END';
group:g1 = interface:r1.;
END

$out = <<'END';
Syntax error: Interface name expected at line 1 of INPUT, near "interface:r1.;<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid network in interface name';
############################################################

$in = <<'END';
group:g1 = interface:r1.n1@vrf2;
END

$out = <<'END';
Syntax error: Interface name expected at line 1 of INPUT, near "interface:r1.n1@vrf2;<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = 'Multiple extensions in interface name';
############################################################

$in = <<'END';
group:g1 = interface:r1.n1.1.2;
END

$out = <<'END';
Syntax error: Interface name expected at line 1 of INPUT, near "interface:r1.n1.1.2;<--HERE-->"
END

test_err($title, $in, $out);

############################################################
$title = 'With umlauts';
############################################################

$in = <<'END';
group:groß = interface:röter.über;
END

$out = <<'END';
group:groß =
 interface:röter.über,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Simple group with many comments';
############################################################

$in = <<'END';
# head1
# head1a

# head2

# This is g1
group:g1 # g1 trailing
= # g1 trailing2

# g1 post def

description = This is a fine group;      # desc
# desc post

# desc post 2

# First element
host:h1, # after first
# post first

# Second
host:h2, # after second
# IGNORED
;
# At end
END

$out = <<'END';
# head1
# head1a

# head2

# This is g1
group:g1 = # g1 trailing
 # g1 trailing2

 # g1 post def

 description = This is a fine group; # desc

 # desc post

 # desc post 2

 # First element
 host:h1, # after first
 # post first

 # Second
 host:h2, # after second
;
# At end
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore comment inside description';
############################################################

$in = <<'END';
group:g1 =
   description # IGNORE
   =  the text; # comment
;
END

$out = <<'END';
group:g1 =
 description =  the text; # comment

;
END

test_run($title, $in, $out);

############################################################
$title = 'Comment before first element';
############################################################

$in = <<'END';
group:g1 =

 # pre h
 host:h
;
END

$out = <<'END';
group:g1 =
 # pre h
 host:h,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Comment after first line of group definition';
############################################################

$in = <<'END';
group:g1 = # pre h
 host:h,
;
group:g2 = host:h1, # post h1
host:h2
;
END

$out = <<'END';
group:g1 =
 # pre h
 host:h,
;

group:g2 =
 host:h1, # post h1
 host:h2,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Comment after interface';
############################################################

$in = <<'END';
group:g1 = interface:r1.Test, # comment1
interface:r2.[ auto ] , # comment2
interface:[network:n1].[all ], # comment3
;
END

$out = <<'END';
group:g1 =
 interface:[network:n1].[all], # comment3
 interface:r1.Test, # comment1
 interface:r2.[auto], # comment2
;
END

test_run($title, $in, $out);

############################################################
$title = 'Without trailing comment at end of file';
############################################################

$in = <<'END';
group:g1 =
 host:h # trailing
 , # more trailing
 # and more
;
END

$out = <<'END';
group:g1 =
 host:h, # trailing
;
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore comment in [any|all]';
############################################################

$in = <<'END';
group:g1 =
 interface:r1.[ # trailing
 # pre
auto # trailing2
 # post
], # real trailing
;
END

$out = <<'END';
group:g1 =
 interface:r1.[auto], # real trailing
;
END

test_run($title, $in, $out);

############################################################
$title = 'Ignore comment in short automatic group';
############################################################

$in = <<'END';
group:g1 = network:[ # trailing start
# pre
area:a # trailing
# post
] # real trailing
;
END

$out = <<'END';
group:g1 =
 network:[area:a], # real trailing
;
END

test_run($title, $in, $out);

############################################################
$title = 'Comment in intersection and complement';
############################################################

$in = <<'END';
group:g1 =
 # post g1

 # pre g2
  group:g2 # g2
 # post g2
 & # &
  group:g3 # g3
 &! # &!
  host:h2, # h2
;
END

$out = <<'END';
group:g1 =
 # post g1

 # pre g2
 group:g2 # g2
 # post g2
 # &
 & group:g3 # g3
 # &!
 &! host:h2 # h2
 ,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Comments in automatic group';
############################################################
# trailing start is ignored

$in = <<'END';
group:g1 =
 network:[ #### trailing start
 # pre h1
 host:h1, # trailing h1
 # post h1

 # pre h2
 host:h2
 ,
 host:h3 # trailing h3
] # trailing list
;
END

$out = <<'END';
group:g1 =
 network:[
  # pre h1
  host:h1, # trailing h1
  # post h1

  # pre h2
  host:h2,
  host:h3, # trailing h3
 ], # trailing list
;
END

test_run($title, $in, $out);

############################################################
$title = 'Sort elements by type, IP and name';
############################################################

$in = <<'END';
group:g1 =
 any:[area:a4],
 interface:r2.n-10_1_9_0-24,
 interface:r1.n99_10_1_9_0-24,
 interface:r2.n-10_1_6_0-24,
 host:h2,
 host:h999_99_9_0_0,
 host:h1-10_1_1_7,
 host:h3-999_999_0_0,
 host:10_1_1_8_h8,
 host:range-10_1_1_6-10_1_1_8,
 host:range-10_1_1_5-10_1_1_9,
 network:n-10_1_9_0-24,
 network:10_1_8_128-10_1_8_255,
 network:10_1_7_0-net,
 network:n-10_1_6_0-24,
 # Before
 network:n_999_10_1_10_0, # not recognized as IP-adress
 network:n-77,
 group:g9, group:g8,
 any:a-10_0_0_0-8,
 any:customerX-0_0_0_0-8,
 network:[area:a2] &! network:n-10_1_9_0-24,
 network:[area:a1] &! network:n-10_1_6_0-24,
;
END

$out = <<'END';
group:g1 =
 group:g8,
 group:g9,
 any:[area:a4],
 any:customerX-0_0_0_0-8,
 any:a-10_0_0_0-8,
 network:n-77,
 # Before
 network:n_999_10_1_10_0, # not recognized as IP-adress
 network:[area:a2]
 &! network:n-10_1_9_0-24
 ,
 network:[area:a1]
 &! network:n-10_1_6_0-24
 ,
 network:n-10_1_6_0-24,
 network:10_1_7_0-net,
 network:10_1_8_128-10_1_8_255,
 network:n-10_1_9_0-24,
 interface:r2.n-10_1_6_0-24,
 interface:r1.n99_10_1_9_0-24,
 interface:r2.n-10_1_9_0-24,
 host:h2,
 host:h3-999_999_0_0,
 host:range-10_1_1_5-10_1_1_9,
 host:range-10_1_1_6-10_1_1_8,
 host:h1-10_1_1_7,
 host:10_1_1_8_h8,
 host:h999_99_9_0_0,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Service with comments';
############################################################

$in = <<'END';
# pre s1
service:s1 = {
 # head s1
 description = s1 # desc s1
 # Pre user
 user = host:h2, host:h1;
 # pre rule1
 permit src = user; dst = network:n1; prt = tcp 80; # after prt
 # pre rule2
 permit src = network:n2, network:n1;
  # Pre dst
        dst = user;
  # Pre prt
        prt = # pre udp after '='
           # pre udp
           udp 123, proto 47, icmp 8, #after icmp
           # post udp
           # pre tcp
           tcp 90; # after tcp
   # Pre log
        log = fw3, # after log1
              asa1; # after log2
}
END

$out = <<'END';
# pre s1
service:s1 = {
 # head s1
 description = s1 # desc s1

 # Pre user
 user = host:h1,
        host:h2,
        ;
 # pre rule1
 permit src = user;
        dst = network:n1;
        prt = tcp 80; # after prt
 # pre rule2
 permit src = network:n1,
              network:n2,
              ;
        # Pre dst
        dst = user;
        # Pre prt
        prt = icmp 8, #after icmp
              proto 47,
              # post udp
              # pre tcp
              tcp 90, # after tcp
              # pre udp after '='
              # pre udp
              udp 123,
              ;
        # Pre log
        log = asa1, # after log2
              fw3, # after log1
              ;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Service with attributes';
############################################################

$in = <<'END';
service:s1 = {
 overlaps = service:s3, service:s6, service:s4, service:s2, service:s5;
 multi_owner;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
END

$out = <<'END';
service:s1 = {

 multi_owner;
 overlaps = service:s2,
            service:s3,
            service:s4,
            service:s5,
            service:s6,
            ;

 user = host:h1;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Service with empty user, src, dst, prt';
############################################################

$in = <<'END';
service:s1 = { user =; permit src =; dst =; prt =; }
END

$out = <<'END';
service:s1 = {
 user = ;
 permit src = ;
        dst = ;
        prt = ;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Service with foreach';
############################################################

$in = <<'END';
service:s1 = {
 user = foreach host:h2, host:h1;
 permit src = user; dst = network:[user]; prt = tcp 80;
}
END

$out = <<'END';
service:s1 = {
 user = foreach
  host:h1,
  host:h2,
 ;
 permit src = user;
        dst = network:[user];
        prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Intersection in first line';
############################################################

$in = <<'END';
service:s1 = {
 user = group:g1 &! host:h1;

 permit src = user;
        dst = host:h2;
        prt = tcp 80;
}
END

$out = <<'END';
service:s1 = {
 user = group:g1
        &! host:h1
        ;
 permit src = user;
        dst = host:h2;
        prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Automatic group in first line';
############################################################

$in = <<'END';
service:s1 = {
 user = host:[network:n2, network:n1]; # host:h3;
 permit src = user; dst = host:h2; prt = tcp 80;
}
END

$out = <<'END';
service:s1 = {
 user = host:[
         network:n1,
         network:n2,
        ]; # host:h3;
 permit src = user;
        dst = host:h2;
        prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Deeply nested automatic group';
############################################################

$in = <<'END';
service:s1 = {
 user = host:[network:[area:a] &! network:[network:[area:b] &! network:n1]];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
END

$out = <<'END';
service:s1 = {
 user = host:[
         network:[area:a]
         &! network:[
             network:[area:b]
             &! network:n1
             ,
            ]
         ,
        ];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Order of protocols';
############################################################

$in = <<'END';
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80, tcp 700, udp 70, tcp 55-59, tcp 20:1024-65535,
              tcp 54 : 64-74,
              tcp 20 : 64-74,
              udp 123,
              icmp 3 3,
              icmp 4 3,
              icmp 3 4,
              proto 43,
              proto 54,
              protocol:smtp, protocol:ftp,
              protocolgroup:ftp-active,
        ;
}
END

$out = <<'END';
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocolgroup:ftp-active,
              protocol:ftp,
              protocol:smtp,
              icmp 3 3,
              icmp 3 4,
              icmp 4 3,
              proto 43,
              proto 54,
              tcp 55 - 59,
              tcp 20 : 64 - 74,
              tcp 54 : 64 - 74,
              tcp 80,
              tcp 700,
              tcp 20 : 1024 - 65535,
              udp 70,
              udp 123,
              ;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Ordered elements in protocolgroups';
############################################################

$in = <<'END';
protocolgroup:g1 =udp 70,tcp 700, tcp 80, ;
END

$out = <<'END';
protocolgroup:g1 =
 tcp 80,
 tcp 700,
 udp 70,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Network';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24;
 nat:n = {
  ip = 9.1.1.0/24;
  dynamic;
 }
 radius_attributes = { banner = hello again; }
 nat:n2 = { ip = 8.1.1.0/24; }
host:range3-5 = { range = 10.1.1.3-10.1.1.5; }
host:h2 = { ip = 10.1.1.2; radius_attributes={ banner= hello h2;}}
host:h10 = { ip =10.1.1.10; owner = o1; }
host:h9 = { ip =10.1.1.9; owner = o1; }
host:long-name = { ip =10.1.1.66; owner = o1; }
}
END

$out = <<'END';
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 9.1.1.0/24; dynamic; }
 radius_attributes = {
  banner = hello again;
 }
 nat:n2 = { ip = 8.1.1.0/24; }
 host:h2 = {
  ip = 10.1.1.2;
  radius_attributes = {
   banner = hello h2;
  }
 }
 host:range3-5  = { range = 10.1.1.3 - 10.1.1.5; }
 host:h9        = { ip = 10.1.1.9; owner = o1; }
 host:h10       = { ip = 10.1.1.10; owner = o1; }
 host:long-name = { ip = 10.1.1.66; owner = o1; }
}
END

test_run($title, $in, $out);

############################################################
$title = 'Network with trailing comment in first line';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; } # comment
network:n1 = {
 ip = 10.1.1.0/24; } # IGNORED
network:n1 = { # comment
 ip = 10.1.1.0/24; }
network:n1 = # comment
{ ip = 10.1.1.0/24; }
network:n1 # comment
= { ip = 10.1.1.0/24; }
END

$out = <<'END';
network:n1 = { # comment
 ip = 10.1.1.0/24;
}

network:n1 = {
 ip = 10.1.1.0/24;
}

network:n1 = { # comment
 ip = 10.1.1.0/24;
}

network:n1 = { # comment
 ip = 10.1.1.0/24;
}

network:n1 = { # comment
 ip = 10.1.1.0/24;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Managed router';
############################################################

$in = <<'END';
router:r1 = { managed;
model =
 ASA,
 VPN,CONTEXT;
interface:n7 = {
 ip = 10.1.7.1; hardware = n7;
 hub = crypto:c1, crypto:c2, ;
 no_check;
}
interface:n1 = {
 ip = 10.1.1.1, 10.1.1.2; hardware = n1;
 virtual = { ip = 10.1.1.3;  type = HSRPv2; }
 routing = manual;
}
interface:n3 = { unnumbered; }
interface:log-name = { ip = 10.1.9.1; hardware = ln; }
interface:n5 = { ip = 10.1.5.1; hardware = n5; }
interface:lo = { ip = 10.1.4.128; hardware = lo; loopback; }
}
END

$out = <<'END';
router:r1 = {
 managed;
 model = ASA, VPN, CONTEXT;
 interface:n7 = {
  ip = 10.1.7.1;
  hardware = n7;
  hub = crypto:c1,
        crypto:c2,
        ;
  no_check;
 }
 interface:n1 = {
  ip = 10.1.1.1,
       10.1.1.2,
       ;
  hardware = n1;
  virtual = { ip = 10.1.1.3; type = HSRPv2; }
  routing = manual;
 }
 interface:n3       = { unnumbered; }
 interface:log-name = { ip = 10.1.9.1; hardware = ln; }
 interface:n5       = { ip = 10.1.5.1; hardware = n5; }
 interface:lo       = { ip = 10.1.4.128; hardware = lo; loopback; }
}
END

test_run($title, $in, $out);

############################################################
$title = 'Sort successive vip interfaces';
############################################################

$in = <<'END';
router:u1 = {
 interface:n7 = { ip = 10.1.1.7; owner = o1; }
 interface:lo = { ip = 10.1.4.128; owner = o2; vip; }
 interface:n1 = { ip = 10.1.1.1; owner = o1; vip; }
 interface:unnum = { unnumbered; }
 interface:short;
}
router:u2 = {
 interface:v2 = { ip = 10.1.4.128; owner = o2; vip; }
 interface:v1 = { ip = 10.1.4.127; owner = o2; vip; }
 interface:n7 = { ip = 10.1.1.7; owner = o1; }
 interface:lo = { ip = 10.1.1.4; owner = o2; vip; }
 interface:n1 = { ip = 10.1.1.1; owner = o1; vip; }
}
END

$out = <<'END';
router:u1 = {
 interface:n7    = { ip = 10.1.1.7; owner = o1; }
 interface:n1    = { ip = 10.1.1.1; owner = o1; vip; }
 interface:lo    = { ip = 10.1.4.128; owner = o2; vip; }
 interface:unnum = { unnumbered; }
 interface:short;
}

router:u2 = {
 interface:v1 = { ip = 10.1.4.127; owner = o2; vip; }
 interface:v2 = { ip = 10.1.4.128; owner = o2; vip; }
 interface:n7 = { ip = 10.1.1.7; owner = o1; }
 interface:n1 = { ip = 10.1.1.1; owner = o1; vip; }
 interface:lo = { ip = 10.1.1.4; owner = o2; vip; }
}
END

test_run($title, $in, $out);

############################################################
$title = 'Aggregate';
############################################################

$in = <<'END';
any:a1 = { ip = 10.1.0.0/16; link = network:n1; nat:n1 = { ip  = 10.9.0.0/16; } owner = o1;
}
END

$out = <<'END';
any:a1 = {
 ip = 10.1.0.0/16;
 link = network:n1;
 nat:n1 = { ip = 10.9.0.0/16; }
 owner = o1;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Area';
############################################################

$in = <<'END';
area:a1 = {
 border = interface:r3.n3, group:g3 &! interface:r1.n1;
 inclusive_border = interface:r3.n3;
 nat:t = { hidden; }
 owner = o;
}
END

$out = <<'END';
area:a1 = {
 nat:t = { hidden; }
 owner = o;
 border = interface:r3.n3,
          group:g3
          &! interface:r1.n1
          ,
          ;
 inclusive_border = interface:r3.n3;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Area with multiple inclusive borders';
############################################################

$in = <<'END';
area:a1 = {
 inclusive_border= interface:r1.n1, interface:r5.n5, interface:r2.n2;
}
END

$out = <<'END';
area:a1 = {
 inclusive_border =
  interface:r1.n1,
  interface:r5.n5,
  interface:r2.n2,
  ;
}
END

test_run($title, $in, $out);

############################################################
$title = 'Pathrestriction';
############################################################
# Elements are sorted by IP in name, same as in group.

$in = <<'END';
pathrestriction:p1 = interface:r1.n_10_1_9_0-24,
 interface:r1.n2,
 interface:r2.n_10_1_8_128-25,
 interface:r3@vrf7.n_10_1_7_0,
 interface:r2.n1
;
END

$out = <<'END';
pathrestriction:p1 =
 interface:r1.n2,
 interface:r2.n1,
 interface:r3@vrf7.n_10_1_7_0,
 interface:r2.n_10_1_8_128-25,
 interface:r1.n_10_1_9_0-24,
;
END

test_run($title, $in, $out);

############################################################
$title = 'Protocol definition';
############################################################

$in = <<'END';
protocol:http =
tcp 80;

protocol:BGP = tcp 179, no_check_supernet_rules;

protocol:all_ip = # trailing
 ip;
protocol:all_icmp =
 description = icmp with any typa and code
 icmp;
END

$out = <<'END';
protocol:http = tcp 80;

protocol:BGP = tcp 179, no_check_supernet_rules;

protocol:all_ip = # trailing
 ip;

protocol:all_icmp =
 description = icmp with any typa and code

 icmp;
END

test_run($title, $in, $out);

############################################################
$title = 'Unfinished protocol definition';
############################################################

$in = <<'END';
protocol:p = tcp
END

$out = <<'END';
Syntax error: Expected ';' at line 2 of INPUT, at EOF
END

test_err($title, $in, $out);

############################################################
done_testing;
