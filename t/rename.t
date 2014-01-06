#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

sub test_run {
    my ($title, $input, $args, $expected) = @_;
    my ($in_fh, $filename) = tempfile(UNLINK => 1);
    print $in_fh $input;
    close $in_fh;

    my $cmd = "perl -CSDAL -I lib bin/rename-netspoc -q - $args < $filename";
    open(my $out_fh, '-|', $cmd) or die "Can't execute $cmd: $!\n";

    # Undef input record separator to read all output at once.
    $/ = undef;
    my $output = <$out_fh>;
    close($out_fh) or die "Syserr closing pipe from $cmd: $!\n";
    eq_or_diff($output, $expected, $title);
    return;
}

############################################################
my $title = 'Rename network';
############################################################

my $in = <<END;
network:Test =  { ip = 10.9.1.0/24; }
group:G = interface:r.Test, # comment
    host:id:h\@dom.top.Test,
    network:Test,
    ;
END

my $out = <<END;
network:Toast =  { ip = 10.9.1.0/24; }
group:G = interface:r.Toast, # comment
    host:id:h\@dom.top.Toast,
    network:Toast,
    ;
END

test_run($title, $in, 'network:Test network:Toast', $out);

############################################################
$title = 'Rename network to name with leading digit';
############################################################

$in = <<END;
network:Test =  { ip = 10.9.1.0/24; }
group:G = interface:r.Test, # comment
    host:id:h\@dom.top.Test,
    network:Test,
    ;
END

$out = <<END;
network:1_2_3_0_Test =  { ip = 10.9.1.0/24; }
group:G = interface:r.1_2_3_0_Test, # comment
    host:id:h\@dom.top.1_2_3_0_Test,
    network:1_2_3_0_Test,
    ;
END

test_run($title, $in, 'network:Test network:1_2_3_0_Test', $out);

############################################################
$title = 'Rename router';
############################################################

$in = <<END;
router:Test = { interface:N = { ip = 10.9.1.0/24; }
 interface:M;
}
group:G = interface:Test.N, # comment
  interface:Test.M
    ;
END

$out = <<END;
router:Toast = { interface:N = { ip = 10.9.1.0/24; }
 interface:M;
}
group:G = interface:Toast.N, # comment
  interface:Toast.M
    ;
END

test_run($title, $in, 'router:Test router:Toast', $out);

############################################################
$title = 'Rename router then network';
############################################################

$in = <<END;
router:R = { interface:NN = { ip = 10.9.1.0/24; } }
network:NN
interface:R.NN;
END

$out = <<END;
router:RR = { interface:N = { ip = 10.9.1.0/24; } }
network:N
interface:RR.N;
END

test_run($title, $in, 'router:R router:RR network:NN network:N', $out);
$title = 'Rename network then router';
test_run($title, $in, 'network:NN network:N router:R router:RR', $out);

############################################################
$title = 'Rename nat';
############################################################

$in = <<END;
network:N = { ip = 1.2.3.0/24; nat:NAT-1 = {ip = 7.8.9.0; } }
bind_nat = NAT-1;
bind_nat = x, # comment
    y,NAT-1, z;
bind_nat =NAT-1#comment
    ;
END

$out = <<END;
network:N = { ip = 1.2.3.0/24; nat:NAT-2 = {ip = 7.8.9.0; } }
bind_nat = NAT-2;
bind_nat = x, # comment
    y,NAT-2, z;
bind_nat =NAT-2#comment
    ;
END

test_run($title, $in, 'nat:NAT-1 nat:NAT-2', $out);

############################################################
$title = 'Rename umlauts';
############################################################

$in = <<END;
owner:Maaß
owner:Wittmüß
owner = Maaß, Wittmuess
END

$out = <<END;
owner:Maass
owner:Wittmüß
owner = Maass, Wittmüß
END

test_run($title, $in, 'owner:Maaß owner:Maass owner:Wittmuess owner:Wittmüß', 
	 $out);

############################################################
$title = 'Read substitutions from file';
############################################################

my $subst = <<END;
host:abc host:a1
owner:foo owner:büro
nat:tick nat:t1
nat:ticks nat:t2
nat:ick nat:_
network:net network:xxxx
END
my ($in_fh, $filename) = tempfile(UNLINK => 1);
print $in_fh $subst;
close $in_fh;

$in = <<END;;
nat:ticks nat:ick
nat:tick
interface:net = { bind_nat = ick,
 ticks, tick;}
network:net = { owner = foo; 
 host:abc;
}
END

$out = <<END;;
nat:t2 nat:_
nat:t1
interface:xxxx = { bind_nat = _,
 t2, t1;}
network:xxxx = { owner = büro; 
 host:a1;
}
END

test_run($title, $in, "-f $filename", $out);

############################################################
done_testing;
