#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use lib 't';
use Test_Netspoc;

# Change to "C" locale, so we get non translated error message.
use POSIX 'locale_h';
setlocale(LC_MESSAGES, 'C');

my ($title, $in, $out);

############################################################
$title = 'Options from config file';
############################################################

$in = <<'END';
-- config
# comment
check_unused_groups = 1;
# empty line follows

ignore_files = ^foo$;
max_errors = 2;
verbose = 1;
time_stamps = 0;
-- foo
SOME INVALID DATA
-- bar
group:g = network:n1;
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Error: unused group:g
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid option in config file';
############################################################

$in = <<'END';
-- config
foo = foo;
END

$out = <<'END';
Error: Invalid keyword in config: foo
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid value in config file';
############################################################

$in = <<'END';
-- config
check_unused_groups = errors;
END

$out = <<'END';
Error: Invalid value for check_unused_groups in config, expected '0|1|warn'
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Invalid line in config file';
############################################################

$in = <<'END';
-- config
bla bla;
END

$out = <<'END';
Error: Unexpected line in config: bla bla;
Aborted
END

test_err($title, $in, $out);

############################################################
$title = 'Command line option overwrites config file';
############################################################

$in = <<'END';
-- config
check_unused_groups = 1;
-- bar
group:g = network:n1;
network:n1 = { ip = 10.1.1.0/24; }
END

$out = <<'END';
Warning: unused group:g
END

test_warn($title, $in, $out, '-check_unused_groups=warn');

############################################################
$title = 'Invalid value for command line option';
############################################################

$in = <<'END';
END

$out = <<'END';
Error: Invalid value for option check_unused_groups, expected '0|1|warn'
Aborted

END

test_err($title, $in, $out, '-check_unused_groups=foo');

############################################################
$title = 'Invalid command line option';
############################################################

$in = <<'END';
END

$out = <<'END';
Unknown option: foo

END

test_err($title, $in, $out, '-foo=foo');

############################################################
$title = 'Non existent out directory';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
END

$out = <<'END';
Error: Can't create output directory missing.dir/file: No such file or directory
Aborted
END

test_err($title, $in, $out, undef, 'missing.dir/file');

############################################################
$title = 'Verbose output with progress messages';
############################################################

$in = <<'END';
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; host:h2 = { ip = 10.1.2.10; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 overlaps = service:s1;
 user = network:n1;
 permit src = user; dst = host:h2; prt = tcp;
 permit src = user; dst = network:n2; prt = ip;
}
END

$out = <<'END';
Netspoc, version TESTING
Read 1 routers, 2 networks, 1 hosts, 1 services
Arranging protocols
Linking topology
Preparing security zones and areas
Preparing fast path traversal
Distributing NAT
Finding subnets in zone
Normalizing services
Checking service owner
Converting hosts to subnets
Grouping rules
Grouped rule count: 2
Finding subnets in 1 NAT domains
Checking rules for unstable subnet relation
Checking rules with hidden or dynamic NAT
Checking supernet rules
Checking transient supernet rules
Checking for redundant rules
Expanded rule count: 2; duplicate: 0; redundant: 1
Removing simple duplicate rules
Setting policy distribution IP
Expanding crypto rules
Finding routes
Generating reverse rules for stateless routers
Marking rules for secondary optimization
Distributing rules
Moving 3 old files in '' to subdirectory '.prev'
Printing intermediate code
Reused 1 files from previous run
Finished
-- r1
! n1_in
access-list n1_in extended permit ip 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
END

test_reuse_prev($title, $in, $in, $out, '-verbose');

############################################################
done_testing;
