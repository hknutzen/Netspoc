#!perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Netspoc;

my ($title, $in, $out, $topo);

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
done_testing;
