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
# Option 'verbose' gets overwritten by default option '--quiet'
# when running tests.
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
Error: Invalid value for check_unused_groups in config: errors
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

test_warn($title, $in, $out, '--check_unused_groups=warn');

############################################################
$title = 'Invalid value for command line option';
############################################################

$in = <<'END';
END

$out = <<'END';
Error: invalid argument "foo" for "--check_unused_groups" flag: Expected 0|1|warn but got foo
END

test_err($title, $in, $out, '--check_unused_groups=foo');

############################################################
$title = 'Invalid command line option';
############################################################

$in = <<'END';
END

$out = <<'END';
Error: unknown flag: --foo
END

test_err($title, $in, $out, '--foo=foo');

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
Error: Can't mkdir missing.dir/file: no such file or directory
Aborted
END

test_err($title, $in, $out, undef, 'missing.dir/file');

############################################################
done_testing;
