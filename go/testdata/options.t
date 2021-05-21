############################################################
=TITLE=Options from config file
=INPUT=
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
=ERROR=
Error: unused group:g
=END=

############################################################
=TITLE=Invalid option or value in config file
=INPUT=
-- config
foo = bar;
check_unused_groups = errors;
-- topo
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Invalid line in config:
 - bad value in 'check_unused_groups = errors'
 - bad keyword 'foo'
Aborted
=END=

############################################################
=TITLE=Invalid line in config file
=INPUT=
-- config
bla bla;
=ERROR=
Error: Invalid line in config:
 - bad keyword 'bla bla'
Aborted
=END=

############################################################
=TITLE=Command line option overwrites config file
=OPTIONS=--check_unused_groups=warn
=INPUT=
-- config
check_unused_groups = 1;
-- bar
group:g = network:n1;
network:n1 = { ip = 10.1.1.0/24; }
=WARNING=
Warning: unused group:g
=END=

############################################################
=TITLE=Reach max_errors
=OPTIONS=--check_unused_groups=err --max_errors=2
=INPUT=
group:g1 = network:n1;
group:g2 = network:n1;
group:g3 = network:n1;
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: unused group:g1
Error: unused group:g2
Aborted after 2 errors
=END=

############################################################
=TITLE=Invalid value for command line option
=OPTIONS=--check_unused_groups=foo
=INPUT= #none
=ERROR=
Error: invalid argument "foo" for "--check_unused_groups" flag: Expected 0|1|warn but got foo
Aborted
=END=

############################################################
=TITLE=Invalid command line option
=OPTIONS=--foo=foo
=INPUT= #
=ERROR=
Error: unknown flag: --foo
Aborted
=END=

############################################################
=TITLE=Non existent out directory
=PARAMS=missing.dir/file
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=ERROR=
Error: Can't mkdir missing.dir/file: no such file or directory
Aborted
=END=
