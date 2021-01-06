
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
=ERROR=Error: unused group:g


=TITLE=Invalid option in config file
=INPUT=
-- config
foo = foo;
=ERROR=
Error: Invalid keyword in config: foo
Aborted
=END=


=TITLE=Invalid value in config file
=INPUT=
-- config
check_unused_groups = errors;
=ERROR=
Error: Invalid value for check_unused_groups in config: errors
Aborted
=END=


=TITLE= Invalid line in config file
=INPUT=
-- config
bla bla;
=ERROR=
Error: Unexpected line in config: bla bla;
Aborted
=END=


=TITLE=Command line option overwrites config file
=INPUT=
-- config
check_unused_groups = 1;
-- bar
group:g = network:n1;
network:n1 = { ip = 10.1.1.0/24; }
=OPTION=--check_unused_groups=warn
=WARNING=Warning: unused group:g


=TITLE=Invalid value for command line option
=INPUT= #none
=OPTION=--check_unused_groups=foo
=ERROR=
Error: invalid argument "foo" for "--check_unused_groups" flag: Expected 0|1|warn but got foo
=END=


=TITLE=Invalid command line option
=INPUT= #
=OPTION=--foo=foo
=ERROR=Error: unknown flag: --foo


=TITLE=Non existent out directory
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

#test_err($title, $in, $out, undef, 'missing.dir/file');
