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
quiet = 0;
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
=TITLE=Directory names "config"
=INPUT=
-- config/foo
bla bla;
=ERROR=
Error: Can't read config: is a directory
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
=OPTIONS=--max_errors=2
=INPUT=
network:n1 = {}
network:n2 = {}
network:n3 = {}
=ERROR=
Error: Missing IP address for network:n1
Error: Missing IP address for network:n2
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
=TITLE=Option --help
=OPTIONS=--help
=INPUT= #
=ERROR=
Usage of PROGRAM:
      --auto_default_route                          (default true)
      --check_duplicate_rules tristate              (default warn)
      --check_fully_redundant_rules tristate
      --check_identical_services tristate
      --check_policy_distribution_point tristate
      --check_redundant_rules tristate              (default warn)
      --check_service_multi_owner tristate          (default warn)
      --check_service_unknown_owner tristate
      --check_subnets tristate                      (default warn)
      --check_supernet_rules tristate               (default warn)
      --check_transient_supernet_rules tristate     (default warn)
      --check_unenforceable tristate                (default warn)
      --check_unused_groups tristate                (default warn)
      --check_unused_owners tristate                (default warn)
      --check_unused_protocols tristate
      --concurrency_pass1 int                       (default 1)
      --concurrency_pass2 int                       (default 1)
      --ignore_files regexp                         (default ^(CVS|RCS|\.#.*|.*~)$)
  -6, --ipv6
  -m, --max_errors int                              (default 10)
  -q, --quiet
  -t, --time_stamps
Aborted
=END=

############################################################
=TITLE=Too many arguments
=PARAMS=abc def
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Expected 1 or 2 args, but got 3
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

############################################################
=TITLE=Can't create out directory
=SETUP=touch out
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=
=ERROR=
Error: Can't mkdir out: file exists
Aborted
=END=

############################################################
=TITLE=Can't write code file
=TODO= Panic can't be handled in tests currently
=SETUP=
mkdir -p out/.prev
mkdir out/r1
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WITH_OUTDIR=
=ERROR=
Aborted
=END=

############################################################