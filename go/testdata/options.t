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
Usage: PROGRAM [options] IN-DIR|IN-FILE [CODE-DIR]
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
      --debug_pass2 string
      --ignore_files regexp                         (default ^(CVS|RCS|.*~)$)
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
network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=
=ERROR=
Error: Can't mkdir out: file exists
Aborted
=END=

############################################################
=TITLE=Can't create tmp directory to save old out directory
=SETUP=
mkdir out
chmod u-w .
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=
=ERROR=
Error: Can't mkdir code.tmp: permission denied
Aborted
=END=

############################################################
=TITLE=Must strip slash from out/ for path.Dir to work correctly
=SETUP=
mkdir out
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=PARAMS=out/
=WARNING=NONE

############################################################
=TITLE=Can't move out directory
=SETUP=
mkdir out
chmod u-w out
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WITH_OUTDIR=
=ERROR=
Error: Can't rename out code.tmp/code: permission denied
Aborted
=END=

############################################################
=TITLE=Can't write to out directory
=SETUP=
mkdir out
mkdir out/.prev
chmod u-w out
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WITH_OUTDIR=
=ERROR=
Error: Can't open out/r1.config: permission denied
Aborted
=END=

############################################################
=TITLE=Can't write code file
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
panic: Can't open out/r1: is a directory
=END=

############################################################
=TITLE=Can't read input directory
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=SETUP=
chmod u-rx netspoc
=ERROR=
panic: open netspoc: permission denied
=END=

############################################################
=TITLE=Can't read intermediate file *.config
=SETUP=
mkdir -p out/.prev
touch out/r1.config
chmod u-r out/r1.config
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WITH_OUTDIR=
=ERROR=
panic: open out/r1.config: permission denied
=END=

############################################################
=TITLE=Can't read intermediate file *.rules
=SETUP=
mkdir -p out/.prev
touch out/r1.rules
chmod u-r out/r1.rules
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=WITH_OUTDIR=
=ERROR=
panic: open out/r1.rules: permission denied
=END=

############################################################
=TITLE=Use debug_pass2
=SETUP=
mkdir out
cat >> out/r1.config <<END
! n1_in
#insert n1_in
END
cat >> out/r1.rules <<END
{
  "model": "ASA",
  "acls": [
    {
      "name": "n1_in",
      "rules": [
        {
          "src": [ "10.1.1.0/24" ],
          "dst": [ "10.1.2.0/24" ],
          "prt": [ "tcp 80" ]
        }
      ],
      "intf_rules": [],
      "add_deny": true
    }
  ]
}
END
=OPTIONS=--debug_pass2=r1
=INPUT= ignored
=WITH_OUTDIR=
=OUTPUT=
--r1
! n1_in
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 80
access-list n1_in extended deny ip any4 any4
=END=

############################################################
=TITLE=debug_pass2 with unknown device
=SETUP=
mkdir out
=OPTIONS=--debug_pass2=r1
=INPUT= ignored
=WITH_OUTDIR=
=ERROR=
panic: open out/r1.rules: no such file or directory
=END=

############################################################
=TITLE=Bad JSON in intermediate code
=SETUP=
mkdir out
cat >> out/r1.config <<END
! n1_in
#insert n1_in
END
cat >> out/r1.rules <<END
BAD_JSON
END
=OPTIONS=--debug_pass2=r1
=INPUT= ignored
=WITH_OUTDIR=
=ERROR=
panic: invalid character 'B' looking for beginning of value
=END=

############################################################
=TITLE=Overlapping ranges in intermediate code
=SETUP=
mkdir out
cat >> out/r1.config <<END
! n1_in
#insert n1_in
END
cat >> out/r1.rules <<END
{
  "model": "ASA",
  "acls": [
    {
      "name": "n1_in",
      "rules": [
        {
          "src": [ "10.1.1.0/24" ],
          "dst": [ "10.1.2.0/24" ],
          "prt": [ "tcp 70-90", "tcp 80-99" ]
        }
      ],
      "intf_rules": [],
      "add_deny": true
    }
  ]
}
END
=OPTIONS=--debug_pass2=r1
=INPUT= ignored
=WITH_OUTDIR=
=ERROR=
panic: Unexpected overlapping ranges [70 90] [80 99]
=END=
