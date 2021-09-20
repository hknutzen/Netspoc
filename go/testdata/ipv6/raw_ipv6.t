
############################################################
=TITLE=Copy raw, check unused raw
=PARAMS=--ipv6
=INPUT=
-- topology
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }

router:r1 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n1 = { ip = ::a01:101; hardware = n1; }
  interface:n2 = { ip = ::a01:201; hardware = n2; }
}

router:r2 = {
  model = ASA;
  managed;
  routing = manual;
  interface:n1 = { ip = ::a01:102; hardware = n1; }
  interface:n2 = { ip = ::a01:202; hardware = n2; }
}
-- raw/aaa/b
!!!
-- raw/r1
! manual route
ipv6 route ::a01:200/120 ::a01:101
-- raw/x
access-list n2_in extended permit udp any6 any6 eq 123
=WARNING=
Warning: Ignoring path raw/aaa
Warning: Found unused file raw/x
=OUTPUT=
--ipv6/r1.raw
! manual route
ipv6 route ::a01:200/120 ::a01:101
=END=

############################################################
=TITLE=Ignore file with name "raw"
=PARAMS=--ipv6
=INPUT=
-- raw
network:n1 = { ip = ::a01:100/120; }
syntax error
=ERROR=
Error: topology seems to be empty
Aborted
=END=

############################################################
=TITLE=Can't copy raw file
=TODO= No IPv6
=SETUP=
mkdir -p out/.prev
mkdir -p out/r1.raw/r1
=PARAMS=--ipv6
=INPUT=
--ipv6/topo
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
  model = IOS;
  managed;
  interface:n1 = { ip = ::a01:101; hardware = n1; }
}
--raw/r1
ipv6 route ::a01:200/120 ::a01:101
=WITH_OUTDIR=
=ERROR=
Error: Can't cp raw/r1 to out/r1.raw: exit status 1
cp: cannot overwrite directory 'out/r1.raw/r1' with non-directory

Aborted
=END=

############################################################
=TITLE=Can't read raw directory
=TODO= No IPv6
=SETUP=
mkdir -p netspoc/raw
chmod u-rx netspoc/raw
=PARAMS=--ipv6
=INPUT=
--ipv6/topo
network:n1 = { ip = ::a01:100/120; }
=WITH_OUTDIR=
=ERROR=
panic: open raw: permission denied
=END=
