
############################################################
=TITLE=Copy raw, check unused raw
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
  model = IOS;
  managed;
  routing = manual;
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
  model = ASA;
  managed;
  routing = manual;
  interface:n1 = { ip = 10.1.1.2; hardware = n1; }
  interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
-- raw/aaa/b
!!!
-- raw/r0
access-list n2_in extended permit udp any4 any4 eq 123
-- raw/r1
! manual route
ip route 10.1.2.0 255.255.255.0 10.1.1.1
=WARNING=
Warning: Ignoring path raw/aaa
Warning: Found unused file raw/r0
=OUTPUT=
--r1.raw
! manual route
ip route 10.1.2.0 255.255.255.0 10.1.1.1
=END=

############################################################
=TITLE=Ignore hidden file and file named CVS
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
-- raw/.hidden
abc
-- raw/CVS
xyz
=WITH_OUTDIR=
=WARNING=NONE

############################################################
=TITLE=Ignore file with name "raw"
=INPUT=
-- raw
network:n1 = { ip = 10.1.1.0/24; }
syntax error
=ERROR=
Error: topology seems to be empty
Aborted
=END=

############################################################
=TITLE=Can't copy raw file
# No IPv6 test
=SETUP=
mkdir -p out/.prev
mkdir -p out/r1.raw/r1
=INPUT=
--topo
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
  model = IOS;
  managed;
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
--raw/r1
ip route 10.1.2.0 255.255.255.0 10.1.1.1
=WITH_OUTDIR=
=ERROR=
Error: Can't cp raw/r1 to out/r1.raw: exit status 1
cp: cannot overwrite directory 'out/r1.raw/r1' with non-directory

Aborted
=END=

############################################################
=TITLE=Can't read raw directory
# No IPv6 test
=SETUP=
mkdir -p netspoc/raw
chmod u-rx netspoc/raw
=INPUT=
--topo
network:n1 = { ip = 10.1.1.0/24; }
=WITH_OUTDIR=
=ERROR=
panic: open raw: permission denied
=END=
