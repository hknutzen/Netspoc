
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
-- raw/r1
! manual route
ip route 10.1.2.0 255.255.255.0 10.1.1.1
-- raw/x
access-list n2_in extended permit udp any4 any4 eq 123
=WARNING=
Warning: Ignoring path raw/aaa
Warning: Found unused file raw/x
=OUTPUT=
--r1.raw
! manual route
ip route 10.1.2.0 255.255.255.0 10.1.1.1
=END=


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
