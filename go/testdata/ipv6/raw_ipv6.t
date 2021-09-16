
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
