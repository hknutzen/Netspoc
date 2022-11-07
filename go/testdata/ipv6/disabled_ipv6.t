
############################################################
=TITLE=Service timed out for 365 days
=TEMPL=topo
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
=END=
=TEMPL=output
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=DATE=-365
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = [[DATE]];
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

=TITLE=Service timed out for 30 days
=DATE=-30
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = [[DATE]];
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

=TITLE=Service timed out for 1 day
=DATE=-1
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = [[DATE]];
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

=TITLE=Service timed out today
=DATE=-0
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = [[DATE]];
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Service times out tomorrow
=TEMPL=output
--ipv6/r1
! n1_in
access-list n1_in extended permit tcp ::a01:100/120 ::a01:200/120 eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=
=DATE=1
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = [[DATE]];
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

=TITLE=Service times out in 10 days
=DATE=10
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = [[DATE]];
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

=TITLE=Service times out in 1000 days
=DATE=1000
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = [[DATE]];
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Invalid date format at service
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = 1-Jan-2020;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Date expected as yyyy-mm-dd in 'disable_at' of service:s
=END=

############################################################
=TITLE=Invalid date at service
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s = {
 disable_at = 2031-31-31;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=ERROR=
Error: Invalid date in 'disable_at' of service:s: parsing time "2031-31-31": month out of range
=END=

############################################################
