=TEMPL=topo
network:n1 = { ip6 = ::a01:100/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
network:n2 = { ip6 = ::a01:200/120; }
=TEMPL=disabled_service
service:s = {
 disable_at = {{DATE .}};
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=TEMPL=output
--ipv6/r1
! n1_in
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Service timed out for 365 days
=INPUT=
[[topo]]
[[disabled_service -365]]
=OUTPUT=
[[output]]
=END=

=TITLE=Service timed out for 30 days
=INPUT=
[[topo]]
[[disabled_service -30]]
=OUTPUT=
[[output]]
=END=

=TITLE=Service timed out for 1 day
=INPUT=
[[topo]]
[[disabled_service -1]]
=OUTPUT=
[[output]]
=END=

=TITLE=Service timed out today
=INPUT=
[[topo]]
[[disabled_service -0]]
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
=INPUT=
[[topo]]
[[disabled_service 1]]
=OUTPUT=
[[output]]
=END=

=TITLE=Service times out in 10 days
=INPUT=
[[topo]]
[[disabled_service 10]]
=OUTPUT=
[[output]]
=END=

=TITLE=Service times out in 1000 days
=INPUT=
[[topo]]
[[disabled_service 1000]]
=OUTPUT=
[[output]]
=END=

############################################################
=TITLE=Invalid date format at service
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
