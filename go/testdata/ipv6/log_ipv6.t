
############################################################
=TEMPL=topo
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:30a; } }
router:r1 = {
 managed;
 model = IOS;
 log:a = log-input;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 log:a = errors;
 log:b = debugging;
 log:c = disable;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
=END=

############################################################
=TITLE=Different log levels and devices; do / don't join ranges
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
 permit src = user; dst = network:n3; prt = tcp 81; log = b;
 permit src = user; dst = network:n3; prt = tcp 82; log = c;
 permit src = user; dst = network:n3; prt = tcp 83; log = c;
 permit src = user; dst = network:n3; prt = tcp 84;
 permit src = user; dst = network:n3; prt = tcp 85; log = a, b, c;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 ::a01:300/120 eq 80 log-input
 permit tcp ::a01:100/120 ::a01:300/120 eq 85 log-input
 permit tcp ::a01:100/120 ::a01:300/120 range 81 84
 deny ipv6 any any
-- ipv6/asa2
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 80 log 3
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 81 log 7
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 range 82 83 log disable
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 85 log 3
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 84
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Unknown log severity at ASA
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
router:r1 = {
 managed;
 model = ASA;
 log:a = foo;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=END=
=ERROR=
Error: Invalid 'log:a = foo' at router:r1 of model ASA
 Expected one of: alerts|critical|debugging|disable|emergencies|errors|informational|notifications|warnings
=END=

############################################################
=TITLE=Unknown log severity at IOS
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
router:r1 = {
 managed;
 model = IOS;
 log:a = foo;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=END=
=ERROR=
Error: Invalid 'log:a = foo' at router:r1 of model IOS
 Expected one of: log-input
=END=

############################################################
=TITLE=Unknown log severity at NX-OS
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
router:r1 = {
 managed;
 model = NX-OS;
 log:a = foo;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=END=
=ERROR=
Error: Unexpected 'log:a = foo' at router:r1 of model NX-OS
 Use 'log:a;' only.
=END=

############################################################
=TITLE=No logging for Linux
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
router:r1 = {
 managed;
 model = Linux;
 log:a;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
}
=END=
=ERROR=
Error: Must not use attribute 'log:a' at router:r1 of model Linux
=END=

############################################################
=TITLE=Unknown log tag
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = d, e/f;
}
=END=
=WARNING=
Warning: Ignoring unknown 'd' in log of service:t
Warning: Ignoring unknown 'e/f' in log of service:t
=END=

############################################################
=TITLE=Duplicate log tag
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = b,a,a,c,b,c,b;
}
=END=
=WARNING=
Warning: Duplicate 'a' in log of service:t
Warning: Duplicate 'b' in log of service:t
Warning: Duplicate 'b' in log of service:t
Warning: Duplicate 'c' in log of service:t
=END=

############################################################
=TITLE=Global optimization with log tag
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
service:t2 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
=END=
=WARNING=
Warning: Redundant rules in service:t1 compared to service:t2:
  permit src=network:n1; dst=network:n3; prt=tcp 80; log=a; of service:t1
< permit src=any:[network:n1]; dst=network:n3; prt=tcp 80; log=a; of service:t2
=END=

############################################################
=TITLE=No global optimization with different log tag
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
service:t2 = {
 user = any:[network:n1], any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = b;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 ::a01:300/120 eq 80 log-input
 permit tcp any ::a01:300/120 eq 80
 deny ipv6 any any
-- ipv6/asa2
! n2_in
access-list n2_in extended permit tcp any6 ::a01:300/120 eq 80 log 7
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 80 log 3
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Duplicate rules with different log tag
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 overlaps = service:s2;
 user = network:n2;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
=END=
=ERROR=
Error: Duplicate rules must have identical log attribute:
 permit src=network:n2; dst=network:n3; prt=tcp 80; of service:s1
 permit src=network:n2; dst=network:n3; prt=tcp 80; log=a; of service:s2
=END=

############################################################
=TITLE=Place line with logging first
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
=END=
=OUTPUT=
-- ipv6/asa2
! n2_in
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 80 log 3
access-list n2_in extended permit tcp any6 ::a01:300/120 eq 80
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Local optimization with log tag
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:t = {
 user = network:n1, any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 permit tcp ::a01:100/120 ::a01:300/120 eq 80 log-input
 deny ipv6 any any
-- ipv6/asa2
! n2_in
access-list n2_in extended permit tcp any6 ::a01:300/120 eq 80 log 3
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=No local optimization with different log tag
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
service:t2 = {
 user = any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = b;
}
=END=
=OUTPUT=
-- ipv6/asa2
! n2_in
access-list n2_in extended permit tcp any6 ::a01:300/120 eq 80 log 7
access-list n2_in extended permit tcp ::a01:100/120 ::a01:300/120 eq 80 log 3
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not join rules with and without logging into object-group
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20b; }
 host:h2 = { ip = ::a01:20c; }
 host:h3 = { ip = ::a01:20d; }
 host:h4 = { ip = ::a01:20e; }
}
router:asa = {
 managed;
 model = ASA;
 # Different tags with equal values get grouped.
 log:a = warnings;
 log:b = errors;
 log:c = warnings;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:t = {
 user = network:n1;
 permit src = user; dst = host:h1; prt = tcp 80; log = a;
 permit src = user; dst = host:h2; prt = tcp 80; log = b;
 permit src = user; dst = host:h3; prt = tcp 80; log = c;
 permit src = user; dst = host:h4; prt = tcp 80;
}
=END=
=OUTPUT=
-- ipv6/asa
! n1_in
object-group network v6g0
 network-object host ::a01:20b
 network-object host ::a01:20d
access-list n1_in extended permit tcp ::a01:100/120 object-group v6g0 eq 80 log 4
access-list n1_in extended permit tcp ::a01:100/120 host ::a01:20c eq 80 log 3
access-list n1_in extended permit tcp ::a01:100/120 host ::a01:20e eq 80
access-list n1_in extended deny ip any6 any6
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Logging at NX-OS
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; host:h3 = { ip = ::a01:30a; } }
router:r1 = {
 managed;
 model = NX-OS;
 log:a;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = NX-OS;
 log:a;
 log:b;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:302; hardware = n3; }
}
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
 permit src = user; dst = network:n3; prt = tcp 81; log = b;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 10 permit tcp ::a01:100/120 ::a01:300/120 eq 80 log
 20 permit tcp ::a01:100/120 ::a01:300/120 eq 81
 30 deny ip any any
-- ipv6/r2
! [ ACL ]
ipv6 access-list n2_in
 10 deny ip any ::a01:302/128
 20 permit tcp ::a01:100/120 ::a01:300/120 range 80 81 log
 30 deny ip any any
=END=

############################################################
=TITLE=Log deny
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 model = IOS;
 log_deny;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
service:t = {
 user = network:n1;
 deny src = user; dst = network:n2; prt = tcp 22;
 permit src = user; dst = network:n2; prt = tcp;
}
=END=
=OUTPUT=
-- ipv6/r1
! [ ACL ]
ipv6 access-list n1_in
 deny ipv6 any host ::a01:201 log
 deny tcp ::a01:100/120 ::a01:200/120 eq 22 log
 permit tcp ::a01:100/120 ::a01:200/120
 deny ipv6 any any log
=END=

############################################################
=TITLE=Unsupported log deny
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; host:h1 = { ip = ::a01:10a; } }
network:n2 = { ip = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 log_deny;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
=ERROR=
Error: Must not use attribute 'log_deny' at router:r1 of model ASA
=END=

############################################################
