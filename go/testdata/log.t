
############################################################
=TEMPL=topo
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = IOS;
 log:a = log-input;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 log:a = errors;
 log:b = debugging;
 log:c = disable;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Different log levels and devices; do / don't join ranges
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
-- r1
! [ ACL ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80 log-input
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 85 log-input
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 range 81 84
 deny ip any any
-- asa2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80 log 3
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 81 log 7
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 range 82 83 log disable
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 85 log 3
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 84
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Unknown log severity at ASA
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = ASA;
 log:a = foo;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Invalid 'log:a = foo' at router:r1 of model ASA
 Expected one of: <empty>|alerts|critical|debugging|disable|emergencies|errors|informational|notifications|warnings
=END=

############################################################
=TITLE=Only use one log value at ASA
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = ASA;
 log:a = alerts, errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Must not use multiple values for log:a in router:r1 of model ASA
=END=

############################################################
=TITLE=Unknown log severity at IOS
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = IOS;
 log:a = foo;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Invalid 'log:a = foo' at router:r1 of model IOS
 Expected one of: <empty>|log-input
=END=

############################################################
=TITLE=Unknown log severity at NX-OS
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = NX-OS;
 log:a = foo;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Unexpected 'log:a = foo' at router:r1 of model NX-OS
 Use 'log:a;' only.
=END=

############################################################
=TITLE=Unknown log values at PAN-OS
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1@v1 = {
 managed;
 model = PAN-OS;
 log:a = foo, bar;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Invalid 'log:a = foo' at router:r1@v1 of model PAN-OS
 Expected: end|setting:|start
Error: Invalid 'log:a = bar' at router:r1@v1 of model PAN-OS
 Expected: end|setting:|start
=END=

############################################################
=TITLE=Empty log value for PAN-OS
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1@v1 = {
 managed;
 model = PAN-OS;
 log:a;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Invalid 'log:a = ' at router:r1@v1 of model PAN-OS
 Expected: end|setting:|start
=END=

############################################################
=TITLE=Missing value in "setting:" for PAN-OS
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1@v1 = {
 managed;
 model = PAN-OS;
 log:a = setting:;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Must give some value after ':' in 'setting:' of log:a in router:r1@v1
=END=

############################################################
=TITLE=No logging for Linux
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
router:r1 = {
 managed;
 model = Linux;
 log:a;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=END=
=ERROR=
Error: Must not use attribute 'log:a' at router:r1 of model Linux
=END=

############################################################
=TITLE=Unknown log tag
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
-- r1
! [ ACL ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80 log-input
 permit tcp any 10.1.3.0 0.0.0.255 eq 80
 deny ip any any
-- asa2
! n2_in
access-list n2_in extended permit tcp any4 10.1.3.0 255.255.255.0 eq 80 log 7
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80 log 3
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Duplicate rules with different log tag
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
-- asa2
! n2_in
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80 log 3
access-list n2_in extended permit tcp any4 10.1.3.0 255.255.255.0 eq 80
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Local optimization with log tag
=INPUT=
[[topo]]
service:t = {
 user = network:n1, any:[network:n2];
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
}
=END=
=OUTPUT=
-- r1
! [ ACL ]
ip access-list extended n1_in
 permit tcp 10.1.1.0 0.0.0.255 10.1.3.0 0.0.0.255 eq 80 log-input
 deny ip any any
-- asa2
! n2_in
access-list n2_in extended permit tcp any4 10.1.3.0 255.255.255.0 eq 80 log 3
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=No local optimization with different log tag
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
-- asa2
! n2_in
access-list n2_in extended permit tcp any4 10.1.3.0 255.255.255.0 eq 80 log 7
access-list n2_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.3.0 255.255.255.0 eq 80 log 3
access-list n2_in extended deny ip any4 any4
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Must not join rules with and without logging into object-group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24;
 host:h1 = { ip = 10.1.2.11; }
 host:h2 = { ip = 10.1.2.12; }
 host:h3 = { ip = 10.1.2.13; }
 host:h4 = { ip = 10.1.2.14; }
}
router:asa = {
 managed;
 model = ASA;
 # Different tags with equal values get grouped.
 log:a = warnings;
 log:b = errors;
 log:c = warnings;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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
-- asa
! n1_in
object-group network g0
 network-object host 10.1.2.11
 network-object host 10.1.2.13
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 object-group g0 eq 80 log 4
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 host 10.1.2.12 eq 80 log 3
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 host 10.1.2.14 eq 80
access-list n1_in extended deny ip any4 any4
access-group n1_in in interface n1
=END=

############################################################
=TITLE=Logging at NX-OS
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:h3 = { ip = 10.1.3.10; } }
router:r1 = {
 managed;
 model = NX-OS;
 log:a;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = NX-OS;
 log:a;
 log:b;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:t = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80; log = a;
 permit src = user; dst = network:n3; prt = tcp 81; log = b;
}
=END=
=OUTPUT=
-- r1
! [ ACL ]
ip access-list n1_in
 10 permit tcp 10.1.1.0/24 10.1.3.0/24 eq 80 log
 20 permit tcp 10.1.1.0/24 10.1.3.0/24 eq 81
 30 deny ip any any
-- r2
! [ ACL ]
ip access-list n2_in
 10 deny ip any 10.1.3.2/32
 20 permit tcp 10.1.1.0/24 10.1.3.0/24 range 80 81 log
 30 deny ip any any
=END=

############################################################
=TITLE=Log deny
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 log_deny;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:t = {
 user = network:n1;
 deny src = user; dst = network:n2; prt = tcp 22;
 permit src = user; dst = network:n2; prt = tcp;
}
=END=
=OUTPUT=
-- r1
! [ ACL ]
ip access-list extended n1_in
 deny ip any host 10.1.2.1 log
 deny tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255 eq 22 log
 permit tcp 10.1.1.0 0.0.0.255 10.1.2.0 0.0.0.255
 deny ip any any log
=END=

############################################################
=TITLE=log_default at ASA
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 log_default = alerts;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:t = {
 user = network:n1;
 deny src = user; dst = network:n2; prt = tcp 22;
 permit src = user; dst = network:n2; prt = tcp;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended deny tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 22 log 1
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 log 1
access-list n1_in extended deny ip any4 any4 log 1
access-group n1_in in interface n1
=END=

############################################################
=TITLE=log_deny overwrites log_default
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 log_default = warnings;
 log_deny = critical;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:t = {
 user = network:n1;
 deny src = user; dst = network:n2; prt = tcp 22;
 permit src = user; dst = network:n2; prt = tcp;
}
=OUTPUT=
-- r1
! n1_in
access-list n1_in extended deny tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 eq 22 log 4
access-list n1_in extended permit tcp 10.1.1.0 255.255.255.0 10.1.2.0 255.255.255.0 log 4
access-list n1_in extended deny ip any4 any4 log 2
access-group n1_in in interface n1
=END=


############################################################
=TITLE=Unsupported log deny
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = Linux;
 log_deny;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=ERROR=
Error: Must not use attribute 'log_deny' at router:r1 of model Linux
=END=

############################################################
