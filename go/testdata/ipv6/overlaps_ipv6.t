
############################################################
# Common topology for multiple tests
=TEMPL=topo
network:n1 = { ip = ::a01:100/120; }
router:filter = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = {
 ip = ::a01:200/120;
 host:h1 = { ip = ::a01:20a; }
 host:h2 = { ip = ::a01:20b; }
}
=END=

############################################################
=TITLE=Warn on duplicate and redundant rule
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test1a = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test1b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
=SHOW_DIAG=
=WARNING=
Warning: Duplicate rules in service:test1b and service:test1a:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
Warning: Redundant rules in service:test1a compared to service:test2:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1a
< permit src=host:h1; dst=network:n1; prt=tcp; of service:test2
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
=OUTPUT=
--ipv6/filter
access-list n2_in extended permit tcp host ::a01:20a ::a01:100/120
access-list n2_in extended deny ip any6 any6
access-group n2_in in interface n2
=END=

############################################################
=TITLE=Suppressed warning
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test1a = {
 overlaps = service:test2;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test1b = {
 # Mark second of duplicate services
 overlaps = service:test1a;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
service:test3a = {
 # Mark first of duplicate services
 overlaps = service:test3b;
 user = host:h1;
 permit src = user; dst = network:n1; prt = udp 123;
}
service:test3b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = udp 123;
}
=SHOW_DIAG=
=WARNING=
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=udp 123; of service:test3b
=END=

############################################################
=TITLE=Reference unknown service
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test1a = {
 overlaps = service:test2, serv:abc;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
=ERROR=
Warning: Unknown 'service:test2' in attribute 'overlaps' of service:test1a
Error: Expected type 'service:' in attribute 'overlaps' of service:test1a
=END=

############################################################
=TITLE=Suppressed warning by protocol modifier
=PARAMS=--ipv6
=INPUT=
[[topo]]
protocol:ssh = tcp 22, overlaps;
protocol:tcp = tcp, overlaps;
service:test1a = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:ssh;
}
service:test1b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:ssh;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:tcp;
}
=SHOW_DIAG=
=WARNING=
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=protocol:ssh; of service:test1b
=END=

############################################################
=TITLE=Single protocol won't suppress warning
=PARAMS=--ipv6
=INPUT=
[[topo]]
protocol:ssh = tcp 22, overlaps;
service:test1a = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = protocol:ssh;
}
service:test1b = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
=SHOW_DIAG=
=WARNING=
Warning: Duplicate rules in service:test1b and service:test1a:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
Warning: Redundant rules in service:test1a compared to service:test2:
  permit src=host:h1; dst=network:n1; prt=protocol:ssh; of service:test1a
< permit src=host:h1; dst=network:n1; prt=tcp; of service:test2
DIAG: Removed duplicate permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test1b
=END=

############################################################
=TITLE=Show useless overlap, if warning was suppressed by modifier
=PARAMS=--ipv6
=INPUT=
[[topo]]
protocol:Ping_Net = icmpv6 8, src_net, dst_net, overlaps;
service:s1 = {
 overlaps = service:s2;
 user = network:n1;
 permit src = user;
        dst = host:h1;
        prt = tcp 80, protocol:Ping_Net;
}
service:s2 = {
 user = network:n1;
 permit src = user;
	dst = host:h2;
	prt = tcp 80, protocol:Ping_Net;
}
=SHOW_DIAG=
=WARNING=
Warning: Useless 'overlaps = service:s2' at service:s1
DIAG: Removed duplicate permit src=network:n1; dst=network:n2; prt=protocol:Ping_Net; of service:s2
=END=

############################################################
=TITLE=Don't show useless overlap for disabled service
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 overlaps = service:s2;
 disable_at = 2000-01-01;
 user = network:n1;
 permit src = user;
        dst = host:h1;
        prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user;
	dst = host:h1;
	prt = tcp 81;
}
=SHOW_DIAG=
=WARNING=NONE

############################################################
=TITLE=Multiple larger rules, one suppressed
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:test = {
 overlaps = service:test2;
 user = host:h1, network:n2;
 permit src = user; dst = network:n1; prt = tcp 22;
}
service:test2 = {
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp;
}
=WARNING=
Warning: Redundant rules in service:test compared to service:test:
  permit src=host:h1; dst=network:n1; prt=tcp 22; of service:test
< permit src=network:n2; dst=network:n1; prt=tcp 22; of service:test
=END=

############################################################
=TITLE=Inherited overlaps = restrict, enable, ok
=PARAMS=--ipv6
=INPUT=
owner:o8 = { admins = a8@example.com; overlaps = ok; }
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
network:n5 = { ip = ::a01:500/120; }
network:n6 = { ip = ::a01:600/121; }
network:n7 = { ip = ::a01:700/120; overlaps = ok; }
network:n8 = {
 ip = ::a01:800/120;
 overlaps = restrict;
 host:h8 = { ip = ::a01:80a; owner = o8; }
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n5 = { ip = ::a01:501; hardware = n5; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = ::a01:302; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
router:r4 = {
 managed;
 model = ASA;
 interface:n5 = { ip = ::a01:502; hardware = n5; }
 interface:n6 = { ip = ::a01:601; hardware = n6; }
 interface:n7 = { ip = ::a01:701; hardware = n7; }
 interface:n8 = { ip = ::a01:801; hardware = n8; }
}
area:all = { anchor = network:n1; overlaps = restrict; }
area:a1234 = { inclusive_border = interface:r2.n5; overlaps = enable; }
area:a1 = { border = interface:r1.n1; overlaps = ok; }
area:a34 = { border = interface:r2.n3; overlaps = ok; }
area:a4 = { border = interface:r3.n4; overlaps = restrict; }
any:a6 = { ip = ::a01:600/120; link = network:n6; overlaps = enable; }
any:a8 = { link = network:n8; overlaps = enable; }
# n1: restrict, enable, ok
# n2: restrict, enable
# n3: restrict, enable, ok
# n4: restrict, enable, ok, restrict
# n5: restrict
# n6: restrict, enable
# n7: restrict, network:ok
# n8: restrict, enable, network:restrict
# h8: restrict, enable, network:restrict, owner:ok

# ok -> ok: no warning
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:n3; prt = tcp;
}
# restrict -> enable: is like enable -> enable, suppressable warning
service:s3 = {
 overlaps = service:s4;
 user = interface:r4.n5;
 permit src = user; dst = network:n6; prt = tcp 80;
}
service:s4 = {
 user = interface:r4.n5;
 permit src = user; dst = network:n6; prt = tcp;
}
# restrict -> restrict: can't suppress warning
service:s5 = {
 overlaps = service:s6;
 user = network:n4;
 permit src = user; dst = network:n5; prt = tcp 80;
}
service:s6 = {
 user = network:n4;
 permit src = user; dst = network:n5; prt = tcp;
}
# ok -> restrict: is like ok -> ok
service:s7 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s8 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = tcp;
}
# enable -> restrict: is like enable -> enable
service:s9 = {
 overlaps = service:s10;
 user = network:n2;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s10 = {
 user = network:n2;
 permit src = user; dst = network:n4; prt = tcp;
}
# ok -> network:ok: no warning
service:s11 = {
 user = network:n3;
 permit src = user; dst = network:n7; prt = tcp 80;
}
service:s12 = {
 user = network:n3;
 permit src = user; dst = network:n7; prt = tcp;
}
# network:restrict -> ok: no warning
service:s13 = {
 user = network:n8;
 permit src = user; dst = network:n3; prt = tcp 80;
}
service:s14 = {
 user = network:n8;
 permit src = user; dst = network:n3; prt = tcp;
}
# network:restrict -> restrict: can't suppress warning
service:s15 = {
 overlaps = service:s16;
 user = network:n8;
 permit src = user; dst = network:n4; prt = tcp 80;
}
service:s16 = {
 user = network:n8;
 permit src = user; dst = network:n4; prt = tcp;
}
# ok -> owner:ok: no warning
service:s17 = {
 user = network:n3;
 permit src = user; dst = host:h8; prt = tcp 80;
}
service:s18 = {
 user = network:n3;
 permit src = user; dst = host:h8; prt = tcp;
}
=WARNING=
Warning: Attribute 'overlaps' is blocked at service:s15
Warning: Attribute 'overlaps' is blocked at service:s5
Warning: Redundant rules in service:s15 compared to service:s16:
  permit src=network:n8; dst=network:n4; prt=tcp 80; of service:s15
< permit src=network:n8; dst=network:n4; prt=tcp; of service:s16
Warning: Redundant rules in service:s5 compared to service:s6:
  permit src=network:n4; dst=network:n5; prt=tcp 80; of service:s5
< permit src=network:n4; dst=network:n5; prt=tcp; of service:s6
=END=

############################################################
