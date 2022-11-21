=TEMPL=topo
network:n1 = {
 ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a;}
 host:h11 = { ip = ::a01:10b;}
 host:h12 = { ip = ::a01:10c;}
 host:h13 = { ip = ::a01:10d;}
 host:h14 = { ip = ::a01:10e;}
}
router:r1 = {
 model = ASA;
 managed;
 log:l1 = disable;
 log:l2 = debugging;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }
=END=

############################################################
=TITLE=Simple duplicate service
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules, but different order in protocols.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80, tcp 81;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 81, tcp 80;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules, but different order in objects.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 permit src = user; dst = host:h10, host:h11; prt = tcp 80, tcp 81;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = host:h11, host:h10; prt = tcp 80, tcp 81;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules, but different order in log attribute
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80; log = l1, l2;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80; log = l2, l1;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with automatic group.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = any:[ip=::a00:0/104 & network:n2]; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = any:[ip=::a00:0/104 & network:n2]; prt = tcp 80;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with changed order in automatic group.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:[host:h10, host:h11]; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = network:[host:h11, host:h10]; prt = tcp 80;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with changed order in intersection.
=PARAMS=--ipv6
=INPUT=
[[topo]]
group:g1 = host:h11;
group:g2 = host:h11, host:h12;
service:s1 = {
 user = network:n2;
 permit src = user; dst = !group:g1 & group:g2; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = group:g2 & !group:g1; prt = tcp 80;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Compare reversed rules, src = user
=PARAMS=--ipv6
=INPUT=
[[topo]]
protocol:reversed = udp 514, reversed;
service:s1 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = protocol:reversed;
}
service:s2 = {
 user = host:h12;
 permit src = user; dst = network:n2; prt = protocol:reversed;
}
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Compare reversed rules, dst = user
=PARAMS=--ipv6
=INPUT=
[[topo]]
protocol:ntp = udp 123;
protocol:ntp-reversed = udp 123, reversed;
protocolgroup:ntp = protocol:ntp, protocol:ntp-reversed;
service:s1 = {
 user = host:h11;
 permit src = network:n2; dst = user; prt = protocolgroup:ntp;
}
service:s2 = {
 user = host:h12;
 permit src = network:n2; dst = user; prt = protocolgroup:ntp;
}
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Different action
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 deny   src = user;
        dst = host:h10, host:h11;
        prt = tcp 90;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user;
        dst = host:h10, host:h11;
        prt = tcp 90;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Many elements are equal, but not all.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = host:h10, host:h11, host:h12;
        prt = tcp 90, tcp 99;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user;
        dst = host:h10, host:h11;
        prt = tcp 90, tcp 99;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Many protocols are equal, but not all (1)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = host:h10, host:h11;
        prt = tcp 90, tcp 99;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user;
        dst = host:h10, host:h11;
        prt = tcp 80, tcp 90, tcp 99;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Many protocols are equal, but not all (2)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = host:h10, host:h11;
        prt = tcp 80, tcp 90, tcp 99;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user;
        dst = host:h10, host:h11;
        prt = tcp 81, tcp 90, tcp 99;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Changed complement.
=PARAMS=--ipv6
=INPUT=
[[topo]]
group:g1 = host:h10, host:h11, host:h12;
group:g2 = host:h11;
service:s1 = {
 user = network:n2;
 permit src = user; dst = group:g1 &! group:g2; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = group:g1 & group:g2; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Changed order of equal rules (1)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 deny   src = host:h10; dst = user; prt = tcp 22;
 deny   src = host:h10; dst = user; prt = tcp 22, tcp 23;
 permit src = network:n1; dst = user; prt = tcp 22;
 permit src = user; dst = network:n1; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 deny   src = host:h10; dst = user; prt = tcp 22, tcp 23;
 permit src = user; dst = network:n1; prt = tcp 80;
 permit src = network:n1; dst = user; prt = tcp 22;
 deny   src = host:h10; dst = user; prt = tcp 22;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn --check_duplicate_rules=0

############################################################
=TITLE=Changed order of equal rules (2)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 permit src = network:n1; dst = user; prt = tcp 22;
 permit src = network:n1; dst = user; prt = tcp 23;
 permit src = network:n1; dst = user; prt = tcp 25;

}
service:s2 = {
 user = interface:r1.n1;
 permit src = network:n1; dst = user; prt = tcp 25;
 permit src = network:n1; dst = user; prt = tcp 23;
 permit src = network:n1; dst = user; prt = tcp 22;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Similar service, but changed src/dst
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal expanded rules, but from different groups
=PARAMS=--ipv6
=INPUT=
[[topo]]
group:g1 = network:n2;
service:s1 = {
 user = host:h10;
 permit src = user; dst = group:g1; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules, but different log attribute
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80; log = l1, l2;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80; log = l1;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules, but different attribute disable_at
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 disable_at = 2999-01-02;
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 disable_at = 2999-12-06;
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with different IP in automatic group.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = any:[ip=::a00:0/104 & network:n2]; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = any:[ip=::a01:0/112 & network:n2]; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with equal IP but different objects in automatic group.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = any:[ip=::a00:0/104 & interface:r1.n2]; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = any:[ip=::a00:0/104 & network:n2]; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with different 'managed' attribute in automatic group.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = interface:[managed & network:n2].[all]; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = interface:[network:n2].[all]; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with different selector in automatic group.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = interface:[network:n2].[all]; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = interface:[network:n2].[auto]; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with textual different elements in automatic group.
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = network:n2;
 permit src = user; dst = network:[host:h11]; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = network:[host:h10]; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Suppressed warning (1)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 identical_body = service:s3;
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s3 = {
 identical_body = service:s1;
 user = host:h12;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Suppressed warning (2)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s3 = {
 identical_body = service:s2, service:s1;
 user = host:h12;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Suppressed warning (3)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 identical_body = service:s2, service:s3;
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 identical_body = service:s1, service:s3;
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s3 = {
 identical_body = service:s2, service:s1;
 user = host:h12;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Incorrect suppressed warning
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 identical_body = service:s3;
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 identical_body = service:s3;
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s3 = {
 user = host:h12;
 permit src = user; dst = network:n2; prt = tcp 81;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
Warning: service:s1 has useless service:s3 in attribute 'identical_body'
Warning: service:s2 has useless service:s3 in attribute 'identical_body'
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Partially suppressed warning
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s3 = {
 identical_body = service:s2;
 user = host:h12;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
 - service:s3
=END=
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Useless attribute 'identical_body' (1)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 identical_body = service:s2, service:s3;
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s3 = {
 identical_body = service:s2, service:s1;
 user = host:h12;
 permit src = user; dst = network:n2; prt = tcp 81;
}
=END=
=WARNING=
Warning: Useless attribute 'identical_body' in service:s3
Warning: service:s1 has useless service:s3 in attribute 'identical_body'
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Useless attribute 'identical_body' (2)
=PARAMS=--ipv6
=INPUT=
[[topo]]
service:s1 = {
 identical_body = service:s1, service:s2; # s1 ok
 user = host:h10;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = network:n2; prt = tcp 80;
}
service:s3 = {
 identical_body = service:s1, service:s2, service:s3; # s3 not ok
 user = host:h12;
 permit src = user; dst = network:n2; prt = tcp 81;
}
=END=
=WARNING=
Warning: Useless attribute 'identical_body' in service:s3
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Useless attribute 'identical_body' (3)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; identical_body = restrict; }

service:s1 = {
 identical_body = service:s2;
 user = network:n1, network:n2;
 permit src = user; dst = user; prt = ip;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: Useless attribute 'identical_body' in service:s1
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Suppressed warning from objects in rules.
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 identical_body = ok;
 host:h10 = { ip = ::a01:10a;}
 host:h11 = { ip = ::a01:10b;}
 host:h12 = { ip = ::a01:10c;}
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
}
network:n2 = { ip = ::a01:200/120; }

service:s1 = {
 user = network:n2;
 permit src = user; dst = host:h10, host:h11; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = host:h10, host:h11; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Non suppressed warning from objects in rules.
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
network:n2 = { ip = ::a01:200/120; identical_body = ok; }
network:n3 = { ip = ::a01:300/120; identical_body = ok; }
network:n4 = { ip = ::a01:400/120; }

service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2, network:n3, network:n4; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2, network:n3, network:n4; prt = tcp 80;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Restricted use of identical_body (1)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; identical_body = restrict; }

service:s1 = {
 identical_body = service:s2;
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
=END=
=WARNING=
Warning: Attribute 'identical_body' is blocked at service:s1
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Restricted use of identical_body (2)
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; identical_body = restrict; }

service:s1 = {
 identical_body = service:s2;
 user = network:n1;
 permit src = user; dst = network:n2, network:n3; prt = tcp 80;
}
service:s2 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=WARNING=
Warning: Attribute 'identical_body' is blocked at service:s1
Warning: Useless attribute 'identical_body' in service:s1
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Auto interface expands to multiple rules
=PARAMS=--ipv6
=INPUT=
network:n1 = {
 ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a;}
 host:h11 = { ip = ::a01:10b;}
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = {ip = ::a01:101;hardware = n1;}
 interface:n2 = {ip = ::a01:201;hardware = n2;}
}
network:n2 = {
 ip = ::a01:200/120;
 host:h20 = { ip = ::a01:214;}
 host:h21 = { ip = ::a01:215;}
}
service:s1 = {
 user = host:h10, host:h20;
 permit src = user; dst = interface:r1.[auto]; prt = udp 161;
 permit src = user; dst = interface:r1.[auto]; prt = udp 162;
}
service:s2 = {
 user = host:h11, host:h21;
 permit src = user; dst = interface:r1.[auto]; prt = udp 162;
 permit src = user; dst = interface:r1.[auto]; prt = udp 161;
}
=END=
=WARNING=
Warning: These services have identical rule definitions.
 A single service should be created instead, with merged users.
 - service:s1
 - service:s2
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Ignore services with user - user rule
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120; }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120; }
network:n4 = { ip = ::a01:400/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
 interface:n4 = { ip = ::a01:401; hardware = n4; }
}
service:s1 = {
 user = network:n1, network:n2, network:n3;
 permit src = user; dst = user; prt = ip;
}
service:s2 = {
 user = network:n2, network:n3, network:n4;
 permit src = user; dst = user; prt = ip;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn --check_duplicate_rules=0

############################################################
=TITLE=Equal rules, but slightly different interfaces
=PARAMS=--ipv6
=INPUT=
network:n1 = { ip = ::a01:100/120;
 host:h10 = { ip = ::a01:10a;}
 host:h11 = { ip = ::a01:10b;}
 host:h12 = { ip = ::a01:10c;}
 host:h13 = { ip = ::a01:10d;} }
network:n2 = { ip = ::a01:200/120; }
network:n3 = { ip = ::a01:300/120;
 host:h30 = { ip = ::a01:31e;}
 host:h33 = { ip = ::a01:321;} }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = ::a01:101; hardware = n1; }
 interface:n2 = { ip = ::a01:201, ::a01:202; hardware = n2; }
 interface:n3 = { ip = ::a01:301; hardware = n3; }
}
router:u = {
 interface:n2 = { ip = ::a01:209; }
}
# Add two unchanged elements in front of dst list and two protocols,
# because hashing is done on first two elements and last two protocols.
service:s1 = {
 user = host:h10;
 permit src = user;
        dst = host:h30, host:h33, interface:r1.n1;
        prt = tcp 80, tcp 90;
}
service:s2 = {
 user = host:h11;
 permit src = user;
        dst = host:h30, host:h33, interface:r1.n2;
        prt = tcp 80, tcp 90;
}
service:s3 = {
 user = host:h12;
 permit src = user;
        dst = host:h30, host:h33, interface:r1.n2.2;
        prt = tcp 80, tcp 90;
}
service:s4 = {
 user = host:h13;
 permit src = user;
        dst = host:h30, host:h33, interface:u.n2;
        prt = tcp 80, tcp 90;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn
