=TEMPL=topo
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10;}
 host:h11 = { ip = 10.1.1.11;}
 host:h12 = { ip = 10.1.1.12;}
 host:h13 = { ip = 10.1.1.13;}
 host:h14 = { ip = 10.1.1.14;}
}
router:r1 = {
 model = ASA;
 managed;
 log:l1 = disable;
 log:l2 = debugging;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
=END=

############################################################
=TITLE=Simple duplicate service
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
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = any:[ip=10.0.0.0/8 & network:n2]; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = any:[ip=10.0.0.0/8 & network:n2]; prt = tcp 80;
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
=TITLE=Many elements are equal, but not all.
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
=TITLE=Equal rules with different IP in automatic group.
=INPUT=
[[topo]]
service:s1 = {
 user = host:h10;
 permit src = user; dst = any:[ip=10.0.0.0/8 & network:n2]; prt = tcp 80;
}
service:s2 = {
 user = host:h11;
 permit src = user; dst = any:[ip=10.1.0.0/16 & network:n2]; prt = tcp 80;
}
=END=
=WARNING=NONE
=OPTIONS=--check_identical_services=warn

############################################################
=TITLE=Equal rules with different 'managed' attribute in automatic group.
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
=TITLE=Equal rules with textual different elements in automatic group.
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; identical_body = restrict; }

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
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 identical_body = ok;
 host:h10 = { ip = 10.1.1.10;}
 host:h11 = { ip = 10.1.1.11;}
 host:h12 = { ip = 10.1.1.12;}
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }

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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
network:n2 = { ip = 10.1.2.0/24; identical_body = ok; }
network:n3 = { ip = 10.1.3.0/24; identical_body = ok; }
network:n4 = { ip = 10.1.4.0/24; }

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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; identical_body = restrict; }

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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; identical_body = restrict; }

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
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10;}
 host:h11 = { ip = 10.1.1.11;}
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = {ip = 10.1.1.1;hardware = n1;}
 interface:n2 = {ip = 10.1.2.1;hardware = n2;}
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:h20 = { ip = 10.1.2.20;}
 host:h21 = { ip = 10.1.2.21;}
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
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
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
