############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR [service:name ...]
  -o, --owner   Keep referenced owners
  -q, --quiet   Don't print progress messages
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR [service:name ...]
  -o, --owner   Keep referenced owners
  -q, --quiet   Don't print progress messages
=END=

############################################################
=TITLE=Unknown option
=INPUT=#
=PARAMS=-x
=ERROR=
Error: unknown shorthand flag: 'x' in -x
=END=

############################################################
=TITLE=Unknown service
=INPUT=#
=PARAMS=other_service
=ERROR=
Warning: Ignoring file 'INPUT' without any content
Error: Unknown service:other_service
=END=

=TEMPL=topo
owner:o2 = { admins = a2@example.com; }
network:n1 = { ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; nat:a2 = { ip = 10.9.8.0/24; } }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; nat_out = a2; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; owner = o2; }
 interface:n3;
}
=END=

############################################################
=TITLE=Simple service, remove all hosts
=INPUT=
[[topo]]
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = ip;
}
=END=

############################################################
=TITLE=Select service on command line, ignore disabled
=INPUT=
[[topo]]
service:s1 = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp 80;
}
service:s2 = {
    user = host:h10;
    permit src = user; dst = network:n2; prt = tcp 81;
}
service:s3= {
    disabled;
    user = host:h10;
    permit src = user; dst = network:n2; prt = tcp 82;
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s2 = {
 user = host:h10;
 permit src = user;
        dst = network:n2;
        prt = tcp 81;
}
=PARAMS=s2 service:s3

############################################################
=TITLE=Unknown service selected
=INPUT=
[[topo]]
=ERROR=
Error: Unknown service:s1
=PARAMS=service:s1

############################################################
=TITLE=Simple service, remove one host
=INPUT=
[[topo]]
service:test = {
    user = host:h11, host:h12;
    permit src = user; dst = network:n2; prt = ip;
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = host:h11,
        host:h12,
        ;
 permit src = user;
        dst = network:n2;
        prt = ip;
}
=END=

############################################################
=TITLE=Simple service, remove network and interface
=INPUT=
[[topo]]
service:test = {
 user = network:n1;
 permit src = user; dst = interface:asa1.n1; prt = ip;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = interface:asa1.n1;
        prt = ip;
}
=END=

############################################################
=TITLE=Simple service, retain interface and attached network
=INPUT=
[[topo]]
service:test = {
    user = network:n2;
    permit src = user; dst = interface:asa1.n1; prt = ip;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = interface:asa1.n1;
        prt = ip;
}
=END=

############################################################
=TITLE=User in src and dst
=INPUT=
[[topo]]
service:test = {
 user = interface:asa1.[all];
 permit src = network:[user]; dst = user; prt = icmp 8;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = interface:asa1.[all];
 permit src = network:[user];
        dst = user;
        prt = icmp 8;
}
=END=

############################################################
=TITLE=Auto interface at unmanaged router
=INPUT=
[[topo]]
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:asa2.[auto];
        prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:asa2.[auto];
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Remove unused protocolgroup
=INPUT=
[[topo]]
protocol:www = tcp 80;
protocolgroup:g1 = tcp 22, tcp 23;
protocolgroup:g2 = protocol:www, tcp 443;
service:test = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = protocolgroup:g2;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
protocol:www = tcp 80;
protocolgroup:g2 =
 protocol:www,
 tcp 443,
;
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocolgroup:g2;
}
=END=

############################################################
=TITLE=Retain identical protocols with different names
=INPUT=
[[topo]]
protocol:http = tcp 80;
protocol:www  = tcp 80;
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = protocol:http;
    permit src = user; dst = network:n3; prt = protocol:www;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 nat:a2 = { ip = 10.9.8.0/24; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  nat_out = a2;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
protocol:http = tcp 80;
protocol:www = tcp 80;
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocol:http;
 permit src = user;
        dst = network:n3;
        prt = protocol:www;
}
=END=

############################################################
=TITLE=Named aggregate behind unmanaged
=INPUT=
[[topo]]
any:n3 = { link = network:n3; }
service:test = {
    user = network:n1;
    permit src = user; dst = any:n3; prt = ip;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 nat:a2 = { ip = 10.9.8.0/24; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  nat_out = a2;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
any:n3 = {
 link = network:n3;
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = any:n3;
        prt = ip;
}
=END=

############################################################
=TITLE=Unnamed aggregate behind unmanaged
=INPUT=
[[topo]]
service:test = {
    user = host:h10;
    permit src = user; dst = any:[ip=10.0.0.0/8 & network:n3]; prt = ip;
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 nat:a2 = { ip = 10.9.8.0/24; }
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  nat_out = a2;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
service:test = {
 user = host:h10;
 permit src = user;
        dst = any:[ip = 10.0.0.0/8 & network:n3];
        prt = ip;
}
=END=

############################################################
=TITLE=Ignore area with owner
=TEMPL=input
[[topo]]
area:n2 = { border = interface:asa1.n2;  owner = foo; }
owner:foo = { admins = a@example.com; }
service:test = {
    user = interface:asa2.n2;
    permit src = user; dst = network:n1; prt = tcp;
}
=INPUT=[[input]]
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; }
}
service:test = {
 user = interface:asa2.n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=END=

############################################################
=TITLE=Keep area with owner
=INPUT=[[input]]
=OUTPUT=
owner:o2 = {
 admins = a2@example.com;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; owner = o2; }
}
area:n2 = {
 owner = foo;
 border = interface:asa1.n2;
}
owner:foo = {
 admins = a@example.com;
}
service:test = {
 user = interface:asa2.n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=OPTIONS=--owner

############################################################
=TITLE=Ignore area without owner if owner is kept
=INPUT=
[[topo]]
area:n2 = { border = interface:asa1.n2; }
service:test = {
    user = interface:asa2.n2;
    permit src = user; dst = network:n1; prt = tcp;
}
=OUTPUT=
owner:o2 = {
 admins = a2@example.com;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 interface:n2 = { ip = 10.1.2.2; owner = o2; }
}
service:test = {
 user = interface:asa2.n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=OPTIONS=--owner

############################################################
=TITLE=Area with NAT
=INPUT=
[[topo]]
area:n2 = { border = interface:asa1.n2; nat:a2 = { ip = 10.9.0.0/16; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  nat_out = a2;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
area:n2 = {
 nat:a2 = { ip = 10.9.0.0/16; }
 border = interface:asa1.n2;
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=END=

############################################################
=TITLE=Area with identity NAT masks NAT of larger area
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; nat_in = a2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
area:n1 = { border = interface:asa1.n1; nat:a2 = { identity; } }
area:n1-n2 = { border = interface:asa2.n2; nat:a2 = { ip = 10.9.0.0/16; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {
  ip = 10.1.2.1;
  hardware = n2;
  nat_in = a2;
 }
}
area:n1 = {
 nat:a2 = { identity; }
 border = interface:asa1.n1;
}
area:n1-n2 = {
 nat:a2 = { ip = 10.9.0.0/16; }
 anchor = network:n2;
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=END=

############################################################
=TITLE=Ignore area with only inherited NAT
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; nat_out = a2; }
}
area:n1 = { border = interface:asa1.n1; }
area:n1-n2 = { border = interface:asa2.n2; nat:a2 = { ip = 10.9.0.0/16; } }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
area:n1-n2 = {
 nat:a2 = { ip = 10.9.0.0/16; }
 anchor = network:n2;
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=END=

############################################################
=TITLE=Supernet with identity NAT masks NAT of larger area
=TEMPL=input
area:all = {
 nat:n = { ip = 10.9.0.0/16; }
 anchor = network:n1;
}
network:n1-16 = {
 ip = 10.1.0.0/16;
 nat:n = { identity; }
}
router:r0 = {
 interface:n1-16;
 interface:n1 = { ip = 10.1.1.2; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.2.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  nat_out = n;
 }
 interface:n2 = { ip = 10.2.2.1; hardware = n2; }
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Useless aggregate
=INPUT=
[[topo]]
any:a2 = { link = network:n2; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=END=

############################################################
=TITLE=Aggregate with NAT and owner
=INPUT=
[[topo]]
any:a2 = {
 link = network:n2;
 nat:a2 = { ip = 10.9.0.0/16; }
 unknown_owner = restrict;
 multi_owner = restrict;
 owner = foo;
}
owner:foo = { admins = a@example.com; }
service:test = {
    user = network:n2;
    permit src = user; dst = network:n1; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  nat_out = a2;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
any:a2 = {
 link = network:n2;
 nat:a2 = { ip = 10.9.0.0/16; }
 unknown_owner = restrict;
 multi_owner = restrict;
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp;
}
=END=

############################################################
=TITLE=Ignore IPv6 part of topology
=TEMPL=input
-- topo
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = {ip6 = 1000::abcd:0001:0001; hardware = n3;}
 interface:n4 = {ip6 = 1000::abcd:0002:0001; hardware = n4;}
 interface:lo = {ip6 = 1000::abcd:0009:0001; hardware = lo; loopback; }
}
network:n3 = { ip6 = 1000::abcd:0001:0/112;}
network:n4 = { ip6 = 1000::abcd:0002:0/112;}
=INPUT=
[[input]]
-- rule
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
=OUTPUT=
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=END=

############################################################
=TITLE=Ignore IPv4 part of topology
=INPUT=
[[input]]
-- rule
service:test = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = ip;
}
=OUTPUT=
service:test = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = ip;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n3 = { ip6 = 1000::abcd:0001:0001; hardware = n3; }
 interface:n4 = { ip6 = 1000::abcd:0002:0001; hardware = n4; }
}
network:n3 = { ip6 = 1000::abcd:0001:0/112; }
network:n4 = { ip6 = 1000::abcd:0002:0/112; }
=END=

############################################################
=TITLE=Show IPv4 + IPv6 part of topology
=INPUT=
[[input]]
-- rule
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = ip;
}
-- ipv6/rule
service:test6 = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = ip;
}
=OUTPUT=
service:test6 = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = ip;
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = ip;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip6 = 1000::abcd:0001:0001; hardware = n3; }
 interface:n4 = { ip6 = 1000::abcd:0002:0001; hardware = n4; }
}
network:n3 = { ip6 = 1000::abcd:0001:0/112; }
network:n4 = { ip6 = 1000::abcd:0002:0/112; }
=END=

############################################################
=TITLE=Completely discard v4 part
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:u = {
 interface:n2 = { ip6 = ::a01:202; }
 interface:lo = { ip6 = ::ff1:1; loopback; }
 interface:n5 = { ip = 10.1.5.1; }
 interface:l1 = { ip = 10.9.9.1; loopback; }
}
network:n5 = { ip = 10.1.5.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:u.lo;
        prt = tcp 22;
}
=OUTPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
router:u = {
 interface:n2 = { ip6 = ::a01:202; }
 interface:lo = { ip6 = ::ff1:1; loopback; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:u.lo;
        prt = tcp 22;
}
=END=

############################################################
=TITLE=Empty automatic network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:[
         any:[ip = 10.9.9.0/24 & network:n1],
        ];
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=OUTPUT=
network:n2 = { ip = 10.1.2.0/24; }
service:test = {
 user = ;
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=END=

############################################################
=TITLE=Empty automatic network from intersection
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
area:n1-2 = {
 border = interface:r2.n2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:test = {
 user = network:[
         any:[ip = 10.9.9.0/24 & area:n1-2]
         &! any:[ip = 10.9.9.0/24 & any:[network:n2]],
        ],
        network:n2,
        ;
 permit src = user;
        dst = network:n3;
        prt = tcp;
}
=OUTPUT=
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = network:n3;
        prt = tcp;
}
=END=

############################################################
=TITLE=Remove aggregate from automatic network that leads to empty networks
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
area:n1-3 = {
 border = interface:r2.n3;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
service:test = {
 user = network:[
         any:[ip = 10.1.0.0/23 & area:n1-3]
         &! any:[ip = 10.1.0.0/23 & any:[network:n3]],
        ],
        network:n3,
        ;
 permit src = user;
        dst = network:n4;
        prt = tcp;
}
=OUTPUT=
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
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
service:test = {
 user = network:[
         any:[ip = 10.1.0.0/23 & network:n1],
         any:[ip = 10.1.0.0/23 & network:n2],
        ],
        network:n3,
        ;
 permit src = user;
        dst = network:n4;
        prt = tcp;
}
=END=

############################################################
=TITLE=Area defined by anchor, anchor outside of path
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
area:all = {
 anchor = network:n4;
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:test = {
 user = network:[
         any:[ip = 10.1.1.0/24 & area:all],
        ];
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=INPUT=[[input]]
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
area:all = {
 anchor = network:n2;
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:[
         any:[ip = 10.1.1.0/24 & area:all],
        ];
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=END=

############################################################
=TITLE=Area with border outside of path
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
area:n2-3 = {
 border = interface:asa1.n2;
 inclusive_border = interface:asa3.n4;
}
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:test = {
 has_unenforceable;
 user = network:[area:n2-3];
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=INPUT=[[input]]
=OUTPUT=
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
area:n2-3 = {
 anchor = network:n2;
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:test = {
 has_unenforceable;
 user = network:[area:n2-3];
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=END=

############################################################
=TITLE=Area with border outside of path, new anchor is subnet
=INPUT=
network:n1 = { ip = 10.1.1.16/28; }
network:n2 = { ip = 10.1.1.32/28; }
network:n3 = { ip = 10.1.1.0/24; has_subnets; }
network:n4 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.18; }
 interface:n3;
 interface:n2 = { ip = 10.1.1.33; hardware = n2; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.1.33; hardware = n2; }
 interface:n4 = { ip = 10.1.2.1;  hardware = n4; }
}
owner:o1 = { admins = o1@example.com; }
area:a1 = {
 owner = o1;
 inclusive_border = interface:r3.n4;
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.n1; prt = tcp 22;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.16/28; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
}
owner:o1 = {
 admins = o1@example.com;
}
area:a1 = {
 owner = o1;
 anchor = network:n1;
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:r1.n1;
        prt = tcp 22;
}
=OPTIONS=--owner

############################################################
=TITLE=Network in name of zone is located outside of path
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.2.3.0/24; }
network:n4 = { ip = 10.2.4.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n3 = { ip = 10.2.3.2; }
 interface:n2 = { ip = 10.1.2.2; }
}
router:r3 = {
 interface:n3;
 interface:n4;
}
service:s1 = {
 user = any:[ip = 10.1.0.0/16 & network:n4];
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Link of zone is located outside of path
# With secondary IP for test coverage
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.2.3.0/24; }
network:n4 = { ip = 10.2.4.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n3 = { ip = 10.2.3.2, 10.2.3.9; }
 interface:n2 = { ip = 10.1.2.2; }
}
router:r3 = {
 interface:n3;
 interface:n4;
}
service:s1 = {
 user = any:n4;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
any:n4 = {
 link = network:n4;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Link of zone with NAT is located outside of path
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.2.3.0/24; }
network:n4 = { ip = 10.2.4.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  nat_out = n3-4;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n3 = { ip = 10.2.3.2; }
 interface:n2 = { ip = 10.1.2.2; }
}
router:r3 = {
 interface:n3;
 interface:n4;
}
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
any:n4 = {
 link = network:n4;
 nat:n3-4 = { ip = 10.1.0.0/16; }
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Replace empty area by nothing
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
router:r3 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:un = { unnumbered; hardware = un;
 }
}
network:un = { unnumbered; }
area:a2 = { border = interface:r1.n2; }
area:a4 = { inclusive_border = interface:r3.n4; }
service:s1 = {
 user = network:[area:a2] &! network:[area:a4];
 permit src = network:n1; dst = user; prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 model = ASA;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n2;
 permit src = network:n1;
        dst = user;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Mark supernet having identity NAT
=INPUT=
any:n1 = {
 nat:N = { ip = 10.9.9.0/24; dynamic; }
 link = network:n1;
}
network:n1 = {
 ip = 10.1.1.0/24;
 nat:N = { identity; }
}
network:n1_sub = {
 ip = 10.1.1.64/26;
 subnet_of = network:n1;
}
network:n1_subsub = {
 ip = 10.1.1.96/27;
 subnet_of = network:n1_sub;
}
router:u = {
 interface:n1;
 interface:n1_sub;
 interface:n1_subsub;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_subsub = { ip = 10.1.1.97; hardware = n1; }
 interface:n2        = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1_subsub;
 permit src = network:n2;
        dst = user;
        prt = tcp 80;
}
=OUTPUT=
any:n1 = {
 nat:N = { ip = 10.9.9.0/24; dynamic; }
 link = network:n1;
}
network:n1 = {
 ip = 10.1.1.0/24;
 nat:N = { identity; }
}
network:n1_subsub = { ip = 10.1.1.96/27; }
router:u = {
 interface:n1;
 interface:n1_subsub;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1_subsub = { ip = 10.1.1.97; hardware = n1; }
 interface:n2        = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1_subsub;
 permit src = network:n2;
        dst = user;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Mark networks inside aggregate
=INPUT=
network:n0 = { ip = 10.3.0.0/24; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
network:un = { unnumbered; }
any:n1-3 = {
 ip = 10.1.0.0/16;
 link = network:un;
}
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n0;
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r2 = {
 interface:n3;
 interface:un;
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:un = { unnumbered; hardware = un; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = any:n1-3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.3.3.0/24; }
network:un = { unnumbered; }
any:n1-3 = {
 ip = 10.1.0.0/16;
 link = network:un;
}
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3;
}
router:r2 = {
 interface:n3;
 interface:un;
}
router:r3 = {
 model = IOS;
 managed;
 routing = manual;
 interface:un = { unnumbered; hardware = un; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = any:n1-3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Matching aggregate without matching network
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.1; }
}
network:n3 = { ip = 10.1.3.0/24; }
any:10_2_0_0 = {
 ip = 10.2.0.0/16;
 link = network:n3;
}
service:s1 = {
 user = any:10_2_0_0;
 permit src = network:n1;
        dst = user;
        prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Mark unmanaged part between managed routers.
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r3 = {
 model = IOS;
 managed;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Mark unmanaged at end of path
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 host:h3 = { ip = 10.1.3.10; }
}
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3;
 interface:n4 = { ip = 10.1.4.2; }
}
router:r3 = {
 interface:n4 = { ip = 10.1.4.3; }
}
group:g1 =
 host:h3,
 group:g2,
;
group:g2 =
 network:[
  interface:r3.n4,
 ],
;
service:s1 = {
 user = group:g1;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Mark 2x unmanaged at end of path
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2;
 interface:n3;
 interface:L = { ip = 10.9.9.2; loopback; }
}
router:r3 = {
 interface:n3;
 interface:L = { ip = 10.9.9.3; loopback; }
}
service:test = {
 user = interface:r2.L,
        interface:r3.L,
        ;
 permit src = network:n1;
        dst = user;
        prt = tcp 22;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Select one path and prevent deep recursion in loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2;
 interface:n3;
}
router:r3 = {
 interface:n3;
 interface:n4;
}
router:r4 = {
 interface:n3;
 interface:n4;
}
service:test = {
 user = network:n4;
 permit src = network:n1;
        dst = user;
        prt = tcp 22;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 managed;
 routing = manual;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n2;
 interface:n3;
}
router:r3 = {
 interface:n3;
 interface:n4;
}
service:test = {
 user = network:n4;
 permit src = network:n1;
        dst = user;
        prt = tcp 22;
}
=END=

############################################################
=TITLE=Remove interface with multiple IP addresses
=INPUT=
network:n1 = { ip = 10.1.1.16/28;}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
}
network:t1 = { ip = 10.9.1.80/28; }
network:t2 = { ip = 10.9.2.80/28; }
router:r2 = {
 interface:t1 = { ip = 10.9.1.83; }
 interface:t2 = { ip = 10.9.2.83, 10.9.2.85; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.16/28; }
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.17; hardware = n1; }
 interface:t1 = { ip = 10.9.1.82; hardware = t1; }
}
network:t1 = { ip = 10.9.1.80/28; }
router:r2 = {
 interface:t1 = { ip = 10.9.1.83; }
 interface:n2;
}
network:n2 = { ip = 10.1.2.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Secondary interface
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 model = IOS;
 managed;
 interface:n1 = {
  ip = 10.1.1.1,
       10.1.1.18,
       ;
  secondary:sec = { ip = 10.1.1.33; }
  hardware = n1;
 }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:r1.n1.2,
              interface:r1.n1.sec,
              ;
        prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Remove interface with virtual address
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = VRRP; }
  hardware = n1;
 }
 interface:lo = {
  virtual = { ip = 10.1.4.1; type = VRRP; }
  loopback;
  hardware = lo;
 }
 interface:n2 = {
  virtual = { ip = 10.1.2.1; type = VRRP; }
  hardware = n2;
 }
 interface:n3 = {
  virtual = { ip = 10.1.3.1; type = VRRP; }
  hardware = n3;
 }
}
service:s1 = {
 user = network:n1;
 permit src = network:n2; dst = user; prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.2;
  virtual = { ip = 10.1.1.1; type = VRRP; }
  hardware = n1;
 }
 interface:n2 = {
  virtual = { ip = 10.1.2.1; type = VRRP; }
  hardware = n2;
 }
}
service:s1 = {
 user = network:n1;
 permit src = network:n2;
        dst = user;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Mark interface, if only virtual is used
=INPUT=
network:u = { ip = 10.9.9.0/24; }
router:g = {
 managed;
 model = IOS, FW;
 interface:u = {ip = 10.9.9.1; hardware = F0;}
 interface:a = {ip = 10.1.1.9; hardware = F1;}
}
network:a = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.1; hardware = E1;}
 interface:b = {ip = 10.2.2.1; virtual = {ip = 10.2.2.9;} hardware = E2;}
}
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = {ip = 10.1.1.2; hardware = E4;}
 interface:b = {ip = 10.2.2.2; virtual = {ip = 10.2.2.9;} hardware = E5;}
}
network:b  = { ip = 10.2.2.0/24; }
pathrestriction:p = interface:r1.a, interface:r1.b.virtual;
service:test = {
 user = network:u;
 permit src = user; dst = network:b; prt = ip;
}
=OUTPUT=
network:u = { ip = 10.9.9.0/24; }
router:g = {
 managed;
 model = IOS, FW;
 interface:u = { ip = 10.9.9.1; hardware = F0; }
 interface:a = { ip = 10.1.1.9; hardware = F1; }
}
network:a = { ip = 10.1.1.0/24; }
router:r2 = {
 managed;
 model = IOS, FW;
 interface:a = { ip = 10.1.1.2; hardware = E4; }
 interface:b = {
  ip = 10.2.2.2;
  virtual = { ip = 10.2.2.9; }
  hardware = E5;
 }
}
network:b = { ip = 10.2.2.0/24; }
service:test = {
 user = network:u;
 permit src = user;
        dst = network:b;
        prt = ip;
}
=END=

############################################################
=TITLE=Remove nat_out only once at interface with virtual
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 1.9.9.2/32; dynamic; } }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.1;
  virtual = { ip = 10.1.1.2; }
  hardware = n1;
  nat_out = n2;
 }
 interface:lo = { ip = 10.9.9.2; loopback; hardware = lo; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = interface:r1.lo; prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = {
  ip = 10.1.1.1;
  virtual = { ip = 10.1.1.2; }
  hardware = n1;
 }
 interface:lo = { ip = 10.9.9.2; loopback; hardware = lo; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = interface:r1.lo;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Used aggregate with owner
=INPUT=
any:n1 = { owner = o; link = network:n1; }
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
owner:o = { admins = a@example.com; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n2;
    permit src = user; dst = any:n1; prt = tcp;
}
=OUTPUT=
any:n1 = {
 link = network:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = any:n1;
        prt = tcp;
}
=END=

############################################################
=TITLE=Owner at network and host
=INPUT=
owner:o1 = { admins = a@example.com; watchers = b@example.com, c@example.com; }
owner:o2 = { admins = b@example.com; }
owner:o3 = { admins = c@example.com; }
owner:o4 = { admins = d@example.com; watchers = e@example.com; }
network:n1 = { ip = 10.1.1.0/24; owner = o1;
 host:h10 = { ip = 10.1.1.10; owner = o2;}
 host:h11 = { ip = 10.1.1.11;
 # owner =
 owner = o3;
 }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = host:h11;
    permit src = user; dst = network:n2; prt = tcp;
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h11 = { ip = 10.1.1.11; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = host:h11;
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=END=

############################################################
=TITLE=Cleanup policy_distribution_point
=INPUT=
network:n1 = { ip = 10.1.1.0/24; host:h10 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
  policy_distribution_point = host:h10;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=END=

############################################################
=TITLE=Cleanup pathrestriction
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n3 = { ip = 10.1.3.3; hardware = n3; }
}
pathrestriction:p = interface:r1.n1, interface:r2.n3, interface:r3.n3;
service:test = {
    user = network:n1, network:n2;
    permit src = user; dst = network:n3; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
pathrestriction:p =
 interface:r1.n1,
 interface:r2.n3,
;
service:test = {
 user = network:n1,
        network:n2,
        ;
 permit src = user;
        dst = network:n3;
        prt = tcp;
}
=END=

############################################################
=TITLE=Cleanup reroute_permit
=INPUT=
network:n1a = { ip = 10.1.1.64/27; subnet_of = network:n1; }
network:n1b = { ip = 10.1.1.96/27; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; reroute_permit = network:n1a, network:n1b; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1b;
    permit src = user; dst = network:n2; prt = tcp;
}
=OUTPUT=
network:n1b = {
 ip = 10.1.1.96/27;
 subnet_of = network:n1;
}
router:u = {
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = n1;
  reroute_permit = network:n1b;
 }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n1b;
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=END=

############################################################
=TITLE=Remove reroute_permit
=INPUT=
network:n1a = { ip = 10.1.1.64/27; subnet_of = network:n1; }
network:n1b = { ip = 10.1.1.96/27; subnet_of = network:n1; }
router:u = {
 interface:n1a;
 interface:n1b;
 interface:n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; reroute_permit = network:n1a, network:n1b; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
    user = network:n1;
    permit src = user; dst = network:n2; prt = tcp;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=END=

############################################################
=TITLE=Remove owner and policy_distribution_point from router_attributes
=INPUT=
owner:o1 = { admins = a@example.com; }
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.10; } }
network:n2 = { ip = 10.1.2.0/24; }
area:a1 = {
 inclusive_border = interface:r1.n2;
 router_attributes = {
  owner = o1;
  policy_distribution_point = host:h1;
 }
 nat:d1 = { ip = 10.9.9.1/32; dynamic; }
}
area:a2 = {
 border = interface:r1.n2;
 router_attributes = {
  owner = o1;
  general_permit = icmp 0, icmp 3, icmp 11;
  policy_distribution_point = host:h1;
 }
 nat:d2 = { ip = 10.9.9.2/32; dynamic; }
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = outside; nat_out = d2;}
 interface:n2 = { ip = 10.1.2.1; hardware = inside; nat_out = d1; }
}
service:s = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = ip;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
area:a1 = {
 nat:d1 = { ip = 10.9.9.1/32; dynamic; }
 inclusive_border = interface:r1.n2;
}
area:a2 = {
 router_attributes = {
  general_permit =
   icmp 0,
   icmp 3,
   icmp 11,
  ;
 }
 nat:d2 = { ip = 10.9.9.2/32; dynamic; }
 border = interface:r1.n2;
}
router:r1 = {
 model = ASA;
 managed;
 interface:n1 = {
  ip = 10.1.1.1;
  hardware = outside;
  nat_out = d2;
 }
 interface:n2 = {
  ip = 10.1.2.1;
  hardware = inside;
  nat_out = d1;
 }
}
service:s = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = ip;
}
=END=

############################################################
=TITLE=Remove unused tags of nat_out
=INPUT=
network:n1 = { ip = 10.1.1.0/24; nat:n1 = { ip = 10.9.1.0/24; } }
network:n2 = { ip = 10.1.2.0/24; nat:n2 = { ip = 10.9.2.0/24; } }
network:n3 = { ip = 10.1.3.0/24; nat:n3 = { ip = 10.9.3.0/24; } }
network:n4 = { ip = 10.1.4.0/24; nat:n4 = { ip = 10.9.4.0/24; } }
network:n5 = { ip = 10.1.5.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; nat_out = n3, n4; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; nat_out = n1, n2; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; nat_out = n1, n4; }
}
router:asa3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:test = {
 user = network:n2;
 permit src = user; dst = network:n3, network:n5; prt = tcp 80;
}
=OUTPUT=
network:n2 = {
 ip = 10.1.2.0/24;
 nat:n2 = { ip = 10.9.2.0/24; }
}
network:n3 = {
 ip = 10.1.3.0/24;
 nat:n3 = { ip = 10.9.3.0/24; }
}
network:n5 = { ip = 10.1.5.0/24; }
router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = {
  ip = 10.1.2.2;
  hardware = n2;
  nat_out = n3;
 }
 interface:n3 = {
  ip = 10.1.3.1;
  hardware = n3;
  nat_out = n2;
 }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
service:test = {
 user = network:n2;
 permit src = user;
        dst = network:n3,
              network:n5,
              ;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Bridged network
=TEMPL=input
network:n1/left = { ip = 10.1.1.0/24; }
router:bridge = {
 managed;
 model = ASA;
 interface:n1/left  = { hardware = left; }
 interface:n1/right = { hardware = right; }
 interface:n1       = { ip = 10.1.1.2; hardware = device; }
}
network:n1/right = { ip = 10.1.1.0/24; }
network:n2       = { ip = 10.1.2.0/24; }
router:asa1 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n1/right = { ip = 10.1.1.1; hardware = n1; }
 interface:n2       = { ip = 10.1.2.1; hardware = n2; }
}
service:test = {
 user = network:n1/right;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Handle split router from pathrestriction
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n1;
 interface:n3;
 interface:n5;
 interface:n7;
}
router:r3 = {
 interface:n2;
 interface:n4;
 interface:n6;
 interface:n8;
}
router:r4 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n7 = { ip = 10.1.7.2; hardware = n7; }
 interface:n8 = { ip = 10.1.8.2; hardware = n8; }
}
pathrestriction:p1 =
 interface:r2.n1,
 interface:r3.n2,
;
pathrestriction:p2 =
 interface:r2.n7,
 interface:r3.n8,
;
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n8; prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24; }
router:r1 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 interface:n1;
 interface:n7;
}
router:r3 = {
 interface:n2;
 interface:n8;
}
router:r4 = {
 managed;
 model = IOS;
 routing = manual;
 interface:n7 = { ip = 10.1.7.2; hardware = n7; }
 interface:n8 = { ip = 10.1.8.2; hardware = n8; }
}
pathrestriction:p1 =
 interface:r2.n1,
 interface:r3.n2,
;
pathrestriction:p2 =
 interface:r2.n7,
 interface:r3.n8,
;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n8;
        prt = tcp 80;
}
=END=

############################################################
# Shared topology for crypto tests
############################################################
=TEMPL=crypto
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn1 = {
 type = ipsec:aes256SHA;
}
crypto:vpn2 = {
 type = ipsec:aes256SHA;
}
=TEMPL=topo
network:intern = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = { ip = 10.1.1.101; hardware = inside; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn1,
        crypto:vpn2,
        ;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = {
 ip = 0.0.0.0/0;
 has_subnets;
}
=TEMPL=clients1
router:softclients1 = {
 interface:internet = {
  spoke = crypto:vpn1;
 }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24;
 vpn_attributes = {
  banner = Willkommen zurück;
 }
 host:id:foo@domain.x = { ip = 10.99.1.10; }
 host:id:bar@domain.x = {
  ip = 10.99.1.11;
  vpn_attributes = {
   banner = Willkommen zu Hause;
  }
 }
}
=TEMPL=clients2
router:softclients2 = {
 interface:internet = {
  spoke = crypto:vpn2;
 }
 interface:customers2;
}
network:customers2 = {
 ip = 10.99.2.0/24;
 vpn_attributes = {
  vpn-idle-timeout = 120;
  trust-point = ASDM_TrustPoint2;
 }
 host:id:domain.x = {
  range = 10.99.2.0 - 10.99.2.63;
  vpn_attributes = {
   split-tunnel-policy = tunnelspecified;
   check-subject-name = ou;
  }
 }
 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  vpn_attributes = {
   vpn-idle-timeout = 40;
   trust-point = ASDM_TrustPoint3;
  }
 }
}
=TEMPL=clients3
router:softclients3 = {
 interface:internet = {
  spoke = crypto:vpn2;
 }
 interface:customers3;
}
network:customers3 = {
 ip = 10.99.3.0/24;
 cert_id = cert.example.com;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint2;
  authentication-server-group = LDAPGROUP_3;
  authorization-server-group = LDAPGROUP_3;
  check-subject-name = cn;
 }
 host:VPN_Org1 = {
  range = 10.99.3.0 - 10.99.3.63;
  ldap_id = CN=ROL-Org1;
 }
 host:VPN_Org2 = {
  range = 10.99.3.64 - 10.99.3.95;
  ldap_id = CN=ROL-Org2;
 }
}
=END=

############################################################
=TITLE=Crypto definitions with router fragments
=TEMPL=input
[[crypto]]
[[topo]]
[[clients1]]
[[clients2]]
service:test1 = {
 user = host:id:foo@domain.x.customers1,
        host:id:@domain.y.customers2,
        ;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
service:test2 = {
 user = host:id:bar@domain.x.customers1,
        host:id:domain.x.customers2,
        ;
 permit src = user;
        dst = network:intern;
        prt = tcp 81;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Take one of multiple crypto networks (1)
=TEMPL=service
service:test1 = {
 user = host:id:bar@domain.x.customers1;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
=INPUT=
[[crypto]]
[[topo]]
[[clients1]]
[[clients2]]
[[service]]
=OUTPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn1 = {
 type = ipsec:aes256SHA;
}
network:intern = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = { ip = 10.1.1.101; hardware = inside; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn1;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = {
 ip = 0.0.0.0/0;
 has_subnets;
}
router:softclients1 = {
 interface:internet = {
  spoke = crypto:vpn1;
 }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24;
 vpn_attributes = {
  banner = Willkommen zurück;
 }
 host:id:bar@domain.x = {
  ip = 10.99.1.11;
  vpn_attributes = {
   banner = Willkommen zu Hause;
  }
 }
}
[[service]]
=END=

############################################################
=TITLE=Take one of multiple crypto networks (2)
=TEMPL=service
service:test1 = {
 user = host:id:@domain.y.customers2;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
=INPUT=
[[crypto]]
[[topo]]
[[clients1]]
[[clients2]]
[[service]]
=OUTPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn2 = {
 type = ipsec:aes256SHA;
}
network:intern = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = { ip = 10.1.1.101; hardware = inside; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn2;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = {
 ip = 0.0.0.0/0;
 has_subnets;
}
router:softclients2 = {
 interface:internet = {
  spoke = crypto:vpn2;
 }
 interface:customers2;
}
network:customers2 = {
 ip = 10.99.2.0/24;
 vpn_attributes = {
  vpn-idle-timeout = 120;
  trust-point = ASDM_TrustPoint2;
 }
 host:id:@domain.y = {
  range = 10.99.2.64 - 10.99.2.127;
  vpn_attributes = {
   vpn-idle-timeout = 40;
   trust-point = ASDM_TrustPoint3;
  }
 }
}
[[service]]
=END=

############################################################
=TITLE=Network with ID hosts
# Take at least one ID host
=TEMPL=service
service:test1 = {
 user = network:customers1;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
=INPUT=
[[crypto]]
[[topo]]
[[clients1]]
[[clients2]]
[[service]]
=OUTPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn1 = {
 type = ipsec:aes256SHA;
}
network:intern = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = { ip = 10.1.1.101; hardware = inside; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn1;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = {
 ip = 0.0.0.0/0;
 has_subnets;
}
router:softclients1 = {
 interface:internet = {
  spoke = crypto:vpn1;
 }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24;
 vpn_attributes = {
  banner = Willkommen zurück;
 }
 host:id:foo@domain.x = { ip = 10.99.1.10; }
}
[[service]]
=END=

############################################################
=TITLE=ID host in intersection
=INPUT=
[[crypto]]
[[topo]]
[[clients1]]
[[clients2]]
group:g1 =
 host:id:foo@domain.x.customers1,
 host:id:bar@domain.x.customers1,
 host:id:domain.x.customers2,
 host:id:@domain.y.customers2,
;
service:s1 = {
 user = group:g1 &! host:id:bar@domain.x.customers1;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
=OUTPUT=
[[crypto]]
[[topo]]
router:softclients1 = {
 interface:internet = {
  spoke = crypto:vpn1;
 }
 interface:customers1;
}
network:customers1 = {
 ip = 10.99.1.0/24;
 vpn_attributes = {
  banner = Willkommen zurück;
 }
 host:id:foo@domain.x = { ip = 10.99.1.10; }
}
[[clients2]]
service:s1 = {
 user = host:id:foo@domain.x.customers1,
        host:id:domain.x.customers2,
        host:id:@domain.y.customers2,
        ;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Host with ldap_id
=TEMPL=service
service:test1 = {
 user = host:VPN_Org1;
 permit src = user;
        dst = network:intern;
        prt = tcp 80;
}
=INPUT=
[[crypto]]
[[topo]]
[[clients1]]
[[clients3]]
[[service]]
=OUTPUT=
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}
isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:vpn2 = {
 type = ipsec:aes256SHA;
}
network:intern = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = { ip = 10.1.1.101; hardware = inside; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn2;
  hardware = outside;
 }
}
network:dmz = { ip = 192.168.0.0/24; }
router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}
network:internet = {
 ip = 0.0.0.0/0;
 has_subnets;
}
router:softclients3 = {
 interface:internet = {
  spoke = crypto:vpn2;
 }
 interface:customers3;
}
network:customers3 = {
 ip = 10.99.3.0/24;
 cert_id = cert.example.com;
 vpn_attributes = {
  trust-point = ASDM_TrustPoint2;
  authentication-server-group = LDAPGROUP_3;
  authorization-server-group = LDAPGROUP_3;
  check-subject-name = cn;
 }
 host:VPN_Org1 = {
  range = 10.99.3.0 - 10.99.3.63;
  ldap_id = CN=ROL-Org1;
 }
}
[[service]]
=END=

############################################################
=TITLE=VPN spoke with unused hub
=TEMPL=input
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 1 hour 100000 kilobytes;
}
isakmp:aes256SHA = {
 nat_traversal = additional;
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 43200 sec;
 trust_point = ASDM_TrustPoint3;
}
crypto:sts = {
 type = ipsec:aes256SHA;
}
network:intern = { ip = 10.1.1.0/24; }
router:asavpn = {
 model = ASA;
 managed;
 interface:intern = {
  ip = 10.1.1.101;
  hardware = inside;
 }
 interface:dmz = {
  ip = 192.168.1.1;
  hub = crypto:sts;
  hardware = outside;
 }
}
network:dmz = {
 ip = 192.168.1.0/24;
 host:ntp = { ip = 192.168.1.123; }
}
router:vpn1 = {
 managed;
 model = ASA;
 interface:dmz = {
  ip = 192.168.1.2;
  id = cert@example.com;
  spoke = crypto:sts;
  hardware = dmz;
 }
 interface:lan1 = {
  ip = 10.99.1.1;
  hardware = Fastethernet8;
 }
}
network:lan1 = { ip = 10.99.1.0/24; }
service:ntp = {
 user = {{.}};
 permit src = user;
        dst = host:ntp;
        prt = udp 123;
}
=INPUT=
[[input interface:vpn1.dmz]]
=OUTPUT=
network:dmz = {
 ip = 192.168.1.0/24;
 host:ntp = { ip = 192.168.1.123; }
}
router:vpn1 = {
 managed;
 model = ASA;
 interface:dmz = { ip = 192.168.1.2; hardware = dmz; }
}
service:ntp = {
 user = interface:vpn1.dmz;
 permit src = user;
        dst = host:ntp;
        prt = udp 123;
}
=END=

############################################################
=TITLE=VPN hub with unused spoke
=INPUT=
[[input interface:asavpn.dmz]]
=OUTPUT=
router:asavpn = {
 model = ASA;
 managed;
 interface:dmz = { ip = 192.168.1.1; hardware = outside; }
}
network:dmz = {
 ip = 192.168.1.0/24;
 host:ntp = { ip = 192.168.1.123; }
}
service:ntp = {
 user = interface:asavpn.dmz;
 permit src = user;
        dst = host:ntp;
        prt = udp 123;
}
=END=

############################################################
=TITLE=With description
=INPUT=
network:n1 = {
 description = network:n1; # looks like code
 ip = 10.1.1.0/24;
 host:h10 = {
  ip = 10.1.1.10;
 }
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 description = description = ;
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s = {
 description = this is really important
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80-90;
}
=OUTPUT=
network:n1 = {
 description = network:n1; # looks like code
 ip = 10.1.1.0/24;
}
network:n2 = { ip = 10.1.2.0/24; }
router:asa1 = {
 description = description =
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s = {
 description = this is really important
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80 - 90;
}
=END=

############################################################
=TITLE=Retain unused network having partition attribute
=INPUT=
network:n0 = {
 ip = 10.1.0.0/24;
 partition = part1;
}
router:r0 = {
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = {
 ip = 10.1.4.0/24;
 partition = part2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.1; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
service:s2 = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=OUTPUT=
network:n0 = {
 ip = 10.1.0.0/24;
 partition = part1;
}
router:r0 = {
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = {
 ip = 10.1.4.0/24;
 partition = part2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.1; hardware = n1; }
 interface:n4 = { ip = 10.1.4.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
service:s2 = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Unenforceable rule
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = 10.1.3.2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 has_unenforceable;
 user = network:n1;
 permit src = user;
        dst = network:n2,
              network:n4,
              ;
        prt = tcp 22;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Ignore secondary interface on path
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1, 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1, 10.1.2.2; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Negated auto interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
area:n2-3 = {
 border = interface:r1.n2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r3 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
service:s1 = {
 user = interface:[managed & area:n2-3].[auto]
        &! interface:r3.[auto]
        ,
        interface:[managed & network:n2, network:n3].[auto]
        &! interface:[managed & network:n2].[auto]
        ;
 permit src = user;
        dst = network:n1;
        prt = udp 123;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = interface:r2.[auto],
        interface:[managed & network:n3].[auto],
        ;
 permit src = user;
        dst = network:n1;
        prt = udp 123;
}
=END=

############################################################
=TITLE=Negated interface
=INPUT=
router:u1 = {
 interface:n1 = { ip = 10.1.1.11, 10.1.1.21; }
}
router:u2 = {
 interface:n1 = { ip = 10.1.1.12; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = interface:[network:n1].[all]
        &! interface:u2.n1,
        ;
 permit src = user;
        dst = network:n2;
        prt = udp 123;
}
=OUTPUT=
router:u1 = {
 interface:n1 = { ip = 10.1.1.11, 10.1.1.21; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = interface:u1.n1,
        interface:r1.n1,
        interface:u1.n1.2,
        ;
 permit src = user;
        dst = network:n2;
        prt = udp 123;
}
=END=

############################################################
=TITLE=Negated host
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = host:[network:n1]
        &! host:h11,
        ;
 permit src = user;
        dst = network:n2;
        prt = udp 123;
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h12 = { ip = 10.1.1.12; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = host:h10,
        host:h12,
        ;
 permit src = user;
        dst = network:n2;
        prt = udp 123;
}
=END=

############################################################
=TITLE=Leave intersection with user unchanged
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
group:g1 =
 network:n1,
 network:n2,
 network:n3,
;
service:s1 = {
 user = group:g1;
 permit src = user
              &! network:n2
              &! network:n3
              ;
        dst = group:g1 &! network:n1 &! network:n2;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=SUBST=/group:g1 &! network:n1 &! network:n2/network:n3/

############################################################
=TITLE=Intersection of nested elements of different type
=TEMPL=input
service:s1 = {
 user = group:g1;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
network:n1 = { ip = 10.1.1.0/24; }
router:r2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.4; hardware = n1; }
 interface:n2 = {
  ip = 10.1.2.1;
  hardware = n2;
  hub = crypto:s2s;
 }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r3 = {
 interface:n2 = {
  ip = 10.1.2.2;
  spoke = crypto:s2s;
 }
 interface:lo = { ip = 10.9.9.13; loopback; }{{.}}
}
crypto:s2s = {
 type = ipsec:s2s;
}
ipsec:s2s = {
 key_exchange = isakmp:s2s;
 esp_encryption = aes256;
 esp_authentication = sha256;
 lifetime = 3600 sec 102400 kilobytes;
}
isakmp:s2s = {
 ike_version = 2;
 authentication = preshare;
 encryption = aes256;
 hash = sha256;
 group = 19;
 lifetime = 28800 sec;
}
=INPUT=
group:g1 =
 any:[ip = 10.9.9.0/24 &
  any:[interface:r3.[all]] &! any:[network:n2]
 ],
;
[[input "\n interface:n3 = { ip = 10.1.3.1; }"]]
network:n3 = { ip = 10.1.3.0/24; }
=OUTPUT=
group:g1 =
 any:[ip = 10.9.9.0/24 &
  any:[
   interface:r3.lo,
  ],
 ],
;
[[input ""]]
=END=

############################################################
=TITLE=Network auto interface
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
area:n2-3 = {
 border = interface:r1.n2;
}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = interface:[
         network:[area:n2-3],
        ].[auto];
 permit src = user;
        dst = network:n1;
        prt = udp 123;
}
=INPUT=[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Negated interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
service:s1 = {
 user = interface:r1.n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 22;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = interface:r1.n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 22;
}
=END=

############################################################
=TITLE=Negated pathrestriction
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
router:r1 =  {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
router:r2 =  {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
}
router:unnütz = {
 interface:n4;
}
pathrestriction:A =
 interface:[network:n4].[all]
 &! interface:unnütz.n4
 ,
;
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}
=END=

############################################################
=TITLE=Remove border of area in unconnected part
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
network:n6 = { ip = 10.1.6.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24; }
area:a = {
 nat:dyn = { ip = 192.168.7.32/27; dynamic; }
 border = interface:r3.n4,
          interface:r3.n5,
          ;
 inclusive_border =
  interface:r1.n1,
  interface:r4.n7,
  ;
}

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n4 = { ip = 10.1.4.2; hardware = n4; }
 interface:n5 = { ip = 10.1.5.2; hardware = n5; }
}
router:r4 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n6 = { ip = 10.1.6.2; hardware = n6; }
 interface:n7 = { ip = 10.1.7.1; hardware = n7; }
}
router:r5 = {
 managed;
 model = IOS;
 interface:n7 = { ip = 10.1.7.2; hardware = n7; }
 interface:n8 = { ip = 10.1.8.1; hardware = n8; nat_out = dyn; }
}
group:p1 = interface:[network:[interface:r3.[all]]].[all] & interface:r2.[all];
pathrestriction:A =
 interface:r2.[all]
 &! group:p1
 ,
;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n8;
        prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24; }
area:a = {
 nat:dyn = { ip = 192.168.7.32/27; dynamic; }
 inclusive_border =
  interface:r1.n1,
  interface:r4.n7,
  ;
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
router:r4 = {
 managed;
 model = IOS;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n7 = { ip = 10.1.7.1; hardware = n7; }
}
router:r5 = {
 managed;
 model = IOS;
 interface:n7 = { ip = 10.1.7.2; hardware = n7; }
 interface:n8 = {
  ip = 10.1.8.1;
  hardware = n8;
  nat_out = dyn;
 }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n8;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Detect unmanaged loop (1)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n2 = { ip = 10.1.2.2; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=OUTPUT=
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Detect unmanaged loop (2)
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.1, 10.1.1.9; }
 interface:n2 = { ip = 10.1.2.1; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n2 = { ip = 10.1.2.2; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = interface:r1.n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1, 10.1.1.9; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = interface:r1.n1;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Path in unmanaged loop
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r2 = {
 interface:n1 = { ip = 10.1.1.2; }
 interface:n2 = { ip = 10.1.2.2; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
any:n3 = { link = network:n3; }
service:s1 = {
 user = any:n3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:n2 = { ip = 10.1.2.1; }
 interface:n3 = { ip = 10.1.3.1; }
}
router:r3 = {
 managed;
 model = IOS;
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
any:n3 = {
 link = network:n3;
}
service:s1 = {
 user = any:n3;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Retain management_instance of used router
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1@v1 = {
 model = NSX, T0;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
router:u = {
 interface:n2;
 interface:n3;
}
router:r1 = {
 model = NSX;
 management_instance;
 interface:n3 = { ip = 10.1.3.1; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Ignore management_instance of unused router
=INPUT=
[[input]]
router:r2 = {
 model = NSX;
 management_instance;
 interface:n3 = { ip = 10.1.3.2; }
}
router:r2@v1 = {
 model = NSX, T0;
 managed;
 routing = manual;
 interface:n3 = { ip = 10.1.3.2; hardware = IN; }
 interface:n4 = { ip = 10.1.4.1; hardware = OUT; }
}
network:n4 = { ip = 10.1.4.0/24; }
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=management_instance in separate zone
=TEMPL=input
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
network:n4 = { ip = 10.1.4.0/24; }
network:n5 = { ip = 10.1.5.0/24; }
router:r1@v1 = {
 model = NSX, T0;
 managed;
 routing = manual;
 interface:n1 = { ip = 10.1.1.2; hardware = IN; }
 interface:n2 = { ip = 10.1.2.1; hardware = OUT; }
}
router:u = {
 interface:n2;
 interface:n3;
 interface:n4;
}
router:r2 = {
 managed;
 model = ASA;
 routing = manual;
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
}
router:r1 = {
 model = NSX;
 management_instance;
 interface:n5 = { ip = 10.1.5.2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n3;
        prt = tcp 80;
}
=INPUT=
[[input]]
=OUTPUT=
[[input]]
=END=

############################################################
=TITLE=Cleanup unused subnet_of
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = {
 ip = 10.1.1.0/26;
 subnet_of = network:n1;
}
network:n3 = {
 ip = 10.1.1.0/28;
 subnet_of = network:n2;
}
router:r1 = {
 interface:n1;
 interface:n2;
 interface:n3 = { ip = 10.1.1.1; }
}
network:n4 = { ip = 10.1.4.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.1.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n2,
        network:n3,
        ;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=OUTPUT=
network:n2 = { ip = 10.1.1.0/26; }
network:n3 = {
 ip = 10.1.1.0/28;
 subnet_of = network:n2;
}
router:r1 = {
 interface:n2;
 interface:n3 = { ip = 10.1.1.1; }
}
network:n4 = { ip = 10.1.4.0/24; }
router:r2 = {
 managed;
 model = ASA;
 interface:n3 = { ip = 10.1.1.2; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}
service:s1 = {
 user = network:n2,
        network:n3,
        ;
 permit src = user;
        dst = network:n4;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Cleanup subnet_of in NAT
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:m = { ip = 10.1.3.16/28; dynamic; subnet_of = network:n3; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1;}
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; nat_out = m; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:m = { ip = 10.1.3.16/28; dynamic; }
}
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Cleanup subnet_of in Area
=INPUT=
area:n1 = {
 nat:m2 = { ip = 10.1.2.16/28; dynamic; subnet_of = network:n2; }
 nat:m3 = { ip = 10.1.3.16/28; dynamic; subnet_of = network:n3; }
 border = interface:r1.n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; nat_out = m2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; nat_out = m3; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=OUTPUT=
area:n1 = {
 nat:m2 = { ip = 10.1.2.16/28; dynamic; subnet_of = network:n2; }
 nat:m3 = { ip = 10.1.3.16/28; dynamic; }
 border = interface:r1.n1;
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = {
  ip = 10.1.2.1;
  hardware = n2;
  nat_out = m2;
 }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=END=
