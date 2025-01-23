
############################################################
=TITLE=Protocol IP and deny rules with prefix and suffix
=INPUT=
network:n1 = {
 ip6 = ::a01:100/120;
 host:h10 = { ip6 = ::a01:10a; }
 host:h12 = { ip6 = ::a01:10c; }
}
router:r1 =  {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
service:s1 = {
 user = interface:r1.n1;
 deny src = host:h10, host:h12; dst = user; prt = ip;
 permit src = network:n1; dst = user; prt = ip;
}
=OUTPUT=
--ipv6/r1.info
{"generated_by":"devel","model":"Linux"}
--ipv6/r1
# [ PREFIX ]
--
#!/sbin/iptables-restore <<EOF
*raw
:PREROUTING ACCEPT
:OUTPUT ACCEPT
-A PREROUTING -i lo -j NOTRACK
-A OUTPUT -o lo -j NOTRACK
COMMIT
*filter
:INPUT DROP
:FORWARD DROP
:OUTPUT ACCEPT
-A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED
-A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED
-A INPUT -j ACCEPT -i lo
:droplog -
-A droplog -j LOG --log-level debug
-A droplog -j DROP
--
# [ ACL ]
:c1 -
-A c1 -j droplog -s ::a01:10c
-A c1 -j droplog -s ::a01:10a
--
:n1_self -
-A n1_self -j c1 -s ::a01:108/125 -d ::a01:101
-A n1_self -j ACCEPT -s ::a01:100/120 -d ::a01:101
-A INPUT -j n1_self -i n1
--
# [ SUFFIX ]
-A INPUT -j droplog
-A FORWARD -j droplog
COMMIT
EOF
=END=

############################################################
=TITLE=Different port ranges
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 =  {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 1-1023,
              udp 1024-65535,
              tcp 4080-4090,
              udp 123,
        ;
 permit src = network:n2; dst = user; prt = udp 1 - 65535;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -p tcp --dport 4080:4090
-A c1 -j ACCEPT -p tcp --dport :1023
-A c2 -j ACCEPT -p udp --dport 1024:
-A c2 -j ACCEPT -p udp --dport 123
-A c3 -g c1 -p tcp --dport :4090
-A c3 -g c2 -p udp --dport 123:
--
:n1_n2 -
-A n1_n2 -g c3 -s ::a01:100/120 -d ::a01:200/120
-A FORWARD -j n1_n2 -i n1 -o n2
--
:n2_n1 -
-A n2_n1 -j ACCEPT -s ::a01:200/120 -d ::a01:100/120 -p udp
-A FORWARD -j n2_n1 -i n2 -o n1
=END=

############################################################
=TITLE=Different src and dst port ranges
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:r1 =  {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
protocol:p1 = tcp 4080-4090:1-1023;
protocol:p2 = tcp 1-1023:4080-4090;
protocol:p3 = tcp 1024-65535:4080-4085;
protocol:p4 = udp 1024-65535:1024-65535;
protocol:p5 = udp 123:123;
protocol:p6 = udp 1-511:1 - 65535;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocol:p1, protocol:p2, protocol:p3, protocol:p4, protocol:p5;
 permit src = network:n2; dst = user; prt = protocol:p6;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -p tcp --sport 1024: --dport 4080:4085
-A c1 -j ACCEPT -p tcp --sport 4080:4090 --dport :1023
-A c2 -g c1 -p tcp --sport 1024:
-A c2 -j ACCEPT -p tcp --sport :1023 --dport 4080:4090
-A c3 -g c2 -p tcp
-A c3 -j ACCEPT -p udp --sport 1024: --dport 1024:
-A c3 -j ACCEPT -p udp --sport 123 --dport 123
--
:n1_n2 -
-A n1_n2 -g c3 -s ::a01:100/120 -d ::a01:200/120
-A FORWARD -j n1_n2 -i n1 -o n2
--
:n2_n1 -
-A n2_n1 -j ACCEPT -s ::a01:200/120 -d ::a01:100/120 -p udp --sport :511
-A FORWARD -j n2_n1 -i n2 -o n1
=END=

############################################################
=TITLE=Udp port ranges
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120;
 host:h10 = { ip6 = ::a01:20a; }
 host:h12 = { ip6 = ::a01:20c; }
 host:h14 = { ip6 = ::a01:20e; }
}
router:r1 =  {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
protocol:p1 = udp 1-1023:53;
protocol:p2 = udp 1-511:69;
protocol:p3 = udp 1024-65535:123;
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = host:h14;
        prt = protocol:p1;
 permit src = user;
        dst = host:h10;
        prt = protocol:p2;
 permit src = user;
        dst = host:h12;
        prt = protocol:p3, udp 137;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -p udp --dport 137
-A c1 -j ACCEPT -p udp --sport 1024: --dport 123
-A c2 -j ACCEPT -d ::a01:20e -p udp --sport :1023 --dport 53
-A c2 -g c1 -d ::a01:20c -p udp
-A c3 -g c2 -d ::a01:20c/126
-A c3 -j ACCEPT -d ::a01:20a -p udp --sport :511 --dport 69
--
:n1_n2 -
-A n1_n2 -g c3 -s ::a01:100/120 -d ::a01:208/125
-A FORWARD -j n1_n2 -i n1 -o n2
=END=

############################################################
=TITLE=Merge port range with sub-range
=TEMPL=input
network:RAS      = { ip6 = ::a02:200/120; }
network:Hoernum  = { ip6 = ::a03:380/125; }
network:StPeter  = { ip6 = ::a03:378/125; }
network:Firewall = { ip6 = f000::c101:100/120; }
router:ras = {
 interface:Trans    = { ip6 = ::a01:102;}
 interface:Firewall = { ip6 = f000::c101:101; }
 interface:RAS      = { ip6 = ::a02:201;}
 interface:StPeter  = { ip6 = ::a03:379;}
 interface:Hoernum  = { ip6 = ::a03:381;}
}
network:Trans = { ip6 = ::a01:100/120;}
router:nak = {
 managed;
 model = Linux;
 interface:Trans    = { ip6 = ::a01:101; hardware = eth0; }
 interface:Hosting  = { ip6 = ::a04:401; hardware = br0; }
}
network:Hosting = { ip6 = ::a04:400/120; }
service:p40-47 = {
 user = network:Firewall, network:RAS;
 permit src = user;
	dst = network:Hosting;
	prt = {{.}};
}
service:p10-60 = {
 user = network:Trans, network:StPeter, network:Hoernum;
 permit src = user;
        dst = network:Hosting;
        prt = tcp 10-49, tcp 50-60;
}
=INPUT=[[input "tcp 30-37, tcp 51-53"]]
=OUTPUT=
--ipv6/nak
-A c1 -j ACCEPT -s ::a03:380/125
-A c1 -j ACCEPT -s ::a03:378/125
-A c2 -g c1 -s ::a03:300/120
-A c2 -j ACCEPT -s ::a01:100/120
-A c3 -j ACCEPT -s f000::c101:100/120
-A c3 -j ACCEPT -s ::a02:200/120
-A c4 -j c2 -s ::a00:0/110 -p tcp --dport 10:60
-A c4 -g c3 -p tcp --dport 51:53
-A c4 -g c3 -p tcp --dport 30:37
---
:eth0_br0 -
-A eth0_br0 -g c4 -d ::a04:400/120 -p tcp --dport 10:60
-A FORWARD -j eth0_br0 -i eth0 -o br0
=END=

############################################################
=TITLE=Un-merged port range with sub-range
# Ranges 10-49 and 50-60 can't be merged,
# because they have three childs 30-37,40-47,51-53
# and a merged range can have at most two childs.
=INPUT=[[input "tcp 30-37, tcp 40-47, tcp 51-53"]]
=OUTPUT=
--ipv6/nak
-A c1 -j ACCEPT -s ::a03:380/125
-A c1 -j ACCEPT -s ::a03:378/125
-A c2 -g c1 -s ::a03:300/120
-A c2 -j ACCEPT -s ::a01:100/120
-A c3 -j ACCEPT -s f000::c101:100/120
-A c3 -j ACCEPT -s ::a02:200/120
-A c4 -j c2 -s ::a00:0/110 -p tcp --dport 50:60
-A c4 -g c3 -p tcp --dport 51:53
-A c5 -g c4 -p tcp --dport 50:60
-A c5 -j c2 -s ::a00:0/110 -p tcp --dport 10:49
-A c5 -g c3 -p tcp --dport 40:47
-A c5 -g c3 -p tcp --dport 30:37
---
:eth0_br0 -
-A eth0_br0 -g c5 -d ::a04:400/120 -p tcp --dport 10:60
-A FORWARD -j eth0_br0 -i eth0 -o br0
=END=

############################################################
=TITLE=Optimize redundant port
=TODO= No IPv6
#
# Different objects get the same IP from NAT.
=INPUT=
network:A = { ip6 = ::a03:378/125; nat:C = { ip6 = ::a02:200/120; dynamic; }}
network:B = { ip6 = ::a03:380/125; nat:C = { ip6 = ::a02:200/120; dynamic; }}
router:ras = {
 managed;
 model = ASA;
 interface:A = { ip6 = ::a03:379; hardware = Fe0; }
 interface:B = { ip6 = ::a03:381; hardware = Fe1; }
 interface:Trans = { ip6 = ::a01:102; bind_nat = C; hardware = Fe2; }
}
network:Trans = { ip6 = ::a01:100/120;}
router:nak = {
 managed;
 model = Linux;
 interface:Trans    = { ip6 = ::a01:101; hardware = eth0; }
 interface:Hosting  = { ip6 = ::a04:401; hardware = br0; }
}
network:Hosting = { ip6 = ::a04:400/120; }
service:A = {
 user = network:A;
 permit src = user;
	dst = network:Hosting;
	prt = tcp 55;
}
service:B = {
 user = network:B;
 permit src = user;
        dst = network:Hosting;
        prt = tcp 50-60;
}
=OUTPUT=
--ipv6/nak
:eth0_br0 -
-A eth0_br0 -j ACCEPT -s ::a02:200/120 -d ::a04:400/120 -p tcp --dport 50:60
-A FORWARD -j eth0_br0 -i eth0 -o br0
=END=

############################################################
=TITLE=Numeric protocols
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120;
 host:h10 = { ip6 = ::a01:20a; }
 host:h12 = { ip6 = ::a01:20c; }
}
router:r1 =  {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = host:h10;
        prt = proto 112, proto 114, proto 111;
 permit src = user;
        dst = host:h12;
        prt = proto 112, proto 111;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -p 111
-A c1 -j ACCEPT -p 112
-A c2 -j ACCEPT -p 111
-A c2 -j ACCEPT -p 112
-A c2 -j ACCEPT -p 114
-A c3 -g c1 -d ::a01:20c
-A c3 -g c2 -d ::a01:20a
--
:n1_n2 -
-A n1_n2 -g c3 -s ::a01:100/120 -d ::a01:208/125
-A FORWARD -j n1_n2 -i n1 -o n2
=END=

############################################################
=TITLE=Loopback at Linux passes other managed device
# Loopback interface and loopback network have identical IP address.
# Linux would abort when generating binary trees of IP addresses,
# where the same IP address comes from two different objects:
# loopback ip vs.loopback network.
# This test case would fail, if the loopback interface is
# changed to loopback network at r1, but left unchanged at r2
# or vice versa.
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
router:r1 = {
 managed;
 model = IOS, FW;
 routing = manual;
 interface:n1 = {ip6 = ::a01:101; hardware = n1;}
 interface:n2 = {ip6 = ::a01:201; hardware = n2;}
}
network:n2 = { ip6 = ::a01:200/120;}
router:r2 = {
 managed;
 model = Linux;
 routing = manual;
 interface:n2 = {
  ip6 = ::a01:202;
  hardware = eth0;
 }
 interface:Mail = {
  ip6 = ::a01:301;
  loopback;
  hardware = eth1;
 }
}
service:test = {
 user =  network:n1, network:n2;
 permit src = user;
	dst = interface:r2.Mail;
	prt = tcp 25;
}
=OUTPUT=
--ipv6/r2
:c1 -
-A c1 -j ACCEPT -s ::a01:200/120
-A c1 -j ACCEPT -s ::a01:100/120
--
:eth0_self -
-A eth0_self -g c1 -s ::a01:0/118 -d ::a01:301 -p tcp --dport 25
-A INPUT -j eth0_self -i eth0
=END=

############################################################
=TITLE=loopback interface, loopback network and NAT with same IP
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = {
 ip6 = ::a01:200/120;
 host:h = {ip6 = ::a01:20b;}
}
router:u = {
 interface:n2;
 interface:n1;
 interface:n3 = { ip6 = ::a01:301;}
}
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n3 = { ip6 = ::a01:302; hardware = eth1; }
 interface:n4 = { ip6 = ::a01:401; hardware = eth0; }
}
network:n4 = { ip6 = ::a01:400/120; }
router:r2 = {
 managed;
 model = Linux;
 interface:n4 = { ip6 = ::a01:402; hardware = eth0; bind_nat = nat1; }
 interface:lo = { ip6 = ::101:101; hardware = eth1; loopback; }
 interface:n5 = { ip6 = ::a01:511; hardware = eth1; }
}
network:n5 = {
 ip6 = ::a01:510/124;
 nat:nat1 = { ip6 = ::101:101/128; dynamic; }
}
protocol:Ping_Net = icmpv6 8, src_net, dst_net;
service:t1 = {
 user = network:n5;
 permit src = user; dst = network:n1; prt = icmpv6 8;
}
service:t2 = {
 user = interface:r2.lo;
 permit src = user; dst = host:h; prt = tcp 2200, protocol:Ping_Net;
}
service:s3 = {
 user = interface:r2.lo;
 permit src = host:h; dst = user; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
# [ ACL ]
:c1 -
:c2 -
-A c1 -j ACCEPT -d ::a01:200/120
-A c1 -j ACCEPT -d ::a01:100/120
-A c2 -j ACCEPT -d ::a01:20b -p tcp --dport 2200
-A c2 -g c1 -d ::a01:0/118 -p ipv6-icmp --icmp-type 8
--
:eth0_eth1 -
-A eth0_eth1 -g c2 -s ::101:101
-A FORWARD -j eth0_eth1 -i eth0 -o eth1
-- ipv6/r2
# [ ACL ]
:eth0_self -
-A eth0_self -j ACCEPT -s ::a01:20b -d ::101:101 -p tcp --dport 80
-A INPUT -j eth0_self -i eth0
--
:eth0_eth1 -
-A FORWARD -j eth0_eth1 -i eth0 -o eth1
=END=

############################################################
=TITLE=Different chains for pairs of input/ouptut interfaces
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
router:r1 =  {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:k1 = { ip6 = ::a02:101; hardware = k1; }
 interface:k2 = { ip6 = ::a02:201; hardware = k2; }
}
network:k1 = { ip6 = ::a02:100/120; }
network:k2 = { ip6 = ::a02:200/120; }
service:t1 = {
 user = network:n1;
 permit src = user; dst = network:k1, network:k2; prt = tcp 80, tcp 82;
}
=OUTPUT=
-- ipv6/r1
# [ ACL ]
:c1 -
:c2 -
-A c1 -j ACCEPT -p tcp --dport 82
-A c1 -j ACCEPT -p tcp --dport 80
-A c2 -j ACCEPT -p tcp --dport 82
-A c2 -j ACCEPT -p tcp --dport 80
--
:n1_k1 -
-A n1_k1 -g c1 -s ::a01:100/120 -d ::a02:100/120 -p tcp --dport 80:82
-A FORWARD -j n1_k1 -i n1 -o k1
--
:n1_k2 -
-A n1_k2 -g c2 -s ::a01:100/120 -d ::a02:200/120 -p tcp --dport 80:82
-A FORWARD -j n1_k2 -i n1 -o k2
=END=

############################################################
=TITLE=Combine adjacent networks (1)
=INPUT=
network:n0 = { ip6 = ::a01:0/120; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
network:n4 = { ip6 = ::a01:400/120;
 host:h44 = { ip6 = ::a01:404; }
 host:h45 = { ip6 = ::a01:405; }
 host:h46 = { ip6 = ::a01:406; }
 host:h47 = { ip6 = ::a01:407; }
}
router:u = {
 interface:n0;
 interface:n1;
 interface:n2;
 interface:n3 = { ip6 = ::a01:302; }
}
router:r1 = {
 managed;
 model = Linux;
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
}
service:s1 = {
 user = network:n0, any:[ip6 = ::a01:100/121 & network:n1];
 permit src = user; dst = host:h44; prt = tcp 20-25;
}
service:s2 = {
 user = network:n1;
 permit src = user; dst = host:h44, host:h46; prt = tcp 22;
}
service:s3 = {
 user = any:[ip6 = ::a01:200/122 & network:n2], network:n3;
 permit src = user; dst = host:h44, host:h45, host:h47; prt = tcp 21-22;
}
service:s4 = {
 user = network:n2, network:n3;
 permit src = user; dst = host:h47; prt = tcp 25;
}
=OUTPUT=
-- ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
:c4 -
:c5 -
:c6 -
-A c1 -j ACCEPT -s ::a01:300/120
-A c1 -j ACCEPT -s ::a01:200/122
-A c2 -j ACCEPT -s ::a01:200/119 -p tcp --dport 25
-A c2 -g c1 -s ::a01:200/119 -p tcp --dport 21:22
-A c3 -g c2 -d ::a01:407 -p tcp --dport 21:25
-A c3 -j ACCEPT -s ::a01:100/120 -d ::a01:406 -p tcp --dport 22
-A c4 -j ACCEPT -s ::a01:100/121
-A c4 -j ACCEPT -s ::a01:0/120
-A c5 -j c4 -s ::a01:0/119 -p tcp --dport 20:25
-A c5 -j ACCEPT -s ::a01:100/120 -p tcp --dport 22
-A c6 -g c3 -d ::a01:406/127
-A c6 -j c1 -s ::a01:200/119 -d ::a01:404/127 -p tcp --dport 21:22
-A c6 -g c5 -d ::a01:404 -p tcp --dport 20:25
--
:n3_n4 -
-A n3_n4 -g c6 -d ::a01:404/126 -p tcp
-A FORWARD -j n3_n4 -i n3 -o n4
=END=

############################################################
=TITLE=Combine adjacent networks (2)
=INPUT=
network:n1 = { ip6 = ::a01:100/120; host:h1 = { ip6 = ::a01:10a; } }
network:n2 = { ip6 = ::a01:200/120; host:h2 = { ip6 = ::a01:20a; } }
network:n3 = { ip6 = ::a01:300/120; host:h3 = { ip6 = ::a01:30a; } }
network:n4 = { ip6 = ::a01:400/120;
 host:h44 = { ip6 = ::a01:404; }
 host:h45 = { ip6 = ::a01:405; }
 host:h46 = { ip6 = ::a01:406; }
 host:h47 = { ip6 = ::a01:407; }
}
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
}
router:r2 = {
 managed;
 model = Linux;
 interface:n3 = { ip6 = ::a01:302; hardware = n3; }
 interface:n4 = { ip6 = ::a01:402; hardware = n4; }
}
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:n4; prt = udp 20;
}
service:s2 = {
 user = host:h1;
 permit src = user; dst = host:h44; prt = udp 20-21;
}
service:s3 = {
 user =  any:[ip6 = ::a01:100/121 & network:n2];
 permit src = user; dst = network:n4; prt = udp 22;
}
service:s4 = {
 user =  any:[ip6 = ::a01:108/126 & network:n2];
 permit src = user; dst = network:n4; prt = udp 22-23;
}
=OUTPUT=
-- ipv6/r2
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -s ::a01:108/126 -p udp --dport 22:23
-A c1 -j ACCEPT -s ::a01:100/121 -p udp --dport 22
-A c2 -g c1 -p udp --dport 22:23
-A c2 -j ACCEPT -s ::a01:100/120 -p udp --dport 20
-A c3 -j c2 -d ::a01:400/120 -p udp --dport 20:23
-A c3 -j ACCEPT -s ::a01:10a -d ::a01:404 -p udp --dport 20:21
--
:n3_n4 -
-A n3_n4 -g c3 -d ::a01:400/120 -p udp
-A FORWARD -j n3_n4 -i n3 -o n4
=END=

############################################################
=TITLE=Combine adjacent networks (3)
=INPUT=
network:n0 = { ip6 = ::a01:0/120; }
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
router:u = {
 interface:n0;
 interface:n1 = { ip6 = ::a01:102; }
}
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}

service:s1 = {
 user = any:[ip6 = ::a01:0/121 & network:n0],
        any:[ip6 = ::a01:80/121 & network:n0],
        any:[ip6 = ::a01:100/121 & network:n1],
        any:[ip6 = ::a01:180/121 & network:n1],
        ;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=OUTPUT=
-- ipv6/r1
:n1_n2 -
-A n1_n2 -j ACCEPT -s ::a01:0/119 -d ::a01:200/120 -p tcp --dport 80
-A FORWARD -j n1_n2 -i n1 -o n2
=END=

############################################################
=TITLE=Check udp/tcp early and combine adjacent networks
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; }
network:n3 = { ip6 = ::a01:300/120; }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = eth1; }
 interface:n2 = { ip6 = ::a01:201; hardware = eth1; }
 interface:n3 = { ip6 = ::a01:301; hardware = eth1; }
}
service:test1 = {
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 22, tcp 25;
}
service:test2 = {
 user = network:n2, network:n3;
 permit src = user; dst = network:n1; prt = udp 53, tcp 53;
}
service:test3 = {
 user = network:n3;
 permit src = user; dst = network:n1; prt = tcp 21;
}
=OUTPUT=
-- ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
:c4 -
-A c1 -j ACCEPT -p tcp --dport 25
-A c1 -j ACCEPT -p tcp --dport 22
-A c2 -j ACCEPT -p tcp --dport 53
-A c2 -j ACCEPT -p tcp --dport 21
-A c3 -g c2 -s ::a01:300/120 -p tcp --dport 21:53
-A c3 -j ACCEPT -s ::a01:200/120 -p tcp --dport 53
-A c4 -g c1 -s ::a01:100/120 -d ::a01:200/120 -p tcp --dport 22:25
-A c4 -g c3 -s ::a01:200/119 -d ::a01:100/120
--
:eth1_eth1 -
-A eth1_eth1 -g c4 -d ::a01:0/118 -p tcp
-A eth1_eth1 -j ACCEPT -s ::a01:200/119 -d ::a01:100/120 -p udp --dport 53
-A FORWARD -j eth1_eth1 -i eth1 -o eth1
=END=

############################################################
=TITLE=Check icmpv6 early
=INPUT=
network:n1 = { ip6 = ::a01:100/120;}
router:u = {
 interface:n1 = { ip6 = ::a01:101; }
 interface:n2 = { ip6 = ::a01:201; }
}
network:n2 = { ip6 = ::a01:200/120;}
router:r1 = {
 managed;
 model = Linux;
 interface:n2 = { ip6 = ::a01:202; hardware = eth0;}
 interface:n3 = { ip6 = ::a01:301; hardware = eth1; }
}
network:n3 = { ip6 = ::a01:300/120;}
service:t1 = {
 user = network:n1, network:n2;
 permit src = network:n3; dst = user; prt = tcp 80, icmpv6 8;
}
=OUTPUT=
-- ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -d ::a01:200/120 -p tcp --dport 80
-A c1 -j ACCEPT -d ::a01:100/120 -p tcp --dport 80
-A c2 -j ACCEPT -d ::a01:200/120 -p ipv6-icmp --icmp-type 8
-A c2 -j ACCEPT -d ::a01:100/120 -p ipv6-icmp --icmp-type 8
-A c3 -g c1 -d ::a01:0/118 -p tcp
-A c3 -g c2 -d ::a01:0/118 -p ipv6-icmp
--
:eth1_eth0 -
-A eth1_eth0 -g c3 -s ::a01:300/120
-A FORWARD -j eth1_eth0 -i eth1 -o eth0
=END=

############################################################
=TITLE=Deterministic output of icmpv6 codes
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; host:h2 = { ip6 = ::a01:202; } }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = icmpv6 5/2, icmpv6 5/1, icmpv6 5/3, icmpv6 5/0;
 permit src = user;
        dst = host:h2;
        prt = icmpv6 5;
 permit src = network:n2;
        dst =  user;
        prt = icmpv6 5/0, icmpv6 5/1, icmpv6 5/2, icmpv6 5/3;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:c1 -
:c2 -
:c3 -
-A c1 -j ACCEPT -p ipv6-icmp --icmp-type 5/0
-A c1 -j ACCEPT -p ipv6-icmp --icmp-type 5/1
-A c1 -j ACCEPT -p ipv6-icmp --icmp-type 5/2
-A c1 -j ACCEPT -p ipv6-icmp --icmp-type 5/3
-A c2 -j c1 -d ::a01:200/120 -p ipv6-icmp --icmp-type 5
-A c2 -j ACCEPT -d ::a01:202 -p ipv6-icmp --icmp-type 5
-A c3 -j ACCEPT -p ipv6-icmp --icmp-type 5/0
-A c3 -j ACCEPT -p ipv6-icmp --icmp-type 5/1
-A c3 -j ACCEPT -p ipv6-icmp --icmp-type 5/2
-A c3 -j ACCEPT -p ipv6-icmp --icmp-type 5/3
--
:n1_n2 -
-A n1_n2 -g c2 -s ::a01:100/120 -d ::a01:200/120 -p ipv6-icmp
-A FORWARD -j n1_n2 -i n1 -o n2
--
:n2_n1 -
-A n2_n1 -g c3 -s ::a01:200/120 -d ::a01:100/120 -p ipv6-icmp --icmp-type 5
-A FORWARD -j n2_n1 -i n2 -o n1
=END=

############################################################
=TITLE=Check ICMP type and code
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = { ip6 = ::a01:200/120; host:h2 = { ip6 = ::a01:202; } }
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:test = {
 user = network:n1;
 permit src = network:n2;
        dst = user;
        prt = icmpv6 5/1;
 permit src = host:h2;
        dst = user;
        prt = icmpv6 5;
}
=OUTPUT=
--ipv6/r1
# [ ACL ]
:c1 -
-A c1 -j ACCEPT -s ::a01:202 -p ipv6-icmp --icmp-type 5
-A c1 -j ACCEPT -s ::a01:200/120 -p ipv6-icmp --icmp-type 5/1
--
:n2_n1 -
-A n2_n1 -g c1 -d ::a01:100/120 -p ipv6-icmp --icmp-type 5
-A FORWARD -j n2_n1 -i n2 -o n1
=END=

############################################################
=TITLE=Ignore ICMP reply messages
=TODO= No IPv6
=INPUT=
network:n1 = { ip6 = ::a01:100/120; }
network:n2 = {
 ip6 = ::a01:200/120;
 host:h2 = { ip6 = ::a01:202; }
 host:h3 = { ip6 = ::a01:203; }
}
router:r1 = {
 managed;
 model = Linux;
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
}
service:test = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = icmpv6 3/0, icmpv6 3/13, icmpv6 0/0, icmpv6 11/1;
 permit src = user;
        dst = host:h2;
        prt = icmpv6 11, icmpv6 0, icmpv6 3;
 permit src = user;
        dst = host:h3;
        prt = icmpv6;
}
=OUTPUT=
--ipv6/r1
:n1_n2 -
-A n1_n2 -j ACCEPT -s ::a01:100/120 -d ::a01:203 -p ipv6-icmp
-A FORWARD -j n1_n2 -i n1 -o n2
=END=

############################################################
