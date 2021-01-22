############################################################
=VAR=topo
network:n1 = {
 ip = 10.1.1.0/24;
 nat:N = { ip = 10.1.9.0/24; }
 host:h1 = { ip = 10.1.1.10; }
}
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; host:range3 = { range = 10.1.3.9-10.1.3.10; } }
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
 interface:n3 = { ip = 10.1.3.2; hardware = n3; bind_nat = N; }
}
=END=

############################################################
=TITLE=Range, source port, deny, host, range, interface
=INPUT=
${topo}
protocolgroup:ftp-all = tcp 21,
			protocol:ftp-passive-data, protocol:ftp-active-data;
protocolgroup:ftp-passive = tcp 21, protocol:ftp-passive-data;
protocol:ftp-passive-data = tcp 1024-65535, stateless;
protocol:ftp-active-data  = tcp 20:1024-65535, stateless, reversed;
service:s1 = {
    user = host:h1, network:n2;
    permit src = user; dst = network:n3; prt = protocolgroup:ftp-all;
    permit src = user; dst = host:range3; prt = udp 123;
    permit src = user; dst = interface:asa2.n3; prt = icmp 3/3;
    deny   src = user; dst = interface:asa2.n3; prt = icmp 5;
    permit src = user; dst = interface:asa2.n3; prt = icmp;
}
=END=
=OUTPUT=
s1:deny 10.1.9.10 10.1.3.2 icmp 5
s1:deny 10.1.2.0/24 10.1.3.2 icmp 5
s1:permit 10.1.9.10 10.1.3.0/24 tcp 21
s1:permit 10.1.2.0/24 10.1.3.0/24 tcp 21
s1:permit 10.1.9.10 10.1.3.0/24 tcp 1024-65535
s1:permit 10.1.2.0/24 10.1.3.0/24 tcp 1024-65535
s1:permit 10.1.3.0/24 10.1.9.10 tcp 20:1024-65535
s1:permit 10.1.3.0/24 10.1.2.0/24 tcp 20:1024-65535
s1:permit 10.1.9.10 10.1.3.9 udp 123
s1:permit 10.1.9.10 10.1.3.10 udp 123
s1:permit 10.1.2.0/24 10.1.3.9 udp 123
s1:permit 10.1.2.0/24 10.1.3.10 udp 123
s1:permit 10.1.9.10 10.1.3.2 icmp 3/3
s1:permit 10.1.2.0/24 10.1.3.2 icmp 3/3
s1:permit 10.1.9.10 10.1.3.2 icmp
s1:permit 10.1.2.0/24 10.1.3.2 icmp
=END=
=OPTION=--nat n3
=PARAM=service:s1

############################################################
=TITLE=All services
=VAR=input
${topo}
service:s1 = {
    user = network:n1;
    permit src = user; dst = network:n3; prt = ip;
}
service:s2 = {
    user = network:n2;
    permit src = user; dst = network:n3; prt = tcp;
}
=END=
=INPUT=${input}
=OUTPUT=
s1:permit 10.1.1.0/24 10.1.3.0/24 ip
s2:permit 10.1.2.0/24 10.1.3.0/24 tcp
=END=

############################################################
=TITLE=Missing "service:" keyword
=INPUT=${input}
=OUTPUT=
s1:permit 10.1.1.0/24 10.1.3.0/24 ip
s2:permit 10.1.2.0/24 10.1.3.0/24 tcp
=END=
=PARAM=s1 service:s2

############################################################
=TITLE=Multiple services, show names of objects
=INPUT=${input}
=OUTPUT=
s1:permit network:n1 network:n3 ip
s2:permit network:n2 network:n3 tcp
=END=
=OPTION=--name
=PARAM=service:s1 service:s2

############################################################
