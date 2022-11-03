=TEMPL=topo
network:x = { ip = 10.1.1.0/24;
}
router:r = {
 model = IOS;
 managed;
 interface:x = { ip = 10.1.1.1; hardware = e0; }
 interface:y = { ip = 10.2.2.2; hardware = e1; }
}
network:y = { ip = 10.2.2.0/24;
 host:y = { ip = 10.2.2.9; }
}
=END=

############################################################
=TITLE=Optimize reverse rules
=INPUT=
[[topo]]
service:test1 = {
 user = network:x;
 permit src = user; dst = network:y; prt = ip;
}
service:test2 = {
 overlaps = service:test1;
 user = network:x;
 # globally redundant to rule of service:test1
 permit src = user; dst = host:y; prt = ip;
 # locally redundant at router:r,
 # after reverse rule has been generated for rule of service:test1
 permit src = host:y; dst = user; prt = ip;
 # a reverse rule will be generated internally:
 # permit src = user; dst = host:y; prt = ip; stateless;
 # This internal rule is globally redundant to rule of service:test1
}
=END=
=OUTPUT=
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit ip 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit ip 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=Reverse UDP ports
=INPUT=
[[topo]]
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = udp 389, udp 1024-65535;
}
=END=
=OUTPUT=
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 eq 389
 permit udp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 gt 1023
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 eq 389 10.1.1.0 0.0.0.255
 permit udp 10.2.2.0 0.0.0.255 gt 1023 10.1.1.0 0.0.0.255
 deny ip any any
=END=

############################################################
=TITLE=UDP source port with unspecified destination port
=INPUT=
[[topo]]
protocol:ike = udp 69:1-65535;
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = protocol:ike;
}
=END=
=OUTPUT=
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 eq 69 10.2.2.0 0.0.0.255
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 10.1.1.0 0.0.0.255 eq 69
 deny ip any any
=END=

############################################################
=TITLE=UDP source ports
=INPUT=
[[topo]]
protocol:ike = udp 500:500;
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = protocol:ike;
}
=END=
=OUTPUT=
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 eq 500 10.2.2.0 0.0.0.255 eq 500
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 eq 500 10.1.1.0 0.0.0.255 eq 500
 deny ip any any
=END=

############################################################
=TITLE=Optimized UDP source ports
=INPUT=
[[topo]]
protocol:ike = udp 500:500;
service:test = {
 user = network:x, network:y;
 permit src = user; dst = user; prt = protocol:ike;
}
=END=
=OUTPUT=
--r
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit udp 10.1.1.0 0.0.0.255 eq 500 10.2.2.0 0.0.0.255 eq 500
 deny ip any any
--
ip access-list extended e1_in
 deny ip any host 10.1.1.1
 permit udp 10.2.2.0 0.0.0.255 eq 500 10.1.1.0 0.0.0.255 eq 500
 deny ip any any
=END=

############################################################
=TITLE=No warning on overlapping stateless range
=INPUT=
[[topo]]
protocol:ftp-passive-data = tcp 1024-65535, stateless;
service:s = {
 user = network:x;
 permit src =   user;
        dst =   network:y;
        prt =   protocol:ftp-passive-data,
                tcp 3389,
                ;
}
=END=
=OUTPUT=
--r
! [ ACL ]
ip access-list extended e0_in
 deny ip any host 10.2.2.2
 permit tcp 10.1.1.0 0.0.0.255 10.2.2.0 0.0.0.255 gt 1023
 deny ip any any
=END=

############################################################
=TITLE=Reverse rule for model with statelessSelf
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 model = IOS, FW;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}

service:s1 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n1; prt = udp 68;
}
=OUTPUT=
--r1
! [ ACL ]
ip access-list extended n1_in
 permit udp 10.1.1.0 0.0.0.255 eq 68 host 10.1.1.1
 deny ip any any
=END=

############################################################
=TITLE=Generate no reverse rule for model without statelessSelf
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 model = Linux;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}

service:s1 = {
 user = interface:r1.n1;
 permit src = user; dst = network:n1; prt = udp 68;
}
=OUTPUT=
--r1
# [ ACL ]
:n1_self -
-A INPUT -j n1_self -i n1
=END=

############################################################
