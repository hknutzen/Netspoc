=VAR=topo
network:x = { ip = ::a01:100/120;
}
router:r = {
 model = IOS;
 managed;
 interface:x = { ip = ::a01:101; hardware = e0; }
 interface:y = { ip = ::a02:202; hardware = e1; }
}
network:y = { ip = ::a02:200/120;
 host:y = { ip = ::a02:209; }
}
=END=

############################################################
=TITLE=Optimize reverse rules
=PARAMS=--ipv6
=INPUT=
${topo}
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
--ipv6/r
ipv6 access-list e0_in
 deny ipv6 any host ::a02:202
 permit ipv6 ::a01:100/120 ::a02:200/120
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any host ::a01:101
 permit ipv6 ::a02:200/120 ::a01:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=Reverse UDP ports
=PARAMS=--ipv6
=INPUT=
${topo}
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = udp 389;
}
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list e0_in
 deny ipv6 any host ::a02:202
 permit udp ::a01:100/120 ::a02:200/120 eq 389
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any host ::a01:101
 permit udp ::a02:200/120 eq 389 ::a01:100/120
 deny ipv6 any any
=END=

############################################################
=TITLE=UDP source port with unspecified destination port
=PARAMS=--ipv6
=INPUT=
${topo}
protocol:ike = udp 69:1-65535;
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = protocol:ike;
}
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list e0_in
 deny ipv6 any host ::a02:202
 permit udp ::a01:100/120 eq 69 ::a02:200/120
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any host ::a01:101
 permit udp ::a02:200/120 ::a01:100/120 eq 69
 deny ipv6 any any
=END=

############################################################
=TITLE=UDP source ports
=PARAMS=--ipv6
=INPUT=
${topo}
protocol:ike = udp 500:500;
service:test = {
 user = network:x;
 permit src = user; dst = network:y; prt = protocol:ike;
}
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list e0_in
 deny ipv6 any host ::a02:202
 permit udp ::a01:100/120 eq 500 ::a02:200/120 eq 500
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any host ::a01:101
 permit udp ::a02:200/120 eq 500 ::a01:100/120 eq 500
 deny ipv6 any any
=END=

############################################################
=TITLE=Optimized UDP source ports
=PARAMS=--ipv6
=INPUT=
${topo}
protocol:ike = udp 500:500;
service:test = {
 user = network:x, network:y;
 permit src = user; dst = user; prt = protocol:ike;
}
=END=
=OUTPUT=
--ipv6/r
ipv6 access-list e0_in
 deny ipv6 any host ::a02:202
 permit udp ::a01:100/120 eq 500 ::a02:200/120 eq 500
 deny ipv6 any any
--
ipv6 access-list e1_in
 deny ipv6 any host ::a01:101
 permit udp ::a02:200/120 eq 500 ::a01:100/120 eq 500
 deny ipv6 any any
=END=

############################################################
=TITLE=No warning on overlapping stateless range
=PARAMS=--ipv6
=INPUT=
${topo}
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
--ipv6/r
! [ ACL ]
ipv6 access-list e0_in
 deny ipv6 any host ::a02:202
 permit tcp ::a01:100/120 ::a02:200/120 gt 1023
 deny ipv6 any any
=END=

############################################################
