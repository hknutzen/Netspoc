
############################################################
=TITLE=General permit
=VAR=input
network:m = { ip = 10.2.2.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmp 0, icmp 3;
 interface:m = { ip = 10.2.2.2; hardware = e0; }
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
network:n = { ip = 10.1.1.0/24; }
service:test = {
 user = network:m;
 permit src = user; dst = network:n; prt = icmp;
}
=END=
=INPUT=${input}
=OUTPUT=
--r
ip access-list e0_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any 10.1.1.2/32
 50 permit icmp 10.2.2.0/24 10.1.1.0/24
 60 deny ip any any
--
ip access-list e1_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any any
=END=

############################################################
=TITLE=General permit (Linux)
=INPUT=${input}
=SUBST=/NX-OS/Linux/
=OUTPUT=
--r
# [ ACL ]
:c1 -
:c2 -
:c3 -
:c4 -
:c5 -
-A c1 -j ACCEPT -p icmp --icmp-type 0
-A c1 -j ACCEPT -p icmp --icmp-type 3
-A c2 -j ACCEPT -p icmp --icmp-type 0
-A c2 -j ACCEPT -p icmp --icmp-type 3
-A c3 -j c2 -p icmp
-A c3 -j ACCEPT -s 10.2.2.0/24 -d 10.1.1.0/24 -p icmp
-A c4 -j ACCEPT -p icmp --icmp-type 0
-A c4 -j ACCEPT -p icmp --icmp-type 3
-A c5 -j ACCEPT -p icmp --icmp-type 0
-A c5 -j ACCEPT -p icmp --icmp-type 3
--
:e0_self -
-A e0_self -j ACCEPT -p tcp
-A e0_self -g c1 -p icmp
-A INPUT -j e0_self -i e0
:e0_e1 -
-A e0_e1 -j ACCEPT -p tcp
-A e0_e1 -g c3 -p icmp
-A FORWARD -j e0_e1 -i e0 -o e1
--
:e1_self -
-A e1_self -j ACCEPT -p tcp
-A e1_self -g c4 -p icmp
-A INPUT -j e1_self -i e1
:e1_e0 -
-A e1_e0 -j ACCEPT -p tcp
-A e1_e0 -g c5 -p icmp
-A FORWARD -j e1_e0 -i e1 -o e0
=END=

############################################################
=TITLE=General permit with no_in_acl
=INPUT=
network:m = { ip = 10.2.2.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmp 0, icmp 3;
 interface:m = { ip = 10.2.2.2; hardware = e0; no_in_acl; }
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
network:n = { ip = 10.1.1.0/24; }
=END=
=OUTPUT=
--r
ip access-list e0_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any 10.2.2.2/32
 50 deny ip any 10.1.1.2/32
 60 permit ip any any
--
ip access-list e1_in
 10 permit icmp any any 0
 20 permit icmp any any 3
 30 permit tcp any any
 40 deny ip any any
=END=

############################################################
=TITLE=No range permitted
=INPUT=
area:all = { anchor = network:n; router_attributes = { general_permit = protocol:ftp-data, tcp 80; } }
network:n = { ip = 10.1.1.0/24; }
protocol:ftp-data = tcp 20:1024-65535;
=END=
=ERROR=
Error: Must not use 'protocol:ftp-data' with ports in general_permit of router_attributes of area:all
Error: Must not use 'tcp 80' with ports in general_permit of router_attributes of area:all
=END=

############################################################
=TITLE=No modifiers permitted
=INPUT=
area:all = { anchor = network:n; router_attributes = { general_permit = protocol:ping-net; } }
network:n = { ip = 10.1.1.0/24; }
protocol:ping-net = icmp 8, src_net, dst_net;
=END=
=ERROR=
Error: Must not use 'protocol:ping-net' with modifiers in general_permit of router_attributes of area:all
=END=

############################################################
=TITLE=Check for useless inheritance
=INPUT=
area:all = { anchor = network:n; router_attributes = { general_permit = icmp, tcp; } }
network:n = { ip = 10.1.1.0/24; }
router:r = {
 managed;
 model = NX-OS;
 general_permit = tcp, icmp;
 interface:n = { ip = 10.1.1.2; hardware = e1; }
}
=END=
=WARNING=
Warning: Useless attribute 'general_permit' at router:r,
 it was already inherited from router_attributes of area:all
=END=

############################################################