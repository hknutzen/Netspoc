
############################################################
=TITLE=Order of elements
# Order of elements in ACL should be the same as in service.
=INPUT=
network:n0 = { ip = 10.1.0.0/25; }
network:n1 = { ip = 10.1.1.0/25; }
network:n2 = { ip = 10.1.2.0/25; }
network:n3 = { ip = 10.1.3.0/25; }
network:n4 = { ip = 10.1.4.0/25; }
network:n5 = { ip = 10.1.5.0/25; }
network:n6 = { ip = 10.1.6.0/25; }
network:n7 = { ip = 10.1.7.0/25; }
network:n8 = { ip = 10.1.8.0/25; }
network:n9 = { ip = 10.1.9.0/25; }
network:n10 = { ip = 10.1.10.0/25; }
router:r1 = {
 model = IOS, FW;
 managed;
 interface:n0 = { ip = 10.1.0.1; hardware = n0; }
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
router:r2 = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
 interface:n5 = { ip = 10.1.5.1; hardware = n5; }
 interface:n6 = { ip = 10.1.6.1; hardware = n6; }
 interface:n7 = { ip = 10.1.7.1; hardware = n7; }
 interface:n8 = { ip = 10.1.8.1; hardware = n8; }
 interface:n9 = { ip = 10.1.9.1; hardware = n9; }
 interface:n10 = { ip = 10.1.10.1; hardware = n10; }
}
service:s1 = {
 user = network:n1,
        network:n2,
        network:n3,
        network:n4,
        network:n5,
        network:n9,
        network:n8,
        network:n7,
        network:n6,
        network:n10,
        ;
 permit src = user; dst = network:n0; prt = ip;
}
=OUTPUT=
--r1
ip access-list extended n1_in
 deny ip any host 10.1.0.1
 permit ip 10.1.1.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.2.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.3.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.4.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.5.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.9.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.8.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.7.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.6.0 0.0.0.127 10.1.0.0 0.0.0.127
 permit ip 10.1.10.0 0.0.0.127 10.1.0.0 0.0.0.127
 deny ip any any
=END=

############################################################
