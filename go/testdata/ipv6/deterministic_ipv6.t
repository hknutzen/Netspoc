
############################################################
=TITLE=Order of elements
# Order of elements in ACL should be the same as in service.
=INPUT=
network:n0 = { ip6 = ::a01:0/121; }
network:n1 = { ip6 = ::a01:100/121; }
network:n2 = { ip6 = ::a01:200/121; }
network:n3 = { ip6 = ::a01:300/121; }
network:n4 = { ip6 = ::a01:400/121; }
network:n5 = { ip6 = ::a01:500/121; }
network:n6 = { ip6 = ::a01:600/121; }
network:n7 = { ip6 = ::a01:700/121; }
network:n8 = { ip6 = ::a01:800/121; }
network:n9 = { ip6 = ::a01:900/121; }
network:n10 = { ip6 = ::a01:a00/121; }
router:r1 = {
 model = IOS, FW;
 managed;
 interface:n0 = { ip6 = ::a01:1; hardware = n0; }
 interface:n1 = { ip6 = ::a01:101; hardware = n1; }
}
router:r2 = {
 model = ASA;
 managed;
 interface:n1 = { ip6 = ::a01:102; hardware = n1; }
 interface:n2 = { ip6 = ::a01:201; hardware = n2; }
 interface:n3 = { ip6 = ::a01:301; hardware = n3; }
 interface:n4 = { ip6 = ::a01:401; hardware = n4; }
 interface:n5 = { ip6 = ::a01:501; hardware = n5; }
 interface:n6 = { ip6 = ::a01:601; hardware = n6; }
 interface:n7 = { ip6 = ::a01:701; hardware = n7; }
 interface:n8 = { ip6 = ::a01:801; hardware = n8; }
 interface:n9 = { ip6 = ::a01:901; hardware = n9; }
 interface:n10 = { ip6 = ::a01:a01; hardware = n10; }
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
--ipv6/r1
ipv6 access-list n1_in
 deny ipv6 any host ::a01:1
 permit ipv6 ::a01:100/121 ::a01:0/121
 permit ipv6 ::a01:200/121 ::a01:0/121
 permit ipv6 ::a01:300/121 ::a01:0/121
 permit ipv6 ::a01:400/121 ::a01:0/121
 permit ipv6 ::a01:500/121 ::a01:0/121
 permit ipv6 ::a01:900/121 ::a01:0/121
 permit ipv6 ::a01:800/121 ::a01:0/121
 permit ipv6 ::a01:700/121 ::a01:0/121
 permit ipv6 ::a01:600/121 ::a01:0/121
 permit ipv6 ::a01:a00/121 ::a01:0/121
 deny ipv6 any any
=END=

############################################################
