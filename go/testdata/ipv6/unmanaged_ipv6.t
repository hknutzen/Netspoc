
############################################################
=TITLE=Owner at unmanaged router
=PARAMS=--ipv6
=INPUT=
owner:o = { admins = a@example.com; }
router:r = {
 owner = o;
 interface:n1 = { ip = ::a01:101; }
}
network:n1 = { ip = ::a01:100/120; }
=END=
=WARNING=
Warning: Ignoring attribute 'owner' at unmanaged router:r
=END=

############################################################
=TITLE=Crypto hub at unmanaged router
=PARAMS=--ipv6
=INPUT=
ipsec:i = {
 key_exchange = isakmp:i;
 lifetime = 600 sec;
}
isakmp:i = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}
crypto:c = {
 type = ipsec:i;
}
router:r = {
 interface:n1 = { ip = ::a01:101; hub = crypto:c; }
}
network:n1 = { ip = ::a01:100/120; }
=END=
=WARNING=
Warning: Ignoring attribute 'hub' at unmanaged interface:r.n1
Warning: No hub has been defined for crypto:c
=END=

############################################################
=TITLE=Unmanaged bridge interfaces
=PARAMS=--ipv6
=INPUT=
network:n1/left = { ip = ::a01:100/120; }
router:bridge = {
 interface:n1/left = { hardware = inside; }
 interface:n1/right = { hardware = outside; }
}
network:n1/right = { ip = ::a01:100/120; }
=END=
=ERROR=
Error: network:n1/right and network:n1/left must be connected by bridge
Error: network:n1/left and network:n1/right have identical IP/mask in any:[network:n1/left]
=END=

############################################################
=TITLE=Unmanaged interfaces inside area
# Prevent duplicate interfaces in complicated unmanaged loop.
=PARAMS=--ipv6
=INPUT=
network:C1 = { ip = ::a01:0/117;}
network:C2 = { ip = ::a02:0/117;}
network:C3 = { ip = ::a03:0/117;}
network:cross = {ip = ::a09:500/126;}
router:u1 = {
 interface:C1 = {ip = ::a01:3;   virtual = {ip = ::a01:1; }}
 interface:C2 = {ip = ::a02:3; virtual = {ip = ::a02:1; }}
 interface:C3 = {ip = ::a03:3; virtual = {ip = ::a03:1; }}
 interface:cross = {ip = ::a09:502;}
 interface:u1n = {ip = ::af1:d262;}
}
router:u2 = {
 interface:C2   = {ip = ::a02:2; virtual = {ip = ::a02:1;} }
 interface:cross = {ip = ::a09:501; }
 interface:u2n = {ip = ::af1:7219; }
}
router:u3 = {
 interface:C1 = {ip = ::a01:2; virtual = {ip = ::a01:1; } }
 interface:C3 = {ip = ::a03:2; virtual = {ip = ::a03:1; } }
 interface:u3n = {ip = ::af1:7211; }
}
network:u1n = {ip = ::af1:d260/126;}
network:u2n = {ip = ::af1:7218/126;}
network:u3n = {ip = ::af1:7210/126;}
router:b1 = {
 interface:u2n = {ip = ::af1:721a;}
 interface:u3n = {ip = ::af1:7212;}
 interface:b = {ip = ::a09:1075;}
}
router:b2 = {
 interface:u1n = {ip = ::af1:d261;}
 interface:b = {ip = ::a09:1076;}
}
network:b = {ip = ::a09:1070/125; }
router:FW = {
 managed;
 routing = manual;
 model = ASA;
 interface:b = {ip = ::a09:1074; hardware = outside;}
 interface:D = {ip = ::a01:b01; hardware = inside;}
}
network:D = { ip = ::a01:b00/120;}
area:g1 = { border = interface:FW.b;}
service:test = {
 user = interface:[area:g1].[all];
 permit src = user; dst = network:D; prt = tcp 80;
}
=END=
=OUTPUT=
--ipv6/FW
object-group network v6g0
 network-object host ::a01:1
 network-object ::a01:2/127
 network-object host ::a02:1
 network-object ::a02:2/127
 network-object host ::a03:1
 network-object ::a03:2/127
 network-object host ::a09:501
 network-object host ::a09:502
 network-object host ::a09:1075
 network-object host ::a09:1076
 network-object host ::af1:7211
 network-object host ::af1:7212
 network-object host ::af1:7219
 network-object host ::af1:721a
 network-object host ::af1:d261
 network-object host ::af1:d262
access-list outside_in extended permit tcp object-group v6g0 ::a01:b00/120 eq 80
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=END=

############################################################
