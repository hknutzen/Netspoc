
############################################################
=TITLE=host at network
=INPUT=
################# Comment in first line must not be appended to added item.
network:Test =  { ip = 10.9.1.0/24; }
group:G = interface:r.Test, # comment
    host:id:h@dom.top.Test,
    network:Test,
host:x, network:Test, host:y,
    ;
=END=
=OUTPUT=
################# Comment in first line must not be appended to added item.
network:Test = { ip = 10.9.1.0/24; }
group:G =
 network:Test,
 network:Test,
 interface:r.Test, # comment
 host:Toast,
 host:Toast,
 host:id:h@dom.top.Test,
 host:x,
 host:y,
;
=END=
=PARAM=network:Test host:Toast

############################################################
=TITLE=host after automatic group
=INPUT=
group:abc =
 any:[ ip = 10.1.0.0/16 & network:def ],
 host:xyz,
;
=END=
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 & network:def],
 host:h,
 host:xyz,
;
=END=
=PARAM=host:xyz host:h

############################################################
=TITLE=host after automatic interface
=INPUT=
group:abc =
 interface:r1@vrf.[auto],
 network:xyz,
;
=END=
=OUTPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
 host:h,
;
=END=
=PARAM=interface:r1@vrf.[auto] host:h

############################################################
=TITLE=automatic interface after host
=INPUT=
group:abc =
 host:h,
 network:xyz,
;
=END=
=OUTPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
 host:h,
;
=END=
=PARAM=host:h interface:r1@vrf.[auto]

############################################################
=TITLE=network after intersection
=INPUT=
group:abc =
 group:g &! host:xyz,
 network:def,
;
=END=
=OUTPUT=
group:abc =
 group:g
 &! host:xyz
 ,
 network:def,
 network:n,
;
=END=
=PARAM=network:def network:n

############################################################
=TITLE=Do not add in intersection
=INPUT= group:g2 = group:g1 &! network:n2;
=OUTPUT=group:g2 = group:g1 &! network:n2;
=PARAM=group:g1 group:g3

############################################################
=TITLE=Group with intersection
=INPUT=
group:g3 = group:g1, group:g2 &! network:n2;
=END=
=OUTPUT=
group:g3 =
 group:g1,
 group:g3,
 group:g2
 &! network:n2
 ,
;
=END=
=PARAM=group:g1 group:g3

############################################################
=TITLE=network in automatic group
=INPUT=
group:abc =
 any:[ ip = 10.1.0.0/16 & network:n1, network:n2,
       network:n3, ],
;
=END=
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 &
  network:n1,
  network:n1a,
  network:n2,
  network:n3,
  network:n4,
 ],
;
=END=
=PARAM=network:n1 network:n1a network:n3 network:n4

############################################################
=TITLE=area in automatic group
=INPUT=
group:abc =
 any:[ ip = 10.1.0.0/16 & area:a1, ],
;
=END=
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 &
  area:a1,
  area:a2,
 ],
;
=END=
=PARAM=area:a1 area:a2

############################################################
=TITLE=in service, but not in area and pathrestriction
=INPUT=
service:x = {
 user = interface:r.x, host:b;
 permit src = any:x; dst = user; prt = tcp;
 permit src = user; dst = any:x;
        prt = tcp;
}
pathrestriction:p =
 interface:r.x,
 interface:r.y
;
area:a = {
 border = interface:r.x;
}
=END=
=OUTPUT=
service:x = {
 user = interface:r.x,
        host:b,
        host:y,
        ;
 permit src = group:y,
              any:x,
              ;
        dst = user;
        prt = tcp;
 permit src = user;
        dst = group:y,
              any:x,
              ;
        prt = tcp;
}
pathrestriction:p =
 interface:r.x,
 interface:r.y,
;
area:a = {
 border = interface:r.x;
}
=END=
=PARAM=interface:r.x host:y any:x group:y

############################################################
=TITLE=with indentation
=INPUT=
group:x =
 host:a,
  host:b, host:c,
  host:d
  ,
  host:e ###
  , host:f,
  host:g;
=END=
=OUTPUT=
group:x =
 host:a,
 host:a1,
 host:b,
 host:b1,
 host:c,
 host:d,
 host:d1,
 host:e, ###
 host:e1,
 host:f,
 host:f1,
 host:g,
 host:g1,
;
=END=
=PARAM=host:a host:a1 host:b host:b1 host:d host:d1 host:e host:e1 host:f host:f1 host:g host:g1

############################################################
=TITLE=Add on new line for single object after definition
=INPUT=
group:g-1 = host:a,
          ;
=END=
=OUTPUT=
group:g-1 =
 host:a,
 host:a1,
;
=END=
=PARAM=host:a host:a1

############################################################
=TITLE=List terminates at EOF
=INPUT=group:g = host:a;
=OUTPUT=
group:g =
 host:a,
 host:b,
;
=END=
=PARAM=host:a host:b
=TODO=How to fill INPUT without EOL?

############################################################
=TITLE=Unchanged list  at EOF
=INPUT=group:g = host:a;
=OUTPUT=group:g = host:a;
=PARAM=host:x host:b
=TODO=How to fill INPUT and OUPUT without EOL?


############################################################
=TITLE=Find and change umlauts
=INPUT=
group:BÖSE = host:Müß, host:Mass;
=END=
=OUTPUT=
group:BÖSE =
 host:Mass,
 host:Maß,
 host:Muess,
 host:Müß,
;
=END=
=PARAM=host:Müß host:Muess host:Mass host:Maß

############################################################
=TITLE=Read pairs from file
=VAR=pairs
host:abc network:abx
network:xyz host:id:xyz@dom
any:aaa group:bbb
interface:r.n.sec interface:r.n
=INPUT=
group:g =
interface:r.n, interface:r.n.sec,
any:aaa, network:xyz,
host:abc;
=END=
=OUTPUT=
group:g =
 group:bbb,
 any:aaa,
 network:abx,
 network:xyz,
 interface:r.n,
 interface:r.n,
 interface:r.n.sec,
 host:abc,
 host:id:xyz@dom,
;
=END=
=OPTION=-f $filename
=TODO=Can't fill file from =VAR=

############################################################
=TITLE=Add multiple entries to one object
=INPUT=
service:s = {
 user = group:g;
 permit src = user; dst = host:x; prt = tcp 80;
}
=END=
=OUTPUT=
service:s = {
 user = group:g,
        host:a,
        host:b,
        ;
 permit src = user;
        dst = host:x;
        prt = tcp 80;
}
=END=
=PARAM=group:g host:a group:g host:b

############################################################
