############################################################
=TITLE=host at network
=INPUT=
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
=OUTPUT=
################# Comment in first line must not be appended to added item.
network:Test = { ip = 10.9.1.0/24; }
group:G =
 network:Test,
 network:Test,
 interface:r.Test, # comment
 host:id:h@dom.top.Test,
 host:x,
 host:y,
;
=END=
=PARAM=host:Toast

############################################################
=TITLE=host after automatic group
=INPUT=
group:abc =
 any:[ip = 10.1.0.0/16 & network:def],
 host:h,
 host:xyz,
;
=END=
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 & network:def],
 host:xyz,
;
=END=
=PARAM=host:h

############################################################
=TITLE=host after automatic interface
=INPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
 host:h,
;
=END=
=OUTPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
;
=END=
=PARAM=host:h

############################################################
=TITLE=automatic interface after host
=INPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
 host:h,
;
=END=
=OUTPUT=
group:abc =
 network:xyz,
 host:h,
;
=END=
=PARAM=interface:r1@vrf.[auto]

############################################################
=TITLE=network after intersection
=INPUT=
group:abc =
 group:g
 &! host:xyz
 ,
 network:def,
 network:n,
;
=END=
=OUTPUT=
group:abc =
 group:g
 &! host:xyz
 ,
 network:def,
;
=END=
=PARAM=network:n

############################################################
=TITLE=network in automatic group
=INPUT=
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
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 &
  network:n1,
  network:n2,
  network:n3,
 ],
;
=END=
=PARAM=network:n1a network:n4

############################################################
=TITLE=area in automatic group
=INPUT=
group:abc =
 any:[ip = 10.1.0.0/16 &
  area:a1,
  area:a2,
 ],
;
=END=
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 & area:a1],
;
=END=
=PARAM=area:a2

############################################################
=TITLE=in service, but not in area and pathrestriction
=INPUT=
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
=OUTPUT=
service:x = {
 user = interface:r.x,
        host:b,
        ;
 permit src = any:x;
        dst = user;
        prt = tcp;
 permit src = user;
        dst = any:x;
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
=PARAM=host:y group:y

############################################################
=TITLE=with indentation
=INPUT=
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
=OUTPUT=
group:x =
 host:a,
 host:b,
 host:c,
 host:d,
 host:e, ###
 host:f,
 host:g,
;
=END=
=PARAM=host:a1 host:b1 host:d1 host:e1 host:f1 host:g1

############################################################
=TITLE=Find group after commented group
=INPUT=
# group:g1 =
# host:c,
# ;
group:g2 =
 host:a,
 host:b,
;
=END=
=OUTPUT=
# group:g1 =
# host:c,
# ;
group:g2 =
 host:b,
;
=END=
=PARAM=host:a

############################################################
=TITLE=Remove trailing comma in separate line
=INPUT=
group:g1 =
 host:a,
 host:b #b
 #c
,
;
group:g2 =
 host:b
 #c
  ,;
=END=
=OUTPUT=
group:g1 =
 host:a,
;
group:g2 =
;
=END=
=PARAM=host:b

############################################################
=TITLE=When all elements in one list are removed, do not change next list
=INPUT=
service:s1 = {
 user = host:a,
        host:b;
 permit src = host:c,
              host:d;
        dst = user;
        prt = tcp 80 90;
}
=END=
=OUTPUT=
service:s1 = {
 user = ;
 permit src = host:c,
              host:d,
              ;
        dst = user;
        prt = tcp 80 90;
}
=END=
=PARAM=host:a host:b

############################################################
=TITLE=Find and change umlauts
=INPUT=
group:BÖSE =
 host:Mass,
 host:Maß,
 host:Muess,
 host:Müß,
;
=END=
=OUTPUT=
group:BÖSE =
 host:Mass,
 host:Müß,
;
=END=
=PARAM=host:Muess host:Maß

############################################################
=TITLE=Read pairs from file
=INPUT=
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
=VAR=filename
network:abx
host:id:xyz@dom
group:bbb
interface:r.n
=END=
=OUTPUT=
group:g =
 any:aaa,
 network:xyz,
 interface:r.n.sec,
 host:abc,
;
=END=
=OPTION=-f $filename
=TODO=Can't fill file from =VAR=

############################################################
=TITLE=Element to remove does not exist
=INPUT=
group:g1 =
 host:a,
 host:b,
;
=END=
=OUTPUT=
group:g1 =
 host:a,
 host:b,
;
=END=
=PARAM=host:c

############################################################
=TITLE=Group with description
=INPUT=
group:g1 =
 description = host:a, host:b, ;
 host:a,
 host:b,
;
=END=
=OUTPUT=
group:g1 =
 description = host:a, host:b, ;
 host:a,
;
=END=
=PARAM=host:b

############################################################