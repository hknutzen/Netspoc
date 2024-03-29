
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR PAIR ...
  -f, --file string   Read pairs from file
  -q, --quiet         Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR PAIR ...
  -f, --file string   Read pairs from file
  -q, --quiet         Don't show changed files
=END=

############################################################
=TITLE=Unknown option
=INPUT=NONE
=PARAMS=--abc
=ERROR=
Error: unknown flag: --abc
=END=

############################################################
=TITLE=Invalid input
=INPUT=
invalid
=ERROR=
Error: Typed name expected at line 1 of INPUT, near "--HERE-->invalid"
=END=

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
=OUTPUT=
################# Comment in first line must not be appended to added item.
network:Test = { ip = 10.9.1.0/24; }
group:G =
 network:Test,
 network:Test,
 interface:r.Test, # comment
 host:id:h@dom.top.Test,
 host:Toast,
 host:Toast,
 host:x,
 host:y,
;
=PARAMS=network:Test host:Toast

############################################################
=TITLE=host after automatic group
=INPUT=
group:abc =
 any:[ ip = 10.1.0.0/16 & network:def ],
 host:xyz,
;
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 & network:def],
 host:h,
 host:xyz,
;
=PARAMS=host:xyz host:h

############################################################
=TITLE=host after automatic interface
=INPUT=
group:abc =
 interface:r1@vrf.[auto],
 network:xyz,
;
=OUTPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
 host:h,
;
=PARAMS=interface:r1@vrf.[auto] host:h

############################################################
=TITLE=automatic interface after host
=INPUT=
group:abc =
 host:h,
 network:xyz,
;
=OUTPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
 host:h,
;
=PARAMS=host:h interface:r1@vrf.[auto]

############################################################
=TITLE=network after intersection
=INPUT=
group:abc =
 group:g &! host:xyz,
 network:def,
;
=OUTPUT=
group:abc =
 group:g
 &! host:xyz
 ,
 network:def,
 network:n,
;
=PARAMS=network:def network:n

############################################################
=TITLE=Do not add in intersection
=INPUT= group:g2 = group:g1 &! network:n2;
=OUTPUT=group:g2 = group:g1 &! network:n2;
=PARAMS=group:g1 group:g3

############################################################
=TITLE=Group with intersection
=INPUT=
group:g3 = group:g1, group:g2 &! network:n2;
=OUTPUT=
group:g3 =
 group:g1,
 group:g2
 &! network:n2
 ,
 group:g3,
;
=PARAMS=group:g1 group:g3

############################################################
=TITLE=network in automatic group
=INPUT=
group:abc =
 any:[ ip = 10.1.0.0/16 & network:n1, network:n2,
       network:n3, ],
;
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
=PARAMS=network:n1 network:n1a network:n3 network:n4

############################################################
=TITLE=area in automatic group
=INPUT=
group:abc =
 network:[area:a1],
;
=OUTPUT=
group:abc =
 network:[
  area:a1,
  area:a2,
 ],
;
=PARAMS=area:a1 area:a2

############################################################
=TITLE=Automatic interface group
=INPUT=
group:abc =
 interface:[network:n1].[all],
;
=OUTPUT=
group:abc =
 interface:[
  network:n1,
  network:n2,
 ].[all],
;
=PARAMS=network:n1 network:n2

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
=PARAMS=interface:r.x host:y any:x group:y

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
=PARAMS=host:a host:a1 host:b host:b1 host:d host:d1 host:e host:e1 host:f host:f1 host:g host:g1

############################################################
=TITLE=Add on new line for single object after definition
=INPUT=
group:g-1 = host:a,
          ;
=OUTPUT=
group:g-1 =
 host:a,
 host:a1,
;
=PARAMS=host:a host:a1

############################################################
=TITLE=List terminates at EOF
=INPUT=group:g = host:a;
=OUTPUT=
group:g =
 host:a,
 host:b,
;
=PARAMS=host:a host:b

############################################################
=TITLE=Unchanged list at EOF
=INPUT=group:g = host:a;
=OUTPUT=group:g = host:a;
=PARAMS=host:x host:b

############################################################
=TITLE=Find and change umlauts
=INPUT=
group:BÖSE = host:Müß, host:Mass;
=OUTPUT=
group:BÖSE =
 host:Mass,
 host:Maß,
 host:Muess,
 host:Müß,
;
=PARAMS=host:Müß host:Muess host:Mass host:Maß

############################################################
=TITLE=Read pairs from file
=INPUT=
group:g =
interface:r.n, interface:r.n.sec,
any:aaa, network:xyz,
host:abc;
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
=FILE_OPTION=
host:abc network:abx
network:xyz host:id:xyz@dom
any:aaa group:bbb
interface:r.n.sec interface:r.n
=END=

############################################################
=TITLE=Read pairs from unknown file
=INPUT=#
=PARAMS=-f unknown
=ERROR=
Error: Can't open unknown: no such file or directory
=END=

############################################################
=TITLE=Add multiple entries to one object
=INPUT=
service:s = {
 user = group:g;
 permit src = user; dst = host:x; prt = tcp 80;
}
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
=PARAMS=group:g host:a group:g host:b

############################################################
=TITLE=Incomplete pair
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Missing 2nd. element for 'host:a'
=PARAMS=host:a

############################################################
=TITLE=Invalid type (1)
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->name1"
=PARAMS=name1 name2

############################################################
=TITLE=Invalid type (2)
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->name2"
=PARAMS=host:a name2

############################################################
=TITLE=Invalid type (3)
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Unknown element type at line 1 of command line, near "--HERE-->service:b"
=PARAMS=service:b host:a

############################################################
=TITLE=Invalid type (4)
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Unknown element type at line 1 of command line, near "--HERE-->service:b"
=PARAMS= host:a service:b

############################################################
=TITLE=Can't add to automatic group
=INPUT=
group:g1 =
 any:[ip=10.1.1.0/24&network:n1],
;
=ERROR=
Error: Can't handle 'any:[ip=10.1.1.0/24&network:n1]'
=PARAMS=any:[ip=10.1.1.0/24&network:n1] network:n2

############################################################
