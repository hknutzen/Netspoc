
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR OBJECT ...
  -f, --file string   Read OBJECTS from file
  -q, --quiet         Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR OBJECT ...
  -f, --file string   Read OBJECTS from file
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
Error while reading netspoc files: Typed name expected at line 1 of INPUT, near "--HERE-->invalid"
=END=

############################################################
=TITLE=Verbose output
=INPUT=
group:g1 =
 host:a,
 host:b,
;
=END=
=OUTPUT=
group:g1 =
 host:b,
;
=END=
=WARNING=
Changed INPUT
=OPTIONS=--quiet=false
=PARAMS=host:a

############################################################
=TITLE=Can't change readonly file
=INPUT=
--f1
group:g1 = host:a;
=SETUP=
chmod u-w netspoc/f1
=PARAMS=host:a
=ERROR=
panic: Can't open f1: permission denied
=END=

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
=PARAMS=host:Toast

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
=PARAMS=host:h

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
=PARAMS=host:h

############################################################
=TITLE=automatic interface before host
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
=PARAMS=interface:r1@vrf.[auto]

############################################################
=TITLE=Don't remove in intersection
=INPUT=
group:abc = group:g &! host:xyz;
=END=
=OUTPUT=
group:abc = group:g &! host:xyz;
=END=
=PARAMS=host:xyz

############################################################
=TITLE=Remove group definition although still referenced in intersection
=INPUT=
group:abc = group:g &! host:xyz;
group:g = host:a;
=END=
=OUTPUT=
group:abc =
 group:g
 &! host:xyz
 ,
;
=END=
=PARAMS=group:g

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
=PARAMS=network:n

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
=PARAMS=network:n1a network:n4

############################################################
=TITLE=area in automatic group
=INPUT=
group:abc =
 network:[
  area:a1,
  area:a2,
 ],
;
=END=
=OUTPUT=
group:abc =
 network:[area:a1],
;
=END=
=PARAMS=area:a2

############################################################
=TITLE=Automatic interface group
=INPUT=
group:abc =
 interface:[
  network:n1,
  network:n2,
 ].[all],
;
=END=
=OUTPUT=
group:abc =
 interface:[network:n1].[all],
;
=END=
=PARAMS=network:n2

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
group:y =
 host:x,
 host:y,
 host:z,
;
=END=
=OUTPUT=
service:x = {
 user = host:b;
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
=PARAMS=host:y group:y interface:r.x

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
=PARAMS=host:a1 host:b1 host:d1 host:e1 host:f1 host:g1

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
=PARAMS=host:a

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
=PARAMS=host:b

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
=PARAMS=host:a host:b

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
=PARAMS=host:Muess host:Maß

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
=OUTPUT=
group:g =
 network:xyz,
 interface:r.n.sec,
 host:abc,
;
=END=
=FOPTION=
any:aaa
network:abx
host:id:xyz@dom
group:bbb
interface:r.n
=END=

############################################################
=TITLE=Read pairs from unknown file
=INPUT=#
=PARAMS=-f unknown
=ERROR=
Error: Can't open unknown: no such file or directory
=END=

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
=PARAMS=host:c group:g2

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
 description = host:a, host:b,
 host:a,
;
=END=
=PARAMS=host:b

############################################################
=TITLE=Missing type
=INPUT=
group:g1 = host:a;
=END=
=ERROR=
Error: Missing type in host_a
=END=
=PARAMS=host_a

############################################################
=TITLE=Unsupported type
=INPUT=
group:g1 = host:a;
=END=
=ERROR=
Error: Can't use type in service:s1
=END=
=PARAMS=service:s1

############################################################
=TITLE=Can't remove automatic group
=INPUT=
group:g1 =
 any:[ip=10.1.1.0/24&network:n1],
;
=END=
=ERROR=
Error: Invalid character '=' in any:[ip=10.1.1.0/24&network:n1]
=END=
=PARAMS=any:[ip=10.1.1.0/24&network:n1]

############################################################
