
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR OBJECT ...
  -d, --delete        Also delete definition if OBJECT is host or interface
  -f, --file string   Read OBJECTS from file
  -q, --quiet         Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR OBJECT ...
  -d, --delete        Also delete definition if OBJECT is host or interface
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
Error: Typed name expected at line 1 of INPUT, near "--HERE-->invalid"
=END=

############################################################
=TITLE=Verbose output
=INPUT=
group:g1 =
 host:a,
 host:b,
;
=OUTPUT=
group:g1 =
 host:b,
;
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
chmod u-w INPUT/f1
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
=PARAMS=host:Toast

############################################################
=TITLE=host after automatic group
=INPUT=
group:abc =
 any:[ip = 10.1.0.0/16 & network:def],
 host:h,
 host:xyz,
;
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 & network:def],
 host:xyz,
;
=PARAMS=host:h

############################################################
=TITLE=host after automatic interface
=INPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
 host:h,
;
=OUTPUT=
group:abc =
 network:xyz,
 interface:r1@vrf.[auto],
;
=PARAMS=host:h

############################################################
=TITLE=automatic interface before host
=INPUT=
group:abc =
 network:xyz,
 interface:r2.[all],
 interface:r1@vrf.[auto],
 host:h,
;
=OUTPUT=
group:abc =
 network:xyz,
 host:h,
;
=PARAMS=interface:r1@vrf.[auto] interface:r2.[all]

############################################################
=TITLE=Don't remove group in complement, don't remove definition
=INPUT=
group:abc = group:g &! group:xyz;
group:xyz = host:xyz;
=OUTPUT=
group:abc = group:g &! group:xyz;
group:xyz = host:xyz;
=PARAMS=group:xyz

############################################################
=TITLE=Don't remove network in complement
=INPUT=
group:abc = network:[area:g14] &! network:n;
=OUTPUT=
group:abc = network:[area:g14] &! network:n;
=OPTIONS=-d
=PARAMS=network:n

############################################################
=TITLE=But network in group is removed even if group is used in complement
=INPUT=
group:abc = network:[area:g14] &! group:g;
group:g = network:x;
=OUTPUT=
group:abc =
 network:[area:g14]
 &! group:g
 ,
;
group:g =
;
=OPTIONS=-d
=PARAMS=network:x

############################################################
=TITLE=Remove host definition, ignore unknown host
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h12 = { ip = 10.1.1.12; }
}
=OPTIONS=-d
=PARAMS=host:h11 host:h10 host:h13

############################################################
=TITLE=Remove host, also in complement, remove definition
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
group:abc = host:[network:n1] &! host:h10;
group:g = host:h12, host:h12;
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h11 = { ip = 10.1.1.11; }
}
group:abc =
 host:[network:n1],
;
group:g =
;
=OPTIONS=-d
=PARAMS=host:h10 host:h12

############################################################
=TITLE=Remove id host in correct network
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:id:a@b.c = { ip = 10.1.1.10; }
}
network:n2 = {
 ip = 10.1.2.0/24;
 host:id:a@b.c = { ip = 10.1.2.10; }
}
group:g = host:id:a@b.c.n1, host:id:a@b.c.n2;
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = {
 ip = 10.1.2.0/24;
 host:id:a@b.c = { ip = 10.1.2.10; }
}
group:g =
 host:id:a@b.c.n2,
;
=OPTIONS=-d
=PARAMS=host:id:a@b.c.n1

############################################################
=TITLE=Remove interface, remove definition of unmanaged loopback interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1 = { ip = 10.1.1.1; }
 interface:lo1 = { ip = 10.1.1.2; loopback; }
 interface:lo = { ip = 10.1.1.3; loopback; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1;
 interface:lo2 = { ip = 10.1.1.4; loopback; hardware = lo2; }
}
group:abc = group:g &! interface:r1.lo;
group:g = interface:r1.n1, interface:r1.lo, interface:r2.lo2;
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; }
router:r1 = {
 interface:n1  = { ip = 10.1.1.1; }
 interface:lo1 = { ip = 10.1.1.2; loopback; }
}
router:r2 = {
 managed;
 model = IOS;
 interface:n1;
 interface:lo2 = { ip = 10.1.1.4; loopback; hardware = lo2; }
}
group:abc =
 group:g,
;
group:g =
;
=OPTIONS=-d
=PARAMS=interface:r1.lo interface:r1.n1 interface:r2.lo2

############################################################
=TITLE=Remove intersection if non complement element becomes empty (1)
=INPUT=
group:abc = group:g &! host:xyz;
group:g = host:a;
=OUTPUT=
group:abc =
;
=PARAMS=group:g

############################################################
=TITLE=Remove intersection if non complement element becomes empty (2)
=INPUT=
group:abc = group:g & network:[area:a];
group:g = network:a;
=OUTPUT=
group:abc =
;
=PARAMS=group:g

############################################################
=TITLE=Remove intersection if non complement element becomes empty (3)
=INPUT=
group:abc = network:[area:a] & network:[area:b];
=OUTPUT=
group:abc =
;
=PARAMS=area:a

############################################################
=TITLE=Remove in automatic group of intersection
=INPUT=
group:abc =
 network:[area:a, area:b]
 & network:[any:[ip = 10.1.0.0/16 & area:c, area:d]]
;
=OUTPUT=
group:abc =
 network:[area:b]
 & network:[
    any:[ip = 10.1.0.0/16 & area:c],
   ]
 ,
;
=PARAMS=area:a area:d

############################################################
=TITLE=Don't remove in automatic group of complement
=INPUT=
group:abc = network:[area:a] &! network:[group:g];
=OUTPUT=
group:abc = network:[area:a] &! network:[group:g];
=PARAMS=group:g

############################################################
=TITLE=Remove in complement of complement
=INPUT=
group:abc = network:[area:a] &! network:[group:g &! group:h];
=OUTPUT=
group:abc =
 network:[area:a]
 &! network:[group:g]
 ,
;
=PARAMS=group:h

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
=OUTPUT=
group:abc =
 group:g
 &! host:xyz
 ,
 network:def,
;
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
=OUTPUT=
group:abc =
 any:[ip = 10.1.0.0/16 &
  network:n1,
  network:n2,
  network:n3,
 ],
;
=PARAMS=network:n1a network:n4

############################################################
=TITLE=automatic group becomes empty
=INPUT=
group:abc =
 network:[any:[ip = 10.1.0.0/16 &
  network:n1,
  network:n2,
 ]],
 network:n3,
;
=OUTPUT=
group:abc =
 network:n3,
;
=PARAMS=network:n1 network:n2

############################################################
=TITLE=area in automatic group
=INPUT=
group:abc =
 network:[
  area:a1,
  area:a2,
 ],
;
=OUTPUT=
group:abc =
 network:[area:a1],
;
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
=OUTPUT=
group:abc =
 interface:[network:n1].[all],
;
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
=OUTPUT=
# group:g1 =
# host:c,
# ;
group:g2 =
 host:b,
;
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
=OUTPUT=
group:g1 =
 host:a,
;
group:g2 =
;
=PARAMS=host:b

############################################################
=TITLE=Remove service with empty user
=INPUT=
service:s1 = {
 user = host:a,
        host:b;
 permit src = host:c,
              host:d;
        dst = user;
        prt = tcp 80;
}
=OUTPUT=NONE
=PARAMS=host:a host:b

############################################################
=TITLE=Remove service with empty src and overlaps
=INPUT=
service:s1 = {
 user = host:a,
        host:b;
 permit src = host:c,
              host:d;
        dst = user;
        prt = tcp 80;
}
service:s2 = {
 overlaps = service:s1;
 user = host:a;
 permit src = network:n1;
        dst = user;
        prt = tcp 80;
}
=OUTPUT=
service:s2 = {
 user = host:a;
 permit src = network:n1;
        dst = user;
        prt = tcp 80;
}
=PARAMS=host:c host:d

############################################################
=TITLE=Remove some rules of service
=INPUT=
service:x = {
 user = host:a;
 deny   src = host:x;
        dst = user;
        prt = tcp 80;
 permit src = user;
        dst = group:y,
              host:x,
              ;
        prt = tcp;
 permit src = host:x;
        dst = user;
        prt = tcp;
}
=OUTPUT=
service:x = {
 user = host:a;
 permit src = user;
        dst = group:y;
        prt = tcp;
}
=PARAMS=host:x

############################################################
=TITLE=Find and change umlauts
=INPUT=
group:BÖSE =
 host:Mass,
 host:Maß,
 host:Muess,
 host:Müß,
;
=OUTPUT=
group:BÖSE =
 host:Mass,
 host:Müß,
;
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
=OUTPUT=
group:g =
 network:xyz,
 interface:r.n.sec,
 host:abc,
;
=FILE_OPTION=
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
=OUTPUT=
group:g1 =
 host:a,
 host:b,
;
=PARAMS=host:c group:g2

############################################################
=TITLE=Group with description
=INPUT=
group:g1 =
 description = host:a, host:b, ;
 host:a,
 host:b,
;
=OUTPUT=
group:g1 =
 description = host:a, host:b,
 host:a,
;
=PARAMS=host:b

############################################################
=TITLE=Missing type
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->host_a"
=PARAMS=host_a

############################################################
=TITLE=Unsupported type
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Unknown element type at line 1 of command line, near "--HERE-->service:s1"
=PARAMS=service:s1

############################################################
=TITLE=List of elements
=INPUT=
group:g1 = host:a, host:b;
=ERROR=
Error: Can't handle 'host:a,host:b'
=PARAMS=host:a,host:b

############################################################
=TITLE=Can't remove automatic group
=INPUT=
group:g1 =
 any:[ip = 10.1.1.0/24 & network:n1],
;
=ERROR=
Error: Can't handle 'any:[ip=10.1.1.0/24&network:n1]'
=PARAMS=any:[ip=10.1.1.0/24&network:n1]

############################################################
=TITLE=Can't remove automatic interface of network
=INPUT=
group:g1 =
interface:[network:n1].[all]
;
=ERROR=
Error: Can't handle 'interface:[network:n1].[all]'
=PARAMS=interface:[network:n1].[all]

############################################################
=TITLE=Can't remove intersection
=INPUT=
group:g1 =
 network:[any:a] &! network:n1
;
=ERROR=
Error: Can't handle 'network:[any:a]&!network:n1'
=PARAMS=network:[any:a]&!network:n1

############################################################
