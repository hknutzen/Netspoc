
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR GROUP-NAME ...
  -f, --file string   Read GROUP-NAMES from file
  -q, --quiet         Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR GROUP-NAME ...
  -f, --file string   Read GROUP-NAMES from file
  -q, --quiet         Don't show changed files
=END=

############################################################
=TITLE=Unknown option
=INPUT=#
=PARAMS=--abc
=ERROR=
Error: unknown flag: --abc
=END=

############################################################
=TITLE=Bad parameter
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Expected group name but got 'bad:name'
=PARAMS=bad:name

############################################################
=TITLE=Read pairs from unknown file
=INPUT=#
=PARAMS=-f unknown
=ERROR=
Error: Can't open unknown: no such file or directory
=END=

############################################################
=TITLE=Invalid input
=INPUT=
invalid
=ERROR=
Error: Typed name expected at line 1 of INPUT, near "--HERE-->invalid"
=END=

############################################################
=TITLE=Abort, if no group definition found
=INPUT=
group:g2 =
 group:g1,
 host:a,
 host:b;
=ERROR=
Error: No defintion found for 'group:g1'
=PARAMS=group:g1

############################################################
=TITLE=Substitute empty group
=INPUT=
group:g2 =
 group:g1,
 host:a,
 host:b,
;
group:g1 = ;
=OUTPUT=
group:g2 =
 host:a,
 host:b,
;
=PARAMS=group:g1

############################################################
=TITLE=Multiple substitutions of nested groups
=INPUT=
group:g1 = host:a;
group:g2 = group:g1, host:b;
group:g3 = group:g2, host:c;
=OUTPUT=
group:g3 =
 host:a,
 host:b,
 host:c,
;
=PARAMS=group:g1 group:g2

############################################################
=TITLE=Multiple substitutions of nested groups from file
=INPUT=
group:g1 = host:a;
group:g2 = group:g1, host:b;
group:g3 = group:g2, host:c;
=OUTPUT=
group:g3 =
 host:a,
 host:b,
 host:c,
;
=FOPTION=
group:g2
group:g1
=END=

############################################################
=TITLE=Substitute in automatic group
=INPUT=
group:g1 = host:a;
group:g2 = host:b, network:c;
group:g3 = interface:[network:n1, interface:r1.n2].[all];
group:g4 =
 network:[group:g1, group:g2],
 any:[ip=10.99.0.0/16 & group:g2],
 interface:[managed & group:g3].[auto],
;
=OUTPUT=
group:g4 =
 any:[ip = 10.99.0.0/16 &
  network:c,
  host:b,
 ],
 network:[
  network:c,
  host:a,
  host:b,
 ],
 interface:[managed &
  interface:[
   network:n1,
   interface:r1.n2,
  ].[all],
 ].[auto],
;
=PARAMS=group:g1 group:g2 group:g3

############################################################
=TITLE=Expand group in intersection
=INPUT=
group:g1 = host:a, host:b;
group:g2 = host:c, host:d;
group:g3 =
 interface:r1.[auto], interface:r2.n1, interface:r2.n2, interface:r3.[all];
group:g4 = group:g1 &! host:a;
group:g5 = !group:g1 & host:[network:n] &! group:g2;
group:g6 =
 group:g3 &! interface:r1.[auto] &! interface:r2.n2 &! interface:r3.[all];
 group:g7 = group:g1 &! host:a &! host:b;
=OUTPUT=
group:g4 =
 host:b,
;
group:g5 =
 host:[network:n]
 &! host:a
 &! host:b
 &! host:c
 &! host:d
 ,
;
group:g6 =
 interface:r2.n1,
;
group:g7 =
;
=PARAMS=group:g1 group:g2 group:g3

############################################################
=TITLE=Expand group with single element even in complex intersection
=INPUT=
group:g1 = host:[network:n];
group:g2 = interface:r.[all];
group:g6 = group:g1 &! host:a &! host:b;
group:g8 = group:g1 &! group:g1;
group:g9 = group:g2 &! interface:r.[auto];
=OUTPUT=
group:g6 =
 host:[network:n]
 &! host:a
 &! host:b
 ,
;
group:g8 =
 host:[network:n]
 &! host:[network:n]
 ,
;
group:g9 =
 interface:r.[all]
 &! interface:r.[auto]
 ,
;
=PARAMS=group:g1 group:g2

############################################################
=TITLE=Leave group unexpanded in complex intersection
=INPUT=
group:g1 = host:a, host:b;
group:g2 = host:[network:n];
group:g3 = group:g1 &! host:c;
group:g4 = group:g1 &! host:[network:n];
group:g5 = group:g1 & group:g2;
=OUTPUT=
group:g1 = host:a, host:b;
group:g2 = host:[network:n];
group:g3 = group:g1 &! host:c;
group:g4 = group:g1 &! host:[network:n];
group:g5 = group:g1 & group:g2;
=PARAMS=group:g1 group:g2

############################################################
=TITLE=Substitute in service
=INPUT=
group:g1 = host:a, host:b;
group:g2 = host:c, host:d;
service:s1 = {
 user = group:g1;
 permit src = user; dst = group:g2; prt = tcp 80;
 permit src = group:g2; dst = user; prt = icmp 8;
}
=OUTPUT=
service:s1 = {
 user = host:a,
        host:b,
        ;
 permit src = user;
        dst = host:c,
              host:d,
              ;
        prt = tcp 80;
 permit src = host:c,
              host:d,
              ;
        dst = user;
        prt = icmp 8;
}
=PARAMS=group:g1 group:g2

############################################################
=TITLE=Substitute in area
=INPUT=
group:g1 = interface:r1.[all] &! interface:r1.n1;
group:g2 = interface:r3.n4;
area:a = {
 border = interface:r3.n3, group:g1;
 inclusive_border = group:g2;
}
=OUTPUT=
area:a = {
 border = interface:r1.[all]
          &! interface:r1.n1
          ,
          interface:r3.n3,
          ;
 inclusive_border = interface:r3.n4;
}
=PARAMS=group:g1 group:g2

############################################################
=TITLE=Substitute in pathrestriction
=INPUT=
group:g1 = interface:r1.[all] &! interface:r1.n1;
pathrestriction:p =
 interface:r3.n3,
 group:g1,
;
=OUTPUT=
pathrestriction:p =
 interface:r1.[all]
 &! interface:r1.n1
 ,
 interface:r3.n3,
;
=PARAMS=group:g1

############################################################
=TITLE=Substitute into different files and preserve comments
=INPUT=
-- file1
group:g1 =
 host:a, # comment a
 host:b, # comment b
;
--file2
group:g2 =
 group:g1, # comment g1
;
-- file3
pathrestriction:r = group:g1;
-- file4
group:g3 =
 group:g1
 &! group:x
 ,
;
=OUTPUT=
-- file1
group:g1 =
 host:a, # comment a
 host:b, # comment b
;
-- file2
group:g2 =
 host:a, # comment a
 host:b, # comment b
;
-- file3
pathrestriction:r =
 host:a, # comment a
 host:b, # comment b
;
-- file4
group:g3 =
 group:g1
 &! group:x
 ,
;
=WARNING=
Changed file2
Changed file3
=OPTIONS=--quiet=false
=PARAMS=group:g1

############################################################
