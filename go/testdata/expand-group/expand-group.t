
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
=END=
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
=END=
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
=END=
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
=END=
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
=TITLE=Leave definition intact, if used in intersection or complement
=INPUT=
group:g1 = host:a, host:b;
group:g2 = host:c, host:d;
group:g3 = group:g1, group:g2;
group:g4 = group:g1 &! host:a;
group:g5 = host:[network:n] &! group:g2;
=END=
=OUTPUT=
group:g1 =
 host:a,
 host:b,
;
group:g2 =
 host:c,
 host:d,
;
group:g3 =
 host:a,
 host:b,
 host:c,
 host:d,
;
group:g4 =
 group:g1
 &! host:a
 ,
;
group:g5 =
 host:[network:n]
 &! group:g2
 ,
;
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
=END=
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
=END=
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
 &! host:b
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
 &! host:b
 ,
;
=WARNING=
Changed file2
Changed file3
=OPTIONS=--quiet=false
=PARAMS=group:g1

############################################################
