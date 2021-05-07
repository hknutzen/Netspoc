
############################################################
=TITLE=Verbose output
=INPUT=
group:g1 =
 host:c,
 host:d,
;
group:g2 =
 group:g1,
 host:a,
 host:b;
=END=
=OUTPUT=
group:g2 =
 host:a,
 host:b,
 host:c,
 host:d,
;
=WARNING=
Changed INPUT
=OPTIONS=--quiet=false
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
group:g3 = network:[group:g1, group:g2];
=END=
=OUTPUT=
group:g3 =
 network:[
  network:c,
  host:a,
  host:b,
 ],
;
=PARAMS=group:g1 group:g2

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
=TITLE=Substitute in area
=INPUT=
group:g1 = interface:r1.[all] &! interface:r1.n1;
area:a = {
 border = interface:r3.n3, group:g1;
}
=END=
=OUTPUT=
area:a = {
 border = interface:r1.[all]
          &! interface:r1.n1
          ,
          interface:r3.n3,
          ;
}
=PARAMS=group:g1

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
=TITLE=Bad parameter
=INPUT=
group:g1 = host:a;
=ERROR=
Error: Expected group name but got 'bad:name'
=PARAMS=bad:name

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
