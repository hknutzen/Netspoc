=TITLE=Simple
=INPUT=
service:s1 = {
 user = network:n1b, network:n1a;
 permit src = user; dst = network:x; prt = 80;
}
service:s3 = {
 user = network:n3a, network:n3b;
 permit src = user; dst = network:x; prt = 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s1 service:s2 service:s3
=OUTPUT=
service:s1 = {
 user = network:n1a,
        network:n1b,
        network:n2,
        network:n3a,
        network:n3b,
        ;
 permit src = user;
        dst = network:x;
        prt = 80;
}
=END=

=TITLE=Merge attributes
=INPUT=
service:s1 = {
 overlaps = service:x;
 has_unenforceable;
 user = network:n1b, network:n1a;
 permit src = user; dst = network:x; prt = 80;
}
service:s3 = {
 overlaps = service:z;
 has_unenforceable;
 user = network:n3a, network:n3b;
 permit src = user; dst = network:x; prt = 80;
}
service:s2 = {
 overlaps = service:y, service:z;
 user = network:n2;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s1 service:s2 service:s3
=OUTPUT=
service:s1 = {
 has_unenforceable;
 overlaps = service:x,
            service:y,
            service:z,
            ;
 user = network:n1a,
        network:n1b,
        network:n2,
        network:n3a,
        network:n3b,
        ;
 permit src = user;
        dst = network:x;
        prt = 80;
}
=END=

=TITLE=Add attributes
=INPUT=
service:s1 = {
 user = network:n1b, network:n1a;
 permit src = user; dst = network:x; prt = 80;
}
service:s2 = {
 overlaps = service:y;
 has_unenforceable;
 user = network:n2;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s1 service:s2
=OUTPUT=
service:s1 = {
 has_unenforceable;
 overlaps = service:y;
 user = network:n1a,
        network:n1b,
        network:n2,
        ;
 permit src = user;
        dst = network:x;
        prt = 80;
}
=END=

=TITLE=Verbose output
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= --quiet=false service:s1 service:s2
=WARNING=
Changed INPUT
=OUTPUT=
service:s1 = {
 user = network:n1,
        network:n2,
        ;
 permit src = user;
        dst = network:x;
        prt = 80;
}
=END=

=TITLE=Lists from file
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:x; prt = 80;
}
service:s3 = {
 user = network:n3;
 permit src = user; dst = network:y; prt = 80;
}
service:s4 = {
 user = network:n4;
 permit src = user; dst = network:y; prt = 80;
}
=FILE_OPTION=
service:s1 service:s2
service:s3 service:s4
=OUTPUT=
service:s1 = {
 user = network:n1,
        network:n2,
        ;
 permit src = user;
        dst = network:x;
        prt = 80;
}
service:s3 = {
 user = network:n3,
        network:n4,
        ;
 permit src = user;
        dst = network:y;
        prt = 80;
}
=END=

=TITLE=Duplicate list from file
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:x; prt = 80;
}
=FILE_OPTION=
service:s1 service:s2
service:s1 service:s2
=ERROR=
Error: Can't find service:s2
=END=

=TITLE= Unknown first service
=INPUT=
service:s2 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= s1 s2
=ERROR=
Error: Can't find service:s1
=END=

=TITLE= Can't combine single service
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s1
=ERROR=
Error: Can't combine single 'service:s1'
=END=

=TITLE= Unknown other service
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s1 service:s3
=ERROR=
Error: Can't find service:s3
=END=

=TITLE= Unknown first service
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s3 service:s1
=ERROR=
Error: Can't find service:s3
=END=

=TITLE= Combine with itself
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s1 service:s1
=ERROR=
Error: Must not combine with itself: service:s1
=END=

=TITLE=Merge service twice
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user; dst = network:x; prt = 80;
}
service:s2 = {
 user = network:n2;
 permit src = user; dst = network:x; prt = 80;
}
=PARAMS= service:s1 service:s2 service:s2
=ERROR=
Error: Can't find service:s2
=END=
