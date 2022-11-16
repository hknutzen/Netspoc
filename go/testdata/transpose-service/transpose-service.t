############################################################
=TITLE=Option '-h'
=INPUT=#
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR [service:]NAME
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR [service:]NAME
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=Unknown option
=INPUT=#
=PARAMS=--hasso
=ERROR=
Error: unknown flag: --hasso
=END=

############################################################
=TITLE=Invalid input
=PARAMS=service
=INPUT=
invalid
=ERROR=
Error while reading netspoc files: Typed name expected at line 1 of INPUT, near "--HERE-->invalid"
=END=

############################################################
=TITLE=Unknown service
=PARAMS=service
=INPUT=
network:x = {ip = 10.0.0.0/24;}
=ERROR=
Error: Can't find service service:service
=END=

############################################################
=TITLE=Transpose service
=PARAMS=s1
=INPUT=
service:s1 = {
 user = host:server1,
        host:server2,
        ;
 permit src = user;
        dst = host:u1,
              host:u2,
              ;
        prt = tcp 6514,
              udp 20514,
              ;
}
=OUTPUT=
service:s1 = {
 user = host:u1,
        host:u2,
        ;
 permit src = host:server1,
              host:server2,
              ;
        dst = user;
        prt = tcp 6514,
              udp 20514,
              ;
}
=END=

############################################################
=TITLE=Transpose service again
=PARAMS=s1
=INPUT=
service:s1 = {
 user = host:u1,
        host:u2,
        ;
 permit src = host:server1,
              host:server2,
              ;
        dst = user;
        prt = tcp 6514,
              udp 20514,
              ;
}
=OUTPUT=
service:s1 = {
 user = host:server1,
        host:server2,
        ;
 permit src = user;
        dst = host:u1,
              host:u2,
              ;
        prt = tcp 6514,
              udp 20514,
              ;
}
=END=

############################################################
=TITLE=Multiple rules
=PARAMS=s1
=INPUT=
service:s1 = {
 user = host:server1,
        host:server2,
        ;
 permit src = user;
        dst = host:u1,
              host:u2,
              ;
        prt = tcp 80;
 permit src = user;
        dst = host:u3,
              host:u4,
              ;
        prt = tcp 90;

}
=ERROR=
Error: Can't transpose service: multiple rules present.
=END=

############################################################
=TITLE=Cannot transpose if foreach is activated
=PARAMS=s1
=INPUT=
service:s1 = {
 user = foreach group:g1;
 permit src = user;
        dst = network:[user];
        prt = tcp 80;
}
=ERROR=
Error: Can't transpose service: foreach present.
=END=

############################################################
=TITLE=Cannot transpose if src and dst is user
=PARAMS=useruser
=INPUT=
service:useruser = {
 user = network:n1;
 permit src = user;
        dst = user;
        prt = tcp 80;
}
=ERROR=
Error: Can't transpose service: Both src and dst reference user.
=END=

############################################################
=TITLE=Cannot transpose: dst references nested user
=PARAMS=s1
=INPUT=
service:s1 = {
 user = host:h1, host:h2;
 permit src = user;
        dst = network:[user];
        prt = tcp 80;
}
=ERROR=
Error: Can't transpose service: dst references nested user.
=END=

############################################################
=TITLE=Cannot transpose: src references nested user
=PARAMS=s1
=INPUT=
service:s1 = {
 user = group:g1;
 permit src = network:[user &! host:h3];
        dst = user;
        prt = tcp 6514,
              udp 20514,
              ;
}
=ERROR=
Error: Can't transpose service: src references nested user.
=END=