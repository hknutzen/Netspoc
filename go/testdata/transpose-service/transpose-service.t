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
 description = testservice
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
 description = testservice
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
=TITLE=Multiple rules
=PARAMS=s1
=INPUT=
service:s1 = {
 description = testservice
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
 permit src = user;
        dst = host:u3,
              host:u4,
              ;
        prt = tcp 6514,
              udp 20514,
              ;

}
=ERROR=
Error: Can't transpose service: multiple rules present.
=END=

############################################################
=TITLE=Cannot transpose if all networks from user present in rule
=TODO= Missing functionality
=PARAMS=usernetwork
=INPUT=
service:usernetwork = {
 description = testservice

 user = host:server1,
        host:server2,
        ;
 permit src = user;
        dst = network:[user];
        prt = tcp 6514,
              udp 20514,
              ;
}
=ERROR=
Error: Can't transpose service: network with user present.