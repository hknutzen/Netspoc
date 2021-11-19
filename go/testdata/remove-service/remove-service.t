############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR [service:]NAME  ...
  -f, --file string   Read SERVICES from file
  -q, --quiet         Don't show changed files
=END=

###############################################################
=TITLE=Try to use without parameter
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR [service:]NAME  ...
  -f, --file string   Read SERVICES from file
  -q, --quiet         Don't show changed files
=END=

############################################################
=TITLE=Read pairs from unknown file
=INPUT=#
=PARAMS=-f unknown
=ERROR=
Error: Can't open unknown: no such file or directory
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
=TITLE=Remove services
=PARAMS= service:s1 service:s2
=INPUT=
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 host:h1 = { ip = 10.1.3.10; }
 host:h2 = { ip = 10.1.3.11; }
}
service:s1 = {
 user = network:n3;
 permit src = user;
	dst = network:n1;
	prt = tcp 25565;
}
service:s2 = {
 user = host:h2;
 permit	src = user;
	dst = network:n1;
	prt = udp 25565;
}
=OUTPUT=
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = {
 ip = 10.1.3.0/24;
 host:h1 = { ip = 10.1.3.10; }
 host:h2 = { ip = 10.1.3.11; }
}
=END=

###############################################################
=TITLE=Try to remove non-existent service
=PARAMS= service:s1
=INPUT=
network:n1 = { ip = 10.1.1.1; }
=ERROR=
Error: Can't find service:s1
=END=

###############################################################
=TITLE=Try to remove host
=PARAMS= host:h1
=INPUT=
network:n3 = {
 ip = 10.1.3.0/24;
 host:h1 = { ip = 10.1.3.10; }
 host:h2 = { ip = 10.1.3.11; }
}
=ERROR=
Error: Can't find service:host:h1
=END=
###############################################################
=TITLE=Remove services with input from file
=FOPTION=
service:s1

service:s2
=INPUT=
service:s1 = {
 user = network:n3;
 permit src = user;
        dst = network:n1;
        prt = udp 25565;
}

service:s2 = {

 overlaps = service:s1, service:s3;

 user = host:h2;
 permit src = user;
        dst = network:n1;
        prt = udp 25565;
}

service:s3 = {
 user = network:n3;
 permit src = user;
        dst = network:n2;
        prt = udp 25565;
}
=OUTPUT=
service:s3 = {
 user = network:n3;
 permit src = user;
        dst = network:n2;
        prt = udp 25565;
}
=END=
