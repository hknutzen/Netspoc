############################################################
=TITLE=Option '-h'
=INPUT=#
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR SOURCE DESTINATION
  -q, --quiet   Don't print progress messages
=END=

############################################################
=TITLE=Unknown option
=INPUT=#
=PARAMS=--abc
=ERROR=
Error: unknown flag: --abc
=END=

############################################################
=TITLE=No input file
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR SOURCE DESTINATION
  -q, --quiet   Don't print progress messages
=END=

############################################################
=TITLE=Invalid input
=PARAMS=network:n1 network:n2
=INPUT=
foo
=ERROR=
Error: Typed name expected at line 1 of INPUT, near "--HERE-->foo"
Aborted
=END=

############################################################
=TITLE=Empty input
=PARAMS=network:n1 network:n2
=INPUT=

=ERROR=
Warning: Ignoring file 'INPUT' without any content
Error: topology seems to be empty
Aborted
=END=

############################################################
=TITLE=Invalid param
=PARAMS=a network:n2
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->a"
Aborted
=END=

############################################################
=TITLE=Unknown network
=PARAMS=network:n2 network:n2
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Can't resolve network:n2 in print-path
=END=

############################################################
=TITLE=Unknown host
=PARAMS=host:h1 network:n2
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Can't resolve host:h1 in print-path
=END=

############################################################
=TITLE=Unknown interface
=PARAMS=interface:r1.n1 network:n2
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=ERROR=
Error: Can't resolve interface:r1.n1 in print-path
=END=

############################################################
=TITLE=Unsupported element
=PARAMS=area:a1 network:n2
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
area:a1 = { anchor = network:n1; }
=ERROR=
Error: Unsupported element: area:a1
Aborted
=END=

############################################################
=TITLE=Only one element
=PARAMS=interface:r1.[all] network:n2
=INPUT=
router:r1 = {
 interface:n1 = { ip = 10.1.1.1;}
 interface:n2 = { ip = 10.1.2.1; }
}
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
=ERROR=
Error: Only one element allowed in [interface:r1.n1 interface:r1.n2]
Aborted
=END=

############################################################
=TITLE=Path with one router
=PARAMS=network:n1 network:n2
=INPUT=
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

=OUTPUT=
["network:n1","network:n2","router:r1"]
=END=

############################################################
=TITLE=From Host to interface
=PARAMS=host:h1 interface:r1.n3
=INPUT=
router:r1 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

router:u1 = {
 interface:n1;
 interface:n2 = { ip = 10.1.2.2; }
}

network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.2;} }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }
=OUTPUT=
["network:n1","network:n2","network:n3","router:r1","router:u1"]