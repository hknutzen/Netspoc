
############################################################
=TITLE=Invalid UTF-8
=INPUT=
network:n1 = { ip6 = 10.1.1.��/24; }
=ERROR=
Error: illegal UTF-8 encoding at line 1 of INPUT, near "10.1.1.--HERE-->��/24"
Aborted
=END=

############################################################
=TITLE=Invalid character NUL
=INPUT=
network:n1 = { ip6 = 10.1.1. /24; }
=ERROR=
Error: illegal character NUL at line 1 of INPUT, near "10.1.1.--HERE--> /24"
Aborted
=END=
