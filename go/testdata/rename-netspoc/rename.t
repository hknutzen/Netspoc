
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR SUBSTITUTION ...
  -f, --file string   Read substitutions from file
  -q, --quiet         Don't show number of changes
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
=TITLE=Unknown type in substitution
=INPUT=NONE
=PARAMS=foo:Test foo:Toast
=ERROR=
Error: Unknown type foo
=END=

############################################################
=TITLE=Missing type in replace string
=INPUT=NONE
=PARAMS=Test host:Toast
=ERROR=
Error: Missing type in 'Test'
=END=

############################################################
=TITLE=Missing type in substitution
=INPUT=NONE
=PARAMS=host:Test Toast
=ERROR=
Error: Missing type in 'Toast'
=END=

############################################################
=TITLE=Missing replace string
=INPUT=NONE
=PARAMS=host:x host:y host:z
=ERROR=
Error: Missing replace string for 'host:z'
=END=

############################################################
=TITLE=Types must be indentical
=INPUT=NONE
=PARAMS=host:x network:y
=ERROR=
Error: Types must be identical in
 - host:x
 - network:y
=END=

############################################################
=TITLE=Ambiguous replace object
=INPUT=NONE
=PARAMS=group:g group:x group:g group:y
=ERROR=
Error: Ambiguous substitution for group:g: group:x, group:y
=END=

############################################################
=TITLE=Leave formatting unchanged if nothing is found
=INPUT=
network:Test={ip=10.1.1.0/24;}
=OUTPUT=
network:Test={ip=10.1.1.0/24;}
=PARAMS=network:Toast network:TTT

############################################################
=TITLE=Rename network
=VAR=input
network:Test =  { ip = 10.1.1.0/24; }
group:G =
    interface:r.Test,
    interface:r.Test.virtual,
    host:id:h@dom.top.Test,
    network:Test,
    ;
network:sub = { ip = 10.1.1.32/28; subnet_of = network:Test; }
area:a = {
 border = interface:r.Test;
 inclusive_border = interface:r2.Test;
}
area:b = {
 border = interface:Test.r, interface:r.Test;
}
pathrestriction:P = interface:r1.Test, interface:r2.Test;
router:r = {
 interface:Test = { reroute_permit = network:Test; }
}
=END=
=INPUT=${input}
=OUTPUT=
network:Toast = { ip = 10.1.1.0/24; }
group:G =
 interface:r.Toast,
 interface:r.Toast.virtual,
 host:id:h@dom.top.Toast,
 network:Toast,
;
network:sub = {
 ip = 10.1.1.32/28;
 subnet_of = network:Toast;
}
area:a = {
 border = interface:r.Toast;
 inclusive_border = interface:r2.Toast;
}
area:b = {
 border = interface:Test.r,
          interface:r.Toast,
          ;
}
pathrestriction:P =
 interface:r1.Toast,
 interface:r2.Toast,
;
router:r = {
 interface:Toast = {
  reroute_permit = network:Toast;
 }
}
=END=
=PARAMS=network:Test network:Toast

############################################################
=TITLE=Rename verbosely
=INPUT=${input}
=WARNING=
13 changes in INPUT
=END=
=OPTIONS=--quiet=0
=PARAMS=network:Test network:Toast

############################################################
=TITLE=Rename bridged network
=INPUT=
network:Test/a = { ip = 10.9.1.0/24; }
network:Test/b = { ip = 10.9.1.0/24; }
router:asa = {
 interface:Test/a = { hardware = inside; }
 interface:Test/b = { hardware = outside; }
 interface:Test = { hardware = device; }
}
group:G = interface:r.Test,
    network:Test/a,
    network:Test/b,
    interface:r.Test/b,
    ;
=END=
=OUTPUT=
network:Toast/a = { ip = 10.9.1.0/24; }
network:Toast/b = { ip = 10.9.1.0/24; }
router:asa = {
 interface:Toast/a = { hardware = inside; }
 interface:Toast/b = { hardware = outside; }
 interface:Toast   = { hardware = device; }
}
group:G =
 interface:r.Toast,
 network:Toast/a,
 network:Toast/b,
 interface:r.Toast/b,
;
=END=
=PARAMS=network:Test network:Toast

############################################################
=TITLE=Rename ID host
=INPUT=
group:G =
    host:id:h@dom.top.Test,
    host:id:h@dom.top.top,
    host:id:dom.top.Test,
    ;
=END=
=OUTPUT=
group:G =
 host:id:xx@yy.zz.Test,
 host:id:xx@yy.zz.top,
 host:id:a.b.c.Test,
;
=END=
=PARAMS=host:id:h@dom.top host:id:xx@yy.zz host:id:dom.top host:id:a.b.c

############################################################
=TITLE=Rename both, ID host and network
=INPUT=
group:G =
    host:id:h@dom.top.Test,
    host:id:h@dom.top.top,
    ;
=END=
=OUTPUT=
group:G =
 host:id:xx@yy.zz.Toast,
 host:id:xx@yy.zz.top,
;
=END=
=PARAMS=host:id:h@dom.top host:id:xx@yy.zz network:Test network:Toast

############################################################
=TITLE=Rename network to name with leading digit
=INPUT=
network:Test =  { ip = 10.9.1.0/24; }
group:G = interface:r.Test,
    host:id:h@dom.top.Test,
    network:Test,
    ;
=END=
=OUTPUT=
network:1_2_3_0_Test = { ip = 10.9.1.0/24; }
group:G =
 interface:r.1_2_3_0_Test,
 host:id:h@dom.top.1_2_3_0_Test,
 network:1_2_3_0_Test,
;
=END=
=PARAMS=network:Test network:1_2_3_0_Test

############################################################
=TITLE=Rename router then network
=VAR=input
router:R = { interface:NN = { ip = 10.9.1.1; } }
network:NN = { ip = 10.9.1.0/24; }
group:g = interface:R.NN;
=END=
=VAR=output
router:RR = {
 interface:N = { ip = 10.9.1.1; }
}
network:N = { ip = 10.9.1.0/24; }
group:g =
 interface:RR.N,
;
=END=
=INPUT=${input}
=OUTPUT=
${output}
=PARAMS=router:R router:RR network:NN network:N

############################################################
=TITLE=Rename network then router
=INPUT=${input}
=OUTPUT=
${output}
=PARAMS=network:NN network:N router:R router:RR

############################################################
=TITLE=Rename VRF router
=INPUT=
router:R = { interface:n = { ip = 10.9.1.1; } }
router:R@vrf = { interface:n = { ip = 10.9.1.2; } }
group:G =
interface:R.n,
interface:R@vrf.n;
=END=
=OUTPUT=
router:RR = {
 interface:n = { ip = 10.9.1.1; }
}
router:r@vrf = {
 interface:n = { ip = 10.9.1.2; }
}
group:G =
 interface:RR.n,
 interface:r@vrf.n,
;
=END=
=PARAMS=router:R router:RR router:R@vrf router:r@vrf

############################################################
=TITLE=Rename inside automatic group
=INPUT=
group:g =
 any:[ip=10.99.0.0/16&network:n1],
 interface:[managed & network:n1].[all],
 group:g2 &! host:[network:n1],
;
=END=
=OUTPUT=
group:g =
 any:[ip = 10.99.0.0/16 & network:NN],
 interface:[managed & network:NN].[all],
 group:g2
 &! host:[network:NN]
 ,
;
=END=
=PARAMS=network:n1 network:NN

############################################################
=TITLE=Rename nat
=INPUT=
network:N = { ip = 1.2.3.0/24; nat:NAT-1 = {ip = 7.8.9.0; } }
router:r = {
interface:n1 = { bind_nat = NAT-1; }
interface:n2 = { bind_nat = x,
    y,NAT-1, z;
}
interface:n3 = { bind_nat =NAT-1
    ;}
interface:n4 = {bind_nat
= NAT-1;
}
}
=END=
=OUTPUT=
network:N = {
 ip = 1.2.3.0/24;
 nat:NAT-2 = { ip = 7.8.9.0; }
}
router:r = {
 interface:n1 = {
  bind_nat = NAT-2;
 }
 interface:n2 = {
  bind_nat = x,
             y,
             NAT-2,
             z,
             ;
 }
 interface:n3 = {
  bind_nat = NAT-2;
 }
 interface:n4 = {
  bind_nat = NAT-2;
 }
}
=END=
=PARAMS=nat:NAT-1 nat:NAT-2

############################################################
=TITLE=Rename group
=INPUT=
group:g1 = group:g2, group:g3;
=OUTPUT=
group:G1 =
 group:g2,
 group:g4,
;
=PARAMS=group:g1 group:G1 group:g3 group:g4

############################################################
=TITLE=Rename protocolgroup
=INPUT=
protocolgroup:g1 = tcp 20 - 21;
=OUTPUT=
protocolgroup:G1 =
 tcp 20 - 21,
;
=PARAMS=protocolgroup:g1 protocolgroup:G1

############################################################
=TITLE=Rename protocol
=INPUT=
protocol:p1 = tcp 20 - 21;
=OUTPUT=
protocol:p11 = tcp 20 - 21;
=PARAMS=protocol:p1 protocol:p11

############################################################
=TITLE=Rename service
=INPUT=
service:s1 = {
 unknown_owner;
 identical_body = service:s3;
 overlaps = service:s2, service:s3;
 user = network:n1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=END=
=OUTPUT=
service:x1 = {
 unknown_owner;
 identical_body = service:x3;
 overlaps = service:s2,
            service:x3,
            ;
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=END=
=PARAMS=service:s1 service:x1 service:s3 service:x3

############################################################
=TITLE=Rename loopback interface
=INPUT=
router:r1 = { interface:Loopback_4 = { ip = 10.9.1.1; loopback; } }
router:r2 = { interface:Loopback_4 = { ip = 10.9.1.2; loopback; } }
group:G = interface:r1.Loopback_4,
          interface:r2.Loopback_4,
    ;
=END=
=OUTPUT=
router:r1 = {
 interface:Loopback = { ip = 10.9.1.1; loopback; }
}
router:r2 = {
 interface:Loopback = { ip = 10.9.1.2; loopback; }
}
group:G =
 interface:r1.Loopback,
 interface:r2.Loopback,
;
=END=
=PARAMS=network:Loopback_4 network:Loopback

############################################################
=TITLE=Rename umlauts
=INPUT=
owner:Maaß = { admins = a@b.c; }
owner:Wittmuess = { admins = a@b.c; }
network:n1 = {
 owner = Maaß, Wittmuess;
}
=END=
=OUTPUT=
owner:Maass = {
 admins = a@b.c;
}
owner:Wittmüß = {
 admins = a@b.c;
}
network:n1 = { owner = Maass, Wittmüß; }
=END=
=PARAMS=owner:Maaß owner:Maass owner:Wittmuess owner:Wittmüß

############################################################
=TITLE=Read substitutions from file
=INPUT=
router:r = {
interface:net = { bind_nat = ick,
 ticks, tick;}
}
network:net = { owner = foo; ip = 10.1.1.0/24;
nat:ticks = { ip = 10.7.1.0/24; } nat:ick = { hidden; }
nat:tick = { dynamic; }
 host:abc = { ip = 10.1.1.10; }
}
=END=
=OUTPUT=
router:r = {
 interface:xxxx = {
  bind_nat = _,
             t2,
             t1,
             ;
 }
}
network:xxxx = {
 owner = büro;
 ip = 10.1.1.0/24;
 nat:t2 = { ip = 10.7.1.0/24; }
 nat:_ = { hidden; }
 nat:t1 = { dynamic; }
 host:a1 = { ip = 10.1.1.10; }
}
=END=
=FOPTION=
host:abc host:a1
owner:foo owner:büro
nat:tick nat:t1
nat:ticks nat:t2
nat:ick nat:_
network:net network:xxxx
=END=

############################################################
=TITLE=Unknown file for substitutions
=INPUT=NONE
=ERROR=
Error: open missing.file: no such file or directory
=END=
=OPTIONS=-f missing.file

############################################################
