
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=Unknown option
=INPUT=#
=PARAMS=-x
=ERROR=
Error: unknown shorthand flag: 'x' in -x
=END=

############################################################
=TITLE=Unknown argument
=INPUT=#
=PARAMS=other_arg
=ERROR=
Usage: PROGRAM [options] FILE|DIR
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=Unknown input file
=INPUT=NONE
=PARAMS=unknown-file
=ERROR=
Error: open unknown-file: no such file or directory
=END=

############################################################
=TITLE=Unknown type
=INPUT=
foo:x =
=END=
=ERROR=
Error: Unknown global definition at line 1 of INPUT, near "--HERE-->foo:x"
=END=

############################################################
=TITLE=Empty input
=INPUT=
--file

=END=
=WARNING=NONE

############################################################
=TITLE=Only comments in file
=INPUT=
# c1
  #c1b
#c2
=END=
# c1
#c1b
#c2
=WARNING=NONE

############################################################
=TITLE=Empty group
=INPUT=
group:g1 = ; # IGNORED
=END=
=OUTPUT=
group:g1 =
;
=END=

############################################################
=TITLE=Ignore trailing ';' in description and empty description
=INPUT=
group:g1 =
 description =
 host:h1;
group:g2 =
 description = ;
 host:h1;
group:g3 =
 description = ; ;
 host:h1;
=END=
=OUTPUT=
group:g1 =
 host:h1,
;

group:g2 =
 host:h1,
;

group:g3 =
 host:h1,
;
=END=

############################################################
=TITLE=Group with union, intersection, complement
=INPUT=
group:g1 =
 host:h1,
 group:g2 & group:g3 &! host:h2 &! host:h3,
 network:n1,;
=END=
=OUTPUT=
group:g1 =
 group:g2
 & group:g3
 &! host:h2
 &! host:h3
 ,
 network:n1,
 host:h1,
;
=END=

############################################################
=TITLE=Complement without intersection
=INPUT=
group:g1 = group:g2, !group:g3; # invalid but parseable.
=OUTPUT=
group:g1 =
 ! group:g3,
 group:g2,
;
=END=

############################################################
=TITLE=Short automatic groups
=INPUT=
group:g1 =
 interface:r1.[auto],
 interface:[
  network:n1
 ].[all],
 interface:r1.[
  auto
 ],
 any:[area:a1]
 ,
 network:[   area:a2, ],  ;
=END=
=OUTPUT=
group:g1 =
 any:[area:a1],
 network:[area:a2],
 interface:[network:n1].[all],
 interface:r1.[auto],
 interface:r1.[auto],
;
=END=

############################################################
=TITLE=Nested automatic groups
=INPUT=
group:g1 =
 interface:[network:n2, network:n1].[all],
 network:[any:[area:a1]],
 network:[
  interface:[area:a3, area:a2].[all] &! interface:r1.n3, interface:r1.n3.virtual
 ]  ;
=END=
=OUTPUT=
group:g1 =
 network:[
  any:[area:a1],
 ],
 network:[
  interface:[
   area:a2,
   area:a3,
  ].[all]
  &! interface:r1.n3
  ,
  interface:r1.n3.virtual,
 ],
 interface:[
  network:n1,
  network:n2,
 ].[all],
;
=END=

############################################################
=TITLE=With umlauts
=INPUT=
group:groß = interface:röter.über;
=END=
=OUTPUT=
group:groß =
 interface:röter.über,
;
=END=

############################################################
=TITLE=Simple group with many comments
=INPUT=
# head1
 # head1a
  # head2


# Multiple empty lines are reduced to one.
# This is g1
group:g1 # IGNORED
= # g1 trailing2
# g1 post def
description = This is a fine group;      # desc
# desc post
# desc post 2
# First element
host:h1, # after first
# post first
# Second
host:h2, # after second
# IGNORED
;
# At end
=END=
=OUTPUT=
# head1
# head1a
# head2

# Multiple empty lines are reduced to one.
# This is g1
group:g1 =
 # g1 trailing2
 # g1 post def
 description = This is a fine group # desc

 # desc post
 # desc post 2
 # First element
 host:h1, # after first
 # post first
 # Second
 host:h2, # after second
;
# At end
=END=

############################################################
=TITLE=Ignore comment inside description
=INPUT=
group:g1 =
   description # IGNORE
   =   the text; ;; # comment
;
=END=
=OUTPUT=
group:g1 =
 description = the text # comment

;
=END=

############################################################
=TITLE=Comment before first element
=INPUT=
group:g1 =
 # pre h
 host:h
;
=END=
=OUTPUT=
group:g1 =
 # pre h
 host:h,
;
=END=

############################################################
=TITLE=Comment after first line of group definition
=INPUT=
group:g1 = # pre h
 host:h,
;
group:g2 = host:h1, # post h1
host:h2
;
=END=
=OUTPUT=
group:g1 =
 # pre h
 host:h,
;

group:g2 =
 host:h1, # post h1
 host:h2,
;
=END=

############################################################
=TITLE=Comment after interface
=INPUT=
group:g1 = interface:r1.Test, # comment1
interface:r2.[ auto ] , # comment2
interface:[network:n1].[all ], # comment3
;
=END=
=OUTPUT=
group:g1 =
 interface:[network:n1].[all], # comment3
 interface:r1.Test, # comment1
 interface:r2.[auto], # comment2
;
=END=

############################################################
=TITLE=Without trailing comment at end of file
=INPUT=
group:g1 =
 host:h # trailing
 , # more trailing
 # and more
;
=END=
=OUTPUT=
group:g1 =
 host:h, # trailing
;
=END=

############################################################
=TITLE=Ignore comment in [any|all]
=INPUT=
group:g1 =
 interface:r1.[ # trailing
 # pre
auto # trailing2
 # post
], # real trailing
;
=END=
=OUTPUT=
group:g1 =
 interface:r1.[auto], # real trailing
;
=END=

############################################################
=TITLE=Ignore comment in short automatic group
=INPUT=
group:g1 = network:[ # trailing start
# pre
area:a # trailing
# post
] # real trailing
;
=END=
=OUTPUT=
group:g1 =
 network:[area:a], # real trailing
;
=END=

############################################################
=TITLE=Comment in intersection and complement
=INPUT=
group:g1 =
 # post g1
 # pre g2
  group:g2 # g2
 # post g2
 & # &
  group:g3 # g3
 &! # &!
  host:h2, # h2
  group:g4 &! # g4
  host:h3 # h3
  ,
  group:g5
  & # &
  ! # !
  host:h4
;
=END=
=OUTPUT=
group:g1 =
 # post g1
 # pre g2
 group:g2 # g2
 # post g2
 # &
 & group:g3 # g3
 # &!
 &! host:h2 # h2
 ,
 group:g4 # g4
 &! host:h3 # h3
 ,
 group:g5
 # &
 # !
 &! host:h4
 ,
;
=END=

############################################################
=TITLE=Comments in automatic group
# trailing start is ignored
=INPUT=
group:g1 =
 network:[ #### trailing start
 # pre h1
 host:h1, # trailing h1
 # post h1
 # pre h2
 host:h2
 ,
 host:h3 # trailing h3
] # trailing list
;
=END=
=OUTPUT=
group:g1 =
 network:[
  # pre h1
  host:h1, # trailing h1
  # post h1
  # pre h2
  host:h2,
  host:h3, # trailing h3
 ], # trailing list
;
=END=

############################################################
=TITLE=Sort elements by type, IP and name
=INPUT=
group:g1 =
 any:[area:a4],
 interface:r2.n-10_1_9_0-24,
 interface:r1.n99_10_1_9_0-24,
 interface:r2.n-10_1_6_0-24,
 host:h2,
 host:h999_99_9_0_0,
 host:h1-10_1_1_7,
 host:h3-999_999_0_0,
 host:10_1_1_8_h8,
 host:range-10_1_1_6-10_1_1_8,
 host:range-10_1_1_5-10_1_1_9,
 network:n-10_1_9_0-24,
 network:10_1_8_128-10_1_8_255,
 network:10_1_7_0-net,
 network:n-10_1_6_0-24,
 # Before
 network:n_999_10_1_10_0, # not recognized as IP-adress
 network:n-77,
 group:g9, group:g8 &! host:hx,
 any:a-10_0_0_0-8,
 any:customerX-0_0_0_0-8,
 network:[area:a2] &! network:n-10_1_9_0-24,
 network:[area:a1] &! network:n-10_1_6_0-24,
;
=END=
=OUTPUT=
group:g1 =
 group:g8
 &! host:hx
 ,
 group:g9,
 any:[area:a4],
 any:customerX-0_0_0_0-8,
 any:a-10_0_0_0-8,
 network:[area:a2]
 &! network:n-10_1_9_0-24
 ,
 network:[area:a1]
 &! network:n-10_1_6_0-24
 ,
 network:n-77,
 # Before
 network:n_999_10_1_10_0, # not recognized as IP-adress
 network:n-10_1_6_0-24,
 network:10_1_7_0-net,
 network:10_1_8_128-10_1_8_255,
 network:n-10_1_9_0-24,
 interface:r2.n-10_1_6_0-24,
 interface:r1.n99_10_1_9_0-24,
 interface:r2.n-10_1_9_0-24,
 host:h2,
 host:h3-999_999_0_0,
 host:range-10_1_1_5-10_1_1_9,
 host:range-10_1_1_6-10_1_1_8,
 host:h1-10_1_1_7,
 host:10_1_1_8_h8,
 host:h999_99_9_0_0,
;
=END=

############################################################
=TITLE=Service with comments
=INPUT=
# pre s1
service:s1 = {
 # head s1
 description = s1 # desc s1
 # Pre user
 user = host:h2, host:h1;
 # pre rule1
 permit src = user; dst = network:n1; prt = tcp 80; # after prt
 # pre rule2
 permit src = network:n2, network:n1;
  # Pre dst
        dst = user;
  # Pre prt
        prt = # pre udp after '='
           # pre udp
           udp 123, proto 47, icmp 8, #after icmp
           # post udp
           # pre tcp
           tcp 90; # after tcp
   # Pre log
        log = fw3, # after log1
              asa1; # after log2
}
=END=
=OUTPUT=
# pre s1
service:s1 = {
 # head s1
 description = s1 # desc s1

 # Pre user
 user = host:h1,
        host:h2,
        ;
 # pre rule1
 permit src = user;
        dst = network:n1;
        prt = tcp 80; # after prt
 # pre rule2
 permit src = network:n1,
              network:n2,
              ;
        # Pre dst
        dst = user;
        # Pre prt
        prt = icmp 8, #after icmp
              proto 47,
              # post udp
              # pre tcp
              tcp 90, # after tcp
              # pre udp after '='
              # pre udp
              udp 123,
              ;
        # Pre log
        log = asa1, # after log2
              fw3, # after log1
              ;
}
=END=

############################################################
=TITLE=Service with attributes
=INPUT=
service:s1 = {
 overlaps = service:s3, service:s6, service:s4, service:s2, service:s5;
 multi_owner;
 user = host:h1;
 permit src = user; dst = network:n1; prt = tcp 80;
}
=END=
=OUTPUT=
service:s1 = {

 multi_owner;
 overlaps = service:s2,
            service:s3,
            service:s4,
            service:s5,
            service:s6,
            ;

 user = host:h1;
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Service without rule
=INPUT=
service:s1 = { user = host:h1; }
=END=
=OUTPUT=
service:s1 = {
 user = host:h1;
}
=END=

############################################################
=TITLE=Service with empty user, src, dst, prt
=INPUT=
service:s1 = { user =; permit src =; dst =; prt =; }
service:s2 = {
user =; #user
permit src =; #src
       dst =   ;  #dst
       prt =; #prt
}
=END=
=OUTPUT=
service:s1 = {
 user = ;
 permit src = ;
        dst = ;
        prt = ;
}

service:s2 = {
 user = ; #user
 permit src = ; #src
        dst = ; #dst
        prt = ; #prt
}
=END=

############################################################
=TITLE=Service with foreach
=INPUT=
service:s1 = {
 user = foreach host:h2, host:h1;
 permit src = user; dst = network:[user]; prt = tcp 80;
}
=END=
=OUTPUT=
service:s1 = {
 user = foreach
  host:h1,
  host:h2,
 ;
 permit src = user;
        dst = network:[user];
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Service with comment after one line
=INPUT=
service:s1 = {
 user = host:h1, host:h2; #user
 deny   src = user; #src
        dst = network:n1; #dst
        prt = tcp 80, tcp 90; #prt
}
=END=
=OUTPUT=
service:s1 = {
 user = host:h1,
        host:h2, #user
        ;
 deny   src = user; #src
        dst = network:n1; #dst
        prt = tcp 80,
              tcp 90, #prt
              ;
}
=END=

############################################################
=TITLE=Comment before and after permit/deny
=INPUT=
service:s1 = {
 user = host:h1;
 # action
 permit #IGNORED
        src = user;
        dst = network:n1;
        prt = tcp 80;
}
=END=
=OUTPUT=
service:s1 = {
 user = host:h1;
 # action
 permit src = user;
        dst = network:n1;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Intersection in first line
=INPUT=
service:s1 = {
 user = group:g1 &! host:h1;
 permit src = user;
        dst = host:h2;
        prt = tcp 80;
}
=END=
=OUTPUT=
service:s1 = {
 user = group:g1
        &! host:h1
        ;
 permit src = user;
        dst = host:h2;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Automatic group in first line
=INPUT=
service:s1 = {
 user = host:[network:n2, network:n1]; # host:h3;
 permit src = user; dst = host:h2; prt = tcp 80;
}
=END=
=OUTPUT=
service:s1 = {
 user = host:[
         network:n1,
         network:n2,
        ]; # host:h3;
 permit src = user;
        dst = host:h2;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Deeply nested automatic group
=INPUT=
service:s1 = {
 user = host:[network:[area:a] &! network:[network:[area:b] &! network:n1]];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=END=
=OUTPUT=
service:s1 = {
 user = host:[
         network:[area:a]
         &! network:[
             network:[area:b]
             &! network:n1
             ,
            ]
         ,
        ];
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=END=

############################################################
=TITLE=Order of protocols
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80, tcp 700, udp 70, tcp 55-59, tcp 20:1024-65535,
              tcp 54 : 64-74,
              tcp 20-21 : 64- 74,
              tcp 20 : 64- 74,
              udp 123,
              icmp 3/3,
              icmp 4 / 3,
              icmp 3 /4,
              icmp 8,
              icmp 8 / 9,
              icmp 3,
              icmp 4 ,
              icmp 4 / 4,
              proto 43,
              proto 54,
              protocol:smtp, protocol:ftp,
              protocolgroup:ftp-active,
        ;
}
=END=
=OUTPUT=
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = protocolgroup:ftp-active,
              protocol:ftp,
              protocol:smtp,
              icmp 3,
              icmp 3 / 3,
              icmp 3 / 4,
              icmp 4,
              icmp 4 / 3,
              icmp 4 / 4,
              icmp 8,
              icmp 8 / 9,
              proto 43,
              proto 54,
              tcp 55 - 59,
              tcp 20 : 64 - 74,
              tcp 20 - 21 : 64 - 74,
              tcp 54 : 64 - 74,
              tcp 80,
              tcp 700,
              tcp 20 : 1024 - 65535,
              udp 70,
              udp 123,
              ;
}
=END=

############################################################
=TITLE=Ordered elements in protocolgroups
=INPUT=
protocolgroup:g1 =udp 70,tcp 700, tcp 80, udp, udp : 0;
=END=
=OUTPUT=
protocolgroup:g1 =
 tcp 80,
 tcp 700,
 udp : 0,
 udp,
 udp 70,
;
=END=

############################################################
=TITLE=Network
=INPUT=
network:n1 = { ip = 10.1.1.0/24;
 nat:n = {
  ip = 9.1.1.0/24;
  dynamic;
 }
 radius_attributes = { banner = hello again; }
 nat:n2 = { ip = 8.1.1.0/24; }
# range
host:range3-5 = { range = 10.1.1.3-10.1.1.5; } # range
host:h2 = { ip = 10.1.1.2; radius_attributes={ banner= hello h2;}}
host:h10 = { ip =10.1.1.10; owner = o1; }
host:h9 = { ip =10.1.1.9; owner = o1; } # h9
# long
host:long-name = { ip =10.1.1.66; owner = o1; }
# nat
host:nat = { ip = 10.1.1.11; nat:n = { ip = 9.1.1.11; } }
}
=END=
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:n = { ip = 9.1.1.0/24; dynamic; }
 radius_attributes = {
  banner = hello again;
 }
 nat:n2 = { ip = 8.1.1.0/24; }
 host:h2 = {
  ip = 10.1.1.2;
  radius_attributes = {
   banner = hello h2;
  }
 }
 # range
 host:range3-5  = { range = 10.1.1.3 - 10.1.1.5; } # range
 host:h9        = { ip = 10.1.1.9; owner = o1; } # h9
 host:h10       = { ip = 10.1.1.10; owner = o1; }
 # nat
 host:nat = {
  ip = 10.1.1.11;
  nat:n = { ip = 9.1.1.11; }
 }
 # long
 host:long-name = { ip = 10.1.1.66; owner = o1; }
}
=END=

############################################################
=TITLE=Aggregate with trailing comment in first line
=INPUT=
any:a1 = { link = network:n1; } # comment
any:a1 = { link = network:n1; nat:x = { identity; } } # comment
any:a1 = {
 link = network:n1; } # comment
any:a1 = { # comment
 link = network:n1; }
any:a1 = # comment
{ link = network:n1; }
any:a1 # comment
= { link = network:n1; }
=END=
=OUTPUT=
any:a1 = {
 link = network:n1; # comment
}

any:a1 = {
 link = network:n1;
 nat:x = { identity; } # comment
}

any:a1 = {
 link = network:n1; # comment
}

any:a1 = { # comment
 link = network:n1;
}

any:a1 = { # comment
 link = network:n1;
}

any:a1 = { # comment
 link = network:n1;
}
=END=

############################################################
=TITLE=Network with trailing comment in first line
=INPUT=
network:n1 = { ip = 10.1.1.0/24; } # comment
network:n1 = { ip = 10.1.1.0/24; nat:x = { identity; } } # comment
network:n1 = { nat:x = { identity; } ip = 10.1.1.0/24; } # comment
network:n1 = { ip = 10.1.1.0/24; host:h1 = { ip = 10.1.1.1; } } # comment
=END=
=OUTPUT=
network:n1 = { ip = 10.1.1.0/24; } # comment

network:n1 = {
 ip = 10.1.1.0/24;
 nat:x = { identity; } # comment
}

network:n1 = {
 nat:x = { identity; }
 ip = 10.1.1.0/24; # comment
}

network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; } # comment
}
=END=

############################################################
=TITLE=Short networks printed in one line and without blank line
=INPUT=
network:n0 = {
 # Not simple
 ip = 10.1.1.0/24;
}
network:n1 = {
 ip = 10.1.1.0/24;
}
network:nn2 = {
 ip = 10.1.2.0/24; }# After n2
# Before n3
network:nnn3 = { ip = 10.1.3.0/24; owner = o; }
network:nnnn4 = { ip = 10.1.4.0/24; crosslink; } # After n4
network:nnnnn5 = {
ip = 10.1.5.0/24; crosslink; owner = o; }
network:nnn6 = { ip = 10.1.6.0/24; host:h6 = { ip = 10.1.6.10; } }
network:nnn7 = { ip = 10.1.7.0/24; }
network:n8 = { ip = 10.1.8.0/24; }
any:a = { link = network:n5; }
=END=
=OUTPUT=
network:n0 = {
 # Not simple
 ip = 10.1.1.0/24;
}

network:n1     = { ip = 10.1.1.0/24; }
network:nn2    = { ip = 10.1.2.0/24; } # After n2
# Before n3
network:nnn3   = { ip = 10.1.3.0/24; owner = o; }
network:nnnn4  = { ip = 10.1.4.0/24; crosslink; } # After n4
network:nnnnn5 = { ip = 10.1.5.0/24; crosslink; owner = o; }

network:nnn6 = {
 ip = 10.1.6.0/24;
 host:h6 = { ip = 10.1.6.10; }
}

network:nnn7 = { ip = 10.1.7.0/24; }
network:n8   = { ip = 10.1.8.0/24; }

any:a = {
 link = network:n5;
}
=END=

############################################################
=TITLE=Sort hosts by IP or range
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h99 = { ip = 10.1.1.99; }
 host:r98-102 = { range = 10.1.1.98-10.1.1.102; }
 host:invalid = {}
 host:h10 = { ip = 10.1.1.10; }
 host:r98-100 = { range = 10.1.1.98-10.1.1.100; }
 host:h11 = { ip = 10.1.1.11; nat:n = { ip = 10.9.9.99; } }
}
=OUTPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:invalid = { }
 host:h10     = { ip = 10.1.1.10; }
 host:h11 = {
  ip = 10.1.1.11;
  nat:n = { ip = 10.9.9.99; }
 }
 host:r98-102 = { range = 10.1.1.98 - 10.1.1.102; }
 host:r98-100 = { range = 10.1.1.98 - 10.1.1.100; }
 host:h99     = { ip = 10.1.1.99; }
}
=END=

############################################################
=TITLE=Invalid, but parseable elements
=INPUT=
network:n1 = {
 x;
 :y = { :ip:; ip2 = { ip3 = 4; }}
 :host:h1 = { a = { b = { c = d; e = f,g;} h;}}
 :h:o:s:t:h2=; # c1
 host:h1 = { ip = 10.1.1.10; }
 host:h1 =;
 host:h1 = 10.1.1.11;
}
router:r1 = { managed = ;
 interface:i = 10.1.1.1, 10.1.1.2;
}
=OUTPUT=
network:n1 = {
 x;
 :y = { :ip:; ip2 = { ip3 = 4; } }
 :host:h1 = { a = { b = { c = d; e = f, g; } h; } }
 :h:o:s:t:h2 = ; # c1
 host:h1 = ;
 host:h1 = 10.1.1.11;
 host:h1 = { ip = 10.1.1.10; }
}

router:r1 = {
 managed = ;
 interface:i =
  10.1.1.1,
  10.1.1.2,
 ;
}
=END=

############################################################
=TITLE=Managed router
=INPUT=
# pre
router:r1 = { managed; # tail
# model
model =
 ASA,
 VPN,CONTEXT;
# i1
interface:n7 = {
 ip = 10.1.7.1; hardware = n7;
 hub = crypto:c1, crypto:c2, ;
 no_check;
}
# i2
interface:n1 = {
 ip = 10.1.1.1, 10.1.1.2; hardware = n1;
 virtual = { ip = 10.1.1.3;  type = HSRPv2; }
 routing = manual;
}
interface:n3 = { unnumbered; }
interface:log-name = { ip = 10.1.9.1; hardware = ln; }
interface:n5 = { ip = 10.1.5.1; hardware = n5; }
interface:lo = { ip = 10.1.4.128; hardware = lo; loopback; }
}
=END=
=OUTPUT=
# pre
router:r1 = {
 managed; # tail
 # model
 model = ASA, VPN, CONTEXT;
 # i1
 interface:n7 = {
  ip = 10.1.7.1;
  hardware = n7;
  hub = crypto:c1,
        crypto:c2,
        ;
  no_check;
 }
 # i2
 interface:n1 = {
  ip = 10.1.1.1,
       10.1.1.2,
       ;
  hardware = n1;
  virtual = { ip = 10.1.1.3; type = HSRPv2; }
  routing = manual;
 }
 interface:n3       = { unnumbered; }
 interface:log-name = { ip = 10.1.9.1; hardware = ln; }
 interface:n5       = { ip = 10.1.5.1; hardware = n5; }
 interface:lo       = { ip = 10.1.4.128; hardware = lo; loopback; }
}
=END=

############################################################
=TITLE=Sort successive vip interfaces
=INPUT=
router:u1 = {
 # i1
 interface:n7 = { owner = o1; ip = 10.1.1.7; }
 # i2
 interface:lo = { ip = 10.1.4.128; owner = o2; vip; }
 interface:n1 = { ip = 10.1.1.1; owner = o1; vip; }
 interface:unnum = { unnumbered; }
 interface:short;
 # IGNORED
}
router:u2 = {
 interface:v2 = { ip = 10.1.4.128; owner = o2; vip; }
 interface:v1 = { ip = 10.1.4.127; owner = o2; vip; }
 interface:n7 = { ip = 10.1.1.7; owner = o1; }
 interface:lo = { ip = 10.1.1.4; owner = o2; vip; }
 interface:n1 = { ip = 10.1.1.1; owner = o1; vip; }
}
=END=
=OUTPUT=
router:u1 = {
 # i1
 interface:n7    = { owner = o1; ip = 10.1.1.7; }
 interface:n1    = { ip = 10.1.1.1; owner = o1; vip; }
 # i2
 interface:lo    = { ip = 10.1.4.128; owner = o2; vip; }
 interface:unnum = { unnumbered; }
 interface:short;
}

router:u2 = {
 interface:v1 = { ip = 10.1.4.127; owner = o2; vip; }
 interface:v2 = { ip = 10.1.4.128; owner = o2; vip; }
 interface:n7 = { ip = 10.1.1.7; owner = o1; }
 interface:n1 = { ip = 10.1.1.1; owner = o1; vip; }
 interface:lo = { ip = 10.1.1.4; owner = o2; vip; }
}
=END=

############################################################
=TITLE=Short interface with comment
=INPUT=
router:u1 = {
 # i1
 interface:n2;
 # i2
 interface:n1;
}
=END=
=OUTPUT=
router:u1 = {
 # i1
 interface:n2;
 # i2
 interface:n1;
}
=END=

############################################################
=TITLE=Aggregate
=INPUT=
any:a1 = { ip = 10.1.0.0/16; link = network:n1; nat:n1 = { ip  = 10.9.0.0/16; } owner = o1;
}
=END=
=OUTPUT=
any:a1 = {
 ip = 10.1.0.0/16;
 link = network:n1;
 nat:n1 = { ip = 10.9.0.0/16; }
 owner = o1;
}
=END=

############################################################
=TITLE=Area
=INPUT=
area:a1 = {
 border = interface:r3.n3, group:g3 &! interface:r1.n1;
 inclusive_border = interface:r3.n3;
 nat:t = { hidden; }
 owner = o;
 router_attributes = {
  owner = o2;
  policy_distribution_point = host:netspoc;
  general_permit = udp, icmp;
  }
}
=END=
=OUTPUT=
area:a1 = {
 nat:t = { hidden; }
 owner = o;
 router_attributes = {
  owner = o2;
  policy_distribution_point = host:netspoc;
  general_permit =
   udp,
   icmp,
  ;
 }
 border = interface:r3.n3,
          group:g3
          &! interface:r1.n1
          ,
          ;
 inclusive_border = interface:r3.n3;
}
=END=

############################################################
=TITLE=Area with multiple inclusive borders
=INPUT=
area:a1 = {
 inclusive_border= interface:r1.n1, interface:r5.n5, interface:r2.n2;
}
=END=
=OUTPUT=
area:a1 = {
 inclusive_border =
  interface:r1.n1,
  interface:r5.n5,
  interface:r2.n2,
  ;
}
=END=

############################################################
=TITLE=Pathrestriction
# Elements are sorted by IP in name, same as in group.
=INPUT=
pathrestriction:p1 = interface:r1.n_10_1_9_0-24,
 interface:r1.n2,
 interface:r2.n_10_1_8_128-25,
 interface:r3@vrf7.n_10_1_7_0,
 interface:r2.n1
;
=END=
=OUTPUT=
pathrestriction:p1 =
 interface:r1.n2,
 interface:r2.n1,
 interface:r3@vrf7.n_10_1_7_0,
 interface:r2.n_10_1_8_128-25,
 interface:r1.n_10_1_9_0-24,
;
=END=

############################################################
=TITLE=Protocol definition
=INPUT=
protocol:all_ip = # IGNORE
 ip;
protocol:http =
tcp 80;
protocol:BGP = tcp 179, no_check_supernet_rules;
protocol:all_icmp =
 description = icmp with any typ and code
 icmp;
=END=
=OUTPUT=
protocol:all_ip = ip;

protocol:http = tcp 80;

protocol:BGP = tcp 179, no_check_supernet_rules;

protocol:all_icmp =
 description = icmp with any typ and code

 icmp;
=END=

############################################################
=TITLE=Owner definition
=INPUT=
owner:a = { admins = a@example.com; }
owner:ab = { admins = a@example.com, b@example.com; }
owner:abw = { watchers = w@example.com; admins = a@example.com, b@example.com; }
=END=
=OUTPUT=
owner:a = {
 admins = a@example.com;
}

owner:ab = {
 admins = a@example.com,
          b@example.com,
          ;
}

owner:abw = {
 watchers = w@example.com;
 admins = a@example.com,
          b@example.com,
          ;
}
=END=

############################################################
=TITLE=Owner definition, verbose output
=INPUT=
--f1
group:g1=;
--f2
group:g2 =
;
-- f3
group:g3=;
=OUTPUT=
-- f1
group:g1 =
;
-- f2
group:g2 =
;
-- f3
group:g3 =
;
=WARNING=
Changed f1
Changed f3
=OPTIONS=--quiet=false

############################################################
=TITLE=Ignore errors in config file
=INPUT=
--config
foo = bar;
xxx
=END=
=WARNING=NONE

############################################################
=TITLE=Can't change readonly file
=INPUT=
--f1
group:g1=;
=SETUP=
chmod u-w netspoc/f1
=ERROR=
Error: Can't open f1: permission denied
=END=

############################################################
