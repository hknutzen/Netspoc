
############################################################
=TITLE=Create group
=INPUT=
-- topo
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
        "value": { "elements": ["host:h11", "host:h10", "host:h12"],
                   "description": "First group"
                 }
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ API
+group:g1 =
+ description = First group
+
+ host:h10,
+ host:h11,
+ host:h12,
+;
=END=

############################################################
=TITLE=Define new group via method 'set'
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "group:g1",
        "value": { "elements": "host:h1" }
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; }
+
+group:g1 =
+ host:h1,
+;
=END=

############################################################
=TITLE=Overwrite definition of group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

group:g1 =
 network:n1,
;
=JOB=
{
    "method": "set",
    "params": {
        "path": "group:g1",
        "value": { "elements": "host:h1" }
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; }
 group:g1 =
- network:n1,
+ host:h1,
 ;
=END=

############################################################
=TITLE=Invalid value for new group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
        "value": ["elements", ["host:h11", "host:h10", "host:h12"] ]
    }
}
=ERROR=
Error: Expecting JSON object when reading 'group:g1' but got: []interface {}
=END=

############################################################
=TITLE=Missing elements for new group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
        "value": {}
    }
}
=ERROR=
Error: Missing attribute 'elements' in 'group:g1'
=END=

############################################################
=TITLE=Invalid description for new group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
        "value": { "elements": ["network:n1"],
                   "description": null
                 }
    }
}
=ERROR=
Error: Expecting string as description
=END=

############################################################
=TITLE=Invalid attribute for new group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
        "value": { "elements": ["network:n1"],
                   "foo": "bar"
                 }
    }
}
=ERROR=
Error: Unexpected attribute 'foo' in 'group:g1'
=END=

############################################################
=TITLE=Invalid element for new group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
        "value": { "elements": ["n1"]
                 }
    }
}
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->n1"
=END=

############################################################
=TITLE=Add to group
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}

group:g1 =
 host:h10,
 host:h12,
;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h11"
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ INPUT
 group:g1 =
  host:h10,
+ host:h11,
  host:h12,
 ;
=END=

############################################################
=TITLE=Add invalid element to group
=INPUT=
group:g1 = ;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h1 + host:h2"
    }
}

=ERROR=
Error: Expected ';' at line 1 of command line, near "host:h1 --HERE-->+"
=END=

############################################################
=TITLE=Only string expected in element list
=INPUT=
group:g1 = ;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": [ null ]
    }
}

=ERROR=
Error: Unexpected type in JSON array: <nil>
=END=

############################################################
=TITLE=Missing value for element to add
=INPUT=
group:g1 = ;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": null
    }
}

=ERROR=
Error: Missing value for element
=END=

############################################################
=TITLE=Must not add multiple elements as string (1)
=INPUT=
group:g1 = ;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h1, host:h2"
    }
}

=ERROR=
Error: Expecting exactly on element in string
=END=

############################################################
=TITLE=Must not add multiple elements as string (2)
=INPUT=
group:g1 = ;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": ["host:h3", "host:h1, host:h2"]
    }
}

=ERROR=
Error: Expecting exactly on element in string
=END=

############################################################
=TITLE=Add to unknown group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h1"
    }
}
=ERROR=
Error: Can't modify unknown toplevel object 'group:g1'
=END=

############################################################
=TITLE=Delete from group
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}

network:n2a = { ip = 10.1.2.0/25; }
network:n2b = { ip = 10.1.2.128/25; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1  = { ip = 10.1.1.1; hardware = n1; }
 interface:n2a = { ip = 10.1.2.1; hardware = n2a; }
}

router:u = {
 interface:n2a = { ip = 10.1.2.126; }
 interface:n2b;
}

group:g1 =
 interface:[managed & network:n2a].[auto],
 host:h10,
 host:[network:n1] &! host:h10,
 any:[ip=10.1.2.0/24 & network:n2b],
;
=JOB=
{
    "method": "delete",
    "params": {
        "path": "group:g1,elements",
        "value": [
            "host:h10",
            "host:[network:n1] &! host:h10",
            "any:[ ip=10.1.2.0/24 & network:n2b ]",
            "interface:[managed&network:n2a].[auto]"
        ]
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ INPUT
 }
 group:g1 =
- interface:[managed & network:n2a].[auto],
- host:h10,
- host:[network:n1] &! host:h10,
- any:[ip=10.1.2.0/24 & network:n2b],
 ;
=END=

############################################################
=TITLE=Delete unknown automatic aggregate from group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

group:g1 =
 any:[network:n1],
;
=JOB=
{
    "method": "delete",
    "params": {
        "path": "group:g1,elements",
        "value": [
            "any:[ ip = 10.1.0.0/16 & network:n1 ]"
        ]
    }
}
=ERROR=
Error: Can't find element 'any:[10.1.0.0/16&network:n1]'
=END=

############################################################
=TITLE=Delete group
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
group:g1 =
 host:h10,
 host:h11,
 host:h12,
;
=JOB=
{
    "method": "delete",
    "params": {
        "path": "group:g1"
    }
}
=OUTPUT=
@@ INPUT
  host:h11 = { ip = 10.1.1.11; }
  host:h12 = { ip = 10.1.1.12; }
 }
-group:g1 =
- host:h10,
- host:h11,
- host:h12,
-;
=END=

############################################################
=TITLE=Missing elements in path
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
group:g1 =
 host:h10,
 host:h11,
 host:h12,
;
=JOB=
{
    "method": "delete",
    "params": {
        "path": "group:g1,host:h12"
    }
}
=ERROR=
Error: Expected attribute 'elements'
=END=

############################################################
=TITLE=Must not descend into group
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
group:g1 =
 host:h10,
 host:h11,
 host:h12,
;
=JOB=
{
    "method": "delete",
    "params": {
        "path": "group:g1,elements,host:h12"
    }
}
=ERROR=
Error: Can't descend into element list
=END=

############################################################
=TITLE=Add description to group
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
}
group:g1 =
 host:h10,
 host:h11,
;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,description",
        "value": "This group"
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ INPUT
  host:h10 = { ip = 10.1.1.10; }
  host:h11 = { ip = 10.1.1.11; }
 }
+
 group:g1 =
+ description = This group
+
  host:h10,
  host:h11,
 ;
=END=

############################################################
=TITLE=Remove description from group
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
}
group:g1 =
 description = This group

 host:h10,
 host:h11,
;
=JOB=
{
    "method": "delete",
    "params": {
        "path": "group:g1,description"
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ INPUT
  host:h10 = { ip = 10.1.1.10; }
  host:h11 = { ip = 10.1.1.11; }
 }
-group:g1 =
- description = This group
+group:g1 =
  host:h10,
  host:h11,
 ;
=END=

############################################################
=TITLE=Replace description at group
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
}

group:g1 =
 description = This group

 host:h10,
 host:h11,
;
=JOB=
{
    "method": "set",
    "params": {
        "path": "group:g1,description",
        "value": "That group"
    }
}
=WARNING=
Warning: unused group:g1
=OUTPUT=
@@ INPUT
 }
 group:g1 =
- description = This group
+ description = That group
  host:h10,
  host:h11,
=END=

############################################################
=TITLE=Add to multi block group (1)
=TEMPL=input
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h_10_1_1_4 = { ip = 10.1.1.4; }
 host:h_10_1_1_5 = { ip = 10.1.1.5; }
 host:h_10_1_1_44 = { ip = 10.1.1.44; }
}
network:n2 = { ip = 10.1.2.0/24;
 host:h_10_1_2_5 = { ip = 10.1.2.5; }
 host:h_10_1_2_6 = { ip = 10.1.2.6; }
 host:h_10_1_2_7 = { ip = 10.1.2.7; }
 host:h_10_1_2_9 = { ip = 10.1.2.9; }
}
network:n3 = { ip = 10.1.3.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
 interface:n4 = { ip = 10.1.4.1; hardware = n4; }
}

network:n4 = { ip = 10.1.4.0/24; }
-- group
group:g1 =
 host:h_10_1_1_4,
 host:h_10_1_1_44,
 network:n3,
 host:h_10_1_2_6,
 host:h_10_1_2_9,
;
-- service
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n4; prt = tcp 80;
}

=INPUT=
[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h_10_1_2_7"
    }
}
=OUTPUT=
@@ group
 group:g1 =
+ network:n3,
  host:h_10_1_1_4,
  host:h_10_1_1_44,
- network:n3,
  host:h_10_1_2_6,
+ host:h_10_1_2_7,
  host:h_10_1_2_9,
 ;
=END=

############################################################
=TITLE=Add to multi block group (2)
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h_10_1_2_5"
    }
}
=OUTPUT=
@@ group
 group:g1 =
+ network:n3,
  host:h_10_1_1_4,
  host:h_10_1_1_44,
- network:n3,
+ host:h_10_1_2_5,
  host:h_10_1_2_6,
  host:h_10_1_2_9,
 ;
=END=

############################################################
=TITLE=Add to multi block group (3)
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h_10_1_1_5"
    }
}
=OUTPUT=
@@ group
 group:g1 =
+ network:n3,
  host:h_10_1_1_4,
+ host:h_10_1_1_5,
  host:h_10_1_1_44,
- network:n3,
  host:h_10_1_2_6,
  host:h_10_1_2_9,
 ;
=END=

############################################################
=TITLE=Add name without IP to group
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24; }
-- group
group:g1 =
 interface:r1.n1,
 network:n1,
 interface:r1.n2,
;
-- service
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "network:n2"
    }
}
=OUTPUT=
@@ group
 group:g1 =
- interface:r1.n1,
  network:n1,
+ network:n2,
+ interface:r1.n1,
  interface:r1.n2,
 ;
=END=

############################################################
=TITLE=Add before first element located on first line
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h_10_1_1_4 = { ip = 10.1.1.4; }
 host:h_10_1_1_5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- group
group:g1 = host:h_10_1_1_5; # Comment
-- service
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h_10_1_1_4"
    }
}
=OUTPUT=
@@ group
-group:g1 = host:h_10_1_1_5; # Comment
+group:g1 =
+ host:h_10_1_1_4,
+ host:h_10_1_1_5, # Comment
+;
=END=

############################################################
=TITLE=Add union with intersection and automatic element
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h_10_1_1_4 = { ip = 10.1.1.4; }
 host:h_10_1_1_5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- group
group:g1 = host:h_10_1_1_5; # Comment
-- service
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": ["interface:r1.[all] &! interface:r1.n1", "host:h_10_1_1_4"]
    }
}
=OUTPUT=
@@ group
-group:g1 = host:h_10_1_1_5; # Comment
+group:g1 =
+ interface:r1.[all]
+ &! interface:r1.n1
+ ,
+ host:h_10_1_1_4,
+ host:h_10_1_1_5, # Comment
+;
=END=

############################################################
=TITLE=Add to group having description ending with semicolon
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

network:n3 = { ip = 10.1.3.0/24; }
-- group
group:g1 =
 description = Some text;
 network:n1,
;
-- service
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n3; prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "network:n2"
    }
}
=OUTPUT=
@@ group
 group:g1 =
- description = Some text;
+ description = Some text
+
  network:n1,
+ network:n2,
 ;
=END=

############################################################
=TITLE=Add to empty group
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; host:h4 = { ip = 10.1.1.4; } }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

network:n2 = { ip = 10.1.2.0/24; }
-- group
group:g1 = ; # IGNORED
-- service
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n2; prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1,elements",
        "value": "host:h4"
    }
}
=OUTPUT=
@@ group
-group:g1 = ; # IGNORED
+group:g1 =
+ host:h4,
+;
=END=
