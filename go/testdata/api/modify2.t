
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR JOB ...
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR JOB ...
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=Unknown option
=INPUT=NONE
=PARAMS=--abc
=ERROR=
Error: unknown flag: --abc
=END=

############################################################
=TITLE=Invalid JSON in job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
=ERROR=
Error: In JSON file job: unexpected end of JSON input
=END=

############################################################
=TITLE=Unknown job file
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=PARAM=foo
=ERROR=
Error: Can't open foo: no such file or directory
=END=

############################################################
=TITLE=Invalid empty job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{}
=ERROR=
Error: Missing "params" in JSON file job
=END=

############################################################
=TITLE=Invalid job without params
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add"
}
=ERROR=
Error: Missing "params" in JSON file job
=END=

############################################################
=TITLE=Invalid job without method
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "params": {}
}
=ERROR=
Error: Unknown method ''
=END=

############################################################
=TITLE=Invalid params
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": "foo"
}
=ERROR=
Error: In "params" of JSON file job: json: cannot unmarshal string into Go value of type map[string]interface {}
=END=

############################################################
=TITLE=Invalid value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": { "value": x }
}
=ERROR=
Error: In JSON file job: invalid character 'x' looking for beginning of value
=END=

############################################################
=TITLE=Invalid empty path
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": { "path": "" }
}
=ERROR=
Error: Invalid empty path
=END=

############################################################
=TITLE=Invalid netspoc data
=INPUT=
foo
=JOB=
{}
=ERROR=
Error: While reading netspoc files: Typed name expected at line 1 of INPUT, near "--HERE-->foo"
=END=

############################################################
=TITLE=Add invalid element to group
=INPUT=
group:g1 = ;
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
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
        "path": "group:g1",
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
        "path": "group:g1",
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
        "path": "group:g1",
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
        "path": "group:g1",
        "value": ["host:h3", "host:h1, host:h2"]
    }
}

=ERROR=
Error: Expecting exactly on element in string
=END=

############################################################
=TITLE=Add invalid element to src of rule
=INPUT=
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules,1,src",
        "value": "invalid"
    }
}

=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->invalid"
=END=

############################################################
=TITLE=Add invalid element to dst of rule
=INPUT=
service:s1 = {
 user = group:g1;
 permit src = user; dst = network:n4; prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules,1,dst",
        "value": "invalid"
    }
}

=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->invalid"
=END=

############################################################
=TITLE=Add to unknown group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "group:g1",
        "value": "host:h1"
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
=TITLE=Define new group
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "group:g1",
        "value": "host:h1"
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
        "value": "host:h1"
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
        "path": "group:g1",
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
        "path": "group:g1",
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
        "path": "group:g1",
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
        "path": "group:g1",
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
        "path": "group:g1",
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
        "path": "group:g1",
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
=TITLE=Group having description ending with semicolon
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
        "path": "group:g1",
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
        "path": "group:g1",
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

############################################################
=TITLE=Added owner exists
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
-- owner
owner:a = {
 admins = a@example.com;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:a",
        "value": { "admins": "a@example.com" }
    }
}
=ERROR=
Error: 'owner:a' already exists
=OUTPUT=NONE

############################################################
=TITLE=Added owner exists, ok
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
-- owner
owner:a = {
 admins = a@example.com;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:a",
        "value": { "admins": "a@example.com" },
        "ok_if_exists": true
    }
}
=WARNING=NONE
=OUTPUT=NONE

############################################################
=TITLE=Replace existing owner with invalid value
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
-- owner
owner:a = {
 admins = a@example.com;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "owner:a",
        "value": { "admins": 42 }
    }
}
=ERROR=
Error: Unexpected type in JSON value: float64
=END=

############################################################
=TITLE=Delete still referenced owner
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
-- owner
owner:a = {
 admins = a@example.com; #}
} # end
# next line
=JOB=
{
    "method": "delete",
    "params": {
        "path": "owner:a"
    }
}
=WARNING=
Warning: Ignoring file 'owner' without any content
Warning: Ignoring undefined owner:a of network:n1
=OUTPUT=
@@ owner
-owner:a = {
- admins = a@example.com; #}
-} # end
 # next line
=END=

############################################################
=TITLE=Modify owner: change admins, add watchers
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
owner:a = {
 admins = a@example.com; } # Comment
=JOB=
{
    "method": "set",
    "params": {
        "path": "owner:a",
        "value": {
            "admins": [ "b@example.com", "a@example.com" ],
            "watchers": [ "c@example.com", "d@example.com" ]
        }
    }
}
=OUTPUT=
@@ topology
 network:n1 = { ip = 10.1.1.0/24; owner = a; }
+
 owner:a = {
- admins = a@example.com; } # Comment
+ admins = a@example.com,
+          b@example.com,
+          ;
+ watchers = c@example.com,
+            d@example.com,
+            ;
+}
=END=

############################################################
=TITLE=Modify owner with swapped admins and watchers
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
owner:a = {
 watchers = b@example.com;
 admins   = a@example.com; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "owner:a",
        "value": {
            "admins": [ "b@example.com" ],
            "watchers": [ "c@example.com" ]
        }
    }
}
=OUTPUT=
@@ topology
 network:n1 = { ip = 10.1.1.0/24; owner = a; }
+
 owner:a = {
- watchers = b@example.com;
- admins   = a@example.com; }
+ admins = b@example.com;
+ watchers = c@example.com;
+}
=END=

############################################################
=TITLE=Modify owner: leave admins untouched, remove watchers
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
owner:a = {
 watchers = b@example.com;
 admins   = a@example.com;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "owner:a,watchers"
    }
}
=OUTPUT=
@@ topology
 network:n1 = { ip = 10.1.1.0/24; owner = a; }
+
 owner:a = {
- watchers = b@example.com;
- admins   = a@example.com;
+ admins = a@example.com;
 }
=END=

############################################################
=TITLE=Modify owner, defined in one line
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
owner:a = { admins = a@example.com; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "owner:a",
        "value": {
            "admins": [ "c@example.com" ]
        }
    }
}
=OUTPUT=
@@ topology
 network:n1 = { ip = 10.1.1.0/24; owner = a; }
-owner:a = { admins = a@example.com; }
+
+owner:a = {
+ admins = c@example.com;
+}
=END=

############################################################
=TITLE=Modify owner: multiple attributes in one line
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; owner = a; }
owner:a = {
 admins = a@example.com; watchers = b@example.com;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "owner:a,admins",
        "value": [ "c@example.com" ]
    }
}
=OUTPUT=
@@ topology
 network:n1 = { ip = 10.1.1.0/24; owner = a; }
+
 owner:a = {
- admins = a@example.com; watchers = b@example.com;
+ admins = c@example.com;
+ watchers = b@example.com;
 }
=END=

############################################################
=TITLE=Add host to known network
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4" }
    }
}
=OUTPUT=
@@ topology
-network:a = { ip = 10.1.1.0/24; }
+network:a = {
+ ip = 10.1.1.0/24;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
+}
=END=

############################################################
=TITLE=Add host with IP range
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:range",
        "value": { "range": "10.1.1.16-10.1.1.31" }
    }
}
=OUTPUT=
@@ topology
-network:a = { ip = 10.1.1.0/24; }
+network:a = {
+ ip = 10.1.1.0/24;
+ host:range = { range = 10.1.1.16-10.1.1.31; }
+}
=END=

############################################################
=TITLE=Add host, insert sorted
=INPUT=
-- topology
network:a = {
 ip = 10.1.1.0/24;
 # Comment1
 host:name_10_1_1_2 = { ip = 10.1.1.2; }
 # Comment2
 # Comment3
 host:name_10_1_1_5 = { ip = 10.1.1.5; }
 host:name_10_1_1_6 = { ip = 10.1.1.6; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4" }
    }
}
=OUTPUT=
@@ topology
  ip = 10.1.1.0/24;
  # Comment1
  host:name_10_1_1_2 = { ip = 10.1.1.2; }
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
  # Comment2
  # Comment3
  host:name_10_1_1_5 = { ip = 10.1.1.5; }
=END=

############################################################
=TITLE=Add host, same name
=INPUT=
-- topology
network:a = {
 ip = 10.1.1.0/24;
 host:name_10_1_1_4 = { ip = 10.1.1.4; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4" }
    }
}
=ERROR=
Error: Can't add to complex value of 'host:name_10_1_1_4'
=END=

############################################################
=TITLE=Add host, same IP
=INPUT=
-- topology
network:a = {
 ip = 10.1.1.0/24;
 host:other_10_1_1_4 = { ip = 10.1.1.4; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4" }
    }
}
=ERROR=
Error: Duplicate IP address for host:other_10_1_1_4 and host:name_10_1_1_4
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.1.0/24;
  host:other_10_1_1_4 = { ip = 10.1.1.4; }
+ host:name_10_1_1_4  = { ip = 10.1.1.4; }
 }
=END=

############################################################
=TITLE=Multiple networks at one line
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; } network:b = { ip = 10.1.2.0/24; }
router:r1 = {
 interface:a;
 interface:b;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4" }
    }
}
=OUTPUT=
@@ topology
-network:a = { ip = 10.1.1.0/24; } network:b = { ip = 10.1.2.0/24; }
+network:a = {
+ ip = 10.1.1.0/24;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
+}
+
+network:b = { ip = 10.1.2.0/24; }
+
 router:r1 = {
  interface:a;
  interface:b;
=END=

############################################################
=TITLE=Add host with owner
=INPUT=
-- topology
owner:DA_abc = {
 admins = abc@example.com;
}

network:a = { ip = 10.1.0.0/21; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4", "owner": "DA_abc" }
    }
}
=OUTPUT=
@@ topology
  admins = abc@example.com;
 }
-network:a = { ip = 10.1.0.0/21; }
+network:a = {
+ ip = 10.1.0.0/21;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; owner = DA_abc; }
+}
=END=

############################################################
=TITLE=Add host, redundant owner
=TODO=
=INPUT=
-- topology
owner:DA_abc = {
 admins = abc@example.com;
}

network:a = {
 ip = 10.1.0.0/21;
 owner = DA_abc;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4", "owner": "DA_abc" }
    }
}
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.0.0/21;
  owner = DA_abc;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
 }
=END=

############################################################
=TITLE=Add host, with warning from previous checkin
=INPUT=
-- topology
owner:DA_abc = {
 admins = abc@example.com;
}

network:a = {
 ip = 10.1.0.0/21;
 owner = DA_abc;
 host:name_10_1_1_4 = { ip = 10.1.1.4; owner = DA_abc; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_3",
        "value": { "ip": "10.1.1.3" }
    }
}
=WARNING=
Warning: Useless owner:DA_abc at host:name_10_1_1_4,
 it was already inherited from network:a
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.0.0/21;
  owner = DA_abc;
+ host:name_10_1_1_3 = { ip = 10.1.1.3; }
  host:name_10_1_1_4 = { ip = 10.1.1.4; owner = DA_abc; }
 }
=END=

############################################################
=TITLE=Add host, with old and new warning
=INPUT=
-- topology
network:a = {
 ip = 10.1.0.0/21;
 host:name_10_1_1_4 = { ip = 10.1.1.4; }
}

router:r = {
 interface:a;
 interface:b;
}

network:b = {
 ip = 10.1.1.0/24;
 subnet_of = network:a;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_3",
        "value": { "ip": "10.1.1.3" }
    }
}
=WARNING=
Warning: IP of host:name_10_1_1_3 overlaps with subnet network:b
Warning: IP of host:name_10_1_1_4 overlaps with subnet network:b
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.0.0/21;
+ host:name_10_1_1_3 = { ip = 10.1.1.3; }
  host:name_10_1_1_4 = { ip = 10.1.1.4; }
 }
=END=

############################################################
=TITLE=Add host, unknown owner
=INPUT=
-- topology
network:a = {
 ip = 10.1.0.0/21;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a,host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4", "owner": "DA_abc" }
    }
}
=WARNING=
Warning: Ignoring undefined owner:DA_abc of host:name_10_1_1_4
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.0.0/21;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; owner = DA_abc; }
 }
=END=

############################################################
=TITLE=Add host, no IP address found
=INPUT=
-- topology
network:a = { ip = 10.1.0.0/21; }
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "[auto]",
        "name": "name_10_1_1_4",
        "ip": "10.1.0.*",
        "mask": "255.255.248.0"
    }
}
=ERROR=
Error: Invalid IP address: '10.1.0.*'
=END=

############################################################
=TITLE=Add host, invalid IP address
=INPUT=
-- topology
network:a = { ip = 10.1.0.0/21; }
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "[auto]",
        "name": "name_10_1_1_4",
        "ip": "10.1.0.444",
        "mask": "255.255.248.0"
    }
}
=ERROR=
Error: Invalid IP address: '10.1.0.444'
=END=

############################################################
=TITLE=Add host, invalid IP mask
=INPUT=
-- topology
network:a = { ip = 10.1.0.0/21; }
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "[auto]",
        "name": "name_10_1_1_4",
        "ip": "10.1.0.4",
        "mask": "123.255.248.0"
    }
}
=ERROR=
Error: Invalid IP mask: '123.255.248.0'
=END=

############################################################
=TITLE=Add host to [auto] network
=INPUT=
-- topology
network:d = { ip = 10.2.0.0/21; }
network:u = { unnumbered; }

network:a = {
 ip = 10.1.0.0/21;
}

router:r = {
 interface:a;
 interface:d;
 interface:u;
}
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "[auto]",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4",
        "mask": "255.255.248.0"
    }
}
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.0.0/21;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
 }
 router:r = {
=END=

############################################################
=TITLE=Add host, can't find [auto] network
=INPUT=
-- topology
network:a = { ip = 10.1.0.0/24; }
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "[auto]",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4",
        "mask": "255.255.248.0"
    }
}
=ERROR=
Error: Can't find network with 'ip = 10.1.0.0/21'
=END=

############################################################
=TITLE=Add host, multiple [auto] networks
=INPUT=
-- topology
network:a = {
 ip = 10.1.0.0/21;
 nat:a = { hidden; }
}

network:b = {
 ip = 10.1.0.0/21;
 nat:b = { hidden; }
}

router:r1 = {
 interface:a = {
  bind_nat = b;
 }
 interface:b = {
  bind_nat = a;
 }
}
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "[auto]",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4",
        "mask": "255.255.248.0"
    }
}
=ERROR=
Error: Duplicate definition of host:name_10_1_1_4 in topology
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.0.0/21;
  nat:a = { hidden; }
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
 }
 network:b = {
  ip = 10.1.0.0/21;
  nat:b = { hidden; }
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
 }
 router:r1 = {
=END=

############################################################
=TITLE=multi_job without jobs
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": []
    }
}
=OUTPUT=NONE

############################################################
=TITLE=multi_job: add host and owner
=INPUT=
-- topology
network:n1 = {
 ip = 10.1.1.0/24;
}
-- owner
# Add owners below.
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "owner:a",
                    "value": {
                        "watchers": [ "c@example.com", "d@example.com" ],
                        "admins": [ "b@example.com", "a@example.com" ]
                    }
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "network:n1,host:name_10_1_1_4",
                    "value": { "ip": "10.1.1.4", "owner": "a" }
                }
            }
        ]
    }
}
=OUTPUT=
@@ owner
+owner:a = {
+ admins = a@example.com,
+          b@example.com,
+          ;
+ watchers = c@example.com,
+            d@example.com,
+            ;
+}
 # Add owners below.
@@ topology
 network:n1 = {
  ip = 10.1.1.0/24;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; owner = a; }
 }
=END=

############################################################
=TITLE=multi_job: add owner that exists and add host
=INPUT=
-- topology
network:n1 = {
 ip = 10.1.1.0/24;
 host:name_10_1_1_5 = { ip = 10.1.1.5; owner = a; }
}
-- owner
owner:a = {
 admins = a@example.com;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "owner:a",
                    "value" : { "admins": [ "b@example.com" ] },
                    "ok_if_exists": true
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "network:n1,host:name_10_1_1_4",
                    "value": { "ip": "10.1.1.4", "owner": "a" }
                }
            }
        ]
    }
}
=OUTPUT=
@@ topology
 network:n1 = {
  ip = 10.1.1.0/24;
+ host:name_10_1_1_4 = { ip = 10.1.1.4; owner = a; }
  host:name_10_1_1_5 = { ip = 10.1.1.5; owner = a; }
 }
=END=

############################################################
=TITLE=multi_job: second job fails
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "network:n1,host:name_10_1_1_4",
                    "value": { "ip": "10.1.1.4" }
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "network:n2,host:name_10_1_2_4",
                    "value": { "ip": "10.1.2.4" }
                }
            }
        ]
    }
}
=ERROR=
Error: Can't modify unknown toplevel object 'network:n2'
=END=

############################################################
=TITLE=Change unknown host
=TODO=
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "host:h1,owner",
        "value": "o1"
    }
}
=ERROR=
Error: Can't find 'host:h1'
=END=

############################################################
=TITLE=Remove owner at host
=INPUT=
-- topology
owner:o1 = {
 admins = a1@example.com;
}

network:n1 = {
 ip = 10.1.1.0/24;
 owner = o1;
 host:h1 = { ip = 10.1.1.1; owner = o1; }
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "network:n1,host:h1,owner"
    }
}
=OUTPUT=
@@ topology
 network:n1 = {
  ip = 10.1.1.0/24;
  owner = o1;
- host:h1 = { ip = 10.1.1.1; owner = o1; }
+ host:h1 = { ip = 10.1.1.1; }
 }
=END=

############################################################
=TITLE=Add owner to host
=INPUT=
-- topology
owner:o1 = {
 admins = a1@example.com;
}

network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; owner = o1; }
 host:h2 = { ip = 10.1.1.2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,host:h2,owner",
        "value": "o1"
    }
}
=OUTPUT=
@@ topology
 network:n1 = {
  ip = 10.1.1.0/24;
  host:h1 = { ip = 10.1.1.1; owner = o1; }
- host:h2 = { ip = 10.1.1.2; }
+ host:h2 = { ip = 10.1.1.2; owner = o1; }
 }
=END=

############################################################
=TITLE=Replace missing owner at host
# "set" acts like "add" on new attribute.
=INPUT=
-- topology
owner:o1 = {
 admins = a1@example.com;
}

network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; owner = o1; }
 host:h2 = { ip = 10.1.1.2; }
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,host:h2,owner",
        "value": "o1"
    }
}
=OUTPUT=
@@ topology
 network:n1 = {
  ip = 10.1.1.0/24;
  host:h1 = { ip = 10.1.1.1; owner = o1; }
- host:h2 = { ip = 10.1.1.2; }
+ host:h2 = { ip = 10.1.1.2; owner = o1; }
 }
=END=

############################################################
=TITLE=Change owner of host, add and delete owner
=INPUT=
-- topology
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = {
  ip = 10.1.1.1;
  owner = o1;
 } host:h2 = { ip = 10.1.1.2; }
}
-- owner
owner:o1 = { admins = a1@example.com; }
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "owner:o2",
                    "value": { "admins": [ "a2@example.com" ] }
                }
            },
            {
                "method": "delete",
                "params": {
                    "path": "owner:o1"
                }
            },
            {
                "method": "set",
                "params": {
                    "path": "network:n1,host:h1,owner",
                    "value": "o2"
                }
            },
            {
                "method": "set",
                "params": {
                    "path": "network:n1,host:h2,owner",
                    "value": "o2"
                }
            }
        ]
    }
}
=OUTPUT=
@@ owner
-owner:o1 = { admins = a1@example.com; }
+owner:o2 = {
+ admins = a2@example.com;
+}
@@ topology
 network:n1 = {
  ip = 10.1.1.0/24;
- host:h1 = {
-  ip = 10.1.1.1;
-  owner = o1;
- } host:h2 = { ip = 10.1.1.2; }
+ host:h1 = { ip = 10.1.1.1; owner = o2; }
+ host:h2 = { ip = 10.1.1.2; owner = o2; }
 }
=END=

############################################################
=TITLE=Change owner at second of multiple ID-hosts
=INPUT=
-- topology
ipsec:aes256SHA = {
 key_exchange = isakmp:aes256SHA;
 esp_encryption = aes256;
 esp_authentication = sha;
 pfs_group = 2;
 lifetime = 600 sec;
}

isakmp:aes256SHA = {
 authentication = rsasig;
 encryption = aes256;
 hash = sha;
 group = 2;
 lifetime = 86400 sec;
}

crypto:vpn1 = {
 type = ipsec:aes256SHA;
}

crypto:vpn2 = {
 type = ipsec:aes256SHA;
}

network:intern = { ip = 10.1.0.0/24; }

router:r = {
 model = IOS;
 managed = routing_only;
 interface:intern = { ip = 10.1.0.1; hardware = e0; }
 interface:trans  = { ip = 10.9.9.1; hardware = e1; }
}

network:trans = { ip = 10.9.9.0/24; }

router:gw = {
 model = IOS;
 managed;
 routing = manual;
 interface:trans   = { ip = 10.9.9.2; hardware = e0; }
 interface:dmz-int = { ip = 192.168.1.2; hardware = e1; }
}

network:dmz-int = { ip = 192.168.1.0/24; }

router:asavpn1 = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:dmz-int = {
  ip = 192.168.1.101;
  hub = crypto:vpn1;
  hardware = outside;
  no_check;
 }
}

router:soft-int = {
 interface:trans = {
  spoke = crypto:vpn1;
  ip = 10.9.9.3;
 }
 interface:n1;
}

router:asavpn2 = {
 model = ASA, VPN;
 managed;
 general_permit = icmp 3;
 radius_attributes = {
  trust-point = ASDM_TrustPoint1;
 }
 interface:intern = { ip = 10.1.0.101; hardware = inside; }
 interface:dmz = {
  ip = 192.168.0.101;
  hub = crypto:vpn2;
  hardware = outside;
 }
}

network:dmz = { ip = 192.168.0.0/24; }

router:extern = {
 interface:dmz = { ip = 192.168.0.1; }
 interface:internet;
}

network:internet = {
 ip = 0.0.0.0/0;
 has_subnets;
}

router:soft-ext = {
 interface:internet = {
  spoke = crypto:vpn2;
 }
 interface:n2;
}

network:n1 = {
 ip = 10.1.1.0/24;
 host:id:a1@example.com = { ip = 10.1.1.1; owner = DA_TOKEN_o1; }
 host:id:a2@example.com = { ip = 10.1.1.2; owner = DA_TOKEN_o1; }
}

network:n2 = {
 ip = 10.1.2.0/24;
 host:id:a1@example.com = { ip = 10.1.2.1; owner = DA_TOKEN_o1; }
 host:id:a2@example.com = { ip = 10.1.2.2; owner = DA_TOKEN_o2; }
}
-- owner-token
owner:DA_TOKEN_o1 = {
 admins = a1@example.com;
}
owner:DA_TOKEN_o2 = { admins = a2@example.com; }
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "set",
                "params": {
                    "path": "network:n2,host:id:a2@example.com,owner",
                    "value": "DA_TOKEN_o3"
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "owner:DA_TOKEN_o3",
                    "value": { "admins": [ "a3@example.com" ] }
                }
            },
            {
                "method": "delete",
                "params": {
                    "path": "owner:DA_TOKEN_o2"
                }
            }
        ]
    }
}
=OUTPUT=
@@ owner-token
 owner:DA_TOKEN_o1 = {
  admins = a1@example.com;
 }
-owner:DA_TOKEN_o2 = { admins = a2@example.com; }
+
+owner:DA_TOKEN_o3 = {
+ admins = a3@example.com;
+}
@@ topology
 network:n2 = {
  ip = 10.1.2.0/24;
  host:id:a1@example.com = { ip = 10.1.2.1; owner = DA_TOKEN_o1; }
- host:id:a2@example.com = { ip = 10.1.2.2; owner = DA_TOKEN_o2; }
+ host:id:a2@example.com = { ip = 10.1.2.2; owner = DA_TOKEN_o3; }
 }
=END=

############################################################
=TITLE=Job with malicous network name
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; } # Comment
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:a exit;,host:h",
        "value": { "ip": "10.1.1.10" }
    }
}
=ERROR=
Error: Can't modify unknown toplevel object 'network:a exit;'
=END=

############################################################
=TITLE=Job with whitespace in email address
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
-- owner
owner:a = { admins = a@example.com; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "owner:a,admins",
        "value": ["b example.com"]
    }
}
=ERROR=
Error: Expected ';' at line 2 of owner, near "b --HERE-->example.com"
Aborted
=OUTPUT=
@@ owner
-owner:a = { admins = a@example.com; }
+owner:a = {
+ admins = b example.com;
+}
=END=

############################################################
=TITLE=Add service, create rule/ directory
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h3 = { ip = 10.1.1.3; }
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:multi",
        "value" : {
            "user": "network:n2",
            "rules": [
            {
                "action": "permit",
                "src": "user",
                "dst": ["host:[network:n1] &! host:h4", "interface:r1.n1"],
                "prt": ["udp", "tcp"]
            },
            {
                "action": "permit",
                "src": "user",
                "dst": "host:h4",
                "prt": ["tcp 90", "  tcp  80-85"]
            },
            {
                "action": "deny",
                "src": "user",
                "dst": "network:n1",
                "prt": "tcp 22"
            },
            {
                "action": "deny",
                "src": "host:h5",
                "dst": "user",
                "prt": "udp, icmp 4"
            }
            ]
        }
    }
}
=OUTPUT=
@@ rule/M
+service:multi = {
+ user = network:n2;
+ permit src = user;
+        dst = interface:r1.n1,
+              host:[network:n1]
+              &! host:h4
+              ,
+              ;
+        prt = tcp,
+              udp,
+              ;
+ permit src = user;
+        dst = host:h4;
+        prt =   tcp  80-85,
+              tcp 90,
+              ;
+ deny   src = user;
+        dst = network:n1;
+        prt = tcp 22;
+ deny   src = host:h5;
+        dst = user;
+        prt = udp, icmp 4;
+}
=END=

############################################################
=TITLE=Add service, complex user
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h3 = { ip = 10.1.1.3; }
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:complex",
        "value": {
            "description": "This one",
            "user": ["host:[network:n1] &! host:h4", "interface:r1.n1"],
            "rules": [
                {
                    "action": "permit",
                    "src": "user",
                    "dst": "network:n2",
                    "prt": "tcp 80"
                }
            ]
        }
    }
}
=OUTPUT=
@@ rule/C
+service:complex = {
+ description = This one
+
+ user = interface:r1.n1,
+        host:[network:n1]
+        &! host:h4
+        ,
+        ;
+ permit src = user;
+        dst = network:n2;
+        prt = tcp 80;
+}
=END=

############################################################
=TITLE=Add service with attributes
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h3 = { ip = 10.1.1.3; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:a = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
service:b = {
 user = host:h3;
 permit src = user;
        dst = network:n2;
        prt = tcp;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:with-attributes",
        "value": {
            "description": "Looks-like-a-value;",
            "overlaps": ["service:a", "service:b"],
            "has_unenforceable": null,
            "disable_at": "2099-11-22",
            "user": "host:h3",
            "rules": [
                {
                    "action": "permit",
                    "src": "user",
                    "dst": ["network:n1", "network:n2"],
                    "prt": "tcp 80"
                }
            ]
        }
    }
}
=OUTPUT=
@@ rule/W
+service:with-attributes = {
+ description = Looks-like-a-value
+
+ disable_at = 2099-11-22;
+ has_unenforceable;
+ overlaps = service:a,
+            service:b,
+            ;
+
+ user = host:h3;
+ permit src = user;
+        dst = network:n1,
+              network:n2,
+              ;
+        prt = tcp 80;
+}
=END=

############################################################
=TITLE=Add service with invalid attribute value
=INPUT=
#
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:with-attributes",
        "value": {
            "overlaps": ["service:a", "service:b", {"service": "c"}],
            "user": "host:h3",
            "rules": [
                {
                    "action": "permit",
                    "src": "user",
                    "dst": "network:n1",
                    "prt": "tcp 80"
                }
            ]
        }
    }
}
=ERROR=
Error: Unexpected type in JSON array: map[string]interface {}
=END=

############################################################
=TITLE=Add service with missing user
=INPUT=
#
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "rules": [
            {
                "action": "permit",
                "src": "user",
                "dst": "network:n1",
                "prt": "tcp 80"
            }]
        }
    }
}
=ERROR=
Error: Missing attribute 'user' in 'service:s1'
=END=

############################################################
=TITLE=Add service with invalid user
=INPUT=
#
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": 42,
            "rules": [
            {
                "action": "permit",
                "src": "user",
                "dst": "network:n1",
                "prt": "tcp 80"
            }]
        }
    }
}
=ERROR=
Error: Unexpected type in element list: float64
=END=

############################################################
=TITLE=Add service without rule
=INPUT=
#
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": "network:n1"
        }
    }
}
=ERROR=
Error: Missing attribute 'rules' in 'service:s1'
=END=

############################################################
=TEMPL=input
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

############################################################
=TITLE=Add empty service, alter user and rule afterwards
=INPUT=
[[input]]
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "service:s1",
                    "value": {
                        "user": [],
                        "rules": []
                    }
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "service:s1,user",
                    "value": "network:n1"
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules",
                    "value": {
                        "action": "permit",
                        "src": "user",
                        "dst": "network:n2",
                        "prt": "tcp 80"
                    }
                }
            }
        ]
    }
}
=OUTPUT=
@@ rule/S
+service:s1 = {
+ user = network:n1;
+ permit src = user;
+        dst = network:n2;
+        prt = tcp 80;
+}
=END=

############################################################
=TITLE=Add service, invalid action
=INPUT=
[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": "network:n1",
            "rules": [
                {
                    "action": "allow",
                    "src": "user",
                    "dst": "network:n2",
                    "prt": "tcp 80"
                }]
            }
    }
}
=ERROR=
Error: Expected 'permit' or 'deny' in 'action'
=END=

############################################################
=TITLE=Add service, invalid user
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": "network:n1",
            "rules": [
                {
                    "action": "permit",
                    "src": "_user_",
                    "dst": "network:n2",
                    "prt": "tcp 80"
                }]
        }
    }
}
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->_user_"
=END=

############################################################
=TITLE=Add service, invalid object type
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": "network:n1",
            "rules": [
                {
                    "action": "permit",
                    "src": "user",
                    "dst": "net:n2",
                    "prt": "tcp 80"
                }]
        }
    }
}
=ERROR=
Error: Unknown element type at line 1 of command line, near "--HERE-->net:n2"
=END=

############################################################
=TITLE=Add service, invalid protocol
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
          "user": "network:n1",
          "rules": [ {
              "action": "permit",
              "src": "user",
              "dst": "network:n2",
              "prt": "udp6" }]
      }
  }
}
=ERROR=
Error: Unknown protocol in 'udp6' of service:s1
=OUTPUT=
@@ rule/S
+service:s1 = {
+ user = network:n1;
+ permit src = user;
+        dst = network:n2;
+        prt = udp6;
+}
=END=

############################################################
=TITLE=Add service, name starting with umlaut
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:Übermut",
        "value": {
          "user": "network:n1",
          "rules": [ {
              "action": "permit",
              "src": "user",
              "dst": "network:n2",
              "prt": "tcp 8888" }]
      }
  }
}
=OUTPUT=
@@ rule/other
+service:Übermut = {
+ user = network:n1;
+ permit src = user;
+        dst = network:n2;
+        prt = tcp 8888;
+}
=END=

############################################################
=TITLE=Add service, missing name
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:",
        "value": {
          "user": "network:n1",
          "rules": [ {
              "action": "permit",
              "src": "user",
              "dst": "network:n2",
              "prt": "tcp 8888" }]
      }
  }
}
=ERROR=
Error: Typed name expected at line 1 of rule/other, near "--HERE-->service:"
Aborted
=END=

############################################################
=TITLE=Add service, insert sorted
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- rule/S
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 81;
}
service:s3 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 83;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "service:s4",
                    "value": {
                        "user": "network:n1",
                        "rules": [
                            {
                                "action": "permit",
                                "src": "user",
                                "dst": "network:n2",
                                "prt": "tcp 84"
                            }
                        ]
                    }
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "service:s2",
                    "value": {
                        "user": "network:n1",
                        "rules": [
                            {
                                "action": "permit",
                                "src": "user",
                                "dst": "network:n2",
                                "prt": "tcp 82"
                            }
                        ]
                    }
                }
            }
            ]
    }
}
=OUTPUT=
@@ rule/S
         dst = network:n2;
         prt = tcp 81;
 }
+
+service:s2 = {
+ user = network:n1;
+ permit src = user;
+        dst = network:n2;
+        prt = tcp 82;
+}
+
 service:s3 = {
  user = network:n1;
  permit src = user;
         dst = network:n2;
         prt = tcp 83;
 }
+
+service:s4 = {
+ user = network:n1;
+ permit src = user;
+        dst = network:n2;
+        prt = tcp 84;
+}
=END=

############################################################
=TITLE=Add service with attributes
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:t1",
        "value": {
            "description": "abc def # ghi",
            "disable_at": "2099-02-03",
            "has_unenforceable": null,
            "user": "network:n1",
            "rules": [{
                "action": "permit",
                "src": "user",
                "dst": ["network:n1", "network:n2"],
                "prt": "tcp 80",
                "log": "high"
             }]
         }
    }
}
=WARNING=
Warning: Ignoring unknown 'high' in log of service:t1
=OUTPUT=
@@ rule/T
+service:t1 = {
+ description = abc def # ghi
+
+ disable_at = 2099-02-03;
+ has_unenforceable;
+
+ user = network:n1;
+ permit src = user;
+        dst = network:n1,
+              network:n2,
+              ;
+        prt = tcp 80;
+        log = high;
+}
=END=

############################################################
=TITLE=Delete service
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1"
    }
}
=WARNING=
Warning: Ignoring file 'service' without any content
=OUTPUT=
@@ service
-service:s1 = {
- user = network:n1;
- permit src = user;
-        dst = network:n2;
-        prt = tcp 80;
-}
=END=

############################################################
=TITLE=Delete service with overlaps
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = {
 ip = 10.1.2.0/24;
 host:h1 = { ip = 10.1.2.11; }
 host:h2 = { ip = 10.1.2.12; }
}

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = udp 25565;
}
service:s2 = {

 overlaps = service:s1;

 user = host:h1;
 permit src = user;
        dst = network:n1;
        prt = udp 25565;
}
service:s3 = {

 overlaps = service:s1, service:s2;

 user = host:h1;
 permit src = user;
        dst = network:n1;
        prt = udp 25565,
              tcp 80,
              ;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1"
    }
}
=OUTPUT=
@@ service
-service:s1 = {
- user = network:n2;
- permit src = user;
-        dst = network:n1;
-        prt = udp 25565;
-}
 service:s2 = {
- overlaps = service:s1;
-
  user = host:h1;
  permit src = user;
         dst = network:n1;
         prt = udp 25565;
 }
+
 service:s3 = {
- overlaps = service:s1, service:s2;
+ overlaps = service:s2;
  user = host:h1;
  permit src = user;
=END=

############################################################
=TITLE=Delete unknown service
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1"
    }
}
=ERROR=
Error: Can't delete unknown toplevel node 'service:s1'
=END=

############################################################
=TITLE=Add to attribute 'overlaps'
=INPUT=
--topology
network:n1 = {
 ip = 10.1.1.0/24;
 host:h3 = { ip = 10.1.1.3; }
 host:h4 = { ip = 10.1.1.4; }
}

network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- rule/A
service:a = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
-- rule/B
service:b = {
 overlaps = service:a;
 user = host:h3;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
--rule/C
service:c = {
 user = host:h3;
 permit src = user;
        dst = network:n2;
        prt = tcp 90;
}
=JOB=
{
   "method": "multi_job",
   "params": {
       "jobs": [
       {
           "method" : "set",
           "params": {
               "path": "service:c,rules,1,prt",
               "value": "tcp"
           }
       },
       {
           "method" : "add",
           "params": {
               "path": "service:b,overlaps",
               "value": "service:c"
           }
       }]
   }
}
=OUTPUT=
@@ rule/B
 service:b = {
- overlaps = service:a;
+
+ overlaps = service:a,
+            service:c,
+            ;
+
  user = host:h3;
  permit src = user;
         dst = network:n2;
@@ rule/C
  user = host:h3;
  permit src = user;
         dst = network:n2;
-        prt = tcp 90;
+        prt = tcp;
 }
=END=

############################################################
=TITLE=Add to user
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
 host:h6 = { ip = 10.1.1.6; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = host:h5;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,user",
        "value": ["host:h4", "host:h6"]
    }
}
=OUTPUT=
@@ service
 service:s1 = {
- user = host:h5;
+ user = host:h4,
+        host:h5,
+        host:h6,
+        ;
  permit src = user;
         dst = network:n2;
         prt = tcp 80;
=END=

############################################################
=TITLE=Add to user in unknown service
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,user",
        "value": "host:h4"
    }
}
=ERROR=
Error: Can't modify unknown toplevel object 'service:s1'
=END=

############################################################
=TITLE=Add invalid element to user
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,user",
        "value": "h4"
    }
}
=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->h4"
=END=

############################################################
=TITLE=Remove unknown element from user
=INPUT=
--all
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,user",
        "value": "host:[network:n1, network:n2]"
    }
}
=ERROR=
Error: Can't find element 'host:[network:n1,network:n2]'
=END=

############################################################
=TITLE=Remove from user
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = host:[network:n1],
        interface:r1.n2,
        ;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,user",
        "value": "host:[ network:n1 ]"
    }
}
=OUTPUT=
@@ service
 service:s1 = {
- user = host:[network:n1],
-        interface:r1.n2,
-        ;
+ user = interface:r1.n2;
  permit src = user;
         dst = network:n2;
         prt = tcp 80;
=END=

############################################################
=TITLE=Replace user
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = host:h5;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "set",
                "params": {
                    "path": "service:s1,user",
                    "value": "host:h4"
                }
            }
        ]
    }
}
=OUTPUT=
@@ service
 service:s1 = {
- user = host:h5;
+ user = host:h4;
  permit src = user;
         dst = network:n2;
         prt = tcp 80;
=END=

############################################################
=TITLE=Replace in user with multi_job
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = host:h5;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "service:s1,user",
                    "value": "host:h4"
                }
            },
            {
                "method": "delete",
                "params": {
                    "path": "service:s1,user",
                    "value": "host:h5"
                }
            }
        ]
    }
}
=OUTPUT=
@@ service
 service:s1 = {
- user = host:h5;
+ user = host:h4;
  permit src = user;
         dst = network:n2;
         prt = tcp 80;
=END=

############################################################
=TITLE=Remove from unknown rule
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,0,dst",
        "value": "network:n2"
    }
}
=ERROR=
Error: Invalid rule num 0; first rule has number 1
=END=

############################################################
=TITLE=Remove last remaining element of rule
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,1,dst",
        "value": "network:n2"
    }
}
=WARNING=
Warning: dst of rule in service:s1 is empty
=OUTPUT=
@@ INPUT
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 }
+
 service:s1 = {
  user = network:n1;
  permit src = user;
-        dst = network:n2;
+        dst = ;
         prt = tcp 80;
 }
=END=

############################################################
=TITLE=Remove invalid element in src of rule
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,1,src",
        "value": "service:s2"
    }
}
=ERROR=
Error: Unknown element type at line 1 of command line, near "--HERE-->service:s2"
=END=

############################################################
=TITLE=Remove unknown server in dst of rule
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,1,dst",
        "value": "network:n1"
    }
}
=ERROR=
Error: Can't find element 'network:n1'
=END=

############################################################
=TITLE=Remove unknown protocol in rule
=INPUT=
--all
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,1,prt",
        "value": "udp 80"
    }
}
=ERROR=
Error: Can't find value 'udp 80'
=END=

############################################################
=TITLE=Remove protocols in rule
=INPUT=
--topo
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
--service
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80,
              tcp 443,
              tcp 9300 - 9302,
              udp 161-162,
              udp 427,
              icmp 3/13,
              ;
}
=JOB=
{
  "method": "delete",
  "params": {
    "value": [
        "icmp 3/13",
        "tcp 443",
        "tcp 9300-9302",
        "udp 161 - 162",
        "udp 427" ],
    "path": "service:s1,rules,1,prt"
  }
}
=OUTPUT=
@@ service
  user = network:n1;
  permit src = user;
         dst = network:n2;
-        prt = tcp 80,
-              tcp 443,
-              tcp 9300 - 9302,
-              udp 161-162,
-              udp 427,
-              icmp 3/13,
-              ;
+        prt = tcp 80;
 }
=END=

############################################################
=TITLE=Change rules
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h3 = { ip = 10.1.1.3; }
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 log:a = errors;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = host:h3;
        prt = tcp 80;
 permit src = user;
        dst = host:h4,
              host:h5,
              ;
        prt = tcp 85- 90, tcp 91;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules,1,prt",
                    "value": "udp 80"
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules,1,dst",
                    "value": "host:h4"
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules,1,log",
                    "value": "a"
                }
            },
            {
                "method": "delete",
                "params": {
                    "path": "service:s1,rules,2,prt",
                    "value": "tcp 85 - 90"
                }
            },
            {
                "method": "delete",
                "params": {
                    "path": "service:s1,rules,2,dst",
                    "value": "host:h4"
                }
            }
        ]
    }
}
=OUTPUT=
@@ service
 service:s1 = {
  user = network:n2;
  permit src = user;
-        dst = host:h3;
-        prt = tcp 80;
- permit src = user;
-        dst = host:h4,
-              host:h5,
+        dst = host:h3,
+              host:h4,
+              ;
+        prt = tcp 80,
+              udp 80,
               ;
-        prt = tcp 85- 90, tcp 91;
+        log = a;
+ permit src = user;
+        dst = host:h5;
+        prt = tcp 91;
 }
=END=

############################################################
=TITLE=Modify attribute log of rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 log:a = errors;
 log:b = debugging;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
        log = a;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "service:s1,rules,1,log",
        "value": "b"
    }
}
=OUTPUT=
@@ topology
  permit src = user;
         dst = network:n2;
         prt = tcp 80;
-        log = a;
+        log = b;
 }
=END=

############################################################
=TITLE=Change unknown attribute of rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules,1,foo",
        "value": "bar"
    }
}
=ERROR=
Error: Invalid attribute in rule: 'foo'
=END=

############################################################
=TITLE=Change unknown rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules,9,prt",
        "value": "tcp 90"
    }
}
=ERROR=
Error: rule num 9 is larger than number of rules: 1
=END=

############################################################
=TITLE=Check rule count when adding rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules,1/2,prt",
        "value": "tcp 90"
    }
}
=ERROR=
Error: rule count 2 doesn't match, having 1 rules
=END=

############################################################
=TITLE=Check rule count when deleting rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,1/2"
    }
}
=ERROR=
Error: rule count 2 doesn't match, having 1 rules
=END=

############################################################
=TITLE=Rule count value 0
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules,1/0,prt",
        "value": "tcp 90"
    }
}
=ERROR=
Error: rule count 0 doesn't match, having 1 rules
=END=

############################################################
=TITLE=Change nothing in rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules,1,dst",
        "value": []
    }
}
=OUTPUT=NONE

############################################################
=TITLE=Add and delete permit rules
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h3 = { ip = 10.1.1.3; }
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = host:h3;
        prt = tcp 80;
 permit src = user;
        dst = host:h4;
        prt = tcp 90;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules",
                    "value": {
                        "action": "permit",
                        "src": "user",
                        "dst": ["host:h5", "interface:r1.n2"],
                        "prt": ["udp 123", "icmp"]
                    }
                }
            },
            {
                "method": "delete",
                "params": {
                    "path": "service:s1,rules,2"
                }
            }
        ]
    }
}
=OUTPUT=
@@ service
         dst = host:h3;
         prt = tcp 80;
  permit src = user;
-        dst = host:h4;
-        prt = tcp 90;
+        dst = interface:r1.n2,
+              host:h5,
+              ;
+        prt = icmp,
+              udp 123,
+              ;
 }
=END=

############################################################
=TITLE=Add deny rule in front
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24;
 host:h3 = { ip = 10.1.1.3; }
 host:h4 = { ip = 10.1.1.4; }
 host:h5 = { ip = 10.1.1.5; }
}
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n2;
 deny   src = user;
        dst = network:n1;
        prt = tcp 22;
 permit src = user;
        dst = host:h3;
        prt = tcp;
 permit src = user;
        dst = host:h4;
        prt = tcp 90;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1,rules",
        "value": {
            "action": "deny",
            "src": "host:h5",
            "dst": "user",
            "prt": "udp, icmp 4"
        }
    }
}
=OUTPUT=
@@ service
  deny   src = user;
         dst = network:n1;
         prt = tcp 22;
+ deny   src = host:h5;
+        dst = user;
+        prt = udp, icmp 4;
  permit src = user;
         dst = host:h3;
         prt = tcp;
=END=

############################################################
=TITLE=Add rule with invalid action
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 22;
}
=JOB=
{
 "method": "add",
 "params": {
   "path": "service:s1,rules",
   "value": {
    "action": "allow",
    "src": "network:n1",
    "dst": "user",
    "prt": "tcp 80"
   }
 }
}

=ERROR=
Error: Expected 'permit' or 'deny' in 'action'
=END=

############################################################
=TITLE=Add rule with invalid src
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 22;
}
=JOB=
{
 "method": "add",
 "params": {
   "path": "service:s1,rules",
   "value": {
    "action": "permit",
    "src": "n1",
    "dst": "user",
    "prt": "tcp 80"
   }
 }
}

=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->n1"
=END=

############################################################
=TITLE=Add rule with invalid dst
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
-- service
service:s1 = {
 user = network:n2;
 permit src = user;
        dst = network:n1;
        prt = tcp 22;
}
=JOB=
{
 "method": "add",
 "params": {
   "path": "service:s1,rules",
   "value": {
    "action": "permit",
    "src": "user",
    "dst": "invalid",
    "prt": "tcp 80"
   }
 }
}

=ERROR=
Error: Typed name expected at line 1 of command line, near "--HERE-->invalid"
=END=

############################################################
=TITLE=Can't replace rules
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "service:s1,rules"
    }
}

=ERROR=
Error: Rule number must be given for 'set'
=END=

############################################################
=TITLE=Can't replace single rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "service:s1,rules,1"
    }
}

=ERROR=
Error: Attribute of rule must be given for 'set'
=END=

############################################################
=TITLE=Missing value to modify in rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = {
 ip = 10.1.2.0/24;
}
router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "service:s1,rules,1,dst"
    }
}

=ERROR=
Error: Missing value to modify in 'dst' of rule
=END=

############################################################
=TITLE=Replace dst of rule
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }

network:n2 = {
 ip = 10.1.2.0/24;
 host:h2a = { ip = 10.1.2.10; }
 host:h2b = { ip = 10.1.2.11; }
}

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "service:s1,rules,1,dst",
        "value": ["host:h2a", "host:h2b"]
    }
}

=OUTPUT=
@@ topology
 service:s1 = {
  user = network:n1;
  permit src = user;
-        dst = network:n2;
+        dst = host:h2a,
+              host:h2b,
+              ;
         prt = tcp 80;
 }
=END=

############################################################
=TITLE=Invalid relative path
=TODO=
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "create_toplevel",
    "params": {
        "definition": "network:n2 = { ip = 10.1.2.0/24; }",
        "file": "../passwd"
    }
}
=ERROR=
Error: Invalid filename ../passwd
=END=

############################################################
=TITLE=Can't create API file
=INPUT=
-- API/topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n2",
        "value": { "ip": "10.1.2.0/24" }
    }
}
=ERROR=
panic: Can't open API: is a directory
=END=

############################################################
=TITLE=Unexpected content after definition
=TODO=
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n2",
        "value": "{ ip = 10.1.2.0/24; } host:h2"
    }
}
=ERROR=
Error: Unexpected content after definition at line 1 of command line, near "10.1.2.0/24; } --HERE-->host:h2"
=END=

############################################################
=TITLE=Add pathrestriction
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "pathrestriction:p",
        "value": ["interface:r1.n1", "interface:r1.n2"]
    }
}
=OUTPUT=
@@ API
+pathrestriction:p =
+ interface:r1.n1,
+ interface:r1.n2,
+;
=END=

############################################################
=TITLE=Delete pathrestriction
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:r2 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.2; hardware = n1; }
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
}
pathrestriction:p =
 interface:r1.n1,
 interface:r1.n2,
;
=JOB=
{
    "method": "delete",
    "params": {
        "path": "pathrestriction:p"
    }
}
=OUTPUT=
@@ topology
  interface:n1 = { ip = 10.1.1.2; hardware = n1; }
  interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 }
-pathrestriction:p =
- interface:r1.n1,
- interface:r1.n2,
-;
=END=

############################################################
=TITLE=Add VIP Interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

owner:a = {
 admins = a@example.com;
}

router:r1 = {
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:VIP_interface",
        "value": {
            "ip": "10.1.3.3",
            "owner": "a",
            "vip": null
        }
    }
}
=OUTPUT=
@@ INPUT
 router:r1 = {
  model = ASA;
- interface:n1 = { ip = 10.1.1.1; hardware = n1; }
- interface:n2 = { ip = 10.1.2.1; hardware = n2; }
+ interface:n1            = { ip = 10.1.1.1; hardware = n1; }
+ interface:n2            = { ip = 10.1.2.1; hardware = n2; }
+ interface:VIP_interface = { ip = 10.1.3.3; owner = a; vip; }
 }
=END=

############################################################
=TITLE=Add VIP Interface without owner
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:VIP_interface",
        "value": {
            "ip": "10.1.3.3",
            "vip": null
        }
    }
}
=OUTPUT=
@@ INPUT
 router:r1 = {
  model = ASA;
- interface:n1 = { ip = 10.1.1.1; hardware = n1; }
- interface:n2 = { ip = 10.1.2.1; hardware = n2; }
+ interface:n1            = { ip = 10.1.1.1; hardware = n1; }
+ interface:n2            = { ip = 10.1.2.1; hardware = n2; }
+ interface:VIP_interface = { ip = 10.1.3.3; vip; }
 }
=END=

############################################################
=TITLE=Add interface with network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

owner:a = {
 admins = a@example.com;
}

router:r1 = {
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "router:r1,interface:n3",
                    "value": {
                        "ip": "10.1.3.1",
                        "owner": "a"
                    }
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "network:n3",
                    "value": {
                        "ip": "10.1.3.0/24"
                    }
                }
            }
        ]
    }
}
=OUTPUT=
@@ INPUT
  model = ASA;
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
  interface:n2 = { ip = 10.1.2.1; hardware = n2; }
+ interface:n3 = { ip = 10.1.3.1; owner = a; }
 }
+
+network:n3 = { ip = 10.1.3.0/24; }
=END=

############################################################
=TITLE=Add Interface to non-existing Router
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

owner:a = {
 admins = a@example.com;
}

router:r1 = {
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r2,interface:VIP_interface",
        "value": {
            "ip": "10.1.3.3",
            "owner": "a",
            "vip": true
        }
    }
}
=ERROR=
Error: Can't modify unknown toplevel object 'router:r2'
=END=

############################################################
=TITLE=Add Interface without name
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:",
        "value": {
           "ip": "10.1.3.3",
           "vip": null
        }
    }
}
=ERROR=
Error: Typed name expected at line 5 of INPUT, near " --HERE-->interface:"
Aborted
=OUTPUT=
@@ INPUT
 router:r1 = {
  interface:n1 = { ip = 10.1.1.1; hardware = n1; }
+ interface:   = { ip = 10.1.3.3; vip; }
 }
=END=

############################################################
=TITLE=Add Interface without IP address
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

owner:a = {
 admins = a@example.com;
}

router:r1 = {
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:VIP_interface",
        "value": {
            "owner": "a",
            "vip": null
        }
    }
}
=ERROR=
Error: 'vip' interface:r1.VIP_interface must have IP address
=OUTPUT=
@@ INPUT
 router:r1 = {
  model = ASA;
- interface:n1 = { ip = 10.1.1.1; hardware = n1; }
+ interface:n1            = { ip = 10.1.1.1; hardware = n1; }
+ interface:VIP_interface = { owner = a; vip; }
 }
=END=

############################################################