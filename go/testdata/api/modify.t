
############################################################
=TITLE=Option '-h'
=INPUT=NONE
=PARAMS=-h
=ERROR=
Usage: PROGRAM [options] FILE|DIR JOB
  -q, --quiet   Don't show changed files
=END=

############################################################
=TITLE=No parameters
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] FILE|DIR JOB
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
=TITLE=Invalid netspoc data
=INPUT=
foo
=JOB=
{}
=ERROR=
Error: While reading netspoc files: Typed name expected at line 1 of INPUT, near "--HERE-->foo"
=END=

############################################################
=TITLE=API works regardless of invalid netspoc config
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
-- config
unknown = value;
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:b",
        "value": { "ip": "10.1.2.0/24" }
    }
}
=OUTPUT=
@@ API
+network:b = { ip = 10.1.2.0/24; }
=ERROR=
Error: Invalid line in config:
 - bad keyword 'unknown'
Aborted
=END=

############################################################
=TITLE=Invalid JSON in job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
=ERROR=
Error: In JSON input: unexpected end of JSON input
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
=TITLE=Missing job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
null
=ERROR=
Error: Missing "params" in JSON input
=END=

############################################################
=TITLE=Invalid empty job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{}
=ERROR=
Error: Missing "params" in JSON input
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
Error: Missing "params" in JSON input
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
=TITLE=Unknown method in job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{ "method": "foo", "params": {} }
=ERROR=
Error: Unknown method 'foo'
=END=

############################################################
=TITLE=Invalid params in job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{ "params": 42 }
=ERROR=
Error: In "params" of JSON input: json: cannot unmarshal number into Go value of type map[string]interface {}
=END=

############################################################
=TITLE=Invalid params with valid method
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": "foo"
}
=ERROR=
Error: In "params" of JSON input: json: cannot unmarshal string into Go value of type map[string]interface {}
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
=TITLE=Ignore invalid value in jobs of multi_job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=

{
    "method": "multi_job",
    "params": {
        "jobs": 42
    }
}
=OUTPUT=NONE

############################################################
=TITLE=Missing job in multi_job
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=

{
    "method": "multi_job",
    "params": {
        "jobs": [null]
    }
}
=ERROR=
Error: Missing "params" in JSON input
=END=

############################################################
=TITLE=Add host to known network
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4"
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
=TITLE=Add host to unknown network
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "n2",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4"
    }
}
=ERROR=
Error: Can't find 'network:n2'
=END=

############################################################
=TITLE=Add host with IP range
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "range",
        "ip": "10.1.1.16-10.1.1.31"
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4"
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4"
    }
}
=ERROR=
Error: Duplicate definition of host:name_10_1_1_4 in topology
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.1.0/24;
  host:name_10_1_1_4 = { ip = 10.1.1.4; }
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
 }
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4"
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
=TITLE=Add host, same IP unsorted
=INPUT=
-- topology
network:a = {
 ip = 10.1.1.0/24;
 host:name_10_1_1_5 = { ip = 10.1.1.5; }
 host:name_10_1_1_4 = { ip = 10.1.1.4; }
}
=JOB=
{
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4"
    }
}
=ERROR=
Error: Duplicate definition of host:name_10_1_1_4 in topology
=OUTPUT=
@@ topology
 network:a = {
  ip = 10.1.1.0/24;
- host:name_10_1_1_5 = { ip = 10.1.1.5; }
  host:name_10_1_1_4 = { ip = 10.1.1.4; }
+ host:name_10_1_1_4 = { ip = 10.1.1.4; }
+ host:name_10_1_1_5 = { ip = 10.1.1.5; }
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4"
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4",
        "owner": "DA_abc"
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4",
        "owner": "DA_abc"
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_3",
        "ip": "10.1.1.3"
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_3",
        "ip": "10.1.1.3"
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
    "method": "create_host",
    "params": {
        "network": "a",
        "name": "name_10_1_1_4",
        "ip": "10.1.1.4",
        "owner": "DA_abc"
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
  nat_out = b;
 }
 interface:b = {
  nat_out = a;
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
