
############################################################
=TITLE=Invalid value for new network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n2",
        "value": []
    }
}
=ERROR=
Error: Expecting JSON object when reading 'network:n2' but got: []interface {}
=END=

############################################################
=TITLE=Invalid value for description
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n2",
        "value": { "description" : {} }
    }
}
=ERROR=
Error: Expecting string as description
=END=

############################################################
=TITLE=Invalid value in list
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:o1",
        "value": { "admins" : [{"x": "y"}] }
    }
}
=ERROR=
Error: Unexpected type in JSON array: map[string]interface {}
=END=

############################################################
=TITLE=Invalid value for new service
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": "body"
    }
}
=ERROR=
Error: Expecting JSON object when reading 'service:s1' but got: string
=END=

############################################################
=TITLE=Invalid value for rules of new service
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": "network:n1",
            "rules": "bad string"
        }
    }
}
=ERROR=
Error: Expecting JSON array after 'rules' but got: string
=END=

############################################################
=TITLE=Missing attributes in rule of new service
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": "network:n1",
            "rules": [{}]
        }
    }
}
=ERROR=
Error: Rule needs keys "action", "src", "dst", "prt" and optional "log"
=END=

############################################################
=TITLE=invalid attribute in rule of new service
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:s1",
        "value": {
            "user": "network:n1",
            "rules": [{
                "action": "permit",
                "src": "network:n2",
                "dst": "user",
                "x": "y"
            }]
        }
    }
}
=ERROR=
Error: Unexpected key 'x' in rule
=END=

############################################################
=TITLE=Invalid rule number
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
 permit src = network:n2;
        dst = user;
        prt = tcp 514;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,n"
    }
}
=ERROR=
Error: Number expected in 'n'
=END=

############################################################
=TITLE=Invalid rule count
=INPUT=
service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
 permit src = network:n2;
        dst = user;
        prt = tcp 514;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,1/n"
    }
}
=ERROR=
Error: Number expected after '/' in '1/n'
=END=

############################################################
=TITLE=Add new attribute
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = o; }

owner:o = {
 admins = a@example.com;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:o,watchers",
        "value": "w@example.com"
    }
}
=OUTPUT=
@@ INPUT
 owner:o = {
  admins = a@example.com;
+ watchers = w@example.com;
 }
=END=

############################################################
=TITLE=Add new attribute with multiple values as string
# Single value only looks like two values.
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = o; }

owner:o = {
 admins = a@example.com;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:o,watchers",
        "value": "w@example.com,   v@example.com "
    }
}
=OUTPUT=
@@ INPUT
 owner:o = {
  admins = a@example.com;
+ watchers = w@example.com,   v@example.com ;
 }
=END=

############################################################
=TITLE=Add new attribute with multiple values as array
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = o; }

owner:o = {
 admins = a@example.com;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:o,watchers",
        "value": ["w@example.com", "v@example.com"]
    }
}
=OUTPUT=
@@ INPUT
 owner:o = {
  admins = a@example.com;
+ watchers = v@example.com,
+            w@example.com,
+            ;
 }
=END=

############################################################
=TITLE=Add attribute value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = o; }

owner:o = {
 admins = a@example.com;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:o,admins",
        "value": "b@example.com"
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; owner = o; }
 owner:o = {
- admins = a@example.com;
+ admins = a@example.com,
+          b@example.com,
+          ;
 }
=END=

############################################################
=TITLE=Delete attribute
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = o; }

owner:o = {
 admins = a@example.com;
 watchers = w@example.com;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "owner:o,watchers"
    }
}
=OUTPUT=
@@ INPUT
 owner:o = {
  admins = a@example.com;
- watchers = w@example.com;
 }
=END=

############################################################
=TITLE=Delete attribute value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; owner = o; }

owner:o = {
 admins = a@example.com,
          b@example.com,
          c@example.com,
          ;
 watchers = w@example.com;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "owner:o,admins",
        "value": "b@example.com"
    }
}
=OUTPUT=
@@ INPUT
 owner:o = {
  admins = a@example.com,
-          b@example.com,
           c@example.com,
           ;
  watchers = w@example.com;
=END=

############################################################
=TITLE=Add host with invalid string value
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,host:h1",
        "value": "10.1.1.10"
    }
}
=ERROR=
Error: Structured value expected in 'host:h1'
Error: host:h1 needs exactly one of attributes 'ip' and 'range'
=OUTPUT=
@@ INPUT
 network:n1 = {
  ip = 10.1.1.0/24;
+ host:h1 = 10.1.1.10;
 }
=END=

############################################################
=TITLE=Descend into string value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,ip,mask",
        "value": "25"
    }
}
=ERROR=
Error: Can't descend into value of 'ip'
=END=

############################################################
=TITLE=Missing replacement value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,ip"
    }
}
=ERROR=
Error: Missing value to set at 'ip'
=END=

############################################################
=TITLE=Add complex value to list value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,ip",
        "value": { "foo": "bar" }
    }
}
=ERROR=
Error: Expecting value list, not complex value
=END=

############################################################
=TITLE=Add number to list value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,ip",
        "value": 123456
    }
}
=ERROR=
Error: Unexpected type in JSON value: float64
=END=

############################################################
=TITLE=Delete unknown attribute
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "delete",
    "params": {
        "path": "network:n1,range"
    }
}
=ERROR=
Error: Can't delete unknown attribute 'range'
=END=

############################################################
=TITLE=Delete host by value
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "network:n1,host:h1",
        "value": "host:h2"
    }
}
=ERROR=
Error: Can't delete from complex value of 'host:h1'
=END=

############################################################
=TITLE=Replace host with invalid string value
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.10; }
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,host:h1",
        "value": "10.1.1.99"
    }
}
=ERROR=
Error: Structured value expected in 'host:h1'
Error: host:h1 needs exactly one of attributes 'ip' and 'range'
=OUTPUT=
@@ INPUT
 network:n1 = {
  ip = 10.1.1.0/24;
- host:h1 = { ip = 10.1.1.10; }
+ host:h1 = 10.1.1.99;
 }
=END=

############################################################
=TITLE=Add host
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,host:h10",
        "value": { "ip": "10.1.1.10" }
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = {
  ip = 10.1.1.0/24;
+ host:h10 = { ip = 10.1.1.10; }
 }
=END=

############################################################
=TITLE=Delete host
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "network:n1,host:h11"
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = {
  ip = 10.1.1.0/24;
  host:h10 = { ip = 10.1.1.10; }
- host:h11 = { ip = 10.1.1.11; }
  host:h12 = { ip = 10.1.1.12; }
 }
=END=

############################################################
=TITLE=Add owner to host
=INPUT=
owner:o1 = {
 admins = o1@example.com;
}

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
        "path": "network:n1,host:h11,owner",
        "value": "o1"
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = {
  ip = 10.1.1.0/24;
  host:h10 = { ip = 10.1.1.10; }
- host:h11 = { ip = 10.1.1.11; }
+ host:h11 = { ip = 10.1.1.11; owner = o1; }
  host:h12 = { ip = 10.1.1.12; }
 }
=END=

############################################################
=TITLE=Add NAT to host
=INPUT=
network:n1 = {
 ip = 10.1.1.0/24;
 nat:h = { ip = 192.168.1.0/29; dynamic; }
 host:h10 = { ip = 10.1.1.10; }
 host:h11 = { ip = 10.1.1.11; }
 host:h12 = { ip = 10.1.1.12; }
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,host:h11,nat:h",
        "value": { "ip": "192.168.1.3" }
    }
}
=WARNING=
Warning: nat:h is defined, but not bound to any interface
=OUTPUT=
@@ INPUT
  ip = 10.1.1.0/24;
  nat:h = { ip = 192.168.1.0/29; dynamic; }
  host:h10 = { ip = 10.1.1.10; }
- host:h11 = { ip = 10.1.1.11; }
+ host:h11 = {
+  ip = 10.1.1.11;
+  nat:h = { ip = 192.168.1.3; }
+ }
  host:h12 = { ip = 10.1.1.12; }
 }
=END=

############################################################
=TITLE=Add interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:l",
        "value": { "ip": "10.9.9.9", "loopback" : null }
    }
}
=OUTPUT=
@@ INPUT
 router:r1 = {
  interface:n1;
+ interface:l = { ip = 10.9.9.9; loopback; }
 }
=END=

############################################################
=TITLE=Add IP & VIP to interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:n1",
        "value": {
          "ip": "10.1.1.2",
          "virtual" : { "ip": "10.1.1.1", "type": "VRRP" }
        }
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; }
 router:r1 = {
- interface:n1;
+ interface:n1 = {
+  ip = 10.1.1.2;
+  virtual = { ip = 10.1.1.1; type = VRRP; }
+ }
 }
=END=

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
=TITLE=Add rule as string
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r = {
 model = ASA;
 managed;
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
        "path": "service:s1,rules",
        "value": "permit src=network:n2; dst=user; prt=tcp 514;"
    }
}
=ERROR=
Error: Unexpected type when reading rule: string
=END=

############################################################
=TITLE=Add rule as JSON
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r = {
 model = ASA;
 managed;
 log:high;
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
        "path": "service:s1,rules",
        "value": {
            "log": "high",
            "action": "permit",
            "src": "network:n2",
            "dst": "user",
            "prt": "tcp 514"
        }
    }
}
=OUTPUT=
@@ INPUT
  permit src = user;
         dst = network:n2;
         prt = tcp 80;
+ permit src = network:n2;
+        dst = user;
+        prt = tcp 514;
+        log = high;
 }
=END=

############################################################
=TITLE=Remove rule
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
 permit src = network:n2;
        dst = user;
        prt = tcp 514;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "service:s1,rules,1/2"
    }
}
=OUTPUT=
@@ INPUT
 service:s1 = {
  user = network:n1;
- permit src = user;
-        dst = network:n2;
-        prt = tcp 80;
  permit src = network:n2;
         dst = user;
         prt = tcp 514;
=END=

############################################################
=TITLE=Add to src, dst and prt
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:r = {
 model = ASA;
 managed;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
 interface:n3 = { ip = 10.1.3.1; hardware = n3; }
}

service:s1 = {
 user = network:n1;
 permit src = user;
        dst = network:n2;
        prt = tcp 80;
 permit src = network:n2;
        dst = user;
        prt = tcp 514;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules,1,dst",
                    "value": "network:n3"
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules,2,src",
                    "value": "network:n3"
                }
            },
            {
                "method": "add",
                "params": {
                    "path": "service:s1,rules,1,prt",
                    "value": "tcp 90"
                }
            }
        ]
    }
}
=OUTPUT=
@@ INPUT
 service:s1 = {
  user = network:n1;
  permit src = user;
-        dst = network:n2;
-        prt = tcp 80;
- permit src = network:n2;
+        dst = network:n2,
+              network:n3,
+              ;
+        prt = tcp 80,
+              tcp 90,
+              ;
+ permit src = network:n2,
+              network:n3,
+              ;
         dst = user;
         prt = tcp 514;
 }
=END=

############################################################
=TITLE=Create owner
=INPUT=
-- topo
network:n1 = { ip = 10.1.1.0/24; owner = o; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "owner:o",
        "value": {
            "admins": "a@example.com", "watchers": "w@example.com"
        }
    }
}
=OUTPUT=
@@ owner
+owner:o = {
+ admins = a@example.com;
+ watchers = w@example.com;
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
            "rules" : [
            {
                "action": "permit",
                "src": "user",
                "dst": ["host:[network:n1] &! host:h4", "interface:r1.n1"],
                "prt": ["udp", "tcp"]
            },
            {
                "action": "permit",
                "src": ["user"],
                "dst": ["host:h4"],
                "prt": ["tcp 90", "tcp 80-85"]
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
                "prt": ["udp", "icmp 4"]
            }]
        }
}}
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
+        prt = tcp 80-85,
+              tcp 90,
+              ;
+ deny   src = user;
+        dst = network:n1;
+        prt = tcp 22;
+ deny   src = host:h5;
+        dst = user;
+        prt = icmp 4,
+              udp,
+              ;
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
            "description": "This one\n",
            "user": ["host:[network:n1] &! host:h4", "interface:r1.n1"],
            "rules": [{
                "action": "permit",
                "src": "user",
                "dst": "network:n2",
                "prt": "tcp 80"
            }]
        }
}}
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
=TITLE=Add router and network
=INPUT=
-- topo
network:n1 = { ip = 10.1.1.0/24; }
-- owner
owner:o1 = {
 admins = o1@example.com;
}
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [{
            "method": "add",
            "params": {
                "path": "router:r1",
                "value": {
                    "model": "ASA",
                    "managed": null,
                    "interface:n1": { "ip": "10.1.1.1", "hardware": "n1" },
                    "interface:n2": { "ip": "10.1.2.1", "hardware": "n2" }

                }
            }
        },
        {
            "method": "add",
            "params": {
                "path": "network:n2",
                "value": {
                    "ip": "10.1.2.0/24",
                    "owner": "o1"
                }
            }
        }]
    }
}
=OUTPUT=
@@ API
+router:r1 = {
+ managed;
+ model = ASA;
+ interface:n1 = { hardware = n1; ip = 10.1.1.1; }
+ interface:n2 = { hardware = n2; ip = 10.1.2.1; }
+}
+
+network:n2 = { ip = 10.1.2.0/24; owner = o1; }
=END=

############################################################
=TITLE=Delete router and network referenced in subnet_of
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { hardware = n1; ip = 10.1.1.1; }
 interface:n2 = { hardware = n2; ip = 10.1.1.129; }
}

network:n2 = { ip = 10.1.1.128/25; subnet_of = network:n1; }

=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [{
            "method": "delete",
            "params": {
                "path": "router:r1"
            }
        },
        {
            "method": "delete",
            "params": {
                "path": "network:n1"
            }
        }]
    }
}
=OUTPUT=
@@ INPUT
-network:n1 = { ip = 10.1.1.0/24; }
-
-router:r1 = {
- managed;
- model = ASA;
- interface:n1 = { hardware = n1; ip = 10.1.1.1; }
- interface:n2 = { hardware = n2; ip = 10.1.1.129; }
-}
-
-network:n2 = { ip = 10.1.1.128/25; subnet_of = network:n1; }
-
+network:n2 = { ip = 10.1.1.128/25; }
=END=

############################################################
=TITLE=Set owner of network
=INPUT=
-- topology
owner:o1 = {
 admins = a1@example.com;
}

network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,owner",
        "value": "o1"
    }
}
=OUTPUT=
@@ topology
  admins = a1@example.com;
 }
-network:n1 = { ip = 10.1.1.0/24; }
+network:n1 = { ip = 10.1.1.0/24; owner = o1; }
=END=

############################################################
=TITLE=Set description of network
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,description",
        "value": "Network in Europe"
    }
}
=OUTPUT=
@@ INPUT
-network:n1 = { ip = 10.1.1.0/24; }
+network:n1 = {
+ description = Network in Europe
+
+ ip = 10.1.1.0/24;
+}
=END=

############################################################
=TITLE=Change description of network
=INPUT=
network:n1 = {
 description = Network in Europe

 ip = 10.1.1.0/24;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,description",
        "value": "In Africa"
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = {
- description = Network in Europe
+ description = In Africa
  ip = 10.1.1.0/24;
 }
=END=

############################################################
=TITLE=Change description of network
=INPUT=
network:n1 = {
 description = Network in Europe

 ip = 10.1.1.0/24;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,description",
        "value": ["In Africa", "In Asia"]
    }
}
=ERROR=
Error: Expecting string as description
=END=

############################################################
=TITLE=Add to existing description of network
=INPUT=
network:n1 = {
 description = Network in Europe

 ip = 10.1.1.0/24;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "network:n1,description",
        "value": "and Africa"
    }
}
=ERROR=
Error: Can't add to description
=END=

############################################################
=TITLE=Descend into description
=INPUT=
network:n1 = {
 description = Network in Europe

 ip = 10.1.1.0/24;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,description,Europe",
        "value": "Africa"
    }
}
=ERROR=
Error: Can't descend into value of 'description'
=END=

############################################################
=TITLE=Remove description of network
=INPUT=
network:n1 = {description = Network in Europe
 ip = 10.1.1.0/24; }
=JOB=
{
    "method": "delete",
    "params": {
        "path": "network:n1,description"
    }
}
=OUTPUT=
@@ INPUT
-network:n1 = {description = Network in Europe
- ip = 10.1.1.0/24; }
+network:n1 = { ip = 10.1.1.0/24; }
=END=

############################################################
=TITLE=Invalid attribute value adding owner to network
=INPUT=
owner:o1 = {
 admins = a1@example.com;
}

network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "set",
    "params": {
        "path": "network:n1,owner",
        "value": ["o1", ["o2", "o3"]]
    }
}
=ERROR=
Error: Unexpected type in JSON array: []interface {}
=END=

############################################################
=TITLE=Set attribute of router
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 managed;
 model = ASA;
 interface:n1 = { hardware = n1; ip = 10.1.1.1; }
 interface:n2 = { hardware = n2; ip = 10.1.2.1; }
}

network:n2 = { ip = 10.1.2.0/24; }
=JOB=
{

    "method": "set",
    "params": {
        "path": "router:r1,owner",
        "value": "o1"
    }
}
=WARNING=
Warning: Ignoring undefined owner:o1 of router:r1
=OUTPUT=
@@ INPUT
 router:r1 = {
  managed;
  model = ASA;
+ owner = o1;
  interface:n1 = { hardware = n1; ip = 10.1.1.1; }
  interface:n2 = { hardware = n2; ip = 10.1.2.1; }
 }
=END=

############################################################
=TITLE=Change border of area
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

area:a2 = {
 border = interface:asa1.n2;
}
=JOB=
{

    "method": "add",
    "params": {
        "path": "area:a2,border",
        "value": "interface:asa2.n2"
    }
}
=OUTPUT=
@@ INPUT
 }
 area:a2 = {
- border = interface:asa1.n2;
+ border = interface:asa1.n2,
+          interface:asa2.n2,
+          ;
 }
=END=

############################################################
=TITLE=Change inclusive_border of area
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

area:a2 = {
 inclusive_border = interface:asa1.n1, interface:asa2.n3;
}
=JOB=
{

    "method": "delete",
    "params": {
        "path": "area:a2,inclusive_border",
        "value": "interface:asa2.n3"
    }
}
=OUTPUT=
@@ INPUT
 }
 area:a2 = {
- inclusive_border = interface:asa1.n1, interface:asa2.n3;
+ inclusive_border = interface:asa1.n1;
 }
=END=

############################################################
=TITLE=Change attribute of area
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
network:n3 = { ip = 10.1.3.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

router:asa2 = {
 managed;
 model = ASA;
 interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 interface:n3 = { ip = 10.1.3.2; hardware = n3; }
}

area:a2 = {
 inclusive_border = interface:asa1.n1;
}
=JOB=
{

    "method": "set",
    "params": {
        "path": "area:a2,router_attributes",
        "value": { "owner": "o1" }
    }
}
=WARNING=
Warning: Ignoring undefined owner:o1 of router_attributes of area:a2
=OUTPUT=
@@ INPUT
 }
 area:a2 = {
+ router_attributes = {
+  owner = o1;
+ }
  inclusive_border = interface:asa1.n1;
 }
=END=