
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
