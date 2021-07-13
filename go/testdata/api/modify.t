
############################################################
=TITLE=Invalid empty job
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{}
=ERROR=
Error: Unknown method ''
=END=

############################################################
=TITLE=Invalid job without params
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add_to_group"
}
=ERROR=
Error: Can't find group:
=END=

############################################################
=TITLE=Add to multi block group (1)
=VAR=input
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
${input}
=JOB=
{
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "host:h_10_1_2_7"
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
=INPUT=${input}
=JOB=
{
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "host:h_10_1_2_5"
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
=INPUT=${input}
=JOB=
{
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "host:h_10_1_1_5"
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
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "network:n2"
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
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "host:h_10_1_1_4"
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
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "interface:r1.[all] &! interface:r1.n1, host:h_10_1_1_4"
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
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "network:n2"
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
    "method": "add_to_group",
    "params": {
        "name": "g1",
        "object": "host:h4"
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
    "method": "create_owner",
    "params": {
        "name": "a",
        "admins": [ "a@example.com" ]
    }
}
=ERROR=
Error: Duplicate definition of owner:a in owner
=OUTPUT=
@@ owner
 owner:a = {
  admins = a@example.com;
 }
+
+owner:a = {
+ admins = a@example.com;
+}
=END=

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
    "method": "create_owner",
    "params": {
        "name": "a",
        "admins": [ "a@example.com" ],
        "ok_if_exists": 1
    }
}
=WARNING=NONE
=OUTPUT=NONE

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
    "method": "delete_owner",
    "params": {
        "name": "a"
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
    "method": "modify_owner",
    "params": {
        "name": "a",
        "admins": [ "b@example.com", "a@example.com" ],
        "watchers": [ "c@example.com", "d@example.com" ]
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
    "method": "modify_owner",
    "params": {
        "name": "a",
        "admins": [ "b@example.com" ],
        "watchers": [ "c@example.com" ]
    }
}
=OUTPUT=
@@ topology
 network:n1 = { ip = 10.1.1.0/24; owner = a; }
+
 owner:a = {
- watchers = b@example.com;
- admins   = a@example.com; }
+ watchers = c@example.com;
+ admins = b@example.com;
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
    "method": "modify_owner",
    "params": {
        "name": "a",
        "watchers": []
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
    "method": "modify_owner",
    "params": {
        "name": "a",
        "admins": [ "c@example.com" ]
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
    "method": "modify_owner",
    "params": {
        "name": "a",
        "admins": [ "c@example.com" ]
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

network:a = {
 ip = 10.1.0.0/21;
}

router:r = {
 interface:a;
 interface:d;
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
                "method": "create_owner",
                "params": {
                    "name": "a",
                    "watchers": [ "c@example.com", "d@example.com" ],
                    "admins": [ "b@example.com", "a@example.com" ]
                }
            },
            {
                "method": "create_host",
                "params": {
                    "network": "n1",
                    "name": "name_10_1_1_4",
                    "ip": "10.1.1.4",
                    "owner": "a"
                }
            }
        ]
    }
}
=OUTPUT=
@@ owner
+owner:a = {
+ admins = b@example.com,
+          a@example.com,
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
                "method": "create_owner",
                "params": {
                    "name": "a",
                    "admins": [ "b@example.com" ],
                    "ok_if_exists": 1
                }
            },
            {
                "method": "create_host",
                "params": {
                    "network": "n1",
                    "name": "name_10_1_1_4",
                    "ip": "10.1.1.4",
                    "owner": "a"
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
                "method": "create_host",
                "params": {
                    "network": "n1",
                    "name": "name_10_1_1_4",
                    "ip": "10.1.1.4"
                }
            },
            {
                "method": "create_host",
                "params": {
                    "network": "n2",
                    "name": "name_10_1_2_4",
                    "ip": "10.1.2.4"
                }
            }
        ]
    }
}
=ERROR=
Error: Can't find 'network:n2'
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
 } host:h2 = { ip = 10.1.1.2; owner = o1; }
}
-- owner
owner:o1 = { admins = a1@example.com; }
=JOB=
{
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "create_owner",
                "params": {
                    "name": "o2",
                    "admins": [ "a2@example.com" ]
                }
            },
            {
                "method": "delete_owner",
                "params": {
                    "name": "o1"
                }
            },
            {
                "method": "modify_host",
                "params": {
                    "name": "h1",
                    "owner": "o2"
                }
            },
            {
                "method": "modify_host",
                "params": {
                    "name": "h2",
                    "owner": "o2"
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
- } host:h2 = { ip = 10.1.1.2; owner = o1; }
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
                "method": "modify_host",
                "params": {
                    "name": "id:a2@example.com.n2",
                    "owner": "DA_TOKEN_o3"
                }
            },
            {
                "method": "create_owner",
                "params": {
                    "name": "DA_TOKEN_o3",
                    "admins": [ "a3@example.com" ]
                }
            },
            {
                "method": "delete_owner",
                "params": {
                    "name": "DA_TOKEN_o2"
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
    "method": "create_host",
    "params": {
        "network": "a exit; "
    }
}
=ERROR=
Error: Can't find 'network:a exit; '
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
    "method": "modify_owner",
    "params": {
        "admins": ["b example.com"],
        "name": "a"
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
    "method": "create_service",
    "params": {
        "name": "multi",
        "user": "network:n2",
        "rules": [
            {
                "action": "permit",
                "src": "user",
                "dst": "host:[network:n1] &! host:h4, interface:r1.n1",
                "prt": "udp, tcp"
            },
            {
                "action": "permit",
                "src": "user",
                "dst": "host:h4",
                "prt": "tcp 90,    tcp 80-85"
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
+        prt = tcp 80 - 85,
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
    "method": "create_service",
    "params": {
        "name": "complex",
        "description": "This one",
        "user": "host:[network:n1] &! host:h4, interface:r1.n1",
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
=TITLE=Add service, invalid action
=VAR=input
-- topology
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 managed;
 model = IOS;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}
=INPUT=
${input}
=JOB=
{
    "method": "create_service",
    "params": {
        "name": "s1",
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
=ERROR=
Error: Expected 'permit' or 'deny' at line 1 of command line, near "network:n1; --HERE-->allow"
=END=

############################################################
=TITLE=Add service, invalid user
=INPUT=${input}
=JOB=
{
    "method": "create_service",
    "params": {
        "name": "s1",
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
=ERROR=
Error: Typed name expected at line 1 of command line, near "src=--HERE-->_user_"
=END=

############################################################
=TITLE=Add service, invalid object type
=INPUT=${input}
=JOB=
{
    "method": "create_service",
    "params": {
        "name": "s1",
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
=ERROR=
Error: Unknown element type at line 1 of command line, near "dst=--HERE-->net:n2"
=END=

############################################################
=TITLE=Add service, invalid protocol
=INPUT=${input}
=JOB=
{ "method": "create_service",
  "params": {
      "name": "s1",
      "user": "network:n1",
      "rules": [ {
          "action": "permit",
          "src": "user",
          "dst": "network:n2",
          "prt": "udp6" }]
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
                "method": "create_service",
                "params": {
                    "name": "s4",
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
            },
            {
                "method": "create_service",
                "params": {
                    "name": "s2",
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
    "method": "create_toplevel",
    "params": {
        "definition": "service:t1 = {\n description = abc def # ghi\n disable_at = 2099-02-03;\n has_unenforceable;\n user = network:n1;\n permit src = user; dst = network:n1, network:n2; prt = tcp 80; log = high;\n}",
        "file": "T"
    }
}
=WARNING=
Warning: Referencing unknown 'high' in log of service:t1
=OUTPUT=
@@ T
+service:t1 = {
+ description = abc def
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
    "method": "delete_service",
    "params": {
        "name": "s1"
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
=TITLE=Delete unknown service
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "delete_service",
    "params": {
        "name": "s1"
    }
}
=ERROR=
Error: Can't find service:s1
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
    "method": "add_to_user",
    "params": {
        "service": "s1",
        "user": "host:h4, host:h6"
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
--netspoc
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add_to_user",
    "params": {
        "service": "s1",
        "user": "host:h4"
    }
}
=ERROR=
Error: Can't find service:s1
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
    "method": "remove_from_user",
    "params": {
        "service": "s1",
        "user": "host:[network:n1, network:n2]"
    }
}
=ERROR=
Error: Can't find 'host:[network:n1,network:n2,]' in 'user' of service:s1
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
    "method": "remove_from_user",
    "params": {
        "service": "s1",
        "user": "host:[ network:n1 ]"
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
=TITLE=Replace in user
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
                "method": "add_to_user",
                "params": {
                    "service": "s1",
                    "user": "host:h4"
                }
            },
            {
                "method": "remove_from_user",
                "params": {
                    "service": "s1",
                    "user": "host:h5"
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
=TITLE=Remove unknown server in rule
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
    "method": "remove_from_rule",
    "params": {
        "service": "s1",
        "rule_num": 1,
        "dst": "network:n1"
    }
}
=ERROR=
Error: Can't find 'network:n1' in 'dst' of rule 1 of service:s1
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
    "method": "remove_from_rule",
    "params": {
        "service": "s1",
        "rule_num": 1,
        "prt": "udp 80"
    }
}
=ERROR=
Error: Can't find 'udp 80' in rule 1 of service:s1
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
  "method": "remove_from_rule",
  "params": {
    "prt": "icmp 3  / 13 , tcp 443, tcp 9300-9302, udp 161 - 162, udp 427",
    "rule_num": 1,
    "service": "s1"
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
                "method": "add_to_rule",
                "params": {
                    "service": "s1",
                    "rule_num": 1,
                    "prt": "udp 80",
                    "dst": "host:h4"
                }
            },
            {
                "method": "remove_from_rule",
                "params": {
                    "service": "s1",
                    "rule_num": 2,
                    "prt": "tcp 85 - 90",
                    "dst": "host:h4"
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
+ permit src = user;
+        dst = host:h5;
+        prt = tcp 91;
 }
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
    "method": "add_to_rule",
    "params": {
        "service": "s1",
        "rule_num": 9,
        "prt": "tcp 90"
    }
}
=ERROR=
Error: Invalid rule_num 9, have 1 rules in service:s1
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
    "method": "add_to_rule",
    "params": {
        "service": "s1",
        "rule_num": 1
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
                "method": "add_rule",
                "params": {
                    "service": "s1",
                    "action": "permit",
                    "src": "user",
                    "dst": "host:h5, interface:r1.n2",
                    "prt": "udp 123, icmp"
                }
            },
            {
                "method": "delete_rule",
                "params": {
                    "service": "s1",
                    "rule_num": 2
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
+        dst = host:h5,
+              interface:r1.n2,
+              ;
+        prt = udp 123,
+              icmp,
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
    "method": "multi_job",
    "params": {
        "jobs": [
            {
                "method": "add_rule",
                "params": {
                    "service": "s1",
                    "action": "deny",
                    "src": "host:h5",
                    "dst": "user",
                    "prt": "udp, icmp 4"
                }
            }
        ]
    }
}
=OUTPUT=
@@ service
  deny   src = user;
         dst = network:n1;
         prt = tcp 22;
+ deny   src = host:h5;
+        dst = user;
+        prt = udp,
+              icmp 4,
+              ;
  permit src = user;
         dst = host:h3;
         prt = tcp;
=END=

############################################################
=TITLE=Add invalid rule
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
 "method": "add_rule",
 "params": {
   "service": "s1",
   "action": "allow",
   "src": "network:n1",
   "dst": "user",
   "prt": "tcp 80"
 }
}

=ERROR=
Error: Expected 'permit' or 'deny': 'allow'
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
    "method": "create_toplevel",
    "params": {
        "definition": "pathrestriction:p = interface:r1.n1, interface:r1.n2;",

        "file": "topology"
    }
}
=OUTPUT=
@@ topology
  interface:n1 = { ip = 10.1.1.2; hardware = n1; }
  interface:n2 = { ip = 10.1.2.2; hardware = n2; }
 }
+
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
    "method": "delete_toplevel",
    "params": {
        "name": "pathrestriction:p"
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
