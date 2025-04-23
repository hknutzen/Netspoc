
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
=TITLE=Add host without network in path
=INPUT=
-- topology
network:a = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "host:name_10_1_1_4",
        "value": { "ip": "10.1.1.4" }
    }
}
=ERROR=
Error: Use path 'network:N1,host:N2' to create 'host:name_10_1_1_4'
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
Error: Can't add duplicate definition of 'host:name_10_1_1_4'
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
Error: Can't modify unknown 'host:h1'
=END=

############################################################
=TITLE=Delete unknown host
=INPUT=
-- topology
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "delete",
    "params": {
        "path": "host:h1"
    }
}
=ERROR=
Error: Can't delete unknown 'host:h1'
=END=

############################################################
=TITLE=Remove host without network in path
=INPUT=
-- topology
network:n1 = {
 ip = 10.1.1.0/24;
 host:h1 = { ip = 10.1.1.1; }
 host:h2 = { ip = 10.1.1.2; }
 host:h3 = { ip = 10.1.1.3; }
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "host:h2"
    }
}
=OUTPUT=
@@ topology
 network:n1 = {
  ip = 10.1.1.0/24;
  host:h1 = { ip = 10.1.1.1; }
- host:h2 = { ip = 10.1.1.2; }
  host:h3 = { ip = 10.1.1.3; }
 }
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
=TITLE=Remove owner at host without network in path
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
        "path": "host:h1,owner"
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
=TITLE=Add owner to host without network in path
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
        "path": "host:h2,owner",
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
=TITLE=Replace missing owner at host without network in path
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
        "path": "host:h2,owner",
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
=TEMPL=input
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
 vpn_attributes = {
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
 vpn_attributes = {
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
=INPUT=
[[input]]
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
=TITLE=Add ID-host with missing network in path
=INPUT=
[[input]]
=JOB=
{
     "method": "add",
     "params": {
         "path": "host:id:a3@example.com",
         "value": { "ip": "10.1.2.3" }
     }
}
=ERROR=
Error: Use path 'network:N1,host:id:N2' to add 'host:id:a3@example.com'
=END=

############################################################
=TITLE=Change owner of ID-host without network in path
=INPUT=
[[input]]
=JOB=
{
     "method": "set",
     "params": {
         "path": "host:id:a2@example.com,owner",
         "value": "DA_TOKEN_o3"
     }
}
=ERROR=
Error: Use path 'network:N1,host:id:N2' to modify 'host:id:a2@example.com'
=END=

############################################################
=TITLE=Delete ID-host without network in path
=INPUT=
[[input]]
=JOB=
{
     "method": "delete",
     "params": {
         "path": "host:id:a2@example.com"
     }
}
=ERROR=
Error: Use path 'network:N1,host:id:N2' to delete 'host:id:a2@example.com'
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
        "value": { "elements": ["interface:r1.n1", "interface:r1.n2"] }
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
=TITLE=Add loopback interface
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
=TITLE=Add VIP Interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

owner:a = {
 admins = a@example.com;
}

router:r1 = {
 interface:n1;
 interface:n2;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:VIP_interface",
        "value": {
            "ip": "10.1.3.3",
            "owner": ["a"],
            "vip": []
        }
    }
}
=OUTPUT=
@@ INPUT
 router:r1 = {
  interface:n1;
  interface:n2;
+ interface:VIP_interface = { ip = 10.1.3.3; owner = a; vip; }
 }
=END=

############################################################
=TITLE=Add VIP Interface without owner
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }

router:r1 = {
 interface:n1;
 interface:n2;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:VIP_interface",
        "value": {
            "ip": "10.1.3.3",
            "vip": []
        }
    }
}
=OUTPUT=
@@ INPUT
 router:r1 = {
  interface:n1;
  interface:n2;
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
 interface:n1;
 interface:n2;
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
 router:r1 = {
  interface:n1;
  interface:n2;
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
 interface:n1;
 interface:n2;
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
=TITLE=Add attribute to short interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1,interface:n1,ip",
        "value": "10.1.1.1"
    }
}
=ERROR=
Error: Can't descend into value of 'interface:n1'
=END=

############################################################
=TITLE=Add IP & VIP to short interface
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
=TITLE=Delete remaining attribute from interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.2; }
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "router:r1,interface:n1,ip"
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; }
 router:r1 = {
- interface:n1 = { ip = 10.1.1.2; }
+ interface:n1 = { }
 }
=END=

############################################################
=TITLE=Change to short interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.2; }
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "router:r1,interface:n1",
        "value": []
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; }
 router:r1 = {
- interface:n1 = { ip = 10.1.1.2; }
+ interface:n1;
 }
=END=

############################################################
=TITLE=Change to short interface using null value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.2; }
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "router:r1,interface:n1",
        "value": null
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; }
 router:r1 = {
- interface:n1 = { ip = 10.1.1.2; }
+ interface:n1;
 }
=END=

############################################################
=TITLE=Change to short interface using no value at all
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1 = { ip = 10.1.1.2; }
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "router:r1,interface:n1"
    }
}
=OUTPUT=
@@ INPUT
 network:n1 = { ip = 10.1.1.0/24; }
 router:r1 = {
- interface:n1 = { ip = 10.1.1.2; }
+ interface:n1;
 }
=END=

############################################################
=TITLE=Set attribute of unknown interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1;
}
=JOB=
{
    "method": "set",
    "params": {
        "path": "router:r1,interface:n2,ip",
        "value": "10.1.1.1"
    }
}
=ERROR=
Error: Can't set attribute of unknown 'interface:n2'
=END=

############################################################
=TITLE=Delete attribute from unknown interface
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }

router:r1 = {
 interface:n1;
}
=JOB=
{
    "method": "delete",
    "params": {
        "path": "router:r1,interface:n2,ip",
        "value": "10.1.1.1"
    }
}
=ERROR=
Error: Can't delete attribute of unknown 'interface:n2'
=END=

############################################################
=TITLE=Add IPv6 router
=INPUT=
network:n2 = { ip6 = 1000::abcd:0001:0/112; }
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1",
        "value": {
            "interface:n2": null
        }
    }
}
=OUTPUT=
@@ INPUT
 network:n2 = { ip6 = 1000::abcd:0001:0/112; }
+
+router:r1 = {
+ interface:n2;
+}
=END=

############################################################
=TITLE=Add IPv6 router that already exists
=INPUT=
network:n2 = { ip6 = 1000::abcd:0001:0/112; }

router:r1 = {
 interface:n2;
}
=JOB=
{
    "method": "add",
    "params": {
        "path": "router:r1",
        "value": {
            "interface:n2": null
        }
    }
}
=ERROR=
Error: 'router:r1' already exists
=END=
