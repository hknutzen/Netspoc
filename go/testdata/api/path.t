
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
=TITLE=Invalid value
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
=JOB=
{
    "method": "add",
    "params": { "value": x }
}
=ERROR=
Error: In JSON input: invalid character 'x' looking for beginning of value
=END=

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

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
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

############################################################
=TITLE=Add duplicate router_attributes
=INPUT=
owner:o1 = { admins = a1@example.com; }
network:n1 = { ip = 10.1.1.0/24; owner = o1; }
network:n2 = { ip = 10.1.2.0/24; }

router:asa1 = {
 managed;
 model = ASA;
 interface:n1 = { ip = 10.1.1.1; hardware = n1; }
 interface:n2 = { ip = 10.1.2.1; hardware = n2; }
}

area:a2 = {
 router_attributes = { owner = o1; }
 inclusive_border = interface:asa1.n1;
}
=JOB=
{

    "method": "add",
    "params": {
        "path": "area:a2,router_attributes",
        "value": { "owner": "o2" }
    }
}
=ERROR=
Error: Can't add duplicate definition of 'router_attributes'
=END=