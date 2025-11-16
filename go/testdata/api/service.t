
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
Error: Expecting JSON object in attribute 'value' but got: string
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
=TITLE=Can't create directory
=INPUT=
-- rule
network:n1 = { ip = 10.1.1.0/24; }
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
                "dst": "network:n2",
                "prt": "tcp 80"
            }]
        }
    }
}
=ERROR=
panic: mkdir rule: not a directory
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
=TITLE=Add service, name starting with hyphen, below ASCII 0
=INPUT=[[input]]
=JOB=
{
    "method": "add",
    "params": {
        "path": "service:-s-",
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
+service:-s- = {
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
            "has_unenforceable": [],
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
=TITLE=Delete from attribute 'overlaps'
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
        prt = tcp 80, tcp 90;
}
-- rule/B
service:b = {

 overlaps = service:a, service:c;

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
        prt = tcp, udp;
}
=JOB=
{
   "method": "multi_job",
   "params": {
       "jobs": [
       {
           "method" : "delete",
           "params": {
               "path": "service:c,rules,1,prt",
               "value": "tcp"
           }
       },
       {
           "method" : "delete",
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
- overlaps = service:a, service:c;
+ overlaps = service:a;
  user = host:h3;
  permit src = user;
@@ rule/C
  user = host:h3;
  permit src = user;
         dst = network:n2;
-        prt = tcp, udp;
+        prt = udp;
 }
=END=

############################################################
=TITLE=Delete all attribute values of 'overlaps'
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
        prt = tcp 80, tcp 90;
}
-- rule/B
service:b = {

 overlaps = service:a, service:c;

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
        prt = tcp, udp;
}
=JOB=
{
   "method": "multi_job",
   "params": {
       "jobs": [
       {
           "method" : "delete",
           "params": {
               "path": "service:a,rules,1,prt",
               "value": "tcp 80"
           }
       },
       {
           "method" : "delete",
           "params": {
               "path": "service:c,rules,1,prt",
               "value": "tcp"
           }
       },
       {
           "method" : "delete",
           "params": {
               "path": "service:b,overlaps",
               "value": ["service:c", "service:a"]
           }
       }]
   }
}
=OUTPUT=
@@ rule/A
  user = network:n1;
  permit src = user;
         dst = network:n2;
-        prt = tcp 80, tcp 90;
+        prt = tcp 90;
 }
@@ rule/B
 service:b = {
- overlaps = service:a, service:c;
-
  user = host:h3;
  permit src = user;
         dst = network:n2;
@@ rule/C
  user = host:h3;
  permit src = user;
         dst = network:n2;
-        prt = tcp, udp;
+        prt = udp;
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
--protocols
protocol:tftp = udp 69, oneway;
protocol:ping_net     = icmp 8, src_net, dst_net;
protocol:ping_net_rev = icmp 8, src_net, dst_net, reversed;
protocolgroup:ping_both = protocol:ping_net, protocol:ping_net_rev;
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
              protocolgroup:ping_both,
              protocol:tftp,
              ;
}
=JOB=
{
  "method": "delete",
  "params": {
    "value": [
        "protocol:tftp",
        "protocolgroup:ping_both",
        "icmp 3/13",
        "tcp 443",
        "tcp 9300-9302",
        "udp 161 - 162",
        "udp 427"
    ],
    "path": "service:s1,rules,1,prt"
  }
}
=WARNING=
Warning: unused protocolgroup:ping_both
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
-              protocolgroup:ping_both,
-              protocol:tftp,
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
=TITLE=Add rule with attribute log
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
=TITLE=Can't remove all rules at once
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
        "path": "service:s1,rules"
    }
}

=ERROR=
Error: Rule number must be given for 'delete'
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
