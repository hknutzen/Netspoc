
############################################################
=TITLE=No input file
=INPUT=NONE
=ERROR=
Usage: PROGRAM [options] netspoc-data [typed-name ...]
  -q, --quiet   Flag is ignored
=END=

############################################################
=TITLE=Invalid input
=INPUT=
foo
=ERROR=
Error: Typed name expected at line 1 of INPUT, near "--HERE-->foo"
=END=

############################################################
=TITLE=Empty input
=INPUT=

=OUTPUT=
{}
=END=

############################################################
=TITLE=Empty group
=INPUT=
group:g1 = ;
=OUTPUT=
{ "group": [ {"name": "group:g1", "elements": []} ] }
=END=

############################################################
=TITLE=Group with union, intersection, complement, automatic groups
=INPUT=
group:g1 =
 host:h1,
 group:g2 & group:g3 &! host:h2 &! host:h3,
 any:[network:n1],
 any:[ip=10.1.0.0/16 & area:a1],
 host:[network:n2],
 network:[host:h1],
 interface:r1.[auto],
 interface:[network:n1].[all]
 ;
=OUTPUT=
{ "group":
  [{
   "name":"group:g1",
   "elements": [
    "host:h1",
    "group:g2&group:g3&!host:h2&!host:h3",
    "any:[network:n1]",
    "any:[ip=10.1.0.0/16&area:a1]",
    "host:[network:n2]",
    "network:[host:h1]",
    "interface:r1.[auto]",
    "interface:[network:n1].[all]"
   ]
  }]
}
=END=

############################################################
=TITLE=Service with intersection in user
=INPUT=
service:s1 = {
 user = network:[group:g1, group:g2] &! network:n1 &! network:[host:h2];
 permit src = user; dst = network:n3; prt = tcp 80;
}
=OUTPUT=
{
 "service":[
  {
   "name": "service:s1",
   "user": [
    "network:[group:g1,group:g2]&!network:n1&!network:[host:h2]"
   ],
   "rules": [
    {
     "action": "permit",
     "src": [ "user" ],
     "dst": [ "network:n3" ],
     "prt": [ "tcp 80" ]
    }
   ]
  }
 ]
}
=END=

############################################################
=TITLE=Protocol and protocolgroup
=INPUT=
protocol:NTP =
 description =With source port
 udp 123:123;
protocol:HTTP = tcp 80;
protocol:Ping = icmp 8;
protocolgroup:g1 =
 description =Look, a description
 protocol:HTTP, tcp 81-85, protocol:NTP;
=OUTPUT=
{
 "protocol":[
 {"name": "protocol:NTP",
  "description": "With source port",
  "value": "udp 123 : 123" },
 {"name": "protocol:HTTP", "value": "tcp 80" },
 {"name": "protocol:Ping", "value": "icmp 8" }
 ],
 "protocolgroup": [
 {
  "name": "protocolgroup:g1",
  "description": "Look, a description",
  "value_list": [ "protocol:HTTP", "tcp 81 - 85", "protocol:NTP" ]
 }]
}
=END=

############################################################
=TITLE=Aggregate
=INPUT=
any:ALL_10 = {
 description =All internal networks
 owner = o2;
 ip = 10.0.0.0/8;
 link = network:n1;
}
=OUTPUT=
{
 "any":[
 {"name": "any:ALL_10",
  "description": "All internal networks",
  "ip": [ "10.0.0.0/8" ],
  "link": [ "network:n1" ],
  "owner": [ "o2" ]
 }]
}
=END=

############################################################
=TITLE=Router with network and service
=INPUT=
network:n1 = { ip = 10.1.1.0/24;}
router:r1 = {
 managed;
 model = ASA;
 interface:n1 = {ip = 10.1.1.1; virtual = {ip = 10.1.1.9;} hardware = n1;}
}
service:s1 = {
 description =This is for testing
 has_unenforceable;
 overlaps = service:s2, service:s3;

 user = foreach interface:r1.[all] &! interface:r1.n1;
 permit src = any:[user]; dst = user; prt = ip;
}
=OUTPUT=
{"network":[
 {"name":"network:n1",
  "ip": [ "10.1.1.0/24" ]}],
 "router":[
 {"name":"router:r1",
  "managed": null,
  "model":["ASA"],
  "interfaces":{
   "interface:n1":{
    "ip": [ "10.1.1.1" ],
    "hardware": [ "n1" ],
    "virtual": { "ip": [ "10.1.1.9" ] }
   }
  }
 }],
 "service":[
 {"name": "service:s1",
  "description": "This is for testing",
  "has_unenforceable": null,
  "overlaps": ["service:s2", "service:s3"],
  "foreach": true,
  "user":["interface:r1.[all]&!interface:r1.n1"],
   "rules": [
   {"action": "permit",
    "src": ["any:[user]"],
    "dst": ["user"],
    "prt": ["ip"]
   }]
 }]
}
=END=

############################################################
=TITLE=Filter objects
=INPUT=
network:n1 = { ip = 10.1.1.0/24; }
network:n2 = { ip = 10.1.2.0/24; }
group:g1 = network:n1;
group:g2 = group:g1;
area:a1 = {
 border = interface:r1.n1; owner = o2;
 router_attributes = { policy_distribution_point = host:netspoc; }
}
=PARAMS= network:n1 group:g2 area:a1
=OUTPUT=
{"area":
  [{
   "name": "area:a1",
   "owner": [ "o2" ],
   "router_attributes": {
    "policy_distribution_point": [ "host:netspoc" ]
   },
   "border": [ "interface:r1.n1" ]
  }],
 "group":
  [{
   "name":"group:g2",
   "elements": ["group:g1"]
  }],
 "network":
  [{
   "name":"network:n1",
   "ip":["10.1.1.0/24"]}]
}
=END=
