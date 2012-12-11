---
layout: default
---

# Policy language

## Introduction

Netspoc reads a policy and generates configuration files for packet
filters. The policy is written in Netspoc's policy language. The policy
consists of a network topology and a set of services. A service is a
set of related rules which describe the traffic permitted between
some network ressource and its users.

The policy is either read from all files inside a directory or from a
single file.


## Getting started

We start with a simple example having one service and a topology which
only consist of a few networks.

### Service to access WWW servers

A `service` defines one or more related rules which describe access to
(or from) a ressource.

![networks access WWW server](www-rules.png)

    service:WWW-access = {
     description = Access of customers to WWW servers network
     user = network:Customer_X1, network:Customer_7;
     permit src = user;
            dst = network:WWW-Servers;
            prt = tcp 80;
    }

This service has a single rule. It permits a set of users as
source to access a destination network with protocol `tcp 80`.

In general, all rules of a service must reference the keyword
`user`. This ensures that the rules operate on the same ressource.

### A small topology

The topology is built from networks and routers, connected by
interfaces. For Netspoc, a network is a logical IP network with IP
address and prefix length. A router is any device which routes IP
packets.  Netspoc generates configuration files for managed
routers. Unmanaged routers are only used to connect networks.

![topology with customers and WWW server](www-topo.png)

    network:Customer_X1 = { ip = 10.6.1.0/24; }
    router:Backbone-X = {
     interface:Customer_X1;
     interface:To-Backbone = { ip = 10.126.4.2; }
    }
    network:To-Backbone = { ip = 10.126.4.0/30; }
    router:X = {
     managed;
     model = IOS, FW;
     interface:To-Backbone = { ip = 10.126.4.1; hardware = FastEthernet1; }
     interface:Transfer    = { ip = 10.1.1.9;   hardware = FastEthernet0; }
    }

    network:Customer_7 = { ip = 10.5.7.0/24; }
    router:Y = {
     managed;
     model = IOS;
     interface:Customer_7 = { ip = 10.5.7.1; hardware = FastEthernet1; }
     interface:Transfer   = { ip = 10.1.1.8; hardware = FastEthernet0; }
    }

    network:Transfer = { ip = 10.1.1.0/24; }
    router:WWW = {
     managed;
     model = ASA;
     interface:Transfer    = { ip = 10.1.1.109; hardware = GigabitEthernet0; }
     interface:WWW-Servers = { ip = 10.2.3.1;   hardware = GigabitEthernet1; }
    }
    network:WWW-Servers = { ip = 10.2.3.0/24; }

The connection between network and router is established by repeating
the network name as interface name.

A managed router has additional attributes, which are used to generate
device specific code:

1. `model` defines the type of the device. E.g. `IOS, FW` means IOS router
   with stateful inspection enabled.
2. Each interface needs an IP address.
3. `hardware` of an interface gives the device's denotation of that interface.

### Apply Netspoc to an example

Save both, service and topology into a file named [example](example) and call Netspoc like this:

    netspoc example code

This generates configuration files for [device X](code/X),
[device Y](code/Y) and [device WWW](code/WWW) 
in a newly created directory named `code`.

The generated files contain commands to configure packet filters rules
and static routes matching the model of each device.

* Since device Y uses stateless packet filters, Netspoc automatically
  generates a rule to permit answer packets.
* For device of model ASA, object-groups are created.

## Defining services

Rules describe, which traffic is permitted to flow between different
network objects. In Netspoc, related rules are grouped into services.
All rules belonging to a service must use the same source or destination
object(s). This is enforced by the keyword "user" which must be
referenced either from src or from dst or both parts of a rule.

### Rules

A rule permits or denies traffic of some protocol to flow from source
to destination. Source and destination are one or more objects from
the topology.

It doesn't matter in which order the rules are written. Netspoc places
deny rules always in front of all permit rules.

### Protocols

Simple protocols like "tcp 80", "udp 161-162", "protocol 50" can be
used directly in rules.

You can define named protocols like

    protocol:HTTP = tcp 80;

and use "protocol:HTTP" instead of "tcp 80" in a rule.

#### Details

For TCP and UDP, if two ranges are given, they describe source and
destination port.

Only one rule is needed to permit a TCP connection from source to
destination. Answer packets are automatically allowed. For stateful
packet filters, this is done at the device. For stateless packet
filters, netspoc automatically generates a rule which allowes any TCP
traffic from destination to source with flag "established" i.e. no SYN
flag set.

Similarly, only one rule is needed to let UDP packets pass from
source to destination and back. For stateless packet filters, a rule
with reversed addresses and reversed port numbers is generated.

For service IP and stateless packet filters, a rules with reversed
addresses is automatically generated. This is done to get an
consistent handling for TCP, UDP and IP.

### Protocol modifiers

One or more protocol modifiers can optionally be appended to a named
protocol definition. A protocol modifier modifies the rule in which
the corresponding protocol is used as follows:

stateless
: The rule is only applied to stateless devices. 

oneway
: At stateless devices, don't automatically generate rules to permit 
answer packets. 

reversed
: Source and destination are swapped. 

dst_net
: If destination of rule is a host or interface, find the enclosing
network N and replace destination by N. Exception: hosts having a
VPN id and interfaces of manged routers are left unchanged.

dst_any
: First apply rules of modifier dst_net above. If afterwards the
destination of rule is a network, find the aggregate of the
enclosing security zone X and replace destination by X.

src_net, src_any
: Equivalent to dst_* modifiers but applied to source of rule. 

### To be continued