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
in a newly created directory `code`.

The generated files contain commands to configure packet filters rules
and static routes matching the model of each device.

* Since device Y uses stateless packet filters, Netspoc automatically
  generates a rule to permit answer packets.
* For device of model ASA, object-groups are used.

### To be continued



