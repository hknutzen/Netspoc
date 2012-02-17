---
layout: default
---

# A Network Security Policy Compiler

## About

Netspoc manages all the packet filter devices inside your
network topology.  Filter rules for each device are generated from one
central ruleset, using a description of your network topology.

## How it works

You define your topology as a graph of networks connected by packet
filters and routers.

You define rules which describe the traffic allowed to flow inside your
topology.

Netspoc processes each rule and 
- finds the path from source to destination,
- automatically distributes rules to packet filters and
- generates device specific filter rules for each packet filter 
  inside the topology.

