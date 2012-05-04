---
layout: default
---

# A Network Security Policy Compiler

## About

Netspoc is [free](https://github.com/hknutzen/Netspoc/raw/releases/LICENSE)
software to manage all the packet filter devices inside your
network topology.  Filter rules for each device are generated from one
central ruleset, using a description of your network topology.

## How it works

<div class="gallery" markdown="1">

<div class="list">
 <a href="intro-rules.png"><img src="intro-rules.png"/></a>

#### Rules

You define rules which describe the traffic allowed to flow between
different networks.

</div>

<div class="list">
 <a href="intro-topo.png"><img src="intro-topo.png"/></a>

#### Topology

You define the networks in more detail with attributes like IP address
and hosts and arrange them into a topology.  
The topology is a graph of networks connected by packet filters and routers.

</div>

<div class="list">
 <a href="intro-topo-with-rules.png"><img src="intro-topo-with-rules.png"/></a>

#### Find paths

Netspoc processes each rule and finds the path from source 
to destination.

</div>

<div class="list">
 <a href="intro-topo-with-rules-covered.png"><img src="intro-topo-with-rules-covered.png"/></a>

#### Distribute rules and generate code

Netspoc automatically distributes rules to packet filters and
generates device specific filter rules for each packet filter inside
the topology.

</div>

</div>
