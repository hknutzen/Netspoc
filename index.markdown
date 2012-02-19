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

<div class="gallery">

<div class="list" markdown="1">
 <img src="intro-topo.png"/>

#### Topology

You define your topology as a graph of networks connected by packet
filters and routers.

</div>

<div class="list" markdown="1">
 <img src="intro-rules.png"/>

#### Rules

You define rules which describe the traffic allowed to flow inside
your topology.

</div>

<div class="list" markdown="1">
 <img src="intro-topo-with-rules.png"/>

#### Find paths

Netspoc processes each rule and finds the path from source 
to destination.

</div>

<div class="list" markdown="1">
 <img src="intro-topo-with-rules-covered.png"/>

#### Distribute rules and generate code

Netspoc automatically distributes rules to packet filters and
generates device specific filter rules for each packet filter inside
the topology.
</div>

</div>
