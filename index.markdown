---
layout: default
---

# A Network Security Policy Compiler

## About

Netspoc manages all the packet filter devices inside your
network topology.  Filter rules for each device are generated from one
central ruleset, using a description of your network topology.

## How it works

<div class="gallery">

<div class="list">
 <img src="intro-topo.png"/>

<p>You define your topology as a graph of networks connected by packet
filters and routers.</p>
</div>

<div class="list">
 <img src="intro-rules.png"/>

<p>You define rules which describe the traffic allowed to flow inside your
topology.</p>
</div>

<div class="list">
 <img src="intro-topo-with-rules.png"/>

<p>Netspoc processes each rule and finds the path from source 
to destination.</p>
</div>

<div class="list">
 <img src="intro-topo-with-rules-covered.png"/>

<p>Netspoc automatically distributes rules to packet filters and
generates device specific filter rules for each packet filter inside
the topology.</p>
</div>

</div>
