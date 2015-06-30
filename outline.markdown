---
layout: default
author: Meike Bruns
---


<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

# Netspoc: A workflow outline.

NetSPoC is a Network Security Policy Compiler. It takes a set of
access rules (services) and a given network topology specified in
NetSPoC Policy language and generates access lists and static routes
for those routers of the network topology that are marked to be
managed by NetSPoC (they will be called managed routers in the
following).

For this task, five steps are conducted:

1. Parsing network topology and rule set.
2. Connecting the elements of the topology to form a topology graph.
3. Breaking the rule set down to elementary rules with exactly one source 
   and destination, remove duplicate and contained rules.
4. Processing the elementary rules by finding all paths in the network 
   graph for every source and destination pair, marking the managed 
   routers on these paths with the respective rule. 
5. Converting the rules collected at managed routers into configurations 
   for the devices and writing a configuration file for every managed router.

Each of the steps consist of several tasks and operations that will be
described below. For more detailed information, have a look at the
technical documentation page, providing an elaborative description of
the individual functions. *The relevant part of the technical
information could be linked within the descriptions below...?*

## 1. Parsing the input

### Read files or directory

NetSpoC parses the input files and transfers the contents into formats
to work with. For the topology, objects are generated and made
accessible by name in the working memory. Along the way, the input is checked
for errors that are already recognizeable at this stage.

### Order protocols *- move this into step 3!*

Prepare the input protocols to receive their contained-in relations.

## 2. Creating the topology graph.

### Link topology

The objects generated from the topology input are linked via
references to form the topology graph, and additional specifications
such as crypto tunneling, path restrictions, bridged networks or
disabled topology parts are applied.

### Prepare security zones and areas 

The topology graph is now abstracted, and parts of the graph are
abstracted to zones and areas. This allows an easy attachment of
properties to the objects of an area as well as a faster path
traversal on the abstracted graph.

### Prepare fast path traversal

The graph is divided into treelike and cycclic parts, and informations
for the navigation during path traversal is added to every node of the
graph.

### Add NAT information

If Network Address Translation is specified in the input, the topology
graph is prepared to deal with NAT. Information about valid IP
addresses of objects are distributed to the different parts of the
network topology.

## 3. Rule preparation

Rules are now prepared to receive a ruleset of elementary rules. To
remove as much redundancay as possible from the ruleset of elementary
rules, duplicate rules will be deleted from the ruleset as well as
rules that are contained in other rules.

### (Order protocols) 

To recognize whether a rule is contained in another rule regarding its
protocols, the input protocols are prepared to receive their
contained-in relations.

### Find subnet relations...?


