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
3. Breaking the rule set down to elementary rules with exactly one
   source and destination, identify inconsistencies and remove
   duplicate and contained rules.
4. Processing the elementary rules by finding all paths in the network 
   graph for every source and destination pair, marking the managed 
   routers on these paths with respective routing informations. 
5. Converting the rules collected at managed routers into configurations 
   for the devices and writing a configuration file for every managed router.

Each of the steps consist of several tasks and operations that will be
described below. For more detailed information, have a look at the
technical documentation page, providing an elaborative description of
the individual functions. *The relevant part of the technical
information could be linked within the descriptions below...?*

### 1. Parsing the input

* **Read files or directory:** `read_file_or_dir`  
    NetSpoC parses the input files and transfers the contents into formats
    to work with. For the topology, objects are generated and made
    accessible by name in the working memory. Along the way, the input
    is checked for errors that are already recognizeable at this
    stage.

* **Order protocols:** `order_protocols`   
    *- move this into step 3!* Prepare the input protocols to receive
    their contained-in relations.

### 2. Creating the topology graph.

In this step, the topology input from the policy files is used to
create a topology graph in working memory.

* **Link topology:** `link_topology`    
    The objects generated from the topology input are linked via
    references to form the topology graph, and additional
    specifications such as crypto tunneling, path restrictions,
    bridged networks or disabled topology parts (*currently handeled
    in another function!*) are applied.

* **Prepare security zones and areas:**
    [set_zone](/Netspoc/technical.html#prepare_zones)  
    The topology graph is now abstracted, and parts of the graph are
    abstracted to zones and areas. This allows an easy attachment of
    properties to the objects of an area as well as a faster path
    traversal on the abstracted graph.

* **Prepare fast path traversal:**
    [setpath](/Netspoc/technical.html#prepare_traversal)  
    The graph is divided into treelike and cyclic parts, and informations
    for the navigation during path traversal is added to every node of
    the graph.

* **Distribute NAT information:** `distribute_nat_info`  
    If Network Address Translation is specified in the input, the topology
    graph is prepared to deal with NAT. Information about valid IP
    addresses of objects is distributed to the different parts of the
    network topology.

* **Identifying subnet relations:** `find_subnets_in_zone`  
    When rules are processed, redundant rules will be rejected
    from the ruleset. Rules can be redundant, because they are
    contained in other rules, for example if two rules are identical
    except for their destinations, but one destination is a subnet of
    the other. To enable redundancy checks in step 3, subnet
    relations (also contained-in relations) of networks in every
    single zone are determined.

* **Transfer ownership information:** `propagate_owners`    
  *part of set_service_owners, the second part, `check_service_owners`
  should maybe be extracted and placed within step 3...* The policy
  contains information about the group or person responsible (owner)
  for certain parts of the topology. This information is now added to
  the topology objects. While ownership is rather needed for Netspoc
  Policy Web than for the Netspoc compiler, it is still used *(in step
  3)* to validate the rules.

* **Coverting hosts to subnets:** `convert_hosts`  
    *is part of function `expand_services` and called in there before
    everything else. Maybe it can be called directly from the
    compile function.* Single IP addresses and IP address ranges of
    hosts are converted into subnets with a matching netmask. This
    helps with identifying contained-in relations when processing the
    rules, and allows to generate ACLs, that can refer to subnets but
    not to IP ranges.

### 3. Preparing the rules

Rules are now prepared to receive a rule set of valid elementary
rules. To remove as much redundancy as possible from the rule set,
duplicates and rules that are contained in other rules will be
deleted.

* **Detect contained-in relations of input protocols:** `order_protocols`     
  *As mentioned before, this function should possibly be placed here.*

* **Check rules for ownership:** `check_service_owners`    
    *This function has been executed in step 2 already, but is part of
    rule processing and should therefore be placed here. As it is
    merely a detail of rule validation, it could maybe be skipped
    at all...?* The source and destination values of the rules are
    checked to have valid owners.

* **Preparing rule optimization:** `expand_services`  
    The services and rules specified in the input policy are now
    expanded into elementary rules. These are stored in the rule tree,
    a data structure that enables an efficient evaluation to detect
    contained rules.

* **Include crypto rules:** `expand_crypto`    
    Rules derived from crypto tunneling are expanded to elementary
    rules and added to the rule tree. *could this be included in
    expand_services...?*

* **Check rules to allow access on every managed device:**
    `set_policy-distribution_ip`    
    The ACLs and static routes that are generated by NetSPoC have to
    be delivered from the Netspoc server to every managed device. To
    guarantee that this is possible, the rule set is now checked to
    allow access on the managed routers. Along the way, the IP
    addresses that are to be used by the Netspoc server for
    distribution are determined.

* **Optimize ruleset:** `optimize_and_warn_delete`    
    Elementary rules are compared to identify and remove redundancies.

* **Perform consistency checks** `check_supernet_rules`   
    Check rules that have networks or aggregates with subnets for
    consistency.

### 4. Rule processing

For every rule of the rule set, the topology graph is traversed now
from source to destination, collecting the information needed to
generate ACLs and static routes.

* **Identify devices that require NAT:** `prepare_nat_commands`    
    For every source and destination pair of the ruleset, the topology
    is traversed to determine the devices that need NAT
    configurations. The specific NAT configurations are stored within
    the router objects.

* **Find routes for rules:** `find_active_routes`  
    Again, the topology is traversed for every source and destination
    pair, generating static routing information and storing it in the
    router objects.

* **Generate reverse rules:** `gen_reverse_rules`    
    For devices that are not stateful, ACLs need to permit traffic
    into both directions. Therefore, for rules that were found during
    path traversal to have a stateless device on a path connecting
    source and destination, a reverse rule is generated and added to
    the ruleset, if it has not been contained before.

* **Identify rules that can be reduced at secondary routers:**
    `mark_secondary_rules`  
    If all routes between a source and destination pair of a rule
    contain at least one managed router, simplified ACLs may be
    generated for that rule on secondary routers. Rules that have been
    identified to fulfill this requirement during path traversal are
    now marked. 

* **Mark rules with NAT on path:** `mark_dynamic_nat_rules`     
    *This is a rule consistency check and should maybe be moved to
     step 3* Check rule set to be free from rules that have invalid
     NAT mappings on a path from source to destination.

* **Distribute rules to managed devices:** `rules_distribution`  
    For every source and destination pair of the rule set, the
    topology is traversed again, adding the associated rule
    information to every managed router on the found paths.

### 5. Convert information collected at routers to configuration files

* **Optimize distributed rules:** `local_optimization`    
    The rule information stored in managed routers is examined to
    detect and remove redundant rules. As the rules are still in an
    elementary format, summarized rules refering to ranges are
    generated if that is possible.

* **Generate configuration code: `print_code`   
    The optimized rules stored in the router objects are transformed
    into configuration commands. These are printed to file, with an
    individual file for every router.

