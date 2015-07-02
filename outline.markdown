---
layout: default
author: Meike Bruns
---


<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

# Netspoc: A workflow outline.

Netspoc is a Network Security Policy Compiler. It takes a set of
access rules (services) and a given network topology specified in
Netspoc policy language and generates access lists and static routes
for those routers of the network topology that are marked to be
managed by Netspoc (they will be called managed routers in the
following).

For this task, five steps are conducted:

1. Parsing network topology and rule set.
2. Connecting elements of the topology to form a topology graph.
3. Breaking the rule set down to elementary rules with exactly one
   source and destination, identify inconsistencies and remove
   duplicate and contained rules.
4. Processing elementary rules by finding all paths in the network 
   graph for every source and destination pair, marking managed 
   routers on these paths with respective routing informations. 
5. Converting the rules collected at managed routers into
   configurations for the router devices and writing a configuration
   file for every managed router.

Each of the steps consists of several tasks and operations that will
be described below. For more detailed information, have a look at the
technical documentation page, providing an elaborate description of
the individual functions. If technical documentation is available for
a certain step, the relevant part is linked within the descriptions
below.

### 1. Parsing the input

* **Read files or directory:** `read_file_or_dir`  
    Netspoc parses input files and transfers the contents into formats
    to work with. For the topology, objects are generated and made
    accessible by name in the working memory. Along the way, the input
    is checked for errors that are already recognizeable at this
    stage.

* **Order protocols:** `order_protocols`   
    Process input protocols to receive their contained-in
    relations. *(This should be moved into step 3!)*

### 2. Creating the topology graph

In this step, topology input from the policy files is used to create a
topology graph in working memory.

* **Link topology:** `link_topology`    
    The objects generated from topology input are linked via
    references to form the topology graph. Additional specifications
    such as crypto tunneling, path restrictions, bridged networks or
    disabled topology parts (*currently handeled in function
    `mark_disabled`*) are applied.

* **Prepare security zones and areas:** 
    [set_zone](/Netspoc/technical.html#prepare_zones)  
    The topology graph is now abstracted, with parts of the graph
    being bundled to zones and areas. This allows easy attachment of
    properties to an areas objects as well as faster path traversal on
    the abstracted graph.

* **Prepare fast path traversal:** 
    [setpath](/Netspoc/technical.html#prepare_traversal)  
    Information to simplify navigation during path traversal is added
    to every node of the graph.

* **Distribute NAT information:** `distribute_nat_info`  
    If Network Address Translation is specified in the input, the topology
    graph has to be prepared to deal with NAT. Information about which IP
    addresses are valid in which topology part is distributed.

* **Identifying subnet relations:** `find_subnets_in_zone`  
    During rule procession, redundant rules will be rejected
    from the rule set. Rules can be redundant, because they are
    contained in other rules, for example if two rules are identical
    except for their destinations, but one destination is a subnet of
    the other. To enable redundancy checks in step 3, subnet
    relations (also contained-in relations) of networks in every
    single zone are determined.

* **Transfer ownership information:** `propagate_owners`    

  The policy contains information about groups or persons responsible
  for certain parts of the topology (owner). This information is now
  added to the topology objects. While ownership is rather needed for
  Netspoc Policy Web than for the Netspoc compiler, it is also used
  *(in step 3, somewhen)* to validate rules. *(This function is the
  first part of `set_service_owners`, the second part,
  `check_service_owners` should maybe be extracted and placed within
  step 3.)*

* **Coverting hosts to subnets:** `convert_hosts`  
    Single IP addresses and IP address ranges of hosts are converted
    into subnets with a matching netmask. This helps to identify
    contained-in relations when processing the rules, and allows to
    generate ACLs, as they can refer to subnets but not to IP
    ranges. *(This function is part of `expand_services` and called in
    there before everything else. Maybe it can be called directly from
    the compile function to achieve a better separation of step 2 and
    3.)*

### 3. Preparing the rules

Rules are now prepared to receive a rule set of valid elementary
rules. To remove as much redundancy as possible from the rule set,
duplicates and rules that are contained in other rules are
deleted.

* **Detect contained-in relations of input protocols:** `order_protocols`     
  (*This function should possibly be placed here, see above.)*

* **Check rules for ownership:** `check_service_owners`    
    The source and destination values of the rules are checked to have
    valid owners. *(This function has been executed in step 2
    already. As it is part of rule processing, it should maybe be
    placed here. On the other hand, it is merely a detail of rule
    validation and could maybe be skipped in here.)*

* **Preparing rule optimization:** `expand_services`  
    Services and rules specified in the input policy are now
    expanded into elementary rules. These are stored in the rule tree,
    a data structure that enables an efficient evaluation to detect
    contained rules.

* **Include crypto rules:** `expand_crypto`    
    Rules derived from crypto tunneling are expanded to elementary
    rules and added to the rule tree. *(Could this be included in
    expand_services?)*

* **Assure that rules allow access on every managed device:**
    `set_policy-distribution_ip`    
    The ACLs and static routes that are generated by Netspoc have to
    be delivered from the Netspoc server to every managed device. To
    ensure that this is possible, the rule set is now checked to
    allow access on managed routers. Along the way, the IP
    addresses that are to be used by the Netspoc server for
    distribution are determined.

* **Optimize ruleset:** `optimize_and_warn_delete`    
    Elementary rules are compared to identify and remove redundancies.

* **Perform consistency checks** `check_supernet_rules`   
    Check rules that have networks or aggregates with subnets for
    consistency.

### 4. Processing the rules

For every rule in the rule set, the topology graph is traversed from
source to destination, collecting the information needed to generate
ACLs and static routes.

* **Identify devices that require NAT:** `prepare_nat_commands`    
    For every source and destination pair of the rule set, the
    topology is traversed to determine devices that need NAT
    configurations. The specific NAT configurations are stored within
    the found router objects.

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

* **Identify rules that can be simplified at secondary routers:** 
    `mark_secondary_rules`  
    If all routes between a source and destination pair of a rule
    contain at least one managed router, simplified ACLs may be
    generated for that rule on secondary routers. Rules that have been
    identified to fulfill this requirement during path traversal are
    now marked. 

* **Check for rules with invalid NAT mapping:** `mark_dynamic_nat_rules`     
     Check rule set to be free from rules that have invalid NAT
     mappings on a path from source to destination. *(This is a rule
     consistency check and should maybe be moved to step 3)*

* **Distribute rules to managed devices:** `rules_distribution`  
    For every source and destination pair of the rule set, the
    topology is traversed again, adding the associated rule
    information to every managed router on the found paths.

### 5. Generating router configurations

The information collected at managed router objects is converted into
router configuration files in this step.

* **Optimize distributed rules:** `local_optimization`    
    Rule information stored in managed router objects is examined to
    detect and remove redundant rules. As the rules are still in an
    elementary format, summarized rules refering to ranges are
    generated, if possible.

* **Generate configuration code:** `print_code`   
    The optimized rules stored in router objects are transformed
    into configuration commands. These are printed to file, creating an
    individual file for every router.

