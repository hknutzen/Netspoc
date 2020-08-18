---
layout: default
author: Meike Bruns
---


<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

# Netspoc: A workflow outline

Netspoc is a Network Security Policy Compiler. It takes a set
of access rules (services) and a given network topology specified in
Netspoc policy language and generates access lists and static routes
for those routers of the network topology marked to be
managed by Netspoc (called managed routers in the following).

Netspoc is a two pass compiler. From input, pass 1 generates two files
for every managed router: The configuration template file, containing
router configurations excluding ACL information, and the rule file
storing those rules of the given service input that affect ACL
generation on the particular router. In pass 2, ACLs are derived from
rule files and inserted in the configuration template. As ACL
generation involves time consuming optimization processes and since
input modifications usually affect a small selection of managed
routers only, pass 2 tries to reuse configuration files generated from
a previous run. For this purpose, pass 2 compares its current input
with the stored input of the previous run, generating new
configuration files only for affected routers and reusing
configuration files otherwise.

To generate router configurations from a given input, following steps
are conducted:

**Pass 1**

1. Parse network topology and rule set.
2. Connect elements of the topology to form a topology graph.
3. Perform consistency checks on the rule set, transfer rules into a path
   rules set with \[source, destination\] pairs.
4. Find all paths in the topology graph for every source and destination
   pair, marking managed routers on the path with the corresponding rules and
   routing information.
5. Convert information collected at managed routers into configuration
   template and rule files.

**Pass 2**

1. Check, whether reusable configuration files from a previous run exist.
2. Optimize ruleset for routers, whose configuration files can not be reused.
3. Generate ACLs and write final router configuration files.

Each of the steps consists of several tasks and operations that will
be described below. For more detailed information, have a look at the
technical documentation page, providing an elaborate description of
the individual functions. If technical documentation is available for
a certain step, the relevant part is linked within the descriptions
below.

## Pass 1

### 1. Parsing the input

First, input topology and rule set need to be parsed.

* **Read files or directory:** `read_file_or_dir`
 :  Netspoc parses input files and transfers the contents into objects
    to work with. Objects are generated and made accessible by name
    for both topology and services. Along the way, the input is
    checked for errors that are already recognizeable at this stage.

* **Order protocols:** `order_protocols`
 :  Process protocols of the services and rules specified in the input
    to receive their contained-in relations.

### 2. Creating the topology graph

In this step, topology objects generated during parsing are used to
create a topology graph.

* **Link topology:** `link_topology`
 :  The objects generated from topology input are linked via
    references to form the topology graph. Additional specifications
    such as crypto tunneling, path restrictions, bridged networks or
    disabled topology parts (*currently handeled in function
    `mark_disabled`*) are applied.

* **Prepare security zones and areas:** [`set_zone`](/Netspoc/technical.html#prepare_zones)
 :  The topology graph is now abstracted, with parts of the graph being
    bundled to zones and areas. This allows inheritance of properties
    from areas to zones and from zones to networks. Using the
    abstracted graph of zones and routers also accelerates path
    traversal.

* **Prepare fast path traversal:** [`SetPath`](/Netspoc/technical.html#prepare_traversal)
 :  The graph is annotated with information that allows efficient
    path traversal.

* **Distribute NAT information:** `DistributeNatInfo`
 :  If Network Address Translation (NAT) is specified in the input, NAT
    domains are determined for the topology. NAT domains are parts of
    the topology with a consistent network address set.

* **Identify subnet relations:** `FindSubnetsInZone`
 :  During pass 2, redundant rules will be removed from rule sets
    of managed routers. Rules can be redundant, because they are contained
    in other rules, for example if two rules are identical except for
    their destinations, but one destination is a subnet of the
    other. To enable later redundancy checks, subnet relations of
    networks in every single zone are determined.



### 3. Preparing rules

Rules are now checked for consistency and grouped to receive a set of
so called path rules. Path rules contain a \[source zone, destination
zone\] pair and references to every input rule having its source within
the source zone and its destination within the destination zone. Thus,
the path rule set represents every rule from input.

* **Normalize rules:** `NormalizeServices`
 :  Normalized rule objects are now generated for every rule by
    resolving source and/or destination groups into specific source or
    destination objects. These are then referenced within the
    normalized rule object.

* **Transfer ownership information:** `CheckServiceOwner`
 :  The policy contains information about groups or persons responsible
    for certain parts of the topology (owner). This information is now
    added to the topology objects. Ownership is primarily needed for
    Netspoc-Web, but is also used to validate rules.

* **Covert hosts to subnets:** `ConvertHostsInRules`
 :  Single IP addresses and IP address ranges of hosts are converted
    into subnets with a matching netmask. Within pass 2, this helps to identify
    contained-in relations when processing the rules and allows to
    generate ACLs, as they can refer to subnets but not to IP
    ranges.

* **Group rules for path detection:** `GroupPathRules`
 :  Path rules are now generated by grouping rules according to their
    source and destination zones. For every normalized rule, source
    and destination zone have been determined and stored. Rules with more
    than one source and/or destination zone are split to achieve pairs
    with exactly one source and destination zone.

* **Identify subnet relations that must not be optimized at secondary routers:** `FindSubnetsInNatDomain`
 :  Within topology declaration, routers can be defined to have
    `secondary` as filter type. Such routers perform general filtering
    for the supernets of a rules source or destination instead of
    filtering for specific host or network addresses. Specific
    filtering is has to be realized by surrounding routers then. To avoid
    cases, where filtering for supernets leads to unintended permits,
    networks in such constallation are identified and marked now.

* **Mark networks that require local filtering:** `MarkManagedLocal`
 :  Routers can be defined to filter locally. Then, traffic that
    has already been filtered by other routers on the path can pass without
    further filtering, and ACLs need to be generated for traffic
    passing no other but the managed local router only. To
    identify traffic that needs local filtering easily, networks from
    clusters connected by local routers are marked in this step.

* **Check for rules with invalid NAT mapping:** `CheckDynamicNatRules`
 :  Check path rule set to be free from rules that have invalid NAT
    mappings on a path from source to destination.


### 4. Distributing rules and routes

For every pair in the path rule set, the topology graph is traversed
from source to destination, collecting routing and rule information
within the managed router objects on the path. During rule and routing
distribution, further consistency checks are performed on the ruleset.

* **Perform consistency checks:** `CheckUnusedGroups`, `CheckSupernetRules`, `CheckRedundantRules`
 :   While rules are distributed within the topology, a parallel process
     performs further checks on the ruleset. These include identification
     of unused protocolgroups, detection of missing supernet rules and an
     analysis for redundant or duplicate rules.

* **Remove duplicate path rules:** `RemoveSimpleDuplicateRules`
 :  To avoid multiple distribution of rules, duplicate rules are removed
    from the path rule set in this step.

* **Assure that rules allow access on every managed device:** `SetPolicyDistributionIP`
 :  ACLs and static routes generated by Netspoc have to
    be delivered from the Netspoc server to every managed device. To
    ensure that this is possible, the rule set is now checked to
    allow access on managed routers. Along the way, IP
    addresses that are to be used by the Netspoc server for
    distribution are determined.

* **Include crypto rules:** `ExpandCrypto`
 :  Rules derived from crypto tunneling are checked and added to path
    rule set.

* **Find routes for rules:** [`FindActiveRoutes`](/Netspoc/technical.html#find_routes)
 :  The topology is traversed for every source and destination
    pair, generating static routing information and storing it in the
    router objects.

* **Generate reverse rules:** `GenReverseRules`
 :  For devices that are not stateful, ACLs need to permit traffic
    into both directions. Therefore, for rules that were found during
    path traversal to have a stateless device on a path connecting
    source and destination, a reverse rule is generated and added to
    the path ruleset.

* **Identify rules that can be simplified at secondary routers:** `MarkSecondaryRules`
:   If all paths between a source and destination pair of a rule contain
    at least one managed router, simplified ACLs may be generated for
    that rule on secondary routers during pass 2.  Rules that have
    been identified to fulfill this requirement during path traversal
    are now marked to be simplified in pass 2.

* **Distribute rules to managed devices:** `RulesDistribution`
 :  For every source and destination pair of the path rule set, the
    topology is traversed again, collecting the associated rule
    information at every managed router on the found paths.

### 5. Generating output

Finally, pass 1 output is generated and printed to a directory
specified by the user.

* **Print config template and rules file** `PrintCode`
 :  For every managed router, collected information is used to
    generate the config template file containing routing information,
    if generated. Additionally, collected rules for ACL generation are
    printed into the routers rules file, using a format independent
    from the routers machine.

* **Add raw files to program output:** `CopyRaw`
 :  Users may specify additional configuration statements for routers
    during declaration within the `/raw` subdirectory, using one file
    per router and the routers name as filename. These files are now
    transferred to the output directory.

## Pass 2

In pass 2, a valid and complete router configuration file is written
for every router, combining its configuration template file and
collected rule information.

### 1. Checking for reusable files

Check, whether configuration files from previous runs can be reused.

* **Reuse files:** `tryPrev`
 :  While new configuration template files and rule files were written
    in pass 1, the old ones have been stored in hidden directory
    `.prev` within the specified output directory. The new files are
    now compared with the old ones, keeping track of those that have
    been altered by the latest run for further processing. For routers
    that have not been affected, configuration files from the previous
    run are transferred to the output directory and reused.

### 2. Optimizing router rule sets

For those routers whose configuration files can not be reused, local
router rulesets are optimized and ACL information is generated from
the optimized ruleset.

* **Optimize router rule set** `optimizeRules`
 :  The routers rule set is now expanded to receive a set of
    elementary rules with exactly one source, destination and
    protocol. This rule set is then optimized by removing duplicate
    and redundant rules.

* **Generate ACL configurations** `prepareAcls`
 :  The routers ACL information is generated from the
    optimized rule set.

### 3. Generating final output

Finally, router configuration files are provided in the specified directory.

* **Write router configuration files:** `printCombined`
 : After the routers configuration template file has been read, its
   contents are printed into the routers final configuration file. Missing ACL
   entries are filled in by writing device specific ACL entries
   derived from the newly generated ACL information.
