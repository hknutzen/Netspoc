---
layout: default
author: Meike Bruns
---


<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

# Technical documentation

On this page, we are going to develop a technical netspoc
documentation describing how Nespoc works
internally. The structure of this documentation will follow the
Netspoc programm procedure, providing a general overview over the
programm as well as orientation when contributing to the source
code. Network architectures are represented and processed by Netspoc
as graphs, with routers and networks as nodes and interfaces as
edges. For better understanding, several pictures are included in this
documentation, using the symbols depicted below. As you
might have noticed, there is no symbol for interfaces included. As
interfaces are needed whenever a network is connected to a router, we
omit their explicit representation.

{% include image.html src="./images/legend.png" description="Legend of used symbols." %}

## Netspocs perspective

Netspoc generates ACLs and static routes for a given network policy,
consisting of a set of services and a network topology. It does so by
finding all paths inside the network topology for a certain source and
destination pair specified in a rule from the service set. It is
important to notice, that the network topology best fed to Netspoc is
not necassarily an exact copy of the real network. Instead, the input
topology should be a model of the network that provides just as much
information as needed for Netspocs purpose. For example, complex parts
of the network with dynamic routing and without filtering are not
affected by Netspoc at all. They should therefore be replaced in the
input topology by a single unmanaged router. This saves time and space
during compilation and is easier to maintain. In very complex network
topologies, even constellations may occur where it is suitable to
include parts of the network twice to reduce complexity. As long as
the ACLs and static routes are not affected, that would also provide a
valid model of the network.

When the abstract topology model created by the user is handed over to
Netspoc, Netspoc takes several steps to transform it into a graph
representation to work on. As before, this representation is not
designed to reproduce reality, but to represent those aspects of the
topology that are important for generating ACLs and static
routes. Moreover, these aspects are modeled to allow completing these
tasks as efficiently as possible.

## Preparing zones and areas

Netspoc combines networks connected by unmanaged routers in
zones. These zones, containing networks and unmanaged routers as
elements, are delimited by zone interfaces of managed or semi-manged
routers. Every zone element is part of exactly one zone. Partitioning
the network topology into zones results in several benefits: Zones can
be used to define attributes for all networks located in a zone, users
may refer to zones as source or destination in rule definition and
finally, zones help to speed up the traversal of the graph. As
filtering takes place only at zone delimiting interfaces, zones can be
traversed instead of single networks.

{% include image.html src="./images/zone.png" description="Zones contain networks and unmanaged routers." %}

Areas, defined in Netspoc topology by the keyword `area`, span a
certain part of the network topology, which is enclosed by the areas
borders. The borders of an area refer to interfaces of managed
routers. While a `border` definition includes the adjacent zone but
excludes the adjacent router from the area, an `inclusive_border`
definition includes the router but not the zone. Areas are used to
define attributes and NAT information for all included managed routers
and networks and may be used by the user as source or destination in
rule definition.

    area:a1 = {
      border = interface:R1.n1;
      inclusive_border = interface:R3.n2;
    }      

{% include image.html src="./images/area.png" description="Areas contain security zones and managed routers." %}


### Creating zones

As every network is contained by exactly one zone, all networks are
processed, creating a new zone object for every network without a
zone. Then a depth first search is conducted beginning at the network
and stopping at managed or semi-managed routers, to collect the zones
elements and border interfaces of a zone object. References to the
zone are set in the collected objects. Zone attributes are set
according to the properties of the included networks.

                
### Identifying zone clusters

Netspoc generates a topology representation to find paths between
sources and destinations, using zones to accelerate graph
traversal. We will see, that Netspoc allows users to refer to security
zones in rules.  From users point of view, security zones look
slightly different from the Netspoc representation though:
Semi-managed routers, which are either unmanaged routers with a path
restriction or managed routers without filtering, appear as unmanaged
routers to the user. Thus, when a user refers to a security zone, a
set of networks is supposed that is internally represented as zone
cluster. Zone clusters contain zones connected by semi-managed routers
and delimited by managed routers.

{% include image.html src="./images/zone_cluster.png" description="Zones: Netspoc representation vs. user view." %}

To generate zone clusters, the zones are processed. If a zone is found
that is not included in a cluster, a new cluster object is
created. Then a depth first search is conducted, starting at the zone
and stopping at managed routers to collect all zones of the cluster.
If the cluster contains a single zone only, it is deleted.

* * * 
The following three steps are not part of zone/area generation,
but are placed inside the set_zone function in source code and
therefore included here.


### Apply no_in_acl declaration

Netspoc allows router interfaces to be tagged as `no_in_acl` 
interfaces, indicating that no ACL is supposed to be generated at the
tagged interface but at the other (outgoing) interfaces of the router
instead. Netspoc distinguishes between logical interface and hardware,
because several networks can be connected to a router via one single
interface hardware. As ACLs are generated for the hardware, all managed
routers with `no_in_acl` interfaces have to be processed, transferring the
tags to the hardware objects of the tagged interfaces, and marking the
routers other hardware objects to need outgoing ACLs.


### Apply crosslink information

Networks just connecting managed routers may be marked as crosslink
networks during topology declaration:

    network:crosslink_network = {ip = 10.2.2.1; crosslink;} 

Routers connected by crosslink networks act as a single router,
causing ACLs to be needed only at the outer interfaces of a
crosslinked router cluster. This holds in cases where the
clustered routers have equal filter types only though. Otherwise, interfaces of
routers with stronger filter types still have to filter information
coming from routers with weaker filter types, letting pass more information.

{% include image.html src="./images/crosslink.png" description="Routers connected by crosslink network." %}

Netspoc processes every crosslink network to identify the adjacent
routers with weakest filter strength. The hardware of the appropriate
interfaces is then tagged with the crosslink flag, indicating that no
ACL needs to be generated.


### Cluster crosslinked routers 

Firewalls recognize, whether the destination of a data packet is the
firewalls interface with IP = 10.1.1.1. or the network with IP =
10.1.1.0/24 connected to this interface, while routers do not. This is
why in router ACLs, access to the interface must be denied if a
permission for the network is given. As Netspoc uses the term `router`
for both routers and firewalls, router devices that need interface
denial in their ACLs are labeled with the `need_protect` flag.

When connected by crosslink networks, some of the interfaces of
 `need_protect` labeled routers will not generate ACLs, relying on the
crosslinked routers to do the filtering. Thus, these routers must be
informed about the interfaces of the `need_protect`-labeled router to
include appropriate deny-clauses in their ACLs.

{% include image.html src="./images/crosslink_with_need_protect.png" description="As no filtering takes place at IF1 and IF4, routers R2 and R3 need to filter packets for IF 1-4." %}

Netspoc identifies clusters of crosslinked routers containing at least
one router labeled with `need_protect`. To do so, a depth first search
is conducted, starting at `need_protect` labeled routers and traversing
routers and crosslink networks only.The interfaces of the clusters
`need_protect` routers are then referenced in every router of the
cluster.

* * *

### Preparing area set up

The border interfaces of an area are referenced in the area object. To
set up the areas, Netspoc needs the information whether an interface
is a border or not, to be available at the interface objects
also. Therefore, references to the limited area are set in border
interfaces now. Along the way, routers that are included in an area via
`inclusive_border` are collected for later use.

### Setting up areas

As was seen above, areas are used to set attributes for routers and
networks included by the areas borders. For this purpose, Netspoc has to
identify the networks and managed routers of every area: Starting at
one of the areas borders, a depth first search is conducted,
traversing the adjacent zones and routers and stopping at the areas
border interfaces. The border type of the start interface indicates
the direction of the traversal: If it is of type `border`, the
adjacent zone is part of the area, while the router is not. If
otherwise the type is `inclusive_border` the router is included in the
area, but not the zone.  Traversed zones and managed routers are collected in
the area object, and references to the area are stored in its zones
and managed routers. If an area object contains no zones, it is deleted.
Netspoc checks for proper border definitions during area set up.

Areas may be defined by the user as anchor areas, that is, without
border definitions, but an anchor network and the attribute
`auto_border` instead. For these areas, depth first search starts at
the zone containing the anchor network and stops at interfaces that
are borders to other areas. References of these interfaces are stored
in the anchor area object as borders.


### Finding subset relations

Areas may be nested, with one area being a proper subset of another
area. Zones and managed routers included by more than one area always
inherit the attributes of the innermost area. For this reason,
intersection of two areas can not be allowed.

{% include image.html src="./images/nested_area.png" description="Area 2 is a proper subset of area 1." %}

Netspoc detects subset relations by processing every zone contained by
one or more areas, identifying all areas containing the zone. Then,
each of these areas is compared with the one next in size to check
whether every zone inside the smaller area is also contained in the
bigger one. A reference to the superset area is added to proper subset
areas. If duplicate areas or areas with intersections are found,
Netspoc will emit an error message.

Of course, proper subset relations have to hold not only for zones,
but also for routers. For most of the routers, proper subset relation
has been assured already by proving subset relations for the
surrounding zones. If routers are placed at the border of an area
though, subset relations can be violated: 

{% include image.html src="./images/areas_overlapping_router.png" description="Overlapping areas with router as intersection." %}

**Routers as intersection.** To prevent overlapping areas with a
single router as intersection, every router contained via
`inclusive_border` is processed: each of the areas containing a
certain router as `inclusive_border` is checked to be in a proper
subset relation with the area next in size regardingthe zones.

{% include image.html src="./images/areas_overlapping_router2.png" description="Wrong border definition of router violates proper subset relation ." %}

**Routers with wrong border classification.** It might happen that
areas forming a proper subset relation regarding their zones are
overlapping because a router is included in the smaller area
but not in the big one. To find such cases, all areas are processed,
checking whether they are a subset of another area. If so, all
managed routers of the smaller area are checked to be included in
the bigger area also.


### Linking aggregates

Users may use the keyword `any` to define aggregates. Aggregates refer
to a set of IP addresses inside a zone and can be used as source or
destination in rules. Internally, aggregates are represented by
network objects with an `is_aggregate` flag set. Aggregates include
either all networks of a zone cluster or, if a specific IP mask is
defined, just those networks of the zone cluster matching the
aggregates IP mask. The zone cluster an aggregate refers to is
specified by its link network, which is a network inside the cluster.

    any:aggregate1 = {link = network:networkA;}
    any:aggregate2 = {link = network:networkB; ip = 10.2.3.0/24;}

Aggregates with no specified IP or IP = 0/0 are used to pass the
aggregates nat definition and owner attributes to the included zones.

Netspoc now processes the aggregates, linking them to the zones of the
zone cluster. Because aggregate objects hold an array of all networks
included by both the aggregare and the linked zone, a new aggregate
object has to be created for every zone to avoid all networks of the
zone cluster being included in the array.  All aggregate objects are
stored within the global network hash for later use.


### Inheriting area attributes

Area attributes are now passed to the zones and managed routers of an
area. To enable inheritance from the innermost area with nested areas,
areas are processed in ascending order regarding their size. For every
area, router attributes are passed on to the areas routers and NAT
attributes are passed to the areas zones. If routers or zones already
have an attribute that is to be passed by the area, either because of
router/zone definitions or because of inheritance from another
(smaller) area, the attribute value is not overwritten. Netspoc
generates a warning though if the area and zone/router values of the
attribute are equal.


### Passing NAT to networks

NAT information is needed within the network objects that are supposed
to have address translation. Netspoc therefore processes all zones
with NAT definitions and passes them to each of the zones networks. If
a NAT attribute of the zone is already set in a network, the networks
NAT attribute is not overwritten, but a warning is emitted if the NAT
attributes values are equal for both zone and network.


## Preparing fast path traversal

Netspoc finds paths inside the network topology. As we have seen
above, zones have been applied to accelerate graph traversal, and
consistently, we will consider the network topology graph to be build
by zones and managed routers (nodes) and interfaces (edges). For a
clearer representation, we will therefore omit the representation of
networks and unmanaged routers in the following pictures. Zones will
be depicted as lines and managed routers by an uncolored router symbol
instead.

{% include image.html src="./images/traversal_graph_representation.png" description="To explain graph traversal, zones will be depicted as lines and managed routers by uncoloured router symbols." %}

* * *
This might be placed somewhere else... or will be replaced anyway...

For the Netspoc approach to find paths from a certain source to a
destination, the topology graph is prepared by a single depth first
search starting at a randomly chosen `zone1`. The distances of the
graphs node objects to `zone1` are identified and stored in the
respective objects. Then, the path from source to destination can be
easily found by starting at source and destination and walking towards
smaller distances/ `zone1` until the paths meet. Loops are contracted
to a single node.

{% include image.html src="./images/find_paths.png" description="Paths are found by walking from source and destination towards zone1." %}

* * *

### Identifying distances and loops 

Netspoc now conducts the depth first search from a randomly chosen
`zone1`. Within every zone and router object reached, the distance
(x2!) to `zone1` is stored. Additionally, the interface leading to
`zone1` is stored in the objects and the zones or routers facing to
`zone1` are stored in every processed interface. Thus, every
interface, router and zone knows where to go to reach `zone1`.

Whenever a loop is found, that is, a node that has already been
discovered is reached again, a loop object is created (Fig. x, 10,
14). This loop object contains the node that has been visited twice as
loop `exit` and the distance of that node to `zone1` +1. Then, Netspoc
returns from recursion and references this loop object in the loop
variable of all nodes located on the loop path (Fig. x, 11-12, 15-21).
As we want all nodes inside a loop to be represented as a single node,
Netspoc needs to recognize nested loops. Whenever Netspoc is on a loop
return path and finds a node already referencing a loop object (Fig.x,
16), the loop objects are compared. The nodes loop reference is then
set to the object of the bigger top level loop (that is, the loop with a lower
distance to `zone1`). Additionally, a reference to the bigger loop
object is set in the `redirect` variable of the smaller sub loop. Thus,
nodes of the sub loop that are not on the loop path of the bigger
loop can be identified later to reset the loop reference.

{% include image.html src="./images/setpath.png" description="Finding loops." %}

When Netspoc is on a loop return path and reaches the exit node of the
loop, a loop exit object is created and referenced in the loop
variable of the exit node (Fig. x, 22). Like the loop object, the loop
exit object stores a reference to the exit node and a distance value,
which is exactly the distance value of the exit node.

The use of different loop objects for loop nodes and loop exit nodes
shows when a special topology is considered (Fig y). In so called
cactus graphs, cycles have single nodes in common. When looking for
paths in such graphs, it is helpful if loops sharing a single node are
represented as different loops and not summarized to one: Different loop
distances help to find the fastes path to `zone1`.  When Netspoc finds
a loop connecting node (Fig. y, 16) different objects for loop and
loop exit allow to keep the already found (green) loop and to
establish the new (orange) loop with a distance closer to
`zone1`. Without different objects, the green loop object would have
been redirected to and included in the orange loop.

{% include image.html src="./images/setpath_obj_cactus.png" description="Finding cactus loops." %}

### Loop preparation

Then, Netspoc iterates over all loop nodes. If a node references a
nested loop in its loop variable, the reference is reset to the top
level containing loop using the information from the redirect variable
of the loop object.

Finally, Netspoc clusters all cactus graph loops by adding a reference
to the exit node of the whole cluster as `cluster_exit` to all loop
objects of the cluster. *TODO:picture?*

### Check for proper pathrestrictions

In cyclic graphs, several paths exists from a destination to a
source. Per default, Netspoc finds all such paths and generates
appropriate ACLs. To exclude paths, pathrestrictions can be
defined. Pathrestrictions refer to 2 or more interfaces inside or at
the borders of a cycle. Netspoc excludes paths including at least 2 of
the interfaces specified in the pathrestriction from ACL generation:
In the picture below, pathrestrictions are defined for interfaces 1
and 2. Therefore, paths from n1 to n5 and n6 are considered during ACL
generation, while the path from n1 to n4 is not. This is reflected in
the interfaces ACLs: traffic between n1 and n4 is not routed by these
interfaces.

{% include image.html src="./images/pathrestriction.png" description="Pathrestrictions on interfaces IF1 and IF2." %}

Netspoc assures all defined pathrestrictions to fulfill the
requirements. Additionally, it is checked whether the defined
pathrestriction have an effect on ACL generation. Proper
pathrestrictions are then stored in a global array.

### Check usage of virtual interfaces

To assure that a connection between two networks will be guaranteed,
they can be connected by more than one router, using HSRP or VRRP and
a virtual IP address to establish a redundant connection.

In Netspoc, such a situation is modelled by additional virtual
interfaces at the participating routers (Fig. )

  and several routers can be established for that connection. these routers share a virtual 
Virtual interfaces are used to provide a redundant connection from one
network to another via different routers. These routers share a
virtual interface with a single ip address. This interface is represented by interfaces with distinct IP addresses, with every participating router providing one. A rank order defines which router is in charge for routing packets through the interfacevirtual interface. In every router participating in the virtual interface, one interface is provided to    
its interfaces representing the virtual interface. If the router in
charge falls apart, the subsequent router will continue the
routing. Obviously, the ACLs of all interfaces participating in the virtual interface have 

Netspoc  

    

 Virtual interfaces are defined at one interface with each of the participating routers  All participating routers, are connected to an interface   