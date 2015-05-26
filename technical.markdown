---
layout: default
---


<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

## `set_zone` - Preparing zones and areas

Netspoc combines networks connected by unmanaged routers in
zones. These zones, containing networks and unmanaged routers as
elements, are delimited by zone interfaces of managed or semi-manged
routers. Every zone element is part of exactly one zone. Zones help to
speed up the traversal of the graph: As filtering takes place only at
zone delimiting interfaces, zones can be traversed instead of single
networks.

{% include image.html src="./zone.png" description="Zones contain networks and unmanaged routers." %}

Areas, defined in Netspoc topology by the keyword `area`, span a
certain part of the network topology, which is delimited by the areas
border definitions. The borders of an area refer to the interfaces of
managed routers. While a `border` definition includes the zone but
excludes the router from the area, an `inclusive_border` definition
includes the router also.  Areas are used to define router attributes
and nat information for all included managed routers and networks.

    area:a1 = {
      border = interface:r1.n1;
      inclusive_border = interface:r3,n2;
    }      

{% include image.html src="./area.png" description="Areas contain security zones and managed routers." %}


### Creating zones

As every network is contained by exactly one zone, all networks are
processed, creating a new zone object for every network without a
zone. Then a depth first search is conducted, beginning at the network
and stopping at managed or semi-managed routers to collect the zones
elements and border interfaces in the zone object. References to the
zone are set in the collected objects.
During the procession of networks, the following property-attributes
of the zone are derived from its networks:

* loopback: zone consists of loopback network only
* is_tunnel: zone consists of tunnel networks only
* private: stores the zones private-status, if not 'public'

                
### Identifying zone clusters

Netspoc generates a topology representation to find paths between
source and destination, using zones to accelerate graph traversal. We
will see, that Netspoc allows users to refer to security zones in
rules.  From users point of view, security zones look
slightly different though: Semi-managed routers, which are either
unmanaged routers with a path restriction, or managed routers without
filtering appear as unmanaged routers to the user. When a user refers
to a security zone then, a set of networks is meant, that is
internally represented as zone cluster, containing zones
connected by semi-managed routers and delimited by managed routers.

{% include image.html src="./zone_cluster.png" description="Zones: Netspoc representation vs. user view." %}

For zone cluster generation zones are processed. If a zone is found
that is not included in a cluster, a new cluster object is
created. Then a depth first search is conducted, starting at the zone
and stopping at managed routers to collect all zones of the cluster.
If the cluster contains a single zone only, it is deleted.

* * * 
the following is not part of zone/area generation!place somewhere else?


### Apply no_in_acl declaration

Netspoc allows router interfaces to be tagged as `no_in_acl`
interfaces, indicating that no ACL is supposed to be generated at the
tagged interface but at the other (outgoing) interfaces of the router
instead. Netspoc distinguishes between logical interface and hardware,
because several networks can be connected to a router via one single
interface hardware. As ACLs are generated for the hardware, all managed
routers with `no_in_acl` interfaces are processed now, transfering the
tags to the hardware objects of the tagged interfaces, and marking the
routers other hardware objects to need outgoing ACLs. Along the way,
proper usage of `no_in_acl` is checked:
 
* number of no_in_acl interfaces per router <= 1 
* no usage with routers perticipating in crypto-tunnels
* usage only with router models suitable for outgoing acl
* only at interfaces with one main-interface per hardware


### Apply crosslink information

Networks just connecting managed routers may be marked as crosslink
networks during topology declaration:

    network:network_1 = {ip = 10.2.2.1; crosslink;} 

Routers connected by crosslink networks act as a single router,
causing ACLs to be needed only at the outer interfaces of a
crosslinked router cluster. This holds only in cases where the
clustered routers have equal filter types though. Otherwise, interfaces of
routers with stronger filter types still have to filter information
coming from routers with weaker filter types, that let pass more information.

{% include image.html src="./crosslink.png" description="Routers connected by crosslink network." %}

Netspoc processes every crosslink network to identify the adjacent
routers with weakest filter strength, tagging the hardware of the appropriate
interfaces with the crosslink flag, indicating that no ACL needs to be
generated. Simultaneously, the proper usage of crosslink network is checked: 

* All routers connected by crosslink networks are managed.
* Hardware of crosslink network interfaces is not used for other networks.
* Routers with filtertypes `secondary` and `local` are not included in one router cluster.
* All no_in_acl-interfaces of routers connected by a crosslink network border the same security zone (consistent border definitions are required, as the cluster represents a single router).
* Either all or none of the crosslink networks interfaces use need_out_acl


### Cluster crosslinked routers 

Firewalls recognize, whether the destination of a data packet is the
firewalls interface with IP = 10.1.1.1. or the network with IP =
10.1.1.0/24 connected to this interface, while routers do not. This is
why in router ACLs, access to the interface must be denied if a
permission for the network is given. As Netspoc uses the term 'router'
for both routers and firewalls, router devices that need interface
denial in their ACLs are labeled by the `need-protect` flag.

When connected by crosslink networks, some of the interfaces of
 `need_protect`-labeled routers will not generate ACLs, relying on the
crosslinked routers to do the filtering. Thus, these routers must be
informed about the interfaces of the `need_protect`-labeled router to
include appropriate deny-clauses in their ACLs.

{% include image.html src="./crosslink_with_need_protect.png" description="need_protect Router connected by crosslink network." %}

Netspoc identifies clusters of crosslinked routers containing at least
one router labeled with `need_protect` using depth first search,
starting at `need_protect`labeled routers and traversing routers and
crosslink networks only.The interfaces of the clusters `need_protect`
routers are then referenced in every router of the cluster.


### Preparing area set up

The area borders are defined in the area objects. To set up the areas,
netspoc needs the information whether an interface is an border or not
needs to be available at the interfaces also. Therefore, references to
the limited area are set in border interfaces now. By the way, routers
that are included into an area by inclusive area borders are collected
for later use.

### Setting up areas

As was seen above, areas are used to set attributes for routers and
networks included by the areas borders. To do so, Netspoc has to
identify the networks and managed routers of every area: Starting at
one of the areas borders, a depth first search is conducted,
traversing the adjacent zones and routers and stopping at the areas
border interfaces. The border type of the start interface indicates
the direction of the traversal: If it is of type `border`, the
adjacent zone is part of the area, while the router is not. If
otherwise the type is `inclusive_border` the router is included in the
area, but not the zone.  Every zone and managed router is collected in
the area object, and references to the area are stored in its zones
and managed routers. If an area object contains no zones, it is deleted.
Netspoc checks for proper border definitions during area set up.

Areas may be defined by the user as anchor areas, that
is, without border definitions, but an anchor network instead. For
these areas, depth first search starts at the zone containing the anchor
network and stops at interfaces that are borders to other
areas. References of these interfaces are stored in the anchor area
object as borders.


### Finding subset relations

Areas may be nested, with one area being a proper subset of another
area. Zones and managed routers included by more than one area always
inherit the attributes of the innermost area. For this reason,
intersection of two areas can not be allowed.

{% include image.html src="./nested_area.png" description="Area 2 is a proper subset of area 1." %}

Netspoc detects subset relations by processing every zone contained by
one or more areas, identifying all areas containing the zone. Then,
each of these areas is compared with the one next in size to check
whether every zone inside the samller area is also contained in the
bigger one. A reference to the superset area is added to proper subset
areas. If duplicate areas or areas with intersections are found,
Netspoc will throw an error.

Naturally, proper subset relations have to hold not only for zones,
but also for routers. For most of the routers, proper subset relation
has been assured already by proving subset relations for the
surrounding zones. If the routers are placed at the border of an area
though, subset relations can be violated: 

{% include image.html src="./areas_overlapping_router.png" description="Overlapping areas with router as intersection." %}

**Routers as intersection.** to prevent overlapping areas with a single
router as intersection, every router contained via `inclusive_border`
is processed: each of the areas containing a certain router as
`inclusive_border` is compared with the area next in size to check
whether every zone inside the smaller area is also contained in the
bigger one. If intersecting areas are found, Netspoc will throw an
error.

{% include image.html src="./areas_overlapping_router2.png" description="Wrong border definition of router violates proper subset relation ." %}

**Routers with wrong border classification.** It might happen that
areas forming a proper subset relation regarding their zones are
overlapping just because a router is included in the smaller area
but not in the big one. To find such cases, all areas are processed,
checking whether they are a subset of a bigger area. If so, all
managed routers of the smaller area are checked to be included in
the bigger area also. Netspoc will throw an error, if overlapping areas are found.


### Linking aggregates

Users may use the keyword `any` to define aggregates. Aggregates refer
to a set of networks and can be used as source or destination in
rules. Internally, aggregates are therefore represented by network
objects with an `is_aggregate` flag set. An aggregate includes either
all networks of a zone cluster or, if a specific IP mask is defined,
just those networks of the zone cluster matching the aggregates IP
mask. The zone cluster an aggregate refers to is specified by its link
network, which is a network inside the cluster:

    any:aggregate1 = {link = network:networkA;}
    any:aggregate2 = {link = network:networkB; ip = 10.2.3.0/24;}

Aggregates with no specified IP or IP = 0/0 are used to pass the
aggregates nat definition and owner attributes to the included zones.

Netspoc now processes the aggregates, assuring proper usage of the
aggregates and linking the aggregates to the zones of the zone
cluster. Because aggregate objects hold an array of all networks of
the zone included by the aggregate, several objects have to be build
for a single aggregate when linking aggregates and zones: To avoid all
networks of the zone cluster being included in this array, every zone
needs its own aggregate object.
All aggregates are stored within the global Network hash for later use.


### Inheriting area attributes

Area attributes are now passed to the zones and managed routers of an
area. To enable inheritance from the innermost area when areas are
nested, areas are processed in ascending order regarding their size.
Then, router attributes are passed on to the areas routers and nat
attributes are passed to the areas zones. If routers or zones already
have an attribute of the area set, because of router/zone definitions
or because of inheritance from another (smaller) area, the attribute
value is not overwritten. Netspoc generates a warning though if the
area and zone/router values of the attribute are equal.


### Passing NAT to networks

NAT information is needed within the network objects that are supposed
to have address translation. Netspoc therefore processes all zones
with NAT definitions and passes them to each of the zones networks. If
a NAT attribute of the zone is already set in a network, the networks
NAT attribute is not overwritten, but a warning is emitted if the NAT
attributes values are equal for both zone and network.


* * *
crosslink networks:
(filtertypes, should probably be placed elsewhere:
`primary`/`full`>`standard`>`secondary`>`local`>`local_secondary`).

* no_in_acl: ACL is not generated at the zone interfaces but ACL information is contained in the ACL of the other interfaces of the corresponding router instead. 