---
layout: default
---


<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

## Preparing security zones and areas (`set_zone`)

Netspoc combines networks connected by unmanaged routers in security
zones. These zones, containing networks and unmanaged routers as
elements, are delimited by zone interfaces of managed or semi-manged
routers. Every zone element is part of **at most/exactly?** one zone. Zone
generation allows a faster traversal of the graph: As filtering takes
place only at zone delimiting interfaces, zones can be traversed
instead of single networks.

{% include image.html src="./zone.png" description="Security zones contain networks and unmanaged routers." %}

Areas, defined in Netspoc topology by the keyword `area`, span a
certain part of the network topology, which is delimited by the areas
border definitions (`border`, `inclusive_border`). The borders of an
area refer to the interfaces of managed routers. While a `border`
definition includes the zone but excludes the router from the area, a
`inclusive_border` definition includes the router also.  Areas are
used to define router attributes and nat information for all included
managed routers and networks.

    area:a1 = {
      border = interface:r1.n1;
      inclusive_border = interface:r3,n2;
    }      

{% include image.html src="./area.png" description="Areas contain security zones and managed routers." %}

### Creating security zones (`set_zone`)

As every network is contained by exactly one zone, zone creation
starts at networks without a zone, adding adjacent unmanaged routers
and networks to the zone object recursively.

    for every network
      if network has no zone
        create new zone object
          via depth-first-search (stop at managed/semi-managed routers)
            identify zone elements and borders
            set references in zone elements/borders and zone object
      end if
    end for

During the procession of networks, the following property-attributes
of the zone are derived from its networks:

* loopback: zone consists of loopback network only
* is_tunnel: zone consists of tunnel networks only
* private: stores the zones private-status, if not 'public'
                
### Identifying zone clusters (`cluster_zones`)

Netspoc generates a topology representation to find paths between
source and destination, using zones to accelerate graph traversal.  We
will see, that Netspoc allows users to refer to security zones in
rules.  From users point of view, topology and security zones look
slightly different though: Semi-managed routers, which are either
unmanaged routers with a path restriction, or managed routers without
filtering appear as unmanaged routers to the user. When a user refers
to a security zone then, a set of networks is meant, that is
internally represented as zone cluster, containing security zones
connected by semi-managed routers and delimited by managed routers.

Zone cluster generation starts at zones without cluster and adds
adjacent zones connected by semi-managed routers the cluster object
via depth first search, stopping at managed routers.

    for every zone
      if zone has no cluster
        create an empty cluster
        via depth-first-search (stop at managed routers) 
          identify cluster members
          set references in zone and cluster object
          check cluster members to have equal private status
      end if
    end for

### Apply router declaration `no_in_acl`
Functions: `set_zone`, `check_no_in_acl` 

**originally, zone no-in-acl-declarations were applied here. Because
  function check_no_in_acl includes further processing of
  no_in_acl-declarations which is needed in following functions, this
  not really zone-related task is still conducted during zone setup**
   
Netspoc processes all managed routers and assures proper usage of
no_in_acl corrsponding to following restrictions:
 
* number of no_in_acl interfaces per router <= 1 
* no usage with routers perticipating in crypto-tunnels
* usage only with router models suitable for out-acl
* only one main-interface per hardware

**Further restrictions (both about crosslink networks)are specified in
  policy language documentation, but not tested for here, will
  probably be tested later...**
 
As Netspoc distinguishes between interface and interface hardware
(where ACLs are generated), Netspoc transfers the information to the
hardware by deleting the `{no_in_acl}` attribute from the routers
interface-objects and setting appropriate hardware flags
`{no_in_acl}`,`{need_out_acl}` in the routers hardware objects.

### Apply crosslink information
Functions: `set_zone`, `check_crosslink`

Networks just connecting managed routers may be marked as crosslink
networks during topology declaration:

    network: network_1 = {ip = 10.2.2.1; crosslink;} 

Routers connected by crosslink networks actually act as a single
router, which is why ACLs need to be be created only at the outer
interfaces of a crosslinked router cluster:


{% include image.html src="./crosslink.png" description="Routers connected by crosslink network. If filtertypes of both routers are equally strong, no filtering is needed at the crosslink network interfaces." %}

Netspoc processes every crosslink network assuring following requirements:

* All routers connected by crosslink networks are managed
* Routers with filtertypes `secondary` and `local` are not included in one router cluster ** - why?**
* Interface hardware of crosslink network interfaces is not used for other interfaces/networks
* All no_in_acl-interfaces of a router cluster border on the same security zone(consistent border definitions are required, as the cluster represents a single router) 
* Either all or none of the crosslink networks interfaces use need_out_acl **why?**
 
Netspoc then sets the crosslink flag for crosslink network interfaces
connected to those routers of the cluster that have the weakest filter
type (filtertypes, should probably be placed elsewhere:
`primary`/`full`>`standard`>`secondary`>`local`>`local_secondary`). The
crosslink flag indicates that no ACL needs to be generated at the
corresponing interface. Interfaces belonging to routers of stronger
filter types still need to filter information coming from routers with
lower filter types, which filter less strictly.
 
**Place this somewhere else?** In Netspoc policy language, the term
router is used for both routers and firewalls. While firewalls
recognize data packets destined for themselves without appropriate
information set in the ACL, routers dont. Therefore, ACL generation is
more difficult for routers than for firewalls, and Netspoc router
objects representing real router devices are marked by the
`{need_protect}`attribute.

Then, router clusters are identified using depth first search, applied
on router and crosslink network objects only. For router clusters
containing at least one router with `need_protect` flag set,
references to the the respective interfaces of these routers are saved
within every router object of the cluster. ** why?**

* * *
* no_in_acl: ACL is not generated at the zone interfaces but ACL information is contained in the ACL of the other interfaces of the corresponding router instead. 