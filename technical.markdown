---
layout: default
---


<div class="maruku_toc" markdown="1">
* Table of Content
{:toc}
</div>

## Preparing security zones and areas
Function: set_zone
... security zones and areas are established by Netspoc::set_zone...

### Creating security zones
Functions: `set_zone`, `set_zone1`

Netspoc combines networks connected by unmanaged routers in security
zones. These zones, containing networks and unmanaged routers as
elements, are delimited by zone interfaces of managed or
semi-manged routers.

![Security zones contain networks and unmanaged routers.](zone.png)

Every network is contained by only one zone, which is referenced in
the network object. The properties of a zone are described by
atrributes, which can either be set during topology definition or
derived during code procession. (this needs more clarification: in
truth, zones can not be declared in topology - aggragates can. But some
zone attributes are derived from the topology more directly than
others...  )

Possible zone attributes are

* no_in_acl: ACL is not generated at the zone interfaces but ACL information is contained in the ACL of the other interfaces of the corresponding router instead. 
* loopback: zone consists of loopback network only
* is_tunnel: zone consists of tunnel networks only
* private: stores the zones private-status, if not 'public'
* has_id_hosts: ... 

    for every network in networks
      if network has no zone
        create new zone object in global @zones array:
          via depth-first-search starting at zone (stop at managed/semi-managed routers)
            identify zone elements
            reference zone element in zone object, and vice versa
          set zone attributes 
      end if
    end for
                
### Identifying zone clusters
Functions: `set_zone`, `set_zone_cluster`

Netspoc combines zones connected by semi-managed routers in zone clusters:

    for every zone in zones
      if zone has no cluster
        create an empty cluster array
        via depth-first-search starting at zone (stop at managed routers) 
          identify cluster members
          reference zone in cluster array and vice versa
          check all cluster members to have equal private status
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

