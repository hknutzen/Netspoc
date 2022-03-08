package pass1

import (
	"inet.af/netaddr"
	"sort"
)

//#############################################################################
// Purpose  : Link aggregate and zone via references in both objects, set
//            aggregate properties according to those of the linked zone.
//            Store aggregates in networks (providing all srcs and dsts).
func (c *spoc) linkAggregateToZone(
	agg *network, z *zone, ipp netaddr.IPPrefix) {

	// Link aggregate with zone.
	agg.zone = z
	z.ipPrefix2aggregate[ipp] = agg

	// Set aggregate properties.
	if z.hasIdHosts {
		agg.hasIdHosts = true
	}

	// Store aggregate in global list of networks.
	c.allNetworks.push(agg)
}

//#############################################################################
// Update attributes .networks and .up for implicitly defined aggregates.
// Remember:
// .up is relation inside set of all networks and aggregates.
// .networks is attribute of aggregates and networks,
//           but value is list of networks.
func (c *spoc) linkImplicitAggregateToZone(
	agg *network, z *zone, ipp netaddr.IPPrefix) {

	ipPrefix2aggregate := z.ipPrefix2aggregate

	// Collect all aggregates, networks and subnets of current zone.
	// Get aggregates in deterministic order.
	var objects netList
	var keys []netaddr.IPPrefix
	for k := range ipPrefix2aggregate {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if cmp := keys[i].IP().Compare(keys[j].IP()); cmp != 0 {
			return cmp == -1
		}
		return keys[i].Bits() > keys[j].Bits()
	})
	for _, k := range keys {
		objects.push(ipPrefix2aggregate[k])
	}
	var addSubnets func(n *network)
	addSubnets = func(n *network) {
		for _, s := range n.networks {
			objects.push(s)
			addSubnets(s)
		}
	}
	for _, n := range z.networks {
		objects.push(n)
		addSubnets(n)
	}

	// Find subnets of new aggregate.
	for _, obj := range objects {
		if obj.ipp.Bits() <= ipp.Bits() {
			continue
		}
		if !ipp.Contains(obj.ipp.IP()) {
			continue
		}

		// Ignore sub-subnets, i.e. supernet is smaller than new aggregate.
		if up := obj.up; up != nil {
			if up.ipp.Bits() > ipp.Bits() {
				continue
			}
		}
		obj.up = agg

		//debug("%s -up1-> %s", obj, agg)
		if obj.isAggregate {
			agg.networks = append(agg.networks, obj.networks...)
		} else {
			agg.networks.push(obj)
		}
	}

	// Find supernet of new aggregate.
	// Iterate from smaller to larger supernets.
	// Stop after smallest supernet has been found.
	var larger netList
	for _, obj := range objects {
		if obj.ipp.Bits() < ipp.Bits() {
			larger.push(obj)
		}
	}
	sort.Slice(larger, func(i, j int) bool {
		return larger[i].ipp.Bits() > larger[j].ipp.Bits()
	})
	for _, obj := range larger {
		if obj.ipp.Contains(ipp.IP()) {
			agg.up = obj

			//debug("%s -up2-> %s", agg., obj)
			break
		}
	}

	c.linkAggregateToZone(agg, z, ipp)
}

// Inversed inheritance: If an implicit aggregate has no direct owner
// and if all directly contained networks have the same owner, then
// set owner of this aggregate to found owner of networks.
func propagateOwnerToAggregates(agg *network) {
	cluster := agg.zone.cluster
	ipp := agg.ipp
	var downOwner *owner
	downSet := false
	var upOwner *owner
	upBits := -1
	for _, z := range cluster {
		agg2 := z.ipPrefix2aggregate[ipp]
		inherit := func(n *network) {
			if n.up == agg2 && n.ipType != unnumberedIP {
				if downSet {
					if downOwner != n.owner {
						downOwner = nil
					}
				} else {
					downOwner = n.owner
					downSet = true
				}
			}
		}
		var withSubnets func(netList)
		withSubnets = func(l netList) {
			for _, n := range l {
				inherit(n)
				withSubnets(n.networks)
			}
		}
		withSubnets(z.networks)
		for _, agg3 := range z.ipPrefix2aggregate {
			inherit(agg3)
		}
		// Take owner from smallest network or aggregate in cluster that
		// encloses agg.
		if up := agg.up; up != nil {
			bits := int(up.ipp.Bits())
			if bits > upBits {
				upOwner = up.owner
				upBits = bits
			}
		}
	}
	if downOwner == nil {
		downOwner = upOwner
	}
	// Inherit from area
	if downOwner == nil {
		for a := agg.zone.inArea; a != nil; a = a.inArea {
			if o := a.owner; o != nil {
				downOwner = o
				break
			}
		}
	}
	if downOwner != nil {
		for _, z := range cluster {
			z.ipPrefix2aggregate[ipp].owner = downOwner
		}
	}
}

//#############################################################################
// Purpose  : Create an aggregate object for every zone inside the zones cluster
//            containing the aggregates link-network.
// Comments : From users point of view, an aggregate refers to networks of a zone
//            cluster. Internally, an aggregate object represents a set of
//            networks inside a zone. Therefore, every zone inside a cluster
//            gets its own copy of the defined aggregate to collect the zones
//            networks matching the aggregates IP address.
// TDOD     : Aggregate may be a non aggregate network,
//            e.g. a network with ip/mask 0/0. ??
func (c *spoc) duplicateAggregateToCluster(agg *network, implicit bool) {
	cluster := agg.zone.cluster
	ipp := agg.ipp

	// Process every zone of the zone cluster
	for _, z := range cluster {
		if z.ipPrefix2aggregate[ipp] != nil {
			continue
		}

		// debug("Dupl. %s to %s", agg, to z)

		// Create new aggregate object for every zone inside the cluster
		agg2 := new(network)
		agg2.name = agg.name
		agg2.isAggregate = true
		agg2.ipp = agg.ipp
		agg2.invisible = agg.invisible
		agg2.owner = agg.owner
		agg2.attr = agg.attr

		// Create copy of NAT map for zones in cluster.
		// If same map is used, NAT tags inherited from area would be
		// added multiple times for each cluster element.
		if nat := agg.nat; nat != nil {
			cpy := make(map[string]*network, len(nat))
			for tag, n := range nat {
				cpy[tag] = n
			}
			agg2.nat = cpy
		}

		// Link new aggregate object and cluster
		if implicit {
			c.linkImplicitAggregateToZone(agg2, z, ipp)
		} else {
			c.linkAggregateToZone(agg2, z, ipp)
		}
	}
	if implicit {
		propagateOwnerToAggregates(agg)
	}
}

func (c *spoc) getAny(
	z *zone, ipp netaddr.IPPrefix, visible bool, ctx string) netList {

	cluster := z.cluster
	if z.ipPrefix2aggregate[ipp] == nil {

		// Check, if there is a network with same IP as the requested
		// aggregate. If found, don't create a new aggregate in zone,
		// but use the network instead. Otherwise .up relation
		// wouldn't be well defined.
		var n *network
	CLUSTER:
		for _, z := range cluster {
			for _, n2 := range z.networks {
				if n2.ipp == ipp {
					n = n2
					break CLUSTER
				}
			}
		}
		if n != nil {

			// Handle network like an aggregate.
			n.zone.ipPrefix2aggregate[ipp] = n

			// Create aggregates in cluster, using the name of the network.
			c.duplicateAggregateToCluster(n, true)
		} else {

			// any:[network:x] => any:[ip=i.i.i.i/pp & network:x]
			name := z.name
			if ipp.Bits() != 0 {
				name =
					name[:len("any:[")] + "ip=" + ipp.String() + " & " +
						name[len("any:["):]
			}
			agg := new(network)
			agg.name = name
			agg.isAggregate = true
			agg.ipp = ipp
			agg.invisible = !visible
			agg.ipV6 = z.ipV6

			c.linkImplicitAggregateToZone(agg, z, ipp)
			c.duplicateAggregateToCluster(agg, true)
		}
	}
	var result netList
	var supernet *network
	for _, z := range cluster {
		aggOrNet := z.ipPrefix2aggregate[ipp]
		result.push(aggOrNet)
		if visible {

			// Mark aggregate as visible for findZoneNetworks.
			aggOrNet.invisible = false

			// Find smallest non aggregate supernet of aggregates in
			// cluster for checking error condition.
			// Only needed if result will be visible.
			s := aggOrNet
			for s.isAggregate {
				s = s.up
				if s == nil {
					break
				}
			}
			if s != nil && (supernet == nil || supernet.ipp.Bits() < s.ipp.Bits()) {
				supernet = s
			}
		}
	}
	// Check error condition.
	if supernet != nil {
		for tag, nat := range supernet.nat {
			if !nat.hidden {
				relation := "has address"
				if supernet.ipp.Bits() != ipp.Bits() {
					relation = "is subnet"
				}
				c.err("Must not use any:[ip = %s & ..] in %s\n"+
					" because it %s of %s which is translated by nat:%s",
					ipp, ctx, relation, supernet, tag)
			}
		}
	}
	return result
}
