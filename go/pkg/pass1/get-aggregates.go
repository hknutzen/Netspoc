package pass1

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// #############################################################################
// linkAggregateToZone links aggregate and zone each to another.
// It sets aggregate properties according to those of the linked zone.
//
//	It Stores aggregates in allNetworks.
func (c *spoc) linkAggregateToZone(agg *network, z *zone) {

	// Link aggregate with zone.
	agg.zone = z
	z.ipPrefix2aggregate[agg.ipp] = agg

	// Set aggregate properties.
	agg.hasIdHosts = z.hasIdHosts

	// Store aggregate in global list of networks.
	c.allNetworks.push(agg)
}

// #############################################################################
// Update attributes .networks and .up for implicitly defined aggregates.
// Remember:
// .up is relation inside set of all networks and aggregates.
// .networks is attribute of aggregates and networks,	but value is list of networks.
func (c *spoc) linkImplicitAggregateToZone(agg *network, z *zone) {

	ipPrefix2aggregate := z.ipPrefix2aggregate

	// Collect all aggregates, networks and subnets of current zone.
	// Get aggregates in deterministic order.
	var objects netList = slices.SortedFunc(maps.Values(ipPrefix2aggregate),
		func(a, b *network) int { return cmp.Compare(a.name, b.name) })
	processWithSubnetworks(z.networks, func(n *network) {
		objects.push(n)
	})

	// Find subnets of new aggregate.
	ipp := agg.ipp
	for _, obj := range objects {
		if obj.ipp.Bits() <= ipp.Bits() {
			continue
		}
		if !ipp.Contains(obj.ipp.Addr()) {
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
	slices.SortFunc(larger, func(a, b *network) int {
		return cmp.Compare(b.ipp.Bits(), a.ipp.Bits())
	})
	for _, obj := range larger {
		if obj.ipp.Contains(ipp.Addr()) {
			agg.up = obj

			//debug("%s -up2-> %s", agg., obj)
			break
		}
	}

	c.linkAggregateToZone(agg, z)
}

// Inversed inheritance: An unnamed aggregate has no direct owner.
// If all directly contained networks and named aggregates have the
// same owner, then set owner of this unnamed aggregate to found owner
// of contained objects.
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
			if n.up == agg2 {
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
		processWithSubnetworks(z.networks, inherit)
		for _, agg3 := range z.ipPrefix2aggregate {
			if !strings.HasPrefix(agg3.name, "any:[") {
				inherit(agg3)
			}
		}
		// Take owner from smallest network or named aggregate in
		// cluster that encloses agg.
		for up := agg.up; up != nil; up = up.up {
			if !strings.HasPrefix(up.name, "any:[") {
				bits := int(up.ipp.Bits())
				if bits > upBits {
					upOwner = up.owner
					upBits = bits
				}
				break
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

func (c *spoc) duplicateAggregateToZone(agg *network, z *zone, implicit bool) {
	clone := func(n *network, z *zone) *network {
		if agg := z.ipPrefix2aggregate[n.ipp]; agg != nil {
			return agg
		}
		// Create new aggregate from aggregate or network and attach it to zone.
		agg := new(network)
		agg.name = n.name
		agg.isAggregate = true
		agg.ipp = n.ipp
		agg.ipV6 = n.ipV6
		agg.invisible = n.invisible
		agg.owner = n.owner
		agg.attr = n.attr
		// Create copy of NAT map for zones in cluster.
		// Otherwise NAT tags inherited from area would be
		// added multiple times for each cluster element.
		agg.nat = maps.Clone(n.nat)
		if implicit {
			c.linkImplicitAggregateToZone(agg, z)
		} else {
			c.linkAggregateToZone(agg, z)
		}
		return agg
	}
	agg2 := clone(agg, z)
	if a6 := agg.combined46; a6 != nil {
		if z2 := z.combined46; z2 != nil {
			a2 := clone(a6, z2)
			agg2.combined46 = a2
			a2.combined46 = agg2
		}
	}
}

/*
#############################################################################
// Purpose  : Create an aggregate object for every zone inside the zones cluster
//            containing the aggregates link-network.
// Comments : From users point of view, an aggregate refers to networks of a zone
//            cluster. Internally, an aggregate object represents a set of
//            networks inside a zone. Therefore, every zone inside a cluster
//            gets its own copy of the defined aggregate to collect the zones
//            networks matching the aggregates IP address.
// TODD     : Aggregate may be a non aggregate network,
//            e.g. a network with ip/mask 0/0. ??
*/
func (c *spoc) duplicateAggregateToCluster(agg *network, implicit bool) {
	// Process every zone of the zone cluster, v4 and dual stack.
	for _, z := range agg.zone.cluster {
		c.duplicateAggregateToZone(agg, z, implicit)
	}
	if a6 := agg.combined46; a6 != nil && a6.ipp.Bits() == 0 {
		// Process v6 only zones.
		for _, z := range a6.zone.cluster {
			c.duplicateAggregateToZone(a6, z, implicit)
		}
	}
	if implicit {
		propagateOwnerToAggregates(agg)
	}
}

func (c *spoc) getAny(z *zone, ipp netip.Prefix, visible bool, ctx string,
) netList {
	var unset netip.Prefix
	if ipp == unset {
		// Make sure to get dual stack zone in mixed v4, v6, v46 cluster.
		if z0 := z.cluster[0]; z0.combined46 != nil {
			z = z0
			if z.ipV6 {
				z = z.combined46
			}
		}
		ipp = c.getNetwork00(z.ipV6).ipp
		result := c.getAny1(z, ipp, visible, ctx)
		// Add non matching aggregate to dual stack zone.
		if z2 := z.combined46; z2 != nil {
			ipp2 := c.getNetwork00(z2.ipV6).ipp
			// Process only once if called from different part of zone cluster
			// or from other side of dual stack zone.
			firstRun := z2.ipPrefix2aggregate[ipp2] == nil
			result = append(result, c.getAny1(z2, ipp2, visible, ctx)...)
			if firstRun {
				c.checkDualStackZone(z2)
				a4 := z.ipPrefix2aggregate[ipp]
				a6 := z2.ipPrefix2aggregate[ipp2]
				if a4.name != a6.name {
					if strings.HasPrefix(a4.name, "network:") {
						c.err("Must not use IPv4 only %s together with dual stack %s",
							a4, z)
					}
					if strings.HasPrefix(a6.name, "network:") {
						c.err("Must not use IPv6 only %s together with dual stack %s",
							a6, z)
					}
				}
				for _, z4 := range z.cluster {
					if z6 := z4.combined46; z6 != nil {
						n4 := z4.ipPrefix2aggregate[ipp]
						n6 := z6.ipPrefix2aggregate[ipp2]
						if n4.name == n6.name {
							n4.combined46 = n6
							n6.combined46 = n4
						}
					}
				}
			}
		}
		return result
	} else {
		return c.getAny1(z, ipp, visible, ctx)
	}
}

func (c *spoc) getAny1(z *zone, ipp netip.Prefix, visible bool, ctx string,
) netList {
	if z.ipPrefix2aggregate[ipp] == nil {

		// Check, if there is a network with same IP as the requested
		// aggregate. If found, don't create a new aggregate in zone,
		// but use the network instead. Otherwise .up relation
		// wouldn't be well defined.
		findNet := func() *network {
			for _, z := range z.cluster {
				for _, n := range z.networks {
					if n.ipp == ipp {
						return n
					}
				}
			}
			return nil
		}
		if n := findNet(); n != nil {

			// Handle network like an aggregate.
			n.zone.ipPrefix2aggregate[ipp] = n
			if n6 := n.combined46; n6 != nil {
				// Must also use IPv6 network as aggregate.
				n6.zone.ipPrefix2aggregate[n6.ipp] = n6
			}

			// Create aggregates in cluster, using the name of the network.
			c.duplicateAggregateToCluster(n, true)
		} else {

			// any:[network:x] => any:[ip=i.i.i.i/pp & network:x]
			name := z.name
			if ipp.Bits() != 0 {
				attr := v6Attr("ip", z.ipV6)
				name =
					name[:len("any:[")] + attr + "=" + ipp.String() + " & " +
						name[len("any:["):]
			}
			agg := new(network)
			agg.name = name
			agg.isAggregate = true
			agg.ipp = ipp
			agg.invisible = !visible
			agg.ipV6 = z.ipV6
			c.linkImplicitAggregateToZone(agg, z)
			c.duplicateAggregateToCluster(agg, true)
		}
	}
	var result netList
	var super *network
	for _, z := range z.cluster {
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
			if s != nil && (super == nil || super.ipp.Bits() < s.ipp.Bits()) {
				super = s
			}
		}
	}
	// Check error condition.
	if super != nil {
		for tag, nat := range super.nat {
			if !nat.hidden {
				relation := "has address"
				if super.ipp.Bits() != ipp.Bits() {
					relation = "is subnet"
				}
				c.err("Must not use any:[%s = %s & ..] in %s\n"+
					" because it %s of %s which is translated by nat:%s",
					v6Attr("ip", super.ipV6),
					ipp, ctx, relation, super, tag)
			}
		}
	}
	return result
}
