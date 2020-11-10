package pass1

import (
	"bytes"
	"net"
	"sort"
	"strconv"
	"strings"
)

//#############################################################################
// Purpose  : Link aggregate and zone via references in both objects, set
//            aggregate properties according to those of the linked zone.
//            Store aggregates in networks (providing all srcs and dsts).
func (c *spoc) linkAggregateToZone(agg *network, z *zone, key ipmask) {

	// Link aggregate with zone.
	agg.zone = z
	z.ipmask2aggregate[key] = agg

	// Set aggregate properties.
	if z.hasIdHosts {
		agg.hasIdHosts = true
	}

	// Store aggregate in global list of networks.
	c.allNetworks.push(agg)
}

//#############################################################################
// Update attributes .networks, .up and .owner for implicitly defined
// aggregates.
// Remember:
// .up is relation inside set of all networks and aggregates.
// .networks is attribute of aggregates and networks,
//            but value is list of networks.
func (c *spoc) linkImplicitAggregateToZone(agg *network, z *zone, key ipmask) {

	ip := net.IP(key.ip)
	mask := net.IPMask(key.mask)

	ipmask2aggregate := z.ipmask2aggregate

	// Collect all aggregates, networks and subnets of current zone.
	// Get aggregates in deterministic order.
	var objects netList
	var keys []ipmask
	for k, _ := range ipmask2aggregate {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		switch strings.Compare(keys[i].ip, keys[j].ip) {
		case -1:
			return true
		case 1:
			return false
		}
		return strings.Compare(keys[i].mask, keys[j].mask) == 1
	})
	for _, k := range keys {
		objects.push(ipmask2aggregate[k])
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
		if bytes.Compare(obj.mask, mask) != 1 {
			continue
		}
		if !matchIp(obj.ip, ip, mask) {
			continue
		}

		// Ignore sub-subnets, i.e. supernet is smaller than new aggregate.
		if up := obj.up; up != nil {
			if bytes.Compare(up.mask, mask) == 1 {
				continue
			}
		}
		obj.up = agg

		//debug("%s -up1-> %s", obj.name, agg.name)
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
		if bytes.Compare(obj.mask, mask) == -1 {
			larger.push(obj)
		}
	}
	sort.Slice(larger, func(i, j int) bool {
		return bytes.Compare(larger[i].mask, larger[j].mask) == 1
	})
	for _, obj := range larger {
		if matchIp(ip, obj.ip, obj.mask) {
			agg.up = obj

			//debug("%s -up2-> %s", agg.name, obj.name)
			break
		}
	}

	c.linkAggregateToZone(agg, z, key)
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
	cluster := agg.zone.zoneCluster
	ip := agg.ip
	mask := agg.mask
	key := ipmask{string(ip), string(mask)}

	// Process every zone of the zone cluster
	for _, z := range cluster {
		if z.ipmask2aggregate[key] != nil {
			continue
		}

		// debug("Dupl. %s to %s", agg.name, to z.name)

		// Create new aggregate object for every zone inside the cluster
		agg2 := new(network)
		agg2.name = agg.name
		agg2.isAggregate = true
		agg2.ip = agg.ip
		agg2.mask = agg.mask
		agg2.invisible = agg.invisible
		agg2.owner = agg.owner
		agg2.attr = agg.attr

		// Link new aggregate object and cluster
		if implicit {
			c.linkImplicitAggregateToZone(agg2, z, key)
		} else {
			c.linkAggregateToZone(agg2, z, key)
		}
	}
}

func (c *spoc) getAny(
	z *zone, ip net.IP, mask net.IPMask, visible bool) netList {

	if ip == nil {
		ip = getZeroIp(z.ipV6)
		mask = getZeroMask(z.ipV6)
	}
	key := ipmask{string(ip), string(mask)}
	cluster := z.zoneCluster
	if z.ipmask2aggregate[key] == nil {

		// Check, if there is a network with same IP as the requested
		// aggregate. If found, don't create a new aggregate in zone,
		// but use the network instead. Otherwise .up relation
		// wouldn't be well defined.
		findNet := func(z *zone) *network {
			for _, n := range z.networks {
				if n.ip.Equal(ip) && bytes.Compare(n.mask, mask) == 0 {
					return n
				}
			}
			return nil
		}
		var net *network
		if cluster != nil {
			for _, z := range cluster {
				if net = findNet(z); net != nil {
					break
				}
			}
		} else {
			net = findNet(z)
		}
		if net != nil {

			// Handle network like an aggregate.
			net.zone.ipmask2aggregate[key] = net

			// Create aggregates in cluster, using the name of the network.
			if cluster != nil {
				c.duplicateAggregateToCluster(net, true)
			}
		} else {

			// any:[network:x] => any:[ip=i.i.i.i/pp & network:x]
			name := z.name
			if prefix, _ := mask.Size(); prefix != 0 {
				name =
					name[:5] +
						"ip=" + ip.String() + "/" + strconv.Itoa(prefix) + " & " +
						name[5:]
			}
			agg := new(network)
			agg.name = name
			agg.isAggregate = true
			agg.ip = ip
			agg.mask = mask
			agg.invisible = !visible
			agg.ipV6 = z.ipV6

			c.linkImplicitAggregateToZone(agg, z, key)
			if cluster != nil {
				c.duplicateAggregateToCluster(agg, true)
			}
		}
	}
	var result netList
	process := func(z *zone) {

		// Ignore zone having no aggregate from unnumbered network.
		aggOrNet := z.ipmask2aggregate[key]
		if aggOrNet == nil {
			return
		}

		result.push(aggOrNet)

		if visible {

			// Mark aggregate as visible for find_zone_networks.
			aggOrNet.invisible = false

			// Check for error condition only if result will be visible.
			for _, nat := range aggOrNet.nat {
				if !nat.hidden {
					pIp := ip.String()
					prefix, _ := mask.Size()
					c.err("Must not use aggregate with IP " +
						pIp + "/" + strconv.Itoa(prefix) +
						" in " + z.name + "\n" +
						" because " + aggOrNet.name +
						" has identical IP but is also translated by NAT")
				}
			}
		}
	}
	if cluster != nil {
		for _, z := range cluster {
			process(z)
		}
	} else {
		process(z)
	}
	return result
}
