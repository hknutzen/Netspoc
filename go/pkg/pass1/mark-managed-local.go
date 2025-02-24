package pass1

import (
	"net/netip"
	"slices"
)

type clusterInfo struct {
	natMap     natMap
	filterOnly []netip.Prefix
	mark       int
}
type managedLocalCluster struct {
	mark  int
	zones []*zone
}

// Find clusters of zones connected by 'local' and semi-managed routers.
//   - Check consistency of attributes.
//   - Set unique attribute localMark for all managed routers
//     belonging to one cluster.
//   - Set attribute managedLocalCluster in all zones in cluster.
//     Zones in same cluster get equal values.
//
// Returns array of cluster infos.
func (c *spoc) getManagedLocalClusters() []clusterInfo {
	mark := 1
	var result []clusterInfo
	for _, r0 := range c.managedRouters {
		if r0.managed != "local" || r0.localMark != 0 {
			continue
		}
		filterOnly := r0.filterOnly

		// IP/mask pairs of current cluster matching filterOnly.
		matched := make(map[netip.Prefix]bool)

		// natMap is known to be identical inside 'local' cluster,
		// because attribute 'bind_nat' is not allowed inside this cluster.
		nm := r0.interfaces[0].natMap

		info := clusterInfo{natMap: nm, mark: mark, filterOnly: filterOnly}
		seen := make(map[*zone]bool)
		var localZones []*zone

		var walk func(r *router)
		walk = func(r *router) {
			r.localMark = mark
			if r.managed == "local" && !slices.Equal(filterOnly, r.filterOnly) {
				c.err("%s and %s must have identical values"+
					" in attribute 'filter_only'", r0.vxName(), r.vxName())
			}

			for _, in := range r.interfaces {
				z := in.zone
				if seen[z] {
					continue
				}
				seen[z] = true
				localZones = append(localZones, z)

				if in.bindNat != nil {
					var reason string
					if r.managed == "local" {
						reason = "with 'managed = local'"
					} else {
						reason = "in zone beside router with 'managed = local'"
					}
					c.err("Attribute 'bind_nat' is not allowed"+
						" at %s %s", in, reason)
				}
				// All networks in local zone must match filterOnly.
			NETWORK:
				for _, n := range z.networks {
					net0 := n.address(nm)
					ip := net0.Addr()
					bits := net0.Bits()
					for _, net := range filterOnly {
						if bits >= net.Bits() && net.Contains(ip) {
							matched[net] = true
							continue NETWORK
						}
					}
					c.err("%s doesn't match attribute 'filter_only' of %s",
						n.vxName(), r.vxName())
				}

				for _, out := range z.interfaces {
					if out == in {
						continue
					}
					r2 := out.router
					switch r2.managed {
					// Semi-managed router may be part of managed=local cluster.
					case "local", "":
						if r2.localMark == 0 {
							walk(r2)
						}
					}
				}
			}
		}

		walk(r0)
		cl := &managedLocalCluster{
			mark:  mark,
			zones: localZones,
		}
		for _, z := range localZones {
			z.managedLocalCluster = cl
		}
		result = append(result, info)
		mark++

		for _, net := range filterOnly {
			if !matched[net] {
				c.warn("Useless 'filter_only = %s' at %s", net, r0)
			}
		}
	}
	return result
}

// Mark networks and aggregates, that are filtered at some
// managed=local devices.
// A network is marked by adding the number of the corresponding
// managed=local cluster as key to a map in attribute filterAt.
func (c *spoc) markManagedLocal() {
	c.network00.filterAt = make(map[int]bool)
	c.network00v6.filterAt = make(map[int]bool)

	for _, cluster := range c.getManagedLocalClusters() {
		mark := cluster.mark
		for _, z := range c.allZones {
			setMark := func(ipp netip.Prefix, n *network) {
				ip := ipp.Addr()
				bits := ipp.Bits()
				for _, net := range cluster.filterOnly {
					if bits >= net.Bits() && net.Contains(ip) {

						// Mark network and enclosing aggregates.
						obj := n
						for obj != nil {
							m := obj.filterAt
							if m == nil {
								m = make(map[int]bool)
								obj.filterAt = m
							} else if m[mark] {
								// Has already been processed as supernet of
								// other network.
								break
							}
							m[mark] = true

							// debug("Filter %s at mark", obj);
							obj = obj.up
						}
					}
				}
			}
			processWithSubnetworks(z.networks, func(n *network) {
				natNetwork := getNatNetwork(n, cluster.natMap)
				if natNetwork.hidden {
					return
				}
				setMark(natNetwork.ipp, n)
			})
			for _, agg := range z.ipPrefix2aggregate {
				setMark(agg.ipp, agg)
			}
		}

		// Rules from general_permit should be applied to all devices
		// with 'managed=local'.
		c.network00.filterAt[mark] = true
		c.network00v6.filterAt[mark] = true
	}
}

// Checks rule where
// - source or destination is some supernet,
// - this supernet is located inside some managed=local cluster
// - and other side of rule is outside of managed=local cluster.
// In this case, the rule would not be filtered inside managed=local cluster
// and hence access from/to subnets in same cluster
// would be allowed by accident.
func (c *spoc) checkManagedLocalSupernets(
	rule *groupedRule, where string,
	supernet *network, gi groupWithPath, info checkInfo, seen map[*zone]bool,
) {
	cl := supernet.zone.managedLocalCluster
	z0 := cl.zones[0]
	mark := cl.mark
	// Check other side of rule.
	// Other side is located in same cluster and hence is filtered.
	switch z := gi.path.getZone().(type) {
	case *zone:
		if cl2 := z.managedLocalCluster; cl2 != nil && z0 == cl2.zones[0] {
			return
		}
	case *router:
		if z.localMark == mark {
			return
		}
	}
	// Other side is not filtered inside cluster.
	var externObj someObj
	for _, obj := range gi.group {
		if !obj.getNetwork().filterAt[mark] {
			externObj = obj
			break
		}
	}
	if externObj == nil {
		return
	}
	ipp := supernet.ipp
	bits := ipp.Bits()
	netMap := info.netMap
	var missing []someObj
	for _, z := range cl.zones {
		if z == supernet.zone {
			continue
		}
		// Aggregate of same size is already part of rule.
		if agg := z.ipPrefix2aggregate[ipp]; agg != nil {
			if _, found := netMap[agg]; found {
				continue
			}
		}
		// Check for subnets of supernet.
		for _, n := range z.networks {
			if n.ipp.Bits() >= bits && ipp.Contains(n.ipp.Addr()) {
				if _, found := netMap[n]; !found {
					missing = append(missing, n)
				}
			}
		}
	}
	if missing == nil {
		return
	}
	seen[z0] = true
	cp := *rule
	if where == "src" {
		cp.src = []someObj{supernet}
		cp.dst = []someObj{externObj}
	} else {
		cp.src = []someObj{externObj}
		cp.dst = []someObj{supernet}
	}
	var r *router
ROUTER:
	for _, z := range cl.zones {
		for _, intf := range z.interfaces {
			if intf.router.managed == "local" {
				r = intf.router
				break ROUTER
			}
		}
	}
	c.showManagedLocalWarning(&cp, where, r, missing)
}

// Checks path of rule at router with managed=local where
// - both sides of rule are located outside of managed=local cluster,
// - source or destination is some supernet,
// - subnet of this supernet is located in managed=local cluster,
// In this case, the rule would not be filtered inside managed=local cluster
// and hence access from/to subnets in same cluster
// would be allowed by accident.
func (c *spoc) checkFilterOnlyAccess(
	rule *groupedRule, where string,
	in *routerIntf, supernet *network, other pathObj, netMap map[*network]bool,
) {
	r := in.router
	mark := r.localMark
	// Supernet is located inside current managed=local cluster.
	// This case has already been checked in checkManagedLocalSupernets.
	if cl := supernet.zone.managedLocalCluster; cl != nil && cl.mark == mark {
		return
	}
	// Other side of rule is located in current managed=local cluster.
	// If both, subnet and other are located inside same managed=local cluster,
	// deny-rules for 'filter_only' prevent access from subnet to other.
	if z, ok := other.(*zone); ok {
		if cl2 := z.managedLocalCluster; cl2 != nil && cl2.mark == mark {
			return
		}
	}
	natNetwork := getNatNetwork(supernet, in.natMap)
	// If natNetwork is hidden, bits is -1 and ipp is the zero value
	// and won't match any other network.
	ipp := natNetwork.ipp
	bits := natNetwork.ipp.Bits()
	cl := in.zone.managedLocalCluster
	var missing []someObj
	for _, z := range cl.zones {
		// Aggregate of same size is already part of rule.
		if agg := z.ipPrefix2aggregate[ipp]; agg != nil {
			if _, found := netMap[agg]; found {
				continue
			}
		}
		// Check for subnets of supernet.
		for _, n := range z.networks {
			if n.ipp.Bits() >= bits && ipp.Contains(n.ipp.Addr()) {
				if _, found := netMap[n]; !found {
					missing = append(missing, n)
				}
			}
		}
	}
	if missing == nil {
		return
	}
	c.showManagedLocalWarning(rule, where, r, missing)
}

func (c *spoc) showManagedLocalWarning(
	rule *groupedRule, where string, r *router, missing []someObj,
) {
	fromTo := "from"
	if where != "src" {
		fromTo = "to"
	}
	c.warnOrErr(
		c.conf.CheckSupernetRules,
		"This supernet rule would permit unexpected access:\n"+
			"  %s\n"+
			" %s with 'managed = local' would allow unfiltered access\n"+
			" %s additional networks:\n"+
			"%s",
		rule.print(),
		r,
		fromTo,
		shortNameList(missing),
	)
}
