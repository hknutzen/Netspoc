package pass1

import (
	"net/netip"
)

// Find cluster of zones connected by 'local' routers.
// - Check consistency of attributes.
// - Set unique attribute localMark for all managed routers
//   belonging to one cluster.
// Returns array of cluster infos, a map with attributes
// - natSet
// - filterOnly
// - mark

type clusterInfo struct {
	natMap     natMap
	filterOnly []netip.Prefix
	mark       int
}

func (c *spoc) getManagedLocalClusters() []clusterInfo {
	mark := 1
	var result []clusterInfo
	seen := make(map[*zone]bool)
	for _, r0 := range c.managedRouters {
		if r0.managed != "local" {
			continue
		}
		if r0.localMark != 0 {
			continue
		}
		filterOnly := r0.filterOnly

		// IP/mask pairs of current cluster matching filterOnly.
		matched := make(map[netip.Prefix]bool)

		// natMap is known to be identical inside 'local' cluster,
		// because attribute 'bind_nat' is not valid at 'local' routers.
		nm := r0.interfaces[0].natMap

		info := clusterInfo{natMap: nm, mark: mark, filterOnly: filterOnly}

		var walk func(r *router)
		walk = func(r *router) {
			r.localMark = mark
			equal := func(f0, f []netip.Prefix) bool {
				if len(f0) != len(f) {
					return false
				}
				for i, ipp := range f {
					if f0[i] != ipp {
						return false
					}
				}
				return true
			}
			if !equal(filterOnly, r.filterOnly) {
				c.err("%s and %s must have identical values"+
					" in attribute 'filter_only'", r0, r)
			}

			for _, in := range r.interfaces {
				z0 := in.zone
				cluster := z0.cluster
				for _, z := range cluster {
					if seen[z] {
						continue
					}
					seen[z] = true

					// All networks in local zone must match filterOnly.
				NETWORK:
					for _, n := range z.networks {
						net0 := n.address(nm)
						ip := net0.Addr()
						bits := net0.Bits()
						for j, net := range filterOnly {
							if bits >= net.Bits() && net.Contains(ip) {
								matched[filterOnly[j]] = true
								continue NETWORK
							}
						}
						c.err("%s doesn't match attribute 'filter_only' of %s", n, r)
					}

					for _, out := range z.interfaces {
						if out == in {
							continue
						}
						r2 := out.router
						if r2.managed == "local" && r2.localMark == 0 {
							walk(r2)
						}
					}
				}
			}
		}

		walk(r0)
		result = append(result, info)
		mark++

		for j, net := range filterOnly {
			if matched[filterOnly[j]] {
				continue
			}
			c.warn("Useless 'filter_only = %s' at %s", net, r0)
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
		for _, zone := range c.allZones {
			processWithSubnetworks(zone.networks, func(n *network) {
				natNetwork := getNatNetwork(n, cluster.natMap)
				if natNetwork.hidden {
					return
				}
				ip := natNetwork.ipp.Addr()
				bits := natNetwork.ipp.Bits()
				for _, net := range cluster.filterOnly {
					if bits >= net.Bits() && net.Contains(ip) {

						// Mark network and enclosing aggregates.
						obj := n
						for obj != nil {
							m := obj.filterAt
							if m == nil {
								m = make(map[int]bool)
								obj.filterAt = m
							}

							// Has already been processed as supernet of
							// other network.
							if m[mark] {
								break
							}
							m[mark] = true

							// debug("Filter %s at mark", obj);
							obj = obj.up
						}
					}
				}
			})
		}

		// Rules from general_permit should be applied to all devices
		// with 'managed=local'.
		c.network00.filterAt[mark] = true
		c.network00v6.filterAt[mark] = true
	}
}
