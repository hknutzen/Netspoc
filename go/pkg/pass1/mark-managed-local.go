package pass1

import (
	"net"
)

// Find cluster of zones connected by 'local' routers.
// - Check consistency of attributes.
// - Set unique 'local_mark' for all managed routers
//   belonging to one cluster.
// Returns array of cluster infos, a hash with attributes
// - nat_set
// - filter_only
// - mark

type clusterInfo struct {
	natSet     natSet
	filterOnly []*net.IPNet
	mark       int
}

func getManagedLocalClusters() []clusterInfo {
	mark := 1
	var result []clusterInfo
	seen := make(map[*zone]bool)
	for _, r0 := range managedRouters {
		if r0.managed != "local" {
			continue
		}
		if r0.localMark != 0 {
			continue
		}
		filterOnly := r0.filterOnly

		// IP/mask pairs of current cluster matching {filter_only}.
		matched := make(map[*net.IPNet]bool)

		// natSet is known to be identical inside 'local' cluster,
		// because attribute 'bind_nat' is not valid at 'local' routers.
		natSet := r0.interfaces[0].natSet

		info := clusterInfo{natSet: natSet, mark: mark, filterOnly: filterOnly}

		var walk func(r *router)
		walk = func(r *router) {
			r.localMark = mark
			equal := func(f0, f []*net.IPNet) bool {
				if len(f0) != len(f) {
					return false
				}
				for i, addr := range f {
					addr0 := f0[i]
					if !addr0.IP.Equal(addr.IP) {
						return false
					}
					if !net.IP(addr0.Mask).Equal(net.IP(addr.Mask)) {
						return false
					}
				}
				return true
			}
			if !equal(filterOnly, r.filterOnly) {
				errMsg(
					"%s and %s must have identical values in attribute 'filter_only'",
					r0.name, r.name)
			}

			for _, inIntf := range r.interfaces {
				z0 := inIntf.zone
				zoneCluster := z0.zoneCluster
				if zoneCluster == nil {
					zoneCluster = []*zone{z0}
				}
				for _, z := range zoneCluster {
					if seen[z] {
						continue
					}
					seen[z] = true

					// All networks in local zone must match filterOnly.
				NETWORK:
					for _, n := range z.networks {
						net0 := n.address(natSet)
						ip := net0.IP
						prefix, _ := net0.Mask.Size()
						for j, net := range filterOnly {
							i := net.IP
							m := net.Mask
							p, _ := m.Size()
							if prefix >= p && matchIp(ip, i, m) {
								matched[filterOnly[j]] = true
								continue NETWORK
							}
						}
						errMsg("%s doesn't match attribute 'filter_only' of %s",
							n.name, r.name)
					}

					for _, outIntf := range z.interfaces {
						if outIntf == inIntf {
							continue
						}
						r2 := outIntf.router
						if r2.managed != "local" {
							continue
						}
						if r2.localMark != 0 {
							continue
						}
						walk(r2)
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
			size, _ := net.Mask.Size()
			warnMsg("Useless %s/%d in attribute 'filter_only' of %s",
				net.IP, size, r0.name)
		}
	}
	return result
}

// Mark networks and aggregates, that are filtered at some
// managed=local devices.
// A network is marked by adding the number of the corresponding
// managed=local cluster as key to a hash in attribute {filter_at}.
func MarkManagedLocal() {
	network00.filterAt = make(map[int]bool)
	network00v6.filterAt = make(map[int]bool)

	for _, cluster := range getManagedLocalClusters() {
		mark := cluster.mark
		var markNetworks func(netList)
		markNetworks = func(list netList) {
			for _, n := range list {
				markNetworks(n.networks)
				natNetwork := getNatNetwork(n, cluster.natSet)
				if natNetwork.hidden {
					continue
				}
				if natNetwork.unnumbered {
					continue
				}
				ip := natNetwork.ip
				prefix, _ := natNetwork.mask.Size()
				for _, ipNet := range cluster.filterOnly {
					i := ipNet.IP
					m := ipNet.Mask
					p, _ := m.Size()
					if prefix >= p && matchIp(ip, i, m) {

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

							// debug "Filter obj->{name} at mark";
							obj = obj.up
						}
					}
				}
			}
		}
		for _, zone := range zones {
			markNetworks(zone.networks)
		}

		// Rules from general_permit should be applied to all devices
		// with 'managed=local'.
		network00.filterAt[mark] = true
		network00v6.filterAt[mark] = true
	}
}
