package pass1

import (
	"inet.af/netaddr"
	"strings"
)

//###################################################################
// Convert hosts to subnets.
// Mark subnet relation of subnets.
//###################################################################

func (c *spoc) checkHostCompatibility(obj, other *netObj) {
	// This simple test is only valid as long as IP range has no NAT.
	if len(obj.nat) != 0 || len(other.nat) != 0 {
		c.err("Inconsistent NAT definition for %s and %s",
			other.name, obj.name)
	}
	if obj.owner != other.owner {
		c.warn("Inconsistent owner definition for %s and %s",
			other.name, obj.name)
	}
}

func (c *spoc) convertHosts() {
	c.progress("Converting hosts to subnets")
	for _, n := range c.allNetworks {
		if n.ipType == unnumberedIP || n.ipType == tunnelIP {
			continue
		}
		ipv6 := n.ipV6
		var bitstrLen uint8
		if ipv6 {
			bitstrLen = 128
		} else {
			bitstrLen = 32
		}
		subnetAref := make([]map[netaddr.IP]*subnet, bitstrLen)

		// Converts hosts and ranges to subnets.
		// Eliminate duplicate subnets.
		for _, host := range n.hosts {
			var nets []netaddr.IPPrefix
			name := host.name
			id := host.id
			if !host.ip.IsZero() {
				nets = []netaddr.IPPrefix{
					netaddr.IPPrefixFrom(host.ip, getHostPrefix(ipv6))}
				if id != "" {
					switch strings.Index(id, "@") {
					case 0:
						c.err("ID of %s must not start with character '@'", name)
					case -1:
						c.err("ID of %s must contain character '@'", name)
					}
				}
			} else {
				// Convert range.
				l := host.ipRange.Prefixes()
				if id != "" {
					if len(l) > 1 {
						c.err("Range of %s with ID must expand to exactly one subnet",
							name)
					} else if l[0].IsSingleIP() {
						c.err("%s with ID must not have single IP", name)
					} else if strings.Index(id, "@") > 0 {
						c.err("ID of %s must start with character '@'"+
							" or have no '@' at all", name)
					}
				}
				nets = l
			}

			for _, ipp := range nets {
				subnetSize := bitstrLen - ipp.Bits()
				ip2subnet := subnetAref[subnetSize]
				if ip2subnet == nil {
					ip2subnet = make(map[netaddr.IP]*subnet)
					subnetAref[subnetSize] = ip2subnet
				}

				if other := ip2subnet[ipp.IP()]; other != nil {
					c.checkHostCompatibility(&host.netObj, &other.netObj)
					host.subnets = append(host.subnets, other)
				} else {
					s := new(subnet)
					s.name = name
					s.network = n
					s.ipp = ipp
					s.nat = host.nat
					s.owner = host.owner
					s.id = id
					s.ldapId = host.ldapId
					s.radiusAttributes = host.radiusAttributes

					ip2subnet[ipp.IP()] = s
					host.subnets = append(host.subnets, s)
					n.subnets = append(n.subnets, s)
				}
			}
		}

		// Set {up} relation and
		// check compatibility of hosts in subnet relation.
		for i := 0; i < len(subnetAref); i++ {
			ip2subnet := subnetAref[i]
			for ip, subnet := range ip2subnet {
				// Search for enclosing subnet.
				for j := i + 1; j < len(subnetAref); j++ {
					net, _ := ip.Prefix(bitstrLen - uint8(j))
					ip = net.IP()
					if up := subnetAref[j][ip]; up != nil {
						subnet.up = up
						c.checkHostCompatibility(&subnet.netObj, &up.netObj)
						break
					}
				}

				// Use network, if no enclosing subnet found.
				if subnet.up == nil {
					subnet.up = n
				}
			}
		}

		// Find adjacent subnets which build a larger subnet.
		s := n.ipp.Bits()
		networkSize := bitstrLen - s
		for i := 0; i < len(subnetAref); i++ {
			ip2subnet := subnetAref[i]
			if ip2subnet == nil {
				continue
			}
			size := bitstrLen - uint8(i)

			// Identify next supernet.
			upSubnetSize := uint8(i + 1)
			upSize := bitstrLen - upSubnetSize

			// left subnet  10.0.0.16/30
			// as range:    10.0.0.16-10.0.0.19
			// add 1 to get IP of right subnet
			// right subnet 10.0.0.20/30
			for ip, s := range ip2subnet {

				// Don't combine subnets with NAT
				// ToDo: This would be possible if all NAT addresses
				// match too.
				if len(s.nat) != 0 {
					continue
				}

				// Don't combine subnets having radius-ID.
				if s.id != "" {
					continue
				}

				// Only take the left part of two adjacent subnets,
				// where lowest network bit is zero.
				net, _ := ip.Prefix(size)
				upNet, _ := ip.Prefix(upSize)
				if net.IP() != upNet.IP() {
					continue
				}

				// Calculate IP of right part.
				rg := s.ipp.Range()
				nextIp := rg.To().Next()

				// Find corresponding right part
				neighbor := ip2subnet[nextIp]
				if neighbor == nil {
					continue
				}

				s.neighbor = neighbor
				neighbor.hasNeighbor = true
				var up someObj

				if upSubnetSize >= networkSize {

					// Larger subnet is whole network.
					up = n
				} else {
					if upSubnetSize < uint8(len(subnetAref)) {
						if upSub, ok := subnetAref[upSubnetSize][ip]; ok {
							up = upSub
						}
					}
					if up == nil {
						pos := strings.Index(s.name, ":")
						name := "autoSubnet" + s.name[pos:]
						u := new(subnet)
						u.name = name
						u.network = n
						u.ipp = upNet
						u.up = s.up
						upIP2subnet := subnetAref[upSubnetSize]
						if upIP2subnet == nil {
							upIP2subnet = make(map[netaddr.IP]*subnet)
							subnetAref[upSubnetSize] = upIP2subnet
						}
						upIP2subnet[ip] = u
						n.subnets = append(n.subnets, u)
						up = u
					}
				}
				s.up = up
				neighbor.up = up
			}
		}

		// Attribute .up has been set for all subnets now.
		// Do the same for unmanaged interfaces.
		for _, intf := range n.interfaces {
			r := intf.router
			if r.managed == "" && !r.routingOnly {
				intf.up = n
			}
		}
	}
}

// Find adjacent subnets and substitute them by their enclosing subnet.
func combineSubnets(list []someObj) []someObj {
	m := make(map[*subnet]bool)
	var others []someObj
	var subnets []*subnet

	// Find subnets in list.
	for _, obj := range list {
		if s, ok := obj.(*subnet); ok {
			if s.neighbor != nil || s.hasNeighbor {
				subnets = append(subnets, s)
				m[s] = true
				continue
			}
		}
		others = append(others, obj)
	}
	if subnets == nil {
		return others
	}

	// Combine found subnets.
	var networks netList
	again := true
	for again {
		again = false
		for i, s := range subnets {
			neighbor := s.neighbor
			if neighbor == nil {
				continue
			}
			if _, ok := m[neighbor]; !ok {
				continue
			}
			delete(m, s)
			delete(m, neighbor)
			up := s.up
			switch x := up.(type) {
			case *network:
				//debug("Combined %s, %s to %s", s.name, neighbor.name, x.name)
				networks.push(x)
			case *subnet:
				//debug("Combined %s, %s to %s", s.name, neighbor.name, x.name)
				m[x] = true
				subnets[i] = x
				again = true
			}
		}
	}

	// Add combined subnets to others again.
	for _, s := range subnets {
		if m[s] {
			others = append(others, s)
		}
	}
	for _, n := range networks {
		others = append(others, n)
	}
	return others
}

//#######################################################################
// Convert hosts in normalized serviceRules to subnets or to networks.
//#######################################################################

func applySrcDstModifier(group []srvObj) []srvObj {
	var modified []srvObj
	var unmodified []srvObj
	seen := make(map[*network]bool)
	for _, obj := range group {
		var n *network
		switch x := obj.(type) {
		case *host:
			if x.id != "" {
				unmodified = append(unmodified, obj)
				continue
			}
			n = x.network
		case *routerIntf:
			if x.router.managed != "" || x.loopback {
				unmodified = append(unmodified, obj)
				continue
			}
			n = x.network
		case *network:
			unmodified = append(unmodified, obj)
			continue
		}
		if !seen[n] {
			seen[n] = true
			modified = append(modified, n)
		}
	}
	return append(unmodified, modified...)
}

func (c *spoc) convertHostsInRules(sRules *serviceRules) (ruleList, ruleList) {
	c.convertHosts()
	subnetWarningSeen := make(map[*subnet]bool)
	process := func(rules []*serviceRule) ruleList {
		cRules := make(ruleList, 0, len(rules))
		for _, rule := range rules {
			processList := func(l []srvObj, toNet bool, context string) []someObj {
				if toNet {
					l = applySrcDstModifier(l)
				}
				var result []someObj
				subnet2host := make(map[*subnet]*host)
				for _, obj := range l {
					switch x := obj.(type) {
					case *network:
						result = append(result, x)
					case *routerIntf:
						result = append(result, x)
					case *host:
						for _, s := range x.subnets {

							// Handle special case, where network and subnet
							// have identical address.
							// E.g. range = 10.1.1.0-10.1.1.255.
							// Convert subnet to network, because
							// - different objects with identical IP
							//   can't be checked for redundancy properly.
							n := s.network
							if s.ipp.Bits() == n.ipp.Bits() {
								if !n.hasIdHosts && !subnetWarningSeen[s] {
									subnetWarningSeen[s] = true
									c.warn(
										"Use %s instead of %s\n"+
											" because both have identical address",
										n.name, s.name)
								}
								result = append(result, n)
							} else if h := subnet2host[s]; h != nil {
								c.warn("%s and %s overlap in %s of %s",
									x.name, h.name, context, rule.rule.service.name)
							} else {
								subnet2host[s] = x
								result = append(result, s)
							}
						}
					}
				}
				return result
			}
			converted := new(groupedRule)
			converted.serviceRule = rule
			converted.src = processList(rule.src, rule.srcNet, "src")
			converted.dst = processList(rule.dst, rule.dstNet, "dst")
			cRules.push(converted)
		}
		return cRules
	}
	return process(sRules.permit), process(sRules.deny)
}

func (c *spoc) combineSubnetsInRules() {
	c.progress("Combining adjacent subnets")
	process := func(rules ruleList) {
		for _, r := range rules {
			r.src = combineSubnets(r.src)
			r.dst = combineSubnets(r.dst)
		}
	}
	process(c.allPathRules.permit)
	process(c.allPathRules.deny)
}
