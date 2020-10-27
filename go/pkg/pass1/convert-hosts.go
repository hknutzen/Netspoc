package pass1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

//###################################################################
// Convert hosts to subnets.
// Mark subnet relation of subnets.
//###################################################################

// Convert an IP range to a set of covering net.IPNet.
func splitIpRange(lo, hi net.IP) ([]net.IPNet, error) {
	var l, h uint64
	var result []net.IPNet
	if len(lo) == 4 && len(hi) == 4 {
		l = uint64(binary.BigEndian.Uint32(lo))
		h = uint64(binary.BigEndian.Uint32(hi))
	} else {
		lo, hi = lo.To16(), hi.To16()
		if bytes.Compare(lo[:8], hi[:8]) != 0 {
			return result, fmt.Errorf(
				"IP range doesn't fit into /64 network")
		}
		l, h = binary.BigEndian.Uint64(lo[8:]), binary.BigEndian.Uint64(hi[8:])
	}
	if l > h {
		return result, fmt.Errorf("Invalid IP range")
	}
	add := func(i, m uint64) {
		var ip net.IP
		var mask net.IPMask
		if len(lo) == net.IPv4len {
			ip = make(net.IP, net.IPv4len)
			binary.BigEndian.PutUint32(ip, uint32(i))
			mask = make(net.IPMask, net.IPv4len)
			binary.BigEndian.PutUint32(mask, uint32(m))
		} else {
			ip = make(net.IP, net.IPv6len)
			copy(ip, lo)
			binary.BigEndian.PutUint64(ip[8:], i)
			mask = net.CIDRMask(64, 128)
			binary.BigEndian.PutUint64(mask[8:], m)
		}
		result = append(result, net.IPNet{IP: ip, Mask: mask})
	}

IP:
	for l <= h {
		// 255.255.255.255, 127.255.255.255, ..., 0.0.0.3, 0.0.0.1, 0.0.0.0
		var invMask uint64 = 0xffffffffffffffff
		for {
			if l&invMask == 0 {
				end := l | invMask
				if end <= h {
					add(l, ^invMask)
					l = end + 1
					continue IP
				}
			}
			if invMask == 0 {
				break
			}
			invMask >>= 1
		}
	}
	return result, nil
}

func ipNATEqual(n1, n2 map[string]net.IP) bool {
	if len(n1) != len(n2) {
		return false
	}
	for tag, ip1 := range n1 {
		ip2, ok := n2[tag]
		if !ok {
			return false
		}
		if !ip1.Equal(ip2) {
			return false
		}
	}
	return true
}

func (c *spoc) checkHostCompatibility(obj, other *netObj) {
	if !ipNATEqual(obj.nat, other.nat) {
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
	for _, n := range allNetworks {
		if n.unnumbered || n.tunnel {
			continue
		}
		ipv6 := n.ipV6
		var bitstrLen int
		if ipv6 {
			bitstrLen = 128
		} else {
			bitstrLen = 32
		}
		subnetAref := make([]map[string]*subnet, bitstrLen)

		// Converts hosts and ranges to subnets.
		// Eliminate duplicate subnets.
		for _, host := range n.hosts {
			var nets []net.IPNet
			name := host.name
			id := host.id
			if ip := host.ip; ip != nil {
				nets = []net.IPNet{{IP: ip, Mask: getHostMask(ipv6)}}
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
				l, err := splitIpRange(host.ipRange[0], host.ipRange[1])
				if err != nil {
					c.err("%s in %s", err, name)
				}
				if id != "" {
					if len(l) > 1 {
						c.err("Range of %s with ID must expand to exactly one subnet",
							name)
					} else if isHostMask(l[0].Mask) {
						c.err("%s with ID must not have single IP", name)
					} else if strings.Index(id, "@") > 0 {
						c.err("ID of %s must start with character '@'"+
							" or have no '@' at all", name)
					}
				}
				nets = l
			}

			for _, net := range nets {
				size, _ := net.Mask.Size()
				subnetSize := bitstrLen - size
				str2subnet := subnetAref[subnetSize]
				if str2subnet == nil {
					str2subnet = make(map[string]*subnet)
					subnetAref[subnetSize] = str2subnet
				}

				if other := str2subnet[string(net.IP)]; other != nil {
					c.checkHostCompatibility(&host.netObj, &other.netObj)
					host.subnets = append(host.subnets, other)
				} else {
					s := new(subnet)
					s.name = name
					s.network = n
					s.ip = net.IP
					s.mask = net.Mask
					s.nat = host.nat
					s.owner = host.owner
					s.id = id
					s.ldapId = host.ldapId
					s.radiusAttributes = host.radiusAttributes

					str2subnet[string(net.IP)] = s
					host.subnets = append(host.subnets, s)
					n.subnets = append(n.subnets, s)
				}
			}
		}

		// Set {up} relation and
		// check compatibility of hosts in subnet relation.
		for i := 0; i < len(subnetAref); i++ {
			ip2subnet := subnetAref[i]
			if ip2subnet == nil {
				continue
			}

			for ipStr, subnet := range ip2subnet {
				ip := net.IP(ipStr)
				// Search for enclosing subnet.
				for j := i + 1; j < len(subnetAref); j++ {
					mask := net.CIDRMask(bitstrLen-j, bitstrLen)
					ip = ip.Mask(mask)
					if up := subnetAref[j][string(ip)]; up != nil {
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
		s, bits := n.mask.Size()
		networkSize := bitstrLen - s
		for i := 0; i < len(subnetAref); i++ {
			ip2subnet := subnetAref[i]
			if ip2subnet == nil {
				continue
			}
			mask := net.CIDRMask(bitstrLen-i, bits)

			// Identify next supernet.
			upSubnetSize := i + 1
			upMask := net.CIDRMask(bitstrLen-upSubnetSize, bits)

			// Network mask and supernet mask differ in one bit.
			// This bit distinguishes left and right subnet of supernet:
			// mask (/30)                   255.255.255.11111100
			// xor upmask (/29)            ^255.255.255.11111000
			// equals next bit             =  0.  0.  0.00000100
			// left subnet  10.0.0.16/30 ->  10.  0.  0.00010000
			// right subnet 10.0.0.20/30 ->  10.  0.  0.00010100
			next := make(net.IP, len(mask))
			for i := 0; i < len(mask); i++ {
				next[i] = upMask[i] ^ mask[i]
			}

			for ipStr, s := range ip2subnet {
				ip := net.IP(ipStr)

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
				if !ip.Mask(mask).Equal(ip.Mask(upMask)) {
					continue
				}

				nextIp := make(net.IP, len(ip))
				for i := 0; i < len(ip); i++ {
					nextIp[i] = ip[i] | next[i]
				}

				// Find corresponding right part
				neighbor := ip2subnet[string(nextIp)]
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
					if upSubnetSize < len(subnetAref) {
						if upSub, ok := subnetAref[upSubnetSize][string(ip)]; ok {
							up = upSub
						}
					}
					if up == nil {
						pos := strings.Index(s.name, ":")
						name := "autoSubnet" + s.name[pos:]
						u := new(subnet)
						u.name = name
						u.network = n
						u.ip = ip
						u.mask = upMask
						u.up = s.up
						upIP2subnet := subnetAref[upSubnetSize]
						if upIP2subnet == nil {
							upIP2subnet = make(map[string]*subnet)
							subnetAref[upSubnetSize] = upIP2subnet
						}
						upIP2subnet[string(ip)] = u
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

var subnetWarningSeen = make(map[*subnet]bool)

func (c *spoc) convertHostsInRules(sRules *serviceRules) (ruleList, ruleList) {
	c.convertHosts()
	process := func(rules []*serviceRule) ruleList {
		cRules := make(ruleList, 0, len(rules))
		for _, rule := range rules {
			processList := func(list []srvObj, context string) []someObj {
				var result []someObj
				subnet2host := make(map[*subnet]*host)
				for _, obj := range list {
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
							if bytes.Compare(s.mask, n.mask) == 0 {
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
			if rule.srcNet {
				rule.src = applySrcDstModifier(rule.src)
			}
			if rule.dstNet {
				rule.dst = applySrcDstModifier(rule.dst)
			}
			converted := new(groupedRule)
			converted.serviceRule = rule
			converted.src = processList(rule.src, "src")
			converted.dst = processList(rule.dst, "dst")
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
