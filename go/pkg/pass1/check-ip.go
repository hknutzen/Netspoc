package pass1

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
)

func (c *spoc) checkIPAddresses() {
	c.checkSubnetOf()
	c.checkIPAddressesAndBridges()
}

func (c *spoc) checkSubnetOf() {
	check := func(n *network) {
		if sn := n.subnetOf; sn != nil {
			ctx := n.descr
			if ctx == "" {
				ctx = n.name
			}
			if sn.ipType == unnumberedIP {
				c.err("Unnumbered %s must not be referenced from"+
					" attribute 'subnet_of'\n of %s", sn, ctx)
				// Prevent further errors;
				n.subnetOf = nil
				return
			}
			if !matchIp(n.ip, sn.ip, sn.mask) {
				c.err("%s is subnet_of %s but its IP doesn't match that's IP/mask",
					ctx, sn)
			}
		}
	}
	checkNat := func(nat map[string]*network) {
		for _, n := range nat {
			check(n)
		}
	}
	for _, n := range c.allNetworks {
		check(n)
		if nat := n.nat; nat != nil {
			checkNat(nat)
		}
	}
	for _, ar := range symTable.area {
		if nat := ar.nat; nat != nil {
			checkNat(nat)
		}
	}
}

func (c *spoc) checkIPAddressesAndBridges() {
	prefix2net := make(map[string][]*network)
	for _, n := range c.allNetworks {
		// Group bridged networks by prefix of name.
		if n.ipType == bridgedIP {
			i := strings.Index(n.name, "/")
			prefix := n.name[:i]
			prefix2net[prefix] = append(prefix2net[prefix], n)
		} else if n.ipType == unnumberedIP {
			l := n.interfaces
			if len(l) > 2 {
				c.err(
					"Unnumbered %s is connected to more than two interfaces:\n%s",
					n.name, l.nameList())
			}
		} else if !(n.ipType == tunnelIP || n.loopback) {
			c.checkIPAddr(n)
		}
	}

	// Check address conflicts for collected parts of bridged networks.
	for _, l := range prefix2net {
		dummy := new(network)
		seen := make(map[*routerIntf]bool)
		for _, n := range l {
			dummy.interfaces = append(dummy.interfaces, n.interfaces...)
			for _, intf := range n.interfaces {
				if l3 := intf.layer3Intf; l3 != nil && !seen[l3] {
					seen[l3] = true
					// Add layer 3 interface for address check.
					dummy.interfaces.push(l3)
				}
			}
			dummy.hosts = append(dummy.hosts, n.hosts...)
		}
		c.checkIPAddr(dummy)
	}

	// Check collected parts of bridged networks.
	c.checkBridgedNetworks(prefix2net)
}

func (c *spoc) checkIPAddr(n *network) {
	ip2name := make(map[string]string)
	redundant := make(map[string]bool)

	// 1. Check for duplicate interface addresses.
	// 2. Short or negotiated interfaces must not be used, if a managed
	//    interface with static routing exists in the same network.
	var shortIntf intfList
	var routeIntf *routerIntf
	for _, intf := range n.interfaces {
		if intf.ipType == shortIP {
			// Ignore short interface from split crypto router.
			if len(intf.router.interfaces) > 1 {
				shortIntf.push(intf)
			}
		} else if intf.ipType == negotiatedIP {
			shortIntf.push(intf)
		} else if intf.ipType != bridgedIP {
			r := intf.router
			if (r.managed != "" || r.routingOnly) &&
				intf.routing == nil && !intf.isLayer3 {

				routeIntf = intf
			}
			ip := intf.ip.String()
			if other, found := ip2name[ip]; found {
				if !(intf.redundant && redundant[other]) {
					c.err("Duplicate IP address for %s and %s", other, intf)
				}
			} else {
				ip2name[ip] = intf.name
				if intf.redundant {
					redundant[intf.name] = true
				}
			}
		}
	}
	if shortIntf != nil && routeIntf != nil {
		c.err("Can't generate static routes for %s"+
			" because IP address is unknown for:\n%s",
			routeIntf, shortIntf.nameList())
	}

	for _, h := range n.hosts {
		if h.ip != nil {
			continue
		}
		lo := h.ipRange[0]
		hi := h.ipRange[1]

		// It is ok for subnet range to overlap with interface IP.
		subnets, _ := splitIpRange(lo, hi)
		if len(subnets) == 1 {
			len, size := subnets[0].Mask.Size()
			if len != size {
				continue
			}
		}

		iterateIPRange(lo, hi, func(ip net.IP) {
			if other, found := ip2name[ip.String()]; found {
				c.err("Duplicate IP address for %s and %s", other, h)
			}
		})
	}

	for _, h := range n.hosts {
		var key string
		if h.ip != nil {
			key = h.ip.String()
		} else {
			key = h.ipRange[0].String() + "-" + h.ipRange[1].String()
		}
		if other, found := ip2name[key]; found {
			c.err("Duplicate IP address for %s and %s", other, h)
		} else {
			ip2name[key] = h.name
		}
	}
}

// Check grouped bridged networks.
// Each group
// - must have the same IP address and mask,
// - must have at least two members,
// - must be adjacent
// - linked by bridged interfaces
// Each router having a bridged interface
// must connect at least two bridged networks of the same group.
func (c *spoc) checkBridgedNetworks(m map[string][]*network) {
	for prefix, _ := range m {
		if n, found := symTable.network[prefix[len("network:"):]]; found {
			c.err(
				"Must not define %s together with bridged networks of same name",
				n)
		}
	}
	for prefix, l := range m {
		n1 := l[0]
		group := l[1:]
		if len(group) == 0 {
			c.warn("Bridged %s must not be used solitary", n1)
		}
		seen := make(map[*router]bool)
		connected := make(map[*network]bool)
		next := netList{n1}
		// Mark all networks connected directly or indirectly with net1
		// by a bridge as 'connected'.
		for len(next) > 0 {
			n2 := next[0]
			next = next[1:]
			if bytes.Compare(n1.ip, n2.ip) != 0 ||
				bytes.Compare(n1.mask, n2.mask) != 0 {
				c.err("%s and %s must have identical ip/mask", n1, n2)
			}
			connected[n2] = true
			for _, in := range n2.interfaces {
				if in.ipType != bridgedIP {
					continue
				}
				r := in.router
				if seen[r] {
					continue
				}
				seen[r] = true
				count := 1
				if l3 := in.layer3Intf; l3 != nil {
					if !matchIp(l3.ip, n1.ip, n1.mask) {
						c.err("%s's IP doesn't match IP/mask of bridged networks",
							l3)
					}
				}
				for _, out := range r.interfaces {
					if out == in || out.ipType != bridgedIP {
						continue
					}
					n3 := out.network
					if !strings.HasPrefix(n3.name, prefix+"/") {
						continue
					}
					next.push(n3)
					count++
				}
				if count == 1 {
					c.err("%s can't bridge a single network", r)
				}
			}
		}
		for _, n2 := range group {
			if !connected[n2] {
				c.err("%s and %s must be connected by bridge", n2, n1)
			}
		}
	}
}

func iterateIPRange(lo, hi net.IP, f func(ip net.IP)) {
	var l, h uint64
	var ip net.IP
	if len(lo) == net.IPv4len && len(hi) == net.IPv4len {
		l = uint64(binary.BigEndian.Uint32(lo))
		h = uint64(binary.BigEndian.Uint32(hi))
		ip = make(net.IP, net.IPv4len)
	} else {
		lo, hi = lo.To16(), hi.To16()
		if bytes.Compare(lo[:8], hi[:8]) != 0 {
			// IP range is too large. Ignore error, it was already checked in
			// splitIpRange.
			return
		}
		l, h = binary.BigEndian.Uint64(lo[8:]), binary.BigEndian.Uint64(hi[8:])
		ip = make(net.IP, net.IPv6len)
		copy(ip, lo)
	}
	for l <= h {
		if len(ip) == net.IPv4len {
			binary.BigEndian.PutUint32(ip, uint32(l))
		} else {
			binary.BigEndian.PutUint64(ip[8:], l)
		}
		f(ip)
		l++
	}
}
