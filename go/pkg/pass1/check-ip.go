package pass1

import (
	"golang.org/x/exp/maps"
	"net/netip"
	"sort"
	"strings"

	"go4.org/netipx"
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
			if !sn.ipp.Contains(n.ipp.Addr()) {
				c.err("%s is subnet_of %s but its IP doesn't match that's IP/mask",
					ctx, sn)
			}
		}
	}
	checkNat := func(nat natTagMap) {
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
	for _, ar := range c.symTable.area {
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
			prefix, _, _ := strings.Cut(n.name, "/")
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
	// Sort prefix names for deterministic error messages.
	prefixes := maps.Keys(prefix2net)
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		l := prefix2net[prefix]
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

		// Check collected parts of bridged networks.
		c.checkBridgedNetworks(prefix, l)
	}
}

func (c *spoc) checkIPAddr(n *network) {
	ip2name := make(map[netip.Addr]string)
	redundant := make(map[string]bool)

	// 1. Check for duplicate interface addresses.
	// 2. Short or negotiated interfaces must not be used, if a managed
	//    interface with static routing exists in the same network.
	var shortIntf intfList
	var bridgedIntf intfList
	var routeIntf *routerIntf
	for _, intf := range withSecondary(n.interfaces) {
		switch intf.ipType {
		case shortIP:
			// Ignore short interface from split crypto router.
			if len(intf.router.interfaces) > 1 {
				shortIntf.push(intf)
			}
		case negotiatedIP:
			shortIntf.push(intf)
		case bridgedIP:
			bridgedIntf.push(intf)
		default:
			r := intf.router
			if (r.managed != "" || r.routingOnly) &&
				intf.routing == nil && !intf.isLayer3 {

				routeIntf = intf
			}
			ip := intf.ip
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

	// Optimization: No need to collect .routeInZone at bridge router.
	if routeIntf == nil {
		for _, intf := range bridgedIntf {
			intf.routing = routingInfo["dynamic"]
		}
	}

	range2name := make(map[netipx.IPRange]string)
	for _, h := range n.hosts {
		if h.ip.IsValid() {
			continue
		}
		rg := h.ipRange
		if other, found := range2name[rg]; found {
			c.err("Duplicate IP address for %s and %s", other, h)
		} else {
			range2name[rg] = h.name
		}

		subnets := h.ipRange.Prefixes()
		if len(subnets) == 1 {
			if !subnets[0].IsSingleIP() {
				// It is ok for subnet range to overlap with interface IP.
				continue
			}
		}
		for ip, other := range ip2name {
			if rg.Contains(ip) {
				c.err("Duplicate IP address for %s and %s", other, h)
			}
		}
	}

	for _, h := range n.hosts {
		if h.ip.IsValid() {
			if other, found := ip2name[h.ip]; found {
				c.err("Duplicate IP address for %s and %s", other, h)
			} else {
				ip2name[h.ip] = h.name
			}
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
func (c *spoc) checkBridgedNetworks(prefix string, l netList) {
	if n, found := c.symTable.network[prefix[len("network:"):]]; found {
		c.err(
			"Must not define %s together with bridged networks of same name",
			n)
	}
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
		if n1.ipp != n2.ipp {
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
			single := true
			if l3 := in.layer3Intf; l3 != nil {
				if !n1.ipp.Contains(l3.ip) {
					c.err("%s's IP doesn't match IP/mask of bridged networks",
						l3)
				}
			}
			for _, out := range r.interfaces {
				if out != in && out.ipType == bridgedIP {
					next.push(out.network)
					single = false
				}
			}
			if single {
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
