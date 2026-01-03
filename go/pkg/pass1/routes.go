package pass1

import (
	"fmt"
	"slices"
)

/*
############################################################################
findActiveRoutes generates and stores routing information for all
managed interfaces.
*/
func (c *spoc) findActiveRoutes() {
	c.progress("Finding routes")

	// Mark interfaces of unmanaged routers such that no routes are collected.
	for _, r := range c.allRouters {
		if r.semiManaged && !r.routingOnly {
			for _, intf := range r.interfaces {
				intf.routing = routingInfo["dynamic"]
			}
		}
	}

	// Generate navigation information for routing inside zones.
	for _, z := range c.allZones {
		c.setRoutesInZone(z)
	}

	// Generate pseudo rule set with all src dst pairs to determine routes for.
	tree := c.generateRoutingTree()

	// Generate routing info for every pseudo rule and store it in interfaces.
	c.generateRoutingInfo(tree)

	c.checkAndConvertRoutes()
}

type netMap map[*network]bool

/*
#############################################################################
Get networks for routing.
Add largest supernet inside the zone, if available.
This is needed, because we use the supernet in secondary optimization too.
Moreover this reduces the number of routing entries.
It isn't sufficient to solely use the supernet because network and supernet
can have different next hops at end of path.
For an aggregate, take all matching networks inside the zone.
These are supernets by design.
*/
func getRouteNetworks(l []someObj) netMap {
	m := make(netMap)
LIST:
	for _, obj := range l {
		var n *network
		switch x := obj.(type) {
		case *network:
			if x.isAggregate {
				for _, n := range x.networks {
					m[n] = true
				}
				continue LIST
			}
			n = x
		case *subnet:
			n = x.network
		case *routerIntf:
			n = x.network
		}
		if max := n.maxRoutingNet; max != nil {
			m[max] = true
		}
		m[n] = true
	}
	return m
}

/*
#############################################################################
setRoutesInZone provides routing information inside a security zone.

Parameters:
- z - a zone object.

Results:
Every zone border interface I contains a map routeInZone, keeping the
zones networks N reachable from I as keys and the next hop interface H
towards N as values.

Comments:
A cluster is a maximal set of connected networks of the security
zone surrounded by hop interfaces. Clusters can be empty.

Optimization:
A default route I.routeInZone[nil] = H is stored for those
border interfaces, that reach networks in zone via a single hop.
*/
func (c *spoc) setRoutesInZone(z *zone) {

	// Check if zone needs static routing at all.
	needRoutes := false
	// Collect networks at zone border and next hop interfaces in lookup maps.
	borderNetworks := make(netMap)
	hopInterfaces := make(map[*routerIntf]bool)
	// Collect networks at zones interfaces as border networks.
	for _, in := range z.interfaces {
		n := in.network
		if borderNetworks[n] {
			continue
		}
		// Collect non border interfaces of the networks as next hop interfaces.
		for _, out := range n.interfaces {
			if out.zone == nil {
				hopInterfaces[out] = true
			}
		}
		// Border network is only needed later, if static routes are generated.
		if in.routing == nil {
			borderNetworks[n] = true
			needRoutes = true
		}
	}
	if len(hopInterfaces) == 0 || !needRoutes {
		return
	}

	// Zone preprocessing: define set of networks surrounded by hop
	// intf (cluster) via depth first search to accelerate later DFS
	// runs starting at hop intfs.

	// Store hop interfaces as key and reached clusters as values.
	type cluster netMap
	hop2cluster := make(map[*routerIntf]*cluster)
	// Store directly linked border networks for clusters.
	cluster2borders := make(map[*cluster]netMap)
	var setCluster func(*router, *routerIntf, *cluster)

	setCluster = func(r *router, in *routerIntf, cl *cluster) {
		if r.activePath {
			return
		}
		r.activePath = true
		defer func() { r.activePath = false }()

		// Process every interface.
		for _, intf := range r.interfaces {

			// Found hop interface. Add its entries on the fly and skip.
			if hopInterfaces[intf] {
				hop2cluster[intf] = cl
				n := intf.network
				cluster2borders[cl][n] = true
				continue
			}
			if intf == in {
				continue
			}

			// Add network behind interface to cluster.
			n := intf.network
			if (*cl)[n] {
				continue
			}
			(*cl)[n] = true

			// Recursively proceed with adjacent routers.
			for _, out := range n.interfaces {
				if out != intf {
					setCluster(out.router, out, cl)
				}
			}
		}
	}

	// Identify network cluster for every hop interface.
	for intf := range hopInterfaces {
		// Hop interface was processed before.
		if hop2cluster[intf] != nil {
			continue
		}
		cl := make(cluster)
		cluster2borders[&cl] = make(netMap)
		setCluster(intf.router, intf, &cl)

		//	debug("Cluster: intf->{name} ",
		//             join ',', map {$_->{name}} values %clust);
	}

	// Perform depth first search to collect all networks behind a hop
	// interface.
	// Map to store the collected sets.
	hop2netMap := make(map[*routerIntf]netMap)
	var setNetworksBehind func(*routerIntf, *network)
	setNetworksBehind = func(hop *routerIntf, inBorder *network) {
		// Hop intf network set is known already.
		if hop2netMap[hop] != nil {
			return
		}
		nMap := make(netMap)

		// Optimization: add networks of directly attached cluster.
		cl := hop2cluster[hop]
		for n := range *cl {
			nMap[n] = true
		}
		// Add preliminary result to stop deep recursion.
		hop2netMap[hop] = nMap

		// Proceed depth first search with adjacent border networks.
		for border := range cluster2borders[cl] {
			if border == inBorder {
				continue
			}
			// Add reachable border networks to set.
			nMap[border] = true

			// Add cluster members of clusters reachable via border networks:
			for _, outHop := range border.interfaces {
				if !hopInterfaces[outHop] {
					continue
				}
				if hop2cluster[outHop] == cl {
					continue
				}

				// Create hop2netMap entry for reachable hops and add networks
				setNetworksBehind(outHop, border)
				for n := range hop2netMap[outHop] {
					nMap[n] = true
				}
			}
		}
		//	debug("Hop: hop->{name} ", join ',', map {$_->{name}} result);
	}

	// For all border interfaces, store reachable networks and
	// corresponding hop interface. Process every border network.
	for border := range borderNetworks {
		var borderIntf intfList
		var hopIntf intfList

		// Collect border and hop interfaces of current border network.
		for _, intf := range border.interfaces {
			if intf.zone == nil {
				hopIntf.push(intf)
			} else if intf.routing == nil {
				borderIntf.push(intf)
				intf.routeInZone = make(map[*network]*routerIntf)
			}
		}

		// Optimization: All networks in zone are located behind single hop.
		if len(hopIntf) == 1 {
			for _, intf := range borderIntf {

				// Spare reachable network specification.
				// debug("Default hop intf->{name} ",
				//        join(',', map {$_->{name}} hop_intf));
				intf.routeInZone[nil] = hopIntf[0]
			}
			// Proceed with next border network.
			continue
		}

		// For all hop interfaces of current border network, gather
		// reachable network set.
		// Collect single virtual hops to change them later to physical interface.
		singleVirtualHops := make(map[*routerIntf]bool)
		for _, h := range hopIntf {
			setNetworksBehind(h, border)
			group := h.redundancyIntfs
			if len(group) > 1 {
				singleVirtualHops[h] = true
			}

			// In border interface of current border network, store
			// reachable networks and hops
			for _, intf := range borderIntf {
				for n := range hop2netMap[h] {

					// Border will be found accidently, if clusters form a
					// loop inside zone.
					if n == border {
						continue
					}
					if other := intf.routeInZone[n]; other != nil {
						// Ignore other redundancy interfaces.
						if group != nil && redundancyEq(group, other.redundancyIntfs) {
							delete(singleVirtualHops, h)
							delete(singleVirtualHops, other)
						} else {
							c.err("Two static routes for %s\n at %s via %s and %s",
								n.vxName(), intf, h, other)
						}
					} else {
						intf.routeInZone[n] = h
					}
				}
			}
		}
		// Change virtual to physical interface, if not used grouped.
		for hop := range singleVirtualHops {
			phys := hop.origMain
			for _, intf := range borderIntf {
				for n, h := range intf.routeInZone {
					if h == hop {
						intf.routeInZone[n] = phys
					}
				}
			}
		}
	}
}

func (c *spoc) getHopInZone(in *routerIntf, n *network) *routerIntf {
	routeInZone := in.routeInZone
	h := routeInZone[nil]
	if h == nil {
		h = routeInZone[n]
	}
	return h
}

/*
#############################################################################
addPathRoutes gathers rule specific routing information at zone border
interfaces: For a pair (in,out) of zone border
interfaces that lies on a path from src to dst, the next hop
interfaces H to reach out from in are determined and stored.

Parameters:
- in - interface zone is entered from.
- out - interface zone is left at.
- dstNetMap - destination networks of associated pseudo rule.

Results:
in holds routing information that dstNetworks are
reachable via next hop interface H.

Comment:
dstNetworks are converted to natNets, before storing as routing
information, because NAT addresses are used in static routes.
*/
func (c *spoc) addPathRoutes(in, out *routerIntf, dstNetMap netMap) {

	// Interface with manual or dynamic routing.
	if in.routing != nil {
		return
	}

	// Identify hop interface.
	var hop *routerIntf
	if in.network == out.network {
		hop = out
	} else {
		hop = c.getHopInZone(in, out.network)
	}
	// Add hop interface and routing information to in.routes
	rMap := in.routes
	if rMap == nil {
		rMap = make(map[*network]intfList)
		in.routes = rMap
	}
	natMap := in.natMap
	for n := range dstNetMap {
		natNet := getNatNetwork(n, natMap)
		// debug("%s -> %s: %s", in, hop, n)
		rMap[natNet] = append(rMap[natNet], hop)
	}
}

/*
##############################################################################
addEndRoutes generates routing information for a single interface at
zone border. Store next hop interface to every destination network
inside zone within the given interface object.

Parameters:
- intf - border interface of a zone.
- dstNetMap - destination networks inside the same zone.

Results:
Interface holds routing entries about which hops to use to
reach the destination networks.

Comment:
dst networks are converted to natNet, before storing as routing
information, because NAT addresses are used in static routes.
*/
func (c *spoc) addEndRoutes(intf *routerIntf, dstNetMap netMap) {

	// Interface with manual or dynamic routing.
	if intf.routing != nil {
		return
	}

	intfNet := intf.network
	natMap := intf.natMap
	rMap := intf.routes
	if rMap == nil {
		rMap = make(map[*network]intfList)
		intf.routes = rMap
	}

	// For every dst network, get the hop that is used to reach it.
	for n := range dstNetMap {
		if n == intfNet {
			continue
		}
		natNet := getNatNetwork(n, natMap)
		h := c.getHopInZone(intf, n)

		// Store the used hop and routes within the interface object.
		// debug("%s -> %s: %s", intf, h, natNet)
		rMap[natNet] = append(rMap[natNet], h)
	}
}

// Find zone of src/dst elements of rule.
// If pathStore is *router or *routerIntf, l is known to have exactly
// one element.
func getZone(l []someObj, s pathStore) *zone {
	switch x := s.(type) {
	case *zone:
		return x
	default:
		return l[0].(*routerIntf).zone
	}
}

/*
############################################################################
generateRoutingTree generates the routing tree,
holding pseudo rules that represent the whole grouped rule set.
As the pseudo rules are generated to determine routes,
ports are omitted, and rules referring to the same src and dst zones
are summarized.
*/
func (c *spoc) generateRoutingTree() routingTree {
	t := make(routingTree)

	for _, ru := range c.allPathRules.permit {
		c.generateRoutingTree1(ru, t)
	}
	return t
}

type pseudoRule struct {
	groupedRule
	srcNetworks  netMap
	dstNetworks  netMap
	srcIntf2nets map[*routerIntf]netMap
	dstIntf2nets map[*routerIntf]netMap
}
type zonePair [2]*zone
type routingTree map[zonePair]*pseudoRule

/*
#############################################################################
generateRoutingTree1 adds information from single grouped rule to routing tree.
*/
func (c *spoc) generateRoutingTree1(rule *groupedRule, t routingTree) {

	// Special handling needed for rules having interface of managed
	// router as src or dst.
	src, dst := rule.src, rule.dst
	srcPath, dstPath := rule.srcPath, rule.dstPath
	srcZone := getZone(src, srcPath)
	dstZone := getZone(dst, dstPath)
	isIntf := func(s pathStore) bool { _, ok := s.(*zone); return !ok }

	// Check, whether
	// - source interface is located in security zone of destination or
	// - destination interface is located in security zone of source.
	// In this case, pathWalk will do nothing.
	if srcZone == dstZone {
		addRoutes := func(from, to []someObj) {
			intf := from[0].(*routerIntf)
			intf = getMainInterface(intf)
			nMap := getRouteNetworks(to)
			c.addEndRoutes(intf, nMap)
		}
		// Detect next hop interfaces if src/dst are zone border interfaces.
		if isIntf(srcPath) {
			addRoutes(src, dst)
		}
		if isIntf(dstPath) {
			addRoutes(dst, src)
		}
		return
	}

	// Check whether pseudo rule for src and dst pair is stored already.
	p := t[zonePair{srcZone, dstZone}]
	if p == nil {
		p = t[zonePair{dstZone, srcZone}]
		if p != nil {
			src, dst = dst, src
			srcPath, dstPath = dstPath, srcPath
		} else {

			// Generate new pseudo rule otherwise.
			p = &pseudoRule{
				groupedRule: groupedRule{
					serviceRule: &serviceRule{
						prt:  rule.prt,
						rule: rule.rule,
					},
					src:     src,
					dst:     dst,
					srcPath: srcZone,
					dstPath: dstZone,
				},
				srcIntf2nets: make(map[*routerIntf]netMap),
				dstIntf2nets: make(map[*routerIntf]netMap),
				srcNetworks:  make(netMap),
				dstNetworks:  make(netMap),
			}
			t[zonePair{srcZone, dstZone}] = p
		}
	}

	// Store src and dst networks of grouped rule within pseudo rule.
	add := func(to, from netMap) {
		for net := range from {
			to[net] = true
		}
	}
	srcNetworks := getRouteNetworks(src)
	add(p.srcNetworks, srcNetworks)
	dstNetworks := getRouteNetworks(dst)
	add(p.dstNetworks, dstNetworks)

	// If src/dst is interface of managed routers, add this info to
	// pseudo rule.
	addI2N := func(i2n map[*routerIntf]netMap, ob []someObj, nets netMap) {
		intf := ob[0].(*routerIntf)
		r := intf.router
		if r.managed != "" || r.routingOnly {
			intf = getMainInterface(intf)
			m := i2n[intf]
			if m == nil {
				m = make(netMap)
				i2n[intf] = m
			}
			add(m, nets)
		}
	}
	if isIntf(srcPath) {
		addI2N(p.srcIntf2nets, src, dstNetworks)
	}
	if isIntf(dstPath) {
		addI2N(p.dstIntf2nets, dst, srcNetworks)
	}
}

/*
#############################################################################
generateRoutingInfo generates routing information for every
(source,destination) pair of the ruleset and store it in the affected interfaces.

Parameters:
- t - a pseudo rule set.

Results:
Every interface object holds next hop routing information for the
rules of original ruleset requiring a path passing the interface.
*/
func (c *spoc) generateRoutingInfo(t routingTree) {

	// Process every pseudo rule.
	for _, p := range t {

		// Add routing information for entry/exit interfaces at
		// start/end zone on path.
		add := func(intf *routerIntf, i2n map[*routerIntf]netMap, nets netMap) {

			// For src/dst interfaces at managed routers, generate
			// routes in both interfaces.
		I2N:
			for intf2, netMap := range i2n {

				// Do not generate routes for src/dst interfaces at
				// path entry/exit routers.
				if intf2.router == intf.router {
					continue
				}
				for _, intf3 := range intf2.redundancyIntfs {
					if intf3 == intf {
						continue I2N
					}
				}
				c.addPathRoutes(intf2, intf, netMap)
			}

			// For src/dst networks, generate routes for zone interface only.
			c.addEndRoutes(intf, nets)
		}

		// Traverse path from src to dst and
		// collect routes for every passed zone.
		getRoutePath := func(r *groupedRule, in, out *routerIntf) {
			// debug("collect: %s -> %s", r.srcPath, r.dstPath)
			// debug("%s -> %s", in, out)
			if in != nil && out != nil {
				// Packets traverse the zone.
				// debug("%s => %s", in, out)
				c.addPathRoutes(in, out, p.dstNetworks)
				c.addPathRoutes(out, in, p.srcNetworks)
			} else if in == nil {
				// Zone contains rule source.
				add(out, p.srcIntf2nets, p.srcNetworks)
			} else {
				// Zone contains rule destination.
				add(in, p.dstIntf2nets, p.dstNetworks)
			}
		}
		c.pathWalk(&p.groupedRule, getRoutePath, "Zone")
	}
}

func (c *spoc) checkAndConvertRoutes() {
	for _, r := range c.managedRouters {
		fixBridgedRoutes(r)
	}
	for _, r := range c.managedRouters {
		if r.routingOnly {
			c.addRoutingOnlyNetworks(r)
		}
		c.adjustVPNRoutes(r)
		c.checkDuplicateRoutes(r)
	}
}

// Add networks of locally attached zone to routing_only devices.
// This is needed because routes between networks inside zone can't be
// derived from packet filter rules.
func (c *spoc) addRoutingOnlyNetworks(r *router) {
	directly := make(netMap)
	for _, intf := range r.interfaces {
		directly[intf.network] = true
	}
	for _, intf := range r.interfaces {
		if intf.routing != nil {
			continue
		}
		switch intf.ipType {
		case hasIP, unnumberedIP, negotiatedIP:
			// debug("intf %s", intf)
			z := intf.zone
			nMap := make(netMap)
			for _, n := range z.networks {
				if !directly[n] {
					// debug("add1 %s", n)
					nMap[n] = true
				}
			}
			c.addEndRoutes(intf, nMap)
			// Process other zones of cluster
			for _, z2 := range z.cluster {
				if z2 == z {
					continue
				}
				for _, n := range z2.networks {
					if !directly[n] {
						c.singlePathWalk(intf, n,
							func(_ *groupedRule, in, out *routerIntf) {
								// debug("walk %s: %s %s", n, in, out)
								if in == intf {
									c.addPathRoutes(in, out, netMap{n: true})
								}
							}, "Zone")
					}
				}
			}
		}
	}
}

// Fix routes where bridged interface without IP address is used as
// next hop.
func fixBridgedRoutes(r *router) {
	for _, intf := range r.interfaces {
		if intf.routing != nil {
			continue
		}
		if intf.network.ipType != bridgedIP {
			continue
		}
		for natNet, hopList := range intf.routes {
			subst := make(map[*routerIntf]intfList)
			for _, hop := range hopList {
				if hop.ipType != bridgedIP {
					continue
				}
				realHops := fixBridgedHops(hop, natNet)

				// Substite real hops later, after loop over hops is finished.
				subst[hop] = realHops
			}
			if len(subst) != 0 {
				var new intfList
				for _, hop := range hopList {
					if real := subst[hop]; real != nil {
						new = append(new, real...)
					} else {
						new.push(hop)
					}
				}
				intf.routes[natNet] = new
			}
		}
	}
}

// Parameters:
// - a bridged interface without an IP address, not usable as hop.
// - the network for which the hop was found.
// Result:
// - one or more layer 3 interfaces, usable as hop.
// Non optimized version.
// Doesn't matter as long we have only a few bridged networks
// or don't use static routing at the border of bridged networks.
func fixBridgedHops(hop *routerIntf, n *network) intfList {
	var result intfList
	r := hop.router
	for _, intf := range r.interfaces {
		if intf == hop {
			continue
		}
		for n2, hopList := range intf.routes {
			if n == n2 {
				for _, hop2 := range hopList {
					if hop2.ipType == bridgedIP {
						result = append(result, fixBridgedHops(hop2, n)...)
					} else {
						result.push(hop2)
					}
				}
			}
		}
	}
	return result
}

// Adjust routes through VPN tunnel to cleartext interface.
func (c *spoc) adjustVPNRoutes(r *router) {
	for _, intf := range r.interfaces {
		if intf.ipType != tunnelIP {
			continue
		}
		realIntf := intf.realIntf
		if realIntf.routing != nil {
			continue
		}
		tunnelRoutes := intf.routes
		intf.routes = nil
		realNet := realIntf.network
		peer := intf.peer
		realPeer := peer.realIntf
		peerNet := realPeer.network

		// Find hop to peer network and add tunneled networks to this hop.
		var hop *routerIntf

		// Peer network is directly connected.
		if realNet == peerNet {
			if realPeer.ipType == hasIP {
				hop = realPeer
			} else {
				c.err("%s used to reach software clients\n"+
					" must not be directly connected to %s\n"+
					" Connect it to some network behind next hop",
					realPeer, realIntf)
				continue
			}
		} else if realNet.zone == peerNet.zone {
			// Peer network is located in directly connected zone.
			hop = c.getHopInZone(realIntf, peerNet)
		} else {
			// Find path to peer network to determine available hops.
			var hops intfList
			walk := func(_ *groupedRule, inIntf, outIntf *routerIntf) {
				if inIntf == realIntf {
					hopNet := outIntf.network
					if hopNet == realNet {
						hops.push(outIntf)
					} else {
						h := c.getHopInZone(realIntf, hopNet)
						hops.push(h)
					}
				}
			}
			c.singlePathWalk(realIntf, peerNet, walk, "Zone")

			intfEq := func(l intfList) bool {
				return !slices.ContainsFunc(l[1:], func(el *routerIntf) bool {
					return el != l[0]
				})
			}
			if !intfEq(hops) && !isRedundanyGroup(hops) {

				// This can only happen for vpn software clients.
				// For hardware clients the route is known
				// for the encrypted traffic which is allowed
				// by genTunnelRules (even for negotiated interface).
				count := len(hops)
				c.err("Can't determine next hop to reach %s"+
					" while moving routes\n"+
					" of %s to %s.\n"+
					" Exactly one route is needed,"+
					" but %d candidates were found:\n%s",
					peerNet, intf, realIntf, count, hops.nameList())
			}
			hop = hops[0]
		}
		routes := realIntf.routes
		if routes == nil {
			routes = make(map[*network]intfList)
			realIntf.routes = routes
		}
		// debug("Use %s as hop for %s", hop, realPeer)

		// Use found hop to reach tunneled networks in tunnelRoutes.
		for tunnelNet := range tunnelRoutes {
			routes[tunnelNet] = append(routes[tunnelNet], hop)
		}

		// Add route to reach peer interface.
		if peerNet != realNet {
			natMap := realIntf.natMap
			natNet := getNatNetwork(peerNet, natMap)
			routes[natNet] = append(routes[natNet], hop)
		}
	}
}

func (c *spoc) checkDuplicateRoutes(r *router) {
	if r.origRouter != nil {
		return
	}

	// Remember, via which local interface a network is reached.
	net2intf := make(map[*network]*routerIntf)

	for _, intf := range getIntf(r) {

		// Routing info not needed, because dynamic routing is in use.
		if intf.routing != nil || intf.ipType == bridgedIP {
			intf.routes = nil
			continue
		}

		// Collect error messages for sorted / deterministic output.
		var errors stringList

		// Abort, if more than one static route exists per network.
		for n, hopList := range intf.routes {

			// Check if network is reached via two different
			// local interfaces.
			if intf2, ok := net2intf[n]; ok {
				if intf2 != intf {
					errors.push(
						fmt.Sprintf(
							"Two static routes for %s\n via %s and %s",
							n, intf, intf2))
				}
			} else {
				net2intf[n] = intf
			}

			// Sort for deterministic error messages.
			hopList = slices.Compact(hopList.sortByName())

			// Simple case: one hop
			if len(hopList) == 1 {
				hop := hopList[0]

				// If dst network is reached via exactly one interface,
				// move hop from virtual to physical interface.
				// Destination is probably a loopback interface of same
				// device.
				// Ignore completly unmanaged virtual interface, which has
				// been checked already.
				if hop.zone != nil {
					if physHop := hop.origMain; physHop != nil {
						hopList[0] = physHop
					}
				}
				intf.routes[n] = hopList
				continue
			}

			// Network is reached via different hops.
			// Abort, if these do not belong to same redundancy group.
			if isRedundanyGroup(hopList) {
				missing := len(hopList[0].redundancyIntfs) - len(hopList)
				if missing == 0 {
					intf.routes[n] = hopList[:1]
					continue
				}

				// Network is reached by more than one but not by all
				// redundancy interfaces.
				errors.push(
					fmt.Sprintf(
						"Pathrestriction ambiguously affects generation"+
							" of static routes\n"+
							"       to interfaces with virtual IP %s:\n"+
							" %s is reached via\n"+
							"%s\n"+
							" But %d interface(s) of group are missing.\n"+
							" Remaining paths must traverse\n"+
							" - all interfaces or\n"+
							" - exactly one interface\n"+
							" of this group.",
						hopList[0].ip, n, hopList.nameList(), missing))
				continue
			}

			errors.push(
				fmt.Sprintf("Ambiguous static routes for %s at %s via\n%s",
					n, intf, hopList.nameList()))
		}

		// Show collected error messages.
		slices.Sort(errors)
		for _, e := range errors {
			c.err(e)
		}
	}
}

// Check, whether input interfaces belong to same redundancy group.
// Each member is known to use the same list in redundancyIntfs
// and each interface can only be member in one redundancy group,
// hence it is sufficient to check only first element.
func isRedundanyGroup(intfs intfList) bool {
	l1 := intfs[0].redundancyIntfs
	if len(l1) == 0 {
		return false
	}
	for _, intf := range intfs[1:] {
		if !redundancyEq(intf.redundancyIntfs, l1) {
			return false
		}
	}
	return true
}

func redundancyEq(l1, l2 intfList) bool {
	return len(l1) == len(l2) && l1[0] == l2[0]
}

func getMainInterface(intf *routerIntf) *routerIntf {
	if m := intf.mainIntf; m != nil {
		return m
	}
	return intf
}
