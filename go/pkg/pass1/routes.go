package pass1

import (
	"fmt"
	"sort"
	"strings"
)

//############################################################################
// Purpose  : Generate and store routing information for all managed interfaces.
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
		setRoutesInZone(z)
	}

	// Generate pseudo rule set with all src dst pairs to determine routes for.
	tree := c.generateRoutingTree()

	// Generate routing info for every pseudo rule and store it in interfaces.
	c.generateRoutingInfo(tree)

	c.addRoutingOnlyNetworks()
	c.checkAndConvertRoutes()
}

type netMap map[*network]bool

//#############################################################################
// Get networks for routing.
// Add largest supernet inside the zone, if available.
// This is needed, because we use the supernet in
// secondary optimization too.
// Moreover this reduces the number of routing entries.
// It isn't sufficient to solely use the supernet because network and supernet
// can have different next hops at end of path.
// For an aggregate, take all matching networks inside the zone.
// These are supernets by design.
func getRouteNetworks(list []someObj) netMap {
	m := make(netMap)
LIST:
	for _, obj := range list {
		var net *network
		switch x := obj.(type) {
		case *network:
			if x.isAggregate {
				for _, net := range x.networks {
					m[net] = true
				}
				continue LIST
			}
			net = x
		case *subnet:
			net = x.network
		case *routerIntf:
			net = x.network
		}
		if max := net.maxRoutingNet; max != nil {
			m[max] = true
		}
		m[net] = true
	}
	return m
}

//#############################################################################
// Purpose    : Provide routing information inside a security zone.
// Parameters : zone - a zone object.
// Results    : Every zone border interface I contains a map
//              routeInZone, keeping the zones networks N reachable from I as
//              keys and the next hop interface H towards N as values.
// Comments   : A cluster is a maximal set of connected networks of the security
//              zone surrounded by hop interfaces. Clusters can be empty.
//              Optimization: a default route I.routeInZone[network00] = [H]
//              is stored for those border interfaces, that reach networks in
//              zone via a single hop.
func setRoutesInZone(zone *zone) {

	// Collect networks at zone border and next hop interfaces in lookup hashes.
	borderNetworks := make(netMap)
	hopInterfaces := make(map[*routerIntf]bool)

	// Collect networks at the zones interfaces as border networks.
	for _, inIntf := range zone.interfaces {
		if inIntf.mainIntf != nil {
			continue
		}
		network := inIntf.network
		if borderNetworks[network] {
			continue
		}
		borderNetworks[network] = true

		// Collect non border interfaces of the networks as next hop interfaces.
		for _, outIntf := range network.interfaces {
			if outIntf.zone != nil {
				continue
			}
			if outIntf.mainIntf != nil {
				continue
			}
			hopInterfaces[outIntf] = true
		}
	}
	if len(hopInterfaces) == 0 {
		return
	}

	// Zone preprocessing: define set of networks surrounded by hop
	// intf (cluster) via depth first search to accelerate later DFS
	// runs starting at hop intfs.

	// Store hop intfs as key && reached clusters as values.
	type cluster netMap
	hop2cluster := make(map[*routerIntf]*cluster)
	// Store directly linked border networks for clusters.
	cluster2borders := make(map[*cluster]netMap)
	var setCluster func(*router, *routerIntf, *cluster)
	setCluster = func(router *router, inIntf *routerIntf, clust *cluster) {
		if router.activePath {
			return
		}
		router.activePath = true
		defer func() { router.activePath = false }()

		// Process every interface.
		for _, intf := range router.interfaces {
			if intf.mainIntf != nil {
				continue
			}

			// Found hop interface. Add its entries on the fly and skip.
			if hopInterfaces[intf] {
				hop2cluster[intf] = clust
				network := intf.network
				cluster2borders[clust][network] = true
				continue
			}
			if intf == inIntf {
				continue
			}

			// Add network behind interface to cluster.
			network := intf.network
			if (*clust)[network] {
				continue
			}
			(*clust)[network] = true

			// Recursively proceed with adjacent routers.
			for _, outIntf := range network.interfaces {
				if outIntf == intf {
					continue
				}
				if outIntf.mainIntf != nil {
					continue
				}
				setCluster(outIntf.router, outIntf, clust)
			}
		}
	}

	// Identify network cluster for every hop interface.
	for intf, _ := range hopInterfaces {
		// Hop interface was processed before.
		if hop2cluster[intf] != nil {
			continue
		}
		clust := make(cluster)
		cluster2borders[&clust] = make(netMap)
		setCluster(intf.router, intf, &clust)

		//	debug("Cluster: intf->{name} ",
		//             join ',', map {$_->{name}} values %clust);
	}

	// Perform depth first search to collect all networks behind a hop interface.
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
		clust := hop2cluster[hop]
		for net, _ := range *clust {
			nMap[net] = true
		}
		// Add preliminary result to stop deep recursion.
		hop2netMap[hop] = nMap

		// Proceed depth first search with adjacent border networks.
		for border, _ := range cluster2borders[clust] {
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
				if hop2cluster[outHop] == clust {
					continue
				}

				// Create hop2netMap entry for reachable hops and add networks
				setNetworksBehind(outHop, border)
				for net, _ := range hop2netMap[outHop] {
					nMap[net] = true
				}
			}
		}
		hop2netMap[hop] = nMap
		//	debug("Hop: hop->{name} ", join ',', map {$_->{name}} result);
	}

	// In every border interfaces, store reachable networks and
	// corresponding hop interface. Process every border network.
	for border, _ := range borderNetworks {
		var borderIntf intfList
		var hopIntf intfList

		// Collect border and hop interfaces of the current border network.
		for _, intf := range border.interfaces {
			if intf.mainIntf != nil {
				continue
			}
			if intf.zone != nil {
				borderIntf.push(intf)
				intf.routeInZone = make(map[*network]intfList)
			} else {
				hopIntf.push(intf)
			}
		}

		// Optimization: All networks in zone are located behind single hop.
		if 1 == len(hopIntf) || isRedundanyGroup(hopIntf) {
			for _, intf := range borderIntf {

				// Spare reachable network specification.
				// debug("Default hop intf->{name} ",
				//        join(',', map {$_->{name}} hop_intf));
				intf.routeInZone[network00] = hopIntf
			}
			// Proceed with next border network.
			continue
		}

		// For every hop interfaces of current network, gather reachable
		// network set.
		for _, hop := range hopIntf {
			setNetworksBehind(hop, border)

			// In border interface of current network, store reachable
			// networks and hops
			for _, intf := range borderIntf {
				for network, _ := range hop2netMap[hop] {

					// Border will be found accidently, if clusters form a
					// loop inside zone.
					if network == border {
						continue
					}
					intf.routeInZone[network] =
						append(intf.routeInZone[network], hop)
				}
			}
		}
	}
}

//#############################################################################
// Purpose    : Gather rule specific routing information at zone border
//              interfaces: For a pair (inIntf,outIntf) of zone border
//              interfaces that lies on a path from src to dst, the next hop
//              interfaces H to reach outIntf from in_intf are determined
//              and stored.
// Parameters : inIntf - interface zone is entered from.
//              outIntf - interface zone is left at.
//              dstNetMap - destination networks of associated pseudo rule.
// Results    : inIntf holds routing information that dstNetworks are
//              reachable via next hop interface H.
// Comment    : dstNetworks are converted to natNets, before storing as
//              routing information, because NAT addresses are used in
//              static routes.
func addPathRoutes(in, out *routerIntf, dstNetMap netMap) {

	// Interface with manual or dynamic routing.
	if in.routing != nil {
		return
	}

	inNet := in.network
	outNet := out.network
	natSet := in.natSet
	natNets := make([]*network, 0, len(dstNetMap))
	for n, _ := range dstNetMap {
		natNets = append(natNets, getNatNetwork(n, natSet))
	}
	rMap := in.routes
	if rMap == nil {
		rMap = make(map[*routerIntf]netMap)
		in.routes = rMap
	}

	// Identify hop interface(s).
	// Store hop interfaces and routing information within inIntf.
	if inNet == outNet {
		nMap := rMap[out]
		if nMap == nil {
			nMap = make(netMap)
			rMap[out] = nMap
		}
		for _, n := range natNets {
			// debug("%s -> %s: %s", in, out, n)
			nMap[n] = true
		}
	} else {
		routeInZone := in.routeInZone
		hops := routeInZone[network00]
		if hops == nil {
			hops = routeInZone[outNet]
		}
		for _, hop := range hops {
			nMap := rMap[hop]
			if nMap == nil {
				nMap = make(netMap)
				rMap[hop] = nMap
			}
			for _, n := range natNets {
				// debug("%s -> %s: %s", in, hop, n)
				nMap[n] = true
			}
		}
	}
}

//############################################################################
// Purpose    : Generate routing information for a single interface at zone
//              border. Store next hop interface to every destination network
//              inside zone within the given interface object.
// Parameters : interface - border interface of a zone.
//              dstNetMap - destination networks inside the same zone.
// Results    : interface holds routing entries about which hops to use to
//              reach the networks specified in dst_networks.
// Comment    : dst networks are converted to natNet, before storing as
//              routing information, because NAT addresses are used in
//              static routes.
func addEndRoutes(intf *routerIntf, dstNetMap netMap) {

	// Interface with manual or dynamic routing.
	if intf.routing != nil {
		return
	}

	intfNet := intf.network
	routeInZone := intf.routeInZone
	natSet := intf.natSet
	rMap := intf.routes
	if rMap == nil {
		rMap = make(map[*routerIntf]netMap)
		intf.routes = rMap
	}

	// For every dst network, check the hops that can be used to get there.
	for n, _ := range dstNetMap {
		if n == intfNet {
			continue
		}
		natNet := getNatNetwork(n, natSet)
		hops := routeInZone[network00]
		if hops == nil {
			hops = routeInZone[n]
		}

		// Store the used hops and routes within the interface object.
		for _, hop := range hops {
			nMap := rMap[hop]
			if nMap == nil {
				nMap = make(netMap)
				rMap[hop] = nMap
			}
			// debug("%s -> %s: %s", intf, hop, natNet)
			nMap[natNet] = true
		}
	}
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

const (
	noIntf = iota
	srcIntf
	dstIntf
	bothIntf
)

//#############################################################################
// Purpose    : Add information from single grouped rule to routing tree.
// Parameters : rule - to be added grouped rule.
//              isIntf - marker: which of src and/or dst is an interface.
//              tree - the routing tree.
func generateRoutingTree1(rule *groupedRule, isIntf int, tree routingTree) {

	src, dst := rule.src, rule.dst
	srcZone, dstZone := rule.srcPath.(*zone), rule.dstPath.(*zone)

	// Check, whether
	// - source interface is located in security zone of destination or
	// - destination interface is located in security zone of source.
	// In this case, pathWalk will do nothing.
	if srcZone == dstZone {
		addRoutes := func(from, to []someObj) {
			intf := from[0].(*routerIntf)
			intf = getMainInterface(intf)
			nMap := getRouteNetworks(to)
			addEndRoutes(intf, nMap)
		}
		// Detect next hop interfaces if src/dst are zone border interfaces.
		switch isIntf {
		case srcIntf:
			addRoutes(src, dst)
		case dstIntf:
			addRoutes(dst, src)
		case bothIntf:
			addRoutes(src, dst)
			addRoutes(dst, src)
		}
		return
	}

	// Construct a pseudo rule with zones as src and dst and store it.
	var pRule *pseudoRule

	// Check whether pseudo rule for src and dst pair is stored already.
	pRule = tree[zonePair{srcZone, dstZone}]
	if pRule == nil {
		pRule = tree[zonePair{dstZone, srcZone}]
		if pRule != nil {
			src, dst = dst, src
			srcZone, dstZone = dstZone, srcZone

			// Change only if set:
			// 'src' -> 'dst, 'dst' -> 'src', 'src,dst' unchanged.
			switch isIntf {
			case srcIntf:
				isIntf = dstIntf
			case dstIntf:
				isIntf = srcIntf
			}
		} else {

			// Generate new pseudo rule otherwise.
			pRule = &pseudoRule{
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
			tree[zonePair{srcZone, dstZone}] = pRule
		}
	}

	// Store src and dst networks of grouped rule within pseudo rule.
	add := func(to, from netMap) {
		for net, _ := range from {
			to[net] = true
		}
	}
	srcNetworks := getRouteNetworks(src)
	add(pRule.srcNetworks, srcNetworks)
	dstNetworks := getRouteNetworks(dst)
	add(pRule.dstNetworks, dstNetworks)

	// If src/dst is interface of managed routers, add this info to
	// pseudo rule.
	addI2N := func(ob []someObj, nets netMap, i2n *map[*routerIntf]netMap) {
		intf := ob[0].(*routerIntf)
		r := intf.router
		if r.managed != "" || r.routingOnly {
			intf = getMainInterface(intf)
			m := (*i2n)[intf]
			if m == nil {
				m = make(netMap)
				(*i2n)[intf] = m
			}
			add(m, nets)
		}
	}
	switch isIntf {
	case srcIntf:
		addI2N(src, dstNetworks, &pRule.srcIntf2nets)
	case dstIntf:
		addI2N(dst, srcNetworks, &pRule.dstIntf2nets)
	case bothIntf:
		addI2N(src, dstNetworks, &pRule.srcIntf2nets)
		addI2N(dst, srcNetworks, &pRule.dstIntf2nets)
	}
}

//############################################################################
// Purpose : Generate the routing tree, holding pseudo rules that represent
//           the whole grouped rule set. As the pseudo rules are
//           generated to determine routes, ports are omitted, and rules
//           refering to the same src and dst zones are summarized.
func (c *spoc) generateRoutingTree() routingTree {
	tree := make(routingTree)

	// Special handling needed for rules grouped not at zone pairs but
	// grouped at routers.
	for _, rule := range c.allPathRules.permit {

		// debug(rule.print())
		if _, ok := rule.srcPath.(*zone); ok {

			if _, ok := rule.dstPath.(*zone); ok {
				// Common case, process directly.
				generateRoutingTree1(rule, noIntf, tree)
			} else {
				// Split group of destination interfaces, one for each zone.
				for _, obj := range rule.dst {
					intf := obj.(*routerIntf)
					copy := *rule
					copy.dst = []someObj{obj}
					copy.dstPath = intf.zone
					generateRoutingTree1(&copy, dstIntf, tree)
				}
			}
		} else if _, ok := rule.dstPath.(*zone); ok {
			for _, obj := range rule.src {
				intf := obj.(*routerIntf)
				copy := *rule
				copy.src = []someObj{obj}
				copy.srcPath = intf.zone
				generateRoutingTree1(&copy, srcIntf, tree)
			}
		} else {
			for _, srcObj := range rule.src {
				srcIntf := srcObj.(*routerIntf)
				for _, dstObj := range rule.dst {
					dstIntf := dstObj.(*routerIntf)
					copy := *rule
					copy.src = []someObj{srcObj}
					copy.dst = []someObj{dstObj}
					copy.srcPath = srcIntf.zone
					copy.dstPath = dstIntf.zone
					generateRoutingTree1(&copy, bothIntf, tree)
				}
			}
		}
	}
	return tree
}

//#############################################################################
// Purpose    : Generate routing information for every (source,destination)
//              pair of the ruleset and store it in the affected interfaces.
// Parameters : routing_tree - a pseudo rule set.
// Results    : Every interface object holds next hop routing information
//              for the rules of original ruleset requiring a path passing the
//              interface.
func (c *spoc) generateRoutingInfo(tree routingTree) {

	// Process every pseudo rule. Within its {path} attribute....
	for _, pRule := range tree {

		// Collect data for every passed zone.
		var path [][2]*routerIntf
		var pathEntries []*routerIntf
		var pathExits []*routerIntf
		getRoutePath := func(r *groupedRule, in, out *routerIntf) {
			/* debug("collect: %s -> %s", r.srcPath, r.dstPath)
			info := ""
			if in != nil {
				info += in.name
			}
			info += " -> "
			if out != nil {
				info += out.name
			}
			debug(info)
			*/
			if in != nil && out != nil {
				// Packets traverse the zone.
				path = append(path, [2]*routerIntf{in, out})
			} else if in == nil {
				// Zone contains rule source.
				pathEntries = append(pathEntries, out)
			} else {
				// Zone contains rule destination.
				pathExits = append(pathExits, in)
			}
		}
		c.pathWalk(&pRule.groupedRule, getRoutePath, "Zone")

		// Determine routing information for every interface pair.
		for _, tuple := range path {
			in, out := tuple[0], tuple[1]
			// debug("%s => %s", in, out)
			addPathRoutes(in, out, pRule.dstNetworks)
			addPathRoutes(out, in, pRule.srcNetworks)
		}

		// Determine routing information for intf of first zone on path.
		for _, entry := range pathEntries {

			// For src interfaces at managed routers, generate routes in
			// both interfaces.
		SRC:
			for srcIntf, netMap := range pRule.srcIntf2nets {

				// Do not generate routes for src interfaces at path entry
				// routers.
				if srcIntf.router == entry.router {
					continue
				}
				for _, intf := range srcIntf.redundancyIntfs {
					if intf.router == entry.router {
						continue SRC
					}
				}
				addPathRoutes(srcIntf, entry, netMap)
			}

			// For src networks, generate routes for zone interface only.
			addEndRoutes(entry, pRule.srcNetworks)
		}

		// Determine routing information for interface of last zone on path.
		for _, exit := range pathExits {

			// For dst interfaces at managed routers, generate routes in
			// both interfaces.
		DST:
			for dstIntf, netMap := range pRule.dstIntf2nets {

				// Do not generate routes for dst interfaces at path exit routers.
				if dstIntf.router == exit.router {
					continue
				}
				for _, intf := range dstIntf.redundancyIntfs {
					if intf.router == exit.router {
						continue DST
					}
				}
				addPathRoutes(dstIntf, exit, netMap)
			}

			// For dst networks, generate routes for zone interface only.
			addEndRoutes(exit, pRule.dstNetworks)
		}
	}
}

// Add networks of locally attached zone to routing_only devices.
// This is needed because routes between networks inside zone can't be
// derived from packet filter rules.
func (c *spoc) addRoutingOnlyNetworks() {
	for _, r := range c.routingOnlyRouters {
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
				addEndRoutes(intf, nMap)
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
										addPathRoutes(in, out, netMap{n: true})
									}
								}, "Zone")
						}
					}
				}
			}
		}
	}
}

func (c *spoc) checkAndConvertRoutes() {
	l := append(c.managedRouters, c.routingOnlyRouters...)
	for _, r := range l {
		fixBridgedRoutes(r)
	}
	for _, r := range l {
		c.adjustVPNRoutes(r)
		c.checkDuplicateRoutes(r)
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
		addRoutes := make(map[*routerIntf][]*network)
		for hop, netMap := range intf.routes {
			if hop.ipType != bridgedIP {
				continue
			}
			for network, _ := range netMap {
				realHops := fixBridgedHops(hop, network)

				// Add real hops and networks later, after loop over
				// routes has been finished.
				for _, rHop := range realHops {
					addRoutes[rHop] = append(addRoutes[rHop], network)
				}
			}
			delete(intf.routes, hop)
		}
		for rHop, networks := range addRoutes {
			nMap := intf.routes[rHop]
			if nMap == nil {
				nMap = make(netMap)
			}
			for _, n := range networks {
				nMap[n] = true
			}
			intf.routes[rHop] = nMap
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
	HOP:
		for hop2, netMap := range intf.routes {
			for n2, _ := range netMap {
				if n == n2 {
					if hop2.ipType == bridgedIP {
						result = append(result, fixBridgedHops(hop2, n)...)
					} else {
						result.push(hop2)
					}
					continue HOP
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
		var hops intfList

		// Peer network is directly connected.
		if realNet == peerNet {
			if realPeer.ipType == hasIP {
				hops.push(realPeer)
			} else {
				c.err("%s used to reach software clients\n"+
					" must not be directly connected to %s\n"+
					" Connect it to some network behind next hop",
					realPeer, realIntf)
				continue
			}
		} else if realNet.zone == peerNet.zone {
			// Peer network is located in directly connected zone.
			routeInZone := realIntf.routeInZone
			h := routeInZone[network00]
			if h == nil {
				h = routeInZone[peerNet]
			}
			hops = append(hops, h...)
		} else {
			// Find path to peer network to determine available hops.
			var zoneHops intfList
			walk := func(_ *groupedRule, inIntf, outIntf *routerIntf) {
				if inIntf == realIntf {
					zoneHops.push(outIntf)
				}
			}
			c.singlePathWalk(realIntf, peerNet, walk, "Zone")
			routeInZone := realIntf.routeInZone
			for _, hop := range zoneHops {
				hopNet := hop.network
				if hopNet == realNet {
					hops.push(hop)
				} else {
					h := routeInZone[network00]
					if h == nil {
						h = routeInZone[hopNet]
					}
					hops = append(hops, h...)
				}
			}
		}

		intfEq := func(list intfList) bool {
			i0 := list[0]
			rest := list[1:]
			for _, i := range rest {
				if i != i0 {
					return false
				}
			}
			return true
		}
		redundEq := func(list intfList) bool {
			r0 := list[0].redundancyIntfs
			if len(r0) == 0 {
				return false
			}
			rest := list[1:]
			for _, i := range rest {
				if !intfListEq(i.redundancyIntfs, r0) {
					return false
				}
			}
			return true
		}
		if !intfEq(hops) && !redundEq(hops) {

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

		hop := hops[0]
		routes := realIntf.routes
		if routes == nil {
			routes = make(map[*routerIntf]netMap)
		}
		hopRoutes := routes[hop]
		if hopRoutes == nil {
			hopRoutes = make(netMap)
			routes[hop] = hopRoutes
		}
		// debug("Use %s as hop for %s", hop, realPeer)

		// Use found hop to reach tunneled networks in tunnel_routes.
		for _, tunnelNetHash := range tunnelRoutes {
			for tunnelNet, _ := range tunnelNetHash {
				hopRoutes[tunnelNet] = true
			}
		}

		// Add route to reach peer interface.
		if peerNet != realNet {
			natSet := realIntf.natSet
			natNet := getNatNetwork(peerNet, natSet)
			hopRoutes[natNet] = true
		}

		realIntf.routes = routes
	}
}
func (c *spoc) checkDuplicateRoutes(r *router) {
	if r.origRouter != nil {
		return
	}

	// Remember, via which local interface a network is reached.
	net2intf := make(map[*network]*routerIntf)

	for _, intf := range getIntf(r) {

		// Collect error messages for sorted / deterministic output.
		var errors stringList

		// Routing info not needed, because dynamic routing is in use.
		if intf.routing != nil || intf.ipType == bridgedIP {
			intf.routes = nil
			continue
		}

		// Remember, via which remote interface a network is reached.
		net2hop := make(map[*network]*routerIntf)

		// Remember, via which extra remote redundancy interfaces networks
		// are reached. We use this to check, that all members of a group
		// of redundancy interfaces are used to reach a network.
		// Otherwise it would be wrong to route to virtual interface.
		var netBehindVirtHop []*network
		net2extraHops := make(map[*network]intfList)

		// Abort, if more than one static route exists per network.
		// Sort interfaces for deterministic output.
		sorted := make([]*routerIntf, 0, len(intf.routes))
		for hop, _ := range intf.routes {
			sorted = append(sorted, hop)
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].name < sorted[j].name
		})
		for _, hop := range sorted {
			for n, _ := range intf.routes[hop] {
				// debug("%s -> %s -> %s", intf, hop, n)

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

				// Check whether network is reached via different hops.
				// Abort, if these do not belong to same redundancy group.
				group := hop.redundancyIntfs
				if hop2, ok := net2hop[n]; ok {

					// If next hop belongs to same redundancy group,
					// collect hops for detailed check below.
					group2 := hop2.redundancyIntfs
					if group != nil && intfListEq(group, group2) {
						delete(intf.routes[hop], n)
						net2extraHops[n] =
							append(net2extraHops[n], hop)
					} else {
						errors.push(
							fmt.Sprintf(
								"Two static routes for %s\n at %s via %s and %s",
								n, intf, hop, hop2))
					}
				} else {
					net2hop[n] = hop
					if group != nil {
						netBehindVirtHop = append(netBehindVirtHop, n)
					}
				}
			}
		}

		// Ensure correct routing at virtual interfaces.
		// Check whether dst network is reached via all
		// redundancy interfaces.
		for _, n := range netBehindVirtHop {
			hop1 := net2hop[n]
			extraHops := net2extraHops[n]
			missing := len(hop1.redundancyIntfs) - len(extraHops) - 1
			if missing == 0 {
				continue
			}

			// If dst network is reached via exactly one interface,
			// move hop from virtual to physical interface.
			// Destination is probably a loopback interface of same
			// device.
			physHop := hop1.origMain
			if len(extraHops) == 0 && physHop != nil {
				delete(intf.routes[hop1], n)
				if intf.routes[physHop] == nil {
					intf.routes[physHop] = make(netMap)
				}
				intf.routes[physHop][n] = true
				continue
			}

			// Show error message if dst network is reached by
			// more than one but not by all redundancy interfaces.
			nameList := stringList{hop1.name}
			for _, hop := range extraHops {
				nameList.push(hop.name)
			}
			sort.Strings(nameList)
			names := strings.Join(nameList, "\n - ")
			errors.push(
				fmt.Sprintf(
					"Pathrestriction ambiguously affects generation"+
						" of static routes\n"+
						"       to interfaces with virtual IP %s:\n"+
						" %s is reached via\n"+
						" - %s\n"+
						" But %d interface(s) of group are missing.\n"+
						" Remaining paths must traverse\n"+
						" - all interfaces or\n"+
						" - exactly one interface\n"+
						" of this group.",
					hop1.ip.String(), n.name, names, missing))
		}

		// Show error messages of both tests above.
		sort.Strings(errors)
		for _, e := range errors {
			c.err(e)
		}
	}
}

func intfListEq(l1, l2 []*routerIntf) bool {
	if len(l1) != len(l2) {
		return false
	}
	for i, e := range l1 {
		if e != l2[i] {
			return false
		}
	}
	return true
}

func getIpv4Ipv6Routers() []*router {
	result := make([]*router, 0, len(symTable.router)+len(symTable.router6))
	for _, r := range symTable.router {
		result = append(result, r)
	}
	for _, r := range symTable.router6 {
		result = append(result, r)
	}
	return result
}

// Check, whether input interfaces belong to same redundancy group.
func isRedundanyGroup(intfs []*routerIntf) bool {
	list1 := intfs[0].redundancyIntfs
	if len(list1) == 0 {
		return false
	}
	// Check for equality of lists.
	for _, intf := range intfs[1:] {
		list2 := intf.redundancyIntfs
		if len(list2) != len(list1) {
			return false
		}
		for i, obj := range list1 {
			if obj != list2[i] {
				return false
			}
		}
	}
	return true
}

func getMainInterface(intf *routerIntf) *routerIntf {
	if m := intf.mainIntf; m != nil {
		return m
	}
	return intf
}
