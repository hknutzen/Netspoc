package pass1

import (
	"fmt"
	"net/netip"
)

// Two zones are zoneEq, if
// - zones are equal or
// - both belong to the same zone cluster.
// Handles zone or router as argument.
func zoneEq(z1, z2 pathObj) bool {
	if z1 == z2 {
		return true
	}
	if z1, ok := z1.(*zone); ok {
		if z2, ok := z2.(*zone); ok {
			// Each zone of a cluster references the same slice, so it is
			// sufficient to compare first element.
			return z1.cluster[0] == z2.cluster[0]
		}
	}
	return false
}

// Print abbreviated list of names in messages.
func shortNameList(l []someObj) string {
	names := make(stringList, 0, 4)
	for _, obj := range l {
		if len(names) == 3 {
			names.push("...")
			break
		}
		names.push(obj.String())
	}
	return names.nameList()
}

type checkInfo struct {
	zone2netMap map[*zone]map[*network]bool
	seen        map[*zone]bool
}

//#############################################################################
// Check if high-level and low-level semantics of rules with an supernet
// as source or destination are equivalent.
//
// I. Typically, we only use incoming ACLs.
// (A) rule "permit any:X dst"
// high-level: any:X in zone X get access to dst
// low-level: like above, but additionally, the networks matching any:X
//            in all zones on the path from zone X to dst get access to dst.
// (B) rule permit src any:X
// high-level: src gets access to any:X in zone X
// low-level: like above, but additionally, src gets access to all networks
//            matching any:X in all zones located directly behind
//            all routers on the path from src to zone X.
//
// II. Alternatively, we have a single interface Y (with attached zone Y)
//     without ACL and all other interfaces having incoming and outgoing ACLs.
// (A) rule "permit any:X dst"
//  a)  dst behind Y: filtering occurs at incoming ACL of X, good.
//  b)  dst not behind Y:
//    1. zone X == zone Y: filtering occurs at outgoing ACL, good.
//    2. zone X != zone Y: outgoing ACL would accidently
//                permit any:Y->dst, bad.
//                Additional rule required: "permit any:Y->dst"
// (B) rule "permit src any:X"
//  a)  src behind Y: filtering occurs at ougoing ACL, good
//  b)  src not behind Y:
//    1. zone X == zone Y: filtering occurs at incoming ACL at src and
//                at outgoing ACls of other non-zone X interfaces, good.
//    2. zone X != zone Y: incoming ACL at src would permit
//                src->any:Y, bad
//                Additional rule required: "permit src->any:Y".
//#############################################################################

// Find aggregate in zone with address equal to ip/mask
// or find networks in zone with address in subnet or supernet relation
// to ip/mask.
// Leave out
// - invisible aggregates, only used intermediately in automatic groups,
// - small networks which are subnet of a matching network,
// - objects that are
//   - element of netMap or
//   - subnet of element of netMap.
// Result: List of found networks or aggregates.
func findZoneNetworks(
	z *zone, isAgg bool, ipp netip.Prefix, natMap natMap,
	netMap map[*network]bool) (*network, netList) {

	// Check if argument or some supernet of argument is member of netMap.
	inNetMap := func(netOrAgg *network) bool {
		for {
			if _, found := netMap[netOrAgg]; found {
				return true
			}
			netOrAgg = netOrAgg.up
			if netOrAgg == nil {
				return false
			}
		}
	}
	agg := z.ipPrefix2aggregate[ipp]
	if agg != nil && !agg.invisible {
		if inNetMap(agg) {
			return nil, nil
		}
		// If aggregate has networks, add those that are not member of netMap.
		if aggNets := agg.networks; len(aggNets) > 0 {
			var l netList
			for _, net := range aggNets {
				if !inNetMap(net) {
					l.push(net)
				}
			}
			if len(l) == 0 {
				return nil, nil
			} else {
				return agg, l
			}
		} else {
			return agg, nil
		}
	}

	// Use cached result.
	l, found := z.ipPrefix2net[ipp]

	// Cheack real networks in zone without aggregates and without subnets.
	if !found {
		bits := ipp.Bits()
		for _, net := range z.networks {
			if inNetMap(net) {
				continue
			}
			natNet := getNatNetwork(net, natMap)
			if natNet.hidden {
				continue
			}
			if natNet.ipp.Bits() >= bits && ipp.Contains(natNet.ipp.Addr()) ||
				isAgg && natNet.ipp.Bits() < bits && natNet.ipp.Contains(ipp.Addr()) {

				l.push(net)
			}
		}
		if z.ipPrefix2net == nil {
			z.ipPrefix2net = make(map[netip.Prefix]netList)
		}
		z.ipPrefix2net[ipp] = l
	}
	return nil, l
}

// rule: the rule to be checked
// where: has value 'src' or 'dst'
// intf: interface, where traffic reaches the device,
//       this is used to determine natMap
// z: The zone to be checked.
//    If where is 'src', then zone is attached to interface
//    If where is 'dst', then zone is at other side of device.
// reversed: the check is for reversed rule at stateless device
func (c *spoc) checkSupernetInZone1(
	rule *groupedRule, where string, intf *routerIntf,
	z *zone, info checkInfo, reversed bool) {

	if z.noCheckSupernetRules {
		return
	}
	if info.seen[z] {
		return
	}
	info.seen[z] = true

	// This is only called if src or dst is some supernet.
	var supernet *network
	if where == "src" {
		supernet = rule.src[0].(*network)
	} else {
		supernet = rule.dst[0].(*network)
	}
	natMap := intf.natMap
	natSuper := getNatNetwork(supernet, natMap)
	if natSuper.hidden {
		return
	}
	ipp := natSuper.ipp
	netMap := info.zone2netMap[z]
	agg, networks :=
		findZoneNetworks(z, supernet.isAggregate, ipp, natMap, netMap)

	if agg == nil && networks == nil {
		return
	}

	orAgg := ""
	if agg == nil {
		if len(networks) > 2 {
			// Show also aggregate, if multiple networks are found.
			orAgg = fmt.Sprintf("any:[ ip=%s & %s ]", ipp, networks[0])
		}
	} else {
		if networks == nil {
			networks = netList{agg}
		} else {
			orAgg = agg.name
		}
	}
	if orAgg != "" {
		orAgg = fmt.Sprintf("\n or add %s to %s of rule", orAgg, where)
	}
	rev := ""
	if reversed {
		rev = "reversed "
	}
	fromTo := "from"
	if (where != "src") != reversed {
		fromTo = "to"
	}
	objects := make([]someObj, len(networks))
	for i, n := range networks {
		objects[i] = n
	}
	c.warnOrErr(
		c.conf.CheckSupernetRules,
		"This %ssupernet rule would permit unexpected access:\n"+
			"  %s\n"+
			" Generated ACL at %s would permit access"+
			" %s additional networks:\n"+
			"%s\n"+
			" Either replace %s by smaller networks that are not supernet\n"+
			" or add above-mentioned networks to %s of rule%s.",
		rev,
		rule.print(),
		intf,
		fromTo,
		shortNameList(objects),
		supernet,
		where,
		orAgg,
	)
}

func (c *spoc) checkSupernetInZone(
	rule *groupedRule, where string, intf *routerIntf,
	z *zone, info checkInfo, reversed bool) {

	for _, z := range z.cluster {
		c.checkSupernetInZone1(rule, where, intf, z, info, reversed)
	}
}

// Check if path between supernet and objList is filtered by
// device with mark from router.localMark.
func isFilteredAt(r *router, supernet *network, objList []someObj) bool {
	mark := r.localMark
	if mark == 0 {
		return true
	}
	if !supernet.filterAt[mark] {
		return false
	}
	for _, obj := range objList {
		objNet := obj.getNetwork()
		if objNet.filterAt[mark] {
			return true
		}
	}
	return false
}

// Returns zone for most objects, but router for interfaces of managed router.
func (x *zone) getZone() pathObj    { return x }
func (x *network) getZone() pathObj { return x.zone }
func (x *subnet) getZone() pathObj  { return x.network.zone }
func (x *router) getZone() pathObj {
	if x.managed == "" {
		return x.interfaces[0].network.zone
	} else {
		return x
	}
}
func (x *routerIntf) getZone() pathObj {
	if x.router.managed == "" {
		return x.network.zone
	} else {
		return x.router
	}
}

// If such rule is defined
//  permit supernet1 dst
//
// and topology is like this:
//
// supernet1-R1-zone2-R2-zone3-R3-dst
//               zone4-/
//
// additional rules need to be defined as well:
//  permit supernet(zone2) dst
//  permit supernet(zone3) dst
//
// If R2 is stateless, we need one more rule to be defined:
//  permit supernet(zone4) dst
// This is needed, because at R2 we would get an automatically generated
// reverse rule
//  permit dst supernet1
// which would accidentally permit traffic to supernet:[zone4] as well.
func (c *spoc) checkSupernetSrcRule(
	rule *groupedRule, in, out *routerIntf, info checkInfo) {

	// Ignore semi-managed router.
	r := in.router
	if r.managed == "" {
		return
	}

	// This is only called if src is some supernet.
	src := rule.src[0].(*network)

	// Non matching rule will be ignored at 'managed=local' router and
	// hence must no be checked.
	if !isFilteredAt(r, src, rule.dst) {
		return
	}

	dstZone := rule.dstPath.getZone()
	inZone := in.zone

	// Check case II, outgoing ACL, (A)
	if noAclIntf := r.noInAcl; noAclIntf != nil {
		noAclZone := noAclIntf.zone

		if noAclIntf == out {
			// a) dst behind Y
		} else if zoneEq(inZone, noAclZone) {
			// b), 1. zone X == zone Y
		} else {
			// b), 2. zone X != zone Y
			c.checkSupernetInZone(rule, "src", noAclIntf, noAclZone, info, false)
		}
	}

	srcZone := src.zone

	// Check if reverse rule would be created and would need additional rules.
	stateful := false
PRT:
	for _, prt := range rule.prt {
		switch prt.proto {
		case "tcp", "udp", "ip":
			stateful = true
			break PRT
		}
	}
	if out != nil && r.model.stateless && !rule.oneway && stateful {
		outZone := out.zone

		// Reverse rule wouldn't allow too much traffic, if a non
		// secondary stateful device filters between current device and dst.
		// This is true if outZone and dstZone have different
		// statefulMark.
		//
		// src is supernet (not an interface) by definition and hence
		// m1 is well defined.
		//
		// If dst is interface or router, m2 is 0.
		// Corresponding router is known to be managed, because
		// unmanaged dstZone has already been converted to zone
		// above. Managed routers are assumed to send answer packet
		// correctly back to source address.
		// Hence reverse rules need not to be checked.
		m1 := outZone.statefulMark
		m2 := 0
		if z2, ok := dstZone.(*zone); ok {
			m2 = z2.statefulMark
		}
		if m2 != 0 && m1 == m2 {

			// Check case II, outgoing ACL, (B), interface Y without ACL.
			if noAclIntf := r.noInAcl; noAclIntf != nil {
				noAclZone := noAclIntf.zone

				if zoneEq(noAclZone, dstZone) {
					// a) dst behind Y
				} else if zoneEq(noAclZone, srcZone) {
					// b) dst not behind Y
					// zone X == zone Y
				} else {
					// zone X != zone Y
					c.checkSupernetInZone(rule, "src", noAclIntf, noAclZone, info, true)
				}
			} else {
				// Standard incoming ACL at all interfaces.

				// Find security zones at all interfaces except the incoming.
				for _, intf := range r.interfaces {
					if intf == in {
						continue
					}
					if intf.loopback {
						continue
					}

					// Nothing to be checked for an interface directly
					// connected to src or dst.
					zone := intf.zone
					if zoneEq(zone, srcZone) {
						continue
					}
					if zoneEq(zone, dstZone) {
						continue
					}
					c.checkSupernetInZone(rule, "src", out, zone, info, true)
				}
			}
		}
	}

	// Nothing to do at first router.
	if zoneEq(srcZone, inZone) {
		return
	}

	// Check if rule "supernet2 -> dst" is defined.
	c.checkSupernetInZone(rule, "src", in, inZone, info, false)
}

// If such rule is defined
//  permit src supernet5
//
// and topology is like this:
//
//                      /-zone4
// src-R1-zone2-R2-zone3-R3-zone5
//      \-zone1
//
// additional rules need to be defined as well:
//  permit src supernet1
//  permit src supernet2
//  permit src supernet3
//  permit src supernet4
func (c *spoc) checkSupernetDstRule(
	rule *groupedRule, in, out *routerIntf, info checkInfo) {

	// Source is interface of current router.
	if in == nil {
		return
	}

	// Ignore semi-managed router.
	r := in.router
	if r.managed == "" {
		return
	}

	// This is only called if dst is some supernet.
	dst := rule.dst[0].(*network)

	// Non matching rule will be ignored at 'managed=local' router and
	// hence must not be checked.
	if !isFilteredAt(r, dst, rule.src) {
		return
	}

	srcZone := rule.srcPath.getZone()
	dstZone := dst.zone

	// Check case II, outgoing ACL, (B), interface Y without ACL.
	if noAclIntf := r.noInAcl; noAclIntf != nil {
		noAclZone := noAclIntf.zone

		if zoneEq(noAclZone, srcZone) {
			// a) src behind Y
		} else if zoneEq(noAclZone, dstZone) {
			// b) src not behind Y
			// zone X == zone Y
		} else {
			// zone X != zone Y
			c.checkSupernetInZone(rule, "dst", in, noAclZone, info, false)
		}
		return
	}

	// Check security zones at all interfaces except those connected
	// to dst or src.
	// For devices which have rules for each pair of incoming and outgoing
	// interfaces we only need to check the direct path to dst.
	inZone := in.zone
	check := func(intf *routerIntf) {

		// Check each intermediate zone only once at outgoing interface.
		if intf == in {
			return
		}
		if intf.loopback {
			return
		}

		// Don't check interface where src or dst is attached.
		z := intf.zone
		if zoneEq(z, srcZone) {
			return
		}
		if zoneEq(z, dstZone) {
			return
		}
		if zoneEq(z, inZone) {
			return
		}
		c.checkSupernetInZone(rule, "dst", in, z, info, false)
	}
	if r.model.hasIoACL {
		check(out)
	} else {
		for _, intf := range r.interfaces {
			check(intf)
		}
	}
}

// Check missing supernet of each serviceRule.
func (c *spoc) checkMissingSupernetRules(
	rules ruleList, what string,
	worker func(c *spoc, r *groupedRule, i, o *routerIntf, inf checkInfo)) {

	for _, rule := range rules {
		if rule.noCheckSupernetRules {
			continue
		}
		var list []someObj
		var oList []someObj
		if what == "src" {
			list = rule.src
			oList = rule.dst
		} else {
			list = rule.dst
			oList = rule.src
		}
		var supernets netList
		for _, obj := range list {
			if x, ok := obj.(*network); ok {
				if x.hasOtherSubnet {
					supernets = append(supernets, x)
				}
			}
		}
		if supernets == nil {
			continue
		}

		// Build mapping from zone to map of all src/dst networks and
		// aggregates of current rule.
		zone2netMap := make(map[*zone]map[*network]bool)
		for _, obj := range list {
			if x, ok := obj.(*network); ok {
				netMap := zone2netMap[x.zone]
				if netMap == nil {
					netMap = make(map[*network]bool)
					zone2netMap[x.zone] = netMap
				}
				netMap[x] = true
			}
		}
		info := checkInfo{zone2netMap: zone2netMap}

		groupInfo := splitRuleGroup(oList)
		checkRule := new(groupedRule)
		checkRule.serviceRule = rule.serviceRule
		for _, supernet := range supernets {
			info.seen = make(map[*zone]bool)
			if what == "src" {
				checkRule.src = []someObj{supernet}
				checkRule.srcPath = supernet.zone
			} else {
				checkRule.dst = []someObj{supernet}
				checkRule.dstPath = supernet.zone
			}
			for _, gi := range groupInfo {
				z2 := gi.path.getZone()
				if zoneEq(supernet.zone, z2) {
					continue
				}
				if what == "src" {
					checkRule.dstPath = gi.path
					checkRule.dst = gi.group
				} else {
					checkRule.srcPath = gi.path
					checkRule.src = gi.group
				}
				c.pathWalk(checkRule,
					func(r *groupedRule, i, o *routerIntf) {
						worker(c, r, i, o, info)
					},
					"Router")
			}
		}
	}
}

func matchPrt(prt1, prt2 *proto) bool {
	proto1 := prt1.proto
	if proto1 == "ip" {
		return true
	}
	proto2 := prt2.proto
	if proto2 == "ip" {
		return true
	}
	if proto1 != proto2 {
		return false
	}
	switch proto1 {
	case "tcp", "udp":
		l1, h1 := prt1.ports[0], prt1.ports[1]
		l2, h2 := prt2.ports[0], prt2.ports[1]
		return l1 <= l2 && h2 <= h1 || l2 <= l1 && h1 <= h2
	case "icmp", "icmpv6":
		type1 := prt1.icmpType
		if type1 == -1 {
			return true
		}
		type2 := prt2.icmpType
		if type2 == -1 {
			return true
		}
		if type1 != type2 {
			return false
		}
		code1 := prt1.icmpCode
		if code1 == -1 {
			return true
		}
		code2 := prt2.icmpCode
		if code2 == -1 {
			return true
		}
		return code1 == code2
	default:
		return true
	}
}

// Matches, if at least one pair of protocols matches.
func matchPrtList(prtList1, prtList2 []*proto) bool {
	for _, prt1 := range prtList1 {
		for _, prt2 := range prtList2 {
			if matchPrt(prt1, prt2) {
				return true
			}
		}
	}
	return false
}

// Find those elements of l, with an IP address matching obj.
// If element is aggregate that is supernet of obj,
// than return all matching networks inside that aggregate.
func getIpMatching(obj *network, l []someObj, natMap natMap) []someObj {
	natObj := getNatNetwork(obj, natMap)
	net1 := natObj.ipp

	var matching []someObj
	for _, src := range l {
		net2 := src.address(natMap)
		if net2.Bits() >= net1.Bits() && net1.Contains(net2.Addr()) {
			// Element is subnet of obj.
			matching = append(matching, src)
		} else if net2.Bits() < net1.Bits() && net2.Contains(net1.Addr()) {
			// Element is supernet of obj.
			if x, ok := src.(*network); ok && x.isAggregate {
				// Convert networks to someObj
				objList := make([]someObj, len(x.networks))
				for i, net := range x.networks {
					objList[i] = net
				}
				networks := getIpMatching(obj, objList, natMap)
				matching = append(matching, networks...)
			} else {
				matching = append(matching, src)
			}
		}
	}
	return matching
}

// Find elements of first list that are not contained in or not equal
// to some element of second list.
func notContainedIn(l1, l2 []someObj) []someObj {
	inL2 := make(map[someObj]bool)
	for _, obj := range l2 {
		inL2[obj] = true
	}
	var result []someObj
OBJ:
	for _, obj := range l1 {
		if inL2[obj] {
			continue
		}
		up := obj
		for {
			up = up.getUp()
			if up == nil {
				break
			}
			if inL2[up] {
				continue OBJ
			}
		}
		result = append(result, obj)
	}
	return result
}

func notInZone(l []someObj, z *zone) []someObj {
	var result []someObj
	for _, obj := range l {
		if !zoneEq(z, obj.getZone()) {
			result = append(result, obj)
		}
	}
	return result
}

func inOneZone(l []someObj) *zone {
	var result *zone
	for _, obj := range l {
		path := obj.getZone()
		z, ok := path.(*zone)
		if !ok {
			return nil
		}
		if result == nil {
			result = z
		} else if result != z {
			return nil
		}
	}
	return result
}

// Mark zones, that are connected by only one router.  Ignore routers
// with only one interface occuring e.g. from split crypto routers.
func (c *spoc) markLeafZones() map[*zone]bool {
	leafZones := make(map[*zone]bool)
	for _, z := range c.allZones {
		count := 0
		for _, intf := range z.interfaces {
			if len(intf.router.interfaces) > 1 {
				count++
			}
		}
		if count <= 1 {
			leafZones[z] = true
		}
	}
	return leafZones
}

// Check if paths from elements of srcList to dstList pass zone.
func (c *spoc) pathsReachZone(z *zone, srcList, dstList []someObj) bool {

	// Collect all zones and routers, where elements are located.
	collect := func(list []someObj) []pathStore {
		seen := make(map[pathStore]bool)
		var result []pathStore
		for _, obj := range list {
			path := obj.getPathNode()
			if !seen[path] {
				seen[path] = true
				result = append(result, path)
			}
		}
		return result
	}
	fromList := collect(srcList)
	toList := collect(dstList)

	zoneReached := false
	checkZone := func(rule *groupedRule, in, out *routerIntf) {

		// Packets traverse zone.
		if in != nil && out != nil && in.zone == z {
			zoneReached = true
		}
	}

	for _, from := range fromList {
		for _, to := range toList {

			// Check if path is available.
			if _, found := from.getPath1()[to]; !found {
				if !pathMark(from, to) {
					continue
				}
			}

			pseudoRule := &groupedRule{
				srcPath: from,
				dstPath: to,
			}
			c.pathWalk(pseudoRule, checkZone, "Zone")
			if zoneReached {
				return true
			}
		}
	}
	return false
}

// Example:
// XX--R1--any:A--R2--R3--R4--YY
//
// If we have rules
//   permit XX any:A
//   permit any:B YY
// and
//   the intersection I of A and B isn't empty
// and
//   XX and YY are subnet of I
// then this traffic is implicitly permitted
//   permit XX YY
// which may be undesired.
// In order to avoid this, a warning is generated if the implied rule is not
// explicitly defined.
func (c *spoc) checkTransientSupernetRules(rules ruleList) {
	c.progress("Checking transient supernet rules")

	isLeafZone := c.markLeafZones()

	// Build mapping from supernet to service rules having supernet as src.
	supernet2rules := make(map[*network]ruleList)

	// Mapping from zone to supernets found in src of rules.
	zone2supernets := make(map[*zone][]*network)
	for _, rule := range rules {
		if rule.noCheckSupernetRules {
			continue
		}
		for _, obj := range rule.src {
			net, ok := obj.(*network)
			if !ok || !net.hasOtherSubnet {
				continue
			}

			// Ignore the internet. If the internet is used as src and dst
			// then the implicit transient rule is assumed to be ok.
			if !net.isAggregate && net.ipp.Bits() == 0 {
				continue
			}

			z := net.zone
			if z.noCheckSupernetRules {
				continue
			}

			// A leaf security zone has only one exit.
			if isLeafZone[z] {

				// Check, if a managed router with only one interface
				// inside the zone is used as destination.
				found := false
				for _, dst := range rule.dst {
					intf, ok := dst.(*routerIntf)
					if !ok {
						continue
					}
					r := intf.router
					if r.managed == "" {
						continue
					}
					if intf.zone != z {
						continue
					}
					if len(r.interfaces) >= 2 {
						continue
					}

					// Then this zone must still be checked.
					delete(isLeafZone, z)
					found = true
				}

				// This leaf zone can't lead to unwanted rule chains.
				if !found {
					continue
				}
			}
			if supernet2rules[net] == nil {
				zone2supernets[z] = append(zone2supernets[z], net)
			}
			supernet2rules[net] = append(supernet2rules[net], rule)
		}
	}
	if len(supernet2rules) == 0 {
		return
	}

	printType := c.conf.CheckTransientSupernetRules

	// Search rules having supernet as dst.
	for _, rule1 := range rules {
		if rule1.noCheckSupernetRules {
			continue
		}
		dstList1 := rule1.dst
		for _, obj1 := range dstList1 {
			net1, ok := obj1.(*network)
			if !ok || !net1.hasOtherSubnet {
				continue
			}
			z := net1.zone
			if isLeafZone[z] {
				continue
			}

			// Find other rules with supernet as src starting in same zone.
			supernets := zone2supernets[z]
			if len(supernets) == 0 {
				continue
			}
			natMap := z.natDomain.natMap
			for _, obj2 := range supernets {

				// Find those elements of src of rule1 with an IP
				// address matching obj2.
				// If mask of obj2 is 0.0.0.0, take all elements.
				// Otherwise check IP addresses in NAT domain of obj2.
				srcList1 := rule1.src
				if obj2.ipp.Bits() != 0 {
					srcList1 = getIpMatching(obj2, srcList1, natMap)
					if len(srcList1) == 0 {
						continue
					}
				}
				for _, rule2 := range supernet2rules[obj2] {
					if !matchPrtList(rule1.prt, rule2.prt) {
						continue
					}
					getSrcRange := func(rule *groupedRule) *proto {
						result := rule.srcRange
						if result == nil {
							result = c.prt.IP
						}
						return result
					}
					if !matchPrt(getSrcRange(rule1), getSrcRange(rule2)) {
						continue
					}

					// Find elements of dst of rule2 with an IP
					// address matching obj1.
					dstList2 := rule2.dst
					if net1.ipp.Bits() != 0 {
						dstList2 = getIpMatching(net1, dstList2, natMap)
						if len(dstList2) == 0 {
							continue
						}
					}
					srcList2 := rule2.src

					// Found transient rules rule1 and rule2.
					// Check, that
					// - either src elements of rule1 are also src of rule2
					// - or dst elements of rule2 are also dst of rule1,
					// - but no problem if src1 and dst2 are located
					//   in same zone, i.e. transient traffic back to src,
					// - also need to ignore unenforceable rule1 and rule2.
					srcList1 = notContainedIn(srcList1, srcList2)
					dstList2 = notContainedIn(dstList2, dstList1)
					if z2 := inOneZone(dstList2); z2 != nil {
						srcList1 = notInZone(srcList1, z2)
					}
					if z1 := inOneZone(srcList1); z1 != nil {
						dstList2 = notInZone(dstList2, z1)
					}
					srcList1 = notInZone(srcList1, z)
					dstList2 = notInZone(dstList2, z)
					if srcList1 != nil && dstList2 != nil &&
						c.pathsReachZone(z, srcList1, dstList2) {

						srv1 := rule1.rule.service.name
						srv2 := rule2.rule.service.name
						match1 := net1.name
						match2 := obj2.name
						match := match1
						if match1 != match2 {
							match = match1 + ", " + match2
						}
						msg := fmt.Sprintf("Missing transient supernet rules\n"+
							" between src of %s and dst of %s,\n"+
							" matching at %s.\n", srv1, srv2, match)
						msg += " Add"
						msg += " missing src elements to " + srv2 + ":\n"
						msg += shortNameList(srcList1)
						msg += "\n or add"
						msg += " missing dst elements to " + srv1 + ":\n"
						msg += shortNameList(dstList2)
						c.warnOrErr(printType, msg)
					}
				}
			}
		}
	}
}

// Handling of supernet rules created by genReverseRules.
// This is not needed if a stateful and not secondary packet filter is
// located on the path between src and dst.
//
// 1. dst is supernet
//
// src--r1:stateful--dst1=supernet1--r2:stateless--dst2=supernet2
//
// genReverseRules will create one additional rule
// supernet2-->src, but not a rule supernet1-->src, because r1 is stateful.
// checkSupernetSrcRule would complain, that supernet1-->src is missing.
// But that doesn't matter, because r1 would permit answer packets
// from supernet2 anyway, because it's stateful.
// Hence we can skip checkSupernetSrcRule for this situation.
//
// 2. src is supernet
//
// a) no stateful router on the path between stateless routers and dst.
//
//             zone2---\
// src=supernet1--r1:stateless--dst
//
// genReverseRules will create one additional rule dst-->supernet1.
// checkSupernetDstRule would complain about a missing rule
// dst-->zone2.
// To prevent this situation, checkSupernetSrcRule checks for a rule
// zone2 --> dst
//
// b) at least one stateful router on the path between
//    stateless router and dst.
//
//               zone3---\
// src1=supernet1--r1:stateless--src2=supernet2--r2:stateful--dst
//
// genReverseRules will create one additional rule
// dst-->supernet1, but not dst-->supernet2 because second router is stateful.
// checkSupernetDstRule would complain about missing rules
// dst-->supernet2 and dst-->supernet3.
// But answer packets back from dst have been filtered by r2 already,
// hence it doesn't hurt if the rules at r1 are a bit too relaxed,
// i.e. r1 would permit dst to zone1 and zone3, but should only
// permit dst to zone1.
// Hence we can skip checkSupernetDstRule for this situation.
//

// Mark zones connected by stateless or secondary packet filters or by
// semiManaged devices.
func markStateful(z *zone, mark int) {
	z.statefulMark = mark
	for _, in := range z.interfaces {
		r := in.router
		managed := r.managed
		if managed != "" && !r.model.stateless &&
			managed != "secondary" && managed != "local" {
			continue
		}
		if r.activePath {
			continue
		}
		r.activePath = true
		defer func() { r.activePath = false }()
		for _, out := range r.interfaces {
			if out == in {
				continue
			}
			next := out.zone
			if next.statefulMark != 0 {
				continue
			}
			markStateful(next, mark)
		}
	}
}

func (c *spoc) checkSupernetRules(p ruleList) {
	if c.conf.CheckSupernetRules != "" {
		c.progress("Checking supernet rules")
		statefulMark := 1
		for _, z := range c.allZones {
			if z.statefulMark == 0 {
				markStateful(z, statefulMark)
				statefulMark++
			}
		}
		// diag.Progress("Checking for missing src in supernet rules");
		c.checkMissingSupernetRules(p, "src", (*spoc).checkSupernetSrcRule)
		// diag.Progress("Checking for missing dst in supernet rules");
		c.checkMissingSupernetRules(p, "dst", (*spoc).checkSupernetDstRule)
	}
	if c.conf.CheckTransientSupernetRules != "" {
		c.checkTransientSupernetRules(p)
	}
}
