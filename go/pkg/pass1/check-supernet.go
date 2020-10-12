package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"net"
	"strings"
)

// Two zones are zoneEq, if
// - zones are equal or
// - both belong to the same zone cluster.
func zoneEq(z1, z2 *zone) bool {
	if z1 == z2 {
		return true
	}
	c1 := z1.zoneCluster
	c2 := z2.zoneCluster
	if len(c1) == 0 || len(c2) == 0 {
		return false
	}
	// Each zone of a cluster references the same slice, so it is
	// sufficient to compare first element.
	return c1[0] == c2[0]
}

// Print abbreviated list of names in messages.
func shortNameList(list []someObj) string {
	names := make([]string, 0, 4)
	for _, obj := range list {
		if len(names) == 3 {
			names = append(names, "...")
			break
		}
		names = append(names, obj.String())
	}
	return " - " + strings.Join(names, "\n - ")
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
// - invible aggregates, only used intermediately in automatic groups,
// - small networks which are subnet of a matching network,
// - objects that are
//   - element of net_hash or
//   - subnet of element of net_hash.
// Result: List of found networks or aggregates or undef.
func findZoneNetworks(zone *zone, ip net.IP, mask net.IPMask, natSet natSet, netMap map[*network]bool) netList {

	// Check if argument or some supernet of argument is member of netMap.
	inNetHash := func(netOrAgg *network) bool {
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
	key := ipmask{string(ip), string(mask)}
	aggregate := zone.ipmask2aggregate[key]
	if aggregate != nil && !aggregate.invisible {
		if inNetHash(aggregate) {
			return nil
		}
		return netList{aggregate}
	}

	// Use cached result.
	if net, found := zone.ipmask2net[key]; found {
		return net
	}

	// Real networks in zone without aggregates and without subnets.
	var result netList
	prefix, _ := mask.Size()
	for _, net := range zone.networks {
		if inNetHash(net) {
			continue
		}
		natNet := getNatNetwork(net, natSet)
		if natNet.hidden {
			continue
		}
		i, m := natNet.ip, natNet.mask
		p, _ := m.Size()
		if p >= prefix && matchIp(i, ip, mask) || p < prefix && matchIp(ip, i, m) {
			result = append(result, net)
		}
	}
	if zone.ipmask2net == nil {
		zone.ipmask2net = make(map[ipmask]netList)
	}
	zone.ipmask2net[key] = result
	return result
}

// Prevent multiple error messages about missing supernet rules;
type intfAndSrv struct {
	inf *routerIntf
	srv *service
}

var missingSupernet = make(map[intfAndSrv]bool)

// rule: the rule to be checked
// where: has value 'src' or 'dst'
// interface: interface, where traffic reaches the device,
//             this is used to determine nat_set
// zone: The zone to be checked.
//        If where is 'src', then zone is attached to interface
//        If where is 'dst', then zone is at other side of device.
// reversed: (optional) the check is for reversed rule at stateless device
func checkSupernetInZone(rule *groupedRule, where string, intf *routerIntf, zone *zone, reversed bool) {
	if zone.noCheckSupernetRules {
		return
	}
	service := rule.rule.service
	if missingSupernet[intfAndSrv{intf, service}] {
		return
	}

	// This is only called if src or dst is some supernet.
	var supernet *network
	if where == "src" {
		supernet = rule.src[0].(*network)
	} else {
		supernet = rule.dst[0].(*network)
	}
	natSet := intf.natSet
	natSuper := getNatNetwork(supernet, natSet)
	if natSuper.hidden {
		return
	}
	ip, mask := natSuper.ip, natSuper.mask
	netMap := rule.zone2netMap[zone]
	networks := findZoneNetworks(zone, ip, mask, natSet, netMap)
	if len(networks) == 0 {
		return
	}

	missingSupernet[intfAndSrv{intf, service}] = true
	orAgg := ""
	net0 := networks[0]

	if len(networks) > 2 {

		// Show also aggregate, if multiple networks are found.
		prefix, _ := mask.Size()
		orAgg = fmt.Sprintf("any:[ ip=%s/%d & %s ]",
			ip.String(), prefix, net0.name)
	} else if net0.isAggregate {

		// If aggregate has networks, show both, networks and aggreagte.
		aggNets := net0.networks
		if len(aggNets) > 0 {
			networks = aggNets
			orAgg = net0.name
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
	if where != "src" {
		fromTo = "to"
	}
	objects := make([]someObj, len(networks))
	for i, n := range networks {
		objects[i] = n
	}
	warnOrErrMsg(
		conf.Conf.CheckSupernetRules,
		"This %ssupernet rule would permit unexpected access:\n"+
			"  %s\n"+
			" Generated ACL at %s would permit access"+
			" %s additional networks:\n"+
			"%s\n"+
			" Either replace %s by smaller networks that are not supernet\n"+
			" or add above-mentioned networks to %s of rule%s.",
		rev,
		rule.print(),
		intf.name,
		fromTo,
		shortNameList(objects),
		supernet.name,
		where,
		orAgg,
	)
}

// Check if path between supernet and objList is filtered by
// device with mark from router.localMark.
func isFilteredAt(mark int, supernet *network, objList []someObj) bool {
	supernetFilterAt := supernet.filterAt
	if supernetFilterAt == nil {
		return false
	}
	if !supernetFilterAt[mark] {
		return false
	}
	for _, obj := range objList {
		objNet := obj.getNetwork()
		objFilterAt := objNet.filterAt
		if objFilterAt == nil {
			continue
		}
		if !objFilterAt[mark] {
			continue
		}
		return true
	}
	return false
}

func (x *zone) getZone() *zone {
	return x
}
func (x *router) getZone() *zone {
	if x.managed == "" {
		return x.interfaces[0].network.zone
	} else {
		return x.zone
	}
}
func (x *routerIntf) getZone() *zone {
	if x.router.managed == "" {
		return x.network.zone
	} else {
		return x.router.zone
	}
}
func (x *network) getZone() *zone {
	return x.zone
}
func (x *subnet) getZone() *zone {
	return x.network.zone
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
// This is so, because at R2 we would get an automatically generated
// reverse rule
//  permit dst supernet1
// which would accidentally permit traffic to supernet:[zone4] as well.
func checkSupernetSrcRule(rule *groupedRule, inIntf, outIntf *routerIntf) {

	// Ignore semi_managed router.
	r := inIntf.router
	if r.managed == "" {
		return
	}

	// This is only called if src is some supernet.
	src := rule.src[0].(*network)

	// Non matching rule will be ignored at 'managed=local' router and
	// hence must no be checked.
	if mark := r.localMark; mark != 0 {
		if !isFilteredAt(mark, src, rule.dst) {
			return
		}
	}

	dstZone := rule.dstPath.getZone()
	inZone := inIntf.zone

	// Check case II, outgoing ACL, (A)
	var noAclIntf *routerIntf
	if noAclIntf = r.noInAcl; noAclIntf != nil {
		noAclZone := noAclIntf.zone

		if zoneEq(noAclZone, dstZone) {
			// a) dst behind Y
		} else if zoneEq(inZone, noAclZone) {
			// b), 1. zone X == zone Y
		} else if noAclIntf.mainIntf != nil {
		} else {
			// b), 2. zone X != zone Y
			checkSupernetInZone(rule, "src", noAclIntf, noAclZone, false)
		}
	}

	srcZone := src.zone

	// Check if reverse rule would be created and would need additional rules.
	stateful := false
	for _, prt := range rule.prt {
		switch prt.proto {
		case "tcp", "udp", "ip":
			stateful = true
			break
		}
	}
	if outIntf != nil && r.model.stateless && !rule.oneway && stateful {
		outZone := outIntf.zone

		// Reverse rule wouldn't allow too much traffic, if a non
		// secondary stateful device filters between current device and dst.
		// This is true if out_zone and dst_zone have different
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
		m2 := dstZone.statefulMark
		if m2 != 0 && m1 == m2 {

			// Check case II, outgoing ACL, (B), interface Y without ACL.
			if noAclIntf := r.noInAcl; noAclIntf != nil {
				noAclZone := noAclIntf.zone

				if zoneEq(noAclZone, dstZone) {
					// a) dst behind Y
				} else if zoneEq(noAclZone, srcZone) {
					// b) dst not behind Y
					// zone X == zone Y
				} else if noAclIntf.mainIntf != nil {
				} else {
					// zone X != zone Y
					checkSupernetInZone(rule, "src", noAclIntf, noAclZone, true)
				}
			} else {
				// Standard incoming ACL at all interfaces.

				// Find security zones at all interfaces except the in_intf.
				for _, intf := range r.interfaces {
					if intf == inIntf {
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
					if intf.mainIntf != nil {
						continue
					}
					checkSupernetInZone(rule, "src", intf, zone, true)
				}
			}
		}
	}

	// Nothing to do at first router.
	// zone2 is checked at R2, because we need the natSet at R2.
	if zoneEq(srcZone, inZone) {
		return
	}

	// Check if rule "supernet2 -> dst" is defined.
	checkSupernetInZone(rule, "src", inIntf, inZone, false)
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
func checkSupernetDstRule(rule *groupedRule, inIntf, outIntf *routerIntf) {

	// Source is interface of current router.
	if inIntf == nil {
		return
	}

	// Ignore semi_managed router.
	r := inIntf.router
	if r.managed == "" {
		return
	}

	// This is only called if dst is some supernet.
	dst := rule.dst[0].(*network)

	// Non matching rule will be ignored at 'managed=local' router and
	// hence must not be checked.
	if mark := r.localMark; mark != 0 {
		if !isFilteredAt(mark, dst, rule.src) {
			return
		}
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
		} else if noAclIntf.mainIntf != nil {
		} else {
			// zone X != zone Y
			checkSupernetInZone(rule, "dst", inIntf, noAclZone, false)
		}
		return
	}

	// Check security zones at all interfaces except those connected
	// to dst or src.
	// For devices which have rules for each pair of incoming and outgoing
	// interfaces we only need to check the direct path to dst.
	inZone := inIntf.zone
	check := func(intf *routerIntf) {

		// Check each intermediate zone only once at outgoing interface.
		if intf == inIntf {
			return
		}
		if intf.loopback {
			return
		}

		// Don't check interface where src or dst is attached.
		zone := intf.zone
		if zoneEq(zone, srcZone) {
			return
		}
		if zoneEq(zone, dstZone) {
			return
		}
		if zoneEq(zone, inZone) {
			return
		}
		if intf.mainIntf != nil {
			return
		}
		checkSupernetInZone(rule, "dst", inIntf, zone, false)
	}
	if r.model.hasIoACL {
		check(outIntf)
	} else {
		for _, intf := range r.interfaces {
			check(intf)
		}
	}
}

// Check missing supernet of each serviceRule.
func checkMissingSupernetRules(rules ruleList, what string,
	worker func(r *groupedRule, i, o *routerIntf)) {
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

		// Build mapping from zone to hash of all src/dst networks and
		// aggregates of current rule.
		zone2netMap := make(map[*zone]map[*network]bool)
		for _, obj := range list {
			if x, ok := obj.(*network); ok {
				zone := x.zone
				netMap := zone2netMap[zone]
				if netMap == nil {
					netMap = make(map[*network]bool)
					zone2netMap[zone] = netMap
				}
				netMap[x] = true
			}
		}
		rule.zone2netMap = zone2netMap

		groupInfo := splitRuleGroup(oList)
		checkRule := new(groupedRule)
		checkRule.serviceRule = rule.serviceRule
		for _, supernet := range supernets {
			if what == "src" {
				checkRule.src = []someObj{supernet}
				checkRule.srcPath = supernet.zone
			} else {
				checkRule.dst = []someObj{supernet}
				checkRule.dstPath = supernet.zone
			}
			for _, gi := range groupInfo {
				otherZone := gi.path.getZone()
				if zoneEq(supernet.zone, otherZone) {
					continue
				}
				if what == "src" {
					checkRule.dstPath = gi.path
					checkRule.dst = gi.group
				} else {
					checkRule.srcPath = gi.path
					checkRule.src = gi.group
				}
				pathWalk(checkRule, worker, "Router")
			}
		}
		rule.zone2netMap = nil
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
	if proto1 == "tcp" || proto1 == "udp" {
		l1, h1 := prt1.ports[0], prt1.ports[1]
		l2, h2 := prt2.ports[0], prt2.ports[1]
		return l1 <= l2 && h2 <= h1 || l2 <= l1 && h1 <= h2
	} else if proto1 == "icmp" {
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
	} else {
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

// Find those elements of list, with an IP address matching obj.
// If element is aggregate that is supernet of obj,
// than return all matching networks inside that aggregate.
func getIpMatching(obj *network, list []someObj, natSet natSet) []someObj {
	natObj := getNatNetwork(obj, natSet)
	ip, mask := natObj.ip, natObj.mask
	prefix, _ := mask.Size()

	var matching []someObj
	for _, src := range list {
		net := src.address(natSet)
		i, m := net.IP, net.Mask
		p, _ := m.Size()

		if p >= prefix && matchIp(i, ip, mask) {
			// Element is subnet of obj.
			matching = append(matching, src)
		} else if p < prefix && matchIp(ip, i, m) {
			// Element is supernet of obj.
			x, ok := src.(*network)
			if ok && x.isAggregate {
				// Convert networks to someObj
				objList := make([]someObj, len(x.networks))
				for i, net := range x.networks {
					objList[i] = net
				}
				networks := getIpMatching(obj, objList, natSet)
				matching = append(matching, networks...)
			} else {
				matching = append(matching, src)
			}
		}
	}
	return matching
}

// Check that all elements of first list are contained in or equal to
// some element of second list.
func allContainedIn(list1, list2 []someObj) bool {
	inList2 := make(map[someObj]bool)
	for _, obj := range list2 {
		inList2[obj] = true
	}
OBJ:
	for _, obj := range list1 {
		if inList2[obj] {
			continue
		}
		up := obj
		for {
			up = up.getUp()
			if up == nil {
				return false
			}
			if inList2[up] {
				continue OBJ
			}
		}
	}
	return true
}

// Get elements that were missing
// from allContainedIn and elementsInOneZone.
func getMissing(list1, list2 []someObj, zone *zone) []someObj {
	inList2 := make(map[someObj]bool)
	for _, obj := range list2 {
		inList2[obj] = true
	}
	var missing []someObj
OBJ:
	for _, obj := range list1 {
		if inList2[obj] {
			continue
		}
		zone2 := obj.getZone()
		if zone2 == zone {
			continue
		}
		up := obj
		for {
			up = up.getUp()
			if up == nil {
				break
			}
			if inList2[up] {
				continue OBJ
			}
		}
		missing = append(missing, obj)
	}
	return missing
}

func elementsInOneZone(list1, list2 []someObj) bool {
	zone0 := list1[0].getZone()
	check := func(list []someObj) bool {
		for _, obj := range list {
			zone := obj.getZone()
			if !zoneEq(zone0, zone) {
				return false
			}
		}
		return true
	}
	return check(list1[1:]) && check(list2)
}

// Mark zones, that are connected by only one router.  Ignore routers
// with only one interface occuring e.g. from split crypto routers.
func markLeafZones() map[*zone]bool {
	leafZones := make(map[*zone]bool)
	for _, zone := range zones {
		count := 0
		for _, intf := range zone.interfaces {
			if len(intf.router.interfaces) > 1 {
				count++
			}
		}
		if count <= 1 {
			leafZones[zone] = true
		}
	}
	return leafZones
}

// Check if paths from elements of srcList to dstList pass zone.
func pathsReachZone(zone *zone, srcList, dstList []someObj) bool {

	// Collect all zones and routers, where elements are located.
	collect := func(list []someObj) []pathStore {
		seen := make(map[pathStore]bool)
		var result []pathStore
		for _, obj := range list {
			path := obj.getPathNode()
			if path == zone {
				continue
			}
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
	checkZone := func(rule *groupedRule, inIntf, outIntf *routerIntf) {

		// Packets traverse zone.
		if inIntf != nil && outIntf != nil && inIntf.zone == zone {
			zoneReached = true
		}
	}

	for _, from := range fromList {
		for _, to := range toList {

			// Check if path from from to to is available.
			if _, found := from.getPath1()[to]; !found {
				if !pathMark(from, to) {
					delete(from.getPath1(), to)

					// No path found, check next pair.
					continue
				}
			}
			pseudoRule := &groupedRule{
				srcPath: from,
				dstPath: to,
			}
			pathWalk(pseudoRule, checkZone, "Zone")
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
func checkTransientSupernetRules(rules ruleList) {
	diag.Progress("Checking transient supernet rules")

	isLeafZone := markLeafZones()

	// Build mapping from supernet to service rules having supernet as src.
	supernet2rules := make(map[*network]ruleList)

	// Mapping from zone to supernets found in src of rules.
	zone2supernets := make(map[*zone][]*network)
	for _, rule := range rules {
		if rule.noCheckSupernetRules {
			continue
		}
		srcList := rule.src
		for _, obj := range srcList {
			net, ok := obj.(*network)
			if !ok || !net.hasOtherSubnet {
				continue
			}

			// Ignore the internet. If the internet is used as src and dst
			// then the implicit transient rule is assumed to be ok.
			if !net.isAggregate {
				if size, _ := net.mask.Size(); size == 0 {
					continue
				}
			}

			zone := net.zone
			if zone.noCheckSupernetRules {
				continue
			}

			// A leaf security zone has only one exit.
			if isLeafZone[zone] {

				// Check, if a managed router with only one interface
				// inside the zone is used as destination.
				found := false
				for _, dst := range rule.dst {
					intf, ok := dst.(*routerIntf)
					if !ok {
						continue
					}
					router := intf.router
					if router.managed == "" {
						continue
					}
					if intf.zone != zone {
						continue
					}
					if len(router.interfaces) >= 2 {
						continue
					}

					// Then this zone must still be checked.
					delete(isLeafZone, zone)
					found = true
				}

				// This leaf zone can't lead to unwanted rule chains.
				if !found {
					continue
				}
			}
			if supernet2rules[net] == nil {
				zone2supernets[zone] = append(zone2supernets[zone], net)
			}
			supernet2rules[net] = append(supernet2rules[net], rule)
		}
	}
	if len(supernet2rules) == 0 {
		return
	}

	printType := conf.Conf.CheckTransientSupernetRules

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
			zone := net1.zone
			if zone.noCheckSupernetRules {
				continue
			}
			if isLeafZone[zone] {
				continue
			}

			// Find other rules with supernet as src starting in same zone.
			supernets := zone2supernets[zone]
			if len(supernets) == 0 {
				continue
			}
			natSet := zone.natDomain.natSet
			for _, obj2 := range supernets {

				// Find those elements of src of rule1 with an IP
				// address matching obj2.
				// If mask of obj2 is 0.0.0.0, take all elements.
				// Otherwise check IP addresses in NAT domain of obj2.
				srcList1 := rule1.src
				if size, _ := obj2.mask.Size(); size != 0 {
					srcList1 = getIpMatching(obj2, srcList1, natSet)
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
							result = prtIP
						}
						return result
					}
					if !matchPrt(getSrcRange(rule1), getSrcRange(rule2)) {
						continue
					}

					// Find elements of dst of rule2 with an IP
					// address matching obj1.
					dstList2 := rule2.dst
					if size, _ := net1.mask.Size(); size != 0 {
						dstList2 = getIpMatching(net1, dstList2, natSet)
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
					if !(allContainedIn(srcList1, srcList2) ||
						allContainedIn(dstList2, dstList1)) &&
						!elementsInOneZone(srcList1, dstList2) &&
						!elementsInOneZone(srcList1, []someObj{obj2}) &&
						!elementsInOneZone([]someObj{obj1}, dstList2) &&
						pathsReachZone(zone, srcList1, dstList2) {
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
						missingSrc := getMissing(srcList1, srcList2, zone)
						missingDst := getMissing(dstList2, dstList1, zone)
						msg += " Add"
						if missingSrc != nil {
							msg += " missing src elements to " + srv2 + ":\n"
							msg += shortNameList(missingSrc)
						}
						if missingDst != nil {
							if missingSrc != nil {
								msg += "\n or add"
							}
							msg += " missing dst elements to " + srv1 + ":\n"
							msg += shortNameList(missingDst)
						}
						warnOrErrMsg(printType, msg)
					}
				}
			}
		}
	}
	//    diag.Progress("Transient check is ready");
}

// Handling of supernet rules created by genReverseRules.
// This is not needed if a stateful and not secondary packet filter is
// located on the path between src and dst.
//
// 1. dst is supernet
//
// src--r1:stateful--dst1=supernet1--r2:stateless--dst2=supernet2
//
// gen_reverse_rule will create one additional rule
// supernet2-->src, but not a rule supernet1-->src, because r1 is stateful.
// check_supernet_src_rule would complain, that supernet1-->src is missing.
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
// gen_reverse_rules will create one additional rule dst-->supernet1.
// check_supernet_dst_rule would complain about a missing rule
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
// gen_reverse_rules will create one additional rule
// dst-->supernet1, but not dst-->supernet2 because second router is stateful.
// check_supernet_dst_rule would complain about missing rules
// dst-->supernet2 and dst-->supernet3.
// But answer packets back from dst have been filtered by r2 already,
// hence it doesn't hurt if the rules at r1 are a bit too relaxed,
// i.e. r1 would permit dst to zone1 and zone3, but should only
// permit dst to zone1.
// Hence we can skip checkSupernetDstRule for this situation.
//

// Mark zones connected by stateless or secondary packet filters or by
// semiManaged devices.
func markStateful(zone *zone, mark int) {
	zone.statefulMark = mark
	for _, inIntf := range zone.interfaces {
		router := inIntf.router
		managed := router.managed
		if managed != "" && !router.model.stateless &&
			managed != "secondary" && managed != "local" {
			continue
		}
		if router.activePath {
			continue
		}
		router.activePath = true
		defer func() { router.activePath = false }()
		for _, outIntf := range router.interfaces {
			if outIntf == inIntf {
				continue
			}
			nextZone := outIntf.zone
			if nextZone.statefulMark != 0 {
				continue
			}
			markStateful(nextZone, mark)
		}
	}
}

func CheckSupernetRules(p ruleList) {
	if conf.Conf.CheckSupernetRules != "" {
		diag.Progress("Checking supernet rules")
		statefulMark := 1
		for _, zone := range zones {
			if zone.statefulMark == 0 {
				markStateful(zone, statefulMark)
				statefulMark++
			}
		}
		// diag.Progress("Checking for missing src in supernet rules");
		checkMissingSupernetRules(p, "src", checkSupernetSrcRule)
		// diag.Progress("Checking for missing dst in supernet rules");
		checkMissingSupernetRules(p, "dst", checkSupernetDstRule)
		missingSupernet = nil
	}
	if conf.Conf.CheckTransientSupernetRules != "" {
		checkTransientSupernetRules(p)
	}
}
