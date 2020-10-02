package pass1

import (
	"bytes"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"net"
	"sort"
)

//##############################################################################
// Purpose  : Create zones and areas.
func SetZone() map[pathObj]map[*area]bool {
	diag.Progress("Preparing security zones and areas")
	setZones()
	clusterZones()
	crosslinkRouters := checkCrosslink()
	clusterCrosslinkRouters(crosslinkRouters)
	objInArea := setAreas()
	checkAreaSubsetRelations(objInArea)
	processAggregates()
	inheritAttributes()
	return objInArea // For use in cut-netspoc
}

//#############################################################################
// Purpose  : Create new zone for every network without a zone.
func setZones() {
	for _, n := range allNetworks {
		if n.zone != nil {
			continue
		}

		// Create zone.
		name := "any:[" + n.name + "]"
		z := &zone{name: name, ipmask2aggregate: make(map[ipmask]*network)}
		z.ipV6 = n.ipV6
		zones = append(zones, z)

		// Collect zone elements...
		setZone1(n, z, nil)

		// Attribute isTunnel was set when zone has some tunnel networks,
		// but must only be set, if it has only tunnel networks.
		if z.networks != nil { // tunnel networks aren't referenced in zone
			z.isTunnel = false
		}
	}
}

//##############################################################################
// Purpose  : Collects all elements (networks, unmanaged routers, interfaces)
//            of a zone and references the zone in its elements.
//            Sets zone attribute.
// Comments : Unnumbered and tunnel networks are not referenced in zones,
//            as they are no valid src or dst.
func setZone1(n *network, z *zone, in *routerIntf) {

	// Network was processed already (= loop was found).
	if n.zone != nil {
		return
	}

	// Reference zone in network and vice versa...
	n.zone = z
	if !(n.unnumbered || n.tunnel) { // no valid src/dst
		z.networks.push(n)
	}

	//debug("%s in %s", n, z)

	// Set zone property attributes depending on network properties...
	if n.tunnel {
		z.isTunnel = true
	}
	if n.hasIdHosts {
		z.hasIdHosts = true
	}
	if n.partition != "" && z.partition != "" {
		errMsg("Only one partition name allowed in zone %s, but found:\n"+
			" - %s\n - %s",
			z, n.partition, z.partition)
	}
	z.partition = n.partition

	// Mark zone at loopback network of managed router.
	if n.loopback && n.interfaces[0].router.managed != "" {
		z.loopback = true
	}

	// Proceed with adjacent elements...
	for _, intf := range n.interfaces {
		if intf == in {
			continue
		}

		// If it's a zone delimiting router, reference interface in zone and v.v.
		r := intf.router
		if r.managed != "" || r.semiManaged {
			intf.zone = z
			z.interfaces.push(intf)
		} else if r.zone == nil {

			// If it's an unmanaged router, reference router in zone and v.v.
			// Traverse each unmanaged router only once.
			r.zone = z // added only to prevent repeated traversal.
			z.unmanagedRouters = append(z.unmanagedRouters, r)

			// Recursively add adjacent networks.
			for _, out := range r.interfaces {
				if out != intf && !out.disabled {
					setZone1(out.network, z, out)
				}
			}
		}
	}
}

//#############################################################################
// Purpose  : Clusters zones connected by semiManaged routers. All
//            zones of a cluster are stored in attribute zoneCluster of
//            the zones.
// Comments : Attribute zoneCluster is only set if the cluster has more
//            than one element.
func clusterZones() {

	// Process remaining unclustered zones.
	for _, z := range zones {
		if z.zoneCluster == nil {

			// Create a new cluster and collect its zones
			cluster := make([]*zone, 0, 1)
			getZoneCluster(z, nil, &cluster)

			// Set cluster if more than current zone was found.
			if len(cluster) > 1 {
				for _, z2 := range cluster {
					z2.zoneCluster = cluster
				}
			} else {
				z.zoneCluster = nil
			}
		}
	}
}

//#############################################################################
// Purpose  : Collect zones connected by semiManaged devices into a cluster.
// Comments : Tunnel zone is not included in zone cluster, because
//            - it is useless in rules and
//            - we would get inconsistent owner since zone of tunnel
//              doesn't inherit from area.
func getZoneCluster(z *zone, in *routerIntf, collected *[]*zone) {

	// Reference zone in cluster list and vice versa.
	if !z.isTunnel {
		*collected = append(*collected, z)
		// Set preliminary list as marker, that this zone has been processed.
		z.zoneCluster = *collected
	}

	// Find zone interfaces connected to semi-managed routers...
	for _, intf := range z.interfaces {
		if intf == in || intf.mainIntf != nil {
			continue
		}
		r := intf.router
		if r.managed != "" || r.activePath {
			continue
		}
		r.activePath = true
		defer func() { r.activePath = false }()

		// Process adjacent zones...
		for _, out := range r.interfaces {
			if out == intf || out.mainIntf != nil {
				continue
			}
			next := out.zone
			if next.zoneCluster == nil {
				// Add adjacent zone recursively.
				getZoneCluster(next, out, collected)
			}
		}
	}
}

// If routers are connected by crosslink network then
// no filter is needed if both have equal strength.
// If routers have different strength,
// then only the weakest devices omit the filter.
var crosslinkStrength = map[string]int{
	"primary":   10,
	"full":      10,
	"standard":  9,
	"secondary": 8,
	"local":     7,
}

//#############################################################################
// A crosslink network combines two or more routers to one virtual router.
// Purpose  : Assures proper usage of crosslink networks and applies the
//            crosslink attribute to the networks weakest interfaces (no
//            filtering needed at these interfaces).
// Returns  : Map storing crosslinked routers with attribute needProtect set.
// Comments : Function uses hardware attributes from func checkNoInAcl.
func checkCrosslink() map[*router]bool {
	// Collect crosslinked routers with attribute needProtect.
	crosslinkRouters := make(map[*router]bool)

	// Process all crosslink networks
	for _, n := range symTable.network {
		if !n.crosslink || n.disabled {
			continue
		}

		// Prepare tests.
		// To identify interfaces with min router strength.
		strength2intf := make(map[int]intfList)
		// Assure outAcl at all/none of the interfaces.
		outAclCount := 0
		// Assure all noInAcl interfaces to border the same zone.
		var noInAclIntf intfList

		// Process network interfaces to fill above variables.
		for _, intf := range n.interfaces {
			if intf.mainIntf != nil {
				continue
			}
			r := intf.router
			hw := intf.hardware

			// Assure correct usage of crosslink network.
			if r.managed == "" {
				errMsg("Crosslink %s must not be connected to unmanged %s", n, r)
				continue
			}
			if nonSecondaryIntfCount(hw.interfaces) != 1 {
				errMsg("Crosslink %s must be the only network"+
					" connected to hardware '%s' of %s", n, hw.name, r)
			}

			strength := crosslinkStrength[r.managed]
			strength2intf[strength] = append(strength2intf[strength], intf)

			if r.needProtect {
				crosslinkRouters[r] = true
			}

			if hw.needOutAcl {
				outAclCount++
			}

			for _, intf := range r.interfaces {
				if intf.hardware.noInAcl {
					noInAclIntf.push(intf)
				}
			}
		}

		// Apply attribute 'crosslink' to the networks weakest interfaces.
		weakest := 99
		for i, _ := range strength2intf {
			if i < weakest {
				weakest = i
			}
		}
		for _, intf := range strength2intf[weakest] {
			intf.hardware.crosslink = true
		}

		// Assure 'secondary' and 'local' are not mixed in crosslink network.
		if weakest == crosslinkStrength["local"] &&
			strength2intf[crosslinkStrength["secondary"]] != nil {
			errMsg("Must not use 'managed=local' and 'managed=secondary'"+
				" together\n at crosslink %s", n)
		}

		// Assure proper usage of crosslink network.
		if outAclCount != 0 && outAclCount != len(n.interfaces) {
			errMsg("All interfaces must equally use or not use outgoing ACLs"+
				" at crosslink %s", n)
		} else if len(noInAclIntf) >= 1 {
			z0 := noInAclIntf[0].zone
			for _, intf := range noInAclIntf[1:] {
				if intf.zone != z0 {
					errMsg("All interfaces with attribute 'no_in_acl'"+
						" at routers connected by\n"+
						" crosslink %s must be border of the same security zone", n)
					break
				}
			}
		}
	}
	return crosslinkRouters
}

//#############################################################################
// Purpose   : Find clusters of routers connected directly or indirectly by
//             crosslink networks and having at least one device with
//             attribute needProtect.
// Parameter : Map with crosslinked routers having attribute needProtect set.
func clusterCrosslinkRouters(crosslinkRouters map[*router]bool) {
	var cluster []*router
	seen := make(map[*router]bool)

	// Add routers to cluster via depth first search.
	var walk func(r *router)
	walk = func(r *router) {
		seen[r] = true
		cluster = append(cluster, r)
		for _, inIntf := range r.interfaces {
			n := inIntf.network
			if n.crosslink && !n.disabled {
				for _, outIntf := range n.interfaces {
					if outIntf == inIntf {
						continue
					}
					r2 := outIntf.router
					if !seen[r2] {
						walk(r2)
					}
				}
			}
		}
	}

	// Process all needProtect crosslinked routers.
	for r, _ := range crosslinkRouters {
		if seen[r] {
			continue
		}

		// Fill router cluster
		cluster = nil
		walk(r)

		sort.Slice(cluster, func(i, j int) bool {
			return cluster[i].name < cluster[j].name
		})

		// Collect all interfaces belonging to needProtect routers of cluster...
		var crosslinkIntfs []*routerIntf
		for _, r2 := range cluster {
			if crosslinkRouters[r2] {
				crosslinkIntfs = append(crosslinkIntfs, r2.interfaces...)
			}
		}

		// ... add information to every cluster member as list
		// used in printAcls.
		for _, r2 := range cluster {
			r2.crosslinkIntfs = crosslinkIntfs
		}
	}
}

const (
	missingBorder = iota
	normalBorder
	inclusiveBorder
	foundBorder
)

type borderType int
type bLookup map[*routerIntf]borderType

//##############################################################################s
// Purpose  : Set up areas, assure proper border definitions.
func setAreas() map[pathObj]map[*area]bool {
	objInArea := make(map[pathObj]map[*area]bool)
	var sortedAreas []*area
	for _, a := range symTable.area {
		sortedAreas = append(sortedAreas, a)
	}
	sort.Slice(sortedAreas, func(i, j int) bool {
		return sortedAreas[i].name < sortedAreas[j].name
	})
	for _, a := range sortedAreas {
		if a.disabled {
			continue
		}
		if n := a.anchor; n != nil {
			setArea(n.zone, a, nil, nil, objInArea)
		} else {

			// For efficient look up if some interface is a border of current area.
			lookup := make(bLookup)

			var start *routerIntf
			var obj1 pathObj

			// Collect all area delimiting interfaces in lookup.
			for _, intf := range a.border {
				lookup[intf] = normalBorder
			}
			for _, intf := range a.inclusiveBorder {
				if _, found := lookup[intf]; found {
					errMsg("%s is used as 'border' and 'inclusive_border' in %s",
						intf, a)
				}
				lookup[intf] = inclusiveBorder
			}
			// Identify start interface and direction for area traversal.
			if len(a.border) >= 1 {
				start = a.border[0]
				obj1 = start.zone
			} else if len(a.inclusiveBorder) >= 1 {
				start = a.inclusiveBorder[0]
				obj1 = start.router
			}

			// Collect zones and routers of area and keep track of borders found.
			lookup[start] = foundBorder
			err := setArea(obj1, a, start, lookup, objInArea)
			if err {
				continue
			}

			// Assert that all borders were found.
			// Remove invalid borders.
			check := func(l []*routerIntf, attr string) []*routerIntf {
				var badIntf intfList
				j := 0
				for _, intf := range l {
					if lookup[intf] != foundBorder {
						badIntf.push(intf)
					} else {
						l[j] = intf
						j++
					}
				}
				l = l[:j]
				if badIntf != nil {
					errMsg("Unreachable %s of %s:\n%s",
						attr, a.name, badIntf.nameList())
				}
				return l
			}
			a.border = check(a.border, "border")
			a.inclusiveBorder = check(a.inclusiveBorder, "inclusiveBorder")

			// Check whether area is empty (= consist of a single router)
			if len(a.zones) == 0 {
				warnMsg("%s is empty", a.name)
			}
		}

		//var names stringList
		//for _, z := range a.zones {
		//	names.push(z.name)
		//}
		//debug("%s:\n %s", a.name, strings.Join(names, "\n "))
	}
	return objInArea
}

//##############################################################################
// Purpose  : Collect zones and routers of an area.
// Returns  : false, or true if error was found.
func setArea(obj pathObj, a *area, in *routerIntf,
	lookup bLookup, objInArea map[pathObj]map[*area]bool) bool {
	errPath := setArea1(obj, a, in, lookup, objInArea)
	if errPath == nil {
		return false
	}

	// Print error path, if errors occurred
	errPath.push(in)
	// Reverse path.
	for i, j := 0, len(errPath)-1; i < j; i, j = i+1, j-1 {
		errPath[i], errPath[j] = errPath[j], errPath[i]
	}
	errMsg("Inconsistent definition of %s in loop.\n"+
		" It is reached from outside via this path:\n%s",
		a.name, errPath.nameList())
	return true
}

//##############################################################################
// Purpose  : Collect zones and managed routers of an area and set a
//            reference to the area in its zones and routers.
//            Keep track of area borders found during area traversal.
// Returns  : nil or list of interfaces, if invalid path was found.
func setArea1(obj pathObj, a *area, in *routerIntf,
	lookup bLookup, objInArea map[pathObj]map[*area]bool) intfList {

	// Found a loop.
	if objInArea[obj][a] {
		return nil
	}

	// Find duplicate/overlapping areas or loops
	m := objInArea[obj]
	if m == nil {
		m = make(map[*area]bool)
		objInArea[obj] = m
	}
	m[a] = true

	isZone := false
	switch x := obj.(type) {
	case *zone:
		isZone = true
		// Reference zones and managed routers in corresponding area.
		if !x.isTunnel {
			a.zones = append(a.zones, x)
		}
	case *router:
		if x.managed != "" || x.routingOnly {
			a.managedRouters = append(a.managedRouters, x)
		}
	}

	for _, intf := range obj.intfList() {
		if intf == in || intf.mainIntf != nil {
			continue
		}

		// For areas with defined borders, check if border was found...
		if t, found := lookup[intf]; found {
			// Reached border from wrong side or border classification wrong.
			if t == inclusiveBorder != !isZone {
				// will be collected to show invalid path
				return intfList{intf}
			}

			// ...mark found border.
			lookup[intf] = foundBorder
			continue
		}

		// Proceed traversal with next element.
		var next pathObj
		if isZone {
			next = intf.router
		} else {
			next = intf.zone
		}
		errPath := setArea1(next, a, intf, lookup, objInArea)
		if errPath != nil {
			// Collect interfaces of invalid path.
			errPath.push(intf)
			return errPath
		}
	}
	return nil
}

func nonSecondaryIntfCount(l []*routerIntf) int {
	count := 0
	for _, intf := range l {
		if intf.mainIntf == nil {
			count++
		}
	}
	return count
}

//##############################################################################
// Purpose : Check subset relation between areas, assure that no duplicate or
//           overlapping areas exist
func checkAreaSubsetRelations(objInArea map[pathObj]map[*area]bool) {

	size := func(a *area) int {
		return len(a.zones) + len(a.managedRouters)
	}
	// Sort areas by size or by name on equal size.
	sortBySize := func(l []*area) []*area {
		sort.SliceStable(l, func(i, j int) bool {
			si := size(l[i])
			sj := size(l[j])
			if si == sj {
				return l[i].name < l[j].name
			}
			return si < sj
		})
		return l
	}

	// Fill global list of areas.
	for _, a := range symTable.area {
		if !a.disabled {
			ascendingAreas = append(ascendingAreas, a)
		}
	}
	ascendingAreas = sortBySize(ascendingAreas)

	// Get list of all zones and managed routers of an area.
	getObjList := func(a *area) []pathObj {
		result := make([]pathObj, 0, size(a))
		for _, obj := range a.zones {
			result = append(result, obj)
		}
		for _, obj := range a.managedRouters {
			result = append(result, obj)
		}
		return result
	}

	// Process all elements contained by one or more areas.
	process := func(obj pathObj) {
		m := objInArea[obj]
		if len(m) == 0 {
			return
		}

		// Find ascending list of areas containing current object.
		containing := make([]*area, 0, len(m))
		for a, _ := range m {
			containing = append(containing, a)
		}
		containing = sortBySize(containing)

		// Take the smallest area.
		next := containing[0]
		containing = containing[1:]
		nextList := getObjList(next)

		if z, ok := obj.(*zone); ok {
			z.inArea = next
		}

	LARGER:
		for len(containing) > 0 {
			small := next
			next = containing[0]
			containing = containing[1:]
			if small.inArea != nil {
				continue
			}
			small.inArea = next
			smallList := nextList
			nextList := getObjList(next)

			// Check that each zone and managed router of small is part of next.
			for _, obj2 := range smallList {
				if objInArea[obj2][next] {
					continue
				}
				for _, obj3 := range nextList {
					if objInArea[obj3][small] {
						continue
					}
					errMsg("Overlapping %s and %s\n"+
						" - both areas contain %s,\n"+
						" - only 1. area contains %s,\n"+
						" - only 2. area contains %s",
						small.name, next.name, obj, obj2, obj3)
					continue LARGER
				}
			}

			// Check for duplicates.
			if len(smallList) == len(nextList) {
				errMsg("Duplicate %s and %s", small.name, next.name)
			}
		}
	}
	for _, obj := range zones {
		process(obj)
	}
	for _, obj := range managedRouters {
		process(obj)
	}
}

//#############################################################################
// Purpose  : Process all explicitly defined aggregates. Check proper usage of
//            aggregates. For every aggregate, link aggregates to all
//            zones inside the zone cluster containing the aggregates link
//            network and set aggregate and zone properties. Add aggregate
//            to global variable allNetworks.
// Comments : Has to be called after zones have been set up. But before
//            findSubnetsInZone calculates .up and .networks relation.
func processAggregates() {

	// Collect all aggregates inside zone clusters.
	var aggInCluster netList
	aggList := make(netList, 0, len(symTable.aggregate))
	for _, agg := range symTable.aggregate {
		if agg.link != nil {
			aggList.push(agg)
		}
	}
	sort.Slice(aggList, func(i, j int) bool {
		return aggList[i].name < aggList[j].name
	})
	for _, agg := range aggList {
		n := agg.link
		if n.disabled {
			agg.disabled = true
			continue
		}

		// Reference network link in security zone.
		z := n.zone
		z.link = n // only used in cut-netspoc

		// Assure that no other aggregate with same IP and mask exists in cluster
		key := ipmask{string(agg.ip), string(agg.mask)}
		cluster := z.zoneCluster
		if cluster == nil {
			cluster = []*zone{z}
		} else {
			// Collect aggregates inside clusters
			aggInCluster.push(agg)
		}
		for _, z2 := range cluster {
			if other := z2.ipmask2aggregate[key]; other != nil {
				errMsg("Duplicate %s and %s in %s", other, agg, z)
			}
		}

		// Use aggregate with ip 0/0 to set attributes of all zones in cluster.
		//
		// Even NAT is moved to zone for aggregate 0/0 although we
		// retain NAT at other aggregates.
		// This is an optimization to prevent the creation of many aggregates 0/0
		// if only inheritance of NAT from area to network is needed.
		prefixlen, _ := agg.mask.Size()
		if prefixlen == 0 {
			if nat := agg.nat; nat != nil {
				if len(cluster) == 1 {
					z.nat = nat
				} else {
					// Must not use identical NAT map at different zones of cluster.
					for _, z2 := range cluster {
						z2.nat = make(map[string]*network)
						for t, n := range nat {
							z2.nat[t] = n
						}
					}
				}
				agg.nat = nil
			}
			if agg.noCheckSupernetRules {
				for _, z2 := range cluster {
					z2.noCheckSupernetRules = true
				}
			}
		}

		// Link aggragate and zone (also setting z.ipmask2aggregate)
		linkAggregateToZone(agg, z, key)
	}

	// Add aggregate to all zones in zone cluster.
	for _, agg := range aggInCluster {
		duplicateAggregateToCluster(agg, false)
	}
}

func inheritAttributes() {
	natSeen := make(map[*network]bool)
	inheritAttributesFromArea(natSeen)
	inheritNatInZone(natSeen)
	checkAttrNoCheckSupernetRules()
	cleanupAfterInheritance(natSeen)
}

//##############################################################################
// Purpose : Assure that areas are processed in the right order and distribute
//           area attributes to zones and managed routers.
func inheritAttributesFromArea(natSeen map[*network]bool) {

	// Areas can be nested. Proceed from small to larger ones.
	for _, a := range ascendingAreas {
		inheritRouterAttributes(a)
		inheritAreaNat(a, natSeen)
	}
}

//##############################################################################
// Purpose : Distribute routerAttributes from area definition to managed
//           routers of an area.
func inheritRouterAttributes(a *area) {

	// Check for attributes to be inherited.
	attr := a.routerAttributes
	if attr == nil {
		return
	}
	if attr.policyDistributionPoint == nil && attr.generalPermit == nil {
		return
	}

	// Process all managed routers of the area inherited from.
	for _, r := range a.managedRouters {
		if p1 := attr.policyDistributionPoint; p1 != nil {
			if p2 := r.policyDistributionPoint; p2 != nil {
				if p1 == p2 {
					warnMsg("Useless attribute 'policy_distribution_point' at %s,\n"+
						" it was already inherited from %s", r, attr.name)
				}
			} else {
				r.policyDistributionPoint = p1
			}
		}
		if l1 := attr.generalPermit; l1 != nil {
			if l2 := r.generalPermit; l2 != nil {
				if protoListEq(l1, l2) {
					warnMsg("Useless attribute 'general_permit' at %s,\n"+
						" it was already inherited from %s", r, attr.name)
				}
			} else {
				r.generalPermit = l1
			}
		}
	}
}

func protoListEq(l1, l2 []*proto) bool {
	if len(l1) != len(l2) {
		return false
	}
	for i, p := range l1 {
		if p != l2[i] {
			return false
		}
	}
	return true
}

//#############################################################################
// Purpose : Distribute NAT from area to zones.
func inheritAreaNat(a *area, natSeen map[*network]bool) {
	m := a.nat
	if m == nil {
		return
	}

	// Process every nat definition of area.
	tags := make(stringList, 0, len(m))
	for t, _ := range m {
		tags.push(t)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		n1 := m[tag]

		// Distribute nat definitions to every zone of area.
		for _, z := range a.zones {

			// Skip zone, if NAT tag exists in zone already...
			if n2 := z.nat[tag]; n2 != nil {

				// ... and warn if zones NAT value holds the same attributes.
				checkUselessNat(n1, n2, natSeen)
				continue
			}

			// Store NAT definition in zone otherwise
			if z.nat == nil {
				z.nat = make(map[string]*network)
			}
			z.nat[tag] = n1

			//debug("%s: %s from %s", z, tag, a)
		}
	}
}

//#############################################################################
// Purpose : 1. Generate warning if NAT values of two objects hold the same
//              attributes.
//           2. Mark NAT value of smaller object, so that warning is only
//              printed once and not again if compared with some larger object.
//              This is also used later to warn on useless identity NAT.
func checkUselessNat(nat1, nat2 *network, natSeen map[*network]bool) {
	//debug("Check useless %s -- %s", nat2.descr, nat1.descr)
	if natSeen[nat2] {
		return
	}
	natSeen[nat2] = true
	if natEqual(nat1, nat2) {
		warnMsg("Useless %s,\n it was already inherited from %s",
			nat2.descr, nat1.descr)
	}
}

//##############################################################################
// Purpose : Check if nat definitions are equal.
func natEqual(nat1, nat2 *network) bool {
	return bytes.Compare(nat1.ip, nat2.ip) == 0 &&
		bytes.Compare(nat1.mask, nat2.mask) == 0 &&
		nat1.dynamic == nat2.dynamic &&
		nat1.hidden == nat2.hidden &&
		nat1.identity == nat2.identity
}

func inheritNatInZone(natSeen map[*network]bool) {
	for _, z := range zones {

		// Find all networks and aggregates of current zone,
		// that have NAT definitions.
		var natSupernets netList
		for _, n := range z.networks {
			if n.nat != nil {
				natSupernets.push(n)
			}
		}
		for _, n := range z.ipmask2aggregate {
			if n.nat != nil {
				natSupernets.push(n)
			}
		}

		// Proceed from smaller to larger objects. (Bigger mask first.)
		sort.Slice(natSupernets, func(i, j int) bool {
			return bytes.Compare(natSupernets[i].mask, natSupernets[j].mask) == 1
		})
		for _, n := range natSupernets {
			inheritNatToSubnetsInZone(n.name, n.nat, n.ip, n.mask, z, natSeen)
		}

		// Process zone instead of aggregate 0/0, because NAT is stored
		// at zone in this case.
		if z.nat != nil {
			// Don't inherit identiy NAT to subnets.
			// It was only used to prevent inheritance from areas
			// and would lead to warning about useless identity NAT at subnet.
			for tag, nat := range z.nat {
				if nat.identity {
					delete(z.nat, tag)
				}
			}
			inheritNatToSubnetsInZone(
				z.name, z.nat, getZeroIp(z.ipV6), getZeroMask(z.ipV6), z, natSeen)
		}

	}
}

//##############################################################################
// Purpose  : Distributes NAT from aggregates and networks to other networks
//            in same zone, that are in subnet relation.
//            If a network A is subnet of multiple networks B < C,
//            then NAT of B is used.
func inheritNatToSubnetsInZone(from string, natMap map[string]*network,
	ip net.IP, mask net.IPMask, z *zone, natSeen map[*network]bool) {

	tags := make(stringList, 0, len(natMap))
	for t, _ := range natMap {
		tags.push(t)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		nat := natMap[tag]

		//debug("inherit %s from %s", tag, from)

		// Distribute nat definitions to every subnet of supernet or
		// aggregate.
		for _, n := range z.networks {

			// Only process subnets.
			if bytes.Compare(n.mask, mask) != 1 || !matchIp(n.ip, ip, mask) {
				continue
			}

			// Skip network, if NAT tag exists in network already...
			if nNat := n.nat[tag]; nNat != nil {

				// ... and warn if networks NAT value holds the
				// same attributes.
				checkUselessNat(nat, nNat, natSeen)
			} else if n.bridged && !nat.identity {
				errMsg("Must not inherit nat:%s at bridged %s from %s",
					tag, n, from)
			} else {
				// Copy NAT defintion; add description and name of original network.
				subNat := *nat
				subNat.name = n.name
				subNat.descr = "nat:" + tag + " of " + n.name

				// Copy attribute subnetOf, to suppress warning.
				// Copy also if undefined, to overwrite value in
				// original definition.
				subNat.subnetOf = n.subnetOf

				// For static NAT
				// - merge IP from NAT network and subnet,
				// - adapt mask to size of subnet
				if !nat.dynamic {

					// Check mask of static NAT inherited from area or zone.
					if bytes.Compare(nat.mask, n.mask) >= 1 {
						errMsg("Must not inherit %s at %s\n"+
							" because NAT network must be larger"+
							" than translated network", nat.descr, n)
					}

					// Take higher bits from NAT IP, lower bits from original IP.
					subNat.ip = mergeIP(n.ip, nat)
					subNat.mask = n.mask
				}

				if n.nat == nil {
					n.nat = make(map[string]*network)
				}
				n.nat[tag] = &subNat
			}
		}
	}
}

func checkAttrNoCheckSupernetRules() {
	var checkSubnets func(l netList) netList
	checkSubnets = func(l netList) netList {
		var errList netList
		for _, n := range l {
			if len(n.hosts) > 0 {
				errList.push(n)
			}
			if subErr := checkSubnets(n.networks); subErr != nil {
				errList = append(errList, subErr...)
			}
		}
		return errList
	}
	for _, z := range zones {
		if z.noCheckSupernetRules {
			if bugList := checkSubnets(z.networks); bugList != nil {
				errMsg("Must not use attribute 'no_check_supernet_rules' at %s\n"+
					" with networks having host definitions:\n%s",
					z, bugList.nameList())
			}
		}
	}
}

// 1. Remove NAT entries from aggregates.
//    These are only used during NAT inheritance.
// 2. Remove identity NAT entries.
//    These are only needed during NAT inheritance.
// 3. Check for useless identity NAT.
func cleanupAfterInheritance(natSeen map[*network]bool) {
	for _, n := range allNetworks {
		m := n.nat
		if m == nil {
			continue
		}
		if n.isAggregate {
			n.nat = nil
			continue
		}
		for tag, nat := range m {
			if nat.identity {
				delete(m, tag)
				if !natSeen[nat] {
					warnMsg("Useless identity nat:%s at %s", tag, n)
				}
			}
		}
		if len(m) == 0 {
			n.nat = nil
		}
	}
}
