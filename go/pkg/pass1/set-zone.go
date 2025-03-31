package pass1

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// setZone create zones and areas.
func (c *spoc) setZone() map[pathObj]map[*area]bool {
	c.progress("Preparing security zones and areas")
	c.setZones()
	c.clusterZones()
	crosslinkRouters := c.checkCrosslink()
	clusterCrosslinkRouters(crosslinkRouters)
	objInArea := c.setAreas()
	c.checkAreaSubsetRelations(objInArea)
	c.processAggregates()
	c.checkReroutePermit()
	c.findSubnetsInZoneCluster()
	c.inheritAttributes()
	c.sortedSpoc(func(c *spoc) { c.propagateOwners() })
	c.markSubnetsInZoneCluster()
	c.updateSubnetRelation()
	return objInArea // For use in cut-netspoc
}

// setZones creates new zone for every network without a zone.
func (c *spoc) setZones() {
	for _, n := range c.allNetworks {
		if n.zone != nil {
			continue
		}

		// Create zone.
		z := &zone{
			name:               "any:[" + n.name + "]",
			ipPrefix2aggregate: make(map[netip.Prefix]*network),
		}
		z.ipV6 = n.ipV6
		c.allZones = append(c.allZones, z)

		// Collect zone elements...
		c.setZone1(n, z, nil)

		// Change name from tunnel network to real network for better
		// error messages and for use in cut-netspoc.
		if len(z.networks) > 0 &&
			(n.ipType == tunnelIP ||
				n.ipType == unnumberedIP &&
					strings.HasSuffix(n.name, "(split Network)")) {
			z.name = "any:[" + z.networks[0].name + "]"
		}
	}
}

/*
##############################################################################
setZone1 collects all elements (networks, unmanaged routers, interfaces)
of a zone and references the zone in its elements.
Sets zone attribute.
Comment: Unnumbered and tunnel networks are not referenced in zones,
as they are no valid src or dst.
*/
func (c *spoc) setZone1(n *network, z *zone, in *routerIntf) {

	// Network was processed already (= loop was found).
	if n.zone != nil {
		return
	}

	// Reference zone in network and vice versa...
	n.zone = z
	if n.ipType != unnumberedIP && n.ipType != tunnelIP { // no valid src/dst
		z.networks.push(n)
	}

	// Link IPv4 and IPv6 zone if it has at least one combined network.
	link := func(z, z2 *zone) {
		if z.combined46 == nil {
			z.combined46 = z2
		} else if z.combined46 != z2 {
			if !slices.Contains(z.combined46Other, z2) {
				z.combined46Other = append(z.combined46Other, z2)
			}
		}
	}
	if n2 := n.combined46; n2 != nil {
		if z2 := n2.zone; z2 != nil {
			link(z, z2)
			link(z2, z)
		}
	}

	//debug("%s in %s", n, z)
	if n.hasIdHosts {
		z.hasIdHosts = true
	}
	if n.partition != "" {
		if z.partition != "" {
			c.err("Only one partition name allowed in zone %s, but found:\n"+
				" - %s\n - %s",
				z, n.partition, z.partition)
		}
		z.partition = n.partition
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
			for _, s := range intf.secondaryIntfs {
				s.zone = z
			}
			z.interfaces.push(intf)
		} else if !r.activePath {
			r.activePath = true
			defer func() { r.activePath = false }()

			// Recursively add adjacent networks.
			for _, out := range r.interfaces {
				if out != intf {
					c.setZone1(out.network, z, out)
				}
			}
		}
	}
}

/*
#############################################################################
clusterZones clusters zones connected by semiManaged routers. All
zones of a cluster are stored in attribute cluster of the zones.
Attribute cluster is also set if the cluster has only one element.
*/
func (c *spoc) clusterZones() {

	// Process remaining unclustered zones.
	for _, z := range c.allZones {
		if z.cluster == nil {

			// Create a new cluster and collect its zones
			var cluster []*zone
			getZoneCluster(z, nil, &cluster)
			if cluster == nil {
				// Zone with only tunnel was not added to cluster.
				z.cluster = []*zone{z}
			} else {
				found46 := false
				for i, z2 := range cluster {
					// Store final cluster elements in all zones of cluster.
					z2.cluster = cluster
					// If cluster has at least one combined46 zone, then store
					// first combined46 zone as first element of cluster. Thus
					// it is simple to check if cluster is combined46 cluster.
					if !found46 && z2.combined46 != nil {
						found46 = true
						cluster[0], cluster[i] = cluster[i], cluster[0]
					}
				}
			}
		}
	}
}

/*
#############################################################################
getZoneCluster collects zones connected by semiManaged devices into a cluster.
Comments : Tunnel zone is not included in zone cluster, because
  - it is useless in rules and
  - we would get inconsistent owner since zone of tunnel
    doesn't inherit from area.
*/
func getZoneCluster(z *zone, in *routerIntf, collected *[]*zone) {

	// Reference zone in cluster list and vice versa.
	if !z.isTunnel() {
		*collected = append(*collected, z)
		// Set preliminary list as marker, that this zone has been processed.
		z.cluster = *collected
	}

	// Find zone interfaces connected to semi-managed routers...
	for _, intf := range z.interfaces {
		if intf == in {
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
			if out == intf {
				continue
			}
			next := out.zone
			if next.cluster == nil {
				// Add adjacent zone recursively.
				getZoneCluster(next, out, collected)
			}
		}
	}
}

func (z *zone) isTunnel() bool {
	return len(z.networks) == 0 && len(z.interfaces) == 2 &&
		z.interfaces[0].ipType == tunnelIP &&
		z.interfaces[1].ipType == tunnelIP
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

/*
#############################################################################
A crosslink network combines two or more routers to one virtual router.
Purpose  : Assures proper usage of crosslink networks and applies the
crosslink attribute to the networks weakest interfaces (no
filtering needed at these interfaces).

Returns  : Map storing crosslinked routers with attribute needProtect set.
Comments : Function uses hardware attributes from func checkNoInAcl.
*/
func (c *spoc) checkCrosslink() map[*router]bool {
	// Collect crosslinked routers with attribute needProtect.
	crosslinkRouters := make(map[*router]bool)

	// Process all crosslink networks
	for _, n := range c.allNetworks {
		if !n.crosslink {
			continue
		}

		// Prepare tests.
		// To identify interfaces with min router strength.
		strength2intf := make(map[int]intfList)
		// Assure outAcl at all/none of the interfaces.
		outAclCount := 0
		// Assure all noInAcl interfaces to border the same zone.
		var noInAclZone *zone

		// Process network interfaces to fill above variables.
		for _, intf := range n.interfaces {
			r := intf.router

			// Assure correct usage of crosslink network.
			if r.managed == "" {
				c.err("Crosslink %s must not be connected to unmanged %s", n, r)
				continue
			}
			hw := intf.hardware
			if len(hw.interfaces) != 1 {
				c.err("Crosslink %s must be the only network"+
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

			if noAclIntf := r.noInAcl; noAclIntf != nil {
				if noInAclZone == nil {
					noInAclZone = noAclIntf.zone
				} else if noInAclZone != noAclIntf.zone {
					c.err("All interfaces with attribute 'no_in_acl'"+
						" at routers connected by\n"+
						" crosslink %s must be border of the same security zone", n)
				}
			}
		}

		// Apply attribute 'crosslink' to the networks weakest interfaces.
		weakest := 99
		for i := range strength2intf {
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
			c.err("Must not use 'managed=local' and 'managed=secondary'"+
				" together\n at crosslink %s", n)
		}

		// Assure proper usage of crosslink network.
		if outAclCount != 0 && outAclCount != len(n.interfaces) {
			c.err("All interfaces must equally use or not use outgoing ACLs"+
				" at crosslink %s", n)
		}
	}
	return crosslinkRouters
}

/*
#############################################################################
clusterCrosslinkRouters finds clusters of routers connected directly or
indirectly by crosslink networks and having at least one device with
attribute needProtect.
Parameter : Map with crosslinked routers having attribute needProtect set.
*/
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
			if n.crosslink {
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
	for r := range crosslinkRouters {
		if seen[r] {
			continue
		}

		// Fill router cluster
		cluster = nil
		walk(r)

		slices.SortFunc(cluster, func(a, b *router) int {
			return strings.Compare(a.name, b.name)
		})

		// Collect all interfaces belonging to needProtect routers of cluster...
		var crosslinkIntfs intfList
		for _, r2 := range cluster {
			if r2.needProtect {
				crosslinkIntfs =
					append(crosslinkIntfs, withSecondary(r2.interfaces)...)
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

// setAreas sets up areas, assure proper border definitions.
func (c *spoc) setAreas() map[pathObj]map[*area]bool {
	objInArea := make(map[pathObj]map[*area]bool)
	slices.SortFunc(c.ascendingAreas, func(a, b *area) int {
		return cmp.Compare(a.name, b.name)
	})
	for _, a := range c.ascendingAreas {
		if n := a.anchor; n != nil {
			c.setArea(n.zone, a, nil, nil, objInArea)
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
					c.err("%s is used as 'border' and 'inclusive_border' in %s",
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
			err := c.setArea(obj1, a, start, lookup, objInArea)
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
					c.err("Unreachable %s of %s:\n%s",
						attr, a, badIntf.nameList())
				}
				return l
			}
			a.border = check(a.border, "border")
			a.inclusiveBorder = check(a.inclusiveBorder, "inclusive_border")

			// Check whether area is empty (= consist of a single router)
			if len(a.zones) == 0 {
				c.warn("%s is empty", a)
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

/*
##############################################################################
setArea collects zones and routers of an area.
Returns false, or true if error was found.
*/
func (c *spoc) setArea(obj pathObj, a *area, in *routerIntf,
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
	c.err("Inconsistent definition of %s in loop.\n"+
		" It is reached from outside via this path:\n%s",
		a, errPath.nameList())
	return true
}

/*
##############################################################################
setArea1 collects zones and managed routers of an area and set a
reference to the area in its zones and routers.
Keep track of area borders found during area traversal.
Returns  : nil or list of interfaces, if invalid path was found.
*/
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
		if !x.isTunnel() {
			a.zones = append(a.zones, x)
		}
	case *router:
		if x.managed != "" || x.routingOnly {
			a.managedRouters = append(a.managedRouters, x)
		} else if x.managementInstance {
			a.managementInstances = append(a.managementInstances, x)
		}
	}

	for _, intf := range obj.intfList() {
		if intf == in {
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

/*
##############################################################################
checkAreaSubsetRelations checks subset relation between areas, assure
that no duplicate or overlapping areas exist
*/
func (c *spoc) checkAreaSubsetRelations(objInArea map[pathObj]map[*area]bool) {

	size := func(a *area) int {
		return len(a.zones) + len(a.managedRouters)
	}
	// Sort areas by size or by name on equal size.
	sortBySize := func(l []*area) {
		slices.SortStableFunc(l, func(a, b *area) int {
			if cmp := cmp.Compare(size(a), size(b)); cmp != 0 {
				return cmp
			}
			return strings.Compare(a.name, b.name)
		})
	}
	sortBySize(c.ascendingAreas)

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
		containing := slices.Collect(maps.Keys(m))
		sortBySize(containing)

		// Take the smallest area.
		next := containing[0]
		nextList := getObjList(next)

		if z, ok := obj.(*zone); ok {
			z.inArea = next
		}

	LARGER:
		for _, a := range containing[1:] {
			small := next
			next = a
			if small.inArea == next {
				continue
			}
			small.inArea = next
			smallList := nextList
			nextList = getObjList(next)

			// Check that each zone and managed router of small is part of next.
			for _, obj2 := range smallList {
				if objInArea[obj2][next] {
					continue
				}
				for _, obj3 := range nextList {
					if objInArea[obj3][small] {
						continue
					}
					c.err("Overlapping %s and %s\n"+
						" - both areas contain %s,\n"+
						" - only 1. area contains %s,\n"+
						" - only 2. area contains %s",
						small, next, obj, obj2, obj3)
					continue LARGER
				}
			}

			// Check for duplicates.
			if len(smallList) == len(nextList) {
				c.err("Duplicate %s and %s", small.vxName(), next.vxName())
			}
		}
	}
	for _, obj := range c.allZones {
		process(obj)
	}
	for _, obj := range c.managedRouters {
		process(obj)
	}
}

/*
#############################################################################
processAggregates processes all explicitly defined aggregates.
Checks proper usage of aggregates. For every aggregate, link aggregates to all
zones inside the zone cluster containing the aggregates link
network and set aggregate and zone properties. Add aggregate
to global variable allNetworks.

Comments : Has to be called after zones have been set up. But before
findSubnetsInZone calculates .up and .networks relation.
*/
func (c *spoc) processAggregates() {
	aggList := slices.SortedFunc(maps.Values(c.symTable.aggregate),
		func(a, b *network) int {
			return strings.Compare(a.name, b.name)
		})
	var unset netip.Prefix
	for _, agg := range aggList {
		process := func(agg *network, z *zone) {
			// Assure that no other aggregate with same IP and mask
			// exists in cluster
			ipp := agg.ipp
			cluster := z.cluster
			for _, z2 := range cluster {
				if other := z2.ipPrefix2aggregate[ipp]; other != nil {
					c.err("Duplicate %s and %s in %s", other, agg, z)
				}
			}
			// Use aggregate with ip 0/0 to set attribute of all zones in cluster.
			if agg.ipp.Bits() == 0 && agg.noCheckSupernetRules {
				for _, z2 := range cluster {
					z2.noCheckSupernetRules = true
					c.checkAttrNoCheckSupernetRules(z2)
				}
			}
			// Link aggragate and zone (also setting z.ipPrefix2aggregate)
			c.linkAggregateToZone(agg, z)
		}
		z := agg.link.zone
		if agg.ipp == unset {
			// Make sure to get dual stack zone in mixed v4, v6, v46 cluster.
			z = agg.link.zone.cluster[0]
			c.checkDualStackZone(z)
			agg.ipp = c.getNetwork00(z.ipV6).ipp
			agg.ipV6 = z.ipV6
			process(agg, z)
			// Add non matching aggregate to combined zone.
			if z2 := z.combined46; z2 != nil {
				agg2 := new(network)
				agg2.name = agg.name
				agg2.isAggregate = true
				agg2.ipV6 = z2.ipV6
				agg2.ipp = c.getNetwork00(agg2.ipV6).ipp
				if !agg2.ipV6 {
					agg2.nat = agg.nat
					agg.nat = nil
				}
				agg.combined46 = agg2
				agg2.combined46 = agg
				process(agg2, z2)
			} else if agg.ipV6 && agg.nat != nil {
				c.err("NAT not supported for IPv6 %s", agg)
			}
		} else {
			process(agg, z)
		}
	}
	// Add aggregate to all zones in zone cluster.
	for _, agg := range aggList {
		c.duplicateAggregateToCluster(agg, false)
	}
}

func (c *spoc) checkDualStackZone(z *zone) {
	check := func(z *zone) {
		for _, z2 := range z.combined46Other {
			if !zoneEq(z.combined46, z2) {
				c.err(`%s zone %q must not be connected to different %s zones:
- %s
- %s`,
					ipvx(z.ipV6), z.name, ipvx(z2.ipV6), z.combined46.name, z2.name)
			}
		}
	}
	if z2 := z.combined46; z2 != nil {
		check(z)
		check(z2)
	}
}

func (c *spoc) checkAttrNoCheckSupernetRules(z *zone) {
	var withHosts, loopbacks netList
	// z.networks currently contains all networks of zone,
	// subnets are discared later in findSubnetsInZone.
	for _, n := range z.networks {
		if len(n.hosts) > 0 {
			withHosts.push(n)
		} else if n.loopback {
			loopbacks.push(n)
		}
	}
	if withHosts != nil {
		c.err("Must not use attribute 'no_check_supernet_rules' at %s\n"+
			" with networks having host definitions:\n%s",
			z, withHosts.nameList())
	}
	if loopbacks != nil {
		c.err("Must not use attribute 'no_check_supernet_rules' at %s\n"+
			" having loopback/vip interfaces:\n%s",
			z, loopbacks.nameList())
	}
}

func (c *spoc) inheritAttributes() {
	c.inheritAttributesFromArea()
	c.inheritAutoIPv6Hosts()
	c.inheritNAT()
	c.cleanupAfterInheritance()
}

// Handling of inheritance for router_attributes of different types.
type routerAttr interface {
	attrName() string
	isNil() bool
	equal(routerAttr) bool
	toRouter(*router)
}

func (p *host) attrName() string         { return "policy_distribution_point" }
func (p *host) isNil() bool              { return p == nil }
func (p *host) equal(p2 routerAttr) bool { return p == p2 }
func (p *host) toRouter(r *router)       { r.policyDistributionPoint = p }

func (l protoList) attrName() string { return "general_permit" }
func (l protoList) isNil() bool      { return l == nil }
func (l1 protoList) equal(a routerAttr) bool {
	l2 := a.(protoList)
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
func (l protoList) toRouter(r *router) { r.generalPermit = l }

func (o *owner) attrName() string         { return "owner" }
func (o *owner) isNil() bool              { return o == nil }
func (o *owner) equal(o2 routerAttr) bool { return o == o2 }
func (o *owner) toRouter(r *router)       { r.owner = o }

// inheritAttributesFromArea distributes area attributes to zones and
// managed routers.
func (c *spoc) inheritAttributesFromArea() {

	// Areas can be nested. Proceed from small to larger ones.
	for _, a := range c.ascendingAreas {
		c.inheritRouterAttributes(
			a,
			func(rA *routerAttributes) routerAttr {
				return rA.policyDistributionPoint
			},
		)
		c.inheritRouterAttributes(
			a,
			func(rA *routerAttributes) routerAttr { return rA.generalPermit },
		)
		c.inheritRouterAttributes(
			a,
			func(rA *routerAttributes) routerAttr { return rA.owner },
		)
	}
}

// Inherit routerAttributes from area to managed routers of area.
func (c *spoc) inheritRouterAttributes(
	a *area,
	getAttr func(*routerAttributes) routerAttr,
) {
	rA1 := &a.routerAttributes
	at1 := getAttr(rA1)
	if at1.isNil() {
		return
	}
	// Check for redundant attribute with enclosing areas.
	for up := a.inArea; up != nil; up = up.inArea {
		if rA2 := &up.routerAttributes; rA2 != nil {
			if at2 := getAttr(rA2); !at2.isNil() {
				if at1.equal(at2) {
					c.warn("Useless '%s' at %s,\n"+
						" it was already inherited from %s",
						at1.attrName(), a, rA2.name)
					return
				}
			}
		}
	}
	inherit := func(r *router) {
		if at2 := getAttr(&r.routerAttributes); !at2.isNil() {
			if at1.equal(at2) {
				c.warn("Useless '%s' at %s,\n"+
					" it was already inherited from %s",
					at2.attrName(), r, rA1.name)
			}
		} else {
			at1.toRouter(r)
		}
	}
	// Distribute to managed routers of area.
	for _, r := range a.managedRouters {
		inherit(r)
	}
	// Distribute policy_distribution_point also to management
	// instances of area.
	if _, ok := at1.(*host); ok {
		for _, r := range a.managementInstances {
			inherit(r)
		}
	}
}

// inheritAutoIPv6Hosts distributes attribute 'autoIPv6Hosts' from
// areas to networks and then builds IPv6 hosts from IPv4 hosts.
func (c *spoc) inheritAutoIPv6Hosts() {
	// Areas can be nested. Proceed from small to larger ones.
AREA:
	for _, a := range c.ascendingAreas {
		if !a.ipV6 {
			continue
		}
		v1 := a.autoIPv6Hosts
		if v1 == "" {
			continue
		}
		// Check for redundant attribute with enclosing areas.
		for up := a.inArea; up != nil; up = up.inArea {
			if up.autoIPv6Hosts == v1 {
				c.warn("Useless 'auto_ipv6_hosts = %s' at %s,\n"+
					" it was already inherited from %s", v1, a, up)
				continue AREA
			}
		}
		for _, z := range a.zones {
			for _, n := range z.networks {
				if n.combined46 == nil {
					continue
				}
				if n.autoIPv6Hosts == "" {
					n.autoIPv6Hosts = v1
				} else if n.autoIPv6Hosts == v1 {
					c.warn("Useless 'auto_ipv6_hosts = %s' at %s,\n"+
						" it was already inherited from %s", v1, n, a)
				}
			}
		}
	}
	c.addAutoIPv6Hosts()
}

func (c *spoc) inheritNAT0() {
	getUp := func(obj natter) natter {
		var a *area
		switch x := obj.(type) {
		case *network:
			if up := x.up; up != nil {
				return up
			}
			a = x.zone.inArea
		case *area:
			a = x.inArea
		}
		if a == nil { // Must not return nil of type *area
			return nil // but nil of type natter.
		}
		return a
	}

	type fromMap map[string]natter
	inherited := make(map[natter]fromMap)

	// Inherit NAT setting from areas and supernets to enclosing obj.
	// Returns:
	// 1. Augmented natTagMap of obj, to be used in enclosed objects.
	// 2. A map showing for current obj, from which object a NAT tag
	//    has been inherited from.
	var inherit func(obj natter) (natTagMap, fromMap)
	inherit = func(obj natter) (natTagMap, fromMap) {
		if obj == nil {
			return nil, nil
		}
		m1 := obj.getNAT()
		if from := inherited[obj]; from != nil {
			return m1, from
		}
		from1 := make(fromMap)
		m2, from2 := inherit(getUp(obj))
		for tag, nat1 := range m1 {
			if nat1.identity && m2[tag] == nil {
				c.warn("Useless identity %s", nat1.descr)
			}
			from1[tag] = obj
		}
		for tag, nat2 := range m2 {
			if nat1, found := m1[tag]; found {
				if natEqual(nat1, nat2) {
					c.warn("Useless %s,\n it was already inherited from %s",
						nat1.descr, from2[tag])
				}
				continue
			} else if n, ok := obj.(*network); ok && !n.isAggregate {
				if n.ipType == bridgedIP && !nat2.identity {
					c.err("Must not inherit nat:%s at bridged %s from %s\n"+
						" Use 'nat:%s = { identity; }' to stop inheritance",
						tag, n, from2[tag], tag)
					continue
				}
				nat2 = c.adaptNAT(n, tag, nat2)
			}
			if m1 == nil {
				m1 = make(natTagMap)
				obj.setNAT(m1)
			}
			m1[tag] = nat2
			from1[tag] = from2[tag]
		}
		inherited[obj] = from1
		return m1, from1
	}
	for _, n := range c.allNetworks {
		inherit(n)
	}
}

func (c *spoc) inheritNAT() {
	// Sorts error messages before output.
	c.sortedSpoc(func(c *spoc) { c.inheritNAT0() })
}

func (c *spoc) adaptNAT(n *network, tag string, nat *network) *network {

	// Copy NAT defintion; add description and name of
	// original network.
	subNat := *nat
	subNat.name = n.name
	subNat.descr = "nat:" + tag + " of " + n.name

	// Always keep attribute subnetOf of inherited NAT with dynmic NAT,
	// because it would override existing subnet relation of networks.
	// Otherwies take attribute subnetOf of original network if available.
	// Else keep attribute subnetOf of inherited NAT.
	if s := n.subnetOf; s != nil && !(subNat.subnetOf != nil && subNat.dynamic) {
		subNat.subnetOf = s
	}

	// For static NAT
	// - merge IP from NAT network and subnet,
	// - adapt mask to size of subnet
	if !nat.dynamic {

		// Check mask of static NAT inherited from area or zone.
		if nat.ipp.Bits() > n.ipp.Bits() {
			c.err("Must not inherit %s at %s\n"+
				" because NAT network must be larger"+
				" than translated network", nat.descr, n)
		}

		// Take higher bits from NAT IP, lower bits from
		// original IP.
		subNat.ipp = netip.PrefixFrom(
			mergeIP(n.ipp.Addr(), nat),
			n.ipp.Bits(),
		)
	}
	return &subNat
}

// natEqual checks if nat definitions are equal.
func natEqual(nat1, nat2 *network) bool {
	return nat1.ipp == nat2.ipp &&
		nat1.dynamic == nat2.dynamic &&
		nat1.hidden == nat2.hidden &&
		nat1.identity == nat2.identity
}

//  1. Remove NAT entries from aggregates.
//     These are only used during NAT inheritance.
//  2. Remove identity NAT entries.
//     These are only needed during NAT inheritance.
func (c *spoc) cleanupAfterInheritance() {
	for _, n := range c.allNetworks {
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
			}
		}
		if len(m) == 0 {
			n.nat = nil
		}
	}
}

// Reroute permit is not allowed between different security zones.
func (c *spoc) checkReroutePermit() {
	for _, z := range c.allZones {
		for _, intf := range z.interfaces {
			for _, n := range intf.reroutePermit {
				if !zoneEq(n.zone, z) {
					c.err("Invalid reroute_permit for %s at %s:"+
						" different security zones", n, intf)
				}
			}
		}
	}
}

// Collect subnets in attribute .subnetsInCluster
//   - to supernet in zone cluster
//   - where subnet is located in same zone cluster, but in other zone and
//   - where zone cluster has interior pathrestriction,
//     i.e. pathrestriction between zones of cluster.
//
// In this case subnet and supernet may be reached by different paths.
//
// ToDo: This should be called after linkPathrestrictions has been called.
//
//	Currently subnet relation has then been changed already
//	from cluster to zone.
func (c *spoc) markSubnetsInZoneCluster() {
	hasInteriorPR := make(map[*zone]bool)
	for _, p := range c.pathrestrictions {
		for _, intf := range p.elements {
			if intf.router.semiManaged {
				hasInteriorPR[intf.zone.cluster[0]] = true
			}
		}
	}
	for _, z := range c.allZones {
		if len(z.cluster) < 2 {
			continue
		}
		if !hasInteriorPR[z.cluster[0]] {
			continue
		}
		for _, n := range z.networks {
			for big := n.up; big != nil; big = big.up {
				if !big.isAggregate {
					if big.zone == n.zone {
						break
					}
					big.subnetsInCluster.push(n)
				}
			}
		}
	}
}
