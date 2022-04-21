package pass1

import (
	"sort"
	"strings"
)

/* SetPath adds navigation information to the nodes of the graph to
/* enable fast path traversal; identifies loops and performs
/* consistency checks on pathrestrictions and virtual interfaces.*/
func (c *spoc) setPath() {
	c.progress("Preparing fast path traversal")
	c.findDistsAndLoops()
	c.processLoops()
	c.checkVirtualInterfaces()
	c.checkPathrestrictions()
	c.linkPathrestrictions()
}

/* findDistsAndLoops sets direction and distances to an arbitrary
/* chosen start zone. Identifies loops inside the graph topology, tags
/* nodes of a cycle with a common loop object and distance. Checks for
/* multiple unconnected parts of topology.*/
func (c *spoc) findDistsAndLoops() {
	if len(c.allZones) == 0 {
		c.abort("topology seems to be empty")
	}

	startDistance := 0
	var partitions []*zone
	var partition2Routers = make(map[*zone][]*router)

	// Find one or more connected partitions in whole topology.
	for _, z := range c.allZones {
		var partitionRouters []*router

		// Zone is part of previously processed partition.
		if z.toZone1 != nil || z.loop != nil {
			continue
		}

		zone1 := z
		//debug("%s", zone1.name)

		// Second parameter stands for not existing starting interface.
		// Value must be "false" and unequal to any interface.
		max, _, partitionRouters := setpathObj(zone1, nil, startDistance)

		// Use other distance values in disconnected partition.
		// Otherwise pathmark would erroneously find a path between
		// disconnected objects.
		startDistance = max + 1

		partitions = append(partitions, zone1)
		partition2Routers[zone1] = partitionRouters
	}

	unconnectedPartitions :=
		extractPartitionsConnectedBySplitRouter(partitions, partition2Routers)
	c.checkProperPartitionUsage(unconnectedPartitions)
}

/* setPathObj prepares efficient topology traversal, finds a path from
/* every zone and router to zone1; stores the distance to zone1 in
/* every object visited; identifies loops and adds loop marker
/* references to loop nodes.

/* Loop markers store following information:
/*  - exit: node of loop where zone1 is reached
/*  - distance: distance of loop exit node + 1.
/* It is needed, as the nodes own distance values are later reset to
/* the value of the cluster exit object. The intermediate value is
/* required by cluster_navigation to work.*/
func setpathObj(obj pathObj, toZone1 *routerIntf,
	distToZone1 int) (int, *loop, []*router) {

	var partitionRouters []*router

	//debug("--%d: %s -->  %s", distToZone1, obj, toZone1)

	// Return from recursion if loop was found.
	if obj.isActivePath() {

		// Create unique loop marker, which will be added to all loop members.
		newDistance := obj.getDistance() + 1
		foundLoop := &loop{
			exit:     obj,         // Reference exit node.
			distance: newDistance, // Required for cluster navigation.
		}
		toZone1.loop = foundLoop
		return newDistance, foundLoop, partitionRouters
	}

	// Continue graph exploration otherwise.
	obj.setActivePath()
	defer func() { obj.clearActivePath() }()
	obj.setDistance(distToZone1)
	maxDistance := distToZone1

	r, isRouter := obj.(*router)
	if isRouter {
		partitionRouters = append(partitionRouters, r)
	}
	// Process all of the objects interfaces.
	for _, objIntf := range obj.intfList() {

		if objIntf == toZone1 {
			continue
		}
		if objIntf.loop != nil {
			continue
		}

		// Get adjacent object/node.
		var nextObject pathObj
		if isRouter {
			nextObject = objIntf.zone
		} else {
			nextObject = objIntf.router
		}

		// Proceed with next node (distance + 2 to enable intermediate values).
		max, foundLoop, collectedRouters :=
			setpathObj(nextObject, objIntf, distToZone1+2)

		if max > maxDistance {
			maxDistance = max
		}

		partitionRouters = append(partitionRouters, collectedRouters...)

		if foundLoop == nil {
			objIntf.toZone1 = obj
		} else {
			objIntf.loop = foundLoop

			// Node is loop exit towards zone1.
			if obj == foundLoop.exit {

				// Mark exit node with a special loop marker.
				// If current loop is part of a cluster,
				// this marker will be overwritten later.
				if obj.getLoop() == nil {
					newLoop := &loop{
						exit:     obj,
						distance: distToZone1,
					}
					obj.setLoop(newLoop)
				}
			} else if obj.getLoop() != nil {

				innerLoop := obj.getLoop()
				// Node is also part of another loop.
				if foundLoop != innerLoop {

					// Set reference to loop object with exit closer to zone1
					if foundLoop.distance < innerLoop.distance {
						innerLoop.redirect = foundLoop
						obj.setLoop(foundLoop)
					} else {
						foundLoop.redirect = innerLoop
					}
				}
			} else {
				// Found intermediate loop node.
				obj.setLoop(foundLoop)
			}
		}
	}

	objLoop := obj.getLoop()
	if objLoop != nil && objLoop.exit != obj {
		return maxDistance, objLoop, partitionRouters
	}

	obj.setToZone1(toZone1)
	return maxDistance, nil, partitionRouters
}

func extractPartitionsConnectedBySplitRouter(partitions []*zone,
	partition2Routers map[*zone][]*router) []*zone {

	// Generate Lookups.
	router2partition := make(map[*router]*zone)
	partition2splitCrypto := make(map[*zone][]*router)

	for partition, routers := range partition2Routers {
		for _, r := range routers {
			router2partition[r] = partition
			if r.origRouter != nil {
				partition2splitCrypto[partition] =
					append(partition2splitCrypto[partition], r)
			}
		}
	}

	// Check which partitions are connected by split crypto router.
	var unconnectedPartitions []*zone
Partition:
	for _, zone1 := range partitions {
		if partition2splitCrypto[zone1] != nil {
			for _, routerPart := range partition2splitCrypto[zone1] {
				origRouter := routerPart.origRouter
				if router2partition[origRouter] != nil {
					zone2 := router2partition[origRouter]
					if zone1 != zone2 {
						continue Partition
					}
				}
			}
		}
		unconnectedPartitions = append(unconnectedPartitions, zone1)
	}
	return unconnectedPartitions
}

func (c *spoc) checkProperPartitionUsage(unconnectedPartitions []*zone) {

	partition2tags := c.mapPartitions2PartitionTags()

	// Several Partition Tags for single zone - show error.
	for zone1 := range partition2tags {
		if len(partition2tags[zone1]) > 1 {
			c.err("Several partition names in partition %s:\n - %s",
				zone1.name, strings.Join(partition2tags[zone1], "\n - "))
		}
	}

	// Split partitions by IP version.
	var unconnectedIPv6Partitions []*zone
	var unconnectedIPv4Partitions []*zone
	for _, unconnectedPartition := range unconnectedPartitions {
		if unconnectedPartition.ipVxObj.isIPv6() {
			unconnectedIPv6Partitions = append(unconnectedIPv6Partitions,
				unconnectedPartition)
		} else {
			unconnectedIPv4Partitions = append(unconnectedIPv4Partitions,
				unconnectedPartition)
		}
	}

	// Named single unconneted partition - show warning.
	c.warnAtNamedSingleUnconnectedPartition(unconnectedIPv6Partitions)
	c.warnAtNamedSingleUnconnectedPartition(unconnectedIPv4Partitions)

	// Several Unconnected Partitions without tags - show error.
	c.errorOnUnnamedUnconnectedPartitions(unconnectedIPv6Partitions,
		partition2tags)
	c.errorOnUnnamedUnconnectedPartitions(unconnectedIPv4Partitions,
		partition2tags)
}

func (c *spoc) mapPartitions2PartitionTags() map[*zone][]string {
	partition2tags := make(map[*zone][]string)
	for _, z := range c.allZones {
		if z.partition == "" {
			continue
		}
		z1 := findZone1(z)
		partition2tags[z1] = append(partition2tags[z1], z.partition)
		z1.partition = z.partition
	}
	return partition2tags
}

func (c *spoc) warnAtNamedSingleUnconnectedPartition(unconnected []*zone) {
	if len(unconnected) == 1 {
		z := unconnected[0]
		if name := z.partition; name != "" {
			c.warn("Spare partition name for single partition %s: %s.", z, name)
		}
	}
}

func (c *spoc) errorOnUnnamedUnconnectedPartitions(
	unconnectedPartitions []*zone,
	partitions2PartitionTags map[*zone][]string) {

	if len(unconnectedPartitions) > 1 {
		var unnamedUnconnectedPartitions []*zone
		for _, unconnectedPartition := range unconnectedPartitions {
			if _, exists := partitions2PartitionTags[unconnectedPartition]; !exists {
				unnamedUnconnectedPartitions = append(unnamedUnconnectedPartitions,
					unconnectedPartition)
			}
		}
		if len(unnamedUnconnectedPartitions) >= 1 {
			var ipVersion string
			if unconnectedPartitions[0].isIPv6() {
				ipVersion = "IPv6"
			} else {
				ipVersion = "IPv4"
			}
			var zone1Names stringList
			for _, zone1 := range unnamedUnconnectedPartitions {
				zone1Names.push(zone1.name)
			}
			c.err("%s topology has unconnected parts:\n"+
				"%s\n Use partition attribute, if intended.",
				ipVersion, zone1Names.nameList())
		}
	}
}

/* processLoops includes node objects and interfaces of nested loops
/* in the containing loop; adds loop cluster exits; adjusts distances of
/* loop nodes.*/
func (c *spoc) processLoops() {
	processObj := func(obj pathObj) {
		lo := obj.getLoop()
		if lo == nil {
			return
		}

		lo = findOuterLoop(lo)
		obj.setLoop(lo)

		// Needed for cactus graph loop clusters.
		setLoopClusterExit(lo)

		// Set distance of loop node to value of cluster exit.
		obj.setDistance(lo.clusterExit.getDistance())
	}

	// Include sub-loop IFs into containing loop with exit closest to zone1.
	processRouter := func(pathNodeRouter *router) {
		for _, intf := range pathNodeRouter.intfList() {
			if intf.loop != nil {
				intf.loop = findOuterLoop(intf.loop)
			}
		}
	}

	for _, obj := range c.allZones {
		processObj(obj)
	}
	for _, obj := range c.allRouters {
		if obj.managed != "" || obj.semiManaged {
			processObj(obj)
			processRouter(obj)
		}
	}
}

func findOuterLoop(lo *loop) *loop {
	for {
		if lo.redirect == nil {
			return lo
		}
		lo = lo.redirect
	}
}

/* setLoopClusterExit identifies clusters of directly connected loops
/* in cactus graphs. Finds exit node of loop cluster or single loop in
/* direction to zone1; adds this exit node as marker to all loop
/* objects of the cluster.*/
func setLoopClusterExit(lo *loop) pathObj {

	if lo.clusterExit != nil {
		return lo.clusterExit
	}

	exitNode := lo.exit

	// Exit node references itself: loop cluster exit found.
	if exitNode.getLoop() == lo {

		//debug("Loop %s, %d is in cluster %s", exit, lo.distance, exit)
		lo.clusterExit = exitNode
		return exitNode
	}

	// Exit node references another loop: proceed with next loop of cluster
	clusterExit := setLoopClusterExit(exitNode.getLoop())

	//debug("Loop %s, %d is in cluster %s", exit, lo.distance, cluster)
	lo.clusterExit = clusterExit
	return clusterExit
}

/* checkPathrestrictions removes pathrestrictions, that aren't proper
/* and effective.
/* Pathrestrictions have to fulfill following requirements:
 - Located inside or at the border of cycles.
 - At least 2 interfaces per pathrestriction.
 - Have an effect on ACL generation. */
func (c *spoc) checkPathrestrictions() {

	for _, p := range c.pathrestrictions {

		// Delete invalid elements of pathrestriction.
		c.removeRestrictedIntfsInWrongOrNoLoop(p)
		if len(p.elements) == 0 {
			continue
		}

		if pathrestrictionHasNoEffect(p) {
			c.warn("Useless %s.\n All interfaces are unmanaged and located "+
				"inside the same security zone", p.name)
			p.elements = nil
		}
	}

	// Collect effective pathrestrictions.
	var effective []*pathRestriction
	for _, restrict := range c.pathrestrictions {
		if len(restrict.elements) != 0 {
			effective = append(effective, restrict)
		}
	}
	c.pathrestrictions = effective
}

func (c *spoc) removeRestrictedIntfsInWrongOrNoLoop(p *pathRestriction) {
	var prevIntf *routerIntf
	var prevCluster pathObj
	j := 0
	for _, intf := range p.elements {
		// Show original interface in error message.
		origIntf := intf
		loop := getIntfLoop(intf)

		// If a pathrestricted interface is applied to an umanaged
		// router, the router is split into an unmanaged and a managed
		// router. The managed part has exactly two non secondary
		// interfaces. Move pathrestriction to the interface that is
		// located at border of loop.
		if loop == nil && intf.splitOther != nil {
			other := intf.splitOther
			if loop = other.zone.loop; loop != nil {
				intf = other
			}
		}

		if loop == nil {
			// Don't show warning for automatically created
			// pathrestriction because equivalent warning was already
			// shown for virtual interfaces.
			if !strings.HasPrefix(p.name, "auto-virtual:") {
				c.warn("Ignoring %s at %s\n because it isn't located "+
					"inside cyclic graph", p.name, intf)
			}
			continue
		}

		// Interfaces must belong to same loop cluster.
		cluster := loop.clusterExit
		if prevCluster != nil {
			if cluster != prevCluster {
				if !strings.HasPrefix(p.name, "auto-virtual:") {
					c.warn("Ignoring %s having elements from different loops:\n"+
						" - %s\n - %s", p.name, prevIntf, origIntf)
				}
				p.elements = nil
				return
			}
		} else {
			prevCluster = cluster
			prevIntf = origIntf
		}
		p.elements[j] = intf
		j++
	}
	p.elements = p.elements[:j]
}

// Pathrestrictions that do not affect any ACLs are useless
func pathrestrictionHasNoEffect(p *pathRestriction) bool {

	// Pathrestrictions at managed routers do most probably have an effect.
	for _, intf := range p.elements {
		if intf.router.managed != "" || intf.router.routingOnly {
			return false
		}
	}
	if restrictSpansDifferentZonesOrZoneclusters(p) {
		return false
	}
	if restrictIsInLoopWithSeveralZoneClusters(p) {
		return false
	}
	return true
}

// Pathrestrictions spanning more than one zone/zone cluster affect ACLs.
// Each zone of a cluster references the same slice, so it is
// sufficient to compare first element.
func restrictSpansDifferentZonesOrZoneclusters(p *pathRestriction) bool {
	ref := p.elements[0].zone.cluster[0]
	for _, intf := range p.elements[1:] {
		if intf.zone.cluster[0] != ref {
			return true
		}
	}
	return false
}

// Pathrestrictions in loops with > 1 zone cluster affect ACLs.
func restrictIsInLoopWithSeveralZoneClusters(r *pathRestriction) bool {
	refIntf := r.elements[0]
	refLoop := getIntfLoop(refIntf)

	// Process every zone in zone cluster...
	for _, z := range refIntf.zone.cluster {
		for _, zIntf := range z.interfaces {
			// ...examine its neighbour zones...
			for _, intf2 := range zIntf.router.interfaces {
				z2 := intf2.zone
				if !zoneEq(z2, z) && refLoop == z2.loop {
					// found other zone cluster in same loop.
					return true
				}
			}
		}
	}
	return false
}

func getIntfLoop(intf *routerIntf) *loop {
	if loop := intf.loop; loop != nil {
		return loop
	}
	if loop := intf.router.loop; loop != nil {
		return loop
	}
	if loop := intf.zone.loop; loop != nil {
		return loop
	}
	return nil
}

// Add non redundant pathrestrictions to attribute .pathRestrict of
// corresponding interfaces.
func (c *spoc) linkPathrestrictions() {
	// Check if elements of p are subset of some larger pathrestriction.
	isRedundantTo := func(p *pathRestriction) *pathRestriction {
	OTHER:
		for _, other := range p.elements[0].pathRestrict {
		INTF:
			for _, intf := range p.elements[1:] {
				for _, other2 := range intf.pathRestrict {
					if other2 == other {
						continue INTF
					}
				}
				continue OTHER
			}
			return other
		}
		return nil
	}
	addToIntf := func(p *pathRestriction) {
		for _, intf := range p.elements {
			intf.pathRestrict = append(intf.pathRestrict, p)
		}
	}

	// Add large pathrestrictions first, so we can check if small
	// pathrestriction is contained in large one.
	sort.Slice(c.pathrestrictions, func(i, j int) bool {
		return len(c.pathrestrictions[j].elements) <
			len(c.pathrestrictions[i].elements)
	})
	j := 0
	for _, p := range c.pathrestrictions {
		if other := isRedundantTo(p); other != nil {
			c.diag("Removed %s; is subset of %s", p.name, other.name)
		} else {
			addToIntf(p)
			c.pathrestrictions[j] = p
			j++
		}
	}
	c.pathrestrictions = c.pathrestrictions[:j]
}

/* checkVirtualInterfaces assures interfaces with identical virtual IP
/* are located inside the same loop.*/
func (c *spoc) checkVirtualInterfaces() {
	var seen = make(map[*routerIntf]bool)

	for _, intf := range c.virtualInterfaces {
		// Ignore single virtual interface.
		if len(intf.redundancyIntfs) <= 1 {
			continue
		}

		// Loops inside a security zone are not known and can not be checked
		if intf.router.managed == "" && !intf.router.semiManaged {
			continue
		}

		// Check whether all virtual interfaces are part of a loop.
		if intf.router.loop == nil {
			c.warn("%s must be located inside cyclic sub-graph", intf)
			continue
		}

		if seen[intf] {
			continue
		}
		for _, redundancyIntf := range intf.redundancyIntfs {
			seen[redundancyIntf] = true
		}

		// Check whether all virtual interfaces are part of same loop.
		referenceLoop := intf.redundancyIntfs[0].loop
		for _, virtIntf := range intf.redundancyIntfs[1:] {
			if referenceLoop != virtIntf.loop {
				c.err("Virtual interfaces\n%s\n must all be part of the "+
					"same cyclic sub-graph", intf.redundancyIntfs.nameList())
				break
			}
		}
	}
}
