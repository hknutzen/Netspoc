package pass1

import (
	"sort"
	"strings"
)

/*
	SetPath adds navigation information to the nodes of the graph to

/* enable fast path traversal; identifies loops and performs
/* consistency checks on pathrestrictions and virtual interfaces.
*/
func (c *spoc) setPath() {
	c.progress("Preparing fast path traversal")
	c.findDistsAndLoops()
	c.processLoops()
	c.checkPartitions()
	c.checkVirtualInterfaces()
	c.checkPathrestrictions()
	c.linkPathrestrictions()
}

// findDistsAndLoops sets direction and distances to an arbitrary
// chosen start zone. Identifies loops inside the graph topology, tags
// nodes of a cycle with a common loop object and distance.
func (c *spoc) findDistsAndLoops() {
	if len(c.allZones) == 0 {
		c.abort("topology seems to be empty")
	}

	startDistance := 0
	for _, z := range c.allZones {

		// Zone is part of previously processed partition.
		if z.toZone1 != nil || z.loop != nil {
			continue
		}

		zone1 := z
		//debug("%s", zone1.name)

		// Second parameter stands for not existing starting interface.
		max, _ := setpathObj(zone1, nil, startDistance)

		// Use other distance values in disconnected partition.
		// Otherwise pathmark would erroneously find a path between
		// disconnected objects.
		startDistance = max + 1
	}
}

/*
	setPathObj prepares efficient topology traversal, finds a path from

/* every zone and router to zone1; stores the distance to zone1 in
/* every object visited; identifies loops and adds loop marker
/* references to loop nodes.

/* Loop markers store following information:
/*  - exit: node of loop where zone1 is reached
/*  - distance: distance of loop exit node + 1.
/* It is needed, as the nodes own distance values are later reset to
/* the value of the cluster exit object. The intermediate value is
/* required by cluster_navigation to work.
*/
func setpathObj(obj pathObj, toZone1 *routerIntf, distToZone1 int,
) (int, *loop) {
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
		return newDistance, foundLoop
	}

	// Continue graph exploration otherwise.
	obj.setActivePath()
	defer func() { obj.clearActivePath() }()
	obj.setDistance(distToZone1)
	maxDistance := distToZone1

	// Process all of the objects interfaces.
	_, isRouter := obj.(*router)
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
		max, foundLoop :=
			setpathObj(nextObject, objIntf, distToZone1+2)

		if max > maxDistance {
			maxDistance = max
		}

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
		return maxDistance, objLoop
	}

	obj.setToZone1(toZone1)
	return maxDistance, nil
}

func (c *spoc) checkPartitions() {
	var unconnected []*zone
	zone2tags := make(map[*zone][]string)
	seen := make(map[*zone]bool)
	for _, z := range c.allZones {
		if !seen[z] {
			tags := markPartitionGetTags(z, seen)
			unconnected = append(unconnected, z)
			zone2tags[z] = tags
		}
	}
	c.checkProperPartitionUsage(unconnected, zone2tags)
}

func markPartitionGetTags(z *zone, seen map[*zone]bool) []string {
	var tags []string
	var mark func(z *zone, fromIntf *routerIntf)
	mark = func(z *zone, fromIntf *routerIntf) {
		seen[z] = true
		if z.partition != "" {
			tags = append(tags, z.partition)
		}
		for _, inIntf := range z.interfaces {
			if inIntf != fromIntf {
				// Also traverse split crypto routers.
				for _, outIntf := range getIntf(inIntf.router) {
					if outIntf != inIntf {
						z2 := outIntf.network.zone
						if !seen[z2] {
							mark(z2, outIntf)
						}
					}
				}
			}
		}
	}
	mark(z, nil)
	return tags
}

func findPartitionTag(store pathStore) string {
	var z *zone
	switch x := store.(type) {
	case *routerIntf:
		z = x.zone
	case *router:
		z = x.interfaces[0].zone
	case *zone:
		z = x
	}
	seen := make(map[*zone]bool)
	if tags := markPartitionGetTags(z, seen); len(tags) > 0 {
		return tags[0]
	}
	return ""
}

func (c *spoc) checkProperPartitionUsage(
	unconnected []*zone, zone2tags map[*zone][]string,
) {
	// Several partition tags for single zone - show error.
	for _, z := range unconnected {
		if tags := zone2tags[z]; len(tags) > 1 {
			c.err("Several partition names in partition %s:\n - %s",
				z.name, strings.Join(tags, "\n - "))
		}
	}

	// Split partitions by IP version.
	var unconnectedIPv6 []*zone
	var unconnectedIPv4 []*zone
	for _, z := range unconnected {
		if z.ipVxObj.isIPv6() {
			unconnectedIPv6 = append(unconnectedIPv6, z)
		} else {
			unconnectedIPv4 = append(unconnectedIPv4, z)
		}
	}

	// Named single unconneted partition - show warning.
	c.warnAtNamedSingleUnconnectedPartition(unconnectedIPv6, zone2tags)
	c.warnAtNamedSingleUnconnectedPartition(unconnectedIPv4, zone2tags)

	// Several Unconnected Partitions without tags - show error.
	c.errorOnUnnamedUnconnectedPartitions(unconnectedIPv6, zone2tags)
	c.errorOnUnnamedUnconnectedPartitions(unconnectedIPv4, zone2tags)
}

func (c *spoc) warnAtNamedSingleUnconnectedPartition(
	unconnected []*zone, zone2tags map[*zone][]string,
) {
	if len(unconnected) == 1 {
		z := unconnected[0]
		if tags := zone2tags[z]; tags != nil {
			c.warn("Spare partition name for single partition %s: %s.", z, tags[0])
		}
	}
}

func (c *spoc) errorOnUnnamedUnconnectedPartitions(
	unconnected []*zone, zone2tags map[*zone][]string,
) {
	if len(unconnected) > 1 {
		var names stringList
		for _, z := range unconnected {
			if zone2tags[z] == nil {
				names.push(z.name)
			}
		}
		if len(names) >= 1 {
			ipVersion := "IPv" + cond(unconnected[0].isIPv6(), "6", "4")
			c.err("%s topology has unconnected parts:\n"+
				"%s\n Use partition attribute, if intended.",
				ipVersion, names.nameList())
		}
	}
}

/*
	processLoops includes node objects and interfaces of nested loops

/* in the containing loop; adds loop cluster exits; adjusts distances of
/* loop nodes.
*/
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

/*
	setLoopClusterExit identifies clusters of directly connected loops

/* in cactus graphs. Finds exit node of loop cluster or single loop in
/* direction to zone1; adds this exit node as marker to all loop
/* objects of the cluster.
*/
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

/*
	checkPathrestrictions removes pathrestrictions, that aren't proper

/* and effective.
/* Pathrestrictions have to fulfill following requirements:
  - Located inside or at the border of cycles.
  - At least 2 interfaces per pathrestriction.
  - Have an effect on ACL generation.
*/
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

// checkVirtualInterfaces assures interfaces with identical virtual IP
// are located inside the same loop.
// Loops inside a security zone are not known and will not be checked.
func (c *spoc) checkVirtualInterfaces() {
	for _, pr := range c.pathrestrictions {
		intf := pr.elements[0]

		// Ignore pathrestriction at other than virtual interface and at
		// single virtual interface.
		if len(intf.redundancyIntfs) <= 1 {
			continue
		}

		// Check whether all virtual interfaces are part of a loop and
		// whether the are part of same loop.
		referenceLoop := intf.loop
		for _, virtIntf := range intf.redundancyIntfs {
			if virtIntf.loop == nil {
				c.warn("%s must be located inside cyclic sub-graph", virtIntf)
			} else if referenceLoop != virtIntf.loop {
				c.err("Virtual interfaces\n%s\n must all be part of the "+
					"same cyclic sub-graph", intf.redundancyIntfs.nameList())
				break
			}
		}
	}
}
