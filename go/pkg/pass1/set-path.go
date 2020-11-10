package pass1

import (
	"strings"
)

/* SetPath adds navigation information to the nodes of the graph to
/* enable fast path traversal; identifies loops and performs
/* consistency checks on pathrestrictions and virtual interfaces.*/
func (c *spoc) setPath() {
	c.progress("Preparing fast path traversal")
	c.findDistsAndLoops()
	c.processLoops()
	c.checkPathrestrictions()
	c.checkVirtualInterfaces()
	c.removeRedundantPathrestrictions()
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

	unconnectedPartitions := extractPartitionsConnectedBySplitRouter(partitions,
		partition2Routers)
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
func setpathObj(obj pathObj, intfToZone1 *routerIntf,
	distToZone1 int) (int, *loop, []*router) {

	var partitionRouters []*router

	/*	//debug
		var intfToZone1Name string
		if intfToZone1 != nil {
			intfToZone1Name = intfToZone1.String()
		}
		debug("--%d: %s -->  %s", distToZone1, obj.String(), intfToZone1Name); //*/

	// Return from recursion if loop was found.
	if obj.isActivePath() {

		// Create unique loop marker, which will be added to all loop members.
		newDistance := obj.getDistance() + 1
		foundLoop := &loop{
			exit:     obj,         // Reference exit node.
			distance: newDistance, // Required for cluster navigation.
		}
		intfToZone1.loop = foundLoop
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

		if objIntf == intfToZone1 {
			continue
		}
		if objIntf.loop != nil {
			continue
		}
		if objIntf.mainIntf != nil {
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
		max, foundLoop, collectedRouters := setpathObj(nextObject, objIntf,
			distToZone1+2)

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

	obj.setToZone1(intfToZone1)
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

	partitions2PartitionTags := c.mapPartitions2PartitionTags()

	// Several Partition Tags for single zone - generate error.
	for zone1 := range partitions2PartitionTags {
		if len(partitions2PartitionTags[zone1]) > 1 {
			c.err("Several partition names in partition %s:\n - %s",
				zone1.name, strings.Join(partitions2PartitionTags[zone1], "\n - "))
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

	// Named single unconneted partition - generate warning.
	c.warnAtNamedSingleUnconnectedPartition(unconnectedIPv6Partitions)
	c.warnAtNamedSingleUnconnectedPartition(unconnectedIPv4Partitions)

	// Several Unconnected Partitions without tags - generate Error.
	c.errorOnUnnamedUnconnectedPartitions(unconnectedIPv6Partitions,
		partitions2PartitionTags)
	c.errorOnUnnamedUnconnectedPartitions(unconnectedIPv4Partitions,
		partitions2PartitionTags)
}

func (c *spoc) mapPartitions2PartitionTags() map[*zone][]string {

	var zonesWithPartitionTag []*zone
	for _, z := range c.allZones {
		if z.partition != "" {
			zonesWithPartitionTag = append(zonesWithPartitionTag, z)
		}
	}

	var partitions2PartitionTags = make(map[*zone][]string)
	for _, z := range zonesWithPartitionTag {
		var zone1 *zone
		zone1 = findZone1(z)
		partitions2PartitionTags[zone1] =
			append(partitions2PartitionTags[zone1], z.partition)
		zone1.partition = z.partition
	}
	return partitions2PartitionTags
}

func (c *spoc) warnAtNamedSingleUnconnectedPartition(
	unconnectedPartitions []*zone) {

	if len(unconnectedPartitions) == 1 {
		var partitionName = unconnectedPartitions[0].partition
		if partitionName != "" {
			c.warn("Spare partition name for single partition %s: %s.",
				unconnectedPartitions[0].name, partitionName)
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
			if unconnectedPartitions[0].ipVxObj.isIPv6() {
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

		/*debug("Loop %s, %d is in cluster %s",
		exit.String(), lo.distance, exit.String());//*/
		lo.clusterExit = exitNode
		//		return lo.clusterExit
		return exitNode
	}

	// Exit node references another loop: proceed with next loop of cluster
	clusterExit := setLoopClusterExit(exitNode.getLoop())

	/*debug("Loop %s, %d is in cluster %s", exit.String(),
	lo.distance, cluster.String());//*/
	lo.clusterExit = clusterExit
	return lo.clusterExit
}

/* checkPathrestrictions removes pathrestrictions, that aren't proper
/* and effective.
/* Pathrestrictions have to fulfill following requirements:
 - Located inside or at the border of cycles.
 - At least 2 interfaces per pathrestriction.
 - Have an effect on ACL generation. */
func (c *spoc) checkPathrestrictions() {

	for _, restrict := range c.pathrestrictions {

		if len(restrict.elements) == 0 {
			continue
		}

		// Delete invalid elements of pathrestriction.
		var toBeDeleted []*routerIntf
		toBeDeleted = c.identifyRestrictedIntfsInWrongOrNoLoop(restrict)

		// Ignore pathrestriction with only one element.
		if len(toBeDeleted)+1 == len(restrict.elements) {
			toBeDeleted = restrict.elements
		}
		if len(toBeDeleted) > 0 {
			removeIntfsfromPathRestriction(restrict, toBeDeleted)
		}
		if len(restrict.elements) == 0 {
			continue
		}

		// Mark pathrestricted interface at border of loop, where loop
		// node is a zone.
		// This needs special handling during path_mark and path_walk.
		for _, intf := range restrict.elements {
			if intf.loop == nil && intf.zone.loop != nil {
				intf.loopZoneBorder = true
			}
		}

		if pathrestrictionHasNoEffect(restrict) {
			c.warn("Useless %s.\n All interfaces are unmanaged and located "+
				"inside the same security zone", restrict.name)
			restrict.elements = nil
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

func (c *spoc) identifyRestrictedIntfsInWrongOrNoLoop(
	restrict *pathRestriction) []*routerIntf {

	var misplacedRestricts []*routerIntf
	var prevInterface *routerIntf
	var prevCluster pathObj
	for _, intf := range restrict.elements {
		loop := getIntfLoop(intf)

		if loop == nil && intf.splitOther != nil {
			loop = movePathrestrictionToLoopIntfOfSplitRouter(intf)
		}

		if loop == nil {
			c.warn("Ignoring %s at %s\n because it isn't located "+
				"inside cyclic graph", restrict.name, intf.name)
			misplacedRestricts = append(misplacedRestricts, intf)
			continue
		}

		// Interfaces must belong to same loop cluster.
		cluster := loop.clusterExit
		if prevCluster != nil {
			if cluster != prevCluster {
				c.warn("Ignoring %s having elements from different loops:\n"+
					" - %s\n - %s", restrict.name, prevInterface.name, intf.name)
				misplacedRestricts = restrict.elements
				break
			}
		} else {
			prevCluster = cluster
			prevInterface = intf
		}
	}
	return misplacedRestricts
}

/* If a pathrestricted interface is applied to an umanaged router, the
/* router is split into an unmanaged and a managed router. The managed
/* part has exactly two non secondary interfaces. Move pathrestriction
/* to the interface that is located at border of loop. */
func movePathrestrictionToLoopIntfOfSplitRouter(intf *routerIntf) *loop {
	other := intf.splitOther

	if other.zone.loop != nil {

		loop := other.zone.loop
		rlist := intf.pathRestrict

		intf.pathRestrict = nil
		other.pathRestrict = rlist

		//debug("Move pathrestrictions from %s to %s", intf.name, other.name)
		for _, restrict := range other.pathRestrict {
			//debug(" - %s", restrict.name)
			restrictedIntfs := restrict.elements
			substituteIntf(restrictedIntfs, intf, other)
		}
		return loop
	}
	return nil
}

// Substitute a routerInterface within a slice.
func substituteIntf(slice []*routerIntf, oldIntf *routerIntf,
	newIntf *routerIntf) {
	for i, intf := range slice {
		if intf == oldIntf {
			slice[i] = newIntf
			break
		}
	}
}

func removeIntfsfromPathRestriction(restrict *pathRestriction,
	toBeDeleted []*routerIntf) {

	for _, intf := range toBeDeleted {
		restrict.elements = deleteIntfFrom(restrict.elements, intf)
		intf.pathRestrict = deletePathRestrictionFrom(intf.pathRestrict,
			restrict)
		if len(intf.pathRestrict) == 0 {
			intf.pathRestrict = nil
		}
	}
}

func deleteIntfFrom(slice []*routerIntf, intf *routerIntf) []*routerIntf {
	for index, sliceIntf := range slice {
		if intf == sliceIntf {
			return append(slice[:index], slice[(index+1):]...)
		}
	}
	return slice
}

// Pathrestrictions that do not affect any ACLs are useless
func pathrestrictionHasNoEffect(restrict *pathRestriction) bool {

	// Pathrestrictions at managed routers do most probably have an effect.
	for _, intf := range restrict.elements {
		if intf.router.managed != "" || intf.router.routingOnly {
			return false
		}
	}
	if restrictSpansDifferentZonesOrZoneclusters(restrict) {
		return false
	}
	if restrictIsInLoopWithSeveralZoneClusters(restrict) {
		return false
	}
	return true
}

// Pathrestrictions spanning more than one zone/zone cluster affect ACLs.
func restrictSpansDifferentZonesOrZoneclusters(r *pathRestriction) bool {
	getZoneOrCluster := func(intf *routerIntf) *zone {
		z := intf.zone
		if c := z.zoneCluster; c != nil {
			// Each zone of a cluster references the same slice, so it is
			// sufficient to compare first element.
			z = c[0]
		}
		return z
	}
	reference := getZoneOrCluster(r.elements[0])
	for _, intf := range r.elements[1:] {
		if getZoneOrCluster(intf) != reference {
			return true
		}
	}
	return false
}

// Pathrestrictions in loops with > 1 zone cluster affect ACLs.
func restrictIsInLoopWithSeveralZoneClusters(restrict *pathRestriction) bool {

	referenceIntf := restrict.elements[0]
	referenceLoop := getIntfLoop(referenceIntf)
	if referenceLoop == nil {
		return false
	}
	referenceCluster := referenceIntf.zone.zoneCluster
	if len(referenceCluster) == 0 {
		referenceCluster = []*zone{referenceIntf.zone}
	}

	for _, z := range referenceCluster {
		for _, zoneIntf := range z.interfaces {
			for _, intf2 := range zoneIntf.router.interfaces {
				z2 := intf2.zone
				if !zoneEq(z2, z) && referenceLoop == z2.loop {
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

/* checkVirtualInterfaces assures interfaces with identical virtual IP
/* are located inside the same loop.*/
func (c *spoc) checkVirtualInterfaces() {
	var seen = make(map[*routerIntf]bool)

	for _, intf := range c.virtualInterfaces {
		if intf.redundancyIntfs == nil {
			continue
		}
		// Ignore single virtual interface.
		if len(intf.redundancyIntfs) <= 1 {
			continue
		}

		// Loops inside a security zone are not known and can not be checked
		if intf.router.managed == "" && !intf.router.semiManaged {
			continue
		}

		if seen[intf] {
			continue
		} else {
			for _, redundancyIntf := range intf.redundancyIntfs {
				seen[redundancyIntf] = true
			}
		}

		// Check whether all virtual interfaces are part of a loop.
		var err bool
		for _, virtIntf := range intf.redundancyIntfs {
			if virtIntf.router.loop == nil {
				c.err("%s must be located inside cyclic sub-graph", virtIntf.name)
				err = true
			}
		}

		if err {
			// Remove invalid pathrestriction to prevent inherited errors.
			for _, virtIntf := range intf.redundancyIntfs {
				virtIntf.pathRestrict = nil
			}
			continue
		}

		// Check whether all virtual interfaces are part of same loop.
		referenceLoop := intf.redundancyIntfs[0].loop
		for _, virtIntf := range intf.redundancyIntfs[1:] {
			if referenceLoop != virtIntf.loop {
				var virtIntfNames stringList
				for _, virtIntf := range intf.redundancyIntfs {
					virtIntfNames.push(virtIntf.name)
				}
				c.err("Virtual interfaces\n%s\n must all be part of the "+
					"same cyclic sub-graph", virtIntfNames.nameList())
				break
			}
		}
	}
}

type prIntfKey struct {
	pr   *pathRestriction
	intf *routerIntf
}

func (c *spoc) removeRedundantPathrestrictions() {

	intf2restrictions := make(map[prIntfKey]bool)
	for _, restrict := range c.pathrestrictions {
		for _, element := range restrict.elements {
			intf2restrictions[prIntfKey{pr: restrict, intf: element}] = true
		}
	}

	var valid []*pathRestriction
	for _, restrict := range c.pathrestrictions {
		other := findContainingPathRestriction(restrict, intf2restrictions)
		if other != nil {
			deletePathrestrictionFromInterfaces(restrict)
			c.diag("Removed %s; is subset of %s", restrict.name, other.name)
		} else {
			valid = append(valid, restrict)
		}
	}
	c.pathrestrictions = valid
}

// Find pathrestriction of equal/bigger size sharing all elements of
// restrict.
func findContainingPathRestriction(restrict *pathRestriction,
	intf2restrictions map[prIntfKey]bool) *pathRestriction {

OTHER:
	for _, other := range restrict.elements[0].pathRestrict {
		if other != restrict && len(other.elements) >= len(restrict.elements) {
			for _, intf := range restrict.elements[1:] {
				if !intf2restrictions[prIntfKey{pr: other, intf: intf}] {
					continue OTHER
				}
			}
			return other
		}
	}
	return nil
}

func deletePathrestrictionFromInterfaces(restrict *pathRestriction) {
	elements := restrict.elements
	for _, intf := range elements {
		intf.pathRestrict = deletePathRestrictionFrom(
			intf.pathRestrict, restrict)

		// Delete empty array to speed up checks in clusterPathMark.
		if len(intf.pathRestrict) == 0 {
			intf.pathRestrict = nil
		}
	}
}

func deletePathRestrictionFrom(
	slice []*pathRestriction, pathRestr *pathRestriction) []*pathRestriction {
	for index, slicePathRestr := range slice {
		if pathRestr == slicePathRestr {
			return append(slice[:index], slice[index+1:]...)
		}
	}
	return slice
}
