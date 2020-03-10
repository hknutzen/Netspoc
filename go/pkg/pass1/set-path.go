package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"sort"
	"strings"
)

//###################################################################
// Set paths for efficient topology traversal
//###################################################################
// Purpose  : Find a path from every zone and router to zone1; store the
//            distance to zone1 in every object visited; identify loops and
//            add loop marker references to loop nodes.
// Parameter: obj     : zone or managed or semi-managed router
//            to_zone1: interface of obj; denotes the direction to reach zone1
//            distance: distance to zone1
// Returns  : 1. maximal value of distance used in current subtree.
//            2. undef, if found path is not part of a loop or loop-marker
//               otherwise.
// Comments : Loop markers store following information:
//            - exit: node of the loop where zone1 is reached
//            - distance: distance of loop exit node + 1. It is needed, as the
//            nodes own distance values are later reset to the value of the
//            cluster exit object. The intermediate value is required by
//            cluster_navigation to work.
//sub setpathObj

func setpathObj(obj pathObj, intfToZone1 *routerIntf, distToZone1 int) (int, *loop) {

/*	// debugging Meike: function if != nil get string
	var i string
	if intfToZone1 != nil {
		i = intfToZone1.String()
	}
	//debug("--%d: %s -->  %s", distToZone1, obj.String(), i);
*/ // end debugging
	// Return from recursion if loop was found.
	if obj.isActivePath() == true { // Loop found, node might be loop exit to zone1.

		// Create unique loop marker, which will be added to all loop members.
		newDistance := obj.getDistance() + 1
		foundLoop := &loop{
			exit:     obj,         // Reference exit node.
			distance: newDistance, // Required for cluster navigation.
		}
		intfToZone1.loop = foundLoop
		return newDistance, foundLoop
	}

	// Continue graph exploration otherwise.
	obj.setActivePath()
	defer func() { obj.clearActivePath() }()
	obj.setDistance(distToZone1)
	maxDistance := distToZone1

	// Process all of the objects interfaces.
	for _, objIntf := range obj.intfList() {

		// Skip interfaces:
		//        no warnings "uninitialized" //Meike: braucht man das??
		if objIntf == intfToZone1 {
			continue
		}

		//        use warnings "uninitialized" //Meike: braucht man das??
		if objIntf.loop != nil {
			continue
		}
		if objIntf.mainIntf != nil {
			continue
		}

		// Get adjacent object/node.  Meike: prüfe, ob das nächste node
		// objekt zone oder router ist.  Problem: wir können hier nicht
		// über zonen laufen, denn der Router ist kein zonen type. also
		// muss die ganze funktion über pfadobjekte laufen.
		_, isRouter := obj.(*router)

		var nextObject pathObj
		if isRouter {
			nextObject = objIntf.zone
		} else {
			nextObject = objIntf.router
		}

		// Proceed with next node (distance + 2 to enable intermediate values).
		max, foundLoop := setpathObj(nextObject, objIntf, distToZone1+2)
		if max > maxDistance {
			maxDistance = max
		}

		// Process recursion stack: Node is on a loop path.
		if foundLoop != nil {
			objIntf.loop = foundLoop
			loopExitObj := foundLoop.exit

			// Found exit of loop in direction to zone1.
			if obj == loopExitObj {

				// Mark exit node with a different loop marker linking to itself.
				// If current loop is part of a cluster,
				// this marker will be overwritten later.
				// Otherwise this is the exit of a cluster of loops.

				// Meike: setLoop testet auch auf nil, if abfrage ist
				// also eigentliche nicht notwendig. aber ich hätte
				// gerne die entscheidung hier noch sichtbar. nochmal
				// drüber nachdenken...
				if obj.getLoop() == nil {
					newLoop := &loop{ //Meike: warum hier nochmal
						exit:     obj,
						distance: distToZone1,
					}
					obj.setLoop(newLoop)
				}
			} else if obj.getLoop() != nil {
				innerLoop := obj.getLoop()
				// Found intermediate loop node which was marked as loop before.
				if foundLoop != innerLoop { //Node is also part of another loop

					// Set reference to loop object with exit closer to zone1
					if foundLoop.distance < innerLoop.distance {
						innerLoop.redirect = foundLoop // keep info in loop
						obj.setLoop(foundLoop)
					} else {
						foundLoop.redirect = innerLoop
					}
				}
			} else {
				// Found intermediate loop node.
				// Meike: blöder Name: hier ist ja noch gar keine Loop da...
				obj.setLoop(foundLoop)
			}
		} else {

			// Mark loop-less path.
			objIntf.toZone1 = obj
		}
	}

	// Return from recursion after all interfaces have been processed.
	objLoop := obj.getLoop()
	if objLoop != nil && objLoop.exit != obj {
		return maxDistance, objLoop

	} else {
		obj.setToZone1(intfToZone1)
		return maxDistance, nil
	}
}

//###############################################################################
// Purpose  : Identify clusters of directly connected loops in cactus graphs.
//            Find exit node of loop cluster or single loop in direction to
//            zone1; add this exit node as marker to all loop objects of the
//            cluster.
// Parameter: loop: Top-level loop object (after redirection).
// Returns  : A reference to the loop cluster exit node.
func setLoopCluster(myLoop *loop) pathObj {

	// Return loop cluster exit node, if loop has been processed before.
	if myLoop.clusterExit != nil {
		return myLoop.clusterExit
	} else {

		// Examine the loop object referenced in the loops exit node.
		exit := myLoop.exit

		// Exit node references itself: loop cluster exit found.
		exitLoop := exit.getLoop()
		if exitLoop == myLoop { //  # Exit node references itself.

			//debug("Loop %s, %d is in cluster %s", exit.String(), myLoop.distance, exit.String());
			myLoop.clusterExit = exit
			return myLoop.clusterExit
		} else {
			// Exit node references another loop: proceed with next loop of cluster
			cluster := setLoopCluster(exit.getLoop())

			//debug("Loop %s, %d is in cluster %s", exit.String(), myLoop.distance, cluster.String());
			myLoop.clusterExit = cluster
			return myLoop.clusterExit
		}
	}
}

// Print list of names in messages.
func nameList(namedZones []*zone) string {
	var listOfZoneNames string
	if len(namedZones) > 0 {
		for _, myZone := range namedZones {
			listOfZoneNames += " - "
			listOfZoneNames += myZone.name
			listOfZoneNames += "\n"
		}
	}
	return listOfZoneNames
}

//##############################################################################
// Purpose : Set direction and distances to an arbitrary chosen start zone.
//           Identify loops inside the graph topology, tag nodes of a
//           cycle with a common loop object and distance.
//           Check for multiple unconnected parts of topology.
func findDistsAndLoops() {
	if len(zones) <= 0 { //Meike: warum <= ??
		abort.Msg("topology seems to be empty")
	}

	var pathRouters []*router
	for _, r := range allRouters {
		if r.semiManaged {
			pathRouters = append(pathRouters, r)
		}
		if r.managed != "" {
			pathRouters = append(pathRouters, r)
		}
	}
	startDistance := 0
	var partitions []*zone
	router2partition := make(map[*router]*zone)
	partition2splitCrypto := make(map[*zone][]*router)

	// Find one or more connected partitions in whole topology.
	// Only iterate zones, because unconnected routers have been
	// rejected before.
	for _, z := range zones { //!!!Nicht wie den typ zone nennen!!!

		// Zone is connected to some previously processed partition.
		if z.getToZone1() != nil || z.getLoop() != nil {
			continue
		}

		// Chose an arbitrary node to start from.
		zone1 := z
		//        debug zone1->{name};

		// Traverse all nodes connected to zone1.
		// Second parameter stands for not existing starting interface.
		// Value must be "false" and unequal to any interface.
		var max int
		max, _ = setpathObj(zone1, zone1.toZone1, startDistance)

		// Use other distance values in disconnected partition.
		// Otherwise pathmark would erroneously find a path between
		// disconnected objects.
		startDistance = max + 1

		// Collect zone1 of each partition.
		partitions = append(partitions, zone1)

		// Check if split crypto parts are located inside current partition.
		// Collect remaining routers for next partititions.
		var unconnected []*router
		for _, r := range pathRouters {
			if r.getToZone1() != nil || r.getLoop() != nil {
				router2partition[r] = zone1
				if r.origRouter != nil {
					partition2splitCrypto[zone1] =
						append(partition2splitCrypto[zone1], r)
				}
			} else {
				unconnected = append(unconnected, r)
			}
		}
		pathRouters = unconnected
	}

	// Check for unconnected partitions.
	// Ignore partition, that is linked to some other partition
	// by split crypto router.
	var unconnected []*zone
Partition:
	for _, zone1 := range partitions {
		if partition2splitCrypto[zone1] != nil {
			var cryptoParts []*router
			cryptoParts = partition2splitCrypto[zone1]
			for _, part := range cryptoParts {
				origRouter := part.origRouter
				if router2partition[origRouter] != nil {
					zone2 := router2partition[origRouter]
					if zone1 != zone2 {
						continue Partition
					}
				}
			}
		}
		unconnected = append(unconnected, zone1)
	}

	// Check whether partitions are unconnected on purpose:
	// Find zones with a partition-flag and partitions zone1.
	var partitionZones []*zone
	for _, z := range zones {
		if z.partition != "" {
			partitionZones = append(partitionZones, z)
		}
	}
	var partitions_hash = make(map[*zone][]string)
	var names = make(map[*zone]string)
	for _, zone_i := range partitionZones {
		var zone1 *zone
		zone1 = findZone1(zone_i)
		partitions_hash[zone1] = append(partitions_hash[zone1], zone_i.partition)
		zone1.partition = zone_i.partition
		names[zone1] = zone1.name
	}

	// Zone1 is found for several partition definitions.
	for zone1, _ := range partitions_hash {
		if len(partitions_hash[zone1]) > 1 {
			partitionsList := strings.Join(partitions_hash[zone1], "\n - ")
			errMsg("Several partition names in partition %s:\n - %s",
				names[zone1], partitionsList)
		}
	}

	// Unconnected partitions without definition are probably
	// accidentally unconnected. Generate an error.
	var onlyInUn []*zone
	for _, unconnectedPartition := range unconnected {
		if _, exists := partitions_hash[unconnectedPartition]; !exists {
			onlyInUn = append(onlyInUn, unconnectedPartition)
		}
	}

	/*
	   for my $ipv6 (1, 0) {
	       my @un = grep { not $_->{ipv6} xor $ipv6 } @unconnected;

	       # Single unconneted partition does not need to be named.
	       @un == 1 and $un[0]->{partition} and
	           warn_msg("Spare partition name for single partition ",
	                    "$un[0]->{name}: $un[0]->{partition}.");
	       @un > 1 or next;
	       @un = grep { not $_->{ipv6} xor $ipv6 } @only_in_un;
	       @un or next;
	       my $ipv = $ipv6 ? 'IPv6' : 'IPv4';
	       err_msg("$ipv topology has unconnected parts:\n",
	               name_list(\@un),
	               "\n Use partition attribute, if intended.");
	   }*/

	//Meike: erstmal schleife auflösen, einmal für den ipv6 fall testen
	//und einmal für den ipv4 Fall:
	//später in eigene Funktion schreiben
	//ipv6
	var un []*zone
	//sammle alle nicht verbundenen partitions mit ipv6 tag
	for _, unconnectedPartition := range unconnected {
		if unconnectedPartition.ipVxObj.isIPv6() == true {
			un = append(un, unconnectedPartition)
		}
	}

	// Single unconneted partition does not need to be named.
	if len(un) == 1 {
		var partitionName = un[0].partition
		if partitionName != "" {
			warnMsg("Spare partition name for single partition %s: %s.",
				un[0].name, partitionName)
		}
	}
	if len(un) > 1 {
		un = nil
		for _, unconnectedPartition := range onlyInUn {
			if unconnectedPartition.ipVxObj.isIPv6() == true {
				un = append(un, unconnectedPartition)
			}
		}
		if len(un) >= 1 {
			errMsg("IPv6 topology has unconnected parts:\n",
				nameList(un),
				"\n Use partition attribute, if intended.")
		}
	}

	//ipv4
	un = nil
	//sammle alle nicht verbundenen partitions ohne ipv6 tag
	for _, unconnectedPartition := range unconnected {
		if unconnectedPartition.ipVxObj.isIPv6() == false {
			un = append(un, unconnectedPartition)
		}
	}

	// Single unconneted partition does not need to be named.
	if len(un) == 1 {
		var partitionName = un[0].partition
		if partitionName != "" {
			warnMsg("Spare partition name for single partition %s: %s.",
				un[0].name, partitionName)
		}
	}
	if len(un) > 1 {
		un = nil
		for _, unconnectedPartition := range onlyInUn {
			if unconnectedPartition.ipVxObj.isIPv6() == false {
				un = append(un, unconnectedPartition)
			}
		}
		if len(un) >= 1 {
			errMsg("IPv4 topology has unconnected parts:\n%s Use partition attribute, if intended.", nameList(un))
		}
	}

}

//##############################################################################
// Purpose : Include node objects and interfaces of nested loops in the
//           containing loop; add loop cluster exits; adjust distances of
//           loop nodes.

func processLoops() { // Meike: statt über router und zonen über pathObj laufen?

	// Check all nodes located inside a cyclic graph.
	var pathRouters []*router //Meike: managed path routers
	for _, pathRouter := range allRouters {
		if pathRouter.managed != "" || pathRouter.semiManaged == true {
			pathRouters = append(pathRouters, pathRouter)
		}
	}

	//Meike: das geht nicht zusammen: einmal zonen, einmal router - 2
	//schleifen draus machen, später inhalt in funktion auslagern.
	//für zonen:
	for _, obj := range zones {
		myLoop := obj.getLoop()
		if myLoop == nil {
			continue
		}

		// Include sub-loop nodes into containing loop with exit closest to zone1
		for true {
			if myLoop.redirect != nil {
				myLoop = myLoop.redirect
			} else {
				break
			}
		}

		obj.setLoop(myLoop)

		// Mark loops with cluster exit, needed for cactus graph loop clusters.
		setLoopCluster(myLoop)

		// Set distance of loop node to value of cluster exit.
		obj.setDistance(myLoop.clusterExit.getDistance()) //  # keeps loop dist
	}

	//für router
	for _, obj := range pathRouters {
		myLoop := obj.getLoop()
		if myLoop == nil {
			continue
		}

		// Include sub-loop nodes into containing loop with exit closest to zone1
		for true {
			if myLoop.redirect != nil {
				myLoop = myLoop.redirect
			} else {
				break
			}
		}

		obj.setLoop(myLoop)

		// Mark loops with cluster exit, needed for cactus graph loop clusters.
		setLoopCluster(myLoop)

		// Set distance of loop node to value of cluster exit.
		obj.setDistance(myLoop.clusterExit.getDistance()) //  # keeps loop dist
	}

	// Include sub-loop IFs into containing loop with exit closest to zone1.
	for _, pathRouter := range pathRouters {
		for _, myIntf := range pathRouter.intfList() {
			if myIntf.loop == nil {
				continue
			}
			myLoop := myIntf.loop

			// Include sub-loop nodes into containing loop with exit
			// closest to zone1
			for true {
				if myLoop.redirect != nil {
					myLoop = myLoop.redirect
				} else {
					break
				}
			}

			myIntf.loop = myLoop
		}
	}
}

//###################################################################
// Check pathrestrictions
//###################################################################

func getIntfLoop(intf *routerIntf) *loop {
	if intf.loop != nil {
		return intf.loop
	}
	if intf.router.getLoop() != nil {
		return intf.router.getLoop()
	}
	if intf.zone.getLoop() != nil {
		return intf.zone.getLoop()
	}
	return nil
}

// Meike: das ist der globale Pathrestriction-Array aus perl
var effectivePathrestrictions []*pathRestriction

// Meike: zum alphabetischen sortieren - wird das überhaupt gebraucht (für die pathrestriction)??

// NameSorter sorts by name.
type NameSorter []*pathRestriction

func (a NameSorter) Len() int           { return len(a) }
func (a NameSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a NameSorter) Less(i, j int) bool { return a[i].name < a[j].name }

// Meike: muss man das 2x machen oder kann man da irgendwie ein Interface bauen??
type zoneNameSorter []*zone

func (a zoneNameSorter) Len() int           { return len(a) }
func (a zoneNameSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a zoneNameSorter) Less(i, j int) bool { return a[i].name < a[j].name }

func deleteIntfFromSlice(slice []*routerIntf, intf *routerIntf) []*routerIntf {
	for index, sliceIntf := range slice {
		if intf == sliceIntf {
			return append(slice[:index], slice[(index+1):]...)
		}
	}
	return slice
}

func deletePathRestrictionFromSlice(
	slice []*pathRestriction, pathRestr *pathRestriction) []*pathRestriction {
	for index, slicePathRestr := range slice {
		if pathRestr == slicePathRestr {
			return append(slice[:index], slice[index+1:]...)
		}
	}
	return slice
}

func areEqualZoneClusters(cluster1 []*zone, cluster2 []*zone) bool {
	if len(cluster1) != len(cluster2) {
		return false
	}
	// Meike: müssen die überhaupt sortiert werden??
	sort.Sort(zoneNameSorter(cluster1))
	sort.Sort(zoneNameSorter(cluster2))
	for index := 0; index < len(cluster1); index++ {
		if cluster1[index] != cluster2[index] {
			return false
		}
	}
	return true
}

//# Substitute an element in an array reference.
//sub aref_subst {
func substituteIntf(slice []*routerIntf, oldIntf *routerIntf,
	newIntf *routerIntf) {
	for i := 0 ; i < len(slice) ; i++ {
		if slice[i] == oldIntf {
			slice[i] = newIntf
		}
	}

}

// Purpose : Collect proper & effective pathrestrictions in a global array.
//           Pathrestrictions have to fulfill following requirements:
//           - Located inside or at the border of cycles.
//           - At least 2 interfaces per pathrestriction.
//           - Have an effect on ACL generation.
func checkPathrestrictions() {

Restrict:

	// Process every pathrestriction.
	// Meike: das ist vom globalen pathrestriction-hash!
	for _, restrict := range pathrestrictions {
		elements := restrict.elements //   # Extract interfaces.
		if len(elements) == 0 {
			continue
		}

		// Collect interfaces to be deleted from pathrestriction.
		var deleted []*routerIntf

		var prevInterface *routerIntf
		var prevCluster pathObj
		for _, intf := range elements {
			loop := getIntfLoop(intf)
/*Meike: das wird gar nicht benutzt??*/
//			loopIntf := intf
// Ende

			// This router is split part of an unmanaged router.
			// It has exactly two non secondary interfaces.
			// Move pathrestriction to other interface, if that one is
			// located at border of loop.
			if intf.splitOther != nil && loop == nil {
				other := intf.splitOther
				if other.zone.getLoop() != nil {
					loop = other.zone.getLoop()
					rlist := intf.pathRestrict
					intf.pathRestrict = nil
					//debug("Move restrict->{name}",
					//" from interface->{name} to other->{name}");
					other.pathRestrict = rlist
					for _, restrict := range other.pathRestrict {
						elements := restrict.elements
						substituteIntf(elements, intf, other)
					}
/* Meike: das wird gar nicht benutzt? */
//					loopIntf = other
//ende
				}
			}

			// Interfaces with pathrestriction need to be located
			// inside or at the border of cyclic graphs.
			if loop == nil {
				warnMsg("Ignoring %s at %s\n because it isn't located inside cyclic graph", restrict.name, intf.name)
				deleted = append(deleted, intf)
				continue
			}

			// Interfaces must belong to same loop cluster.
			cluster := loop.clusterExit
			if prevCluster != nil {
				if cluster != prevCluster {
					warnMsg("Ignoring %s having elements from different loops:\n - %s\n - %s",
						restrict.name, prevInterface.name, intf.name)
					deleted = elements
					break
				}
			} else {
				prevCluster = cluster
				prevInterface = intf
			}
		}

		// Delete invalid elements of pathrestriction.
		if len(deleted) > 0 {

			// Ignore pathrestriction with only one element.
			if len(deleted)+1 == len(elements) {
				deleted = elements
			}

			// Remove deleted elements from pathrestriction and
			// remove pathrestriction from deleted elements.
			// Work with copy of elements, because we change elements in loop.
			/* Meike:
			            // In Perl brauchten wir hier eine Kopie, wenn der Array
			   			// deleted derselbe war wir der elements-Array (selbe
			   			// Speicheradresse.) Hier haben wir slices, ich gehe davon
			   			// aus, dass ich deshalb keine Kopie mehr machen muss...
			   			if deleted == elements {
			   				deleted = elements
			   			}
			*/
			for _, element := range deleted {
				elements = deleteIntfFromSlice(elements, element)
				rlist := element.pathRestrict
				element.pathRestrict = deletePathRestrictionFromSlice(rlist, restrict)
				if len(element.pathRestrict) == 0 { //Meike: kann das weg?
					element.pathRestrict = nil
				}
			}
			if len(elements) == 0 {
				continue
			}
		}

		// Mark pathrestricted interface at border of loop, where loop
		// node is a zone.
		// This needs special handling during path_mark and path_walk.
		for _, intf := range elements {
			if intf.loop == nil && intf.zone.getLoop() != nil {
				intf.loopZoneBorder = true
			}
		}

		// Check for useless pathrestrictions that do not affect any ACLs...
		// Pathrestrictions at managed routers do most probably have an effect.
		for _, intf := range elements {
			if intf.router.managed != "" || intf.router.routingOnly == true {
				continue Restrict
			}
		}

		// Pathrestrictions spanning different zone clusters have an effect.
		/* Meike: Perl - Original. ist übersetzt ellenlang - macht es
		   das richtige? geht es kürzer??

		   equal(map { $_->{zone_cluster} || $_ } map { $_->{zone} } @$elements)
		   		or next;
		*/
		// Meike: Prüfe ob alle interfaces zum selben zone/Zonencluster
		// gehören. Falls ja, ist es wahrscheinlich dass die PR keinen
		// Effekt hat. falls nicht, gehen wir davon aus, dass sie einen
		// effekt hat und machen mit der nächsten weiter.
		var intfZones []*zone
		for _, intf := range elements {
			if intf.zone != nil {
				intfZones = append(intfZones, intf.zone)
			}
		}
		var intfZoneClusters [][]*zone
		for _, intfZone := range intfZones {
			if intfZone.zoneCluster != nil {
				intfZoneClusters = append(intfZoneClusters, intfZone.zoneCluster)
			}
		}

		// Meike: gehören alle interfaces zur selben Zone/demselben
		// Zonencluster? wenn ja, sind Anzahl von intfZone und
		// IntfZoneCluster gleich.
		if len(intfZoneClusters) == 0 {
			referenceZone := intfZones[0]
			for _, zoneElem := range intfZones {
				if zoneElem != referenceZone {
					continue Restrict
				}
			}
		}

		if len(intfZoneClusters) > 0 {
			if len(intfZoneClusters) != len(intfZones) {
				continue Restrict
			} else {
				referenceZoneCluster := intfZoneClusters[0]
				for _, zoneClusterElem := range intfZoneClusters {
					for j, zoneElem := range zoneClusterElem {
						if referenceZoneCluster[j] != zoneElem {
							continue Restrict
						}
					}
				}
			}
		}
		// Pathrestrictions in loops with > 1 zone cluster have an effect.
		intf := elements[0]
		intfLoop := getIntfLoop(intf)
		intfZone := intf.zone
		zoneCluster := intfZone.zoneCluster
		if len(zoneCluster) == 0 {
			zoneCluster = append(zoneCluster, intfZone)
		}

		// Process every zone in zone cluster...
		for _, zone1 := range zoneCluster {
			for _, intf1 := range zone1.interfaces {
				r := intf1.router

				// ...examine its neighbour zones:
				for _, intf2 := range r.interfaces {
					zone2 := intf2.zone
					if zone2 == intfZone {
						continue
					}
					if zone2.zoneCluster != nil {
						cluster2 := zone2.zoneCluster

						if areEqualZoneClusters(zoneCluster, cluster2) {
							continue
						}
					}
					if zone2.getLoop() != nil {
						loop2 := zone2.getLoop()
						if intfLoop == loop2 {
							// Found other zone cluster in same loop.
							continue Restrict
						}
					}
				}
			}
		}

		warnMsg("Useless %s.\n All interfaces are unmanaged and located inside the same security zone", restrict.name)

		// Clear interfaces of useless pathrestriction.
		restrict.elements = nil
	}

	// Collect all effective pathrestrictions.
	for _, restrict := range pathrestrictions {
		if restrict.elements != nil {
			effectivePathrestrictions = append(effectivePathrestrictions, restrict)
		}
	}
	sort.Sort(NameSorter(effectivePathrestrictions))
}

//###################################################################
// Virtual interfaces
//###################################################################
// Purpose : Assure interfaces with identical virtual IP are located inside
//           the same loop.
func checkVirtualInterfaces() {

	var seen = make(map[string]bool) //Meike: das ist wichtig, nachziehen!
	for _, intf := range virtualInterfaces {
		if intf.redundancyIntfs == nil {
			continue
		}
		relatedVirtualIntfs := intf.redundancyIntfs

		// Loops inside a security zone are not known and can not be checked
		if intf.router.managed == "" &&  !intf.router.semiManaged {
			continue
		}

		// Ignore single virtual interface.
		if len(relatedVirtualIntfs) <= 1 {
			continue
		}

/*
	// Meike: wie funktioniert dieser LookUp in go?? -> Interfaces als gesehen markieren: redundancyintfs haben alle dieselbe Adresse, können also nicht in mehreren redundancyIntf-gruppen sein.
		if seen[relatedVirtualIntfs.] == true {
			continue
		}
*/
		if seen[intf.netObj.ipObj.ip.String()] == true {
			continue
		} else {
			seen[intf.netObj.ipObj.ip.String()] = true
		}

		// Check whether all virtual interfaces are part of a loop.
		var err bool
		for _, virtIntf := range relatedVirtualIntfs {
			if virtIntf.router.getLoop() == nil {
				errMsg("%s must be located inside cyclic sub-graph", virtIntf.name)
				err = true
			}
		}

		if err {

			// Remove invalid pathrestriction to prevent inherited errors.
			for _, virtIntf := range relatedVirtualIntfs {
				virtIntf.pathRestrict = nil
			}
			continue
		}

		// Check whether all virtual interfaces are part of the same loop.
		var referenceLoop *loop
		referenceLoop = relatedVirtualIntfs[0].loop// Meike: ist das die richtige GetLoop() funktion??
		for _, virtIntf := range relatedVirtualIntfs {
			if referenceLoop != virtIntf.loop {
				var virtIntfNames []string
				for _, virtIntf := range relatedVirtualIntfs {
					virtIntfNames = append(virtIntfNames, virtIntf.name)
				}
				namesList := strings.Join(virtIntfNames, ", ")
				errMsg(
					"Virtual interfaces\n %s\n must all be part of the same cyclic sub-graph",namesList)
				break
			}
		}
	}
}

func deletePathrestrictionFromInterfaces (restrict *pathRestriction) {
    elements := restrict.elements
    for _, intf := range elements {
		 intf.pathRestrict = deletePathRestrictionFromSlice(
			 intf.pathRestrict, restrict)

//Meike: das kann man glaube ich weglassen, oder?
		 // Delete empty array to speed up checks in cluster_path_mark.
		 if len(intf.pathRestrict) == 0 {
			 intf.pathRestrict = nil
		 }
    }
}

func removeRedundantPathrestrictions() {

	// Calculate number of elements once for each pathrestriction.
	var size  = make(map[*pathRestriction]int)

	// For each element E, find pathrestrictions that contain E.
//	var element2restrictions [*routerIntf] *pathRestrict // Meike: umbenannt
	intf2restrictions := make(map[*routerIntf]map[*pathRestriction]*pathRestriction)
	for _, restrict := range effectivePathrestrictions {
		restrictedIntfs := restrict.elements
		size[restrict] = len(restrictedIntfs)// Meike: der kann eig. raus.
		for _, element := range restrictedIntfs {
			if intf2restrictions[element] == nil {
				intf2restrictions[element] = make(
					map[*pathRestriction]*pathRestriction)
			}
			intf2restrictions[element][restrict] = restrict
		}
	}

	for _, restrict := range effectivePathrestrictions {
		restrictedIntfs := restrict.elements
		restrictSize := len(restrictedIntfs)
		var intf1 *routerIntf
		var href map[*pathRestriction]*pathRestriction
		if restrictSize > 0 {
			intf1 = restrictedIntfs[0]
			//Meike: restrictions, die auch Intf1 enthalten
			href = intf2restrictions[intf1]
		}

		//Meike: Finde andere PRs, die auch IF1 enthalten und ebensoviele oder
		// mehr Interfaces haben wie restrict. Diese könnten mit
		// restrict redundant sein (d.h. gleich sein wie restrict, oder
		// restrict ist in einer otherRestrict enthalten.)
		var list []*pathRestriction
		for _, otherRestrict := range href {
			if len(otherRestrict.elements) >= restrictSize {
				list = append(list, otherRestrict)
			}
		}
		if len(list) < 2 { // Meike: compare with itself only
			continue
		}

			// Larger pathrestrictions, that reference elements of
			// restrict.  Meike: Wenn es solche anderen Pathrestrictions
			// gibt, prüfe für jedes weitere Interface von restrict, ob
			// es in diesen Pathrestrictions enthalten ist. wenn ja, sind
			// diese Pathrestrictions, die beide enthalten,
			// möglicherweise redundant mit restrict und wird in nextSuperset aufgehoben, um
		superset := list

		// Check all elements = Interfaces of current pathrestriction.
		for _, element := range restrictedIntfs {
			if element == intf1 {
				continue
			}

			// href2 is set of all pathrestrictions that contain element.
			// meike: href= pathrestrictions mit interface element
			href2 := intf2restrictions[element]

			// Build superset for next iteration.
			var nextSuperset []*pathRestriction
			// Meike: für jede PR im superset (= restrict2): ist in
			// der Restriction das IF element enthalten? wenn ja, ab
			// ins nextSuperset!
			for _, restrict2 := range superset {

				if restrict2 == restrict {
					continue
				}
				if restrict2.deleted != nil {
					continue
				}
				if href2[restrict2] != nil {
					nextSuperset = append(nextSuperset, restrict2)
				}
			}

			// Pathrestriction isn't redundant if superset becomes
			// empty. //Meike: d.h. kein gemeinsames superset!
			superset = nextSuperset
			if len(superset) == 0 {
				break
			}
		}

		// superset holds those pathrestrictions, that have
		// superset of elements of restrict.
		if len(superset) == 0 {
			continue
		}
		restrict.deleted = superset
		deletePathrestrictionFromInterfaces(restrict)
	}

	if diag.Active() {
		for _, restrict := range effectivePathrestrictions {
			if restrict.deleted == nil {
				continue
			}
			superset := restrict.deleted
			rName := restrict.name
			oName := make([]string, 0, len(superset))
			for _, supersetRestrict := range superset {
				oName = append(oName, supersetRestrict.name)
			}
			sort.Strings(oName)
			names := strings.Join(oName, ", ")
			msg := "Removed " + rName + "; is subset of " + names
			diag.Msg(msg)
		}
	}

	for _, restrict := range effectivePathrestrictions {
		if restrict.deleted != nil {
			effectivePathrestrictions = deletePathRestrictionFromSlice(
				effectivePathrestrictions, restrict) // Meike: funktioniert das???
		}
	}
}

//##############################################################################
// Purpose : Add navigation information to the nodes of the graph to
//           enable fast traversal; identify loops and perform further
//           consistency checks.
func SetPath() {
	diag.Progress("Preparing fast path traversal")
	findDistsAndLoops()      //        # Add navigation info.
	processLoops()           //          # Refine navigation info at loop nodes.
	checkPathrestrictions()  //       # Consistency checks, need {loop} attribute.
	checkVirtualInterfaces() //    # Consistency check, needs {loop} attribute.
	removeRedundantPathrestrictions()
	//    optimize_pathrestrictions();    # Add navigation info to pathrestricted IFs.
}
