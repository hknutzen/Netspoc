package pass1

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// getPathNode provides path node objects for objects specified as src or dst.
// Parameter: Source or destination object.
// Returns:
// Zone or router of the given object or the object itself,
// if it is a pathrestricted interface.
func (obj *network) getPathNode() pathStore {
	return obj.zone
}
func (obj *subnet) getPathNode() pathStore {
	return obj.network.zone
}
func (obj *routerIntf) getPathNode() pathStore {
	r := obj.router
	if r.managed != "" || r.semiManaged {

		// If this is a secondary interface, use the main interface instead.
		if main := obj.mainIntf; main != nil {
			obj = main
		}

		// Special handling needed if object is interface with pathrestriction.
		if obj.pathRestrict != nil {
			return obj
		} else {
			return obj.router
		}
	} else {

		// Unmanaged routers are part of zone objects.
		return obj.network.zone
	}
}

// This is used, if called from findAutoInterfaces.
func (obj *router) getPathNode() pathStore {
	if obj.managed != "" || obj.semiManaged {
		return obj
	} else {
		return obj.interfaces[0].network.zone
	}
}

// This is used in cut-netspoc and if pathWalk is called early to
// expand auto interfaces.
func (obj *host) getPathNode() pathStore {
	return obj.network.zone
}

// This is used, if called from expandAutoIntfWithDstList.
func (obj *autoIntf) getPathNode() pathStore {
	return obj.object.getPathNode()
}

type navigation map[*loop]map[*loop]bool

type intfPair [2]*routerIntf
type intfPairs []intfPair
type loopPath struct {
	enter        intfList
	leave        intfList
	routerTuples intfPairs
	zoneTuples   intfPairs
}

type loopConn struct {
	entry pathStore
	exit  pathStore
}

// Add element to slice.
func (a *intfPairs) push(e intfPair) {
	*a = append(*a, e)
}

// delDupl replaces multiple equal elements with a single copy.
// delDupl modifies the contents of the slice s; it does not create a new slice.
func delDupl[S ~[]E, E comparable](s *S) {
	seen := make(map[E]bool)
	j := 0
	for _, e := range *s {
		if !seen[e] {
			seen[e] = true
			(*s)[j] = e
			j++
		}
	}
	*s = (*s)[:j]
}

func calcNext(from pathObj) func(intf *routerIntf) pathObj {
	switch from.(type) {
	case *router:
		return func(intf *routerIntf) pathObj { return intf.zone }
	default:
		return func(intf *routerIntf) pathObj { return intf.router }
	}
}

// getPathObj extracts the pathObj from a pathStore.
func getPathObj(store pathStore) pathObj {
	var result pathObj
	switch x := store.(type) {
	case *routerIntf:
		result = x.router
	case *router:
		result = x
	case *zone:
		result = x
	}
	return result
}

// clusterPathMark1 recursively finds
// path through a loop or loop cluster
// for a	given pair (start, end) of loop nodes and collects path information.
//
// Parameters :
//   - obj: current (or start) loop node (zone or router).
//   - inIntf: interface current loop node was entered from.
//   - end: loop node that is to be reached.
//   - lPath: collect tuples and enter+leave interfaces of path.
//   - navi: lookup hash to reduce search space, holds loops to enter.
//   - blockingCount: map to record blocking pathrestrictions and their counts.
//
// Returns : true, if path is found.
func clusterPathMark1(
	obj pathObj, inIntf *routerIntf, end pathObj,
	startInLoop, endInLoop *routerIntf,
	lPath *loopPath, navi navigation,
	blockingCount map[*pathRestriction]int,
) bool {

	isBlocked := func(intf *routerIntf) bool {
		for _, restrict := range intf.pathRestrict {
			if restrict.activePath {
				// Count blocking pathrestriction only once per path attempt.
				// Since pathfinding is bidirectional, we encounter each
				// restriction from both sides. To avoid double-counting,
				// only count when inIntf is in the restriction. We check if
				// inIntf is one of the restriction's elements to ensure
				// we're at the right location.
				for _, intf := range restrict.elements {
					if intf == inIntf {
						// Count only from one side: count from the
						// lexicographically larger router (this is the "second
						// encounter" side where activePath is set)
						shouldCount := true
						for _, other := range restrict.elements {
							if other != inIntf && other.router.name > inIntf.router.name {
								shouldCount = false
								break
							}
						}
						if shouldCount {
							blockingCount[restrict]++
						}
						break
					}
				}
				return true
			}
		}
		return false
	}
	if endInLoop != nil {
		// If path ends at interface inside loop then check earlier if this
		// interface has been reached.
		if inIntf == endInLoop {
			// Pathrestriction is ignored if path ends at current
			// interface and is about to leave zone.
			if obj.isRouter() {
				// Store interface where we leave the loop.
				lPath.leave.push(inIntf)
				return true
			}
		} else if slices.Contains(endInLoop.redundancyIntfs, inIntf) {
			// Prohibit paths traversing related redundancy interfaces.
			return false
		}
	}
	if startInLoop != nil && inIntf != startInLoop {
		if slices.Contains(startInLoop.redundancyIntfs, inIntf) {
			// Prohibit paths traversing related redundancy interfaces.
			return false
		}
		if inIntf.router == startInLoop.router {
			// Pathrestriction at startInLoop must be checked or activated if
			// start router is left at other interface than startInLoop.
			if isBlocked(startInLoop) {
				return false
			}
			defer handlePathrestriction(startInLoop)()
		}
	}

	if inIntf == startInLoop && !obj.isRouter() {
		// Pathrestriction is ignored if path starts at current
		// interface and is about to enter zone.
	} else {
		// Stop path exploration when activated PR (2nd occurrence) is reached.
		if isBlocked(inIntf) {
			return false
		}
	}

	// Node has been visited before - avoid walking loops.
	if obj.isActivePath() {
		return false
	}

	// Mark current path for loop detection.
	obj.setActivePath()
	defer obj.clearActivePath()

	// Activate passed pathrestriction.
	// But ignore pathrestriction if path starts at current interface and
	// is about to enter zone.
	if inIntf.pathRestrict != nil && (inIntf != startInLoop || obj.isRouter()) {
		defer handlePathrestriction(inIntf)()
	}
	if endInLoop != nil {
		if inIntf.router == endInLoop.router && isBlocked(endInLoop) {
			// endInLoop is reached from same router but pathrestriction
			// will be crossed.
			return false
		}
	}

	// Found path to router or zone.
	if obj == end {
		// Store interface where we leave the loop.
		lPath.leave.push(inIntf)
		return true
	}

	var typeTuples *intfPairs
	switch obj.(type) {
	case *router:
		typeTuples = &lPath.routerTuples
	default:
		typeTuples = &lPath.zoneTuples
	}
	success := false

	// Extract navigation lookup map.
	allowed := navi[obj.getLoop()]

	// Proceed loop path exploration with every loop interface of current node.
	getNext := calcNext(obj)
	for _, intf := range obj.intfList() {
		loop := intf.loop
		if loop == nil {
			continue
		}
		if !allowed[loop] {
			continue
		}
		if intf == inIntf {
			continue
		}
		next := getNext(intf)

		//debug("Try %s -> %s", obj, next)

		// If a valid path is found from next node to end...
		if clusterPathMark1(
			next, intf, end, startInLoop, endInLoop, lPath, navi, blockingCount,
		) {
			// ...collect path information.
			typeTuples.push(intfPair{inIntf, intf})
			success = true
		}
	}

	return success
}

// clusterNavigation optimizes navigation inside a cluster of loops.
// For a pair (from,to) of loop nodes,
// identify order of loops passed on the path from from to to.
// Store information as lookup map at node 'from'
// to reduce search space when finding paths	from 'from' to 'to'.
//
// Parameters : from, to - loop nodes pair.
// Returns:
// Map with order/navigation information.
//   - keys: loops,
//   - values: loops that may be entered next from key loop.
//
// Results:
// 'from' node holds navigation map
// suggesting for every loop of the cluster those loops,
// that are allowed to be entered when	traversing the path to 'to'.
func clusterNavigation(from, to pathObj) navigation {
	// debug("Navi: from->{name}, to->{name}");

	navi := from.getNavi()[to]
	// Return filled navi map, if pair (from, to) has been processed before.
	if navi != nil {
		//	debug(" Cached");
		return navi
	}

	// Attach navi map to from node object.
	navi = make(navigation)
	from.setNavi(to, navi)

	add := func(l1, l2 *loop) {
		m := navi[l1]
		if m == nil {
			m = make(map[*loop]bool)
			navi[l1] = m
		}
		m[l2] = true
	}

	// Determine loops that are passed on path from from to to.
	fromLoop := from.getLoop()
	toLoop := to.getLoop()
	for {

		// Loops are equal, order of loops has been detected.
		if fromLoop == toLoop {
			// Same node, no loop path to detect.
			if from == to {
				break
			}

			// Add loops that may be entered from loop during path traversal.
			add(fromLoop, fromLoop)
			//	    debug("- Eq: from_loop->{exit}->{name}from_loop to itself");

			// Path from -> to traverses fromLoop and exitLoop.
			// Inside exitLoop, enter only fromLoop, but not from other loops
			exitLoop := fromLoop.exit.getLoop()
			add(exitLoop, fromLoop)

			//	    debug("- Add from_loop->{exit}->{name}from_loop to exit exit_loop->{exit}->{name}exit_loop");
			break
		} else if fromLoop.distance >= toLoop.distance {
			// Different loops, take next step from loop with higher distance.
			add(fromLoop, fromLoop)

			//	    debug("- Fr: from_loop->{exit}->{name}from_loop to itself");
			from = fromLoop.exit
			fromLoop = from.getLoop()
		} else {
			// Take step from toLoop.
			//debug("- To: to_loop->{exit}->{name}to_loop to itself");
			add(toLoop, toLoop)
			to = toLoop.exit
			entryLoop := to.getLoop()
			add(entryLoop, toLoop)

			//	    debug("- Add to_loop->{exit}->{name}to_loop to entry entry_loop->{exit}->{name}entry_loop");
			toLoop = entryLoop
		}
	}
	return navi
}

// #############################################################################
// clusterPathMark collects path information through a loop
// for a pair of loop nodes (zone or router) and
// stores it at the object where loop paths begins.
//
// Parameters :
//   - from: source loop node.
//   - to: destination loop node.
//   - startInLoop: Interface where path starts in loop or nil.
//   - endInLoop: Interface where path ends in loop or nil.
//   - blockingCount: map to record blocking pathrestrictions and their counts.
//
// Returns: loopPath if a valid path was found, nil otherwise.
func clusterPathMark(
	from, to pathObj,
	startInLoop, endInLoop *routerIntf,
	blockingCount map[*pathRestriction]int,
) *loopPath {

	// Find loop paths via depth first search.
	success := false

	// Create navigation look up map to reduce search space in loop cluster.
	navi := clusterNavigation(from, to)
	allowed := navi[from.getLoop()]

	// This describes valid paths inside loop.
	lPath := new(loopPath)

	// Mark current path for loop detection.
	from.setActivePath()
	defer from.clearActivePath()

	// To find paths, process every loop interface of from node.
	getNext := calcNext(from)
	for _, intf := range from.intfList() {
		loop := intf.loop
		if loop == nil {
			continue
		}

		// Skip interface that will not lead to a path,
		// because node is not included in navi.
		if !allowed[loop] {
			continue
		}

		// Extract adjacent node (= next node on path).
		next := getNext(intf)

		// Track which pathrestrictions block this specific interface choice
		localBlocking := make(map[*pathRestriction]int)

		// Search path from next node to to, store it in lPath.
		if clusterPathMark1(
			next, intf, to, startInLoop, endInLoop,
			lPath, navi, localBlocking,
		) {
			success = true
			lPath.enter.push(intf)
		} else {
			// This interface choice failed - add the accumulated counts.
			for pr, count := range localBlocking {
				blockingCount[pr] += count
			}
		}
	}

	// Only store complete result.
	if success {
		delDupl(&lPath.routerTuples)
		delDupl(&lPath.zoneTuples)

		// Remove duplicates, which occur from nested loops.
		delDupl(&lPath.leave)

		return lPath
	}
	return nil
}

func connectClusterPath(
	from, to pathObj,
	fromIn, toOut *routerIntf,
	startStore, endStore pathStore,
	blockingCount map[*pathRestriction]int,
) bool {

	// 1. Find object to store path information inside loop.
	//    Path may differ depending on whether loop entering and exiting
	//    interfaces are pathrestricted or not. Storing path information
	//    in different objects respects this.
	// 2. Find interface at border / entry / exit of loop
	//    where pathrestriction must be activated.
	// 3. Find interface with pathrestriction
	//    where path starts / ends inside loop.
	// 4. Set flag if path starts at zone at border of loop.
	setup := func(s pathStore, obj pathObj, ioIntf *routerIntf,
	) (pathStore, *routerIntf, *routerIntf, bool) {
		var store pathStore
		var restricted, inLoop *routerIntf
		atZone := false
		if intf, ok := s.(*routerIntf); ok && (ioIntf == nil || ioIntf == intf) {
			// Path starts/ends at pathrestricted interface.
			if intf.loop == nil {
				// Path starts/ends at border of current loop.
				switch x := obj.(type) {
				case *router:
					restricted = intf
					store = intf
				case *zone:
					// Ignore pathrestriction when entering a loop at zone and
					// path starts at interface at border of this zone,
					// because IP address of interface belongs to IP adress of
					// entered network and hence must no be restricted.
					store = x
					atZone = true
				}
			} else {
				// Path starts/ends inside current loop.
				inLoop = intf
				store = intf
			}
		} else if ioIntf != nil && ioIntf.pathRestrict != nil {
			// Loop is entered/exited at pathrestricted interface.
			store = ioIntf
			restricted = ioIntf
		} else {
			// Loop starts/ends or is entered/exited at obj; no
			// pathrestriction is effective.
			switch x := obj.(type) {
			case *router:
				store = x
			case *zone:
				store = x
			}
		}
		return store, restricted, inLoop, atZone
	}
	fromStore, fromRestricted, startIntf, startAtZone :=
		setup(startStore, from, fromIn)
	toStore, toRestricted, endIntf, _ :=
		setup(endStore, to, toOut)

	// Check, if loop path from fromStore to toStore has been marked already.
	if fromStore.getLoopPath()[toStore] == nil {

		// Activate pathrestrictions now and deactivate later.
		if fromRestricted != nil {
			defer handlePathrestriction(fromRestricted)()
		}
		if toRestricted != nil {
			defer handlePathrestriction(toRestricted)()
		}

		lPath := clusterPathMark(from, to, startIntf, endIntf, blockingCount)
		if lPath == nil {
			return false
		}
		fromStore.setLoopPath(toStore, lPath)
	}
	// If loop path was found, connect it with linear path.
	var store pathStore
	if fromIn != nil {
		store = fromIn
		store.setPath(endStore, toOut)
	} else {
		store = startStore
		store.setPath1(endStore, toOut)
	}
	// Collect path information at beginning of loop path (fromStore).
	// Loop paths beginning at loop node can differ depending on the way
	// the node is entered (interface with/without pathrestriction,
	// pathrestricted src/dst interface), requiring storing path
	// information at different objects and at different attributes.
	if startAtZone {
		x := store.(*routerIntf)
		x.setLoopConnZone(endStore, fromStore, toStore)
	} else {
		store.setLoopConn(endStore, fromStore, toStore)
	}
	return true
}

func handlePathrestriction(intf *routerIntf) func() {
	for _, restrict := range intf.pathRestrict {
		restrict.activePath = true
	}
	return func() {
		for _, restrict := range intf.pathRestrict {
			restrict.activePath = false
		}
	}
}

// Remove partially marked path.
func removePath(fromStore, toStore pathStore) {
	pathMap := fromStore.getPath1()
	out := pathMap[toStore]
	delete(pathMap, toStore)
	for out != nil {
		pathMap = out.getPath()
		out = pathMap[toStore]
		delete(pathMap, toStore)
	}
}

// pathMark finds and marks path from source to destination.
// Parameter:
//   - fromStore: Object, where path starts.
//   - toStore: Objects, where path ends.
//     Typically both are of type zone or router.
//     For details see description of func pathWalk.
//
// Returns:
//   - bool: True if valid path is found, False otherwise.
//   - map: Pathrestrictions that blocked the path (if any).
//
// Results: The next interface towards toStore is stored in attribute
//   - .path1 of fromStore and
//   - .path of subsequent interfaces on path.
func pathMark(fromStore, toStore pathStore) (bool, map[*pathRestriction]int) {

	// debug("pathMark %s --> %s", fromStore, toStore)
	from := getPathObj(fromStore)
	to := getPathObj(toStore)

	// Count how many path attempts each pathrestriction blocks
	blockingCount := make(map[*pathRestriction]int)

	// debug("pathMark %s --> %s", fromStore, toStore)
	fromLoop := from.getLoop()
	toLoop := to.getLoop()

	// No subsequent interface before first and behind last node on path.
	var fromIn, toOut *routerIntf

	// Follow paths from source and destination towards zone1 until they meet.
PATH:
	for {

		// debug("Dist: %d %s -> Dist: %d %s", from.getDistance(), from, to.getDistance(), to)

		// Paths meet outside a loop or at the edge of a loop.
		if from == to {

			// We need to distinguish between .path1 and .path for
			// the case, where fromStore is a pathrestricted
			// interface I of zone at border of loop. In this case, the
			// next interface is interface I again.
			if fromIn != nil {
				fromIn.setPath(toStore, toOut)
			} else {
				fromStore.setPath1(toStore, toOut)
			}
			return true, blockingCount
		}

		// Paths meet inside a loop.
		if fromLoop != nil && toLoop != nil &&
			fromLoop.clusterExit == toLoop.clusterExit {
			if connectClusterPath(from, to, fromIn, toOut, fromStore, toStore, blockingCount) {
				return true, blockingCount
			}
			break PATH
		}

		// Otherwise, take a step towards zone1 from the more distant node.
		if from.getDistance() >= to.getDistance() { // Take step from node from.

			// Return, if mark has already been set for a sub-path.
			if fromIn != nil && fromIn.getPath()[toStore] != nil {
				return true, blockingCount
			}

			// Get interface towards zone1.
			fromOut := from.getToZone1()

			// If from is a loop node, mark whole loop path within this step.
			if fromOut == nil {

				// Reached border of graph partition.
				if fromLoop == nil {
					break PATH
				}

				// Get next interface behind loop from loop cluster exit.
				exit := fromLoop.clusterExit
				fromOut = exit.getToZone1()

				// Reached border of graph partition.
				if fromOut == nil {
					break PATH
				}

				// Mark loop path towards next interface.
				if !connectClusterPath(
					from, exit, fromIn, fromOut, fromStore, toStore, blockingCount) {

					break PATH
				}
			}

			// Mark path at the interface we came from (step in path direction)
			//debug("pAth: %s %s -> %s", fromIn, fromStore, fromOut)
			if fromIn != nil {
				fromIn.setPath(toStore, fromOut)
			} else {
				fromStore.setPath1(toStore, fromOut)
			}
			from = fromOut.toZone1
			fromLoop = from.getLoop()

			// Go to next node towards zone1.
			fromIn = fromOut
		} else {
			// Take step towards zone1 from node to (backwards on path).

			// Get interface towards zone1.
			toIn := to.getToZone1()

			// If to is a loop node, mark whole loop path within this step.
			if toIn == nil {

				// Reached border of graph partition, linear part.
				if toLoop == nil {
					break PATH
				}

				// Get next interface behind loop from loop cluster exit.
				entry := toLoop.clusterExit
				toIn = entry.getToZone1()

				// Reached border of graph partition behind loop.
				if toIn == nil {
					break PATH
				}

				// Mark loop path towards next interface.
				if !connectClusterPath(entry, to, toIn, toOut, fromStore, toStore, blockingCount) {
					break PATH
				}
			}

			// Mark path at interface we go to (step in opposite path direction).

			//debug("path: %s -> %s %s", toIn, toStore, toOut)
			toIn.setPath(toStore, toOut)
			to = toIn.toZone1
			toLoop = to.getLoop()

			// Go to next node towards zone1.
			toOut = toIn
		}
	}
	// Remove partially marked path.
	removePath(fromStore, toStore)
	return false, blockingCount
}

// #############################################################################
// loopPathWalk walks loop section of a path
// from a rules source to its	destination.
// Apply given function to every zone or router	on loop path.
//
// Parameters :
//   - in - interface the loop is entered at.
//   - out - interface loop is left at.
//   - lc - contains entry and exit objects of loop.
//   - callAtZone - flag for node function is to be called at
//     (true - zone. false - router)
//   - rule - rule providing source and destination.
//   - fun - Function to be applied.
func loopPathWalk(
	in, out *routerIntf,
	lc loopConn,
	callAtZone bool,
	rule *groupedRule,
	fun func(r *groupedRule, i, o *routerIntf),
) bool {

	lPath := lc.entry.getLoopPath()[lc.exit]

	// Process entry of cyclic graph.
	isRouter := false
	switch x := lc.entry.(type) {
	case *router:
		isRouter = true
	case *routerIntf:
		// Take only interface which originally was a router.
		if x.router == lPath.enter[0].router {
			isRouter = true
		}
	}
	if isRouter != callAtZone {
		for _, outIntf := range lPath.enter {
			fun(rule, in, outIntf)
		}
	}

	// Process paths inside cyclic graph.
	var pathTuples intfPairs
	if callAtZone {
		pathTuples = lPath.zoneTuples
	} else {
		pathTuples = lPath.routerTuples
	}

	for _, tuple := range pathTuples {
		fun(rule, tuple[0], tuple[1])
	}

	// Process paths at exit of cyclic graph.
	isRouter = false
	switch x := lc.exit.(type) {
	case *router:
		isRouter = true
	case *routerIntf:
		if x.router == lPath.leave[0].router {
			isRouter = true
		}
	}
	callIt := isRouter != callAtZone
	if callIt {
		for _, inIntf := range lPath.leave {
			fun(rule, inIntf, out)
		}
	}
	return callIt
}

func (c *spoc) showErrNoValidPath(srcPath, dstPath pathStore, context string, blockingCount map[*pathRestriction]int) {
	tag1 := findPartitionTag(srcPath)
	tag2 := findPartitionTag(dstPath)

	var msg string
	var prMsg string
	if tag1 != tag2 {
		// Different partitions
		msg = fmt.Sprintf(" Source and destination objects are located in "+
			"different topology partitions: %s, %s.", tag1, tag2)
	} else {
		// Same partition - check if pathrestrictions are blocking
		msg = ""
		if len(blockingCount) > 0 {
			// Sort pathrestrictions by number of blocked path attempts (ascending).
			// Restrictions blocking fewer paths appear first, as they typically represent
			// earlier bottlenecks in the topology and are closer to the source.
			type prInfo struct {
				pr        *pathRestriction
				pathCount int
				name      string
			}
			sorted := make([]prInfo, 0, len(blockingCount))

			for pr, count := range blockingCount {
				sorted = append(sorted, prInfo{
					pr:        pr,
					pathCount: count,
					name:      pr.name,
				})
			}

			// Sort: primary by path count (ascending), secondary by name (alphabetical)
			slices.SortFunc(sorted, func(a, b prInfo) int {
				if a.pathCount != b.pathCount {
					return a.pathCount - b.pathCount
				}
				return cmp.Compare(a.name, b.name)
			})

			prMsg = " Possible blocking pathrestrictions:\n"
			for _, item := range sorted {
				// Use correct singular/plural form
				attempts := "attempts"
				if item.pathCount == 1 {
					attempts = "attempt"
				}
				prMsg += fmt.Sprintf("  - %s (blocked %d path %s)\n", item.name, item.pathCount, attempts)
			}
		}
		msg += " Check path restrictions and crypto interfaces."
	}

	// Always print blocking pathrestrictions at the end if present
	if prMsg != "" {
		msg += "\n" + strings.TrimSuffix(prMsg, "\n")
	}

	c.err("No valid path\n from %s\n to %s\n %s\n%s",
		srcPath.vxName(), dstPath.vxName(), context, msg)
}

// pathWalk visits every node
// on path from rules source to its destination for a given rule.
// At every second node (every router or every zone node) call given function.
//
// Parameters:
//   - rule: rule object.
//   - fun: function to be called.
//   - where: "Router" or "Zone", specifies where the function gets
//     called, default is "Router".
func (c *spoc) pathWalk(
	rule *groupedRule,
	fun func(r *groupedRule, i, o *routerIntf),
	where string,
) {
	atZone := where == "Zone"

	// Extract path store objects (zone/router/pathrestricted interface).
	// These are typically zone or router objects:
	// - zone object for network or host,
	// - router object for interface without pathrestriction.
	// But for interface with pathrestriction, we may get different
	// paths for interfaces of the same router.
	// Hence we can't use the router but use interface object for
	// interface with pathrestriction.
	fromStore, toStore := rule.srcPath, rule.dstPath
	/*
		debug(rule.print())
		debug(" start: %s, %s at %s", fromStore, toStore, where)
		fun2 := fun
		fun = func(rule *groupedRule, i, o *routerIntf) {
			debug(" Walk: %s, %s", i, o)
			fun2(rule, i, o)
		}
	*/
	// Identify path from source to destination if not known.
	if _, found := fromStore.getPath1()[toStore]; !found {
		// Attempt to find a path
		found, blockingCount := pathMark(fromStore, toStore)
		if !found {
			// Path finding failed.
			// No need to show error message when finding static routes,
			// because this will be shown again when distributing rules.
			if !atZone {
				c.showErrNoValidPath(fromStore, toStore, "for rule "+rule.print(), blockingCount)
			}
			// Abort, if path does not exist.
			return
		}
	}

	// If path store is a pathrestricted interface, handle like router.
	isRouter := false
	switch fromStore.(type) {
	case *routerIntf, *router:
		isRouter = true
	}

	// Set flag whether to call function at first node visited (in 1.iteration)
	callIt := isRouter != atZone

	var in *routerIntf
	out := fromStore.getPath1()[toStore]

	// Check, if path starts inside or at border of cyclic graph.
	var lc loopConn

	// Special case: Path starts at pathrestricted interface of
	// zone at border of loop and hence this pathrestriction will
	// not be activated. Use attribute loopEntryZone, to find correct
	// path in loop.
	if x, ok := fromStore.(*routerIntf); ok {
		lc = x.loopConnZone[toStore]
		if lc.entry != nil {
			in = x
			out = x.path[toStore]
		}
	}
	if lc.entry == nil {
		// Otherwise use attribute loopEntry, to find possibly
		// pathrestricted path in loop.
		lc = fromStore.getLoopConn()[toStore]
	}

	// Walk loop at beginning of path.
	if lc.entry != nil {
		callIt = loopPathWalk(in, out, lc, atZone, rule, fun)

		// Finish, if end of path has been reached.
		if out == nil {
			return
		}
		in = out

		// Prepare to traverse path behind loop.
		out = in.path[toStore]
		callIt = !callIt
	}

	// Start walking path.
	for {

		// Path continues with loop: walk whole loop path in this iteration step.
		var lc loopConn
		if in != nil {
			lc = in.loopConn[toStore]
		}
		if lc.entry != nil {
			callIt = // Was function called on last node of loop?
				loopPathWalk(in, out, lc, atZone, rule, fun)
		} else if callIt {
			// Non-loop path continues - call function, if switch is set.
			fun(rule, in, out)
		}

		// Finish, if end of path has been reached.
		if out == nil {
			return
		}
		in = out

		// Prepare next iteration otherwise.
		out = in.getPath()[toStore]
		callIt = !callIt
	}
}

func (c *spoc) singlePathWalk(
	src, dst someObj, f func(r *groupedRule, i, o *routerIntf), where string) {

	rule := &groupedRule{
		serviceRule: &serviceRule{
			prt: []*proto{c.prt.IP},
		},
		src:     []someObj{src},
		dst:     []someObj{dst},
		srcPath: src.getPathNode(),
		dstPath: dst.getPathNode(),
	}
	c.pathWalk(rule, f, where)
}

func (c *spoc) setAutoIntfFromBorder(border *routerIntf) {
	var reachFromBorder func(*network, *routerIntf, map[netOrRouter]intfList)
	reachFromBorder =
		func(n *network, in *routerIntf, result map[netOrRouter]intfList) {
			result[n] = append(result[n], in)

			//debug("%s: %s", n, in)
			for _, intf := range n.interfaces {
				if m := intf.origMain; m != nil {
					intf = m
				}
				if intf == in || intf.zone != nil {
					continue
				}
				r := intf.router
				if r.activePath {
					continue
				}
				r.activePath = true
				defer func() { r.activePath = false }()
				result[r] = append(result[r], intf)

				//debug("%s: %s", r, intf)
				for _, out := range r.interfaces {
					if m := out.origMain; m != nil {
						out = m
					}
					if out != intf {
						reachFromBorder(out.network, out, result)
					}
				}
			}
		}
	result := make(map[netOrRouter]intfList)
	reachFromBorder(border.network, border, result)
	for key, l := range result {
		delDupl(&l)
		result[key] = l
	}
	c.border2obj2auto[border] = result
}

// Find auto interface inside zone.
// border is interface at border of zone.
func (c *spoc) autoIntfInZone(border *routerIntf, obj netOrRouter) intfList {
	if c.border2obj2auto == nil {
		c.border2obj2auto = make(map[*routerIntf]map[netOrRouter]intfList)
	}
	if c.border2obj2auto[border] == nil {
		c.setAutoIntfFromBorder(border)
	}
	return c.border2obj2auto[border][obj]
}

func addPathrestictedIntfs(path pathStore, obj netOrRouter) []pathStore {
	result := []pathStore{path}
	if x, ok := obj.(*router); ok {
		for _, intf := range getIntf(x) {
			if intf.pathRestrict != nil {
				result = append(result, intf)
			}
		}
	}
	return result
}

// Result is the set of interfaces of src located at direction to dst.
func (c *spoc) pathRouterInterfaces(src *router, dst someObj) intfList {
	srcPath := src.getPathNode()
	dstPath := dst.getPathNode()
	toList := []pathStore{dstPath}
	return c.findAutoInterfaces(srcPath, dstPath, toList, src.name, dst.String(), src)
}

func (c *spoc) findAutoInterfaces(
	srcPath, dstPath pathStore, toList []pathStore,
	srcName, dstName string, src2 netOrRouter) intfList {

	var result intfList
	// Collect blocking pathrestrictions for error reporting.
	blockingCount := make(map[*pathRestriction]int)

	// Check path separately for interfaces with pathrestriction,
	// because path from inside the router to destination may be restricted.
	fromList := addPathrestictedIntfs(srcPath, src2)
	for _, fromStore := range fromList {
		for _, toStore := range toList {
			if _, found := fromStore.getPath1()[toStore]; !found {
				found, localBlocking := pathMark(fromStore, toStore)
				if !found {
					// Aggregate blocking path restrictions from all failed attempts
					for pr, cnt := range localBlocking {
						blockingCount[pr] += cnt
					}
					continue
				}
			}
			// Handle special case, where path starts at pathrestricted
			// interface at border of loop and corresponding router is located
			// outside of loop.
			if x, ok := fromStore.(*routerIntf); ok {
				if _, found := x.loopConnZone[toStore]; found {
					result.push(x)
					continue
				}
			}
			if lc, found := fromStore.getLoopConn()[toStore]; found {
				enter := lc.entry.getLoopPath()[lc.exit].enter
				switch x := fromStore.(type) {
				case *zone:
					for _, intf := range enter {
						result = append(result, c.autoIntfInZone(intf, src2)...)
					}
				case *router:
					result = append(result, enter...)

				case *routerIntf:
					// Path is only ok, if it doesn't traverse
					// corrensponding router.
					// Path starts inside loop.
					// Check if some path doesn't traverse current router.
					// Then interface is ok as [auto] interface.
					if x.loop != nil {
						for _, intf := range enter {
							if intf == fromStore {
								result.push(x)
							}
						}
					}
				}
			} else {
				next := fromStore.getPath1()[toStore]
				switch fromStore.(type) {
				case *zone:
					result = append(result, c.autoIntfInZone(next, src2)...)
				case *router:
					result.push(next)
				case *routerIntf:
					// routerIntf with pathrestriction at border of loop,
					// wont get additional path.
				}
			}
		}
	}
	if len(result) == 0 {
		c.showErrNoValidPath(srcPath, dstPath,
			fmt.Sprintf("while resolving %s (destination is %s).",
				srcName, dstName), blockingCount)
		return nil
	}
	delDupl(&result)

	// Remove tunnel interfaces, change slice in place.
	j := 0
	for _, intf := range result {
		if intf.ipType != tunnelIP {
			result[j] = intf
			j++
		}
	}
	result = result[:j]

	bridgedSeen := false
	for i, intf := range result {
		if orig := intf.origMain; orig != nil {
			// If device has virtual interface, main and virtual interface
			// are swapped.  Swap it back here because we need the
			// original main interface if an interface is used in a rule.
			result[i] = orig
		} else if l3 := intf.layer3Intf; l3 != nil {
			// Change bridge interface to layer3 interface.
			// Prevent duplicate layer3 interface.
			result[i] = l3
			bridgedSeen = true
		}
	}
	if bridgedSeen {
		delDupl(&result)
	}

	//debug("%s = \n"+result.nameList(), srcName)

	return result
}
