package pass1

import (
	"fmt"
	"slices"
)

// Package-level map to store pathrestriction distances for sorting at display time
var prDistances map[*pathRestriction]int

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

		// If this is a secondary interface, we can't use it to enter
		// the router, because it has an active pathrestriction attached.
		// But it doesn't matter if we use the main interface instead.
		if main := obj.mainIntf; main != nil {
			obj = main
		}

		// Special handling needed if src or dst is interface
		// which has pathrestriction attached.
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

// clusterPathMark1 recursively finds
// path through a loop or loop cluster
// for a	given pair (start, end) of loop nodes and collects path information.
//
// Parameters :
//   - obj: current (or start) loop node (zone or router).
//   - inIntf: interface current loop node was entered from.
//   - end: loop node that is to be reached.
//   - lPath: collect tuples and last interfaces of path.
//   - navi: lookup hash to reduce search space, holds loops to enter.
//   - blocking: closure to record blocking pathrestrictions.
//
// Returns : true, if path is found.
func clusterPathMark1(obj pathObj, inIntf *routerIntf, end pathObj,
	lPath *loopPath, navi navigation, blocking func(*pathRestriction)) bool {

	//    debug("cluster_path_mark1: obj: obj->{name},
	//           in_intf: in_intf->{name} to: end->{name}");

	// Stop path exploration when activated PR (2nd occurrence) was passed.
	pathrestriction := inIntf.pathRestrict
	for _, restrict := range pathrestriction {
		if restrict.activePath {
			//       debug(" effective restrict->{name} at in_intf->{name}");
			// Record this pathrestriction as blocking the path.
			if blocking != nil {
				blocking(restrict)
			}
			return false
		}
	}

	// Node has been visited before - return to avoid walking loops.
	if obj.isActivePath() {
		//    debug(" active: obj->{name}");
		return false
	}

	// Found a path to router or zone.
	if obj == end {

		// Store interface where we leave the loop.
		lPath.leave.push(inIntf)
		//    debug(" leave: in_intf->{name} -> end->{name}");
		return true
	}

	// Mark current path for loop detection.
	obj.setActivePath()
	defer func() { obj.clearActivePath() }()

	// debug "activated obj->{name}";

	// Activate passed pathrestrictions.
	if pathrestriction != nil {
		for _, restrict := range pathrestriction {

			//       debug(" enabled restrict->{name} at in_intf->{name}");
			restrict.activePath = true
		}

		// Deactivate pathrestrictions later.
		defer func() {
			//       debug "deactivated obj->{name}";
			for _, restrict := range pathrestriction {

				//          debug(" disabled restrict->{name} at in_intf->{name}");
				restrict.activePath = false
			}
		}()
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
		if clusterPathMark1(next, intf, end, lPath, navi, blocking) {

			// ...collect path information.
			//debug(" loop: %s -> %s", inIntf, intf)
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

// fixupZonePath adapts path starting/ending at zone,
// such that the original start/end-interface is reached.
//
//	First step:
//	Remove paths, that traverse router of start/end interface,
//	but don't terminate at that router. This would lead to
//	invalid paths entering the same router two times.
//	Second step:
//	Adjust start/end of paths from zone to router.
//
// Parameters:
//   - start, end: start and/or end interface of orginal path
//   - lPath: Describes path inside loop.
//
// Returns: nothing
// Results: Changes attributes of lPath.
func fixupZonePath(start, end *routerIntf, lPath *loopPath) {
	tuples := &lPath.routerTuples
	delIn := make(map[*routerIntf]bool)
	delOut := make(map[*routerIntf]bool)
	markDeleted := func(idx int) {
		tuple := (*tuples)[idx]
		// Mark interfaces of to be removed tuple, because adjacent tuples
		// could become dangling now.
		delIn[tuple[1]] = true
		delOut[tuple[0]] = true
		// Mark tuple at position idx as deleted.
		(*tuples)[idx][0] = nil
	}
	setup := func(startEnd *routerIntf, inOut int) {
		if startEnd == nil {
			return
		}
		// Remove tuples traversing that router, where path should start/end.
		// Collect interfaces of to be removed tuples.
		router := startEnd.router
		for idx, tuple := range *tuples {
			intf := tuple[inOut]
			if intf.router == router {
				if intf != startEnd {
					markDeleted(idx)
				}
			} else {
				// Prohibit paths traversing related redundancy interfaces.
				if slices.Contains(startEnd.redundancyIntfs, intf) {
					markDeleted(idx)
				}
			}
		}
	}
	setup(start, 0)
	setup(end, 1)

	// Remove dangling tuples.
	changed := false
	for len(delIn) != 0 || len(delOut) != 0 {
		changed = true

		// Remove mark, if non removed tuples are adjacent.
		for _, tuple := range *tuples {
			if tuple[0] != nil {
				delete(delIn, tuple[1])
				delete(delOut, tuple[0])
			}
		}
		// Find dangling tuples for next iteration.
		if tuples == &lPath.routerTuples {
			tuples = &lPath.zoneTuples
		} else {
			tuples = &lPath.routerTuples
		}
		delInPrev := delIn
		delOutPrev := delOut
		delIn = make(map[*routerIntf]bool)
		delOut = make(map[*routerIntf]bool)
		for idx, tuple := range *tuples {
			if tuple[0] != nil {
				if delInPrev[tuple[0]] || delOutPrev[tuple[1]] {
					markDeleted(idx)
				}
			}
		}
	}

	if changed {

		// Remove tuples that are marked as deleted. Change in place.
		delTuples := func(path intfPairs) intfPairs {
			j := 0
			for _, tuple := range path {
				if tuple[0] != nil {
					path[j] = tuple
					j++
				}
			}
			return path[:j]
		}
		lPath.routerTuples = delTuples(lPath.routerTuples)
		lPath.zoneTuples = delTuples(lPath.zoneTuples)

		// Find dangling interfaces at start and end of path by marking
		// all interfaces that are used in path.
		hasIn := make(map[*routerIntf]bool)
		hasOut := make(map[*routerIntf]bool)

		// First/last tuple of path is known to be part of router,
		// because path starts/ends at zone.
		// But for other side of path, we don't know if it starts at
		// router or zone; so we must check zoneTuples also.
		mark := func(tuples intfPairs) {
			for _, tuple := range tuples {
				hasIn[tuple[0]] = true
				hasOut[tuple[1]] = true
			}
		}
		mark(lPath.routerTuples)
		mark(lPath.zoneTuples)

		// Remove dangling interfaces while preserving original backing
		// array.
		delIntf := func(l intfList, m map[*routerIntf]bool) intfList {
			j := 0
			for _, intf := range l {
				if m[intf] {
					l[j] = intf
					j++
				}
			}
			return l[:j]
		}
		lPath.enter = delIntf(lPath.enter, hasIn)
		lPath.leave = delIntf(lPath.leave, hasOut)
	}

	// Change start/end of paths from zone to router of original interface.
	change := func(startEnd *routerIntf, inOut int) {
		if startEnd == nil {
			return
		}
		isStart := inOut == 0
		outIn := 1
		enterLeave := &lPath.enter
		if !isStart {
			outIn = 0
			enterLeave = &lPath.leave
		}
		addIntf := make(intfList, 0)
		seenIntf := false
		for _, intf := range *enterLeave {
			if intf == startEnd {
				j := 0
				for _, tuple := range lPath.routerTuples {
					if tuple[inOut] == intf {
						addIntf.push(tuple[outIn])
					} else {
						lPath.routerTuples[j] = tuple
						j++
					}
				}
				lPath.routerTuples = lPath.routerTuples[:j]
			} else {
				if isStart {
					lPath.zoneTuples.push(intfPair{startEnd, intf})
				} else {
					lPath.zoneTuples.push(intfPair{intf, startEnd})
				}
				if !seenIntf {
					seenIntf = true
					addIntf.push(startEnd)
				}
			}
		}
		*enterLeave = addIntf
	}
	change(start, 0)
	change(end, 1)
}

// intfClusterPathMark marks path starting/ending at pathrestricted
// interface by first marking path from/to related zone and
// afterwards fixing found path.
//
// Parameters:
//   - startStore: start node or interface
//   - endStore: end node or interface
//   - startIntf: set if path starts at pathrestricted interface
//   - endIntf: set if path ends at pathrestricted interface
//   - blocking: closure to record blocking pathrestrictions.
//
// Returns: True if path was found, false otherwise.
// Results: Sets attributes for found path:
// loopEnter, loopLeave, PathTuples for found path.
func intfClusterPathMark(
	startStore, endStore pathStore,
	startIntf, endIntf *routerIntf,
	blocking func(*pathRestriction),
) bool {
	if startIntf != nil {
		startStore = startIntf.zone
	}
	if endIntf != nil {
		endStore = endIntf.zone
	}

	// Check if zones are equal.
	zoneEq := func(s1, s2 pathStore) bool {
		if intf, ok := s1.(*routerIntf); ok {
			if zone, ok := s2.(*zone); ok {
				return intf.zone == zone
			}
		}
		return false
	}

	lPath := new(loopPath)

	// Set minimal path manually.
	if startStore == endStore ||
		zoneEq(endStore, startStore) ||
		zoneEq(startStore, endStore) {
		if startIntf != nil && endIntf != nil {
			lPath.enter = intfList{startIntf}
			lPath.leave = intfList{endIntf}
			lPath.zoneTuples = intfPairs{{startIntf, endIntf}}
			startStore = startIntf
			endStore = endIntf
		} else if startIntf != nil {
			lPath.enter = intfList{startIntf}
			lPath.leave = intfList{startIntf}
			startStore = startIntf
		} else {
			lPath.enter = intfList{endIntf}
			lPath.leave = intfList{endIntf}
			endStore = endIntf
		}
	} else {

		// Mark cluster path between different zones.
		if !clusterPathMark(startStore, endStore, blocking) {
			return false
		}

		origPath := startStore.getLoopPath()[endStore]

		// Copy arrays, othwise origPath would be changed below.
		lPath.enter = append(lPath.enter, origPath.enter...)
		lPath.leave = append(lPath.leave, origPath.leave...)
		lPath.routerTuples = append(lPath.routerTuples, origPath.routerTuples...)
		lPath.zoneTuples = append(lPath.zoneTuples, origPath.zoneTuples...)

		// Fixup start and/or end of path.
		if startIntf != nil || endIntf != nil {
			fixupZonePath(startIntf, endIntf, lPath)
			if startIntf != nil {
				startStore = startIntf
			}
			if endIntf != nil {
				endStore = endIntf
			}
		}
	}

	// Check if path is empty after fixup.
	if len(lPath.enter) == 0 {
		return false
	}

	// Store found path.
	startStore.setLoopPath(endStore, lPath)

	return true
}

// #############################################################################
// clusterPathMark collects path information through a loop
// for a pair of loop nodes (zone or router) and
// stores it at the object where loop paths begins.
//
// Parameters :
//   - startStore: source loop node or interface, if source
//     is a pathrestricted interface of loop.
//   - endStore: destination loop node or interface, if destination
//     is a pathrestricted interface of loop.
//   - blocking: closure to record blocking pathrestrictions.
//
// Returns: True if a valid path was found, false otherwise.
// Results:
// Loop entering interface
// holds reference to where loop path information is stored.
//
//	(Starting or ending at pathrestricted interface may lead
//	 to different paths than for a simple node).
//	Referenced object holds loop path description.
func clusterPathMark(startStore, endStore pathStore, blocking func(*pathRestriction)) bool {

	// Path from startStore to endStore has been marked already.
	if startStore.getLoopPath()[endStore] != nil {
		return true
	}

	// Entry and exit nodes inside loop.
	var from, to pathObj

	// Set variables, if path starts/ends at pathrestricted interface
	// inside of loop.
	var startIntf, endIntf *routerIntf

	// Set variables, if path starts or enters loop at pathrestricted
	// interface at border of loop.
	// If path starts/ends, corresponding loop node is always a router,
	// because zones case has been transformed before.
	var fromIn, toOut *routerIntf

	setup := func(s pathStore, obj *pathObj, loopIntf, borderIntf **routerIntf) {
		switch x := s.(type) {
		case *routerIntf:
			if x.loop != nil {
				*loopIntf = x
				*obj = x.router
			} else {
				*borderIntf = x
				if x.zone.loop != nil {
					*obj = x.zone
				} else {
					*obj = x.router
				}
			}
		case *router:
			*obj = x
		case *zone:
			*obj = x
		}
	}
	setup(startStore, &from, &startIntf, &fromIn)
	setup(endStore, &to, &endIntf, &toOut)

	if startIntf != nil || endIntf != nil {
		return intfClusterPathMark(startStore, endStore, startIntf, endIntf, blocking)
	}

	//debug("clusterPathMark: %s -> %s", startStore, endStore);
	//debug(" %s -> %s", from, to);
	success := true

	// Activate pathrestriction at border of loop.
	for _, intf := range []*routerIntf{fromIn, toOut} {
		if intf == nil {
			continue
		}
		pathrestriction := intf.pathRestrict
		if pathrestriction != nil {
			for _, restrict := range pathrestriction {

				// No path possible, if restriction has been just
				// activated at other side of loop.
				if restrict.activePath {
					success = false
				}
				restrict.activePath = true
			}

			// Deactivate pathrestrictions later.
			defer func() {
				//       debug "deactivated obj->{name}";
				for _, restrict := range pathrestriction {

					//          debug(" disabled restrict->{name} at in_intf->{name}");
					restrict.activePath = false
				}
			}()
		}
	}

	// Find loop paths via depth first search.
	// Ignore path, if not valid due to pathrestrictions.
	if success {
		success = false

		// Create navigation look up map to reduce search space in loop cluster.
		navi := clusterNavigation(from, to)
		allowed := navi[from.getLoop()]

		// These attributes describe valid paths inside loop.
		lPath := new(loopPath)

		// Mark current path for loop detection.
		from.setActivePath()
		defer func() { from.clearActivePath() }()

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

			// Search path from next node to to, store it in lPath.
			//debug(" try: %s -> %s", from, intf)
			if clusterPathMark1(next, intf, to, lPath, navi, blocking) {
				success = true
				lPath.enter.push(intf)
				//debug(" enter: %s -> %s", from, intf);
			}
		}

		// Only store complete result.
		if success {
			delDupl(&lPath.routerTuples)
			delDupl(&lPath.zoneTuples)

			// Remove duplicates, which occur from nested loops.
			delDupl(&lPath.leave)

			// Add loop path information to start node or interface.
			startStore.setLoopPath(endStore, lPath)
		}
	}

	return success
}

func connectClusterPath(
	from, to pathObj,
	fromIn, toOut *routerIntf,
	fromStore, toStore pathStore,
	blocking func(*pathRestriction),
) bool {

	// Find object to store path information inside loop.
	// Path may differ depending on whether loop entering and exiting
	// interfaces are pathrestricted or not. Storing path information
	// in different objects respects this.
	setup := func(
		s pathStore, obj pathObj, borderIntf **routerIntf) (pathStore, bool) {

		var store pathStore
		// Clear borderIntf if we are about to enter/exit a loop at zone,
		// because pathrestriction at borderIntf must not be activated.
		storeIntf, storeIsIntf := s.(*routerIntf)
		if storeIsIntf {
			if *borderIntf == storeIntf {
				*borderIntf = nil
			}
		}
		// Path starts/ends at pathrestricted interface inside or at
		// border of current loop.
		// Set flag, if path starts at interface of zone at border of loop.
		atZone := false
		if *borderIntf == nil && storeIsIntf {
			// Path starts/ends at border of current loop at zone node.
			// Pathrestriction must not be activated, hence use zone as
			// store.
			if storeIntf.loop == nil && storeIntf.zone.loop != nil {
				store = storeIntf.zone
				atZone = true
			} else {
				// Path starts/ends inside or at border of current loop at
				// router node.
				store = storeIntf
			}
		} else if *borderIntf != nil && (*borderIntf).pathRestrict != nil {
			// Loop is entered/exited at pathrestricted interface.
			store = *borderIntf
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
		return store, atZone
	}

	startStore, startAtZone := setup(fromStore, from, &fromIn)
	endStore, endAtZone := setup(toStore, to, &toOut)

	success := clusterPathMark(startStore, endStore, blocking)

	// If loop path was found, set path information for fromIn and
	// toOut interfaces and connect them with loop path.
	if success {
		var store pathStore

		if fromIn != nil {
			store = fromIn
		} else {
			store = fromStore
		}
		if endAtZone {
			// Path ends at interface of zone at border of loop.
			// Continue path to router of interface outside of loop.
			toOut = toStore.(*routerIntf)
		}
		if fromIn != nil || startAtZone {
			store.setPath(toStore, toOut)
		} else {
			store.setPath1(toStore, toOut)
		}

		/*
			var debuggingPathAttr string
			if fromIn != nil || startAtZone {
				debuggingPathAttr = "path"
			} else {
				debuggingPathAttr = "path1"
			}
			debug("loop %s: %s -> %s", debuggingPathAttr, store, toStore)
		*/

		// Collect path information at beginning of loop path (startStore).
		// Loop paths beginning at loop node can differ depending on the way
		// the node is entered (interface with/without pathrestriction,
		// pathrestricted src/dst interface), requiring storing path
		// information at different objects.
		// Path information is stored at attribute loopEntry.
		if startAtZone {
			x := store.(*routerIntf)
			x.setLoopEntryZone(toStore, startStore)
		} else {
			store.setLoopEntry(toStore, startStore)
		}
		startStore.setLoopExit(toStore, endStore)
	}

	return success
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

// getPathObj extracts the pathObj from a pathStore.
func getPathObj(store pathStore) pathObj {
	switch x := store.(type) {
	case *routerIntf:
		return x.router
	case *router:
		return x
	case *zone:
		return x
	default:
		return nil
	}
}

// pathMark finds and marks path from source to destination.
// Parameter:
//   - fromStore: Object, where path starts.
//   - toStore: Objects, where path ends.
//     Typically both are of type zone or router.
//     For details see description of sub pathWalk.
//
// Returns:
//   - bool: True if valid path is found, False otherwise.
//   - map: Pathrestrictions that blocked the path (if any).
//
// Results: The next interface towards toStore is stored in attribute
//   - .path1 of fromStore and
//   - .path of subsequent interfaces on path.
func pathMark(fromStore, toStore pathStore) (bool, map[*pathRestriction]bool) {
	// Count how many path attempts each pathrestriction blocks
	blockingCount := make(map[*pathRestriction]int)
	blocking := make(map[*pathRestriction]bool)

	recordBlocking := func(pr *pathRestriction) {
		blockingCount[pr]++
		blocking[pr] = true
	}

	// Store counts in package-level map for display sorting
	defer func() {
		if len(blockingCount) > 0 {
			prDistances = blockingCount
		}
	}()

	// debug("pathMark %s --> %s", fromStore, toStore)
	from := getPathObj(fromStore)
	to := getPathObj(toStore)
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
			return true, blocking
		}

		// Paths meet inside a loop.
		if fromLoop != nil && toLoop != nil &&
			fromLoop.clusterExit == toLoop.clusterExit {
			if connectClusterPath(from, to, fromIn, toOut, fromStore, toStore, recordBlocking) {
				return true, blocking
			}
			break PATH
		}

		// Otherwise, take a step towards zone1 from the more distant node.
		if from.getDistance() >= to.getDistance() { // Take step from node from.

			// Return, if mark has already been set for a sub-path.
			if fromIn != nil && fromIn.getPath()[toStore] != nil {
				return true, blocking
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
					from, exit, fromIn, fromOut, fromStore, toStore, recordBlocking) {

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
				if !connectClusterPath(entry, to, toIn, toOut, fromStore, toStore, recordBlocking) {
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
	return false, blocking
}

// #############################################################################
// loopPathWalk walks loop section of a path
// from a rules source to its	destination.
// Apply given function to every zone or router	on loop path.
//
// Parameters :
//   - in - interface the loop is entered at.
//   - out - interface loop is left at.
//   - loopEntry - entry object, holding path information.
//   - loopExit - loop exit node.
//   - callAtZone - flag for node function is to be called at
//     (true - zone. false - router)
//   - rule - rule providing source and destination.
//   - fun - Function to be applied.
func loopPathWalk(
	in, out *routerIntf,
	loopEntry, loopExit pathStore,
	callAtZone bool,
	rule *groupedRule,
	fun func(r *groupedRule, i, o *routerIntf),
) bool {

	// debug("loopPathWalk: %s->%s=>%s->%s", in, loopEntry, loopExit, out)

	lPath := loopEntry.getLoopPath()[loopExit]

	// Process entry of cyclic graph.
	isRouter := false
	switch x := loopEntry.(type) {
	case *router:
		isRouter = true
	case *routerIntf:

		// Take only interface which originally was a router.
		if x.router == lPath.enter[0].router {
			isRouter = true
		}
	}
	if isRouter != callAtZone {

		//        debug(" loop_enter");
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

	// debug(" loop_tuples");
	for _, tuple := range pathTuples {
		fun(rule, tuple[0], tuple[1])
	}

	// Process paths at exit of cyclic graph.
	isRouter = false
	switch x := loopExit.(type) {
	case *router:
		isRouter = true
	case *routerIntf:
		if x.router == lPath.leave[0].router {
			isRouter = true
		}
	}
	callIt := isRouter != callAtZone
	if callIt {
		// debug(" loop_leave");
		for _, inIntf := range lPath.leave {
			fun(rule, inIntf, out)
		}
	}
	return callIt
}

func (c *spoc) showErrNoValidPath(srcPath, dstPath pathStore, context string, blocking map[*pathRestriction]bool) {
	tag1 := findPartitionTag(srcPath)
	tag2 := findPartitionTag(dstPath)

	var msg string
	if tag1 != tag2 {
		// Different partitions - this is the root cause
		msg = fmt.Sprintf(" Source and destination objects are located in "+
			"different topology partitions: %s, %s.", tag1, tag2)
	} else {
		// Same partition - check if pathrestrictions are blocking
		if len(blocking) > 0 {
			msg = " Possible blocking pathrestrictions:\n"

			// Sort by specificity: pathrestrictions that block fewer paths are more specific
			// and more likely to be the targeted restriction for this scenario
			type prInfo struct {
				pr        *pathRestriction
				pathCount int // Number of paths blocked
				name      string
			}
			var sorted []prInfo

			for pr := range blocking {
				count := prDistances[pr] // Number of path attempts blocked
				sorted = append(sorted, prInfo{
					pr:        pr,
					pathCount: count,
					name:      pr.name,
				})
			}

			// Sort by number of blocked paths (fewer first), then alphabetically
			slices.SortFunc(sorted, func(a, b prInfo) int {
				// Primary: number of blocked paths (fewer = more specific = more relevant)
				if a.pathCount != b.pathCount {
					return a.pathCount - b.pathCount
				}
				// Secondary: alphabetical for deterministic output
				if a.name < b.name {
					return -1
				} else if a.name > b.name {
					return 1
				}
				return 0
			})

			for _, item := range sorted {
				msg += fmt.Sprintf("  - %s (blocked %d path attempts)\n", item.name, item.pathCount)
			}
		}
		msg += " Check path restrictions and crypto interfaces."
	}

	c.err("No valid path\n from %s\n to %s\n %s\n"+msg,
		srcPath, dstPath, context)
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
		found, blocking := pathMark(fromStore, toStore)
		if !found {
			// Path finding failed.
			// No need to show error message when finding static routes,
			// because this will be shown again when distributing rules.
			if !atZone {
				c.showErrNoValidPath(fromStore, toStore, "for rule "+rule.print(), blocking)
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
	var loopEntry pathStore

	// Path starts inside or at border of cyclic graph.
	//
	// Special case: Path starts at pathrestricted interface of
	// zone at border of loop and hence this pathrestriction will
	// not be activated. Use attribute loopEntryZone, to find correct
	// path in loop.
	if x, ok := fromStore.(*routerIntf); ok {
		loopEntry = x.loopEntryZone[toStore]

		if loopEntry != nil {

			// Walk path starting at router outside of loop.
			if callIt {
				fun(rule, nil, x)
			}
			in = x
			out = x.path[toStore]
		}
	}
	if loopEntry == nil {
		// Otherwise use attribute loopEntry, to find possibly
		// pathrestricted path in loop.
		loopEntry = fromStore.getLoopEntry()[toStore]
	}

	// Walk loop path.
	if loopEntry != nil {
		loopExit := loopEntry.getLoopExit()[toStore]
		callIt = loopPathWalk(in, out, loopEntry, loopExit, atZone, rule, fun)

		// Return, if end of path has been reached.
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
		var loopEntry pathStore
		if in != nil {
			loopEntry = in.loopEntry[toStore]
		}
		if loopEntry != nil {
			loopExit := loopEntry.getLoopExit()[toStore]
			callIt = // Was function called on last node of loop?
				loopPathWalk(in, out, loopEntry, loopExit, atZone, rule, fun)
		} else if callIt {

			// Non-loop path continues - call function, if switch is set.
			fun(rule, in, out)
		}

		// Return, if end of path has been reached.
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
	var blocking map[*pathRestriction]bool

	// Check path separately for interfaces with pathrestriction,
	// because path from inside the router to destination may be restricted.
	fromList := addPathrestictedIntfs(srcPath, src2)
	for _, fromStore := range fromList {
		for _, toStore := range toList {
			if _, found := fromStore.getPath1()[toStore]; !found {
				var found bool
				found, blocking = pathMark(fromStore, toStore)
				if !found {
					continue
				}
			}
			if x, ok := fromStore.(*routerIntf); ok {
				if _, found := x.loopEntryZone[toStore]; found {
					result.push(x)
					continue
				}
			}
			if entry, found := fromStore.getLoopEntry()[toStore]; found {
				exit := entry.getLoopExit()[toStore]
				enter := entry.getLoopPath()[exit].enter
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
				srcName, dstName), blocking)
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
