package pass1

import ()

func findZone1(store pathStore) *zone {
	var obj pathObj
	switch x := store.(type) {
	case *routerIntf:
		obj = x.router
	case *router:
		obj = x
	case *zone:
		obj = x
	}
	for {
		intf := obj.getToZone1()
		if intf == nil {
			loop := obj.getLoop()
			if loop == nil {
				return obj.(*zone)
			}
			loopExit := loop.exit
			intf = loopExit.getToZone1()

			// Zone1 is adjacent to loop.
			if intf == nil {
				return loopExit.(*zone)
			}
		}
		obj = intf.toZone1
	}
}

//###################################################################
// Efficient path traversal.
//###################################################################

type pathStoreData struct {
	path      map[pathStore]*routerIntf
	path1     map[pathStore]*routerIntf
	loopEntry map[pathStore]pathStore
	loopExit  map[pathStore]pathStore
	loopPath  map[pathStore]*loopPath
}

type pathStore interface {
	getName() string
	getPath() map[pathStore]*routerIntf
	getPath1() map[pathStore]*routerIntf
	getLoopEntry() map[pathStore]pathStore
	getLoopExit() map[pathStore]pathStore
	getLoopPath() map[pathStore]*loopPath
	setPath(pathStore, *routerIntf)
	setPath1(pathStore, *routerIntf)
	setLoopEntry(pathStore, pathStore)
	setLoopExit(pathStore, pathStore)
	setLoopPath(pathStore, *loopPath)
}

func (x *pathStoreData) getPath() map[pathStore]*routerIntf    { return x.path }
func (x *pathStoreData) getPath1() map[pathStore]*routerIntf   { return x.path1 }
func (x *pathStoreData) getLoopEntry() map[pathStore]pathStore { return x.loopEntry }
func (x *pathStoreData) getLoopExit() map[pathStore]pathStore  { return x.loopExit }
func (x *pathStoreData) getLoopPath() map[pathStore]*loopPath  { return x.loopPath }

func (x *pathStoreData) setPath(s pathStore, i *routerIntf) {
	if x.path == nil {
		x.path = make(map[pathStore]*routerIntf)
	}
	x.path[s] = i
}
func (x *pathStoreData) setPath1(s pathStore, i *routerIntf) {
	if x.path1 == nil {
		x.path1 = make(map[pathStore]*routerIntf)
	}
	x.path1[s] = i
}
func (x *pathStoreData) setLoopEntry(s pathStore, e pathStore) {
	if x.loopEntry == nil {
		x.loopEntry = make(map[pathStore]pathStore)
	}
	x.loopEntry[s] = e
}
func (x *routerIntf) setLoopEntryZone(s pathStore, e pathStore) {
	if x.loopEntryZone == nil {
		x.loopEntryZone = make(map[pathStore]pathStore)
	}
	x.loopEntryZone[s] = e
}
func (x *pathStoreData) setLoopExit(s pathStore, e pathStore) {
	if x.loopExit == nil {
		x.loopExit = make(map[pathStore]pathStore)
	}
	x.loopExit[s] = e
}
func (x *pathStoreData) setLoopPath(s pathStore, i *loopPath) {
	if x.loopPath == nil {
		x.loopPath = make(map[pathStore]*loopPath)
	}
	x.loopPath[s] = i
}

type pathObjData struct {
	interfaces []*routerIntf
	activePath bool
	distance   int
	loop       *loop
	navi       map[pathObj]navigation
	toZone1    *routerIntf
}

type pathObj interface {
	intfList() []*routerIntf
	isActivePath() bool
	setActivePath()
	clearActivePath()
	getDistance() int
	getLoop() *loop
	getNavi() map[pathObj]navigation
	setNavi(pathObj, navigation)
	getToZone1() *routerIntf
}

func (x *pathObjData) intfList() []*routerIntf         { return x.interfaces }
func (x *pathObjData) isActivePath() bool              { return x.activePath }
func (x *pathObjData) setActivePath()                  { x.activePath = true }
func (x *pathObjData) clearActivePath()                { x.activePath = false }
func (x *pathObjData) getDistance() int                { return x.distance }
func (x *pathObjData) getLoop() *loop                  { return x.loop }
func (x *pathObjData) getNavi() map[pathObj]navigation { return x.navi }
func (x *pathObjData) getToZone1() *routerIntf         { return x.toZone1 }

func (x *pathObjData) setNavi(o pathObj, n navigation) {
	if x.navi == nil {
		x.navi = make(map[pathObj]navigation)
	}
	x.navi[o] = n
}

//#############################################################################
// Purpose   : Provide path node objects for objects specified as src or dst.
// Parameter : Source or destination object from an elementary rule.
// Returns   : Reference to zone or router of the given object or reference
//             to object itself, if it is a pathrestricted interface.
// Results   : Return value for given object is stored in obj2path lookup hash.
func (obj *network) getPathNode() pathStore {
	return obj.zone
}
func (obj *subnet) getPathNode() pathStore {
	return obj.network.zone
}
func (obj *routerIntf) getPathNode() pathStore {
	router := obj.router
	if router.managed != "" || router.semiManaged {

		// If this is a secondary interface, we can't use it to enter
		// the router, because it has an active pathrestriction attached.
		// But it doesn't matter if we use the main interface instead.
		main := obj.mainIntf
		if main == nil {
			main = obj
		}

		// Special handling needed if src or dst is interface
		// which has pathrestriction attached.
		if main.pathRestrict != nil {
			return main
		} else {
			return main.router
		}
	} else {

		// Unmanaged routers are part of zone objects.
		return obj.network.zone
	}
}

// This is used, if called from pathAutoIntfs.
func (obj *router) getPathNode() pathStore {
	if obj.managed != "" || obj.semiManaged {
		return obj
	} else {
		return obj.interfaces[0].network.zone
	}
}

// This is used, if pathWalk is called from findActiveRoutes.
func (obj *zone) getPathNode() pathStore {
	return obj
}

// This is used in cut-netspoc and if pathWalk is called early to
// expand auto interfaces.
/*
func (obj *Host) getPathNode() pathObj {
	return obj.network.zone
}

// This is used, if called from groupPathRules.
func (obj *Autointerface) getPathNode() pathObj {
	object := obj.object
	switch object.(type) {
	case *network:

		// This will be refined later, if real interface is known.
		return object.zone
	case *Router:
		if object.managed || object.semiManaged {

			// This will be refined later, if real interface has pathrestriction.
			return object
		} else {

			// Take arbitrary interface to find zone.
			return object.interfaces[0].network.zone
		}
	}
	return nil
}
*/

type loop struct {
	exit        pathObj
	distance    int
	clusterExit pathObj
}
type navigation map[*loop]map[*loop]bool

type intfTuple [2]*routerIntf
type tupleList []intfTuple
type intfList []*routerIntf
type loopPath struct {
	enter        intfList
	leave        intfList
	routerTuples tupleList
	zoneTuples   tupleList
}

// Add element to slice.
func (a *tupleList) push(e intfTuple) {
	*a = append(*a, e)
}
func (a *intfList) push(e *routerIntf) {
	*a = append(*a, e)
}

// Remove duplicates from slice; change in place.
func (a *intfList) delDupl() {
	seen := make(map[*routerIntf]bool)
	j := 0
	for _, e := range *a {
		if !seen[e] {
			seen[e] = true
			(*a)[j] = e
			j++
		}
	}
	*a = (*a)[:j]
}

//#############################################################################
// Purpose    : Recursively find path through a loop or loop cluster for a
//              given pair (start, end) of loop nodes, collect path information.
// Parameters : obj - current (or start) loop node (zone or router).
//              inIntf - interface current loop node was entered from.
//              end - loop node that is to be reached.
//              lPath - collect tuples and last interfaces of path.
//              navi - lookup hash to reduce search space, holds loops to enter.
// Returns   :  true, if path is found
func clusterPathMark1(obj pathObj, inIntf *routerIntf, end pathObj, lPath *loopPath, navi navigation) bool {

	//    debug("cluster_path_mark1: obj: obj->{name},
	//           in_intf: in_intf->{name} to: end->{name}");

	// Stop path exploration when activated PR (2nd occurrence) was passed.
	pathrestriction := inIntf.pathRestrict
	for _, restrict := range pathrestriction {
		if restrict.activePath {
			//       debug(" effective restrict->{name} at in_intf->{name}");
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

	var getNext func(i *routerIntf) pathObj
	var typeTuples *tupleList
	switch obj.(type) {
	case *router:
		getNext = func(i *routerIntf) pathObj { return i.zone }
		typeTuples = &lPath.routerTuples
	default:
		getNext = func(i *routerIntf) pathObj { return i.router }
		typeTuples = &lPath.zoneTuples
	}
	success := false

	// Extract navigation lookup map.
	allowed := navi[obj.getLoop()]

	// Proceed loop path exploration with every loop interface of current node.
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

		//    debug "Try obj->{name} -> next->{name}";

		// If a valid path is found from next node to end...
		if clusterPathMark1(next, intf, end, lPath, navi) {

			// ...collect path information.
			//	    debug(" loop: in_intf->{name} -> interface->{name}");
			typeTuples.push(intfTuple{inIntf, intf})
			success = true
		}
	}

	return success
}

//#############################################################################
// Purpose    : Optimize navigation inside a cluster of loops: For a pair
//              (from,to) of loop nodes, identify order of loops passed
//              on the path from from to to. Store information as lookup
//              hash at node from to reduce search space when finding paths
//              from from to to.
// Parameters : from, to - loop nodes pair.
// Returns    : Hash with order/navigation information: keys = loops,
//              values = loops that may be entered next from key loop.
// Results    : from node holds navigation hash suggesting for every loop
//              of the cluster those loops, that are allowed to be entered when
//              traversing the path to to.
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

			// Path from -> to traverses from_loop and exit_loop.
			// Inside exit_loop, enter only from_loop, but not from other loops
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
			// Take step from to_loop.
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

// Remove element from slice without modifying original slice.
func (a *tupleList) deleteElement(e intfTuple) {
	index := -1
	for i, x := range *a {
		if x == e {
			index = i
			break
		}
	}
	if index == -1 {
		return
	}
	*a = append((*a)[:index], (*a)[index+1:]...)
}
func (a *intfList) deleteElement(e *routerIntf) {
	index := -1
	for i, x := range *a {
		if x == e {
			index = i
			break
		}
	}
	if index == -1 {
		return
	}
	*a = append((*a)[:index], (*a)[index+1:]...)
}

//#############################################################################
// Purpose    : Adapt path starting/ending at zone, such that the original
//              start/end-interface is reached.
//              First step:
//              Remove paths, that traverse router of start/end interface,
//              but don't terminate at that router. This would lead to
//              invalid paths entering the same router two times.
//              Second step:
//              Adjust start/end of paths from zone to router.
// Parameters : start_end: start or end interface of orginal path
//              in_out: has value 0 or 1, to access in or out interface
//                       of path tuples.
//              loop_path: Describes path inside loop.
// Returns    : nothing
// Results    : Changes attributes of loop_path.
func fixupZonePath(startEnd *routerIntf, inOut int, lPath *loopPath) {

	router := startEnd.router
	isRedundancy := make(map[*routerIntf]bool)

	// Prohibt paths traversing related redundancy interfaces.
	for _, i := range startEnd.redundancyIntfs {
		isRedundancy[i] = true
	}

	delTuples := make(tupleList, 0)

	// Remove tuples traversing that router, where path should start/end.
	for _, tuple := range lPath.routerTuples {
		intf := tuple[inOut]
		if intf.router == router {
			if intf != startEnd {
				delTuples.push(tuple)
			}
		} else if isRedundancy[intf] {
			delTuples.push(tuple)
		}
	}
	tuples := &lPath.routerTuples
	changed := false

	// Remove dangling tuples.
	for len(delTuples) != 0 {
		changed = true
		delIn := make(map[*routerIntf]bool)
		delOut := make(map[*routerIntf]bool)
		for _, tuple := range delTuples {
			tuples.deleteElement(tuple)
			in, out := tuple[0], tuple[1]

			// Mark interfaces of just removed tuple, because adjacent tuples
			// could become dangling now.
			delIn[out] = true
			delOut[in] = true
		}

		// Remove mark, if non removed tuples are adjacent.
		for _, tuple := range *tuples {
			in, out := tuple[0], tuple[1]
			delete(delIn, out)
			delete(delOut, in)
		}
		if len(delIn) == 0 && len(delOut) == 0 {
			break
		}
		if tuples == &lPath.routerTuples {
			tuples = &lPath.zoneTuples
		} else {
			tuples = &lPath.routerTuples
		}
		delTuples = delTuples[0:0]
		for _, tuple := range *tuples {
			in, out := tuple[0], tuple[1]
			if delIn[in] || delOut[out] {
				delTuples.push(tuple)
			}
		}
	}

	// Remove dangling interfaces from start and end of path.
	if changed {
		hasIn := make(map[*routerIntf]bool)
		hasOut := make(map[*routerIntf]bool)

		// First/last tuple of path is known to be part of router,
		// because path starts/ends at zone.
		// But for other side of path, we don't know if it starts at
		// router or zone; so we must check zone_tuples also.
		for _, tuples := range []*tupleList{&lPath.routerTuples, &lPath.zoneTuples} {
			for _, tuple := range *tuples {
				in, out := tuple[0], tuple[1]
				hasIn[in] = true
				hasOut[out] = true
			}
		}

		// Delete interfaces while preserving original backing array.
		j := 0
		for _, intf := range lPath.enter {
			if hasIn[intf] {
				lPath.enter[j] = intf
				j++
			}
		}
		lPath.enter = lPath.enter[:j]
		j = 0
		for _, intf := range lPath.leave {
			if hasOut[intf] {
				lPath.leave[j] = intf
				j++
			}
		}
		lPath.leave = lPath.leave[:j]
	}

	// Change start/end of paths from zone to router of original interface.
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
				lPath.zoneTuples.push(intfTuple{startEnd, intf})
			} else {
				lPath.zoneTuples.push(intfTuple{intf, startEnd})
			}
			if !seenIntf {
				seenIntf = true
				addIntf.push(startEnd)
			}
		}
	}
	*enterLeave = (*enterLeave)[:0]
	*enterLeave = append(*enterLeave, addIntf...)
}

//#############################################################################
// Purpose    : Mark path starting/ending at pathrestricted interface
//              by first marking path from/to related zone and afterwards
//              fixing found path.
// Parameters : start_store: start node or interface
//              end_store: end node or interface
//              start_intf: set if path starts at pathrestricted interface
//              end_intf: set if path ends at pathrestricted interface
// Returns    : True if path was found, false otherwise.
// Results    : Sets attributes {loop_enter}, {loop_leave}, {*_path_tuples}
//              for found path and reversed path.
func intfClusterPathMark(startStore, endStore pathStore, startIntf, endIntf *routerIntf) bool {
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
			lPath.enter = []*routerIntf{startIntf}
			lPath.leave = []*routerIntf{endIntf}
			lPath.zoneTuples = []intfTuple{intfTuple{startIntf, endIntf}}
			startStore = startIntf
			endStore = endIntf
		} else if startIntf != nil {
			lPath.enter = []*routerIntf{startIntf}
			lPath.leave = []*routerIntf{startIntf}
			startStore = startIntf
		} else {
			lPath.enter = []*routerIntf{endIntf}
			lPath.leave = []*routerIntf{endIntf}
			endStore = endIntf
		}
	} else {

		// Mark cluster path between different zones.
		if !clusterPathMark(startStore, endStore) {
			return false
		}

		origPath := startStore.getLoopPath()[endStore]

		// Copy arrays, othwise origPath would be changed below.
		lPath.enter = append(lPath.enter, origPath.enter...)
		lPath.leave = append(lPath.leave, origPath.leave...)
		lPath.routerTuples = append(lPath.routerTuples, origPath.routerTuples...)
		lPath.zoneTuples = append(lPath.zoneTuples, origPath.zoneTuples...)

		// Fixup start of path.
		if startIntf != nil {
			fixupZonePath(startIntf, 0, lPath)
			startStore = startIntf
		}

		// Fixup end of path.
		if endIntf != nil {
			fixupZonePath(endIntf, 1, lPath)
			endStore = endIntf
		}
	}

	// Store found path.
	// Don't store reversed path, because few path start at interface.
	startStore.setLoopPath(endStore, lPath)

	return true
}

//#############################################################################
// Purpose    : Collect path information through a loop for a pair of
//              loop nodes (zone or router).
//              Store it at the object where loop paths begins.
// Parameters : start_store - source loop node or interface, if source
//                             is a pathrestricted interface of loop.
//              end_store - destination loop node or interface, if destination
//                           is a pathrestricted interface of loop.
// Returns    : True if a valid path was found, false otherwise.
// Results    : Loop entering interface holds reference to where loop path
//              information is stored.
//              (Starting or ending at pathrestricted interface may lead
//               to different paths than for a simple node).
//              Referenced object holds loop path description.
func clusterPathMark(startStore, endStore pathStore) bool {

	// Path from start_store to end_store has been marked already.
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
				if x.loopZoneBorder {
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
		return intfClusterPathMark(startStore, endStore, startIntf, endIntf)
	}

	//    debug("cluster_path_mark: start_store->{name} -> end_store->{name}");
	//    debug(" from->{name} -> to->{name}");
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

		// Create navigation look up hash to reduce search space in loop cluster.
		navi := clusterNavigation(from, to)
		if len(navi) == 0 {
			internalErr("Empty navi")
		}

		// These attributes describe valid paths inside loop.
		lPath := new(loopPath)

		// Mark current path for loop detection.
		from.setActivePath()
		defer func() { from.clearActivePath() }()

		var getNext func(i *routerIntf) pathObj
		switch from.(type) {
		case *router:
			getNext = func(i *routerIntf) pathObj { return i.zone }
		default:
			getNext = func(i *routerIntf) pathObj { return i.router }
		}
		allowed := navi[from.getLoop()]
		if len(allowed) == 0 {
			internalErr("Loop with empty navi %v -> %v", from, to)
		}

		// To find paths, process every loop interface of from node.
		for _, intf := range from.intfList() {
			loop := intf.loop
			if loop == nil {
				continue
			}

			// Skip interface that will not lead to a path,
			// because node is not included in navi.
			if !allowed[loop] {
				//		debug("No: loop->{exit}->{name}loop");
				continue
			}

			// Skip ...networks connecting virtual loopback interfaces.
			if intf.loopback {
				if _, ok := from.(*router); ok {
					continue
				}
			}

			// Extract adjacent node (= next node on path).
			next := getNext(intf)

			// Search path from next node to to, store it in provided variables.
			//       debug(" try: from->{name} -> interface->{name}");
			if clusterPathMark1(next, intf, to, lPath, navi) {
				success = true
				lPath.enter.push(intf)
				//          debug(" enter: from->{name} -> interface->{name}");
			}
		}

		// Only store complete result.
		if success {

			// Remove duplicates from path tuples.
			// Create reversed path.
			rPath := new(loopPath)
			adapt := func(orig, rev *tupleList) {
				var tuples, revTuples tupleList
				seen := make(map[intfTuple]bool)
				for _, tuple := range *orig {
					if seen[tuple] {
						continue
					}
					seen[tuple] = true
					tuples.push(tuple)
					revTuples.push(intfTuple{tuple[1], tuple[0]})
					//             debug("Tuple: in_intf->{name}, out_intf->{name} type");
				}
				*orig = tuples
				*rev = revTuples
			}
			adapt(&lPath.routerTuples, &rPath.routerTuples)
			adapt(&lPath.zoneTuples, &rPath.zoneTuples)

			// Remove duplicates, which occur from nested loops.
			lPath.leave.delDupl()

			// Add loop path information to start node or interface.
			startStore.setLoopPath(endStore, lPath)

			// Add data for reverse path.
			rPath.enter = lPath.leave
			rPath.leave = lPath.enter
			endStore.setLoopPath(startStore, rPath)
		}
	}

	return success
}

func connectClusterPath(from, to pathObj, fromIn, toOut *routerIntf, fromStore, toStore pathStore) bool {

	// Find objects to store path information inside loop.
	// Path may differ depending on whether loop entering and exiting
	// interfaces are pathrestricted or not. Storing path information
	// in different objects respects this.
	var startStore, endStore pathStore

	// Don't set fromIn if we are about to enter a loop at zone,
	// because pathrestriction at fromIn must not be activated.
	fromStoreIntf, fromStoreIsIntf := fromStore.(*routerIntf)
	if fromStoreIsIntf {
		if fromIn == fromStoreIntf {
			fromIn = nil
		}
	}
	toStoreIntf, toStoreIsIntf := toStore.(*routerIntf)
	if toStoreIsIntf {
		if toOut == toStoreIntf {
			toOut = nil
		}
	}

	// Path starts at pathrestricted interface inside or at border of
	// current loop.
	// Set flag, if path starts at interface of zone at border of loop.
	startAtZone := false
	if fromIn == nil && fromStoreIsIntf {

		// Path starts at border of current loop at zone node.
		// Pathrestriction must not be activated, hence use zone as
		// start_store.
		if fromStoreIntf.loopZoneBorder {
			startStore = fromStoreIntf.zone
			startAtZone = true
		} else {
			// Path starts inside or at border of current loop at router node.
			startStore = fromStoreIntf
		}
	} else if fromIn != nil && fromIn.pathRestrict != nil {

		// Loop is entered at pathrestricted interface.
		startStore = fromIn
	} else {

		// Loop starts or is entered at from node; no pathrestriction is effective.
		switch x := from.(type) {
		case *router:
			startStore = x
		case *zone:
			startStore = x
		}
	}

	// Set end_store with same logic that is used for start_store.
	if toOut == nil && toStoreIsIntf {
		if toStoreIntf.loopZoneBorder {
			endStore = toStoreIntf.zone

			// Path ends at interface of zone at border of loop.
			// Continue path to router of interface outside of loop.
			toOut = toStoreIntf
		} else {
			endStore = toStore
		}
	} else if toOut != nil && toOut.pathRestrict != nil {
		endStore = toOut
	} else {
		switch x := to.(type) {
		case *router:
			endStore = x
		case *zone:
			endStore = x
		}
	}

	success := clusterPathMark(startStore, endStore)

	// If loop path was found, set path information for fromIn and
	// toOut interfaces and connect them with loop path.
	if success {
		var store pathStore
		if fromIn != nil {
			store = fromIn
		} else {
			store = fromStore
		}
		if fromIn != nil || startAtZone {
			store.setPath(toStore, toOut)
		} else {
			store.setPath1(toStore, toOut)
		}

		//        debug "loop path_attr: path_store->{name} -> to_store->{name}";
		// Collect path information at beginning of loop path (start_store).
		// Loop paths beginning at loop node can differ depending on the way
		// the node is entered (interface with/without pathrestriction,
		// pathrestricted src/dst interface), requiring storing path
		// information at different objects.
		// Path information is stored at {loop_entry} attribute.
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

//#############################################################################
// Purpose   : Find and mark path from source to destination.
// Parameter : from_store - Object, where path starts.
//             to_store   - Objects, where path ends
//             Typically both are of type zone or router.
//             For details see description of sub path_walk.
// Returns   : True if valid path is found, False otherwise.
// Results   : The next interface towards to_store is stored in attribute
//             - {path1} of from_store and
//             - {path} of subsequent interfaces on path.
func pathMark(fromStore, toStore pathStore) bool {

	//   debug("path_mark from_store->{name} --> to_store->{name}");
	var from, to pathObj
	switch x := fromStore.(type) {
	case *routerIntf:
		from = x.router
	case *router:
		from = x
	case *zone:
		from = x
	}
	switch x := toStore.(type) {
	case *routerIntf:
		to = x.router
	case *router:
		to = x
	case *zone:
		to = x
	}
	fromLoop := from.getLoop()
	toLoop := to.getLoop()

	// No subsequent interface before first and behind last node on path.
	var fromIn, toOut *routerIntf

	// Follow paths from source and destination towards zone1 until they meet.
	for {

		//debug("Dist: from->{distance} from->{name} -> ",
		//      "Dist: to->{distance} to->{name}");

		// Paths meet outside a loop or at the edge of a loop.
		if from == to {

			// We need to distinguish between {path1} and {path} for
			// the case, where from_store is a pathrestricted
			// interface I of zone at border of loop. In this case, the
			// next interface is interface I again.
			if fromIn != nil {
				fromIn.setPath(toStore, toOut)
			} else {
				fromStore.setPath1(toStore, toOut)
			}
			return true
		}

		// Paths meet inside a loop.
		if fromLoop != nil && toLoop != nil && fromLoop.clusterExit == toLoop.clusterExit {
			return connectClusterPath(from, to, fromIn, toOut, fromStore, toStore)
		}

		// Otherwise, take a step towards zone1 from the more distant node.
		if from.getDistance() >= to.getDistance() { // Take step from node from.

			// Return, if mark has already been set for a sub-path.
			if fromIn != nil && fromIn.getPath()[toStore] != nil {
				return true
			}

			// Get interface towards zone1.
			fromOut := from.getToZone1()

			// If from is a loop node, mark whole loop path within this step.
			if fromOut == nil {

				// Reached border of graph partition.
				if fromLoop == nil {
					return false
				}

				// Get next interface behind loop from loop cluster exit.
				exit := fromLoop.clusterExit
				fromOut = exit.getToZone1()

				// Reached border of graph partition.
				if fromOut == nil {
					return false
				}

				// Mark loop path towards next interface.
				if !connectClusterPath(from, exit, fromIn, fromOut, fromStore, toStore) {
					return false
				}
			}

			// Mark path at the interface we came from (step in path direction)
			//           debug('pAth: ', from_in ? from_in->{name}:'', "from_store->{name} -> from_out->{name}");
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

				// Reached border of graph partition.
				if toLoop == nil {
					return false
				}

				// Get next interface behind loop from loop cluster exit.
				entry := toLoop.clusterExit
				toIn = entry.getToZone1()

				// Reached border of graph partition.
				if toIn == nil {
					return false
				}

				// Mark loop path towards next interface.
				if !connectClusterPath(entry, to, toIn, toOut, fromStore, toStore) {
					return false
				}
			}

			// Mark path at interface we go to (step in opposite path direction).
			//           debug("path: to_in->{name} -> to_store->{name}".(to_out ? to_out->{name}:''));
			toIn.setPath(toStore, toOut)
			to = toIn.toZone1
			toLoop = to.getLoop()

			// Go to next node towards zone1.
			toOut = toIn
		}
	}
}

//#############################################################################
// Purpose :    Walk loop section of a path from a rules source to its
//              destination. Apply given function to every zone or router
//              on loop path.
// Parameters : in - interface the loop is entered at.
//              out - interface loop is left at.
//              loop_entry - entry object, holding path information.
//              loop_exit - loop exit node.
//              call_at_zone - flag for node function is to be called at
//                              (1 - zone. 0 - router)
//              rule - elementary rule providing source and destination.
//              fun - Function to be applied.

func loopPathWalk(in, out *routerIntf, loopEntry, loopExit pathStore, callAtZone bool, rule *groupedRule, fun func(r *groupedRule, i, o *routerIntf)) bool {

	//    my info = "loop_path_walk: ";
	//    info .= "in->{name}->" if in;
	//    info .= "loop_entry->{name}=>loop_exit->{name}";
	//    info .= "->out->{name}" if out;
	//    debug(info);

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
	var pathTuples tupleList
	if callAtZone {
		pathTuples = lPath.zoneTuples
	} else {
		pathTuples = lPath.routerTuples
	}

	//    debug(" loop_tuples");
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
		//        debug(" loop_leave");
		for _, inIntf := range lPath.leave {
			fun(rule, inIntf, out)
		}
	}
	return callIt
}

func showErrNoValidPath(srcPath, dstPath pathStore, context string) {
	zone1 := findZone1(srcPath)
	zone2 := findZone1(dstPath)
	var msg string
	if zone1.partition != zone2.partition {
		msg = " Source && destination objects are located in " +
			"different topology partitions: " +
			zone1.partition + ", " + zone2.partition + "."
	} else {
		msg = " Check path restrictions && crypto interfaces."
	}
	errMsg("No valid path\n" +
		" from srcPath.name\n" +
		" to dstPath.name\n" +
		" context\n" +
		msg)
}

//#############################################################################
// Purpose    : For a given rule, visit every node on path from rules source
//              to its destination. At every second node (every router or
//              every zone node) call given function.
// Parameters : rule - rule object.
//              fun - function to be called.
//              where - 'Router' or 'Zone', specifies where the function gets
//              called, default is 'Router'.
func pathWalk(rule *groupedRule, fun func(r *groupedRule, i, o *routerIntf), where string) {

	// Extract path store objects (zone/router/pathrestricted interface).
	// These are typically zone or router objects:
	// - zone object for network or host,
	// - router object for interface without pathrestriction.
	// But for interface with pathrestriction, we may get different
	// paths for interfaces of the same router.
	// Hence we can't use the router but use interface object for
	// interface with pathrestriction.
	fromStore, toStore := rule.srcPath, rule.dstPath

	/*	debug(rule.print());
		debug(" start: %s, %s at %s",fromStore.getName(), toStore.getName(), where)
		fun2 := fun
		fun = func(rule *Rule, i, o *routerIntf) {
			var inName, outName string
			if i != nil {
				inName = i.name
			}
			if o != nil {
				outName = o.name
			}
			debug(" Walk: %s, %s", inName, outName)
			fun2(rule, i, o)
		}
	*/
	// Identify path from source to destination if not known.
	if _, found := fromStore.getPath1()[toStore]; !found {
		if !pathMark(fromStore, toStore) {
			delete(fromStore.getPath1(), toStore)

			// Abort, if path does not exist.
			showErrNoValidPath(fromStore, toStore, "for rule "+rule.print())
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
	atZone := where == "Zone"
	callIt := isRouter != atZone

	var in *routerIntf
	out := fromStore.getPath1()[toStore]
	var loopEntry pathStore

	// Path starts inside or at border of cyclic graph.
	//
	// Special case: Path starts at pathrestricted interface of
	// zone at border of loop and hence this pathrestriction will
	// not be activated. Use attribute loop_entry_zone, to find correct
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
		// Otherwise use attribute loop_entry, to find possibly
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

/*
func singlePathWalk
    (rule, fun, where) {
    src := rule.src
    dst := rule.dst
    rule.srcPath = obj2path[src] || getPathNode(src)
    rule.dstPath = obj2path[dst] || getPathNode(dst)
    return pathWalk(rule, fun, where)
}
*/

type NetOrRouter interface{}

var border2obj2auto = make(map[*routerIntf]map[NetOrRouter][]*routerIntf)

func setAutoIntfFromBorder(border *routerIntf) {
	var reachFromBorder func(*network, *routerIntf, map[NetOrRouter][]*routerIntf)
	reachFromBorder =
		func(network *network, inIntf *routerIntf, result map[NetOrRouter][]*routerIntf) {
			result[network] = append(result[network], inIntf)

			//    debug "network->{name}: in_intf->{name}";
			for _, intf := range network.interfaces {
				if intf == inIntf {
					continue
				}
				if intf.zone != nil {
					continue
				}
				if intf.origMain != nil {
					continue
				}
				router := intf.router
				if router.activePath {
					continue
				}
				router.activePath = true
				defer func() { router.activePath = false }()
				result[router] = append(result[router], intf)

				//            debug "router->{name}: interface->{name}";

				for _, outIntf := range router.interfaces {
					if outIntf == intf {
						continue
					}
					if outIntf.origMain != nil {
						continue
					}
					reachFromBorder(outIntf.network, outIntf, result)
				}
			}
		}
	result := make(map[NetOrRouter][]*routerIntf)
	reachFromBorder(border.network, border, result)
	for key, list := range result {
		seen := make(map[*routerIntf]bool)
		j := 0
		for _, intf := range list {
			if !seen[intf] {
				seen[intf] = true
				list[j] = intf
				j++
			}
		}
		result[key] = list[:j]
	}
	border2obj2auto[border] = result
}

// Find auto interface inside zone.
// border is interface at border of zone.
// src2 is unmanaged router or network inside zone.
func autoIntfInZone(border *routerIntf, src2 NetOrRouter) []*routerIntf {
	if border2obj2auto[border] == nil {
		setAutoIntfFromBorder(border)
	}
	return border2obj2auto[border][src2]
}

func addPathrestictedIntfs(path pathStore, obj NetOrRouter) []pathStore {
	result := []pathStore{path}
	switch x := path.(type) {
	case *router:
		for _, intf := range getIntf(x) {
			if intf.pathRestrict != nil {
				result = append(result, intf)
			}
		}
	}
	return result
}

/*
// src is an auto_interface or router.
// Result is the set of interfaces of src located at direction to dst.
func pathAutoIntfs(src, dst) {
    src2, managed :=
      isAutointerface(src)
      ? @{src}{ "object", "managed" }
      : (src, undef)
    dst2 := isAutointerface(dst) ? dst.object : dst

    srcPath := obj2path[src2] || getPathNode(src2)
    dstPath := obj2path[dst2] || getPathNode(dst2)
    if srcPath == dstPath { return }

    // Check path separately for interfaces with pathrestriction,
    // because path from inside the router to destination may be restricted.
    fromList := addPathrestictedIntfs(srcPath, src2)
    toList := addPathrestictedIntfs(dstPath, dst2)
    var result
    for _, fromStore := range fromList {
        for _, toStore := range toList {
            if ! fromStore.path1[toStore] {
                if ! pathMark(fromStore, toStore) {
                    delete fromStore.path1[toStore]
                    continue
                }
            }
            type := ref fromStore
            if (fromStore.loopEntryZone &&
                fromStore.loopEntryZone[toStore])
            {
                push result, fromStore
            }
            elsif (fromStore.loopEntry &&
                entry := fromStore.loopEntry[toStore])
            {
                exit := entry.loopExit[toStore]
                enter := entry.loopEnter[exit]
                if type == "Zone" {
                    push result, map { autoIntfInZone($_, src2) } enter
                }
                else if type == "Router" {
                    push result, enter
                }

                // type eq 'routerIntf'
                // Path is only ok, if it doesn't traverse
                // corrensponding router.
                // Path starts inside loop.
                // Check if some path doesn't traverse current router.
                // Then interface is ok as [auto] interface.
                else if fromStore.loop {
                    if grep { $_ == fromStore } enter {
                        push result, fromStore
                    }
                }
            }
            else {
                continue := fromStore.path1[toStore]
                if type == "Zone" {
                    push result, autoIntfInZone(continue, src2)
                }
                else if type == "Router" {
                    push result, continue
                }

                // else
                // type eq 'routerIntf'
                // routerIntf with pathrestriction at border of loop,
                // wont get additional path.
            }
        }
    }
    if ! result {
        showErrNoValidPath(srcPath, dstPath,
                               "while resolving src.name" .
                               " (destination is dst.name).")
        return
    }
    result = grep { $_.ip != "tunnel" } unique result

    bridgedCount := 0
    for _, interface := range result {

        // If device has virtual interface, main and virtual interface
        // are swapped.  Swap it back here because we need the
        // original main interface if an interface is used in a rule.
        if orig := interface.origMain {
            interface = orig
        }

        // Change bridge interface to layer3 interface.
        // Prevent duplicate layer3 interface.
        else if layer3Intf := interface.layer3routerIntf {
            interface = layer3Intf
            bridgedCount++
        }
    }
    if bridgedCount > 1 {
        result = unique(result)
    }

//    debug("src2->{name}.[auto] = ", join ',', map {$_->{name}} result);
    return (managed ? grep { $_.router.managed } result : result)
}
*/
