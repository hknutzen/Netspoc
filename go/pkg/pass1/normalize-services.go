package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"sort"
	"strings"
)

// Check for referencing log tags, that corresponding defining log tags exist.
func checkLog(log, ctx string) string {
	var known stringList
	for _, tag := range strings.Split(log, ",") {
		if !knownLog[tag] {
			warnMsg("Referencing unknown '%s' in log of %s", tag, ctx)
		} else {
			known.push(tag)
		}
	}
	return strings.Join(known, ",")
}

//#############################################################################
// Purpose    : Expand auto interface to one or more real interfaces
//              with respect to list of destination objects.
// Note       : Different destination objects may lead to different result lists.
// Result     : An array of pairs:
//              1. List of real interfaces.
//              2. Those objects from dst_list that lead to result in 1.

type expAutoPair struct {
	srcList srvObjList
	dstList groupObjList
}

type pathOrAuto interface{}

func pathAutoInterfaces(src *autoIntf, dst pathOrAuto, origDst groupObj) intfList {
	managed := src.managed
	srcPath := src.getPathNode()

	var dstPath pathStore
	var toList []pathStore
	switch x := dst.(type) {
	case *autoIntf:
		dstPath = x.getPathNode()
		toList = addPathrestictedIntfs(dstPath, x.object)
	case pathStore:
		dstPath = x
		toList = []pathStore{x}
	}
	if srcPath == dstPath {
		return nil
	}
	result := findAutoInterfaces(
		srcPath, dstPath, toList, src.name, origDst.String(), src.object)
	if managed {
		j := 0
		for _, intf := range result {
			if intf.router.managed != "" {
				result[j] = intf
				j++
			}
		}
		result = result[:j]
	}
	return result
}

func expandAutoIntfWithDstList(a *autoIntf, dstList groupObjList, ctx string) []*expAutoPair {
	path2pair := make(map[pathOrAuto]*expAutoPair)
	var result []*expAutoPair
	for _, dst := range dstList {
		var path pathOrAuto
		switch x := dst.(type) {
		case someObj:
			path = x.getPathNode()
		case *host:
			path = x.getPathNode()
		case *autoIntf:
			path = x
		}
		pair, found := path2pair[path]
		if !found {
			var real srvObjList
			for _, intf := range pathAutoInterfaces(a, path, dst) {
				if intf.short {
					errMsg("%s without IP address (from .[auto])\n"+
						" must not be used in rule of %s",
						intf.name, ctx)
				} else if intf.unnumbered {

					// Ignore unnumbered interfaces.
				} else {
					real.push(intf)
				}
			}

			if real != nil {

				// If identical result already was found with other destination,
				// then share this result for both destinations.
			PAIR:
				for _, pair2 := range result {
					if len(pair2.srcList) != len(real) {
						continue
					}
					for i, intf := range pair2.srcList {
						if real[i] != intf {
							continue PAIR
						}
						pair = pair2
						break PAIR
					}
				}
				if pair == nil {
					pair = &expAutoPair{srcList: real}
					result = append(result, pair)
				}
			}

			// Store nil for empty list of interfaces.
			path2pair[path] = pair
		}
		if pair != nil {
			pair.dstList.push(dst)
		}
	}
	return result
}

func substituteAutoIntf(srcList, dstList groupObjList, ctx string) (srvObjList, []*expAutoPair) {
	var convertedSrc srvObjList
	var resultPairList []*expAutoPair
	for _, src := range srcList {
		var a *autoIntf
		switch x := src.(type) {
		case srvObj:
			convertedSrc.push(x)
			continue
		case *autoIntf:
			a = x
		}
		pairList := expandAutoIntfWithDstList(a, dstList, ctx)

		// All elements of dstList lead to same result list of interfaces.
		if len(pairList) == 1 {
			for _, intf := range pairList[0].srcList {
				convertedSrc.push(intf)
			}
			continue
		}

		// Different destination objects lead to different result sets.
		// Skip auto interface in convertedSrc,
		// but add src/dst pairs to second return value.
		resultPairList = append(resultPairList, pairList...)
	}
	return convertedSrc, resultPairList
}

type modifiedProto struct {
	prt       *proto
	src       *proto
	modifiers *modifiers
}

func classifyProtocols(l []interface{}) (protoList, []*modifiedProto) {
	var simple protoList
	var complex []*modifiedProto
	for _, p := range l {

		// If p is duplicate of an identical protocol, use the
		// main protocol, but remember the original one to retrieve
		// .modifiers.
		var prt *proto
		var srcRange *proto
		var m *modifiers
		switch x := p.(type) {
		case *complexProto:
			srcRange, prt, m = x.src, x.dst, x.orig.modifiers
		case *proto:
			m = x.modifiers
			if x.main != nil {
				prt = x.main
			} else {
				prt = x
			}
		}

		if m != nil &&
			(m.reversed || m.stateless || m.oneway ||
				m.srcNet || m.dstNet || m.overlaps || m.noCheckSupernetRules) ||
			srcRange != nil || prt.statelessICMP {
			complex = append(complex, &modifiedProto{prt, srcRange, m})
		} else {
			simple.push(prt)
		}
	}
	return simple, complex
}

func normalizeSrcDstList(
	r *unexpRule, l groupObjList, s *service) [][2]srvObjList {

	ctx := s.name
	ipv6 := s.ipV6
	userObj.elements = l
	srcList := expandGroupInRule(r.src, "src of rule in "+ctx, ipv6)
	dstList := expandGroupInRule(r.dst, "dst of rule in "+ctx, ipv6)
	userObj.elements = nil

	// Expand auto interfaces in srcList.
	expSrcList, extraSrcDst := substituteAutoIntf(srcList, dstList, ctx)

	var extraResult [][2]srvObjList

	toGrp := func(l srvObjList) groupObjList {
		result := make(groupObjList, len(l))
		for i, obj := range l {
			result[i] = obj.(groupObj)
		}
		return result
	}
	toSrv := func(l groupObjList) srvObjList {
		result := make(srvObjList, len(l))
		for i, obj := range l {
			result[i] = obj.(srvObj)
		}
		return result
	}

	// Expand auto interfaces in dst of extraSrcDst.
	for _, pair := range extraSrcDst {
		sList, dList := pair.srcList, pair.dstList
		expDstList, extraDstSrc := substituteAutoIntf(dList, toGrp(sList), ctx)
		extraResult = append(extraResult, [2]srvObjList{sList, expDstList})
		for _, pair := range extraDstSrc {
			extraResult = append(
				extraResult, [2]srvObjList{toSrv(pair.dstList), pair.srcList})
		}
	}

	// Expand auto interfaces in dstList.
	expDstList, extraDstSrc :=
		substituteAutoIntf(dstList, toGrp(expSrcList), ctx)
	for _, pair := range extraDstSrc {
		extraResult = append(
			extraResult, [2]srvObjList{toSrv(pair.dstList), pair.srcList})
	}

	return append([][2]srvObjList{{expSrcList, expDstList}}, extraResult...)
}

func normalizeServiceRules(s *service) {
	ipv6 := s.ipV6
	ctx := s.name
	user := expandGroup(s.user, "user of "+ctx, ipv6, false)
	s.expandedUser = user
	ruleCount := 0

	for _, uRule := range s.rules {
		deny := uRule.action == "deny"
		var store *serviceRuleList
		if deny {
			store = &sRules.deny
		} else {
			store = &sRules.permit
		}
		log := uRule.log
		if log != "" {
			log = checkLog(log, ctx)
		}
		prtList := splitProtocols(uRule.prt)
		if prtList == nil {
			continue
		}
		simplePrtList, complexPrtList := classifyProtocols(prtList)
		process := func(elt groupObjList) {
			srcDstListPairs := normalizeSrcDstList(uRule, elt, s)
			for _, srcDstList := range srcDstListPairs {
				srcList, dstList := srcDstList[0], srcDstList[1]
				if srcList != nil || dstList != nil {
					ruleCount++
				}
				if srcList == nil && dstList == nil {
					continue
				}
				if s.disabled {
					continue
				}
				if simplePrtList != nil {
					rule := &serviceRule{
						deny: deny,
						src:  srcList,
						dst:  dstList,
						prt:  simplePrtList,
						log:  log,
						rule: uRule,
					}
					store.push(rule)
				}
				for _, c := range complexPrtList {
					prt, srcRange := c.prt, c.src
					var mod modifiers
					if c.modifiers != nil {
						mod = *c.modifiers
					}
					srcList, dstList := srcList, dstList
					if mod.reversed {
						srcList, dstList = dstList, srcList
					}
					rule := &serviceRule{
						deny:                 deny,
						src:                  srcList,
						dst:                  dstList,
						prt:                  protoList{prt},
						log:                  log,
						rule:                 uRule,
						srcRange:             srcRange,
						stateless:            mod.stateless,
						oneway:               mod.oneway,
						overlaps:             mod.overlaps,
						noCheckSupernetRules: mod.noCheckSupernetRules,
						srcNet:               mod.srcNet,
						dstNet:               mod.dstNet,
						reversed:             mod.reversed,
						statelessICMP:        prt.statelessICMP,
					}
					store.push(rule)
				}
			}
		}
		if s.foreach {
			for _, elt := range user {
				process(groupObjList{elt})
			}
		} else {
			process(user)
		}
	}
	if ruleCount == 0 && len(user) == 0 {
		warnMsg("Must not define %s with empty users and empty rules", ctx)
	}

	// Result is stored in global variable sRules.
}

func NormalizeServices() {
	diag.Progress("Normalizing services")

	var names stringList
	for n, _ := range symTable.service {
		names.push(n)
	}
	sort.Strings(names)
	for _, n := range names {
		normalizeServiceRules(symTable.service[n])
	}
}
