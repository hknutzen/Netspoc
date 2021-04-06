package pass1

import (
	"sort"
)

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

func (c *spoc) pathAutoInterfaces(
	src *autoIntf, dst pathOrAuto, origDst groupObj) intfList {

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
	result := c.findAutoInterfaces(
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

func (c *spoc) expandAutoIntfWithDstList(
	a *autoIntf, dstList groupObjList, ctx string) []*expAutoPair {

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
			for _, intf := range c.pathAutoInterfaces(a, path, dst) {
				switch intf.ipType {
				case shortIP:
					c.err("%s without IP address (from .[auto])\n"+
						" must not be used in rule of %s",
						intf.name, ctx)
				case unnumberedIP:
					// Ignore unnumbered interfaces.
				default:
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

func (c *spoc) substituteAutoIntf(
	srcList, dstList groupObjList, ctx string) (srvObjList, []*expAutoPair) {

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
		pairList := c.expandAutoIntfWithDstList(a, dstList, ctx)

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

func (c *spoc) normalizeSrcDstList(
	r *unexpRule, l groupObjList, s *service) [][2]srvObjList {

	ctx := s.name
	ipv6 := s.ipV6
	c.userObj.elements = l
	srcList := c.expandGroupInRule(r.src, "src of rule in "+ctx, ipv6)
	dstList := c.expandGroupInRule(r.dst, "dst of rule in "+ctx, ipv6)
	c.userObj.elements = nil

	// Expand auto interfaces in srcList.
	expSrcList, extraSrcDst := c.substituteAutoIntf(srcList, dstList, ctx)

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
		expDstList, extraDstSrc := c.substituteAutoIntf(dList, toGrp(sList), ctx)
		extraResult = append(extraResult, [2]srvObjList{sList, expDstList})
		for _, pair := range extraDstSrc {
			extraResult = append(
				extraResult, [2]srvObjList{toSrv(pair.dstList), pair.srcList})
		}
	}

	// Expand auto interfaces in dstList.
	expDstList, extraDstSrc :=
		c.substituteAutoIntf(dstList, toGrp(expSrcList), ctx)
	for _, pair := range extraDstSrc {
		extraResult = append(
			extraResult, [2]srvObjList{toSrv(pair.dstList), pair.srcList})
	}

	return append([][2]srvObjList{{expSrcList, expDstList}}, extraResult...)
}

func (c *spoc) normalizeServiceRules(s *service, sRules *serviceRules) {
	ipv6 := s.ipV6
	ctx := s.name
	user := c.expandGroup(s.user, "user of "+ctx, ipv6, false)
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
		prtList := uRule.prt
		if prtList == nil {
			continue
		}
		simplePrtList, complexPrtList := classifyProtocols(prtList)
		process := func(elt groupObjList) {
			srcDstListPairs := c.normalizeSrcDstList(uRule, elt, s)
			for _, srcDstList := range srcDstListPairs {
				srcList, dstList := srcDstList[0], srcDstList[1]
				if srcList != nil || dstList != nil {
					ruleCount++
				}
				if srcList == nil || dstList == nil {
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
					srcList, dstList := srcList, dstList
					var mod *modifiers
					if c.modifiers != nil {
						mod = c.modifiers
						if mod.reversed {
							srcList, dstList = dstList, srcList
						}
					}
					rule := &serviceRule{
						deny:          deny,
						src:           srcList,
						dst:           dstList,
						prt:           protoList{prt},
						log:           log,
						rule:          uRule,
						statelessICMP: prt.statelessICMP,
					}
					if mod != nil {
						rule.modifiers = *mod
					}
					rule.srcRange = srcRange
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
		c.warn("Must not define %s with empty users and empty rules", ctx)
	}
}

func (c *spoc) normalizeServices() *serviceRules {
	c.progress("Normalizing services")

	var names stringList
	for n, _ := range symTable.service {
		names.push(n)
	}
	sort.Strings(names)
	sRules := new(serviceRules)
	for _, n := range names {
		c.normalizeServiceRules(symTable.service[n], sRules)
	}
	return sRules
}
