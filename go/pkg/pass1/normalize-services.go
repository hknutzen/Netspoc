package pass1

import (
	"net/netip"
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
	src *autoIntf, dst pathOrAuto, origDst groupObj,
) intfList {
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
	if srcPath == dstPath || srcPath.isIPv6() != dstPath.isIPv6() {
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
						" must not be used in rule of %s", intf, ctx)
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

func splitCombined46(l groupObjList) (v4, v6 groupObjList, v46 bool) {
	for _, obj := range l {
		if obj.isCombined46() {
			v46 = true
		}
		if obj.isIPv6() {
			v6.push(obj)
		} else {
			v4.push(obj)
		}
	}
	return
}

func (c *spoc) normalizeSrcDstList(
	r *unexpRule, l groupObjList, s *service) ([][2]srvObjList, bool) {

	ctx := s.name
	c.userObj.elements = l
	srcList := c.expandGroupInRule(r.src, "src of rule in "+ctx)
	dstList := c.expandGroupInRule(r.dst, "dst of rule in "+ctx)
	c.userObj.elements = nil

	srcList4, srcList6, srcHas46 := splitCombined46(srcList)
	dstList4, dstList6, dstHas46 := splitCombined46(dstList)
	has46 := srcHas46 || dstHas46
	if has46 {
		if s.ipV4Only {
			srcList6 = c.filterV46Only(srcList6, s.ipV4Only, s.ipV6Only, s.name)
			dstList6 = c.filterV46Only(dstList6, s.ipV4Only, s.ipV6Only, s.name)
			has46 = false
		}
		if s.ipV6Only {
			srcList4 = c.filterV46Only(srcList4, s.ipV4Only, s.ipV6Only, s.name)
			dstList4 = c.filterV46Only(dstList4, s.ipV4Only, s.ipV6Only, s.name)
			has46 = false
		}
	} else {
		if s.ipV4Only {
			c.err("Must not use 'ipv4_only' in %s,"+
				" because no combined IPv4/IPv6 objects are in use", s)
		}
		if s.ipV6Only {
			c.err("Must not use 'ipv6_only' in %s,"+
				" because no combined IPv4/IPv6 objects are in use", s)
		}
		if srcList4 != nil && dstList6 != nil {
			c.err("Must not use IPv4 %s and IPv6 %s together in %s",
				srcList4[0], dstList6[0], s)
		} else if srcList6 != nil && dstList4 != nil {
			c.err("Must not use IPv6 %s and IPv4 %s together in %s",
				srcList6[0], dstList4[0], s)
		}
	}

	var resultPairs [][2]srvObjList
	process := func(srcList, dstList groupObjList) {
		if srcList == nil && dstList == nil {
			return
		}
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
		addExtra := func(extraDstSrc []*expAutoPair) {
			for _, pair := range extraDstSrc {
				extraResult = append(
					extraResult, [2]srvObjList{toSrv(pair.dstList), pair.srcList})
			}
		}

		// Expand auto interfaces in dst of extraSrcDst.
		for _, pair := range extraSrcDst {
			sList, dList := pair.srcList, pair.dstList
			expDstList, extraDstSrc :=
				c.substituteAutoIntf(dList, toGrp(sList), ctx)
			extraResult = append(extraResult, [2]srvObjList{sList, expDstList})
			addExtra(extraDstSrc)
		}

		// Expand auto interfaces in dstList.
		expDstList, extraDstSrc :=
			c.substituteAutoIntf(dstList, toGrp(expSrcList), ctx)
		addExtra(extraDstSrc)

		if expSrcList == nil && expDstList == nil {
			return
		}
		resultPairs = append(resultPairs, [2]srvObjList{expSrcList, expDstList})
		resultPairs = append(resultPairs, extraResult...)
	}
	process(srcList4, dstList4)
	process(srcList6, dstList6)
	return resultPairs, has46
}

func (c *spoc) normalizeServiceRules(s *service, sRules *serviceRules) {
	user := c.expandUser(s)
	hasRules := false
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
			srcDstListPairs, has46 := c.normalizeSrcDstList(uRule, elt, s)
			for _, srcDstList := range srcDstListPairs {
				srcList, dstList := srcDstList[0], srcDstList[1]
				if srcList != nil || dstList != nil {
					hasRules = true
				}
				if srcList == nil || dstList == nil || s.disabled {
					continue
				}
				v6Active := srcList[0].isIPv6()
				l := c.checkProtoListV4V6(simplePrtList, v6Active, has46, s.name)
				rule := serviceRule{
					deny: deny,
					src:  srcList,
					dst:  dstList,
					prt:  l,
					log:  log,
					rule: uRule,
				}
				if l != nil {
					store.push(&rule)
				}
				for _, compl := range complexPrtList {
					prt, srcRange := compl.prt, compl.src
					l := protoList{prt}
					l = c.checkProtoListV4V6(l, v6Active, has46, s.name)
					if l == nil {
						continue
					}
					r2 := rule
					if compl.modifiers != nil {
						r2.modifiers = *compl.modifiers
						if compl.modifiers.reversed {
							r2.src, r2.dst = rule.dst, rule.src
						}
					}
					r2.prt = l
					r2.srcRange = srcRange
					r2.statelessICMP = prt.statelessICMP
					store.push(&r2)
				}
			}
		}
		if s.foreach {
			// Must not split aggregate set of zone cluster.
			// Otherwise we would get wrong result for interface[user].[all].
			var cluster *zone
			var ipp netip.Prefix
			clusterIdx := 0
			for i, elt := range user {
				if n, ok := elt.(*network); ok {
					cl := n.zone.cluster[0]
					if cl == cluster && n.ipp == ipp {
						continue
					} else {
						cluster = cl
						ipp = n.ipp
					}
				}
				process(user[clusterIdx:i])
				clusterIdx = i
			}
			process(user[clusterIdx:])
		} else {
			process(user)
		}
	}
	if !hasRules && len(user) == 0 {
		c.warn("Must not define %s with empty users and empty rules", s.name)
	}
}

func (c *spoc) normalizeServices() *serviceRules {
	c.progress("Normalizing services")
	sRules := new(serviceRules)
	for _, sv := range c.ascendingServices {
		c.normalizeServiceRules(sv, sRules)
	}
	return sRules
}
