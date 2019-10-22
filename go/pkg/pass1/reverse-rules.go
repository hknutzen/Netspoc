package pass1

import ()

//#############################################################################
// Generate reverse rules for stateless packet filters:
// For each rule with protocol tcp, udp or ip we need a reverse rule
// with swapped src, dst and src-port, dst-port.
// For rules with a tcp protocol, the reverse rule gets a tcp protocol
// without range checking but with checking for 'established` flag.
//#############################################################################

func genReverseRules1(rules []*groupedRule) []*groupedRule {
	var extraRules []*groupedRule
	type pair struct {
		srcPath pathStore
		dstPath pathStore
	}
	cache := make(map[pair]bool)
	for _, rule := range rules {
		if rule.oneway {
			continue
		}
		var newPrtGroup []*proto
		var tcpSeen bool
		for _, prt := range rule.prt {
			proto := prt.proto
			if proto == "tcp" {

				// Create tcp established only once.
				if tcpSeen {
					continue
				}
				tcpSeen = true

				// No reverse rules will be generated for denied TCP
				// packets, because
				// - there can't be an answer if the request is already
				//   denied and
				// - the 'established' optimization for TCP below would
				//   produce wrong results.
				if rule.deny {
					continue
				}
			} else if !(proto == "udp" || proto == "ip") {
				continue
			}
			newPrtGroup = append(newPrtGroup, prt)
		}
		if newPrtGroup == nil {
			continue
		}

		// Check path for existence of stateless router.
		srcPath := rule.srcPath
		dstPath := rule.dstPath
		hasStatelessRouter, ok := cache[pair{srcPath, dstPath}]
		if !ok {

			// Local function called by path_walk.
			// It uses free variable hasStatelessRouter.
			markReverseRule := func(r *groupedRule, inIntf, outIntf *routerIntf) {

				// Destination of current rule is current router.
				// Outgoing packets from a router itself are never filtered.
				// Hence we don't need a reverse rule for current router.
				if outIntf == nil {
					return
				}
				router := outIntf.router

				// It doesn't matter if a semi Managed device is stateless
				// because no code is generated.
				if router.managed == "" {
					return
				}
				model := router.model

				if model.stateless ||
					// Source of current rule is current router.
					inIntf == nil && model.statelessSelf {
					hasStatelessRouter = true
				}
			}

			pathWalk(rule, markReverseRule, "Router")
			cache[pair{srcPath, dstPath}] = hasStatelessRouter
		}
		if !hasStatelessRouter {
			continue
		}

		// Create reverse rule.
		// Create new rule for different values of srcRange.
		// Preserve original order of protocols mostly,
		// but order by srcrange.
		var srcRangeList []*proto
		srcRange2prtList := make(map[*proto][]*proto)
		for _, prt := range newPrtGroup {
			newSrcRange := prtIP
			var newPrt *proto
			switch prt.proto {
			case "tcp":
				newPrt = rangeTCPEstablished
			case "udp":
				// Swap src and dst range.
				if !(prt.ports[0] == 1 && prt.ports[1] == 65535) {
					newSrcRange = prt
				}
				if rule.srcRange != nil {
					newPrt = rule.srcRange
				} else {
					newPrt = prtUDP.dst
				}
			default: // proto == "ip"
				newPrt = prt
			}
			prev, ok := srcRange2prtList[newSrcRange]
			if !ok {
				srcRangeList = append(srcRangeList, newSrcRange)
			}
			srcRange2prtList[newSrcRange] = append(prev, newPrt)
		}

		for _, srcRange := range srcRangeList {
			prtList := srcRange2prtList[srcRange]
			newRule := &groupedRule{
				serviceRule: &serviceRule{
					// This rule must only be applied to stateless routers.
					stateless: true,
					deny:      rule.deny,
					prt:       prtList,
				},
				src:     rule.dst,
				dst:     rule.src,
				srcPath: dstPath,
				dstPath: srcPath,
			}
			if srcRange != prtIP {
				newRule.srcRange = srcRange
			}

			// Don't modify rules while we are iterating over it.
			extraRules = append(extraRules, newRule)
		}
	}
	return append(rules, extraRules...)
}

func GenReverseRules() {
	progress("Generating reverse rules for stateless routers")
	pRules.deny = genReverseRules1(pRules.deny)
	pRules.permit = genReverseRules1(pRules.permit)
}
