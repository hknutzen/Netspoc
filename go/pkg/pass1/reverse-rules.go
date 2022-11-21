package pass1

//#############################################################################
// Generate reverse rules for stateless packet filters:
// For each rule with protocol tcp, udp or ip we need a reverse rule
// with swapped src, dst and src-port, dst-port.
// For rules with a tcp protocol, the reverse rule gets a tcp protocol
// without range checking but with checking for 'established` flag.
//#############################################################################

func (c *spoc) genReverseRules1(rules []*groupedRule) []*groupedRule {
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
			markReverseRule := func(_ *groupedRule, inIntf, outIntf *routerIntf) {

				// Destination of current rule is current router.
				// Outgoing packets from a router itself are never filtered.
				// Hence we don't need a reverse rule for current router.
				if outIntf == nil {
					return
				}
				r := outIntf.router

				// It doesn't matter if a semi Managed device is stateless
				// because no code is generated.
				if r.managed == "" {
					return
				}
				model := r.model

				if model.stateless ||
					// Source of current rule is current router.
					inIntf == nil && model.statelessSelf {
					hasStatelessRouter = true
				}
			}

			c.pathWalk(rule, markReverseRule, "Router")
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
			newSrcRange := c.prt.IP
			var newPrt *proto
			switch prt.proto {
			case "tcp":
				newPrt = c.prt.TCPEsta
			case "udp":
				// Swap src and dst range.
				if !(prt.ports[0] == 1 && prt.ports[1] == 65535) {
					newSrcRange = prt
				}
				if rule.srcRange != nil {
					newPrt = rule.srcRange
				} else {
					newPrt = c.prt.UDP
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
					modifiers: modifiers{stateless: true},
					deny:      rule.deny,
					prt:       prtList,
				},
				src:     rule.dst,
				dst:     rule.src,
				srcPath: dstPath,
				dstPath: srcPath,
			}
			if srcRange != c.prt.IP {
				newRule.srcRange = srcRange
			}

			// This will not affect current iteration over rules.
			rules = append(rules, newRule)
		}
	}
	return rules
}

func (c *spoc) genReverseRules() {
	c.progress("Generating reverse rules for stateless routers")
	c.allPathRules.deny = c.genReverseRules1(c.allPathRules.deny)
	c.allPathRules.permit = c.genReverseRules1(c.allPathRules.permit)
}
