package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"sort"
	"strings"
)

type expandedRule struct {
	deny      bool
	stateless bool
	src       someObj
	dst       someObj
	srcRange  *proto
	prt       *proto
	log       string
	rule      *unexpRule
	redundant bool
	overlaps  bool
}

func fillExpandedRule(rule *groupedRule) *expandedRule {
	return &expandedRule{
		deny:      rule.deny,
		stateless: rule.stateless,
		log:       rule.log,
		srcRange:  rule.srcRange,
		rule:      rule.rule,
		overlaps:  rule.overlaps,
	}
}

func (r *groupedRule) print() string {
	e := fillExpandedRule(r)
	e.src = r.src[0]
	e.dst = r.dst[0]
	e.prt = r.prt[0]
	return e.print()
}

func (r *expandedRule) print() string {
	extra := ""
	if r.log != "" {
		extra += " log=" + r.log + ";"
	}
	if r.stateless {
		extra += " stateless"
	}
	var ipV6 bool
	origPrt := r.prt
	if oRule := r.rule; oRule != nil {
		s := oRule.service
		extra += " of " + s.name
		ipV6 = s.ipV6
		origPrt = getOrigPrt(r)
	}
	var action string
	if r.deny {
		action = "deny"
	} else {
		action = "permit"
	}
	pName := origPrt.name
	if ipV6 {
		pName = strings.Replace(pName, "icmp", "icmpv6", 1)
	}
	return fmt.Sprintf("%s src=%s; dst=%s; prt=%s;%s",
		action, r.src.String(), r.dst.String(), pName, extra)
}

func isSubRange(p *proto, o *proto) bool {
	l1, h1 := p.ports[0], p.ports[1]
	l2, h2 := o.ports[0], o.ports[1]
	return l2 <= l1 && h1 <= h2
}

func getOrigPrt(rule *expandedRule) *proto {
	prt := rule.prt
	proto := prt.proto
	oRule := rule.rule
	for _, oPrt := range oRule.prt {
		if proto != oPrt.proto {
			continue
		}
		switch oPrt.proto {
		case "tcp", "udp":
			if !isSubRange(prt, oPrt) {
				continue
			}
			srcRange := rule.srcRange
			if (srcRange == nil) !=
				(oPrt.modifiers == nil || oPrt.modifiers.srcRange == nil) {
				continue
			} else if srcRange == nil {
				return oPrt
			} else if isSubRange(srcRange, oPrt.modifiers.srcRange) {
				return oPrt
			}
		default:
			if mainPrt := oPrt.main; mainPrt != nil {
				if mainPrt == prt {
					return oPrt
				}
			}
		}
	}
	return prt
}

/*########################################################################
# Expand rules and check them for redundancy
########################################################################*/

// Derive reduced 'localUp' relation from 'up' relation between protocols.
// Reduced relation has only protocols that are referenced in list of rules.
// New relation is used in findRedundantRules.
// We get better performance compared to original relation, because
// transient chain from some protocol to largest protocol becomes shorter.
func setLocalPrtRelation(rules []*groupedRule) {
	prtMap := make(map[*proto]bool)
	for _, rule := range rules {
		prtList := rule.prt
		for _, prt := range prtList {
			prtMap[prt] = true
		}
	}
	for prt := range prtMap {
		var localUp *proto
		up := prt.up
		for up != nil {
			if prtMap[up] {
				localUp = up
				break
			}
			up = up.up
		}
		prt.localUp = localUp
	}
}

// Returns true, if overlap should be ignored.
func (c *spoc) checkAttrOverlaps(
	service, oservice *service, rule *expandedRule) bool {

	srcAttr := rule.src.getAttr("overlaps")
	dstAttr := rule.dst.getAttr("overlaps")
	overlapsUsed := func() bool {
		for _, overlap := range service.overlaps {
			if oservice == overlap {
				return true
			}
		}
		return false
	}
	if overlapsUsed() {
		service.overlapsUsed[oservice] = true
		if srcAttr == "restrict" && dstAttr == "restrict" {
			if !service.overlapsRestricted {
				service.overlapsRestricted = true
				c.warn("Must not use attribute 'overlaps' at %s", service.name)
			}
			return false
		}
		return true
	}
	if srcAttr == "ok" || dstAttr == "ok" {
		return true
	}
	return false
}

func (c *spoc) collectDuplicateRules(
	rule, other *expandedRule, collect *[][2]*expandedRule) {

	svc := rule.rule.service

	// Mark duplicate rules in both services.

	// But count each rule only once. For duplicate rules, this can
	// only occur for rule other, because all identical rules are
	// compared with other. But we need to mark rule as well, because
	// it must only be counted once, if it is both duplicate and
	// redundandant.
	rule.redundant = true
	svc.duplicateCount++
	osvc := other.rule.service
	if !other.redundant {
		osvc.duplicateCount++
		other.redundant = true
	}

	// Link both services, so we later show only one of both service as
	// redundant.
	if svc.hasSameDupl == nil {
		svc.hasSameDupl = make(map[*service]bool)
	}
	svc.hasSameDupl[osvc] = true
	if osvc.hasSameDupl == nil {
		osvc.hasSameDupl = make(map[*service]bool)
	}
	osvc.hasSameDupl[svc] = true

	// Return early, so overlapsUsed isn't set below.
	if rule.overlaps && other.overlaps {
		return
	}

	if c.checkAttrOverlaps(svc, osvc, rule) ||
		c.checkAttrOverlaps(osvc, svc, rule) {
		return
	}

	if conf.Conf.CheckDuplicateRules != "" {
		*collect = append(*collect, [2]*expandedRule{rule, other})
	}
}

type twoSvc [2]*service

func (c *spoc) showDuplicateRules(collected [][2]*expandedRule) {
	twoSvc2Duplicate := make(map[twoSvc][]*expandedRule)
	for _, pair := range collected {
		rule, other := pair[0], pair[1]
		key := twoSvc{rule.rule.service, other.rule.service}
		twoSvc2Duplicate[key] = append(twoSvc2Duplicate[key], rule)
	}
	for key, rules := range twoSvc2Duplicate {
		msg := "Duplicate rules in " + key[0].name + " and " + key[1].name + ":"
		for _, rule := range rules {
			msg += "\n  " + rule.print()
		}
		c.warnOrErr(conf.Conf.CheckDuplicateRules, msg)
	}
}

func (c *spoc) collectRedundantRules(
	rule, other *expandedRule, collect *[][2]*expandedRule) int {

	service := rule.rule.service
	count := 0

	// Count each redundant rule only once.
	if !rule.redundant {
		rule.redundant = true
		count++
		service.redundantCount++
	}

	if rule.overlaps && other.overlaps {
		return count
	}

	if !c.checkAttrOverlaps(service, other.rule.service, rule) {
		*collect = append(*collect, [2]*expandedRule{rule, other})
	}
	return count
}

func (c *spoc) showRedundantRules(collected [][2]*expandedRule) {
	action := conf.Conf.CheckRedundantRules
	if action == "" {
		return
	}
	twoSvc2Redundant := make(map[twoSvc][][2]*expandedRule)
	for _, pair := range collected {
		rule, other := pair[0], pair[1]
		key := twoSvc{rule.rule.service, other.rule.service}
		twoSvc2Redundant[key] = append(twoSvc2Redundant[key], pair)
	}
	for key, rulePairs := range twoSvc2Redundant {
		msg :=
			"Redundant rules in " + key[0].name +
				" compared to " + key[1].name + ":\n  "
		var list stringList
		for _, pair := range rulePairs {
			list.push(pair[0].print() + "\n< " + pair[1].print())
		}
		sort.Strings(list)
		msg += strings.Join(list, "\n  ")
		c.warnOrErr(action, msg)
	}
}

func (c *spoc) showFullyRedundantRules() {
	action := conf.Conf.CheckFullyRedundantRules
	if action == "" {
		return
	}
	sNames := make([]string, 0, len(symTable.service))
	for name := range symTable.service {
		sNames = append(sNames, name)
	}
	sort.Strings(sNames)
	keep := make(map[*service]bool)
	for _, name := range sNames {
		service := symTable.service[name]
		if keep[service] {
			continue
		}
		ruleCount := service.ruleCount
		if ruleCount == 0 {
			continue
		}
		if service.duplicateCount+service.redundantCount != ruleCount {
			continue
		}
		for service := range service.hasSameDupl {
			keep[service] = true
		}
		c.warnOrErr(action, service.name+" is fully redundant")
	}
}

func (c *spoc) warnUnusedOverlaps() {
	var errList []string
	for _, service := range symTable.service {
		if service.disabled {
			continue
		}
		if overlaps := service.overlaps; overlaps != nil {
			used := service.overlapsUsed
			for _, overlap := range overlaps {
				if overlap.disabled || used[overlap] {
					continue
				}
				errList = append(errList,
					fmt.Sprintf("Useless 'overlaps = %s' in %s",
						overlap.name, service.name))
			}
		}
	}
	sort.Strings(errList)
	for _, msg := range errList {
		c.warn(msg)
	}
}

// Expand path_rules to elementary rules.
func expandRules(rules []*groupedRule) []*expandedRule {
	var result []*expandedRule
	for _, rule := range rules {
		service := rule.rule.service
		for _, src := range rule.src {
			for _, dst := range rule.dst {
				for _, prt := range rule.prt {
					e := fillExpandedRule(rule)
					e.src = src
					e.dst = dst
					e.prt = prt
					result = append(result, e)
					service.ruleCount++
				}
			}
		}
	}
	return result
}

// Build rule tree of nested maps.
// Leaf node has rule as value.
type ruleTree1 map[*proto]*expandedRule
type ruleTree2 map[someObj]ruleTree1
type ruleTree3 map[someObj]ruleTree2
type ruleTree4 map[*proto]ruleTree3
type ruleTree5 map[bool]ruleTree4
type ruleTree map[bool]ruleTree5

func (tree ruleTree2) add(dst someObj) ruleTree1 {
	subtree, found := tree[dst]
	if !found {
		subtree = make(ruleTree1)
		tree[dst] = subtree
	}
	return subtree
}
func (tree ruleTree3) add(src someObj) ruleTree2 {
	subtree, found := tree[src]
	if !found {
		subtree = make(ruleTree2)
		tree[src] = subtree
	}
	return subtree
}
func (tree ruleTree4) add(srcRange *proto) ruleTree3 {
	subtree, found := tree[srcRange]
	if !found {
		subtree = make(ruleTree3)
		tree[srcRange] = subtree
	}
	return subtree
}
func (tree ruleTree5) add(deny bool) ruleTree4 {
	subtree, found := tree[deny]
	if !found {
		subtree = make(ruleTree4)
		tree[deny] = subtree
	}
	return subtree
}
func (tree ruleTree) add(stateless bool) ruleTree5 {
	subtree, found := tree[stateless]
	if !found {
		subtree = make(ruleTree5)
		tree[stateless] = subtree
	}
	return subtree
}

// Build rule tree from expanded rules for efficient comparison of rules.
// Rule tree is a nested map for ordering all rules.
// Put attributes with small value set first, to get a more
// memory efficient tree with few branches at root.
func (c *spoc) buildRuleTree(
	rules []*expandedRule, collect *[][2]*expandedRule) (ruleTree, int) {
	count := 0
	ruleTree := make(ruleTree)

	// Simpler version of rule tree. It is used for rules without attributes
	// deny, stateless and srcRange.
	simpleTree := make(ruleTree3)

	for _, rule := range rules {
		srcRange := rule.srcRange
		var midTree ruleTree3

		if rule.deny || rule.stateless || srcRange != nil {
			if srcRange == nil {
				srcRange = prtIP
			}
			midTree = ruleTree.add(rule.stateless).add(rule.deny).add(srcRange)
		} else {
			midTree = simpleTree
		}
		leafMap := midTree.add(rule.src).add(rule.dst)

		if otherRule, found := leafMap[rule.prt]; found {
			if rule.log != otherRule.log {
				c.err(
					"Duplicate rules must have identical log attribute:\n %s\n %s",
					otherRule.print(), rule.print())
			}

			// Found identical rule.
			c.collectDuplicateRules(rule, otherRule, collect)
			count++
		} else {
			leafMap[rule.prt] = rule
		}
	}

	// Insert simpleTree into ruleTree.
	if len(simpleTree) != 0 {
		ruleTree.add(false).add(false)[prtIP] = simpleTree
	}
	return ruleTree, count
}

func (c *spoc) findRedundantRules(
	cmpHash ruleTree, collect *[][2]*expandedRule) int {

	chgHash := cmpHash
	count := 0
	for stateless, chgHash := range chgHash {
		for {
			if cmpHash, found := cmpHash[stateless]; found {
				for deny, chgHash := range chgHash {
					for {
						if cmpHash, found := cmpHash[deny]; found {
							for srcRange, chgHash := range chgHash {
								for {
									if cmpHash, found := cmpHash[srcRange]; found {
										for src, chgHash := range chgHash {
											for {
												if cmpHash, found := cmpHash[src]; found {
													for dst, chgHash := range chgHash {
														for {
															if cmpHash, found := cmpHash[dst]; found {
																for prt, chgRule := range chgHash {
																	for {
																		if cmpRule, found :=
																			cmpHash[prt]; found {
																			if cmpRule !=
																				chgRule &&
																				cmpRule.log ==
																					chgRule.log {
																				count += c.collectRedundantRules(chgRule, cmpRule, collect)
																			}
																		}
																		prt = prt.localUp
																		if prt == nil {
																			break
																		}
																	}
																}
															}
															dst = dst.getUp()
															if dst == nil {
																break
															}
														}
													}
												}
												src = src.getUp()
												if src == nil {
													break
												}
											}
										}
									}
									srcRange = srcRange.up
									if srcRange == nil {
										break
									}
								}
							}
						}
						if deny {
							break
						}
						deny = true
					}
				}
			}
			if !stateless {
				break
			}
			stateless = false
		}
	}
	return count
}

func (c *spoc) checkRedundantRules() {
	c.progress("Checking for redundant rules")

	// Sorts error messages before output.
	c2 := c.sortingSpoc()

	var collectDupl, collectRedun [][2]*expandedRule
	count := 0
	dcount := 0
	rcount := 0

	// Process rules in chunks to reduce memory usage and allow
	// concurrent processing. Rules with different srcPath / dstPath
	// can't be redundant to each other.
	type pathPair [2]pathStore
	path2rules := make(map[pathPair][]*groupedRule)
	add := func(rules []*groupedRule) {
		for _, rule := range rules {
			key := pathPair{rule.srcPath, rule.dstPath}
			path2rules[key] = append(path2rules[key], rule)
		}
	}
	add(c.allPathRules.deny)
	add(c.allPathRules.permit)
	for _, rules := range path2rules {
		expandedRules := expandRules(rules)
		count += len(expandedRules)
		ruleTree, deleted := c2.buildRuleTree(expandedRules, &collectDupl)
		dcount += deleted
		setLocalPrtRelation(rules)
		rcount += c2.findRedundantRules(ruleTree, &collectRedun)
	}

	c2.showDuplicateRules(collectDupl)
	c2.showRedundantRules(collectRedun)
	c2.finish()
	c.warnUnusedOverlaps()
	c.showFullyRedundantRules()
	c.info("Expanded rule count: %d; duplicate: %d; redundant: %d",
		count, dcount, rcount)
}
