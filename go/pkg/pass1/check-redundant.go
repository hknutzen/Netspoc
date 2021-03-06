package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"sort"
	"strings"
)

type redundInfo struct {
	duplicate          [][2]*expandedRule
	redundant          [][2]*expandedRule
	hasSameDupl        map[*service]map[*service]bool
	overlapsUsed       map[[2]*service]bool
	overlapsRestricted map[*service]bool
}

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
	origPrt := r.prt
	if oRule := r.rule; oRule != nil {
		s := oRule.service
		extra += " of " + s.name
		origPrt = getOrigPrt(r)
	}
	var action string
	if r.deny {
		action = "deny"
	} else {
		action = "permit"
	}
	pName := origPrt.name
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
	sv, osv *service, rule *expandedRule, ri *redundInfo) bool {

	srcAttr := getAttr(rule.src, overlapsAttr)
	dstAttr := getAttr(rule.dst, overlapsAttr)
	overlapsUsed := func() bool {
		for _, overlap := range sv.overlaps {
			if osv == overlap {
				return true
			}
		}
		return false
	}
	if overlapsUsed() {
		ri.overlapsUsed[[2]*service{sv, osv}] = true
		if srcAttr == restrictVal && dstAttr == restrictVal {
			if !ri.overlapsRestricted[sv] {
				ri.overlapsRestricted[sv] = true
				c.warn("Must not use attribute 'overlaps' at %s", sv)
			}
			return false
		}
		return true
	}
	if srcAttr == okVal || dstAttr == okVal {
		return true
	}
	return false
}

func (c *spoc) collectDuplicateRules(
	rule, other *expandedRule, ri *redundInfo) {

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

	// Link redundant service, so we later show only one of both services as
	// fully redundant.
	// Link only from small to large service, because services are
	// processed ordered by sorted names later.
	link := func(s, o *service) {
		m := ri.hasSameDupl[s]
		if m == nil {
			m = make(map[*service]bool)
			ri.hasSameDupl[s] = m
		}
		m[o] = true
	}
	if svc.name < osvc.name {
		link(svc, osvc)
	} else if svc.name > osvc.name {
		link(osvc, svc)
	}

	// Return early, so overlapsUsed isn't set below.
	if rule.overlaps && other.overlaps {
		return
	}

	if c.checkAttrOverlaps(svc, osvc, rule, ri) ||
		c.checkAttrOverlaps(osvc, svc, rule, ri) {
		return
	}

	if conf.Conf.CheckDuplicateRules != "" {
		ri.duplicate = append(ri.duplicate, [2]*expandedRule{rule, other})
	}
}

type twoSvc [2]*service

func (c *spoc) showDuplicateRules(ri *redundInfo) {
	twoSvc2Duplicate := make(map[twoSvc][]*expandedRule)
	for _, pair := range ri.duplicate {
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
	rule, other *expandedRule, ri *redundInfo) int {

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

	if !c.checkAttrOverlaps(service, other.rule.service, rule, ri) {
		ri.redundant = append(ri.redundant, [2]*expandedRule{rule, other})
	}
	return count
}

func (c *spoc) showRedundantRules(ri *redundInfo) {
	action := conf.Conf.CheckRedundantRules
	if action == "" {
		return
	}
	twoSvc2Redundant := make(map[twoSvc][][2]*expandedRule)
	for _, pair := range ri.redundant {
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

func (c *spoc) showFullyRedundantRules(ri *redundInfo) {
	action := conf.Conf.CheckFullyRedundantRules
	if action == "" {
		return
	}
	sNames := make(stringList, 0, len(symTable.service))
	for name := range symTable.service {
		sNames.push(name)
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
		for other := range ri.hasSameDupl[service] {
			keep[other] = true
		}
		c.warnOrErr(action, service.name+" is fully redundant")
	}
}

func (c *spoc) warnUnusedOverlaps(ri *redundInfo) {
	var errList stringList
	for _, sv := range symTable.service {
		if sv.disabled {
			continue
		}
		used := ri.overlapsUsed
		for _, overlap := range sv.overlaps {
			if !(overlap.disabled || used[[2]*service{sv, overlap}]) {
				errList.push(
					fmt.Sprintf("Useless 'overlaps = %s' in %s", overlap, sv))
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
	rules []*expandedRule, ri *redundInfo) (ruleTree, int) {
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
				srcRange = c.prt.IP
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
			c.collectDuplicateRules(rule, otherRule, ri)
			count++
		} else {
			leafMap[rule.prt] = rule
		}
	}

	// Insert simpleTree into ruleTree.
	if len(simpleTree) != 0 {
		ruleTree.add(false).add(false)[c.prt.IP] = simpleTree
	}
	return ruleTree, count
}

func (c *spoc) findRedundantRules(cmpHash ruleTree, ri *redundInfo) int {
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
																				count += c.collectRedundantRules(chgRule, cmpRule, ri)
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

	count := 0
	dcount := 0
	rcount := 0
	ri := new(redundInfo)
	ri.hasSameDupl = make(map[*service]map[*service]bool)
	ri.overlapsUsed = make(map[[2]*service]bool)
	ri.overlapsRestricted = make(map[*service]bool)

	// Sorts error messages before output.
	c.sortedSpoc(func(c *spoc) {

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
			ruleTree, deleted := c.buildRuleTree(expandedRules, ri)
			dcount += deleted
			setLocalPrtRelation(rules)
			rcount += c.findRedundantRules(ruleTree, ri)
		}

		c.showDuplicateRules(ri)
		c.showRedundantRules(ri)
	})
	c.warnUnusedOverlaps(ri)
	c.showFullyRedundantRules(ri)
	c.info("Expanded rule count: %d; duplicate: %d; redundant: %d",
		count, dcount, rcount)
}
