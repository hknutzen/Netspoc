package pass1

import (
	"fmt"
	"sort"
	"strings"
)

type objPair [2]someObj
type svc2unenforceable map[*service]map[objPair]bool

// This handles a rule between objects inside a single security zone or
// between interfaces of a single managed router.
// Suppress warning or error message for user-user rule
// - different interfaces or
// - different networks or
// - subnets/hosts of different networks.
// Rules between identical objects are silently ignored.
// But a message is shown if a service only has rules between identical objects.
func (c *spoc) collectUnenforceable(rule *groupedRule, s2u svc2unenforceable) {
	uRule := rule.rule
	sv := uRule.service
	pairs := s2u[sv]
	if uRule.hasUser == "both" && !sv.foreach {
		if pairs == nil {
			s2u[sv] = nil
		}
		return
	}
	if pairs == nil {
		pairs = make(map[objPair]bool)
		s2u[sv] = pairs
	}
	if c.conf.CheckUnenforceable == "" {
		return
	}
	for _, src := range rule.src {
		for _, dst := range rule.dst {
			if !pairs[objPair{src, dst}] {
				srcAttr := getAttr(src, hasUnenforceableAttr)
				dstAttr := getAttr(dst, hasUnenforceableAttr)
				if sv.hasUnenforceable {
					if srcAttr == restrictVal && dstAttr == restrictVal {
						if !sv.hasUnenforceableRestricted {
							sv.hasUnenforceableRestricted = true
							c.warn("Attribute 'has_unenforceable' is blocked at %s", sv)
						}
					} else {
						continue
					}
				} else if srcAttr == okVal || dstAttr == okVal {
					continue
				}
				pairs[objPair{src, dst}] = true
			}
		}
	}
}

func (c *spoc) showUnenforceable(s2u svc2unenforceable) {
	for _, sv := range c.ascendingServices {
		pairs, found := s2u[sv]
		if sv.hasUnenforceable && (pairs == nil || !sv.seenEnforceable) {
			c.uselessSvcAttr("has_unenforceable", sv)
		}
		// Warning about fully unenforceable service can't be suppressed by
		// attribute has_unenforceable.
		if !sv.seenEnforceable {
			// Don't warn on empty service without any expanded rules.
			if found {
				c.warnOrErr(c.conf.CheckUnenforceable,
					"No firewalls found between all source/destination pairs of %s",
					sv)
			}
		} else if len(pairs) != 0 {
			var list stringList
			for pair := range pairs {
				src, dst := pair[0], pair[1]
				list.push(fmt.Sprintf("src=%s; dst=%s", src, dst))
			}
			sort.Strings(list)
			c.warnOrErr(c.conf.CheckUnenforceable,
				"Some source/destination pairs of %s don't affect any firewall:\n"+
					" %s",
				sv, strings.Join(list, "\n "))
		}
	}
}

func (c *spoc) isUnenforceableRule(rule *groupedRule, s2u svc2unenforceable,
) bool {
	srcZone := rule.srcPath.getZone()
	dstZone := rule.dstPath.getZone()
	if zoneEq(srcZone, dstZone) {
		c.collectUnenforceable(rule, s2u)
		return true
	}

	// At least one rule of service is enforceable.
	// This is used to decide, if a service is fully unenforceable.
	rule.rule.service.seenEnforceable = true

	return false
}

//#######################################################################
// Convert normalized service rules to grouped path rules.
//#######################################################################

type groupWithPath struct {
	path  pathStore
	group []someObj
}

// Collect elements into groups of elements from identical zone.
// Put multiple interfaces of managed router always into different
// groups, even if router is identical.
func splitRuleGroup(group []someObj) []groupWithPath {
	// Check if group has elements from different zones and must be split.
	path0 := group[0].getPathNode()
	different := false
	for _, el := range group[1:] {
		if _, ok := el.(*routerIntf); ok || path0 != el.getPathNode() {
			different = true
			break
		}
	}
	if !different {
		// Use unchanged group, add path info.
		return []groupWithPath{{path0, group}}
	}
	path2group := make(map[pathStore][]someObj)
	var result []groupWithPath
	for _, el := range group {
		path := el.getPathNode()
		if _, ok := el.(*routerIntf); ok {
			result = append(result, groupWithPath{path, []someObj{el}})
			continue
		}
		if path2group[path] == nil {
			result = append(result, groupWithPath{path, nil})
		}
		path2group[path] = append(path2group[path], el)
	}
	for i, pair := range result {
		// Add elements of zones.
		// Ignore already inserted interface of managed router.
		if pair.group == nil {
			result[i].group = path2group[pair.path]
		}
	}
	return result
}

func (c *spoc) splitRulesByPath(rules ruleList, s2u svc2unenforceable,
) ruleList {
	var newRules ruleList
	for _, sRule := range rules {
		sGroupInfo := splitRuleGroup(sRule.src)
		dGroupInfo := splitRuleGroup(sRule.dst)
		for _, sInfo := range sGroupInfo {
			for _, dInfo := range dGroupInfo {
				rule := new(groupedRule)
				rule.serviceRule = sRule.serviceRule
				rule.srcPath = sInfo.path
				rule.dstPath = dInfo.path
				rule.src = sInfo.group
				rule.dst = dInfo.group
				if c.isUnenforceableRule(rule, s2u) {
					continue
				}
				newRules.push(rule)
			}
		}
	}
	return newRules
}

func (c *spoc) groupPathRules(p, d ruleList) {
	c.progress("Grouping rules")
	s2u := make(svc2unenforceable)

	// Split grouped rules such, that all elements of src and dst
	// have identical srcPath/dstPath.
	c.allPathRules.permit = c.splitRulesByPath(p, s2u)
	c.allPathRules.deny = c.splitRulesByPath(d, s2u)
	count := len(c.allPathRules.permit) + len(c.allPathRules.deny)
	c.info("Grouped rule count: %d", count)

	c.showUnenforceable(s2u)
}
