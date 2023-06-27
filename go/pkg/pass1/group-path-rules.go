package pass1

import (
	"fmt"
	"sort"
	"strings"
)

type objPair [2]someObj

// This handles a rule between objects inside a single security zone or
// between interfaces of a single managed router.
// Suppress warning or error message for user-user rule
// - different interfaces or
// - different networks or
// - subnets/hosts of different networks.
// Rules between identical objects are silently ignored.
// But a message is shown if a service only has rules between identical objects.
func (c *spoc) collectUnenforceable(rule *groupedRule) {
	uRule := rule.rule
	sv := uRule.service
	sv.seenUnenforceable = true
	if uRule.hasUser == "both" && !sv.foreach {
		return
	}
	if sv.unenforceableMap == nil {
		sv.unenforceableMap = make(map[objPair]bool)
	}
	if c.conf.CheckUnenforceable == "" {
		return
	}
	for _, src := range rule.src {
		for _, dst := range rule.dst {
			if !sv.unenforceableMap[objPair{src, dst}] {
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
				sv.unenforceableMap[objPair{src, dst}] = true
			}
		}
	}
}

func (c *spoc) showUnenforceable() {
	for _, sv := range c.ascendingServices {
		if sv.hasUnenforceable &&
			(sv.unenforceableMap == nil || !sv.seenEnforceable) {
			c.uselessSvcAttr("has_unenforceable", sv)
		}

		// Warning about fully unenforceable service can't be suppressed by
		// attribute has_unenforceable.
		if !sv.seenEnforceable {

			// Don't warn on empty service without any expanded rules.
			if sv.seenUnenforceable {
				c.warnOrErr(c.conf.CheckUnenforceable,
					"No firewalls found between all source/destination pairs of %s",
					sv)
			}
		} else if len(sv.unenforceableMap) != 0 {
			var list stringList
			for pair := range sv.unenforceableMap {
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

func (c *spoc) isUnenforceableRule(rule *groupedRule) bool {
	srcZone := rule.srcPath.getZone()
	dstZone := rule.dstPath.getZone()
	if zoneEq(srcZone, dstZone) {
		c.collectUnenforceable(rule)
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

func (c *spoc) splitRulesByPath(rules ruleList) ruleList {
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
				if c.isUnenforceableRule(rule) {
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

	// Split grouped rules such, that all elements of src and dst
	// have identical srcPath/dstPath.
	c.allPathRules.permit = c.splitRulesByPath(p)
	c.allPathRules.deny = c.splitRulesByPath(d)
	count := len(c.allPathRules.permit) + len(c.allPathRules.deny)
	c.info("Grouped rule count: %d", count)

	c.showUnenforceable()
}
