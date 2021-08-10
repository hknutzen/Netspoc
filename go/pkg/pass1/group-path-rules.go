package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
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
func collectUnenforceable(rule *groupedRule) {
	sv := rule.rule.service
	sv.silentUnenforceable = true
	isCoupling := rule.rule.hasUser == "both"

	for _, src := range rule.src {
		for _, dst := range rule.dst {
			if isCoupling {
				continue
			}
			if sv.seenUnenforceable == nil {
				sv.seenUnenforceable = make(map[objPair]bool)
			}
			sv.seenUnenforceable[objPair{src, dst}] = true
		}
	}
}

func (c *spoc) showUnenforceable() {
	for _, sv := range c.ascendingServices {
		if sv.hasUnenforceable &&
			(sv.seenUnenforceable == nil || !sv.seenEnforceable) {
			c.warn("Useless attribute 'has_unenforceable' at %s", sv)
		}
		if conf.Conf.CheckUnenforceable == "" {
			continue
		}

		// Warning about fully unenforceable service can't be disabled with
		// attribute has_unenforceable.
		if !sv.seenEnforceable {

			// Don't warn on empty service without any expanded rules.
			if sv.seenUnenforceable != nil || sv.silentUnenforceable {
				c.warnOrErr(conf.Conf.CheckUnenforceable,
					"%s is fully unenforceable", sv)
			}
			continue
		}

		var list stringList
		for pair, _ := range sv.seenUnenforceable {
			src, dst := pair[0], pair[1]
			srcAttr := getAttr(src, hasUnenforceableAttr)
			dstAttr := getAttr(dst, hasUnenforceableAttr)
			if sv.hasUnenforceable {
				if srcAttr == restrictVal && dstAttr == restrictVal {
					if !sv.hasUnenforceableRestricted {
						sv.hasUnenforceableRestricted = true
						c.warn("Must not use attribute 'has_unenforceable' at %s", sv)
					}
				} else {
					continue
				}
			} else if srcAttr == okVal || dstAttr == okVal {
				continue
			}
			list.push(fmt.Sprintf("src=%s; dst=%s", src, dst))
		}
		if list != nil {
			sort.Strings(list)
			c.warnOrErr(conf.Conf.CheckUnenforceable,
				"%s has unenforceable rules:\n"+
					" %s",
				sv, strings.Join(list, "\n "))
		}
	}
}

func removeUnenforceableRules(rules ruleList) ruleList {
	changed := false
	for i, rule := range rules {
		srcZone := rule.srcPath.getZone()
		dstZone := rule.dstPath.getZone()
		if zoneEq(srcZone, dstZone) {
			collectUnenforceable(rule)
			rules[i] = nil
			changed = true
		} else {

			// At least one rule of service is enforceable.
			// This is used to decide, if a service is fully unenforceable.
			rule.rule.service.seenEnforceable = true
		}
	}
	if changed {
		j := 0
		for _, r := range rules {
			if r != nil {
				rules[j] = r
				j++
			}
		}
		rules = rules[:j]
	}
	return rules
}

//#######################################################################
// Convert normalized service rules to grouped path rules.
//#######################################################################

type groupWithPath struct {
	path  pathStore
	group []someObj
}

func splitRuleGroup(group []someObj) []groupWithPath {
	// Check if group has elements from different zones and must be split.
	path0 := group[0].getPathNode()
	different := false
	for _, el := range group[1:] {
		if path0 != el.getPathNode() {
			different = true
			break
		}
	}
	if !different {
		// Use unchanged group, add path info.
		return []groupWithPath{{path0, group}}
	}
	var pathList []pathStore
	path2group := make(map[pathStore][]someObj)
	for _, el := range group {
		path := el.getPathNode()
		if path2group[path] == nil {
			pathList = append(pathList, path)
		}
		path2group[path] = append(path2group[path], el)
	}
	result := make([]groupWithPath, len(pathList))
	for i, path := range pathList {
		part := path2group[path]
		result[i] = groupWithPath{path, part}
	}
	return result
}

func splitRulesByPath(rules ruleList) ruleList {
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
	process := func(sRules ruleList) ruleList {
		gRules := splitRulesByPath(sRules)
		gRules = removeUnenforceableRules(gRules)
		return gRules
	}
	c.allPathRules.permit = process(p)
	c.allPathRules.deny = process(d)
	count := len(c.allPathRules.permit) + len(c.allPathRules.deny)
	c.info("Grouped rule count: %d", count)

	c.showUnenforceable()
}
