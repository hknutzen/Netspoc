package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"inet.af/netaddr"
	"sort"
	"strings"
)

type objPair [2]someObj

// This handles a rule between objects inside a single security zone or
// between interfaces of a single managed router.
// Show warning or error message if rule is between
// - different interfaces or
// - different networks or
// - subnets/hosts of different networks.
// Rules between identical objects are silently ignored.
// But a message is shown if a service only has rules between identical objects.
func collectUnenforceable(rule *groupedRule) {
	service := rule.rule.service
	service.silentUnenforceable = true
	isCoupling := rule.rule.hasUser == "both"

	for _, src := range rule.src {
		for _, dst := range rule.dst {

			if isCoupling {
				if src == dst {
					continue
				}
				switch s := src.(type) {
				case *subnet:
					if d, ok := dst.(*subnet); ok {

						// For rules with different subnets of a single
						// network we don't know if the subnets have been
						// split from a single range.
						// E.g. range 1-4 becomes four subnets 1,2-3,4
						// For most splits the resulting subnets would be
						// adjacent. Hence we check for adjacency.
						if s.network == d.network {
							var n netaddr.IPPrefix
							var next netaddr.IP
							if s.ipp.IP.Less(d.ipp.IP) {
								n = s.ipp
								next = d.ipp.IP
							} else {
								n = d.ipp
								next = s.ipp.IP
							}
							if n.Contains(next.Prior()) {
								continue
							}
						}
					}
				case *network:
					if s.isAggregate {
						if s.ipp.Bits == 0 {
							// This is a common case, which results from
							// rules like user -> any:[user]
							continue
						}
						if d, ok := dst.(*network); ok {

							// Different aggregates with identical IP,
							// inside a zone cluster must be considered as equal.
							if d.isAggregate &&
								s.ipp == d.ipp {
								continue
							}
						}
					}
				}
				if d, ok := dst.(*network); ok {
					if d.isAggregate {
						if d.ipp.Bits == 0 {
							continue
						}
					}
				}
			}
			if service.seenUnenforceable == nil {
				service.seenUnenforceable = make(map[objPair]bool)
			}
			service.seenUnenforceable[objPair{src, dst}] = true
		}
	}
}

func (c *spoc) showUnenforceable() {
	names := make([]string, 0, len(symTable.service))
	for name, _ := range symTable.service {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		service := symTable.service[name]
		context := service.name

		if service.hasUnenforceable &&
			(service.seenUnenforceable == nil || !service.seenEnforceable) {
			c.warn("Useless attribute 'has_unenforceable' at %s", context)
		}
		if conf.Conf.CheckUnenforceable == "" {
			continue
		}
		if service.disabled {
			continue
		}

		// Warning about fully unenforceable service can't be disabled with
		// attribute has_unenforceable.
		if !service.seenEnforceable {

			// Don't warn on empty service without any expanded rules.
			if service.seenUnenforceable != nil || service.silentUnenforceable {
				c.warnOrErr(conf.Conf.CheckUnenforceable,
					"%s is fully unenforceable", context)
			}
			continue
		}

		var list stringList
		for pair, _ := range service.seenUnenforceable {
			src, dst := pair[0], pair[1]
			srcAttr := getAttr(src, hasUnenforceableAttr)
			dstAttr := getAttr(dst, hasUnenforceableAttr)
			if service.hasUnenforceable {
				if srcAttr == restrictVal && dstAttr == restrictVal {
					if !service.hasUnenforceableRestricted {
						service.hasUnenforceableRestricted = true
						c.warn("Must not use attribute 'has_unenforceable' at %s",
							context)
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
				context, strings.Join(list, "\n "))
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
