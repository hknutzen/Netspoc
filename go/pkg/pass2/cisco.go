package pass2

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/jcode"
	"inet.af/netaddr"
	"os"
	"sort"
	"strconv"
	"strings"
)

func optimizeRedundantRules(cmp, chg ruleTree) bool {
	changed := false
	for deny, chg := range chg {
		for {
			if cmp, ok := cmp[deny]; ok {
				for srcRange, chg := range chg {
					for {
						if cmp, ok := cmp[srcRange]; ok {
							for src, chg := range chg {
								for {
									if cmp, ok := cmp[src]; ok {
										for dst, chg := range chg {
											for {
												if cmp, ok := cmp[dst]; ok {
													for prt, chgRule := range chg {
														if chgRule.deleted {
															continue
														}
														for {
															if cmpRule, ok := cmp[prt]; ok {
																if cmpRule != chgRule &&
																	cmpRule.log == chgRule.log {
																	chgRule.deleted = true
																	changed = true
																	break
																}
															}
															prt = prt.up
															if prt == nil {
																break
															}
														}
													}
												}
												dst = dst.up
												if dst == nil {
													break
												}
											}
										}
									}
									src = src.up
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
	return changed
}

type ciscoRule struct {
	deny          bool
	src, dst      *ipNet
	prt, srcRange *proto
	log           string
	deleted       bool
	optSecondary  bool
}

type ciscoRules []*ciscoRule

func (rules *ciscoRules) push(rule *ciscoRule) {
	*rules = append(*rules, rule)
}

// Build rule tree from nested maps.
// Leaf nodes have rules as values.
type ruleTree1 map[*proto]*ciscoRule
type ruleTree2 map[*ipNet]ruleTree1
type ruleTree3 map[*ipNet]ruleTree2
type ruleTree4 map[*proto]ruleTree3
type ruleTree map[bool]ruleTree4

func (tree ruleTree2) add(dst *ipNet) ruleTree1 {
	subtree, ok := tree[dst]
	if !ok {
		subtree = make(ruleTree1)
		tree[dst] = subtree
	}
	return subtree
}
func (tree ruleTree3) add(src *ipNet) ruleTree2 {
	subtree, ok := tree[src]
	if !ok {
		subtree = make(ruleTree2)
		tree[src] = subtree
	}
	return subtree
}
func (tree ruleTree4) add(srcRange *proto) ruleTree3 {
	subtree, ok := tree[srcRange]
	if !ok {
		subtree = make(ruleTree3)
		tree[srcRange] = subtree
	}
	return subtree
}
func (tree ruleTree) add(deny bool) ruleTree4 {
	subtree, ok := tree[deny]
	if !ok {
		subtree = make(ruleTree4)
		tree[deny] = subtree
	}
	return subtree
}

func optimizeRules1(rules ciscoRules, aclInfo *aclInfo) ciscoRules {
	prtIP := aclInfo.prt2obj["ip"]
	changed := false

	// Add rule to rule tree.
	addRule := func(ruleTree ruleTree, rule *ciscoRule) {
		srcRange := rule.srcRange
		if srcRange == nil {
			srcRange = prtIP
		}

		subtree1 :=
			ruleTree.add(rule.deny).add(srcRange).add(rule.src).add(rule.dst)
		if _, ok := subtree1[rule.prt]; ok {
			rule.deleted = true
			changed = true
		} else {
			subtree1[rule.prt] = rule
		}
	}

	// For comparing redundant rules.
	tree := make(ruleTree)

	// Fill rule tree.
	for _, rule := range rules {
		addRule(tree, rule)
	}

	changed = optimizeRedundantRules(tree, tree) || changed

	// Implement rules as secondary rule, if possible.
	secondaryTree := make(ruleTree)
	for _, rule := range rules {
		if !rule.optSecondary {
			continue
		}
		if rule.deleted {
			continue
		}
		if rule.src.noOptAddrs {
			continue
		}
		if rule.dst.noOptAddrs {
			continue
		}

		// Replace obj by supernet.
		if rule.src.optNetworks != nil {
			rule.src = rule.src.optNetworks
		}
		if rule.dst.optNetworks != nil && !rule.dst.needProtect {
			rule.dst = rule.dst.optNetworks
		}

		// Change protocol to IP.
		rule.prt = prtIP
		rule.srcRange = nil

		addRule(secondaryTree, rule)
	}

	if len(secondaryTree) != 0 {
		changed =
			optimizeRedundantRules(secondaryTree, secondaryTree) || changed
		changed =
			optimizeRedundantRules(secondaryTree, tree) || changed
	}

	if changed {
		newRules := make(ciscoRules, 0)
		for _, rule := range rules {
			if !rule.deleted {
				newRules.push(rule)
			}
		}
		rules = newRules
	}
	return rules
}

func optimizeRules(aclInfo *aclInfo) {
	aclInfo.intfRules = optimizeRules1(aclInfo.intfRules, aclInfo)
	aclInfo.rules = optimizeRules1(aclInfo.rules, aclInfo)
}

// Join adjacent port ranges.
func joinRanges1(rules ciscoRules, prt2obj name2Proto) ciscoRules {
	type key struct {
		deny       bool
		src, dst   *ipNet
		srcRange   *proto
		log, proto string
	}
	key2rules := make(map[key]ciscoRules)
	for _, rule := range rules {

		// Only ranges which have a neighbor may be successfully optimized.
		// Currently only dstRanges are handled.
		if !rule.prt.hasNeighbor {
			continue
		}

		// Collect rules with identical deny/src/dst/srcRange log values
		// and identical TCP or UDP protocol.
		k := key{
			rule.deny, rule.src, rule.dst, rule.srcRange, rule.log,
			rule.prt.protocol,
		}
		key2rules[k] = append(key2rules[k], rule)
	}
	changed := false
	for _, list := range key2rules {
		if len(list) < 2 {
			continue
		}

		// When sorting these rules by low port number, rules with
		// adjacent protocols will placed side by side. There can't be
		// overlaps, because they have been split in function
		// 'orderRanges'. There can't be sub-ranges, because they have
		// been deleted as redundant already.
		sort.Slice(list, func(i, j int) bool {
			return list[i].prt.ports[0] < list[j].prt.ports[0]
		})
		ruleA := list[0]
		proto := ruleA.prt.protocol
		a1, a2 := ruleA.prt.ports[0], ruleA.prt.ports[1]
		for _, ruleB := range list[1:] {
			b1, b2 := ruleB.prt.ports[0], ruleB.prt.ports[1]

			// Found adjacent port ranges.
			if a2+1 == b1 {

				// Add extended protocol.
				b1 = a1
				name := jcode.GenPortName(proto, a1, b2)
				ruleB.prt = getPrtObj(name, prt2obj)

				// Mark other rule as deleted.
				ruleA.deleted = true
				changed = true
			}
			ruleA = ruleB
			a1, a2 = b1, b2
		}
	}

	if changed {

		// Change slice in place.
		j := 0
		for _, rule := range rules {
			if !rule.deleted {
				rules[j] = rule
				j++
			}
		}
		rules = rules[:j]
	}
	return rules
}

func joinRanges(aclInfo *aclInfo) {
	prt2obj := aclInfo.prt2obj
	aclInfo.intfRules = joinRanges1(aclInfo.intfRules, prt2obj)
	aclInfo.rules = joinRanges1(aclInfo.rules, prt2obj)
}

// Place those rules first in Cisco ACL that have
// - attribute 'log'
//   because larger rule must not be placed before them,
// - protocols ESP or AH
//   for performance reasons.
// Crypto rules need to have a fixed order,
// Protocols ESP and AH are be placed first in Cisco ACL
// for performance reasons.
// These rules need to have a fixed order.
// Otherwise the connection may be lost,
// - if the device is accessed over an IPSec tunnel
// - and we change the ACL incrementally.
func moveRules(aclInfo *aclInfo) {
	prt2obj := aclInfo.prt2obj
	aclInfo.intfRules =
		moveRulesEspAh(aclInfo.intfRules, prt2obj, aclInfo.intfRuHasLog)
	aclInfo.rules =
		moveRulesEspAh(aclInfo.rules, prt2obj, aclInfo.rulesHasLog)
}

func moveRulesEspAh(
	rules ciscoRules, prt2obj name2Proto, hasLog bool) ciscoRules {

	if rules == nil {
		return nil
	}
	prtEsp := prt2obj["proto 50"]
	prtAh := prt2obj["proto 51"]
	if prtEsp == nil && prtAh == nil && !hasLog {
		return rules
	}

	// Sort crypto rules.
	// Leave deny rules unchanged before and
	// other permit rules unchanged after crypto rules.
	needSort := func(rule *ciscoRule) bool {
		return rule.prt == prtEsp || rule.prt == prtAh || rule.log != ""
	}
	cmpAddr := func(a, b *ipNet) int {
		if val := a.IP.Compare(b.IP); val != 0 {
			return val
		}
		if a.Bits < b.Bits {
			return -1
		}
		if a.Bits > b.Bits {
			return 1
		}
		return 0
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].deny {
			return !rules[j].deny
		}
		if rules[j].deny {
			return false
		}
		if !needSort(rules[i]) {
			return false
		}
		if !needSort(rules[j]) {
			return true
		}
		if cmp := strings.Compare(
			rules[i].prt.protocol,
			rules[j].prt.protocol); cmp != 0 {

			return cmp == -1
		}
		if cmp := cmpAddr(rules[i].src, rules[j].src); cmp != 0 {
			return cmp == -1
		}
		return cmpAddr(rules[i].dst, rules[j].dst) == -1
	})
	return rules
}

func createGroup(
	elements []*ipNet, aclInfo *aclInfo, routerData *routerData) *objGroup {

	name := "g" + strconv.Itoa(routerData.objGroupCounter)
	if routerData.ipv6 {
		name = "v6" + name
	}
	// Use zero value IP to mark group.
	// Note that "0.0.0.0" and "::" are not the zero value.
	groupRef := &ipNet{name: name}
	group := &objGroup{
		name:     name,
		elements: elements,
		ref:      groupRef,
	}
	routerData.objGroupCounter++

	// Store group for later printing of its definition.
	aclInfo.objectGroups = append(aclInfo.objectGroups, group)
	return group
}

// Add deny and permit rules at device which filters only locally.
func addLocalDenyRules(aclInfo *aclInfo, routerData *routerData) {
	network00, prtIP := aclInfo.network00, aclInfo.prtIP
	filterOnly := aclInfo.filterOnly
	var srcNetworks []*ipNet
	if aclInfo.filterAnySrc {
		srcNetworks = []*ipNet{network00}
	} else {
		srcNetworks = filterOnly
	}

	if routerData.doObjectgroup {
		groupOrSingle := func(objList []*ipNet) *ipNet {
			if len(objList) == 1 {
				return objList[0]
			}
			if routerData.filterOnlyGroup != nil {

				// Reuse object-group at all interfaces.
				return routerData.filterOnlyGroup
			}
			group := createGroup(objList, aclInfo, routerData)
			routerData.filterOnlyGroup = group.ref
			return group.ref
		}
		aclInfo.rules.push(
			&ciscoRule{
				deny: true,
				src:  groupOrSingle(srcNetworks),
				dst:  groupOrSingle(filterOnly),
				prt:  prtIP,
			})
	} else {
		for _, src := range srcNetworks {
			for _, dst := range filterOnly {
				aclInfo.rules.push(
					&ciscoRule{deny: true, src: src, dst: dst, prt: prtIP})
			}
		}
	}
	aclInfo.rules.push(
		&ciscoRule{src: network00, dst: network00, prt: prtIP})
}

/*
 Purpose    : Adjacent IP/mask objects are combined to larger objects.
              It is assumed, that no duplicate or redundant IP/mask objects
              are given.
 Parameters : r - rules
              isDst - Take IP/mask objects from dst of rule
              ipNet2obj - map of all known IP/mask objects
 Result     : Returns rules with combined IP/mask objects.
*/
func combineAdjacentIPMask(rules []*ciscoRule, isDst bool, ipNet2obj name2ipNet) []*ciscoRule {

	// Take and change objects from src/dst of rules.
	var get func(*ciscoRule) *ipNet
	var set func(*ciscoRule, *ipNet)
	if isDst {
		get = func(r *ciscoRule) *ipNet { return r.dst }
		set = func(r *ciscoRule, e *ipNet) { r.dst = e }
	} else {
		get = func(r *ciscoRule) *ipNet { return r.src }
		set = func(r *ciscoRule, e *ipNet) { r.src = e }
	}

	// Sort by IP address. Adjacent networks will be adjacent elements then.
	// Precondition is, that list already has been optimized and
	// therefore has no redundant elements.
	sort.Slice(rules, func(i, j int) bool {
		return get(rules[i]).IP.Less(get(rules[j]).IP)
	})

	// Find left and rigth part with identical mask and combine them
	// into next larger network.
	// Compare up to last but one element.
	for i := 0; i < len(rules)-1; i++ {
		element1 := get(rules[i])
		element2 := get(rules[i+1])
		prefix := element1.Bits
		if prefix != element2.Bits {
			continue
		}
		prefix--
		ip1 := element1.IP
		ip2 := element2.IP
		up1, _ := ip1.Prefix(prefix)
		up2, _ := ip2.Prefix(prefix)
		if up1.IP != up2.IP {
			continue
		}
		upElement := getIPObj(ip1, prefix, ipNet2obj)

		// Substitute left part by combined network.
		set(rules[i], upElement)

		// Mark right part as deleted and remove it at [i+1].
		rules[i+1].deleted = true
		copy(rules[i+1:], rules[i+2:]) // Shift [:i+2] left one index.
		rules = rules[:len(rules)-1]

		if i > 0 {
			// Check previous network again, if newly created network
			// is right part, i.e. lowest bit of network part is set.
			up3, _ := ip1.Prefix(prefix - 1)
			if ip1 != up3.IP {
				i--
			}
		}

		// Only one element left.
		// Condition of for-loop isn't effective, because of 'i--' below.
		if i >= len(rules)-1 {
			break
		}

		// Compare current network again.
		i--
	}
	return rules
}

type objGroup struct {
	name       string
	elements   []*ipNet
	ref        *ipNet
	eltNameMap map[string]bool
}

// For searching efficiently for matching group.
type groupKey struct {
	size  int
	first string
}

// Find object groups and/or adjacent IP networks in set of rules.
func findObjectgroups(aclInfo *aclInfo, routerData *routerData) {
	ipNet2obj := aclInfo.ipNet2obj

	// Reuse identical groups from different ACLs.
	if routerData.objGroupsMap == nil {
		routerData.objGroupsMap = make(map[groupKey][]*objGroup)
	}
	doObjectgroup := routerData.doObjectgroup
	key2group := routerData.objGroupsMap

	// Leave 'intfRules' untouched, because
	// - these rules are ignored at ASA,
	// - NX-OS needs them individually when optimizing needProtect.
	rules := aclInfo.rules

	// Find object-groups in src / dst of rules.
	for _, thisIsDst := range []bool{false, true} {

		type key struct {
			deny          bool
			that          *ipNet
			srcRange, prt *proto
			log           string
		}
		key2rules := make(map[key][]*ciscoRule)

		// Find groups of rules with identical
		// deny, srcRange, prt, log, src/dst and different dst/src.
		for _, rule := range rules {
			var that *ipNet
			if thisIsDst {
				that = rule.src
			} else {
				that = rule.dst
			}
			k := key{rule.deny, that, rule.srcRange, rule.prt, rule.log}
			key2rules[k] = append(key2rules[k], rule)
		}

		rule2rules := make(map[*ciscoRule][]*ciscoRule)
		for _, list := range key2rules {
			if len(list) < 2 {
				continue
			}
			combined := combineAdjacentIPMask(list, thisIsDst, ipNet2obj)

			if len(combined) > 1 && doObjectgroup {

				// First rule will use object group.
				rule2rules[combined[0]] = combined

				// All other rules will be deleted.
				for _, rule := range combined[1:] {
					rule.deleted = true
				}
			}
		}

		// Find group with identical elements or define a new one.
		// Returns ipNet object with empty IP, representing a group.
		getGroup := func(list []*ciscoRule) *ipNet {

			// Get list of objects from list of rules.
			// Also find smallest object for lookup below.
			elements := make([]*ipNet, len(list))
			for i, rule := range list {
				var el *ipNet
				if thisIsDst {
					el = rule.dst
				} else {
					el = rule.src
				}
				elements[i] = el
			}

			// Rules have been sorted by src/dst IP already.
			// So take smallest object for lookup below from first rule.
			smallest := elements[0]
			size := len(elements)

			// Use size and smallest element as keys for efficient lookup.
			// Name of element is used, because elements are regenerated
			// between processing of different ACLs.
			key := groupKey{size, smallest.name}

			// Search group with identical elements.
			if groups, ok := key2group[key]; ok {
			SEARCH:
				for _, group := range groups {
					href := group.eltNameMap

					// Check elements for equality.
					for _, elem := range elements {
						if _, ok := href[elem.name]; !ok {
							continue SEARCH
						}
					}

					// Found group with matching elements.
					return group.ref
				}
			}

			// No group found, build new group.
			group := createGroup(elements, aclInfo, routerData)
			namesInGroup := make(map[string]bool, len(elements))
			for _, elem := range elements {
				namesInGroup[elem.name] = true
			}
			group.eltNameMap = namesInGroup
			key2group[key] = append(key2group[key], group)
			return group.ref
		}

		var newRules ciscoRules
		for _, rule := range rules {
			if rule.deleted {
				continue
			}
			if list := rule2rules[rule]; list != nil {
				group := getGroup(list)
				if thisIsDst {
					rule.dst = group
				} else {
					rule.src = group
				}
			}
			newRules.push(rule)
		}
		rules = newRules
	}
	aclInfo.rules = rules
}

func addProtectRules(aclInfo *aclInfo, hasFinalPermit bool) {
	needProtect := aclInfo.needProtect
	if len(needProtect) == 0 {
		return
	}
	network00, prtIP := aclInfo.network00, aclInfo.prtIP

	// Add deny rules to protect own interfaces.
	// If a rule permits traffic to a directly connected network behind
	// the device, this would accidently permit traffic to an interface
	// of this device as well.

	// To be added deny rule is needless if there is a rule which
	// permits any traffic to the interface.
	// This permit rule can be deleted if there is a permit any any rule.
	noProtect := make(map[*ipNet]bool)
	var deleted int
	rules := aclInfo.intfRules
	for i, rule := range rules {
		if rule.deny {
			continue
		}
		if rule.src != network00 {
			continue
		}
		if rule.prt != prtIP {
			continue
		}
		dst := rule.dst
		if dst.needProtect {
			noProtect[dst] = true
		}

		if hasFinalPermit {
			rules[i] = nil
			deleted++
		}
	}
	if deleted != 0 {
		newRules := make(ciscoRules, 0, len(rules)-deleted)
		for _, rule := range rules {
			if rule != nil {
				newRules.push(rule)
			}
		}
		aclInfo.intfRules = newRules
	}

	// Deny rule is needless if there is no such permit rule.
	// Try to optimize this case.
	protectMap := make(map[*ipNet]bool)
	for _, rule := range aclInfo.rules {
		if rule.deny {
			continue
		}
		if rule.prt.established {
			continue
		}
		m := rule.dst.isSupernetOfNeedProtect
		if m == nil {
			continue
		}
		for _, intf := range needProtect {
			if m[intf] {
				protectMap[intf] = true
			}
		}
	}

	// Protect own interfaces.
	for _, intf := range needProtect {
		if noProtect[intf] || !protectMap[intf] && !hasFinalPermit {
			continue
		}
		aclInfo.intfRules.push(
			&ciscoRule{
				deny: true,
				src:  network00,
				dst:  intf,
				prt:  prtIP,
			})
	}
}

// Check if last rule is 'permit ip any any'.
func checkFinalPermit(aclInfo *aclInfo) bool {
	rules := aclInfo.rules
	l := len(rules)
	if l == 0 {
		return false
	}
	last := rules[l-1]
	return !last.deny &&
		last.src == aclInfo.network00 &&
		last.dst == aclInfo.network00 &&
		last.prt == aclInfo.prtIP
}

// Add 'deny|permit ip any any' at end of ACL.
func addFinalPermitDenyRule(aclInfo *aclInfo, addDeny, addPermit bool) {
	if addDeny || addPermit {
		aclInfo.rules.push(
			&ciscoRule{
				deny: addDeny,
				src:  aclInfo.network00,
				dst:  aclInfo.network00,
				prt:  aclInfo.prtIP,
			})
	}
}

func finalizeCiscoACL(aclInfo *aclInfo, routerData *routerData) {

	// Join adjacent port ranges. This must be called after
	// local optimization, because protocols will be
	// overlapping again after joining.
	joinRanges(aclInfo)
	moveRules(aclInfo)
	hasFinalPermit := checkFinalPermit(aclInfo)
	addPermit := aclInfo.addPermit
	addDeny := aclInfo.addDeny
	addProtectRules(aclInfo, hasFinalPermit || addPermit)
	if !aclInfo.isCryptoACL {
		findObjectgroups(aclInfo, routerData)
	}
	if len(aclInfo.filterOnly) > 0 && !addPermit {
		addLocalDenyRules(aclInfo, routerData)
	} else if !hasFinalPermit {
		addFinalPermitDenyRule(aclInfo, addDeny, addPermit)
	}
}

// Given IP or group object, return its address in Cisco syntax.
func ciscoACLAddr(obj *ipNet, model string) string {

	// Object group.
	if obj.IPPrefix.IsZero() {
		var keyword string
		if model == "NX-OS" {
			keyword = "addrgroup"
		} else {
			keyword = "object-group"
		}
		return keyword + " " + obj.name
	}

	prefix := obj.Bits
	ip := obj.IP
	if prefix == 0 {
		if model == "ASA" {
			if ip.Is4() {
				return "any4"
			}
			return "any6"
		}
		return "any"
	}
	if model == "NX-OS" {
		return obj.name
	}
	ipCode := ip.String()
	if obj.IPPrefix.IsSingleIP() {
		return "host " + ipCode
	}
	if ip.Is6() {
		return obj.name
	}

	maskNet, _ := netaddr.IPv4(255, 255, 255, 255).Prefix(prefix)
	bytes := maskNet.IP.As4()

	// Inverse mask bits.
	if model == "NX-OS" || model == "IOS" {
		for i, byte := range bytes {
			bytes[i] = ^byte
		}
	}
	maskCode := netaddr.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).String()
	return ipCode + " " + maskCode
}

func printObjectGroups(fd *os.File, aclInfo *aclInfo, model string) {
	var keyword string
	if model == "NX-OS" {
		keyword = "object-group ip address"
	} else {
		keyword = "object-group network"
	}
	for _, group := range aclInfo.objectGroups {
		numbered := 10
		fmt.Fprintln(fd, keyword, group.name)
		for _, element := range group.elements {
			adr := ciscoACLAddr(element, model)
			if model == "NX-OS" {
				fmt.Fprintln(fd, "", numbered, adr)
				numbered += 10
			} else {
				fmt.Fprintln(fd, " network-object", adr)
			}
		}
	}
}

// Returns 3 values for building a Cisco ACL:
// permit <val1> <src> <val2> <dst> <val3>
func ciscoPrtCode(
	srcRange, prt *proto, model string, ipv6 bool) (t1, t2, t3 string) {
	protocol := prt.protocol

	switch protocol {
	case "ip":
		var ip string
		if model == "IOS" && ipv6 {
			ip = "ipv6"
		} else {
			ip = "ip"
		}
		return ip, "", ""
	case "tcp", "udp":
		portCode := func(rangeObj *proto) string {
			ports := rangeObj.ports
			v1, v2 := ports[0], ports[1]
			if v1 == v2 {
				return "eq " + strconv.Itoa(v1)
			}
			if v1 == 1 && v2 == 65535 {
				return ""
			}
			if v2 == 65535 {
				return "gt " + strconv.Itoa(v1-1)
			}
			if v1 == 1 {
				return "lt " + strconv.Itoa(v2+1)
			}
			return "range " + strconv.Itoa(v1) + " " + strconv.Itoa(v2)
		}
		dstPrt := portCode(prt)
		var srcPrt string
		if srcRange != nil {
			srcPrt = portCode(srcRange)
		}
		return protocol, srcPrt, dstPrt
	case "icmp":
		icmp := "icmp"
		if ipv6 && model == "ASA" {
			icmp = "icmp6"
		}
		icmpType := prt.icmpType
		if icmpType != -1 {
			code := prt.icmpCode
			if code != -1 {
				return icmp, "", strconv.Itoa(icmpType) + " " + strconv.Itoa(code)
			}
			return icmp, "", strconv.Itoa(icmpType)
		}
		return icmp, "", ""
	default:
		return protocol, "", ""
	}
}

func getCiscoAction(deny bool) string {
	if deny {
		return "deny"
	}
	return "permit"
}

func printAsaStdACL(fd *os.File, aclInfo *aclInfo, model string) {
	for _, rule := range aclInfo.rules {
		fmt.Fprintln(
			fd,
			"access-list",
			aclInfo.name,
			"standard",
			getCiscoAction(rule.deny),
			ciscoACLAddr(rule.src, model))
	}
}

func printCiscoACL(fd *os.File, aclInfo *aclInfo, routerData *routerData) {
	model := routerData.model

	if aclInfo.isStdACL {
		printAsaStdACL(fd, aclInfo, model)
		return
	}

	name := aclInfo.name
	ipv6 := routerData.ipv6
	numbered := 10
	prefix := ""
	switch model {
	case "IOS", "NX-OS":
		if ipv6 {
			fmt.Fprintln(fd, "ipv6 access-list", name)
			break
		}
		switch model {
		case "IOS":
			fmt.Fprintln(fd, "ip access-list extended", name)
		case "NX-OS":
			fmt.Fprintln(fd, "ip access-list", name)
		}
	case "ASA":
		prefix = "access-list " + name + " extended"
	}

	for _, rules := range []ciscoRules{aclInfo.intfRules, aclInfo.rules} {
		for _, rule := range rules {
			action := getCiscoAction(rule.deny)
			protoCode, srcPortCode, dstPortCode :=
				ciscoPrtCode(rule.srcRange, rule.prt, model, ipv6)
			result := prefix + " " + action + " " + protoCode
			result += " " + ciscoACLAddr(rule.src, model)
			if srcPortCode != "" {
				result += " " + srcPortCode
			}
			result += " " + ciscoACLAddr(rule.dst, model)
			if dstPortCode != "" {
				result += " " + dstPortCode
			}
			if rule.prt.established {
				result += " established"
			}
			if rule.log != "" {
				result += " " + rule.log
			} else if rule.deny && routerData.logDeny != "" {
				result += " " + routerData.logDeny
			}

			// Add line numbers.
			if model == "NX-OS" {
				result = " " + strconv.Itoa(numbered) + result
				numbered += 10
			}
			fmt.Fprintln(fd, result)
		}
	}
}
