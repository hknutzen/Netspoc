package pass1

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

/*#############################################################################
Distribute Network Address Translation Info

NetSPoC can deal with Network Address Translation (NAT) to translate
or hide Network addresses in parts of the topology.

NAT is defined by adding a NAT definition to the network or host
definition of the element that is to be translated or hidden. To
determine topology parts where NAT definitions are effective, NAT tags
referring to a nat definition are bound to interfaces within the
topology. This NAT binding activates NAT for every topology element
behind the interface as seen from router, so NAT is effective in
network direction of NAT binding.

The NAT binding separates the topology into a part in front of the
binding (as seen from the element with NAT defined) where the elements
original address is valid and a part behind the binding, where NAT is
effective. It is possible and sometimes neccessary to apply more than
one NAT binding: Additional NAT bindings can be used to delimit the
topology part where NAT is active, and for topologies with loops,
several NAT bindings can be required to obtain clear separation into
NAT active and inactive parts.

To keep track of which NAT tags are active in which part of the
topology, NetSpoC divides the topology into NAT domains. A NAT domain
is a maximal area of the topology (a set of connected networks) where
a common set of NAT tags (NAT set) is effective at every network.
*/

// getLookupMapForNatType checks for equal type of NAT definitions.
//
//	This is used for more efficient check of dynamic NAT rules,
//	so we need to check only once for each pair of src / dst zone.
//
// Returns a map, mapping NAT tag to its type: static, dynamic or hidden.
func (c *spoc) getLookupMapForNatType() map[string]string {
	natTag2network := make(map[string]*network)
	natType := make(map[string]string)
	for _, n := range c.allNetworks {
		tags := maps.Keys(n.nat)
		sort.Strings(tags)
		for _, tag := range tags {
			getTyp := func(natNet *network) string {
				switch {
				case natNet.hidden:
					return "hidden"
				case natNet.dynamic:
					return "dynamic"
				default:
					return "static"
				}
			}
			typ1 := getTyp(n.nat[tag])
			if other := natTag2network[tag]; other != nil {
				typ2 := getTyp(other.nat[tag])
				if typ2 != typ1 {
					c.err("All definitions of nat:%s must have equal type.\n"+
						" But found\n"+
						" - %s for %s\n"+
						" - %s for %s", tag, typ2, other, typ1, n)
				}
			} else {
				natTag2network[tag] = n
				natType[tag] = typ1
			}
		}
	}
	return natType
}

// checkNatDefinitions checks for
//  1. unused NAT definitions,
//  2. useless bind_nat, referencing unknown NAT definition.
//     Remove useless tags from bind_nat.
func (c *spoc) checkNatDefinitions(natType map[string]string) {
	natUsed := make(map[string]bool)
	for _, n := range c.allNetworks {
		for _, intf := range n.interfaces {
			j := 0
			l := intf.bindNat
			for _, tag := range l {
				if _, found := natType[tag]; found {
					natUsed[tag] = true
					l[j] = tag
					j++
				} else {
					c.warn("Ignoring useless nat:%s bound at %s", tag, intf)
				}
			}
			intf.bindNat = l[:j]
		}
	}
	var messages stringList
	for tag := range natType {
		if !natUsed[tag] {
			messages.push(
				"nat:" + tag + " is defined, but not bound to any interface")
		}
	}
	sort.Strings(messages)
	for _, m := range messages {
		c.warn(m)
	}
}

// Mark invalid NAT transitions.
// A transition from nat:t1 to nat:t2 occurs at an interface I
// - if nat:t1 was active previously
// - and nat:t2 is activated at I with "bind_nat = t2".
// This transition is invalid
//   - if a network:n1 exists having NAT definitions for both t1 and t2
//   - and some other network:n2 exists having a NAT definition for t1,
//     but not for t2.
func markInvalidNatTransitions(multi map[string][]natTagMap) map[string]natTagMap {
	result := make(map[string]natTagMap)
	for _, list := range multi {
		if len(list) == 1 {
			continue
		}
		union := make(map[string]bool)
		for _, multiNatMap := range list {
			for tag := range multiNatMap {
				union[tag] = true
			}
		}
		count := len(union)
		for _, multiNatMap := range list {
			if len(multiNatMap) == count {
				continue
			}
			var missing stringList
			for tag := range union {
				if multiNatMap[tag] == nil {
					missing.push(tag)
				}
			}
			for tag1 := range multiNatMap {
				natNet := multiNatMap[tag1]
				m := result[tag1]
				if m == nil {
					m = make(natTagMap)
					result[tag1] = m
				}
				for _, tag2 := range missing {
					m[tag2] = natNet
				}
			}
		}
	}
	return result
}

// Returns   : Map with NAT tags occurring in multi NAT definitions
//
//	(several NAT definitions grouped at one network) as keys
//	and arrays of NAT maps containing the key NAT tag as values.
//
// Comments: Also checks consistency of multi NAT tags at one network. If
//
//	non hidden NAT tags are grouped at one network, the same NAT
//	tags must be used as group in all other occurrences to avoid
//	ambiguities: Suppose tags A and B are both defined at network n1,
//	but only A is defined at network n2. An occurence of
//	bind_nat = A activates NAT:A. A successive bind_nat = B activates
//	NAT:B, but implicitly disables NAT:A, as for n1 only one NAT can be
//	active at a time. As NAT:A can not be active (n2) and inactive
//	(n1) in the same NAT domain, this restriction is needed.
func (c *spoc) generateMultinatDefLookup(
	natType map[string]string) map[string][]natTagMap {

	// Check if two natTagMaps contain the same keys. Values can be different.
	keysEq := func(m1, m2 natTagMap) bool {
		if len(m1) != len(m2) {
			return false
		}
		for tag := range m1 {
			if m2[tag] == nil {
				return false
			}
		}
		return true
	}
	// Get number of common keys of two natTagMaps.
	commonKeysCount := func(m1, m2 natTagMap) int {
		count := 0
		for tag := range m1 {
			if m2[tag] != nil {
				count++
			}
		}
		return count
	}

	multi := make(map[string][]natTagMap)
	for _, n := range c.allNetworks {
		map1 := n.nat
	NAT_TAG:
		for tag := range map1 {
			list := multi[tag]
			if list != nil {
				// Do not add same group twice.
				if natType[tag] != "hidden" {
					for _, map2 := range list {
						if keysEq(map1, map2) {
							continue NAT_TAG
						}
					}
				} else {
					// Check for subset relation. Keep superset only.
					for i, map2 := range list {
						switch commonKeysCount(map1, map2) {
						case len(map1):
							// map1 is subset, ignore.
							continue NAT_TAG
						case len(map2):
							// map1 is superset, replace previous entry.
							list[i] = map1
							continue NAT_TAG
						}
					}
				}
			}
			multi[tag] = append(list, map1)
		}
	}

	// Remove entry if NAT tag never occurs grouped in multi NAT definitions.
	for tag, list := range multi {
		if len(list) == 1 && len(list[0]) == 1 {
			delete(multi, tag)
		}
	}

	return multi
}

// Compare two list element wise.
// Return true if both contain the same elements in same order.
func bindNatEq(l1, l2 stringList) bool {
	if len(l1) != len(l2) {
		return false
	}
	for i, tag := range l1 {
		if tag != l2[i] {
			return false
		}
	}
	return true
}

// findNatDomains divides topology into NAT domains.
//
//	Networks and NAT domain limiting routers keep references
//	to their domains.
//
// Results : domain has lists of its zones and limiting routers,
//
//	routers that are domain limiting, contain references to the
//	limited domains and store NAT tags bound to domains border
//	interfaces.
//	Returns nil on error.
func (c *spoc) findNatDomains() []*natDomain {

	type key struct {
		router   *router
		natList1 string
		natList2 string
	}
	natErrSeen := make(map[key]bool)

	// Perform depth first search to collect zones and limiting
	// routers of given NAT-domain.
	var setNatDomain func(z *zone, d *natDomain, inIntf *routerIntf)
	setNatDomain = func(z *zone, d *natDomain, inIntf *routerIntf) {

		// Zone was processed by a former call from setNatDomain
		// or loop found inside a NAT domain.
		if z.natDomain != nil {
			return
		}
		//debug("%s: %s", d.name, z)

		z.natDomain = d
		d.zones = append(d.zones, z)

		// Find adjacent zones to proceed with.
		for _, intf := range z.interfaces {

			// Ignore interface where we reached this zone.
			if intf == inIntf {
				continue
			}

			//debug("IN %s", intf)
			natTags := intf.bindNat
			r := intf.router

			uselessNatBinding := true
			for _, outIntf := range r.interfaces {

				// Don't process interface where we reached this router.
				if outIntf == intf {
					continue
				}
				//debug("OUT %s", outIntf)

				// Current NAT domain continues behind outIntf
				if bindNatEq(outIntf.bindNat, natTags) {

					// Prevent deep recursion inside a single NAT domain.
					if r.activePath {
						continue
					}
					r.activePath = true
					setNatDomain(outIntf.zone, d, outIntf)
					r.activePath = false
					continue
				}

				// Another NAT domain starts at current router behind outIntf.
				uselessNatBinding = false

				// Loop found: router is already marked to limit domain.
				// Perform consistency check.
				if other, found := r.natTags[d]; found {
					if bindNatEq(natTags, other) {
						continue
					}
					info := func(tags stringList) string {
						if s := strings.Join(tags, ","); s != "" {
							return s
						} else {
							return "(none)"
						}
					}
					names1 := info(natTags)
					names2 := info(other)
					k := key{r, names1, names2}
					if natErrSeen[k] {
						continue
					}
					natErrSeen[k] = true
					c.err("Inconsistent NAT in loop at %s:\n"+
						" nat:%s vs. nat:%s",
						r, names1, names2)
					continue
				}

				// Mark router as domain limiting,
				// 1. add router as domain border,
				// 2. initialized NAT set for model.aclUseRealIP
				if r.natTags == nil {
					r.natTags = make(map[*natDomain]stringList)
					if r.model != nil && r.model.aclUseRealIP {
						natSet := make(natSet)
						r.natSet = natSet
					}
				}
				r.natTags[d] = natTags
				d.routers = append(d.routers, r)
				//debug("ADD to %s: %s", r, d.name)
				r.natDomains = append(r.natDomains, d)
			}

			// Routers with same NAT tag at every interface may occur with VPN.
			onlyVPN := true
			for _, intf := range r.interfaces {
				if intf.hub == nil && intf.spoke == nil {
					onlyVPN = false
					break
				}
			}

			if uselessNatBinding && len(natTags) != 0 && !onlyVPN {

				fullTags := make(stringList, len(natTags))
				for i, tag := range natTags {
					fullTags[i] = "nat:" + tag
				}
				list := strings.Join(fullTags, ",")
				c.warn("Ignoring %s without effect, bound at every interface of %s",
					list, r)
			}
		}
	}

	var result []*natDomain
	for _, z := range c.allZones {
		if z.natDomain != nil {
			continue
		}
		name := "nat_domain:" + strings.SplitN(z.name, ":", 2)[1]
		natSet := make(natSet)
		d := &natDomain{
			name:   name,
			natSet: natSet,
		}
		result = append(result, d)
		setNatDomain(z, d, nil)
	}
	if len(natErrSeen) > 0 {
		return nil
	}
	return result
}

// errMissingBindNat shows interfaces, where bind_nat for NAT tag is missing.
func (c *spoc) errMissingBindNat(
	inRouter *router, d *natDomain, tag string, multinatMaps []natTagMap) {

	// Collect interfaces where bind_nat for natTag is applied correctly.
	// First, add interface between inRouter and d.
	// Other interfaces are added later, during traversal.
	var natIntf intfList
	for _, intf := range getNatDomainBorders(d) {
		if intf.router == inRouter {
			natIntf.push(intf)
		}
	}

	// Collect interfaces with missing bind_nat.
	var missingIntf intfList

	// Don't traverse these domains in other direction, if
	// - either a valid path was found behind this domain
	// - or a missing bind_nat is assumed at interface of this domain.
	dSeen := make(map[*natDomain]bool)

	// Cache result depending on (router, domain).
	type key struct {
		router *router
		domain *natDomain
	}
	cache := make(map[key]int)

	// debug("Missing bind_nat = %s", tag)
	// Traverse the topology recursively and depth first.
	// Returns:
	//  1 if valid path is found,
	// -1 if invalid path,
	//  0 on loop or dead end.
	var traverse func(*router, *natDomain) int
	traverse = func(inRouter *router, d *natDomain) int {
		if inRouter.activePath {
			return 0
		}
		if dSeen[d] {
			return 0
		}
		if result, found := cache[key{inRouter, d}]; found {
			return result
		}
		// debug("ENTER %s %s" inRouter, d.name)
		inRouter.activePath = true
		defer func() { inRouter.activePath = false }()

		// For combined result (-1, 0, 1) of all neighbor routers.
		rResult := 0

		// For collecting router where invalid path starts.
		rInvalid := make(map[*router]bool)

	ROUTER:
		for _, r := range d.routers {
			if r == inRouter {
				continue
			}
			dom2tags := r.natTags
			inNatTags := dom2tags[d]

			for _, inTag := range inNatTags {
				if inTag == tag {

					// Found valid path.
					// debug("I %s %s", d.name, r)
					dSeen[d] = true
					rResult = 1
					for _, intf := range getNatDomainBorders(d) {
						if intf.router == r {
							natIntf.push(intf)
						}
					}
					continue ROUTER
				}
			}

			// For combined result (-1, 0, 1) of all neighbor domains.
			dResult := 0

			// For collecting domains where invalid path starts.
			dInvalid := make(map[*natDomain]bool)

		DOMAIN:
			for _, outDomain := range r.natDomains {
				if outDomain == d {
					continue
				}
				outNatTags := dom2tags[outDomain]

				// Found invalid path.
				for _, t := range outNatTags {
					if t == tag {
						// debug("O %s %s %s", d.name, r, outDomain.name)
						dInvalid[outDomain] = true
						if dResult == 0 {
							dResult = -1
						}
						continue DOMAIN
					}
				}
				if multinatMaps != nil {
					for _, natTag2 := range outNatTags {
						for _, natMap := range multinatMaps {
							if natMap[natTag2] != nil {

								// Ignore path at imlpicit border.
								continue DOMAIN
							}
						}
					}
				}

				if iResult := traverse(r, outDomain); iResult != 0 {
					// debug("%s- %s %s", iResult, d.name, r)
					if iResult == -1 {
						dInvalid[outDomain] = true
					} else {
						dSeen[outDomain] = true
					}
					if dResult != 1 {
						dResult = iResult
					}
				}
			}
			if dResult == 0 {
				continue
			}

			// Valid and invalid paths are joining at router.
			// Add bind_nat at inbound interface.
			// But also add bind_nat at outbound interfaces of valid paths,
			// to prevent duplicate NAT, effectively reverting the effect
			// of bind_nat at inbound interface.
			if dResult == 1 && len(dInvalid) != 0 {
				for _, outDomain := range r.natDomains {
					if dInvalid[outDomain] {
						continue
					}
					for _, intf := range getNatDomainBorders(outDomain) {
						if intf.router == r {
							missingIntf.push(intf)
						}
					}
				}
			}

			if dResult != 1 {
				rInvalid[r] = true
			}
			if rResult != 1 {
				rResult = dResult
			}
		}

		// Valid and invalid paths are joining at domain.
		// Collect interfaces to neighbor routers located on
		// invalid paths, where bind_nat is missing.
		if rResult == 1 && len(rInvalid) != 0 {
			for _, intf := range getNatDomainBorders(d) {
				if rInvalid[intf.router] {
					missingIntf.push(intf)
				}
			}
		}
		// debug("EXIT %s %s", inRouter, d.name)
		cache[key{inRouter, d}] = rResult
		return rResult
	}
	_ = traverse(inRouter, d)

	// No valid path was found, hence add all interfaces of current domain
	// that have no bind_nat for tag.
	if missingIntf == nil {
		//debug("Add all %s ", d.name)
	INTF:
		for _, intf := range getNatDomainBorders(d) {
			for _, t := range intf.bindNat {
				if t == tag {
					continue INTF
				}
			}
			missingIntf.push(intf)
		}
	}

	sortByName := func(l intfList) intfList {
		sort.Slice(l, func(i, j int) bool {
			return l[i].name < l[j].name
		})
		return l
	}
	natIntf = slices.Compact(sortByName(natIntf))
	missingIntf = slices.Compact(sortByName(missingIntf))
	c.err("Incomplete 'bind_nat = %s' at\n"+
		natIntf.nameList()+"\n"+
		" Possibly 'bind_nat = %s' is missing at these interfaces:\n"+
		missingIntf.nameList(),
		tag, tag)
}

func getNatDomainBorders(d *natDomain) intfList {
	var result intfList
	for _, r := range d.routers {
		for _, intf := range getIntf(r) {

			// Must get zone from network, because some interfaces are unmanaged.
			if intf.network.zone.natDomain == d {
				result.push(intf)
			}
		}
	}
	return result
}

// checkForProperNatTransition shows errors for invalid transitions of
// grouped NAT tags.
//
// Parameter: tag: NAT tag that is distributed during domain traversal.
//
//	tag2: NAT tag that implicitly deactivates tag.
//	nat: NAT map of network with both tag and tag2 defined.
//	invalid: Map from NAT tags t1, t2 to network,
//	    where transition from t1 to t2 is invalid.
//	r: router where NAT transition occurs at.
func (c *spoc) checkForProperNatTransition(
	tag, tag2 string, nat natTagMap, invalid map[string]natTagMap, r *router) {

	natInfo := nat[tag]
	nextInfo := nat[tag2]

	// Transition from hidden NAT to any other NAT is invalid.
	// Even hidden to hidden is not allowed, since relaxed multi NAT rules
	// for hidden NAT could lead to inconsistent NAT set.
	if natInfo.hidden {

		// Use nextInfo.name and not natInfo.name because
		// natInfo may show wrong network, because we combined
		// different hidden networks into natTag2multinatDdef.
		c.err("Must not change hidden nat:%s using nat:%s\n"+
			" for %s at %s", tag, tag2, nextInfo, r)
	} else if natInfo.dynamic && !nextInfo.dynamic {

		// Transition from dynamic to static NAT is invalid.
		c.err("Must not change dynamic nat:%s to static using nat:%s\n"+
			" for %s at %s", tag, tag2, natInfo, r)
	} else if n := invalid[tag][tag2]; n != nil {

		// Transition from tag to tag2 is invalid,
		// if tag occurs somewhere not grouped with tag2.
		c.err("Invalid transition from nat:%s to nat:%s at %s.\n"+
			" Reason: Both NAT tags are used grouped at %s\n"+
			" but nat:%s is missing at %s",
			tag, tag2, r, natInfo, tag2, n)
	}
}

// distributeNat1 performs a depth first traversal
// to distribute specified NAT tag to reachable domains where NAT tag
// is active; checks whether NAT declarations are applied correctly.
//
// Parameters:
//   - inRouter: Router domain was entered from.
//   - d: Domain the depth first traversal proceeds from.
//   - tag: NAT tag that is to be distributed.
//   - multinatMaps: List of multi NAT maps containing nat_tag.
//   - invalid: Map with pairs of NAT tags as keys,
//     where transition from first to second tag is invalid.
//
// Results:
// All domains, where NAT tag is active contain 'tag' in their	natSet.
// Returns:
// false on success,	true on error, if same NAT tag is reached twice.
func (c *spoc) distributeNat1(
	inRouter *router, d *natDomain, tag string,
	multinatMaps []natTagMap, invalid map[string]natTagMap) bool {

	//debug("nat:%s at %s from %s", tag, d.name, inRouter)

	// Loop found or domain was processed by earlier call of distributeNat.
	natSet := d.natSet
	if natSet[tag] {
		return false
	}
	natSet[tag] = true

	// Find adjacent domains with active 'tag' to proceed traversal.
ROUTER:
	for _, r := range d.routers {
		if r == inRouter {
			continue
		}
		dom2tags := r.natTags

		// 'tag' is deactivated at routers domain facing interface.
		inNatTags := dom2tags[d]
		for _, tag2 := range inNatTags {
			if tag2 == tag {
				continue ROUTER
			}
		}

		if r.model != nil && r.model.aclUseRealIP {
			r.natSet[tag] = true
		}

		// Check whether tag is active in adjacent NAT domains.
	DOMAIN:
		for _, outDom := range r.natDomains {
			if outDom == d {
				continue
			}
			outNatTags := dom2tags[outDom]

			// Found error: reached the same NAT tag twice.
			// Signal this error with return value true.
			for _, tag2 := range outNatTags {
				if tag2 == tag {
					return true
				}
			}

			// 'tag' is implicitly deactivated by activation of another NAT
			// tag used together with 'tag' in a multi NAT definition.
			if multinatMaps != nil {
				for _, tag2 := range outNatTags {
					//debug("- %s", tag2)
					for _, m := range multinatMaps {
						if m[tag2] == nil {
							continue
						}
						c.checkForProperNatTransition(tag, tag2, m, invalid, r)
						continue DOMAIN
					}
				}
			}

			// tag is active within adjacent domain: proceed traversal
			//debug("Caller %s", d.name)
			if c.distributeNat1(r, outDom, tag, multinatMaps, invalid) {
				return true
			}
		}
	}
	return false
}

// distributeNat calls distribute_nat1
// to distribute specified NAT tag to reachable domains where NAT tag is active.
// Shows an	error message, if called function returns an error value.
//
// Parameters:
//   - in: router the depth first traversal starts at.
//   - d: Domain the depth first traversal starts at.
//   - tag: NAT tag that is to be distributed.
//   - multinatMaps: List of multi NAT maps containing nat_tag.
//   - invalid: Map with pairs of NAT tags as keys,
//     where transition from first to second tag is invalid.
//
// Returns:    true if NAT errors have occured.
func (c *spoc) distributeNat(
	in *router, d *natDomain, tag string,
	multinatMaps []natTagMap, invalid map[string]natTagMap) bool {

	if c.distributeNat1(in, d, tag, multinatMaps, invalid) {
		c.errMissingBindNat(in, d, tag, multinatMaps)
		return true
	}
	return false
}

// distributeNatTagsToNatDomains distributes
// NAT tags to domains they are active in.
// Returns: true if NAT errors have occured.
func (c *spoc) distributeNatTagsToNatDomains(
	multi map[string][]natTagMap, doms []*natDomain) bool {

	invalid := markInvalidNatTransitions(multi)
	var natErrors bool
	for _, d := range doms {
		for _, r := range d.routers {
			natTags := r.natTags[d]
			// debug("%s %s: %s", d.name, r, strings.Join(natTags, ",")
			for _, tag := range natTags {
				multinatMaps := multi[tag]
				natErrors =
					natErrors || c.distributeNat(r, d, tag, multinatMaps, invalid)
			}
		}
	}
	return natErrors
}

// For networks with multiple NAT definitions,
// at most one NAT definition must be active in a domain.
// Show error otherwise.
func (c *spoc) checkMultinatErrors(
	multi map[string][]natTagMap, doms []*natDomain) {

	// Collect pairs of multi NAT tags and interfaces
	// - at border of NAT domain where both tags are active and
	// - interface has at least one of those tags active in bind_nat.
	type key struct {
		tag1   string
		tag2   string
		natNet *network
	}
	pair2errors := make(map[key]intfList)
	for _, d := range doms {
		natSet := d.natSet
		for tag1 := range natSet {
			for _, m := range multi[tag1] {
				for tag2, n := range m {
					if tag2 <= tag1 {
						continue
					}
					if !natSet[tag2] {
						continue
					}
					l := getNatDomainBorders(d)
					for _, intf := range l {
						for _, t := range intf.bindNat {
							if t == tag1 || t == tag2 {
								k := key{tag1, tag2, n}
								pair2errors[k] = append(pair2errors[k], intf)
								break
							}
						}
					}
				}
			}
		}
	}
	var errors stringList
	for p, l := range pair2errors {
		tag1, tag2 := p.tag1, p.tag2

		// If some interfaces use both NAT tags in bind_nat,
		// show only those interfaces for more concise error message.
		var hasBoth intfList
		for _, intf := range l {
			var seen1, seen2 bool
			for _, t := range intf.bindNat {
				if t == tag1 {
					seen1 = true
				}
				if t == tag2 {
					seen2 = true
				}
			}
			if seen1 && seen2 {
				hasBoth.push(intf)
			}
		}
		if hasBoth != nil {
			l = hasBoth
		}
		errors.push(fmt.Sprintf(
			"Grouped NAT tags '%s, %s' of %s must not both be active at\n%s",
			tag1, tag2, p.natNet, l.nameList()))
	}
	sort.Strings(errors)
	for _, m := range errors {
		c.err(m)
	}
}

// Network which has translation with tag 'tag'
// must not be located in domain where this tag is active.
func (c *spoc) checkNatNetworkLocation(doms []*natDomain) {
	for _, d := range doms {
		natSet := d.natSet
		for _, z := range d.zones {
			for _, n := range z.networks {
				natMap := n.nat
				var messages stringList
				for tag := range natMap {
					if natSet[tag] {
						var list stringerList
						for _, r := range d.routers {
							list = append(list, r)
						}
						messages.push(
							fmt.Sprintf(
								"%s is translated by nat:%s,\n"+
									" but is located inside the translation domain of %s.\n"+
									" Probably %s was bound to wrong interface at\n",
								n, tag, tag, tag) +
								list.nameList())
					}
				}
				sort.Strings(messages)
				for _, m := range messages {
					c.err(m)
				}
			}
		}
	}
}

// Check if a single NAT tag is bound to all interfaces of a router.
// A similar check for equalty of all tags has already been performed in
// findNatDomains.
func (c *spoc) CheckUselessBindNat(doms []*natDomain) {
	seen := make(map[*router]bool)
	for _, d := range doms {
		for _, r := range d.routers {
			if seen[r] {
				continue
			}
			seen[r] = true
			intersect := make(map[string]bool)
			tags := r.natTags[d]
			for _, t := range tags {
				intersect[t] = true
			}
			for d2, tags := range r.natTags {
				if d2 == d {
					continue
				}
				intersect2 := make(map[string]bool)
				for _, t := range tags {
					if intersect[t] {
						intersect2[t] = true
					}
				}
				intersect = intersect2
				if len(intersect) == 0 {
					break
				}
			}
			if len(intersect) > 0 {
				fullTags := make(stringList, 0, len(intersect))
				for t := range intersect {
					fullTags.push("nat:" + t)
				}
				sort.Strings(fullTags)
				list := strings.Join(fullTags, ",")
				c.warn("Ignoring %s without effect, bound at every interface of %s",
					list, r)
			}
		}
	}
}

// checkNatCompatibility checks compatibility of host/interface and network NAT.
// A NAT definition for a single host/interface is only allowed,
// if network has a dynamic NAT definition.
func (c *spoc) checkNatCompatibility() {
	for _, n := range c.allNetworks {
		check := func(obj netObj) {
			nat := obj.nat
			if nat == nil {
				return
			}
			tags := maps.Keys(obj.nat)
			sort.Strings(tags)
			for _, tag := range tags {
				objIP := nat[tag]
				natNet := n.nat[tag]
				if natNet != nil && natNet.dynamic {
					if !natNet.ipp.Contains(objIP) {
						c.err("nat:%s: IP of %s doesn't match IP/mask of %s",
							tag, obj, n)
					}
				} else {
					c.warn(
						"Ignoring nat:%s at %s because %s has static NAT definition",
						tag, obj, n)
				}
			}
		}
		for _, obj := range n.hosts {
			check(obj.netObj)
		}
		for _, obj := range n.interfaces {
			check(obj.netObj)
		}
	}
}

// checkInterfacesWithDynamicNat finds interface with dynamic NAT
// which is bound at the same	device.
// This is invalid for device with "need_protect".
//
// "need_protect" devices
// use NetSPoC generated ACLs to manage access to their interfaces.
// To ensure safety, the devices interfaces need to have a fixed address.
func (c *spoc) checkInterfacesWithDynamicNat() {
	for _, n := range c.allNetworks {
		for tag, info := range n.nat {
			if !info.dynamic || info.identity || info.hidden {
				continue
			}
			for _, intf := range n.interfaces {
				intfNat := intf.nat

				// Interface has static translation,
				if _, found := intfNat[tag]; found {
					continue
				}

				r := intf.router
				if !r.needProtect {
					continue
				}
				for _, bindIntf := range r.interfaces {
					for _, tag2 := range bindIntf.bindNat {
						if tag2 == tag {
							c.err(
								"Must not apply dynamic nat:%s"+
									" to %s at %s of same device.\n"+
									" This isn't supported for model %s.",
								tag, intf, bindIntf, r.model.name)
						}
					}
				}
			}
		}
	}
}

// Convert natSet to natMap for faster access from network to NAT network.
func (c *spoc) convertNatSetToNatMap(doms []*natDomain) {

	// Collect domains, where tag T is active.
	tag2doms := make(map[string][]*natDomain)
	for _, d := range doms {
		for tag := range d.natSet {
			tag2doms[tag] = append(tag2doms[tag], d)
		}
		//d.natSet = nil
		d.natMap = make(map[*network]*network)
	}
	// Add network with NAT tag T to natMap of domain, where T is active.
	for _, n := range c.allNetworks {
		for tag, nat := range n.nat {
			for _, d := range tag2doms[tag] {
				d.natMap[n] = nat
			}
		}
	}
	// Collect routers, where tag T is active.
	tag2routers := make(map[string][]*router)
	for _, r := range c.managedRouters {
		if ns := r.natSet; ns != nil {
			for tag := range ns {
				tag2routers[tag] = append(tag2routers[tag], r)
			}
			r.natSet = nil // No longer used.
			r.natMap = make(map[*network]*network)
		}
	}
	// Add network with NAT tag T to natMap of router, where T is active.
	for _, n := range c.allNetworks {
		for tag, nat := range n.nat {
			for _, r := range tag2routers[tag] {
				r.natMap[n] = nat
			}
		}
	}
}

// Result:
// natMap is stored
// at logical and hardware interfaces of managed and semi managed routers.
//
// Comment:
// Neccessary at semi managed routers
// to calculate .up relation between subnets.
func distributeNatMapsToInterfaces(doms []*natDomain) {
	for _, d := range doms {
		m := d.natMap
		for _, z := range d.zones {
			for _, intf := range z.interfaces {
				// debug("%s: NAT %s", d.name, intf)
				intf.natMap = m
				r := intf.router
				if r.managed != "" || r.routingOnly {
					if r.model.aclUseRealIP {

						// Set natMap of router inside NAT domain.
						if r.natMap == nil {
							r.natMap = m
						}
					}
					if intf.ipType != tunnelIP {
						intf.hardware.natMap = m
					}
				}
			}
		}
	}
}

// distributeNatInfo determines NAT domains
// and generates NAT set for every NAT domain.
func (c *spoc) distributeNatInfo() (
	[]*natDomain, map[string]string, map[string][]natTagMap) {

	c.progress("Distributing NAT")
	natType := c.getLookupMapForNatType()
	c.checkNatDefinitions(natType)
	natdomains := c.findNatDomains()
	multi := c.generateMultinatDefLookup(natType)
	natErrors := c.distributeNatTagsToNatDomains(multi, natdomains)
	c.checkMultinatErrors(multi, natdomains)
	if !natErrors {
		c.checkNatNetworkLocation(natdomains)
		c.CheckUselessBindNat(natdomains)
	}
	c.checkNatCompatibility()
	c.checkInterfacesWithDynamicNat()
	c.convertNatSetToNatMap(natdomains)
	distributeNatMapsToInterfaces(natdomains)

	return natdomains, natType, multi
}

// Combine different natSets into a single natSet in a way
// that NAT mapping remains mostly identical.
// Single NAT tags remain active if they are active in all sets.
// Different real NAT tags of a multi NAT set can't be combined.
// In this case NAT is disabled for this multi NAT set.
// Hidden NAT tag is ignored if combined with a real NAT tag,
// because hidden tag doesn't affect address calculation.
// Multiple hidden tags without real tag are ignored.
func combineNatSets(sets []natSet, multi map[string][]natTagMap, natType map[string]string) natSet {
	if len(sets) == 1 {
		return sets[0]
	}

	// Collect single NAT tags and multi NAT maps.
	combined := make(natSet)
	var activeMulti []map[string]*network
	seen := make(map[string]bool)
	for _, set := range sets {
		for tag := range set {
			if list := multi[tag]; list != nil {
				for _, multiNatMap := range list {
					allSeen := true
					for tag := range multiNatMap {
						if !seen[tag] {
							allSeen = false
							seen[tag] = true
						}
					}
					if !allSeen {
						activeMulti = append(activeMulti, multiNatMap)
					}
				}
			} else {
				combined[tag] = true
			}
		}
	}

	// Build intersection for NAT tags of all sets.
	activeMultiSets := make([]map[string]bool, len(activeMulti))
	for i := range activeMultiSets {
		activeMultiSets[i] = make(map[string]bool)
	}
	for _, set := range sets {
		for tag := range combined {
			if !set[tag] {
				delete(combined, tag)
			}
		}
		for i, multiNatMap := range activeMulti {
			active := ""
			for tag := range multiNatMap {
				if set[tag] {
					active = tag
					break
				}
			}
			activeMultiSets[i][active] = true
		}
	}

	// Process multi NAT tags.
	// Collect to be added and to be ignored tags.
	ignore := make(map[string]bool)
	toAdd := make(map[string]bool)
	for _, m := range activeMultiSets {
		add := ""

		// Analyze active and inactive tags.
		if !m[""] {
			var realTag string
			for tag := range m {
				if natType[tag] != "hidden" {
					if realTag != "" {

						// Ignore multiple real tags.
						realTag = ""
						break
					}
					realTag = tag
				}
			}

			// Add single real tag with ignored hidden tags or ignore
			// multiple tags.
			add = realTag
		}
		if add != "" {
			toAdd[add] = true
		}
		// Ignore all tags, if none is active.

		// Tag that is ignored in one multi set must be ignored completely.
		for tag := range m {
			if tag == add {
				continue
			}
			ignore[tag] = true
		}
	}
	for tag := range toAdd {
		if ignore[tag] {
			continue
		}
		combined[tag] = true
	}
	return combined
}
