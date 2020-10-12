package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"sort"
	"strings"
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

//############################################################################
// Comment: Check for equal type of NAT definitions.
//          This is used for more efficient check of dynamic NAT rules,
//          so we need to check only once for each pair of src / dst zone.
// Returns: A map, mapping NAT tag to its type: static, dynamic or hidden.
func getLookupMapForNatType() map[string]string {
	natTag2network := make(map[string]*network)
	natType := make(map[string]string)
	for _, n := range allNetworks {
		tags := make(stringList, 0)
		for tag, _ := range n.nat {
			tags.push(tag)
		}
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
					errMsg("All definitions of nat:%s must have equal type.\n"+
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

// Mark invalid NAT transitions.
// A transition from nat:t1 to nat:t2 occurs at an interface I
// - if nat:t1 was active previously
// - and nat:t2 is activated at I with "bind_nat = t2".
// This transition is invalid
// - if a network:n1 exists having NAT definitions for both t1 and t2
// - and some other network:n2 exists having a NAT definition for t1,
//   but not for t2.
func markInvalidNatTransitions(multi map[string][]natMap) map[string]natMap {
	result := make(map[string]natMap)
	for _, list := range multi {
		if len(list) == 1 {
			continue
		}
		union := make(map[string]bool)
		for _, multiNatMap := range list {
			for tag, _ := range multiNatMap {
				union[tag] = true
			}
		}
		count := len(union)
		for _, multiNatMap := range list {
			if len(multiNatMap) == count {
				continue
			}
			var missing stringList
			for tag, _ := range union {
				if multiNatMap[tag] == nil {
					missing.push(tag)
				}
			}
			for tag1, _ := range multiNatMap {
				natNet := multiNatMap[tag1]
				m := result[tag1]
				if m == nil {
					m = make(natMap)
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

//#############################################################################
// Returns   : Map with NAT tags occurring in multi NAT definitions
//             (several NAT definitions grouped at one network) as keys
//             and arrays of NAT maps containing the key NAT tag as values.
// Comments: Also checks consistency of multi NAT tags at one network. If
//           non hidden NAT tags are grouped at one network, the same NAT
//           tags must be used as group in all other occurrences to avoid
//           ambiguities: Suppose tags A and B are both defined at network n1,
//           but only A is defined at network n2. An occurence of
//           bind_nat = A activates NAT:A. A successive bind_nat = B activates
//           NAT:B, but implicitly disables NAT:A, as for n1 only one NAT can be
//           active at a time. As NAT:A can not be active (n2) and inactive
//           (n1) in the same NAT domain, this restriction is needed.
func generateMultinatDefLookup(natType map[string]string) map[string][]natMap {
	multi := make(map[string][]natMap)

	// Check if two natMaps contain the same keys. Values can be different.
	keysEq := func(m1, m2 natMap) bool {
		if len(m1) != len(m2) {
			return false
		}
		for tag, _ := range m1 {
			if m2[tag] == nil {
				return false
			}
		}
		return true
	}

	for _, n := range allNetworks {
		map1 := n.nat
		tags := make(stringList, 0)
		for tag, _ := range map1 {
			tags.push(tag)
		}
		sort.Strings(tags)
		//debug("%s nat=%s", n, strings.Join(tags, ","))

	NAT_TAG:
		for _, tag := range tags {
			if list := multi[tag]; list != nil {

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
						var common stringList
						for tag, _ := range map1 {
							if map2[tag] != nil {
								common.push(tag)
							}
						}
						if len(common) == len(map1) {

							// Ignore new natMap, because it is subset.
							continue NAT_TAG
						} else if len(common) == len(map2) {

							// Replace previous natMap by new superset.
							list[i] = map1
							continue NAT_TAG
						}
					}
				}
			}
			multi[tag] = append(multi[tag], map1)
		}
	}

	// Remove entry if nat tag never occurs in multi nat definitions (grouped).
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

//#############################################################################
// Purpose : Divide topology into NAT domains.
//           Networks and NAT domain limiting routers keep references
//           to their domains.
// Results : domain has lists of its zones and limiting routers,
//           routers that are domain limiting, contain references to the
//           limited domains and store NAT tags bound to domains border
//           interfaces.
func findNatDomains() []*natDomain {

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
			if intf.mainIntf != nil {
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
				if outIntf.mainIntf != nil {
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
					errMsg("Inconsistent NAT in loop at %s:\n"+
						" nat:%s vs. nat:%s",
						r, names1, names2)
					continue
				}

				// Mark router as domain limiting, add router as domain border.
				if r.natTags == nil {
					r.natTags = make(map[*natDomain]stringList)
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
				warnMsg("Ignoring %s without effect, bound at every interface of %s",
					list, r)
			}
		}
	}

	var result []*natDomain
	for _, z := range zones {
		if z.natDomain != nil {
			continue
		}
		name := "nat_domain:" + strings.SplitN(z.name, ":", 2)[1]
		natSet := make(map[string]bool)
		d := &natDomain{
			name:   name,
			natSet: &natSet,
		}
		result = append(result, d)
		setNatDomain(z, d, nil)
	}
	return result
}

//#############################################################################
// Purpose : Show interfaces, where bind_nat for NAT tag is missing.
func errMissingBindNat(inRouter *router, d *natDomain, tag string, multinatMaps []natMap) {

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

	sortByNameUniq := func(l intfList) intfList {
		seen := make(map[*routerIntf]bool)
		j := 0
		for _, intf := range l {
			if !seen[intf] {
				seen[intf] = true
				l[j] = intf
				j++
			}
		}
		l = l[:j]
		sort.Slice(l, func(i, j int) bool {
			return l[i].name < l[j].name
		})
		return l
	}
	natIntf = sortByNameUniq(natIntf)
	missingIntf = sortByNameUniq(missingIntf)
	errMsg("Incomplete 'bind_nat = %s' at\n"+
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

//#############################################################################
// Purpose:   Show errors for invalid transitions of grouped NAT tags.
// Parameter: tag: NAT tag that is distributed during domain traversal.
//            tag2: NAT tag that implicitly deactivates tag.
//            nat: NAT map of network with both tag and tag2 defined.
//            invalid: Map from NAT tags t1, t2 to network,
//                where transition from t1 to t2 is invalid.
//            r: router where NAT transition occurs at.
func checkForProperNatTransition(tag, tag2 string, nat natMap, invalid map[string]natMap, r *router) {
	natInfo := nat[tag]
	nextInfo := nat[tag2]

	// Transition from hidden NAT to any other NAT is invalid.
	if natInfo.hidden {

		// Use nextInfo.name and not natInfo.name because
		// natInfo may show wrong network, because we combined
		// different hidden networks into natTag2multinatDdef.
		errMsg("Must not change hidden nat:%s using nat:%s\n"+
			" for %s at %s", tag, tag2, nextInfo, r)
	} else if natInfo.dynamic && !nextInfo.dynamic {

		// Transition from dynamic to static NAT is invalid.
		errMsg("Must not change dynamic nat:%s to static using nat:%s\n"+
			" for %s at %s", tag, tag2, natInfo, r)
	} else if n := invalid[tag][tag2]; n != nil {

		// Transition from tag to tag2 is invalid,
		// if tag occurs somewhere not grouped with tag2.
		errMsg("Invalid transition from nat:%s to nat:%s at %s.\n"+
			" Reason: Both NAT tags are used grouped at %s\n"+
			" but nat:%s is missing at %s",
			tag, tag2, r, natInfo, tag2, n)
	}
}

//#############################################################################
// Purpose:    Performs a depth first traversal to distribute specified
//             NAT tag to reachable domains where NAT tag is active;
//             checks whether NAT declarations are applied correctly.
// Parameters: inRouter: Router domain was entered from.
//             d: Domain the depth first traversal proceeds from.
//             tag: NAT tag that is to be distributed.
//             multinatMaps: List of multi NAT maps containing nat_tag.
//             invalid: Map with pairs of NAT tags as keys,
//                 where transition from first to second tag is invalid.
// Results:    All domains, where NAT tag is active contain 'tag' in their
//             natSet.
// Returns:    false on success,
//             true on error, if same NAT tag is reached twice.
func distributeNat1(inRouter *router, d *natDomain, tag string, multinatMaps []natMap, invalid map[string]natMap) bool {
	//debug("nat:%s at %s from %s", tag, d.name, inRouter)

	// Loop found or domain was processed by earlier call of distributeNat.
	natSet := *d.natSet
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
						checkForProperNatTransition(tag, tag2, m, invalid, r)
						continue DOMAIN
					}
				}
			}

			// tag is active within adjacent domain: proceed traversal
			//debug("Caller %s", d.name)
			if distributeNat1(r, outDom, tag, multinatMaps, invalid) {
				return true
			}
		}
	}
	return false
}

//#############################################################################
// Purpose:    Calls distribute_nat1 to distribute specified NAT tag
//             to reachable domains where NAT tag is active. Generate
//             error message, if called function returns an error value.
// Parameters: in: router the depth first traversal starts at.
//             d: Domain the depth first traversal starts at.
//             tag: NAT tag that is to be distributed.
//             multinatMaps: List of multi NAT maps containing nat_tag.
//             invalid: Map with pairs of NAT tags as keys,
//                 where transition from first to second tag is invalid.
// Returns:    true if NAT errors have occured.
func distributeNat(in *router, d *natDomain, tag string, multinatMaps []natMap, invalid map[string]natMap) bool {
	if distributeNat1(in, d, tag, multinatMaps, invalid) {
		errMissingBindNat(in, d, tag, multinatMaps)
		return true
	}
	return false
}

//#############################################################################
// Purpose: Distribute NAT tags to domains they are active in.
// Returns: true if NAT errors have occured.
func distributeNatTagsToNatDomains(multi map[string][]natMap, doms []*natDomain) bool {
	invalid := markInvalidNatTransitions(multi)
	var natErrors bool
	for _, d := range doms {
		for _, r := range d.routers {
			natTags := r.natTags[d]
			// debug("%s %s: %s", d.name, r, strings.Join(natTags, ",")
			for _, tag := range natTags {
				multinatMaps := multi[tag]
				natErrors = natErrors || distributeNat(r, d, tag, multinatMaps, invalid)
			}
		}
	}
	return natErrors
}

//############################################################################
// Purpose: For networks with multiple NAT definitions, at most one NAT
//          definition must be active in a domain. Show error otherwise.
func checkMultinatErrors(multi map[string][]natMap, doms []*natDomain) {
	for _, d := range doms {
		seen := make(map[string]bool)
		natSet := *d.natSet
		var errors stringList
		for tag, _ := range natSet {
			for _, m := range multi[tag] {
				for tag2, natNet := range m {
					if tag2 == tag {
						continue
					}
					if !natSet[tag2] {
						continue
					}
					var pair string
					if tag2 > tag {
						pair = tag + ", " + tag2
					} else {
						pair = tag2 + ", " + tag
					}
					if seen[pair] {
						continue
					}
					seen[pair] = true
					errors.push(fmt.Sprintf("Grouped NAT tags '%s' of %s"+
						" must not both be active at\n", pair, natNet) +
						getNatDomainBorders(d).nameList())
				}
			}
		}
		sort.Strings(errors)
		for _, m := range errors {
			errMsg(m)
		}
	}
}

//############################################################################
// Purpose: Check that every NAT tag is both bound and defined somewhere.
func checkNatDefinitions(natType map[string]string, doms []*natDomain) {
	natDefinitions := make(map[string]bool)
	for tag, _ := range natType {
		natDefinitions[tag] = true
	}
	for _, d := range doms {
		for _, r := range d.routers {
			natTags := r.natTags[d]
			for _, tag := range natTags {
				if _, found := natDefinitions[tag]; found {
					natDefinitions[tag] = false
					continue
				}

				// Prevent undefined value when checking NAT type later.
				natType[tag] = "static"

				warnMsg("Ignoring useless nat:%s bound at %s", tag, r)
			}
		}
	}
	var messages stringList
	for tag, unused := range natDefinitions {
		if unused {
			messages.push(
				fmt.Sprintf("nat:%s is defined, but not bound to any interface", tag))
		}
	}
	sort.Strings(messages)
	for _, m := range messages {
		warnMsg(m)
	}
}

//############################################################################
// Purpose:   Network which has translation with tag 'tag' must not be located
//            in domain where this tag is active.
func checkNatNetworkLocation(doms []*natDomain) {
	for _, d := range doms {
		natSet := *d.natSet
		for _, z := range d.zones {
			for _, n := range z.networks {
				natMap := n.nat
				var messages stringList
				for tag, _ := range natMap {
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
					errMsg(m)
				}
			}
		}
	}
}

//############################################################################
// Purpose: Check compatibility of host/interface and network NAT.
// Comment: A NAT definition for a single host/interface is only allowed,
//          if network has a dynamic NAT definition.
func checkNatCompatibility() {
	for _, n := range allNetworks {
		check := func(obj netObj) {
			nat := obj.nat
			if nat == nil {
				return
			}
			var tags stringList
			for tag, _ := range obj.nat {
				tags.push(tag)
			}
			sort.Strings(tags)
			for _, tag := range tags {
				objIP := nat[tag]
				natNet := n.nat[tag]
				if natNet != nil && natNet.dynamic {
					if !matchIp(objIP, natNet.ip, natNet.mask) {
						errMsg("nat:%s: IP of %s doesn't match IP/mask of %s",
							tag, obj, n)
					}
				} else {
					warnMsg(
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

//############################################################################
// Purpose: Find interface with dynamic NAT which is bound at the same
//          device. This is invalid for device with "need_protect".
// Comment: "need_protect" devices use NetSPoC generated ACLs to manage access
//          to their interfaces. To ensure safety, the devices interfaces
//          need to have a fixed address.
func checkInterfacesWithDynamicNat() {
	for _, n := range allNetworks {
		var tags stringList
		for tag, _ := range n.nat {
			tags.push(tag)
		}
		sort.Strings(tags)
		for _, tag := range tags {
			info := n.nat[tag]
			if !info.dynamic || (info.identity || info.hidden) {
				continue
			}
			for _, intf := range n.interfaces {
				intfNat := intf.nat

				// Interface has static translation,
				if intfNat != nil && intfNat[tag] != nil {
					continue
				}

				r := intf.router
				if !r.needProtect {
					continue
				}
				for _, bindIntf := range r.interfaces {
					for _, tag2 := range bindIntf.bindNat {
						if tag2 == tag {
							errMsg(
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

//############################################################################
// Result : natSet is stored at logical and hardware interfaces of
//          managed and semi managed routers.
// Comment: Neccessary at semi managed routers to calculate .up relation
//          between subnets.
func distributeNatSetsToInterfaces(doms []*natDomain) {
	for _, d := range doms {
		natSet := d.natSet
		for _, z := range d.zones {
			for _, intf := range z.interfaces {
				r := intf.router
				if r.managed == "" && !r.semiManaged {
					continue
				}

				// debug("%s: NAT %s", d.name, intf)
				intf.natSet = natSet
				if (r.managed != "" || r.routingOnly) && !intf.tunnel {
					intf.hardware.natSet = natSet
				}
			}
		}
	}
}

func prepareRealIpNat(r *router, multi map[string][]natMap, natType map[string]string) {

	var twoEffective [2]map[string]bool
	var twoHWList [2][]*hardware
HARDWARE:
	for _, hw := range r.hardware {

		// Build effective list of bound NAT tags.
		// Remove hidden NAT. This doesn't matter because errors with
		// hidden addresses will be detected before this is used.
		effective := make(map[string]bool)
		for _, tag := range hw.bindNat {
			if natType[tag] != "hidden" {
				effective[tag] = true
			}
		}

		// Find identical effective bound NAT tags.
	EQ:
		for i, seen := range twoEffective {
			if seen == nil {
				twoEffective[i] = effective
			} else {
				if len(effective) != len(seen) {
					continue EQ
				}
				for tag, _ := range effective {
					if !seen[tag] {
						continue EQ
					}
				}
			}
			twoHWList[i] = append(twoHWList[i], hw)
			continue HARDWARE
		}
		errMsg(
			"Must not use attribute 'acl_use_real_ip' at %s\n"+
				" having different effective NAT at more than two interfaces", r)
		return
	}
	if twoEffective[1] == nil {
		warnMsg("Useless attribute 'acl_use_real_ip' at %s", r)
		return
	}

	combine := func(list []*hardware) natSet {
		var natSets []natSet
		for _, hw := range list {
			natSets = append(natSets, hw.natSet)
		}
		return combineNatSets(natSets, multi, natType)
	}
	modify := func(list []*hardware, new natSet) {
		for _, hw := range list {
			hw.dstNatSet = new
		}
	}

	// Found two sets of hardware having identical effective bound NAT.
	// Combine natSets of each set of hardware.
	// Modify dstNatSet of other set of hardware with combined natSet.
	set1 := combine(twoHWList[0])
	set2 := combine(twoHWList[1])
	modify(twoHWList[0], set2)
	modify(twoHWList[1], set1)
}

func prepareRealIpNatRouters(multi map[string][]natMap, natType map[string]string) {
	for _, r := range append(managedRouters, routingOnlyRouters...) {
		if r.aclUseRealIp {
			prepareRealIpNat(r, multi, natType)
		}
	}
}

//############################################################################
// Purpose : Determine NAT domains and generate NAT set
//           for every NAT domain.
func DistributeNatInfo() ([]*natDomain, map[string]string, map[string][]natMap) {
	diag.Progress("Distributing NAT")
	natdomains := findNatDomains()
	natType := getLookupMapForNatType()
	multi := generateMultinatDefLookup(natType)
	natErrors := distributeNatTagsToNatDomains(multi, natdomains)
	checkMultinatErrors(multi, natdomains)
	checkNatDefinitions(natType, natdomains)
	if !natErrors {
		checkNatNetworkLocation(natdomains)
	}
	checkNatCompatibility()
	checkInterfacesWithDynamicNat()
	distributeNatSetsToInterfaces(natdomains)
	prepareRealIpNatRouters(multi, natType)

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
func combineNatSets(sets []natSet, multi map[string][]natMap, natType map[string]string) natSet {
	if len(sets) == 1 {
		return sets[0]
	}

	// Collect single NAT tags and multi NAT maps.
	combined := make(map[string]bool)
	var activeMulti []map[string]*network
	seen := make(map[string]bool)
	for _, set := range sets {
		for tag, _ := range *set {
			if list := multi[tag]; list != nil {
				for _, multiNatMap := range list {
					allSeen := true
					for tag, _ := range multiNatMap {
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
	for i, _ := range activeMultiSets {
		activeMultiSets[i] = make(map[string]bool)
	}
	for _, set := range sets {
		for tag, _ := range combined {
			if (*set)[tag] {
				continue
			}
			if multi[tag] != nil {
				continue
			}
			delete(combined, tag)
		}
		for i, multiNatMap := range activeMulti {
			active := ""
			for tag, _ := range multiNatMap {
				if (*set)[tag] {
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
			for tag, _ := range m {
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
		for tag, _ := range m {
			if tag == add {
				continue
			}
			ignore[tag] = true
		}
	}
	for tag, _ := range toAdd {
		if ignore[tag] {
			continue
		}
		combined[tag] = true
	}
	return &combined
}
