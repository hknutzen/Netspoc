package pass1

import (
	"net"
	"sort"
)

func getZoneClusterBorders(z *zone) intfList {
	var result intfList
	for _, z := range z.cluster {
		for _, intf := range z.interfaces {
			if intf.router.managed != "" {
				result.push(intf)
			}
		}
	}
	return result
}

// Check path for at least one managed device R that is filtering
// original address of network n.
func pathHasFullFilter(tag string, pairs intfPairs) bool {
	hasNATPrimary := false
	hasFull := false
	hasStandard := false
	for _, pair := range pairs {
		r := pair[0].router
		inLoop := pair[0].loop != nil && pair[1].loop != nil
		filtersNAT := (*pair[0].natSet)[tag]
		if filtersNAT || inLoop {
			if r.managed == "primary" {
				hasNATPrimary = true
			}
			continue
		}
		switch r.managed {
		case "primary", "full":
			hasFull = true
		case "standard":
			hasStandard = true
		}
	}
	if hasNATPrimary {
		return hasFull
	} else {
		return hasStandard || hasFull
	}
}

// Disable secondary optimization for networks with active dynamic NAT
// at border routers of zone cluster of these networks.
// This is neccessary because we would accidently permit traffic for
// the whole network where only a single host should be permitted.
func disableSecondOptForDynHostNet(n *network, tag string, p intfPairs) {
	if pathHasFullFilter(tag, p) {
		return
	}
	z := n.zone
	for _, intf := range getZoneClusterBorders(z) {
		r := intf.router
		nMap := r.noSecondaryOpt
		if nMap == nil {
			nMap = make(netMap)
			r.noSecondaryOpt = nMap
		}
		nMap[n] = true
	}
}

// 1. Check for invalid rules accessing hidden objects.
// 2. Check host rule with dynamic NAT.
// 3. Check for partially applied hidden or dynamic NAT on path.
func (c *spoc) checkDynamicNatRules(
	natDoms []*natDomain, natTag2natType map[string]string) {

	c.progress("Checking and marking rules with hidden or dynamic NAT")

	// 1. Collect hidden or dynamic NAT tags that
	//    a) are active inside natSet (i.e. NAT domain),
	//    b) are defined inside zone.
	// 2. Mark networks having host or interface with dynamic NAT
	natSet2activeTags := make(map[natSet]map[string]bool)
	zone2dynNat := make(map[*zone]map[string]bool)
	hasDynHost := make(map[*network]bool)
	for _, n := range c.allNetworks {
		foundDyn := false
		tagMap := n.nat
		if len(tagMap) == 0 {
			continue
		}
		z := n.zone
		zTagMap := zone2dynNat[z]
		if zTagMap == nil {
			zTagMap = make(map[string]bool)
			zone2dynNat[z] = zTagMap
		}
	TAG:
		for natTag, natNetwork := range tagMap {

			// We already know, that type of natTag is equal at
			// all networks.
			typ := natTag2natType[natTag]
			if typ != "static" {
				zTagMap[natTag] = true
			}

			// Check for host or interface with dynamic NAT.
			if !foundDyn && natNetwork.dynamic && !natNetwork.hidden {
				for _, s := range n.subnets {
					if s.nat[natTag] == nil {
						foundDyn = true
						continue TAG
					}
				}
				for _, intf := range n.interfaces {
					if intf.nat[natTag] == nil {
						foundDyn = true
						continue TAG
					}
				}
			}
		}
		if foundDyn {
			hasDynHost[n] = true
		}
	}
	for _, nd := range natDoms {
		set := nd.natSet
		tagMap := natSet2activeTags[set]
		if tagMap == nil {
			tagMap = make(map[string]bool)
			natSet2activeTags[set] = tagMap
		}
		for tag, _ := range *set {
			if natTag2natType[tag] != "static" {
				tagMap[tag] = true
			}
		}
	}

	type zonePair [2]*zone
	cache := make(map[zonePair]intfPairs)
	natPathToCheck := make(map[zonePair][]string)
	type objAndZone struct {
		obj  someObj
		zone *zone
	}
	seen := make(map[objAndZone]bool)

	getPathPairs := func(r *groupedRule, rev bool, s, d *zone) intfPairs {
		if rev {
			s, d = d, s
		}
		pairs := cache[zonePair{s, d}]
		if len(pairs) == 0 {
			rule := *r
			rule.srcPath = s
			rule.dstPath = d

			// Collect managed interfaces on path.
			collect := func(r *groupedRule, inIntf, outIntf *routerIntf) {
				pairs.push(intfPair{inIntf, outIntf})
			}
			c.pathWalk(&rule, collect, "Router")
			cache[zonePair{s, d}] = pairs
		}
		return pairs
	}

	checkDynNatPath := func(pathRule *groupedRule, reversed bool, fromList []someObj, fromZone *zone, toObj someObj, toZone *zone) {
		toCheck := natPathToCheck[zonePair{fromZone, toZone}]
		if toCheck == nil {
			dynNat := zone2dynNat[fromZone]
			if len(dynNat) == 0 {
				return
			}
			pairs := getPathPairs(pathRule, reversed, fromZone, toZone)
		TAG:
			for natTag, _ := range dynNat {
				for _, pair := range pairs {
					for _, intf := range pair {
						if natSet2activeTags[intf.natSet][natTag] {
							toCheck = append(toCheck, natTag)
							continue TAG
						}
					}
				}
			}
			natPathToCheck[zonePair{fromZone, toZone}] = toCheck
		}
		if len(toCheck) == 0 {
			return
		}

		// Check with Nat set at destination object.
		dstNatSet := toZone.natDomain.natSet

		pairs := getPathPairs(pathRule, reversed, fromZone, toZone)
		for _, obj := range fromList {
			n := obj.getNetwork()
			natMap := n.nat
			if len(natMap) == 0 {
				continue
			}

			var cacheObj someObj
			if hasDynHost[n] {
				cacheObj = obj
			} else {
				cacheObj = n
			}
			if seen[objAndZone{cacheObj, toZone}] {
				continue
			}
			seen[objAndZone{cacheObj, toZone}] = true
			hiddenSeen := false
			staticSeen := false

			showRule := func() string {
				rule := *pathRule
				if reversed {
					rule.src = []someObj{toObj}
					rule.dst = []someObj{obj}
				} else {
					rule.src = []someObj{obj}
					rule.dst = []someObj{toObj}
				}
				return rule.print()
			}

			// Anonymous function is called immediately.
			// Only declared, so we can use "return" inside.
			func() {

				// Find, which NAT tag of src object is active at dst object.
				natTag := ""
				for tag, _ := range natMap {
					if (*dstNatSet)[tag] {
						natTag = tag
						break
					}
				}
				if natTag == "" {
					staticSeen = true
					return
				}

				natNet := natMap[natTag]

				// Network is hidden by NAT.
				if natNet.hidden {
					if !hiddenSeen {
						hiddenSeen = true
						c.err("%s is hidden by nat:%s in rule\n "+showRule(),
							obj.String(), natTag)
					}
					return
				}

				disableSecondOptForDynHostNet(n, natTag, pairs)

				// Ignore network.
				if obj == n {
					return
				}

				// Ignore host / interface with static NAT.
				var objNat map[string]net.IP
				switch x := obj.(type) {
				case *subnet:
					objNat = x.nat
				case *routerIntf:
					objNat = x.nat
				}
				if objNat[natTag] != nil {
					return
				}

				// Detailed check for host / interface with dynamic NAT.
				// 1. Dynamic NAT address of host / interface object is
				//    used in ACL at managed router at the border of zone
				//    of that object. Hence the whole network would
				//    accidentally be permitted.
				// 2. Check later to be added reverse rule as well.
				check := func(rule *groupedRule, inIntf, outIntf *routerIntf) {
					var r *router
					if inIntf != nil {
						r = inIntf.router
					} else {
						r = outIntf.router
					}
					if r.managed == "" {
						return
					}

					// Only check at border router.
					// intf would have value 'nil' if obj is
					// interface of current router and src/dst of rule.
					intf := inIntf
					if reversed {
						intf = outIntf
					}
					if intf != nil && !zoneEq(n.zone, intf.zone) {
						return
					}

					checkCommon := func(natIntf *routerIntf, reversed2 bool) {
						natSet := natIntf.natSet
						natNetwork := getNatNetwork(n, natSet)
						if !natNetwork.dynamic {
							return
						}
						natTag := natNetwork.natTag
						if objNat[natTag] != nil {
							return
						}
						ruleTxt := "rule"
						if reversed2 {
							ruleTxt = "reversed rule for"
						}
						c.err("%s needs static translation for nat:%s at %s"+
							" to be valid in %s\n "+showRule(),
							obj.String(), natTag, r.name, ruleTxt)
					}
					checkCommon(inIntf, false)
					if r.model.stateless {

						// Reversed tcp rule would check for
						// 'established' flag and hence is harmless
						// even if it can reach whole network, because
						// it only sends answer back for correctly
						// established connection.
						for _, prt := range rule.prt {
							if prt.proto == "udp" || prt.proto == "ip" {
								checkCommon(outIntf, true)
								break
							}
						}
					}
				}
				c.pathWalk(pathRule, check, "Router")
			}()

			if hiddenSeen {
				continue
			}

			// Check error conditition:
			// We already know that src object
			// - has static translation in dst zone and
			//   dynamic NAT is active somewhere on path or
			// - has dynamic translation in dst zone and
			//   hidden NAT is active somewhere on path.
			// Find sub-path where dynamic / hidden NAT is partially active,
			// i.e. dynamic / hidden NAT is enabled first and disabled later.
			var toCheckNext []string
			for _, natTag := range toCheck {
				natNetwork := natMap[natTag]
				if natNetwork == nil || !natNetwork.hidden && !staticSeen {
					toCheckNext = append(toCheckNext, natTag)
					continue
				}
				var natInterfaces intfList
				for _, pair := range pairs {
					for _, intf := range pair {
						if natSet2activeTags[intf.natSet][natTag] {
							natInterfaces.push(intf)
						}
					}
				}
				natInterfaces.delDupl()
				sort.Slice(natInterfaces, func(i, j int) bool {
					return natInterfaces[i].name < natInterfaces[j].name
				})
				var typ string
				if natNetwork.hidden {
					typ = "hidden"
				} else {
					typ = "dynamic"
				}
				revTxt := ""
				if reversed {
					revTxt = " reversed"
				}
				c.err("Must not apply %s NAT '%s' on path\n"+
					" of%s rule\n"+
					" %s\n"+
					" NAT '%s' is active at\n"+
					natInterfaces.nameList()+"\n"+
					" Add pathrestriction to exclude this path",
					typ, natTag, revTxt, showRule(), natTag,
				)
			}
			toCheck = toCheckNext
			natPathToCheck[zonePair{fromZone, toZone}] = toCheck
		}
	}

	process := func(list ruleList) {
		for _, rule := range list {
			if srcZone, ok := rule.srcPath.(*zone); ok {
				if dstZone, ok := rule.dstPath.(*zone); ok {
					checkDynNatPath(rule, false,
						rule.src, srcZone, rule.dst[0], dstZone)
					checkDynNatPath(rule, true,
						rule.dst, dstZone, rule.src[0], srcZone)
				} else {
					// Interface or Router
					for _, obj := range rule.dst {
						dstIntf := obj.(*routerIntf)
						dstZone := dstIntf.zone
						checkDynNatPath(rule, false,
							rule.src, srcZone, dstIntf, dstZone)
						checkDynNatPath(rule, true,
							[]someObj{dstIntf}, dstZone, rule.src[0], srcZone)
					}
				}
			} else {
				for _, obj := range rule.src {
					srcIntf := obj.(*routerIntf)
					srcZone := srcIntf.zone
					if dstZone, ok := rule.dstPath.(*zone); ok {
						checkDynNatPath(rule, false,
							[]someObj{srcIntf}, srcZone, rule.dst[0], dstZone)
						checkDynNatPath(rule, true,
							rule.dst, dstZone, srcIntf, srcZone)
					} else {
						for _, obj := range rule.dst {
							dstIntf := obj.(*routerIntf)
							dstZone := dstIntf.zone
							checkDynNatPath(rule, false,
								[]someObj{srcIntf}, srcZone, dstIntf, dstZone)
							checkDynNatPath(rule, true,
								[]someObj{dstIntf}, dstZone, srcIntf, srcZone)
						}
					}
				}
			}
		}
	}
	process(c.allPathRules.deny)
	process(c.allPathRules.permit)
}
