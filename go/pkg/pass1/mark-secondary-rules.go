package pass1

import (
	"net"
)

func matchIp(ip, i net.IP, m net.IPMask) bool {
	return i.Equal(ip.Mask(m))
}

//#############################################################################
// Mark rules for secondary filtering.
// A rule is implemented at a device
// either as a 'typical' or as a 'secondary' filter.
// A filter is called to be 'secondary' if it only checks
// for the source and destination network and not for the protocol.
// A typical filter checks for full source and destination IP and
// for the protocol of the rule.
//
// There are four types of packet filters: secondary, standard, full, primary.
// A rule is marked by two attributes which are determined by the type of
// devices located on the path from source to destination.
// - 'some_primary': at least one device is primary packet filter,
// - 'some_non_secondary': at least one device is not secondary packet filter.
// A rule is implemented as a secondary filter at a device if
// - the device is secondary and the rule has attribute 'some_non_secondary' or
// - the device is standard and the rule has attribute 'some_primary'.
// Otherwise a rules is implemented typical.
//#############################################################################

// Mark security zone zone and additionally mark all security zones
// which are connected with zone by secondary packet filters.
func markSecondary(zone *zone, mark int) {
	zone.secondaryMark = mark

	//	debug("%d %s", mark, zone.name);
	for _, inIntf := range zone.interfaces {
		if inIntf.mainIntf != nil {
			continue
		}
		router := inIntf.router
		if m := router.managed; m != "" {
			if m != "secondary" && m != "local" {
				continue
			}
		}
		zone.hasSecondary = true
		if router.secondaryMark != 0 {
			continue
		}
		router.secondaryMark = mark
		for _, outIntf := range router.interfaces {
			if outIntf == inIntf {
				continue
			}
			if outIntf.mainIntf != nil {
				continue
			}
			nextZone := outIntf.zone
			if nextZone.secondaryMark != 0 {
				continue
			}
			markSecondary(nextZone, mark)
		}
	}
}

// Mark security zone zone with mark and
// additionally mark all security zones
// which are connected with zone by non-primary packet filters.
func markPrimary(zone *zone, mark int) {
	zone.primaryMark = mark
	for _, inIntf := range zone.interfaces {
		if inIntf.mainIntf != nil {
			continue
		}
		router := inIntf.router
		if router.managed == "primary" {
			continue
		}
		zone.hasNonPrimary = true
		if router.primaryMark != 0 {
			continue
		}
		router.primaryMark = mark
		for _, outIntf := range router.interfaces {
			if outIntf == inIntf {
				continue
			}
			if outIntf.mainIntf != nil {
				continue
			}
			nextZone := outIntf.zone
			if nextZone.primaryMark != 0 {
				continue
			}
			markPrimary(nextZone, mark)
		}
	}
}

func getZones(path pathStore, list []someObj) []*zone {
	switch x := path.(type) {
	case *zone:
		return []*zone{x}
	case *routerIntf:
		return []*zone{x.zone}
	case *router:
		result := make([]*zone, 0)
		seen := make(map[*zone]bool)
		// Elements of list are interfaces of x.
		// Collect attached zones without duplicates.
		for _, obj := range list {
			z := obj.(*routerIntf).zone
			if !seen[z] {
				seen[z] = true
				result = append(result, z)
			}
		}
		return result
	}
	return nil
}

func haveDifferentMarks(srcZones, dstZones []*zone, getMark func(*zone) int) bool {
	srcMarks := make(map[int]bool)
	for _, z := range srcZones {
		srcMarks[getMark(z)] = true
	}
	for _, z := range dstZones {
		if srcMarks[getMark(z)] {
			return false
		}
	}
	return true
}

type conflictKey = struct {
	isSrc     bool
	isPrimary bool
	mark      int
	zone      *zone
}

type conflictInfo = struct {
	supernets map[*network]bool
	rules     []*groupedRule
}

// Collect conflicting rules and supernet rules for check_conflict below.
func collectConflict(rule *groupedRule, srcZones, dstZones []*zone, src, dst []someObj, conflict map[conflictKey]*conflictInfo, isPrimary bool) {
	allEstablished := true
	for _, p := range rule.prt {
		if p.modifiers.noCheckSupernetRules {
			return
		}
		if !p.established {
			allEstablished = false
		}
	}
	collect := func(zones, otherZones []*zone, list []someObj, isSrc bool) {
		for _, zone := range zones {
			var mark int
			if isPrimary {
				if !zone.hasNonPrimary {
					continue
				}
				mark = zone.primaryMark
			} else {
				if !zone.hasSecondary {
					continue
				}
				mark = zone.secondaryMark
			}
			pushed := false
			for _, otherZone := range otherZones {
				key := conflictKey{isSrc, isPrimary, mark, otherZone}
				info, found := conflict[key]
				if !found {
					info = &conflictInfo{supernets: make(map[*network]bool)}
					conflict[key] = info
				}
				for _, obj := range list {
					switch x := obj.(type) {
					case *network:
						if x.hasOtherSubnet {
							if !allEstablished {
								info.supernets[x] = true
							}
							continue
						}
					}
					if !pushed {
						info.rules = append(info.rules, rule)
						pushed = true
					}
				}
			}
		}
	}
	collect(srcZones, dstZones, src, true)
	collect(dstZones, srcZones, dst, false)
}

// Disable secondary optimization for conflicting rules.
//
//## Case A:
// Topology:
// src--R1--any--R2--dst,
// with R1 is "managed=secondary"
// Rules:
// 1. permit any->net:dst, telnet
// 2. permit host:src->host:dst, http
// Generated ACLs:
// R1:
// permit net:src->net:dst ip (with secondary optimization)
// R2:
// permit any net:dst telnet
// permit host:src host:dst http
// Problem:
// - src would be able to access dst with telnet, but only http was permitted,
// - the whole network of src would be able to access dst, even if
//   only a single host of src was permitted.
// - src would be able to access the whole network of dst, even if
//   only a single host of dst was permitted.
//
//## Case B:
// Topology:
// src--R1--any--R2--dst,
// with R2 is "managed=secondary"
// Rules:
// 1. permit net:src->any, telnet
// 2. permit host:host:src->host:dst, http
// Generated ACLs:
// R1:
// permit net:src any telnet
// permit host:src host:dst http
// R2
// permit net:src net:dst ip
// Problem: Same as case A.
func checkConflict(conflict map[conflictKey]*conflictInfo) {
	type pair struct {
		super *network
		net   *network
	}
	cache := make(map[pair]bool)
	for key, val := range conflict {
		isSrc, isPrimary := key.isSrc, key.isPrimary
		supernetMap := val.supernets
		if supernetMap == nil {
			continue
		}
		rules := val.rules
		if rules == nil {
			continue
		}
	RULE:
		for _, rule1 := range rules {
			var zone1 pathStore
			var objects []someObj
			if isSrc {
				zone1 = rule1.srcPath
				objects = rule1.src
			} else {
				zone1 = rule1.dstPath
				objects = rule1.dst
			}
			var list1 []*network
			for _, obj := range objects {
				var net *network
				switch x := obj.(type) {
				case *routerIntf:
					net = x.network
				case *subnet:
					net = x.network
				case *network:
					if x.hasOtherSubnet {
						continue
					}
					net = x
				}
				list1 = append(list1, net)
			}
			for supernet, _ := range supernetMap {
				var zone2 pathStore = supernet.zone
				if zone1 == zone2 {
					continue
				}
				for _, network := range list1 {
					isSubnet, found := cache[pair{supernet, network}]
					if !found {
						ip, mask := network.ip, network.mask
						prefix, _ := mask.Size()
						natSet := network.zone.natDomain.natSet
						obj := getNatNetwork(supernet, natSet)
						i, m := obj.ip, obj.mask
						p, _ := m.Size()
						isSubnet = p < prefix && matchIp(ip, i, m)
						cache[pair{supernet, network}] = isSubnet
					}
					if !isSubnet {
						continue
					}
					if isPrimary {
						rule1.somePrimary = false
					} else {
						rule1.someNonSecondary = false
					}
					/*					name1 := ""
										if s := rule1.rule.service; s != nil {
											name1 = s.name
										}
										debug("%s isSrc:%v", name1, isSrc)
										debug(rule1.print())
										debug("%s < %s", network.name, supernet.name)
					*/
					continue RULE
				}
			}
		}
	}
}

func MarkSecondaryRules() {
	progress("Marking rules for secondary optimization")

	secondaryMark := 1
	primaryMark := 1
	for _, zone := range zones {
		if zone.secondaryMark == 0 {
			markSecondary(zone, secondaryMark)
			secondaryMark++
		}
		if zone.primaryMark == 0 {
			markPrimary(zone, primaryMark)
			primaryMark++
		}
	}

	// Mark only permit rules for secondary optimization.
	// Don't modify a deny rule from e.g. tcp to ip.
	// Collect conflicting optimizeable rules and supernet rules.
	conflict := make(map[conflictKey]*conflictInfo)
	for _, rule := range pRules.permit {
		src, dst, srcPath, dstPath :=
			rule.src, rule.dst, rule.srcPath, rule.dstPath

		// Type of srcPath / dstPath is zone, interface or router.
		// If type is router, then src/dst may contain interfaces of
		// different zones with different values of secondaryMark/primaryMark.
		// Only do optimization, if all interfaces would allow optimization.
		srcZones := getZones(srcPath, src)
		dstZones := getZones(dstPath, dst)
		getS := func(z *zone) int { return z.secondaryMark }
		if haveDifferentMarks(srcZones, dstZones, getS) {
			rule.someNonSecondary = true
			collectConflict(rule, srcZones, dstZones, src, dst, conflict, false)
		}
		getP := func(z *zone) int { return z.primaryMark }
		if haveDifferentMarks(srcZones, dstZones, getP) {
			rule.somePrimary = true
			collectConflict(rule, srcZones, dstZones, src, dst, conflict, true)
		}
	}
	checkConflict(conflict)
}
