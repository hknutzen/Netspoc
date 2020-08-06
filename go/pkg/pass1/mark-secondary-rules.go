package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
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

func getNetwork(obj someObj) *network {
	switch x := obj.(type) {
	case *routerIntf:
		return x.network
	case *subnet:
		return x.network
	case *network:
		if x.hasOtherSubnet {
			return nil
		}
		return x
	}
	return nil
}

func getNetworks(list []someObj) []*network {
	seen := make(map[*network]bool)
	var result []*network
	for _, obj := range list {
		var n *network
		switch x := obj.(type) {
		case *subnet, *routerIntf:
			n = obj.getNetwork()
		case *network:
			n = x
		}
		if !seen[n] {
			seen[n] = true
			result = append(result, n)
		}
	}
	return result
}

func getZone(path pathStore, list []someObj) *zone {
	switch x := path.(type) {
	case *zone:
		return x
	case *routerIntf:
		return x.zone
	case *router:
		// src/dst may contain interfaces of different zones with
		// different values of secondaryMark/primaryMark.
		//
		// If router is "managed = secondary", choose zone of arbitrary
		// interface, because all zones have identical mark and
		// for all zones hasSecondary and hasNonPrimary is set.
		//
		// Loopback interface can be ignored, it has unique mark.
		if x.managed == "secondary" {
			return x.interfaces[0].zone
		}
		var z, l *zone
		for _, obj := range list {
			intf := obj.(*routerIntf)
			z2 := intf.zone
			if intf.loopback {
				l = z2
			} else if z == nil {
				z = z2
			} else if z != z2 {
				return nil
			}
		}
		if z == nil {
			return l
		}
		return z
	}
	return nil
}

type conflictKey = struct {
	isSrc     bool
	isPrimary bool
	mark      int
	net       *network
}

type conflictInfo = struct {
	supernets map[*network]bool
	rules     []*groupedRule
}

// Collect conflicting rules and supernet rules for check_conflict below.
func collectConflict(rule *groupedRule, z1, z2 *zone,
	conflict map[conflictKey]*conflictInfo, isPrimary bool) {

	allNoCheck := true
	allEstablished := true
	for _, p := range rule.prt {
		if p.modifiers == nil || !p.modifiers.noCheckSupernetRules {
			allNoCheck = false
		}
		if !p.established {
			allEstablished = false
		}
	}
	if allNoCheck {
		return
	}

	collect := func(list, otherList []someObj, z *zone, isSrc bool) {
		var mark int
		if isPrimary {
			if !z.hasNonPrimary {
				return
			}
			mark = z.primaryMark
		} else {
			if !z.hasSecondary {
				return
			}
			mark = z.secondaryMark
		}
		pushed := false
		for _, otherNet := range getNetworks(otherList) {
			if otherNet == nil {
				continue
			}
			key := conflictKey{isSrc, isPrimary, mark, otherNet}
			info, found := conflict[key]
			if !found {
				info = &conflictInfo{supernets: make(map[*network]bool)}
				conflict[key] = info
			}
			for _, obj := range list {
				if x, ok := obj.(*network); ok {
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
	collect(rule.src, rule.dst, z1, true)
	collect(rule.dst, rule.src, z2, false)
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
		if len(supernetMap) == 0 {
			continue
		}
		rules := val.rules
		if rules == nil {
			continue
		}
	RULE:
		for _, rule1 := range rules {
			var objects []someObj
			if isSrc {
				objects = rule1.src
			} else {
				objects = rule1.dst
			}
			var list1 []*network
			seen := make(map[*network]bool)
			for _, obj := range objects {
				n := getNetwork(obj)
				if n != nil && !seen[n] {
					seen[n] = true
					list1 = append(list1, n)
				}
			}
			for supernet, _ := range supernetMap {
				var z = supernet.zone
				for _, n := range list1 {
					if n.zone == z {
						continue
					}
					isSubnet, found := cache[pair{supernet, n}]
					if !found {
						ip, mask := n.ip, n.mask
						prefix, _ := mask.Size()
						natSet := n.zone.natDomain.natSet
						obj := getNatNetwork(supernet, natSet)
						i, m := obj.ip, obj.mask
						p, _ := m.Size()
						isSubnet = p < prefix && matchIp(ip, i, m)
						cache[pair{supernet, n}] = isSubnet
					}
					if !isSubnet {
						continue
					}
					if isPrimary {
						rule1.somePrimary = false
					} else {
						rule1.someNonSecondary = false
					}
					/*
						name1 := ""
						if r := rule1.rule; r != nil {
							name1 = r.service.name
						}
						debug("%s isSrc:%v", name1, isSrc)
						debug(rule1.print())
						debug("%s < %s", n.name, supernet.name)
					*/
					continue RULE
				}
			}
		}
	}
}

func MarkSecondaryRules() {
	diag.Progress("Marking rules for secondary optimization")

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
		srcZone := getZone(rule.srcPath, rule.src)
		if srcZone == nil {
			continue
		}
		dstZone := getZone(rule.dstPath, rule.dst)
		if dstZone == nil {
			continue
		}
		if srcZone.secondaryMark != dstZone.secondaryMark {
			rule.someNonSecondary = true
			collectConflict(rule, srcZone, dstZone, conflict, false)
		}
		if srcZone.primaryMark != dstZone.primaryMark {
			rule.somePrimary = true
			collectConflict(rule, srcZone, dstZone, conflict, true)
		}
	}
	checkConflict(conflict)
}
