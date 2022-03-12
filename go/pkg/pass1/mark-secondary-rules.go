package pass1

import ()

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
func markSecondary(z *zone, mark int) {
	z.secondaryMark = mark

	//	debug("%d %s", mark, z.name);
	for _, inIntf := range z.interfaces {
		if inIntf.mainIntf != nil {
			continue
		}
		r := inIntf.router
		if m := r.managed; m != "" {
			if m != "secondary" && m != "local" {
				continue
			}
		}
		z.hasSecondary = true
		if r.secondaryMark != 0 {
			continue
		}
		r.secondaryMark = mark
		for _, outIntf := range r.interfaces {
			if outIntf == inIntf {
				continue
			}
			if outIntf.mainIntf != nil {
				continue
			}
			next := outIntf.zone
			if next.secondaryMark == 0 {
				markSecondary(next, mark)
			}
		}
	}
}

// Mark security zone zone with mark and
// additionally mark all security zones
// which are connected with zone by non-primary packet filters.
func markPrimary(z *zone, mark int) {
	z.primaryMark = mark
	for _, inIntf := range z.interfaces {
		if inIntf.mainIntf != nil {
			continue
		}
		r := inIntf.router
		if r.managed == "primary" {
			continue
		}
		z.hasNonPrimary = true
		if r.primaryMark != 0 {
			continue
		}
		r.primaryMark = mark
		for _, outIntf := range r.interfaces {
			if outIntf == inIntf {
				continue
			}
			if outIntf.mainIntf != nil {
				continue
			}
			next := outIntf.zone
			if next.primaryMark == 0 {
				markPrimary(next, mark)
			}
		}
	}
}

// Find zone of src/dst elements of rule.
// Return nil, if zone of elements can't be determined.
func getZone(path pathStore, list []someObj) *zone {
	var result *zone
	switch x := path.(type) {
	case *zone:
		result = x
	case *routerIntf:
		result = x.zone
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
			result = x.interfaces[0].zone
			break
		}
		var l *zone
		for _, obj := range list {
			intf := obj.(*routerIntf)
			if intf.loopback {
				l = intf.zone
			} else if result == nil {
				result = intf.zone
			} else if result != intf.zone {
				return nil
			}
		}
		if result == nil {
			result = l
		}
	}
	return result
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

// Collect potentially conflicting rules and supernet rules for
// checkConflict below.
func collectConflict(rule *groupedRule, z1, z2 *zone,
	conflict map[conflictKey]*conflictInfo, isPrimary bool) {

	if rule.noCheckSupernetRules {
		return
	}
	allEstablished := true
	for _, p := range rule.prt {
		if !p.established {
			allEstablished = false
		}
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
		seen := make(map[*network]bool)
		for _, other := range otherList {
			otherNet := other.getNetwork()
			if seen[otherNet] {
				continue
			}
			seen[otherNet] = true
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
// 2. permit host:src->host:dst, http
// Generated ACLs:
// R1:
// permit net:src any telnet
// permit host:src host:dst http
// R2
// permit net:src net:dst ip
// Problem: Same as case A.
func checkConflict(conflict map[conflictKey]*conflictInfo) {
	for key, val := range conflict {
		supernetMap := val.supernets
		if len(supernetMap) == 0 {
			continue
		}
		isSrc, isPrimary := key.isSrc, key.isPrimary
	RULE:
		for _, rule1 := range val.rules {
			var objects []someObj
			if isSrc {
				objects = rule1.src
			} else {
				objects = rule1.dst
			}
			var list1 netList
			seen := make(map[*network]bool)
			for _, obj := range objects {
				var n *network
				switch x := obj.(type) {
				case *routerIntf:
					n = x.network
				case *subnet:
					n = x.network
				case *network:
					if x.hasOtherSubnet {
						continue
					}
					n = x
				}
				if !seen[n] {
					seen[n] = true
					list1.push(n)
				}
			}
			for supernet := range supernetMap {
				z := supernet.zone
				for _, n := range list1 {
					if zoneEq(n.zone, z) {
						continue
					}
					obj := getNatNetwork(supernet, n.zone.natDomain.natMap)
					if !(obj.ipp.Bits() < n.ipp.Bits() &&
						obj.ipp.Contains(n.ipp.IP())) {

						continue
					}
					if isPrimary {
						rule1.somePrimary = false
					} else {
						rule1.someNonSecondary = false
					}

					//name1 := ""
					//if r := rule1.rule; r != nil {
					//	name1 = r.service.name
					//}
					//debug("%s isSrc:%v", name1, isSrc)
					//debug(rule1.print())
					//debug("%s < %s", n.name, supernet.name)

					continue RULE
				}
			}
		}
	}
}

func (c *spoc) markSecondaryRules() {
	c.progress("Marking rules for secondary optimization")

	secondaryMark := 1
	primaryMark := 1
	for _, z := range c.allZones {
		if z.secondaryMark == 0 {
			markSecondary(z, secondaryMark)
			secondaryMark++
		}
		if z.primaryMark == 0 {
			markPrimary(z, primaryMark)
			primaryMark++
		}
	}

	// Mark only permit rules for secondary optimization.
	// Don't modify a deny rule from e.g. tcp to ip.
	// Collect conflicting optimizeable rules and supernet rules.
	conflict := make(map[conflictKey]*conflictInfo)
	for _, rule := range c.allPathRules.permit {
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
