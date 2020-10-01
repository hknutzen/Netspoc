package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"sort"
	"strings"
)

//#############################################################################
// Distribute owner, identify service owner
//#############################################################################

func propagateOwners() {

	// Inversed inheritance: If an aggregate has no direct owner and if
	// all contained toplevel networks have the same owner,
	// then set owner of this zone to the one owner.
	aggGotNetOwner := make(map[*network]bool)
	seen := make(map[*zone]bool)
	for _, z := range zones {
		if seen[z] {
			continue
		}
		cluster := z.zoneCluster
	AGGREGATE:
		for key, agg := range z.ipmask2aggregate {

			// If an explicit owner was set, it has been set for
			// the whole cluster in link_aggregates.
			if agg.owner != nil {
				continue
			}

			var found *owner
			var contained netList
			if cluster != nil {
				for _, z2 := range cluster {
					seen[z2] = true
					contained =
						append(contained, z2.ipmask2aggregate[key].networks...)
				}
			} else {
				contained = append(contained, agg.networks...)
			}
			for _, n := range contained {
				netOwner := n.owner
				if netOwner == nil {
					continue AGGREGATE
				}
				if found != nil {
					if netOwner != found {
						continue AGGREGATE
					}
				} else {
					found = netOwner
				}
			}
			if found == nil {
				continue
			}
			//debug("Inversed inherit: %s %s", agg.name, found.name)
			if cluster != nil {
				for _, z2 := range cluster {
					agg2 := z2.ipmask2aggregate[key]
					agg2.owner = found
					aggGotNetOwner[agg2] = true
				}
			} else {
				agg.owner = found
				aggGotNetOwner[agg] = true
			}
		}
	}

	getUp := func(obj ownerer) ownerer {
		var a *area
		switch x := obj.(type) {
		case *host:
			return x.network
		case *routerIntf:
			return x.network
		case *network:
			if up := x.up; up != nil {
				return up
			}
			a = x.zone.inArea
		case *area:
			a = x.inArea
		}
		if a == nil {
			return nil
		}
		return a
	}

	inherited := make(map[ownerer]ownerer)
	checked := make(map[ownerer]bool)

	var inheritOwner func(obj ownerer) (*owner, ownerer)
	inheritOwner = func(obj ownerer) (*owner, ownerer) {
		if obj == nil {
			return nil, nil
		}
		o := obj.getOwner()
		if upper := inherited[obj]; upper != nil {
			return o, upper
		}

		// Don't send inversed inherited owner down to enclosed empty
		// aggregates.
		if n, ok := obj.(*network); ok {
			if aggGotNetOwner[n] {
				return inheritOwner(getUp(obj))
			}
		}
		if o != nil {
			if !checked[obj] {
				checked[obj] = true
				o2, upper := inheritOwner(getUp(obj))
				if o2 != nil && o2 == o {
					warnMsg("Useless %s at %s,\n"+
						" it was already inherited from %s",
						o.name, obj, upper)
				}
			}
			o.isUsed = true
			return o, obj
		}
		up := getUp(obj)
		if up == nil {
			return nil, obj
		}

		o, upper := inheritOwner(up)
		inherited[obj] = upper
		obj.setOwner(o)
		return o, upper
	}

	var processSubnets func(n *network)
	processSubnets = func(n *network) {
		for _, n2 := range n.networks {
			processSubnets(n2)
		}
		for _, host := range n.hosts {
			inheritOwner(host)
		}
		for _, intf := range n.interfaces {
			r := intf.router
			if !(r.managed != "" || r.routingOnly) {
				inheritOwner(intf)
			}
		}
		inheritOwner(n)
	}

	for _, n := range allNetworks {
		processSubnets(n)
	}

	// Collect list of owners and watchingOwners from areas at
	// zones in attribute .watchingOwners. Is needed in export-netspoc.
	zone2owner2seen := make(map[*zone]map[*owner]bool)
	for _, area := range ascendingAreas {
		o := area.watchingOwner
		if o == nil {
			o = area.owner
		}
		if o == nil {
			continue
		}
		o.isUsed = true
		for _, z := range area.zones {
			owner2seen := zone2owner2seen[z]
			if !owner2seen[o] {
				if owner2seen == nil {
					owner2seen = make(map[*owner]bool)
					zone2owner2seen[z] = owner2seen
				}
				owner2seen[o] = true
				z.watchingOwners = append(z.watchingOwners, o)
			}
		}
	}

	// Check owner with attribute showAll.
	var errList stringList
	for _, o := range symTable.owner {
		if !o.showAll {
			continue
		}
		var invalid stringList
	NETWORK:
		for _, n := range allNetworks {
			if netOwner := n.owner; netOwner != nil {
				if netOwner == o {
					continue
				}
			}
			z := n.zone
			if z.isTunnel {
				continue
			}
			for _, wo := range z.watchingOwners {
				if wo == o {
					continue NETWORK
				}
			}
			invalid.push(n.name)
		}
		if invalid != nil {
			errList.push(fmt.Sprintf(
				"%s has attribute 'show_all',"+
					" but doesn't own whole topology.\n"+
					" Missing:\n"+
					invalid.nameList(),
				o.name))
		}
	}
	sort.Strings(errList)
	for _, msg := range errList {
		errMsg(msg)
	}

	// Handle routerAttributes.owner separately.
	// Areas can be nested. Proceed from small to larger ones.
	for _, a := range ascendingAreas {
		attributes := a.routerAttributes
		if attributes == nil {
			continue
		}
		owner := attributes.owner
		if owner == nil {
			continue
		}
		owner.isUsed = true
		for _, r := range a.managedRouters {
			if rOwner := r.owner; rOwner != nil {
				if rOwner == owner {
					warnMsg(
						"Useless %s at %s,\n"+
							" it was already inherited from %s",
						rOwner.name, r.name, attributes.name)
				}
			} else {
				r.owner = owner
			}
		}
	}

	// Set owner for interfaces of managed routers.
	for _, r := range append(managedRouters, routingOnlyRouters...) {
		o := r.owner
		if o == nil {
			continue
		}
		o.isUsed = true

		// Interface of managed router is not allowed to have individual owner.
		for _, intf := range getIntf(r) {
			intf.owner = o
		}
	}

	// Propagate owner of loopback interface to loopback network and
	// loopback zone. Even reset owners to undef, if loopback interface
	// has no owner.
	for _, r := range getIpv4Ipv6Routers() {
		for _, intf := range r.interfaces {
			if !intf.loopback {
				continue
			}
			owner := intf.owner
			if owner != nil {
				owner.isUsed = true
			}
			intf.network.owner = owner
		}
	}
}

func CheckServiceOwner() {
	diag.Progress("Checking service owner")

	propagateOwners()

	type svcInfo struct {
		// Is set, if all rules use same objects.
		sameObjects bool
		// Is set, if all rules are coupling rules.
		isCoupling bool
		objects    map[srvObj]bool
	}
	service2info := make(map[*service]*svcInfo)

	process := func(rules serviceRuleList) {
		for _, rule := range rules {
			unexpanded := rule.rule
			svc := unexpanded.service
			info := service2info[svc]
			if info == nil {
				info = &svcInfo{
					sameObjects: true,
					isCoupling:  true,
				}
				service2info[svc] = info
			}

			// Collect non 'user' objects.
			objects := info.objects

			// Check, if service contains only coupling rules with only
			// "user" elements.
			hasUser := unexpanded.hasUser
			if hasUser != "both" {
				info.isCoupling = false
				if rule.reversed {
					if hasUser == "src" {
						hasUser = "dst"
					} else {
						hasUser = "src"
					}
				}
			}

			// Collect objects referenced in rules of service.
			// Mark service, where different rules have different objects
			// for multi_owner check below.
			check := func(group []srvObj) {
				if objects == nil {
					objects = make(map[srvObj]bool)
					for _, obj := range group {
						objects[obj] = true
					}
				} else {
					if len(objects) != len(group) {
						info.sameObjects = false
					}
					for _, obj := range group {
						if !objects[obj] {
							info.sameObjects = false
							objects[obj] = true
						}
					}
				}
			}
			if hasUser != "src" {
				check(rule.src)
			}
			if hasUser != "dst" {
				check(rule.dst)
			}

			// Store found objects and remember that first rule has
			// been processed.
			info.objects = objects
		}
	}
	process(sRules.permit)
	process(sRules.deny)

	unknown2services := make(map[srvObj]stringList)
	for svc, info := range service2info {

		// Collect service owners, remember if unknown owners;
		ownerSeen := make(map[*owner]bool)
		hasUnknown := false

		objects := info.objects
		for obj, _ := range objects {
			o := obj.getOwner()
			if o != nil {
				if !ownerSeen[o] {
					ownerSeen[o] = true
					svc.owners = append(svc.owners, o)
				}
			} else {
				hasUnknown = true
			}
		}

		// Check for redundant service owner.
		// Allow dedicated service owner, if we have multiple owners
		// from objects of rule.
		if subOwner := svc.subOwner; subOwner != nil {
			subOwner.isUsed = true
			if len(ownerSeen) == 1 && ownerSeen[subOwner] {
				warnMsg("Useless %s at %s", subOwner.name, svc.name)
			}
		}

		// Check for multiple owners.
		hasMulti := !info.isCoupling && len(svc.owners) > 1
		if svc.multiOwner {
			if !hasMulti {
				warnMsg("Useless use of attribute 'multi_owner' at %s", svc.name)
			} else {

				// Check if attribute 'multi_owner' is restricted at this service.
				restricted := false
				for obj, _ := range objects {
					if obj.getOwner() != nil &&
						obj.getAttr("multi_owner") == "restrict" {
						restricted = true
						break
					}
				}
				if restricted {
					warnMsg("Must not use attribute 'multi_owner' at %s", svc.name)
				} else if info.sameObjects {

					// Check if attribute 'multi_owner' could be avoided,
					// if objects of user and objects of rules are swapped.
					var userOwner *owner
					simpleUser := true
					for _, user := range svc.expandedUser {
						var o *owner
						if obj, ok := user.(srvObj); ok {
							o = obj.getOwner()
						}
						if o == nil {
							simpleUser = false
							break
						}
						if userOwner == nil {
							userOwner = o
						} else if userOwner != o {
							simpleUser = false
							break
						}
					}
					if simpleUser && userOwner != nil {
						warnMsg("Useless use of attribute 'multi_owner' at %s\n"+
							" All 'user' objects belong to single %s.\n"+
							" Either swap objects of 'user' and objects of rules,\n"+
							" or split service into multiple parts,"+
							" one for each owner.", svc.name, userOwner.name)
					}
				}
			}
		} else if hasMulti {
			if printType := conf.Conf.CheckServiceMultiOwner; printType != "" {
				var names stringList
				ok := true
				for obj, _ := range objects {
					if obj.getOwner() != nil {
						if obj.getAttr("multi_owner") != "ok" {
							ok = false
						}
						names.push(strings.TrimPrefix(obj.getOwner().name, "owner:"))
					}
				}

				if !ok {
					sort.Strings(names)
					warnOrErrMsg(printType,
						"%s has multiple owners:\n %s",
						svc.name, strings.Join(names, ", "))
				}
			}
		}

		// Check for unknown owners.
		if svc.unknownOwner {
			if !hasUnknown {
				warnMsg("Useless use of attribute 'unknown_owner' at %s", svc.name)
			} else {
				for obj, _ := range objects {
					if obj.getOwner() == nil &&
						obj.getAttr("unknown_owner") == "restrict" {
						warnMsg("Must not use attribute 'unknown_owner' at %s",
							svc.name)
						break
					}
				}
			}
		} else if hasUnknown && conf.Conf.CheckServiceUnknownOwner != "" {
			for obj, _ := range objects {
				if obj.getOwner() == nil && obj.getAttr("unknown_owner") != "ok" {
					unknown2services[obj] = append(unknown2services[obj], svc.name)
				}
			}
		}
	}

	// Show unused owners.
	if printType := conf.Conf.CheckUnusedOwners; printType != "" {
		var unused stringList
		for _, o := range symTable.owner {
			if !o.isUsed {
				unused.push(o.name)
			}
		}
		if unused != nil {
			sort.Strings(unused)
			for _, name := range unused {
				warnOrErrMsg(printType, "Unused %s", name)
			}
		}
	}

	// Show objects with unknown owner.
	var list []srvObj
	for obj, names := range unknown2services {
		sort.Strings(names)
		list = append(list, obj)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].String() < list[j].String()
	})
	for _, obj := range list {
		warnOrErrMsg(conf.Conf.CheckServiceUnknownOwner,
			"Unknown owner for %s in %s",
			obj, strings.Join(unknown2services[obj], ", "))
	}
}
