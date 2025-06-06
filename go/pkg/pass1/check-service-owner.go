package pass1

import (
	"fmt"
	"slices"
	"strings"
)

//#############################################################################
// Distribute owner, identify service owner
//#############################################################################

func (c *spoc) propagateOwners() {

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
		if a == nil { // Must not return nil of type *area
			return nil // but nil of type ownerer.
		}
		return a
	}

	inherited := make(map[ownerer]ownerer)

	var inheritOwner func(obj ownerer) (*owner, ownerer)
	inheritOwner = func(obj ownerer) (*owner, ownerer) {
		if obj == nil {
			return nil, nil
		}
		o := obj.getOwner()
		if upper := inherited[obj]; upper != nil {
			return o, upper
		}
		o2, upper := inheritOwner(getUp(obj))
		if o != nil {
			if o2 == o {
				if !obj.isCombined46() || upper.isCombined46() {
					c.warn("Useless %s at %s,\n it was already inherited from %s",
						o, obj.vxName(), upper)
				}
			}
			inherited[obj] = obj
			return o, obj
		}
		obj.setOwner(o2)
		inherited[obj] = upper
		return o2, upper
	}

	processSubnets := func(n *network) {
		for _, host := range n.hosts {
			inheritOwner(host)
		}
		for _, intf := range withSecondary(n.interfaces) {
			r := intf.router
			if !(r.managed != "" || r.routingOnly) {
				inheritOwner(intf)
			}
		}
		inheritOwner(n)
	}

	for _, n := range c.allNetworks {
		processSubnets(n)
	}

	// Collect list of owners and watchingOwners from areas at
	// zones in attribute .watchingOwners. Is needed in export-netspoc.
	type key struct {
		z *zone
		o *owner
	}
	zoneOwnerSeen := make(map[key]bool)
	for _, area := range c.ascendingAreas {
		o := area.watchingOwner
		if o == nil {
			o = area.owner
		}
		if o == nil {
			continue
		}
		for _, z := range area.zones {
			k := key{z, o}
			if !zoneOwnerSeen[k] {
				zoneOwnerSeen[k] = true
				z.watchingOwners = append(z.watchingOwners, o)
			}
		}
	}

	// Check owner with attribute showAll.
	for _, o := range c.symTable.owner {
		if !o.showAll {
			continue
		}
		var invalid netList
		for _, n := range c.allNetworks {
			if netOwner := n.owner; netOwner != nil {
				if netOwner == o {
					continue
				}
			}
			if n.ipType == tunnelIP {
				continue
			}
			if !slices.Contains(n.zone.watchingOwners, o) {
				invalid.push(n)
			}
		}
		if invalid != nil {
			c.err("%s has attribute 'show_all',"+
				" but doesn't own whole topology.\n"+
				" Missing:\n"+
				invalid.nameList(), o)
		}
	}

	// Set owner for interfaces of managed routers.
	for _, r := range c.managedRouters {
		o := r.owner
		if o == nil {
			continue
		}

		// Interface of managed router is not allowed to have individual owner.
		for _, intf := range withSecondary(getIntf(r)) {
			intf.owner = o
		}
	}

	// Propagate owner of loopback interface to loopback network. Even
	// reset owner to nil, if loopback interface has no owner.
	for _, r := range c.allRouters {
		for _, intf := range r.interfaces {
			if intf.loopback {
				o := intf.owner
				intf.network.owner = o
			}
		}
	}
}

func (c *spoc) checkServiceOwner(sRules *serviceRules) {
	c.progress("Checking service owner")

	// Sorts error messages before output.
	c.sortedSpoc(func(c *spoc) {
		type svcInfo struct {
			// Is set, if all rules use same objects.
			sameObjects bool
			// Is set, if all rules are coupling rules.
			isCoupling bool
			// Collect non 'user' objects.
			objects map[srvObj]bool
			// List of lists of users.
			users [][]srvObj
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
				if hasUser == "src" {
					info.users = append(info.users, rule.src)
				} else {
					check(rule.src)
				}
				if hasUser == "dst" {
					info.users = append(info.users, rule.dst)
				} else {
					check(rule.dst)
				}
				info.objects = objects
			}
		}
		process(sRules.permit)
		process(sRules.deny)

		unknown2services := make(map[srvObj]stringList)
		for svc, info := range service2info {
			objects := info.objects

			// Check if service has multiple owners or has unknown owner.
			var objOwner *owner
			hasMulti := false
			hasUnknown := false
			for obj := range objects {
				if o := obj.getOwner(); o != nil {
					if objOwner == nil {
						objOwner = o
					} else if o != objOwner {
						hasMulti = true
					}
				} else {
					hasUnknown = true
				}
			}
			checkAttrMultiOwner := func() bool {
				if !svc.multiOwner {
					return false
				}
				// Check if attribute 'multi_owner' is restricted at this service.
				for obj := range objects {
					if obj.getOwner() != nil &&
						getAttr(obj, multiOwnerAttr) == restrictVal {
						c.warn("Attribute 'multi_owner' is blocked at %s", svc)
						return false
					}
				}
				return true
			}
			// Check if attribute 'multi_owner' could be avoided,
			// if objects of user and objects of rules are swapped.
			isSingeUserOwner := func(info *svcInfo) string {
				if !info.sameObjects {
					return ""
				}
				var userOwner *owner
			USERS:
				for _, users := range info.users {
					for _, user := range users {
						o := user.getOwner()
						if o == nil {
							userOwner = nil
							break USERS
						}
						if userOwner == nil {
							userOwner = o
						} else if userOwner != o {
							userOwner = nil
							break USERS
						}
					}
				}
				if userOwner == nil {
					return ""
				}
				return fmt.Sprintf(" All 'user' objects belong to single %s.\n"+
					" Either swap objects of 'user' and objects of rules,\n"+
					" or split service into multiple parts,"+
					" one for each owner.", userOwner)
			}
			hasMulti = !info.isCoupling && hasMulti
			if checkAttrMultiOwner() {
				if !hasMulti {
					c.uselessSvcAttr("multi_owner", svc)
				} else if msg := isSingeUserOwner(info); msg != "" {
					c.warn("Unnecessary 'multi_owner' at %s\n"+msg, svc)
				}
			} else if hasMulti {
				if printType := c.conf.CheckServiceMultiOwner; printType != "" {
					var names stringList
					ok := true
					for obj := range objects {
						if obj.getOwner() != nil {
							if getAttr(obj, multiOwnerAttr) != okVal {
								ok = false
							}
							name := obj.getOwner().name[len("owner:"):]
							names.push(name)
						}
					}
					if !ok {
						slices.Sort(names)
						names = slices.Compact(names)
						unnecessary := ""
						if msg := isSingeUserOwner(info); msg != "" {
							unnecessary = "\n This should be avoided.\n" + msg
						}
						c.warnOrErr(printType,
							"%s has multiple owners:\n %s%s",
							svc, strings.Join(names, ", "), unnecessary)
					}
				}
			}

			// Check for unknown owners.
			checkAttrUnknownOwner := func() bool {
				if !svc.unknownOwner {
					return false
				}
				// Check if attribute 'unknown_owner' is restricted at this service.
				for obj := range objects {
					if obj.getOwner() == nil &&
						getAttr(obj, unknownOwnerAttr) == restrictVal {
						c.warn("Attribute 'unknown_owner' is blocked at %s", svc)
						return false
					}
				}
				return true
			}
			if checkAttrUnknownOwner() {
				if !hasUnknown {
					c.uselessSvcAttr("unknown_owner", svc)
				}
			} else if hasUnknown && c.conf.CheckServiceUnknownOwner != "" {
				for obj := range objects {
					if obj.getOwner() == nil &&
						getAttr(obj, unknownOwnerAttr) != okVal {

						unknown2services[obj] =
							append(unknown2services[obj], svc.name)
					}
				}
			}
		}

		// Show objects with unknown owner.
		for obj, names := range unknown2services {
			slices.Sort(names)
			c.warnOrErr(c.conf.CheckServiceUnknownOwner,
				"Unknown owner for %s in %s",
				obj.vxName(), strings.Join(names, ", "))
		}
	})
}
