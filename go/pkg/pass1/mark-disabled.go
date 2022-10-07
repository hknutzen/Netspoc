package pass1

import (
	"sort"
)

//###################################################################
// Mark all parts of the topology located behind disabled interfaces.
// "Behind" is defined like this:
// Look from a router to its interfaces;
// if an interface is marked as disabled,
// recursively mark the whole part of the topology located behind
// this interface as disabled.
// Be cautious with loops:
// Mark all interfaces at loop entry as disabled,
// otherwise the whole topology will get disabled.
//###################################################################

func disableBehind(in *routerIntf) {

	//debug("disable_behind %s", in)
	in.disabled = true
	n := in.network
	if n == nil || n.disabled {

		//debug("Stop disabling at %s", n)
		return
	}
	n.disabled = true
	for _, h := range n.hosts {
		h.disabled = true
	}
	for _, intf := range n.interfaces {
		if intf == in {
			continue
		}

		// This stops at other entry of a loop as well.
		if intf.disabled {

			//debug("Stop disabling at %s", intf)
			continue
		}
		intf.disabled = true
		r := intf.router
		r.disabled = true
		for _, out := range r.interfaces {
			if out == intf {
				continue
			}
			disableBehind(out)
		}
	}
}

func (c *spoc) markDisabled() {
	var disabled intfList
	for _, r := range c.allRouters {
		for _, intf := range r.interfaces {
			if intf.disabled {
				disabled.push(intf)
			}
		}
	}

	for _, intf := range disabled {
		if intf.router.disabled {
			continue
		}
		disableBehind(intf)
		if intf.router.disabled {

			// We reached an initial element of disabledIntf,
			// which seems to be part of a loop.
			// This is dangerous, since the whole topology
			// may be disabled by accident.
			c.err("%s must not be disabled,\n"+
				" since it is part of a loop", intf)
		}
	}

	// Delete disabled interfaces from routers.
	for _, intf := range disabled {
		delIntf := func(intf *routerIntf, l intfList) intfList {
			var clean intfList
			for _, intf2 := range l {
				if intf2 != intf {
					clean.push(intf2)
				}
			}
			return clean
		}
		delHW := func(hw *hardware, l []*hardware) []*hardware {
			var clean []*hardware
			for _, hw2 := range l {
				if hw2 != hw {
					clean = append(clean, hw2)
				}
			}
			return clean
		}
		r := intf.router
		r.interfaces = delIntf(intf, r.interfaces)
		if r.managed != "" || r.routingOnly {
			hw := intf.hardware
			hw.interfaces = delIntf(intf, hw.interfaces)
			if len(hw.interfaces) == 0 {
				r.hardware = delHW(hw, r.hardware)
			}
		}
	}

	// Disable area, where all interfaces or anchor are disabled.
	for _, a := range c.symTable.area {
		if anchor := a.anchor; anchor != nil {
			if anchor.disabled {
				a.disabled = true
			}
		} else {
			ok := false
			cleanup := func(l intfList) intfList {
				var clean intfList
				for _, intf := range l {
					if !intf.disabled {
						clean.push(intf)
					}
				}
				if clean != nil {
					ok = true
				}
				return clean
			}
			a.border = cleanup(a.border)
			a.inclusiveBorder = cleanup(a.inclusiveBorder)
			if !ok {
				a.disabled = true
			}
		}
	}

	// Remove disabled routers
	rl := c.allRouters
	sort.Slice(rl, func(i, j int) bool {
		return rl[i].name < rl[j].name
	})
	j := 0
	for _, r := range rl {
		if r.disabled {
			continue
		}
		rl[j] = r
		j++
		if r.managed != "" || r.routingOnly {
			c.managedRouters = append(c.managedRouters, r)
		}
	}
	c.allRouters = rl[:j]

	// Collect vrf instances belonging to one device.
	// Also collect all IPv4 and IPv6 routers with same name.
	sameIPvDevice := make(map[string][]*router)
	sameDevice := make(map[string][]*router)
	for _, r := range c.managedRouters {
		if r.origRouter != nil {
			continue
		}
		name := r.deviceName
		nameIPv := name
		if r.ipV6 {
			nameIPv += ",6"
		}
		sameIPvDevice[nameIPv] = append(sameIPvDevice[nameIPv], r)
		sameDevice[name] = append(sameDevice[name], r)
	}
	for _, l := range sameDevice {
		r1 := l[0]
		m1 := r1.model.class
		if r1.model.needManagementInstance {
			mr := c.getRouter(r1.deviceName, r1.ipV6)
			if mr == nil {
				c.err("Must define unmanaged router:%s\n"+
					" with attribute 'management_instance'\n"+
					" for %s",
					r1.deviceName, r1)
			} else if !mr.managementInstance {
				c.err("Must add attribute 'management_instance' at %s", mr)
			} else if mr.backupOf != nil {
				c.err("Must define unmanaged router:%s\n"+
					" - with attribute 'management_instance'\n"+
					" - but without attribute 'backup_of'\n"+
					" for %s",
					r1.deviceName, r1)
			} else if mm := mr.model; mm != nil {
				if m1 != mm.class {
					c.err("%s and %s must have identical model", r1, mr)
				}
				if br := mr.backupInstance; br != nil {
					if bm := br.model; bm != nil && mm.name != bm.class {
						c.err("%s and %s must have identical model", mr, br)
					}
				}
			}
		}

		if len(l) == 1 {
			continue
		}
		for _, r := range l[1:] {
			if m1 != r.model.class {
				c.err("All instances of router:%s must have identical model",
					l[0].deviceName)
				break
			}
		}
		for _, r := range l {
			r.ipvMembers = l
		}
	}

	for _, l := range sameIPvDevice {
		if len(l) == 1 {
			continue
		}

		if l[0].model.vrfShareHardware {
			sameHWDevice := make(map[string]*router)
			for _, r := range l {
				for _, hw := range r.hardware {
					name := hw.name
					if r2 := sameHWDevice[name]; r2 != nil {
						c.err("Duplicate hardware '%s' at %s and %s",
							name, r2, r)
					} else {
						sameHWDevice[name] = r
					}
				}
			}
		}
		for _, router := range l {
			router.vrfMembers = l
		}
	}

	// Collect networks into allNetworks.
	// We need a deterministic order.
	// Don't sort by name because code shouldn't change if a network is renamed.
	// Derive order from order of routers and interfaces.
	seen := make(map[*network]bool)
	for _, r := range c.allRouters {
		if len(r.interfaces) == 0 && len(r.origIntfs) == 0 {
			c.err("%s isn't connected to any network", r)
			continue
		}
		for _, intf := range r.interfaces {
			n := intf.network
			if !seen[n] {
				seen[n] = true
				c.allNetworks.push(n)
			}
		}
	}

	// Find networks not connected to any router.
	for _, n := range c.symTable.network {
		if n.disabled {
			continue
		}
		if seen[n] {
			continue
		}
		if len(c.symTable.network) > 1 ||
			len(c.symTable.router) > 0 ||
			len(c.symTable.router6) > 0 {

			c.err("%s isn't connected to any router", n)
			n.disabled = true
			for _, h := range n.hosts {
				h.disabled = true
			}
		} else {
			c.allNetworks.push(n)
		}
	}
}
