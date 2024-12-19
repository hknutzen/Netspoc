package pass1

import (
	"slices"
	"strings"
)

func (c *spoc) collectRoutersAndNetworks() {
	rl := c.allRouters
	slices.SortFunc(rl, func(a, b *router) int {
		return strings.Compare(a.name, b.name)
	})
	for _, r := range rl {
		if r.managed != "" || r.routingOnly {
			c.managedRouters = append(c.managedRouters, r)
		}
	}
	c.allRouters = rl

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
			mr := c.getManagementInstance(r1)
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

	// Add networks not connected to any router.
	for _, n := range c.symTable.network {
		if !seen[n] {
			c.allNetworks.push(n)
		}
		if n6 := n.combined46; n6 != nil && !seen[n6] {
			c.allNetworks.push(n6)
		}
	}
}
