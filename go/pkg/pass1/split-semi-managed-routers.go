package pass1

// If a pathrestriction or attribute nat_out is added to an unmanged router,
// it is marked as semiManaged. As a consequence, a new zone would be
// created at each interface of this router.
// If an unmanaged router has a large number of interfaces, but only
// one or a few pathrestrictions or nat_out attached, we would get a
// large number of useless zones.
// To reduce the number of newly created zones, we split an unmanaged
// router with pathrestrictions or nat_out, if it has two or more
// interfaces without any pathrestriction or nat_out:
// - original part having only interfaces without pathrestriction or nat_out,
// - one split part for each interface with pathrestriction or nat_out.
// All parts are connected by a freshly created unnumbered network.
func (c *spoc) splitSemiManagedRouters() {
	var splitRouters []*router
	for _, r := range c.allRouters {

		// Unmanaged router is marked as semi_managed, if
		// - it has pathrestriction,
		// - it has interface with nat_out or
		// - is managed=routing_only.
		if !r.semiManaged {
			continue
		}

		// Don't split device with 'managed=routing_only'.
		if r.routingOnly {
			continue
		}

		// Count interfaces without pathrestriction or nat_out.
		count := 0
		for _, intf := range r.interfaces {
			if intf.pathRestrict == nil && intf.natOutgoing == nil {
				count++
			}
		}
		if count < 2 {
			continue
		}

		// Retain copy of original interfaces for finding [all] interfaces.
		if r.origIntfs == nil {
			r.origIntfs = append(r.origIntfs, r.interfaces...)
		}

		split := func(intf *routerIntf, i int) *router {
			// Create new semiManged router with identical name.
			// Add reference to original router having 'origIntfs'.
			nr := new(router)
			nr.name = r.name
			nr.ipV6 = r.ipV6
			nr.semiManaged = true
			nr.origRouter = r
			intf.router = nr
			splitRouters = append(splitRouters, nr)

			// Link current and newly created router by unnumbered network.
			// Add reference to original interface at internal interface.
			iName := intf.name
			n := new(network)
			n.name = iName + "(split Network)"
			n.ipType = unnumberedIP
			n.ipV6 = r.ipV6
			intf1 := new(routerIntf)
			intf1.name = iName + "(split1)"
			intf1.ipType = unnumberedIP
			intf1.ipV6 = r.ipV6
			intf1.router = r
			intf1.network = n
			intf2 := new(routerIntf)
			intf2.name = iName + "(split2)"
			intf2.ipType = unnumberedIP
			intf2.ipV6 = r.ipV6
			intf2.router = nr
			intf2.network = n
			n.interfaces = intfList{intf1, intf2}
			nr.interfaces = intfList{intf2, intf}

			// Replace original interface at current router.
			r.interfaces[i] = intf1
			return nr
		}
		// Split router into two or more parts.
		// Move each interface with pathrestriction or nat_out to new router,
		// - at most one pathrestriction per new router,
		// - try to combine all nat_out at single new router.
		var natRouter *router
		j := 0
		for _, intf := range r.interfaces {
			if intf.pathRestrict == nil && intf.natOutgoing == nil {
				r.interfaces[j] = intf
			} else if natRouter == nil {
				natRouter = split(intf, j)
			} else if intf.pathRestrict != nil {
				split(intf, j)
			} else {
				natRouter.interfaces.push(intf)
				intf.router = natRouter
				continue
			}
			j++
		}
		r.interfaces = r.interfaces[:j]

		// Original router is no longer semiManged.
		r.semiManaged = false
	}
	c.allRouters = append(c.allRouters, splitRouters...)
}
