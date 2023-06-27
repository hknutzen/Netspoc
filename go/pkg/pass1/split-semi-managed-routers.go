package pass1

// If a pathrestriction or a bind_nat is added to an unmanged router,
// it is marked as semiManaged. As a consequence, a new zone would be
// created at each interface of this router.
// If an unmanaged router has a large number of interfaces, but only
// one or a few pathrestrictions or bind_nat attached, we would get a
// large number of useless zones.
// To reduce the number of newly created zones, we split an unmanaged
// router with pathrestrictions or bind_nat, if it has more than two
// interfaces without any pathrestriction or bind_nat:
// - original part having only interfaces without pathrestriction or bind_nat,
// - one split part for each interface with pathrestriction or bind_nat.
// All parts are connected by a freshly created unnumbered network.
func (c *spoc) splitSemiManagedRouters() {
	var splitRouters []*router
	for _, r := range c.allRouters {

		// Unmanaged router is marked as semi_managed, if
		// - it has pathrestriction,
		// - it has interface with bind_nat or
		// - is managed=routing_only.
		if !r.semiManaged {
			continue
		}

		// Don't split device with 'managed=routing_only'.
		if r.routingOnly {
			continue
		}

		// Count interfaces without pathrestriction or bind_nat.
		count := 0
		for _, intf := range r.interfaces {
			if intf.pathRestrict == nil && intf.bindNat == nil {
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

		// Split router into two or more parts.
		// Move each interface with pathrestriction or bind_nat and
		// corresponding secondary interface to new router.
		for i, intf := range r.interfaces {
			if intf.pathRestrict == nil && intf.bindNat == nil {
				continue
			}

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
			intf1 := new(routerIntf)
			intf1.name = iName + "(split1)"
			intf1.ipType = unnumberedIP
			intf1.router = r
			intf1.network = n
			intf2 := new(routerIntf)
			intf2.name = iName + "(split2)"
			intf2.ipType = unnumberedIP
			intf2.router = nr
			intf2.network = n
			n.interfaces = intfList{intf1, intf2}
			nr.interfaces = intfList{intf2, intf}

			// Add reference to other interface at original interface
			// at newly created router. This is needed for post
			// processing in checkPathrestrictions.
			if intf.pathRestrict != nil {
				intf.splitOther = intf2
			}

			// Replace original interface at current router.
			r.interfaces[i] = intf1
		}

		// Original router is no longer semiManged.
		r.semiManaged = false
	}
	c.allRouters = append(c.allRouters, splitRouters...)
}
