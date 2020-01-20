package pass1

// Group of reroute_permit networks must be expanded late, after areas,
// aggregates and subnets have been set up. Otherwise automatic groups
// wouldn't work.
//
// Reroute permit is not allowed between different security zones.
func LinkReroutePermit() {
	for _, z := range zones {
		ipv6 := z.ipV6
		for _, intf := range z.interfaces {
			group := expandGroup(intf.reroutePermitNames,
				"'reroute_permit' of " + intf.name,
				ipv6, false)
			for _, obj := range group {
				n, ok := obj.(*network)
				if ok && ! n.isAggregate {
					if ! zoneEq(n.zone, z) {
						errMsg("Invalid reroute_permit for %s at %s:"+
							" different security zones", n, intf)
					} else {
						intf.reroutePermit = append(intf.reroutePermit, n)
					}
				} else {
					errMsg("%s not allowed in attribute 'reroute_permit' of %s",
						obj, intf)
				}
			}
		}
	}
}
