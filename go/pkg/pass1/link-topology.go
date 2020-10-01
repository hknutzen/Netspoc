package pass1

// Reroute permit is not allowed between different security zones.
func CheckReroutePermit() {
	for _, z := range zones {
		for _, intf := range z.interfaces {
			for _, n := range intf.reroutePermit {
				if !zoneEq(n.zone, z) {
					errMsg("Invalid reroute_permit for %s at %s:"+
						" different security zones", n, intf)
				}
			}
		}
	}
}
