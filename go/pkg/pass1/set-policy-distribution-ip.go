package pass1

//#############################################################################
// Find IP of each device, reachable from policy distribution point.
//#############################################################################

// For each device, find the IP address which is used
// to manage the device from a central policy distribution point (PDP).
// This address is added as a comment line to each generated code file.
// This is to be used later when approving the generated code file.
func SetPolicyDistributionIP() {
	progress("Setting policy distribution IP")

	needAll := config.CheckPolicyDistributionPoint
	var pdpRouters []*router
	seen := make(map[*router]bool)
	var missing stringerList
	collect := func(list []*router) {
		for _, r := range list {
			if r.policyDistributionPoint != nil {
				pdpRouters = append(pdpRouters, r)
				continue
			}
			if needAll == "0" {
				continue
			}
			if seen[r] {
				continue
			}
			if r.origRouter != nil {
				continue
			}
			if list := r.ipvMembers; list != nil {
				found := false
				for _, m := range list {
					if m.policyDistributionPoint != nil {
						found = true
					}
					seen[m] = true
				}
				if found {
					continue
				}
				r = &router{
					name: "at least one instance of router:" + r.deviceName,
				}
			}
			missing = append(missing, r)
		}
	}
	collect(managedRouters)
	collect(routingOnlyRouters)
	if count := len(missing); count > 0 {
		warnOrErrMsg(needAll,
			"Missing attribute 'policy_distribution_point' for %d devices:\n"+
				missing.nameList(),
			count)
	}
	if len(pdpRouters) == 0 {
		return
	}

	// Find all TCP ranges which include port 22 and 23.
	isAdminPrt := make(map[*proto]bool)
	for _, prt := range prtMap.tcp {
		p1, p2 := prt.ports[0], prt.ports[1]
		if p1 <= 22 && 22 <= p2 || p1 <= 23 && 23 <= p2 {
			isAdminPrt[prt] = true
		}
	}
	isAdminPrt[prtIP] = true

	// Mapping from policy distribution host to subnets, networks and
	// aggregates that include this host.
	host2isPdpSrc := make(map[*host]map[someObj]bool)
	getPdpSrc := func(host *host) map[someObj]bool {
		isPdpSrc := host2isPdpSrc[host]
		if isPdpSrc != nil {
			return isPdpSrc
		}
		isPdpSrc = make(map[someObj]bool)
		for _, s := range host.subnets {
			var pdp someObj = s
			for pdp != nil {
				isPdpSrc[pdp] = true
				pdp = pdp.getUp()
			}
		}
		host2isPdpSrc[host] = isPdpSrc
		return isPdpSrc
	}

	router2foundInterfaces := make(map[*router]map[*routerIntf]bool)
	for _, rule := range pRules.permit {
		var r *router
		switch x := rule.dstPath.(type) {
		case *zone:
			continue
		case *routerIntf:
			r = x.router
		case *router:
			r = x
		}
		pdp := r.policyDistributionPoint
		if pdp == nil {
			continue
		}
		foundPrt := false
		for _, prt := range rule.prt {
			if isAdminPrt[prt] {
				foundPrt = true
				break
			}
		}
		if !foundPrt {
			continue
		}
		isPdpSrc := getPdpSrc(pdp)
		foundSrc := false
		for _, src := range rule.src {
			if isPdpSrc[src] {
				foundSrc = true
			}
		}
		if !foundSrc {
			continue
		}
		intfMap := router2foundInterfaces[r]
		if intfMap == nil {
			intfMap = make(map[*routerIntf]bool)
			router2foundInterfaces[r] = intfMap
		}
		for _, dst := range rule.dst {
			intfMap[dst.(*routerIntf)] = true
		}
	}
	for _, r := range pdpRouters {
		pdp := r.policyDistributionPoint.subnets[0]
		foundMap := router2foundInterfaces[r]
		var result intfList

		// Ready, if exactly one management interface was found.
		if len(foundMap) == 1 {
			for intf, _ := range foundMap {
				result.push(intf)
			}
		} else {

			// debug("%s: %d", router->{name}, len(intfMap));
			frontList := pathAutoInterfaces(r, pdp)

			// If multiple management interfaces were found, take that which is
			// directed to policy_distribution_point.
			for _, front := range frontList {
				if foundMap[front] {
					result.push(front)
				}
			}

			// Take all management interfaces.
			// Preserve original order of router interfaces.
			if len(result) == 0 {
				for _, intf := range r.interfaces {
					if foundMap[intf] {
						result.push(intf)
					}
				}
			}

			// Don't set AdminIP if no address is found.
			// Warning is printed below.
			if len(result) == 0 {
				continue
			}
		}

		// Lookup interface address in NAT domain of PDP, because PDP
		// needs to access the device.
		// Prefer loopback interface if available.
		natSet := pdp.network.zone.natDomain.natSet
		var l, o intfList
		for _, intf := range result {
			if intf.loopback {
				l.push(intf)
			} else {
				o.push(intf)
			}
		}
		for _, intf := range append(l, o...) {
			r.adminIP = append(r.adminIP, intf.address(natSet).IP.String())
		}
	}
	var unreachable stringerList
	for _, r := range pdpRouters {
		if len(r.adminIP) == 0 && r.origRouter == nil {
			unreachable = append(unreachable, r)
		}
	}
	if len(unreachable) > 0 {
		warnMsg("Missing rules to reach %d devices from"+
			" policy_distribution_point:\n"+unreachable.nameList(),
			len(unreachable))
	}
}
