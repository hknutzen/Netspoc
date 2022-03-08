package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
)

//#############################################################################
// Find IP of each device, reachable from policy distribution point.
//#############################################################################

// For each device, find the IP address which is used
// to manage the device from a central policy distribution point (PDP).
// This address is added as a comment line to each generated code file.
// This is to be used later when approving the generated code file.
func (c *spoc) setPolicyDistributionIP() {
	c.progress("Setting policy distribution IP")

	needAll := conf.Conf.CheckPolicyDistributionPoint
	var pdpRouters []*router
	seen := make(map[*router]bool)
	var missing stringList
	for _, r := range c.allRouters {
		if r.managed != "" || r.routingOnly {
			if seen[r] || r.origRouter != nil {
				continue
			}
			if r.model.needManagementInstance {
				continue
			}
			if l := r.ipvMembers; l != nil {
				var found *host
				for _, m := range l {
					seen[m] = true
					if p := m.policyDistributionPoint; p != nil {
						pdpRouters = append(pdpRouters, m)
						if found != nil && found != p {
							c.err("Instances of router:%s must not use different"+
								" 'policy_distribution_point':\n -%s\n -%s",
								m.deviceName, found, p)
							break
						} else {
							found = p
						}
					}
				}
				if found == nil && needAll != "" {
					missing.push("at least one instance of router:" + r.deviceName)
				}
				continue
			}
		} else if !r.managementInstance || r.backupInstance != nil {
			continue
		}
		if r.policyDistributionPoint != nil {
			pdpRouters = append(pdpRouters, r)
		} else if needAll != "" {
			missing.push(r.name)
		}
	}
	if count := len(missing); count > 0 {
		c.warnOrErr(needAll,
			"Missing attribute 'policy_distribution_point' for %d devices:\n"+
				missing.nameList(),
			count)
	}
	if len(pdpRouters) == 0 {
		return
	}

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
	for _, rule := range c.allPathRules.permit {
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
	PRT:
		for _, prt := range rule.prt {
			switch prt.proto {
			case "tcp", "udp":
				p1, p2 := prt.ports[0], prt.ports[1]
				if p1 <= 22 && 22 <= p2 || p1 <= 23 && 23 <= p2 {
					foundPrt = true
					break PRT
				}
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
			for intf := range foundMap {
				result.push(intf)
			}
		} else if r.managed != "" || r.routingOnly {

			// debug("%s: %d", router->{name}, len(intfMap));
			frontList := c.pathRouterInterfaces(r, pdp)

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
		natMap := pdp.network.zone.natDomain.natMap
		var l, o intfList
		for _, intf := range result {
			if intf.loopback {
				l.push(intf)
			} else {
				o.push(intf)
			}
		}
		for _, intf := range append(l, o...) {
			r.adminIP = append(r.adminIP, intf.address(natMap).IP().String())
		}
	}
	var unreachable stringerList
	for _, r := range pdpRouters {
		if len(r.adminIP) == 0 && r.origRouter == nil {
			unreachable = append(unreachable, r)
		}
	}
	if len(unreachable) > 0 {
		c.warn("Missing rules to reach %d devices from"+
			" policy_distribution_point:\n"+unreachable.nameList(),
			len(unreachable))
	}
}
