package pass1

import (
	"sort"
)

//#############################################################################
// Distributing rules to managed devices
//#############################################################################

func distributeRule(ru *groupedRule, in, out *routerIntf) {

	// Traffic from ru.src reaches this router via in
	// and leaves it via out.
	// in is undefined if src is an interface of current router.
	// out is undefined if dst is an interface of current router.
	// Outgoing packets from a router itself are never filtered.
	if in == nil {
		return
	}
	r := in.router
	if r.managed == "" {
		return
	}
	model := r.model

	// Rules of type stateless must only be processed at
	// - stateless routers or
	// - routers which are stateless for packets destined for
	//   their own interfaces or
	// - stateless tunnel interfaces of ASA-VPN.
	if ru.stateless {
		if !(model.stateless || out == nil && model.statelessSelf) {
			return
		}
	}

	// Rules of type statelessIcmp must only be processed at routers
	// which don't handle statelessIcmp automatically;
	if ru.statelessICMP && !model.statelessICMP {
		return
	}

	// Apply only matching rules to 'managed=local' router.
	// Filter out non matching elements from srcList and dstList.
	if mark := r.localMark; mark != 0 {
		filter := func(list []someObj) []someObj {
			var result []someObj
			for _, obj := range list {
				net := obj.getNetwork()
				filterAt := net.filterAt
				if filterAt[mark] {
					result = append(result, obj)
				}
			}
			return result
		}

		// Filter srcList and dstList. Ignore rule if no matching element.
		srcList := ru.src
		matchingSrc := filter(srcList)
		if matchingSrc == nil {
			return
		}
		dstList := ru.dst
		matchingDst := filter(dstList)
		if matchingDst == nil {
			return
		}

		// Create copy of rule. Try to reuse original srcList / dstList.
		cp := *ru
		ru = &cp

		// Overwrite only if list has changed.
		if len(srcList) != len(matchingSrc) {
			ru.src = matchingSrc
		}
		if len(dstList) != len(matchingDst) {
			ru.dst = matchingDst
		}
	}

	intfRules := false

	// Packets for the router itself.
	if out == nil {

		// No ACL generated for traffic to device itself.
		if model.noACLself {
			return
		}

		intfRules = true
	} else {
		if out.hardware.needOutAcl {
			out.hardware.outRules.push(ru)
			if in.hardware.noInAcl {
				return
			}
		}

		// Outgoing rules are needed at tunnel for generating
		// detailedCryptoAcl.
		if out.ipType == tunnelIP &&
			out.getCrypto().detailedCryptoAcl &&
			out.idRules == nil {

			out.outRules.push(ru)
		}
	}

	if in.ipType == tunnelIP {
		addRule := func(intf *routerIntf, ru *groupedRule) {
			if intfRules {
				intf.intfRules.push(ru)
			} else {
				intf.rules.push(ru)
			}
		}
		// Rules for single software clients are stored individually.
		// Consistency checks have already been done at expandCrypto.
		// Rules are needed at tunnel for generating split tunnel ACL
		// regardless of noCryptoFilter value.
		if id2rules := in.idRules; id2rules != nil {
			var extraHosts []someObj
			for _, src := range ru.src {

				// Check individual ID hosts of network at
				// authenticating router.
				if network, ok := src.(*network); ok {
					if network.hasIdHosts {
						for _, host := range network.subnets {
							id := host.id
							newRule := *ru
							newRule.src = []someObj{host}
							addRule(id2rules[id].routerIntf, &newRule)
							extraHosts = append(extraHosts, host)
						}
					}
					continue
				}
				id := src.(*subnet).id
				newRule := *ru
				newRule.src = []someObj{src}
				addRule(id2rules[id].routerIntf, &newRule)
			}
			if extraHosts != nil && model.noCryptoFilter {
				for _, src := range ru.src {
					if _, ok := src.(*subnet); ok {
						extraHosts = append(extraHosts, src)
					}
				}
				cp := *ru
				ru = &cp
				ru.src = extraHosts
			}
		}
		addRule(in, ru)
	} else if !intfRules && model.hasIoACL {
		// Remember outgoing interface.
		m := in.hardware.ioRules
		if m == nil {
			m = make(map[string]ruleList)
			in.hardware.ioRules = m
		}
		n := out.hardware.name
		m[n] = append(m[n], ru)
	} else {
		hw := in.hardware
		if intfRules {
			hw.intfRules.push(ru)
		} else {
			hw.rules.push(ru)
		}
	}
}

func getMulticastObjects(info *mcastProto, ipV6 bool) []someObj {
	var m *multicast
	if ipV6 {
		m = &info.v6
	} else {
		m = &info.v4
	}
	result := make([]someObj, len(m.networks))
	for i, n := range m.networks {
		result[i] = n
	}
	return result
}

func (c *spoc) addRouterAcls() {
	for _, r := range c.managedRouters {
		ipv6 := r.ipV6
		hasIoACL := r.model.hasIoACL
		hardwareList := r.hardware
		for _, hw := range hardwareList {

			// Some managed devices are connected by a crosslink network.
			// Permit any traffic at the internal crosslink interface.
			if hw.crosslink {
				permitAny := []*groupedRule{c.getPermitAnyRule(ipv6)}

				// We can savely change rules at hardware interface
				// because it has been checked that no other logical
				// networks are attached to the same hardware.
				//
				// Substitute or set rules for each outgoing interface.
				if hasIoACL {
					for _, outHw := range hardwareList {
						if hw == outHw {
							continue
						}
						if hw.ioRules == nil {
							hw.ioRules = make(map[string]ruleList)
						}
						hw.ioRules[outHw.name] = permitAny
					}
				} else {
					hw.rules = permitAny
					if hw.needOutAcl {
						hw.outRules = permitAny
					}
				}
				hw.intfRules = permitAny
				continue
			}

			for _, intf := range hw.interfaces {

				// Current router is used as default router even for
				// some internal networks.
				if len(intf.reroutePermit) != 0 {
					nList := intf.reroutePermit
					objList := make([]someObj, len(nList))
					for i, n := range nList {
						objList[i] = n
					}
					rule := newRule(
						[]someObj{c.getNetwork00(ipv6)},
						objList,
						[]*proto{c.prt.IP},
					)

					// Prepend to all other rules.
					if hasIoACL {

						// Incoming and outgoing interface are equal.
						m := hw.ioRules
						if m == nil {
							m = make(map[string]ruleList)
							hw.ioRules = m
						}
						n := hw.name
						m[n] = append([]*groupedRule{rule}, m[n]...)
					} else {
						hw.rules = append([]*groupedRule{rule}, hw.rules...)
					}
				}

				// Is dynamic routing used?
				if routing := intf.routing; routing != nil {
					if prt := routing.prt; prt != nil {
						prtList := []*proto{prt}
						netList := []someObj{intf.network}

						// Permit multicast packets from current network.
						mcast := getMulticastObjects(routing, ipv6)
						hw.intfRules.push(newRule(netList, mcast, prtList))

						// Additionally permit unicast packets.
						// We use the network address as destination
						// instead of the interface address,
						// because we get fewer rules if the interface has
						// multiple addresses.
						hw.intfRules.push(newRule(netList, netList, prtList))
					}
				}

				// Handle multicast packets of redundancy protocols.
				if xrrp := intf.redundancyType; xrrp != nil {
					netList := []someObj{intf.network}
					mcast := getMulticastObjects(xrrp, ipv6)
					prtList := []*proto{xrrp.prt}
					hw.intfRules.push(newRule(netList, mcast, prtList))
				}

				// Handle DHCP requests.
				if intf.dhcpServer {
					netList := []someObj{c.getNetwork00(ipv6)}
					prtList := []*proto{c.prt.Bootps}
					hw.intfRules.push(newRule(netList, netList, prtList))
				}

				// Handle DHCP answer.
				if intf.dhcpClient {
					netList := []someObj{c.getNetwork00(ipv6)}
					prtList := []*proto{c.prt.Bootpc}
					hw.intfRules.push(newRule(netList, netList, prtList))
				}
			}
		}
	}
}

func (c *spoc) distributeGeneralPermit() {
	for _, r := range c.managedRouters {
		generalPermit := r.generalPermit
		if len(generalPermit) == 0 {
			continue
		}
		net00List := []someObj{c.getNetwork00(r.ipV6)}
		ru := newRule(net00List, net00List, generalPermit)
		needProtect := r.needProtect
		for _, in := range r.interfaces {
			if in.loopback {
				continue
			}

			// At VPN hub, don't permit any -> any, but only traffic
			// from each encrypted network.
			if in.isHub {
				addRule := func(src someObj) {
					copy := *ru
					ru = &copy
					ru.src = []someObj{src}
					for _, out := range r.interfaces {
						if out != in && out.ipType != tunnelIP {

							// Traffic traverses the device. Traffic for
							// the device itself isn't needed at VPN hub.
							distributeRule(ru, in, out)
						}
					}
				}
				if idRules := in.idRules; idRules != nil {
					var srcList []someObj
					for _, idIntf := range idRules {
						srcList = append(srcList, idIntf.src)
					}
					sort.Slice(srcList, func(i, j int) bool {
						return srcList[i].String() < srcList[j].String()
					})
					for _, src := range srcList {
						addRule(src)
					}
				} else {
					for _, net := range in.peerNetworks {
						addRule(net)
					}
				}
			} else {
				for _, out := range r.interfaces {
					if out == in {
						continue
					}
					if out.loopback {
						continue
					}

					// For IOS and NX-OS print this rule only
					// once at interface filter rules below
					// (for incoming ACL).
					if needProtect {
						outHw := out.hardware

						// For interface with outgoing ACLs
						// we need to add the rule.
						// distributeRule would add rule to incoming,
						// hence we add rule directly to outgoing rules.
						if outHw.needOutAcl {
							outHw.outRules.push(ru)
						}
						continue
					}

					// Traffic traverses the device.
					distributeRule(ru, in, out)
				}

				// Traffic for the device itself.
				if in.ipType != bridgedIP {
					distributeRule(ru, in, nil)
				}
			}
		}
	}
}

func (c *spoc) rulesDistribution() {
	c.progress("Distributing rules")

	// Deny rules
	for _, ru := range c.allPathRules.deny {
		c.pathWalk(ru, distributeRule, "Router")
	}

	// Handle global permit after deny rules.
	c.distributeGeneralPermit()

	// Permit rules
	for _, ru := range c.allPathRules.permit {
		c.pathWalk(ru, distributeRule, "Router")
	}

	c.addRouterAcls()
}
