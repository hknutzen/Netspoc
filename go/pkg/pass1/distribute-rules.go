package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"net"
	"sort"
)

func (l *ruleList) push(r *groupedRule) {
	*l = append(*l, r)
}

//#############################################################################
// Distributing rules to managed devices
//#############################################################################

func distributeRule(rule *groupedRule, inIntf, outIntf *routerIntf) {

	// Traffic from src reaches this router via inIntf
	// and leaves it via outIntf.
	// inIntf is undefined if src is an interface of current router.
	// outIntf is undefined if dst is an interface of current router.
	// Outgoing packets from a router itself are never filtered.
	if inIntf == nil {
		return
	}
	router := inIntf.router
	if router.managed == "" {
		return
	}
	model := router.model

	// Rules of type stateless must only be processed at
	// - stateless routers or
	// - routers which are stateless for packets destined for
	//   their own interfaces or
	// - stateless tunnel interfaces of ASA-VPN.
	if rule.stateless {
		if !(model.stateless || outIntf == nil && model.statelessSelf) {
			return
		}
	}

	// Rules of type statelessIcmp must only be processed at routers
	// which don't handle statelessIcmp automatically;
	if rule.statelessICMP && !model.statelessICMP {
		return
	}

	// Apply only matching rules to 'managed=local' router.
	// Filter out non matching elements from srcList and dstList.
	if mark := router.localMark; mark != 0 {
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
		srcList := rule.src
		matchingSrc := filter(srcList)
		if matchingSrc == nil {
			return
		}
		dstList := rule.dst
		matchingDst := filter(dstList)
		if matchingDst == nil {
			return
		}

		// Create copy of rule. Try to reuse original srcList / dstList.
		copy := *rule
		rule = &copy

		// Overwrite only if list has changed.
		if len(srcList) != len(matchingSrc) {
			rule.src = matchingSrc
		}
		if len(dstList) != len(matchingDst) {
			rule.dst = matchingDst
		}
	}

	intfRules := false

	// Packets for the router itself.
	if outIntf == nil {

		// No ACL generated for traffic to device itself.
		if model.filter == "ASA" {
			return
		}

		intfRules = true
	} else {
		if outIntf.hardware.needOutAcl {
			outIntf.hardware.outRules.push(rule)
			if inIntf.hardware.noInAcl {
				return
			}
		}

		// Outgoing rules are needed at tunnel for generating
		// detailedCryptoAcl.
		if outIntf.tunnel &&
			outIntf.crypto.detailedCryptoAcl &&
			outIntf.idRules == nil {
			outIntf.outRules.push(rule)
		}
	}

	addRule := func(intf *routerIntf, rule *groupedRule) {
		if intfRules {
			intf.intfRules = append(intf.intfRules, rule)
		} else {
			intf.rules = append(intf.rules, rule)
		}
	}
	if inIntf.tunnel {
		noCryptoFilter := model.noCryptoFilter

		// Rules for single software clients are stored individually.
		// Consistency checks have already been done at expandCrypto.
		// Rules are needed at tunnel for generating split tunnel ACL
		// regardless of noCryptoFilter value.
		if id2rules := inIntf.idRules; id2rules != nil {
			srcList := rule.src
			var extraHosts []someObj
			for _, src := range srcList {

				// Check individual ID hosts of network at
				// authenticating router.
				if network, ok := src.(*network); ok {
					if network.hasIdHosts {
						for _, host := range network.subnets {
							id := host.id
							newRule := *rule
							newRule.src = []someObj{host}
							addRule(id2rules[id].routerIntf, &newRule)
							extraHosts = append(extraHosts, host)
						}
					}
					continue
				}
				id := src.(*subnet).id
				newRule := *rule
				newRule.src = []someObj{src}
				addRule(id2rules[id].routerIntf, &newRule)
			}
			if extraHosts != nil && noCryptoFilter {
				for _, src := range srcList {
					if _, ok := src.(*subnet); ok {
						extraHosts = append(extraHosts, src)
					}
				}
				copy := *rule
				rule = &copy
				rule.src = extraHosts
			}
		}
		addRule(inIntf, rule)
	} else if !intfRules && model.hasIoACL {
		// Remember outgoing interface.
		m := inIntf.hardware.ioRules
		if m == nil {
			m = make(map[string]ruleList)
			inIntf.hardware.ioRules = m
		}
		n := outIntf.hardware.name
		m[n] = append(m[n], rule)
	} else {
		hw := inIntf.hardware
		if intfRules {
			hw.intfRules = append(hw.intfRules, rule)
		} else {
			hw.rules = append(hw.rules, rule)
		}
	}
}

func getMulticastObjects(info mcastInfo, ipV6 bool) []someObj {
	var ipList []string
	if ipV6 {
		ipList = info.v6
	} else {
		ipList = info.v4
	}
	result := make([]someObj, len(ipList))
	for i, s := range ipList {
		ip := net.ParseIP(s)
		result[i] = &network{ipObj: ipObj{ip: ip}, mask: getHostMask(ipV6)}
	}
	return result
}

func addRouterAcls() {
	for _, router := range managedRouters {
		ipv6 := router.ipV6
		hasIoACL := router.model.hasIoACL
		hardwareList := router.hardware
		for _, hardware := range hardwareList {

			// Some managed devices are connected by a crosslink network.
			// Permit any traffic at the internal crosslink interface.
			if hardware.crosslink {
				permitAny := []*groupedRule{getPermitAnyRule(ipv6)}

				// We can savely change rules at hardware interface
				// because it has been checked that no other logical
				// networks are attached to the same hardware.
				//
				// Substitute or set rules for each outgoing interface.
				if hasIoACL {
					for _, outHardware := range hardwareList {
						if hardware == outHardware {
							continue
						}
						if hardware.ioRules == nil {
							hardware.ioRules = make(map[string]ruleList)
						}
						hardware.ioRules[outHardware.name] = permitAny
					}
				} else {
					hardware.rules = permitAny
					if hardware.needOutAcl {
						hardware.outRules = permitAny
					}
				}
				hardware.intfRules = permitAny
				continue
			}

			for _, intf := range hardware.interfaces {

				// Current router is used as default router even for
				// some internal networks.
				if len(intf.reroutePermit) != 0 {
					nList := intf.reroutePermit
					objList := make([]someObj, len(nList))
					for i, n := range nList {
						objList[i] = n
					}
					rule := newRule(
						[]someObj{getNetwork00(ipv6)},
						objList,
						[]*proto{prtIP},
					)

					// Prepend to all other rules.
					if hasIoACL {

						// Incoming and outgoing interface are equal.
						m := hardware.ioRules
						if m == nil {
							m = make(map[string]ruleList)
							hardware.ioRules = m
						}
						n := hardware.name
						m[n] = append([]*groupedRule{rule}, m[n]...)
					} else {
						hardware.rules = append([]*groupedRule{rule}, hardware.rules...)
					}
				}

				// Is dynamic routing used?
				if routing := intf.routing; routing != nil {
					if prt := routing.prt; prt != nil {
						prtList := []*proto{prt}
						netList := []someObj{intf.network}

						// Permit multicast packets from current network.
						mcast := getMulticastObjects(routing.mcast, ipv6)
						hardware.intfRules.push(newRule(netList, mcast, prtList))

						// Additionally permit unicast packets.
						// We use the network address as destination
						// instead of the interface address,
						// because we get fewer rules if the interface has
						// multiple addresses.
						hardware.intfRules.push(newRule(netList, netList, prtList))
					}
				}

				// Handle multicast packets of redundancy protocols.
				if typ := intf.redundancyType; typ != "" {
					netList := []someObj{intf.network}
					xrrp := xxrpInfo[typ]
					mcast := getMulticastObjects(xrrp.mcast, ipv6)
					prtList := []*proto{xrrp.prt}
					hardware.intfRules.push(newRule(netList, mcast, prtList))
				}

				// Handle DHCP requests.
				if intf.dhcpServer {
					netList := []someObj{getNetwork00(ipv6)}
					prtList := []*proto{prtBootps}
					hardware.intfRules.push(newRule(netList, netList, prtList))
				}

				// Handle DHCP answer.
				if intf.dhcpClient {
					netList := []someObj{getNetwork00(ipv6)}
					prtList := []*proto{prtBootpc}
					hardware.intfRules.push(newRule(netList, netList, prtList))
				}
			}
		}
	}
}

func distributeGeneralPermit() {
	for _, router := range managedRouters {
		generalPermit := router.generalPermit
		if len(generalPermit) == 0 {
			continue
		}
		net00List := []someObj{getNetwork00(router.ipV6)}
		rule := newRule(net00List, net00List, generalPermit)
		needProtect := router.needProtect
		for _, inIntf := range router.interfaces {
			if inIntf.mainIntf != nil {
				continue
			}
			if inIntf.loopback {
				continue
			}

			// At VPN hub, don't permit any -> any, but only traffic
			// from each encrypted network.
			if inIntf.isHub {
				addRule := func(src someObj) {
					copy := *rule
					rule = &copy
					rule.src = []someObj{src}
					for _, outIntf := range router.interfaces {
						if outIntf == inIntf {
							continue
						}
						if outIntf.tunnel {
							continue
						}

						// Traffic traverses the device. Traffic for
						// the device itself isn't needed at VPN hub.
						distributeRule(rule, inIntf, outIntf)
					}
				}
				if idRules := inIntf.idRules; idRules != nil {
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
					for _, net := range inIntf.peerNetworks {
						addRule(net)
					}
				}
			} else {
				for _, outIntf := range router.interfaces {
					if outIntf == inIntf {
						continue
					}
					if outIntf.loopback {
						continue
					}

					// For IOS and NX-OS print this rule only
					// once at interface filter rules below
					// (for incoming ACL).
					if needProtect {
						outHw := outIntf.hardware

						// For interface with outgoing ACLs
						// we need to add the rule.
						// distribute_rule would add rule to incoming,
						// hence we add rule directly to outgoing rules.
						if outHw.needOutAcl {
							outHw.outRules.push(rule)
						}
						continue
					}
					if outIntf.mainIntf != nil {
						continue
					}

					// Traffic traverses the device.
					distributeRule(rule, inIntf, outIntf)
				}

				// Traffic for the device itself.
				if inIntf.bridged {
					continue
				}
				distributeRule(rule, inIntf, nil)
			}
		}
	}
}

func RulesDistribution() {
	diag.Progress("Distributing rules")

	// Deny rules
	for _, rule := range pRules.deny {
		pathWalk(rule, distributeRule, "Router")
	}

	// Handle global permit after deny rules.
	distributeGeneralPermit()

	// Permit rules
	for _, rule := range pRules.permit {
		pathWalk(rule, distributeRule, "Router")
	}

	addRouterAcls()
}
