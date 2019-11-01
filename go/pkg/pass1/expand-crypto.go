package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"sort"
	"strings"
)

func (obj *zone) nonSecondaryInterfaces() intfList {
	var result intfList
	for _, intf := range obj.interfaces {
		if intf.mainIntf == nil {
			result = append(result, intf)
		}
	}
	return result
}

func (obj *network) nonSecondaryInterfaces() intfList {
	var result intfList
	for _, intf := range obj.interfaces {
		if intf.mainIntf == nil {
			result = append(result, intf)
		}
	}
	return result
}

func cryptoBehind(intf *routerIntf, managed string) netList {
	if managed != "" {
		zone := intf.zone
		if len(zone.nonSecondaryInterfaces()) != 1 {
			errMsg("Exactly one security zone must be located behind"+
				" managed %s of crypto router", intf.name)
		}
		return zone.networks
	} else {
		net := intf.network
		if len(net.nonSecondaryInterfaces()) != 1 {
			errMsg("Exactly one network must be located behind"+
				" unmanaged %s of crypto router", intf.name)
		}
		return netList{net}
	}
}

func verifyAsaVpnAttributes(name string, attributes map[string]string) {
	if attributes == nil {
		return
	}
	sorted := make([]string, 0, len(attributes))
	for key, _ := range attributes {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)
	for _, key := range sorted {
		_, found := asaVpnAttributes[key]
		if !found {
			errMsg("Invalid radiusAttribute '%s' at %s", key, name)
		}
		value := attributes[key]
		if key == "split-tunnel-policy" {
			if value != "tunnelall" && value != "tunnelspecified" {
				errMsg("Unsupported value in radiusAttributes of %s '%s = %s'",
					name, key, value)
			}
		}
	}
}

func getRadiusAttr0(attr string, l ...map[string]string) string {
	for _, m := range l {
		if val, found := m[attr]; found {
			return val
		}
	}
	return ""
}
func getRadiusAttr(attr string, s *subnet, r *router) string {
	return getRadiusAttr0(
		attr,
		s.radiusAttributes,
		s.network.radiusAttributes,
		r.radiusAttributes)
}

// Attribute 'authentication-server-group' must only be used
// together with 'ldpa_id' and must then be available at network.
func verifyAuthServer(s *subnet, r *router) {
	attr := "authentication-server-group"
	if _, found := s.radiusAttributes[attr]; found {
		delete(s.radiusAttributes, attr)
		errMsg("Attribute '%s' must not be used directly at %s", attr, s.name)
	}
	auth := getRadiusAttr(attr, s, r)
	network := s.network
	if s.ldapId != "" {
		if auth == "" {
			errMsg("Missing attribute '%s' at %s having host with 'ldap_id'",
				attr, network.name)
			network.radiusAttributes[attr] = "ERROR"
		}
	} else if auth != "" {
		var name string
		if network.radiusAttributes[attr] != "" {
			name = network.name
		} else {
			name = r.name
		}
		errMsg("Attribute '%s' at %s must only be used"+
			" together with attribute 'ldap_id' at host", attr, name)
	}
}

// Host with ID that doesn't contain a '@' must use attribute
// 'check-subject-name'.
func verifySubjectNameForHost(s *subnet, r *router) {
	id := s.id
	if strings.Index(id, "@") != -1 {
		return
	}
	if getRadiusAttr("check-subject-name", s, r) != "" {
		return
	}
	errMsg("Missing radius_attribute 'check-subject-name'\n for %s", s.name)
}

// Network with attribute 'cert_id' must use attribute
// 'check-subject-name'.
func verifySubjectNameForNet(network *network, r *router) {
	if getRadiusAttr0("check-subject-name",
		network.radiusAttributes, r.radiusAttributes) != "" {
		return
	}
	errMsg("Missing radius_attribute 'check-subject-name'\n for %s",
		network.name)
	network.radiusAttributes["check-subject-name"] = "ERROR"
}

func verifyExtendedKeyUsage(s *subnet, r *router) {
	extKeys := r.extendedKeys
	if extKeys == nil {
		extKeys = make(map[string]string)
		r.extendedKeys = extKeys
	}
	id := s.id
	idx := strings.Index(id, "@")
	if idx == -1 {
		return
	}
	domain := id[idx:]
	oid := getRadiusAttr("check-extended-key-usage", s, r)
	if other, found := extKeys[domain]; found {
		if oid != other {
			errMsg("All ID hosts having domain '%s'"+
				" must use identical value from 'check-extended-key-usage'",
				domain)
		}
	} else {
		extKeys[domain] = oid
	}
}

func verifyAsaTrustpoint(r *router, crypto *crypto) {
	isakmp := crypto.ipsec.isakmp
	if isakmp.authentication == "rsasig" && isakmp.trustPoint == "" {
		errMsg("Missing attribute 'trust_point' in %s for %s",
			isakmp.name, r.name)
	}
}

// Generate rules to permit crypto traffic between tunnel endpoints.
func genTunnelRules(intf1, intf2 *routerIntf, ipsec *ipsec) ruleList {
	natTraversal := ipsec.isakmp.natTraversal

	var rules ruleList
	template := groupedRule{
		src:     []someObj{intf1},
		dst:     []someObj{intf2},
		srcPath: intf1.getPathNode(),
		dstPath: intf2.getPathNode(),
	}
	if natTraversal == "" || natTraversal != "on" {
		var prt []*proto
		if ipsec.ah != "" {
			prt = append(prt, prtAh)
		}
		if ipsec.espAuthentication != "" || ipsec.espEncryption != "" {
			prt = append(prt, prtEsp)
		}
		if len(prt) > 0 {
			rule := template
			rule.serviceRule = new(serviceRule)
			rule.prt = prt
			rules.push(&rule)
		}
		rule := template
		rule.serviceRule = new(serviceRule)
		rule.srcRange = prtIke.src
		rule.prt = []*proto{prtIke.dst}
		rules.push(&rule)
	}
	if natTraversal != "" {
		rule := template
		rule.serviceRule = new(serviceRule)
		rule.srcRange = prtNatt.src
		rule.prt = []*proto{prtNatt.dst}
		rules.push(&rule)
	}
	return rules
}

func ExpandCrypto() {
	diag.Progress("Expanding crypto rules")
	var managedCryptoHubs []*router
	hubSeen := make(map[*router]bool)
	id2intf := make(map[string]intfList)

	sorted := make([]*crypto, 0, len(cryptoMap))
	for _, c := range cryptoMap {
		sorted = append(sorted, c)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].name < sorted[j].name
	})
	for _, c := range sorted {
		isakmp := c.ipsec.isakmp
		needId := isakmp.authentication == "rsasig"

		// Do consistency checks and
		// add rules which allow encrypted traffic.
		for _, tunnel := range c.tunnels {
			if tunnel.disabled {
				continue
			}
			spoke, hub := tunnel.interfaces[0], tunnel.interfaces[1]
			router := spoke.router
			managed := router.managed
			hubRouter := hub.router
			hubModel := hubRouter.model
			natSet := hub.natSet
			hubIsAsaVpn := hubModel.crypto == "ASA_VPN"
			var encrypted netList
			hasIdHosts := false
			hasOtherNetwork := false

			if !hubSeen[hubRouter] {
				hubSeen[hubRouter] = true
				managedCryptoHubs = append(managedCryptoHubs, hubRouter)
			}

			// Analyze cleartext networks behind spoke router.
			for _, intf := range router.interfaces {
				if intf == spoke {
					continue
				}
				net := intf.network
				allNetworks := cryptoBehind(intf, managed)
				if net.hasIdHosts {
					hasIdHosts = true
					idRules := hub.idRules
					if idRules == nil {
						idRules = make(map[string]*idIntf)
						hub.idRules = idRules
					}
					if managed != "" {
						errMsg(
							"%s having ID hosts must not be located behind managed %s",
							net.name, router.name)
					}
					if hubIsAsaVpn {
						verifyAsaVpnAttributes(net.name, net.radiusAttributes)
						key := "trust-point"
						if net.radiusAttributes[key] != "" {
							for _, s := range net.subnets {
								if isHostMask(s.mask) {
									errMsg("Must not use radiusAttribute '%s' at %s",
										key, s.name)
								}
							}
						}
					}

					// Rules for single software clients are stored
					// individually at crypto hub interface.
					// ID host has one to one relation with subnet.
					for _, s := range net.subnets {
						id := s.id
						if hubIsAsaVpn {
							verifyAsaVpnAttributes(s.name, s.radiusAttributes)
							key := "trust-point"
							if s.radiusAttributes[key] != "" &&
								isHostMask(s.mask) {
								errMsg("Must not use radiusAttribute '%s' at %s",
									key, s.name)
							}

							verifyAuthServer(s, hubRouter)
							if s.ldapId != "" {
								verifySubjectNameForNet(net, hubRouter)
							} else {
								verifySubjectNameForHost(s, hubRouter)
								verifyExtendedKeyUsage(s, hubRouter)
							}
						}
						if other, found := hub.idRules[id]; found {
							src := other.src
							errMsg("Duplicate ID-host %s from %s and %s at %s",
								id, src.network.name, s.network.name,
								hubRouter.name)
							continue
						}
						idRules[id] = &idIntf{
							routerIntf: &routerIntf{
								netObj: netObj{
									ipObj: ipObj{
										name:   hub.name + "." + id,
										tunnel: true,
									},
								},
								natSet: natSet,
							},
							src: s,
						}
					}
					encrypted = append(encrypted, net)
				} else {
					hasOtherNetwork = true
					encrypted = append(encrypted, allNetworks...)
				}
			}
			if hasIdHosts && hasOtherNetwork {
				errMsg("Must not use networks having ID hosts"+
					" and other networks having no ID hosts\n"+
					" together at %s:\n"+encrypted.nameList(),
					router.name)
			}

			doAuth := hubModel.doAuth
			if id := spoke.id; id != "" {
				if !needId {
					errMsg("Invalid attribute 'id' at %s.\n"+
						" Set authentication=rsasig at %s",
						spoke.name, isakmp.name)
				}
				list := id2intf[id]
				var other intfList
				for _, intf := range list {
					if intf.peer.router == hubRouter {
						other = append(other, intf)
					}
				}
				if len(other) != 0 {
					other = append(other, spoke)
					// Id must be unique per crypto hub, because it
					// is used to generate ACL names and other names.
					errMsg("Must not reuse 'id = %s' at different"+
						" crypto spokes of '%s':\n"+other.nameList(),
						id, hubRouter.name)
				}
				id2intf[id] = append(id2intf[id], spoke)
			} else if hasIdHosts {
				if !doAuth {
					errMsg("%s can't check IDs of %s",
						hubRouter.name, encrypted[0].name)
				}
			} else if len(encrypted) != 0 {
				if doAuth && managed == "" {
					errMsg("Networks need to have ID hosts because"+
						" %s has attribute 'do_auth':\n"+encrypted.nameList(),
						hubRouter.name)
				} else if needId {
					errMsg("%s needs attribute 'id', because %s"+
						" has authentication=rsasig",
						spoke.name, isakmp.name)
				}
			}

			// Add only non hidden peer networks.
			for _, net := range encrypted {
				if getNatNetwork(net, natSet).hidden {
					continue
				}
				hub.peerNetworks = append(hub.peerNetworks, net)
			}

			if managed != "" {
				if router.model.crypto == "ASA" {
					verifyAsaTrustpoint(router, c)
				}
				if c.detailedCryptoAcl {
					errMsg("Attribute 'detailed_crypto_acl' is not"+
						" allowed for managed spoke %s", router.name)
				}
			}

			// Add rules to permit crypto traffic between tunnel endpoints.
			// If one tunnel endpoint has no known IP address,
			// some rules have to be added manually.
			realSpoke := spoke.realIntf
			if realSpoke != nil && !realSpoke.short && !realSpoke.unnumbered {
				realHub := hub.realIntf
				gen := func(in, out *routerIntf) {
					// Don't generate incoming ACL from unknown address.
					if in.negotiated {
						return
					}

					rules := genTunnelRules(in, out, c.ipsec)
					pRules.permit = append(pRules.permit, rules...)
				}
				gen(realSpoke, realHub)
				gen(realHub, realSpoke)
			}
		}
	}

	// Check for duplicate IDs of different hosts
	// coming into different hardware at current device.
	// ASA_VPN can't distinguish different hosts with same ID
	// coming into different hardware interfaces.
	for _, router := range managedCryptoHubs {
		cryptoType := router.model.crypto
		if cryptoType != "ASA_VPN" {
			continue
		}
		var idRulesIntfs intfList
		for _, intf := range router.interfaces {
			if intf.idRules != nil {
				idRulesIntfs = append(idRulesIntfs, intf)
			}
		}
		if len(idRulesIntfs) < 2 {
			continue
		}
		id2src := make(map[string]someObj)
		for _, intf := range idRulesIntfs {
			m := intf.idRules
			for id, idIntf := range m {
				src1 := idIntf.src
				if src2, found := id2src[id]; found {
					errMsg("Duplicate ID-host %s from %s and %s at %s",
						id, src1.network.name, src2.getNetwork().name, router.name)
				} else {
					id2src[id] = src1
				}
			}
		}
	}

	for _, r := range managedCryptoHubs {

		// No longer needed.
		r.extendedKeys = nil

		cryptoType := r.model.crypto
		if cryptoType == "ASA_VPN" {
			verifyAsaVpnAttributes(r.name, r.radiusAttributes)

			// Move 'trust-point' from radius_attributes to router attribute.
			if trustPoint, found := r.radiusAttributes["trust-point"]; found {
				delete(r.radiusAttributes, "trust-point")
				r.trustPoint = trustPoint
			} else {
				errMsg("Missing 'trust-point' in radiusAttributes of %s", r.name)
			}
		} else if cryptoType == "ASA" {
			for _, intf := range r.interfaces {
				if crypto := intf.crypto; crypto != nil {
					verifyAsaTrustpoint(r, crypto)
				}
			}
		}
	}
}