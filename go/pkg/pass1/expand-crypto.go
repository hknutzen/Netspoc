package pass1

import (
	"cmp"
	"maps"
	"slices"
	"strings"
)

func (c *spoc) cryptoBehind(intf *routerIntf, managed string) netList {
	if managed != "" {
		z := intf.zone
		if len(z.interfaces) != 1 {
			c.err("Exactly one security zone must be located behind"+
				" managed %s of crypto router", intf)
		}
		return z.networks
	} else {
		net := intf.network
		if len(net.interfaces) != 1 {
			c.err("Exactly one network must be located behind"+
				" unmanaged %s of crypto router", intf)
		}
		return netList{net}
	}
}

func (c *spoc) verifyAsaVpnAttributes(
	name string, attributes map[string]string) {

	for _, key := range slices.Sorted(maps.Keys(attributes)) {
		if _, found := asaVpnAttributes[key]; !found {
			c.err("Invalid vpn_attribute '%s' at %s", key, name)
		}
		value := attributes[key]
		switch key {
		case "split-tunnel-policy":
			if value != "tunnelall" && value != "tunnelspecified" {
				c.err("Unsupported value in vpn_attribute of %s '%s = %s'",
					name, key, value)
			}
		case "group-lock":
			if value != "" {
				c.warn("Ignoring value at vpn_attribute '%s' of %s"+
					" (will be set automatically)",
					key, name)
			}
		}
	}
}

func getVPNAttr0(attr string, l ...map[string]string) string {
	for _, m := range l {
		if val, found := m[attr]; found {
			return val
		}
	}
	return ""
}
func getVPNAttr(attr string, s *subnet, r *router) string {
	return getVPNAttr0(
		attr,
		s.vpnAttributes,
		s.network.vpnAttributes,
		r.vpnAttributes)
}

// Attribute 'authentication-server-group' must only be used
// together with 'ldap_id' and must then be available at network.
func (c *spoc) verifyAuthServer(s *subnet, r *router) {
	attr := "authentication-server-group"
	if _, found := s.vpnAttributes[attr]; found {
		delete(s.vpnAttributes, attr)
		c.err("Attribute '%s' must not be used directly at %s", attr, s)
	}
	auth := getVPNAttr(attr, s, r)
	n := s.network
	if s.ldapId != "" {
		if auth == "" {
			c.err("Missing attribute '%s' at %s having host with 'ldap_id'",
				attr, n)
			n.vpnAttributes[attr] = "ERROR"
		}
	} else if auth != "" {
		var name string
		if n.vpnAttributes[attr] != "" {
			name = n.name
		} else {
			name = r.name
		}
		c.err("Attribute '%s' at %s must only be used"+
			" together with attribute 'ldap_id' at host", attr, name)
	}
}

// Host with ID that doesn't contain a '@' must use attribute
// 'check-subject-name'.
func (c *spoc) verifySubjectNameForHost(s *subnet, r *router) {
	id := s.id
	if strings.Contains(id, "@") {
		return
	}
	if getVPNAttr("check-subject-name", s, r) != "" {
		return
	}
	c.err("Missing vpn_attribute 'check-subject-name'\n for %s", s)
}

// Network with attribute 'cert_id' must use attribute
// 'check-subject-name'.
func (c *spoc) verifySubjectNameForNet(n *network, r *router) {
	if getVPNAttr0("check-subject-name",
		n.vpnAttributes, r.vpnAttributes) != "" {
		return
	}
	c.err("Missing vpn_attribute 'check-subject-name'\n for %s", n)
	n.vpnAttributes["check-subject-name"] = "ERROR"
}

func (c *spoc) verifyExtendedKeyUsage(s *subnet, r *router) {
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
	oid := getVPNAttr("check-extended-key-usage", s, r)
	if other, found := extKeys[domain]; found {
		if oid != other {
			c.err("All ID hosts having domain '%s'"+
				" must use identical value from 'check-extended-key-usage'",
				domain)
		}
	} else {
		extKeys[domain] = oid
	}
}

func (c *spoc) verifyAsaTrustpoint(r *router, crypto *crypto) {
	isakmp := crypto.ipsec.isakmp
	if isakmp.authentication == "rsasig" && isakmp.trustPoint == "" {
		c.err("Missing attribute 'trust_point' in %s for %s", isakmp.name, r)
	}
}

// Generate rules to permit crypto traffic between tunnel endpoints.
func (c *spoc) genTunnelRules(intf1, intf2 *routerIntf, ipsec *ipsec) ruleList {
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
			prt = append(prt, c.prt.Ah)
		}
		if ipsec.espAuthentication != "" || ipsec.espEncryption != "" {
			prt = append(prt, c.prt.Esp)
		}
		if len(prt) > 0 {
			rule := template
			rule.serviceRule = new(serviceRule)
			rule.prt = prt
			rules.push(&rule)
		}
		rule := template
		rule.serviceRule = new(serviceRule)
		rule.srcRange = c.prt.Ike.modifiers.srcRange
		rule.prt = []*proto{c.prt.Ike.main}
		rules.push(&rule)
	}
	if natTraversal != "" {
		rule := template
		rule.serviceRule = new(serviceRule)
		rule.srcRange = c.prt.Natt.modifiers.srcRange
		rule.prt = []*proto{c.prt.Natt.main}
		rules.push(&rule)
	}
	return rules
}

func (c *spoc) expandCrypto() {
	c.progress("Expanding crypto rules")
	var managedCryptoHubs []*router
	hubSeen := make(map[*router]bool)
	id2intf := make(map[string]intfList)
	hasTunnel := make(map[*network]bool)

	l := slices.SortedFunc(maps.Values(c.symTable.crypto),
		func(a, b *crypto) int { return cmp.Compare(a.name, b.name) })
	for _, cr := range l {
		isakmp := cr.ipsec.isakmp
		needId := isakmp.authentication == "rsasig"

		// Do consistency checks and
		// add rules which allow encrypted traffic.
		for _, tunnel := range cr.tunnels {
			spoke, hub := tunnel.interfaces[0], tunnel.interfaces[1]
			router := spoke.router
			managed := router.managed
			hubRouter := hub.router
			hubModel := hubRouter.model
			doAuth := hubModel.doAuth
			natMap := hub.natMap
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
				allNetworks := c.cryptoBehind(intf, managed)
				if net.hasIdHosts {
					hasIdHosts = true
					hasTunnel[net] = true
					idRules := hub.idRules
					if idRules == nil {
						idRules = make(map[string]*idIntf)
						hub.idRules = idRules
					}
					if !doAuth {
						c.err("%s having ID hosts can't be checked by %s",
							net, hubRouter)
					}
					if managed != "" {
						c.err(
							"%s having ID hosts must not be located behind managed %s",
							net, router)
					}
					if hubIsAsaVpn {
						c.verifyAsaVpnAttributes(net.name, net.vpnAttributes)
					}

					// Rules for single software clients are stored
					// individually at crypto hub interface.
					// ID host has one to one relation with subnet.
					for _, s := range net.subnets {
						id := s.id
						if hubIsAsaVpn {
							c.verifyAsaVpnAttributes(s.name, s.vpnAttributes)
							key := "trust-point"
							if (net.vpnAttributes[key] != "" ||
								s.vpnAttributes[key] != "") &&
								s.ipp.IsSingleIP() {

								c.err("Must not use vpn_attribute '%s' at %s",
									key, s)
							}

							c.verifyAuthServer(s, hubRouter)
							if s.ldapId != "" {
								c.verifySubjectNameForNet(net, hubRouter)
							} else {
								c.verifySubjectNameForHost(s, hubRouter)
								c.verifyExtendedKeyUsage(s, hubRouter)
							}
						}
						if other, found := hub.idRules[id]; found {
							src := other.src
							c.err("Duplicate ID-host %s from %s and %s at %s",
								id, src.network, s.network, hubRouter)
							continue
						}
						idRules[id] = &idIntf{
							routerIntf: &routerIntf{
								netObj: netObj{
									ipObj: ipObj{
										name: hub.name + "." + id,
									},
								},
								ipType: tunnelIP,
								natMap: natMap,
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
				c.err("Must not use networks having ID hosts"+
					" and other networks having no ID hosts\n"+
					" together at %s:\n"+encrypted.nameList(),
					router)
			}

			id := spoke.id
			if id != "" {
				if !needId {
					c.err("Invalid attribute 'id' at %s.\n"+
						" Set authentication=rsasig at %s", spoke, isakmp.name)
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
					c.err("Must not reuse 'id = %s' at different"+
						" crypto spokes of '%s':\n"+other.nameList(),
						id, hubRouter)
				}
				id2intf[id] = append(id2intf[id], spoke)
			}
			if len(encrypted) != 0 && !hasIdHosts && id == "" {
				if doAuth && managed == "" {
					c.err("Networks behind crypto tunnel to %s of model '%s'"+
						" need to have ID hosts:\n"+encrypted.nameList(),
						hubRouter, hubRouter.model.name)
				} else if needId {
					c.err("%s needs attribute 'id', because %s"+
						" has authentication=rsasig",
						spoke, isakmp.name)
				}
			}

			// Add only non hidden peer networks.
			for _, net := range encrypted {
				if !getNatNetwork(net, natMap).hidden {
					hub.peerNetworks = append(hub.peerNetworks, net)
				}
			}

			if managed != "" {
				if router.model.crypto == "ASA" {
					c.verifyAsaTrustpoint(router, cr)
				}
				if cr.detailedCryptoAcl {
					c.err("Attribute 'detailed_crypto_acl' is not"+
						" allowed for managed spoke %s", router)
				}
			}

			// Add rules to permit crypto traffic between tunnel endpoints.
			// If one tunnel endpoint has no known IP address,
			// some rules have to be added manually.
			realSpoke := spoke.realIntf
			if realSpoke != nil &&
				realSpoke.ipType != shortIP &&
				realSpoke.ipType != unnumberedIP {

				realHub := hub.realIntf
				gen := func(in, out *routerIntf) {
					// Don't generate incoming ACL from unknown address.
					if in.ipType != negotiatedIP {
						rules := c.genTunnelRules(in, out, cr.ipsec)
						c.allPathRules.permit = append(c.allPathRules.permit, rules...)
					}
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
	for _, r := range managedCryptoHubs {
		cryptoType := r.model.crypto
		if cryptoType != "ASA_VPN" {
			continue
		}
		var idRulesIntfs intfList
		for _, intf := range r.interfaces {
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
					c.err("Duplicate ID-host %s from %s and %s at %s",
						id, src1.network, src2.getNetwork(), r)
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
			c.verifyAsaVpnAttributes(r.name, r.vpnAttributes)

			// Move 'trust-point' from vpn_attributes to router attribute.
			if trustPoint, found := r.vpnAttributes["trust-point"]; found {
				delete(r.vpnAttributes, "trust-point")
				r.trustPoint = trustPoint
			} else {
				c.err("Missing 'trust-point' in vpnAttributes of %s", r)
			}
		} else if cryptoType == "ASA" {
			for _, intf := range r.interfaces {
				if intf.ipType == tunnelIP {
					c.verifyAsaTrustpoint(r, intf.getCrypto())
				}
			}
		}
	}

	for _, n := range c.allNetworks {
		if !n.isAggregate && n.hasIdHosts && !hasTunnel[n] {
			c.err(
				"%s having ID hosts must be connected to router with crypto spoke",
				n)
		}
	}
}
