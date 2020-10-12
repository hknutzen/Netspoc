package pass1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/jcode"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

var program string

func getIntf(router *router) []*routerIntf {
	if origRouter := router.origRouter; origRouter != nil {
		return origRouter.origIntfs
	} else if origIntfs := router.origIntfs; origIntfs != nil {
		return origIntfs
	} else {
		return router.interfaces
	}
}

func (z *zone) nonSecondaryIntfs() []*routerIntf {
	var result []*routerIntf
	for _, intf := range z.interfaces {
		if intf.mainIntf == nil {
			result = append(result, intf)
		}
	}
	return result
}

var permitAnyRule, permitAny6Rule *groupedRule

func getPermitAnyRule(ipv6 bool) *groupedRule {
	if ipv6 {
		return permitAny6Rule
	} else {
		return permitAnyRule
	}
}

var denyAnyRule, denyAny6Rule *groupedRule

func getDenyAnyRule(ipv6 bool) *groupedRule {
	if ipv6 {
		return denyAny6Rule
	} else {
		return denyAnyRule
	}
}

func printHeader(fh *os.File, router *router, what string) {
	commentChar := router.model.commentChar
	if router.vrfMembers != nil {
		what += " for " + router.name
	}
	fmt.Fprintln(fh, commentChar, "[", what, "]")
}

func iosRouteCode(n *net.IPNet) string {
	ipCode := n.IP.String()
	maskCode := net.IP(n.Mask).String()
	return ipCode + " " + maskCode
}

func printRoutes(fh *os.File, router *router) {
	ipv6 := router.ipV6
	model := router.model
	vrf := router.vrf
	doAutoDefaultRoute := conf.Conf.AutoDefaultRoute
	zeroIp := getZeroIp(ipv6)
	cryptoType := model.crypto
	asaCrypto := cryptoType == "ASA"
	prefix2ip2net := make(map[int]map[string]*network)
	type hopInfo struct {
		intf *routerIntf
		hop  *routerIntf
	}
	net2hopInfo := make(map[*network]hopInfo)

	for _, intf := range router.interfaces {

		// Must not combine static routes to default route if any
		// interface has dynamic routing enabled.
		if intf.routing != nil {
			doAutoDefaultRoute = false
			continue
		}

		// ASA with site-to-site VPN needs individual routes for each peer.
		if asaCrypto && intf.hub != nil {
			doAutoDefaultRoute = false
		}

		// netHash: A map having all networks reachable via current hop
		// both as key and as value.
		for hop, netMap := range intf.routes {
			info := hopInfo{intf, hop}
			for natNetwork, _ := range netMap {
				if natNetwork.hidden {
					continue
				}

				ip := natNetwork.ip
				prefixlen, _ := natNetwork.mask.Size()
				if prefixlen == 0 {
					doAutoDefaultRoute = false
				}

				// Implicitly overwrite duplicate networks.
				// Can't use ip slice as key.
				m := prefix2ip2net[prefixlen]
				if m == nil {
					m = make(map[string]*network)
					prefix2ip2net[prefixlen] = m
				}
				m[string(ip)] = natNetwork

				// This is unambiguous, because only a single static
				// route is allowed for each network.
				net2hopInfo[natNetwork] = info
			}
		}
	}
	if len(net2hopInfo) == 0 {
		return
	}

	// Combine adjacent networks, if both use same hop and
	// if combined network doesn't already exist.
	// Prepare invPrefixAref.
	var bitstrLen int
	if ipv6 {
		bitstrLen = 128
	} else {
		bitstrLen = 32
	}
	invPrefixAref := make([]map[string]*network, bitstrLen+1)
	keys := make([]int, 0, len(prefix2ip2net))
	for k, _ := range prefix2ip2net {
		keys = append(keys, k)
	}
	for _, prefix := range keys {
		invPrefix := bitstrLen - prefix
		ip2net := prefix2ip2net[prefix]
		keys := make([]string, 0, len(ip2net))
		for k, _ := range ip2net {
			keys = append(keys, k)
		}
		for _, ip := range keys {
			net := ip2net[string(ip)]

			// Don't combine peers of ASA with site-to-site VPN.
			if asaCrypto {
				hopInfo := net2hopInfo[net]
				if hopInfo.intf.hub != nil {
					continue
				}
			}
			m := invPrefixAref[invPrefix]
			if m == nil {
				m = make(map[string]*network)
				invPrefixAref[invPrefix] = m
			}
			m[string(ip)] = net
		}
	}

	// Go from small to large networks. So we combine newly added
	// networks as well.
	for invPrefix, ip2net := range invPrefixAref {

		// Must not optimize network 0/0; it has no supernet.
		if invPrefix >= bitstrLen {
			break
		}
		if ip2net == nil {
			continue
		}
		partPrefix := bitstrLen - invPrefix
		partMask := net.CIDRMask(partPrefix, bitstrLen)
		combinedInvPrefix := invPrefix + 1
		combinedPrefix := bitstrLen - combinedInvPrefix
		combinedMask := net.CIDRMask(combinedPrefix, bitstrLen)
		n := len(partMask)

		// A single bit, masking the lowest network bit.
		nextBit := make(net.IPMask, n)
		for i := 0; i < n; i++ {
			nextBit[i] = ^combinedMask[i] & partMask[i]
		}

		keys := make([]net.IP, 0, len(ip2net))
		for k, _ := range ip2net {
			keys = append(keys, net.IP(k))
		}
		for _, ip := range keys {

			// Only analyze left part of two adjacent networks.
			if !ip.Mask(nextBit).Equal(zeroIp) {
				continue
			}
			left := ip2net[string(ip)]

			// Find corresponding right part.
			nextIP := make(net.IP, n)
			for i := 0; i < n; i++ {
				nextIP[i] = ip[i] | nextBit[i]
			}
			right := ip2net[string(nextIP)]
			if right == nil {
				continue
			}

			// Both parts must use equal next hop.
			hopLeft := net2hopInfo[left]
			hopRight := net2hopInfo[right]
			if hopLeft != hopRight {
				continue
			}

			ip2net := invPrefixAref[combinedInvPrefix]

			if ip2net == nil {
				ip2net = make(map[string]*network)
				invPrefixAref[combinedInvPrefix] = ip2net
			} else if ip2net[string(ip)] != nil {
				// Combined network already exists.
				continue
			}

			// Add combined route.
			combined := &network{ipObj: ipObj{ip: ip}, mask: combinedMask}
			ip2net[string(ip)] = combined

			ip2net = prefix2ip2net[combinedPrefix]
			if ip2net == nil {
				ip2net = make(map[string]*network)
				prefix2ip2net[combinedPrefix] = ip2net
			}
			ip2net[string(ip)] = combined
			net2hopInfo[combined] = hopLeft

			// Left and right part are no longer used.
			delete(prefix2ip2net[partPrefix], string(ip))
			delete(prefix2ip2net[partPrefix], string(nextIP))
		}
	}

	// Find and remove duplicate networks.
	// Go from smaller to larger networks.
	prefixes := make([]int, 0, len(prefix2ip2net))
	for k, _ := range prefix2ip2net {
		prefixes = append(prefixes, k)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(prefixes)))
	type netInfo struct {
		*net.IPNet
		noOpt bool
	}
	intf2hop2netInfos := make(map[*routerIntf]map[*routerIntf][]netInfo)
	for len(prefixes) != 0 {
		prefix := prefixes[0]
		prefixes = prefixes[1:]
		ip2net := prefix2ip2net[prefix]
		ips := make([]net.IP, 0, len(ip2net))
		for k, _ := range ip2net {
			ips = append(ips, net.IP(k))
		}
		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i], ips[j]) == -1
		})
	NETWORK:
		for _, ip := range ips {
			small := ip2net[string(ip)]
			hopInfo := net2hopInfo[small]
			noOpt := false

			// ASA with site-to-site VPN needs individual routes for each peer.
			if !(asaCrypto && hopInfo.intf.hub != nil) {

				// Compare current mask with masks of larger networks.
				for _, p := range prefixes {
					i := ip.Mask(net.CIDRMask(p, bitstrLen))
					big := prefix2ip2net[p][string(i)]
					if big == nil {
						continue
					}

					// small is subnet of big.
					// If both use the same hop, then small is redundant.
					if net2hopInfo[big] == hopInfo {

						//                debug "Removed: small.name -> hop.name"
						continue NETWORK
					}

					// Otherwise small isn't redundant, even if a bigger network
					// with same hop exists.
					// It must not be removed by default route later.
					noOpt = true

					//             debug "No opt: small.name -> hop.name"
					break
				}
			}
			m := intf2hop2netInfos[hopInfo.intf]
			if m == nil {
				m = make(map[*routerIntf][]netInfo)
				intf2hop2netInfos[hopInfo.intf] = m
			}
			info := netInfo{
				&net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, bitstrLen)},
				noOpt,
			}
			m[hopInfo.hop] = append(m[hopInfo.hop], info)
		}
	}

	if doAutoDefaultRoute {

		// Find interface and hop with largest number of routing entries.
		var maxIntf *routerIntf
		var maxHop *routerIntf

		// Substitute routes to one hop with a default route,
		// if there are at least two entries.
		max := 1
		for _, intf := range router.interfaces {
			hop2nets := intf2hop2netInfos[intf]
			for hop, nets := range hop2nets {
				count := 0
				for _, netInfo := range nets {
					if !netInfo.noOpt {
						count++
					}
				}
				if count > max {
					maxIntf = intf
					maxHop = hop
					max = count
				}
			}
		}
		if maxIntf != nil {

			// Use default route for this direction.
			// But still generate routes for small networks
			// with supernet behind other hop.
			hop2nets := intf2hop2netInfos[maxIntf]
			nets := []netInfo{{
				&net.IPNet{IP: zeroIp, Mask: net.CIDRMask(0, bitstrLen)},
				false,
			}}
			for _, net := range hop2nets[maxHop] {
				if net.noOpt {
					nets = append(nets, net)
				}
			}
			hop2nets[maxHop] = nets
		}
	}
	printHeader(fh, router, "Routing")

	iosVrf := ""
	if vrf != "" && model.routing == "IOS" {
		iosVrf = "vrf " + vrf + " "
	}
	nxosPrefix := ""

	for _, intf := range router.interfaces {
		hop2nets := intf2hop2netInfos[intf]
		hops := make([]*routerIntf, 0, len(hop2nets))
		for k, _ := range hop2nets {
			hops = append(hops, k)
		}
		sort.Slice(hops, func(i, j int) bool {
			return hops[i].name < hops[j].name
		})
		for _, hop := range hops {

			// For unnumbered and negotiated interfaces use interface name
			// as next hop.
			var hopAddr string
			if intf.unnumbered || intf.negotiated || intf.tunnel {
				hopAddr = intf.hardware.name
			} else {
				hopAddr = hop.ip.String()
			}

			for _, netinfo := range hop2nets[hop] {
				switch model.routing {
				case "IOS":
					var adr string
					ip := "ip"
					if ipv6 {
						adr = fullPrefixCode(netinfo.IPNet)
						ip += "v6"
					} else {
						adr = iosRouteCode(netinfo.IPNet)
					}
					fmt.Fprintln(fh, ip, "route", iosVrf+adr, hopAddr)
				case "NX-OS":
					if vrf != "" && nxosPrefix == "" {

						// Print "vrf context" only once
						// and indent "ip route" commands.
						fmt.Fprintln(fh, "vrf context", vrf)
						nxosPrefix = " "
					}
					adr := fullPrefixCode(netinfo.IPNet)
					ip := "ip"
					if ipv6 {
						ip += "v6"
					}
					fmt.Fprintln(fh, nxosPrefix+ip, "route", adr, hopAddr)
				case "ASA":
					var adr string
					ip := ""
					if ipv6 {
						adr = fullPrefixCode(netinfo.IPNet)
						ip = "ipv6 "
					} else {
						adr = iosRouteCode(netinfo.IPNet)
					}
					fmt.Fprintln(fh, ip+"route", intf.hardware.name, adr, hopAddr)
				case "iproute":
					adr := prefixCode(netinfo.IPNet)
					fmt.Fprintln(fh, "ip route add", adr, "via", hopAddr)
				case "none":
					// Do nothing.
				}
			}
		}
	}
}

func printAclPlaceholder(fh *os.File, router *router, aclName string) {

	// Add comment at start of ACL to easier find first ACL line in tests.
	model := router.model
	filter := model.filter
	if filter == "ASA" {
		commentChar := model.commentChar
		fmt.Fprintln(fh, commentChar, aclName)
	}

	fmt.Fprintln(fh, "#insert", aclName)
}

// Parameter: routerIntf
// Analyzes dst/src list of all rules collected at this interface.
// Result:
// List of all networks which are reachable when entering this interface.
func getSplitTunnelNets(intf *routerIntf) []*network {
	var result []*network
	seen := make(map[*network]bool)
	checkRules := func(rules []*groupedRule, takeDst bool) {
		for _, rule := range rules {
			if rule.deny {
				continue
			}
			objList := rule.dst
			if takeDst {
				objList = rule.src
			}
			for _, obj := range objList {
				network := obj.getNetwork()

				// Don't add 'any' (resulting from global:permit)
				// to split_tunnel networks.
				prefix, _ := network.mask.Size()
				if prefix == 0 {
					continue
				}
				if seen[network] {
					continue
				}
				result = append(result, network)
				seen[network] = true
			}
		}
	}
	checkRules(intf.rules, false)
	checkRules(intf.intfRules, false)
	checkRules(intf.outRules, true)

	// Sort for deterministic output:
	sort.Slice(result, func(i, j int) bool {
		switch bytes.Compare(result[i].ip, result[j].ip) {
		case -1:
			return true
		case 1:
			return false
		}
		return bytes.Compare(result[i].mask, result[j].mask) == -1
	})
	return result
}

func printAsaTrustpoint(fh *os.File, router *router, trustpoint string) {
	model := router.model
	fmt.Fprintln(fh, " ikev1 trust-point", trustpoint)

	// This command is not known, if ASA runs as virtual context.
	if !model.cryptoInContext {
		fmt.Fprintln(fh, " ikev1 user-authentication none")
	}
}

func printTunnelGroupRa(fh *os.File, id, idName string, attributes map[string]string, router *router, groupPolicyName string, certGroupMap map[string]string) {

	subjectName := attributes["check-subject-name"]
	delete(attributes, "check-subject-name")
	if id[0] == '@' {
		subjectName = "ea"
	}
	mapName := "ca-map-" + idName
	fmt.Fprintln(fh, "crypto ca certificate map", mapName, "10")
	fmt.Fprintln(fh, " subject-name attr", subjectName, "co", id)
	if oid := attributes["check-extended-key-usage"]; oid != "" {
		delete(attributes, "check-extended-key-usage")
		fmt.Fprintln(fh, " extended-key-usage co", oid)
	}
	trustpoint2 := attributes["trust-point"]
	if trustpoint2 == "" {
		trustpoint2 = router.trustPoint
	} else {
		delete(attributes, "trust-point")
	}
	var tunnelGenAtt []string
	authentication := "certificate"
	if groupPolicyName != "" {
		tunnelGenAtt = append(tunnelGenAtt, "default-group-policy "+groupPolicyName)
	} else {
		authentication = "aaa " + authentication
	}

	// Select attributes for tunnel-group general-attributes.
	keys := make([]string, 0, len(attributes))
	for k, _ := range attributes {
		if spec := asaVpnAttributes[k]; spec == tgGeneral {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		out := key

		// Replace "_" by " " in keys,
		// e.g. password-management_password-expire-in-days =>
		//      "password-management password-expire-in-days"
		out = strings.Replace(out, "_", " ", -1)
		if value := attributes[key]; value != "" {
			out += " " + value
		}
		tunnelGenAtt = append(tunnelGenAtt, out)
	}

	tunnelGroupName := "VPN-tunnel-" + idName
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "type remote-access")
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "general-attributes")

	for _, line := range tunnelGenAtt {
		fmt.Fprintln(fh, " "+line)
	}
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "ipsec-attributes")
	printAsaTrustpoint(fh, router, trustpoint2)

	// For anyconnect clients.
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "webvpn-attributes")
	fmt.Fprintln(fh, " authentication", authentication)
	certGroupMap[mapName] = tunnelGroupName

	fmt.Fprintln(fh, "tunnel-group-map", mapName, "10", tunnelGroupName)
	fmt.Fprintln(fh)
}

func combineAttr(list ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, attr := range list {
		for k, v := range attr {
			result[k] = v
		}
	}
	return result
}

var asaVpnAttrNeedValue = map[string]bool{
	"anyconnect-custom_perapp":  true,
	"banner":                    true,
	"dns-server":                true,
	"default-domain":            true,
	"split-dns":                 true,
	"wins-server":               true,
	"address-pools":             true,
	"split-tunnel-network-list": true,
	"vpn-filter":                true,
}

func printAsavpn(fh *os.File, router *router) {
	ipv6 := router.ipV6

	globalGroupName := "global"
	fmt.Fprintln(fh, "group-policy", globalGroupName, "internal")
	fmt.Fprintln(fh, "group-policy", globalGroupName, "attributes")
	fmt.Fprintln(fh, " pfs enable")
	fmt.Fprintln(fh)

	// Define tunnel group used for single VPN users.
	defaultTunnelGroup := "VPN-single"
	trustPoint := router.trustPoint

	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "type remote-access")
	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "general-attributes")
	fmt.Fprintln(fh, " authorization-server-group LOCAL")
	fmt.Fprintln(fh, " default-group-policy", globalGroupName)
	fmt.Fprintln(fh, " authorization-required")
	fmt.Fprintln(fh, " username-from-certificate EA")
	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "ipsec-attributes")
	fmt.Fprintln(fh, " chain")
	printAsaTrustpoint(fh, router, trustPoint)
	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "webvpn-attributes")
	fmt.Fprintln(fh, " authentication certificate")
	fmt.Fprintln(fh, "tunnel-group-map default-group", defaultTunnelGroup)
	fmt.Fprintln(fh)

	printGroupPolicy := func(name string, attributes map[string]string) {
		fmt.Fprintln(fh, "group-policy", name, "internal")
		fmt.Fprintln(fh, "group-policy", name, "attributes")
		keys := make([]string, 0, len(attributes))
		for k, _ := range attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {

			// Ignore attributes for tunnel-group general or own attributes.
			if spec := asaVpnAttributes[key]; spec == tgGeneral || spec == ownAttr {
				continue
			}

			value := attributes[key]
			out := key

			// Replace "_" by " " in keys,
			// e.g. anyconnect-custom_perapp => "anyconnect-custom perapp"
			out = strings.Replace(out, "_", " ", -1)
			if value != "" {
				if asaVpnAttrNeedValue[key] {
					out += " value"
				}
				out += " " + value
			}
			fmt.Fprintln(fh, " "+out)
		}
	}

	// Use id with normal length as name for group-policy, etc.
	// Total length is limited to 64 characters.
	// Max prefix is 11 characters "VPN-tunnel-"
	// Max postfix is 7 "-drc-nn".
	// Hence, usable length is limited to 46 characters.
	// Use running integer, if id is too long.
	idCounter := 0
	genIdName := func(id string) string {
		if len(id) <= 46 {
			for _, c := range id {
				if unicode.IsDigit(c) || unicode.IsLetter(c) {
					continue
				}
				switch c {
				case '@', '.', '-', '_':
					continue
				}
				goto BAD
			}
			return id
		}
	BAD:
		idCounter++
		return strconv.Itoa(idCounter)
	}
	certGroupMap := make(map[string]string)
	singleCertMap := make(map[string]bool)
	extendedKey := make(map[string]string)
	type ldapEntry struct {
		dn     string
		gpName string
	}
	ldapMap := make(map[string][]ldapEntry)
	networkSeen := make(map[*network]bool)
	aclCounter := 1
	denyAny := getDenyAnyRule(ipv6)
	for _, intf := range router.interfaces {
		if !intf.tunnel {
			continue
		}
		natSet := intf.natSet
		splitTCache := make(map[int]map[string][]*network)

		if hash := intf.idRules; hash != nil {
			keys := make([]string, 0, len(hash))
			for k, _ := range hash {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, id := range keys {
				idIntf := hash[id]
				idName := genIdName(id)
				src := idIntf.src
				attributes := combineAttr(
					router.radiusAttributes,
					src.getNetwork().radiusAttributes,
					src.radiusAttributes)

				// Define split tunnel ACL.
				// Use default value if not defined.
				splitTunnelPolicy := attributes["split-tunnel-policy"]
				if splitTunnelPolicy == "" {

					// Do nothing.
				} else if splitTunnelPolicy == "tunnelall" {

					// This is the default value.
					// Prevent new group-policy to be created.
					delete(attributes, "split-tunnel-policy")
				} else if splitTunnelPolicy == "tunnelspecified" {
					splitTunnelNets := getSplitTunnelNets(idIntf.routerIntf)
					aclName := ""
				CACHED_NETS:
					for name, nets := range splitTCache[len(splitTunnelNets)] {
						for i, net := range nets {
							if splitTunnelNets[i] != net {
								continue CACHED_NETS
							}
						}
						aclName = name
						break
					}
					if aclName == "" {
						aclName = "split-tunnel-" + strconv.Itoa(aclCounter)
						aclCounter++
						var rule *groupedRule
						if splitTunnelNets != nil {
							objects := make([]someObj, len(splitTunnelNets))
							for i, n := range splitTunnelNets {
								objects[i] = n
							}
							rule = newRule(
								objects,
								[]someObj{getNetwork00(ipv6)},
								[]*proto{prtIP},
							)
						} else {
							rule = denyAny
						}
						name2nets := splitTCache[len(splitTunnelNets)]
						if name2nets == nil {
							name2nets = make(map[string][]*network)
							splitTCache[len(splitTunnelNets)] = name2nets
						}
						name2nets[aclName] = splitTunnelNets
						info := &aclInfo{
							name:        aclName,
							rules:       []*groupedRule{rule},
							natSet:      natSet,
							isStdACL:    true,
							isCryptoACL: true,
						}
						router.aclList = append(router.aclList, info)
						printAclPlaceholder(fh, router, aclName)
					}
					attributes["split-tunnel-network-list"] = aclName
				}

				// Access list will be bound to cleartext interface.
				// Only check for valid source address at vpn-filter.
				idIntf.rules = nil
				rule := newRule(
					[]someObj{src},
					[]someObj{getNetwork00(ipv6)},
					[]*proto{prtIP},
				)
				filterName := "vpn-filter-" + idName
				info := &aclInfo{
					name:    filterName,
					rules:   []*groupedRule{rule},
					addDeny: true,
					natSet:  natSet,
				}
				router.aclList = append(router.aclList, info)
				printAclPlaceholder(fh, router, filterName)

				ip := src.ip.String()
				network := src.getNetwork()
				if isHostMask(src.mask) {

					// For anyconnect clients.
					pos := strings.IndexByte(id, '@')
					domain := id[pos:]
					singleCertMap[domain] = true

					extendedKey[domain] = attributes["check-extended-key-usage"]
					delete(attributes, "check-extended-key-usage")

					mask := net.IP(network.mask).String()
					groupPolicyName := ""
					if len(attributes) > 0 {
						groupPolicyName = "VPN-group-" + idName
						printGroupPolicy(groupPolicyName, attributes)
					}
					fmt.Fprintln(fh, "username", id, "nopassword")
					fmt.Fprintln(fh, "username", id, "attributes")
					fmt.Fprintln(fh, " vpn-framed-ip-address", ip, mask)
					fmt.Fprintln(fh, " service-type remote-access")
					fmt.Fprintln(fh, " vpn-filter value", filterName)
					if groupPolicyName != "" {
						fmt.Fprintln(fh, " vpn-group-policy", groupPolicyName)
					}
					fmt.Fprintln(fh)
				} else {
					name := "pool-" + idName
					mask := net.IP(src.mask).String()
					n := len(src.ip)
					maxIP := make(net.IP, n)
					for i := 0; i < n; i++ {
						maxIP[i] = src.ip[i] | ^src.mask[i]
					}
					max := maxIP.String()
					fmt.Fprintln(fh, "ip local pool", name, ip+"-"+max, "mask", mask)
					attributes["address-pools"] = name
					attributes["vpn-filter"] = filterName
					groupPolicyName := "VPN-group-" + idName
					printGroupPolicy(groupPolicyName, attributes)

					if ldapId := src.ldapId; ldapId != "" {
						network := src.getNetwork()
						netAttr := combineAttr(
							router.radiusAttributes,
							network.radiusAttributes,
						)
						authServer := netAttr["authentication-server-group"]
						ldapMap[authServer] = append(
							ldapMap[authServer], ldapEntry{ldapId, groupPolicyName})
						if !networkSeen[network] {
							networkSeen[network] = true
							certId := network.certId
							printTunnelGroupRa(
								fh,
								certId,
								genIdName(certId),
								netAttr,
								router,
								"",
								certGroupMap,
							)
						}
					} else {
						printTunnelGroupRa(
							fh,
							id,
							idName,
							attributes,
							router, groupPolicyName,
							certGroupMap,
						)
					}
				}
			}
		} else if id := intf.peer.id; id != "" {
			// A VPN network.

			// Access list will be bound to cleartext interface.
			// Only check for correct source address at vpn-filter.
			objects := make([]someObj, len(intf.peerNetworks))
			for i, n := range intf.peerNetworks {
				objects[i] = n
			}
			rules := []*groupedRule{newRule(
				objects,
				[]someObj{getNetwork00(ipv6)},
				[]*proto{prtIP},
			)}
			idName := genIdName(id)
			filterName := "vpn-filter-" + idName
			info := &aclInfo{
				name:    filterName,
				rules:   rules,
				addDeny: true,
				natSet:  natSet,
			}
			router.aclList = append(router.aclList, info)
			printAclPlaceholder(fh, router, filterName)

			attributes := router.radiusAttributes

			groupPolicyName := ""
			if len(attributes) > 0 {
				groupPolicyName = "VPN-router-" + idName
				printGroupPolicy(groupPolicyName, attributes)
			}
			fmt.Fprintln(fh, "username", id, "nopassword")
			fmt.Fprintln(fh, "username", id, "attributes")
			fmt.Fprintln(fh, " service-type remote-access")
			fmt.Fprintln(fh, " vpn-filter value", filterName)
			if groupPolicyName != "" {
				fmt.Fprintln(fh, " vpn-group-policy", groupPolicyName)
			}
			fmt.Fprintln(fh)
		}
	}

	// Do nothing for unmanaged VPN router without any networks.

	// Generate certificate-group-map for anyconnect/ikev2 clients.
	if len(certGroupMap) > 0 || len(singleCertMap) > 0 {
		keys := make([]string, 0, len(singleCertMap))
		for k, _ := range singleCertMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, id := range keys {
			idName := genIdName(id)
			mapName := "ca-map-" + idName
			fmt.Fprintln(fh, "crypto ca certificate map", mapName, "10")
			fmt.Fprintln(fh, " subject-name attr ea co", id)
			if oid := extendedKey[id]; oid != "" {
				fmt.Fprintln(fh, " extended-key-usage co", oid)
			}
			certGroupMap[mapName] = defaultTunnelGroup
		}
		fmt.Fprintln(fh, "webvpn")
		keys = make([]string, 0, len(certGroupMap))
		for k, _ := range certGroupMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, mapName := range keys {
			tunnelGroupMap := certGroupMap[mapName]
			fmt.Fprintln(fh, " certificate-group-map", mapName, "10", tunnelGroupMap)
		}
		fmt.Fprintln(fh)
	}

	// Generate ldap attribute-maps and aaa-server referencing each map.
	keys := make([]string, 0, len(ldapMap))
	for k, _ := range ldapMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fmt.Fprintln(fh, "aaa-server", name, "protocol ldap")
		fmt.Fprintln(fh, "aaa-server", name, "host X")
		fmt.Fprintln(fh, " ldap-attribute-map", name)
		fmt.Fprintln(fh, "ldap attribute-map", name)
		fmt.Fprintln(fh, " map-name memberOf Group-Policy")
		for _, entry := range ldapMap[name] {
			dn := strings.ReplaceAll(entry.dn, `"`, `\"`)
			fmt.Fprintf(fh, " map-value memberOf \"%s\" %s\n", dn, entry.gpName)
		}
	}
}

// Pre-processing for all interfaces.
func printAclPrefix(fh *os.File, router *router) {
	model := router.model
	if model.filter != "iptables" {
		return
	}
	commentChar := model.commentChar
	fmt.Fprintln(fh, commentChar, "[ PREFIX ]")
	fmt.Fprintln(fh, "#!/sbin/iptables-restore <<EOF")

	// Excempt loopback packets from connection tracking.
	fmt.Fprintln(fh, "*raw")
	fmt.Fprintln(fh, ":PREROUTING ACCEPT")
	fmt.Fprintln(fh, ":OUTPUT ACCEPT")
	fmt.Fprintln(fh, "-A PREROUTING -i lo -j NOTRACK")
	fmt.Fprintln(fh, "-A OUTPUT -o lo -j NOTRACK")
	fmt.Fprintln(fh, "COMMIT")

	// Start filter table
	fmt.Fprintln(fh, "*filter")
	fmt.Fprintln(fh, ":INPUT DROP")
	fmt.Fprintln(fh, ":FORWARD DROP")
	fmt.Fprintln(fh, ":OUTPUT ACCEPT")
	fmt.Fprintln(fh, "-A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED")
	fmt.Fprintln(fh, "-A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED")
	fmt.Fprintln(fh, "-A INPUT -j ACCEPT -i lo")

	// Add user defined chain 'droplog'.
	fmt.Fprintln(fh, ":droplog -")
	fmt.Fprintln(fh, "-A droplog -j LOG --log-level debug")
	fmt.Fprintln(fh, "-A droplog -j DROP")
	fmt.Fprintln(fh)
}

func printAclSuffix(fh *os.File, router *router) {
	model := router.model
	if model.filter != "iptables" {
		return
	}
	commentChar := model.commentChar
	fmt.Fprintln(fh, commentChar, "[ SUFFIX ]")
	fmt.Fprintln(fh, "-A INPUT -j droplog")
	fmt.Fprintln(fh, "-A FORWARD -j droplog")
	fmt.Fprintln(fh, "COMMIT")
	fmt.Fprintln(fh, "EOF")
}

func printIptablesAcls(fh *os.File, router *router) {
	for _, hardware := range router.hardware {

		// Ignore if all logical interfaces are loopback interfaces.
		if hardware.loopback {
			continue
		}

		inHw := hardware.name
		natSet := hardware.natSet

		// Collect interface rules.
		// Add call to chain in INPUT chain.
		intfAclName := inHw + "_self"
		intfAclInfo := &aclInfo{
			name:    intfAclName,
			rules:   hardware.intfRules,
			addDeny: true,
			natSet:  natSet,
		}
		hardware.intfRules = nil
		router.aclList = append(router.aclList, intfAclInfo)
		printAclPlaceholder(fh, router, intfAclName)
		fmt.Fprintln(fh, "-A INPUT -j", intfAclName, "-i", inHw)

		// Collect forward rules.
		// One chain for each pair of in_intf / out_intf.
		// Add call to chain in FORRWARD chain.
		// Sort keys for deterministic output.
		keys := make([]string, 0, len(hardware.ioRules))
		for k, _ := range hardware.ioRules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, outHw := range keys {
			aclName := inHw + "_" + outHw
			info := &aclInfo{
				name:    aclName,
				rules:   hardware.ioRules[outHw],
				addDeny: true,
				natSet:  natSet,
			}
			router.aclList = append(router.aclList, info)
			printAclPlaceholder(fh, router, aclName)
			fmt.Fprintln(fh, "-A FORWARD -j", aclName, "-i", inHw, "-o", outHw)
		}
		hardware.ioRules = nil

		// Empty line after each chain.
		fmt.Fprintln(fh)
	}
}

func printCiscoAcls(fh *os.File, router *router) {
	model := router.model
	filter := model.filter
	managedLocal := router.managed == "local"
	ipv6 := router.ipV6
	permitAny := getPermitAnyRule(ipv6)

	for _, hardware := range router.hardware {

		// Ignore if all logical interfaces are loopback interfaces.
		if hardware.loopback {
			continue
		}

		// Ignore layer3 interface of ASA.
		if hardware.name == "device" && model.class == "ASA" {
			continue
		}

		natSet := hardware.natSet
		dstNatSet := hardware.dstNatSet
		if dstNatSet == nil {
			dstNatSet = natSet
		}

		// Generate code for incoming and possibly for outgoing ACL.
		for _, suffix := range []string{"in", "out"} {

			info := &aclInfo{}

			// - Collect incoming ACLs,
			// - protect own interfaces,
			// - set {filter_any_src}.
			if suffix == "in" {
				rules := hardware.rules
				intfRules := hardware.intfRules
				hardware.rules = nil
				hardware.intfRules = nil

				// Don't generate single 'permit ip any any'.
				if !model.needACL &&
					len(rules) == 1 && rules[0] == permitAny &&
					len(intfRules) == 1 && intfRules[0] == permitAny {
					continue
				}
				info.natSet = natSet
				info.dstNatSet = dstNatSet
				info.rules = rules

				// Marker: Generate protect_self rules, if available.
				info.protectSelf = true

				if router.needProtect {
					info.intfRules = intfRules
				}
				if hardware.noInAcl {
					info.addPermit = true
				} else {
					info.addDeny = true
				}

				if managedLocal {

					// If attached zone has only one connection to this
					// firewall than we don't need to check the source
					// address. It has already been checked, that all
					// networks of this zone match attribute filterOnly.
					intfOk := 0
					for _, intf := range hardware.interfaces {
						zone := intf.zone
						if zone.zoneCluster != nil {
							break
						}

						// Ignore real interface of virtual interface.
						interfaces := zone.nonSecondaryIntfs()

						// Multiple interfaces belonging to one redundancy
						// group can't be used to cross the zone.
						if len(interfaces) > 1 && !isRedundanyGroup(interfaces) {
							break
						}
						intfOk++
					}
					if intfOk == len(hardware.interfaces) {
						info.filterAnySrc = true
					}
				}

				// Add ACL of corresponding tunnel interfaces.
				// We have exactly one crypto interface per hardware.
				intf := hardware.interfaces[0]
				if (intf.hub != nil || intf.spoke != nil) && router.model.noCryptoFilter {
					for _, tunnelIntf := range getIntf(router) {
						realIntf := tunnelIntf.realIntf
						if realIntf == nil || realIntf != intf {
							continue
						}
						tunnelInfo := &aclInfo{
							natSet:    tunnelIntf.natSet,
							rules:     tunnelIntf.rules,
							intfRules: tunnelIntf.intfRules,
						}
						info.subAclList = append(info.subAclList, tunnelInfo)
					}
				}
			} else {
				// Outgoing ACL
				if !hardware.needOutAcl {
					continue
				}
				rules := hardware.outRules
				hardware.outRules = nil
				if len(rules) == 1 && rules[0] == permitAny {
					continue
				}
				info.rules = rules
				info.natSet = dstNatSet
				info.dstNatSet = natSet
				info.addDeny = true
			}

			aclName := hardware.name + "_" + suffix
			info.name = aclName
			router.aclList = append(router.aclList, info)
			printAclPlaceholder(fh, router, aclName)

			// Post-processing for hardware interface
			if filter == "IOS" || filter == "NX-OS" {
				var filterCmd string
				if ipv6 {
					filterCmd = "ipv6 traffic-filter"
				} else {
					filterCmd = "ip access-group"
				}
				filterCmd += " " + aclName + " " + suffix
				hardware.subcmd = append(hardware.subcmd, filterCmd)
			} else if filter == "ASA" {
				fmt.Fprintln(fh, "access-group", aclName, suffix, "interface", hardware.name)
			}

			// Empty line after each ACL.
			fmt.Fprintln(fh)
		}
	}
}

func generateAcls(fh *os.File, router *router) {
	model := router.model
	filter := model.filter
	printHeader(fh, router, "ACL")

	if filter == "iptables" {
		printIptablesAcls(fh, router)
	} else {
		printCiscoAcls(fh, router)
	}
}

func genCryptoRules(local, remote []*network) []*groupedRule {
	src := make([]someObj, len(local))
	for i, n := range local {
		src[i] = n
	}
	dst := make([]someObj, len(remote))
	for i, n := range remote {
		dst[i] = n
	}
	return []*groupedRule{newRule(
		src,
		dst,
		[]*proto{prtIP},
	)}
}

func printEzvpn(fh *os.File, router *router) {
	interfaces := router.interfaces
	var tunnelIntf *routerIntf
	for _, intf := range interfaces {
		if intf.tunnel {
			tunnelIntf = intf
		}
	}
	tunNatSet := tunnelIntf.natSet
	wanIntf := tunnelIntf.realIntf
	wanHw := wanIntf.hardware
	wanNatSet := wanHw.natSet
	var lanIntf []*routerIntf
	for _, intf := range interfaces {
		if intf != wanIntf && intf != tunnelIntf {
			lanIntf = append(lanIntf, intf)
		}
	}

	// Ezvpn configuration.
	ezvpnName := "vpn"
	cryptoAclName := "ACL-Split-Tunnel"
	cryptoFilterName := "ACL-crypto-filter"
	virtualIntfNumber := 1
	fmt.Fprintln(fh, "crypto ipsec client ezvpn", ezvpnName)
	fmt.Fprintln(fh, " connect auto")
	fmt.Fprintln(fh, " mode network-extension")

	// Unnumbered, negotiated and short interfaces have been
	// rejected already.
	peer := tunnelIntf.peer
	peerIp := prefixCode(peer.realIntf.address(wanNatSet))
	fmt.Fprintln(fh, " peer", peerIp)

	// Bind split tunnel ACL.
	fmt.Fprintln(fh, " acl", cryptoAclName)

	// Use virtual template defined above.
	fmt.Fprintln(fh, " virtual-interface", virtualIntfNumber)

	// xauth is unused, but syntactically needed.
	fmt.Fprintln(fh, " username test pass test")
	fmt.Fprintln(fh, " xauth userid mode local")

	// Apply ezvpn to WAN and LAN interface.
	for _, lanIntf := range lanIntf {
		lanHw := lanIntf.hardware
		lanHw.subcmd = append(
			lanHw.subcmd,
			"crypto ipsec client ezvpn "+ezvpnName+" inside")
	}
	wanHw.subcmd =
		append(wanHw.subcmd, "crypto ipsec client ezvpn "+ezvpnName)

	// Crypto ACL controls which traffic needs to be encrypted.
	cryptoRules :=
		genCryptoRules(tunnelIntf.peer.peerNetworks, []*network{getNetwork00(router.ipV6)})
	acls := &aclInfo{
		name:        cryptoAclName,
		rules:       cryptoRules,
		natSet:      tunNatSet,
		isCryptoACL: true,
	}
	router.aclList = append(router.aclList, acls)
	printAclPlaceholder(fh, router, cryptoAclName)

	// Crypto filter ACL.
	acls = &aclInfo{
		name:        cryptoFilterName,
		rules:       tunnelIntf.rules,
		intfRules:   tunnelIntf.intfRules,
		addDeny:     true,
		protectSelf: true,
		natSet:      tunNatSet,
	}
	tunnelIntf.rules = nil
	tunnelIntf.intfRules = nil
	router.aclList = append(router.aclList, acls)
	printAclPlaceholder(fh, router, cryptoFilterName)

	// Bind crypto filter ACL to virtual template.
	fmt.Fprintln(fh,
		"interface Virtual-Template"+strconv.Itoa(virtualIntfNumber),
		"type tunnel")
	var prefix string
	if router.ipV6 {
		prefix = " ipv6 traffic-filter"
	} else {
		prefix = " ip access-group"
	}

	fmt.Fprintln(fh, prefix, cryptoFilterName, "in")
}

// Print crypto ACL.
// It controls which traffic needs to be encrypted.
func printCryptoAcl(fh *os.File, intf *routerIntf, suffix string, crypto *crypto) string {
	cryptoAclName := "crypto-" + suffix

	// Generate crypto ACL entries.
	// - either generic from remote network to any or
	// - detailed to all networks which are used in rules.
	isHub := intf.isHub
	var hub *routerIntf
	if isHub {
		hub = intf
	} else {
		hub = intf.peer
	}
	router := intf.router
	var local []*network
	if crypto.detailedCryptoAcl {
		local = getSplitTunnelNets(hub)
	} else {
		local = []*network{getNetwork00(router.ipV6)}
	}
	remote := hub.peerNetworks
	if !isHub {
		local, remote = remote, local
	}
	cryptoRules := genCryptoRules(local, remote)
	aclInfo := &aclInfo{
		name:        cryptoAclName,
		rules:       cryptoRules,
		natSet:      intf.natSet,
		isCryptoACL: true,
	}
	router.aclList = append(router.aclList, aclInfo)
	printAclPlaceholder(fh, router, cryptoAclName)
	return cryptoAclName
}

// Print filter ACL. It controls which traffic is allowed to leave from
// crypto tunnel. This may be needed, if we don't fully trust our peer.
func printCryptoFilterAcl(fh *os.File, intf *routerIntf, suffix string) string {
	router := intf.router

	if router.model.noCryptoFilter {
		return ""
	}
	cryptoFilterName := "crypto-filter-" + suffix
	natSet := intf.natSet
	aclInfo := &aclInfo{
		name:        cryptoFilterName,
		rules:       intf.rules,
		intfRules:   intf.intfRules,
		addDeny:     true,
		protectSelf: true,
		natSet:      natSet,
	}
	intf.rules = nil
	intf.intfRules = nil
	router.aclList = append(router.aclList, aclInfo)
	printAclPlaceholder(fh, router, cryptoFilterName)
	return cryptoFilterName
}

// Called for static and dynamic crypto maps.
func printCryptoMapAttributes(fh *os.File, prefix, cryptoType, cryptoAclName, cryptoFilterName string, isakmp *isakmp, ipsec *ipsec, ipsec2transName map[*ipsec]string) {

	// Bind crypto ACL to crypto map.
	fmt.Fprintln(fh, prefix, "match address", cryptoAclName)

	// Bind crypto filter ACL to crypto map.
	if cryptoFilterName != "" {
		fmt.Fprintln(fh, prefix, "set ip access-group", cryptoFilterName, "in")
	}

	transformName := ipsec2transName[ipsec]
	if cryptoType == "ASA" {
		if isakmp.ikeVersion == 2 {
			fmt.Fprintln(fh, prefix, "set ikev2 ipsec-proposal", transformName)
		} else {
			fmt.Fprintln(fh, prefix, "set ikev1 transform-set", transformName)
		}
	} else {
		fmt.Fprintln(fh, prefix, "set transform-set", transformName)
	}

	if pfsGroup := ipsec.pfsGroup; pfsGroup != "" {
		fmt.Fprintln(fh, prefix, "set pfs group"+pfsGroup)
	}

	if pair := ipsec.lifetime; pair != nil {
		sec, kb := pair[0], pair[1]
		args := ""

		// Don't print default values for backend IOS.
		if sec != -1 && !(sec == 3600 && cryptoType == "IOS") {
			args += "seconds " + strconv.Itoa(sec)
		}
		if kb != -1 && !(kb == 4608000 && cryptoType == "IOS") {
			if args != "" {
				args += " "
			}
			args += "kilobytes " + strconv.Itoa(kb)
		}
		if args != "" {
			fmt.Fprintln(fh, prefix, "set security-association lifetime", args)
		}
	}
}

func printTunnelGroupL2l(fh *os.File, router *router, name string, isakmp *isakmp) {
	authentication := isakmp.authentication
	fmt.Fprintln(fh, "tunnel-group", name, "type ipsec-l2l")
	fmt.Fprintln(fh, "tunnel-group", name, "ipsec-attributes")
	if authentication == "rsasig" {
		trustPoint := isakmp.trustPoint
		if isakmp.ikeVersion == 2 {
			fmt.Fprintln(fh, " ikev2 local-authentication certificate", trustPoint)
			fmt.Fprintln(fh, " ikev2 remote-authentication certificate")
		} else {
			printAsaTrustpoint(fh, router, trustPoint)
		}
	} else {
		// Preshared key is configured manually.
		fmt.Fprintln(fh, " peer-id-validate nocheck")
	}
}

func printCaAndTunnelGroupMap(fh *os.File, id, tgName string) {

	// Activate tunnel-group with tunnel-group-map.
	// Use id as ca-map name.
	fmt.Fprintln(fh, "crypto ca certificate map", id, "10")
	fmt.Fprintln(fh, " subject-name attr ea eq", id)
	fmt.Fprintln(fh, "tunnel-group-map", id, "10", tgName)
}

func printStaticCryptoMap(fh *os.File, router *router, hw *hardware, mapName string, interfaces []*routerIntf, ipsec2transName map[*ipsec]string) {
	model := router.model
	cryptoType := model.crypto

	// Sequence number for parts of crypto map with different peers.
	seqNum := 0

	// Peer IP must obey NAT.
	natSet := hw.natSet

	// Sort crypto maps by peer IP to get deterministic output.
	sorted := make([]*routerIntf, 0, len(interfaces))
	sorted = append(sorted, interfaces...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].peer.realIntf.ip, sorted[j].peer.realIntf.ip) == -1
	})

	// Build crypto map for each tunnel interface.
	for _, intf := range sorted {
		seqNum++
		seq := strconv.Itoa(seqNum)
		peer := intf.peer
		peerIp := prefixCode(peer.realIntf.address(natSet))
		suffix := peerIp

		crypto := intf.crypto
		ipsec := crypto.ipsec
		isakmp := ipsec.isakmp

		cryptoAclName := printCryptoAcl(fh, intf, suffix, crypto)
		cryptoFilterName := printCryptoFilterAcl(fh, intf, suffix)

		// Define crypto map.
		var prefix = ""
		if cryptoType == "IOS" {
			fmt.Fprintln(fh, "crypto map "+mapName+" "+seq+" ipsec-isakmp")
		} else if cryptoType == "ASA" {
			prefix = "crypto map " + mapName + " " + seq
		}

		// Set crypto peer.
		fmt.Fprintln(fh, prefix, "set peer "+peerIp)

		printCryptoMapAttributes(fh, prefix, cryptoType,
			cryptoAclName, cryptoFilterName, isakmp, ipsec,
			ipsec2transName)

		if cryptoType == "ASA" {
			printTunnelGroupL2l(fh, router, peerIp, isakmp)

			// Tunnel group needs to be activated, if certificate is in use.
			if id := peer.id; id != "" {
				printCaAndTunnelGroupMap(fh, id, peerIp)
			}
		}
	}
}

func printDynamicCryptoMap(fh *os.File, router *router, mapName string, interfaces []*routerIntf, ipsec2transName map[*ipsec]string) {
	model := router.model
	cryptoType := model.crypto

	// Sequence number for parts of crypto map with different certificates.
	seqNum := 65536

	// Sort crypto maps by certificate to get deterministic output.
	sorted := make([]*routerIntf, 0, len(interfaces))
	sorted = append(sorted, interfaces...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].peer.id < sorted[j].peer.id
	})

	// Build crypto map for each tunnel interface.
	for _, intf := range sorted {
		seqNum--
		seq := strconv.Itoa(seqNum)
		id := intf.peer.id
		suffix := id

		crypto := intf.crypto
		ipsec := crypto.ipsec
		isakmp := ipsec.isakmp

		cryptoAclName := printCryptoAcl(fh, intf, suffix, crypto)
		cryptoFilterName := printCryptoFilterAcl(fh, intf, suffix)

		// Define dynamic crypto map.
		// Use certificate as name.
		prefix := "crypto dynamic-map " + id + " 10"

		printCryptoMapAttributes(fh, prefix, cryptoType,
			cryptoAclName, cryptoFilterName, isakmp, ipsec,
			ipsec2transName)

		// Bind dynamic crypto map to crypto map.
		prefix = "crypto map " + mapName + " " + seq
		fmt.Fprintln(fh, prefix+" ipsec-isakmp dynamic "+id)

		// Use id as tunnel-group name
		printTunnelGroupL2l(fh, router, id, isakmp)

		// Activate tunnel-group with tunnel-group-map.
		printCaAndTunnelGroupMap(fh, id, id)
	}
}

// If string has prefix and tail isn't empty, add "-" between prefix
// and tail.
func ciscoCryptoWithDash(s, prefix string) string {
	tail := strings.TrimPrefix(s, prefix)
	if tail == "" || tail == s {
		return s
	}
	return prefix + "-" + tail
}

func printCrypto(fh *os.File, router *router) {
	model := router.model
	cryptoType := model.crypto

	// List of ipsec definitions used at current router.
	var ipsecList []*ipsec
	seenIpsec := make(map[*ipsec]bool)
	for _, intf := range router.interfaces {
		if intf.tunnel {
			i := intf.crypto.ipsec
			if seenIpsec[i] {
				continue
			}
			seenIpsec[i] = true
			ipsecList = append(ipsecList, i)
		}
	}

	// Return if no crypto is used at current router.
	if ipsecList == nil {
		return
	}

	// Sort entries by name to get deterministic output.
	sort.Slice(ipsecList, func(i, j int) bool {
		return ipsecList[i].name < ipsecList[j].name
	})

	// List of isakmp definitions used at current router.
	// Sort entries by name to get deterministic output.
	var isakmpList []*isakmp
	seenIsakmp := make(map[*isakmp]bool)
	for _, i := range ipsecList {
		k := i.isakmp
		if seenIsakmp[k] {
			continue
		}
		seenIsakmp[k] = true
		isakmpList = append(isakmpList, k)
	}

	printHeader(fh, router, "Crypto")

	if cryptoType == "EZVPN" {
		printEzvpn(fh, router)
		return
	}

	// Use interface access lists to filter incoming crypto traffic.
	// Group policy and per-user authorization access list can't be used
	// because they are stateless.
	if strings.HasPrefix(cryptoType, "ASA") {
		fmt.Fprintln(fh, "! VPN traffic is filtered at interface ACL")
		fmt.Fprintln(fh, "no sysopt connection permit-vpn")
	}

	if cryptoType == "ASA_VPN" {
		printAsavpn(fh, router)
		return
	}

	// Crypto config for ASA as EZVPN client is configured manually once.
	// No config is generated by netspoc.
	if cryptoType == "ASA_EZVPN" {
		return
	}

	isakmpCount := 0
	for _, isakmp := range isakmpList {

		// Only print isakmp for IOS. Approve for ASA will ignore it anyway.
		if cryptoType != "IOS" {
			continue
		}
		isakmpCount++
		fmt.Fprintln(fh, "crypto isakmp policy "+strconv.Itoa(isakmpCount))

		// Don't print default value 'rsa-sig'.
		if isakmp.authentication == "preshare" {
			fmt.Fprintln(fh, " authentication pre-share")
		}

		encryption := isakmp.encryption
		rest := strings.TrimPrefix(encryption, "aes")
		if len(rest) != len(encryption) && len(rest) > 0 {
			encryption = "aes " + rest
		}
		fmt.Fprintln(fh, " encryption "+encryption)
		fmt.Fprintln(fh, " hash "+isakmp.hash)
		fmt.Fprintln(fh, " group "+isakmp.group)

		lifetime := isakmp.lifetime

		// Don't print default value for backend IOS.
		if lifetime != 86400 {
			fmt.Fprintln(fh, " lifetime "+strconv.Itoa(lifetime))
		}
	}

	// Handle IPSEC definition.
	transformCount := 0
	ipsec2transName := make(map[*ipsec]string)
	for _, ipsec := range ipsecList {
		transformCount++
		transformName := "Trans" + strconv.Itoa(transformCount)
		ipsec2transName[ipsec] = transformName
		isakmp := ipsec.isakmp

		// IKEv2 syntax for ASA.
		if cryptoType == "ASA" && isakmp.ikeVersion == 2 {
			fmt.Fprintln(fh, "crypto ipsec ikev2 ipsec-proposal", transformName)
			if ah := ipsec.ah; ah != "" {
				fmt.Fprintln(fh, " protocol ah", ah)
			}
			var espEncr string
			if esp := ipsec.espEncryption; esp == "" {
				espEncr = "null"
			} else if esp == "aes192" {
				espEncr = "aes-192"
			} else if esp == "aes256" {
				espEncr = "aes-256"
			} else {
				espEncr = esp
			}
			fmt.Fprintln(fh, " protocol esp encryption "+espEncr)
			if espAh := ipsec.espAuthentication; espAh != "" {
				if espAh == "sha" {
					espAh = "sha-1"
				} else {
					espAh = ciscoCryptoWithDash(espAh, "sha")
				}
				fmt.Fprintln(fh, " protocol esp integrity "+espAh)
			}
		} else {
			// IKEv1 syntax of ASA is identical to IOS.
			transform := ""
			if ah := ipsec.ah; ah != "" {
				transform += "ah-" + ah + "-hmac "
			}
			transform += "esp-"
			if esp := ipsec.espEncryption; esp == "" {
				transform += "null"
			} else {
				esp = ciscoCryptoWithDash(esp, "aes")
				if cryptoType == "IOS" {
					esp = strings.Replace(esp, "-", " ", 1)
				}
				transform += esp
			}
			if espAh := ipsec.espAuthentication; espAh != "" {
				transform += " esp-" + espAh + "-hmac"
			}
			prefix := "crypto ipsec"
			if cryptoType == "ASA" {
				prefix += " ikev1"
			}
			fmt.Fprintln(fh, prefix, "transform-set", transformName, transform)
		}
	}

	for _, hardware := range router.hardware {

		// Collect tunnel interfaces attached to each hardware interface.
		// Differentiate on peers having static || dynamic IP address.
		var static, dynamic []*routerIntf
		var haveCryptoMap = false
		for _, intf := range hardware.interfaces {
			if !intf.tunnel {
				continue
			}
			real := intf.peer.realIntf
			if real.negotiated || real.short || real.unnumbered {
				dynamic = append(dynamic, intf)
			} else {
				static = append(static, intf)
			}
			haveCryptoMap = true
		}

		hwName := hardware.name

		// Name of crypto map.
		mapName := "crypto-" + hwName

		if static != nil {
			printStaticCryptoMap(fh, router, hardware, mapName, static,
				ipsec2transName)
		}
		if dynamic != nil {
			printDynamicCryptoMap(fh, router, mapName, dynamic,
				ipsec2transName)
		}

		// Bind crypto map to interface.
		if !haveCryptoMap {
			continue
		}
		if cryptoType == "IOS" {
			hardware.subcmd = append(hardware.subcmd, "crypto map "+mapName)
		} else if cryptoType == "ASA" {
			fmt.Fprintln(fh, "crypto map", mapName, "interface", hwName)
		}
	}
}

func printRouterIntf(fh *os.File, router *router) {
	model := router.model
	if !model.printRouterIntf {
		return
	}
	class := model.class
	stateful := !model.stateless
	ipv6 := router.ipV6
	for _, hardware := range router.hardware {
		name := hardware.name
		var subcmd []string
		secondary := false

		for _, intf := range hardware.interfaces {
			var addrCmd string
			if intf.redundant {
				continue
			}
			if intf.tunnel {
				continue
			}
			if intf.unnumbered {
				addrCmd = "ip unnumbered X"
			} else if intf.negotiated {
				addrCmd = "ip address negotiated"
			} else if model.usePrefix || ipv6 {
				addr := intf.ip.String()
				prefix, _ := intf.network.mask.Size()
				if ipv6 {
					addrCmd = "ipv6"
				} else {
					addrCmd = "ip"
				}
				addrCmd += " address " + addr + "/" + strconv.Itoa(prefix)
				if secondary {
					addrCmd += " secondary"
				}
			} else {
				addr := intf.ip.String()
				mask := net.IP(intf.network.mask).String()
				addrCmd = "ip address " + addr + " " + mask
				if secondary {
					addrCmd += " secondary"
				}
			}
			subcmd = append(subcmd, addrCmd)
			if !ipv6 {
				secondary = true
			}
		}
		if vrf := router.vrf; vrf != "" {
			if class == "NX-OS" {
				subcmd = append(subcmd, "vrf member "+vrf)
			} else {
				subcmd = append(subcmd, "ip vrf forwarding "+vrf)
			}
		}

		// Add "ip inspect" as marker, that stateful filtering is expected.
		// The command is known to be incomplete, "X" is only used as
		// placeholder.
		if class == "IOS" && stateful && !hardware.loopback {
			subcmd = append(subcmd, "ip inspect X in")
		}

		subcmd = append(subcmd, hardware.subcmd...)

		fmt.Fprintln(fh, "interface "+name)
		for _, cmd := range subcmd {
			fmt.Fprintln(fh, " "+cmd)
		}
	}
	fmt.Fprintln(fh)
}

func printPrt(prt *proto) string {
	// Use cached result.
	if p := prt.printed; p != "" {
		return p
	}
	proto := prt.proto
	result := proto

	switch proto {
	case "tcp", "udp":
		for _, port := range prt.ports {
			result += " " + strconv.Itoa(port)
		}
		if prt.established {
			result += " established"
		}
	case "icmp", "icmpv6":
		if t := prt.icmpType; t != -1 {
			result += " " + strconv.Itoa(t)
			if c := prt.icmpCode; c != -1 {
				result += " " + strconv.Itoa(c)
			}
		}
	}
	// Cache result.
	prt.printed = result
	return result
}

func isHostMask(m net.IPMask) bool {
	prefix, size := m.Size()
	return prefix == size
}

func prefixCode(n *net.IPNet) string {
	prefix, size := n.Mask.Size()
	if prefix == size {
		return n.IP.String()
	}
	return n.IP.String() + "/" + strconv.Itoa(prefix)

}

func fullPrefixCode(n *net.IPNet) string {
	prefix, _ := n.Mask.Size()
	return n.IP.String() + "/" + strconv.Itoa(prefix)
}

// Collect interfaces that need protection by additional deny rules.
// Add list to each ACL separately, because IP may be changed by NAT.
func getNeedProtect(r *router) []*routerIntf {

	// ASA protects IOS router behind crosslink interface.
	// Routers connected by crosslink networks are handled like one
	// large router. Protect the collected interfaces of the whole
	// cluster at each entry.
	list := r.crosslinkIntfs
	if list != nil {
		return list
	}
	if !r.needProtect {
		return nil
	}
	for _, i := range r.interfaces {
		if len(i.ip) == 0 {
			continue
		}
		list = append(list, i)
	}
	return list
}

type natCache struct {
	nat   natSet
	cache map[someObj]string
}

var nat2Cache = make(map[natSet]*natCache)

func getAddrCache(n natSet) *natCache {
	if nc, ok := nat2Cache[n]; ok {
		return nc
	}
	nc := natCache{
		nat:   n,
		cache: make(map[someObj]string),
	}
	nat2Cache[n] = &nc
	return &nc
}

func getCachedAddr(o someObj, nc *natCache) string {
	if a, ok := nc.cache[o]; ok {
		return a
	}
	a := fullPrefixCode(o.address(nc.nat))
	nc.cache[o] = a
	return a
}

func getCachedAddrList(l []someObj, nc *natCache) []string {
	result := make([]string, len(l))
	for i, o := range l {
		result[i] = getCachedAddr(o, nc)
	}
	return result
}

func printAcls(fh *os.File, vrfMembers []*router) {
	var aclList []*jcode.ACLInfo
	for _, router := range vrfMembers {
		managed := router.managed
		secondaryFilter := strings.HasSuffix(managed, "secondary")
		standardFilter := managed == "standard"
		model := router.model
		doAuth := model.doAuth
		activeLog := router.log
		needProtect := getNeedProtect(router)

		process := func(acl *aclInfo) *jcode.ACLInfo {
			jACL := new(jcode.ACLInfo)
			jACL.Name = acl.name
			if acl.addPermit {
				jACL.AddPermit = 1
			}
			if acl.addDeny {
				jACL.AddDeny = 1
			}
			if acl.filterAnySrc {
				jACL.FilterAnySrc = 1
			}
			if acl.isStdACL {
				jACL.IsStdACL = 1
			}
			if acl.isCryptoACL {
				jACL.IsCryptoACL = 1
			}
			// Collect networks used in secondary optimization and
			// cache for address calculation.
			optAddr := make(map[*network]*natCache)
			// Collect objects forbidden in secondary optimization and
			// cache for address calculation.
			noOptAddrs := make(map[someObj]*natCache)
			natSet := acl.natSet
			addrCache := getAddrCache(natSet)
			dstNatSet := acl.dstNatSet
			if dstNatSet == nil {
				dstNatSet = natSet
			}
			dstAddrCache := getAddrCache(dstNatSet)

			// Set attribute NeedProtect in jACL.
			// Value is list of IP addresses of to be protected interfaces.
			//
			// This possibly generates invalid IP address 0.0.0.0/32 for
			// hidden interface, if some LAN interface is hidden in NAT
			// set of crypto interface.
			// But that doesn't matter, because only IOS routers
			// - need protection of interfaces and
			// - are also used as crypto device.
			// But IOS routers have separate crypto-filter-ACL
			// and therefore these invalid addresses are never used.
			if needProtect != nil && acl.protectSelf {
				// For removing duplicate addresses from redundancy interfaces.
				seen := make(map[string]bool)
				for _, intf := range needProtect {
					a := getCachedAddr(intf, addrCache)
					if !seen[a] {
						seen[a] = true
						jACL.NeedProtect = append(jACL.NeedProtect, a)
					}
				}
			}

			optRules := func(rules []*groupedRule) []*jcode.Rule {
				jRules := make([]*jcode.Rule, len(rules))
				for i, rule := range rules {
					newRule := new(jcode.Rule)
					jRules[i] = newRule
					if rule.deny {
						newRule.Deny = 1
					}

					// Add code for logging.
					// This code is machine specific.
					if activeLog != nil && rule.log != "" {
						logCode := ""
						for _, tag := range strings.Split(rule.log, ",") {
							if modifier, ok := activeLog[tag]; ok {
								if modifier != "" {
									normalized := model.logModifiers[modifier]
									if normalized == ":subst" {
										logCode = modifier
									} else {
										logCode = "log " + normalized
									}
								} else {
									logCode = "log"
								}
								// Take first of possibly several matching tags.
								break
							}
						}
						newRule.Log = logCode
					}

					if secondaryFilter && rule.someNonSecondary ||
						standardFilter && rule.somePrimary {
						for _, isSrc := range []bool{true, false} {
							var objList []someObj
							var useCache *natCache
							if isSrc {
								objList = rule.src
								useCache = addrCache
							} else {
								objList = rule.dst
								useCache = dstAddrCache
							}
							for _, obj := range objList {

								// Prepare secondary optimization.

								// Restrict secondary optimization at
								// authenticating router to prevent
								// unauthorized access with spoofed IP
								// address.
								// It would be sufficient to disable
								// optimization only for incoming
								// traffic. But for a VPN router with
								// only a single interface, incoming
								// and outgoing traffic is mixed at
								// this interface.
								// At this stage, network with
								// attribute hasIdHosts has already been
								// converted to single ID hosts.
								if doAuth {
									if o, ok := obj.(*subnet); ok {
										if o.id != "" {
											continue
										}
									}
								}

								var subst *network
								switch o := obj.(type) {
								case *subnet, *routerIntf:
									net := obj.getNetwork()
									if net.hasOtherSubnet {
										continue
									}
									if noOpt := router.noSecondaryOpt; noOpt != nil {
										if noOpt[net] {
											noOptAddrs[obj] = useCache
											continue
										}
									}
									subst = net
									if max := subst.maxSecondaryNet; max != nil {
										subst = max
									}

									// Ignore loopback network.
									if isHostMask(subst.mask) {
										continue
									}

									// Network or aggregate.
								case *network:

									// Don't modify protocol of rule
									// with hasOtherSubnet, because
									// this could introduce new missing
									// supernet rules.
									if o.hasOtherSubnet {
										noOptAddrs[obj] = useCache
										continue
									}
									max := o.maxSecondaryNet
									if max == nil {
										continue
									}
									subst = max
								}
								optAddr[subst] = useCache
							}
						}
						newRule.OptSecondary = 1
					}

					newRule.Src = getCachedAddrList(rule.src, addrCache)
					newRule.Dst = getCachedAddrList(rule.dst, dstAddrCache)
					prtList := make([]string, len(rule.prt))
					for i, p := range rule.prt {
						prtList[i] = printPrt(p)
					}
					newRule.Prt = prtList
					if srcRange := rule.srcRange; srcRange != nil {
						newRule.SrcRange = printPrt(srcRange)
					}
				}
				return jRules
			}
			jACL.IntfRules = optRules(acl.intfRules)
			jACL.Rules = optRules(acl.rules)

			// Secondary optimization is done in pass 2.
			// It converts protocol to IP and
			// src/dst address to network address.
			// It is controlled by this three attributes:
			// - OptSecondary enables secondary optimization
			// - if enabled, then networks in OptNetworks are used
			//   for optimization.
			// - if src/dst matches NoOptAddrs, then
			//   optimization is disabled for this single rule.
			//   This is needed because OptSecondary is set for
			//   grouped rules and we need to control optimization
			//   for sinlge rules.
			addrList := make([]string, 0, len(optAddr))
			for n, cache := range optAddr {
				a := getCachedAddr(n, cache)
				addrList = append(addrList, a)
			}
			sort.Strings(addrList)
			jACL.OptNetworks = addrList

			addrList = make([]string, 0, len(noOptAddrs))
			for o, cache := range noOptAddrs {
				a := getCachedAddr(o, cache)
				addrList = append(addrList, a)
			}
			sort.Strings(addrList)
			jACL.NoOptAddrs = addrList
			return jACL
		}

		aref := router.aclList
		router.aclList = nil
		for _, acl := range aref {
			result := process(acl)
			for _, acl := range acl.subAclList {
				subResult := process(acl)
				result.Rules = append(result.Rules, subResult.Rules...)
				result.IntfRules = append(result.IntfRules, subResult.IntfRules...)
				result.OptNetworks =
					append(result.OptNetworks, subResult.OptNetworks...)
				result.NoOptAddrs =
					append(result.NoOptAddrs, subResult.NoOptAddrs...)
			}
			aclList = append(aclList, result)
		}
	}

	router := vrfMembers[0]
	model := router.model
	result := &jcode.RouterData{Model: model.class, ACLs: aclList}

	if filterOnly := router.filterOnly; filterOnly != nil {
		list := make([]string, len(filterOnly))
		for i, f := range filterOnly {
			list[i] = prefixCode(f)
		}
		result.FilterOnly = list
	}
	if model.canObjectgroup && !router.noGroupCode {
		result.DoObjectgroup = 1
	}
	if router.logDeny {
		result.LogDeny = "log"
	}

	enc := json.NewEncoder(fh)
	//	enc.SetIndent("", " ")
	err := enc.Encode(result)
	if err != nil {
		panic(err)
	}
}

// Make output directory available.
// Move old content into subdirectory ".prev/" for reuse during pass 2.
func checkOutputDir(dir string) {
	if !fileop.IsDir(dir) {
		err := os.Mkdir(dir, 0777)
		if err != nil {
			abort.Msg("Can't %v", err)
		}
	} else {
		os.Remove(dir + "/.devlist")

		prev := dir + "/.prev"
		if !fileop.IsDir(prev) {
			oldFiles := fileop.Readdirnames(dir)
			if count := len(oldFiles); count > 0 {
				if fileop.IsDir(dir + "/ipv6") {
					v6files := fileop.Readdirnames(dir + "/ipv6")
					count += len(v6files) - 1
				}
				info("Saving %d old files of '%s' to subdirectory '.prev'",
					count, dir)

				// Try to remove file or symlink with same name.
				os.Remove(prev)
				err := os.Mkdir(prev, 0777)
				if err != nil {
					abort.Msg("Can't %v", err)
				}
				for i, name := range oldFiles {
					oldFiles[i] = dir + "/" + name
				}
				cmd := exec.Command("mv", append(oldFiles, prev)...)
				if err = cmd.Run(); err != nil {
					abort.Msg("Can't mv old files to prev: %v", err)
				}
			}
		}
	}
}

// Print generated code for each managed router.
func printCode(dir string) {
	diag.Progress("Printing intermediate code")

	var toPass2 *os.File
	if conf.Conf.Pipe {
		toPass2 = os.Stdout
	} else {
		devlist := dir + "/.devlist"
		var err error
		toPass2, err = os.Create(devlist)
		if err != nil {
			abort.Msg("Can't %v", err)
		}
	}

	checkedV6Dir := false
	seen := make(map[*router]bool)
	printRouter := func(routers []*router) {
		for _, r := range routers {
			if seen[r] {
				continue
			}

			// Ignore split part of crypto router.
			if r.origRouter != nil {
				continue
			}

			deviceName := r.deviceName
			path := deviceName
			if r.ipV6 {
				path = "ipv6/" + path
				v6dir := dir + "/ipv6"
				if !checkedV6Dir && !fileop.IsDir(v6dir) {
					checkedV6Dir = true
					err := os.Mkdir(v6dir, 0777)
					if err != nil {
						abort.Msg("Can't %v", err)
					}
				}
			}

			// File for router config without ACLs.
			configFile := dir + "/" + path + ".config"
			fd, err := os.Create(configFile)
			if err != nil {
				abort.Msg("Can't %v", err)
			}
			model := r.model
			commentChar := model.commentChar

			// Restore interfaces of split router.
			if orig := r.origIntfs; orig != nil {
				r.interfaces = orig
				r.hardware = r.origHardware
			}

			// Collect VRF members.
			vrfMembers := r.vrfMembers
			if vrfMembers == nil {
				vrfMembers = []*router{r}
			}

			// Print version header.
			fmt.Fprintln(fd, commentChar, "Generated by", program+", version", version)
			fmt.Fprintln(fd)

			header := func(key, val string) {
				fmt.Fprintf(fd, "%s [ %s %s ]\n", commentChar, key, val)
			}
			header("BEGIN", deviceName)
			header("Model =", model.class)
			ips := make([]string, 0, len(vrfMembers))
			for _, r := range vrfMembers {
				if r.adminIP != nil {
					ips = append(ips, r.adminIP...)
				}
			}
			if len(ips) != 0 {
				header("IP =", strings.Join(ips, ","))
			}

			for _, vrouter := range vrfMembers {
				seen[vrouter] = true
				printRoutes(fd, vrouter)
				if vrouter.managed == "" {
					continue
				}
				printCrypto(fd, vrouter)
				printAclPrefix(fd, vrouter)
				generateAcls(fd, vrouter)
				printAclSuffix(fd, vrouter)
				printRouterIntf(fd, vrouter)
			}

			header("END", deviceName)
			fmt.Fprintln(fd)
			if err := fd.Close(); err != nil {
				abort.Msg("Can't %v", err)
			}

			// Print ACLs in machine independent format into separate file.
			// Collect ACLs from VRF parts.
			aclFile := dir + "/" + path + ".rules"
			aclFd, err := os.Create(aclFile)
			if err != nil {
				abort.Msg("Can't %v", err)
			}
			printAcls(aclFd, vrfMembers)
			if err := aclFd.Close(); err != nil {
				abort.Msg("Can't %v", err)
			}

			// Send device name to pass 2, showing that processing for this
			// device can be started.
			fmt.Fprintln(toPass2, path)
		}
	}
	printRouter(managedRouters)
	printRouter(routingOnlyRouters)
}

func PrintCode(dir string) {
	checkOutputDir(dir)
	printCode(dir)
}
