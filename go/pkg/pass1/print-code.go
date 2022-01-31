package pass1

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/jcode"
	"github.com/hknutzen/Netspoc/go/pkg/pass2"
	"inet.af/netaddr"
	"net"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

func getIntf(r *router) []*routerIntf {
	if orig := r.origRouter; orig != nil {
		return orig.origIntfs
	} else if l := r.origIntfs; l != nil {
		return l
	} else {
		return r.interfaces
	}
}

func (z *zone) nonSecondaryIntfs() intfList {
	var result intfList
	for _, intf := range z.interfaces {
		if intf.mainIntf == nil {
			result.push(intf)
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

func printHeader(fh *os.File, r *router, what string) {
	commentChar := r.model.commentChar
	if r.vrfMembers != nil {
		what += " for " + r.name
	}
	fmt.Fprintln(fh, commentChar, "[", what, "]")
}

func iosRouteCode(n netaddr.IPPrefix) string {
	return n.IP().String() + " " + net.IP(n.IPNet().Mask).String()
}

func printRoutes(fh *os.File, r *router) {
	ipv6 := r.ipV6
	model := r.model
	vrf := r.vrf
	doAutoDefaultRoute := conf.Conf.AutoDefaultRoute
	zeroNet := getNetwork00(ipv6).ipp
	asaCrypto := model.crypto == "ASA"
	prefix2ip2net := make(map[uint8]map[netaddr.IP]*network)
	type hopInfo struct {
		intf *routerIntf
		hop  *routerIntf
	}
	net2hopInfo := make(map[*network]hopInfo)
	hop2intf := make(map[*routerIntf]*routerIntf)

	for _, intf := range r.interfaces {

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

		for natNet, hopList := range intf.routes {
			if natNet.hidden {
				continue
			}

			prefixlen := natNet.ipp.Bits()
			if prefixlen == 0 {
				doAutoDefaultRoute = false
			}

			// Implicitly overwrite duplicate networks.
			m := prefix2ip2net[prefixlen]
			if m == nil {
				m = make(map[netaddr.IP]*network)
				prefix2ip2net[prefixlen] = m
			}
			m[natNet.ipp.IP()] = natNet

			// This is unambiguous, because only a single static
			// route is allowed for each network.
			hop := hopList[0]
			net2hopInfo[natNet] = hopInfo{intf, hop}
			hop2intf[hop] = intf
		}
	}
	if len(net2hopInfo) == 0 {
		return
	}

	// Combine adjacent networks, if both use same hop and
	// if combined network doesn't already exist.
	// Prepare invPrefixAref.
	var bitstrLen uint8
	if ipv6 {
		bitstrLen = 128
	} else {
		bitstrLen = 32
	}
	invPrefixAref := make([]map[netaddr.IP]*network, bitstrLen+1)
	keys := make([]uint8, 0, len(prefix2ip2net))
	for k, _ := range prefix2ip2net {
		keys = append(keys, k)
	}
	for _, prefix := range keys {
		invPrefix := bitstrLen - prefix
		ip2net := prefix2ip2net[prefix]
		keys := make([]netaddr.IP, 0, len(ip2net))
		for k, _ := range ip2net {
			keys = append(keys, k)
		}
		for _, ip := range keys {
			net := ip2net[ip]

			// Don't combine peers of ASA with site-to-site VPN.
			if asaCrypto {
				hopInfo := net2hopInfo[net]
				if hopInfo.intf.hub != nil {
					continue
				}
			}
			m := invPrefixAref[invPrefix]
			if m == nil {
				m = make(map[netaddr.IP]*network)
				invPrefixAref[invPrefix] = m
			}
			m[ip] = net
		}
	}

	// Go from small to large networks. So we combine newly added
	// networks as well.
	for invPrefix, ip2net := range invPrefixAref {

		// Must not optimize network 0/0; it has no supernet.
		if uint8(invPrefix) >= bitstrLen {
			break
		}
		if ip2net == nil {
			continue
		}
		partPrefix := bitstrLen - uint8(invPrefix)
		combinedInvPrefix := uint8(invPrefix + 1)
		combinedPrefix := bitstrLen - combinedInvPrefix

		for ip, left := range ip2net {

			// Only analyze left part of two adjacent networks.
			part, _ := ip.Prefix(partPrefix)
			comb, _ := ip.Prefix(combinedPrefix)
			if part.IP() != comb.IP() {
				continue
			}

			// Calculate IP of right part.
			rg := left.ipp.Range()
			nextIP := rg.To().Next()

			// Find corresponding right part.
			right := ip2net[nextIP]
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
				ip2net = make(map[netaddr.IP]*network)
				invPrefixAref[combinedInvPrefix] = ip2net
			} else if ip2net[ip] != nil {
				// Combined network already exists.
				continue
			}

			// Add combined route.
			combined := &network{ipp: comb}
			ip2net[ip] = combined

			ip2net = prefix2ip2net[combinedPrefix]
			if ip2net == nil {
				ip2net = make(map[netaddr.IP]*network)
				prefix2ip2net[combinedPrefix] = ip2net
			}
			ip2net[ip] = combined
			net2hopInfo[combined] = hopLeft

			// Left and right part are no longer used.
			delete(prefix2ip2net[partPrefix], ip)
			delete(prefix2ip2net[partPrefix], nextIP)
		}
	}

	// Find and remove duplicate networks.
	// Go from small to larger networks.
	prefixes := make([]uint8, 0, len(prefix2ip2net))
	for k, _ := range prefix2ip2net {
		prefixes = append(prefixes, k)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i] > prefixes[j]
	})
	type netInfo struct {
		netaddr.IPPrefix
		noOpt bool
	}
	hop2netInfos := make(map[*routerIntf][]netInfo)
	for len(prefixes) != 0 {
		prefix := prefixes[0]
		prefixes = prefixes[1:]
		ip2net := prefix2ip2net[prefix]
		ips := make([]netaddr.IP, 0, len(ip2net))
		for k, _ := range ip2net {
			ips = append(ips, k)
		}
		sort.Slice(ips, func(i, j int) bool {
			return ips[i].Less(ips[j])
		})
	NETWORK:
		for _, ip := range ips {
			small := ip2net[ip]
			hopInfo := net2hopInfo[small]
			noOpt := false

			// ASA with site-to-site VPN needs individual routes for each peer.
			if !(asaCrypto && hopInfo.intf.hub != nil) {

				// Compare current mask with masks of larger networks.
				for _, p := range prefixes {
					net, _ := ip.Prefix(p)
					big := prefix2ip2net[p][net.IP()]
					if big == nil {
						continue
					}

					// small is subnet of big.
					// If both use the same hop, then small is redundant.
					if net2hopInfo[big] == hopInfo {

						// debug("Removed: %s -> %s", small, hop)
						continue NETWORK
					}

					// Otherwise small isn't redundant, even if a bigger network
					// with same hop exists.
					// It must not be removed by default route later.
					noOpt = true

					// debug("No opt: %s -> %s", small, hop)
					break
				}
			}
			info := netInfo{
				netaddr.IPPrefixFrom(ip, prefix),
				noOpt,
			}
			hop2netInfos[hopInfo.hop] = append(hop2netInfos[hopInfo.hop], info)
		}
	}

	// Get sorted list of hops for deterministic output.
	hops := make(intfList, 0, len(hop2netInfos))
	for k, _ := range hop2netInfos {
		hops.push(k)
	}
	sort.Slice(hops, func(i, j int) bool {
		return hops[i].name < hops[j].name
	})

	if doAutoDefaultRoute {

		// Find hop with largest number of routing entries.
		var maxHop *routerIntf

		// Substitute routes to one hop with a default route,
		// if there are at least two entries.
		max := 1
		for _, hop := range hops {
			count := 0
			for _, info := range hop2netInfos[hop] {
				if !info.noOpt {
					count++
				}
			}
			if count > max {
				maxHop = hop
				max = count
			}
		}
		if maxHop != nil {

			// Use default route for this direction.
			nets := []netInfo{{zeroNet, false}}
			// But still generate routes for small networks
			// with supernet behind other hop.
			for _, net := range hop2netInfos[maxHop] {
				if net.noOpt {
					nets = append(nets, net)
				}
			}
			hop2netInfos[maxHop] = nets
		}
	}

	printHeader(fh, r, "Routing")
	iosVrf := ""
	if vrf != "" && model.routing == "IOS" {
		iosVrf = "vrf " + vrf + " "
	}
	nxosPrefix := ""

	for _, hop := range hops {
		intf := hop2intf[hop]

		// For unnumbered and negotiated interfaces use interface name
		// as next hop.
		var hopAddr string
		if intf.ipType != hasIP {
			hopAddr = intf.hardware.name
		} else {
			hopAddr = hop.ip.String()
		}

		for _, netinfo := range hop2netInfos[hop] {
			switch model.routing {
			case "IOS":
				var adr string
				ip := "ip"
				if ipv6 {
					adr = fullPrefixCode(netinfo.IPPrefix)
					ip += "v6"
				} else {
					adr = iosRouteCode(netinfo.IPPrefix)
				}
				fmt.Fprintln(fh, ip, "route", iosVrf+adr, hopAddr)
			case "NX-OS":
				if vrf != "" && nxosPrefix == "" {

					// Print "vrf context" only once
					// and indent "ip route" commands.
					fmt.Fprintln(fh, "vrf context", vrf)
					nxosPrefix = " "
				}
				adr := fullPrefixCode(netinfo.IPPrefix)
				ip := "ip"
				if ipv6 {
					ip += "v6"
				}
				fmt.Fprintln(fh, nxosPrefix+ip, "route", adr, hopAddr)
			case "ASA":
				var adr string
				ip := ""
				if ipv6 {
					adr = fullPrefixCode(netinfo.IPPrefix)
					ip = "ipv6 "
				} else {
					adr = iosRouteCode(netinfo.IPPrefix)
				}
				fmt.Fprintln(fh, ip+"route", intf.hardware.name, adr, hopAddr)
			case "iproute":
				adr := prefixCode(netinfo.IPPrefix)
				fmt.Fprintln(fh, "ip route add", adr, "via", hopAddr)
			}
		}
	}
}

func printAclPlaceholder(fh *os.File, r *router, aclName string) {

	// Add comment at start of ACL to easier find first ACL line in tests.
	model := r.model
	filter := model.filter
	if filter == "ASA" {
		commentChar := model.commentChar
		fmt.Fprintln(fh, commentChar, aclName)
	}

	fmt.Fprintln(fh, "#insert", aclName)
}

// Analyzes dst/src list of all rules collected at this interface.
// Result:
// List of all networks which are reachable when entering this interface.
func getSplitTunnelNets(intf *routerIntf) netList {
	var result netList
	seen := make(map[*network]bool)
	checkRules := func(rules []*groupedRule, takeDst bool) {
		for _, ru := range rules {
			if ru.deny {
				continue
			}
			objList := ru.dst
			if takeDst {
				objList = ru.src
			}
			for _, obj := range objList {
				n := obj.getNetwork()

				// Don't add 'any' (resulting from global:permit)
				// to split_tunnel networks.
				if n.ipp.Bits() == 0 {
					continue
				}
				if seen[n] {
					continue
				}
				result.push(n)
				seen[n] = true
			}
		}
	}
	checkRules(intf.rules, false)
	checkRules(intf.intfRules, false)
	checkRules(intf.outRules, true)

	// Sort for better readability of ACL.
	sort.Slice(result, func(i, j int) bool {
		return result[i].ipp.IP().Less(result[j].ipp.IP())
	})
	return result
}

// Create aggregate objects from IP/prefix list.
func getMergeTunnelAggregates(r *router) netList {
	var l netList
	for _, ipp := range r.mergeTunnelSpecified {
		agg := &network{
			withStdAddr: withStdAddr{stdAddr: ipp.String()},
			ipp:         ipp,
		}
		l.push(agg)
	}
	return l
}

// Remove networks that are subnet of aggregates in 'merge'.
// Add aggregates to result.
func mergeSplitTunnelNets(l, merge netList, m natMap) netList {
	j := 0
NET:
	for _, n := range l {
		ipp := n.address(m)
		for _, agg := range merge {
			ipp2 := agg.ipp
			if ipp.Bits() >= ipp2.Bits() && ipp2.Contains(ipp.IP()) {
				continue NET
			}
		}
		l[j] = n
		j++
	}
	return append(l[:j], merge...)
}

func printAsaTrustpoint(fh *os.File, r *router, trustpoint string) {
	model := r.model
	fmt.Fprintln(fh, " ikev1 trust-point", trustpoint)

	// This command is not known, if ASA runs as virtual context.
	if !model.cryptoInContext {
		fmt.Fprintln(fh, " ikev1 user-authentication none")
	}
}

func printTunnelGroupRa(
	fh *os.File, id, idName string, attributes map[string]string, r *router,
	groupPolicyName string, certGroupMap map[string]string) string {

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
		trustpoint2 = r.trustPoint
	} else {
		delete(attributes, "trust-point")
	}
	var tunnelGenAtt stringList
	authentication := "certificate"
	if groupPolicyName != "" {
		tunnelGenAtt.push("default-group-policy " + groupPolicyName)
	} else {
		authentication = "aaa " + authentication
	}

	// Select attributes for tunnel-group general-attributes.
	keys := make(stringList, 0, len(attributes))
	for k, _ := range attributes {
		if spec := asaVpnAttributes[k]; spec == tgGeneral {
			keys.push(k)
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
		tunnelGenAtt.push(out)
	}

	tunnelGroupName := "VPN-tunnel-" + idName
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "type remote-access")
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "general-attributes")

	for _, line := range tunnelGenAtt {
		fmt.Fprintln(fh, " "+line)
	}
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "ipsec-attributes")
	printAsaTrustpoint(fh, r, trustpoint2)

	// For anyconnect clients.
	fmt.Fprintln(fh, "tunnel-group", tunnelGroupName, "webvpn-attributes")
	fmt.Fprintln(fh, " authentication", authentication)
	certGroupMap[mapName] = tunnelGroupName

	fmt.Fprintln(fh, "tunnel-group-map", mapName, "10", tunnelGroupName)
	return tunnelGroupName
}

func combineAttr(l ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, attr := range l {
		for k, v := range attr {
			result[k] = v
		}
	}
	return result
}

const (
	noAttr = iota
	ownAttr
	groupPolicy
	tgGeneral
)

var asaVpnAttributes = map[string]int{

	// Our own attributes
	"check-subject-name":       ownAttr,
	"check-extended-key-usage": ownAttr,
	"trust-point":              ownAttr,

	// group-policy attributes
	"anyconnect-custom_perapp": groupPolicy,
	"banner":                   groupPolicy,
	"dns-server":               groupPolicy,
	"default-domain":           groupPolicy,
	"group-lock":               groupPolicy,
	"split-dns":                groupPolicy,
	"wins-server":              groupPolicy,
	"vpn-access-hours":         groupPolicy,
	"vpn-idle-timeout":         groupPolicy,
	"vpn-session-timeout":      groupPolicy,
	"vpn-simultaneous-logins":  groupPolicy,
	"vlan":                     groupPolicy,
	"split-tunnel-policy":      groupPolicy,

	// tunnel-group general-attributes
	"authentication-server-group":                 tgGeneral,
	"authorization-server-group":                  tgGeneral,
	"authorization-required":                      tgGeneral,
	"username-from-certificate":                   tgGeneral,
	"password-management_password-expire-in-days": tgGeneral,
}

var asaVpnAttrNeedValue = map[string]bool{
	"anyconnect-custom_perapp":  true,
	"banner":                    true,
	"dns-server":                true,
	"default-domain":            true,
	"group-lock":                true,
	"split-dns":                 true,
	"wins-server":               true,
	"address-pools":             true,
	"split-tunnel-network-list": true,
	"vpn-filter":                true,
}

func (c *spoc) printAsavpn(fh *os.File, r *router) {
	ipv6 := r.ipV6

	globalGroupName := "global"
	fmt.Fprintln(fh, "group-policy", globalGroupName, "internal")
	fmt.Fprintln(fh, "group-policy", globalGroupName, "attributes")
	fmt.Fprintln(fh, " pfs enable")
	fmt.Fprintln(fh)

	// Define tunnel group used for single VPN users.
	defaultTunnelGroup := "VPN-single"
	trustPoint := r.trustPoint

	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "type remote-access")
	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "general-attributes")
	fmt.Fprintln(fh, " authorization-server-group LOCAL")
	fmt.Fprintln(fh, " default-group-policy", globalGroupName)
	fmt.Fprintln(fh, " authorization-required")
	fmt.Fprintln(fh, " username-from-certificate EA")
	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "ipsec-attributes")
	fmt.Fprintln(fh, " chain")
	printAsaTrustpoint(fh, r, trustPoint)
	fmt.Fprintln(fh, "tunnel-group", defaultTunnelGroup, "webvpn-attributes")
	fmt.Fprintln(fh, " authentication certificate")
	fmt.Fprintln(fh, "tunnel-group-map default-group", defaultTunnelGroup)
	fmt.Fprintln(fh)

	printGroupPolicy := func(name string, attributes map[string]string) {
		fmt.Fprintln(fh, "group-policy", name, "internal")
		fmt.Fprintln(fh, "group-policy", name, "attributes")
		keys := make(stringList, 0, len(attributes))
		for k, _ := range attributes {
			keys.push(k)
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
	splitTunnelMerge := getMergeTunnelAggregates(r)
	certGroupMap := make(map[string]string)
	singleCertMap := make(map[string]bool)
	extendedKey := make(map[string]string)
	type ldapEntry struct {
		dn     string
		gpName string
	}
	ldapMap := make(map[string][]ldapEntry)
	network2tg := make(map[*network]string)
	aclCounter := 1
	denyAny := getDenyAnyRule(ipv6)
	for _, intf := range r.interfaces {
		if intf.ipType != tunnelIP {
			continue
		}
		natMap := intf.natMap
		splitTCache := make(map[int]map[string][]*network)

		if hash := intf.idRules; hash != nil {
			keys := make(stringList, 0, len(hash))
			for k, _ := range hash {
				keys.push(k)
			}
			sort.Strings(keys)
			for _, id := range keys {
				idIntf := hash[id]
				idName := genIdName(id)
				src := idIntf.src
				attributes := combineAttr(
					r.radiusAttributes,
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
					splitTunnelNets = mergeSplitTunnelNets(
						splitTunnelNets, splitTunnelMerge, natMap)
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
						if len(splitTunnelNets) != 0 {
							objects := make([]someObj, len(splitTunnelNets))
							for i, n := range splitTunnelNets {
								objects[i] = n
							}
							rule = newRule(
								objects,
								[]someObj{getNetwork00(ipv6)},
								[]*proto{c.prt.IP},
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
							natMap:      natMap,
							isStdACL:    true,
							isCryptoACL: true,
						}
						r.aclList.push(info)
						printAclPlaceholder(fh, r, aclName)
					}
					attributes["split-tunnel-network-list"] = aclName
				}

				// Access list will be bound to cleartext interface.
				// Only check for valid source address at vpn-filter.
				idIntf.rules = nil
				rule := newRule(
					[]someObj{src},
					[]someObj{getNetwork00(ipv6)},
					[]*proto{c.prt.IP},
				)
				filterName := "vpn-filter-" + idName
				info := &aclInfo{
					name:    filterName,
					rules:   []*groupedRule{rule},
					addDeny: true,
					natMap:  natMap,
				}
				r.aclList.push(info)
				printAclPlaceholder(fh, r, filterName)

				ip := src.ipp.IP().String()
				network := src.getNetwork()
				if src.ipp.IsSingleIP() {

					// For anyconnect clients.
					pos := strings.IndexByte(id, '@')
					domain := id[pos:]
					singleCertMap[domain] = true

					extendedKey[domain] = attributes["check-extended-key-usage"]
					delete(attributes, "check-extended-key-usage")

					mask := net.IP(network.ipp.IPNet().Mask).String()
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
					mask := net.IP(src.ipp.IPNet().Mask).String()

					max := src.ipp.Range().To().String()
					fmt.Fprintln(fh, "ip local pool", name, ip+"-"+max, "mask", mask)
					attributes["address-pools"] = name
					attributes["vpn-filter"] = filterName
					groupPolicyName := "VPN-group-" + idName

					var tgName string
					if ldapId := src.ldapId; ldapId != "" {
						network := src.getNetwork()
						netAttr := combineAttr(
							r.radiusAttributes,
							network.radiusAttributes,
						)
						authServer := netAttr["authentication-server-group"]
						ldapMap[authServer] = append(
							ldapMap[authServer], ldapEntry{ldapId, groupPolicyName})
						tgName = network2tg[network]
						if tgName == "" {
							certId := network.certId
							tgName = printTunnelGroupRa(
								fh,
								certId,
								genIdName(certId),
								netAttr,
								r,
								"",
								certGroupMap,
							)
							network2tg[network] = tgName
						}
					} else {
						tgName = printTunnelGroupRa(
							fh,
							id,
							idName,
							attributes,
							r, groupPolicyName,
							certGroupMap,
						)
					}

					// Lock group-policy to tunnel-group.
					if _, found := attributes["group-lock"]; found {
						attributes["group-lock"] = tgName
					}
					printGroupPolicy(groupPolicyName, attributes)
					fmt.Fprintln(fh)
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
				[]*proto{c.prt.IP},
			)}
			idName := genIdName(id)
			filterName := "vpn-filter-" + idName
			info := &aclInfo{
				name:    filterName,
				rules:   rules,
				addDeny: true,
				natMap:  natMap,
			}
			r.aclList.push(info)
			printAclPlaceholder(fh, r, filterName)

			attributes := r.radiusAttributes

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
		keys := make(stringList, 0, len(singleCertMap))
		for k, _ := range singleCertMap {
			keys.push(k)
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
		keys = make(stringList, 0, len(certGroupMap))
		for k, _ := range certGroupMap {
			keys.push(k)
		}
		sort.Strings(keys)
		for _, mapName := range keys {
			tunnelGroupMap := certGroupMap[mapName]
			fmt.Fprintln(fh, " certificate-group-map", mapName, "10", tunnelGroupMap)
		}
		fmt.Fprintln(fh)
	}

	// Generate ldap attribute-maps and aaa-server referencing each map.
	keys := make(stringList, 0, len(ldapMap))
	for k, _ := range ldapMap {
		keys.push(k)
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
func printAclPrefix(fh *os.File, r *router) {
	model := r.model
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

func printAclSuffix(fh *os.File, r *router) {
	model := r.model
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

func collectAclsFromIORules(r *router) {
	for _, in := range r.hardware {

		// Ignore if all logical interfaces are loopback interfaces.
		if in.loopback {
			continue
		}

		inHw := in.name
		natMap := in.natMap

		if !r.model.noACLself {
			// Collect interface rules.
			aclName := inHw + "_self"
			info := &aclInfo{
				name:   aclName,
				rules:  in.intfRules,
				natMap: natMap,
			}
			in.intfRules = nil
			r.aclList.push(info)
		}

		// Collect forward rules.
		// One chain for each pair of in_intf / out_intf.
		for _, out := range r.hardware {
			if out.loopback {
				continue
			}
			outHw := out.name
			rules := in.ioRules[outHw]
			if in == out && len(rules) == 0 {
				continue
			}
			aclName := inHw + "_" + outHw
			info := &aclInfo{
				name:   aclName,
				rules:  rules,
				natMap: natMap,
			}
			r.aclList.push(info)
		}
		in.ioRules = nil
	}
}

func printIptablesAcls(fh *os.File, r *router) {
	collectAclsFromIORules(r)
	for _, acl := range r.aclList {
		acl.addDeny = true
		name := acl.name
		i := strings.Index(name, "_")
		inHw := name[:i]
		outHw := name[i+1:]
		printAclPlaceholder(fh, r, name)
		if outHw == "self" {
			// Add call to chain in INPUT chain.
			fmt.Fprintln(fh, "-A INPUT -j", name, "-i", inHw)
		} else {
			// Add call to chain in FORRWARD chain.
			fmt.Fprintln(fh, "-A FORWARD -j", name, "-i", inHw, "-o", outHw)
		}
		// Empty line after all chains.
		fmt.Fprintln(fh)
	}
}

func printCiscoAcls(fh *os.File, r *router) {
	model := r.model
	filter := model.filter
	managedLocal := r.managed == "local"
	ipv6 := r.ipV6
	permitAny := getPermitAnyRule(ipv6)

	getNatMap := func(r *router, m natMap) natMap {
		if model.aclUseRealIP {
			return r.natMap
		} else {
			return m
		}
	}

	for _, hw := range r.hardware {

		// Ignore if all logical interfaces are loopback interfaces.
		if hw.loopback {
			continue
		}

		natMap := getNatMap(r, hw.natMap)

		// Generate code for incoming and possibly for outgoing ACL.
		for _, suffix := range []string{"in", "out"} {

			info := &aclInfo{}

			// - Collect incoming ACLs,
			// - protect own interfaces,
			// - set {filter_any_src}.
			if suffix == "in" {
				rules := hw.rules
				intfRules := hw.intfRules
				hw.rules = nil
				hw.intfRules = nil

				// Don't generate single 'permit ip any any'.
				if !model.needACL &&
					len(rules) == 1 && rules[0] == permitAny &&
					len(intfRules) == 1 && intfRules[0] == permitAny {
					continue
				}
				info.natMap = natMap
				info.rules = rules

				// Marker: Generate protect_self rules, if available.
				info.protectSelf = true

				if r.needProtect {
					info.intfRules = intfRules
				}
				if hw.noInAcl {
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
					for _, intf := range hw.interfaces {
						zone := intf.zone
						if len(zone.cluster) > 1 {
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
					if intfOk == len(hw.interfaces) {
						info.filterAnySrc = true
					}
				}

				// Add ACL of corresponding tunnel interfaces.
				// We have exactly one crypto interface per hardware.
				intf := hw.interfaces[0]
				if (intf.hub != nil || intf.spoke != nil) && model.noCryptoFilter {
					for _, tunnelIntf := range getIntf(r) {
						realIntf := tunnelIntf.realIntf
						if realIntf == nil || realIntf != intf {
							continue
						}
						tunnelInfo := &aclInfo{
							natMap:    getNatMap(r, tunnelIntf.natMap),
							rules:     tunnelIntf.rules,
							intfRules: tunnelIntf.intfRules,
						}
						info.subAclList = append(info.subAclList, tunnelInfo)
					}
				}
			} else {
				// Outgoing ACL
				if !hw.needOutAcl {
					continue
				}
				rules := hw.outRules
				hw.outRules = nil
				if len(rules) == 1 && rules[0] == permitAny {
					continue
				}
				info.rules = rules
				info.natMap = natMap
				info.addDeny = true
			}

			aclName := hw.name + "_" + suffix
			info.name = aclName
			r.aclList.push(info)
			printAclPlaceholder(fh, r, aclName)

			// Post-processing for hardware interface
			if filter == "IOS" || filter == "NX-OS" {
				var filterCmd string
				if ipv6 {
					filterCmd = "ipv6 traffic-filter"
				} else {
					filterCmd = "ip access-group"
				}
				filterCmd += " " + aclName + " " + suffix
				hw.subcmd.push(filterCmd)
			} else if filter == "ASA" {
				fmt.Fprintln(fh,
					"access-group", aclName, suffix, "interface", hw.name)
			}

			// Empty line after each ACL.
			fmt.Fprintln(fh)
		}
	}
}

func generateAcls(fh *os.File, r *router) {
	printHeader(fh, r, "ACL")

	switch r.model.filter {
	case "iptables":
		printIptablesAcls(fh, r)
	default:
		printCiscoAcls(fh, r)
	}
}

func (c *spoc) genCryptoRules(local, remote []*network) []*groupedRule {
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
		[]*proto{c.prt.IP},
	)}
}

func (c *spoc) printEzvpn(fh *os.File, r *router) {
	interfaces := r.interfaces
	var tunnelIntf *routerIntf
	for _, intf := range interfaces {
		if intf.ipType == tunnelIP {
			tunnelIntf = intf
		}
	}
	tunNatMap := tunnelIntf.natMap
	wanIntf := tunnelIntf.realIntf
	wanHw := wanIntf.hardware
	wanNatMap := wanHw.natMap
	var lanIntfs intfList
	for _, intf := range interfaces {
		if intf != wanIntf && intf != tunnelIntf {
			lanIntfs.push(intf)
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
	peerIp := prefixCode(peer.realIntf.address(wanNatMap))
	fmt.Fprintln(fh, " peer", peerIp)

	// Bind split tunnel ACL.
	fmt.Fprintln(fh, " acl", cryptoAclName)

	// Use virtual template defined above.
	fmt.Fprintln(fh, " virtual-interface", virtualIntfNumber)

	// xauth is unused, but syntactically needed.
	fmt.Fprintln(fh, " username test pass test")
	fmt.Fprintln(fh, " xauth userid mode local")

	// Apply ezvpn to WAN and LAN interface.
	for _, intf := range lanIntfs {
		lanHw := intf.hardware
		lanHw.subcmd.push("crypto ipsec client ezvpn " + ezvpnName + " inside")
	}
	wanHw.subcmd.push("crypto ipsec client ezvpn " + ezvpnName)

	// Crypto ACL controls which traffic needs to be encrypted.
	cryptoRules := c.genCryptoRules(tunnelIntf.peer.peerNetworks,
		[]*network{getNetwork00(r.ipV6)})
	acls := &aclInfo{
		name:        cryptoAclName,
		rules:       cryptoRules,
		natMap:      tunNatMap,
		isCryptoACL: true,
	}
	r.aclList.push(acls)
	printAclPlaceholder(fh, r, cryptoAclName)

	// Crypto filter ACL.
	acls = &aclInfo{
		name:        cryptoFilterName,
		rules:       tunnelIntf.rules,
		intfRules:   tunnelIntf.intfRules,
		addDeny:     true,
		protectSelf: true,
		natMap:      tunNatMap,
	}
	tunnelIntf.rules = nil
	tunnelIntf.intfRules = nil
	r.aclList.push(acls)
	printAclPlaceholder(fh, r, cryptoFilterName)

	// Bind crypto filter ACL to virtual template.
	fmt.Fprintln(fh,
		"interface Virtual-Template"+strconv.Itoa(virtualIntfNumber),
		"type tunnel")
	var prefix string
	if r.ipV6 {
		prefix = " ipv6 traffic-filter"
	} else {
		prefix = " ip access-group"
	}

	fmt.Fprintln(fh, prefix, cryptoFilterName, "in")
}

// Print crypto ACL.
// It controls which traffic needs to be encrypted.
func (c *spoc) printCryptoAcl(fh *os.File, intf *routerIntf, suffix string, crypto *crypto) string {
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
	r := intf.router
	var local []*network
	if crypto.detailedCryptoAcl {
		local = getSplitTunnelNets(hub)
	} else {
		local = []*network{getNetwork00(r.ipV6)}
	}
	remote := hub.peerNetworks
	if !isHub {
		local, remote = remote, local
	}
	cryptoRules := c.genCryptoRules(local, remote)
	aclInfo := &aclInfo{
		name:        cryptoAclName,
		rules:       cryptoRules,
		natMap:      intf.natMap,
		isCryptoACL: true,
	}
	r.aclList.push(aclInfo)
	printAclPlaceholder(fh, r, cryptoAclName)
	return cryptoAclName
}

// Print filter ACL. It controls which traffic is allowed to leave from
// crypto tunnel. This may be needed, if we don't fully trust our peer.
func printCryptoFilterAcl(fh *os.File, intf *routerIntf, suffix string) string {
	r := intf.router

	if r.model.noCryptoFilter {
		return ""
	}
	cryptoFilterName := "crypto-filter-" + suffix
	natMap := intf.natMap
	aclInfo := &aclInfo{
		name:        cryptoFilterName,
		rules:       intf.rules,
		intfRules:   intf.intfRules,
		addDeny:     true,
		protectSelf: true,
		natMap:      natMap,
	}
	intf.rules = nil
	intf.intfRules = nil
	r.aclList.push(aclInfo)
	printAclPlaceholder(fh, r, cryptoFilterName)
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

func printTunnelGroupL2l(fh *os.File, r *router, name string, isakmp *isakmp) {
	authentication := isakmp.authentication
	fmt.Fprintln(fh, "tunnel-group", name, "type ipsec-l2l")
	fmt.Fprintln(fh, "tunnel-group", name, "ipsec-attributes")
	if authentication == "rsasig" {
		trustPoint := isakmp.trustPoint
		if isakmp.ikeVersion == 2 {
			fmt.Fprintln(fh, " ikev2 local-authentication certificate", trustPoint)
			fmt.Fprintln(fh, " ikev2 remote-authentication certificate")
		} else {
			printAsaTrustpoint(fh, r, trustPoint)
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

func (c *spoc) printStaticCryptoMap(
	fh *os.File, r *router, hw *hardware, mapName string,
	interfaces []*routerIntf, ipsec2transName map[*ipsec]string) {

	cryptoType := r.model.crypto

	// Sequence number for parts of crypto map with different peers.
	seqNum := 0

	// Peer IP must obey NAT.
	natMap := hw.natMap

	// Sort crypto maps by peer IP to get deterministic output.
	l := make([]*routerIntf, 0, len(interfaces))
	l = append(l, interfaces...)
	sort.Slice(l, func(i, j int) bool {
		return l[i].peer.realIntf.ip.Less(l[j].peer.realIntf.ip)
	})

	// Build crypto map for each tunnel interface.
	for _, intf := range l {
		seqNum++
		seq := strconv.Itoa(seqNum)
		peer := intf.peer
		peerIp := prefixCode(peer.realIntf.address(natMap))
		suffix := peerIp

		crypto := intf.getCrypto()
		ipsec := crypto.ipsec
		isakmp := ipsec.isakmp

		cryptoAclName := c.printCryptoAcl(fh, intf, suffix, crypto)
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
			printTunnelGroupL2l(fh, r, peerIp, isakmp)

			// Tunnel group needs to be activated, if certificate is in use.
			if id := peer.id; id != "" {
				printCaAndTunnelGroupMap(fh, id, peerIp)
			}
		}
	}
}

func (c *spoc) printDynamicCryptoMap(
	fh *os.File, r *router, mapName string,
	interfaces []*routerIntf, ipsec2transName map[*ipsec]string) {

	cryptoType := r.model.crypto

	// Sequence number for parts of crypto map with different certificates.
	seqNum := 65536

	// Sort crypto maps by certificate to get deterministic output.
	l := make([]*routerIntf, 0, len(interfaces))
	l = append(l, interfaces...)
	sort.Slice(l, func(i, j int) bool {
		return l[i].peer.id < l[j].peer.id
	})

	// Build crypto map for each tunnel interface.
	for _, intf := range l {
		seqNum--
		seq := strconv.Itoa(seqNum)
		id := intf.peer.id
		suffix := id

		crypto := intf.getCrypto()
		ipsec := crypto.ipsec
		isakmp := ipsec.isakmp

		cryptoAclName := c.printCryptoAcl(fh, intf, suffix, crypto)
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
		printTunnelGroupL2l(fh, r, id, isakmp)

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

func (c *spoc) printCrypto(fh *os.File, r *router) {
	cryptoType := r.model.crypto

	// List of ipsec definitions used at current router.
	var ipsecList []*ipsec
	seenIpsec := make(map[*ipsec]bool)
	for _, intf := range r.interfaces {
		if intf.ipType == tunnelIP {
			s := intf.getCrypto().ipsec
			if !seenIpsec[s] {
				seenIpsec[s] = true
				ipsecList = append(ipsecList, s)
			}
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
		if !seenIsakmp[k] {
			seenIsakmp[k] = true
			isakmpList = append(isakmpList, k)
		}
	}

	printHeader(fh, r, "Crypto")

	if cryptoType == "EZVPN" {
		c.printEzvpn(fh, r)
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
		c.printAsavpn(fh, r)
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
			espEncr := ipsec.espEncryption
			switch espEncr {
			case "":
				espEncr = "null"
			case "aes192":
				espEncr = "aes-192"
			case "aes256":
				espEncr = "aes-256"
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

	for _, hw := range r.hardware {

		// Collect tunnel interfaces attached to each hardware interface.
		// Differentiate on peers having static || dynamic IP address.
		var static, dynamic intfList
		var haveCryptoMap = false
		for _, intf := range hw.interfaces {
			if intf.ipType != tunnelIP {
				continue
			}
			real := intf.peer.realIntf
			if real.ipType != hasIP {
				dynamic.push(intf)
			} else {
				static.push(intf)
			}
			haveCryptoMap = true
		}

		hwName := hw.name

		// Name of crypto map.
		mapName := "crypto-" + hwName

		if static != nil {
			c.printStaticCryptoMap(fh, r, hw, mapName, static,
				ipsec2transName)
		}
		if dynamic != nil {
			c.printDynamicCryptoMap(fh, r, mapName, dynamic,
				ipsec2transName)
		}

		// Bind crypto map to interface.
		if !haveCryptoMap {
			continue
		}
		if cryptoType == "IOS" {
			hw.subcmd.push("crypto map " + mapName)
		} else if cryptoType == "ASA" {
			fmt.Fprintln(fh, "crypto map", mapName, "interface", hwName)
		}
	}
}

func printRouterIntf(fh *os.File, r *router) {
	model := r.model
	if !model.printRouterIntf {
		return
	}
	class := model.class
	stateful := !model.stateless
	ipv6 := r.ipV6
	for _, hw := range r.hardware {
		name := hw.name
		var subcmd stringList
		secondary := false

	INTF:
		for _, intf := range hw.interfaces {
			var addrCmd string
			if intf.redundant {
				continue
			}
			switch intf.ipType {
			case tunnelIP:
				continue INTF
			case unnumberedIP:
				addrCmd = "ip unnumbered X"
			case negotiatedIP:
				addrCmd = "ip address negotiated"
			default:
				if model.usePrefix || ipv6 {
					if ipv6 {
						addrCmd = "ipv6"
					} else {
						addrCmd = "ip"
					}
					addrCmd += " address " + netaddr.IPPrefixFrom(
						intf.ip,
						intf.network.ipp.Bits(),
					).String()
				} else {
					addr := intf.ip.String()
					mask := net.IP(intf.network.ipp.IPNet().Mask).String()
					addrCmd = "ip address " + addr + " " + mask
				}
				if secondary {
					addrCmd += " secondary"
				}
			}
			subcmd.push(addrCmd)
			if !ipv6 || class == "NX-OS" {
				secondary = true
			}
		}
		if vrf := r.vrf; vrf != "" {
			if class == "NX-OS" {
				subcmd.push("vrf member " + vrf)
			} else {
				subcmd.push("ip vrf forwarding " + vrf)
			}
		}

		// Add "ip inspect" as marker, that stateful filtering is expected.
		// The command is known to be incomplete, "X" is only used as
		// placeholder.
		if class == "IOS" && stateful && !hw.loopback {
			subcmd.push("ip inspect X in")
		}

		subcmd = append(subcmd, hw.subcmd...)

		fmt.Fprintln(fh, "interface "+name)
		for _, cmd := range subcmd {
			fmt.Fprintln(fh, " "+cmd)
		}
	}
	fmt.Fprintln(fh)
}

func prefixCode(n netaddr.IPPrefix) string {
	if n.IsSingleIP() {
		return n.IP().String()
	}
	return n.String()

}

func fullPrefixCode(n netaddr.IPPrefix) string {
	return n.String()
}

// Collect interfaces that need protection by additional deny rules.
// Add list to each ACL separately, because IP may be changed by NAT.
func getNeedProtect(r *router) []*routerIntf {

	// ASA protects IOS router behind crosslink interface.
	// Routers connected by crosslink networks are handled like one
	// large router. Protect the collected interfaces of the whole
	// cluster at each entry.
	l := r.crosslinkIntfs
	if l != nil {
		return l
	}
	if !r.needProtect {
		return nil
	}
	for _, i := range r.interfaces {
		if !i.ip.IsZero() {
			l.push(i)
		}
	}
	return l
}

// Precompute string representation of IP addresses when NAT is not active.
func (c *spoc) setupStdAddr() {
	addNet := func(n *network) {
		n.stdAddr = n.ipp.String()
	}
	// Aggregates, networks, subnets.
	for _, n := range c.allNetworks {
		if n.ipType == unnumberedIP || n.ipType == tunnelIP {
			continue
		}
		addNet(n)
		for _, s := range n.subnets {
			s.stdAddr = s.ipp.String()
		}
	}
	// network00
	for _, n := range []*network{network00, network00v6} {
		addNet(n)
	}
	// Multicast networks
	addMcast := func(info map[string]*mcastProto) {
		for _, mp := range info {
			for _, m := range []*multicast{&mp.v4, &mp.v6} {
				for _, n := range m.networks {
					addNet(n)
				}
			}
		}
	}
	addMcast(routingInfo)
	addMcast(xxrpInfo)
	// Interfaces
	for _, r := range c.allRouters {
		v6 := r.ipV6
		for _, intf := range r.interfaces {
			switch intf.ipType {
			case hasIP:
				intf.stdAddr =
					netaddr.IPPrefixFrom(intf.ip, getHostPrefix(v6)).String()
			case negotiatedIP:
				intf.stdAddr = intf.network.stdAddr
			}
		}
	}
}

// Optimization: Use precomputed stdAddr.
func getAddr(o someObj, natMap natMap) string {
	switch x := o.(type) {
	case *network:
		if natMap[x] == nil {
			return x.stdAddr
		}
	case *subnet:
		if natMap[x.network] == nil {
			return x.stdAddr
		}
	case *routerIntf:
		if natMap[x.network] == nil {
			return x.stdAddr
		}
	}
	return fullPrefixCode(o.address(natMap))
}

func getAddrList(l []someObj, natMap natMap) []string {
	result := make([]string, len(l))
	for i, o := range l {
		result[i] = getAddr(o, natMap)
	}
	return result
}

func (c *spoc) printAcls(path string, vrfMembers []*router) {
	var aclList []*jcode.ACLInfo
	for _, r := range vrfMembers {
		managed := r.managed
		secondaryFilter := managed == "secondary"
		standardFilter := managed == "standard"
		model := r.model
		doAuth := model.doAuth
		activeLog := r.log
		needProtect := getNeedProtect(r)

		process := func(acl *aclInfo) *jcode.ACLInfo {
			jACL := new(jcode.ACLInfo)
			jACL.Name = acl.name
			jACL.AddPermit = acl.addPermit
			jACL.AddDeny = acl.addDeny
			jACL.FilterAnySrc = acl.filterAnySrc
			jACL.IsStdACL = acl.isStdACL
			jACL.IsCryptoACL = acl.isCryptoACL
			// Collect networks used in secondary optimization.
			optAddr := make(map[*network]bool)
			// Collect objects forbidden in secondary optimization.
			noOptAddrs := make(map[someObj]bool)
			natMap := acl.natMap

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
					a := getAddr(intf, natMap)
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
					newRule.Deny = rule.deny

					// Add code for logging.
					// This code is machine specific.
					newRule.Log = r.logDefault
					if activeLog != nil && rule.log != "" {
						for _, tag := range strings.Split(rule.log, " ") {
							if logCode, found := activeLog[tag]; found {
								// Take first of possibly several matching tags.
								newRule.Log = logCode
								break
							}
						}
					}

					if secondaryFilter && rule.someNonSecondary ||
						standardFilter && rule.somePrimary {
						for _, isSrc := range []bool{true, false} {
							var objList []someObj
							if isSrc {
								objList = rule.src
							} else {
								objList = rule.dst
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
									if intf, ok := obj.(*routerIntf); ok {

										// Must not optimize interface of
										// current router. This would allow
										// unexpected access if another rule
										// allows access to the network of this
										// interface, located directly before or
										// behind this router.
										//
										// Ignore loopback interface that isn't
										// part of other network.
										if intf.router == r && !intf.loopback {
											noOptAddrs[obj] = true
											continue
										}
									}
									net := obj.getNetwork()
									if net.hasOtherSubnet {
										continue
									}
									if noOpt := r.noSecondaryOpt; noOpt != nil {
										if noOpt[net] {
											noOptAddrs[obj] = true
											continue
										}
									}
									subst = net
									if max := subst.maxSecondaryNet; max != nil {
										subst = max
									}

									// Ignore loopback network.
									if subst.ipp.IsSingleIP() {
										continue
									}

									// Network or aggregate.
								case *network:

									// Don't modify protocol of rule
									// with hasOtherSubnet, because
									// this could introduce new missing
									// supernet rules.
									if o.hasOtherSubnet {
										noOptAddrs[obj] = true
										continue
									}
									max := o.maxSecondaryNet
									if max == nil {
										continue
									}
									subst = max
								}
								optAddr[subst] = true
							}
						}
						newRule.OptSecondary = true
					}

					newRule.Src = getAddrList(rule.src, natMap)
					newRule.Dst = getAddrList(rule.dst, natMap)
					prtList := make([]string, len(rule.prt))
					for i, p := range rule.prt {
						if p.proto == "icmpv6" {
							prtList[i] = "icmp" + p.name[len("icmpv6"):]
						} else {
							prtList[i] = p.name
						}
					}
					newRule.Prt = prtList
					if srcRange := rule.srcRange; srcRange != nil {
						newRule.SrcRange = srcRange.name
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
			addrList := make(stringList, 0, len(optAddr))
			for n, _ := range optAddr {
				a := getAddr(n, natMap)
				addrList.push(a)
			}
			sort.Strings(addrList)
			jACL.OptNetworks = addrList

			addrList = make(stringList, 0, len(noOptAddrs))
			for o, _ := range noOptAddrs {
				a := getAddr(o, natMap)
				addrList.push(a)
			}
			sort.Strings(addrList)
			jACL.NoOptAddrs = addrList

			if model.needVRF {
				jACL.VRF = r.vrf
			}
			return jACL
		}

		aref := r.aclList
		r.aclList = nil
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

	r := vrfMembers[0]
	model := r.model
	result := &jcode.RouterData{
		Model:         model.class,
		ACLs:          aclList,
		DoObjectgroup: model.canObjectgroup && !r.noGroupCode,
	}

	if filterOnly := r.filterOnly; filterOnly != nil {
		list := make([]string, len(filterOnly))
		for i, f := range filterOnly {
			list[i] = fullPrefixCode(f)
		}
		result.FilterOnly = list
	}
	if r.logDeny {
		result.LogDeny = "log"
	}
	c.writeJson(path, result)
}

// Make output directory available.
// Move old content into subdirectory ".prev/" for reuse during pass 2.
func (c *spoc) checkOutputDir(dir, prev string, devices []*router) {
	if !fileop.IsDir(dir) {
		err := os.Mkdir(dir, 0777)
		if err != nil {
			c.abort("Can't %v", err)
		}
	} else if !fileop.IsDir(prev) {
		// Don't move files if directory .prev already exists.
		// In this case the previous run of netspoc must have failed,
		// since .prev is removed on successfull completion.

		// Try to remove file or symlink with same name.
		os.Remove(prev)
		oldFiles := fileop.Readdirnames(dir)
		if count := len(oldFiles); count > 0 {
			if fileop.IsDir(dir + "/ipv6") {
				v6files := fileop.Readdirnames(dir + "/ipv6")
				count += len(v6files) - 1
			}
			c.info("Saving %d old files of '%s' to subdirectory '.prev'",
				count, dir)

			err := os.Mkdir(prev, 0777)
			if err != nil {
				c.abort("Can't %v", err)
			}
			for i, name := range oldFiles {
				oldFiles[i] = dir + "/" + name
			}
			cmd := exec.Command("mv", append(oldFiles, prev)...)
			if out, err := cmd.CombinedOutput(); err != nil {
				c.abort("Can't mv old files to prev: %v\n%s", err, out)
			}
		}
	}
	needV6 := false
	for _, r := range devices {
		if r.ipV6 {
			needV6 = true
		}
	}
	if needV6 {
		v6dir := dir + "/ipv6"
		if !fileop.IsDir(v6dir) {
			err := os.Mkdir(v6dir, 0777)
			if err != nil {
				c.abort("Can't %v", err)
			}
		}
	}
}

func (c *spoc) getDevices() []*router {

	// Take only one router of multi VRF device.
	// Ignore split part of crypto router.
	// Create ipv6 subdirectory.
	var result []*router
	seen := make(map[*router]bool)
	for _, r := range c.managedRouters {
		if seen[r] || r.origRouter != nil {
			continue
		}
		result = append(result, r)
		for _, vrouter := range r.vrfMembers {
			seen[vrouter] = true
		}
	}
	return result
}

func (c *spoc) printPanOS(fd *os.File, l []*router) {
	r := l[0]
	mgmt := getRouter(r.deviceName, symTable, r.ipV6)
	hostnames := mgmt.deviceName
	ipList := mgmt.interfaces[0].ip.String()
	if backup := mgmt.backupInstance; backup != nil {
		hostnames += ", " + backup.deviceName
		ipList += ", " + backup.interfaces[0].ip.String()
	}
	fmt.Fprintf(fd,
		`<?xml version = "1.0" ?>
<!--
Generated by %s, version %s

[ BEGIN %s ]
[ Model = %s ]
[ IP = %s ]
-->
`,
		program, version, hostnames, r.model.class, ipList)

	fmt.Fprintln(fd, "<config><devices><entry><vsys>")
	for _, r := range l {
		fmt.Fprintln(fd, "#insert", r.vrf)
	}
	fmt.Fprintln(fd, "</vsys></entry></devices></config>")
}

// Print generated code for each managed router.
func (c *spoc) printRouter(r *router, dir string) string {
	deviceName := r.deviceName
	path := deviceName
	if r.ipV6 {
		path = "ipv6/" + path
	}

	// File for router config without ACLs.
	configFile := dir + "/" + path + ".config"
	fd, err := os.OpenFile(configFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		c.abort("Can't %v", err)
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

	if model.filter == "PAN-OS" {
		c.printPanOS(fd, vrfMembers)
		for _, vrouter := range vrfMembers {
			collectAclsFromIORules(vrouter)
		}
	} else {

		// Print version header.
		fmt.Fprintf(fd, "%s Generated by %s, %s", commentChar, program, version)
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
			printRoutes(fd, vrouter)
			if vrouter.managed == "" {
				continue
			}
			c.printCrypto(fd, vrouter)
			printAclPrefix(fd, vrouter)
			generateAcls(fd, vrouter)
			printAclSuffix(fd, vrouter)
			printRouterIntf(fd, vrouter)
		}

		header("END", deviceName)
		fmt.Fprintln(fd)
		if err := fd.Close(); err != nil {
			panic(err)
		}
	}

	// Print ACLs in machine independent format into separate file.
	// Collect ACLs from VRF parts.
	aclFile := dir + "/" + path + ".rules"
	c.printAcls(aclFile, vrfMembers)
	return path
}

func (c *spoc) printConcurrent(devices []*router, dir, prev string) {
	var reused int32 = 0
	if conf.Conf.ConcurrencyPass2 <= 1 {
		for _, r := range devices {
			path := c.printRouter(r, dir)
			reused += int32(pass2.File(path, dir, prev))
		}
	} else {
		concurrentGoroutines := make(chan struct{}, conf.Conf.ConcurrencyPass2)
		var wg sync.WaitGroup
		for _, r := range devices {
			concurrentGoroutines <- struct{}{}
			wg.Add(1)
			go func(r *router) {
				defer wg.Done()
				path := c.printRouter(r, dir)
				atomic.AddInt32(&reused, int32(pass2.File(path, dir, prev)))
				<-concurrentGoroutines
			}(r)
		}
		wg.Wait()
	}
	// Remove directory '.prev' created by pass1
	// or remove symlink '.prev' created by newpolicy.pl.
	// Error is ignored; would use unneeded space only.
	os.RemoveAll(prev)

	generated := int32(len(devices)) - reused
	if generated > 0 {
		c.info("Generated files for %d devices", generated)
	}
	if reused > 0 {
		c.info("Reused files for %d devices from previous run", reused)
	}
}

func (c *spoc) printCode(dir string) {
	c.progress("Printing code")
	c.setupStdAddr()
	devices := c.getDevices()
	prev := path.Join(dir, ".prev")
	c.checkOutputDir(dir, prev, devices)
	c.printConcurrent(devices, dir, prev)
}
