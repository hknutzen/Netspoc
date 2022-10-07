package pass2

import (
	"encoding/json"
	"fmt"
	"golang.org/x/exp/maps"
	"os"
	"sort"
	"strconv"
	"strings"
)

type jsonMap map[string]interface{}

func printNSXRules(fd *os.File, rData *routerData) {

	// Remove redundant rules and find object-groups.
	prepareACLs(rData)

	// Build mapping from object-group name to object-group + use count.
	// Used to replace group by its elements if only used once.
	type groupUse struct {
		g     *objGroup
		count int
	}
	n2gU := make(map[string]*groupUse)
	countGroup := func(n *ipNet) {
		if !n.Prefix.IsValid() {
			gU := n2gU[n.name]
			gU.count++
		}
	}
	for _, acl := range rData.acls {
		joinRanges(acl)
		findObjectgroups(acl, rData)
		addFinalPermitDenyRule(acl)
		for _, g := range acl.objectGroups {
			n2gU[g.name] = &groupUse{g: g}
		}
		for _, rule := range acl.rules {
			countGroup(rule.src)
			countGroup(rule.dst)
		}
	}

	// Print JSON.
	getAction := func(ru *ciscoRule) string {
		if ru.deny {
			return "DROP"
		} else {
			return "ALLOW"
		}
	}
	single := func(s string) []string { return []string{s} }
	var getAddress func(n *ipNet) []string
	getAddress = func(n *ipNet) []string {
		// Object group.
		if !n.Prefix.IsValid() {
			gU := n2gU[n.name]
			if gU.count > 1 {
				return single("Netspoc-" + n.name)
			}
			var result []string
			for _, e := range gU.g.elements {
				result = append(result, getAddress(e)...)
			}
			return result
		}
		if n.Bits() == 0 {
			return single("ANY")
		}
		if n.IsSingleIP() {
			return single(n.Addr().String())
		}
		return single(n.String())
	}
	type srcRgPrt struct {
		srcRg *proto
		prt   *proto
		name  string
	}
	protoMap := make(map[string]srcRgPrt)
	getService := func(ru *ciscoRule) string {
		prt := ru.prt
		proto := prt.protocol
		if proto == "ip" {
			return "ANY"
		}
		var name string
		srcRange := ru.srcRange
		if srcRange != nil {
			var dPorts string
			if len(prt.name) > len(proto) {
				dPorts = prt.name[len(proto)+1:]
			} else {
				dPorts = "1-65535"
			}
			name = srcRange.name + ":" + dPorts
		} else {
			name = prt.name
		}
		name = "Netspoc-" + name
		protoMap[name] = srcRgPrt{prt: prt, srcRg: srcRange}
		return name
	}
	getPolicies := func(l []*aclInfo) []jsonMap {
		var result []jsonMap
		// Collect rules of each firewall into a separate policy.
		pm := make(map[string][]*aclInfo)
		for _, acl := range l {
			pm[acl.vrf] = append(pm[acl.vrf], acl)
		}
		vrfs := maps.Keys(pm)
		sort.Strings(vrfs)
		for _, vrf := range vrfs {
			acls := pm[vrf]
			scope := fmt.Sprintf("/infra/tier-%ss/%s", acls[0].tier, vrf)
			var nsxRules []jsonMap
			count := 1
			for _, acl := range acls {
				hardware := strings.TrimSuffix(acl.name, "_in")
				direction := "IN"
				if hardware == "IN" {
					direction = "OUT"
				}
				for _, rule := range acl.rules {
					rName := fmt.Sprintf("r%d", count)
					count++
					nsxRule := jsonMap{
						"resource_type":      "Rule",
						"id":                 rName,
						"display_name":       rName,
						"action":             getAction(rule),
						"source_groups":      getAddress(rule.src),
						"destination_groups": getAddress(rule.dst),
						"services":           single(getService(rule)),
						"scope":              single(scope),
						"direction":          direction,
					}
					nsxRules = append(nsxRules, nsxRule)
				}
			}
			policyName := "Netspoc-" + vrf
			path := "/infra/domains/default/gateway-policies/" + policyName
			result = append(result, jsonMap{
				"resource_type": "GatewayPolicy",
				"path":          path,
				"id":            policyName,
				"display_name":  policyName,
				"rules":         nsxRules,
			})
		}
		return result
	}
	getGroups := func() []jsonMap {
		var result []jsonMap
		for _, acl := range rData.acls {
			for _, g := range acl.objectGroups {
				if n2gU[g.name].count > 1 {
					var l []string
					for _, n := range g.elements {
						l = append(l, getAddress(n)...)
					}
					path := "/infra/domains/default/groups/" + "Netspoc-" + g.name
					addresses := jsonMap{
						"resource_type": "IPAddressExpression",
						"ip_addresses":  l,
					}
					result = append(result, jsonMap{
						"path":       path,
						"expression": []jsonMap{addresses},
					})
				}
			}
		}
		return result
	}
	getServices := func() []jsonMap {
		var result []jsonMap
		names := maps.Keys(protoMap)
		sort.Strings(names)
		for _, name := range names {
			pair := protoMap[name]
			p := pair.prt
			proto := p.protocol
			svcEntry := jsonMap{}
			switch proto {
			case "tcp", "udp":
				svcEntry["resource_type"] = "L4PortSetServiceEntry"
				svcEntry["l4_protocol"] = strings.ToUpper(proto)
				if len(p.name) > len(proto) {
					ports := p.name[len(proto)+1:]
					svcEntry["destination_ports"] = single(ports)
				}
				if s := pair.srcRg; s != nil {
					ports := s.name[len(s.protocol)+1:]
					svcEntry["source_ports"] = single(ports)
				}
			case "icmp":
				svcEntry["resource_type"] = "IcmpTypeServiceEntry"
				if typ := p.icmpType; typ != -1 {
					svcEntry["icmp_type"] = typ
					if code := p.icmpCode; code != -1 {
						svcEntry["icmp_code"] = code
					}
				}
			default:
				svcEntry["resource_type"] = "IpProtocolServiceEntry"
				svcEntry["protocol_number"], _ = strconv.Atoi(proto)
			}
			path := "/infra/services/" + name
			result = append(result, jsonMap{
				"display_name":    name,
				"path":            path,
				"service_entries": []jsonMap{svcEntry},
			})
		}
		return result
	}

	fmt.Fprintln(fd)
	s2 := getPolicies(rData.acls)
	s1 := getGroups()
	s1 = append(s1, getServices()...)
	s1 = append(s1, s2...)
	enc := json.NewEncoder(fd)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	enc.Encode(s1)
	fmt.Fprintln(fd)
}

func printCombinedNSX(fd *os.File, config []string, rData *routerData) {
	// Print config and insert printed configuration at aclMarker.
	for _, line := range config {
		if strings.HasPrefix(line, aclMarker) {
			// Print rules.
			printNSXRules(fd, rData)
		} else {
			// Print unchanged config line.
			fmt.Fprintln(fd, line)
		}
	}
}
