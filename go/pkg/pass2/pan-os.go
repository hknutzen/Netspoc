package pass2

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
)

func printPanOSRules(fd *os.File, vsys string, rData *routerData) {

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
		optimizeRules(acl)
		joinRanges(acl)
		findObjectgroups(acl, rData)
		for _, g := range acl.objectGroups {
			n2gU[g.name] = &groupUse{g: g}
		}
		for _, rule := range acl.rules {
			countGroup(rule.src)
			countGroup(rule.dst)
		}
	}

	// Print XML.
	getAction := func(ru *ciscoRule) string {
		if ru.deny {
			return "drop"
		} else {
			return "allow"
		}
	}
	member := func(e string) string {
		return "<member>" + e + "</member>"
	}
	ip2addr := make(map[*ipNet]string)
	addrSeen := make(map[string]bool)
	var getAddress func(n *ipNet) string
	getAddress = func(n *ipNet) string {
		// Object group.
		if !n.Prefix.IsValid() {
			gU := n2gU[n.name]
			g := gU.g
			if gU.count > 1 {
				return member(n.name)
			}
			result := "\n"
			for _, e := range g.elements {
				result += getAddress(e) + "\n"
			}
			return result
		}
		if n.Bits() == 0 {
			return member("any")
		}
		if name, ok := ip2addr[n]; ok {
			return member(name)
		}
		var name string
		if n.IsSingleIP() {
			name = "IP_" + strings.ReplaceAll(n.Addr().String(), ":", "_")
		} else {
			name = "NET_" + strings.ReplaceAll(strings.Replace(n.String(), "/", "_", 1), ":", "_")
		}
		if !addrSeen[name] {
			ip2addr[n] = name
			addrSeen[name] = true
		}
		return member(name)
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
			return member("any")
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
		protoMap[name] = srcRgPrt{prt: prt, srcRg: srcRange, name: name}
		return member(name)
	}
	getLog := func(ru *ciscoRule, aclInfo *aclInfo) string {
		result := ""
		modifiers := ru.log
		if modifiers == "" && ru.deny {
			modifiers = aclInfo.logDeny
		}
		if modifiers != "" {
			for _, log := range strings.Split(modifiers, " ") {
				k, v, found := strings.Cut(log, ":")
				if !found {
					v = "yes"
				}
				result += fmt.Sprintf("<log-%s>%s</log-%s>\n", k, v, k)
			}
		}
		return result
	}
	printRules := func(l []*aclInfo) {
		fmt.Fprintln(fd, "<rulebase><security><rules>")
		count := 1
		for _, acl := range l {
			zones := strings.Split(acl.name, "_")
			from := member(zones[0])
			to := member(zones[1])
			for _, rule := range acl.rules {
				name := fmt.Sprintf("r%d", count)
				count++
				// Prevent name clash between IPv4 and IPv6 rules
				if rData.ipv6 {
					name = "v6" + name
				}
				action := getAction(rule)
				source := getAddress(rule.src)
				destination := getAddress(rule.dst)
				service := getService(rule)
				log := getLog(rule, acl)
				fmt.Fprintf(fd,
					`<entry name="%s">
<action>%s</action>
<from>%s</from>
<to>%s</to>
<source>%s</source>
<destination>%s</destination>
<service>%s</service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
%s</entry>
`,
					name, action, from, to, source, destination, service, log)
			}
		}
		fmt.Fprintln(fd, "</rules></security></rulebase>")
	}
	printAddresses := func() {
		l := slices.Collect(maps.Keys(ip2addr))
		sort.Slice(l, func(i, j int) bool {
			if l[i].Addr() == l[j].Addr() {
				return l[i].Bits() > l[j].Bits()
			}
			return l[i].Addr().Less(l[j].Addr())
		})
		fmt.Fprintln(fd, "<address>")
		for _, n := range l {
			name := ip2addr[n]
			ipp := n.String()
			entry := `<entry name="` + name + `"><ip-netmask>` + ipp +
				`</ip-netmask></entry>`
			fmt.Fprintln(fd, entry)
		}
		fmt.Fprintln(fd, "</address>")
	}
	printAddressGroups := func() {
		fmt.Fprintln(fd, "<address-group>")
		for _, acl := range rData.acls {
			for _, g := range acl.objectGroups {
				if n2gU[g.name].count > 1 {
					fmt.Fprintln(fd, `<entry name="`+g.name+`"><static>`)
					for _, n := range g.elements {
						fmt.Fprintln(fd, getAddress(n))
					}
					fmt.Fprintln(fd, "</static></entry>")
				}
			}
		}
		fmt.Fprintln(fd, "</address-group>")
	}
	printServices := func() {
		l := slices.SortedFunc(maps.Values(protoMap),
			func(a, b srcRgPrt) int {
				v := cmp.Or(
					cmp.Compare(a.prt.protocol, b.prt.protocol),
					cmp.Compare(a.prt.ports[0], b.prt.ports[0]),
					cmp.Compare(a.prt.ports[1], b.prt.ports[1]))
				if v == 0 && a.srcRg != nil && b.srcRg != nil {
					return cmp.Or(
						cmp.Compare(a.srcRg.ports[0], b.srcRg.ports[0]),
						cmp.Compare(a.srcRg.ports[1], b.srcRg.ports[1]))
				}
				return v
			})
		fmt.Fprintln(fd, "<service>")
		for _, pair := range l {
			p := pair.prt
			proto := p.protocol
			var details string
			switch proto {
			case "tcp", "udp":
				var ports string
				if len(p.name) > len(proto) {
					ports = p.name[len(proto)+1:]
				} else {
					ports = "1-65535"
				}
				ports = "<port>" + ports + "</port>"
				sPorts := ""
				if s := pair.srcRg; s != nil {
					sPorts =
						"<source-port>" + s.name[len(s.protocol)+1:] + "</source-port>"
				}
				details = "<" + proto + ">" + ports + sPorts + "</" + proto + ">"
			default:
				// <other> is invalid tag for PAN-OS.
				details = "<other>" + p.name + "</other>"
			}

			entry := `<entry name="` + pair.name + `"><protocol>` + details +
				`</protocol></entry>`
			fmt.Fprintln(fd, entry)
		}
		fmt.Fprintln(fd, "</service>")
	}

	fmt.Fprintln(fd)
	fmt.Fprintf(fd, "<entry name=\"%s\">\n", vsys)
	printRules(rData.acls)
	printAddressGroups()
	printAddresses()
	printServices()
	fmt.Fprintln(fd, "</entry>")
	fmt.Fprintln(fd)
}

func printCombinedPanOS(fd *os.File, config []string, rData *routerData) {

	// Split routerData into separate chunks for each VSYS.
	// This is necessary as we don't want to get shared addressgroups
	// between different VSYS.
	lookup := make(map[string]*routerData)
	for _, acl := range rData.acls {
		d := lookup[acl.vrf]
		if d == nil {
			e := *rData
			e.acls = nil
			d = &e
			lookup[acl.vrf] = d
		}
		d.acls = append(d.acls, acl)
	}

	// Print config and insert printed vsys configuration at aclMarker.
	for _, line := range config {
		if strings.HasPrefix(line, aclMarker) {
			// Print rules.
			vsys := line[len(aclMarker):]
			printPanOSRules(fd, vsys, lookup[vsys])
		} else {
			// Print unchanged config line.
			fmt.Fprintln(fd, line)
		}
	}
}
