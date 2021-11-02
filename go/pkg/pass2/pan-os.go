package pass2

import (
	"fmt"
	"os"
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
		if n.IPPrefix.IsZero() {
			gU := n2gU[n.name]
			gU.count++
		}
	}
	for _, acl := range rData.acls {
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
		if n.IPPrefix.IsZero() {
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
			name = "IP_" + n.IP().String()
		} else {
			name = "NET_" + strings.Replace(n.String(), "/", "_", 1)
		}
		if !addrSeen[name] {
			ip2addr[n] = name
			addrSeen[name] = true
		}
		return member(name)
	}
	protoMap := make(map[string]*proto)
	getService := func(ru *ciscoRule) string {
		prt := ru.prt
		proto := prt.protocol
		if proto == "ip" {
			return member("any")
		}
		name := prt.name
		protoMap[name] = prt
		return member(name)
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
				action := getAction(rule)
				source := getAddress(rule.src)
				destination := getAddress(rule.dst)
				service := getService(rule)
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
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
`,
					name, action, from, to, source, destination, service)
			}
		}
		fmt.Fprintln(fd, "</rules></security></rulebase>")
	}
	printAddresses := func() {
		l := make([]*ipNet, 0, len(ip2addr))
		for n := range ip2addr {
			l = append(l, n)
		}
		sort.Slice(l, func(i, j int) bool {
			return l[i].IP().Less(l[j].IP())
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
		l := make([]*proto, 0, len(protoMap))
		for _, p := range protoMap {
			l = append(l, p)
		}
		sort.Slice(l, func(i, j int) bool {
			return l[i].protocol < l[j].protocol ||
				l[i].protocol == l[j].protocol &&
					(l[i].ports[0] < l[j].ports[0] ||
						l[i].ports[0] == l[j].ports[0] &&
							l[i].ports[1] < l[j].ports[1])
		})
		fmt.Fprintln(fd, "<service>")
		for _, p := range l {
			name := p.name
			proto := p.protocol
			var details string
			switch proto {
			case "tcp", "udp":
				var ports string
				if len(name) > len(proto) {
					ports = name[len(proto)+1:]
				} else {
					ports = "1-65535"
				}
				details = "<" + proto + "><port>" +
					ports + "</port></" + proto + ">"
			default:
				// <other> is invalid tag for PAN-OS.
				details = "<other>" + name + "</other>"
			}

			entry := `<entry name="` + name + `"><protocol>` + details +
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
