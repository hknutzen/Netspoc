package pass2

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Count how often an object group is referenced.
type groupUse struct {
	g     *objGroup
	count int
}

func printPanOSRules(
	fd *os.File, vsys string, l []*aclInfo, n2gU map[string]*groupUse) {

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
	addrGroupMap := make(map[*objGroup]bool)
	var getAddress func(n *ipNet) string
	getAddress = func(n *ipNet) string {
		// Object group.
		if n.IPPrefix.IsZero() {
			gU := n2gU[n.name]
			g := gU.g
			if gU.count > 1 {
				addrGroupMap[g] = true
				return member(n.name)
			}
			result := "\n"
			for _, e := range g.elements {
				result += getAddress(e) + "\n"
			}
			return result
		}
		if n.Bits == 0 {
			return member("any")
		}
		if name, ok := ip2addr[n]; ok {
			return member(name)
		}
		var name string
		if n.IsSingleIP() {
			name = "IP_" + n.IP.String()
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
	printRules := func() {
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
		if len(ip2addr) == 0 {
			return
		}
		l := make([]*ipNet, 0, len(ip2addr))
		for n := range ip2addr {
			l = append(l, n)
		}
		sort.Slice(l, func(i, j int) bool {
			return l[i].IP.Less(l[j].IP)
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
		if len(addrGroupMap) == 0 {
			return
		}
		l := make([]*objGroup, 0, len(addrGroupMap))
		for g := range addrGroupMap {
			l = append(l, g)
		}
		sort.Slice(l, func(i, j int) bool {
			return l[i].name < l[j].name
		})
		fmt.Fprintln(fd, "<address-group>")
		for _, g := range l {
			fmt.Fprintln(fd, `<entry name="`+g.name+`"><static>`)
			for _, n := range g.elements {
				fmt.Fprintln(fd, getAddress(n))
			}
			fmt.Fprintln(fd, "</static></entry>")
		}
		fmt.Fprintln(fd, "</address-group>")
	}
	printServices := func() {
		if len(protoMap) == 0 {
			return
		}
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
	printRules()
	printAddressGroups()
	printAddresses()
	printServices()
	fmt.Fprintln(fd, "</entry>")
	fmt.Fprintln(fd)
}

func printCombinedPanOS(fd *os.File, config []string, routerData *routerData) {

	// Build mapping from object-group name to object-group + use count.
	// Used to replace group by its elements.
	name2groupUse := make(map[string]*groupUse)
	countGroup := func(n *ipNet) {
		if n.IPPrefix.IsZero() {
			gU := name2groupUse[n.name]
			gU.count++
		}
	}

	// Collect rules belonging to same vsys.
	vsysLookup := make(map[string][]*aclInfo)
	for _, acl := range routerData.acls {
		vsysLookup[acl.vrf] = append(vsysLookup[acl.vrf], acl)
		for _, g := range acl.objectGroups {
			name2groupUse[g.name] = &groupUse{g: g}
		}
		for _, rule := range acl.rules {
			countGroup(rule.src)
			countGroup(rule.dst)
		}
	}

	// Print config and insert printed vsys configuration at aclMarker.
	for _, line := range config {
		if strings.HasPrefix(line, aclMarker) {
			// Print rules.
			vsys := line[len(aclMarker):]
			aclList := vsysLookup[vsys]
			printPanOSRules(fd, vsys, aclList, name2groupUse)
		} else {
			// Print unchanged config line.
			fmt.Fprintln(fd, line)
		}
	}
}
