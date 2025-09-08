package pass1

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/spf13/pflag"
)

// Print IP address of obj in context of natMap.
func printAddress(obj groupObj, nm natMap) string {
	netAddr := func(n *network) string {
		return prefixCode(n.ipp)
	}
	dynamicAddr := func(m map[string]netip.Addr, n *network) string {
		tag := n.natTag
		if ip, found := m[tag]; found {

			// Single static NAT IP for this object.
			return ip.String()
		} else if n.hidden {
			return "hidden"
		} else {

			// Dynamic NAT, take whole network.
			return netAddr(n)
		}
	}

	// Take higher bits from network NAT, lower bits from original IP.
	// This works with and without NAT.
	natAddr := func(ip netip.Addr, n *network) string {
		return mergeIP(ip, n).String()
	}

	switch x := obj.(type) {
	case *network:
		n := getNatNetwork(x, nm)
		if n.ipType == unnumberedIP {
			return "unnumbered"
		}
		if n.hidden {
			return "hidden"
		}
		return netAddr(n)
	case *host:
		n := getNatNetwork(x.network, nm)
		if n.dynamic {
			return dynamicAddr(x.nat, n)
		}
		if ip := x.ip; ip.IsValid() {
			return natAddr(ip, n)
		}
		return natAddr(x.ipRange.From(), n) + "-" + natAddr(x.ipRange.To(), n)
	case *routerIntf:
		n := getNatNetwork(x.network, nm)
		if n.dynamic {
			return dynamicAddr(x.nat, n)
		}
		switch x.ipType {
		case unnumberedIP:
			return "unnumbered"
		case shortIP:
			return "short"
		case bridgedIP:
			return "bridged"
		case negotiatedIP:
			// Take whole network.
			return netAddr(n)
		}
		return natAddr(x.ip, n)
	case *autoIntf:
		return "unknown"
	}
	return ""
}

func (c *spoc) printGroup(
	stdout io.Writer,
	path, group, natNet string,
	showIP, showName, showOwner, showAdmins, showUnused bool) {

	if !(showIP || showName) {
		showIP = true
		showName = true
	}
	parsed, err := parser.ParseUnion([]byte(group))
	if err != nil {
		c.abort("%v", err)
	}
	c.readNetspoc(path)
	c.setZone()
	c.stopOnErr()

	// Find network for resolving NAT addresses.
	var natMap natMap
	if natNet != "" {
		c.distributeNatInfo()
		c.stopOnErr()
		natNet = strings.TrimPrefix(natNet, "network:")
		if net := c.symTable.network[natNet]; net != nil {
			natMap = net.zone.natDomain.natMap
		} else {
			c.abort("Unknown network:%s of option '--nat'", natNet)
		}
	}

	// Prepare finding unused objects by marking used objects.
	used := make(map[groupObj]bool)
	if showUnused {
		c.setPath()
		sRules := c.normalizeServices()
		c.stopOnErr()
		process := func(rules []*serviceRule) {
			for _, rule := range rules {
				processObjects := func(group []srvObj) {
					for _, obj := range group {
						if gOb, ok := obj.(groupObj); ok {
							used[gOb] = true
						}
						switch x := obj.(type) {
						case *host:
							used[x.network] = true
						case *routerIntf:
							used[x.network] = true
						case *network:
							if x.hasIdHosts {
								for _, h := range x.hosts {
									used[h] = true
								}
							}
						}
					}
				}
				processObjects(rule.src)
				processObjects(rule.dst)
			}
		}
		process(sRules.permit)
		process(sRules.deny)
	}

	// Expand group definition.
	elements := c.expandGroup(parsed, "print-group", true)

	if showUnused {
		j := 0
		for _, ob := range elements {
			if !used[ob] {
				elements[j] = ob
				j++
			}
		}
		elements = elements[:j]
	}

	// Print IP address, name, owner, admins.
	//
	// Duplicate lines can result from
	// - combined IPv4/IPv6 objects and
	// - duplicated zones in zone cluster.
	seen := make(map[string]bool)
	for _, ob := range elements {
		var result stringList
		if showIP {
			result.push(printAddress(ob, natMap))
		}
		if showName {
			result.push(ob.String())
		}
		if showOwner || showAdmins {
			var ow *owner
			switch x := ob.(type) {
			case srvObj:
				ow = x.getOwner()
			case *area:
				ow = x.owner
			}
			oName := "none"
			admins := ""
			if ow != nil {
				oName = ow.name
				admins = strings.Join(ow.admins, ",")
			}
			if showOwner {
				result.push(oName)
			}
			if showAdmins {
				result.push(admins)
			}
		}
		line := strings.Join(result, "\t")
		if !seen[line] {
			fmt.Fprintln(stdout, line)
			seen[line] = true
		}
	}
}

func PrintGroupMain(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR 'group:name,...'\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't print progress messages")

	nat := fs.String("nat", "",
		"Use network:name as reference when resolving IP address")
	unused := fs.BoolP("unused", "u", false,
		"Show only elements not used in any rules")
	name := fs.BoolP("name", "n", false, "Show only name of elements")
	ip := fs.BoolP("ip", "i", false, "Show only IP address of elements")
	owner := fs.BoolP("owner", "o", false, "Show owner of elements")
	admins := fs.BoolP("admins", "a", false,
		"Show admins of elements as comma separated list")
	if err := fs.Parse(d.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		fs.Usage()
		return 1
	}

	// Argument processing
	args := fs.Args()
	if len(args) != 2 {
		fs.Usage()
		return 1
	}
	path := args[0]
	group := args[1]

	cnf := conf.ConfigFromFile(path)
	cnf.Quiet = *quiet
	return toplevelSpoc(d, cnf, func(c *spoc) {
		c.printGroup(
			d.Stdout, path, group, *nat, *ip, *name, *owner, *admins, *unused)
	})
}
