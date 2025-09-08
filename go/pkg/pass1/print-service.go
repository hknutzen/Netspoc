package pass1

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/spf13/pflag"
)

func prtInfo(srcRange, prt *proto) string {
	ptype := prt.proto
	desc := ptype
	switch ptype {
	case "tcp", "udp":
		portCode := func(rangeObj *proto) string {
			v1, v2 := rangeObj.ports[0], rangeObj.ports[1]
			if v1 == v2 {
				return strconv.Itoa(v1)
			} else if v1 == 1 && v2 == 65535 {
				return ""
			} else {
				return strconv.Itoa(v1) + "-" + strconv.Itoa(v2)
			}
		}
		var sport string
		if srcRange != nil {
			sport = portCode(srcRange)
		}
		dport := portCode(prt)
		if sport != "" {
			desc += " " + sport + ":" + dport
		} else if dport != "" {
			desc += " " + dport
		}
	case "icmp", "icmpv6":
		if t := prt.icmpType; t != -1 {
			s := strconv.Itoa(t)
			if c := prt.icmpCode; c != -1 {
				desc += " " + s + "/" + strconv.Itoa(c)
			} else {
				desc += " " + s
			}
		}
	}
	return desc
}

func (c *spoc) printService(
	stdout io.Writer,
	path string,
	srvNames []string, natNet string, showName bool, showIP bool) {

	c.readNetspoc(path)
	c.setZone()
	c.setPath()
	c.distributeNatInfo()
	c.stopOnErr()

	if !(showIP || showName) {
		showIP = true
		showName = false
	}

	// Find network for resolving NAT addresses or use empty map.
	var natMap natMap
	if natNet != "" {
		natNet = strings.TrimPrefix(natNet, "network:")
		if net := c.symTable.network[natNet]; net != nil {
			natMap = net.zone.natDomain.natMap
		} else {
			c.abort("Unknown network:%s of option '--nat'", natNet)
		}
	}

	sRules := c.normalizeServices()
	permitRules, denyRules := c.convertHostsInRules(sRules)
	c.stopOnErr()

	nameMap := make(map[string]bool)
	for _, name := range srvNames {
		name = strings.TrimPrefix(name, "service:")
		if _, found := c.symTable.service[name]; !found {
			c.abort("Unknown service:%s", name)
		}
		nameMap[name] = true
	}

	// Collect expanded rules.
	type rule struct {
		deny     bool
		src      someObj
		dst      someObj
		srcRange *proto
		prt      *proto
	}
	s2rules := make(map[string][]rule)
	// Remove duplicates resulting from aggregates of zone cluster.
	uniq := func(l []someObj) []someObj {
		var prev string
		j := 0
		for _, ob := range l {
			if n, ok := ob.(*network); ok {
				if n.name == prev {
					continue
				}
				prev = n.name
			}
			l[j] = ob
			j++
		}
		return l[:j]
	}
	collect := func(rules ruleList) {
		for _, r := range rules {
			sName := r.rule.service.name
			sName = strings.TrimPrefix(sName, "service:")
			if len(nameMap) != 0 && !nameMap[sName] {
				continue
			}
			sList := uniq(r.src)
			dList := uniq(r.dst)
			for _, src := range sList {
				for _, dst := range dList {
					for _, prt := range r.prt {
						s2rules[sName] = append(
							s2rules[sName],
							rule{
								deny:     r.deny,
								src:      src,
								dst:      dst,
								srcRange: r.srcRange,
								prt:      prt})
					}
				}
			}
		}
	}
	collect(denyRules)
	collect(permitRules)

	objInfo := func(obj someObj) string {
		var result stringList
		if showIP {
			result.push(prefixCode(obj.address(natMap)))
		}
		if showName {
			result.push(obj.String())
		}
		return strings.Join(result, " ")
	}

	for _, name := range slices.Sorted(maps.Keys(s2rules)) {
		for _, r := range s2rules[name] {
			action := "permit"
			if r.deny {
				action = "deny"
			}
			srcInfo := objInfo(r.src)
			dstInfo := objInfo(r.dst)
			prtInfo := prtInfo(r.srcRange, r.prt)
			fmt.Fprintf(stdout, "%s:%s %s %s %s\n",
				name, action, srcInfo, dstInfo, prtInfo)
		}
	}
}

func PrintServiceMain(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR [SERVICE-NAME ...]\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't print progress messages")

	nat := fs.String("nat", "",
		"Use network:name as reference when resolving IP address")
	name := fs.BoolP("name", "n", false, "Show only name of elements")
	ip := fs.BoolP("ip", "i", false, "Show only IP address of elements")
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
	if len(args) == 0 {
		fs.Usage()
		return 1
	}
	path := args[0]
	names := args[1:]

	cnf := conf.ConfigFromFile(path)
	cnf.Quiet = *quiet
	return toplevelSpoc(d, cnf, func(c *spoc) {
		c.printService(d.Stdout, path, names, *nat, *name, *ip)
	})
}
