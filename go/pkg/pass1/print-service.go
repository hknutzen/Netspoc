package pass1

/*
=head1 NAME

print-service - Show info about a netspoc service definition

=head1 SYNOPSIS

print-service [options] FILE|DIR [SERVICE-NAME]

=head1 DESCRIPTION

This program prints expanded rules about all or a single netspoc
service definition.
Output format is
service-name:permit|deny src-ip dst-ip protocol-description

=head1 OPTIONS

=over 4

=item B<-nat> name

Uses network:name as reference when resolving IP address in a NAT environment.

=item B<-name>

Show name, not IP of elements.

=item B<-ipv6>

Expect IPv6 definitions everywhere except in subdirectory "ipv4/".

=item B<-quiet>

Don't print progress messages.

=item B<-help>

Prints a brief help message && exits.

=item B<-man>

Prints the manual page && exits.

=back

=head1 COPYRIGHT AND DISCLAIMER

(c) 2021 by Heinz Knutzen <heinz.knutzengooglemail.com>

This program uses modules of Netspoc, a Network Security Policy Compiler.
http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/spf13/pflag"
	"os"
	"sort"
	"strconv"
	"strings"
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
	path string, srvNames []string, natNet string, showName bool) {

	c.readNetspoc(path)
	c.markDisabled()
	c.setZone()
	c.setPath()
	c.distributeNatInfo()
	c.stopOnErr()

	// Find network for resolving NAT addresses or use empty map.
	var natMap natMap
	if natNet != "" {
		natNet = strings.TrimPrefix(natNet, "network:")
		if net := symTable.network[natNet]; net != nil {
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
		if _, found := symTable.service[name]; !found {
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
		if showName {
			return obj.String()
		}
		return prefixCode(obj.address(natMap))
	}

	names := make(stringList, 0, len(s2rules))
	for name, _ := range s2rules {
		names.push(name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, r := range s2rules[name] {
			action := "permit"
			if r.deny {
				action = "deny"
			}
			srcInfo := objInfo(r.src)
			dstInfo := objInfo(r.dst)
			prtInfo := prtInfo(r.srcRange, r.prt)
			fmt.Printf("%s:%s %s %s %s\n",
				name, action, srcInfo, dstInfo, prtInfo)
		}
	}
}

func PrintServiceMain() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR [SERVICE-NAME ...]\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't print progress messages")
	ipv6 := fs.BoolP("ipv6", "6", false, "Expect IPv6 definitions")

	nat := fs.String("nat", "",
		"Use network:name as reference when resolving IP address")
	name := fs.BoolP("name", "n", false, "Show name, not IP of elements")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
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

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
		fmt.Sprintf("--ipv6=%v", *ipv6),
	}
	conf.ConfigFromArgsAndFile(dummyArgs, path)
	return toplevelSpoc(func(c *spoc) {
		c.printService(path, names, *nat, *name)
	})
}
