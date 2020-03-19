package pass1

/*
=head1 NAME

print-service - Show info about a netspoc service definition

=head1 SYNOPSIS

print-service [options] FILE|DIR [SERVICE-NAME]

=head1 DESCRIPTION

This program prints expanded rules about all || a single netspoc
service definition.
Output format is
service-name:permit|deny src-ip dst-ip protocol-description

=head1 OPTIONS

=over 4

=item B<-nat> name

Uses network:name as reference when resolving IP address in a NAT environment.

=item B<-name>

Show name, ! IP of elements.

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

(c) 2020 by Heinz Knutzen <heinz.knutzengooglemail.com>

This program uses modules of Netspoc, a Network Security Policy Compiler.
http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it &&/|| modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, ||
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY || FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if !, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
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
	case "icmp":
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

func PrintService(m xMap) {

	DistributeNatInfo()
	FindSubnetsInZone()
	AbortOnError()
	natNet := getString(m["nat_net"])
	showName := getBool(m["show_name"])
	srvNames := getStrings(m["service_names"])

	// Find network for resolving NAT addresses.
	var natSet natSet
	if natNet != "" {
		natNet = strings.TrimPrefix(natNet, "network:")
		if net := networks[natNet]; net != nil {
			natSet = net.zone.natDomain.natSet
		} else {
			abort.Msg("Unknown network:%s of option '-n'", natNet)
		}
	} else {

		// Create empty NAT set.
		var m map[string]bool
		natSet = &m
	}


	NormalizeServices()
	permitRules, denyRules := ConvertHostsInRules()
	GroupPathRules(permitRules, denyRules)
	AbortOnError()

	nameMap := make(map[string]bool)
	for _, name := range srvNames {
		nameMap[name] = true;
	}

	// Collect expanded rules.
	type rule struct {
		deny bool
		src someObj
		dst someObj
		srcRange *proto
		prt *proto
	}
	s2rules := make(map[string][]rule)
	collect := func(rules ruleList) {
		for _, r := range rules {
			sName := r.rule.service.name
			sName = strings.TrimPrefix(sName, "service:")
			if len(nameMap) != 0 {
				if !nameMap[sName] { continue }
			}
			for _, src := range r.src {
				for _, dst := range r.dst {
					for _, prt := range r.prt {
						s2rules[sName] = append(
							s2rules[sName],
							rule{
								deny: r.deny,
								src: src,
								dst: dst,
								srcRange: r.srcRange,
								prt: prt })
					}
				}
			}
		}
	}
	collect(pRules.deny)
	collect(pRules.permit)

	objInfo := func(obj someObj) string {
		if showName {
			return obj.String()
		}
		return prefixCode(obj.address(natSet))
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
