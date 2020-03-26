package pass1

/*
=head1 NAME

print-group - Show elements of a netspoc group definition

=head1 SYNOPSIS

print-group [options] FILE|DIR ["group:name,..."]

=head1 DESCRIPTION

This program prints the elements of one || more netspoc group
definitions.  By default it reads a group definition from command line
&& shows a line with IP/prefixlen && name for each element separated
by tab character. Group is a simple group, some automatic group, || a
union || intersection || complement of simpler groups.

With option B<-f>, group definitions are read from a file with a
single group definition per line. In the output, a comment line is
prepended to elements of each group. The format of this comment line
is a B<#> character followed by the corresponding input line.

=head1 OPTIONS

=over 4

=item B<-nat> name

Uses network:name as reference when resolving IP address in a NAT environment.

=item B<-unused>

Show only elements ! used in any rules.

=item B<-name>

Show only name of elements.

=item B<-ip>

Show only IP address of elements.

=item B<-owner>

Show owner of elements.

=item B<-ipv6>

Expect IPv6 definitions everywhere except in subdirectory "ipv4/".

=item B<-f> FILE

Read group definitions from FILE, one definition per line.
If B<-> is specified, read from standard input.

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
	"bytes"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"io"
	"net"
	"os"
	"sort"
	"strings"
)

// Print IP address of obj in context of natSet.
func printAddress(obj groupObj, ns natSet) string {
	netAddr := func(n *network) string {
		return prefixCode(net.IPNet{IP: n.ip, Mask: n.mask})
	}
	dynamicAddr := func(m map[string]net.IP, n *network) string {
		tag := n.natTag
		if ip := m[tag]; ip != nil {

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
	natAddr := func(ip net.IP, n *network) string {
		l := len(n.ip)
		natIP := make(net.IP, l)
		for i := 0; i < l; i++ {
			natIP[i] = n.ip[i] | ip[i] & ^n.mask[i]
		}
		return natIP.String()
	}

	switch x := obj.(type) {
	case *network:
		n := getNatNetwork(x, ns)
		if n.unnumbered {
			return "unnumbered"
		}
		if n.hidden {
			return "hidden"
		}
		return netAddr(n)
	case *host:
		n := getNatNetwork(x.network, ns)
		if n.dynamic {
			return dynamicAddr(x.nat, n)
		}
		if ip := x.ip; ip != nil {
			return natAddr(ip, n)
		}
		return natAddr(x.ipRange[0], n) + "-" + natAddr(x.ipRange[1], n)
	case *routerIntf:
		n := getNatNetwork(x.network, ns)
		if n.dynamic {
			return dynamicAddr(x.nat, n)
		}
		if x.unnumbered {
			return "unnumbered"
		}
		if x.short {
			return "short"
		}
		if x.bridged {
			return "bridged"
		}
		if x.negotiated {

			// Take whole network.
			return netAddr(n)
		}
		return natAddr(x.ip, n)
	case *autoIntf:
		return "unknown"
	}
	return ""
}

func captureStderr(f func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	stderr := os.Stderr
	os.Stderr = w
	defer func() {
		os.Stderr = stderr
	}()

	f()

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// Try to expand group as IPv4 or IPv6, but don't abort on error.
func tryExpand(parsed []*parsedObjRef, ipv6 bool) (groupObjList, string) {
	var expanded groupObjList
	conf.Conf.MaxErrors = 9999
	ErrorCounter = 0
	stderr := captureStderr(func() {
		expanded = expandGroup(parsed, "print-group", ipv6, true)
	})
	if ErrorCounter > 0 {
		return nil, stderr
	} else {
		return expanded, ""
	}
}

func PrintGroup(m xMap) {

	DistributeNatInfo()
	FindSubnetsInZone()
	AbortOnError()
	natNet := getString(m["nat_net"])
	parsed := convParsedObjRefs(m["parsed"])
	showIP := getBool(m["show_ip"])
	showName := getBool(m["show_name"])
	showOwner := getBool(m["show_owner"])
	showUnused := getBool(m["show_unused"])

	// Find network for resolving NAT addresses.
	var natSet natSet
	if natNet != "" {
		natNet = strings.TrimPrefix(natNet, "network:")
		if net := networks[natNet]; net != nil {
			natSet = net.zone.natDomain.natSet
		} else {
			abort.Msg("Unknown network:%s of option '-nat'", natNet)
		}
	} else {

		// Create empty NAT set.
		var m map[string]bool
		natSet = &m
	}

	// Prepare finding unused objects by marking used objects.
	used := make(map[groupObj]bool)
	if showUnused {
		NormalizeServices()
		AbortOnError()
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

	if showOwner {
		propagateOwners()
	}

	// Expand group definition.
	// We don't know if this expands to IPv4 or IPv6 addresses,
	// so we try both  IPv4 and IPv6.
	elements, msg := tryExpand(parsed, true)
	if elements == nil {
		elements, msg = tryExpand(parsed, false)
	}
	if elements == nil {
		abort.Msg(msg)
	}

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

	// Collect IP address, name, owner.
	type objInfo struct {
		addr  string
		name  string
		owner string
	}
	infoList := make([]objInfo, len(elements))
	for i, ob := range elements {
		info := objInfo{
			addr: printAddress(ob, natSet),
			name: ob.String(),
		}
		if showOwner {
			var ow *owner
			switch x := ob.(type) {
			case srvObj:
				ow = x.getOwner()
			case *area:
				ow = x.owner
			}
			if ow != nil {
				info.owner = ow.name
			} else {
				info.owner = "none"
			}
		}
		infoList[i] = info
	}

	// Sort by printed IP address.
	sort.SliceStable(infoList, func(i, j int) bool {
		return infoList[i].addr < infoList[j].addr
	})

	// Print results.
	for _, info := range infoList {
		var result stringList
		if showIP {
			result.push(info.addr)
		}
		if showName {
			result.push(info.name)
		}
		if showOwner {
			result.push(info.owner)
		}
		fmt.Println(strings.Join(result, "\t"))
	}
}
