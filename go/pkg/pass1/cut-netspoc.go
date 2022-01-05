package pass1

/*
=head1 NAME

cut-netspoc - Print parts of a netspoc configuration to stdout

=head1 SYNOPSIS

cut-netspoc [options] FILE|DIR [service:name] ...

=head1 DESCRIPTION

Reads a Netspoc configuration and prints parts of this configuration
to STDOUT. If one or more services are given as argument, only those
parts are printed, that are referenced by given serices. If no service
is given, it acts as if all services are specified. This is useful to
eliminate all disabled parts of the topology.

=head1 OPTIONS

=item B<-q>

Quiet, don't print status messages.

=item B<-help>

Prints a brief help message and exits.

=back

=head1 COPYRIGHT AND DISCLAIMER

(c) 2021 by Heinz Knutzen <heinz.knutzengooglemail.com>

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
	"os"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
)

var isUsed map[string]bool

func removeAttr(ref *[]*ast.Attribute, name string) {
	var l []*ast.Attribute
	for _, a := range *ref {
		if a.Name != name {
			l = append(l, a)
		}
	}
	*ref = l
}

func removeSubAttr(ref *[]*ast.Attribute, name, sub string) {
	var l []*ast.Attribute
	for _, a := range *ref {
		if a.Name == name {
			var l2 []*ast.Attribute
			for _, a2 := range a.ComplexValue {
				if a2.Name != sub {
					l2 = append(l2, a2)
				}
			}
			a.ComplexValue = l2
		}
		if a.Name != name || a.ComplexValue != nil {
			l = append(l, a)
		}
	}
	*ref = l
}

func selectBindNat(l []*ast.Value) []*ast.Value {
	var result []*ast.Value
	for _, v := range l {
		if isUsed["nat:"+v.Value] {
			result = append(result, v)
		}
	}
	return result

}

func selectReroutePermit(l []*ast.Value) []*ast.Value {
	var result []*ast.Value
	for _, v := range l {
		if isUsed[v.Value] {
			result = append(result, v)
		}
	}
	return result
}

func setRouterUsed(r *router) {
	name := r.name
	if r.ipV6 {
		name = "6" + name
	}
	isUsed[name] = true
}

func isRouterUsed(r *router) bool {
	lookup := r.name
	if r.ipV6 {
		lookup = "6" + lookup
	}
	return isUsed[lookup]
}

func setIntfUsed(intf *routerIntf) {
	iName := intf.name
	isUsed[iName] = true
	// Ignore extension if virtual interface is used as main interface.
	iName = strings.TrimSuffix(iName, ".virtual")
	isUsed[iName] = true
}

type netPathObj interface {
	intfList() intfList
	String() string
}

// This is called for each zone on path of rule.
func markTopology(ru *groupedRule, in, out *routerIntf) {
	if in != nil {
		setIntfUsed(in)
		setRouterUsed(in.router)
	}
	if out != nil {
		setIntfUsed(out)
		setRouterUsed(out.router)
	}
	mark := func(l []someObj, n2 *network) {
		for _, o := range l {
			if intf, ok := o.(*routerIntf); ok {
				setIntfUsed(intf)
				setRouterUsed(intf.router)
			}
			n1 := o.getNetwork()
			if !n1.isAggregate {
				markUnconnectedPair(n1, n2)
			}
		}
	}
	if in == nil {
		mark(ru.src, out.network)
	} else if out == nil {
		mark(ru.dst, in.network)
	} else {
		markUnconnectedPair(in.network, out.network)
	}
}

// Mark path between endpoints of rules.
func (c *spoc) markRulesPath(p pathRules) {
	for _, r := range append(p.deny, p.permit...) {
		c.pathWalk(r, markTopology, "Zone")
	}
}

// Mark path between two networks inside same zone.
func markUnconnectedPair(n1, n2 *network) {
	//debug("\nConnecting %s %s", n1, n2)
	seen := make(map[netPathObj]bool)
	var mark func(netPathObj, *routerIntf) bool
	mark = func(obj netPathObj, in *routerIntf) bool {
		if seen[obj] {
			return false
		}
		seen[obj] = true
		if obj == n2 {
			//debug("Found %s", obj)
			return true
		}
		r, isRouter := obj.(*router)
		result := false
		for _, intf := range obj.intfList() {
			if intf == in {
				continue
			}
			if intf.mainIntf != nil {
				continue
			}
			var next netPathObj
			if isRouter {
				if r.managed != "" || r.semiManaged {
					continue
				}
				next = intf.network
			} else {
				next = intf.router
			}
			if mark(next, intf) {
				isUsed[obj.String()] = true
				isUsed[intf.name] = true
				//debug("Marked %s + %s", obj, intf)
				result = true
				break
			}
		}
		return result
	}
	mark(n1, nil)
	isUsed[n2.name] = true
}

// Mark path between object and marked parts of topology.
// Mark only inside zone or zone cluster.
func markUnconnectedObj(n *network) {
	var seen map[netPathObj]bool
	var mark func(obj netPathObj, in *routerIntf) bool
	mark = func(obj netPathObj, in *routerIntf) bool {
		if seen[obj] {
			return false
		}
		seen[obj] = true
		if isUsed[obj.String()] {
			//debug("Found %s", obj)
			return true
		}
		r, isRouter := obj.(*router)
		if isRouter && r.managed != "" {
			return false
		}
		result := false
		for _, intf := range obj.intfList() {
			if intf == in {
				continue
			}
			if intf.mainIntf != nil {
				continue
			}
			var next netPathObj
			if isRouter {
				next = intf.network
			} else {
				next = intf.router
			}
			if mark(next, intf) {
				isUsed[obj.String()] = true
				isUsed[intf.name] = true
				//debug("Marked %s + %s", obj, intf)
				result = true
				break
			}
		}
		return result
	}

	//debug("\nConnecting %s", n)
	seen = make(map[netPathObj]bool)
	//mark(n, nil)
	seen[n] = true
	for _, intf := range n.interfaces {
		if intf.mainIntf != nil {
			continue
		}
		next := intf.router
		//debug("-Try %s %s", next, intf)
		if mark(next, intf) {
			isUsed[intf.name] = true
			//debug("Marked %s", intf)
			// Only mark first found path.
			break
		}
	}
	isUsed[n.name] = true
}

func (c *spoc) markCryptoPath(src, dst *routerIntf) {
	isUsed[src.name] = true
	isUsed[dst.name] = true
	//debug("Path %s %s", src, dst)
	c.singlePathWalk(src, dst, markTopology, "Zone")
}

func (c *spoc) markUsedNatTags() {
	for _, n := range c.allNetworks {
		if isUsed[n.name] {
			for tag, natNet := range n.nat {
				if !natNet.identity {
					isUsed["nat:"+tag] = true
				}
			}
		}
	}
}

// Mark used elements and substitute intersection by its expanded elements.
func (c *spoc) markAndSubstElements(
	elemList *[]ast.Element, ctx string, v6 bool, m map[string]*ast.TopList) {

	expand := func(el ast.Element) groupObjList {
		return c.expandGroup([]ast.Element{el}, ctx, v6, false)
	}
	var traverse func(l []ast.Element) []ast.Element
	traverse = func(l []ast.Element) []ast.Element {
		var expanded groupObjList
		j := 0
		for _, el := range l {
			switch x := el.(type) {
			case *ast.NamedRef:
				typedName := x.Type + ":" + x.Name
				if isUsed[typedName] {
					break
				}
				if x.Type == "group" {
					if def, found := m[typedName]; found {
						c.markAndSubstElements(&def.Elements, typedName, v6, m)
					}
				}
				isUsed[typedName] = true
			case ast.AutoElem:
				if len(expand(el)) == 0 {
					continue // Ignore empty automatic group
				}
				l2 := traverse(x.GetElements())
				x.SetElements(l2)
			case *ast.IntfRef:
				for _, obj := range expand(el) {
					switch x := obj.(type) {
					case *routerIntf:
						setIntfUsed(x)
						setRouterUsed(x.router)
					}
				}
			case *ast.Intersection:
				expanded = append(expanded, expand(el)...)
				continue // Ignore original intersection.
			}
			l[j] = el
			j++
		}
		result := l[:j]
		for _, obj := range expanded {
			name := obj.String()
			i := strings.Index(name, ":")
			// ast.NamedRef is not fully correct for IntfRef, SimpleAuto,
			// AggAuto, IntfAuto, but is printed correctly by
			// printer.print anyway.
			a := new(ast.NamedRef)
			a.Type = name[:i]
			a.Name = name[i+1:]
			result = append(result, a)
		}
		return result
	}
	*elemList = traverse(*elemList)
}

func (c *spoc) markElements(
	toplevel []ast.Toplevel, m map[string]*ast.TopList) {

	for _, top := range toplevel {
		if x, ok := top.(*ast.Service); ok {
			typedName := x.Name
			if !isUsed[typedName] {
				continue
			}
			v6 := x.IPV6
			c.markAndSubstElements(&x.User.Elements, "user of "+typedName, v6, m)
			for _, r := range x.Rules {
				c.markAndSubstElements(&r.Src.Elements, "src of "+typedName, v6, m)
				c.markAndSubstElements(&r.Dst.Elements, "dst of "+typedName, v6, m)
			}
		}
	}
}

func (c *spoc) collectGroups(toplevel []ast.Toplevel) map[string]*ast.TopList {
	m := make(map[string]*ast.TopList)
	for _, top := range toplevel {
		if x, ok := top.(*ast.TopList); ok {
			typedName := x.Name
			typ, _ := splitTypedName(typedName)
			if typ == "group" {
				m[typedName] = x
			}
		}
	}
	return m
}

func (c *spoc) cutNetspoc(path string, names []string, keepOwner bool) {
	toplevel := c.parseFiles(path)
	if len(names) > 0 {
		var copy []ast.Toplevel
		retain := make(map[string]bool)
		for i, name := range names {
			if !strings.HasPrefix(name, "service:") {
				name = "service:" + name
				names[i] = name
			}
			retain[name] = true
		}
		seen := make(map[string]bool)
		for _, top := range toplevel {
			name := top.GetName()
			if !strings.HasPrefix(name, "service:") {
				copy = append(copy, top)
			} else if retain[name] {
				copy = append(copy, top)
				seen[name] = true
			}
		}
		toplevel = copy
		for _, name := range names {
			if !seen[name] {
				c.err("Unknown %s", name)
			}
		}
	}

	c.setupTopology(toplevel)
	for _, sv := range c.ascendingServices {
		if !sv.disabled {
			isUsed[sv.name] = true
		}
	}
	c.markDisabled()
	c.setZone()
	c.setPath()
	c.distributeNatInfo()
	c.findSubnetsInZone()
	sRules := c.normalizeServices()
	permitRules, denyRules := c.convertHostsInRules(sRules)
	c.groupPathRules(permitRules, denyRules)

	c.markRulesPath(c.allPathRules)

	// Collect objects referenced from rules.
	// Use serviceRules here, to get also objects from unenforceable rules.
	collectRules := func(rules []*serviceRule) {
		for _, rule := range rules {
			collectObjects := func(group []srvObj) {
				for _, obj := range group {

					// pathWalk only handles managed routers and interfaces.
					// Mark all objects additionally here.
					markUnconnectedObj(obj.getNetwork())
					isUsed[obj.String()] = true
				}
			}
			collectObjects(rule.src)
			collectObjects(rule.dst)
		}
	}
	collectRules(sRules.permit)
	collectRules(sRules.deny)

	group2def := c.collectGroups(toplevel)
	c.markElements(toplevel, group2def)

	// Mark NAT tags referenced in networks used in rules.
	c.markUsedNatTags()

	// Mark bridge and bridged networks.
	for _, n := range c.allNetworks {
		if !isUsed[n.name] {
			continue
		}
		if n.ipType != bridgedIP {
			continue
		}
		for _, in := range n.interfaces {
			if in.ipType != bridgedIP {
				continue
			}
			isUsed[in.name] = true
			bridge := in.router
			isUsed[bridge.name] = true
			for _, out := range bridge.interfaces {
				if out.hardware.name == "device" && bridge.model.class == "ASA" {
					isUsed[out.name] = true
				} else if out.ipType == bridgedIP {
					isUsed[out.name] = true
					isUsed[out.network.name] = true
				}
			}
		}
	}

	zoneUsed := make(map[*zone]bool)
	zoneCheck := make(map[*zone]bool)
	for _, z := range c.allZones {
		for _, agg := range z.ipPrefix2aggregate {
			if !isUsed[agg.name] {
				continue
			}
			zoneUsed[agg.zone] = true
			zoneCheck[agg.zone] = true
			// debug("Marking networks of %s in %s", agg, z")
			for _, n := range agg.networks {
				markUnconnectedObj(n)
			}
		}
	}

	// Mark zones having attributes that influence their networks.
	for _, n := range c.allNetworks {
		if !isUsed[n.name] {
			continue
		}
		z := n.zone
		zoneCheck[z] = true
		if len(z.nat) == 0 {
			continue
		}
		ipp := getNetwork00(z.ipV6).ipp
		if agg0 := z.ipPrefix2aggregate[ipp]; agg0 != nil {
			isUsed[agg0.name] = true
		}
		zoneUsed[z] = true
	}

	for _, agg := range c.allNetworks {
		if agg.isAggregate && isUsed[agg.name] {
			if n := agg.link; n != nil {
				markUnconnectedObj(n)
			} else {
				// Find network name from name of zone: any:[network:name]
				z := agg.zone
				zName := z.name
				nName := zName[len("any:[") : len(zName)-1]
				for _, n := range z.networks {
					if n.name == nName {
						markUnconnectedObj(n)
						break
					}
				}
			}
		}
	}

	zone2areas := make(map[*zone][]*area)
	for _, z := range c.allZones {
		a := z.inArea
		for a != nil {
			zone2areas[z] = append(zone2areas[z], a)
			a = a.inArea
		}
	}

	// Mark areas having NAT attribute that influence their networks.
	for z := range zoneCheck {
		for _, a := range zone2areas[z] {
			att := a.routerAttributes
			if len(a.nat) != 0 ||
				keepOwner && (a.owner != nil || att != nil && att.owner != nil) {

				isUsed[a.name] = true
			}
		}
	}

	for _, top := range toplevel {
		if aTop, ok := top.(*ast.Area); ok {
			name := aTop.Name[len("area:"):]
			a := symTable.area[name]
			if isUsed[a.name] {
				// Change anchor to some used network
				if anchor := a.anchor; anchor != nil {
					if !isUsed[anchor.name] {
					ZONE:
						for _, z := range a.zones {
							for _, n := range z.networks {
								if isUsed[n.name] {
									for _, at := range aTop.Attributes {
										if at.Name == "anchor" {
											at.ValueList = []*ast.Value{{Value: n.name}}
											break ZONE
										}
									}
								}
							}
						}
					}
				} else {
					// Remove unused interfaces from border and inclusiveBorder
					cleanup := func(u **ast.NamedUnion) {
						if *u == nil {
							return
						}
						j := 0
						l := (*u).Elements
						for _, el := range l {
							if x, ok := el.(*ast.IntfRef); ok {
								if x.Network != "[" && x.Extension == "" {
									name := "interface:" + x.GetName()
									if !isUsed[name] {
										continue
									}
								}
							}
							l[j] = el
							j++
						}
						l = l[:j]
						if len(l) == 0 {
							*u = nil
						} else {
							(*u).Elements = l
						}
					}
					cleanup(&aTop.Border)
					cleanup(&aTop.InclusiveBorder)
					// Add anchor, if all interfaces have been removed.
					if aTop.Border == nil && aTop.InclusiveBorder == nil {
					Z2:
						for _, z := range a.zones {
							for _, n := range z.networks {
								if isUsed[n.name] {
									aTop.Attributes = append(aTop.Attributes,
										&ast.Attribute{
											Name:      "anchor",
											ValueList: []*ast.Value{{Value: n.name}},
										})
									break Z2
								}
							}
						}
					}
				}
			}
		}
	}

	// Mark networks having NAT attributes that influence their subnets.
	for _, n := range c.allNetworks {
		if !isUsed[n.name] {
			continue
		}
		up := n
		var upChain netList

		// Walk chain of inheritance.
		// Mark supernet with NAT attribute and also all supernets in between.
		// We need to mark supernets in between, because they might have
		// identity NAT attributes, which have been deleted already.
		for {
			up = up.up
			if up == nil {
				break
			}
			if up.isAggregate {
				if up.ipp.Bits() != 0 {
					continue
				}
				z := up.zone

				// Check if NAT attribute was inherited from zone or areas.
				if !zoneUsed[z] {
					found := false
					for _, a := range zone2areas[z] {
						if isUsed[a.name] {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}
			} else {
				upChain.push(up)
				if up.nat == nil {
					continue
				}
			}
			for _, supernet := range upChain {
				markUnconnectedObj(supernet)
				// debug("marked: %s", supernet)
			}
			upChain = nil
		}
	}

	// Call this after topology has been marked.
	c.expandCrypto()

	mark1 := func(r *router) {

		// Mark split router, if some split part is marked.
		for _, intf := range getIntf(r) {
			fragment := intf.router
			if fragment == r {
				continue
			}
			if isRouterUsed(fragment) {
				// debug("From split: %s", r)
				setRouterUsed(r)
			}
		}

		if !isRouterUsed(r) {
			return
		}

		// Mark fragments of marked crypto routers.
		for _, intf := range getIntf(r) {
			fragment := intf.router
			if fragment == r {
				continue
			}
			// debug("Fragment: %s", fragment)
			setRouterUsed(fragment)
		}

		for _, intf := range getIntf(r) {
			if !isUsed[intf.name] {
				continue
			}

			// Mark path of crypto tunnel.
			if intf.ipType == tunnelIP {
				peer := intf.peer
				real := intf.realIntf
				c.markCryptoPath(real, peer.realIntf)
			}
		}
	}
	for _, r := range c.allRouters {
		mark1(r)
	}

	mark2 := func(r *router) {
		if !isRouterUsed(r) {
			return
		}
		for _, intf := range getIntf(r) {
			if !isUsed[intf.name] {
				continue
			}

			// Mark main interface of secondary or virtual interface.
			if main := intf.mainIntf; main != nil {
				isUsed[main.name] = true
			}
			if main := intf.origMain; main != nil {
				isUsed[main.name] = true
			}

			// Mark crypto definitions which are referenced by
			// already marked interfaces.
			for _, crypto := range intf.hub {
				isUsed[crypto.name] = true
				typ := crypto.ipsec
				isUsed[typ.name] = true
				isUsed[typ.isakmp.name] = true
			}

			// Mark networks referenced by interfaces
			// marked by markAndSubstElements.
			if isUsed[intf.name] {
				isUsed[intf.network.name] = true
			}
		}
	}
	for _, r := range c.allRouters {
		mark2(r)
	}

	// Collect names of marked areas, groups, protocols, protocolgroups.
	// Collect names of marked owners.
	markOwner := func(o *owner) {
		if keepOwner && o != nil {
			isUsed[o.name] = true
		}
	}
	for _, a := range symTable.area {
		if isUsed[a.name] {
			markOwner(a.owner)

		}
	}
	for _, p := range symTable.protocol {
		if p.isUsed {
			isUsed[p.name] = true
		}
	}
	for _, p := range symTable.protocolgroup {
		if p.isUsed {
			isUsed[p.name] = true
		}
	}

	// Collect names of marked networks, aggregates, routers, interfaces.
	for _, n := range c.allNetworks {
		if isUsed[n.name] {
			markOwner(n.owner)
			added := false
			for _, h := range n.hosts {
				if isUsed[h.name] {
					added = true
					markOwner(h.owner)
				}
			}

			// Retain at least one host of network with ID hosts.
			if n.hasIdHosts && !added && len(n.hosts) > 0 {
				isUsed[n.hosts[0].name] = true
			}
		}
	}
	markRouter := func(r *router) {
		if isRouterUsed(r) {
			markOwner(r.owner)
			for _, intf := range getIntf(r) {
				if isUsed[intf.name] {
					setIntfUsed(intf)
					markOwner(intf.owner)
				}
			}
		}
	}
	for _, r := range c.allRouters {
		markRouter(r)
	}
	if keepOwner {
		for _, sv := range c.ascendingServices {
			markOwner(sv.subOwner)
		}
	}

	// Source of pathrestrictions can't be used literally,
	// but must be reconstructed from internal data structure.
	name2pathrestriction := make(map[string]*ast.TopList)
	for _, pr := range c.pathrestrictions {
		elemList := pr.elements
		var l []ast.Element
		for _, intf := range elemList {
			if isUsed[intf.name] {
				n := new(ast.IntfRef)
				n.Type = "interface"
				n.Router = intf.router.name[len("router:"):]
				n.Network = intf.network.name[len("network:"):]
				if l := strings.Split(intf.name, "."); len(l) == 3 {
					n.Extension = l[2]
				}
				l = append(l, n)
			}
		}
		if len(l) < 2 {
			continue
		}
		n := new(ast.TopList)
		name := pr.name
		n.Name = name
		n.Elements = l
		isUsed[name] = true
		name2pathrestriction[name] = n
	}

	removeOwner := func(ref *[]*ast.Attribute) {
		if !keepOwner {
			removeAttr(ref, "owner")
		}
	}

	selectHosts := func(n *ast.Network) {
		nName := n.Name[len("network:"):]
		var l []*ast.Attribute
		for _, a := range n.Hosts {
			hName := a.Name
			if strings.HasPrefix(hName, "host:id:") {
				hName += "." + nName
			}
			if isUsed[hName] {
				l = append(l, a)
				removeOwner(&a.ComplexValue)
			}
		}
		n.Hosts = l
	}

	selectInterfaces := func(n *ast.Router) {
		name := "interface:" + n.Name[len("router:"):] + "."
		var l []*ast.Attribute
		for _, a := range n.Interfaces {
			if isUsed[name+a.Name[len("interface:"):]] {
				l = append(l, a)
				attrList := a.ComplexValue
				j := 0
				for _, a2 := range attrList {
					l2 := a2.ValueList
					changed := false
					switch a2.Name {
					case "bind_nat":
						l2 = selectBindNat(l2)
						changed = true
					case "reroute_permit":
						l2 = selectReroutePermit(l2)
						changed = true
					case "owner":
						if !keepOwner {
							l2 = nil
							changed = true
						}
					}
					if !changed || l2 != nil {
						a2.ValueList = l2
						attrList[j] = a2
						j++
					}
				}
				a.ComplexValue = attrList[:j]
			}
		}
		n.Interfaces = l
	}

	// Print marked parts of netspoc configuration.
	// Routers and networks have been marked by markTopology.
	// Protocols have been marked while pathRules have been processed above.
	// Groups and protocolroups objects have been marked during NormalizeServices.
	var active []ast.Toplevel

	for _, top := range toplevel {
		typedName := top.GetName()
		ipv6 := top.GetIPV6()
		lookup := typedName
		if strings.HasPrefix(typedName, "router:") && ipv6 {
			lookup = "6" + lookup
		}
		if !isUsed[lookup] {
			continue
		}
		typ, _ := splitTypedName(typedName)
		switch x := top.(type) {
		case *ast.Network:
			removeOwner(&x.Attributes)
			selectHosts(x)
		case *ast.Router:
			removeOwner(&x.Attributes)
			removeAttr(&x.Attributes, "policy_distribution_point")
			selectInterfaces(x)
		case *ast.Area:
			removeOwner(&x.Attributes)
			removeSubAttr(&x.Attributes,
				"router_attributes", "policy_distribution_point")
			if !keepOwner {
				removeSubAttr(&x.Attributes, "router_attributes", "owner")
			}
		case *ast.TopStruct:
			if typ == "any" {
				removeOwner(&x.Attributes)
			}
		case *ast.TopList:
			switch typ {
			case "pathrestriction":
				top = name2pathrestriction[typedName]
			}
		case *ast.Service:
			if !keepOwner {
				removeAttr(&x.Attributes, "sub_owner")
			}
		}
		active = append(active, top)
	}
	f := new(ast.File)
	f.Nodes = active
	out := printer.File(f)
	os.Stdout.Write(out)
}

func CutNetspocMain() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR [service:name ...]\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't print progress messages")
	ipv6 := fs.BoolP("ipv6", "6", false, "Expect IPv6 definitions")
	keepOwner := fs.BoolP("owner", "o", false, "Keep referenced owners")
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
	services := args[1:]

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
		fmt.Sprintf("--ipv6=%v", *ipv6),
		"--max_errors=9999",
	}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Initialize global variables.
	isUsed = make(map[string]bool)

	return toplevelSpoc(func(c *spoc) {
		c.cutNetspoc(path, services, *keepOwner)
	})
}
