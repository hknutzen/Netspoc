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

(c) 2025 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
)

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

func setRouterUsed(r *router, isUsed map[string]bool) {
	isUsed[r.name] = true
}

func isRouterUsed(r *router, isUsed map[string]bool) bool {
	return isUsed[r.name]
}

func setIntfUsed(intf *routerIntf, isUsed map[string]bool) {
	iName := intf.name
	isUsed[iName] = true
	// Ignore extension if virtual interface is used as main interface.
	iName = strings.TrimSuffix(iName, ".virtual")
	isUsed[iName] = true
}

func (c *spoc) saveOrigNat(origNat map[*network]natTagMap) {
	copyNat := func(n *network) {
		if nat := n.nat; nat != nil {
			origNat[n] = maps.Clone(nat)
		}
	}
	for _, n := range c.symTable.network {
		copyNat(n)
	}
	for _, agg := range c.symTable.aggregate {
		copyNat(agg)
	}
}

type netPathObj interface {
	intfList() intfList
	String() string
}

// This is called for each zone on path of rule.
func markTopology(
	ru *groupedRule, in, out *routerIntf, isUsed map[string]bool) {

	if in != nil {
		setIntfUsed(in, isUsed)
		setRouterUsed(in.router, isUsed)
	}
	if out != nil {
		setIntfUsed(out, isUsed)
		setRouterUsed(out.router, isUsed)
	}
	mark := func(l []someObj, n2 *network) {
		for _, o := range l {
			if intf, ok := o.(*routerIntf); ok {
				setIntfUsed(intf, isUsed)
				setRouterUsed(intf.router, isUsed)
			}
			n1 := o.getNetwork()
			if !n1.isAggregate {
				markUnconnectedPair(n1, n2, isUsed)
			}
		}
	}
	if in == nil {
		mark(ru.src, out.network)
	} else if out == nil {
		mark(ru.dst, in.network)
	} else {
		markUnconnectedPair(in.network, out.network, isUsed)
	}
}

// Mark path between endpoints of rules.
func (c *spoc) markRulesPath(p pathRules, isUsed map[string]bool) {
	for _, r := range append(p.deny, p.permit...) {
		c.pathWalk(r, func(ru *groupedRule, in, out *routerIntf) {
			markTopology(r, in, out, isUsed)
		}, "Zone")
	}
}

// Mark path between two networks inside same zone.
func markUnconnectedPair(n1, n2 *network, isUsed map[string]bool) {
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
				if isRouter {
					setRouterUsed(obj.(*router), isUsed)
				} else {
					isUsed[obj.String()] = true
				}
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
func markUnconnectedObj(n *network, isUsed map[string]bool) {
	var seen map[netPathObj]bool
	var mark func(obj netPathObj, in *routerIntf) bool
	mark = func(obj netPathObj, in *routerIntf) bool {
		if seen[obj] {
			return false
		}
		seen[obj] = true
		// If we connect an IPv6 network, it isn't sufficient to find a
		// used IPv4 part of a dual stack network. The corresponding
		// IPv6 part may still be unconnected. Hence check the
		// interfaces.
		if slices.ContainsFunc(obj.intfList(), func(intf *routerIntf) bool {
			return isUsed[intf.name]
		}) {
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
			var next netPathObj
			if isRouter {
				next = intf.network
			} else {
				next = intf.router
			}
			if mark(next, intf) {
				isUsed[obj.String()] = true
				isUsed[intf.name] = true
				result = true
				break
			}
		}
		return result
	}

	seen = make(map[netPathObj]bool)
	if n.isAggregate {
		isUsed[n.name] = true
		if l := n.link; l != nil {
			n = l
		} else {
			n = n.zone.interfaces[0].network
		}
		//debug("->Connecting %s", n)
	}
	mark(n, nil)
}

func (c *spoc) markPath(src, dst *routerIntf, isUsed map[string]bool) {
	isUsed[src.name] = true
	isUsed[dst.name] = true
	//debug("Path %s %s", src, dst)
	c.singlePathWalk(src, dst, func(ru *groupedRule, in, out *routerIntf) {
		markTopology(ru, in, out, isUsed)
	}, "Zone")
}

func (c *spoc) markUsedNatTags(isUsed map[string]bool) {
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
	elemList *[]ast.Element, ctx string, m map[string]*ast.TopList,
	isUsed map[string]bool) {

	expand := func(el ast.Element, visible bool) groupObjList {
		l := c.expandGroup1([]ast.Element{el}, ctx, visible, false)
		// Remove duplicates from dual stack objects.
		slices.SortFunc(l, func(e1, e2 groupObj) int {
			return strings.Compare(e1.String(), e2.String())
		})
		return slices.CompactFunc(l, func(e1, e2 groupObj) bool {
			return e1.String() == e2.String()
		})
	}
	toAST := func(obj groupObj) ast.Element {
		var result ast.Element
		name := obj.String()
		typ, name, _ := strings.Cut(name, ":")
		switch x := obj.(type) {
		case *host, *area:
			isUsed[name] = true
			a := new(ast.NamedRef)
			a.Type = typ
			a.Name = name
			result = a
		case *network:
			if x.isAggregate && name[0] == '[' {
				name = name[1:]
				ip := ""
				if left, right, found := strings.Cut(name, " & "); found {
					ip = left[len("ip="):]
					name = right
				}
				name = name[:len(name)-1]
				a := new(ast.AggAuto)
				a.Type = typ
				a.Net = ip
				switch typ2, name2, _ := strings.Cut(name, ":"); typ2 {
				case "network":
					obj := c.symTable.network[name2]
					markUnconnectedObj(obj, isUsed)
					n := new(ast.NamedRef)
					n.Type = typ2
					n.Name = name2
					a.Elements = []ast.Element{n}
				case "interface":
					isUsed[name] = true
					r, net, _ := strings.Cut(name2, ".")
					n := new(ast.IntfRef)
					n.Type = typ2
					n.Router = r
					n.Network = net
					a.Elements = []ast.Element{n}
				}
				result = a
			} else {
				markUnconnectedObj(x, isUsed)
				a := new(ast.NamedRef)
				a.Type = typ
				a.Name = name
				result = a
			}
		case *routerIntf:
			setIntfUsed(x, isUsed)
			r, net, _ := strings.Cut(name, ".")
			a := new(ast.IntfRef)
			a.Type = typ
			a.Router = r
			if left, right, found := strings.Cut(net, "."); found {
				net = left
				a.Extension = right
			}
			a.Network = net
			result = a
		case *autoIntf:
			if r, ok := x.object.(*router); ok {
				setRouterUsed(r, isUsed)
				a := new(ast.IntfRef)
				a.Type = typ
				a.Router = r.name[len("router:"):]
				a.Network = "["
				a.Extension = "auto"
				result = a
			} else {
				net := x.object.(*network)
				markUnconnectedObj(net, isUsed)
				a := new(ast.IntfAuto)
				a.Type = typ
				a.Managed = x.managed
				a.Selector = "auto"
				n := new(ast.NamedRef)
				n.Type = "network"
				n.Name = net.name[len("network:"):]
				a.Elements = []ast.Element{n}
				result = a
			}
		}
		return result
	}
	var traverse func(l []ast.Element, visible bool) []ast.Element
	traverse = func(l []ast.Element, visible bool) []ast.Element {
		var expanded groupObjList
		j := 0
		for _, el := range l {
			switch x := el.(type) {
			case *ast.NamedRef:
				typedName := x.Type + ":" + x.Name
				if isUsed[typedName] {
					break
				}
				switch x.Type {
				case "any", "network":
					for _, obj := range expand(el, visible) {
						markUnconnectedObj(obj.(*network), isUsed)
					}
				case "group":
					if def, found := m[typedName]; found {
						c.markAndSubstElements(&def.Elements, typedName, m, isUsed)
					}
				}
				isUsed[typedName] = true
			case ast.AutoElem:
				// Ignore empty automatic group
				if len(expand(el, false)) == 0 {
					continue
				}
				// Remove sub elements that would evaluate to empty list.
				l2 := traverse(x.GetElements(), false)
				j2 := 0
				for _, el2 := range l2 {
					if len(expand(el2, false)) != 0 {
						l2[j2] = el2
						j2++
					}
				}
				x.SetElements(l2[:j2])
			case *ast.IntfRef:
				for _, obj := range expand(el, visible) {
					switch x := obj.(type) {
					case *routerIntf:
						setIntfUsed(x, isUsed)
						setRouterUsed(x.router, isUsed)
					}
				}
			case *ast.Intersection:
				expanded = append(expanded, expand(el, visible)...)
				continue // Ignore original intersection.
			}
			l[j] = el
			j++
		}
		result := l[:j]
		for _, obj := range expanded {
			result = append(result, toAST(obj))
		}
		return result
	}
	*elemList = traverse(*elemList, true)
}

func (c *spoc) markElements(
	toplevel []ast.Toplevel, m map[string]*ast.TopList, isUsed map[string]bool,
) {
	for _, top := range toplevel {
		if x, ok := top.(*ast.Service); ok {
			typedName := x.Name
			if !isUsed[typedName] {
				continue
			}
			c.markAndSubstElements(
				&x.User.Elements, "user of "+typedName, m, isUsed)
			for _, r := range x.Rules {
				if !hasUserInList(r.Src.Elements) {
					c.markAndSubstElements(
						&r.Src.Elements, "src of "+typedName, m, isUsed)
				}
				if !hasUserInList(r.Dst.Elements) {
					c.markAndSubstElements(
						&r.Dst.Elements, "dst of "+typedName, m, isUsed)
				}
			}
		}
	}
}

func hasUserInList(l []ast.Element) bool {
	return slices.ContainsFunc(l, hasUser)
}

func hasUser(el ast.Element) bool {
	switch x := el.(type) {
	case *ast.User:
		return true
	case ast.AutoElem:
		return hasUserInList(x.GetElements())
	case *ast.Intersection:
		return hasUserInList(x.Elements)
	case *ast.Complement:
		return hasUser(x.Element)
	default:
		return false
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

func (c *spoc) cutNetspoc(
	stdout io.Writer,
	path string, names []string, keepOwner bool) {

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
	isUsed := make(map[string]bool)
	for _, sv := range c.ascendingServices {
		if !sv.disabled {
			isUsed[sv.name] = true
		}
	}
	origNat := make(map[*network]natTagMap)
	c.saveOrigNat(origNat)
	c.setZone()
	c.setPath()
	c.distributeNatInfo()
	sRules := c.normalizeServices()
	permitRules, denyRules := c.convertHostsInRules(sRules)
	c.groupPathRules(permitRules, denyRules)

	c.markRulesPath(c.allPathRules, isUsed)

	// Collect objects referenced from rules.
	// Use serviceRules here, to get also objects from unenforceable rules.
	collectRules := func(rules []*serviceRule) {
		for _, rule := range rules {
			collectObjects := func(group []srvObj) {
				for _, obj := range group {

					// pathWalk only handles networks connected to managed routers.
					// Mark all objects additionally here.
					markUnconnectedObj(obj.getNetwork(), isUsed)
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
	c.markElements(toplevel, group2def, isUsed)

	// Mark management_instance of routers
	for _, r := range c.managedRouters {
		if isUsed[r.name] && r.model.needManagementInstance {
			if mr := c.symTable.router[r.deviceName]; mr != nil {
				if r.ipV6 != mr.ipV6 {
					if mr.combined46 == nil || mr.ipV6 {
						continue
					}
					mr = mr.combined46
				}
				for _, intf := range getIntf(mr) {
					for _, intf2 := range getIntf(r) {
						c.markPath(intf, intf2, isUsed)
					}
				}
			}
		}
	}

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

	// Mark networks of named and unnamed aggregates used in rules.
	for _, agg := range c.allNetworks {
		if agg.isAggregate && isUsed[agg.name] {
			// debug("Marking networks of %s in %s", agg, z")
			for _, n := range agg.networks {
				markUnconnectedObj(n, isUsed)
			}
		}
	}

	// Call this after topology has been marked.
	c.expandCrypto()

	mark1 := func(r *router) {

		// Mark split router, if some split part is marked.
		for _, intf := range getIntf(r) {
			if frag := intf.router; frag != r && isRouterUsed(frag, isUsed) {
				// debug("From split: %s", r)
				setRouterUsed(r, isUsed)
			}
		}

		if !isRouterUsed(r, isUsed) {
			return
		}

		// Mark fragments of marked crypto routers.
		for _, intf := range getIntf(r) {
			if frag := intf.router; frag != r {
				// debug("Fragment: %s", fragment)
				setRouterUsed(frag, isUsed)
			}
		}

		// Mark path of crypto tunnel.
		for _, intf := range getIntf(r) {
			if isUsed[intf.name] && intf.ipType == tunnelIP {
				c.markPath(intf.realIntf, intf.peer.realIntf, isUsed)
			}
		}
	}
	for _, r := range c.allRouters {
		mark1(r)
	}

	hubUsed := make(map[*crypto]bool)
	spokeUsed := make(map[*crypto]bool)
	mark2 := func(r *router) {
		if !isRouterUsed(r, isUsed) {
			return
		}
		for _, intf := range withSecondary(getIntf(r)) {
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
				hubUsed[crypto] = true
			}
			if crypto := intf.spoke; crypto != nil {
				spokeUsed[crypto] = true
			}

			// Mark networks referenced by interfaces
			// marked by markAndSubstElements.
			isUsed[intf.network.name] = true
		}
	}
	for _, r := range c.allRouters {
		mark2(r)
	}
	for crypto := range spokeUsed {
		if hubUsed[crypto] {
			isUsed[crypto.name] = true
			typ := crypto.ipsec
			isUsed[typ.name] = true
			isUsed[typ.isakmp.name] = true
		}
	}

	// Mark networks and aggregates having NAT attributes that
	// influence their subnets.
	for _, n := range c.allNetworks {
		if !isUsed[n.name] {
			continue
		}
		// Walk chain of inheritance.
		// Mark supernet with NAT attribute.
		up := n
		for {
			up = up.up
			if up == nil {
				break
			}
			if origNat[up] != nil || up.noCheckSupernetRules {
				markUnconnectedObj(up, isUsed)
			}
		}
	}

	// Collect used zones.
	zoneUsed := make(map[*zone]bool)
	for _, n := range c.allNetworks {
		if isUsed[n.name] {
			z := n.zone
			zoneUsed[z] = true
		}
	}

	// Mark network as used if it has attribute "partition" and
	// is located inside used partition.
	for _, n := range c.allNetworks {
		if n.partition != "" && !isUsed[n.name] {
			partition := make(map[*zone]bool)
			markPartitionGetTags(n.zone, partition)
			for z := range partition {
				if zoneUsed[z] {
					markUnconnectedObj(n, isUsed)
					break
				}
			}
		}
	}

	// Mark NAT tags referenced in used networks.
	c.markUsedNatTags(isUsed)

	// Collect areas of used networks.
	areaUsed := make(map[string]bool)
	for z := range zoneUsed {
		a := z.inArea
		for a != nil {
			areaUsed[a.name] = true
			a = a.inArea
		}
	}
	for _, top := range toplevel {
		ar, ok := top.(*ast.Area)
		if !ok {
			continue
		}
		name := ar.Name
		if !areaUsed[name] {
			continue
		}
		// Check areas having attributes that influence their networks.
		hasAttr := func(n *ast.Area) bool {
			for _, a := range n.Attributes {
				switch a.Name {
				case "has_unenforceable", "overlaps":
					return true
				case "owner":
					if keepOwner {
						return true
					}
				case "router_attributes":
					if keepOwner && a.GetAttr("owner") != nil {
						return true
					}
				default:
					if strings.HasPrefix(a.Name, "nat:") {
						return true
					}
				}
			}
			return false
		}
		if isUsed[name] || hasAttr(ar) {
			isUsed[name] = true
			name := name[len("area:"):]
			a := c.symTable.area[name]
			// Remove unused anchor and border from used areas.
			if anchor := a.anchor; anchor != nil {
				// Change anchor to some used network
				if !isUsed[anchor.name] {
					found := false
					for _, z := range a.zones {
						processWithSubnetworks(z.networks, func(n *network) {
							if !found && isUsed[n.name] {
								ar.GetAttr("anchor").ValueList =
									[]*ast.Value{{Value: n.name}}
								found = true
							}
						})
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
				cleanup(&ar.Border)
				cleanup(&ar.InclusiveBorder)
				// Add anchor, if all interfaces have been removed.
				if ar.Border == nil && ar.InclusiveBorder == nil {
					found := false
					for _, z := range a.zones {
						processWithSubnetworks(z.networks, func(n *network) {
							if !found && isUsed[n.name] {
								ar.Attributes = append(ar.Attributes,
									&ast.Attribute{
										Name:      "anchor",
										ValueList: []*ast.Value{{Value: n.name}},
									})
								found = true
							}
						})
					}
				}
			}
		}
	}

	// Collect names of marked areas, groups, protocols, protocolgroups.
	// Collect names of marked owners.
	markOwner := func(o *owner) {
		if keepOwner && o != nil {
			isUsed[o.name] = true
		}
	}
	for _, a := range c.symTable.area {
		if isUsed[a.name] {
			markOwner(a.owner)

		}
	}
	for _, p := range c.symTable.protocol {
		if p.isUsed {
			isUsed[p.name] = true
		}
	}
	for _, p := range c.symTable.protocolgroup {
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
		if isRouterUsed(r, isUsed) {
			markOwner(r.owner)
			for _, intf := range getIntf(r) {
				if isUsed[intf.name] {
					setIntfUsed(intf, isUsed)
					markOwner(intf.owner)
				}
			}
		}
	}
	for _, r := range c.allRouters {
		markRouter(r)
	}

	// Source of pathrestrictions can't be used literally,
	// because automatic groups may be used.
	// Hence it must be reconstructed from internal data structure.
	name2pathrestriction := make(map[string]*ast.TopList)
	seen := make(map[string]bool)
	for _, pr := range c.pathrestrictions {
		// Other part of dual stack pathrestriction has already been
		// processed or pathrestriction was automatically created.
		if seen[pr.name] || strings.HasPrefix(pr.name, "auto-virtual:") {
			continue
		}
		seen[pr.name] = true
		getUsedInterfaces := func(pr *pathRestriction) []string {
			var result []string
			for _, intf := range pr.elements {
				if isUsed[intf.name] {
					result = append(result, intf.name)
				}
			}
			if len(result) < 2 {
				result = nil
			}
			return result
		}
		names := getUsedInterfaces(pr)
		if pr6 := pr.combined46; pr6 != nil {
			for _, nm := range getUsedInterfaces(pr6) {
				if !slices.Contains(names, nm) {
					names = append(names, nm)
				}
			}
		}
		if len(names) < 2 {
			continue
		}
		var l []ast.Element
		for _, nm := range names {
			typ, rest := splitTypedName(nm)
			parts := strings.Split(rest, ".")
			n := new(ast.IntfRef)
			n.Type = typ
			n.Router = parts[0]
			n.Network = parts[1]
			if len(parts) == 3 {
				n.Extension = parts[2]
			}
			l = append(l, n)
		}
		n := new(ast.TopList)
		n.Name = pr.name
		n.Elements = l
		isUsed[pr.name] = true
		name2pathrestriction[pr.name] = n
	}

	removeOwner := func(ref *[]*ast.Attribute) {
		if !keepOwner {
			removeAttr(ref, "owner")
		}
	}

	selectSubnetOf := func(ref *[]*ast.Attribute) {
		var l []*ast.Attribute
		for _, a := range *ref {
			l2 := a.ValueList
			if a.Name != "subnet_of" || len(l2) == 1 && isUsed[l2[0].Value] {
				l = append(l, a)
			}
		}
		*ref = l
	}
	selectSubnetOfInNAT := func(ref []*ast.Attribute) {
		for _, a := range ref {
			if strings.HasPrefix(a.Name, "nat:") {
				selectSubnetOf(&a.ComplexValue)
			}
		}
	}

	selectNatTags := func(l []*ast.Value) []*ast.Value {
		var result []*ast.Value
		for _, v := range l {
			if isUsed["nat:"+v.Value] {
				result = append(result, v)
			}
		}
		return result

	}

	selectAttrValues := func(l []*ast.Value) []*ast.Value {
		var result []*ast.Value
		for _, v := range l {
			if isUsed[v.Value] {
				result = append(result, v)
			}
		}
		return result
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
				delSpoke := false
				l = append(l, a)
				attrList := a.ComplexValue
				j := 0
				for _, a2 := range attrList {
					l2 := a2.ValueList
					changed := true
					switch a2.Name {
					case "nat_in", "nat_out":
						l2 = selectNatTags(l2)
					case "reroute_permit":
						l2 = selectAttrValues(l2)
					case "owner":
						if !keepOwner {
							l2 = nil
						}
					case "hub":
						l2 = selectAttrValues(l2)
					case "spoke":
						if l2 = selectAttrValues(l2); l2 == nil {
							delSpoke = true
						}
					default:
						changed = false
					}
					if !changed || l2 != nil {
						a2.ValueList = l2
						attrList[j] = a2
						j++
					}
				}
				a.ComplexValue = attrList[:j]
				if delSpoke {
					removeAttr(&a.ComplexValue, "id")
				}
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
		if !isUsed[typedName] {
			continue
		}
		typ, _ := splitTypedName(typedName)
		switch x := top.(type) {
		case *ast.Network:
			removeOwner(&x.Attributes)
			selectSubnetOf(&x.Attributes)
			selectSubnetOfInNAT(x.Attributes)
			selectHosts(x)
		case *ast.Router:
			removeOwner(&x.Attributes)
			removeAttr(&x.Attributes, "policy_distribution_point")
			selectInterfaces(x)
		case *ast.Area:
			removeOwner(&x.Attributes)
			selectSubnetOfInNAT(x.Attributes)
			removeSubAttr(&x.Attributes,
				"router_attributes", "policy_distribution_point")
			if !keepOwner {
				removeSubAttr(&x.Attributes, "router_attributes", "owner")
			}
		case *ast.Service:
			if !keepOwner {
				removeAttr(&x.Attributes, "multi_owner")
			}
		case *ast.TopStruct:
			if typ == "any" {
				removeOwner(&x.Attributes)
				selectSubnetOfInNAT(x.Attributes)
			}
		case *ast.TopList:
			switch typ {
			case "pathrestriction":
				top = name2pathrestriction[typedName]
			}
		}
		active = append(active, top)
	}
	f := new(ast.File)
	f.Nodes = active
	out := printer.File(f)
	stdout.Write(out)
}

func CutNetspocMain(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR [service:name ...]\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't print progress messages")
	keepOwner := fs.BoolP("owner", "o", false, "Keep referenced owners")
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
	services := args[1:]

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
		"--max_errors=9999",
	}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, path)

	return toplevelSpoc(d, cnf, func(c *spoc) {
		c.cutNetspoc(d.Stdout, path, services, *keepOwner)
	})
}
