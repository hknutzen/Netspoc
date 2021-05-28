package pass1

/*
=head1 NAME

cut-netspoc - Print parts of a netspoc configuration to stdout

=head1 SYNOPSIS

cut-netspoc [options] FILE|DIR [service:name] ...

=head1 DESCRIPTION

Reads a Netspoc configuration && prints parts of this configuration
to STDOUT. If one or more services are given as argument, only those
parts are printed, that are referenced by given serices. If no service
is given, it acts as if all services are specified. This is useful to
eliminate all disabled parts of the topology.

=head1 OPTIONS

=item B<-q>

Quiet, don't print status messages.

=item B<-help>

Prints a brief help message && exits.

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
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
	"os"
	"strings"
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

type netPathObj interface {
	intfList() intfList
	getUsed() bool
	setUsed()
}
type netPathObjList []netPathObj

func (a *netPathObjList) push(e netPathObj) {
	*a = append(*a, e)
}

// Collect networks that need to be connected by unmanaged parts of topology.
var todoUnmanaged netPathObjList

// This function is called by pathWalk to mark all managed routers
// on path from src to dst of rule with attribute .isUsed set.
func markTopology(_ *groupedRule, in, out *routerIntf) {
	var r *router
	if in != nil {
		r = in.router
	} else {
		r = out.router
	}
	r.isUsed = true
	//debug("Used %s", r)
	for _, intf := range []*routerIntf{in, out} {
		if intf == nil {
			continue
		}
		n := intf.network
		intf.isUsed = true
		n.isUsed = true
		todoUnmanaged.push(n)
	}
}

// Mark path between objects and marked parts of topology.
// object must be of type network or router.
// Depending on managed, mark only unmanaged or also managed parts.
func (c *spoc) markUnconnected(list netPathObjList, managed bool) {
	var what string
	if managed {
		what = "managed"
	} else {
		what = "unmanaged"
	}
	c.progress("Marking " + what + " routers")

	var mark func(obj netPathObj, in *routerIntf, seen map[netPathObj]bool) bool
	mark = func(obj netPathObj, in *routerIntf, seen map[netPathObj]bool) bool {
		if seen[obj] {
			return false
		}
		seen[obj] = true
		if obj.getUsed() {
			//debug("Found %s", obj)
			return true
		}
		r, isRouter := obj.(*router)
		if isRouter && !managed {
			if r.managed != "" || r.semiManaged {
				return false
			}
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
			if mark(next, intf, seen) {
				obj.setUsed()
				intf.isUsed = true
				//debug("Marked %s + %s", obj, intf)
				result = true
			}
		}
		return result
	}

	for _, obj := range list {
		//debug("Connecting %s", obj)
		seen := map[netPathObj]bool{obj: true}
		for _, intf := range obj.intfList() {
			if intf.mainIntf != nil {
				continue
			}
			_, isRouter := obj.(*router)
			var next netPathObj
			if isRouter {
				next = intf.network
			} else {
				next = intf.router
			}
			//debug("Try %s %s", next, intf)
			if mark(next, intf, seen) {
				intf.isUsed = true
				//debug("Marked %s", intf)
			}
		}
	}
}

func (c *spoc) markPath(src, dst *routerIntf) {
	for _, intf := range []*routerIntf{src, dst} {
		n := intf.network
		intf.isUsed = true
		n.isUsed = true
		todoUnmanaged.push(n)
	}
	//debug("Path %s %s", src, dst)
	c.singlePathWalk(src, dst, markTopology, "Router")
}

func (c *spoc) markUsedNatTags() {
	for _, n := range c.allNetworks {
		if n.isUsed {
			for tag, natNet := range n.nat {
				if !natNet.identity {
					isUsed["nat:"+tag] = true
				}
			}
		}
	}
}

// Mark path between endpoints of rules.
func (c *spoc) markRulesPath(p pathRules) {
	for _, r := range append(p.deny, p.permit...) {
		c.pathWalk(r, markTopology, "Router")
	}
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
	for _, s := range symTable.service {
		if !s.disabled {
			isUsed[s.name] = true
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

	// Collect objects referenced from rules.
	// Use serviceRules here, to get also objects from unenforceable rules.
	onPath := make(map[srvObj]bool)
	var addLater intfList
	seen := make(map[*network]bool)
	collectRules := func(rules []*serviceRule) {
		for _, rule := range rules {
			collectObjects := func(group []srvObj) {
				for _, obj := range group {
					onPath[obj] = true

					// pathWalk only handles managed routers and interfaces.
					// Mark all objects additionally here.
					obj.setUsed()
					if intf, ok := obj.(*routerIntf); ok {
						addLater.push(intf)
					}
					n := obj.getNetwork()
					n.isUsed = true
					if seen[n] {
						continue
					}
					seen[n] = true
					todoUnmanaged.push(n)
				}
			}
			collectObjects(rule.src)
			collectObjects(rule.dst)
		}
	}
	collectRules(sRules.permit)
	collectRules(sRules.deny)

	// Mark NAT tags referenced in networks used in rules.
	c.markUsedNatTags()

	// Collect objects, that are referenced, but not visible in rules:
	// Networks, interfaces, hosts, aggregates from negated part of intersection.
	// These need to be connected with other parts of topology
	// by managed and unmanaged routers.
	var todoManaged netPathObjList
	collectNegated := func(obj srvObj) {
		if !obj.getUsed() || onPath[obj] {
			return
		}
		n := obj.getNetwork()
		todoManaged.push(n)
		if intf, ok := obj.(*routerIntf); ok {
			addLater.push(intf)
		}
	}
	for _, n := range c.allNetworks {
		collectNegated(n)
		for _, h := range n.hosts {
			collectNegated(h)
		}
	}
	for _, r := range c.allRouters {
		for _, intf := range r.interfaces {
			collectNegated(intf)
		}
	}

	zoneUsed := make(map[*zone]bool)
	zoneCheck := make(map[*zone]bool)
	for _, z := range c.allZones {
		for _, agg := range z.ipPrefix2aggregate {
			if !agg.isUsed {
				continue
			}
			zoneUsed[agg.zone] = true
			zoneCheck[agg.zone] = true
			// debug("Marking networks of %s in %s", agg, z")
			for _, n := range agg.networks {
				n.isUsed = true
				todoUnmanaged.push(n)
			}
		}
	}

	// Mark zones having attributes that influence their networks.
	for _, n := range c.allNetworks {
		if !n.isUsed {
			continue
		}
		z := n.zone
		zoneCheck[z] = true
		if len(z.nat) == 0 {
			continue
		}
		ipp := getNetwork00(z.ipV6).ipp
		if agg0 := z.ipPrefix2aggregate[ipp]; agg0 != nil {
			agg0.isUsed = true
		}
		zoneUsed[z] = true
	}

	for _, agg := range c.allNetworks {
		if agg.isUsed {
			if n := agg.link; n != nil {
				n.isUsed = true
				todoManaged.push(n)
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
	for _, z := range c.allZones {
		if !zoneCheck[z] {
			continue
		}
		for _, a := range zone2areas[z] {
			att := a.routerAttributes
			if len(a.nat) != 0 ||
				keepOwner && (a.owner != nil || att != nil && att.owner != nil) {

				a.isUsed = true
			}
		}
	}

	// Mark interfaces / networks which are referenced by used areas.
	var emptyAreas stringList
	for _, a := range symTable.area {
		if !a.isUsed {
			continue
		}
		if anchor := a.anchor; anchor != nil {
			anchor.isUsed = true
			todoManaged.push(anchor)
		} else {

			// Ignore and collect empty areas.
			used := false
		ZONE:
			for _, z := range a.zones {
				for _, n := range z.networks {
					if n.isUsed {
						used = true
						break ZONE
					}
				}
			}
			if !used {
				a.isUsed = false
				emptyAreas.push(a.name[len("area:"):])
				continue
			}

			for _, intf := range append(a.border, a.inclusiveBorder...) {
				if intf.isUsed {
					continue
				}
				intf.network.isUsed = true
				todoManaged.push(intf.network)
				addLater.push(intf)
			}
		}
	}

	// Mark networks having NAT attributes that influence their subnets.
	for _, n := range c.allNetworks {
		if !n.isUsed {
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
				if up.ipp.Bits != 0 {
					continue
				}
				z := up.zone

				// Check if NAT attribute was inherited from zone or areas.
				if !zoneUsed[z] {
					found := false
					for _, a := range zone2areas[z] {
						if a.isUsed {
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
				supernet.isUsed = true
				todoUnmanaged.push(supernet)
				// debug("marked: %s", supernet)
			}
			upChain = nil
		}
	}

	c.markRulesPath(c.allPathRules)

	// Call this after topology has been marked.
	c.expandCrypto()

	// 1. call to mark unmanaged parts of topology.
	// Needed to mark unmanaged crypto routers.
	c.markUnconnected(todoUnmanaged, false)
	todoUnmanaged = nil

	// Mark negated auto interfaces.
	for r, intf := range c.routerAutoInterfaces {
		if intf.isUsed && !r.isUsed {
			r.isUsed = true
			todoManaged = append(todoManaged, r)
		}
	}

	// Connect objects, that are located outside of any path.
	c.markUnconnected(todoManaged, true)
	for _, intf := range addLater {
		intf.isUsed = true
		intf.router.isUsed = true
	}

	// Mark bridge and bridged networks.
	for _, n := range c.allNetworks {
		if !n.isUsed {
			continue
		}
		if n.ipType != bridgedIP {
			continue
		}
		for _, in := range n.interfaces {
			if in.ipType != bridgedIP {
				continue
			}
			in.isUsed = true
			bridge := in.router
			bridge.isUsed = true
			for _, out := range bridge.interfaces {
				if out.hardware.name == "device" && bridge.model.class == "ASA" {
					out.isUsed = true
				} else if out.ipType == bridgedIP {
					out.isUsed = true
					out.network.isUsed = true
				}
			}
		}
	}

	mark1 := func(r *router) {

		// Mark split router, if some split part is marked.
		for _, intf := range getIntf(r) {
			fragment := intf.router
			if fragment == r {
				continue
			}
			if fragment.isUsed {
				// debug("From split: %s", r)
				r.isUsed = true
			}
		}

		if !r.isUsed {
			return
		}

		// Mark fragments of marked crypto routers.
		for _, intf := range getIntf(r) {
			fragment := intf.router
			if fragment == r {
				continue
			}
			// debug("Fragment: %s", fragment)
			fragment.isUsed = true
		}

		for _, intf := range getIntf(r) {
			if !intf.isUsed {
				continue
			}

			// Mark path of crypto tunnel.
			if intf.ipType == tunnelIP {
				peer := intf.peer
				real := intf.realIntf
				c.markPath(real, peer.realIntf)
			}
		}
	}
	for _, r := range c.allRouters {
		mark1(r)
	}

	// 2. call to mark unmanaged parts of topology.
	// Need to mark crypto path of crypto routers.
	c.markUnconnected(todoUnmanaged, false)

	mark2 := func(r *router) {
		if !r.isUsed {
			return
		}
		for _, intf := range getIntf(r) {
			if !intf.isUsed {
				continue
			}

			// Mark main interface of secondary or virtual interface.
			if main := intf.mainIntf; main != nil {
				main.isUsed = true
			}
			if main := intf.origMain; main != nil {
				main.isUsed = true
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
			// implictly marked by expandGroup.
			if intf.isUsed {
				intf.network.isUsed = true
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
		if a.isUsed {
			isUsed[a.name] = true
			markOwner(a.owner)

		}
	}
	for _, g := range symTable.group {
		if g.isUsed {
			isUsed[g.name] = true
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
		if n.isUsed {
			isUsed[n.name] = true
			markOwner(n.owner)
			added := false
			for _, h := range n.hosts {
				if h.isUsed {
					isUsed[h.name] = true
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
		if r.isUsed {
			name := r.name
			if r.ipV6 {
				name = "6" + name
			}
			isUsed[name] = true
			markOwner(r.owner)
			for _, intf := range getIntf(r) {
				if intf.isUsed {
					iName := intf.name
					isUsed[iName] = true
					// Ignore extension if virtual interface is used as
					// main interface.
					iName = strings.TrimSuffix(iName, ".virtual")
					isUsed[iName] = true
					markOwner(intf.owner)
				}
			}
		}
	}
	for _, r := range c.allRouters {
		markRouter(r)
	}
	if keepOwner {
		for _, s := range symTable.service {
			markOwner(s.subOwner)
		}
	}

	// Prepare emptyGroup
	var emptyGroupRef *ast.NamedRef
	if emptyAreas != nil {
		name := "empty-area"
		emptyGroupRef = new(ast.NamedRef)
		emptyGroupRef.Type = "group"
		emptyGroupRef.Name = name
		fmt.Println("group:" + name + " = ;")
	}

	substEmptyAreas := func(elemList []ast.Element) {
		if emptyAreas == nil {
			return
		}
		needSubst := func(name string) bool {
			for _, name2 := range emptyAreas {
				if name == name2 {
					return true
				}
			}
			return false
		}
		var substList func(l []ast.Element)
		substList = func(l []ast.Element) {
			for i, el := range l {
				switch x := el.(type) {
				case *ast.NamedRef:
					if x.Type == "area" && needSubst(x.Name) {
						l[i] = emptyGroupRef
					}
				case *ast.SimpleAuto:
					substList(x.Elements)
				case *ast.AggAuto:
					substList(x.Elements)
				case *ast.IntfAuto:
					substList(x.Elements)
				case *ast.Intersection:
					substList(x.Elements)
				case *ast.Complement:
					l2 := []ast.Element{x.Element}
					substList(l2)
					x.Element = l2[0]
				}
			}
		}
		substList(elemList)
	}

	// Source of pathrestrictions can't be used literally,
	// but must be reconstructed from internal data structure.
	name2pathrestriction := make(map[string]*ast.TopList)
	for _, pr := range c.pathrestrictions {
		elemList := pr.elements
		var l []ast.Element
		for _, intf := range elemList {
			if intf.isUsed {
				n := new(ast.IntfRef)
				n.Type = "interface"
				n.Router = intf.router.name[len("router:"):]
				n.Network = intf.network.name[len("network:"):]
				if intf.redundant {
					n.Extension = "virtual"
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
		lookup := typedName
		if strings.HasPrefix(typedName, "router:") && top.GetIPV6() {
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
			case "group":
				substEmptyAreas(x.Elements)
			case "pathrestriction":
				top = name2pathrestriction[typedName]
			}
		case *ast.Service:
			if !keepOwner {
				removeAttr(&x.Attributes, "sub_owner")
			}
			substEmptyAreas(x.User.Elements)
			for _, r := range x.Rules {
				substEmptyAreas(r.Src.Elements)
				substEmptyAreas(r.Dst.Elements)
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
		fmt.Sprintf("--verbose=%v", !*quiet),
		fmt.Sprintf("--ipv6=%v", *ipv6),
		"--max_errors=9999",
	}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Initialize global variables.
	isUsed = make(map[string]bool)
	todoUnmanaged = nil

	return toplevelSpoc(func(c *spoc) {
		c.cutNetspoc(path, services, *keepOwner)
	})
}
