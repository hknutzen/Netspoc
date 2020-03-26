package pass1

/*
=head1 NAME

cut-netspoc - Print parts of a netspoc configuration to stdout

=head1 SYNOPSIS

cut-netspoc [options] FILE|DIR [service:name] ...

=head1 DESCRIPTION

Reads a Netspoc configuration && prints parts of this configuration
to STDOUT. If one || more services are given as argument, only those
parts are printed, that are referenced by given serices. If no service
is given, it acts as if all services are specified. This is useful to
eliminate all disabled parts of the topology.

=head1 OPTIONS

=item B<-q>

Quiet, don't print status messages.

=item B<-help>

Prints a brief help message && exits.

=item B<-man>

Prints the manual page && exits.

=back

=head1 COPYRIGHT AND DISCLAIMER

(c) 2020 by Heinz Knutzen <heinz.knutzengooglemail.com>

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
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"net"
	"regexp"
	"sort"
	"strings"
)

type hasSrc interface {
}

var srcCode = make(map[hasSrc]string)
var srcIndex = make(map[hasSrc]int)

func getSource(m xMap) {
	global := []string{
		"aggregates", "areas",
		"crypto", "ipsec", "isakmp",
		"groups", "networks",
		"protocols", "protocolgroups",
		"routers", "routers6", "services",
	}
	for _, g := range global {
		for _, xOb := range getMap(m[g]) {
			m := getMap(xOb)
			if ob := m["ref"]; ob != nil {
				if s := m["src_code"]; s != nil {
					srcCode[ob] = getString(s)
					srcIndex[ob] = getInt(m["src_index"])
				}
			}
		}
	}
}

func changeAttributeSrcCodeAt(attr string, ob hasSrc, subName, replace string) {
	code := srcCode[ob]
	input := code

	// Current position inside code.
	pos := 0

	// Match pattern in input and skip matched pattern; update pos
	match := func(re *regexp.Regexp) bool {
		loc := re.FindStringIndex(input)
		if loc == nil {
			return false
		}
		skip := loc[1]
		input = input[skip:]
		pos += skip
		return true
	}

	// Start changing at subName.
	// Do nothing, if subName can't be found, e.g. virtual interface.
	if subName != "" {
		re := regexp.MustCompile(`(?m)^[^#]*\Q` + subName + `\E[\s;=#]`)
		if !match(re) {
			return
		}
	}

	// Find attribute outside of comment,
	// either at new line or directly behind subName.
	re := regexp.MustCompile(`(?m)(?:^|\A)[^#]*?\b\Q` + attr + `\E[\s;=#]`)
	if !match(re) {
		panic("Can't find " + attr)
	}

	// Unread last character.
	pos--
	input = code[pos:]
	start := pos - len(attr)

	// Helper functions to parse attribute value.
	skipSpaceAndComment := func() {
		re := regexp.MustCompile(`\A(?m:(?:[#].*$)|\s*)*`)
		match(re)
	}
	check := func(what string) bool {
		skipSpaceAndComment()
		re := regexp.MustCompile(`\A\Q` + what + `\E`)
		return match(re)
	}
	readToken := func() {
		skipSpaceAndComment()
		re := regexp.MustCompile(`\A[^,;\s#]+`)
		if !match(re) {
			panic("Parse error: Token expected")
		}
	}
	var readAttrBody func()
	readAttrBody = func() {
		if check(";") {

			// Attribute has no value; finished.
			return
		}
		if check("=") {

			// Read complex value.
			if check("{") {
				if check("description") {
					check("=")
					re := regexp.MustCompile(`\A.*?\n`)
					match(re)
				}
				for {
					if check("}") {
						break
					}
					readToken()
					readAttrBody()
				}
			} else {

				// Read comma separated list of values.
				for {
					if check(";") {
						break
					}
					readToken()
					check(",")
				}
			}
		}
	}
	readAttrBody()
	end := pos

	// Remove leading white space and trailing line break.
	if replace == "" {

		// Find trailing line break.
		re := regexp.MustCompile(`\A[ \t]*(?:[#].*)?(?:\n|\z)`)
		match(re)
		end = pos

		// Find leading white space.
	FIND:
		for start > 0 {
			switch code[start-1] {
			case ' ', '\t':
				start--
				continue
			default:
				break FIND
			}
		}
	}
	srcCode[ob] = code[:start] + replace + code[end:]
}

func removeAttributeSrcCodeAt(attr string, object hasSrc, subName string) {
	changeAttributeSrcCodeAt(attr, object, subName, "")
}

func removeAttributeSrcCode(attr string, object hasSrc) {
	changeAttributeSrcCodeAt(attr, object, "", "")
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
	// debug("Used %s", r)
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
func markUnconnected(list netPathObjList, managed bool) {
	var what string
	if managed {
		what = "managed"
	} else {
		what = "unmanaged"
	}
	diag.Progress("Marking " + what + " routers")

	var mark func(obj netPathObj, in *routerIntf, seen map[netPathObj]bool) bool
	mark = func(obj netPathObj, in *routerIntf, seen map[netPathObj]bool) bool {
		if seen[obj] {
			return false
		}
		seen[obj] = true
		if obj.getUsed() {
			// debug("Found %s", obj)
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
				// debug "Marked %s + %s", obj, intf)
				result = true
			}
		}
		return result
	}

	for _, obj := range list {
		// debug "Connecting %s", obj)
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
			// debug("Try %s %s", next, intf)
			if mark(next, intf, seen) {
				intf.isUsed = true
				// debug("Marked %s", inf)
			}
		}
	}
}

func markPath(src, dst *routerIntf) {
	for _, intf := range []*routerIntf{src, dst} {
		n := intf.network
		intf.isUsed = true
		n.isUsed = true
		todoUnmanaged.push(n)
	}
	// debug("Path %s %s", src, dst)
	singlePathWalk(src, dst, markTopology, "Router")
}

func getUsedNatTags() map[string]bool {
	result := make(map[string]bool)
	for _, n := range allNetworks {
		if !n.isUsed {
			continue
		}
		nat := n.nat
		for tag, natNet := range nat {
			if !natNet.identity {
				result[tag] = true
			}
		}
	}
	return result
}

// Mark path between endpoints of rules.
func markRulesPath(p pathRules) {
	for _, r := range append(p.deny, p.permit...) {
		pathWalk(r, markTopology, "Router")
	}
}

func CutNetspoc(m xMap) {

	getSource(m)

	DistributeNatInfo()
	FindSubnetsInZone()
	LinkReroutePermit()
	NormalizeServices()
	permitRules, denyRules := ConvertHostsInRules()
	GroupPathRules(permitRules, denyRules)

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
	usedNat := getUsedNatTags()

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
	for _, x := range networks {
		collectNegated(x)
	}
	for _, x := range hosts {
		collectNegated(x)
	}
	for _, x := range interfaces {
		collectNegated(x)
	}
	for _, x := range aggregates {
		collectNegated(x)
	}

	zoneUsed := make(map[*zone]bool)
	for _, z := range zones {
		for _, agg := range z.ipmask2aggregate {
			if !agg.isUsed {
				continue
			}
			zoneUsed[agg.zone] = true
			// debug("Marking networks of %s in %s", agg, z")
			for _, n := range agg.networks {
				n.isUsed = true
				todoUnmanaged.push(n)
			}
		}
	}

	// Mark zones having attributes that influence their networks.
	for _, n := range networks {
		if !n.isUsed {
			continue
		}
		z := n.zone
		if len(z.nat) == 0 {
			continue
		}
		ip := getZeroIp(z.ipV6)
		var mask net.IPMask
		if z.ipV6 {
			mask = net.CIDRMask(0, 128)
		} else {
			mask = net.CIDRMask(0, 32)
		}
		key := ipmask{string(ip), string(mask)}
		if agg0 := z.ipmask2aggregate[key]; agg0 != nil {
			agg0.isUsed = true
		}
		zoneUsed[z] = true
	}

	for _, z := range zones {
		if !zoneUsed[z] {
			continue
		}
		if n := z.link; n != nil {
			n.isUsed = true
			todoManaged.push(n)
		}
	}

	zone2areas := make(map[*zone][]*area)
	for _, z := range zones {
		a := z.inArea
		for a != nil {
			zone2areas[z] = append(zone2areas[z], a)
			a = a.inArea
		}
	}

	// Mark areas having NAT attribute that influence their networks.
	for _, z := range zones {
		if !zoneUsed[z] {
			continue
		}
		for _, a := range zone2areas[z] {
			if len(a.nat) == 0 {
				continue
			}
			a.isUsed = true
		}
	}

	// Mark interfaces / networks which are referenced by used areas.
	var emptyAreas stringList
	for _, a := range areas {
		if !a.isUsed {
			continue
		}
		if anchor := a.anchor; anchor != nil {
			if anchor.isUsed {
				continue
			}
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
				emptyAreas.push(a.name)
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
	for _, n := range networks {
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
				size, _ := up.mask.Size()
				if size != 0 {
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

	markRulesPath(pRules)

	// Call this after topology has been marked.
	ExpandCrypto()

	// 1. call to mark unmanaged parts of topology.
	// Needed to mark unmanaged crypto routers.
	markUnconnected(todoUnmanaged, false)
	todoUnmanaged = nil

	// Mark negated auto interfaces.
	for r, intf := range routerAutoInterfaces {
		if intf.isUsed && !r.isUsed {
			r.isUsed = true
			todoManaged = append(todoManaged, r)
		}
	}
	for key, intf := range networkAutoInterfaces {
		n := key.network
		if intf.isUsed && !n.isUsed {
			n.isUsed = true
			todoManaged = append(todoManaged, n)
		}
	}

	// Connect objects, that are located outside of any path.
	markUnconnected(todoManaged, true)
	for _, intf := range addLater {
		intf.isUsed = true
		intf.router.isUsed = true
	}

	// Mark bridge and bridged networks.
	for _, n := range networks {
		if !n.isUsed {
			continue
		}
		if !n.bridged {
			continue
		}
		for _, in := range n.interfaces {
			if !in.bridged {
				continue
			}
			in.isUsed = true
			bridge := in.router
			bridge.isUsed = true
			for _, out := range bridge.interfaces {
				if out.hardware.name == "device" && bridge.model.class == "ASA" {
					out.isUsed = true
				} else if out.bridged {
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
			if intf.tunnel {
				peer := intf.peer
				real := intf.realIntf
				markPath(real, peer.realIntf)
			}
		}
	}
	for _, r := range routers {
		mark1(r)
	}
	for _, r := range routers6 {
		mark1(r)
	}

	// 2. call to mark unmanaged parts of topology.
	// Need to mark crypto path of crypto routers.
	markUnconnected(todoUnmanaged, false)

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

			// Remove unused nat tags referenced in attribute bind_nat.
			// interface:routerName.netName --> interface:netName
			intfName :=
				"interface:" + strings.TrimPrefix(intf.network.name, "network:")
			if tags := intf.bindNat; tags != nil {
				var used stringList
				for _, tag := range tags {
					if usedNat[tag] {
						used.push(tag)
					}
				}
				if used == nil {
					removeAttributeSrcCodeAt("bind_nat", r, intfName)
				} else if len(tags) != len(used) {
					newList := strings.Join(used, ", ")
					newCode := "bind_nat = " + newList + ";"
					changeAttributeSrcCodeAt("bind_nat", r, intfName, newCode)
				}
			}

			// Remove unused networks referenced in attribute reroute_permit.
			attr := "reroute_permit"
			if l := intf.reroutePermit; l != nil {
				var used stringList
				for _, n := range l {
					if n.isUsed {
						used.push(n.name)
					}
				}
				if used == nil {
					removeAttributeSrcCodeAt(attr, r, intfName)
				} else if len(l) != len(used) {
					newList := strings.Join(used, ", ")
					newCode := attr + " = " + newList + ";"
					changeAttributeSrcCodeAt(attr, r, intfName, newCode)
				}
			}

			// Mark crypto definitions which are referenced by
			// already marked interfaces.
			for _, crypto := range intf.hub {
				crypto.isUsed = true
				typ := crypto.ipsec
				typ.isUsed = true
				typ.isakmp.isUsed = true
			}

			// Mark networks referenced by interfaces
			// implictly marked by expandGroup.
			if intf.isUsed {
				intf.network.isUsed = true
			}
		}
	}
	for _, r := range routers {
		mark2(r)
	}
	for _, r := range routers6 {
		mark2(r)
	}

	// Remove definitions of unused hosts from networks.
	diag.Progress("Removing unused hosts")
	for _, n := range networks {
		if !n.isUsed {
			continue
		}
		hosts := n.hosts

		// Retain at least one host of network with ID hosts.
		if n.hasIdHosts {
			used := false
			for _, h := range hosts {
				if h.isUsed {
					used = true
					break
				}
			}
			if !used {
				hosts[0].isUsed = true
			}
		}

		for _, h := range hosts {
			if h.isUsed {
				continue
			}
			name := h.name

			// Remove trailing network name of ID-host.
			if i := strings.LastIndex(name, "."); i != -1 {
				name = name[:i]
			}
			removeAttributeSrcCode(name, n)
		}
	}

	// Remove definitions of unused interfaces from routers
	diag.Progress("Removing unused interfaces")
	removeIntf := func(r *router) {
		if !r.isUsed {
			return
		}
		for _, intf := range getIntf(r) {
			if intf.isUsed {
				continue
			}
			if intf.tunnel {
				continue
			}

			// Ignore secondary and virtual interfaces.
			if intf.mainIntf != nil {
				continue
			}

			// Remove name of router and optional extension
			// in "interface:router.network", "interface:router.network.virtual",
			// "interface:router.loopback" or "interface:router.loopback.virtual"
			name := intf.name
			tail := name[strings.Index(name, ".")+1:]
			name = "interface:" + strings.TrimSuffix(tail, ".virtual")
			removeAttributeSrcCode(name, r)
		}
	}
	for _, r := range routers {
		removeIntf(r)
	}
	for _, r := range routers6 {
		removeIntf(r)
	}

	// Remove one or multiple occurences of attribute 'owner'.
	// Multiple from embedded host or interface definiton.
	diag.Progress("Removing referenced owners")

	// Must not match attribute 'unknown_owner = restrict;'
	ownerPattern := regexp.MustCompile(`(?m)^[^#]*\bowner[ ]*=`)
	type userer interface {
		getUsed() bool
		setUsed()
	}
	removeOwner := func(ob userer) {
		if !ob.getUsed() {
			return
		}
		if srcCode[ob] == "" {
			return
		}

		for ownerPattern.MatchString(srcCode[ob]) {
			removeAttributeSrcCode("owner", ob)
		}
	}
	for _, x := range networks {
		removeOwner(x)
	}
	for _, x := range routers {
		removeOwner(x)
	}
	for _, x := range routers6 {
		removeOwner(x)
	}
	for _, x := range areas {
		removeOwner(x)
	}
	for _, x := range aggregates {
		removeOwner(x)
	}

	// Remove attribute 'sub_owner'.
	diag.Progress("Removing referenced sub_owners")
	for _, s := range services {
		if s.subOwner != nil {
			removeAttributeSrcCode("sub_owner", s)
		}
	}

	// Remove attribute 'router_attributes'
	// with 'owner', 'policy_distribution_point' and 'general_permit'.
	for _, a := range areas {
		if a.isUsed && a.routerAttributes != nil {
			removeAttributeSrcCode("router_attributes", a)
		}
	}

	// Remove attribute 'policy_distribution_point'
	diag.Progress("Removing referenced policy_distribution_point")
	pdpPattern := regexp.MustCompile("^[^#]*policy_distribution_point")
	removePdp := func(r *router) {
		if r.isUsed && r.policyDistributionPoint != nil &&
			pdpPattern.MatchString(srcCode[r]) {
			removeAttributeSrcCode("policy_distribution_point", r)
		}
	}
	for _, r := range routers {
		removePdp(r)
	}
	for _, r := range routers6 {
		removePdp(r)
	}

	// Prepare emptyGroup
	var emptyGroup string
	if emptyAreas != nil {
		emptyGroup = "group:empty-area"
		fmt.Println(emptyGroup + " = ;")
	}

	substEmptyAreas := func(ob hasSrc) {
		for _, name := range emptyAreas {
			srcCode[ob] = strings.ReplaceAll(srcCode[ob], name, emptyGroup)
		}
	}

	// Print marked parts of netspoc configuration.
	// Routers and networks have been marked by markTopology.
	// Protocols have been marked while pathRules have been processed above.
	// Groups and protocolroups objects have been marked during NormalizeServices.
	var defs []userer
	add := func(ob userer) {

		// There are some internal objects without srcCode.
		if ob.getUsed() && srcCode[ob] != "" {
			defs = append(defs, ob)
		}
	}
	for _, x := range routers {
		add(x)
	}
	for _, x := range routers6 {
		add(x)
	}
	for _, x := range networks {
		add(x)
	}
	for _, x := range aggregates {
		add(x)
	}
	for _, x := range areas {
		add(x)
	}
	for _, x := range groups {
		add(x)
	}
	for _, x := range protocols {
		add(x)
	}
	for _, x := range protocolGroups {
		add(x)
	}
	for _, x := range isakmpMap {
		add(x)
	}
	for _, x := range ipsecMap {
		add(x)
	}
	for _, x := range cryptoMap {
		add(x)
	}

	sort.Slice(defs, func(i, j int) bool {
		return srcIndex[defs[i]] < srcIndex[defs[j]]
	})
	for _, ob := range defs {
		substEmptyAreas(ob)
		fmt.Println(srcCode[ob])
	}

	// Source of pathrestrictions can't be used literally,
	// but must be reconstructed from internal data structure.
	var rDefs []*pathRestriction
	for _, r := range pathrestrictions {
		rDefs = append(rDefs, r)
	}
	sort.Slice(rDefs, func(i, j int) bool {
		return srcIndex[rDefs[i]] < srcIndex[rDefs[j]]
	})
	used := 0
	for _, r := range rDefs {
		for i, intf := range r.elements {
			if intf.isUsed {
				used++
			} else {
				r.elements[i] = nil
			}
		}
		if used < 2 {
			continue
		}
		fmt.Println(r.name + " =")
		for _, intf := range r.elements {
			if intf != nil && !intf.tunnel {
				fmt.Println(" " + intf.name + ",")
			}
		}
		fmt.Println(";")
	}

	// All unwanted services have already been deleted above.
	var sDefs []*service
	for _, s := range services {
		sDefs = append(sDefs, s)
	}
	sort.Slice(sDefs, func(i, j int) bool {
		return srcIndex[sDefs[i]] < srcIndex[sDefs[j]]
	})
	for _, s := range sDefs {
		if !s.disabled {
			substEmptyAreas(s)
			fmt.Println(srcCode[s])
		}
	}
}
