package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"net"
	"strings"
)

func cond(t bool, s1, s2 string) string {
	if t {
		return s1
	}
	return s2
}

func expandTypedName(typ, name string) ipVxGroupObj {
	var obj ipVxGroupObj
	switch typ {
	case "host":
		if x := symTable.host[name]; x != nil {
			obj = x
		}
	case "network":
		if x := symTable.network[name]; x != nil {
			obj = x
		}
	case "any":
		if x := symTable.aggregate[name]; x != nil {
			obj = x
		}
	case "group":
		if x := symTable.group[name]; x != nil {
			obj = x
		}
	case "area":
		if x := symTable.area[name]; x != nil {
			obj = x
		}
	}
	if obj == nil {
		return nil
	}
	return obj
}

// Cache created autointerface objects.
var routerAutoInterfaces = make(map[*router]*autoIntf)

type networkAutoIntfKey = struct {
	network *network
	managed bool
}

var networkAutoInterfaces = make(map[networkAutoIntfKey]*autoIntf)

// Create autoIntf from router.
func getRouterAutoIntf(r *router) *autoIntf {

	// Restore effect of split router from transformation in
	// split_semi_managed_router and move_locked_interfaces.
	if r.origRouter != nil {
		r = r.origRouter
	}

	if r.disabled {
		return nil
	}

	result := routerAutoInterfaces[r]
	if result == nil {
		name := "interface:" + strings.TrimPrefix(r.name, "router:") + ".[auto]"
		result = &autoIntf{
			name:   name,
			object: r,
		}
		routerAutoInterfaces[r] = result
	}
	return result
}

// Create autoIntf from network.
func getNetworkAutoIntf(n *network, managed bool) *autoIntf {
	if n.disabled {
		return nil
	}
	result := networkAutoInterfaces[networkAutoIntfKey{n, managed}]
	if result == nil {
		name := "interface:[" + n.name + "].[auto]"
		result = &autoIntf{
			name:    name,
			object:  n,
			managed: managed,
		}
		networkAutoInterfaces[networkAutoIntfKey{n, managed}] = result
	}
	return result
}

// Remove duplicate elements in place and warn about them.
func removeDuplicates(list groupObjList, ctx string) groupObjList {
	seen := make(map[groupObj]bool)
	var duplicates stringList
	j := 0
	for _, obj := range list {
		if seen[obj] {
			duplicates.push(obj.String())
		} else {
			seen[obj] = true
			list[j] = obj
			j++
		}
	}
	list = list[:j]
	if duplicates != nil {
		warnMsg("Duplicate elements in %s:\n"+duplicates.nameList(), ctx)
	}
	return list
}

func expandIntersection(
	l []ast.Element, ctx string, ipv6, visible, withSubnets bool) groupObjList {

	var nonCompl []groupObjList
	var compl groupObjList
	for _, el := range l {
		var el1 ast.Element
		if x, ok := el.(*ast.Complement); ok {
			el1 = x.Element
		} else {
			el1 = el
		}
		subResult := expandGroup1([]ast.Element{el1},
			"intersection of "+ctx, ipv6, visible, withSubnets)
		for _, obj := range subResult {
			obj.setUsed()
		}
		if _, ok := el.(*ast.Complement); ok {
			compl = append(compl, subResult...)
		} else {
			nonCompl = append(nonCompl, subResult)
		}
	}
	if nonCompl == nil {
		errMsg("Intersection needs at least one element"+
			" which is not complement in %s", ctx)
		return nil
	}
	intersect := make(map[groupObj]bool)
	firstSet := nonCompl[0]
	for _, el := range firstSet {
		intersect[el] = true
	}
	for _, set := range nonCompl[1:] {
		intersect2 := make(map[groupObj]bool)
		for _, el := range set {
			if intersect[el] {
				intersect2[el] = true
			}
		}
		intersect = intersect2
	}
	for _, el := range compl {
		if _, found := intersect[el]; !found {
			warnMsg("Useless delete of %s in %s", el, ctx)
		} else {
			delete(intersect, el)
		}
	}

	// Put result into same order as the elements of first non
	// complemented set. This set contains all elements of resulting
	// set, because we are doing intersection here.
	var result groupObjList
	for _, el := range firstSet {
		if intersect[el] {
			result.push(el)
		}
	}

	// Warn on empty intersection of non empty parts.
	if len(result) == 0 && len(firstSet) > 0 {

		// Reconstruct visual representation of original group.
		var printable stringList
		for _, a := range l {
			var info string
			if x, ok := a.(*ast.Complement); ok {
				info = "!"
				a = x.Element
			} else {
				info = " "
			}
			info += a.GetType() + ":"
			if name := a.GetName(); name != "" {
				info += name
			} else {
				info += "[..]"
			}
			if x, ok := a.(*ast.IntfAuto); ok {
				info += ".[" + x.Selector + "]"
			}
			printable.push(info)
		}
		warnMsg("Empty intersection in %s:\n "+strings.Join(printable, "\n&"), ctx)
	}

	return result
}

// If parameters 'visible' is set, result will be returned after recursion.
// Otherwise it is only used intermediately.
// Visible result from automatic group will be cleaned from duplicates.
// Parameter 'withSubnets' controls if subnets of networks will be
// added to result.
func expandGroup1(list []ast.Element, ctx string, ipv6,
	visible, withSubnets bool) groupObjList {

	// Silently remove unnumbered, bridged and tunnel interfaces from
	// automatic groups.
	check := func(intf *routerIntf) bool {
		return !(intf.tunnel || visible && (intf.unnumbered || intf.bridged))
	}
	result := make(groupObjList, 0)
	for _, el := range list {
		switch x := el.(type) {
		case *ast.Intersection:
			subResult :=
				expandIntersection(x.Elements, ctx, ipv6, visible, withSubnets)
			result = append(result, subResult...)
		case *ast.Complement:
			errMsg(
				"Complement (!) is only supported as part of intersection in %s",
				ctx)
		case *ast.User:
			l := userObj.elements
			if l == nil {
				errMsg("Unexpected reference to 'user' in %s", ctx)
			}
			result = append(result, l...)
			userObj.used = true
		case *ast.IntfAuto:
			selector, managed := x.Selector, x.Managed
			subObjects := expandGroup1(
				x.Elements, "interface:[..].["+selector+"] of "+ctx,
				ipv6, false, false)
			routerSeen := make(map[*router]bool)
			for _, obj := range subObjects {
				obj.setUsed()
				switch x := obj.(type) {
				case *network:
					if selector == "all" {
						if x.isAggregate {

							// We can't simply take
							// aggregate -> networks -> interfaces,
							// because subnets may be missing.
							if size, _ := x.mask.Size(); size != 0 {
								errMsg("Must not use interface:[..].[all]\n"+
									" with %s having ip/mask\n"+
									" in %s", x.name, ctx)
							}
							for _, intf := range x.zone.interfaces {
								r := intf.router
								if (r.managed != "" || r.routingOnly) && check(intf) {
									result.push(intf)
								}
							}
						} else if managed {

							// Find managed interfaces of non aggregate network.
							for _, intf := range x.interfaces {
								r := intf.router
								if (r.managed != "" || r.routingOnly) && check(intf) {
									result.push(intf)
								}
							}
						} else {

							// Find all interfaces of non aggregate network.
							for _, intf := range x.interfaces {
								if check(intf) {
									result.push(intf)
								}
							}
						}
					} else {
						if x.isAggregate {
							errMsg("Must not use interface:[any:..].[auto] in %s",
								ctx)
						} else if a := getNetworkAutoIntf(x, managed); a != nil {
							result.push(a)
						}
					}
				case *routerIntf:
					r := x.router
					if routerSeen[r] {
						continue
					}
					routerSeen[r] = true
					if managed && r.managed == "" && !r.routingOnly {
						// Do nothing.
					} else if selector == "all" {
						for _, intf := range getIntf(r) {
							if check(intf) {
								result.push(intf)
							}
						}
					} else if a := getRouterAutoIntf(r); a != nil {
						result.push(a)
					}
				case *area:
					var routers []*router

					// Prevent duplicates and border routers.
					seen := make(map[*router]bool)

					// Don't add routers at border of this area.
					for _, intf := range x.border {
						seen[intf.router] = true
					}

					// Add routers at border of security zones inside
					// current area.
					for _, z := range x.zones {
						for _, intf := range z.interfaces {
							r := intf.router
							if !seen[r] {
								seen[r] = true
								routers = append(routers, r)
							}
						}
					}
					if managed {

						// Remove semi managed routers.
						j := 0
						for _, r := range routers {
							if r.managed != "" || r.routingOnly {
								routers[j] = r
								j++
							}
						}
						routers = routers[:j]
					} else {
						for _, z := range x.zones {
							for _, r := range z.unmanagedRouters {
								routers = append(routers, r)
							}
						}
					}
					if selector == "all" {
						for _, r := range routers {
							for _, intf := range getIntf(r) {
								if check(intf) {
									result.push(intf)
								}
							}
						}
					} else {
						for _, r := range routers {
							if a := getRouterAutoIntf(r); a != nil {
								result.push(a)
							}
						}
					}
				case *autoIntf:
					obj := x.object
					if r, ok := obj.(*router); ok {
						if routerSeen[r] {
							continue
						}
						routerSeen[r] = true
						if managed && !(r.managed != "" || r.routingOnly) {

							// This router has no managed interfaces.
						} else if selector == "all" {
							for _, intf := range getIntf(r) {
								if check(intf) {
									result.push(intf)
								}
							}
						} else if a := getRouterAutoIntf(r); a != nil {
							result.push(a)
						}
					} else {
						errMsg("Can't use %s inside interface:[..].[%s] of %s",
							x, selector, ctx)
					}
				default:
					errMsg("Unexpected '%s' in interface:[..].[%s] of %s",
						obj, selector, ctx)
				}
			}
		case *ast.IntfRef:
			if x.Network == "[" {
				// interface:name.[xxx]
				selector := x.Extension
				var r *router
				if ipv6 {
					r = symTable.router6[x.Router]
				} else {
					r = symTable.router[x.Router]
				}
				if r != nil {
					if selector == "all" {
						for _, intf := range getIntf(r) {
							if check(intf) {
								result.push(intf)
							}
						}
					} else if a := getRouterAutoIntf(r); a != nil {
						result.push(a)
					}
				} else {
					errMsg("Can't resolve %s:%s.[%s] in %s",
						x.Type, x.Router, x.Extension, ctx)
				}
			} else {
				// interface:name.name
				name := x.Router + "." + x.Network
				if e := x.Extension; e != "" {
					name += "." + e
				}
				if intf, found := symTable.routerIntf[name]; found {
					if !intf.disabled {
						result.push(intf)
					}
				} else {
					errMsg("Can't resolve %s:%s in %s", x.Type, name, ctx)
				}
			}
		case ast.AutoElem:
			subObjects := expandGroup1(x.GetElements(),
				x.GetType()+":[..] of "+ctx, ipv6, false, false)
			for _, obj := range subObjects {
				obj.setUsed()
			}

			getAggregates :=
				func(obj groupObj, ip net.IP, mask net.IPMask) netList {

					var zones []*zone
					switch x := obj.(type) {
					case *area:
						seen := make(map[*zone]bool)
						for _, z := range x.zones {
							if c := z.zoneCluster; c != nil {
								z = c[0]
								if seen[z] {
									continue
								} else {
									seen[z] = true
								}
							}
							zones = append(zones, z)
						}
					case *network:
						if x.isAggregate {
							zones = append(zones, x.zone)
						}
					}
					if zones == nil {
						return nil
					}
					result := netList{}
					for _, z := range zones {

						// Silently ignore loopback aggregate.
						if z.loopback {
							continue
						}
						result = append(result, getAny(z, ip, mask, visible)...)
					}
					return result
				}
			getNetworks := func(obj groupObj, withSubnets bool) netList {
				result := netList{}
				switch x := obj.(type) {
				case *host:
					return netList{x.network}
				case *routerIntf:

					// Ignore network at managed loopback interface.
					if x.loopback && x.router.managed != "" {
						return netList{}
					} else {
						return netList{x.network}
					}
				case *network:
					if !x.isAggregate {
						result.push(x)
					} else {

						// Take aggregate directly. Don't use next "case"
						// below, where it would be changed to non matching
						// aggregate with IP 0/0.
						result = append(result, x.networks...)
					}
				default:
					if list := getAggregates(obj, nil, nil); len(list) > 0 {
						for _, agg := range list {

							// Check type, because getAggregates
							// eventually returns non aggregate network if
							// one matches 0/0.
							if agg.isAggregate {
								result = append(result, agg.networks...)
							} else {
								result.push(agg)
							}
						}
					} else {
						return nil
					}
				}
				if withSubnets {
					var getSubnets func(l netList) netList
					getSubnets = func(l netList) netList {
						var result netList
						for _, n := range l {
							if subnets := n.networks; len(subnets) > 0 {
								result = append(result, subnets...)
								result = append(result, getSubnets(subnets)...)
							}
						}
						return result
					}
					result = append(result, getSubnets(result)...)
				}
				return result
			}
			switch x.GetType() {
			case "host":
				for _, obj := range subObjects {
					switch x := obj.(type) {
					case *host:
						result.push(x)
						continue
					case *routerIntf:
						errMsg("Unexpected '%s' in host:[..] of %s", x, ctx)
						continue
					}
					if networks := getNetworks(obj, true); networks != nil {
						for _, n := range networks {
							for _, h := range n.hosts {
								result.push(h)
							}
						}
					} else {
						errMsg("Unexpected '%s' in host:[..] of %s", obj, ctx)
					}
				}
			case "network":

				// Ignore duplicate networks resulting from different
				// interfaces connected to the same network.
				seen := make(map[*network]bool)

				for _, obj := range subObjects {
					if networks := getNetworks(obj, withSubnets); networks != nil {
						for _, n := range networks {

							// Silently remove crosslink network from
							// automatic groups.
							if !visible || !n.crosslink {
								if !seen[n] {
									seen[n] = true
									result.push(n)
								}
							}
						}
					} else {
						errMsg("Unexpected '%s' in network:[..] of %s", obj, ctx)
					}
				}
			case "any":
				x := x.(*ast.AggAuto)
				var ip net.IP
				var mask net.IPMask
				if n := x.Net; n != nil {
					ip = getVxIP(n.IP, ipv6, "any:[..]", ctx)
					mask = n.Mask
				}

				// Ignore duplicate aggregates resulting
				// - from different interfaces connected to the same aggregate,
				// - group of aggregates.
				seen := make(map[*network]bool)

				for _, obj := range subObjects {
					if l := getAggregates(obj, ip, mask); l != nil {
						for _, agg := range l {
							if !seen[agg] {
								seen[agg] = true
								result.push(agg)
							}
						}
					} else if l := getNetworks(obj, false); l != nil {
						for _, n := range l {
							for _, a := range getAny(n.zone, ip, mask, visible) {
								if !seen[a] {
									seen[a] = true
									result.push(a)
								}
							}
						}
					} else {
						errMsg("Unexpected '%s' in any:[..] of %s", obj, ctx)
					}
				}
			default:
				errMsg("Unexpected %s:[..] in %s", x.GetType(), ctx)
			}
		case *ast.NamedRef:
			// An object named simply 'type:name'.
			typ := x.Type
			name := x.Name
			obj := expandTypedName(typ, name)
			if obj == nil {
				errMsg("Can't resolve %s:%s in %s", typ, name, ctx)
				continue
			}
			checkV4V6CrossRef(obj, ipv6, ctx)
			if obj.isDisabled() {
				continue
			}

			// Split a group into its members.
			// There may be two different versions depending on 'visible'.
			if grp, ok := obj.(*objGroup); ok {

				// Two different expanded values, depending on 'visible'.
				var elPtr *groupObjList
				if visible {
					elPtr = &grp.expandedClean
				} else {
					elPtr = &grp.expandedNoClean
				}
				elements := *elPtr

				// Check for recursive definition.
				if grp.recursive {
					errMsg("Found recursion in definition of %s", ctx)
					elements = make(groupObjList, 0)
				} else if elements == nil {

					// Group has not been converted from names to references.

					// Mark group as used.
					grp.isUsed = true

					ctx := typ + ":" + name

					// 'user' must not be referenced in group.
					user := userObj.elements
					userObj.elements = nil
					defer func() { userObj.elements = user }()

					// Add marker for detection of recursive group definition.
					grp.recursive = true
					elements =
						expandGroup1(grp.elements, ctx, ipv6, visible, withSubnets)
					grp.recursive = false

					// Detect and remove duplicate values in group.
					elements = removeDuplicates(elements, ctx)
				}

				// Cache result for further references to the same group
				// in same visible context.
				*elPtr = elements
				result = append(result, elements...)
			} else {
				n, ok := obj.(*network)
				if ok && n.isAggregate {

					// Substitute aggregate by aggregate set of zone cluster.
					// Ignore zone having no aggregate from unnumbered network.
					if cluster := n.zone.zoneCluster; cluster != nil {
						key := ipmask{string(n.ip), string(n.mask)}
						for _, z := range cluster {
							if agg2 := z.ipmask2aggregate[key]; agg2 != nil {
								result.push(agg2)
							}
						}
					} else {
						result.push(n)
					}
				} else {
					result.push(obj)
				}
			}
		}
	}
	return result
}

func checkV4V6CrossRef(obj ipVxGroupObj, ipv6 bool, ctx string) {
	if ipv6 != obj.isIPv6() {
		expected := cond(ipv6, "6", "4")
		found := cond(obj.isIPv6(), "6", "4")
		errMsg("Must not reference IPv%s %s in IPv%s context %s",
			found, obj, expected, ctx)
	}
}

// Parameter showAll is set, if called from command "print-group".
// This changes the result of
// 1. network:[any|area|network:..]:
//    For each resulting network, all subnets of this network in same
//    zone are added.
//    Crosslink networks are no longer suppressed.
// 2. interface:[..].[all]:
//    Unnumbered and bridged interfaces are no longer suppressed.
func expandGroup(l []ast.Element, ctx string, ipv6, showAll bool) groupObjList {
	result := expandGroup1(l, ctx, ipv6, !showAll, showAll)
	return removeDuplicates(result, ctx)
}

func expandGroupInRule(l []ast.Element, ctx string, ipv6 bool) groupObjList {
	list := expandGroup(l, ctx, ipv6, false)

	// Ignore unusable objects.
	j := 0
	for _, obj := range list {
		var ignore string
		switch x := obj.(type) {
		case *network:
			if x.unnumbered {
				ignore = "unnumbered " + x.name
			} else if x.crosslink {
				ignore = "crosslink " + x.name
			} else if x.isAggregate {
				if x.hasIdHosts {
					ignore = x.name + " with software clients"
				}
			}
		case *routerIntf:
			if x.bridged {
				ignore = "bridged " + x.name
			} else if x.unnumbered {
				ignore = "unnumbered " + x.name
			} else if x.short {
				ignore = x.name + " without IP address"
			}
		case *area:
			ignore = obj.String()
		}
		if ignore != "" {
			warnMsg("Ignoring " + ignore + " in " + ctx)
		} else {
			list[j] = obj
			j++
		}
	}
	list = list[:j]
	return list
}
