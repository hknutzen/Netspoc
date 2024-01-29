// Sort list elements of AST before printing.
package ast

import (
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

var typeOrder = map[string]int{
	"group":     1,
	"area":      2,
	"any":       3,
	"network":   4,
	"interface": 5,
	"host":      6,
}

var ipV4NameRegex = regexp.MustCompile(`(?i:^|[-_])(\d{1,3}(?:_\d{1,3}){3})`)
var ipV6NameRegex = regexp.MustCompile(
	`(?i:^|[-_])([\da-f]{1,4}(?:_[\da-f]{1,4}){7})`)

func findIPInName(s string) netip.Addr {
	if l := ipV6NameRegex.FindStringSubmatch(s); l != nil {
		m := strings.ReplaceAll(l[1], "_", ":")
		if ip, err := netip.ParseAddr(m); err == nil {
			return ip
		}
	}
	if l := ipV4NameRegex.FindStringSubmatch(s); l != nil {
		m := strings.ReplaceAll(l[1], "_", ".")
		ip, _ := netip.ParseAddr(m)
		return ip
	}
	return netip.Addr{}
}

func sortElem(l []Element) {
	sort.SliceStable(l, func(i, j int) bool {
		t1 := typeOrder[l[i].GetType()]
		t2 := typeOrder[l[j].GetType()]
		if t1 != t2 {
			return t1 < t2
		}
		getNameIP := func(el Element) (string, netip.Addr) {
			if x, ok := el.(*Intersection); ok {
				el = x.Elements[0]
			}
			if x, ok := el.(NamedElem); ok {
				n := x.GetName()
				ip := findIPInName(n)
				return strings.ToLower(n), ip
			}
			return "", netip.Addr{}
		}
		n1, ip1 := getNameIP(l[i])
		n2, ip2 := getNameIP(l[j])
		return ip1.Less(ip2) || ip1 == ip2 && n1 < n2
	})
}

func getType(v string) string {
	typ, _, found := strings.Cut(v, ":")
	if !found {
		return ""
	}
	return typ
}

func getName(v string) string {
	return v[strings.Index(v, ":")+1:]
}

// Place named protocols before simple protocols.
var protoOrder = map[string]int{
	"protocolgroup": -2,
	"protocol":      -1,
}

func sortProto(l []*Value) {
	sort.Slice(l, func(i, j int) bool {
		v1 := l[i].Value
		v2 := l[j].Value
		o1 := protoOrder[getType(v1)]
		o2 := protoOrder[getType(v2)]
		if o1 != o2 {
			return o1 < o2
		}
		if o1 != 0 {
			return getName(v1) < getName(v2)
		}
		// Simple protocol
		d1 := strings.Split(v1, " ")
		d2 := strings.Split(v2, " ")
		// icmp < ip < proto < tcp < udp
		p1 := d1[0]
		p2 := d2[0]
		if p1 != p2 {
			return p1 < p2
		}
		var n1, n2 []int
		if p1 == "tcp" || p1 == "udp" {
			conv := func(l []string) []int {
				getPorts := func(s string) (int, int) {
					if s == "" {
						return 1, 65535
					}
					p := strings.Split(s, "-")
					switch len(p) {
					case 1:
						n1, _ := strconv.Atoi(p[0])
						return n1, n1
					default:
						n1, _ := strconv.Atoi(p[0])
						n2, _ := strconv.Atoi(p[1])
						return n1, n2
					}
				}
				s := strings.Join(l, "")
				sp := strings.Split(s, ":")
				var s1, s2, p1, p2 int
				switch len(sp) {
				case 1:
					s1, s2 = getPorts("")
					p1, p2 = getPorts(sp[0])
				default:
					s1, s2 = getPorts(sp[0])
					p1, p2 = getPorts(sp[1])
				}
				return []int{p1, p2, s1, s2}
			}
			n1 = conv(d1[1:])
			n2 = conv(d2[1:])
		} else {
			conv := func(l []string) []int {
				r := make([]int, len(l))
				for i, d1 := range l {
					r[i], _ = strconv.Atoi(d1)
				}
				return r
			}
			n1 = conv(d1[1:])
			n2 = conv(d2[1:])
		}
		return slices.Compare(n1, n2) == -1
	})
}

func sortAttr(l []*Attribute) {
	sort.Slice(l, func(i, j int) bool {
		return l[i].Name < l[j].Name
	})
}

func OrderElements(l []Element) {
	for _, n := range l {
		n.Order()
	}
	sortElem(l)
}

func (a *Base) Order() {}

func (a *SimpleAuto) Order() {
	OrderElements(a.Elements)
}

func (a *Complement) Order() {
	a.Element.Order()
}

func (a *Intersection) Order() {
	for _, n := range a.Elements {
		n.Order()
	}
}

func (a *TopList) Order() {
	OrderElements(a.Elements)
}

func (a *Protocolgroup) Order() {
	sortProto(a.ValueList)
}

func (a *NamedUnion) Order() {
	OrderElements(a.Elements)
}

func (a *Attribute) Order() {
	vals := a.ValueList
	sort.Slice(vals, func(i, j int) bool {
		return strings.ToLower(vals[i].Value) < strings.ToLower(vals[j].Value)
	})
}

func (a *Rule) Order() {
	a.Src.Order()
	a.Dst.Order()
	sortProto(a.Prt.ValueList)
	if attr := a.Log; attr != nil {
		attr.Order()
	}
}

func (a *TopStruct) Order() {
	for _, attr := range a.Attributes {
		attr.Order()
	}
}

func (a *Service) Order() {
	sortAttr(a.Attributes)
	a.TopStruct.Order()
	a.User.Order()
	for _, r := range a.Rules {
		r.Order()
	}
}

func sortByIP(l []*Attribute) {
	getIP := func(host *Attribute) netip.Addr {
		for _, a := range host.ComplexValue {
			if a.Name == "ip" || a.Name == "range" {
				list := a.ValueList
				if len(list) >= 1 {
					v := list[0].Value
					if a.Name == "range" {
						v, _, _ = strings.Cut(v, "-")
					}
					v = strings.TrimSpace(v)
					ip, _ := netip.ParseAddr(v)
					return ip
				}
			}
		}
		return netip.Addr{}
	}
	sort.SliceStable(l, func(i, j int) bool {
		return getIP(l[i]).Less(getIP(l[j]))
	})
}

func (a *Network) Order() {
	sortByIP(a.Hosts)
}

// Only sort successive vip interfaces.
func (a *Router) Order() {
	start := -1
	for i, intf := range a.Interfaces {
		vip := false
		for _, a := range intf.ComplexValue {
			if a.Name == "vip" {
				vip = true
				break
			}
		}
		if vip {
			if start == -1 {
				start = i
			}
		} else if start != -1 {
			sortByIP(a.Interfaces[start:i])
			start = -1
		}
	}
	if start != -1 {
		sortByIP(a.Interfaces[start:])
	}
}
