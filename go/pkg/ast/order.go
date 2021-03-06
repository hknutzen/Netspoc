// Sort list elements of AST before printing.
//
package ast

import (
	"encoding/binary"
	"net"
	"regexp"
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

var ipv4NameRegex = regexp.MustCompile(`(?:^|[-_])(\d+_\d+_\d+_\d+)`)

func ipV4ToInt(s string) int {
	if ip := net.ParseIP(s); ip != nil {
		ip = ip.To4()
		return int(binary.BigEndian.Uint32(ip))
	}
	return 0
}

func findIPv4InName(s string) int {
	l := ipv4NameRegex.FindStringSubmatch(s)
	if l != nil {
		m := strings.ReplaceAll(l[1], "_", ".")
		return ipV4ToInt(m)
	}
	return 0
}

func sortElem(l []Element) {
	sort.SliceStable(l, func(i, j int) bool {
		t1 := typeOrder[l[i].GetType()]
		t2 := typeOrder[l[j].GetType()]
		if t1 != t2 {
			return t1 < t2
		}
		getNameIP := func(el Element) (string, int) {
			if x, ok := el.(*Intersection); ok {
				el = x.Elements[0]
			}
			if x, ok := el.(NamedElem); ok {
				n := x.GetName()
				i := findIPv4InName(n)
				return n, i
			}
			return "", 0
		}
		n1, i1 := getNameIP(l[i])
		n2, i2 := getNameIP(l[j])
		if i1 == i2 {
			return n1 < n2
		}
		return i1 < i2
	})
}

func getType(v string) string {
	i := strings.Index(v, ":")
	if i == -1 {
		return ""
	}
	return v[:i]
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
		for i, d1 := range n1 {
			if i >= len(n2) {
				return false
			}
			if d2 := n2[i]; d1 != d2 {
				return d1 < d2
			}
		}
		return true
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
		return vals[i].Value < vals[j].Value
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

func (a *Service) Order() {
	for _, attr := range a.Attributes {
		attr.Order()
	}
	sortAttr(a.Attributes)
	a.User.Order()
	for _, r := range a.Rules {
		r.Order()
	}
}

var ipv4StartRegex = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+`)

func sortByIP(l []*Attribute) {
	getIPv4 := func(host *Attribute) int {
		for _, a := range host.ComplexValue {
			if a.Name == "ip" || a.Name == "range" {
				list := a.ValueList
				if len(list) >= 1 {
					return ipV4ToInt(ipv4StartRegex.FindString(list[0].Value))
				}
			}
		}
		return 0
	}
	sort.SliceStable(l, func(i, j int) bool {
		return getIPv4(l[i]) < getIPv4(l[j])
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
