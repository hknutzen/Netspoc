// Normalize AST before printing.
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

var ipv4Regex = regexp.MustCompile(`\d+_\d+_\d+_\d+`)

func findIPv4(n string) int {
	if m := ipv4Regex.FindString(n); m != "" {
		m = strings.ReplaceAll(m, "_", ".")
		if ip := net.ParseIP(m); ip != nil {
			ip = ip.To4()
			return int(binary.BigEndian.Uint32(ip))
		}
	}
	return 0
}

func sortElem(l []Element) {
	sort.SliceStable(l, func(i, j int) bool {
		t1 := typeOrder[l[i].getType()]
		t2 := typeOrder[l[j].getType()]
		if t1 != t2 {
			return t1 < t2
		}
		n1 := l[i].getName()
		n2 := l[j].getName()
		i1 := findIPv4(n1)
		i2 := findIPv4(n2)
		if i1 == i2 {
			return n1 < n2
		}
		return i1 < i2
	})
}

// Place named protocols before simple protocols.
var protoOrder = map[string]int{
	"protocolgroup": -2,
	"protocol":      -1,
}

func sortProto(l []*Value) {
	sort.Slice(l, func(i, j int) bool {
		t1 := protoOrder[l[i].getType()]
		t2 := protoOrder[l[j].getType()]
		if t1 != t2 {
			return t1 < t2
		}
		if t1 != 0 {
			// Named protocol or protocolgroup.
			n1 := l[i].getName()
			n2 := l[j].getName()
			return n1 < n2
		}
		// Simple protocol
		d1 := strings.Split(l[i].Value, " ")
		d2 := strings.Split(l[j].Value, " ")
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
					p := strings.Split(s, "-")
					switch len(p) {
					case 0:
						return 1, 65535
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
				case 0:
					s1, s2 = getPorts("")
					p1, p2 = getPorts("")
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
		return false
	})
}

func sortAttr(l []*Attribute) {
	sort.Slice(l, func(i, j int) bool {
		return l[i].Name < l[j].Name
	})
}

func normalize(l []Element) {
	for _, n := range l {
		n.Normalize()
	}
	sortElem(l)
}

func (a *Base) Normalize() {}

func (a *SimpleAuto) Normalize() {
	normalize(a.Elements)
}

func (a *Complement) Normalize() {
	a.Element.Normalize()
}

func (a *Intersection) Normalize() {
	for _, n := range a.Elements {
		n.Normalize()
	}
}

func (a *TopList) Normalize() {
	normalize(a.Elements)
}

func (a *NamedUnion) Normalize() {
	normalize(a.Elements)
}

func (a *Attribute) Normalize() {
	vals := a.ValueList
	sort.Slice(vals, func(i, j int) bool {
		return vals[i].Value < vals[j].Value
	})
	for _, attr := range a.ComplexValue {
		attr.Normalize()
	}
	sortAttr(a.ComplexValue)
}

func (a *Rule) Normalize() {
	a.Src.Normalize()
	a.Dst.Normalize()
	sortProto(a.Prt.ValueList)
	if attr := a.Log; attr != nil {
		attr.Normalize()
	}
}

func (a *Service) Normalize() {
	for _, attr := range a.Attributes {
		attr.Normalize()
	}
	sortAttr(a.Attributes)
	a.User.Normalize()
	for _, r := range a.Rules {
		r.Normalize()
	}
}
