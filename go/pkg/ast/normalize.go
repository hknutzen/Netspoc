// Normalize AST before printing.
//
package ast

import (
	"encoding/binary"
	"net"
	"regexp"
	"sort"
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

func (a *Attribute) Normalize() {
	vals := a.Values
	sort.Slice(vals, func(i, j int) bool {
		return vals[i].Value < vals[j].Value
	})
}

func (a *Rule) Normalize() {
	normalize(a.Src)
	normalize(a.Dst)
	//normalize(a.Prt)
	if attr := a.Log; attr != nil {
		attr.Normalize()
	}
}

func (a *Service) Normalize() {
	for _, attr := range a.Attributes {
		attr.Normalize()
	}
	sortAttr(a.Attributes)
	normalize(a.User)
	for _, r := range a.Rules {
		r.Normalize()
	}
}
