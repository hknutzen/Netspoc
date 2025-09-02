// This file implements printing of AST nodes.

package printer

import (
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
)

type printer struct {
	// Current state
	output []byte // raw printer result
	indent int    // current indentation
}

func (p *printer) print(line string) {
	if line != "" {
		for range p.indent {
			p.output = append(p.output, ' ')
		}
		p.output = append(p.output, []byte(line)...)
	}
	p.output = append(p.output, '\n')
}

func (p *printer) emptyLine() {
	l := len(p.output)
	if l < 2 || p.output[l-1] != '\n' || p.output[l-2] != '\n' {
		p.output = append(p.output, '\n')
	}
}

func (p *printer) preComment(n ast.Node) {
	if c := n.PreComment(); c != "" {
		lines := strings.Split(c, "\n")
		for _, l := range lines {
			p.print(l)
		}
	}
}

func utfLen(s string) int {
	return len([]rune(s))
}

func isShort(l []ast.Element) string {
	if len(l) == 1 {
		switch x := l[0].(type) {
		case *ast.NamedRef:
			return x.Type + ":" + x.Name
		case *ast.User:
			return "user"
		}
	}
	return ""
}

func (p *printer) subElements(p1, p2 string, l []ast.Element, stop string) {
	if name := isShort(l); name != "" {
		if !strings.HasSuffix(p2, "[") {
			p2 += " "
		}
		p.print(p1 + p2 + name + stop)
	} else {
		p.print(p1 + p2)
		ind := utfLen(p1)
		p.indent += ind
		p.elementList(l, stop)
		p.indent -= ind
	}
}

func (p *printer) element(pre string, el ast.Element, post string) {
	switch x := el.(type) {
	case *ast.User, *ast.NamedRef, *ast.IntfRef:
		p.print(pre + el.String() + post)
	case *ast.SimpleAuto:
		p.subElements(pre, x.Type+":[", x.Elements, "]"+post)
	case *ast.AggAuto:
		p2 := x.Type + ":["
		if x.Net != "" {
			p2 += "ip"
			if x.IPV6 {
				p2 += "6"
			}
			p2 += " = " + x.Net + " &"
		}
		p.subElements(pre, p2, x.Elements, "]"+post)
	case *ast.IntfAuto:
		p2 := x.Type + ":["
		stop := "].[" + x.Selector + "]" + post
		if x.Managed {
			p2 += "managed &"
		}
		p.subElements(pre, p2, x.Elements, stop)
	case *ast.Intersection:
		p.intersection(pre, x.Elements, post)
	case *ast.Complement:
		p.element("! ", x.Element, post)
	}
}

func (p *printer) intersection(pre string, l []ast.Element, post string) {
	p.preComment(l[0])
	p.element(pre, l[0], l[0].PostComment())
	ind := utfLen(pre)
	p.indent += ind
	for _, el := range l[1:] {
		pre := "&"
		if x, ok := el.(*ast.Complement); ok {
			pre += "!"
			el = x.Element
		}
		pre += " "
		p.preComment(el)
		p.element(pre, el, el.PostComment())
	}
	p.print(post)
	p.indent -= ind
}

func (p *printer) elementList(l []ast.Element, stop string) {
	p.indent++
	for _, el := range l {
		p.preComment(el)
		p.element("", el, ","+el.PostComment())
	}
	p.indent--
	p.print(stop)
}

func (p *printer) description(n ast.Toplevel) {
	if d := n.GetDescription(); d != nil {
		// Remove leading and trailing whitespace.
		// Prevent two spaces before comment when printing.
		// Remove trailing ';'.
		t := strings.TrimRight(strings.TrimSpace(d.Text), " \t\r;")
		// Ignore empty description.
		if t != "" {
			p.indent++
			p.preComment(d)
			p.print("description = " + t + d.PostComment())
			p.indent--
			p.emptyLine()
		}
	}
}

func (p *printer) topListHead(n ast.Toplevel) {
	p.print(n.GetName() + " =")
	p.description(n)
}

func (p *printer) topElementList(n *ast.TopList) {
	p.topListHead(n)
	p.elementList(n.Elements, ";")
}

func (p *printer) topProtocol(n *ast.Protocol) {
	// Add whitespace before printing protocol modifier.
	proto := strings.ReplaceAll(n.Value, ",", ", ") + ";"
	// Print name and value on different lines, if protocol has
	// description or trailing comment.
	if n.GetDescription() != nil {
		p.print(n.Name + " =")
		p.description(n)
		p.indent++
		p.print(proto)
		p.indent--
	} else {
		p.print(n.Name + " = " + proto)
	}
}

func (p *printer) topProtocolList(n *ast.Protocolgroup) {
	p.topListHead(n)
	p.indent++
	for _, el := range n.ValueList {
		p.preComment(el)
		p.print(el.Value + "," + el.PostComment())
	}
	p.indent--
	p.print(";")
}

const shortName = 10

func (p *printer) namedUnion(prefix string, n *ast.NamedUnion) {
	p.preComment(n)
	name := prefix + n.Name
	l := n.Elements
	pre := name + " = "
	if len(l) == 0 {
		p.print(pre + ";" + n.PostComment())
		return
	}

	// Put first value on same line with name, if it has no comment.
	first := l[0]
	var rest []ast.Element
	ind := utfLen(pre)
	if len(name) > shortName {
		ind = 1
	}
	cmt := first.PreComment()
	if cmt != "" || len(l) > 1 && ind == 1 {
		p.print(pre[:len(pre)-1])
		rest = l
	} else {
		rest = l[1:]
		var post string
		if len(rest) == 0 {
			post = ";"
		} else {
			post = ","
		}
		p.element(pre, first, post+first.PostComment())
	}

	// Show other lines with same indentation as first line.
	if len(rest) != 0 {
		p.indent += ind
		for _, v := range rest {
			p.preComment(v)
			p.element("", v, ","+v.PostComment())
		}
		p.print(";")
		p.indent -= ind
	}
}

func (p *printer) namedValueList(name string, l []*ast.Value) {

	// Put first value(s) on same line with name, if it has no comment.
	first := l[0]
	var rest []*ast.Value
	pre := name + " = "
	var ind int
	cmt := first.PreComment()
	if cmt != "" || (len(name) > shortName && len(l) > 1) {
		p.print(pre[:len(pre)-1])
		ind = 1
		rest = l
	} else if name == "model" || len(l) == 1 {
		line, comment := getValueList(l)
		p.print(pre + line + comment)
	} else {
		ind = utfLen(pre)
		rest = l[1:]
		p.print(pre + first.Value + "," + first.PostComment())
	}

	// Show other lines with same indentation as first line.
	if len(rest) != 0 {
		p.indent += ind
		for _, v := range rest {
			p.preComment(v)
			p.print(v.Value + "," + v.PostComment())
		}
		if ind == 1 {
			p.indent -= ind
			p.print(";")
		} else {
			p.print(";")
			p.indent -= ind
		}
	}
}

func (p *printer) complexValue(n *ast.Attribute) {
	pre := n.Name + " = {"
	p.print(pre)
	p.indent++
	for _, a := range n.ComplexValue {
		p.attribute(a)
	}
	p.indent--
	p.print("}")
}

func (p *printer) attribute(n *ast.Attribute) {
	p.preComment(n)
	name := n.Name
	if l := n.ValueList; l != nil {
		if len(l) == 0 {
			p.print(name + " = ;" + n.PostComment())
		} else {
			p.namedValueList(name, l)
		}
	} else if l := n.ComplexValue; l != nil {
		if name == "virtual" || strings.Contains(name, ":") {
			p.shortAttributeList(name, l)
		} else {
			p.complexValue(n)
		}
	} else {
		// Short attribute without values.
		p.print(name + ";" + n.PostComment())
	}
}

func (p *printer) attributeList(l []*ast.Attribute) {
	p.indent++
	for _, a := range l {
		p.attribute(a)
	}
	p.indent--
}

func (p *printer) shortAttributeList(name string, l []*ast.Attribute) {
	val, comment := getAttrList(l)
	p.print(name + val + comment)
}

func (p *printer) rule(n *ast.Rule) {
	p.preComment(n)
	action := "permit"
	if n.Deny {
		action = "deny  "
	}
	action += " "
	ind := len(action)
	p.namedUnion(action, n.Src)
	p.indent += ind
	p.namedUnion("", n.Dst)
	p.attribute(n.Prt)
	if a := n.Log; a != nil {
		p.attribute(a)
	}
	p.indent -= ind
}

func (p *printer) topStructHead(n ast.Toplevel) {
	p.print(n.GetName() + " = {" + n.PostComment())
	p.description(n)
}

func (p *printer) service(n *ast.Service) {
	p.topStructHead(n)
	if l := n.Attributes; l != nil {
		p.emptyLine()
		p.attributeList(l)
		p.emptyLine()
	}
	p.indent++
	if n.Foreach {
		p.print("user = foreach")
		p.elementList(n.User.Elements, ";")
	} else {
		p.namedUnion("", n.User)
	}
	for _, r := range n.Rules {
		p.rule(r)
	}
	p.indent--
	p.print("}")
}

func getValueList(l []*ast.Value) (string, string) {
	line := ""
	var comment string
	for _, v := range l {
		if line != "" {
			line += ", "
		}
		line += v.Value
		if c := v.PostComment(); c != "" {
			comment = c
		}
	}
	return line + ";", comment
}

func getAttr(n *ast.Attribute) (string, string) {
	var val string
	var comment string
	if l := n.ValueList; l != nil {
		var vl string
		vl, comment = getValueList(l)
		val += " = " + vl
	} else if l := n.ComplexValue; l != nil {
		val, comment = getAttrList(l)
	} else {
		comment = n.PostComment()
		val = ";"
	}
	return n.Name + val, comment
}

func getAttrList(l []*ast.Attribute) (string, string) {
	var line string
	var comment string
	for _, a := range l {
		var val string
		val, comment = getAttr(a)
		line += " " + val
	}
	return " = {" + line + " }", comment
}

func (p *printer) indentedAttribute(n *ast.Attribute, max int) {
	p.preComment(n)
	name := n.Name
	if len := utfLen(name); len < max {
		name += strings.Repeat(" ", max-len)
	}
	p.shortAttributeList(name, n.ComplexValue)
}

func getMaxAndNoIndent(
	l []*ast.Attribute, simple map[string]bool) (int, map[*ast.Attribute]bool) {

	max := 0
	noIndent := make(map[*ast.Attribute]bool)
ATTR:
	for _, a := range l {
		if l2 := a.ComplexValue; l2 != nil {
			dual := false
			for _, a2 := range l2 {
				if len(l2) > 3 && strings.HasPrefix(a2.Name, "ip") {
					if dual {
						noIndent[a] = true
						continue ATTR
					}
					dual = true
				}
				if !simple[a2.Name] {
					noIndent[a] = true
					continue ATTR
				}
			}
			if len := utfLen(a.Name); len > max {
				max = len
			}
		}
	}
	return max, noIndent
}

func (p *printer) indentedAttributeList(
	l []*ast.Attribute, simple map[string]bool) {

	p.indent++
	max, noIndent := getMaxAndNoIndent(l, simple)
	for _, a := range l {
		if a.ComplexValue == nil {
			p.attribute(a)
		} else if noIndent[a] {
			p.preComment(a)
			p.complexValue(a)
		} else {
			p.indentedAttribute(a, max)
		}
	}
	p.indent--
}

var simpleHostAttr = map[string]bool{
	"ip":    true,
	"ip6":   true,
	"range": true,
	"owner": true,
}

func (p *printer) network(n *ast.Network) {
	p.topStructHead(n)
	p.attributeList(n.Attributes)
	p.indentedAttributeList(n.Hosts, simpleHostAttr)
	p.print("}")
}

var simpleIntfAttr = map[string]bool{
	"ip":         true,
	"ip6":        true,
	"unnumbered": true,
	"negotiated": true,
	"hardware":   true,
	"loopback":   true,
	"vip":        true,
	"owner":      true,
}

func (p *printer) router(n *ast.Router) {
	p.topStructHead(n)
	p.attributeList(n.Attributes)
	p.indentedAttributeList(n.Interfaces, simpleIntfAttr)
	p.print("}")
}

func (p *printer) namedUnionIfSet(n *ast.NamedUnion) {
	if n != nil {
		p.indent++
		p.namedUnion("", n)
		p.indent--
	}
}

func (p *printer) area(n *ast.Area) {
	p.topStructHead(n)
	p.attributeList(n.Attributes)
	p.namedUnionIfSet(n.Border)
	p.namedUnionIfSet(n.InclusiveBorder)
	p.print("}")
}

func (p *printer) topStruct(n *ast.TopStruct) {
	p.topStructHead(n)
	p.attributeList(n.Attributes)
	p.print("}")
}

func (p *printer) toplevel(n ast.Toplevel) {
	p.preComment(n)
	switch x := n.(type) {
	case *ast.TopStruct:
		p.topStruct(x)
	case *ast.TopList:
		p.topElementList(x)
	case *ast.Protocol:
		p.topProtocol(x)
	case *ast.Protocolgroup:
		p.topProtocolList(x)
	case *ast.Service:
		p.service(x)
	case *ast.Network:
		p.network(x)
	case *ast.Router:
		p.router(x)
	case *ast.Area:
		p.area(x)
	}
}

func isSimpleNet(t ast.Toplevel) bool {
	if n, ok := t.(*ast.Network); ok {
		if len(n.Hosts) == 0 && n.Description == nil {
			dual := false
			for _, a := range n.Attributes {
				if a.PreComment() != "" {
					return false
				}
				switch a.Name {
				case "ip", "ip6":
					if len(n.Attributes) > 3 && dual {
						return false
					}
					dual = true
				case "owner", "crosslink", "unnumbered", "unnumbered6":
				default:
					return false
				}
			}
			return true
		}
	}
	return false
}

func (p *printer) simpleNetList(l []*ast.Network) {
	max := 0
	for _, a := range l {
		if len := utfLen(a.Name); len > max {
			max = len
		}
	}
	for _, a := range l {
		name := a.Name
		if len := utfLen(name); len < max {
			name += strings.Repeat(" ", max-len)
		}
		p.preComment(a)
		p.shortAttributeList(name, a.Attributes)
	}
}

func File(aF *ast.File) []byte {
	p := new(printer)

	list := aF.Nodes
	var simple []*ast.Network
	for i, t := range list {
		if isSimpleNet(t) {
			simple = append(simple, t.(*ast.Network))
			continue
		}
		if simple != nil {
			p.simpleNetList(simple)
			p.print("")
			simple = nil
		}
		p.toplevel(t)
		// Add empty line between output.
		if i != len(list)-1 {
			p.print("")
		}
	}
	p.simpleNetList(simple)

	// Print comments
	// - in file without nodes and
	// - at end of file.
	if c := aF.BottomCmt; c != "" {
		p.print(c)
	}
	return p.output
}
