// This file implements printing of AST nodes.

package printer

import (
	"fmt"
	"github.com/hknutzen/spoc-parser/ast"
	"strings"
)

type printer struct {
	src []byte // Original source code with comments.
	// Current state
	output []byte // raw printer result
	indent int    // current indentation
}

func (p *printer) init(src []byte) {
	p.src = src
}

func (p *printer) print(line string) {
	if line != "" {
		for i := 0; i < p.indent; i++ {
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

func utfLen(s string) int {
	return len([]rune(s))
}

func isShort(l []ast.Element) string {
	if len(l) == 1 {
		switch x := l[0].(type) {
		case *ast.NamedRef:
			return x.Typ + ":" + x.Name
		case *ast.User:
			return "user"
		}
	}
	return ""
}

func (p *printer) subElements(p1, p2 string, l []ast.Element, stop string) {
	if name := isShort(l); name != "" {
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
	case *ast.NamedRef:
		p.print(pre + x.Typ + ":" + x.Name + post)
	case *ast.IntfRef:
		ext := x.Extension
		net := x.Network
		if net == "[" {
			net = "[" + ext + "]"
			ext = ""
		} else if ext != "" {
			ext = "." + ext
		}
		p.print(pre + x.Typ + ":" + x.Router + "." + net + ext + post)
	case *ast.SimpleAuto:
		p.subElements(pre, x.Typ+":[", x.Elements, "]"+post)
	case *ast.AggAuto:
		p2 := x.Typ + ":["
		if n := x.Net; n != nil {
			p2 += "ip = " + n.String() + " & "
		}
		p.subElements(pre, p2, x.Elements, "]"+post)
	case *ast.IntfAuto:
		p2 := x.Typ + ":["
		stop := "].[" + x.Selector + "]" + post
		if x.Managed {
			p2 += "managed & "
		}
		p.subElements(pre, p2, x.Elements, stop)
	case *ast.Intersection:
		p.intersection(pre, x.Elements, post)
	case *ast.Complement:
		p.element("! ", x.Element, post)
	case *ast.User:
		p.print(pre + "user" + post)
	default:
		panic(fmt.Sprintf("Unknown element: %T", el))
	}
}

func (p *printer) intersection(pre string, l []ast.Element, post string) {
	// First element already gets pre comment from union.
	p.element(pre, l[0], p.TrailingComment(l[0], "&!"))
	ind := utfLen(pre)
	p.indent += ind
	for _, el := range l[1:] {
		pre := "&"
		if x, ok := el.(*ast.Complement); ok {
			pre += "!"
			el = x.Element
		}
		pre += " "
		p.PreComment(el, "&!")
		p.element(pre, el, p.TrailingComment(el, "&!,;"))
	}
	p.print(post)
	p.indent -= ind
}

func (p *printer) elementList(l []ast.Element, stop string) {
	p.indent++
	for _, el := range l {
		p.PreComment(el, ",")
		post := ","
		if _, ok := el.(*ast.Intersection); ok {
			// Intersection already prints comments of its elements.
			p.element("", el, post)
		} else {
			p.element("", el, post+p.TrailingComment(el, ",;"))
		}
	}
	p.indent--
	p.print(stop)
}

func (p *printer) topElementList(l []ast.Element) {
	p.elementList(l, ";")
}

func (p *printer) topProtocol(n *ast.Protocol) {
	p.indent++
	p.print(n.Value + ";" + p.TrailingComment(n, ";"))
	p.indent--
}

func (p *printer) topProtocolList(l []*ast.Value) {
	p.indent++
	for _, el := range l {
		p.PreComment(el, ",")
		p.print(el.Value + "," + p.TrailingComment(el, ",;"))
	}
	p.indent--
	p.print(";")
}

func (p *printer) namedList(name string, l []ast.Element) {

	// Put first value on same line with name, if it has no comment.
	first := l[0]
	var rest []ast.Element
	pre := name + " = "
	ind := utfLen(pre)
	if p.hasPreComment(first, ",") {
		p.print(pre[:ind-1])
		rest = l
	} else {
		rest = l[1:]
		var post string
		if len(rest) == 0 {
			post = ";"
		} else {
			post = ","
		}
		p.element(pre, first, post+p.TrailingComment(first, ",;"))
	}

	// Show other lines with same indentation as first line.
	if len(rest) != 0 {
		p.indent += ind
		for _, v := range rest {
			p.PreComment(v, ",")
			p.element("", v, ","+p.TrailingComment(v, ",;"))
		}
		p.print(";")
		p.indent -= ind
	}
}

func (p *printer) namedUnion(pre string, n *ast.NamedUnion) {
	p.PreComment(n, "")
	p.namedList(pre+n.Name, n.Elements)
}

const shortList = 40

func (p *printer) namedValueList(name string, l []*ast.Value) {

	// Put first value on same line with name, if it has no comment.
	first := l[0]
	var rest []*ast.Value
	pre := name + " = "
	ind := utfLen(pre)
	if p.hasPreComment(first, ",") {
		p.print(pre[:ind-1])
		rest = l
	} else if line := p.getValueList(l); utfLen(line) <= shortList {
		p.print(pre + line + p.TrailingComment(l[len(l)-1], ",;"))
	} else {
		rest = l[1:]
		var post string
		if len(rest) == 0 {
			post = ";"
		} else {
			post = ","
		}
		p.print(pre + first.Value + post + p.TrailingComment(first, ",;"))
	}

	// Show other lines with same indentation as first line.
	if len(rest) != 0 {
		p.indent += ind
		for _, v := range rest {
			p.PreComment(v, ",")
			p.print(v.Value + "," + p.TrailingComment(v, ",;"))
		}
		p.print(";")
		p.indent -= ind
	}
}

func (p *printer) complexValue(name string, l []*ast.Attribute) {
	pre := name + " = {"
	p.print(pre)
	p.indent++
	for _, a := range l {
		p.attribute(a)
	}
	p.indent--
	p.print("}")
}

func (p *printer) attribute(n *ast.Attribute) {
	p.PreComment(n, "")
	if l := n.ValueList; l != nil {
		p.namedValueList(n.Name, l)
	} else if l := n.ComplexValue; l != nil {
		name := n.Name
		if name == "virtual" || strings.Index(name, ":") != -1 {
			p.print(name + " = {" + p.getAttrList(l) + " }")
		} else {
			p.complexValue(name, l)
		}
	} else {
		// Short attribute without values.
		p.print(n.Name + ";" + p.TrailingComment(n, ",;"))
	}
}

func (p *printer) attributeList(l []*ast.Attribute) {
	p.indent++
	for _, a := range l {
		p.attribute(a)
	}
	p.indent--
}

func (p *printer) rule(n *ast.Rule) {
	p.PreComment(n, "")
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

func (p *printer) service(n *ast.Service) {
	p.emptyLine()
	p.attributeList(n.Attributes)
	p.emptyLine()
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

func (p *printer) getValueList(l []*ast.Value) string {
	line := ""
	for _, v := range l {
		if line != "" {
			line += ", "
		}
		line += v.Value
	}
	return line + ";"
}

func (p *printer) getAttr(n *ast.Attribute) string {
	if l := n.ValueList; l != nil {
		return n.Name + " = " + p.getValueList(l)
	}
	if l := n.ComplexValue; l != nil {
		return n.Name + " = {" + p.getAttrList(l) + " }"
	} else {
		return n.Name + ";"
	}
}

func (p *printer) getAttrList(l []*ast.Attribute) string {
	var line string
	for _, a := range l {
		line += " " + p.getAttr(a)
	}
	return line
}

func (p *printer) indentedAttribute(n *ast.Attribute, max int) {
	p.PreComment(n, "")
	if l := n.ComplexValue; l != nil {
		name := n.Name
		if len := utfLen(name); len < max {
			name += strings.Repeat(" ", max-len)
		}
		p.print(name + " = {" + p.getAttrList(l) + " }" +
			p.TrailingComment(n, "}"))
	} else {
		// Short attribute without values.
		p.print(n.Name + ";" + p.TrailingComment(n, ",;"))
	}
}

func getMaxAndNoIndent(
	l []*ast.Attribute, simple map[string]bool) (int, map[*ast.Attribute]bool) {

	max := 0
	noIndent := make(map[*ast.Attribute]bool)
ATTR:
	for _, a := range l {
		if l2 := a.ComplexValue; l2 != nil {
			for _, a2 := range l2 {
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
		if noIndent[a] {
			p.complexValue(a.Name, a.ComplexValue)
		} else {
			p.indentedAttribute(a, max)
		}
	}
	p.indent--
}

var simpleHostAttr = map[string]bool{
	"ip":    true,
	"range": true,
	"owner": true,
}

func (p *printer) network(n *ast.Network) {
	p.attributeList(n.Attributes)
	p.indentedAttributeList(n.Hosts, simpleHostAttr)
	p.print("}")
}

var simpleIntfAttr = map[string]bool{
	"ip":         true,
	"unnumbered": true,
	"negotiated": true,
	"hardware":   true,
	"loopback":   true,
	"vip":        true,
	"owner":      true,
}

func (p *printer) router(n *ast.Router) {
	p.attributeList(n.Attributes)
	p.indentedAttributeList(n.Interfaces, simpleIntfAttr)
	p.print("}")
}

func (p *printer) topStruct(n *ast.TopStruct) {
	p.attributeList(n.Attributes)
	p.print("}")
}

func (p *printer) toplevel(n ast.Toplevel) {
	p.PreComment(n, "")
	sep := " ="
	if n.IsStruct() {
		sep += " {"
	}
	pos := n.Pos() + len(n.GetName())
	p.print(n.GetName() + sep + p.TrailingCommentAt(pos, sep))

	if d := n.GetDescription(); d != nil {
		p.indent++
		p.PreComment(d, sep)
		p.print("description =" + d.Text + p.TrailingComment(d, "="))
		p.indent--
		p.emptyLine()
	}

	switch x := n.(type) {
	case *ast.TopStruct:
		p.topStruct(x)
	case *ast.TopList:
		p.topElementList(x.Elements)
	case *ast.Protocol:
		p.topProtocol(x)
	case *ast.Protocolgroup:
		p.topProtocolList(x.ValueList)
	case *ast.Service:
		p.service(x)
	case *ast.Network:
		p.network(x)
	case *ast.Router:
		p.router(x)
	default:
		panic(fmt.Sprintf("Unknown type: %T", n))
	}
}

func File(list []ast.Toplevel, src []byte) []byte {
	p := new(printer)
	p.init(src)

	for i, t := range list {
		p.toplevel(t)
		// Add empty line between output.
		if i != len(list)-1 {
			p.print("")
		}
	}

	return p.output
}
