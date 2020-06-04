// This file implements printing of AST nodes.

package printer

import (
	"fmt"
	"github.com/hknutzen/spoc-parser/ast"
)

type printer struct {
	src []byte // Original source code with comments.
	// Current state
	output []byte // raw printer result
	indent int    // current indentation
}

func (p *printer) init(src []byte) {

	// Add \n at end of last line.
	l := len(src)
	if l > 0 && src[l-1] != 0x0a {
		src = append(src, 0x0a)
	}
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

func isShort(l []ast.Element) string {
	if len(l) == 1 {
		el := l[0]
		if x, ok := el.(*ast.NamedRef); ok {
			return x.Typ + ":" + x.Name
		}
	}
	return ""
}

func (p *printer) subElements(pre string, l []ast.Element, stop string) {
	if name := isShort(l); name != "" {
		p.print(pre + name + stop)
	} else {
		p.print(pre)
		p.elementList(l, stop)
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
		out := pre + x.Typ + ":["
		p.subElements(out, x.Elements, "]"+post)
	case *ast.AggAuto:
		out := pre + x.Typ + ":["
		if n := x.Net; n != nil {
			out += "ip = " + n.String() + " & "
		}
		p.subElements(out, x.Elements, "]"+post)
	case *ast.IntfAuto:
		out := pre + x.Typ + ":["
		stop := "].[" + x.Selector + "]" + post
		if x.Managed {
			out += "managed & "
		}
		p.subElements(out, x.Elements, stop)
	case *ast.Intersection:
		p.intersection(pre, x.List, post)
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
	p.element("", l[0], p.TrailingComment(l[0], "&!"))
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

func (p *printer) topList(n *ast.TopList) {
	p.elementList(n.Elements, ";")
}

func (p *printer) group(g *ast.Group) {
	p.topList(&g.TopList)
}

func (p *printer) attribute(n *ast.Attribute) {
	p.PreComment(n, "")

	// Short attribute without values.
	if len(n.Values) == 0 {
		p.print(n.Name + ";" + p.TrailingComment(n, ",;"))
		return
	}
	// Try to put name and values in one line.
	out := n.Name + " = "
	for i, v := range n.Values {
		if i != 0 {
			out += ", "
		}
		out += v.Value
	}
	out += ";" + p.TrailingComment(n, ",;")
	if len(out) < 60 || len(n.Values) == 1 {
		p.print(out)
		return
	}
	// Put many or long values into separate lines.
	p.print(n.Name + " =")
	p.indent++
	for _, v := range n.Values {
		p.PreComment(v, ",")
		p.print(v.Value + "," + p.TrailingComment(v, ",;"))
	}
	p.indent--
	p.print(";")
}

func (p *printer) protocol(el ast.Element, post string) {
	var out string
	switch x := el.(type) {
	case *ast.NamedRef:
		out = x.Typ + ":" + x.Name
	case *ast.SimpleProtocol:
		out = x.Proto
		for _, d := range x.Details {
			out += " " + d
		}
	}
	p.print(out + post)
}

func (p *printer) protocolList(l []ast.Protocol) {
	p.indent++
	for _, el := range l {
		p.PreComment(el, ",")
		p.protocol(el, ","+p.TrailingComment(el, ",;"))
	}
	p.indent--
	p.print(";")
}

func (p *printer) rule(n *ast.Rule) {
	p.PreComment(n, "")
	action := "permit"
	if n.Deny {
		action = "deny  "
	}
	p.print(action)
	p.indent++
	p.print("src =")
	p.elementList(n.Src, ";")
	p.print("dst =")
	p.elementList(n.Dst, ";")
	p.print("prt =")
	p.protocolList(n.Prt)
	if a := n.Log; a != nil {
		p.attribute(a)
	}
	p.indent--
}

func (p *printer) service(n *ast.Service) {
	p.indent++
	for _, a := range n.Attributes {
		p.attribute(a)
	}
	p.print("user =")
	p.elementList(n.User, ";")
	p.indent--
	for _, r := range n.Rules {
		p.rule(r)
	}
	p.print("}")
}

func (p *printer) toplevel(n ast.Toplevel) {
	p.PreComment(n, "")
	sep := " ="
	if !n.IsList() {
		sep += " {"
	}
	pos := n.Pos() + len(n.GetName())
	p.print(n.GetName() + sep + p.TrailingCommentAt(pos, sep))

	if d := n.GetDescription(); d != nil {
		p.PreComment(d, sep)
		p.print("description =" + d.Text + p.TrailingComment(d, "="))
	}

	switch x := n.(type) {
	case *ast.Group:
		p.group(x)
	case *ast.Service:
		p.service(x)
	default:
		panic(fmt.Sprintf("Unknown type: %T", n))
	}
}

func File(list []ast.Toplevel, src []byte) {
	p := new(printer)
	p.init(src)

	for _, t := range list {
		p.toplevel(t)
	}

	fmt.Print(string(p.output))
}
