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
	trailing, after := p.PostComment(l[0], "&!")
	if trailing != "" {
		trailing = " " + trailing
	}
	p.element("", l[0], trailing)
	p.comment(head1(after))
	for _, el := range l[1:] {
		pre := "&"
		if x, ok := el.(*ast.Complement); ok {
			pre += "!"
			el = x.Element
		}
		pre += " "
		p.comment(p.PreCommentX(el, "&!", false))
		trailing, after := p.PostComment(el, "&!,;")
		if trailing != "" {
			trailing = " " + trailing
		}
		p.element(pre, el, trailing)
		p.comment(head1(after))
	}
	p.print(post)
}

func (p *printer) elementList(l []ast.Element, stop string) {
	p.indent++
	for i, el := range l {
		p.comment(p.PreCommentX(el, ",", i == 0))
		post := ","
		if _, ok := el.(*ast.Intersection); ok {
			// Intersection already prints comments of its elements.
			p.element("", el, post)
		} else {
			trailing, after := p.PostComment(el, ",;")
			if trailing != "" {
				post += " " + trailing
			}
			p.element("", el, post)
			p.comment(head1(after))
		}
	}
	p.indent--
	p.print(stop)
}

func (p *printer) topList(n *ast.TopList, first bool) {
	p.comment(p.PreCommentX(n, "", first))
	pos := n.Pos() + len(n.Name)
	trailing, after := p.FindCommentAfter(pos, "=")
	post := " ="
	if trailing != "" {
		post += " " + trailing
	}
	p.print(n.Name + post)
	if d := n.Description; d != nil {
		p.comment(p.FindCommentBefore(d.Pos(), "="))
		trailing, after = p.PostComment(d, "=")
		p.print("description =" + d.Text + trailing)
	}
	p.comment(headN1(after))

	p.elementList(n.Elements, ";")
}

func (p *printer) group(g *ast.Group, first bool) {
	p.topList(&g.TopList, first)
}

func (p *printer) attribute(a *ast.Attribute) {
	// Short attribute without values.
	if len(a.Values) == 0 {
		p.print(a.Name + ";")
		return
	}
	// Try to put name and values in one line.
	out := a.Name + " = "
	for i, v := range a.Values {
		if i != 0 {
			out += ", "
		}
		out += v
	}
	out += ";"
	if len(out) < 60 || len(a.Values) == 1 {
		p.print(out)
		return
	}
	// Put many or long values into separate lines.
	p.print(a.Name + " = ")
	p.indent++
	for _, v := range a.Values {
		p.print(v + ",")
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
	for i, el := range l {
		p.comment(p.PreCommentX(el, ",", i == 0))
		post := ","
		trailing, after := p.PostComment(el, ",;")
		if trailing != "" {
			post += " " + trailing
		}
		p.protocol(el, post)
		p.comment(head1(after))
	}
	p.indent--
	p.print(";")
}

func (p *printer) rule(n *ast.Rule) {
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
	p.indent--
}

func (p *printer) service(n *ast.Service, first bool) {
	p.comment(p.PreCommentX(n, "", first))
	pos := n.Pos() + len(n.Name)
	trailing, after := p.FindCommentAfter(pos, "={")
	post := " = {"
	if trailing != "" {
		post += " " + trailing
	}
	p.print(n.Name + post)
	p.indent++
	if d := n.Description; d != nil {
		p.comment(p.FindCommentBefore(d.Pos(), "="))
		trailing, after = p.PostComment(d, "=")
		p.print("description =" + d.Text + trailing)
	}
	p.comment(after)
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

func (p *printer) toplevel(t ast.Toplevel, first bool) {
	switch x := t.(type) {
	case *ast.Group:
		p.group(x, first)
	case *ast.Service:
		p.service(x, first)
	default:
		panic(fmt.Sprintf("Unknown type: %T", t))
	}
}

func File(list []ast.Toplevel, src []byte) {
	p := new(printer)
	p.init(src)

	first, after := p.FindCommentAfter(0, "")
	if first != "" {
		p.print(first)
	}
	if len(list) == 0 {
		p.comment(after)
	} else {

		// N-1 comment blocks at top of file.
		p.comment(headN1(after))

		// Toplevel declarations.
		// First one gets only one comment block.
		for i, t := range list {
			p.toplevel(t, i == 0)
		}

		// N-1 comment blocks at bottom of file
		p.comment(tailN1(p.FindCommentBefore(len(p.src), ",;")))
	}
	fmt.Print(string(p.output))
}
