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

func (p *printer) emptyLine() {
	l := len(p.output)
	if l < 2 || p.output[l-1] != '\n' || p.output[l-2] != '\n' {
		p.output = append(p.output, '\n')
	}
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
		ind := len(p1)
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
	ind := len(pre)
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

func (p *printer) topList(n *ast.TopList) {
	p.elementList(n.Elements, ";")
}

func (p *printer) namedList(
	name string, l []ast.Element,
	show func(*printer, string, ast.Element, string)) {

	// Put first value on same line with name, if it has no comment.
	first := l[0]
	var rest []ast.Element
	pre := name + " = "
	ind := len(pre)
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
		show(p, pre, first, post+p.TrailingComment(first, ",;"))
	}

	// Show other lines with same indentation as first line.
	if len(rest) != 0 {
		p.indent += ind
		for _, v := range rest {
			p.PreComment(v, ",")
			show(p, "", v, ","+p.TrailingComment(v, ",;"))
		}
		p.print(";")
		p.indent -= ind
	}
}

func (p *printer) complexValue(name string, l []*ast.Attribute) {
	p.print(name + " = {")
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

		// Convert type of slice, so we can use func namedList.
		nodes := make([]ast.Element, len(l))
		for i, v := range l {
			nodes[i] = v
		}
		p.namedList(
			n.Name, nodes,
			func(p *printer, pre string, l ast.Element, post string) {
				a := l.(*ast.Value)
				p.print(pre + a.Value + post)
			})
	} else if l := n.ComplexValue; l != nil {
		p.complexValue(n.Name, l)
	} else {
		// Short attribute without values.
		p.print(n.Name + ";" + p.TrailingComment(n, ",;"))
		return
	}
}

func (p *printer) namedUnion(pre string, n *ast.NamedUnion) {
	p.PreComment(n, "")
	p.namedList(pre+n.Name, n.Elements, (*printer).element)
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
	p.indent++
	p.emptyLine()
	for _, a := range n.Attributes {
		p.attribute(a)
	}
	p.emptyLine()
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

func (p *printer) topStruct(n *ast.TopStruct) {
	p.indent++
	for _, a := range n.Attributes {
		p.attribute(a)
	}
	p.indent--
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
		p.topList(x)
	case *ast.Service:
		p.service(x)
	default:
		panic(fmt.Sprintf("Unknown type: %T", n))
	}
}

func File(list []ast.Toplevel, src []byte) {
	p := new(printer)
	p.init(src)

	for i, t := range list {
		p.toplevel(t)
		// Add empty line between output.
		if i != len(list)-1 {
			p.print("")
		}
	}

	fmt.Print(string(p.output))
}
