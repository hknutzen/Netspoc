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
	if src[len(src)-1] != 0x0a {
		src = append(src, 0x0a)
	}
	p.src = src
}

func (p *printer) print(line string) {
	for i := 0; i < p.indent; i++ {
		p.output = append(p.output, ' ')
	}
	p.output = append(p.output, []byte(line)...)
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
	default:
		panic(fmt.Sprintf("Unknown element: %v", el))
	}
}

func (p *printer) intersection(pre string, l []ast.Element, post string) {
	p.element("", l[0], "")
	for _, el := range l[1:] {
		switch x := el.(type) {
		case *ast.Complement:
			p.element("&! ", x.Element, "")
		default:
			p.element("& ", el, "")
		}
	}
	p.print(post)
}

func (p *printer) elementList(l []ast.Element, stop string) {
	p.indent++
	for i, el := range l {
		post := ","
		p.comment(p.PreCommentX(el, ",", i == 0))
		trailing, after := p.PostComment(el, ",;")
		if trailing != "" {
			post += " " + trailing
		}
		p.element("", el, post)
		p.comment(head1(after))
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
		p.comment(p.PreComment(d))
		trailing, after = p.PostComment(d, "=")
		post := ""
		if trailing != "" {
			post += " " + trailing
		}
		p.print("description = " + d.Text + post)
	}
	p.comment(headN1(after))
	p.elementList(n.Elements, ";")
}

func (p *printer) group(g *ast.Group, first bool) {
	p.topList(&g.TopList, first)
}

func (p *printer) toplevel(t ast.Toplevel, first bool) {
	switch x := t.(type) {
	case *ast.Group:
		p.group(x, first)
	default:
		panic(fmt.Sprintf("Unknown type: %v", t))
	}
}

func File(l []ast.Toplevel, src []byte) {
	p := new(printer)
	p.init(src)

	// N-1 comment blocks at top of file.
	_, after := p.FindCommentAfter(0, "")
	p.comment(headN1(after))

	// Toplevel declarations.
	// First one gets only one comment block.
	for i, t := range l {
		p.toplevel(t, i == 0)
	}

	// N-1 comment blocks at bottom of file
	p.comment(tailN1(p.FindCommentBefore(len(p.src), ",;")))
	fmt.Print(string(p.output))
}
