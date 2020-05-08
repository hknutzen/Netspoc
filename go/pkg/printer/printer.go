// This file implements printing of AST nodes.

package printer

import (
	"fmt"
	"github.com/hknutzen/spoc-parser/ast"
)

type printer struct {
	// Current state
	output []byte // raw printer result
	indent int    // current indentation
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
		p.elList(l, stop)
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

func (p *printer) elList(l []ast.Element, stop string) {
	p.indent++
	for _, el := range l {
		p.element("", el, ",")
	}
	p.indent--
	p.print(stop)
}

func (p *printer) description(d *ast.Description) {
	if d != nil {
		if s := d.Text; s != "" {
			p.print("description = " + s)
		}
	}
}

func (p *printer) topList(n ast.TopList) {
	p.print(n.Name + " =")
	p.description(n.Description)
	p.elList(n.Elements, ";")
}

func (p *printer) group(g *ast.Group) {
	p.topList(g.TopList)
}

func (p *printer) toplevel(t ast.Toplevel) {
	switch x := t.(type) {
	case *ast.Group:
		p.group(x)
	default:
		panic(fmt.Sprintf("Unknown type: %v", t))
	}
}

func File(l []ast.Toplevel) {
	p := new(printer)
	for _, t := range l {
		p.toplevel(t)
	}
	fmt.Print(string(p.output))
}
