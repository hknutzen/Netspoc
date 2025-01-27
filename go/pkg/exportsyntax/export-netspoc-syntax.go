package exportsyntax

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/spf13/pflag"
)

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] netspoc-data [TYPE:NAME|TYPE: ...]\n%s",
			d.Args[0], fs.FlagUsages())
	}
	fs.BoolP("quiet", "q", false, "Flag is ignored")
	if err := fs.Parse(d.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		fs.Usage()
		return 1
	}

	// Argument processing
	args := fs.Args()
	if len(args) < 1 {
		fs.Usage()
		return 1
	}
	filter := make(map[string]bool)
	for _, name := range args[1:] {
		filter[name] = true
	}
	path := args[0]
	// Group definitions by type.
	definitions := make(map[string][]jsonMap)
	err := filetree.Walk(path, func(input *filetree.Context) error {
		source := []byte(input.Data)
		path := input.Path
		aF, err := parser.ParseFile(source, path, 0)
		if err != nil {
			return err
		}
		for _, node := range aF.Nodes {
			name := node.GetName()
			i := strings.Index(name, ":")
			if len(filter) == 0 || filter[name[:i+1]] || filter[name] {
				typ := name[:i]
				definitions[typ] = append(definitions[typ], convertToMap(node))
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	enc := json.NewEncoder(d.Stdout)
	enc.SetEscapeHTML(false)
	enc.Encode(definitions)
	return 0
}

type jsonMap map[string]interface{}

func convertToMap(n ast.Toplevel) jsonMap {
	m := make(jsonMap)
	m["name"] = n.GetName()
	if d := n.GetDescription(); d != nil {
		m["description"] = d.Text
	}
	if x, ok := n.(ast.ToplevelWithAttr); ok {
		mapAttributes(m, x.GetAttributes())
	}
	switch x := n.(type) {
	case *ast.Protocol:
		m["value"] = x.Value
	case *ast.Protocolgroup:
		m["value_list"] = valueStrings(x.ValueList)
	case *ast.TopList:
		m["elements"] = elementStrings(x.Elements)
	case *ast.Network:
		if x.Hosts != nil {
			m["hosts"] = mapAttributes(make(jsonMap), x.Hosts)
		}
	case *ast.Router:
		m["interfaces"] = mapAttributes(make(jsonMap), x.Interfaces)
	case *ast.Area:
		if x.Border != nil {
			m["border"] = elementStrings(x.Border.Elements)
		}
		if x.InclusiveBorder != nil {
			m["inclusive_border"] = elementStrings(x.InclusiveBorder.Elements)
		}
	case *ast.Service:
		m["user"] = elementStrings(x.User.Elements)
		m["rules"] = mapRules(x.Rules)
		if x.Foreach {
			m["foreach"] = true
		}
	}
	return m
}

func mapRules(l []*ast.Rule) []jsonMap {
	result := make([]jsonMap, len(l))
	for i, r := range l {
		m := make(jsonMap)
		act := "permit"
		if r.Deny {
			act = "deny"
		}
		m["action"] = act
		m["src"] = elementStrings(r.Src.Elements)
		m["dst"] = elementStrings(r.Dst.Elements)
		m["prt"] = valueStrings(r.Prt.ValueList)
		if r.Log != nil {
			m["log"] = valueStrings(r.Log.ValueList)
		}
		result[i] = m
	}
	return result
}

func mapAttributes(m jsonMap, l []*ast.Attribute) jsonMap {
	for _, a := range l {
		if a.ValueList != nil {
			m[a.Name] = valueStrings(a.ValueList)
		} else if a.ComplexValue != nil {
			m[a.Name] = mapAttributes(make(jsonMap), a.ComplexValue)
		} else {
			m[a.Name] = nil
		}
	}
	return m
}

func valueStrings(l []*ast.Value) []string {
	result := make([]string, len(l))
	for i, v := range l {
		result[i] = v.Value
	}
	return result
}

func elementStrings(l []ast.Element) []string {
	result := make([]string, len(l))
	for i, e := range l {
		result[i] = e.String()
	}
	return result
}
