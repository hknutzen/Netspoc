package rename

import (
	"fmt"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/spf13/pflag"
)

var globalType = map[string]bool{
	"router":          true,
	"network":         true,
	"host":            true,
	"any":             true,
	"group":           true,
	"area":            true,
	"service":         true,
	"owner":           true,
	"protocol":        true,
	"protocolgroup":   true,
	"pathrestriction": true,
	"nat":             true,
	"isakmp":          true,
	"ipsec":           true,
	"crypto":          true,
}

// Interface definition uses network name.
var alias = map[string]string{
	"network": "interface",
}

func getTypeAndName(objName string) (string, string, error) {
	typ, name, ok := strings.Cut(objName, ":")
	if !ok {
		return "", "", fmt.Errorf("Missing type in '%s'", objName)
	}
	return typ, name, nil
}

// Fill subst with mapping from search to replace for given type.
func setupSubst(subst map[string]map[string]string, old, new string) error {
	objType, search, err := getTypeAndName(old)
	if err != nil {
		return err
	}
	newType, replace, err := getTypeAndName(new)
	if err != nil {
		return err
	}
	if objType != newType {
		return fmt.Errorf("Types must be identical in\n - %s\n - %s", old, new)
	}
	if !globalType[objType] {
		return fmt.Errorf("Unknown type %s", objType)
	}
	addSubst := func(typ, search, replace string) error {
		subMap, ok := subst[typ]
		if !ok {
			subMap = make(map[string]string)
			subst[typ] = subMap
		}
		if other := subMap[search]; other != "" {
			return fmt.Errorf("Ambiguous substitution for %s:%s: %s:%s, %s:%s",
				typ, search, typ, other, typ, replace)
		}
		subMap[search] = replace
		return nil
	}

	if err := addSubst(objType, search, replace); err != nil {
		return err
	}

	if other, found := alias[objType]; found {
		addSubst(other, search, replace)
	}
	return nil
}

func process(s *astset.State, subst map[string]map[string]string) {
	s.Modify(func(n ast.Toplevel) bool {
		changed := false
		substitute := func(typ, name string) string {
			if replace, ok := subst[typ][name]; ok {
				changed = true
				return replace
			}
			if typ == "network" || typ == "interface" {
				// Ignore right part of bridged network.
				name, bridged, ok := strings.Cut(name, "/")
				if ok {
					if replace, ok := subst[typ][name]; ok {
						changed = true
						return replace + "/" + bridged
					}
				}
			}
			return name
		}

		var elementList func([]ast.Element)
		var element func(n ast.Element)
		element = func(n ast.Element) {
			typ := n.GetType()
			if typ == "interface" {
				if intf, ok := n.(*ast.IntfRef); ok {
					intf.Router = substitute("router", intf.Router)
					intf.Network = substitute("network", intf.Network)
					return
				}
			}
			switch obj := n.(type) {
			case *ast.NamedRef:
				name := obj.Name
				if typ == "host" && strings.HasPrefix(name, "id:") {
					// ID host is extended by network name: host:id:a.b@c.d.net_name
					parts := strings.Split(name, ".")
					network := parts[len(parts)-1]
					host := strings.Join(parts[:len(parts)-1], ".")
					if replace, ok := subst["host"][host]; ok {
						host = replace
					}
					if replace, ok := subst["network"][network]; ok {
						network = replace
					}
					name = host + "." + network
					if name != obj.Name {
						obj.Name = name
						changed = true
					}
				} else {
					obj.Name = substitute(typ, name)
				}
			case *ast.SimpleAuto:
				elementList(obj.Elements)
			case *ast.AggAuto:
				elementList(obj.Elements)
			case *ast.IntfAuto:
				elementList(obj.Elements)
			case *ast.Intersection:
				elementList(obj.Elements)
			case *ast.Complement:
				element(obj.Element)
			}
		}

		elementList = func(l []ast.Element) {
			for _, n := range l {
				element(n)
			}
		}

		substTypedName := func(v string) string {
			if typ, name, ok := strings.Cut(v, ":"); ok {
				replace := substitute(typ, name)
				return typ + ":" + replace
			}
			return v
		}

		value := func(n *ast.Value) {
			n.Value = substTypedName(n.Value)
		}

		valueList := func(l []*ast.Value) {
			for _, n := range l {
				value(n)
			}
		}

		var attributeList func(l []*ast.Attribute)
		attribute := func(n *ast.Attribute) {
			var m map[string]string
			switch n.Name {
			case "nat_in", "nat_out":
				m = subst["nat"]
			case "owner":
				m = subst["owner"]
			}
			if m != nil {
				for _, v := range n.ValueList {
					if replace, ok := m[v.Value]; ok {
						v.Value = replace
						changed = true
					}
				}
			} else {
				n.Name = substTypedName(n.Name)
			}
			valueList(n.ValueList)
			attributeList(n.ComplexValue)
		}

		attributeList = func(l []*ast.Attribute) {
			for _, n := range l {
				attribute(n)
			}
		}

		namedUnion := func(n *ast.NamedUnion) {
			if n != nil {
				elementList(n.Elements)
			}
		}

		n.SetName(substTypedName(n.GetName()))
		switch x := n.(type) {
		case *ast.TopList:
			elementList(x.Elements)
		case *ast.Protocolgroup:
			valueList(x.ValueList)
		case *ast.TopStruct:
			attributeList(x.Attributes)
		case *ast.Service:
			attributeList(x.Attributes)
			namedUnion(x.User)
			for _, r := range x.Rules {
				namedUnion(r.Src)
				namedUnion(r.Dst)
				valueList(r.Prt.ValueList)
			}
		case *ast.Network:
			attributeList(x.Attributes)
			for _, h := range x.Hosts {
				h.Name = substTypedName(h.Name)
				attributeList(h.ComplexValue)
			}
		case *ast.Router:
			attributeList(x.Attributes)
			for _, intf := range x.Interfaces {
				intf.Name = substTypedName(intf.Name)
				attributeList(intf.ComplexValue)
			}
		case *ast.Area:
			attributeList(x.Attributes)
			namedUnion(x.Border)
			namedUnion(x.InclusiveBorder)
		}
		if changed {
			n.Order()
		}
		return changed
	})
}

func setupPairs(subst map[string]map[string]string, pattern []string) error {
	for len(pattern) > 0 {
		old := pattern[0]
		if len(pattern) < 2 {
			return fmt.Errorf("Missing replace string for '%s'", old)
		}
		new := pattern[1]
		pattern = pattern[2:]
		if err := setupSubst(subst, old, new); err != nil {
			return err
		}
	}
	return nil
}

func readPairs(subst map[string]map[string]string, path string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pattern := strings.Fields(string(bytes))
	return setupPairs(subst, pattern)
}

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR SUBSTITUTION ...\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := fs.StringP("file", "f", "", "Read substitutions from file")
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
	if len(args) == 0 {
		fs.Usage()
		return 1
	}
	path := args[0]

	// Initialize search/replace pairs.
	subst := make(map[string]map[string]string)
	if *fromFile != "" {
		if err := readPairs(subst, *fromFile); err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	if err := setupPairs(subst, args[1:]); err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	// Initialize config.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, path)

	s, err := astset.Read(path)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	process(s, subst)
	s.ShowChanged(d.Stderr, cnf.Quiet)
	s.Print()
	return 0
}
