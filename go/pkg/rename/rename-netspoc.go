package rename

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/info"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
	"os"
	"strings"
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

// NAT is applied with bind_nat.
// Owner is optionally referenced as sub_owner.
// Interface definition uses network name.
var alias = map[string]string{
	"nat":     "bind_nat",
	"owner":   "sub_owner",
	"network": "interface",
}

func getTypeAndName(objName string) (string, string, error) {
	pair := strings.SplitN(objName, ":", 2)
	if len(pair) != 2 {
		return "", "", fmt.Errorf("Missing type in '%s'", objName)
	}
	return pair[0], pair[1], nil
}

var subst map[string]map[string]string
var changes int

// Fill subst with mapping from search to replace for given type.
func setupSubst(old, new string) error {
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

func substitute(typ, name string) string {
	if replace, ok := subst[typ][name]; ok {
		changes++
		return replace
	}
	if typ == "network" || typ == "interface" {
		// Ignore right part of bridged network.
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			if replace, ok := subst[typ][parts[0]]; ok {
				changes++
				return replace + "/" + parts[1]
			}
		}
	}
	return name
}

func element(n ast.Element) {
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
				changes++
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

func elementList(l []ast.Element) {
	for _, n := range l {
		element(n)
	}
}

func substTypedName(v string) string {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) == 2 {
		typ, name := parts[0], parts[1]
		replace := substitute(typ, name)
		return typ + ":" + replace
	}
	return v
}

func value(n *ast.Value) {
	n.Value = substTypedName(n.Value)
}

func valueList(l []*ast.Value) {
	for _, n := range l {
		value(n)
	}
}

func attribute(n *ast.Attribute) {
	if m := subst[n.Name]; m != nil {
		for _, v := range n.ValueList {
			if replace, ok := m[v.Value]; ok {
				v.Value = replace
				changes++
			}
		}
	} else {
		n.Name = substTypedName(n.Name)
	}
	valueList(n.ValueList)
	attributeList(n.ComplexValue)
}

func attributeList(l []*ast.Attribute) {
	for _, n := range l {
		attribute(n)
	}
}

func namedUnion(n *ast.NamedUnion) {
	if n != nil {
		elementList(n.Elements)
	}
}

func toplevel(n ast.Toplevel) {
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
}

func processFile(l []ast.Toplevel) int {
	changes = 0
	for _, n := range l {
		toplevel(n)
	}
	return changes
}

func processInput(input *filetree.Context) error {
	source := []byte(input.Data)
	path := input.Path
	astFile, err := parser.ParseFile(source, path, parser.ParseComments)
	if err != nil {
		return err
	}
	count := processFile(astFile.Nodes)
	if count == 0 {
		return nil
	}

	info.Msg("%d changes in %s", count, path)
	copy := printer.File(astFile)
	err = fileop.Overwrite(path, copy)
	return err
}

func setupPairs(pattern []string) error {
	for len(pattern) > 0 {
		old := pattern[0]
		if len(pattern) < 2 {
			return fmt.Errorf("Missing replace string for '%s'", old)
		}
		new := pattern[1]
		pattern = pattern[2:]
		if err := setupSubst(old, new); err != nil {
			return err
		}
	}
	return nil
}

func readPairs(path string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pattern := strings.Fields(string(bytes))
	if len(pattern) == 0 {
		return fmt.Errorf("Missing pattern in %s", path)
	}
	return setupPairs(pattern)
}

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR SUBSTITUTION ...\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := fs.StringP("file", "f", "", "Read pairs from file")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
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
	subst = make(map[string]map[string]string)
	if *fromFile != "" {
		if err := readPairs(*fromFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	if len(args) > 1 {
		if err := setupPairs(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Do substitution.
	if err := filetree.Walk(path, processInput); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	return 0
}
