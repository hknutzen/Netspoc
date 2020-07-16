package main

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
	"io/ioutil"
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
var aliases = map[string][]string{
	"nat":     {"bind_nat"},
	"owner":   {"sub_owner"},
	"network": {"interface"},
}

func getTypeAndName(objName string) (string, string) {
	pair := strings.SplitN(objName, ":", 2)
	if len(pair) != 2 {
		abort.Msg("Missing type in '%s'", objName)
	}
	return pair[0], pair[1]
}

var subst = make(map[string]map[string]string)
var changes = 0

// Fill subst with mapping from search to replace for given type.
func setupSubst(old, new string) {
	objType, search := getTypeAndName(old)
	newType, replace := getTypeAndName(new)
	if objType != newType {
		abort.Msg("Types must be identical in\n - %s\n - %s", old, new)
	}
	if !globalType[objType] {
		abort.Msg("Unknown type %s", objType)
	}
	addSubst := func(typ, search, replace string) {
		subMap, ok := subst[typ]
		if !ok {
			subMap = make(map[string]string)
			subst[typ] = subMap
		}
		if other := subMap[search]; other != "" {
			abort.Msg("Ambiguous substitution for %s:%s: %s:%s, %s:%s",
				typ, search, typ, other, typ, replace)
		}
		subMap[search] = replace
	}

	addSubst(objType, search, replace)

	for _, other := range aliases[objType] {
		addSubst(other, search, replace)
	}
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
		elementList(x.User.Elements)
		for _, r := range x.Rules {
			elementList(r.Src.Elements)
			elementList(r.Dst.Elements)
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
	}
}

func process(l []ast.Toplevel) int {
	for _, n := range l {
		toplevel(n)
	}
	return changes
}

func processInput(input *filetree.Context) {
	source := []byte(input.Data)
	path := input.Path
	nodes := parser.ParseFile(source, path)
	count := process(nodes)
	if count == 0 {
		return
	}

	diag.Info("%d changes in %s", count, path)
	copy := printer.File(nodes, source)
	err := fileop.Overwrite(path, copy)
	if err != nil {
		abort.Msg("%v", err)
	}
}

func setupPairs(pattern []string) {
	for len(pattern) > 0 {
		old := pattern[0]
		if len(pattern) < 2 {
			abort.Msg("Missing replace string for '%s'", old)
		}
		new := pattern[1]
		pattern = pattern[2:]
		setupSubst(old, new)
	}
}

func readPairs(path string) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		abort.Msg("Can't %s", err)
	}
	pattern := strings.Fields(string(bytes))
	if len(pattern) == 0 {
		abort.Msg("Missing pattern in %s", path)
	}
	setupPairs(pattern)
}

func main() {

	// Setup custom usage function.
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR SUBSTITUTION ...\n", os.Args[0])
		pflag.PrintDefaults()
	}

	// Command line flags
	quiet := pflag.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := pflag.StringP("file", "f", "", "Read pairs from file")
	pflag.Parse()

	// Argument processing
	args := pflag.Args()
	if len(args) == 0 {
		pflag.Usage()
		os.Exit(1)
	}
	path := args[0]

	// Initialize search/replace pairs.
	if *fromFile != "" {
		readPairs(*fromFile)
	}
	if len(args) > 1 {
		setupPairs(args[1:])
	}
	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Do substitution.
	filetree.Walk(path, processInput)
}
