package addto

import (
	"fmt"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/spf13/pflag"
)

func checkName(name string) error {
	l, err := parser.ParseUnion([]byte(name))
	if err != nil {
		return err
	}
	if len(l) == 1 {
		obj := l[0]
		switch obj.(type) {
		case *ast.NamedRef, *ast.IntfRef:
			return nil
		}
	}
	return fmt.Errorf("Can't handle '%s'", name)
}

// Fill addTo with old => new pairs.
func setupAddTo(addTo map[string][]ast.Element, old, new string) error {
	if err := checkName(old); err != nil {
		return err
	}
	list, err := parser.ParseUnion([]byte(new))
	if err != nil {
		return err
	}
	addTo[old] = append(addTo[old], list...)
	return nil
}

func process(s *astset.State, addTo map[string][]ast.Element) {
	// Add elements to element lists.
	s.Modify(func(n ast.Toplevel) bool {
		changed := false
		var change func(*[]ast.Element)
		addToElement := func(n ast.Element) []ast.Element {
			switch obj := n.(type) {
			case ast.NamedElem:
				name := n.GetType() + ":" + obj.GetName()
				if add := addTo[name]; add != nil {
					changed = true
					return add
				}
			case *ast.SimpleAuto:
				change(&obj.Elements)
			case *ast.AggAuto:
				change(&obj.Elements)
			case *ast.IntfAuto:
				change(&obj.Elements)
			}
			return nil
		}
		change = func(l *[]ast.Element) {
			var add []ast.Element
			for _, n := range *l {
				add = append(add, addToElement(n)...)
			}
			*l = append(*l, add...)
		}
		switch x := n.(type) {
		case *ast.TopList:
			if strings.HasPrefix(x.Name, "group:") {
				change(&x.Elements)
			}
		case *ast.Service:
			change(&x.User.Elements)
			for _, r := range x.Rules {
				change(&r.Src.Elements)
				change(&r.Dst.Elements)
			}
		}
		if changed {
			n.Order()
		}
		return changed
	})
}

func setupPairs(addTo map[string][]ast.Element, pairs []string) error {
	for len(pairs) > 0 {
		old := pairs[0]
		if len(pairs) == 1 {
			return fmt.Errorf("Missing 2nd. element for '%s'", old)
		}
		new := pairs[1]
		pairs = pairs[2:]
		if err := setupAddTo(addTo, old, new); err != nil {
			return err
		}
	}
	return nil
}

func readPairs(addTo map[string][]ast.Element, path string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Can't %s", err)
	}
	pairs := strings.Fields(string(bytes))
	return setupPairs(addTo, pairs)
}

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR PAIR ...\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	fromFile := fs.StringP("file", "f", "", "Read pairs from file")
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

	// Initialize search/add pairs.
	addTo := make(map[string][]ast.Element)
	if *fromFile != "" {
		if err := readPairs(addTo, *fromFile); err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	if err := setupPairs(addTo, args[1:]); err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}

	s, err := astset.Read(path)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	process(s, addTo)
	s.ShowChanged(d.Stderr, *quiet)
	s.Print()
	return 0
}
