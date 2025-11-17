package removefrom

import (
	"cmp"
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

func setupObjects(m map[string]bool, objects []string) error {
	for _, object := range objects {
		if err := checkName(object); err != nil {
			return err
		}
		m[object] = true
	}
	return nil
}

func process(s *astset.State, remove map[string]bool, delDef bool) {
	var emptySvc []*ast.Service
	retain := make(map[string]bool)
	// Remove elements from element lists.
	s.Modify(func(n ast.Toplevel) bool {
		changed := false
		var traverse func([]ast.Element, bool) []ast.Element
		traverse = func(l []ast.Element, compl bool) []ast.Element {
			j := 0
		OUTER:
			for _, el := range l {
				switch x := el.(type) {
				case ast.NamedElem:
					typ := x.GetType()
					name := typ + ":" + x.GetName()
					if remove[name] {
						if !compl || typ == "host" || typ == "interface" {
							changed = true
							continue
						}
						retain[name] = true
					}
				case ast.AutoElem:
					l2 := traverse(x.GetElements(), compl)
					if len(l2) == 0 {
						changed = true
						continue
					}
					x.SetElements(l2)
				case *ast.Intersection:
					// Discard intersection if at least one non complement
					// element becomes empty.
					for _, obj := range x.Elements {
						if _, ok := obj.(*ast.Complement); !ok {
							l2 := traverse([]ast.Element{obj}, compl)
							if len(l2) == 0 {
								changed = true
								continue OUTER
							}
						}
					}
					j2 := 0
					for _, obj := range x.Elements {
						if c, ok := obj.(*ast.Complement); ok {
							l2 := traverse([]ast.Element{c.Element}, !compl)
							if len(l2) == 0 {
								changed = true
								continue
							}
						}
						x.Elements[j2] = obj
						j2++
					}
					x.Elements = x.Elements[:j2]
					if len(x.Elements) == 1 {
						obj := x.Elements[0]
						if _, ok := obj.(*ast.Complement); !ok {
							el = obj
						}
					}
				}
				l[j] = el
				j++
			}
			return l[:j]
		}
		change := func(l *[]ast.Element) bool {
			l2 := traverse(*l, false)
			*l = l2
			return len(l2) == 0
		}

		switch x := n.(type) {
		case *ast.TopList:
			if strings.HasPrefix(x.Name, "group:") {
				change(&x.Elements)
			}
		case *ast.Service:
			if change(&x.User.Elements) {
				emptySvc = append(emptySvc, x)
			} else {
				j := 0
				for _, r := range x.Rules {
					if cmp.Or(change(&r.Src.Elements), change(&r.Dst.Elements)) {
						changed = true
					} else {
						x.Rules[j] = r
						j++
					}
				}
				x.Rules = x.Rules[:j]
				if j == 0 {
					emptySvc = append(emptySvc, x)
				}
			}
		}
		return changed
	})

	// Delete definition of removed group, host, unmanaged loopback interface.
	// Silently ignore error, if definition isn't found.
	for name := range remove {
		if retain[name] {
			continue
		}
		typ, _, _ := strings.Cut(name, ":")
		switch typ {
		case "group":
			s.DeleteToplevel(name)
		case "host":
			if delDef {
				s.DeleteHost(name)
			}
		case "interface":
			if delDef {
				s.DeleteUnmanagedLoopbackInterface(name)
			}
		}
	}
	// Delete definition of empty service.
	for _, sv := range emptySvc {
		s.DeleteToplevelNode(sv)
	}
}

func readObjects(m map[string]bool, path string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Can't %s", err)
	}
	objects := strings.Fields(string(bytes))
	return setupObjects(m, objects)
}

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR OBJECT ...\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	fromFile := fs.StringP("file", "f", "", "Read OBJECTS from file")
	delDef := fs.BoolP("delete", "d", false,
		"Also delete definition if OBJECT is host or interface")
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

	// Initialize to be removed objects.
	remove := make(map[string]bool)
	if *fromFile != "" {
		if err := readObjects(remove, *fromFile); err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	if err := setupObjects(remove, args[1:]); err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}

	s, err := astset.Read(path)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	process(s, remove, *delDef)
	s.ShowChanged(d.Stderr, *quiet)
	s.Print()
	return 0
}
