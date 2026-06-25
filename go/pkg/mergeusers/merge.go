package mergeusers

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/spf13/pflag"
)

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] netspoc [service:]s1 [service:]s2 ...\n",
			d.Args[0])
		fs.PrintDefaults()
	}
	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := fs.StringP("file", "f", "", "Read service lists from file")
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
	path := args[0]

	// Initialize service lists.
	var svLists [][]string
	if *fromFile != "" {
		l, err := readServiceLists(*fromFile)
		if err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
		svLists = l
	}
	svArgs := args[1:]
	if len(svArgs) > 0 {
		svLists = append(svLists, svArgs)
	}

	// Do work.
	s, err := astset.Read(path)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	if err := process(s, svLists); err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	s.ShowChanged(d.Stderr, *quiet)
	s.Print()
	return 0
}

func readServiceLists(path string) ([][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Can't %s", err)
	}
	lines := strings.Split(string(data), "\n")
	var result [][]string
	for _, line := range lines {
		names := strings.Fields(line)
		if len(names) != 0 {
			result = append(result, names)
		}
	}
	return result, nil
}

func process(s *astset.State, svLists [][]string) error {
	for _, svNames := range svLists {
		if err := combine(s, svNames); err != nil {
			return err
		}
	}
	return nil
}

func combine(set *astset.State, svNames []string) error {
	addPrefix := func(n string) string {
		if !strings.HasPrefix(n, "service:") {
			n = "service:" + n
		}
		return n
	}
	name1 := addPrefix(svNames[0])
	otherNames := svNames[1:]
	if len(otherNames) == 0 {
		return fmt.Errorf("Can't combine single '%s'", name1)
	}

	// Find other services that will be merged into first service.
	// Collect attributes and delete afterwards.
	var users []ast.Element
	hasUnenforceable := false
	var overlaps []*ast.Value
	for _, name := range otherNames {
		name = addPrefix(name)
		if name == name1 {
			return fmt.Errorf("Must not combine with itself: %s", name)
		}
		found := false
		// Here we only traverse and actually don't modify.
		set.Modify(func(obj ast.Toplevel) bool {
			if s, ok := obj.(*ast.Service); ok {
				if name == s.Name {
					found = true
					users = append(users, s.User.Elements...)
					for _, a := range s.Attributes {
						switch a.Name {
						case "has_unenforceable":
							hasUnenforceable = true
						case "overlaps":
							overlaps = append(overlaps, a.ValueList...)
						}
					}
				}
			}
			return false // Not modified.
		})
		if !found {
			return fmt.Errorf("Can't find %s", name)
		}
		// Delete.
		set.DeleteToplevel(name)
	}

	// Modify first service
	var s1 *ast.Service
	set.Modify(func(obj ast.Toplevel) bool {
		if s, ok := obj.(*ast.Service); ok && s.Name == name1 {
			s1 = s
			return true // Mark as modified.
		}
		return false
	})
	if s1 == nil {
		return fmt.Errorf("Can't find %s", name1)
	}
	s1.User.Elements = append(s1.User.Elements, users...)
	if hasUnenforceable {
		s1.ReplaceAttr(&ast.Attribute{Name: "has_unenforceable"})
	}
	if overlaps != nil {
		var l []*ast.Value
		if a := s1.GetAttr("overlaps"); a != nil {
			l = a.ValueList
		}
		overlaps = slices.Concat(l, overlaps)
		slices.SortFunc(overlaps, func(a, b *ast.Value) int {
			return strings.Compare(a.Value, b.Value)
		})
		overlaps = slices.CompactFunc(overlaps, func(a, b *ast.Value) bool {
			return a.Value == b.Value
		})
		s1.ReplaceAttr(&ast.Attribute{Name: "overlaps", ValueList: overlaps})
	}
	s1.Order()
	return nil
}
