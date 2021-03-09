package mergeusers

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"strings"
)

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] netspoc service:s1 service:s2 ...\n", os.Args[0])
		fs.PrintDefaults()
	}
	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := fs.StringP("file", "f", "", "Read service lists from file")
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
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		svLists = l
	}
	svArgs := args[1:]
	if len(svArgs) > 0 {
		if err := checkServiceList(svArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		svLists = append(svLists, svArgs)
	}

	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Do work.
	if err := process(path, svLists); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	return 0
}

func readServiceLists(path string) ([][]string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Can't %s", err)
	}
	lines := strings.Split(string(data), "\n")
	var result [][]string
	for _, line := range lines {
		names := strings.Fields(line)
		if len(names) != 0 {
			if err := checkServiceList(names); err != nil {
				return nil, err
			}
			result = append(result, names)
		}
	}
	return result, nil
}

func checkServiceList(l []string) error {
	for _, n := range l {
		if !strings.HasPrefix(n, "service:") {
			return fmt.Errorf("Missing prefix 'service:' in '%s'", n)
		}
	}
	if len(l) == 1 {
		return fmt.Errorf("Can't combine single '%s'", l[0])
	}
	return nil
}

func process(path string, svLists [][]string) error {
	s, err := astset.Read(path)
	if err != nil {
		return err
	}
	for _, svNames := range svLists {
		if err := combine(s, svNames); err != nil {
			return err
		}
	}
	if conf.Conf.Verbose {
		changes := s.Changed()
		fmt.Fprintf(os.Stderr, "Changed %d files\n", len(changes))
	}
	s.Print()
	return nil
}

func combine(set *astset.State, svNames []string) error {
	name1 := svNames[0]
	otherNames := svNames[1:]

	// Find other services that will be merged into first service.
	// Collect attributes and delete afterwards.
	var users []ast.Element
	hasUnenforceable := false
	var overlaps []*ast.Value
	for _, name := range otherNames {
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
	err := set.ModifyObj(name1, func(obj ast.Toplevel) {
		s := obj.(*ast.Service)
		s.User.Elements = append(s.User.Elements, users...)
		if hasUnenforceable {
			s.ReplaceAttr(&ast.Attribute{Name: "has_unenforceable"})
		}
		if overlaps != nil {
			for _, a := range s.Attributes {
				if a.Name == "overlaps" {
					overlaps = append(overlaps, a.ValueList...)
				}
			}
			seen := make(map[string]bool)
			j := 0
			for _, v := range overlaps {
				if !seen[v.Value] {
					seen[v.Value] = true
					overlaps[j] = v
					j++
				}
			}
			overlaps = overlaps[:j]
			s.ReplaceAttr(&ast.Attribute{Name: "overlaps", ValueList: overlaps})
		}
		s.Order()
	})
	if err != nil {
		return err
	}
	return nil
}
