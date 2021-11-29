package expand

/*
NAME

expand-group - Substitute group reference by its elements

SYNOPSIS

expand-group [options] FILE|DIR GROUP-NAME ...

DESCRIPTION

This program reads a netspoc configuration and one or more
GROUP-NAMES. It substitutes specified group references in each file
and removes the corresponding group-definition. Each group reference
is substituted by elements of corresponding group definition.
GROUP-NAME is given with type as "group:NAME". Substitution occurs
textual, groups in groups are not expanded. Groups referenced in
intersection or complement are not substituted. In this case the group
definition is left unchanged.

Changes are done in place, no backup files are created. But only
changed files are touched.

OPTIONS

-f file
Read GROUP-NAMES from file.

-q
Quiet, don't print status messages.

-h
Prints a brief help message and exits.

COPYRIGHT AND DISCLAIMER

(c) 2021 by Heinz Knutzen <heinz.knutzengooglemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if !, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/info"
	"github.com/spf13/pflag"
	"os"
	"strings"
)

type state struct {
	*astset.State
	expand   map[string]bool
	elements map[string][]ast.Element
	retain   map[string]bool
	changed  bool
}

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR GROUP-NAME ...\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	fromFile := fs.StringP("file", "f", "", "Read GROUP-NAMES from file")
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

	// Names of to be substituted groups.
	var names []string
	if *fromFile != "" {
		l, err := readNames(*fromFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		names = append(names, l...)
	}
	if len(args) > 1 {
		if err := checkNames(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
		names = append(names, args[1:]...)
	}

	// Initialize config, especially "ignoreFiles'.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Change files.
	s := new(state)
	var err error
	s.State, err = astset.Read(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	err = s.process(names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	s.Print()
	return 0
}

func readNames(path string) ([]string, error) {
	var result []string
	bytes, err := os.ReadFile(path)
	if err != nil {
		return result, fmt.Errorf("Can't %s", err)
	}
	result = strings.Fields(string(bytes))
	return result, checkNames(result)
}

func checkNames(names []string) error {
	for _, name := range names {
		if !strings.HasPrefix(name, "group:") {
			return fmt.Errorf("Expected group name but got '%s'", name)
		}
	}
	return nil
}

func (s *state) process(names []string) error {

	s.expand = make(map[string]bool)
	s.elements = make(map[string][]ast.Element)
	s.retain = make(map[string]bool)
	for _, name := range names {
		s.expand[name] = true
	}

	// Collect elements from definitions of to be expanded groups.
	s.Modify(func(n ast.Toplevel) bool {
		name := n.GetName()
		if s.expand[name] {
			group, _ := n.(*ast.TopList)
			s.elements[name] = group.Elements
		}
		return false
	})

	for name := range s.expand {
		if _, found := s.elements[name]; !found {
			return fmt.Errorf("No defintion found for '%s'", name)
		}
	}

	// Repeatedly expand groups in collected elements.
	for name, l := range s.elements {
		for {
			s.changed = false
			s.elementList(&l)
			if !s.changed {
				break
			}
			s.elements[name] = l
		}
	}

	// Expand groups in element lists.
	s.Modify(func(n ast.Toplevel) bool { return s.toplevel(n) })

	// Remove definition of group.
	for name := range s.expand {
		if !s.retain[name] {
			s.DeleteToplevel(name)
		}
	}

	for _, file := range s.Changed() {
		info.Msg("Changed %s", file)
	}
	return nil
}

func (s *state) toplevel(n ast.Toplevel) bool {
	s.changed = false
	switch x := n.(type) {
	case *ast.TopList:
		s.elementList(&x.Elements)
	case *ast.Service:
		s.elementList(&x.User.Elements)
		for _, r := range x.Rules {
			s.elementList(&r.Src.Elements)
			s.elementList(&r.Dst.Elements)
		}
	case *ast.Area:
		if x.Border != nil {
			s.elementList(&x.Border.Elements)
		}
		if x.InclusiveBorder != nil {
			s.elementList(&x.InclusiveBorder.Elements)
		}
	}
	return s.changed
}

func (s *state) elementList(l *[]ast.Element) {
	var mod []ast.Element
	for _, n := range *l {
		if vals, ok := s.needExpand(n); ok {
			mod = append(mod, vals...)
			s.changed = true
			continue
		}
		switch obj := n.(type) {
		case *ast.SimpleAuto:
			s.elementList(&obj.Elements)
		case *ast.AggAuto:
			s.elementList(&obj.Elements)
		case *ast.IntfAuto:
			s.elementList(&obj.Elements)
		case *ast.Intersection:
			vals := s.intersection(obj)
			mod = append(mod, vals...)
			continue
		}
		mod = append(mod, n)
	}
	*l = mod
	ast.OrderElements(*l)
}

func (s *state) needExpand(obj ast.Element) ([]ast.Element, bool) {
	if el, ok := obj.(*ast.NamedRef); ok {
		name := el.Type + ":" + el.Name
		if vals, found := s.elements[name]; found {
			return vals, true
		}
	}
	return nil, false
}

func (s *state) intersection(obj *ast.Intersection) []ast.Element {
	// First step:
	// - Split into negated and non negated elements,
	// - substitute negated group by its elements,
	var negated []ast.Element
	var nonNegated []ast.Element
	for _, n := range obj.Elements {
		switch obj := n.(type) {
		case *ast.Complement:
			if vals, ok := s.needExpand(obj.Element); ok {
				s.changed = true
				for _, v := range vals {
					compl := &ast.Complement{Element: v}
					negated = append(negated, compl)
				}
				continue
			}
			negated = append(negated, n)
		default:
			nonNegated = append(nonNegated, n)
		}
	}
	obj.Elements = append(nonNegated, negated...)

	// Second step:
	// If exactly one non negated element was found and if this element
	// is a to be substituted group, then try to expand intersection by
	// intersecting groups elements with negated elements.
	result := []ast.Element{obj}
	if len(nonNegated) != 1 {
		for _, n := range nonNegated {
			s.checkRetain(n)
		}
		return result
	}
	vals, ok := s.needExpand(nonNegated[0])
	if !ok {
		return result
	}
	g := nonNegated[0].(*ast.NamedRef)
	name := g.Type + ":" + g.Name
	retain := true
	if len(vals) == 1 {
		// It is safe to substitute group by its single value,
		// even if intersection can't be expanded below.
		obj.Elements = append(vals, negated...)
		s.changed = true
		retain = false
	}
	for _, n := range negated {
		el1 := n.(*ast.Complement)
		switch compl := el1.Element.(type) {
		default:
			goto NOEXPAND
		case ast.NamedElem:
			t := compl.GetType()
			n := compl.GetName()
			var cp []ast.Element
			for _, v := range vals {
				switch el2 := v.(type) {
				default:
					goto NOEXPAND
				case ast.NamedElem:
					if !(t == el2.GetType() && n == el2.GetName()) {
						cp = append(cp, v)
					}
				}
			}
			if len(cp) == len(vals) {
				// Complement was not found in values of group.
				goto NOEXPAND
			}
			vals = cp
		}
	}
	s.changed = true
	return vals
NOEXPAND:
	s.retain[name] = s.retain[name] || retain
	return result

}

func (s *state) checkRetain(n ast.Element) {
	if obj, ok := n.(*ast.NamedRef); ok {
		name := obj.Type + ":" + obj.Name
		if _, found := s.expand[name]; found {
			s.retain[name] = true
		}
	}
}
