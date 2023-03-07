package addto

/*
=head1 NAME

add-to-netspoc - Augment one or more objects in netspoc files

=head1 SYNOPSIS

add-to-netspoc [options] FILE|DIR PAIR ...

=head1 DESCRIPTION

This program reads a netspoc configuration and one or more
PAIRS. It augments given object by specified new object in
each file. Changes are done in place, no backup files are created. But
only changed files are touched.

=head1 PAIR

A PAIR is a tuple of typed names "type1:NAME1" "type2:NAME2".
Occurences of "type1:NAME1" are searched and
replaced by "type1:NAME1, type2:NAME2".
Changes are applied only in group definitions and
in implicit groups inside rules, i.e. after "user =", "src =", "dst = ".
Multiple PAIRS can be applied in a single run of add-to-netspoc.

The following types can be used in PAIRS:
B<network host interface any group area>.

=head1 OPTIONS

=over 4

=item B<-f> file

Read PAIRS from file.

=item B<-q>

Quiet, don't print status messages.

=item B<-help>

Prints a brief help message and exits.

=back

=head1 COPYRIGHT AND DISCLAIMER

(c) 2022 by Heinz Knutzen <heinz.knutzen@googlemail.com>

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
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"fmt"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
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

	// Initialize config.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, path)

	s, err := astset.Read(path, cnf.IPV6)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	process(s, addTo)
	s.ShowChanged(d.Stderr, cnf.Quiet)
	s.Print()
	return 0
}
