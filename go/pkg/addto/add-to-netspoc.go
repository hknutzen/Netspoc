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
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

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

var addTo map[string][]ast.Element
var changes int

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
func setupAddTo(old, new string) error {
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

func addToElement(n ast.Element) []ast.Element {
	switch obj := n.(type) {
	case ast.NamedElem:
		name := n.GetType() + ":" + obj.GetName()
		return addTo[name]
	case *ast.SimpleAuto:
		elementList(&obj.Elements)
	case *ast.AggAuto:
		elementList(&obj.Elements)
	case *ast.IntfAuto:
		elementList(&obj.Elements)
	}
	return nil
}

func elementList(l *([]ast.Element)) {
	var add []ast.Element
	for _, n := range *l {
		add = append(add, addToElement(n)...)
	}
	changes += len(add)
	*l = append(*l, add...)
}

func toplevel(n ast.Toplevel) {
	switch x := n.(type) {
	case *ast.TopList:
		if strings.HasPrefix(x.Name, "group:") {
			elementList(&x.Elements)
		}
	case *ast.Service:
		elementList(&x.User.Elements)
		for _, r := range x.Rules {
			elementList(&r.Src.Elements)
			elementList(&r.Dst.Elements)
		}
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
	for _, n := range astFile.Nodes {
		n.Order()
	}
	copy := printer.File(astFile)
	return fileop.Overwrite(path, copy)
}

func setupPairs(pairs []string) error {
	for len(pairs) > 0 {
		old := pairs[0]
		if len(pairs) == 1 {
			return fmt.Errorf("Missing 2nd. element for '%s'", old)
		}
		new := pairs[1]
		pairs = pairs[2:]
		if err := setupAddTo(old, new); err != nil {
			return err
		}
	}
	return nil
}

func readPairs(path string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Can't %s", err)
	}
	pairs := strings.Fields(string(bytes))
	return setupPairs(pairs)
}

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR PAIR ...\n", os.Args[0])
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

	// Initialize search/add pairs.
	addTo = make(map[string][]ast.Element)
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

	// Initialize config, especially "ignoreFiles'.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Do substitution.
	if err := filetree.Walk(path, processInput); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	return 0
}
