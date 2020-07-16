package main

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
B<network host interface any group>.

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

(c) 2020 by Heinz Knutzen <heinz.knutzengooglemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it &&/|| modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, ||
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY || FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

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
	"regexp"
	"strings"
)

var validType = map[string]bool{
	"network":   true,
	"host":      true,
	"interface": true,
	"any":       true,
	"group":     true,
	"area":      true,
}

var addTo = make(map[string][]ast.Element)
var changes = 0

func checkName(typedName string) {
	pair := strings.SplitN(typedName, ":", 2)
	if len(pair) != 2 {
		abort.Msg("Missing type in %s", typedName)
	}
	typ, name := pair[0], pair[1]
	if !validType[typ] {
		abort.Msg("Can't use type in %s", typedName)
	}
	re := regexp.MustCompile(`[^-\w\p{L}.:\@\/\[\]]`)
	if m := re.FindStringSubmatch(name); m != nil {
		abort.Msg("Invalid character '%s' in %s", m[0], typedName)
	}
}

// Fill addTo with old => new pairs.
func setupAddTo(old, new string) {
	checkName(old)
	list := parser.ParseUnion([]byte(new))
	addTo[old] = append(addTo[old], list...)
}

func element(n ast.Element) []ast.Element {
	switch obj := n.(type) {
	case *ast.NamedRef, *ast.IntfRef:
		name := obj.GetType() + ":" + obj.GetName()
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
		add = append(add, element(n)...)
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
	for _, n := range l {
		toplevel(n)
	}
	return changes
}

func processInput(input *filetree.Context) {
	source := []byte(input.Data)
	path := input.Path
	nodes := parser.ParseFile(source, path)
	count := processFile(nodes)
	if count == 0 {
		return
	}

	diag.Info("%d changes in %s", count, path)
	for _, n := range nodes {
		n.Order()
	}
	copy := printer.File(nodes, source)
	err := fileop.Overwrite(path, copy)
	if err != nil {
		abort.Msg("%v", err)
	}
}

func setupPairs(pairs []string) {
	for len(pairs) > 0 {
		old := pairs[0]
		if len(pairs) == 1 {
			abort.Msg("Missing 2nd. element for '%s'", old)
		}
		new := pairs[1]
		pairs = pairs[2:]
		setupAddTo(old, new)
	}
}

func readPairs(path string) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		abort.Msg("Can't %s", err)
	}
	pairs := strings.Fields(string(bytes))
	setupPairs(pairs)
}

func main() {

	// Setup custom usage function.
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR PAIR ...\n", os.Args[0])
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

	// Initialize search/add pairs.
	if *fromFile != "" {
		readPairs(*fromFile)
	}
	if len(args) > 1 {
		setupPairs(args[1:])
	}

	// Initialize config, especially "ignoreFiles'.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Do substitution.
	filetree.Walk(path, processInput)
}
