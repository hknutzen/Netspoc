package removefrom

/*
=head1 NAME

remove-from-netspoc - Remove one or more objects from netspoc files

=head1 SYNOPSIS

remove-from-netspoc [options] FILE|DIR OBJECT ...

=head1 DESCRIPTION

This program reads a netspoc configuration and one or more OBJECTS. It
removes specified objects in each file. Changes are done in place, no
backup files are created. But only changed files are touched.

=head1 OBJECT

An OBJECT is a typed name "type:NAME". Occurrences of
"type:NAME" are removed. Changes are applied only in group
definitions and in implicit groups inside rules, i.e. after "user =",
"src =", "dst = ".  Multiple OBJECTS can be removed in a single run of
remove-from-netspoc.

The following types can be used in OBJECTS:
B<network host interface any group area>.

=head1 OPTIONS

=over 4

=item B<-f> file

Read OBJECTS from file.

=item B<-q>

Quiet, don't print status messages.

=item B<-h>

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
with this program; if !, write to the Free Software Foundation, Inc.,
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

var remove map[string]bool
var changes int

func checkName(typedName string) error {
	pair := strings.SplitN(typedName, ":", 2)
	if len(pair) != 2 {
		return fmt.Errorf("Missing type in %s", typedName)
	}
	if !validType[pair[0]] {
		return fmt.Errorf("Can't use type in %s", typedName)
	}
	re := regexp.MustCompile(`[^-\w\p{L}.:\@\/\[\]]`)
	if m := re.FindStringSubmatch(pair[1]); m != nil {
		return fmt.Errorf("Invalid character '%s' in %s", m[0], typedName)
	}
	return nil
}

func setupObjects(objects []string) error {
	for _, object := range objects {
		if err := checkName(object); err != nil {
			return err
		}
		remove[object] = true
	}
	return nil
}

func removeElement(n ast.Element) bool {
	switch obj := n.(type) {
	case *ast.NamedRef, *ast.IntfRef:
		name := obj.GetType() + ":" + obj.GetName()
		return remove[name]
	case *ast.SimpleAuto:
		elementList(&obj.Elements)
	case *ast.AggAuto:
		elementList(&obj.Elements)
	case *ast.IntfAuto:
		elementList(&obj.Elements)
	}
	return false
}

func elementList(l *([]ast.Element)) {
	removed := 0
	for i, n := range *l {
		if removeElement(n) {
			(*l)[i] = nil
			removed++
		}
	}
	if removed > 0 {
		changes += removed
		new := make([]ast.Element, 0, len(*l)-removed)
		for _, n := range *l {
			if n != nil {
				new = append(new, n)
			}
		}
		*l = new
	}
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
	nodes, err := parser.ParseFile(source, path)
	if err != nil {
		return err
	}
	count := processFile(nodes)
	if count == 0 {
		return nil
	}

	info.Msg("%d changes in %s", count, path)
	for _, n := range nodes {
		n.Order()
	}
	copy := printer.File(nodes, source)
	return fileop.Overwrite(path, copy)
}

func readObjects(path string) error {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Can't %s", err)
	}
	objects := strings.Fields(string(bytes))
	if len(objects) == 0 {
		return fmt.Errorf("Missing objects in %s", path)
	}
	return setupObjects(objects)
}

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR OBJECT ...\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := fs.StringP("file", "f", "", "Read OBJECTS from file")
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

	// Initialize to be removed objects.
	remove = make(map[string]bool)
	if *fromFile != "" {
		if err := readObjects(*fromFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	if len(args) > 1 {
		if err := setupObjects(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}

	// Initialize config, especially "ignoreFiles'.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Do removal.
	if err := filetree.Walk(path, processInput); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	return 0
}
