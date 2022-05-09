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

If a service gets empty "user","src" or "dst" after removal of OBJECT,
the definition of this service is removed as well.

If the to be removed object is a host or an unmanaged interface with
attribute 'loopback' or 'vip', the definition of this object is
removed as well.

The following types can be used in OBJECTS:
B<network host interface any group area>.

=head1 OPTIONS

=over 4

=item B<-d> file

Delete definition of host, interface.

=item B<-f> file

Read OBJECTS from file.

=item B<-q>

Quiet, don't print status messages.

=item B<-h>

Prints a brief help message and exits.

=back

=head1 COPYRIGHT AND DISCLAIMER

(c) 2022 by Heinz Knutzen <heinz.knutzengooglemail.com>

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
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/info"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/spf13/pflag"
	"os"
	"strings"
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
	var emptySvc []string
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
		empty := false
		change := func(l *[]ast.Element) {
			l2 := traverse(*l, false)
			if len(l2) == 0 {
				empty = true
			}
			*l = l2
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
			if empty {
				emptySvc = append(emptySvc, x.Name)
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
	for _, name := range emptySvc {
		s.RemoveServiceFromOverlaps(name)
		s.DeleteToplevel(name)
	}

	for _, file := range s.Changed() {
		info.Msg("Changed %s", file)
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

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR OBJECT ...\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	fromFile := fs.StringP("file", "f", "", "Read OBJECTS from file")
	delDef := fs.BoolP("delete", "d", false,
		"Also delete definition if OBJECT is host or interface")
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
	remove := make(map[string]bool)
	if *fromFile != "" {
		if err := readObjects(remove, *fromFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	if len(args) > 1 {
		if err := setupObjects(remove, args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}

	// Initialize config, especially "ignoreFiles'.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	s, err := astset.Read(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	process(s, remove, *delDef)
	s.Print()
	return 0
}
