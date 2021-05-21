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
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/info"
	"github.com/spf13/pflag"
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

var validName = regexp.MustCompile(`[^-\w\p{L}.:\@\/\[\]]`)

type state struct {
	*astset.State
	remove map[string]bool
}

func checkName(typedName string) error {
	pair := strings.SplitN(typedName, ":", 2)
	if len(pair) != 2 {
		return fmt.Errorf("Missing type in %s", typedName)
	}
	if !validType[pair[0]] {
		return fmt.Errorf("Can't use type in %s", typedName)
	}
	if m := validName.FindStringSubmatch(pair[1]); m != nil {
		return fmt.Errorf("Invalid character '%s' in %s", m[0], typedName)
	}
	return nil
}

func (s *state) setupObjects(objects []string) error {
	for _, object := range objects {
		if err := checkName(object); err != nil {
			return err
		}
		s.remove[object] = true
	}
	return nil
}

func (s *state) elementList(l *([]ast.Element)) bool {
	changed := false
	j := 0
	for _, n := range *l {
		switch obj := n.(type) {
		case ast.NamedElem:
			name := n.GetType() + ":" + obj.GetName()
			if s.remove[name] {
				changed = true
				continue
			}
		case *ast.SimpleAuto:
			changed = s.elementList(&obj.Elements) || changed
		case *ast.AggAuto:
			changed = s.elementList(&obj.Elements) || changed
		case *ast.IntfAuto:
			changed = s.elementList(&obj.Elements) || changed
		}
		(*l)[j] = n
		j++
	}
	*l = (*l)[:j]
	return changed
}

func (s *state) toplevel(n ast.Toplevel) bool {
	switch x := n.(type) {
	case *ast.TopList:
		if strings.HasPrefix(x.Name, "group:") {
			return s.elementList(&x.Elements)
		}
	case *ast.Service:
		changed := s.elementList(&x.User.Elements)
		for _, r := range x.Rules {
			changed = s.elementList(&r.Src.Elements) || changed
			changed = s.elementList(&r.Dst.Elements) || changed
		}
		return changed
	}
	return false
}

func (s *state) process() {

	// Remove elements from element lists.
	s.Modify(func(n ast.Toplevel) bool { return s.toplevel(n) })

	// Remove definition of group.
	// Silently ignore error, if definition isn't found.
	for name := range s.remove {
		if strings.HasPrefix(name, "group:") {
			s.DeleteToplevel(name)
		}
	}

	for _, file := range s.Changed() {
		info.Msg("Changed %s", file)
	}
}

func (s *state) readObjects(path string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Can't %s", err)
	}
	objects := strings.Fields(string(bytes))
	return s.setupObjects(objects)
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
	s := new(state)
	s.remove = make(map[string]bool)
	if *fromFile != "" {
		if err := s.readObjects(*fromFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	if len(args) > 1 {
		if err := s.setupObjects(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}

	// Initialize config, especially "ignoreFiles'.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	var err error
	s.State, err = astset.Read(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	s.process()
	s.Print()
	return 0
}
