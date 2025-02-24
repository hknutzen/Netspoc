package transposeservice

/*
=head1 NAME

transpose-service - Transpose one service in netspoc files

=head1 SYNOPSIS

transpose-service [options] FILE|DIR [service:]NAME ...

=head1 DESCRIPTION

This program reads a netspoc configuration and one or more SERVICE name(s). It
transposes the specified service in each file. Keyword user in src/dst is switched
but functionality of the service is not changed. Filechanges are done in place,
no backup files are created. But only changed files are touched.

=head1 OPTIONS

=over 4

=item B<-f> file

Read services from file.

=item B<-q>

Quiet, don't print status messages.

=item B<-h>

Prints a brief help message and exits.

=back

=head1 COPYRIGHT AND DISCLAIMER

(c) 2023 by Dominik Kunkel <netspoc@drachionix.eu>
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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
	"github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/spf13/pflag"
)

type state struct {
	*astset.State
}

func (s *state) readObjects(path string) ([]string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Can't %s", err)
	}
	objects := strings.Fields(string(bytes))
	return objects, nil
}

func (s *state) transposeService(name string) error {
	var errMsg string
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		n, ok := toplevel.(*ast.Service)
		if !ok || n.GetName() != name {
			return false
		}
		if n.Foreach {
			errMsg = "Can't transpose service: foreach present."
			return false
		}
		if len(n.Rules) > 1 {
			errMsg = "Can't transpose service: multiple rules present."
			return false
		}
		if len(n.Rules) == 0 {
			errMsg = "Can't transpose service: no rule present."
			return false
		}
		srcElements := n.Rules[0].Src.Elements
		dstElements := n.Rules[0].Dst.Elements
		userElements := n.User.Elements
		srcIsUser := len(srcElements) == 1 && srcElements[0].GetType() == "user"
		dstIsUser := len(dstElements) == 1 && dstElements[0].GetType() == "user"
		if srcIsUser && dstIsUser {
			errMsg = "Can't transpose service: both src and dst reference user."
			return false
		}
		if !(srcIsUser || dstIsUser) {
			errMsg = "Can't transpose service:" +
				" none of src and dst directly reference user."
			return false
		}
		if srcIsUser {
			if hasUserInElements(dstElements) {
				errMsg = "Can't transpose service: dst references nested user."
				return false
			}
			n.Rules[0].Src.Elements = userElements
			n.Rules[0].Dst.Elements = srcElements
			n.User.Elements = dstElements
		} else {
			if hasUserInElements(srcElements) {
				errMsg = "Can't transpose service: src references nested user."
				return false
			}
			n.Rules[0].Src.Elements = dstElements
			n.Rules[0].Dst.Elements = userElements
			n.User.Elements = srcElements
		}
		return true
	})

	if found {
		return nil
	}
	if errMsg == "" {
		errMsg = "Can't find service " + name
	}
	return errors.New(errMsg)
}

func hasUserInElements(l []ast.Element) bool {
	var hasUser func(el ast.Element) bool
	hasUser = func(el ast.Element) bool {
		switch x := el.(type) {
		case *ast.User:
			return true
		case ast.AutoElem:
			return hasUserInElements(x.GetElements())
		case *ast.Intersection:
			return hasUserInElements(x.Elements)
		case *ast.Complement:
			return hasUser(x.Element)
		default:
			return false
		}
	}
	for _, el := range l {
		if hasUser(el) {
			return true
		}
	}
	return false
}

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR [service:]NAME ...\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	fromFile := fs.StringP("file", "f", "", "Read SERVICES from file")
	if err := fs.Parse(d.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		fs.Usage()
		return 1
	}

	s := new(state)

	// Argument processing
	args := fs.Args()
	var services []string
	if *fromFile != "" {
		l, err := s.readObjects(*fromFile)
		if err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
		services = l
	} else if len(args) == 0 {
		fs.Usage()
		return 1
	}
	path := args[0]
	services = append(services, args[1:]...)

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
	}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, path)

	var err error
	s.State, err = astset.Read(path)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error while reading netspoc files: %s\n", err)
		return 1
	}

	for _, service := range services {
		name := service
		if !strings.HasPrefix(service, "service:") {
			name = "service:" + service
		}
		err = s.transposeService(name)
		if err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	s.ShowChanged(d.Stderr, cnf.Quiet)
	s.Print()
	return 0
}
