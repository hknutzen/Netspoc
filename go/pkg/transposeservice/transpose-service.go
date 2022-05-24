package transposeservice

/*
=head1 NAME

transpose-service - Transpose one service in netspoc files

=head1 SYNOPSIS

transpose-service [options] FILE|DIR [service:]NAME

=head1 DESCRIPTION

This program reads a netspoc configuration and one SERVICE name. It
transposes the specified service in each file. Keyword user in src/dst is switched
but functionality of the service is not changed. Filechanges are done in place,
no backup files are created. But only changed files are touched.

=head1 OPTIONS

=over 4

=item B<-q>

Quiet, don't print status messages.

=item B<-h>

Prints a brief help message and exits.

=back

=head1 COPYRIGHT AND DISCLAIMER

(c) 2021 by Dominik Kunkel <netspoc@drachionix.eu>
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

func (s *state) transposeService(name string) error {
	var err error
	found := s.Modify(func(toplevel ast.Toplevel) bool {
		if n, ok := toplevel.(*ast.Service); ok {
			if name == n.GetName() {
				if n.Foreach {
					err = fmt.Errorf("Can't transpose service: foreach present.")
					return false
				}
				srcelements := n.Rules[0].Src.Elements
				dstelements := n.Rules[0].Dst.Elements
				userelements := n.User.Elements
				if len(n.Rules) > 1 {
					err = fmt.Errorf("Can't transpose service: multiple rules present.")
					return false

				}
				// If source and destination are user no transformation needed
				if len(srcelements) == 1 && len(dstelements) == 1 &&
					srcelements[0].GetType() == "user" &&
					dstelements[0].GetType() == "user" {

					err = fmt.Errorf("Can't transpose service: src and dst are user.")
					return false
				}
				if len(srcelements) == 1 {
					if srcelements[0].GetType() == "user" {
						n.Rules[0].Src.Elements = userelements
						n.Rules[0].Dst.Elements = srcelements
						n.User.Elements = dstelements
						return true
					}
				}
				if len(dstelements) == 1 {
					if dstelements[0].GetType() == "user" {
						n.Rules[0].Src.Elements = dstelements
						n.Rules[0].Dst.Elements = userelements
						n.User.Elements = srcelements
						return true
					}
				}
			}
		}
		return false
	})
	if err == nil {
		err = fmt.Errorf("Can't find service %s", name)
	}

	if found {
		return nil
	} else {
		return err
	}
}

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR [service:]NAME\n%s",
			d.Args[0], fs.FlagUsages())
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
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
	if len(args) != 2 {
		fs.Usage()
		return 1
	}
	path := args[0]
	service := args[1]

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
	}
	cnf := conf.ConfigFromArgsAndFile(dummyArgs, path)

	var err error
	s.State, err = astset.Read(path, cnf.IPV6)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error while reading netspoc files: %s\n", err)
		return 1
	}

	name := service
	if !strings.HasPrefix(service, "service:") {
		name = "service:" + service
	}
	err = s.transposeService(name)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	s.ShowChanged(d.Stderr, cnf.Quiet)
	s.Print()
	return 0
}
