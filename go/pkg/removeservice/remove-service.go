package removeservice

/*
=head1 NAME

remove-service - Remove one or more services from netspoc files

=head1 SYNOPSIS

remove-service [options] FILE|DIR [service:]NAME ...

=head1 DESCRIPTION

This program reads a netspoc configuration and one or more SERVICE names. It
removes specified services in each file. Changes are done in place, no
backup files are created. But only changed files are touched.

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

	"github.com/hknutzen/Netspoc/go/pkg/astset"
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

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR [service:]NAME  ...\n%s",
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
	var err error
	s.State, err = astset.Read(path)
	if err != nil {
		fmt.Fprintf(d.Stderr, "Error while reading netspoc files: %s\n", err)
		return 1
	}

	for _, srv := range services {
		name := srv
		if !strings.HasPrefix(srv, "service:") {
			name = "service:" + srv
		}
		err = s.DeleteToplevel(name)
		if err != nil {
			fmt.Fprintf(d.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	s.ShowChanged(d.Stderr, *quiet)
	s.Print()
	return 0
}
