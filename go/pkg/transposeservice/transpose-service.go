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
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/info"
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

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR [service:]NAME\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "Don't show changed files")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
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
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	var err error
	s.State, err = astset.Read(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while reading netspoc files: %s\n", err)
		return 1
	}

	name := service
	if !strings.HasPrefix(service, "service:") {
		name = "service:" + service
	}
	err = s.TransposeService(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}

	for _, file := range s.Changed() {
		info.Msg("Changed %s", file)
	}
	s.Print()
	return 0
}
