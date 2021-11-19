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
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/info"
        "github.com/hknutzen/Netspoc/go/pkg/astset"
	"github.com/spf13/pflag"
	"os"
	"strings"
)

type state struct {
	*astset.State
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
	services := args[1:]

	dummyArgs := []string{
		fmt.Sprintf("--quiet=%v", *quiet),
		"--max_errors=9999",
	}
	conf.ConfigFromArgsAndFile(dummyArgs, path)
	
	s := new(state)
	var err error
	s.State, err = astset.Read(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while reading netspoc files: %s\n", err)
		return 1
	}
	
	for _, srv := range services {
		name := srv
		if !strings.HasPrefix(srv, "service:"){
			name = "service:" + srv
		}	
		s.RemoveServiceFromOverlaps(name)
		err = s.DeleteToplevel(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return 1
		}
	}
	for _, file := range s.Changed() {
		info.Msg("Changed %s", file)
	}
	s.Print()
	return 0
}
