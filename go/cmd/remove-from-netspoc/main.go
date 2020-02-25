package main

/*
=head1 NAME

remove-from-netspoc - Remove one || more objects from netspoc files

=head1 SYNOPSIS

remove-from-netspoc [options] FILE|DIR OBJECT ...

=head1 DESCRIPTION

This program reads a netspoc configuration && one || more OBJECTS. It
removes specified objects in each file. Changes are done in place, no
backup files are created. But only changed files are touched.

=head1 OBJECT

An OBJECT is a typed name "type:NAME". Occurences of
"type:NAME" are removed. Changes are applied only in group
definitions && in implicit groups inside rules, i.e. after "user =",
"src =", "dst = ".  Multiple OBJECTS can be removed in a single run of
remove-from-netspoc.

The following types can be used in OBJECTS:
B<network host interface any group>.

=head1 OPTIONS

=over 4

=item B<-f> file

Read OBJECTS from file.

=item B<-q>

Quiet, don't print status messages.

=item B<-help>

Prints a brief help message && exits.

=item B<-man>

Prints the manual page && exits.

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
with this program; if !, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
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

var remove = make(map[string]bool)

func checkName(typedName string) {
	pair := strings.SplitN(typedName, ":", 2)
	if len(pair) != 2 {
		abort.Msg("Missing type in %s", typedName)
	}
	if !validType[pair[0]] {
		abort.Msg("Can't use type in %s", typedName)
	}
	re := regexp.MustCompile(`[^-\w\p{L}.:\@\/\[\]]`)
	if m := re.FindStringSubmatch(pair[1]); m != nil {
		abort.Msg("Invalid character '%s' in %s", m[0], typedName)
	}
}

func setupObjects(objects []string) {
	for _, object := range objects {
		checkName(object)
		remove[object] = true
	}
}

// Find occurrence of typed name in list of objects:
// - group:<name> = <typed name>, ... <typed name>;
// - src = ...;
// - dst = ...;
// - user = ...;
// but ignore typed name in definition:
// - <typed name> =
func process(input string) (int, string) {
	changed := 0
	inList := false
	var copy strings.Builder
	copy.Grow(len(input))

	comment := regexp.MustCompile(`^\s*[#].*\n`)
	typedName := regexp.MustCompile(`^(\s*)(\w+:[-\w\p{L}.\@:]+)`)
	extension := regexp.MustCompile(`^\[(?:auto|all)\]`)
	commaEOL := regexp.MustCompile(`^[ \t]*(,?)[ \t]*(?:[#].*)?(?:\n|$)`)
	semicolon := regexp.MustCompile(`^\s*;`)
	commaSpace := regexp.MustCompile(`^[ \t]*,[ \t]*`)
	comma := regexp.MustCompile(`^\s*,`)
	startAuto := regexp.MustCompile(`^\s*\w+:\[`)
	managedAuto := regexp.MustCompile(`^\s*managed\s*&`)
	ipAuto := regexp.MustCompile(`^\s*ip\s*=\s*[a-f:/0-9.]+\s*&`)
	endAuto := regexp.MustCompile(`^\s*\]`)
	negation := regexp.MustCompile(`^\s*[!]`)
	intersection := regexp.MustCompile(`^\s*[&]`)
	commaSpaceEOL := regexp.MustCompile(`^\s*,(?:[ \t]*\n)?`)
	description := regexp.MustCompile(`^\s*description\s*=.*\n`)
	startGroup := regexp.MustCompile(`^.*?(?:src|dst|user|group:[-\w\p{L}]+)`)
	equalSign := regexp.MustCompile(`^\s*=[ \t]*`)
	restToEOL := regexp.MustCompile(`^(?:.*\n|.+$)`)

	// Match pattern in input and skip matched pattern.
	match := func(re *regexp.Regexp) []string {
		matches := re.FindStringSubmatch(input)
		if matches == nil {
			return nil
		}
		skip := len(matches[0])
		input = input[skip:]
		return matches
	}

	for {
		if m := match(comment); m != nil {
			// Ignore comment.
			copy.WriteString(m[0])
		} else if inList {
			// Find next "type:name".
			if m := match(typedName); m != nil {
				space := m[1]
				object := m[2]
				if m := match(extension); m != nil {
					object += m[0]
				}
				if !remove[object] {
					copy.WriteString(space)
					copy.WriteString(object)
					continue
				}
				changed++

				// Check if current line has only one entry, then remove
				// whole line including comment.
				var prefix string
				processed := copy.String()
				idx := strings.LastIndex(processed, "\n")
				if idx != -1 {
					prefix = processed[idx+1:]
				} else {
					prefix = processed
				}
				if strings.TrimSpace(prefix) == "" {
					if m := match(commaEOL); m != nil {
						// Ready, if comma seen.
						if m[1] != "" {
							continue
						}
					}
				}
				if m := match(semicolon); m != nil {
					// Remove leading comma, if removed object is followed
					// by semicolon.
					trailing := m[0]
					re := regexp.MustCompile(`,\s*$`)
					processed := re.ReplaceAllString(processed, "")
					copy.Reset()
					copy.WriteString(processed)
					copy.WriteString(trailing)
					inList = false
					continue
				}
				if space != "" && space[0] == '\n' {

					// Retain indentation of removed object if it is first
					// object in line and is followed by other object in
					// same line.
					if ok, _ := regexp.MatchString(`^[ \t]*,[ \t]*\w`, input); ok {
						match(commaSpace)
						copy.WriteString(space)
						continue
					}
				}

				// Object with leading whitespace will be removed.
				// Also remove comma in current or some following
				// line if only separated by comment and whitespace.
				for {

					if m := match(comma); m != nil {
						// Remove found comma. Don't remove EOL.
						break
					} else if m := match(comment); m != nil {
						// Skip and retain comment at end of line.
						copy.WriteString(m[0])
					} else {
						break
					}
				}
			} else {
				// Check if list continues.
				for _, re := range []*regexp.Regexp{
					startAuto, managedAuto, ipAuto, endAuto,
					negation, intersection, commaSpaceEOL, description} {
					if m = match(re); m != nil {
						break
					}
				}
				if m != nil {
					copy.WriteString(m[0])
				} else {
					// Everything else terminates list.
					inList = false
				}
			}
		} else if m = match(startGroup); m != nil {
			// Find start of group.
			copy.WriteString(m[0])

			// Find equal sign.
			if m = match(equalSign); m != nil {
				copy.WriteString(m[0])
				inList = true
			}
		} else if m = match(restToEOL); m != nil {
			// Ignore rest of line if nothing matches.
			copy.WriteString(m[0])
		} else {
			// Terminate if everything has been processed.
			break
		}
	}
	return changed, copy.String()
}

func processInput(input *filetree.Context) {
	count, copy := process(input.Data)
	if count == 0 {
		return
	}
	path := input.Path
	diag.Info("%d changes in %s", count, path)
	err := os.Remove(path)
	if err != nil {
		abort.Msg("Can't remove %s: %s", path, err)
	}
	file, err := os.Create(path)
	if err != nil {
		abort.Msg("Can't create %s: %s", path, err)
	}
	_, err = file.WriteString(copy)
	if err != nil {
		abort.Msg("Can't write to %s: %s", path, err)
	}
	file.Close()
}

func readObjects(path string) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		abort.Msg("Can't %s", err)
	}
	objects := strings.Fields(string(bytes))
	if len(objects) == 0 {
		abort.Msg("Missing objects in %s", path)
	}
	setupObjects(objects)
}

func main() {

	// Setup custom usage function.
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR OBJECT ...\n", os.Args[0])
		pflag.PrintDefaults()
	}

	// Command line flags
	quiet := pflag.BoolP("quiet", "q", false, "Don't show number of changes")
	fromFile := pflag.StringP("file", "f", "", "Read OBJECTS from file")
	pflag.Parse()

	// Argument processing
	args := pflag.Args()
	if len(args) == 0 {
		pflag.Usage()
		os.Exit(1)
	}
	path := args[0]

	// Initialize to be removed objects.
	if *fromFile != "" {
		readObjects(*fromFile)
	}
	if len(args) > 1 {
		setupObjects(args[1:])
	}

	// Initialize config, especially "ignoreFiles'.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Do removal.
	filetree.Walk(path, processInput)
}
