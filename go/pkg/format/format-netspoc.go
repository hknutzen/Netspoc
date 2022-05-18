package format

import (
	"bytes"
	"fmt"

	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
)

func Main(d oslink.Data) int {
	fs := pflag.NewFlagSet(d.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(d.Stderr,
			"Usage: %s [options] FILE|DIR\n%s",
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

	// Argument processing
	args := fs.Args()
	if len(args) != 1 {
		fs.Usage()
		return 1
	}
	path := args[0]
	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Process each file.
	err := filetree.Walk(path, func(input *filetree.Context) error {
		source := []byte(input.Data)
		path := input.Path
		aF, err := parser.ParseFile(source, path, parser.ParseComments)
		if err != nil {
			return err
		}
		for _, n := range aF.Nodes {
			n.Order()
		}
		copy := printer.File(aF)

		if bytes.Equal(source, copy) {
			return nil
		}
		if !conf.Conf.Quiet {
			fmt.Fprintf(d.Stderr, "Changed %s\n", path)
		}
		return fileop.Overwrite(path, copy)
	})

	if err != nil {
		fmt.Fprintf(d.Stderr, "Error: %s\n", err)
		return 1
	}
	return 0
}
