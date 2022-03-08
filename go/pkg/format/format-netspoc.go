package format

import (
	"bytes"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/info"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
	"os"
)

func processInput(input *filetree.Context) error {
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
	info.Msg("Changed %s", path)

	return fileop.Overwrite(path, copy)
}

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR\n", os.Args[0])
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
	if len(args) != 1 {
		fs.Usage()
		return 1
	}
	path := args[0]
	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--quiet=%v", *quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Process each file.
	err := filetree.Walk(path, processInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 1
	}
	return 0
}
