package main

import (
	"bytes"
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/fileop"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"github.com/spf13/pflag"
	"os"
)

func processInput(input *filetree.Context) {
	source := []byte(input.Data)
	path := input.Path
	list, err := parser.ParseFile(source, path)
	if err != nil {
		abort.Msg("%v", err)
	}
	for _, n := range list {
		n.Order()
	}
	copy := printer.File(list, source)

	if bytes.Compare(source, copy) == 0 {
		return
	}
	diag.Info("Changed %s", path)

	err = fileop.Overwrite(path, copy)
	if err != nil {
		abort.Msg("%v", err)
	}
}

func main() {
	// Setup custom usage function.
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE|DIR\n", os.Args[0])
		pflag.PrintDefaults()
	}

	// Command line flags
	quiet := pflag.BoolP("quiet", "q", false, "Don't show changed files")
	pflag.Parse()

	// Argument processing
	args := pflag.Args()
	if len(args) != 1 {
		pflag.Usage()
		os.Exit(1)
	}
	path := args[0]
	// Initialize Conf, especially attribute IgnoreFiles.
	dummyArgs := []string{fmt.Sprintf("--verbose=%v", !*quiet)}
	conf.ConfigFromArgsAndFile(dummyArgs, path)

	// Process each file.
	filetree.Walk(path, processInput)
}
