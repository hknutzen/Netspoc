package main

import (
	"fmt"
	"github.com/hknutzen/Netspoc/go/pkg/abort"
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/filetree"
	"github.com/hknutzen/Netspoc/go/pkg/parser"
	"github.com/hknutzen/Netspoc/go/pkg/printer"
	"os"
)

func processInput(input *filetree.Context) {
	bytes := []byte(input.Data)
	path := input.Path
	list := parser.ParseFile(bytes, path)
	for _, n := range list {
		n.Order()
	}
	copy := printer.File(list, bytes)
	err := os.Remove(path)
	if err != nil {
		abort.Msg("Can't remove %s: %s", path, err)
	}
	file, err := os.Create(path)
	if err != nil {
		abort.Msg("Can't create %s: %s", path, err)
	}
	_, err = file.Write(copy)
	if err != nil {
		abort.Msg("Can't write to %s: %s", path, err)
	}
	file.Close()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s FILE|DIR\n", os.Args[0])
		os.Exit(1)
	}
	path := os.Args[1]
	conf.ConfigFromArgsAndFile(nil, path)
	filetree.Walk(path, processInput)
}
