package main

import (
	"os"

	"github.com/hknutzen/Netspoc/go/pkg/exportsyntax"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
)

func main() {
	os.Exit(exportsyntax.Main(oslink.Get()))
}
