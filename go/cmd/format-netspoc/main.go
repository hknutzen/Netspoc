package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/format"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"os"
)

func main() {
	os.Exit(format.Main(oslink.Get()))
}
