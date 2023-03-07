package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/rename"
	"os"
)

func main() {
	os.Exit(rename.Main(oslink.Get()))
}
