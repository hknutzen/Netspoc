package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/transposeservice"
	"os"
)

func main() {
	os.Exit(transposeservice.Main(oslink.Get()))
}
