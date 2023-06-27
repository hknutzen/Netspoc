package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/expand"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"os"
)

func main() {
	os.Exit(expand.Main(oslink.Get()))
}
