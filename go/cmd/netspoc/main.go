package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"os"
)

func main() {
	os.Exit(pass1.SpocMain(oslink.Get()))
}
