package main

import (
	"os"

	"github.com/hknutzen/Netspoc/go/pkg/mergeusers"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
)

func main() {
	os.Exit(mergeusers.Main(oslink.Get()))
}
