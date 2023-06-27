package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/addto"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"os"
)

func main() {
	os.Exit(addto.Main(oslink.Get()))
}
