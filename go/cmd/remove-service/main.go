package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/removeservice"
	"os"
)

func main() {
	os.Exit(removeservice.Main(oslink.Get()))
}
