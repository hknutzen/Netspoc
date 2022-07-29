package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/removefrom"
	"os"
)

func main() {
	os.Exit(removefrom.Main(oslink.Get()))
}
