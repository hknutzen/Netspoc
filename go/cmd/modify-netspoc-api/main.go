package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/api"
	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"os"
)

func main() {
	os.Exit(api.Main(oslink.Get()))
}
