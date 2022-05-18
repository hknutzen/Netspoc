package main

import (
	"os"

	"github.com/hknutzen/Netspoc/go/pkg/oslink"
	"github.com/hknutzen/Netspoc/go/pkg/pass2"
)

func main() {
	os.Exit(pass2.CheckACLMain(oslink.Get()))
}
