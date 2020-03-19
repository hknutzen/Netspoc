package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
)

func main() {
	rawArgs := pass1.ImportFromPerl()
	pass1.PrintService(rawArgs)
}
