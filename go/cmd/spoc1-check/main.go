package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"os"
)

func main() {
	pass1.ImportFromPerl()
	pass1.CheckSupernetRules()
	pass1.CheckRedundantRules()
	os.Exit(pass1.ErrorCounter)
}
