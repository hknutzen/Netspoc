package main

import (
	"github.com/hknutzen/go-Netspoc/pkg/pass1"
	"os"
)

func main() {
	pass1.ImportFromPerl()
	pass1.CheckRedundantRules()
	os.Exit(pass1.ErrorCounter)
}
