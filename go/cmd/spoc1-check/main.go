package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"os"
)

func main() {
	initialErrors := pass1.ErrorCounter
	pass1.ImportFromPerl()
	pass1.CheckUnusedGroups()
	pass1.CheckSupernetRules()
	pass1.CheckRedundantRules()
	os.Exit(pass1.ErrorCounter - initialErrors)
}
