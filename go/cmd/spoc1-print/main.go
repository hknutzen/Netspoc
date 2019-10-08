package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"os"
)

func main() {
	pass1.ImportFromPerl()
	pass1.ExpandCrypto()
	pass1.FindActiveRoutes()
	pass1.GenReverseRules()
	if pass1.OutDir != "" {
		pass1.MarkSecondaryRules()
		pass1.RulesDistribution()
		pass1.PrintCode(pass1.OutDir)
	}
	os.Exit(pass1.ErrorCounter)
}
