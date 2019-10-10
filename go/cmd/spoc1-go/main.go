package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
	"os"
)

func main() {
	pass1.ImportFromPerl()
	initialErrors := pass1.ErrorCounter

	pass1.CheckUnusedGroups()
	pass1.CheckSupernetRules()
	pass1.CheckRedundantRules()

	pass1.RemoveSimpleDuplicateRules()
	pass1.SetPolicyDistributionIP()
	pass1.ExpandCrypto()
	pass1.FindActiveRoutes()
	pass1.GenReverseRules()
	if pass1.OutDir != "" {
		pass1.MarkSecondaryRules()
		pass1.RulesDistribution()
		pass1.PrintCode(pass1.OutDir)
	}
	os.Exit(pass1.ErrorCounter - initialErrors)
}
