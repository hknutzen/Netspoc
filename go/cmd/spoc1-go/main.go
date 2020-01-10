package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
)

func main() {
	pass1.ImportFromPerl()

	pass1.NormalizeServices()
	pass1.AbortOnError()

	pass1.CheckServiceOwner()
	pRules, dRules := pass1.ConvertHostsInRules()
	pass1.GroupPathRules(pRules, dRules)
	pass1.FindSubnetsInNatDomain(pass1.NATDomains)
	pass1.CheckUnstableNatRules()
	pass1.MarkManagedLocal()
	pass1.CheckDynamicNatRules(pass1.NATDomains, pass1.NATTag2natType)
	pass1.CheckUnusedGroups()
	pass1.CheckSupernetRules(pRules)
	pass1.CheckRedundantRules()

	pass1.RemoveSimpleDuplicateRules()
	pass1.CombineSubnetsInRules()
	pass1.SetPolicyDistributionIP()
	pass1.ExpandCrypto()
	pass1.FindActiveRoutes()
	pass1.GenReverseRules()
	if pass1.OutDir != "" {
		pass1.MarkSecondaryRules()
		pass1.RulesDistribution()
		pass1.PrintCode(pass1.OutDir)
		pass1.CopyRaw(pass1.InPath, pass1.OutDir)
	}
	pass1.AbortOnError()
	diag.Progress("Finished pass1")
}
