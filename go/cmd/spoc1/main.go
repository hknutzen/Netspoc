package main

import (
	"github.com/hknutzen/Netspoc/go/pkg/conf"
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/pass1"
)

var (
	program = "Netspoc"
	version = "devel"
)

func main() {
	inDir, outDir := conf.GetArgs()
	diag.Info(program + ", version " + version)
	pass1.ReadNetspoc(inDir)
	pass1.MarkDisabled()
	pass1.CheckIPAdresses()
	pass1.SetZone()
	pass1.SetPath()
	NATDomains, NATTag2natType, _ := pass1.DistributeNatInfo()
	pass1.FindSubnetsInZone()
	// Call after findSubnetsInZone, where zone.networks has
	// been set up.
	pass1.CheckReroutePermit()
	pass1.NormalizeServices()
	pass1.AbortOnError()

	pass1.CheckServiceOwner()
	pRules, dRules := pass1.ConvertHostsInRules()
	pass1.GroupPathRules(pRules, dRules)
	pass1.FindSubnetsInNatDomain(NATDomains)
	pass1.CheckUnstableNatRules()
	pass1.MarkManagedLocal()
	pass1.CheckDynamicNatRules(NATDomains, NATTag2natType)
	pass1.CheckUnusedGroups()
	pass1.CheckSupernetRules(pRules)
	pass1.CheckRedundantRules()

	pass1.RemoveSimpleDuplicateRules()
	pass1.CombineSubnetsInRules()
	pass1.SetPolicyDistributionIP()
	pass1.ExpandCrypto()
	pass1.FindActiveRoutes()
	pass1.GenReverseRules()
	if outDir != "" {
		pass1.MarkSecondaryRules()
		pass1.RulesDistribution()
		pass1.PrintCode(outDir)
		pass1.CopyRaw(inDir, outDir)
	}
	pass1.AbortOnError()
	diag.Progress("Finished pass1")
}
