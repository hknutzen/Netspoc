package pass1

func (c *spoc) checkUnstableNatRules() {
	c.progress("Checking rules for unstable subnet relation")
	process := func(l ruleList) {
		for _, rule := range l {
			getUnstable := func(l []someObj) netList {
				var result netList
				for _, obj := range l {
					if n, ok := obj.(*network); ok {
						if n.unstableNat != nil {
							result.push(n)
						}
					}
				}
				return result
			}
			unstableSrc := getUnstable(rule.src)
			unstableDst := getUnstable(rule.dst)
			if unstableSrc == nil && unstableDst == nil {
				continue
			}
			check := func(l netList, intf *routerIntf, isSrc bool) {
				for _, n := range l {
					subnets := n.unstableNat[intf.zone.natDomain]
					if subnets == nil {
						continue
					}
					rule := *rule
					if isSrc {
						rule.src = []someObj{n}
					} else {
						rule.dst = []someObj{n}
					}
					c.err("Must not use %s in rule\n"+
						" %s,\n"+
						" because it is no longer supernet of\n"+
						"%s\n"+
						" at %s",
						n, rule.print(), subnets.nameList(), intf)
				}
			}
			walk := func(rule *groupedRule, inIntf, outIntf *routerIntf) {
				if inIntf != nil {
					check(unstableSrc, inIntf, true)
					check(unstableDst, inIntf, false)
				}
				if outIntf != nil && outIntf.router.model != nil &&
					outIntf.router.model.stateless {

					for _, prt := range rule.prt {
						switch prt.proto {
						case "tcp", "udp", "ip":
							check(unstableSrc, outIntf, true)
							check(unstableDst, outIntf, false)
							return
						}
					}
				}
			}
			c.pathWalk(rule, walk, "Router")
		}
	}
	process(c.allPathRules.deny)
	process(c.allPathRules.permit)
}
