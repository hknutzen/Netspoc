package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
)

func RemoveSimpleDuplicateRules() {
	diag.Progress("Removing simple duplicate rules")

	// Change slice in place.
	process := func(rules ruleList) ruleList {
		type key struct {
			src someObj
			dst someObj
			prt *proto
		}
		seen := make(map[key]bool)
		j := 0
		for _, r := range rules {
			if len(r.src) == 1 && len(r.dst) == 1 && len(r.prt) == 1 &&
				r.srcRange == nil &&
				r.log == "" && !r.oneway && !r.stateless {

				s := r.src[0]
				d := r.dst[0]
				p := r.prt[0]
				if seen[key{s, d, p}] {
					diag.Msg("Removed duplicate " + r.print())
					continue
				}
				seen[key{s, d, p}] = true
			}
			rules[j] = r
			j++
		}
		return rules[:j]
	}
	pRules.permit = process(pRules.permit)
	pRules.deny = process(pRules.deny)
}
