package pass1

import ()

func (c *spoc) removeSimpleDuplicateRules() {
	c.progress("Removing simple duplicate rules")

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
					c.diag("Removed duplicate " + r.print())
					continue
				}
				seen[key{s, d, p}] = true
			}
			rules[j] = r
			j++
		}
		return rules[:j]
	}
	c.allPathRules.permit = process(c.allPathRules.permit)
	c.allPathRules.deny = process(c.allPathRules.deny)
}
