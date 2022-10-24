package pass1

import (
	"sort"

	"github.com/hknutzen/Netspoc/go/pkg/ast"
)

func (c *spoc) checkIdenticalServices(sRules *serviceRules) {
	printType := c.conf.CheckIdenticalServices
	if printType == "" {
		return
	}
	c.progress("Checking for services with identical body")

	// Sort error messages before output.
	c.sortedSpoc(func(c *spoc) {

		// Regenerate service lists from serviceRules.
		// Start with serviceRules, because we need expanded objects
		// for getAttr() to work.
		type ruleInfo struct {
			deny       bool
			objIsSrc   bool
			objects    []srvObj
			names      stringList
			unexpanded *unexpRule
		}
		svc2ruleInfoList := make(map[*service][]*ruleInfo)
		process := func(rules serviceRuleList) {
			for _, rule := range rules {
				unexpanded := rule.rule
				svc := unexpanded.service
				hasUser := unexpanded.hasUser
				if hasUser == "both" {
					if svc.identicalBody != nil {
						c.warn("Useless attribute 'identical_body' in %s", svc)
						svc.identicalBody = nil
					}
					continue
				}
				if rule.reversed {
					if hasUser == "src" {
						hasUser = "dst"
					} else {
						hasUser = "src"
					}
				}
				var objects []srvObj
				if hasUser == "src" {
					objects = rule.dst
				} else {
					objects = rule.src
				}
				names := make(stringList, len(objects)+len(rule.prt))
				for i, obj := range objects {
					names[i] = obj.String()
				}
				for i, prt := range rule.prt {
					names[i+len(objects)] = prt.name
				}
				sort.Strings(names)
				info := &ruleInfo{
					deny:       rule.deny,
					objIsSrc:   hasUser != "src",
					objects:    objects,
					names:      names,
					unexpanded: unexpanded,
				}
				svc2ruleInfoList[svc] = append(svc2ruleInfoList[svc], info)
			}
		}
		process(sRules.permit)
		process(sRules.deny)

		// Group similar services.
		// Use this as hash key.
		type svcInfo struct {
			count int
			names [4]string
		}
		svcInfo2svcList := make(map[svcInfo][]*service)
		for svc, riList := range svc2ruleInfoList {
			sort.Slice(riList, func(i, j int) bool {
				if riList[i].deny != riList[j].deny {
					return riList[i].deny
				}
				if riList[i].objIsSrc != riList[j].objIsSrc {
					return !riList[i].objIsSrc
				}
				l1 := riList[i].names
				l2 := riList[j].names
				for k, name := range l1 {
					if k >= len(l2) {
						return false
					}
					if l1[k] != l2[k] {
						return name < l2[k]
					}
				}
				// l1 is prefix of l2 or equal to l2.
				return true
			})
			var si svcInfo
			si.count = len(riList)
			// Build hash key from first rule of service.
			names := riList[0].names
			// List has at least 2 elements: 1x object, 1x protocol
			// Take first and last two elements.
			ln := len(names)
			si.names[0] = names[0]
			si.names[1] = names[1]
			si.names[2] = names[ln-1]
			si.names[3] = names[ln-2]
			svcInfo2svcList[si] = append(svcInfo2svcList[si], svc)

			// Check, if attribute identical_body is forbidden.
			if svc.identicalBody != nil {
				for _, ri := range riList {
					for _, obj := range ri.objects {
						if getAttr(obj, identicalBodyAttr) == restrictVal {
							c.warn("Attribute 'identical_body' is blocked at %s",
								svc)
							break
						}
					}
				}
			}
		}

		// Check, if warning / error message is suppressed.
		msgSuppressed := func(l []*service) bool {
			// 1. Each object of rules has attribute "identical_body = ok"
			riList := svc2ruleInfoList[l[0]]
			ok := true
			for _, ri := range riList {
				for _, obj := range ri.objects {
					if getAttr(obj, identicalBodyAttr) != okVal {
						ok = false
					}
				}
			}
			if ok {
				return true
			}

			// 2. Each element occurs either at left or at right side
			//    of 'identical_body' relation.
			inSet := make(map[*service]bool)
			for _, s1 := range l {
				inSet[s1] = true
			}
			seen := make(map[*service]bool)
			for _, s1 := range l {
				for _, s2 := range s1.identicalBody {
					if inSet[s2] {
						seen[s1] = true
						seen[s2] = true
					} else {
						c.warn("%s has useless %s in attribute 'identical_body'",
							s1, s2)
					}
				}
			}
			for _, s := range l {
				if !seen[s] {
					return false
				}
			}
			return true
		}
		sortPrt := func(l protoList) {
			sort.Slice(l, func(i, j int) bool {
				return l[i].name < l[j].name
			})
		}
		prtEq := func(l1, l2 protoList) bool {
			if len(l1) != len(l2) {
				return false
			}
			sortPrt(l1)
			sortPrt(l2)
			for i, prt := range l1 {
				if prt.name != l2[i].name {
					return false
				}

			}
			return true
		}
		sortRules := func(s *service) {
			unsorted := s.rules
			if len(unsorted) < 2 {
				return
			}
			// ruleInfo is sorted already.
			riList := svc2ruleInfoList[s]
			seen := make(map[*unexpRule]bool)
			sorted := make([]*unexpRule, 0, len(unsorted))
			for _, ri := range riList {
				un := ri.unexpanded
				if !seen[un] {
					seen[un] = true
					sorted = append(sorted, un)
				}
			}
			s.rules = sorted
		}
		svcEq := func(s1, s2 *service) bool {
			if s1.disableAt != s2.disableAt {
				return false
			}
			l1 := s1.rules
			l2 := s2.rules
			for i, r1 := range l1 {
				r2 := l2[i]
				if !(r1.action == r2.action &&
					elementsEq(r1.src, r2.src) &&
					elementsEq(r1.dst, r2.dst) &&
					prtEq(r1.prt, r2.prt) &&
					r1.log == r2.log) {
					return false
				}
			}
			return true
		}
		// Check if similar rule definitions are really identical.
		for _, l := range svcInfo2svcList {
			sort.Slice(l, func(i, j int) bool {
				return l[i].name < l[j].name
			})
			for {
				m := len(l) - 1
				s1 := l[m] // Last element
				sortRules(s1)
				var areEq, notEq []*service
				for _, s2 := range l[:m] {
					sortRules(s2)
					if svcEq(s1, s2) {
						areEq = append(areEq, s2)
					} else {
						notEq = append(notEq, s2)
					}
				}
				if len(areEq) > 0 {
					areEq = append(areEq, s1)
					if !msgSuppressed(areEq) {
						msg := "These services have identical rule definitions.\n" +
							" A single service should be created instead," +
							" with merged users."
						for _, svc := range areEq {
							msg += "\n - " + svc.name
						}
						c.warnOrErr(printType, msg)
					}
				} else if s1.identicalBody != nil {
					c.warn("Useless attribute 'identical_body' in %s", s1)
				}
				if notEq == nil {
					break
				}
				l = notEq
			}
		}
	})
}

func elementsEq(l1, l2 []ast.Element) bool {
	if len(l1) != len(l2) {
		return false
	}
	ast.OrderElements(l1)
	ast.OrderElements(l2)
	for i, el := range l1 {
		if !elemEq(el, l2[i]) {
			return false
		}
	}
	return true
}

func elemEq(e1, e2 ast.Element) bool {
	result := false
	switch a := e1.(type) {
	case *ast.User:
		_, result = e2.(*ast.User)
	case *ast.NamedRef:
		if b, ok := e2.(*ast.NamedRef); ok {
			result = a.Type == b.Type && a.Name == b.Name
		}
	case *ast.IntfRef:
		if b, ok := e2.(*ast.IntfRef); ok {
			result = a.Router == b.Router &&
				a.Network == b.Network &&
				a.Extension == b.Extension
		}
	case *ast.SimpleAuto:
		if b, ok := e2.(*ast.SimpleAuto); ok {
			result = a.Type == b.Type && elementsEq(a.Elements, b.Elements)
		}
	case *ast.AggAuto:
		if b, ok := e2.(*ast.AggAuto); ok {
			result = a.Net == b.Net && elementsEq(a.Elements, b.Elements)
		}
	case *ast.IntfAuto:
		if b, ok := e2.(*ast.IntfAuto); ok {
			result = a.Managed == b.Managed && a.Selector == b.Selector &&
				elementsEq(a.Elements, b.Elements)
		}
	case *ast.Complement:
		if b, ok := e2.(*ast.Complement); ok {
			result = elemEq(a.Element, b.Element)
		}
	case *ast.Intersection:
		if b, ok := e2.(*ast.Intersection); ok {
			result = elementsEq(a.Elements, b.Elements)
		}
	}
	return result
}
