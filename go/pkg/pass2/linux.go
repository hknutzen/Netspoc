package pass2

import (
	"fmt"
	"inet.af/netaddr"
	"os"
	"sort"
	"strconv"
)

// Needed for model=Linux.
func addTCPUDPIcmp(prt2obj name2Proto) {
	_ = getPrtObj("tcp", prt2obj)
	_ = getPrtObj("udp", prt2obj)
	_ = getPrtObj("icmp", prt2obj)
}

// Returns iptables code for filtering a protocol.
func iptablesPrtCode(srcRangeNode, prtNode *prtBintree, ipv6 bool) string {
	prt := &prtNode.proto
	protocol := prt.protocol
	result := " -p " + protocol
	switch protocol {
	case "tcp", "udp":
		portCode := func(rangeObj *proto) string {
			ports := rangeObj.ports
			v1, v2 := ports[0], ports[1]
			if v1 == v2 {
				return strconv.Itoa(v1)
			}
			if v1 == 1 && v2 == 65535 {
				return ""
			}
			if v2 == 65535 {
				return strconv.Itoa(v1) + ":"
			}
			if v1 == 1 {
				return ":" + strconv.Itoa(v2)
			}
			return strconv.Itoa(v1) + ":" + strconv.Itoa(v2)
		}
		if srcRangeNode != nil {
			if sport := portCode(&srcRangeNode.proto); sport != "" {
				result += " --sport " + sport
			}
		}
		if dport := portCode(prt); dport != "" {
			result += " --dport " + dport
		}
	case "icmp":
		if ipv6 {
			result = " -p ipv6-icmp"
		}
		if icmpType := prt.icmpType; icmpType != -1 {
			result += " --icmp-type " + strconv.Itoa(icmpType)
			if code := prt.icmpCode; code != -1 {
				result += "/" + strconv.Itoa(code)
			}
		}
	}
	return result
}

// Handle iptables.
/*
func debugBintree (tree *netBintree, depth string) {
	ip      := tree.IP.String()
	len, _  := tree.Mask.Size()
   var subtree string
	if tree.subtree != nil {
		subtree = "subtree";
	}
	diag.Info("%s %s/%d %s", depth, ip, len, subtree)
	if lo := tree.lo; lo != nil {
		debugBintree(lo, depth + "l")
	}
	if hi := tree.hi; hi != nil {
		debugBintree(hi, depth + "r")
	}
}
*/

type netOrProt interface {
}

type lRuleTree map[netOrProt]*lRuleTree

type netBintree struct {
	ipNet
	subtree npBintree
	hi      *netBintree
	lo      *netBintree
	noop    bool
}

// Nodes are reverse sorted before being added to bintree.
// Redundant nodes are discarded while inserting.
// A node with value of sub-tree S is discarded,
// if some parent node already has sub-tree S.
func addBintree(tree *netBintree, node *netBintree) *netBintree {
	treeIP, prefix := tree.IP, tree.Bits
	nodeIP, nodePref := node.IP, node.Bits
	var result *netBintree

	// The case where new node is larger than root node will never
	// occur, because nodes are sorted before being added.

	if prefix < nodePref && tree.Contains(nodeIP) {

		// Optimization for this special case:
		// Root of tree has attribute .subtree which is identical to
		// attribute .subtree of current node.
		// Node is known to be less than root node.
		// Hence node together with its subtree can be discarded
		// because it is redundant compared to root node.
		// ToDo:
		// If this optimization had been done before mergeSubtrees,
		// it could have merged more subtrees.
		if tree.subtree == nil || node.subtree == nil ||
			tree.subtree != node.subtree {

			var hilo **netBintree
			upNet, _ := nodeIP.Prefix(prefix + 1)
			if upNet.IP == treeIP {
				hilo = &tree.lo
			} else {
				hilo = &tree.hi
			}
			if *hilo != nil {
				*hilo = addBintree(*hilo, node)
			} else {
				*hilo = node
			}
		}
		result = tree
	} else {

		// Create common root for tree and node.
		var root netaddr.IPPrefix
		for {
			prefix--
			root, _ = nodeIP.Prefix(prefix)
			trNet, _ := treeIP.Prefix(prefix)
			if root.IP == trNet.IP {
				break
			}
		}
		result = &netBintree{ipNet: ipNet{IPPrefix: root}}
		if nodeIP.Less(treeIP) {
			result.lo, result.hi = node, tree
		} else {
			result.hi, result.lo = node, tree
		}
	}

	// Merge adjacent sub-networks.
	if result.subtree == nil {
		lo, hi := result.lo, result.hi
		if lo == nil || hi == nil {
			goto NOMERGE
		}
		prefix := result.Bits
		prefix++
		if prefix != lo.Bits {
			goto NOMERGE
		}
		if prefix != hi.Bits {
			goto NOMERGE
		}
		if lo.subtree == nil || hi.subtree == nil {
			goto NOMERGE
		}
		if lo.subtree != hi.subtree {
			goto NOMERGE
		}
		if lo.lo != nil || lo.hi != nil || hi.lo != nil || hi.hi != nil {
			goto NOMERGE
		}
		result.subtree = lo.subtree
		result.lo = nil
		result.hi = nil
	}
NOMERGE:
	return result
}

// Build a binary tree for src/dst objects.
func genAddrBintree(
	tree lRuleTree, tree2bintree map[*lRuleTree]npBintree) *netBintree {

	elements := make([]*ipNet, 0, len(tree))
	for key := range tree {
		elements = append(elements, key.(*ipNet))
	}

	// The tree's node is a simplified network object with
	// missing attribute .name and extra .subtree.
	nodes := make([]*netBintree, len(elements))
	for i, elem := range elements {
		nodes[i] = &netBintree{
			ipNet:   *elem,
			subtree: tree2bintree[tree[elem]],
		}
	}

	// Sort by mask size and then by IP.
	// I.e. large networks coming first.
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Bits == nodes[j].Bits {
			return !nodes[i].IP.Less(nodes[j].IP)
		}
		return nodes[i].Bits < nodes[j].Bits
	})

	bintree := nodes[0]
	for _, node := range nodes[1:] {
		bintree = addBintree(bintree, node)
	}

	// Add attribute .noop to node which doesn't add any test to
	// generated rule.
	if bintree.Bits == 0 {
		bintree.noop = true
	}

	//	debugBintree(bintree, "")
	return bintree
}

func (tree *netBintree) Hi() npBintree {
	if hi := tree.hi; hi != nil {
		return hi
	}
	// Must not use nil *netBintree, but nil interface.
	return nil
}
func (tree *netBintree) Lo() npBintree {
	if lo := tree.lo; lo != nil {
		return lo
	}
	// Must not use nil *netBintree, but nil interface.
	return nil
}
func (tree *netBintree) Seq() []*prtBintree { return nil }
func (tree *netBintree) Subtree() npBintree {
	if subtree := tree.subtree; subtree != nil {
		return subtree
	}
	// Must not use nil *netBintree, but nil interface.
	return nil
}
func (tree *netBintree) Noop() bool { return tree.noop }

// Build a tree for src-range/prt objects. Sub-trees for tcp and udp
// will be binary trees. Nodes have attributes .protocol, .ports,
// .icmpType, .icmpCode like protocols (but without .name).
// Additional attributes for building the tree:
// For tcp and udp:
// .lo, .hi for sub-ranges of current node.
// For other protocols:
// .seq an array of ordered nodes for sub protocols of current node.
// Elements of .lo and .hi or elements of .seq are guaranteed to be
// disjoint.
// Additional attribute .subtree is set to corresponding subtree of
// protocol object if current node comes from a rule and wasn't inserted
// for optimization.

type prtBintree struct {
	proto
	subtree npBintree
	hi      *prtBintree
	lo      *prtBintree
	seq     []*prtBintree
	noop    bool
}

func genprtBintree(
	tree lRuleTree, tree2bintree map[*lRuleTree]npBintree) *prtBintree {

	elements := make([]*proto, 0, len(tree))
	for key := range tree {
		elements = append(elements, key.(*proto))
	}
	var ipPrt *proto
	topPrt := make(map[string][]*proto)
	subPrt := make(map[*proto][]*proto)

	// Add all protocols directly below protocol 'ip' into map topPrt
	// grouped by protocol. Add protocols below top protocols or below
	// other protocols of current set of protocols to map subPrt.
PRT:
	for _, prt := range elements {
		protocol := prt.protocol
		if protocol == "ip" {
			ipPrt = prt
			continue PRT
		}

		// Check if prt is sub protocol of any other protocol of
		// current set. But handle direct sub protocols of 'ip' as top
		// protocols.
		for up := prt.up; up.up != nil; up = up.up {
			if subtree, ok := tree[up]; ok {

				// Found sub protocol of current set.
				// Optimization:
				// Ignore the sub protocol if both protocols have
				// identical subtrees.
				// In this case we found a redundant sub protocol.
				if tree[prt] != subtree {
					subPrt[up] = append(subPrt[up], prt)
				}
				continue PRT
			}
		}

		// Not a sub protocol (except possibly of IP).
		var key string
		if _, err := strconv.ParseUint(protocol, 10, 16); err == nil {
			key = "proto"
		} else {
			key = protocol
		}
		topPrt[key] = append(topPrt[key], prt)
	}

	// Collect subtrees for tcp, udp, proto and icmp.
	var seq []*prtBintree

	//Build subtree of tcp and udp protocols.
	//
	// We need not to handle 'tcp established' because it is only used
	// for stateless routers, but iptables is stateful.
	var genLohitrees func(prtAref []*proto) (*prtBintree, *prtBintree)
	var genRangetree func(prtAref []*proto) *prtBintree
	genLohitrees = func(prtAref []*proto) (*prtBintree, *prtBintree) {
		switch len(prtAref) {
		case 0:
			return nil, nil
		case 1:
			prt := prtAref[0]
			lo, hi := genLohitrees(subPrt[prt])
			node := &prtBintree{
				proto:   *prt,
				subtree: tree2bintree[tree[prt]],
				lo:      lo,
				hi:      hi,
			}
			return node, nil
		default:
			ports := make([]*proto, len(prtAref))
			copy(ports, prtAref)
			sort.Slice(ports, func(i, j int) bool {
				return ports[i].ports[0] < ports[j].ports[0]
			})

			// Split array in two halves (prefer larger left part).
			mid := (len(ports)-1)/2 + 1
			left := ports[:mid]
			right := ports[mid:]
			return genRangetree(left), genRangetree(right)
		}
	}
	genRangetree = func(prtAref []*proto) *prtBintree {
		lo, hi := genLohitrees(prtAref)
		if hi == nil {
			return lo
		}

		// Take low port from lower tree and high port from high tree.
		prt := *prtAref[0]
		prt.ports = [2]int{lo.ports[0], hi.ports[1]}

		// Merge adjacent port ranges.
		if lo.ports[1]+1 == hi.ports[0] &&
			lo.subtree != nil && hi.subtree != nil && lo.subtree == hi.subtree {

			hilo := make([]*prtBintree, 0, 4)
			for _, what := range []*prtBintree{lo.lo, lo.hi, hi.lo, hi.hi} {
				if what != nil {
					hilo = append(hilo, what)
				}
			}
			if len(hilo) <= 2 {

				//		debug("Merged: $lo->{range}->[0]-$lo->{range}->[1]",
				//		      " $hi->{range}->[0]-$hi->{range}->[1]");
				node := &prtBintree{
					proto:   prt,
					subtree: lo.subtree,
				}
				if len(hilo) > 0 {
					node.lo = hilo[0]
				}
				if len(hilo) > 1 {
					node.hi = hilo[1]
				}
				return node
			}
		}
		return &prtBintree{
			proto: prt,
			lo:    lo,
			hi:    hi,
		}
	}
	for _, what := range []string{"tcp", "udp"} {
		if aref, ok := topPrt[what]; ok {
			seq = append(seq, genRangetree(aref))
		}
	}

	// Add single nodes for numeric protocols.
	if aref, ok := topPrt["proto"]; ok {
		sort.Slice(aref, func(i, j int) bool {
			return aref[i].protocol < aref[j].protocol
		})
		for _, prt := range aref {
			node := &prtBintree{proto: *prt, subtree: tree2bintree[tree[prt]]}
			seq = append(seq, node)
		}
	}

	// Build subtree of icmp protocols.
	if icmpAref, ok := topPrt["icmp"]; ok {
		type2prt := make(map[int][]*proto)
		var icmpAny *proto

		// If one protocol is 'icmp any' it is the only top protocol,
		// all other icmp protocols are sub protocols.
		if icmpAref[0].icmpType == -1 {
			icmpAny = icmpAref[0]
			icmpAref = subPrt[icmpAny]
		}

		// Process icmp protocols having defined type and possibly defined code.
		// Group protocols by type.
		for _, prt := range icmpAref {
			icmpType := prt.icmpType
			type2prt[icmpType] = append(type2prt[icmpType], prt)
		}

		// Parameter is array of icmp protocols all having
		// the same type and different but defined code.
		// Return reference to array of nodes sorted by code.
		genIcmpTypeCodeSorted := func(aref []*proto) []*prtBintree {
			sort.Slice(aref, func(i, j int) bool {
				return aref[i].icmpCode < aref[j].icmpCode
			})
			result := make([]*prtBintree, len(aref))
			for i, proto := range aref {
				result[i] = &prtBintree{
					proto:   *proto,
					subtree: tree2bintree[tree[proto]],
				}
			}
			return result
		}

		// For collecting subtrees of icmp subtree.
		var seq2 []*prtBintree

		// Process grouped icmp protocols having the same type.
		types := make([]int, 0, len(type2prt))
		for icmpType := range type2prt {
			types = append(types, icmpType)
		}
		sort.Ints(types)
		for _, icmpType := range types {
			aref2 := type2prt[icmpType]
			var node2 *prtBintree

			// If there is more than one protocol,
			// all have same type and defined code.
			if len(aref2) > 1 {
				seq3 := genIcmpTypeCodeSorted(aref2)

				// Add a node 'icmp type any' as root.
				node2 = &prtBintree{
					proto: proto{protocol: "icmp", icmpType: icmpType, icmpCode: -1},
					seq:   seq3,
				}
			} else {

				// One protocol 'icmp type any'.
				prt := aref2[0]
				node2 = &prtBintree{
					proto:   *prt,
					subtree: tree2bintree[tree[prt]],
				}
				if aref3, ok := subPrt[prt]; ok {
					node2.seq = genIcmpTypeCodeSorted(aref3)
				}
			}
			seq2 = append(seq2, node2)
		}

		// Add root node for icmp subtree.
		var node *prtBintree
		if icmpAny != nil {
			node = &prtBintree{
				proto:   *icmpAny,
				seq:     seq2,
				subtree: tree2bintree[tree[icmpAny]],
			}
		} else if len(seq2) > 1 {
			node = &prtBintree{
				proto: proto{protocol: "icmp", icmpType: -1, icmpCode: -1},
				seq:   seq2,
			}
		} else {
			node = seq2[0]
		}
		seq = append(seq, node)
	}

	// Add root node for whole tree.
	var bintree *prtBintree
	if ipPrt != nil {
		bintree = &prtBintree{
			proto:   *ipPrt,
			seq:     seq,
			subtree: tree2bintree[tree[ipPrt]],
		}
	} else if len(seq) > 1 {
		bintree = &prtBintree{proto: proto{protocol: "ip"}, seq: seq}
	} else {
		bintree = seq[0]
	}

	// Add attribute .noop to node which doesn't need any test in
	// generated chain.
	if bintree.protocol == "ip" {
		bintree.noop = true
	}
	return bintree
}

func (tree *prtBintree) Hi() npBintree {
	if hi := tree.hi; hi != nil {
		return hi
	}
	// Must not use nil *prtBintree, but nil interface.
	return nil
}
func (tree *prtBintree) Lo() npBintree {
	if lo := tree.lo; lo != nil {
		return lo
	}
	// Must not use nil *prtBintree, but nil interface.
	return nil
}
func (tree *prtBintree) Seq() []*prtBintree { return tree.seq }
func (tree *prtBintree) Subtree() npBintree {
	if subtree := tree.subtree; subtree != nil {
		return subtree
	}
	// Must not use nil *prtBintree, but nil interface.
	return nil
}
func (tree *prtBintree) Noop() bool { return tree.noop }

type attrOrder [4]struct {
	count int
	get   func(*ciscoRule) interface{}
	set   func(*linuxRule, interface{})
	name  string
}
type lChain struct {
	name  string
	rules linuxRules
}
type npBintree interface {
	Hi() npBintree
	Lo() npBintree
	Seq() []*prtBintree
	Subtree() npBintree
	Noop() bool
}

type linuxRule struct {
	deny          bool
	src, dst      *netBintree
	prt, srcRange *prtBintree
	chain         *lChain
	useGoto       bool
}

type linuxRules []*linuxRule

func (rules *linuxRules) push(rule *linuxRule) {
	*rules = append(*rules, rule)
}

func findChains(aclInfo *aclInfo, routerData *routerData) {
	rules := aclInfo.rules
	prt2obj := aclInfo.prt2obj
	prtIP := prt2obj["ip"]
	prtIcmp := prt2obj["icmp"]
	prtTCP := prt2obj["tcp"]
	prtUDP := prt2obj["udp"]
	network00 := aclInfo.network00

	// Specify protocols tcp, udp, icmp in
	// .srcRange, to get more efficient chains.
	for _, rule := range rules {
		if rule.srcRange == nil {
			switch rule.prt.protocol {
			case "tcp":
				rule.srcRange = prtTCP
			case "udp":
				rule.srcRange = prtUDP
			case "icmp":
				rule.srcRange = prtIcmp
			default:
				rule.srcRange = prtIP
			}
		}
	}

	//    my $printTree;
	//    $printTree = sub {
	//        my ($tree, $order, $depth) = @_;
	//        for my $name (keys %$tree) {
	//
	//            debug(' ' x $depth, $name);
	//            if ($depth < $#$order) {
	//                $printTree->($tree->{$name}, $order, $depth + 1);
	//            }
	//        }
	//    };

	codedLpermit := &lRuleTree{false: nil}
	codedLdeny := &lRuleTree{true: nil}
	codedBpermit := &netBintree{noop: false}
	codedBdeny := &netBintree{noop: true}
	subtree2bintree := make(map[*lRuleTree]npBintree)
	subtree2bintree[codedLdeny] = codedBdeny
	subtree2bintree[codedLpermit] = codedBpermit

	insertBintree := func(tree *lRuleTree) npBintree {
		var elem1 netOrProt
		for key := range *tree {
			elem1 = key
			break
		}
		if _, ok := elem1.(*ipNet); ok {
			// Put prt/src/dst objects at the root of some subtree into a
			// (binary) tree. This is used later to convert subsequent tests
			// for ip/mask or port ranges into more efficient nested chains.
			return genAddrBintree(*tree, subtree2bintree)
		}
		return genprtBintree(*tree, subtree2bintree)
	}

	// Used by mergeSubtrees1 to find identical subtrees.
	// Use map for efficient lookup.
	type lookup struct {
		depth int
		size  int
	}
	depth2size2subtrees := make(map[lookup][]*lRuleTree)

	// Find and merge identical subtrees.
	// Create bintree from subtree and store in subtree2bintree.
	mergeSubtrees1 := func(tree *lRuleTree, depth int) {

	SUBTREE:
		for k, subtree := range *tree {
			size := len(*subtree)
			l := lookup{depth, size}

			// Find subtree with identical keys and values;
		FIND:
			for _, subtree2 := range depth2size2subtrees[l] {
				for key, val := range *subtree {
					if val2, ok := (*subtree2)[key]; !ok || val2 != val {
						continue FIND
					}
				}

				// Substitute current subtree with identical subtree2
				(*tree)[k] = subtree2
				continue SUBTREE
			}

			// Found a new subtree.
			depth2size2subtrees[l] = append(depth2size2subtrees[l], subtree)
			bintree := insertBintree(subtree)
			subtree2bintree[subtree] = bintree
		}
	}

	mergeSubtrees := func(tree *lRuleTree) npBintree {

		// Process leaf nodes first.
		for _, tree1 := range *tree {
			for _, tree2 := range *tree1 {
				mergeSubtrees1(tree2, 2)
			}
		}

		// Process nodes next to leaf nodes.
		for _, tree1 := range *tree {
			mergeSubtrees1(tree1, 1)
		}

		// Process nodes next to root.
		mergeSubtrees1(tree, 0)
		return insertBintree(tree)
	}

	// Add new chain to current router.
	newChain := func(rules linuxRules) *lChain {
		routerData.chainCounter++
		chain := &lChain{
			name:  "c" + strconv.Itoa(routerData.chainCounter),
			rules: rules,
		}
		routerData.chains = append(routerData.chains, chain)
		return chain
	}

	getSeq := func(bintree npBintree) []npBintree {
		seq := bintree.Seq()
		var result []npBintree
		if seq == nil {
			if hi := bintree.Hi(); hi != nil {
				result = append(result, hi)
			}
			if lo := bintree.Lo(); lo != nil {
				result = append(result, lo)
			}
		} else {
			result = make([]npBintree, len(seq))
			for i, v := range seq {
				result[i] = v
			}
		}
		return result
	}

	cache := make(map[npBintree]linuxRules)

	var genChain func(tree npBintree, order *attrOrder, depth int) linuxRules
	genChain = func(tree npBintree, order *attrOrder, depth int) linuxRules {
		setter := order[depth].set
		var newRules linuxRules

		// We need the original value later.
		bintree := tree
		for {
			seq := getSeq(bintree)
			subtree := bintree.Subtree()
			if subtree != nil {
				/*
				   if($order->[$depth+1]&&
				      $order->[$depth+1] =~ /^(src|dst)$/) {
				       debug($order->[$depth+1]);
				       debugBintree($subtree);
				   }
				*/
				rules := cache[subtree]
				if rules == nil {
					if depth+1 >= len(order) {
						rules = linuxRules{{deny: subtree.(*netBintree).noop}}
					} else {
						rules = genChain(subtree, order, depth+1)
					}
					if len(rules) > 1 && !bintree.Noop() {
						chain := newChain(rules)
						rules = linuxRules{{chain: chain, useGoto: true}}
					}
					cache[subtree] = rules
				}

				// Don't use "goto", if some tests for sub-nodes of
				// subtree are following.
				if len(seq) != 0 || !bintree.Noop() {
					for _, rule := range rules {

						// Create a copy of each rule because we must not change
						// the original cached rules.
						newRule := *rule
						if len(seq) != 0 {
							newRule.useGoto = false
						}
						if !bintree.Noop() {
							setter(&newRule, bintree)
						}
						newRules.push(&newRule)
					}
				} else {
					newRules = append(newRules, rules...)
				}
			}
			if seq == nil {
				break
			}

			// Take this value in next iteration.
			last := len(seq) - 1
			bintree, seq = seq[last], seq[:last]

			// Process remaining elements.
			for _, node := range seq {
				rules := genChain(node, order, depth)
				newRules = append(newRules, rules...)
			}
		}
		if len(newRules) > 1 && !tree.Noop() {

			// Generate new chain. All elements of @seq are
			// known to be disjoint. If one element has matched
			// and branched to a chain, then the other elements
			// need not be tested again. This is implemented by
			// calling the chain using '-g' instead of the usual '-j'.
			chain := newChain(newRules)
			newRule := &linuxRule{chain: chain, useGoto: true}
			setter(newRule, tree)
			return linuxRules{newRule}
		}
		return newRules
	}

	// Build rule trees. Generate and process separate tree for
	// adjacent rules with same 'deny' attribute.
	// Store rule tree together with order of attributes.
	type treeAndOrder struct {
		tree  *lRuleTree
		order *attrOrder
	}
	var ruleSets []treeAndOrder
	var count [4]map[interface{}]int
	for i := range count {
		count[i] = make(map[interface{}]int)
	}
	order := attrOrder{
		{
			get: func(rule *ciscoRule) interface{} { return rule.srcRange },
			set: func(rule *linuxRule, val interface{}) {
				rule.srcRange = val.(*prtBintree)
			},
			name: "srcRange",
		},
		{
			get: func(rule *ciscoRule) interface{} { return rule.dst },
			set: func(rule *linuxRule, val interface{}) {
				rule.dst = val.(*netBintree)
			},
			name: "dst",
		},
		{
			get: func(rule *ciscoRule) interface{} { return rule.prt },
			set: func(rule *linuxRule, val interface{}) {
				rule.prt = val.(*prtBintree)
			},
			name: "prt",
		},
		{
			get: func(rule *ciscoRule) interface{} { return rule.src },
			set: func(rule *linuxRule, val interface{}) {
				rule.src = val.(*netBintree)
			},
			name: "src",
		},
	}
	if len(rules) > 0 {
		prevDeny := rules[0].deny

		// Add special rule as marker, that end of rules has been reached.
		rules.push(&ciscoRule{src: nil})
		var start = 0
		last := len(rules) - 1
		var i = 0
		for {
			rule := rules[i]
			deny := rule.deny
			if deny == prevDeny && i < last {

				// Count, which attribute has the largest number of
				// different values.
				for i, what := range order {
					count[i][what.get(rule)]++
				}
				i++
			} else {
				for i, attrMap := range count {
					order[i].count = len(attrMap)

					// Reset counter for next tree.
					count[i] = make(map[interface{}]int)
				}

				// Use key with smaller number of different values
				// first in rule tree. This gives smaller tree and
				// fewer tests in chains.
				sort.SliceStable(order[:], func(i, j int) bool {
					return order[i].count < order[j].count
				})
				ruleTree := make(lRuleTree)
				for _, rule := range rules[start:i] {
					add := func(what int, tree *lRuleTree) *lRuleTree {
						key := order[what].get(rule)
						subtree := (*tree)[key]
						if subtree == nil {
							m := make(lRuleTree)
							(*tree)[key] = &m
							subtree = &m
						}
						return subtree
					}
					subtree := add(0, &ruleTree)
					subtree = add(1, subtree)
					subtree = add(2, subtree)
					key3 := order[3].get(rule)
					if rule.deny {
						(*subtree)[key3] = codedLdeny
					} else {
						(*subtree)[key3] = codedLpermit
					}
				}
				ruleSets = append(ruleSets, treeAndOrder{&ruleTree, &order})
				if i == last {
					break
				}
				start = i
				prevDeny = deny
			}
		}
		rules = nil
	}

	var lrules linuxRules
	for i, set := range ruleSets {

		//    $printTree->($tree, $order, 0);
		bintree := mergeSubtrees(set.tree)
		result := genChain(bintree, set.order, 0)

		// Goto must not be used in last rule of rule tree which is
		// not the last tree.
		if i < len(ruleSets)-1 {
			rule := result[len(result)-1]
			rule.useGoto = false
		}

		// Postprocess lrules: Add missing attributes prt, src, dst
		// with no-op values.
		for _, rule := range result {
			if rule.src == nil {
				rule.src = &netBintree{ipNet: *network00}
			}
			if rule.dst == nil {
				rule.dst = &netBintree{ipNet: *network00}
			}
			prt := rule.prt
			srcRange := rule.srcRange
			if prt == nil && srcRange == nil {
				rule.prt = &prtBintree{proto: *prtIP}
			} else if prt == nil {
				switch srcRange.protocol {
				case "tcp":
					rule.prt = &prtBintree{proto: *prtTCP}
				case "udp":
					rule.prt = &prtBintree{proto: *prtUDP}
				case "icmp":
					rule.prt = &prtBintree{proto: *prtIcmp}
				}
			}
		}
		lrules = append(lrules, result...)
	}
	aclInfo.lrules = lrules
}

// Given an IP and mask, return its address
// as "x.x.x.x/x" or "x.x.x.x" if prefix == 32 (128 for IPv6).
func prefixCode(ipNet *ipNet) string {
	if ipNet.IPPrefix.IsSingleIP() {
		return ipNet.IP.String()
	}
	return ipNet.String()
}

func jumpCode(rule *linuxRule) string {
	if rule.useGoto {
		return "-g"
	}
	return "-j"
}

func actionCode(rule *linuxRule) string {
	if rule.chain != nil {
		return rule.chain.name
	}
	if rule.deny {
		return "droplog"
	}
	return "ACCEPT"
}

// Print chains of iptables.
// Objects have already been normalized to ip/mask pairs.
// NAT has already been applied.
func printChains(fd *os.File, routerData *routerData) {
	chains := routerData.chains
	routerData.chains = nil
	if len(chains) == 0 {
		return
	}

	aclInfo := routerData.acls[0]
	prt2obj := aclInfo.prt2obj
	prtIcmp := prt2obj["icmp"]
	prtTCP := prt2obj["tcp"]
	prtUDP := prt2obj["udp"]

	// Declare chain names.
	for _, chain := range chains {
		fmt.Fprintf(fd, ":%s -\n", chain.name)
	}

	// Define chains.
	for _, chain := range chains {
		prefix := "-A " + chain.name
		for _, rule := range chain.rules {
			result := jumpCode(rule) + " " + actionCode(rule)
			if src := rule.src; src != nil {
				if src.Bits != 0 {
					result += " -s " + prefixCode(&src.ipNet)
				}
			}
			if dst := rule.dst; dst != nil {
				if dst.Bits != 0 {
					result += " -d " + prefixCode(&dst.ipNet)
				}
			}
			srcRange := rule.srcRange
			prt := rule.prt
			if prt == nil && srcRange != nil {
				prt = new(prtBintree)
				switch srcRange.protocol {
				case "tcp":
					prt.proto = *prtTCP
				case "udp":
					prt.proto = *prtUDP
				case "icmp":
					prt.proto = *prtIcmp
				}
			}
			if prt != nil {
				result += iptablesPrtCode(srcRange, prt, routerData.ipv6)
			}
			fmt.Fprintln(fd, prefix, result)
		}
	}

	// Empty line as delimiter.
	fmt.Fprintln(fd)
}

func iptablesACLLine(fd *os.File, rule *linuxRule, prefix string, ipv6 bool) {
	src, dst, srcRange, prt := rule.src, rule.dst, rule.srcRange, rule.prt
	result := prefix + " " + jumpCode(rule) + " " + actionCode(rule)
	if src.Bits != 0 {
		result += " -s " + prefixCode(&src.ipNet)
	}
	if dst.Bits != 0 {
		result += " -d " + prefixCode(&dst.ipNet)
	}
	if prt.protocol != "ip" {
		result += iptablesPrtCode(srcRange, prt, ipv6)
	}
	fmt.Fprintln(fd, result)
}

func printIptablesACL(fd *os.File, aclInfo *aclInfo, routerData *routerData) {
	name := aclInfo.name
	fmt.Fprintf(fd, ":%s -\n", name)
	intfPrefix := "-A " + name
	for _, rule := range aclInfo.lrules {
		iptablesACLLine(fd, rule, intfPrefix, routerData.ipv6)
	}
}
