package pass1

func expandProtocols(list []protoOrName, ctx string) []*proto {
	result := make(protoList, 0)
	for _, pair := range list {
		switch p := pair.(type) {

		// Handle anonymous protocol.
		case *proto:
			result.push(p)

		case []string:
			typ, name := p[0], p[1]
			switch typ {
			case "protocol":
				if prt, ok := protocols[name]; ok {
					result.push(prt)

					// Currently needed by external program 'cut-netspoc'.
					prt.isUsed = true
				} else {
					errMsg("Can't resolve reference to %s:%s in %s",
						typ, name, ctx)
				}
			case "protocolgroup":
				if prtgroup, ok := protocolGroups[name]; ok {
					if prtgroup.recursive {
						errMsg("Found recursion in definition of %s", ctx)
						prtgroup.elements = nil

						// Check if it has already been converted
						// from names to references.
					} else if !prtgroup.isUsed {
						prtgroup.isUsed = true

						// Detect recursive definitions.
						prtgroup.recursive = true
						prtgroup.elements =
							expandProtocols(prtgroup.pairs, typ+":"+name)
						prtgroup.recursive = false
					}
					result = append(result, prtgroup.elements...)
				} else {
					errMsg("Can't resolve reference to %s:%s in %s",
						typ, name, ctx)
				}
			default:
				errMsg("Unknown type of %s:%s in %s",
					typ, name, ctx)
			}
		}
	}
	return result
}

func expandSplitProtocol(p *proto) protoList {

	// Handle unset srcRange.
	if p == nil {
		return protoList{p}
	} else if split := p.split; split != nil {
		prt1, prt2 := split[0], split[1]
		return (append(expandSplitProtocol(prt1), expandSplitProtocol(prt2)...))
	} else {
		return protoList{p}
	}
}

// Split protocols.
// Result:
// list of elements
// - non TCP/UDP protocol
// - dstRange of (split) TCP/UDP protocol
// - [ srcRange, dstRange, origPrt ]
//   of (split) protocol having src_range or main_prt.
func splitProtocols(l protoList) []interface{} {
	var result []interface{}
	for _, p := range l {
		if !(p.proto == "tcp" || p.proto == "udp") {
			result = append(result, p)
			continue
		}

		// Collect split srcRange / dstRange pairs.
		dstRange := p.dst
		srcRange := p.src

		// Remember original protocol as third value
		// - if srcRange is given or
		// - if original protocol has modifiers or
		// - if dstRange is shared between different protocols.
		// Cache list of triples at original protocol for re-use.
		if srcRange != nil || p.modifiers != nil || dstRange.name != p.name {
			cached := p.srcDstRangeList
			if cached == nil {
				for _, s := range expandSplitProtocol(srcRange) {
					for _, d := range expandSplitProtocol(dstRange) {
						cached = append(cached, &complexProto{src: s, dst: d, orig: p})
					}
				}
				p.srcDstRangeList = cached
			}
			for _, c := range cached {
				result = append(result, c)
			}
		} else {
			for _, dstSplit := range expandSplitProtocol(dstRange) {
				result = append(result, dstSplit)
			}
		}
	}
	return result
}
