package pass1

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

// Split and classify protocols.
type modifiedProto struct {
	prt       *proto
	src       *proto
	modifiers *modifiers
}

func classifyProtocols(l protoList) (protoList, []*modifiedProto) {
	var simple protoList
	var complex []*modifiedProto
	for _, p := range l {

		// Use the main protocol, but retrieve .modifiers from original.
		m := p.modifiers
		if p.main != nil {
			p = p.main
		}

		hasPorts := p.proto == "tcp" || p.proto == "udp"
		if m != nil || p.statelessICMP {
			if !hasPorts {
				complex = append(complex, &modifiedProto{p, nil, m})
			} else {
				srcRange := m.srcRange
				for _, s := range expandSplitProtocol(srcRange) {
					for _, d := range expandSplitProtocol(p) {
						complex = append(complex, &modifiedProto{d, s, m})
					}
				}
			}
		} else {
			if !hasPorts {
				simple.push(p)
			} else {
				simple = append(simple, expandSplitProtocol(p)...)
			}
		}
	}
	return simple, complex
}
