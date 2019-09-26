package pass1

func (l *protoList) push(p *proto) {
	*l = append(*l, p)
}

func expandProtocols(list []protoOrName, context string) []*proto {
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
						typ, name, context)
				}
			case "protocolgroup":
				if prtgroup, ok := protocolgroups[name]; ok {
					if prtgroup.recursive {
						errMsg("Found recursion in definition of %s", context)
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
					for _, prt := range prtgroup.elements {
						result.push(prt)
					}
				} else {
					errMsg("Can't resolve reference to %s:%s in %s",
						typ, name, context)
				}
			default:
				errMsg("Unknown type of  %s:%s in %s",
					typ, name, context)
			}
		}
	}
	return result
}
