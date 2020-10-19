package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"github.com/hknutzen/Netspoc/go/pkg/jcode"
	"sort"
)

var network00 = &network{
	ipObj: ipObj{
		name: "network:0/0",
		ip:   getZeroIp(false),
	},
	mask:           getZeroMask(false),
	isAggregate:    true,
	hasOtherSubnet: true,
}

var network00v6 = &network{
	ipObj: ipObj{
		name: "network:0/0",
		ip:   getZeroIp(true),
	},
	mask:           getZeroMask(true),
	isAggregate:    true,
	hasOtherSubnet: true,
}

func getNetwork00(ipv6 bool) *network {
	if ipv6 {
		return network00v6
	} else {
		return network00
	}
}

func initStdProtocols(sym *symbolTable) {
	define := func(s string) *proto {
		return getSimpleProtocol(s, sym, false, s)
	}
	prtIP = define("ip")
	prtTCP := define("tcp")
	prtUDP = define("udp")
	prtIke = define("udp 500 : 500")
	prtNatt = define("udp 4500 : 4500")
	prtEsp = define("proto 50")
	prtAh = define("proto 51")
	cp := *prtTCP.dst
	cp.established = true
	cp.name = "tcp established"
	cp.up = prtTCP.dst
	rangeTCPEstablished = &cp

	prtBootps = define("udp 67").dst
	prtBootpc = define("udp 68").dst

	permitAnyRule = &groupedRule{
		src: []someObj{network00},
		dst: []someObj{network00},
		serviceRule: &serviceRule{
			prt: []*proto{prtIP},
		},
	}
	permitAny6Rule = &groupedRule{
		src: []someObj{network00v6},
		dst: []someObj{network00v6},
		serviceRule: &serviceRule{
			prt: []*proto{prtIP},
		},
	}
	denyAnyRule = &groupedRule{
		src: []someObj{network00},
		dst: []someObj{network00},
		serviceRule: &serviceRule{
			deny: true,
			prt:  []*proto{prtIP},
		},
	}
	denyAny6Rule = &groupedRule{
		src: []someObj{network00v6},
		dst: []someObj{network00v6},
		serviceRule: &serviceRule{
			deny: true,
			prt:  []*proto{prtIP},
		},
	}
}

// Order protocols. We need this to simplify optimization.
func OrderProtocols() {
	diag.Progress("Arranging protocols")

	var tcp, udp, icmp, proto protoList
	for _, p := range symTable.rangeProto {
		switch p.proto {
		case "tcp":
			tcp.push(p)
		case "udp":
			udp.push(p)
		}
	}
	for _, p := range symTable.unnamedProto {
		switch p.proto {
		case "icmp":
			icmp.push(p)
		case "proto":
			proto.push(p)
		}
	}
	up := prtIP
	orderRanges(tcp, up)
	orderRanges(udp, up)
	orderIcmp(icmp, up)
	orderProto(proto, up)
}

// Set 'up' relation from port range to the smallest port range which
// includes it.
// If no including range is found, link it with next larger protocol.
// Find overlapping ranges and split one of them to eliminate the overlap.
// Set attribute 'split' at original range, referencing pair of split ranges.
func orderRanges(l protoList, up *proto) {

	// Sort by low port. If low ports are equal, sort reverse by high port.
	// I.e. larger ranges coming first, if there are multiple ranges
	// with identical low port.
	sort.Slice(l, func(i, j int) bool {
		return l[i].ports[0] < l[j].ports[0] ||
			l[i].ports[0] == l[j].ports[0] &&
				l[i].ports[1] > l[j].ports[1]
	})

	// Check current range [a1, a2] for sub-ranges, starting at position i.
	// Return position of range which isn't sub-range.
	var checkSubrange func(a *proto, a2, i int) int
	checkSubrange = func(a *proto, a2, i int) int {
		for {
			if i == len(l) {
				return i
			}
			b := l[i]
			b1, b2 := b.ports[0], b.ports[1]

			// Not related.
			// aaaa    bbbbb
			// or neighbors
			// aaaabbbb
			if a2 < b1 {
				return i
			}

			// a includes b.
			// aaaaaaa
			//  bbbbb
			if a2 >= b2 {
				b.up = a

				//debug("%s [%d-%d] < %s [%d-%d]",
				//	b.name, b1, b2, a.name, a.ports[0], a2)
				i = checkSubrange(b, b2, i+1)

				// Stop at end of array.
				if i == len(l) {
					return i
				}
				continue
			}

			// a and b are overlapping.
			// aaaaa
			//   bbbbbb
			// Split b in two parts x and y with x included by a:
			// aaaaa
			//   xxxyyy
			x1 := b1
			x2 := a2
			y1 := a2 + 1
			y2 := b2

			//debug("%s [%d-5d] split into [%d-%d] and [%d-%d]",
			//b.name, b1, b2, x1, x2, y1, y2)
			findOrInsertRange := func(a1, a2, i int, orig *proto) *proto {
				for {
					if i == len(l) {
						break
					}
					b := l[i]
					b1, b2 := b.ports[0], b.ports[1]

					// New range starts at higher position and therefore must
					// be inserted behind current range.
					if a1 > b1 {
						i++
						continue
					}

					// New and current range start a same position.
					if a1 == b1 {

						// New range is smaller and therefore must be inserted
						// behind current range.
						if a2 < b2 {
							i++
							continue
						}

						// Found identical range, return this one.
						if a2 == b2 {

							//debug("Split range is already defined: %s", b.name)
							return b
						}

						// New range is larger than current range and therefore
						// must be inserted in front of current one.
						break
					}

					// New range starts at lower position than current one.
					// It must be inserted in front of current range.
					break
				}
				pr := orig.proto
				new := &proto{
					name:  jcode.GenPortName(pr, a1, a2),
					proto: pr,
					ports: [2]int{a1, a2},
				}
				// Insert new range at position i.
				l = append(l, nil)
				copy(l[i+1:], l[i:])
				l[i] = new
				return new
			}
			left := findOrInsertRange(x1, x2, i+1, b)
			rigth := findOrInsertRange(y1, y2, i+1, b)
			b.split = &[2]*proto{left, rigth}

			// Continue processing with next element.
			i++
		}
	}

	// Array wont be empty because prtTCP and prtUDP are defined internally.
	if len(l) == 0 {
		return
	}

	a := l[0]
	a.up = up
	a2 := a.ports[1]
	checkSubrange(a, a2, 1)
}

// Set 'up' relation between all ICMP protocols and to larger 'ip' protocol.
func orderIcmp(l protoList, up *proto) {
	m := make(map[int]*proto)
	for _, p := range l {
		if t := p.icmpType; t == -1 {
			// Handle 'icmp any'.
			p.up = up
			up = p
		} else if p.icmpCode == -1 {
			// Remember 'icmp type' as larger than 'icmp type code'.
			m[p.icmpType] = p
		}
	}
	for _, p := range l {
		if t := p.icmpType; t != -1 {
			if p.icmpCode != -1 {
				if u, found := m[t]; found {
					p.up = u
				} else {
					p.up = up
				}
			} else {
				p.up = up
			}
		}
	}
}

// Set 'up' relation for all numeric protocols to larger 'ip' protocol.
func orderProto(l protoList, up *proto) {
	for _, p := range l {
		p.up = up
	}
}
