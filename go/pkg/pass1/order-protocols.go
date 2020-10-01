package pass1

import (
	"github.com/hknutzen/Netspoc/go/pkg/diag"
	"sort"
	"strconv"
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
		p := getSimpleProtocol(s, false, s)
		return cacheUnnamedProtocol(p, sym)
	}
	prtIP = define("ip")
	prtTCP := define("tcp")
	prtUDP = define("udp")
	prtIke = define("udp 500 : 500")
	prtNatt = define("udp 4500 : 4500")
	prtEsp = define("proto 50")
	prtAh = define("proto 51")
	tcpAny := *prtTCP.dst
	tcpAny.established = true
	tcpAny.name = "reversed:tcp"
	rangeTCPEstablished = &tcpAny
	rangeTCPEstablished.up = prtTCP.dst

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
// Additionally add internal predefined protocols.
func orderProtocols(sym *symbolTable) {
	diag.Progress("Arranging protocols")

	// Internal protocols need to be processed before user defined protocols,
	// because we want to avoid handling of 'main' for internal protocols.
	// prtTcp and prtUdp need to be processed before all other TCP and UDP
	// protocols, because otherwise the range 1..65535 would get a misleading
	// name.
	preparePrtOrdering(prtIP)
	preparePrtOrdering(prtUDP)
	preparePrtOrdering(prtIke)
	preparePrtOrdering(prtNatt)
	preparePrtOrdering(prtEsp)
	preparePrtOrdering(prtAh)
	for _, p := range sym.protocol {
		preparePrtOrdering(p)
	}
	for _, p := range sym.unnamedProto {
		preparePrtOrdering(p)
	}

	up := prtIP
	orderRanges(prtMap.tcp, up)
	orderRanges(prtMap.udp, up)
	orderIcmp(prtMap.icmp, up)
	orderProto(prtMap.proto, up)
}

// Add protocol to prtMap.
// Link duplicate protocol definitions via attribute 'main'.
func preparePrtOrdering(p *proto) {
	var main *proto
	switch p.proto {
	case "tcp", "udp":
		// sub protocols for src and dst ranges have already been added
		// to prtMap in getRangeProto.
		return
	case "icmp":
		t := p.icmpType
		c := p.icmpCode
		key := ""
		if t != -1 {
			key += strconv.Itoa(t)
			if c != -1 {
				key += "/" + strconv.Itoa(c)
			}
		}
		if main = prtMap.icmp[key]; main == nil {
			prtMap.icmp[key] = p
		}
	case "ip":
		if main = prtMap.ip; main == nil {
			prtMap.ip = p
		}
	default:
		// Other protocol.
		key := p.proto
		if main = prtMap.proto[key]; main == nil {
			prtMap.proto[key] = p
		}
	}
	if main != nil {

		// Found duplicate protocol definition. Link protocol with main.
		// We link all duplicate protocols to the first protocol found.
		// This assures that we always reach the main protocol from any
		// duplicate protocol in one step via '.main'. This is used
		// later to substitute occurrences of p with main.
		p.main = main
	}
}

// Set 'up' relation from port range to the smallest port range which
// includes it.
// If no including range is found, link it with next larger protocol.
// Set attribute 'hasNeighbor' to range adjacent to upper port.
// Find overlapping ranges and split one of them to eliminate the overlap.
// Set attribute 'split' at original range, referencing pair of split ranges.
func orderRanges(m map[string]*proto, up *proto) {
	l := make(protoList, 0, len(m))
	for _, p := range m {
		l.push(p)
	}

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

			// Neighbors
			// aaaabbbb
			if a2+1 == b1 {
				// Mark protocol as candidate for joining of port ranges during
				// optimization.
				a.hasNeighbor = true
				b.hasNeighbor = true
			}

			// Not related.
			// aaaa    bbbbb
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
			// Split b in two parts x and y with x included by b:
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
					name:  pr + " " + strconv.Itoa(a1) + " - " + strconv.Itoa(a2),
					proto: pr,
					ports: [2]int{a1, a2},
					// Mark for range optimization.
					hasNeighbor: true,
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
func orderIcmp(m map[string]*proto, up *proto) {
	// Handle 'icmp any'.
	if p, found := m[""]; found {
		p.up = up
		up = p
	}
	for _, p := range m {
		if t := p.icmpType; t != -1 {
			if p.icmpCode != -1 {
				if u, found := m[strconv.Itoa(t)]; found {
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
func orderProto(m map[string]*proto, up *proto) {
	for _, p := range m {
		p.up = up
	}
}
